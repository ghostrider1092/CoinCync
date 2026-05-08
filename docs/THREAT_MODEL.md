# CoinCync threat model

This document specifies what CoinCync defends against, what it does not,
and which feature defends against which adversary. It exists because
"22 privacy features" is unfalsifiable on its own — competent reviewers
will ask "what is the adversary?" and "what is the trust model?" Without
explicit answers the privacy claims are marketing, not engineering.

The intended audience is auditors, integrators, journalists, and users
trying to decide whether CoinCync's privacy meets their threat model.
If your adversary is in §2 we describe how we resist them; if your
adversary is in §3 ("explicit non-defenses") we are not the right tool.

## 1. Trust model

A user running CoinCync trusts:

- **Their own machine.** Wallet keys live on disk encrypted with a
  password (Argon2id KDF). If the machine is compromised below the
  wallet's encryption — keylogger, RAM dump, OS-level malware — privacy
  is forfeit. Mainline crypto wallets share this assumption.
- **The Rust standard library, the curve25519-dalek crate, the
  RandomX implementation, and the Bulletproofs+ verifier.** Any
  cryptographic bug in these libraries is fatal to CoinCync's privacy
  claims. We pin versions and track upstream advisories.
- **The peer-to-peer network for liveness, NOT for privacy.** A
  user's privacy properties hold even when 100% of P2P peers are the
  same adversary. (Liveness — being able to send a tx — does require
  at least one honest peer to relay.)
- **The consensus rules in `src/consensus/` and `src/constants.rs`.**
  These are the contract. A user who upgrades to a binary built from
  modified consensus has a different chain.

A user does NOT trust:

- Any single CoinCync developer or operator.
- Block explorers, faucets, or other web services hosted by the
  CoinCync project. They see only chain-public data.
- Other wallets or other peers on the network.

## 2. Adversary classes and what we defend against

We name four classes. Real-world adversaries usually combine
capabilities; we map each privacy feature to the class it defeats so the
user can compose.

### 2.1 Class A: chain-only adversary

**Capabilities:** can read every confirmed block from genesis to tip.
Cannot observe the P2P network, cannot run a malicious wallet, cannot
coerce a user to disclose keys. This is the "block-explorer adversary"
— a researcher, a regulator with read-only chain access, or a chain
analytics firm.

**What we defend against:**

| Question they want to answer | Feature that defeats it |
|---|---|
| "Who sent this output?" | CLSAG ring signatures (16 members, 11 during bootstrap) hide the spender among other plausible spenders. |
| "Who received this output?" | Stealth addresses — every output is sent to a fresh one-time public key; the recipient's permanent address never appears on chain. |
| "How much was sent?" | Pedersen commitments — output amounts are never plaintext. Bulletproofs+ range proofs prove the amount is in `[0, 2^64)` without revealing it. |
| "Are these two outputs to the same user?" | One-time stealth derivation per output; identical recipient produces uncorrelated stealth addresses across txs. |
| "Is this a payment or self-transfer?" | Uniform 2-in/2-out tx shape post-activation: every Transfer looks structurally identical. |
| "Did this user spend output X?" | Decoy selection via gamma distribution — the spender's real input is statistically indistinguishable from decoys with realistic age profile. |
| "What's the recipient's wallet doing?" | View tags allow scanning without revealing match-or-not in tx structure; encrypted memos require the recipient's view key. |

**What does NOT defend against:**

- **Fee-side fingerprinting.** Two txs with very different fees per
  byte are obviously different "products" (e.g., a faucet drip-pair tx
  burns ~89 CYNC fee where a normal user tx burns ~7e-6). A chain
  analyst can flag drip-pair txs by fee anomaly today. Tracked in
  `docs/launch/KNOWN_ISSUES.md` as "drip-pair fee fingerprint";
  scheduled fix maintains right-sized faucet UTXOs.
- **Bootstrap-window analysis.** Heights 0–10000 use ring 11 instead
  of 16 (constitutional `BOOTSTRAP_MIN_RING_SIZE`). A user transacting
  in the bootstrap window has measurably weaker per-input
  unlinkability (1/11 ≈ 9% vs 1/16 = 6.25%). Document explicitly so
  privacy-sensitive users wait for ring 16.
- **Long-term timing analysis when the user only ever transacts at
  predictable times.** No protocol can hide "this person sends every
  Friday at 9am from a low-population timezone." The auto-churn
  feature (random self-sends) intentionally adds noise here, but
  defeating a determined statistical adversary requires user
  discipline.

### 2.2 Class B: network-observing adversary

**Capabilities:** can see every P2P packet on the network — a global
network observer, a Sybil-attacking peer cluster, or an ISP-level
adversary. Cannot read chain unless they also subscribe to it. Cannot
break encryption. This is the "Tor exit node adversary" or "passive
correlator."

**What we defend against:**

| Question they want to answer | Feature that defeats it |
|---|---|
| "Which IP submitted this tx?" | Dandelion++ stem-then-fluff relay: the originating IP is laundered through a stem-phase chain of single-peer hops before the tx fluffs into normal broadcast. A network observer who sees only the fluff phase cannot distinguish the originator from any node along the stem. |
| "Are these two txs from the same wallet?" | Each tx is independently stem-routed; the entry node into the network differs per tx. |
| "What is this peer's view of the chain?" | Noise_XX P2P encryption: every peer-peer link is authenticated and encrypted. A passive observer sees only ciphertext. |
| "Can I downgrade this peer's privacy?" | Peer scoring + per-peer "consecutive empty Blocks" counter (commit 28b3420) demotes peers that exhibit the IBD-stall pattern; a Sybil attempting to wedge a peer into a single-peer relationship for stem-phase deanon is auto-banned within 5 attempts. |
| "Can I time-correlate a tx submission with subsequent activity?" | Constant-rate padding on the wire — peer links emit fixed-shape traffic regardless of payload, so submit-then-relay timing is indistinguishable from idle peer chatter. |

**What does NOT defend against:**

- **Active cut-route adversary.** An attacker who controls the
  routing layer between the user and EVERY peer they connect to can
  partition them and observe their submissions in isolation. Defense
  requires Tor or a similar anonymizing transport beneath CoinCync's
  P2P. Ship Tor support and recommend its use for users in this
  threat model. Currently optional; mainnet wallet should default to
  Tor when available.
- **Persistent IP observation.** If the user runs a node continuously
  from a static IP, that IP is on the network. CoinCync's network
  layer hides which txs ORIGINATED from that node, not the existence
  of the node.

### 2.3 Class C: chain + network adversary

**Capabilities:** combines A and B. Can read every block AND every
packet. This is the "global passive adversary" — a state-level actor
or a chain-analytics firm partnering with a regional ISP.

**What we defend against:**

The composition of A and B; CoinCync's privacy properties are
independent across the two layers, so the adversary's capability is the
worse of the two for any given question. There is no privacy property
defended by A but not by C, or vice versa.

**What does NOT defend against:**

- **Wallet-side leaks.** If the user's wallet machine is compromised
  by the same adversary, all bets are off. CoinCync's privacy stops
  at the wallet's encryption boundary; below that boundary is the OS
  and the user's discipline.
- **Linkability via subaddress reuse.** If a user gives the same
  receive address to two payers and those payers later collude with
  the chain+network adversary, both payments are linked to that
  receive address. Recommendation: use fresh subaddresses per payer.
  Wallet UX should make this default; documented in §4 below.

### 2.4 Class D: coercion / key-extraction adversary

**Capabilities:** can demand the user's view key, spend key, or both.
"Open the wallet or you're arrested." The "rubber-hose adversary."

**What we defend against:**

| Question they want to answer | Feature that defeats it |
|---|---|
| "Where did your money come from? Show me." | Time-scoped view keys — a user can disclose a view key that decrypts only outputs received in a specified epoch range. Older / future outputs remain private. The `epoch` parameter on `KeyEpoch` enforces this scoping. |
| "Send me everything you own NOW." | Plausible-deniability wallets: the wallet binary supports decoy passwords that unlock a separate "deniable" wallet with its own (small, pre-arranged) balance. The adversary is shown a wallet that exists but doesn't reflect the user's full holdings. |
| "Confirm you didn't move funds in the last hour." | Dead man's switch — the user can pre-set a recovery address that, after N blocks of inactivity, can sweep the wallet without the user's signing input. A user under coercion can simply stop signing; their funds get rescued automatically. (Caveat: needs a watchtower for full automation; see KNOWN_ISSUES.md item #11.) |
| "Sign this tx." | FROST multi-sig — a user can split signing authority M-of-N across geographically/legally separated parties. No single coerced signer can produce a valid signature. |

**What does NOT defend against:**

- **Pre-coercion key copy.** If the adversary has already extracted
  the spend key (e.g. before the user's wallet was hardened), they
  can sign arbitrary txs. CoinCync's coercion defenses assume the
  user retains key custody at the moment of confrontation.
- **Threats to non-cryptographic targets.** Threats against the
  user's family, livelihood, etc. are outside any cryptographic
  threat model. Privacy tools reduce the *information value* of
  attacking the user, but they don't change the human side.

## 3. Explicit non-defenses

CoinCync does NOT claim to defend against:

- **Endpoint compromise.** Malware on the user's wallet machine.
  Use a hardware wallet, an air-gapped signing box, or accept that
  the wallet's privacy is bounded by the OS's privacy.
- **Social engineering of the user.** Phishing, fake wallet
  applications, fake "support" personnel asking for the seed. The
  cryptography assumes the user retains key custody.
- **Side-channel attacks on cryptographic primitives.** Power
  analysis of an embedded RandomX miner, EM emanations from a wallet
  machine, etc. Out of scope for the protocol; mitigated only at the
  hardware level.
- **Quantum adversary.** CoinCync uses ed25519 (curve25519). A
  fault-tolerant quantum computer running Shor's algorithm could
  forge signatures and recover spend keys. No deployed cryptocurrency
  has a current defense against this, but be honest: CoinCync isn't
  post-quantum. A migration plan exists at the spec level (lattice-
  based signatures via FROST-aware schemes) but is not deployed.
- **Coordinated chain-rewind by >51% of hashpower.** A miner who
  controls more than half the network's hashrate can rewrite recent
  history. PoW gives no defense beyond "obtaining 51% costs money."
  CoinCync's reorg-defense work (MESS / H-16 hybrid; see KNOWN_ISSUES
  item #4) reduces the depth at which this becomes feasible but does
  not eliminate it. Use enough confirmations.
- **Censorship at the relay layer.** A malicious node can refuse to
  relay specific txs. Dandelion++ helps because the user picks the
  stem entry; a Sybil cluster that owns most of the network can still
  censor. No L1 with open peering can fully prevent this.
- **Plaintext correlations made by the user themselves.** Posting
  "send 10 CYNC to address X" on a public forum and then sending 10
  CYNC to address X is a deanon the protocol cannot stop.

## 4. User-discipline assumptions

The threat model above assumes the user does the following. Wallet UX
should make these defaults; users who deviate accept proportional
privacy loss.

1. **Use a fresh subaddress per payer.** Reusing a single receive
   address links every payer who paid to it.
2. **Don't post addresses publicly tied to identity.** "My donation
   address: tCYNC..." on a public profile defeats stealth-address
   privacy for that address.
3. **Run auto-churn or randomize self-spend timing.** Predictable
   tx timing is a partial deanon channel even with full crypto privacy.
4. **Wait for sufficient confirmations on received funds.** A
   recipient who acts on 1-confirmation outputs is exposed to reorg
   attacks. The wallet's default `MIN_OUTPUT_AGE = 10` confirmations
   is the floor; high-value recipients should wait longer.
5. **Understand the bootstrap window.** During heights 0–10000,
   ring=11. Privacy-sensitive transfers should wait for ring=16.
6. **For high-coercion threat models, pre-configure FROST + dead
   man's switch BEFORE you need them.** They are useless if first
   set up under duress.

## 5. Versioning and changes to this document

Changes that REDUCE the set of defenses (i.e., remove a property from §2
or move one to §3) are consensus-breaking changes that require:
- A CIP describing the change and its rationale.
- A 30-day review window.
- Sign-off in `CODEOWNERS`-noted reviewers.

Changes that ADD defenses (new feature in §2) follow standard CIP
process and ship with the next protocol upgrade.

Changes that improve the wording of THIS document without changing
the underlying defense set are normal docs PRs.

## 6. References

- Source: `src/crypto/` (CLSAG, stealth, Pedersen, Bulletproofs+,
  view tags, ECDH).
- Source: `src/network/` (Dandelion++, Noise_XX, peer scoring,
  traffic shaping).
- Source: `src/wallet/scanner.rs` (output detection + commitment
  verification per Item 12).
- Source: `src/wallet/balance.rs` (in-flight UTXO reservations per
  Item 1, lifetime documented in `Reservation` doc-comment).
- Constitution invariants: `src/constants.rs` (supply cap, ring
  minimums, uniform-shape activation, fee-burn ratios).
- Outstanding gaps: `docs/launch/KNOWN_ISSUES.md` for items not yet
  fixed and their current mitigations.
