# Privacy model

CoinCync inherits the privacy stack used by Monero (CLSAG ring signatures + stealth addresses + bulletproofs), with two upgrades for Phase 2 (MimbleWimble cut-through and Lelantus Spark anonymity sets), and one design difference: **mandatory privacy enforced as a consensus rule**, with no transparent escape hatch.

## What an outside observer sees

For a CoinCync transaction in a public block:

| Field | Visible to observer? | Why |
|---|---|---|
| **Sender** | hidden | The CLSAG ring signature proves "one of these N ring members signed" without revealing which one |
| **Recipient** | hidden | The stealth address is a one-time public key only the recipient can recognize using their view key |
| **Amount** | hidden | The Pedersen commitment is encrypted; the Bulletproofs+ range proof attests it falls in `[0, 2^64)` without revealing the value |
| **Transaction graph** | obscured | Decoy outputs in every ring make it computationally infeasible to track UTXOs through history |
| **Block-level metadata** | visible | Block height, timestamp, miner pubkey (a one-time stealth address), tx count, total block size — these are by-design public so the chain can be verified by anyone |

A network observer who logs every transaction sees: timestamps, byte sizes, ring sizes, and the cryptographic proofs. That's all.

## The four primitives

### 1. CLSAG ring signatures

CLSAG (Concise Linkable Spontaneous Anonymous Group signatures) is a ring-signature scheme where:

- The signer chooses **N − 1 decoy outputs** from the chain's anonymity set (the UTXO pool of all unspent outputs)
- The signer's real input is mixed in with the decoys
- The resulting signature proves "I know the spending key for one of these N outputs" without revealing which
- A **key image** (`I = x · H_p(x · G)`, where `x` is the secret key) is published with the signature so the network can detect double-spends without learning which output was actually spent

CoinCync's minimum ring size is **11** (constitutional minimum, `MIN_RING_SIZE` in `src/constants.rs`). The default is the same as the minimum — there's no incentive to use a larger ring than the network requires, since wallets are uniform in their behavior and any deviation creates a fingerprint.

The CLSAG implementation lives in `src/crypto/clsag.rs`. The verifier in `src/consensus/validation.rs::verify_ring_signature` is called by both the consensus block-validator and the mempool admission path — **same function, no drift between miner and verifier**.

### 2. Stealth addresses

A stealth address pair `(spend_pub, view_pub)` lets a sender generate a fresh one-time output public key for every transaction:

```text
shared_secret = ECDH(tx_secret, view_pub)
output_pub_key = H(shared_secret || output_index) · G + spend_pub
```

The sender publishes `tx_pub_key = tx_secret · G` along with the output. The recipient, scanning the chain with their **view key**, recomputes the shared secret and tests every output for membership.

Because each output has a unique key, an external observer cannot link multiple payments to the same recipient. The recipient sees them all (they all derive from the same `(spend_pub, view_pub)` pair), but nobody else can.

Implementation: `src/crypto/stealth.rs`. The wallet's chain scanner is in `src/wallet/scanner.rs`.

### 3. Bulletproofs+ range proofs

Output amounts are stored as **Pedersen commitments** `C = a·G + b·H` where `a` is the amount and `b` is a blinding factor. The amount itself is never on the chain.

A **range proof** attests that the committed amount falls in `[0, 2^64)` without revealing it — this prevents a malicious sender from creating a transaction with a negative amount (which would let them mint money from nothing). CoinCync uses Bulletproofs+, which is ~96 bytes shorter and ~10% faster to verify than original Bulletproofs.

Implementation: `src/crypto/bulletproofs.rs`. Verification is called from `src/consensus/validation.rs::verify_output_range_proofs`, used by both the consensus path and mempool admission.

### 4. Balance proof

Pedersen commitments are additively homomorphic: `C(a) + C(b) = C(a + b)`. The balance proof leverages this:

```text
sum(input_pseudo_commitments) = sum(output_commitments) + fee_commitment
```

The verifier checks this equation without learning any individual amount. If the sender tried to create money from nothing, the equation wouldn't hold and the transaction would be rejected.

Implementation: `src/crypto/disclosure.rs::verify_balance_proof`. Same dual-call pattern as ring sig and range proof.

## View keys

A **view key** is a separate scalar that lets a third party scan the chain for outputs to a specific address **without** being able to spend them. The wallet derives one view key per epoch.

This enables selective disclosure:

- Show your view key to your accountant — they see your incoming and outgoing payments and can compute capital gains, but they cannot move funds
- Provide your view key to an exchange for KYC compliance — they verify your deposits without holding withdrawal authority
- Prove a specific transaction is yours without revealing your spend key

The view key is **read-only**. The spend key (which CAN move funds) is never required to be shared.

Implementation: `src/crypto/view_keys.rs`. Wallet integration: `src/wallet/key_epoch.rs`.

## Mandatory privacy

This is where CoinCync differs from Zcash. In Zcash you can hold value in a **transparent address** (`t-addr`) that behaves exactly like a Bitcoin address — sender, recipient, and amount all visible. The shielded pool is an *option*, not a requirement. In practice, most Zcash transactions are transparent because shielded operations were historically expensive.

CoinCync follows the **Pirate Chain model**: there is no transparent escape hatch. The consensus rule in `src/consensus/privacy_policy.rs::enforce_privacy_policy` rejects any transaction that:

- Has a zero output commitment (a transparent amount)
- Has a zero stealth address (a transparent recipient)
- Has zero ring inputs (a transparent sender) — coinbase exempt

This is enforced at the consensus level, not the mempool level — even a maliciously-crafted block trying to include a transparent transaction is rejected.

The motivation: optional privacy is no privacy at all, because the small population of users who *do* opt in stands out from the larger population who don't. Mandatory privacy means every user is part of the same anonymity set.

## Phase 2 upgrades

These are implemented in the codebase, header-committed in every block, but verification is gated until the respective fork-signal activation heights:

### MimbleWimble cut-through

Once a transaction is buried under enough confirmations and the chain is sure no reorg will revisit it, MW cut-through **collapses the historical transaction graph**. Outputs that have been spent and re-spent disappear from the chain, leaving only the unspent commitments. This:

- Compresses the chain (the chain shrinks rather than grows monotonically)
- Eliminates traceable transaction history (you can't analyze a graph that no longer exists)
- Comes with a kernel-set commitment (`mw_kernel_root` in the block header) that proves the cut-through was valid

Activation: CIP-006 (BIP9-style fork signaling). Implementation: `src/crypto/mw_cutthrough.rs` + `src/storage/kernels.rs`.

### Lelantus Spark anonymity sets

The current 11-member CLSAG ring gives a 1-in-11 anonymity set. Lelantus Spark replaces this with a **one-out-of-many proof** scheme that supports anonymity sets of up to **16,384 coins per spend**. The crypto is more expensive but the anonymity gain is roughly 1000× per transaction.

Activation: CIP-005 (BIP9-style fork signaling). Implementation: `src/crypto/lelantus_spark.rs` + `src/storage/spark.rs`. The current implementation is a Schnorr-style one-out-of-many proof using the existing CLSAG primitives — not the logarithmic-size Groth-Kohlweiss proof from the original Spark paper, but with the same security properties (completeness, soundness, anonymity, linkability).

## Hash domain separation

Every hash preimage in the protocol is **domain-separated** with a unique tag prefix. This is the kind of thing that doesn't matter until it does, and when it does, it's a consensus split.

| Preimage | Domain tag |
|---|---|
| Block header hash | `coincync/header/v1` |
| Transaction signing hash | `coincync/tx-sign/v1` |
| CLSAG Fiat-Shamir | (per the CLSAG construction in `src/crypto/clsag.rs`) |
| Bulletproof transcript | `CoinCync_RangeProof` (Merlin transcript) |
| BP+ transcript | `CoinCync_BPPlus_RangeProof` |

Two hashes computed with different tags can never collide, even if they hash the same underlying bytes. This eliminates a class of cross-protocol attacks where an adversary tries to make a CLSAG signature also be a valid block header hash, or similar.

## What CoinCync's privacy doesn't protect against

Honesty about limitations:

- **Network-layer correlation.** If you broadcast a transaction from your home IP, the network sees the IP that broadcast it. Use Tor (Caddy supports `.onion`, the node binary supports `--proxy socks5://...`) if your threat model requires it. See [Tor hidden services](../operations/tor.md).
- **Timing analysis.** A user who broadcasts at predictable times reveals patterns. Wallets should batch and randomize broadcast timing where possible.
- **Public infrastructure correlation.** A user who only ever queries the chain through `explorer.coincync.network` from one IP is correlated by the explorer's logs. Use a self-hosted node, federation mirrors, or the `.onion` mirror.
- **Out-of-band metadata leakage.** If you tell someone "I sent you 10 CYNC at 14:32 on Tuesday," your privacy is bounded by what you've voluntarily disclosed, regardless of how good the on-chain crypto is.
- **Chainalysis-style scraping.** Industrial-rate scraping of public explorers builds correlation datasets over time. The defense is rate limiting at the explorer (`deploy/explorer/Caddyfile`) and federation across multiple hosts. See [Federation & DDoS](../operations/federation-and-ddos.md).
- **Ring decoy-selection attacks.** If a wallet's decoy selection algorithm is biased, an attacker can statistically distinguish the real input from the decoys. CoinCync uses an age-weighted decoy selector (`src/crypto/ring_selection.rs`) that matches Monero's current best practice.

## Next reading

- [Consensus & PoW](./consensus.md) — RandomX, difficulty adjustment, finality
- [Transaction format](./transaction-format.md) — wire format, signing hash construction, range proof layout
- [JSON-RPC reference](../api/json-rpc.md) — how to query privacy-relevant chain state
