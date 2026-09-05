# WP-017 · Private Light-Wallet Sync
### The output-digest protocol: download a range, never reveal an interest

**Status:** Shipped · **Layer:** Wallet / Network · **Series:** [CoinCync Whitepapers](README.md)

---

## 1. Motivation

Light wallets are where privacy chains usually leak. The full-node privacy model
is excellent and unaffordable: most users will not download and validate the whole
chain on a phone. So they use a server — and the server learns what they own.

This is not a hypothetical weakness of some deployments; it is the default outcome
of every obvious design. Ask a server "do you have outputs for my address" and it
knows your address. Ask it "send me block 41,205" after a filter match and it
knows that block matters to you.

CoinCync's light protocol is built around removing the second request — the one
that turns local matching into a disclosed interest.

---

## 2. Threat addressed

| Attack | Assumption it needs | What we removed |
|---|---|---|
| **Address disclosure to the server** | The wallet tells the server what to look for | The wallet sends only a **height range** |
| **Interest disclosure by follow-up fetch** — the wallet requests exactly the blocks that matched | Matching locally is enough for privacy | Digests for the *whole* range arrive in one response; no match-triggered second request |
| **Bandwidth cost forcing a worse protocol** | Privacy-preserving sync is unaffordably large | Output-only digests, ~138 B/output — 50–100× smaller than full blocks |
| **Scan-cost forcing server-side matching** | Client-side ECDH over every output is too slow | View tags reject ~255/256 outputs before any ECDH; parallel scanning via rayon |
| **Server-forged checkpoints** — a hostile server hands the wallet a checkpoint that skips real history | A checkpoint is trustworthy because the server sent it | Checkpoints must authenticate against the binary's hardcoded set, else full scan |
| **Miner rewards invisible to the wallet** | Every output is confidential | Explicit coinbase detection in the digest path (§3.5) |

---

## 3. Design

### 3.1 Range in, digests out

The wallet asks for output digests across a height range. The server returns
digests for **every output** in that range. The wallet scans them locally.

The server therefore learns the range and nothing else — not the wallet's
addresses, not its view key, not which outputs matched, not even *whether* any
did. There is no second request keyed on a match, because the wallet already has
everything it needs.

This is the property the design is organised around, and it is why the protocol
sends more data than it strictly needs to. **The extra bandwidth buys the absence
of a follow-up request.**

Per-request cap: **100 blocks**, a byte-budget limit (digests are substantially
larger than compact filters).

Wire surface: `GetOutputDigests` (62) / `OutputDigests` (63) at the network layer,
plus `get_output_digests` over JSON-RPC.

### 3.2 The comparison to BIP-157/158

The module states the protocol is **strictly stronger than BIP-157**, where "the
wallet's address set leaks to whoever serves the filters." The precise mechanism
is worth spelling out, since compact block filters are also designed for privacy:

Under BIP-157/158 the wallet downloads filters and matches *locally*, which is
good. But on a match it must then **fetch the matching block** — and that request
tells the server exactly which blocks are relevant to this wallet. Over a sync,
the pattern of fetched blocks is a strong fingerprint of the wallet's activity.

The digest protocol has no such step. Everything in the range is already local.
The full comparison, including the cases where the advantage narrows, is in
`docs/security/LIGHTSYNC_AUDIT.md` — this paper cites the claim rather than
re-deriving it.

### 3.3 Compact digests

A digest is an output-only summary: roughly **138 bytes per output** against a
full block, yielding a **50–100× bandwidth reduction**. It carries what a scanner
needs — the one-time key, commitment, view tag, encrypted amount, and (see §3.5)
whether the output is coinbase — and nothing else.

### 3.4 View tags and parallel scanning

Each output carries a one-byte **view tag**, letting the wallet reject about
255/256 of outputs before doing any elliptic-curve work. Remaining candidates are
scanned in parallel via rayon.

The view tag is a **deliberate privacy trade**, not a free win: it narrows the
candidate set for an observer by the same factor it narrows it for the owner. We
take the trade, as Monero does, and record it as a trade (WP-009 §3.7).

### 3.5 Coinbase outputs — the bug this protocol taught us

Coinbase outputs are deliberately **not** confidential: plaintext amount,
zero-blinding commitment, public-data view tag. The confidential scan path — view
tag gate, then ECDH, then amount decryption, then commitment recomputation —
fails on all three counts.

The full wallet scanner had a coinbase case. **The light scanner did not.**

The symptom: a solo miner using light sync saw a **zero balance**. Their block
rewards existed on chain, were unambiguously theirs, and were invisible to their
wallet — every one silently discarded by a scan path that had no case for them.

The fix flags coinbase outputs in the block digest (`is_coinbase` on
`OutputDigest`, set when the digest is built from a block) and gives the light
scanner its own detection path: direct/ECDH ownership check, plaintext amount,
zero blinding. Hooks were added to **both** light-scan paths, not just the one
where the bug was observed.

*Composition lesson (WP-009 §3.1):* **transparency inside a privacy chain is
itself a special case, and it must be special-cased everywhere — including in the
reader you wrote last.** The full scanner was written first and got the case; the
light scanner inherited the assumption that all outputs are confidential.

A detail from fixing it, worth recording: two existing tests used `TxType::Coinbase`
fixtures carrying *encrypted* amounts — a combination that cannot occur on chain.
They passed, and they were testing a situation that does not exist. They were
corrected to `TxType::Transfer`, and a genuine coinbase test was added.
**A test built on an impossible fixture provides no coverage while looking like
it does.**

### 3.6 Checkpoint authentication

Sync checkpoints let a wallet fast-skip early history. A checkpoint supplied by
the *server* is untrusted input: accepting one blindly lets a hostile server hand
the wallet a fabricated starting point.

The rule (audit **Gap 2**): a consumer must call `SyncCheckpoint::authenticate`
and fast-skip **only** on `CheckpointAuth::Authenticated`, which validates the
server-provided checkpoint against the binary's **hardcoded** `CONSENSUS_CHECKPOINTS`
set. A height not in that set is `Unverifiable` and **must fall back to a full
scan**.

The three-valued result is deliberate, for the same reason as WP-013 §3.5:
"unverifiable" and "invalid" are different facts. The wallet's response to
unverifiable is to do more work, not to reject.

Full miner-signed rolling checkpoints (WP-008) are the longer-term answer; until
then the hardcoded set bounds what can be skipped.

---

## 4. Security analysis

**What holds.** The server learns a height range only; no request is keyed on a
match; server-supplied checkpoints cannot shortcut history unless they match a
hardcoded value; coinbase outputs are detected in both scanners.

**What this does not protect against.**

- **The range itself is metadata.** Repeated requests reveal when a wallet syncs
  and roughly how far back it cares about. A wallet that starts at its birth
  height leaks that birth height.
- **Network-level identification.** The server sees an IP and a connection
  pattern. Traffic shaping (WP-012) and Tor transport address that layer; the
  digest protocol does not.
- **A lying server.** Authentication covers checkpoints. A server can still
  **omit** outputs from a range, and the wallet has no proof of completeness — it
  would see a missing payment, not an error. Detecting omission requires either
  multiple servers or header-chain-anchored proofs; neither is implemented.
- **Bandwidth is still substantial.** 50–100× better than full blocks is not
  small in absolute terms on a metered connection, and the 100-block request cap
  means long syncs are many round trips.
- **Light wallets do not validate consensus.** They trust that the chain they are
  handed digests from is the real one, bounded by checkpoints. This is the
  standard SPV trade.

---

## 5. Implementation

| Component | Location |
|---|---|
| `BlockDigest`, `OutputDigest`, `is_coinbase`, scan paths | `src/wallet/lightsync.rs` |
| `detect_coinbase_digest` | `src/wallet/lightsync.rs` |
| `SyncCheckpoint::authenticate`, `CheckpointAuth` | `src/wallet/lightsync.rs` |
| P2P handlers (`GetOutputDigests` / `OutputDigests`) | `src/network/node.rs` |
| JSON-RPC `get_output_digests`, per-request range cap | `src/rpc/lightwallet.rs` |
| Full-scanner coinbase case (the one that was right) | `src/wallet/scanner.rs` |

**Audit trail.** `docs/security/LIGHTSYNC_AUDIT.md` — the BIP-157 comparison and
the numbered audit gaps, including Gap 2 (§3.6). Failure record: H-4 coinbase
detection; WP-100 §5.3.

---

## 6. Known limits

- No completeness proof — a server can omit outputs undetectably (§4).
- Height ranges are themselves metadata.
- Checkpoint fast-skip is limited to hardcoded heights until WP-008 lands.
- View tags are an accepted privacy cost.
- No measurement of real-world sync time or bandwidth on a large chain.

---

## 7. References

- BIP-157 / BIP-158 (compact block filters) — the design compared against in
  §3.2, and its match-then-fetch leak.
- Monero view tags — the scanning/privacy trade adopted in §3.4.
- Internal: [WP-009 §3.1, §3.7](WP-009-privacy-feature-composition.md),
  [WP-008 Rolling checkpoints](WP-008-rolling-checkpoints.md),
  [WP-013 §3.5](WP-013-selective-disclosure.md),
  [WP-100](WP-100-solved-issues-ledger.md),
  `docs/security/LIGHTSYNC_AUDIT.md`.
