# CIP-Shielded — Anonymity-Set Determinism Contract

Status: **DRAFT / provisional** (not ratified; not activated). Companion to
`cip-shielded-txtype.md` and `cip-shielded-proof.md`.

## Problem

The Groth-Kohlweiss one-out-of-many spend proof proves that a spent coin's
commitment is one of an ordered vector of `N` commitments, where **`N = 2^m`**.
The prover builds the proof against a specific commitment vector; every
validating node must reconstruct the **byte-identical** vector, or the proof
fails to verify (best case) or a malleability seam opens (worst case). So the
question "which commitments are in the anonymity set for this spend?" is a
**consensus rule**, not a wallet choice. This contract fixes that rule.

## Contract: fixed-size position buckets

The note-commitment tree assigns each minted note a dense leaf position
`p = 0, 1, 2, …` (see `storage::shielded::ShieldedStore`, invariant §6: positions
are dense over `0..tree_size`). The anonymity set is a **fixed-size bucket of
`N = 2^m` consecutive leaves**:

- A coin at position `p` belongs to **bucket `b = p / N`**, at **offset
  `p mod N`**.
- Bucket `b` covers positions `[b·N, b·N + N)`.
- A shielded spend proves membership **within its own bucket** — the ordered
  vector is the `N` commitments at those positions.

This is the Zerocoin/Lelantus "coin group" model, chosen because it:

1. is **deterministic** — every node computes the same bucket from `p`;
2. is inherently **power-of-two** — no ad-hoc padding policy for the common case;
3. **ages gracefully** — an old bucket stays fully provable forever (unlike a
   sliding "most-recent-N" window, where a coin becomes unspendable once it ages
   out);
4. **bounds proof size** at `log2(N)` and verifier work at `O(N)` per spend.

### Partially-filled final bucket

The newest bucket is usually not full (`tree_size` is rarely a multiple of `N`).
Positions past the frontier are filled with a **deterministic NUMS filler**
point:

```
pad(b, i) = RistrettoPoint::from_uniform_bytes(SHA3_512(
                "COINCYNC_SPARK_ANON_PAD_v1" ‖ b_le_u64 ‖ i_le_u64 ))
```

The filler is a nothing-up-my-sleeve point with no known opening, so it can never
be the spent coin (an honest prover never targets a pad slot) and it is identical
on every node. A spend into a partially-filled bucket is still a sound
one-out-of-many over `N` elements; the pads simply cannot be the witness.

### What the spend reveals / binds

- The witness carries the spent coin's **bucket index `b`** and **offset**
  (offset stays hidden inside the one-of-many; `b` is revealed so the verifier
  resolves the same window).
- The **anon-set identifier** folded into the spend transcript
  (`shielded_pipeline::spend_challenge`) is
  `root = SHA3_256("…ANON_ROOT…" ‖ b ‖ N ‖ commitments[0..N])` — binding the
  proof to exactly this bucket's contents and index, so a proof for bucket `b`
  cannot be replayed against a different bucket.

## Open ratification questions (before activation)

1. **`N` (i.e. `m = GK_ANON_SET_LOG2`).** Larger `N` = stronger anonymity but
   `O(N)` verify and slower bucket fill on a young chain. Provisional `m = 8`
   (`N = 256`); to be chosen with the privacy WG + measured against testnet
   fill-rate before activation.
2. **Cross-bucket spends / bucket selection when a wallet owns coins in several
   buckets** (each input proves against its own bucket — confirm mempool/relay
   cost is acceptable).
3. **Anchor recency policy** — whether a spend may anchor to any historical
   bucket state or only buckets sealed below the finalized tip (interacts with
   reorg-rewind of the `ShieldedStore`).
4. **Interaction with `spark_set_root`** in the header (currently gated to zero).

## Implementation status

The pure, deterministic transform (`bucket_of`, `bucket_window`, the NUMS pad,
and the bucket anon-set identifier) is implemented and unit-tested in
`consensus::shielded_pipeline`, **non-gated** (pure math, no protocol risk), so
the compound proof has a ratified set shape to build against. It is **not wired
into consensus** — the production `SpendVerifier` is `FailClosedVerifier` and
shielded stays gated off (`SHIELDED_TX_ACTIVATION_HEIGHT = u64::MAX`). `N` and
the ratification questions above are still open.

## Parameter ratification — anonymity-set size N (audit-prep, 2026-09-30)

Status: **ANALYSIS for ratification.** N is a consensus privacy/performance
parameter; this records the tradeoff + a recommendation. The final value is a
user + audit decision, ideally backed by the benchmark below.

**What N is.** The anonymity set per spend. Native GK path: fixed-position bucket
`N = 2^GK_ANON_SET_LOG2 = 256`. libspark (production) path: libspark does NOT
hardcode the set size — Grootle's base `n` and depth `m` are constructor
parameters (`grootle.h`), and the cover set is a monotonically-growing group the
CALLER assembles (`spend_transaction.h`). So `N` (≈ `n^m`) and `(n, m)` are
**CoinCync's to choose** on the libspark path too — not fixed by libspark.

**Tradeoff.**
- Privacy scales with N: a spend is indistinguishable among its N cover members.
  `N = 256` gives only a 256-member anonymity set — weak for a privacy coin.
- Cost: Grootle proof size ≈ O(m·(n−1)) group elements (≈ O(log N) at fixed n);
  verification ≈ O(N) multiexponentiation per spend (batchable across spends).
  Larger N ⇒ linearly more per-spend verify work.

**Reference.** Firo Spark mainnet runs a large set (`n = 8, m = 5 ⇒ 32768`). A
privacy coin generally wants ≥ 2^12 for the set to be meaningful.

**Recommendation.** `256` is too small for the production (libspark) path. Target
Firo-class — ideally ~2^15 (`n=8, m=5`), or a benchmarked point in 2^12..2^15 that
keeps worst-case per-block shielded verify within the block budget. **Ratify only
after the benchmark.**

**Benchmark needed before ratification (the decision data):**
- libspark `verify_spend` wall-time + proof bytes at `N ∈ {256, 1024, 4096,
  16384, 32768}`, single and batched, on target hardware; pick the largest N whose
  worst-case per-block shielded-verify fits the block time budget.
- Confirm the bucket / cover-set model (above) composes a monotonic group of the
  chosen N that every node derives identically (determinism contract).
