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

## Benchmark results (2026-10-18) — the decision data

Measured via the `spark-connector` `libspark_verify_cost_benchmark` test (gated
`libspark-ffi`; add `spark-prod-params` for the N=32768 point). `shim_params()`
selects `get_test()` (the shipped default) vs `get_default()` (production) at
compile time. libspark's `Params` is a **private-ctor singleton**, so only these
TWO points are measurable without modifying — and thus un-pinning (firo
v0.14.18.1) — the vendored libspark; the `{256..16384}` intermediates in the plan
above are NOT reachable.

| params | N (n,m) | per-verify | bundle bytes |
|---|---|---|---|
| `get_test` | 16 | **20.1 ms** | 5 825 |
| `get_default` (PROD) | 32768 (8,5) | **3 324 ms** | 7 998 375 |

Debug and `--release` agree within noise (20.9/20.1 ms; 3448/3324 ms), so the
Rust profile / cc opt-level is NOT the driver — this is a real, reproducible cost.

**Cost model (from the two points):** `verify ≈ 18 ms fixed (bpplus range +
chaum) + ~0.1 ms/coin`. The Grootle membership check is an O(N)
multiexponentiation; the ~8 MB embedded-cover-set re-parse in this self-contained
test bundle is only ~100 ms of the 3.3 s (point decompression ×32768), so the
**O(N) multiexp — not the re-parse — dominates** (a real node holds the set in
memory, so re-parse is not the production cost anyway). Extrapolated:

| N (n,m) | est. verify | 10-spend block | IBD outlook |
|---|---|---|---|
| 512 (8,3) | ~70 ms | 0.7 s | fine |
| 4096 (8,4) | ~430 ms | 4.3 s | borderline |
| 32768 (8,5) | 3 324 ms | 33 s | non-viable |

**★ KEY FINDING: N=32768 verify (~3.3 s) is ~100× Firo's reported Spark verify
(tens of ms).** That gap is almost certainly a MISSING OPTIMIZATION — Firo's
production verify uses BATCHED multiexponentiation (`secp256k1_ecmult_multi` /
Pippenger / Straus) and amortizes the O(N) multiexp across the block, whereas the
current shim verifies each spend singly through an unbatched path. **The anon-set
ceiling is set by the multiexp implementation, not by N.**

**Recommendation (2026-10-18):**
1. **Do NOT ratify N=32768, and do NOT flip the shipped default to
   `spark-prod-params`, on this evidence** — 3.3 s/verify is non-viable for block
   validation and catastrophic for IBD (verifying chain history).
2. **Resolve the 100× gap FIRST (the higher-value path).** Confirm/enable
   batched multiexp verify (Firo-style, per block). If it recovers Firo-class
   speed, Firo's AUDITED `n=8, m=5 ⇒ 32768` stays on the table and we keep a
   Firo-class anonymity set — the "match the proven params" outcome. This is a
   verify-path/benchmark investigation, not a consensus change.
3. **If the gap cannot be closed (we accept the current single-verify cost),
   ratify `n=8, m=3 ⇒ 512`** (~70 ms/verify) — a viable cost with a 512-member
   set (far larger than Monero's ring of 16; smaller than Firo). `n=8, m=4 ⇒
   4096` (~430 ms) is the aggressive alternative, with heavier IBD.
4. **Interim:** the gated testnet/beta pool stays at `get_test()`; the
   `spark-prod-params` flip remains audit-gated and user-cleared.

Shipped default unchanged (`get_test()`); the selector + benchmark are additive.
The next decision datum is a clean per-block BATCHED-verify measurement.
