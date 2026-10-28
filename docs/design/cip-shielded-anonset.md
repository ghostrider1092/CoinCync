# CIP-Shielded — Anonymity-Set Determinism Contract

Status: **SUPERSEDED for the shipped engine** (and still not activated). This CIP
specifies the anon-set contract for the **v1 native-GK** shielded path
(`consensus::shielded_pipeline` + `storage::ShieldedStore`). The engine CoinCync
actually ships and submits for audit is the **v2 libspark** path
(`storage::SparkPoolStore` + `consensus::spark_payload::verify_spark_payload`);
its anon-set contract is summarized under "Shipped engine (v2 libspark)" below,
and the v1 model in the rest of this document is retained for history/reference
only — it is **not the audited path**. Companion to `cip-shielded-txtype.md`,
`cip-shielded-proof.md`, and `cip-shielded-libspark-ffi.md`.

> ## Shipped engine (v2 libspark) — the audited anon-set
>
> The audited shielded engine verifies each spend against a **node-authoritative
> cover set** resolved from `SparkPoolStore::cover_set_at(cover_set_id,
> anchor_height)`: the pool is bucketed into fixed groups of at most
> **`N = n^m = 8^3 = 512`** coins (libspark `get_coincync` Grootle params —
> CoinCync's RATIFIED production anon-set; see "Ratified parameters" below),
> where group `g` is the coins at insertion positions `[g·N, (g+1)·N)` with
> `height ≤ anchor_height`, in canonical order. The Groth-Kohlweiss one-of-many
> proof is verified against *that* set, and the cover-set representation is
> **recomputed deterministically on the node** (`cc_cover_set_rep`, a
> domain-separated hash over the ordered coins) so a spender cannot prove
> membership in a set they made up (#258). A spend whose resolved group is
> **empty** is rejected before the backend runs (#308), and the spend's public
> output `vout` is bound to the transaction's `value_balance` (#258). This path is
> gated `sketch-gk-proof` + `libspark-ffi` and stays **activation-gated off**
> (`u64::MAX`) on testnet/mainnet until the external libspark audit passes. The
> same `N`-group bucketing idea as the v1 model below, but the set capacity,
> representation, and proof system are libspark's, not the native pipeline's.

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

1. **`N` (i.e. `m = GK_ANON_SET_LOG2`).** [v1 native only] Larger `N` = stronger
   anonymity but `O(N)` verify and slower bucket fill on a young chain.
   Provisional `m = 8` (`N = 256`). **RATIFIED for the shipped v2 engine:**
   `N = 512` (libspark `get_coincync`, Grootle n=8/m=3 — a CoinCync delta to the
   vendored tree; see `crates/spark-connector/vendor/NOTICE.md`). See "Ratified
   parameters" below. The provisional v1 figure above applies only to the
   unshipped native path.
2. **Cross-bucket spends / bucket selection when a wallet owns coins in several
   buckets** (each input proves against its own bucket — confirm mempool/relay
   cost is acceptable).
3. **Anchor recency policy** — whether a spend may anchor to any historical
   bucket state or only buckets sealed below the finalized tip (interacts with
   reorg-rewind of the `ShieldedStore`).
4. **Interaction with `spark_set_root`** in the header (currently gated to zero).

## Ratified parameters

The shipped v2 engine is ratified at **`N = 512`** (`get_coincync`, Grootle
n=8/m=3), chosen from a direct libspark verify-cost benchmark on CoinCync's
secp256k1 build (not an extrapolation):

| Params                         | `N`     | per-block base multiexp | IBD verdict          |
| ------------------------------ | ------- | ----------------------- | -------------------- |
| `get_test` (n=2/m=4)           | 16      | negligible              | anon set = CLSAG ring; breaks once pool > N |
| **`get_coincync` (n=8/m=3)**   | **512** | **~60 ms** (meas. 63.8) | **viable — RATIFIED** |
| Firo `get_default` (n=8/m=5)   | 32768   | ~2.7 s                  | not viable here      |

Why not 32768 (Firo's audited param): at N=32768 a single-block verify is ~3.3 s
(release ≈ debug), ~100× Firo's reported Spark verify. That gap is a *missing
batched multiexp*, not an `N` problem — but even a fully batched 32768 cannot
remove the intrinsic ~2.7 s/block **base** multiexp, so a chain where shielded
spends are the norm would not stay in sync. 512 keeps the base ~60 ms; a
10-spend block with batched verify is ~160 ms (a batched block verify amortizes
the per-spend multiexp within a block, landed separately). m≥3 is required by
the `Params` ctor, so 512 is the smallest valid n=8 set. The choice is
consensus-relevant and network-wide: a coin built under one param set is not
verifiable under another, so all nodes MUST agree. Ratification is backed by a
24 h in-block consensus soak at N=512 (`scripts/soak-24h-shielded.sh`).

## Implementation status

The pure, deterministic transform (`bucket_of`, `bucket_window`, the NUMS pad,
and the bucket anon-set identifier) is implemented and unit-tested in
`consensus::shielded_pipeline`, **non-gated** (pure math, no protocol risk), so
the compound proof has a ratified set shape to build against. It is **not wired
into consensus** — the production `SpendVerifier` is `FailClosedVerifier` and
shielded stays gated off (`SHIELDED_TX_ACTIVATION_HEIGHT = u64::MAX`). `N` and
the ratification questions above are still open.
