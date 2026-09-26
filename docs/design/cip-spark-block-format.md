# CIP — Spark block format: carrying libspark coins & tags in blocks

**Status:** design (draft; NOT built). Unblocks the FEED for
[[cip-triptych-ki-binding]]'s `SparkPoolStore`.
**Depends on:** the libspark FFI connector (`build_spend_over_set`,
`verify_solvency`, `serial_context`), the `SparkPoolStore` (built, gated), and
its `Phase2Store` reorg wiring (built).
**Goal:** define how libspark Spark **coins** (mints) and **spend bundles**
(with their VRF **tags**) ride inside a `TxType::Shielded` transaction, so the
chain's apply path can FEED `SparkPoolStore` — `add_coin` on each minted coin,
`mark_tag_spent` on each spend's revealed tag — and so shielded solvency /
payments verify against the live pool. Everything stays gated
(`sketch-gk-proof` + `libspark-ffi`) and activation-locked
(`SHIELDED_TX_ACTIVATION_HEIGHT = u64::MAX`) until externally audited.

## Why a new payload shape
The existing [`ShieldedPayload`](../../src/consensus/shielded.rs) (borsh in
`tx.extra`) is the CoinCync-native sketch: 32-byte `note_commitment` /
`nullifier`, opaque `spend_proof`, applied to the **Halo2 `ShieldedStore`**. The
audited libspark engine has different shapes — variable-length serialized
`Coin`s (`CoinBytes`, carrying `S, K, C`), a `SpendTransaction` bundle
(Grootle + Chaum + BPPlus + balance), and **34-byte** VRF linking tags
`T = (U−D)·s⁻¹`. Per the one-pool strategy ([[coincync-strategy-narrow-shielded]])
libspark is the chosen engine, so the block must carry ITS bytes, not the
sketch's. This CIP defines a **versioned `SparkPayload`** (payload `version = 2`)
that supersedes the v1 sketch for the shielded path.

## The payload (`SparkPayload`, tx.extra, borsh)
```
SparkPayload {
    version: u8,                 // = 2 (v1 = the native sketch; readers switch on it)
    outputs: Vec<CoinBytes>,     // libspark-serialized mint coins created by this tx
    spend:   Option<SpendBundle>,// present iff this tx spends shielded value
    value_balance: i64,          // transparent↔shielded bridge (Sapling-style)
}
SpendBundle {
    cover_set_id: u64,           // the pool anchor the Grootle membership is over
    anchor_height: u64,          // pool snapshot height (cover set = pool coins ≤ this)
    bundle: SpendBytes,          // the libspark verify bundle (S1/C1/T + proofs)
}
```
- **Mints** (`outputs`): each `CoinBytes` is exactly what `create_output`
  produces. The tx's transparent side funds them; `value_balance` moves value
  across the veil.
- **Spends** (`spend`): `bundle` is exactly what `build_spend_over_set` emits and
  `verify_solvency` / `verify_spend` consumes. The revealed tags come back from
  verification (34 bytes each).

## Serial context — breaking the circularity (the key design point)
A coin's serial commitment `S` binds a **serial context** at mint time, and the
spender must recompute the identical context later. The obvious choice —
`context = serial_context(tx_hash ‖ vout)` — is **circular**: the tx hash covers
`outputs`, which depend on the coins, which depend on the context. Break it by
deriving the context from data fixed **before** the outputs exist:

```
outpoint(vout)   = H( sorted(transparent input outpoints of this tx) ‖ vout )
serial_context   = spark_connector serial_context(outpoint(vout))
```

The transparent `TxInput`s ([types.rs](../../src/transaction/types.rs)) are
fixed before the shielded outputs are built and are recomputable by any verifier
from the tx, so both mint and spend derive the same context with no dependence
on the tx hash. (A pure-shielded tx with no transparent inputs uses a
domain-separated per-tx nonce carried in the payload instead; see Open
Questions.) This mirrors Firo's use of a deterministic per-tx serial context.

## Cover-set anchoring
The Grootle membership proves the spent coin is one of a fixed set `{C_i}`. The
verifier must resolve the **same** set. `cover_set_id` + `anchor_height` name a
pool snapshot: the cover set is `SparkPoolStore`'s coins with `height ≤
anchor_height` for that group (libspark treats cover sets as monotonic — a
spend's set is a subset of the largest set for its id). `anchor_height` must be
final enough to be reorg-stable (e.g. ≥ `max_reorg_depth` behind tip), so a
reorg cannot change the set a proof was built against.

## Validation (pre-apply, store-aware) — the gated path
Runs where [`verify_block_shielded_spends`](../../src/chain.rs) runs (gated
`sketch-gk-proof`), but for v2 payloads:
1. Decode `SparkPayload`; reject `version != 2` on the libspark path.
2. Resolve the cover set from `SparkPoolStore` at `(cover_set_id, anchor_height)`.
3. For a spend: `backend.verify_solvency(cover_set, bundle, fee, value_balance,
   store.spent_tags())` — this verifies Grootle+Chaum+range+balance AND enforces
   every revealed `T ∉ spent-set`. Reject on any failure (fail-closed).
4. Intra-block double-spend guard: no tag repeats within the block (mirrors
   `check_block_shielded_double_spends`).
5. Balance: `Σ mint values − Σ spend values = value_balance − fee`, enforced by
   the bundle's own balance proof + the transparent side.

The double-spend / unspent check MUST be in validation (contextual, against the
store) so an invalid block is rejected pre-apply — the apply step then never
faults (matching the native path's PRE-ACTIVATION TODO note).

## Apply (feed `SparkPoolStore`) — the actual wiring this unblocks
In the chain apply path, after validation, in lock-step with the other Phase-2
stores (checkpoint already taken):
```
for (vout, coin) in payload.outputs.enumerate():
    op  = outpoint(vout);  ctx = serial_context(op)
    spark_pool_store.add_coin(op, coin, ctx, height)      // FEED: mints
if let Some(sp) = payload.spend:
    for tag in verify_result.tags:
        spark_pool_store.mark_tag_spent(tag, height)      // FEED: spends
```
`add_coin`/`mark_tag_spent` are built and persisted; the checkpoint/rewind story
is already handled by the `Phase2Store` wiring (a reorg rolls these back in
lock-step). This is the only missing link between the tested store and live
chain state.

## Consensus gating & safety
- New payload `version = 2` behind `sketch-gk-proof` + `libspark-ffi`;
  `TxType::Shielded` stays fail-closed and `SHIELDED_TX_ACTIVATION_HEIGHT =
  u64::MAX` until audited. A default node rejects `TxType::Shielded` exactly as
  today.
- Adding/altering the shielded validation branch touches
  `consensus/validation.rs`, which is **hash-locked** (`critical_files.lock`):
  any edit there is an intentional consensus change requiring
  `COINCYNC_REGEN_LOCK=1` regen + review. This CIP deliberately keeps that edit
  small and last (a version switch + a call into the gated verifier).

## Consolidation (one pool)
`SparkPayload` v2 is the libspark pool's format; the native v1 `ShieldedPayload`
+ Halo2 `ShieldedStore` become legacy. Retiring them (and the native
`SparkStore` sketch) is a follow-up migration, not part of this CIP — but v2 is
designed so the two never mix in one tx (a tx is v1 xor v2).

## Open questions (resolve before coding)
1. **Pure-shielded serial context.** A tx with no transparent inputs has no
   input outpoints to seed the context. Options: a payload-carried per-tx nonce
   (must be unique + bound into the tx hash), or seeding from the spent coins'
   tags. Pick one; both must stay non-circular and unique per coin.
2. **Cover-set determinism across nodes.** `SparkPoolStore` ordering must be
   canonical (coin_id/append order is, today) so every node resolves an
   identical `{C_i}` for `(cover_set_id, anchor_height)`. Pin the ordering rule.
3. **`value_balance` sign & fee interaction** — reuse the transparent balance
   equation exactly; specify overflow guards (libspark already guards fee+vout).
4. **Weight/size** — a Grootle proof over `n^m` is O(log) but the cover-set
   reference + bundle add bytes; set a per-tx shielded weight bound.
5. **Coin uniqueness** — reject a mint whose derived outpoint already exists in
   the pool (the store's `add_coin` already returns `None` on a duplicate).

## Build order (after design sign-off + audit lined up)
1. `SparkPayload` v2 type + borsh + decode gate (mirror `ShieldedPayload`).
2. Cover-set resolver on `SparkPoolStore` (`cover_set_at(id, height)`).
3. Gated v2 validation branch (verify_solvency + intra-block guard + balance).
4. Gated apply feed (`add_coin` / `mark_tag_spent`) in `apply_shielded_txs`.
5. Regtest end-to-end: mint → pool → spend → verify → tag spent → reorg rolls back.
6. 24h shielded soak. 7. External audit. 8. Activation height set.
