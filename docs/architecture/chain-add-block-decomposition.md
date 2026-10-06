# Plan: decomposing `Blockchain::add_block` (issue #108)

## Status
The module-level split of #108 is **done** (PR #112): read-only queries, fork
calculations, DB recovery, and chain events now live in `src/chain/{queries,
fork_calc,recovery,events}.rs`. `chain.rs` is ~4.6k lines (from 5.2k).

What remains is the hard part the issue defers to last: **`add_block` is still a
single ~1,900-line function** (chain.rs, `pub fn add_block` → `add_block_async`).
This document plans its decomposition into small, reviewable, strictly
behavior-preserving slices.

## Non-negotiable invariants (every slice must preserve)
1. **`apply_lock` lifetime.** `add_block` holds `apply_lock` across the whole
   read→decide→mutate→persist sequence. A helper extraction must be called
   *synchronously within* that held lock, in the same position — it must NOT
   take `apply_lock` itself, must NOT return-then-reacquire, and must NOT create
   a new point where another writer can interleave.
2. **`begin_state_update` guard** scope and ordering unchanged.
3. **Reorg fork-choice**: cumulative-work comparison, the three-tier H-16 reorg
   defense, `evaluate_reorg_acceptability`, and the `fork_point < finality_floor`
   reject (pure function of tip height) — semantics and ordering unchanged.
4. **CIP-009.D / CIP-011 finality gates** (soft-final tip, rolling finality)
   unchanged; a reorg must still beat *both* the depth and the finality tests.
5. **Phase-2 privacy-store checkpoints/rewinds** taken/rolled back at the exact
   same sites with the same consistency + failure semantics.
6. **Rollback / DB-corruption paths** (SEV-A `checked_sub`, sync-to-disk Phase D)
   unchanged; a failed application must leave a consistent state.
7. **Observable results**: `BlockStatus` values and ordering identical; reopening
   the DB restores the same chain.
8. **Critical-file verification** for any hash-locked file touched (note:
   `chain.rs` is NOT in `critical_files.lock`; `consensus/*` it calls into are).

## Slices (each its own PR, in order)
1. **Pre-checks classifier — DONE (this PR).** Already-known (cache/DB) + orphan
   + parent resolution → `chain/apply.rs::classify_incoming` returning
   `AlreadyKnown | Orphan | Proceed{parent}`. Pure reads + orphan event; no lock
   change. Oracle: existing `add_block_duplicate_*` tests + full suite.
2. **Height + checkpoint gate.** Extract the expected-height check and the
   hardcoded-checkpoint match into `apply.rs` (`&self`, pure). Returns
   `Option<BlockStatus::Invalid>` or the computed `is_main_chain`.
3. **Context-free validation call site.** Wrap the `validate_block_ctx`
   invocation (+ the C-1 fork-vs-active-UTXO `contextual` decision) in a helper
   that takes the already-read `inner` snapshot; no lock change (helper borrows
   the guard the caller holds).
4. **Linear tip-extend application.** Extract the `is_main_chain` extend path
   (UTXO apply, persist, Phase-2 checkpoint site 1, event) into `apply.rs`,
   taking the `inner.write()` guard from the caller so the write scope is
   verbatim.
5. **Reorg path.** The largest slice — extract the heavier-fork branch (fork walk,
   rewind, re-validate against fork-point UTXO, reorg-acceptability + finality
   gates, Phase-2 rewind/checkpoint) into `apply.rs`, preserving the
   lock-released fork walk exactly. Add focused reorg/rollback tests before/with
   this slice.
6. **Persist + finality feed.** Extract the CIP-011 rolling-finality feed and the
   Phase-D sync-to-disk tail.

## Method
- One slice per PR; behavior fixes stay separate from moves.
- Each slice: run chain/reorg/persistence/recovery tests + full lib suite green
  before commit; add focused coverage where a slice exposes an untested boundary
  (esp. slice 5's failed-application-leaves-consistent-state).
- Prefer moving whole `impl Blockchain` methods into `apply.rs` (child module
  sees private fields) over threading new public accessors — keeps the interface
  small, as the issue requires.

## Explicitly out of scope
- No behavior changes, no lock-scope changes, no new interleave points.
- `add_block_async` wrapper stays; only its shared body is decomposed.
