# CoinCync — Master Test Plan (path to 100% behavioral coverage)

**Date:** 2026-09-11
**Scope:** every subsystem in the tree (`~187K LOC`), enumerated behavior-by-behavior.
**Method:** eight read-only subsystem reviewers each read the real source under
`src/`, scanned every `#[cfg(test)]` block and the `tests/` tree, and classified
each behavior as **EXISTS** (a concrete test function was found and is cited) or
**MISSING**. No test names were invented; every EXISTS entry names a real test.

This is the companion to the bug hunt (`bug-hunt-2026-09-10.md`) and the
coverage-gap analysis (`test-coverage-gaps-2026-09-11.md`). Where the bug hunt
asked *"what is broken?"*, this asks *"what would a test have to check for us to
know it isn't?"* — and answers it for the whole codebase.

> **Why this exists.** 1206 green tests caught **0 of 38** bugs in the hunt. Green
> ≠ covered. The gap is not test *count*, it's the untested *branches*: the
> adversarial rejects, the reorg-with-real-tx paths, the liveness invariants, the
> crash-consistency of the atomic commits. This plan enumerates them all.

---

## Grand total

| Subsystem | Behaviors | Exist | Missing | Coverage | Detail |
|---|---:|---:|---:|---:|---|
| Crypto (CLSAG, BP+, stealth, disclosure…) | 215 | 151 | 64 | **70%** | [crypto.md](test-plan/crypto.md) |
| Chain + Storage + DB | 196 | 84 | 112 | 43% | [chain-storage.md](test-plan/chain-storage.md) |
| Mining + Primitives + Snapshot | 213 | 113 | 100 | 53% | [mining.md](test-plan/mining.md) |
| Wallet | 277 | 113 | 164 | 41% | [wallet.md](test-plan/wallet.md) |
| RPC (JSON-RPC, REST, WS, TLS) | 223 | 81 | 142 | 36% | [rpc.md](test-plan/rpc.md) |
| Consensus (validation, PoW, emission) | 168 | 63 | 105 | 38% | [consensus.md](test-plan/consensus.md) |
| Mempool + Transaction | 148 | 42 | 106 | 28% | [mempool.md](test-plan/mempool.md) |
| Network / P2P | 168 | 54† | 92 | 32% | [network.md](test-plan/network.md) |
| **TOTAL** | **1608** | **701** | **885** | **~44%** | |

† Network also has **22 PARTIAL** behaviors (some coverage, a gap remains) tracked
separately in its detail file; folded into "not complete" the true grand total of
incomplete behaviors is **907**.

```
Covered   ████████████████████░░░░░░░░░░░░░░░░░░░░░░░░░░  44%  (701 / 1608)
```

Read that number honestly: the cryptographic core is well tested (70%). The
**stateful, concurrent, adversarial** layers — mempool (28%), network (32%), RPC
(36%), consensus (38%), wallet (41%), chain/DB (43%) — are where the bugs lived
and where coverage is thinnest. Reaching 100% is ~900 tests of work; the ranking
below is the order that buys the most safety per test.

---

## Cross-cutting priority ranking

Pulled from each subsystem's own "highest-value gaps" section and ordered by blast
radius. **P0 = a missing test for a known consensus/funds/liveness risk.**

### P0 — consensus & funds correctness (write these first)

1. **Accepted reorg re-applying REAL non-coinbase txs** (chain-storage). The entire
   *successful* reorg-with-transactions path is untested — the one real-tx reorg
   test only covers *rejection*. Balances, key-image un-marking, output-index, and
   orphaned-tx mempool return on the winning branch are all unverified. *This is the
   single most important missing test in the tree.*
2. **PoW / anchor malleability** (consensus §1). Reuse a valid PoW with a mutated
   bound header field must be rejected via anchor/binding mismatch — no direct test.
   (The live C2 validation surfaced exactly this binding at work against the testnet;
   it needs a unit test pinning it.)
3. **Balance-equation collapse via identity pseudo-output** (consensus + crypto +
   batch_verify, "FIX #44"/"R-29"). Identity pseudo-output / commitment must be
   rejected in `verify_balance_proof`, `verify_ring_signature`, and
   `batch_verify::verify_single` — the reject branches exist, no test drives them.
4. **Key-image ↔ signature binding** (consensus "C-2"). `input.key_image !=
   signature.key_image` must be rejected *before* the verify cache (supply-inflation
   binding). Untested.
5. **Ring-size determinism** (consensus, `total_outputs_ever - reorg_disconnects_total`,
   commit 1d27d3c8). The v1.0.12 release-blocker fork-risk fix has no test — two
   nodes reaching the same tip via different reorg histories must compute the same
   bootstrap-window ring size.
6. **Crash-consistency of the atomic commits** (chain-storage). Zero tests kill the
   process mid-operation. `commit_block_atomic` and `apply_reorg_atomic` have no
   direct atomicity-under-crash test — only clean-reopen proxies. Kill mid-add /
   mid-reorg / mid-rollback → restart must show all-or-nothing, never a hybrid tip.
7. **Send↔receive derivation symmetry** (wallet). No round-trip builds an output via
   `send/assembly.rs` and confirms `scanner.rs` re-detects+decrypts it to the exact
   amount — for all five kinds (main, subaddress, change, coinbase, coinbase-to-sub).
8. **Lightsync loses `lock_height`** (wallet). `OutputDigest` carries no lock_height,
   so a locked/vesting output detected on light sync counts as immediately spendable.
   No guard test — a funds-correctness hole.

### P1 — liveness & availability (the class the whole suite omits)

9. **"A peer that stops reading must not freeze others"** (network). The C2 invariant
   is now unit-tested at `send_to_peer` and **live-validated** (PR #110), but there is
   still no end-to-end test through `handle_connection` + `spawn_message_processor`.
10. **Handler-level P2P harness does not exist** (network). Every `dispatch/*` handler
    (verack-without-version, version/headers/verack replay, per-peer NotFound scoping,
    accept-then-relay tx gate, Veil GetAddr plaintext refusal) is untested. Cheap
    async-fn tests once a driver exists.
11. **Sync anti-wedge recomputes** (network). `refresh_best_known`,
    `recompute_best_difficulty`, `retain_connected_peers`, single-use/cross-peer nonce
    — each encodes a documented production wedge, none has a direct test.
12. **Reservation lifecycle on submit** (wallet `spend/submission.rs`). reserved-on-submit,
    released-on-Rejected, retained-on-Unknown/Accepted, survives-crash — entirely untested.

### P2 — differential & bounds

13. **True differential** (chain-storage): two nodes fed the same blocks in *different
    orders*, and reorg-built vs linearly-built to the same tip, compared on UTXO-set +
    phase-2 roots (not just tip/height). Existing "identical state" tests use one order.
14. **Per-message `validate()` caps** (network + mempool): only `InvMessage` dup is
    tested; Headers/Blocks/Addr/Txs/GetBlocks/Reject/NotFound/Version count+length caps
    are unverified at the message layer.
15. **RPC audit-span + pre-decode caps** (rpc): the six chain-audit methods'
    `MAX_RPC_AUDIT_BLOCK_SPAN=128` rejects, `verify_keyimage_uniqueness` height cap, and
    per-method hex-length caps are all untested.
16. **Template never exceeds size/weight/count & excludes conflicts** (mempool):
    `build_template_json` has zero integration tests — only fee-floor drift units.

---

## Structural blockers to fix before mass-writing tests

Two findings make whole test classes impossible to write cheaply today; fix these
first or the coverage work will fight the harness:

- **`mempool.rs`'s primary `mod tests` is dead** (`#[cfg(any())]`). Nearly all
  mempool coverage runs through the `add_skip_crypto` escape hatch, so the real
  `add()` crypto-rejection branches (range proof / balance / ring sig) are untested
  at the mempool layer. Re-enable the module or add a real-crypto add() path.
- **No P2P handler test-driver exists.** A driver that calls `process_message` /
  the `dispatch/*` handlers directly with a real `DashMap` / `ChainSync` /
  `PeerScorer` would unlock ~60 network tests at once (items 9–11 above).

Also latent (worth a targeted regression each): the reorg disconnect loop
(`chain.rs`) is **cache-only** with no DB fallback (unlike `rollback_to_height`) —
a reorg whose fork-point sits near the ~200-block cache edge could silently skip
disconnects; `db/blocks.rs::remove_heights_above` has an R-39 mutate-during-iteration
history with no multi-key test; `is_spent`'s DB-error **fail-closed → true** branch
is untested.

---

## How to use this plan

1. Work **top-down by priority**, not by file. A single P0 (reorg-with-real-tx) is
   worth more than fifty primitive round-trips.
2. Each subsystem file is a literal checklist: `[x]` = exists (test named), `[ ]` =
   write it. Category tags (HAPPY / EDGE / ERROR / ADVERSARIAL / PROPERTY / LIVENESS /
   DIFFERENTIAL / CRASH-CONSISTENCY) tell you the shape of the test to write.
3. When you add a test, flip its box in the detail file and cite the new fn — keep
   this plan the living source of truth for coverage.
4. **100% is the target**, and it's ~900 tests. But the first ~40 (all of P0/P1) close
   every *known* consensus, funds, and liveness risk in the tree. Do those, and the
   codebase is audit-ready even before the long tail of P2 bounds tests is finished.

## Provenance

Read-only review of `C:\Users\unkno\dev\CoinCync-wt-bughunt` (current main + the C1
and C2 fix branches). No source files were modified by the reviewers. Test counts
treat one checklist line = one behavior; a line marked EXISTS may be satisfied by an
`#[ignore]`d test (noted inline in the detail files, e.g. the RandomX-gated
block_builder/stratum e2e happy paths).
