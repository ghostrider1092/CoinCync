# CoinCync Chain State Machine + Storage + DB — Exhaustive Behavioral Test Plan

Legend — categories: HAPPY / EDGE / ERROR / ADVERSARIAL / PROPERTY / DIFFERENTIAL / CRASH-CONSISTENCY (CC). EXISTS cites a real test found via `#[cfg(test)]` scan or `tests/` grep; MISSING otherwise. "chain-level" = drives `Blockchain::add_block`/`rollback_to_height` with a real `Database`, not an in-memory `HashSet`/`Vec` toy.

Note on the four emphasized gap classes: **reorg-with-real-tx** has exactly one test (`reorg_tip_double_spend_is_rejected`, and it is a *rejected* reorg); **multi-node differential** compares tip/height/supply/difficulty but never a UTXO-set root, and never feeds the same blocks in *different orders*; **crash-consistency** (kill mid-op) has **zero** tests and `commit_block_atomic`/`apply_reorg_atomic` are referenced by no test; **chain-level checkpoint/rewind round-trips** are shallow (height-only assertions).

---

### src/chain.rs — `add_block` (extend path)

- [x] add_block — extends main chain, returns Accepted, tip/height/supply advance (HAPPY) (EXISTS: reorg_double_spend_e2e::total_supply_is_conserved_per_block; tier5_genesis_state_correct)
- [x] add_block — duplicate block already in memory → AlreadyKnown (EDGE) (EXISTS: implicitly via replay; but no direct assert — treat as MISSING for a direct AlreadyKnown assertion) → actually MISSING (no test asserts BlockStatus::AlreadyKnown on in-memory dup)
- [ ] add_block — duplicate block already in DB (not in cache) → AlreadyKnown (EDGE) (MISSING)
- [ ] add_block — `db.blocks.contains` returns DB error → propagates Err (ERROR) (MISSING)
- [x] add_block — missing-parent block, height&gt;0 → Orphan + OrphanReceived event (EDGE) (EXISTS: tier5_orphan_block_without_parent_not_added_to_main)
- [x] add_block — height mismatch vs parent+1 → Invalid("Invalid height") (EDGE) (EXISTS: tier5_height_skip_rejected; consensus_edges::child_block_skipping_one_height_rejected)
- [ ] add_block — height-0 block with nonzero prev but chain already has genesis → Invalid (EDGE) (EXISTS: consensus_edges::block_claiming_height_0_when_chain_exists_rejected — validate_block level, not add_block; add-block path MISSING)
- [x] add_block — hardcoded checkpoint mismatch → Invalid("Hardcoded checkpoint mismatch") (ADVERSARIAL) (MISSING — no test injects a checkpoint-height block with wrong hash)
- [x] add_block — full consensus validation fails (bad PoW/merkle/coinbase/future-ts/difficulty) → Invalid(errors) + BlockRejected event, state byte-identical (ADVERSARIAL) (EXISTS: reorg_double_spend_e2e::invalid_block_does_not_mutate_chain_state; tier5_invalid_block_correctly_rejected)
- [ ] add_block — validate_block returns Err (not just invalid) → Err(InvalidState) (ERROR) (MISSING)
- [ ] add_block — assume-valid: block below last_checkpoint skips VDF, still applied (EDGE) (MISSING)
- [x] add_block — MTP: height≥11, timestamp ≤ median-of-lineage → Invalid (ADVERSARIAL) (EXISTS at unit level: chain.rs::mtp_uses_fork_lineage_not_active_chain_by_height; add-block-path assertion MISSING)
- [ ] add_block — MTP uses fork lineage not active-chain-by-height for a competing fork block (ADVERSARIAL) (EXISTS: chain.rs::mtp_uses_fork_lineage_not_active_chain_by_height)
- [ ] add_block — MTP skipped when &lt;11 ancestors reachable (EDGE) (MISSING)
- [ ] add_block — difficulty/target mismatch on main chain (window ≥2) → Invalid("Difficulty target mismatch") (EDGE) (MISSING — chain-level; tier5 uses forged blocks that fail earlier)
- [ ] add_block — difficulty check skipped when window &lt;2 (near genesis) (EDGE) (MISSING)
- [ ] add_block — `serialize(OutputIndexEntry)` fails → Err(Internal) (ERROR) (MISSING)
- [x] add_block — supply `checked_add(emission)` overflow on connect → panic (ADVERSARIAL) (MISSING — no test drives supply to overflow on connect)
- [ ] add_block — burn `checked_add` overflow on connect → panic (ADVERSARIAL) (MISSING)
- [ ] add_block — auto-checkpoint recorded at `height % CHECKPOINT_INTERVAL == 0` → CheckpointRecorded event, last_checkpoint set (HAPPY) (MISSING)
- [ ] add_block — auto-checkpoint `add_checkpoint` returns Err → logged, block still Accepted (ERROR) (MISSING)
- [ ] add_block — state serialize failure on connect → panic (ERROR) (MISSING)
- [x] add_block — extend path commits all four trees atomically via commit_block_atomic (CC) (EXISTS at DB-unit level: db/mod.rs::commit_block_atomic_writes_all_four_trees_together; chain-level MISSING)
- [ ] add_block — `commit_block_atomic` returns Err → panic (halt, in-memory ahead of disk) (CC/ERROR) (MISSING)
- [ ] add_block — RACE-R7: tip moved between read and apply (`inner.tip.hash != tip_hash`) → race_detected, falls through to fork path, block not double-applied (ADVERSARIAL/PROPERTY) (MISSING)
- [ ] add_block — `db.flush` after commit returns Err → logged, still Accepted (ERROR) (MISSING)
- [ ] add_block — cut-through engine processes connected block when candidates registered (HAPPY) (MISSING)

### src/chain.rs — `add_block` (fork choice + reorg)

- [x] fork choice — fork_cumulative &gt; current → take_fork true, reorg (HAPPY) (EXISTS: chaos_partition_l6::two_node_partition_heals_to_heavier_chain; tier14 unit tests of the numeric fn)
- [x] fork choice — fork_cumulative == current → hash-lex tiebreak (fork_tip &lt; current_tip wins) (PROPERTY/ADVERSARIAL) (EXISTS: sim_l3_consensus::equivocating_miner_does_not_split_honest_nodes covers deterministic tie convergence; direct add_block tiebreak assertion MISSING)
- [x] fork choice — fork_cumulative &lt; current → take_fork false → AcceptedFork (stored, not switched) (EDGE) (MISSING — no test asserts BlockStatus::AcceptedFork)
- [x] fork choice — equal-work fork with lexicographically larger hash → NOT taken (ADVERSARIAL) (MISSING)
- [ ] reorg — `find_fork_point` returns None (cycle/missing parent) → Err(Corruption), reorg rejected (ADVERSARIAL) (MISSING)
- [x] reorg — depth ≤10 unconditional with ≥ work → accepted (HAPPY) (EXISTS: tier14_reorg_defense::tier1_* — numeric fn only, not chain)
- [x] reorg — depth 11-100 MESS: fork must exceed exponential-cost threshold → ReorgTooDeep if not (ADVERSARIAL) (EXISTS: tier14 tier2_* — numeric fn only)
- [x] reorg — depth &gt;max_reorg_depth → ReorgTooDeep hard reject (ADVERSARIAL) (EXISTS: tier14 tier3_* — numeric fn only; chain-level MISSING)
- [ ] reorg — finality floor: fork_point &lt; (tip − CHECKPOINT_INTERVAL) → ReorgTooDeep (ADVERSARIAL) (MISSING — chain-level)
- [ ] reorg — soft-finality gate (rolling-finality feature) rejects fork below soft-final tip (ADVERSARIAL) (MISSING)
- [x] reorg — **fork sharing a REAL non-coinbase tx / double-spent key image with active branch → reorg rejected, tip unchanged, key image stays unspent, supply unchanged** (ADVERSARIAL) (EXISTS: reorg_double_spend_e2e::reorg_tip_double_spend_is_rejected)
- [ ] reorg — **ACCEPTED reorg that re-applies real non-coinbase txs onto the winning branch → new UTXO/key-image/output-index state correct, orphaned txs returned** (HAPPY/ADVERSARIAL) (MISSING — the single most important gap; existing test only covers a *rejected* reorg)
- [ ] reorg — disconnect loop un-marks key images spent by orphaned blocks so their inputs become spendable on the new branch (ADVERSARIAL) (MISSING at chain level; storage-level EXISTS: storage/utxos::ring_size_availability_is_reorg_history_invariant)
- [ ] reorg — orphaned block's outputs removed from UTXO set and output_index on disconnect (EDGE) (MISSING chain-level)
- [ ] reorg — **supply AND total_burned conserved across an ACCEPTED reorg** (PROPERTY) (MISSING — existing supply-invariance is only for rejected reorg / per-block)
- [ ] reorg — reorg to a HIGHER tip removes no stale heights (height_removals empty branch) (EDGE) (MISSING)
- [ ] reorg — reorg to a LOWER-height heavier tip removes stale heights above new tip (EDGE) (MISSING)
- [ ] reorg — REORG-TIP-VALIDATE: tip re-validated against reorged UTXO catches a key image already spent by a fork block → routed through reorg_error cleanup, no inflation (ADVERSARIAL) (MISSING)
- [ ] reorg — fork-block validation fails mid-loop → rollback path A restores pre-reorg tip/stats/UTXO/output_index exactly (ADVERSARIAL/CC) (MISSING)
- [ ] reorg — fork-block difficulty mismatch → reorg_error, rollback, original chain intact (ADVERSARIAL) (MISSING)
- [ ] reorg — rollback path B (`reorg_error &amp;&amp; !rolled_back`, the un-dead-coded gate) restores state when only the triggering-block difficulty recheck fails (ADVERSARIAL) (MISSING)
- [ ] reorg — supply/burn `checked_sub` underflow during disconnect → panic (halt) (ADVERSARIAL) (MISSING — the four panic sites are untested)
- [ ] reorg — `apply_reorg_atomic` returns Err → panic (in-memory advanced, disk left at prior canonical) (CC) (MISSING)
- [ ] reorg — disconnect loop is cache-only (no DB fallback): reorg whose fork_point is just inside the ~200-block cache boundary still disconnects every block (EDGE/ADVERSARIAL) (MISSING — latent skip risk)
- [ ] reorg — total_blocks/total_transactions accounting: `checked_sub(disconnected)` None branch logs STATS INVARIANT VIOLATION and floors instead of panicking (EDGE) (MISSING)
- [ ] reorg — orphaned_txs excludes coinbase, includes all non-coinbase from every disconnected block, in the returned Vec (PROPERTY) (MISSING)
- [ ] reorg — Reorg event + metrics::record_reorg emitted with correct depth/fork_point (HAPPY) (MISSING)
- [x] reorg — losing fork's work never leaks into total_difficulty (PROPERTY) (EXISTS: reorg_double_spend_e2e::total_difficulty_is_reorg_history_independent)

### src/chain.rs — `rollback_to_height`

- [x] rollback — target ≥ current height → no-op, empty Vec (EDGE) (EXISTS: tier5_rollback_to_current_height_is_noop)
- [x] rollback — target 0 / beyond genesis handled → height 0 (EDGE) (EXISTS: tier5_rollback_beyond_genesis_handled)
- [ ] rollback — target &lt; last_checkpoint → FINALITY VIOLATION, Err(InvalidState), no mutation (ADVERSARIAL) (MISSING)
- [x] rollback — disconnects DB-only blocks past the cache window (cache→DB fallback) correctly (EDGE/CC) (EXISTS: chain.rs::rollback_to_height_disconnects_db_only_blocks_past_the_cache)
- [x] rollback — total_burned unwound through the real disconnect site, symmetric with connect (PROPERTY) (EXISTS: chain.rs::rollback_to_height_unwinds_total_burned_through_the_real_disconnect_site; total_burned_apply_disconnect_is_symmetric_and_reorg_correct)
- [ ] rollback — block body missing from cache AND DB → Err(InvalidState "resync required"), no partial under-disconnect (ERROR/CC) (MISSING)
- [ ] rollback — supply/burn `checked_sub` underflow → panic (ADVERSARIAL) (MISSING)
- [ ] rollback — total_difficulty saturating_sub (not panic) per disconnected block; ends at recomputable value (PROPERTY) (MISSING)
- [ ] rollback — real non-coinbase txs returned as orphaned for mempool restoration; key images un-marked (HAPPY) (MISSING — tier5_key_image_unspent_after_rollback only checks a never-spent KI)
- [ ] rollback — tip reset: cache hit vs DB hit vs DB-block-missing (hash+height only) vs genesis fallback vs nothing-found (tip unchanged, logged) — all five branches (EDGE) (MISSING)
- [ ] rollback — `remove_heights_above` clears all stale heights; `save_state` failure logged not returned (CC/ERROR) (MISSING)
- [ ] rollback — CC: crash between `remove_heights_above` and `save_state` → restart reloads consistent (non-atomic path) (CC) (MISSING)

### src/chain.rs — fork/difficulty helpers, load, genesis, misc

- [x] calculate_fork_cumulative_work — genesis contributes base 1 (not dft(genesis)); equal-work fork not spuriously heavier (PROPERTY) (EXISTS: chain.rs::total_difficulty_recompute_and_fork_walk_agree_on_genesis_base; total_difficulty_recompute_and_fork_walk_agree...)
- [ ] calculate_fork_cumulative_work — prev_hash cycle → max_steps break, returns partial work (ADVERSARIAL) (MISSING)
- [ ] calculate_fork_cumulative_work — u128 saturation warn path on deep/absurd targets (EDGE) (MISSING)
- [ ] calculate_fork_cumulative_work — parent-not-found → break with partial work (EDGE) (MISSING)
- [x] recompute_total_difficulty — equals 1 + Σ dft(1..=h); agrees with fork walk (PROPERTY) (EXISTS: total_difficulty_recompute_and_fork_walk_agree_on_genesis_base)
- [ ] recompute_total_difficulty — missing block in [1,h] → None (caller keeps stored) (EDGE) (MISSING)
- [ ] find_fork_point — genuine common ancestor → Some(height); genesis fork point → Some(0) (HAPPY) (MISSING direct; exercised via reorg tests)
- [ ] find_fork_point — cycle detected → None (corruption) (ADVERSARIAL) (MISSING)
- [ ] find_fork_point — prev_hash not in storage → None (ADVERSARIAL) (MISSING)
- [ ] collect_fork_chain — ascending order, stops at fork_point, cycle/missing-block break (EDGE) (MISSING)
- [x] checkpoint_phase2_stores / rewind_phase2_stores — all three stores rewind together (PROPERTY) (EXISTS: chain.rs::phase2_stores_rewind_together_through_helpers; phase2_stores_rewind_together...)
- [ ] rewind_phase2_stores — non-empty store with empty checkpoint stack (rewind past restart) → loud error branch (CC/ADVERSARIAL) (MISSING)
- [ ] checkpoint_phase2_stores — debug cross-store divergence assertion fires when a store skips a checkpoint (ADVERSARIAL) (MISSING)
- [x] load_from_database — fresh DB (no state, no chain data) → Fresh (HAPPY) (EXISTS: chain.rs::load_from_database_distinguishes_fresh_and_loaded_state)
- [x] load_from_database — block data present but no chain state → Err (ERROR) (EXISTS: load_from_database_rejects_blocks_without_chain_state)
- [x] load_from_database — chain state references missing tip block → Err (ERROR) (EXISTS: load_from_database_rejects_missing_tip_block)
- [x] load_from_database — genesis hash ≠ expected network genesis → Err (ERROR) (EXISTS: load_from_database_rejects_wrong_network_genesis)
- [ ] load_from_database — genesis height index missing → Err("no genesis entry") (ERROR) (MISSING)
- [ ] load_from_database — chain state height ≠ tip block height → Err (ERROR) (MISSING)
- [ ] load_from_database — total_difficulty self-heal overwrites drifted stored value on load (PROPERTY/CC) (MISSING)
- [ ] load_from_database — tx-index rebuild when empty; per-tx index_tx failures counted, warned (EDGE) (MISSING)
- [x] load_from_database — Loaded reconstructs identical fingerprint incl. utxo count after reopen (DIFFERENTIAL/CC) (EXISTS: reorg_double_spend_e2e::db_reopen_reconstructs_identical_state)
- [ ] rebuild_utxo_set — chain-link corruption (prev_hash mismatch) → truncate to good height, remove bad heights, save corrected state, break (ADVERSARIAL/CC) (MISSING)
- [ ] rebuild_utxo_set — Ok(None) missing block mid-range → warn + continue (EDGE) (MISSING)
- [ ] rebuild_utxo_set — Err reading block → abort with Err (ERROR) (MISSING)
- [ ] rebuild_utxo_set — total_blocks/total_transactions reconstructed (not reset to 0) after restart (CC) (MISSING — this is the L8 finding)
- [ ] rebuild_utxo_set — output_index migration when persistent tree empty (EDGE) (MISSING)
- [ ] restore_state — sets tip/stats then load_from_database; propagates load errors (EDGE) (MISSING)
- [x] init_genesis — genesis hash mismatch vs expected → Err(InvalidState) (ERROR) (MISSING — test_genesis_block only checks happy path)
- [x] init_genesis — happy path sets supply=reward(0), burned=0, persists genesis+height+state (HAPPY) (EXISTS: test_genesis_block; tier5_genesis_supply_matches_emission)
- [ ] verify_tip_integrity — tip.hash ≠ state.tip_hash (height&gt;0) → reload from DB (CC) (MISSING)
- [x] next/expected target — ASERT window ≥2 vs maintain-genesis-difficulty &lt;2; Regtest pinning branch (EDGE) (EXISTS partial: property_invariants_difficulty.*; regtest branch MISSING)
- [x] is_spent — in-memory hit; DB fallback; DB error → fail-closed true; no-DB → false (ADVERSARIAL) (MISSING — fail-closed branch untested)
- [x] block_fee_burn — below fee_distribution_height or zero fees → 0; congestion split otherwise (EDGE) (EXISTS: chain.rs::block_fee_burn_matches_validator_burn_split)
- [x] supply — u128 accumulator survives old u64 ceiling (PROPERTY) (EXISTS: total_supply_accumulator_is_u128_and_survives_the_old_u64_ceiling)
- [x] max_reorg_depth — uses runtime network not compile feature (EDGE) (EXISTS: f31_blockchain_max_reorg_depth_uses_runtime_network)

**chain.rs subtotal: 78 items — 24 exist, 54 missing**

---

### src/db/mod.rs — atomic commit / reorg

- [x] commit_block_atomic — writes output_index + height_index + state + tx_index together (CC) (EXISTS: commit_block_atomic_writes_all_four_trees_together)
- [x] commit_block_atomic — height index never outruns state (crash barrier) (CC) (EXISTS: commit_block_atomic_height_index_never_outruns_state)
- [ ] commit_block_atomic — oldest-wins: existing stealth address in committed index not overwritten (EDGE) (MISSING)
- [ ] commit_block_atomic — transaction body failure → whole batch rolls back, none of the four trees mutated (CC/ERROR) (MISSING)
- [ ] commit_block_atomic — **CC: kill process after tree-transaction commit but before/after flush → reopen sees all-or-nothing** (CC) (MISSING)
- [x] apply_reorg_atomic — re-mined output re-inserted (removed+re-added in same batch) not silently dropped (ADVERSARIAL) (EXISTS: reorg_does_not_drop_a_re_mined_output_index_entry)
- [x] apply_reorg_atomic — oldest-wins preserved for non-removed shared address (EDGE) (EXISTS: reorg_preserves_oldest_wins_for_non_removed_shared_address)
- [ ] apply_reorg_atomic — output removals, height sets, height removals, state, tx add/remove all applied atomically (CC) (MISSING full-tuple test)
- [ ] apply_reorg_atomic — transaction failure → all four trees unchanged (CC/ERROR) (MISSING)
- [ ] apply_reorg_atomic — **CC: kill mid-reorg-commit → reopen shows prior canonical state intact, not divergent tip** (CC) (MISSING)
- [ ] index_tx / get_tx_location / remove_tx_index / tx_index_is_empty — round-trip + 12-byte height‖idx encoding (HAPPY) (MISSING direct)
- [ ] flush / flush_best_effort — error surfaced vs logged (ERROR) (MISSING)
- [x] schema — stamped on fresh, preserved across reopen, future version rejected, older requires migration, wrong length rejected, legacy unstamped rejected (ERROR/EDGE) (EXISTS: schema_version_* suite)
- [x] migrate v1→v2 supply — migrates, reopens, rejects v1 downgrade, empty DB doesn't invent state, failed migration doesn't advance stamp (CC/ERROR) (EXISTS: schema_v1_* + failed_v1_supply_migration_does_not_advance_schema_stamp)
- [x] migrate_legacy_db_to_v1 — matching genesis stamps; wrong genesis / empty rejected; idempotent when stamped (ERROR/EDGE) (EXISTS: migrate_legacy_db_to_v1_* suite)
- [x] DbConfig presets (fast_sync/low_memory/maximum_safety/auto) + open/open_temp (HAPPY) (EXISTS: test_database_open, test_database_config)

**db/mod.rs subtotal: 16 items — 7 exist, 9 missing**

---

### src/db/shim.rs (RocksDB abstraction)

- [x] Tree insert/get/remove/contains_key round-trip (HAPPY) (MISSING direct — exercised indirectly by higher layers; no shim-level unit tests present)
- [ ] compare_and_swap — matches expected → set; mismatch → returns current; used for key-image CAS (ADVERSARIAL) (MISSING)
- [ ] fetch_and_update — atomic read-modify-write (EDGE) (MISSING)
- [ ] scan_prefix / range / iter / iter_rev / last — ordering + `upper_bound` prefix boundary (EDGE) (MISSING)
- [ ] multi-tree `transaction` — commits all trees or none; closure Err aborts (CC) (MISSING direct — only via mod.rs atomic tests)
- [ ] clear / len / is_empty (EDGE) (MISSING)
- [ ] size_on_disk walk; tree_names; generate_id monotonic; was_recovered flag (EDGE) (MISSING)
- [ ] IVec conversions (from Vec/Box, as_ref/deref/borrow) (EDGE) (MISSING)
- [ ] open_path / open with temporary + flush_every_ms options (EDGE) (MISSING)

**db/shim.rs subtotal: 9 items — 0 exist, 9 missing** (entire shim relies on transitive coverage)

---

### src/db/blocks.rs

- [x] insert / get / get_by_height / get_hash_by_height / contains / height / tip round-trip (HAPPY) (EXISTS: test_block_storage)
- [ ] set_height_hash / remove_height_hash round-trip (EDGE) (MISSING direct)
- [ ] remove_heights_above — removes ALL stale heights across a wide (&gt;1 key) range with no skip/duplicate (R-39 mutate-during-iteration regression) (ADVERSARIAL) (MISSING — high-value regression target)
- [ ] remove_heights_above — scan error mid-collect → break, partial removal logged (ERROR) (MISSING)
- [ ] delete — removes block + its height mapping; returns prior (EDGE) (MISSING)
- [ ] get_range — inclusive bounds, missing heights skipped (EDGE) (MISSING)
- [ ] has_any_chain_data / is_empty — true only when genuinely empty (EDGE) (MISSING direct)
- [ ] store_pruned_header / store_pruned_and_remove / has_pruned_header / get_pruned_header — prune round-trip (EDGE) (MISSING)
- [ ] iter / count (EDGE) (MISSING)

**db/blocks.rs subtotal: 9 items — 1 exists, 8 missing**

---

### src/db/utxos.rs

- [x] add_output / get_output / has_output / count round-trip (HAPPY) (EXISTS: test_utxo_storage, test_utxo_store_retrieve)
- [x] spend_output — CAS wins, clears height index (HAPPY) (EXISTS: spend_output_clears_height_index)
- [x] spend_output — decrements and removes zero height count (EDGE) (EXISTS: spend_output_decrements_and_removes_zero_height_count)
- [x] spend_output — second attempt (already spent) → false (ADVERSARIAL) (EXISTS: spend_output_second_attempt_returns_false)
- [ ] add_output — 2-tree atomic (outputs + utxo_by_height) commit; failure → neither written (CC) (MISSING)
- [ ] add_output — post-commit height_count bump failure → logged, UTXO still durable (ERROR) (MISSING)
- [ ] spend_output — cleanup 3-tree transaction fails after CAS → KI stays spent (no double-spend), stale entry tolerated (CC) (MISSING)
- [ ] spend_output — concurrent double-spend: two threads, only one CAS wins (ADVERSARIAL) (MISSING — TOCTOU)
- [ ] is_spent / mark_key_image round-trip (HAPPY) (MISSING direct)
- [ ] get_outputs_at_height / increment/get_height_count consistency (EDGE) (MISSING)
- [ ] clear — empties all trees (EDGE) (MISSING)

**db/utxos.rs subtotal: 11 items — 4 exist, 7 missing**

---

### src/db/state.rs

- [x] save_state / get_state round-trip (HAPPY) (EXISTS: test_state_storage)
- [x] get_state — rejects schema-v1 layout without open-time migration (ERROR) (EXISTS: get_state_rejects_schema_v1_layout_without_open_time_migration)
- [x] checkpoints — add/get/get_all (HAPPY) (EXISTS: test_checkpoints)
- [x] checkpoint ordering above height 255 (big-endian key) (EDGE) (EXISTS: test_checkpoint_ordering_above_255)
- [x] undo data ordering by height (EDGE) (EXISTS: test_undo_data_ordering)
- [ ] store_undo / get_undo / remove_undo round-trip (HAPPY) (MISSING direct)
- [ ] prune_undo — removes all below keep_from_height, returns count (EDGE) (MISSING)
- [ ] genesis hash get/set round-trip (EDGE) (MISSING direct)
- [ ] get_state — None on truly empty DB (EDGE) (MISSING)
- [ ] put/get/delete generic KV (EDGE) (MISSING)

**db/state.rs subtotal: 10 items — 5 exist, 5 missing**

---

### src/storage/utxos.rs (in-memory UTXO set)

- [x] add_output/add_output_ext (coinbase maturity), spend_output, mark/contains/remove key image (HAPPY) (EXISTS: phase1_critical::utxo_* + utxos.rs unit tests)
- [x] ring-size availability is reorg-history invariant (outputs survive spend; only KI marked) (PROPERTY/ADVERSARIAL) (EXISTS: ring_size_availability_is_reorg_history_invariant)
- [x] reorg batches replace orphaned outputs in decoy catalog (ADVERSARIAL) (EXISTS: reorg_batches_replace_orphaned_outputs_in_decoy_catalog)
- [x] canonical output locators ignore insertion order / survive spends / reject out-of-range ordinal (PROPERTY) (EXISTS: canonical_locators_*, locator_resolution_rejects_out_of_range_ordinal)
- [x] output_distribution height-sorted and bounded (PROPERTY) (EXISTS: output_distribution_is_height_sorted_and_bounded)
- [x] height index add/evict (EDGE) (EXISTS: test_height_index)
- [x] apply_batch — adds, KI marks, removes, KI removals (disconnect) all applied; returns count (HAPPY) (EXISTS: covered by reorg batch tests)
- [ ] batch_from_block vs batch_disconnect_block — exact inverse: applying then disconnecting a real 2-in/2-out tx block restores prior set + KI state (PROPERTY) (MISSING — direct inverse property)
- [ ] apply_batch — atomicity caveat: partial failure leaves consistent set (documented non-atomic) (EDGE) (MISSING)
- [ ] evict_old_outputs — keeps keep_depth window, older fall back to DB (EDGE) (MISSING direct)
- [ ] checkpoint() — persists set to DB (CC) (MISSING)
- [ ] resolve_output_locators — canonical ordering under concurrent adds (PROPERTY) (EXISTS partial via canonical_locators_ignore_insertion_order)

**storage/utxos.rs subtotal: 12 items — 8 exist, 4 missing**

---

### src/storage/shielded.rs

- [x] empty tree deterministic root; append changes root (PROPERTY) (EXISTS: empty_tree_has_deterministic_root, appending_commitments_changes_root)
- [x] nullifier double-spend rejected; isolation across stores (ADVERSARIAL) (EXISTS: nullifier_double_spend_rejected, nullifier_isolation)
- [x] checkpoint→rewind restores root (round-trip) (PROPERTY) (EXISTS: checkpoint_then_rewind_restores_root)
- [x] rewind on empty stack → false (EDGE) (EXISTS: rewind_on_empty_stack_returns_false)
- [x] rewind drops entries + nullifiers, not just the tree (ADVERSARIAL) (EXISTS: rewind_drops_entries_and_nullifiers_not_just_the_tree)
- [x] multiple rewinds disconnect multiple blocks (PROPERTY) (EXISTS: multiple_rewinds_disconnect_multiple_blocks)
- [x] rewind cleans persistence so replay matches (CC) (EXISTS: rewind_cleans_persistence_so_replay_matches)
- [x] checkpoint stack cap keeps tree + side tables synced (ADVERSARIAL) (EXISTS: checkpoint_stack_cap_keeps_tree_and_side_tables_synced)
- [x] non-monotonic checkpoint id does not desync (BridgeTree declines) (ADVERSARIAL) (EXISTS: non_monotonic_checkpoint_id_does_not_desync)
- [x] aggressive random op sequences keep tree+entries consistent (PROPERTY) (EXISTS: aggressive_random_op_sequences_keep_tree_and_entries_consistent)
- [x] high-volume checkpoint/append/rewind stress; concurrent read/write; persist+replay round-trip (CC/PROPERTY) (EXISTS: stress_*, persist_and_replay_roundtrips)
- [ ] append_commitment — borsh serialize failure → panic (R-61 halt); persistence write failure → panic (ERROR) (MISSING)
- [ ] rewind — tree_rewound false while side-table checkpoint exists → desync warn branch, side tables still aligned (ADVERSARIAL) (MISSING)
- [ ] witness_path / mark_current / entry_at boundary behavior (EDGE) (MISSING)

**storage/shielded.rs subtotal: 14 items — 11 exist, 3 missing**

---

### src/storage/spark.rs

- [x] checkpoint→rewind restores size and root (round-trip) (PROPERTY) (EXISTS: checkpoint_then_rewind_restores_size_and_root)
- [x] rewind on empty stack → false (EDGE) (EXISTS: rewind_on_empty_stack_returns_false)
- [x] rewind drops serials above restored height (ADVERSARIAL) (EXISTS: rewind_drops_serials_above_restored_height)
- [x] multiple rewinds disconnect multiple blocks (PROPERTY) (EXISTS: multiple_rewinds_disconnect_multiple_blocks)
- [x] rewind handles block with serials-but-no-coins and coins-but-no-serials (EDGE) (EXISTS: rewind_handles_block_with_serials_but_no_coins, ..._coins_but_no_serials)
- [x] re-applying after rewind reaches same root; rewind then different coins → different root (PROPERTY) (EXISTS: re_applying_after_rewind_reaches_the_same_root, rewind_then_different_coins_gives_a_different_root)
- [x] checkpoint stack cap holds, rewind works past it (ADVERSARIAL) (EXISTS: checkpoint_stack_cap_holds_and_rewind_works_past_it)
- [x] persistence rewind survives reopen; reorg with coin-id reuse + shorter fork; repeated reorg-reopen cycles (CC/ADVERSARIAL) (EXISTS: persistence_rewind_survives_reopen, persistence_reorg_with_coin_id_reuse_and_a_shorter_fork, persistence_survives_repeated_reorg_reopen_cycles)
- [x] is_serial_spent double-spend; aggressive random ops; high-volume + concurrent stress (PROPERTY/CC) (EXISTS: aggressive_random_op_sequences_stay_consistent, stress_*)
- [ ] add_coin / mark_serial_spent — persistence write failure → panic path (ERROR) (MISSING)

**storage/spark.rs subtotal: 10 items — 9 exist, 1 missing**

---

### src/storage/kernels.rs

- [x] checkpoint→rewind restores len and root (round-trip) (PROPERTY) (EXISTS: checkpoint_then_rewind_restores_len_and_root)
- [x] rewind on empty stack → false; handles block with no kernels (EDGE) (EXISTS: rewind_on_empty_stack_returns_false, rewind_handles_block_with_no_kernels)
- [x] multiple rewinds; re-apply reaches same root (PROPERTY) (EXISTS: multiple_rewinds_disconnect_multiple_blocks, re_applying_after_rewind_reaches_the_same_root)
- [x] empty store root consistent across constructors (PROPERTY) (EXISTS: empty_store_root_is_consistent_across_constructors)
- [x] checkpoint stack cap holds, rewind past it (ADVERSARIAL) (EXISTS: checkpoint_stack_cap_holds_and_rewind_works_past_it)
- [x] persistence rewind survives reopen; repeated reorg-reopen cycles (CC) (EXISTS: persistence_rewind_survives_reopen, persistence_survives_repeated_reorg_reopen_cycles)
- [x] aggressive random ops; high-volume + concurrent stress (PROPERTY/CC) (EXISTS: aggressive_random_op_sequences_stay_consistent, stress_*)
- [ ] append — borsh serialize / persistence write failure → panic (R-61 class) (ERROR) (MISSING)

**storage/kernels.rs subtotal: 8 items — 7 exist, 1 missing**

---

### src/storage/pruning.rs

- [x] archive mode never prunes; keep-recent honored; protected/unprotected blocks; custom rules (EDGE) (EXISTS: test_archive_mode, test_keep_recent, test_protected_blocks, test_custom_rules)
- [x] checkpoint-protected blocks not pruned (EDGE) (EXISTS: test_checkpoint_protected)
- [x] can_prune does not panic on zero checkpoint interval (EDGE) (EXISTS: can_prune_does_not_panic_on_zero_checkpoint_interval)
- [x] pruning plan creation; from_block / empty / block_count (HAPPY) (EXISTS: test_pruning_plan)
- [ ] prunable_heights range correctness; estimate_savings; record_prune stats accumulation (EDGE) (MISSING direct)
- [ ] pruning + reorg interaction: a pruned height later needed by a reorg fork_point (ADVERSARIAL) (MISSING)

**storage/pruning.rs subtotal: 6 items — 4 exist, 2 missing**

---

### Cross-cutting integration (the four emphasized classes)

- [ ] **DIFFERENTIAL — two nodes fed the same block set in DIFFERENT orders (interleaved forks) reach byte-identical state: tip, height, total_difficulty, total_supply, total_burned, UTXO-set root, output_index, shielded/spark/kernel roots** (DIFFERENTIAL) (MISSING — existing replay/db-reopen use SAME order and never compare a UTXO/set root)
- [x] DIFFERENTIAL — replay of same blocks (same order) → identical state (DIFFERENTIAL) (EXISTS: replay_of_same_blocks_produces_identical_state)
- [x] DIFFERENTIAL — two-node partition heals to heavier chain, identical tip/height/total_difficulty (coinbase-only) (DIFFERENTIAL) (EXISTS: chaos_partition_l6::two_node_partition_heals_to_heavier_chain)
- [x] DIFFERENTIAL — validator vs independent reference agree on ~25 mutations + 400 random cases (DIFFERENTIAL/PROPERTY) (EXISTS: stf_validator_differential::*)
- [ ] **DIFFERENTIAL — node built via a reorg vs node built linearly to the SAME tip have identical total_difficulty AND identical UTXO/output-index state** (DIFFERENTIAL) (MISSING)
- [ ] **CC — kill mid-add_block (extend), restart, invariants hold: height index never ahead of state, no orphaned output-index entries, supply matches replay** (CC) (MISSING)
- [ ] **CC — kill mid-reorg (before vs after apply_reorg_atomic), restart → either prior canonical or new tip, never a hybrid; no double-spend admitted** (CC) (MISSING)
- [ ] **CC — kill mid-rollback_to_height (between remove_heights_above and save_state), restart → consistent** (CC) (MISSING)
- [ ] **CC — phase-2 store reorg past a restart: checkpoint stack is in-memory only → reorg rewind hits the loud-error branch; document/guard that shielded/spark/MW stay dormant** (CC/ADVERSARIAL) (MISSING)
- [ ] **REORG-REAL-TX — accepted reorg re-applying real transfers: recipient balances, key images, output_index, and orphaned-tx mempool return all correct on the winning branch** (ADVERSARIAL) (MISSING)
- [x] REORG-REAL-TX — rejected reorg double-spend leaves state intact (ADVERSARIAL) (EXISTS: reorg_tip_double_spend_is_rejected)
- [ ] **PROPERTY — apply/disconnect symmetry over random real-tx block sequences: connect N blocks then rollback to any k → state equals the state after connecting exactly k** (PROPERTY) (MISSING)
- [ ] PROPERTY — supply == Σ reward(0..=h) − Σ burned across arbitrary connect/reorg/rollback histories (PROPERTY) (MISSING — only per-block + rejected-reorg exist)

**Cross-cutting subtotal: 13 items — 4 exist, 9 missing**

---

## Counts

| File / group | Total | Exist | Missing |
|---|---|---|---|
| src/chain.rs (add_block, fork/reorg, rollback, helpers, load, genesis) | 78 | 24 | 54 |
| src/db/mod.rs (atomic commit/reorg, schema, migration) | 16 | 7 | 9 |
| src/db/shim.rs | 9 | 0 | 9 |
| src/db/blocks.rs | 9 | 1 | 8 |
| src/db/utxos.rs | 11 | 4 | 7 |
| src/db/state.rs | 10 | 5 | 5 |
| src/storage/utxos.rs | 12 | 8 | 4 |
| src/storage/shielded.rs | 14 | 11 | 3 |
| src/storage/spark.rs | 10 | 9 | 1 |
| src/storage/kernels.rs | 8 | 7 | 1 |
| src/storage/pruning.rs | 6 | 4 | 2 |
| Cross-cutting integration | 13 | 4 | 9 |
| **TOTAL** | **196** | **84** | **112** |

**Coverage: ~43% (84/196).**

### Highest-value missing tests (the four emphasized classes, all MISSING)
1. **Accepted reorg re-applying REAL non-coinbase txs** — the entire "successful reorg with real transactions" path is untested; the one real-tx reorg test only covers rejection. Covers add_block lines 2603-3623.
2. **Crash-consistency** — zero tests kill mid-operation; `commit_block_atomic` and `apply_reorg_atomic` have no direct atomicity-under-crash test, only clean-reopen and reject-path proxies.
3. **True differential (different feed orders / reorg-vs-linear) comparing UTXO + phase-2 roots** — existing "identical state" tests use the same order and never compare a set/merkle root.
4. **Chain-level checkpoint/rewind round-trips + finality-floor rejection** — `rollback_to_height` past a checkpoint (FINALITY VIOLATION), the five-branch tip-reset cascade, and the four supply/burn `checked_sub` panic sites are all untested.

### Notable latent-risk branches worth a targeted test
- Reorg disconnect loop (chain.rs:2614) is **cache-only** (no DB fallback), unlike `rollback_to_height` — a reorg whose fork_point sits near the ~200-block cache edge could silently skip disconnects (supply/UTXO/phase-2 under-counted).
- `db/blocks.rs::remove_heights_above` R-39 mutate-during-iteration regression has no dedicated multi-key test.
- `is_spent` DB-error **fail-closed → true** branch (chain.rs:3801) is untested.
- Path-B rollback gate (`!rolled_back`, chain.rs:3159), previously dead code, has no test that reaches it.

All findings are from read-only inspection of `C:\Users\unkno\dev\CoinCync-wt-bughunt` (current main); no files were modified.