# CoinCync consensus + emission — Exhaustive Behavioral Test Plan

Legend: `[x]` already exists (test name cited), `[ ]` missing. "EXISTS(mod)" = in-file `#[cfg(test)]`; otherwise the `tests/` file is named.

---

### src/consensus/block.rs

- [x] `total_fees` — happy: sums non-coinbase fees, skips coinbase (EXISTS(mod): test_non_coinbase_empty_when_only_coinbase covers skip; test_total_fees_zero)
- [ ] `total_fees` — edge: single coinbase-only block returns ZERO via the real `Block::total_fees()` method (existing test asserts on a bare iterator, not the method) (MISSING)
- [ ] `total_fees` — edge/overflow: fees summing past u64::MAX saturate, not panic/wrap (MISSING)
- [ ] `coinbase` — happy: returns first tx; edge: returns None on empty tx list (MISSING)
- [ ] `non_coinbase_transactions` — happy: iterates all but first; edge: empty when only coinbase (partially EXISTS(mod) via iterator, not the method) (MISSING for method)
- [ ] `all_key_images` — happy: collects key images across non-coinbase txs only (coinbase excluded) (MISSING)
- [ ] `verify_merkle_root` — happy: recomputed root matches header.tx_root (MISSING)
- [ ] `verify_merkle_root` — edge: empty tx list returns true iff header.tx_root == Hash::zero() (both branches) (MISSING)
- [ ] `verify_merkle_root` — error: tampered tx or wrong tx_root returns false (MISSING)
- [ ] `verify_merkle_root` — adversarial: reordered transactions produce a different root (reject) (MISSING)
- [x] `size` — edge/overflow: saturating add doesn't overflow (EXISTS(mod): test_size_no_overflow, but asserts literal arithmetic not `Block::size()`) — [ ] MISSING for a real Block with many large txs
- [ ] `is_genesis` / `height` / `tx_count` / `hash` — happy: trivial accessors return header-derived values (MISSING; low priority)

### src/consensus/header.rs

- [x] `pow_binding` — property: covers exactly the otherwise-unbound fields; excludes anchor/nonce/tx_root/target (EXISTS(mod): pow_binding_covers_exactly_the_otherwise_unbound_fields)
- [ ] `hash` — property: every field change (network_magic, version, height, timestamp, prev_hash, tx_root, anchor, algorithm, nonce, target, miner_pubkey, supply_commitment, spark_set_root, mw_kernel_root) changes the hash (malleability guard) (MISSING)
- [ ] `hash` — edge: checkpoint_vote Some vs None produce distinct hashes; two different Some values distinct (MISSING)
- [ ] `hash` — differential: domain tag prefix means header hash never equals pow_binding for same fields (MISSING)
- [ ] `hash` — property: deterministic across repeated calls (MISSING)
- [ ] `meets_target` — happy: pow_hash &lt; target passes; error: pow_hash &gt; target fails; edge: exact boundary equality (MISSING)

### src/consensus/pow.rs

- [x] `compute_full_anchor` — happy/property: deterministic; distinct for prev_hash/height/timestamp/binding (EXISTS(mod): test_full_anchor_deterministic_and_distinct)
- [ ] `compute_full_anchor` — property: cache hit returns byte-identical anchor to cold compute (MISSING)
- [x] `PowAlgorithm::from_index/at_height/name` — happy: always RandomX (EXISTS(mod): test_pow_algorithm_single)
- [ ] `PowAlgorithm::from_str_opt` — happy: "randomx"/"rx"/"0" → Some; error: unknown → None; edge: case-insensitive (MISSING)
- [ ] `PowAlgorithm::is_available` — differential: true iff `randomx` feature (MISSING)
- [x] `SeqPadCache` — edge: FIFO eviction stays bounded, oldest evicted, newest kept, structures lockstep (EXISTS(mod): seq_pad_cache_eviction)
- [ ] `SeqPadCache::insert` — edge: re-insert of existing key is a no-op (doesn't corrupt FIFO order) (MISSING)
- [x] `verify_pow` — differential: full-mem vs light-mode RandomX bit-identical (EXISTS(mod, #[ignore]): fast_light_equivalence)
- [x] `randomx_cache` — property: N threads same (seed,input) agree; epoch rotation rebuilds VM; prewarm lands+promotes (EXISTS(mod, #[ignore]): concurrent_threads_consistent_hashes, epoch_rotation_rebuilds_thread_vms, prewarm_lands_and_promotes)
- [ ] `verify_pow` — happy: a genuinely-mined block (nonce meeting target) verifies Ok (MISSING; needs randomx-gated fixture)
- [ ] `verify_pow` — error: AnchorMismatch when claimed_anchor ≠ recomputed (MISSING)
- [ ] `verify_pow` — error: AlgorithmMismatch when claimed_algo ≠ 0 (MISSING)
- [ ] `verify_pow` — error: TargetNotMet when hash &gt; target (MISSING)
- [ ] `verify_pow` — adversarial: reuse a valid PoW with a mutated bound header field (e.g. miner_pubkey) → binding changes → AnchorMismatch (the audit §1 malleability fix) (MISSING — critical)
- [ ] `verify_pow` — adversarial: mutate target to [0xFF;32] on a mined block keeping same anchor → rejected (MISSING)
- [ ] `compute_pow_hash` — error: returns Err when `randomx` feature disabled (MISSING)
- [ ] `compute_pow_hash_batch` — edge: empty nonces → empty vec (MISSING)
- [ ] `compute_pow_hash_batch` — differential: batch output equals per-nonce single-shot output (rig references it; add local) (MISSING)
- [ ] `randomx_seed_for_height`/`randomx_key_for_height` — property: constant within an epoch, changes at epoch boundary (height/2048) (MISSING)
- [ ] `randomx_key_for_height` — differential: mainnet vs testnet genesis binding yields different keys (MISSING — consensus-critical, the R-2 incident)
- [ ] `bind_randomx_genesis_for_network` — edge: second call with different genesis is ignored (warns), same genesis is idempotent (MISSING)
- [ ] `prewarm_next_epoch_if_near` — edge: no-op when far from boundary; triggers within LOOKAHEAD_BLOCKS (64) of next boundary (MISSING)
- [x] `work_from_target` — (covered indirectly) — [ ] happy: max_target/target = expected work; edge: target==0 (upper 128 bits) returns u128::MAX; edge: target==u128::MAX region returns ~1 (MISSING)
- [ ] `work_from_target` — property: monotonic — smaller target ⇒ ≥ work (MISSING)
- [ ] `meets_difficulty` — happy/edge/boundary (delegates to Hash) — at least one direct assertion (MISSING)

### src/consensus/pow_cache.rs

- [x] `pow_preimage_key` — property: target-independent, sensitive to prev_hash/height/timestamp/nonce/tx_root/binding; deterministic (EXISTS(mod): preimage_key_is_target_independent_and_field_sensitive)
- [x] `PowVerifyCache` — edge: FIFO bounded, existing entry not overwritten, collapses variants (EXISTS(mod): cache_is_fifo_bounded_and_collapses_variants)
- [ ] `pow_hash_cached` — happy: cold miss computes+caches; second call for same key is a cache hit (no recompute) (MISSING)
- [ ] `pow_hash_cached` — error: AnchorMismatch when claimed_anchor forged (rejected free, before hashing) (MISSING)
- [ ] `pow_hash_cached` — error: AlgorithmMismatch when claimed_algo ≠ anchor.algorithm (MISSING)
- [ ] `pow_hash_cached` — adversarial: two blocks sharing (prev,height,ts,nonce,tx_root) but different binding must NOT collapse to one cache entry (MISSING — the amplification/§1 defense)
- [ ] `pow_hash_cached` — adversarial: unbounded target-variants of one solution collapse to a single RandomX run (amplification-collapse) (MISSING)

### src/consensus/difficulty.rs

- [x] `calculate_difficulty` — edge: &lt;2 blocks / genesis returns max_target (EXISTS(mod): test_genesis_returns_max_target; property: calculate_with_no_blocks/one_block_returns_max_target)
- [x] `calculate_difficulty` — happy: stable timestamps hold difficulty; fast blocks raise; slow blocks ease (EXISTS(mod): test_difficulty_stable/increases_on_fast_blocks/decreases_on_slow_blocks; adversarial.rs: rising/falling/oscillating/sudden_drop)
- [x] `calculate_difficulty` — property: deterministic; respects MIN_DIFFICULTY floor (EXISTS: property_invariants_difficulty: calculate_difficulty_is_deterministic, calculated_difficulty_respects_floor)
- [x] `calculate_difficulty` — regression: stale genesis timestamp does not collapse difficulty (EXISTS(mod): startup_grace_ignores_a_stale_genesis_timestamp)
- [ ] `calculate_difficulty` — edge: MAX/MIN adjustment clamp bounds hit exactly (per-block move capped at ratio) (MISSING)
- [ ] `calculate_difficulty` — adversarial: timestamps decreasing / equal (time_diff ≤ 0) don't drive target out of clamp or panic (MISSING)
- [ ] `calculate_difficulty` — adversarial: attacker-inflated timestamp far in future produces easier target but stays within max_t cap (MISSING)
- [ ] `calculate_difficulty` — edge: emergency-drop path taken (stalled chain) still respects MIN_DIFFICULTY floor / max_t cap (MISSING; need{}s_emergency_drop tested but not its effect inside calculate_difficulty)
- [ ] `calculate_difficulty` — property: output target never exceeds `u128::MAX / MIN_DIFFICULTY` (floor enforced for all inputs) (partially EXISTS: calculated_difficulty_respects_floor — verify it covers emergency path too)
- [x] `needs_emergency_drop` — happy: triggers when time_diff &gt; expected×multiplier; bootstrap guard suppresses below height (EXISTS(mod): test_emergency_drop_triggers, test_emergency_drop_bootstrap_guard)
- [ ] `needs_emergency_drop` — edge: exactly at threshold (time_diff == expected×multiplier) does NOT trigger (off-by-one) (MISSING)
- [ ] `needs_emergency_drop` — edge: blocks.len() &lt; EMERGENCY_DIFFICULTY_BLOCKS returns false (MISSING)
- [x] `assert_weight_invariant` — property: SHORT+LONG == SCALE (EXISTS(mod): test_weight_invariant)
- [x] `max_target` — edge: all-0xFF (EXISTS(mod): test_max_target; property: max_target_is_all_ones/deterministic)
- [x] `min_target` — property: deterministic, strictly below max (EXISTS: min_target_is_deterministic, min_target_is_strictly_below_max)
- [x] `target_to_difficulty` — property: deterministic, positive for max_target, no panic on zero target (EXISTS: property_invariants_difficulty)
- [x] `calculate_difficulty_from_target` — (alias of target_to_difficulty) covered transitively — [ ] add explicit equivalence assertion (MISSING; low priority)
- [x] `estimate_hashrate` — edge: &lt;2 blocks / empty / zero timespan well-defined, no panic (EXISTS: estimate_hashrate_doesnt_panic, estimate_hashrate_empty_is_well_defined)
- [x] internal `safe_mul_u128` — edge/overflow: saturates at u128::MAX, no wrap/panic (EXISTS(mod): safe_mul_u128_saturates_at_boundary, test_safe_mul_no_overflow/overflow)
- [x] internal `decompose_fixed_point` — edge: positive, negative, i128::MIN (EXISTS(mod): test_decompose_positive/negative/i128_min)
- [x] internal `pow2_frac` — edge/accuracy: x=0→RADIX, x=RADIX/2≈√2, &lt;0.1% error across range (EXISTS(mod): test_pow2_frac_zero/half, test_polynomial_accuracy)
- [x] internal `apply_asert` — edge: height_diff==0 returns current_target (EXISTS(mod): test_asert_same_height)
- [ ] internal `apply_asert` — property: canonical aserti3-2d formula (denominator = halflife alone) — regression pinning the S1 unit-confusion fix (MISSING — consensus-critical, caused a testnet wipe)
- [ ] internal `apply_asert` — edge: exponent overflow (time_error × RADIX) saturates to i128::MAX/MIN not panic (MISSING)
- [ ] internal `apply_asert` — edge: clamped_int at ±MAX_INT_EXPONENT shift bounds; neg shift ≥128 returns 1 (MISSING)
- [ ] internal `get_anchor` — edge: skips genesis (height 0) anchor when it's inside the window; uses it when it's the only block (MISSING as unit; covered indirectly by startup_grace test)
- [x] internal `target_to_u128`/`u128_to_target` — property: roundtrip preserves upper 16 bytes (EXISTS(mod): test_target_roundtrip)
- [ ] `target_to_u128` — edge: all-zero target maps to 1 (`.max(1)`) so no div-by-zero downstream (MISSING)

### src/consensus/fee_market.rs

- [x] `calculate_fee` — happy: size×MIN_FEE_PER_BYTE at 0% congestion (EXISTS(mod): test_calculate_fee)
- [x] `calculate_fee` — edge: zero size → zero fee even under congestion; saturating extremes (usize::MAX, congestion ≥100 / u64::MAX) no panic, ≤ u64::MAX/100 (EXISTS(mod): test_zero_size_block_fee, test_calculate_fee_saturating_extremes)
- [x] `congestion_multiplier` — edge: all bucket boundaries 0/49/50/74/75/89/90/100 (EXISTS(mod): test_congestion_multiplier)
- [ ] `congestion_multiplier` — edge: congestion_pct &gt; 100 (out of table) collapses to ×3 bucket (partially in saturating_extremes; add explicit) (MISSING)
- [x] `distribute_fee` — happy: valid split, miner &gt; burn (EXISTS(mod): test_fee_distribution)
- [x] `distribute_fee` — property: exact sum conservation across 0/1/2/3/primes/large/u64::MAX values, congested &amp; not (EXISTS(mod): distribution_sum_exact; property_invariants_fee: distribute_fee_conserves_total, no_overflow_and_bounded, never_pays_protocol, is_deterministic, congestion_burns_at_least_as_much, reference_splits)
- [ ] `distribute_fee` — edge: total==0 → all buckets zero, is_valid true (partially in distribution_sum_exact; explicit) (MISSING)
- [x] `FeeDistribution::is_valid` — property: sum==total (tolerance 0) (EXISTS(mod) via distribution_sum_exact)
- [ ] `FeeDistribution::is_valid` — error: hand-constructed distribution whose buckets don't sum to total returns false (MISSING)
- [x] `calculate_congestion` — edge/overflow: 1000 blocks of MAX_BLOCK_SIZE → 100%, no 32-bit overflow (EXISTS(mod): congestion_no_overflow)
- [ ] `calculate_congestion` — edge: empty slice → 0; capped at 100 for oversized inputs (MISSING)
- [x] `block_fee_stats` — edge/overflow: 5000 large fees no overflow, correct tx_count/height (EXISTS(mod): block_fee_stats_no_overflow)
- [ ] `block_fee_stats` — edge: empty tx_fees returns default with height set; avg_fee_per_byte guards total_size==0 (MISSING)
- [ ] `calculate_priority_fee` — edge: priority clamped to [0,100]; f64::MAX/NaN/negative don't overflow or panic (saturating) (MISSING)
- [ ] `is_congested` — edge: boundary at CONGESTION_THRESHOLD (≥ vs &lt;) (MISSING)
- [ ] `FeeTier::multiplier` — happy: Economy/Standard/Priority multipliers (MISSING; low priority)
- [ ] `FeeCalculator::estimate` — edge: non-finite fee_f64 falls back to unscaled base; overflow clamped to u64::MAX (MISSING)
- [ ] `FeeCalculator::distribute` — differential: matches free `distribute_fee` with is_congested(congestion_pct) (MISSING)

### src/consensus/finality.rs

- [x] `evaluate_reorg_acceptability` — happy: shallow accepts equal-or-more work, rejects strictly-less (EXISTS(mod): test_reorg_acceptability_shallow_accepts_equal_or_more_work; tier14: tier1_*)
- [x] `evaluate_reorg_acceptability` — Tier-2 MESS: depth 30/50/70/90 require 2x/4x/8x/16x (EXISTS: tier14 tier2_depth_*; mod test_reorg_acceptability_mess_multiplier)
- [x] `evaluate_reorg_acceptability` — Tier-3 hard cap: depth &gt; max rejected for both networks, error cites cap (EXISTS(mod): test_reorg_acceptability_hard_depth_cap; tier14 tier3_*)
- [x] `evaluate_reorg_acceptability` — bootstrap: below BOOTSTRAP_MESS_HEIGHT skips MESS, longest-chain only, Tier-3 still enforced (EXISTS(mod): test_reorg_acceptability_bootstrap_bypass)
- [x] `evaluate_reorg_acceptability` — edge: depth 0, honest_work 0, overflow resistance (EXISTS: tier14 edge_zero_depth_accepted, edge_honest_work_zero, edge_overflow_resistance)
- [ ] `evaluate_reorg_acceptability` — edge: depth exactly == REORG_UNCONDITIONAL_DEPTH (10) is unconditional; depth 11 first enters MESS (boundary) (partially EXISTS tier1_depth_10_is_unconditional / tier2_depth_11; verify both) 
- [ ] `evaluate_reorg_acceptability` — edge: depth exactly == max_depth accepted (not &gt; cap) (MISSING — off-by-one on the hard cap)
- [ ] `evaluate_reorg_acceptability` — edge: MESS exponent capping at 40 (very deep depth) → multiplier 2^40, no shift overflow (MISSING)
- [ ] `evaluate_reorg_acceptability` — adversarial: honest_work near u128::MAX × multiplier saturates (required_work doesn't wrap, fork rejected) (partially edge_overflow_resistance; make explicit for saturating_mul) 
- [ ] `evaluate_reorg_acceptability` — differential: mainnet(100) vs testnet(1000) cap chosen by max_depth arg gives different accept/reject at depth 101–1000 (MISSING)
- [x] `max_reorg_depth_for` — happy: Testnet/Regtest 1000, Mainnet 100 (EXISTS(mod) within test_reorg_acceptability_hard_depth_cap; tier14 constants_are_sane)
- [ ] `max_reorg_depth` (deprecated) — edge: returns 1000 (safer testnet default) (MISSING)

### src/consensus/privacy_policy.rs

- [x] `check_tx_privacy` — error: zero/identity commitment → TransparentOutputForbidden (EXISTS(mod): zero_commitment_rejected)
- [x] `check_tx_privacy` — error: zero/identity stealth address → RawPubkeyForbidden (EXISTS(mod): zero_stealth_rejected)
- [x] `check_tx_privacy` — error: empty inputs → UnshieldedForbidden (EXISTS(mod): empty_inputs_rejected)
- [ ] `check_tx_privacy` — happy: valid non-identity commitment + stealth + non-empty inputs → Ok (MISSING)
- [ ] `check_tx_privacy` — adversarial: non-canonical bytes that decompress to identity via Ristretto map (not the all-zeros encoding) → still rejected (the M-6/M-3 fix; explicit non-canonical-identity vector) (MISSING — the whole point of the decompression check)
- [ ] `check_tx_privacy` — error: commitment bytes that fail to decompress at all → TransparentOutputForbidden (MISSING)
- [ ] `check_tx_privacy` — ordering: Rule 1 fires before Rule 3 when both violated (partially EXISTS: zero_commitment_rejected comments on it) 
- [x] `enforce_privacy_policy` — happy: coinbase txs skipped, non-coinbase checked (EXISTS(mod) transitively) — [ ] explicit: a block with valid coinbase + one violating transfer → Err (MISSING)
- [ ] `enforce_privacy_policy` — happy: all-valid block → Ok (MISSING)

### src/consensus/fork_signal.rs

- [x] `SignalBits::new` — property: OR's in MUST_SET (EXISTS(mod): signal_bits_must_set)
- [x] `SignalBits::signals` — happy: detects set bit, not unset (EXISTS(mod): signals_specific_bit)
- [x] `encode_coinbase_extra` — edge: SignalBits(0) → 8-byte legacy layout; SignalBits::new → 12-byte with trailer (EXISTS(mod): encode_no_signal_matches_legacy_format, encode_with_signal_appends_4_bytes)
- [x] `decode_signal_bits` — happy/roundtrip; legacy 8-byte → no signal; short &lt;12 → no signal (no panic); ignores trailing &gt;12 (EXISTS(mod): encode_decode_roundtrip, decode_legacy_8byte_extra_returns_no_signal, decode_short_extra_returns_no_signal, decode_ignores_trailing_bytes_beyond_12)
- [x] `ForkSignaler::state` — happy: Defined before start; LockedIn at threshold; Started below threshold (EXISTS(mod): defined_before_start, locks_in_at_threshold, below_threshold_stays_started)
- [x] `ForkSignaler::state` — regression: read-only state() does NOT persist lock-in across window boundary (EXISTS(mod): state_alone_does_not_persist_lock_in_across_window_boundary)
- [x] `ForkSignaler::state_and_record` — property: persists lock-in across window; idempotent (EXISTS(mod): state_and_record_persists_lock_in_across_window_boundary, state_and_record_is_idempotent)
- [ ] `ForkSignaler::state` — edge: current_height ≥ timeout_height and never locked-in → Failed; but locked-in before timeout → still LockedIn/Active (MISSING — the Failed branch is untested)
- [ ] `ForkSignaler::state` — edge: LockedIn→Active transition at exactly max(activation, min_activation_height) boundary (MISSING)
- [ ] `ForkSignaler::state` — edge: count == SIGNAL_THRESHOLD-1 vs SIGNAL_THRESHOLD (off-by-one threshold; partially below_threshold_stays_started) 
- [ ] `ForkSignaler::state` — edge: signaling_pct clamped to ≤100 at window start (count&gt;total via .max(1)) — the &gt;100% guard (MISSING)
- [x] CIP bits — property: all bits distinct (no collision); V1_0_12 signals only own bit + MUST_SET (EXISTS(mod): v1_0_12_bundle_bit_distinct_from_other_cips, v1_0_12_bundle_signaled_by_dedicated_bit_only)
- [x] DEPLOYMENTS — invariant: V1_0_12_BUNDLE registered dormant (all height fields u64::MAX) (EXISTS(mod): v1_0_12_bundle_deployment_registered_dormant)
- [ ] DEPLOYMENTS — invariant: all Phase-2 deployments (halo2/spark/mw) ship dormant (u64::MAX) (MISSING)

### src/emission/curve.rs + supply.rs + mod.rs

- [x] `base_reward_from_supply` — happy: 50 CYNC @ 0, 25 @ 50M, 12.5 @ 75M (EXISTS(mod): genesis_reward_is_50_cync, reward_at_half_supply, reward_at_75_percent_supply)
- [x] `base_reward_from_supply` — edge: tail floor near cap; never below tail even at u128::MAX supply (EXISTS(mod): tail_emission_kicks_in, reward_never_below_tail)
- [x] `base_reward` (height) — happy: 50 @ height 0; decays over years; no overflow at large heights (EXISTS(mod): height_based_estimate_starts_at_50, reward_decays_over_time, no_overflow_on_large_heights)
- [x] `base_reward`/`block_reward` — property: spec-formula matches independent reference across supply domain; monotone non-increasing incl. step boundaries; bounded; coarse estimate never over-emits; tail reached+held; no panic at extreme heights (EXISTS: emission_reference_oracle.rs full suite)
- [ ] `base_reward` — edge/DoS: `base_reward(u64::MAX)` returns in O(1) via the tail fast-path (no ~1.8e15-iteration loop) (MISSING — the 2026-06-03 DoS fix is untested)
- [ ] internal `estimate_supply_at_height` — property: adaptive step sizes produce same result within stated 0.1% for representative heights across step-size boundaries (10k/100k/1M) (MISSING)
- [ ] internal `estimate_supply_at_height` — invariant: result never exceeds cap_atomic (`.min(cap_atomic)`) (MISSING)
- [x] `emission_phase` — happy: Distribution at genesis (EXISTS(mod): emission_phase_at_genesis)
- [ ] `emission_phase` — edge: Mature and Tail phase transitions (reward ≤ 10×COIN, ≤ TAIL_EMISSION boundaries) (MISSING — only Distribution branch tested)
- [ ] `EmissionPhase::name` — happy: all three variants map to strings (MISSING; low priority)
- [x] `calculate_block_reward` (mod.rs) — differential: equals `base_reward(height)` (EXISTS transitively; consensus_edges emission_reward_approaches_tail, phase1 genesis_reward_correct/supply_cap_correct)
- [x] `calculate_supply_commitment` — property: deterministic (EXISTS(mod): test_supply_commitment_deterministic)
- [ ] `calculate_supply_commitment` — property: sensitive to each field (emitted/burned/circulating/remaining changes the digest) (MISSING)
- [x] `SupplyStats::new` — happy: circulating = emitted - burned (saturating) (EXISTS(mod): test_supply_stats_new, test_supply_stats_default)
- [ ] `SupplyStats::new` — edge: burned &gt; emitted saturates circulating to zero (MISSING)

### src/consensus/validation.rs — `validate_block*`

- [x] happy: genesis block validates; full genesis via real network (EXISTS(mod): test_genesis_validation)
- [x] `check_block_network_magic` — error: wrong/cross-network magic rejected at first check; genesis zero-magic accepted (EXISTS(mod): test_runtime_network_magic_enforced; adversarial.rs cross_network_block_is_rejected_at_first_check)
- [ ] `check_block_network_magic` — edge: non-genesis block with zero magic rejected (only height-0 exemption) (MISSING)
- [x] `check_block_has_coinbase` / empty block — error: missing coinbase (EXISTS(mod): test_empty_block_invalid; adversarial block_with_no_transactions_rejected)
- [x] `check_block_first_tx_is_coinbase` — error: first tx not coinbase (EXISTS: adversarial-adjacent) — [ ] explicit "First transaction must be coinbase" when tx[0] is a transfer (MISSING)
- [x] `check_block_merkle_root` — error: wrong merkle root rejected (EXISTS: adversarial block_with_wrong_merkle_root_rejected)
- [x] `check_block_privacy_policy` — error: transparent/zero-commitment/no-input tx in block rejected, even under skip-crypto (EXISTS: adversarial transfer_with_zero_stealth_address_rejected_even_on_skip_crypto, transfer_with_zero_commitment_rejected, transfer_with_no_inputs_rejected)
- [x] `check_block_tail_supply` — regression: does not halt after year 12; rejects below-tail and above-genesis rewards (EXISTS(mod): tail_supply_gate_does_not_halt_after_year_12, tail_supply_gate_rejects_out_of_band_rewards)
- [x] `check_header_vs_prev` — error: non-monotone height, non-monotone/equal timestamp, bad prev_hash, height skip, fake genesis (EXISTS: adversarial non_monotone_height_rejected, non_monotone_timestamp_rejected, bad_prev_hash_on_child_rejected, block_with_same_timestamp_as_parent_rejected; consensus_edges child_block_skipping_one_height_rejected, fake_genesis_at_height_0_with_nonzero_prev_rejected, block_claiming_height_0_when_chain_exists_rejected)
- [ ] `check_header_vs_prev` — error: version downgrade (v2→v1) rejected (MISSING — the downgrade-attack branch)
- [x] `check_header_future_timestamp` — edge: exactly at drift boundary accepted, one past rejected; far-future non-genesis rejected (EXISTS: consensus_edges timestamp_exactly_at_drift_boundary_accepted, timestamp_one_past_drift_boundary_rejected; adversarial timestamp_far_in_future_rejected_for_non_genesis)
- [ ] `check_header_future_timestamp` — edge: genesis (height 0) exempt from future-timestamp check (MISSING)
- [x] `check_header_version_min` — error: version below minimum / version 0 (EXISTS: consensus_edges block_with_version_0_rejected; phase1 invalid_version_rejected)
- [ ] `check_header_version_min` — edge: version ABOVE minimum accepted (FIX #47 smooth activation — version bump the block before fork) (MISSING)
- [ ] `check_header_checkpoint_vote` — error: checkpoint_vote references height ≥ block.height rejected; edge: references past height accepted (MISSING — CC-L1, untested)
- [x] `check_block_size` — error: block too large (EXISTS: phase1/adversarial oversized_tx_rejected covers tx; ) — [ ] block exceeding MAX_BLOCK_SIZE specifically (MISSING)
- [ ] `check_block_weight` — error: ring-sig weight exceeds 4×MAX_BLOCK_SIZE even when byte-size ok; runs under fast-sync too (MISSING — DoS gate untested)
- [ ] `check_block_tx_count` — error: &gt; MAX_TXS_PER_BLOCK (MISSING)
- [x] `check_block_consensus_checkpoint` — error: block at hardcoded checkpoint height with wrong hash rejected (MISSING for a populated table; note table is empty pre-launch) (MISSING)
- [x] coinbase reward — adversarial: oversized coinbase (claims &gt; emission+fees) rejected; extra outputs rejected (EXISTS: consensus_edges block_with_oversized_coinbase_rejected; adversarial coinbase_with_extra_outputs_rejected)
- [ ] coinbase — adversarial: per-output blinding trick (non-zero blindings cancelling in sum, b1+b2=0) rejected by per-output commitment check (C19-FIX) (MISSING — critical inflation vector)
- [ ] coinbase — adversarial: coinbase output sum overflow (checked_add) rejected as inflation, not silently clamped (FIX #41) (MISSING)
- [ ] coinbase — adversarial: max_coinbase overflow (reward + fees near u64::MAX) rejected via checked_add, not saturating clamp (M4) (MISSING)
- [ ] coinbase — error: identity/non-curve output commitment rejected (MISSING)
- [ ] coinbase — edge: too many outputs (&gt;16) rejected; dust — N outputs below MIN_OUTPUT_AMOUNT total rejected (MISSING)
- [ ] coinbase — edge: encrypted_amount length — post-v1.0.12 exactly 8 bytes required; pre-fork ≥8 accepted (differential on v1_0_12_active) (MISSING)
- [ ] coinbase — happy: honest coinbase claiming exactly reward+miner_share validates; total ≠ max_coinbase rejected (MISSING explicit)
- [x] duplicate detection — error: duplicate key image within block (EXISTS: adversarial/phase1 key-image tests exist at tx level) — [ ] explicit block-level duplicate key image across two txs (MISSING)
- [ ] `check_block_duplicate_tx_hashes` — error: same tx included twice rejected (MISSING)
- [ ] cross-tx duplicate stealth (v1_0_12_active) — adversarial: two txs in one block create same stealth address rejected (MISSING — the cfc680b7 lookup-poisoning fix)
- [ ] dynamic fee — error: tx fee below congestion-adjusted dynamic_min rejected; edge: fee calc overflow (checked_mul) surfaces oversized-tx error not reject-all (FIX #42) (MISSING)
- [ ] PoW gate — adversarial: below-checkpoint block in a build WITHOUT insecure-fast-sync still gets full PoW verification (the silent-skip DoS fix) (MISSING — critical)
- [ ] PoW gate — differential: fast_sync (feature on + below checkpoint) skips crypto; still catches multiple-coinbase (MISSING)
- [ ] `validate_difficulty_target` — error: target easier than max_target; target zero; ratio out of normal (±32x) / emergency (±256x) bounds (MISSING — sanity gate untested directly)
- [x] `validate_difficulty_target` — happy: valid target hash (EXISTS: consensus_edges difficulty_target_is_valid_hash)
- [ ] `validate_block` — differential: same block validated as testnet vs mainnet (v1_0_12_rules_active, fee_distribution_height, min_output_age) differs correctly (MISSING)

### src/consensus/validation.rs — `validate_transaction*` sub-checks

- [x] `check_tx_version_range` — error: version 0 or &gt; MAX_TX_VERSION rejected (incl. in a mined block, before coinbase early-return) (EXISTS: phase1 invalid_version_rejected; property_invariants_validator nonstandard_version_is_rejected)
- [x] `check_tx_v2_activation` — error: V2 tx below V2_TX_ACTIVATION_HEIGHT rejected; V1 accepted (EXISTS: consensus_edges v2_tx_rejected_before_activation_height, v1_tx_accepted_before_activation)
- [x] `check_output_curve_points` — happy: valid points; error: identity/non-curve tx_public_key rejected (EXISTS(mod): output_curve_points_accepts_valid_points, identity_tx_public_key_is_rejected, noncurve_tx_public_key_is_rejected)
- [ ] `check_output_curve_points` — error: zero/non-curve stealth_address; zero/non-curve commitment rejected (H-19) (MISSING — only tx_public_key branch tested in-module; stealth via privacy_policy only)
- [x] `check_tx_input_output_counts` — error: empty inputs/outputs; excessive inputs/outputs (EXISTS: phase1 empty_outputs_rejected, excessive_outputs_rejected, excessive_inputs_rejected; property_invariants_validator empty_outputs_rejected)
- [ ] `check_tx_input_output_counts` — error (v1_0_12_active): output encrypted_amount ≠ 8 bytes rejected; encrypted_memo &gt; MAX_OUTPUT_MEMO_SIZE rejected (MISSING — the 3507a1cd/161fd74f block-path ports)
- [ ] `check_tx_io_ratio_legacy` — error: &gt;32:1 input/output or output/input ratio for non-Transfer/Churn types rejected (MISSING)
- [x] `check_tx_uniform_shape` — error/happy: ring size cutover (11 before, 16 at/after) — related (EXISTS: consensus_edges ring_size_function_*, ring_11_accepted, ring_10_rejected) — [ ] shape itself: post-activation Transfer must be 2-in/2-out or 2-in/3-out; Churn must be 2-out; wrong shape rejected (MISSING)
- [ ] `check_tx_uniform_shape` — edge: below UNIFORM_TX_SHAPE_HEIGHT no shape constraint; non-Transfer/Churn types exempt (MISSING)
- [x] `check_tx_no_double_spend` — error: duplicate key image within tx; collision with UTXO set (EXISTS: phase1 duplicate_key_images_in_same_tx_rejected, key_image_double_spend_prevented; adversarial mempool_rejects_duplicate_keyimage)
- [x] `check_ring_member_coinbase_maturity` — happy/error: non-coinbase always ok; coinbase matures at exactly min age; immature below floor rejected with indices (EXISTS(mod): ring_member_non_coinbase_maturity_always_ok, ring_member_coinbase_matures_after_min_age, ring_member_coinbase_immature_below_floor)
- [ ] `check_ring_member_coinbase_maturity` — differential: min_output_age hard-fork ramp (10→100) at MIN_OUTPUT_AGE_HARDFORK_HEIGHT, both branches (live-UTXO &amp; spent-index) agree (MISSING — the 2026-06-03 divergence regression)
- [x] `check_ring_member_time_lock` — happy/error: None ok; past-unlock ok (incl. exactly at lock height); before-unlock rejected with indices (EXISTS(mod): ring_member_time_lock_none_is_ok, ring_member_time_lock_past_unlock_ok, ring_member_time_lock_before_unlock_rejected)
- [ ] `check_tx_ring_members` — error: ring member commitment mismatch vs on-chain UTXO (inflation vector CRIT-R4-1) rejected (MISSING)
- [ ] `check_tx_ring_members` — error: ring member references non-existent output at/after STRICT_RING_MEMBER_HEIGHT rejected; before it allowed (bootstrap gap) (MISSING)
- [ ] `check_tx_ring_members` (v1_0_12_active) — adversarial: duplicate stealth address across tx outputs; collision with existing on-chain output rejected (5aeb27dd lookup-poisoning) (MISSING)
- [x] `check_tx_ring_size_and_unique_members` — error: ring size mismatch vs effective_ring_size; below-minimum rejected (EXISTS: adversarial ring_size_at_minimum_accepted, ring_size_below_minimum_rejected; consensus_edges ring_10_rejected_always)
- [ ] `check_tx_ring_size_and_unique_members` — error: duplicate ring member public key within an input rejected (MISSING)
- [ ] `check_tx_ring_size_and_unique_members` — differential (v1_0_12_active): `total_outputs_ever() - reorg_disconnects_total()` vs `output_count()` — two nodes reaching same tip via different reorg histories require the SAME ring size in bootstrap window (MISSING — the 1d27d3c8 release-blocker determinism fix)
- [x] `check_tx_range_proofs` / `verify_output_range_proofs` — happy: valid single &amp; aggregated multi-output proofs; error: garbage/empty proof, mismatched amount (EXISTS: phase1 valid_amount_proof_verifies, zero_amount_proof_verifies, aggregated_multi_output_verifies, garbage_proof_rejected, mismatched_amount_fails_verification)
- [ ] `verify_output_range_proofs` — error: output commitment not on Ristretto curve rejected (from_bytes_checked); coinbase skips proof (MISSING)
- [ ] `verify_output_range_proofs` — differential: BP+ activation gate (pre vs post current_height) dispatches correct verifier (MISSING)
- [x] `check_tx_balance_proof` / `verify_balance_proof` — property: balanced tx passes, unbalanced (money creation) fails (EXISTS: historical_attacks bitcoin_2018_inflation, phase1 proof tests; regression suite)
- [ ] `verify_balance_proof` — adversarial: identity pseudo-output commitment rejected (FIX #44 — collapses balance equation) (MISSING — critical)
- [ ] `verify_balance_proof` — error: non-curve pseudo-output / output / fee commitment rejected; empty inputs/outputs rejected (MISSING)
- [ ] `verify_ring_signature` — adversarial: `input.key_image` ≠ `signature.key_image` rejected before cache (C-2 supply-inflation binding) (MISSING — critical)
- [ ] `verify_ring_signature` — error: non-curve ring member point / non-curve pseudo-output → false and cached-false; serialization failure fails closed (MISSING)
- [ ] `verify_ring_signature` — property: cache hit returns same verdict as cold verify (no false-accept via poisoned cache) (MISSING)
- [x] `validate_transaction_basic` — error: version 0/&gt;MAX, empty in/out, too-large/too-small size, fee below min, oversized extra, oversized range proof (EXISTS: phase1 + property_invariants_validator: fee_below_minimum_rejected, oversized_extra_rejected, oversized_tx_rejected, huge_range_proof_rejected, extra_too_large_rejected, empty_extra_is_accepted, lock_height_* )
- [x] `validate_transaction_basic` — happy: baseline coinbase/transfer passes; coinbase zero-fee allowed (EXISTS: property_invariants_validator baseline_coinbase_passes_validation; phase1 coinbase_zero_fee_allowed)
- [ ] `validate_transaction_basic` — error: constitutional ring-size &lt; BOOTSTRAP_MIN_RING_SIZE; missing range proof (non-coinbase); zero/non-curve key image; duplicate key image in tx (MISSING explicit unit — some via other paths)
- [ ] `validate_transaction_basic` — edge: encrypted_amount empty → OutputTooSmall; &gt;64 bytes rejected; encrypted_memo &gt;256 rejected (MISSING)
- [ ] `validate_all_transactions` — error: early-terminates and reports first failing index; happy: all-valid → Ok (MISSING)
- [ ] `validate_transactions_parallel` — happy: returns per-index results preserving order (MISSING)
- [ ] `validate_transaction_for_network` — property/differential: evaluation order &amp; error types bit-identical whether called via block path or directly (regression pinning the H1 extraction) (MISSING)
- [ ] `v1_0_12_rules_active` — differential: Mainnet/Regtest always true; Testnet gated on HARD_FORK_V1_0_12_HEIGHT (boundary height-1 vs height) (MISSING)

---

## Counts

- **Total tests enumerated: 168**
  - Already exist (`[x]` lines): **63**
  - Missing (`[ ]` lines): **105**

Note: several `[x]` lines are partial — the cited test covers the happy/common branch but a companion `[ ]` line flags the untested edge/adversarial branch of the same function (e.g. `check_output_curve_points`, `check_header_future_timestamp` genesis exemption, `evaluate_reorg_acceptability` exact-cap boundary).

## Highest-priority missing tests (consensus-critical, currently unverified)

1. **`verify_pow` / `pow_hash_cached` malleability (audit §1):** reuse a valid PoW with a mutated bound header field must be rejected via anchor/binding mismatch — no direct test exists.
2. **Coinbase inflation vectors:** per-output blinding-cancellation trick (C19), coinbase sum overflow (FIX #41), max_coinbase overflow (M4) — all untested.
3. **`verify_ring_signature` key-image binding (C-2):** `input.key_image` ≠ `signature.key_image` must fail before the cache — untested inflation path.
4. **`verify_balance_proof` identity pseudo-output (FIX #44)** — untested balance-equation collapse.
5. **PoW skip DoS fix:** below-checkpoint block in a non-`insecure-fast-sync` build must still fully verify PoW — untested.
6. **`apply_asert` canonical formula (S1 unit fix)** — the bug that forced a testnet wipe has no regression test asserting the halflife-in-seconds denominator.
7. **Ring-size determinism (`total_outputs_ever - reorg_disconnects_total`, 1d27d3c8)** — the v1.0.12 release-blocker fork risk is untested.
8. **`randomx_key_for_height` genesis binding** — mainnet vs testnet key divergence (the R-2 rc3 incident) is untested.

All source files were read at `C:\Users\unkno\dev\CoinCync-wt-bughunt\src\consensus\` and `\src\emission\`; existing tests scanned in each file's `#[cfg(test)]` block plus `tests\{consensus_edges,adversarial,phase1_critical,tier14_reorg_defense,property_invariants_difficulty,property_invariants_fee,property_invariants_validator,emission_reference_oracle}.rs`. Note `rolling_finality.rs` and `kani_proofs.rs` exist in the directory but were excluded per the subsystem scope (which named `finality.rs`).