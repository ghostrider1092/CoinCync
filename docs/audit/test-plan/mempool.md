# Exhaustive Behavioral Test Plan — mempool + transactions subsystem

Scope: `src/mempool.rs`, `src/transaction/{types,builder,validator,recovery}.rs`, `src/mining/template.rs`. Scanned in-crate `#[cfg(test)]` modules and all of `tests/`. Note: the main `mod tests` in `mempool.rs` is gated out with `#[cfg(any())]` (dead — relied on removed `AssetIssuance`), so the *only* live mempool unit tests are `generation_tests` and `load_from_disk_tests`. Most mempool behavioral coverage lives in `tests/mempool_ordering.rs`, `tests/adversarial.rs`, `tests/tier6_dos_resource.rs`, and `tests/transaction_lifecycle.rs`, all via the `add_skip_crypto`/`add_skip_signatures` escape hatch.

Categories: HAPPY / EDGE / ERROR / ADVERSARIAL / PROPERTY / ROUND-TRIP.

### src/mempool.rs

**`MempoolEntry::new` / `scaled_fee_per_byte`**
- [ ] HAPPY: fee_per_byte = fee*1e6/size for typical values (EXISTS-implicit via ordering; MISSING as direct unit)
- [ ] EDGE: zero-size tx clamped to size.max(1), no divide-by-zero (MISSING)
- [ ] EDGE: small fee (50 syncs / 100 bytes) retains micro-precision, not truncated to 0 (MISSING — the documented A5 scenario)
- [ ] ADVERSARIAL: extreme fee (u64::MAX) clamps fee_per_byte to u64::MAX, does NOT wrap to near-zero (MISSING — the A5-MEM-01 anti-wraparound branch, untested)

**`add` / `accept` (production admission path)**
- [ ] HAPPY: valid tx accepted, returns hash, contained afterward (EXISTS: transaction_lifecycle::mempool_accepts_valid_tx_and_dedups_on_second_add — but that uses full path? it uses add; check ring/crypto)
- [ ] EDGE: second add of identical tx is idempotent no-op returning same hash (EXISTS: mempool_accepts_valid_tx_and_dedups_on_second_add)
- [ ] ERROR: coinbase rejected before crypto (EXISTS: mempool_ordering::test_coinbase_rejected, transaction_lifecycle::mempool_rejects_coinbase_transactions, tier6::tier6_coinbase_injection_flood_rejected)
- [ ] ERROR: structural failure via validate_transaction_basic rejected + audited (EXISTS-partial: tier6_oversized; MISSING for privacy_policy branch)
- [ ] ERROR: range-proof verify failure rejected at mempool (MISSING — verify_crypto_for_admission not exercised on real add path in tests/)
- [ ] ERROR: balance-proof verify failure rejected (MISSING)
- [ ] ERROR: ring-signature verify failure rejected, error names failing input index (MISSING)
- [ ] ADVERSARIAL: **a REJECTED tx evicts ZERO residents** — fill pool, submit oversized/too-low-fee/crypto-invalid tx that would need eviction; assert every prior resident still present and current_size unchanged (MISSING — this is the ATOMICITY 2026-08-18 fix; no test covers the simulate-before-mutate guarantee)
- [ ] PROPERTY: after any failed add, `verify_size_invariant()` holds and key_images set unchanged (MISSING)

**`admit_after_checks` — size / dynamic-fee / RBF / eviction**
- [ ] ERROR: size &gt; MAX_TX_SIZE (500_000) → TransactionTooLarge, audited (EXISTS: tier6_oversized_transaction_rejected)
- [ ] ERROR: fee below dynamic min at &lt;25% fullness (1x) → FeeTooLow (EXISTS: tier6_below_minimum_fee_rejected, transaction_lifecycle::mempool_rejects_below_minimum_fee)
- [ ] EDGE: dynamic fee multiplier boundary 25% → 2x required (MISSING — fullness buckets 2x/4x/8x never asserted)
- [ ] EDGE: dynamic fee multiplier 50% → 4x, 75%+ → 8x (MISSING)
- [ ] EDGE: max_size == 0 → fullness_pct 0 path, no divide-by-zero (MISSING)
- [ ] HAPPY: fee exactly equal to min_fee accepted (boundary `&lt;` not `&lt;=`) (MISSING)

**RBF (replace-by-fee)**
- [ ] HAPPY: higher-fee tx with same key image replaces incumbent; pool count stays 1 (EXISTS: adversarial::mempool_allows_rbf_with_fee_bump)
- [ ] ERROR: same-fee duplicate key image rejected, no replacement (EXISTS: adversarial::mempool_rejects_duplicate_keyimage_without_fee_bump, mempool_ordering::test_key_image_conflict_rejected)
- [ ] EDGE: **exact 125% bump accepted** (cross-multiply `lhs&gt;=rhs`, the Phase-D rounding fix) (MISSING — only 5x tested; the boundary the fix targets is untested)
- [ ] EDGE: 124% bump rejected (just under threshold) (MISSING)
- [ ] EDGE: new_fee_rate &gt; old_fee_rate required even when `lhs&gt;=rhs` (equal rate at rate=1 rejected — the "silently allowed no-bump at fee_rate=1" bug) (MISSING)
- [ ] ADVERSARIAL: RBF on absolute fee vs fee-rate — a larger tx with higher absolute fee but LOWER fee-per-byte must NOT replace (RBF keys on fee_per_byte). Assert semantics explicitly (MISSING — the caller asked specifically for RBF absolute-fee behavior)
- [ ] ADVERSARIAL: one tx conflicting on MULTIPLE key images collects ALL conflicts into to_replace, dedups, replaces every one (MISSING — the BUG-12 multi-conflict loop)
- [ ] PROPERTY: after any RBF, no two mempool txs share a key image (invariant) (MISSING)
- [ ] ADVERSARIAL: RBF where replacement itself fails a later check leaves incumbent intact (rejected-evicts-nothing applied to RBF) (MISSING)

**Eviction (`evict_lowest_fee` + admission eviction loop)**
- [ ] HAPPY: higher-fee tx evicts lowest-fee resident when full (EXISTS: mempool_ordering::test_eviction_at_capacity)
- [ ] ADVERSARIAL: low-fee tx meeting dynamic floor must NOT evict a strictly-higher-fee-rate resident (#88 fix) (EXISTS: mempool_ordering::low_fee_tx_does_not_evict_higher_fee_resident_issue_88)
- [ ] EDGE: eviction candidate whose fee_rate &gt;= incoming breaks loop (by_fee ascending stop condition) (EXISTS-partial via issue_88; MISSING as direct assertion of the `cand_fee_rate &gt;= new_fee_rate` break)
- [ ] ERROR: incoming tx cannot fit even after MAX_EVICTION_ATTEMPTS (100) → MempoolFull, pool untouched (MISSING — the 100-attempt budget &amp; up-front reject)
- [ ] ADVERSARIAL: attacker cannot evict &gt;100 residents per oversized send (the pre-fix exploit) (MISSING)
- [ ] EDGE: evict when incoming equals total capacity boundary (`current+size &gt; max`) (MISSING)
- [ ] PROPERTY: after eviction loop, current_size &lt;= max_size OR tx rejected; invariant holds (MISSING)

**`remove`**
- [ ] HAPPY: remove existing tx returns Some(tx), clears key_images, by_fee, decrements size (EXISTS-implicit: test_remove_confirmed_cleans_state, test_size_invariant)
- [ ] EDGE: remove non-existent hash returns None, no state change (MISSING)
- [ ] PROPERTY: current_size uses saturating_sub, never underflows (MISSING)

**`remove_confirmed` (2-pass: confirmed drop + shadow-conflict evict)**
- [ ] HAPPY: confirmed txs removed from mempool (EXISTS: tier6_confirmed_txs_removed_from_mempool, tier10 line 359, transaction_lifecycle, test_remove_confirmed_cleans_state)
- [ ] ADVERSARIAL: shadow conflict — mempool tx_B shares key image with confirmed tx_A (never in our mempool) is evicted with DoubleSpend reason (MISSING — the core anti-chain-stall behavior; pass-2 untested)
- [ ] EDGE: confirmed tx also present in mempool doesn't double-count / pass-2 finds nothing after pass-1 removed it (MISSING)
- [ ] EDGE: multiple confirmed txs, dedup of conflicting_hashes (MISSING)
- [ ] PROPERTY: audit log records Confirmed vs DoubleSpend reasons correctly (MISSING)

**`shadow_evict_invalid`**
- [ ] HAPPY: no invalid txs → early return, nothing evicted (MISSING as direct)
- [ ] ADVERSARIAL: tx that now fails chain.validate_transaction (hard-fork rule / reorg) evicted (MISSING — only referenced in cycle_01 regression comment, not behaviorally tested with a fake ShadowEvictChain)
- [ ] EDGE: ShadowEvictChain fake impl drives eviction of a subset while keeping valid ones (MISSING — trait explicitly designed for test fakes, no fake exists in tests/)
- [ ] PROPERTY: evicted set = exactly those failing validate; size invariant holds after (MISSING)

**`get_block_transactions` (template selection)**
- [ ] HAPPY: returns highest-fee-first ordering (EXISTS: mempool_ordering::test_highest_fee_mined_first)
- [ ] EDGE: empty mempool → empty vec (EXISTS: test_empty_mempool)
- [ ] EDGE: max_count bound respected — never returns more than max_count (EXISTS-partial: test_highest_fee_mined_first uses max_count 1)
- [ ] EDGE: max_size (bytes) bound respected — total_size never exceeds max_size (MISSING as direct assertion)
- [ ] ADVERSARIAL: **never includes two txs conflicting on a key image** — selected_key_images HashSet skips the conflict (MISSING — the O(1) conflict-detection branch untested)
- [ ] EDGE: a tx skipped for size does not block a later smaller tx (continue vs break) (MISSING)
- [ ] PROPERTY: result is a subset of mempool, fee-descending, size≤max, count≤max, key-image-disjoint (MISSING — single combined property test)

**`expire_old` / `expire_old_transactions` / `set_height`**
- [ ] HAPPY: tx older than max_age_secs evicted, count returned (EXISTS: mempool_ordering::test_expire_old_transactions)
- [ ] EDGE: expire_old(0) expires everything with nonzero age (EXISTS-implicit: test_size_invariant calls expire_old(0))
- [ ] EDGE: set_height beyond TX_EXPIRY_BLOCKS (288) evicts by height_added (MISSING — height-based expiry path distinct from time-based)
- [ ] EDGE: saturating_sub on height (height_added &gt; current_height, reorg) no panic (MISSING)
- [ ] PROPERTY: expired entries audited with Expired reason (MISSING)

**`fee_percentiles`**
- [ ] HAPPY: p25/p50/p75/p90 computed from sorted by_fee keys (MISSING)
- [ ] EDGE: empty mempool returns MIN_FEE_PER_BYTE for all, count 0 (MISSING)
- [ ] EDGE: single tx — all percentiles equal, idx clamped to n-1 (MISSING)
- [ ] EDGE: percentile floor at MIN_FEE_PER_BYTE (`.max(min_fee)`) (MISSING)
- [ ] PROPERTY: p25 ≤ p50 ≤ p75 ≤ p90 always (MISSING)

**`save_to_disk` / `load_from_disk` (persistence)**
- [ ] ROUND-TRIP: **save N txs → load → all N restored and queryable** (MISSING — the caller's explicit gap; no save→load round-trip test exists anywhere. cycle_01 only mentions save in a shutdown-ordering comment)
- [ ] EDGE: empty mempool save removes stale mempool.dat, returns 0 (MISSING)
- [ ] EDGE: save writes .tmp then atomic-renames; partial .tmp ignored on load (MISSING — atomic-write crash-safety branch)
- [ ] EDGE: load on missing file returns Ok(0) (MISSING as direct)
- [ ] EDGE: load with empty-Vec file returns 0, deletes file (EXISTS: load_from_disk_tests::load_from_disk_accepts_empty_vec)
- [ ] ERROR: oversized file (&gt;MAX_MEMPOOL_BYTES) rejected at stat(), file removed, no fail-loop (EXISTS: load_from_disk_tests::load_from_disk_rejects_oversized_file)
- [ ] ADVERSARIAL: file with Vec length &gt; MAX_MEMPOOL_TXS (100_000) rejected (MISSING — acknowledged skipped in test comment; the `&gt; MAX_MEMPOOL_TXS` branch is untested)
- [ ] ADVERSARIAL: crafted borsh bytes (huge length prefix, truncated payload) fails cleanly as SerializationError, file already deleted (MISSING)
- [ ] EDGE: load calls add() per tx → invalid/conflicting silently skipped, loaded count &lt; file count (MISSING)
- [ ] ADVERSARIAL: file deleted even when borsh parse fails mid-way (avoid stale replay) (MISSING)

**`remove_conflicts`**
- [ ] HAPPY: removes txs whose key image is in supplied list (MISSING — public fn, zero tests)
- [ ] EDGE: empty key_images list → no removals (MISSING)

**`contains_key_image` / `contains` / `get` / `len` / `size` / `is_empty` / `clear` / `stats`**
- [ ] HAPPY: contains_key_image true after add, false after remove (MISSING as direct)
- [ ] HAPPY: clear empties transactions/by_fee/key_images and zeroes current_size (EXISTS: tier6_mempool_clear_removes_all — note clear() does NOT reset audit_log; assert that)
- [ ] EDGE: stats totals fee across entries, reports size/max/count (MISSING)
- [ ] PROPERTY: verify_size_invariant true after arbitrary add/remove/evict sequence (EXISTS-partial: test_size_invariant; MISSING as randomized property)

**Audit log**
- [ ] HAPPY: TxAdded / TxRejected / TxRemoved events recorded with correct reason (MISSING)
- [ ] EDGE: log capped at AUDIT_LOG_CAPACITY (4096), oldest dropped (MISSING)
- [ ] EDGE: clear_audit_log empties log without touching txs (MISSING)
- [ ] ADVERSARIAL: reject() maps each Error variant to correct low-cardinality metric label (MISSING)

**`unix_now` monotonic clamp**
- [ ] EDGE: never returns value below last-seen (NTP step-back doesn't mark entries ancient) (MISSING — the documented clock-hiccup fix)

**`retry_stable_admission` (generation guard)**
- [ ] HAPPY/EDGE: retries when generation changes before commit, then succeeds (EXISTS: generation_tests::retries_when_generation_changes_before_commit)
- [ ] ERROR: bounded at MAX_CHAIN_GENERATION_ATTEMPTS (4) then InvalidState (EXISTS: generation_tests::generation_retries_are_bounded)
- [ ] EDGE: stable_generation returns None (updating) → yields and continues (MISSING as direct)

**`SharedMempool` wrappers + `add_with_chain` / `restore_orphaned`**
- [ ] HAPPY: add_with_chain runs cheap precheck then full validator then add (EXISTS: cycle_01::regression_finding_01_mempool_calls_full_validator_at_admission)
- [ ] ERROR: add_with_chain rejects coinbase / structural / privacy before chain validator (MISSING — cheap-first ordering branch)
- [ ] ADVERSARIAL: restore_orphaned re-admits orphaned txs, drops those superseded on new fork; returns restored count (MISSING)
- [ ] EDGE: SharedMempool concurrency — Arc&lt;RwLock&gt; add/read under contention preserves invariant (MISSING)
- [ ] EDGE: oldest_timestamp / total_fees / get_all wrappers (MISSING)

### src/transaction/types.rs

**`Transaction::hash`**
- [ ] HAPPY: deterministic — same tx → same hash (EXISTS: types::tests::test_transaction_hash_determinism)
- [ ] ROUND-TRIP: hash stable across borsh serialize→deserialize (EXISTS: transaction_lifecycle::tx_hash_stable_across_borsh_roundtrip)
- [ ] PROPERTY: any field change → different hash (injectivity) (MISSING as property; version covered below)

**`Transaction::size`**
- [ ] HAPPY: returns borsh byte length (MISSING as direct)
- [ ] PROPERTY: size == borsh::to_vec(tx).len() for arbitrary txs (MISSING)

**`is_coinbase` / `key_images` / counts**
- [ ] HAPPY: is_coinbase true for Coinbase type (EXISTS: types::tests::test_coinbase_detection)
- [ ] HAPPY: key_images collects one per input (MISSING as direct)
- [ ] EDGE: TxType variants distinct (EXISTS: test_tx_type_variants)

**`signing_hash` / `compute_signing_hash`**
- [ ] PROPERTY: signer path (from_parts) == verifier path (from_txinput) byte-identical preimage (MISSING — critical sign/verify no-drift, only implicitly via full build+verify)
- [ ] EDGE: version byte covered (EXISTS: types::tests::test_version_bytes_affect_signing_hash)
- [ ] ADVERSARIAL: Some(0) lock_height vs None produce different signing hash (the explicit-tag branch) (MISSING)
- [ ] ADVERSARIAL: length-prefixing prevents field-reshuffle collision (move bytes between encrypted_amount/memo) (MISSING)
- [ ] ADVERSARIAL: extra bytes covered by signing_hash — mutating extra invalidates signature (MISSING — the documented with_extra sign/verify fix)
- [ ] ROUND-TRIP: signing_hash stable across borsh round-trip (EXISTS: transaction_lifecycle line 276)

**Borsh de/serialization of Transaction/TxInput/TxOutput/TxType**
- [ ] ROUND-TRIP: full Transaction borsh round-trip equals original (EXISTS: transaction_lifecycle::tx_hash_stable_across_borsh_roundtrip does serialize+deserialize)
- [ ] ADVERSARIAL: truncated / trailing-garbage / wrong-enum-discriminant bytes fail to decode cleanly, no panic (EXISTS-partial: fuzz_protocol.rs, p2p_adversarial.rs decode fuzzing — verify Transaction specifically covered; MISSING for TxType out-of-range discriminant)
- [ ] ADVERSARIAL: TxOutput with multi-GB encrypted_amount/memo length prefix rejected/bounded (MISSING)

### src/transaction/builder.rs

**`TransactionBuilder::build` (happy path)**
- [ ] HAPPY: full transfer with real CLSAG + BP+ builds, verifies, admits to mempool (EXISTS-likely: full_pipeline_real_crypto.rs / transaction_lifecycle — confirm it drives builder)
- [ ] ERROR: non-coinbase with no inputs → InvalidInputCount (MISSING as direct)
- [ ] ERROR: no outputs → InvalidOutputCount (MISSING as direct)
- [ ] ERROR: unbalanced (input_sum != output_sum + fee) → TransactionUnbalanced (MISSING)
- [ ] ADVERSARIAL: input_sum overflow → AmountOverflow (checked_add, M-1 fix) (MISSING)
- [ ] ADVERSARIAL: output_sum + fee overflow → AmountOverflow (MISSING)
- [ ] EDGE: memo attached only to first recipient output with known view key, skips dummies (MISSING)
- [ ] EDGE: pseudo-output blindings sum to output blindings (balance) for n inputs; n=1 special-case (MISSING)
- [ ] ROUND-TRIP: built tx's signing hash matches Transaction::signing_hash (sign==verify) (MISSING as direct assertion)

**`add_input_at_position` / `add_input_random_position`**
- [ ] ERROR: ring_size &lt; 2 → InvalidRingSize (MISSING)
- [ ] ERROR: real_position &gt;= ring_size → InvalidRingSize (MISSING)
- [ ] EDGE: real output placed at exact position, decoys fill rest; ring_refs match clsag_ring (MISSING)
- [ ] ERROR: too few decoys for ring size → InvalidRingSize mid-loop (MISSING)
- [ ] ADVERSARIAL: invalid decoy public key / commitment point → CryptoError not panic (A6 fix) (MISSING)
- [ ] PROPERTY: random position uniformly in 0..ring_size (MISSING)

**`add_output` / `add_output_ext` / `add_change` / `add_dummy_output`**
- [ ] ERROR: outputs at MAX_TX_OUTPUTS (16) → InvalidOutputCount (MISSING)
- [ ] ERROR: amount &lt; MIN_OUTPUT_AMOUNT (1_000_000) → OutputTooSmall (MISSING)
- [ ] ADVERSARIAL: invalid recipient view public key → CryptoError not panic (A6-STEALTH) (MISSING)
- [ ] EDGE: blinding derived deterministically from ECDH (recipient reconstructs same) (EXISTS-partial: amount roundtrip; MISSING for blinding match)
- [ ] EDGE: is_subaddress=true uses R=r*D_i form (MISSING)
- [ ] EDGE: add_dummy_output silently skips at output limit, else amount-0 valid commitment (MISSING)

**`calculate_min_fee` / `set_fee` / `with_extra` / `with_target_height`**
- [ ] HAPPY: min_fee &gt; 0 (EXISTS: builder::tests::test_calculate_min_fee)
- [ ] EDGE: with_target_height sets tx_version via block_version_at_height (MISSING)
- [ ] EDGE: with_extra populates extra AND is covered by signing hash (MISSING — cross-ref types)

**`encrypt_amount` / `decrypt_amount` / `compute_view_tag`**
- [ ] ROUND-TRIP: amount encrypt→decrypt equals original (EXISTS: builder::tests::test_amount_encryption_roundtrip)
- [ ] EDGE: decrypt with wrong length (!=8) → None (MISSING)
- [ ] EDGE: encrypt with invalid view point → vec![0u8;8] fallback (MISSING)
- [ ] HAPPY: view tag sender==receiver, output_index affects tag (EXISTS: builder::tests::test_view_tag_generation)

**`SimpleTransactionBuilder` (deprecated)**
- [ ] HAPPY: construct-and-build wiring (EXISTS: builder::tests::test_simple_builder)
- [ ] ERROR: no outputs → InvalidOutputCount (MISSING)

### src/transaction/validator.rs — `validate_transaction`

- [ ] HAPPY: coinbase passes structural validation (EXISTS: validator::tests::test_coinbase_passes_structural_validation)
- [ ] ERROR: version != 1 → InvalidTxVersion (EXISTS: validator::tests::test_invalid_version_rejected; property_invariants_validator likely)
- [ ] ERROR: empty outputs → InvalidOutputCount (EXISTS: validator::tests::test_empty_outputs_rejected)
- [ ] ERROR: size &gt; MAX_TX_SIZE → TransactionTooLarge (MISSING as direct)
- [ ] ERROR: size &lt; MIN_TX_SIZE (100) non-coinbase → TransactionTooSmall (MISSING)
- [ ] ERROR: inputs &gt; MAX_TX_INPUTS (256) → InvalidInputCount (MISSING)
- [ ] ERROR: outputs &gt; MAX_TX_OUTPUTS (16) → InvalidOutputCount (MISSING)
- [ ] EDGE: lock_height &lt;= height+525_960 accepted; &gt; rejected (EXISTS: property_invariants_validator lock_height prop for accept side; MISSING explicit reject-far-future)
- [ ] ADVERSARIAL: duplicate key image within one tx → DuplicateKeyImage (MISSING at this layer — acknowledged skipped in property_invariants_validator comment; deferred to in-crate/consensus)
- [ ] EDGE: young chain (&lt;10_000) ring 2..target accepted; ≥10_000 exact target required (MISSING)
- [ ] ERROR: ring_members len mismatch signature.ring_size() → InvalidSignature (MISSING)
- [ ] ERROR: signature.key_image != input.key_image bytes → InvalidSignature (MISSING)
- [ ] ERROR: fee &lt; size*MIN_FEE_PER_BYTE non-coinbase → FeeTooLow (MISSING as direct)
- [ ] ERROR: range_proof.len() &gt; MAX_TX_SIZE → RangeProofInvalid (EXISTS: property_invariants_validator::huge_range_proof_rejected)
- [ ] ADVERSARIAL: **extra.len() &gt; 256 rejected** → InvalidMessage (EXISTS: property_invariants_validator::extra_too_large_rejected)
- [ ] EDGE: empty extra accepted (EXISTS: property_invariants_validator::empty_extra_is_accepted)
- [ ] ADVERSARIAL: **non-empty extra that isn't valid RecoveryMeta rejected on consensus path** → InvalidTransaction("invalid recovery metadata") (MISSING — the caller's explicit gap; validate_recovery_extra failure branch inside validate_transaction untested)

### src/transaction/recovery.rs

**`RecoveryMeta::encode` / `decode`**
- [ ] ROUND-TRIP: encode→decode equals original, len == 42 (EXISTS: recovery::tests::encode_decode_round_trip)
- [ ] EDGE: decode slice too short → None (MISSING as direct)
- [ ] EDGE: decode wrong tag byte → None (MISSING)

**`decode_all` / `encode_all`**
- [ ] HAPPY: two entries round-trip in order (EXISTS: recovery::tests::decode_all_from_extra)
- [ ] ADVERSARIAL: extra with non-recovery bytes interleaved — scanner skips junk, decodes valid tags (MISSING — the pos+=1 skip branch vs pos+=42)
- [ ] ADVERSARIAL: truncated final entry (tag present but &lt; 42 bytes remaining) not decoded, no panic (MISSING — the `pos + SIZE &lt;= len` guard)
- [ ] ADVERSARIAL: RECOVERY_TAG byte appearing inside a valid entry's address/timeout not misparsed as new entry (framing ambiguity — decode_all advances by fixed 42) (MISSING — real risk: 0xDE inside address)

**`validate` / `validate_recovery_extra`**
- [ ] ERROR: output_index &gt;= output_count → Err (EXISTS: recovery::tests::validate_rejects_bad_index, phase1::recovery_bad_index_rejected)
- [ ] ERROR: timeout &lt; MIN_RECOVERY_TIMEOUT (720) → Err (EXISTS: recovery::tests::validate_rejects_bad_timeout, phase1::recovery_short_timeout_rejected)
- [ ] ERROR: timeout &gt; MAX_RECOVERY_TIMEOUT (525_960) → Err (EXISTS: validate_rejects_bad_timeout)
- [ ] ERROR: zero recovery_address → Err (EXISTS: recovery::tests::validate_rejects_zero_address, phase1::recovery_zero_address_rejected)
- [ ] HAPPY: valid entry passes (EXISTS: phase1::valid_recovery_passes)
- [ ] ADVERSARIAL: duplicate output_index across entries → Err (EXISTS: recovery::tests::validate_rejects_duplicate_indices)
- [ ] EDGE: empty extra valid (EXISTS: recovery::tests::empty_extra_is_valid)
- [ ] EDGE: timeout exactly MIN and exactly MAX accepted (boundary) (MISSING)

**`is_recovery_eligible`**
- [ ] HAPPY/EDGE: not eligible below timeout, eligible at exactly timeout and above (EXISTS: recovery::tests::recovery_eligibility)
- [ ] EDGE: saturating_sub when creation_height &gt; current_height (reorg) → not eligible, no panic (MISSING)

### src/mining/template.rs

**`build_template_json`**
- [ ] HAPPY: template packs fee-sorted mempool txs, JSON has height/prev_hash/target/transactions (MISSING — build_template_json has NO integration test)
- [ ] ADVERSARIAL: **assembled block never exceeds MAX_BLOCK_SIZE** — budget = MAX_BLOCK_SIZE - COINBASE_HEADROOM enforced (MISSING)
- [ ] ADVERSARIAL: **never includes key-image-conflicting txs** (inherited from get_block_transactions) (MISSING)
- [ ] ADVERSARIAL: chain-invalid tx (immature coinbase / time-locked ring member) filtered via chain.validate_transaction (the 2026-05-08 poison-template fix) (MISSING)
- [ ] EDGE: congestion floor (b) — low-fee tx past a bucket boundary excluded, not breaking the loop (later smaller tx still considered) (MISSING)
- [ ] EDGE: fixpoint loop drops txs that fall under the FINAL congestion bucket; converges (MISSING — the second-pass shrink loop)
- [ ] EDGE: timestamp bumped to at least prev+1 after stall (MISSING)
- [ ] EDGE: count bound 4096 respected (MISSING)
- [ ] PROPERTY: emitted template always passes validate_block's floor by construction (no poison template) (MISSING)

**`dynamic_min_fee` / `congestion_pct_for_size`**
- [ ] PROPERTY: builder floor bit-identical to validator across bucket boundaries (EXISTS: congestion_packing_tests::builder_and_validator_use_identical_floor)
- [ ] PROPERTY: congestion_pct matches validator u128 formula (EXISTS: congestion_packing_tests::congestion_pct_matches_validator_formula)
- [ ] PROPERTY: floor monotonic across buckets (EXISTS: congestion_packing_tests::floor_is_monotonic_across_buckets)
- [ ] ADVERSARIAL: dynamic_min_fee overflow (huge tx_size) → None → tx excluded (MISSING — the checked_mul None branch)

**`BlockTemplate::new` / `update_nonce` / `update_timestamp`**
- [ ] HAPPY: new() copies header fields (supply_commitment, roots, anchor, checkpoint_vote) (MISSING)
- [ ] EDGE: update_nonce / update_timestamp mutate header (MISSING)

---

## Counts

- **Total tests enumerated: 148**
- **EXISTS (full or partial): 42**
- **MISSING: 106**

### Highest-priority MISSING (the caller's named gaps, all currently uncovered)
1. Rejected tx evicts ZERO residents (mempool.rs ATOMICITY fix) — no test.
2. RBF absolute-fee vs fee-rate semantics; exact-125% boundary; equal-rate-at-1 bug — only 5x tested.
3. Template never exceeds size/weight/count and excludes conflicts — `build_template_json` has zero integration tests; only the fee-floor drift unit tests exist.
4. Persistence save→LOAD round-trip actually restores — **no save→load round-trip test exists** anywhere; only oversized-reject and empty-Vec load are covered.
5. Unbounded `extra` / invalid RecoveryMeta rejected on the consensus path — `extra&gt;256` covered, but the `validate_recovery_extra` failure branch inside `validate_transaction` is untested; `decode_all` framing/truncation adversarial cases untested.
6. Borsh round-trips + adversarial decode — Transaction round-trip EXISTS; TxType out-of-range discriminant and oversized length-prefix decode are MISSING.
7. `shadow_evict_invalid` and `remove_confirmed` pass-2 (shadow conflict eviction) — the anti-chain-stall behaviors — have no behavioral test with a fake chain.

Note on structure: the primary `mod tests` in `mempool.rs` is dead (`#[cfg(any())]`), so nearly all mempool coverage runs through the `add_skip_crypto` escape hatch in `tests/`. The real `add()` crypto-verification rejection branches (range proof / balance / ring sig) are therefore effectively untested at the mempool layer.