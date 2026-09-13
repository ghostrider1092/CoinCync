# CoinCync Crypto — Exhaustive Behavioral Test Plan

### src/crypto/clsag.rs

- [x] clsag_sign/clsag_verify — valid signature round-trips (HAPPY) (EXISTS: test_clsag_sign_verify in src/crypto/clsag.rs; ic_084_clsag_roundtrip in tests/ic_crypto.rs)
- [x] clsag_verify — wrong message rejected (ERROR) (EXISTS: test_clsag_sign_verify in src/crypto/clsag.rs)
- [x] clsag_verify — wrong pseudo_output rejected (ERROR) (EXISTS: test_clsag_sign_verify in src/crypto/clsag.rs)
- [x] clsag_verify — responses.len() != ring size rejected (ERROR) (EXISTS: attack_clsag_mismatched_response_count in tests/tier12_crypto_warfare.rs; real_crypto_corrupted_clsag_responses_rejected in tests/full_pipeline_real_crypto.rs)
- [x] clsag_verify — ring size &lt; 2 rejected (ERROR) (EXISTS: monero_linkability_below_minimum_rejected in tests/historical_attacks/monero_ring_linkability.rs)
- [x] clsag_verify — identity key_image rejected (ADVERSARIAL) (EXISTS: monero_2017_zero_key_image_rejected in tests/historical_attacks/monero_2017_key_image.rs)
- [ ] clsag_verify — identity commitment_image rejected (ADVERSARIAL) (MISSING)
- [x] clsag_verify — identity ring-member public_key rejected (R-1) (ADVERSARIAL) (EXISTS: clsag_verify_rejects_identity_ring_public_key in src/crypto/clsag.rs)
- [ ] clsag_verify — identity ring-member commitment rejected (ADVERSARIAL) (MISSING)
- [ ] clsag_verify — non-canonical response scalar rejected (ADVERSARIAL) (MISSING)
- [ ] clsag_verify — non-canonical c1 scalar rejected (ADVERSARIAL) (MISSING)
- [ ] clsag_verify — zero challenge c1 rejected (A6) (ADVERSARIAL) (MISSING)
- [x] clsag_verify — arbitrary forged key image rejected (C-1 malleability) (ADVERSARIAL) (EXISTS: clsag_rejects_arbitrary_forged_key_image in src/crypto/clsag.rs; real_crypto_unbound_key_image_rejected in tests/full_pipeline_real_crypto.rs)
- [x] clsag_verify — tampered commitment_image rejected (ADVERSARIAL) (EXISTS: clsag_verify_rejects_tampered_commitment_image in tests/clsag_commitment_binding.rs)
- [x] clsag_verify — tampered response/challenge rejected (forgery without secret) (ADVERSARIAL) (EXISTS: attack_clsag_forgery_without_secret in tests/tier11_brutal_attacks.rs; real_crypto_corrupted_clsag_rejected in tests/full_pipeline_real_crypto.rs)
- [x] clsag_verify — tampered/bit-flipped key_image rejected (ADVERSARIAL) (EXISTS: real_crypto_corrupted_key_image_rejected in tests/full_pipeline_real_crypto.rs; ic_086_key_image_bit_flip in tests/ic_crypto.rs)
- [x] clsag_verify — swapped ring member rejected (ADVERSARIAL) (EXISTS: real_crypto_swapped_ring_member_rejected in tests/full_pipeline_real_crypto.rs)
- [x] clsag_verify — complete ring forgery rejected (ADVERSARIAL) (EXISTS: real_crypto_complete_ring_forgery_rejected in tests/full_pipeline_real_crypto.rs)
- [x] clsag_sign+verify — signature not replayable across messages (PROPERTY) (EXISTS: attack_clsag_signature_not_replayable_across_messages in tests/tier11_brutal_attacks.rs)
- [x] clsag_verify — constant-time / timing independent of real signer (PROPERTY) (EXISTS: tier9_clsag_verify_timing_independent_of_signer, tier9_invalid_sig_not_faster_than_valid in tests/tier9_timing_sidechannel.rs)
- [ ] clsag_sign — ring size &lt; 2 rejected (ERROR) (MISSING)
- [ ] clsag_sign — real_index &gt;= n rejected (ERROR) (MISSING)
- [ ] clsag_sign — secret key mismatch with ring[real_index] rejected (ERROR) (MISSING)
- [x] KeyImage — same secret ⇒ same key image (linkability) (PROPERTY) (EXISTS: test_key_image_linkability in src/crypto/clsag.rs; attack_key_image_linkability_preserved in tests/tier12_crypto_warfare.rs)
- [x] KeyImage — distinct secrets ⇒ distinct key images (PROPERTY) (EXISTS: test_key_image_uniqueness in src/crypto/clsag.rs; ic_087_key_image_uniqueness in tests/ic_crypto.rs)
- [x] ClsagSignature::to_bytes/from_bytes — round-trips and re-verifies (ROUND-TRIP) (EXISTS: test_clsag_serialization in src/crypto/clsag.rs)
- [x] ClsagSignature::from_bytes — corrupted/garbage bytes rejected without panic (ADVERSARIAL) (EXISTS: ic_094_corrupted_proof_no_panic in tests/ic_crypto.rs)
- [x] simple_ring_sign/verify — valid round-trip and ring_size (HAPPY) (EXISTS: test_simple_ring_signature in src/crypto/clsag.rs)
- [x] simple_ring_verify — wrong message rejected (ERROR) (EXISTS: test_simple_ring_wrong_message in src/crypto/clsag.rs)
- [x] simple_ring_sign/verify — different real_index positions (EDGE) (EXISTS: test_different_real_index in src/crypto/clsag.rs)
- [ ] simple_ring_verify — identity key_image / identity ring member rejected (ADVERSARIAL) (MISSING)
- [ ] simple_ring_verify — non-canonical scalar / zero challenge rejected (ADVERSARIAL) (MISSING)
- [ ] simple_ring_sign — ring size &lt; 2 / real_index out of range rejected (ERROR) (MISSING)

### src/crypto/stealth.rs

- [x] is_output_ours — recipient detects own output (HAPPY) (EXISTS: test_stealth_address_roundtrip in src/crypto/stealth.rs; generated_address_is_detected_by_recipient in tests/property_invariants_stealth.rs)
- [x] is_output_ours — wrong recipient keys ⇒ false (ERROR) (EXISTS: test_stealth_address_wrong_keys in src/crypto/stealth.rs; ic_098_wrong_view_key in tests/ic_crypto.rs)
- [x] is_output_ours — wrong output_idx ⇒ false (EDGE) (EXISTS: test_stealth_address_output_index_matters in src/crypto/stealth.rs; stealth_address_is_output_index_sensitive in tests/property_invariants_stealth.rs)
- [x] is_output_ours — non-curve tx_public ⇒ false (ADVERSARIAL) (EXISTS: is_output_ours_rejects_non_curve_tx_public in tests/property_invariants_stealth.rs)
- [ ] is_output_ours — non-curve stealth.public_key ⇒ false (ADVERSARIAL) (MISSING)
- [ ] is_output_ours — non-curve spend_pub ⇒ false (ADVERSARIAL) (MISSING)
- [x] is_output_ours — deterministic across calls (PROPERTY) (EXISTS: is_output_ours_is_deterministic in tests/property_invariants_stealth.rs)
- [x] generate_stealth_address — each output unique / send↔receive ECDH symmetry (PROPERTY) (EXISTS: test_stealth_addresses_unique in src/crypto/stealth.rs; stealth_addresses_for_same_recipient_are_all_different in tests/crypto_properties.rs)
- [x] generate_stealth_address — different recipients ⇒ unlinkable (PROPERTY) (EXISTS: attack_stealth_addresses_unlinkable in tests/tier12_crypto_warfare.rs; monero_2020_janus_different_wallets_unrelated in tests/historical_attacks/monero_2020_janus.rs)
- [x] compute_one_time_secret — derives to stealth public key (spending equation) (ROUND-TRIP) (EXISTS: test_one_time_secret_derivation in src/crypto/stealth.rs; one_time_secret_satisfies_spending_equation, ic_102_one_time_secret in tests/property_invariants_stealth.rs / tests/ic_crypto.rs)
- [x] compute_one_time_secret — deterministic (PROPERTY) (EXISTS: compute_one_time_secret_is_deterministic in tests/property_invariants_stealth.rs)
- [ ] compute_one_time_secret — invalid tx_public_key ⇒ Err (ERROR) (MISSING)
- [x] RecipientKeys::owns — detects owned, rejects wrong index (HAPPY/EDGE) (EXISTS: test_recipient_keys_scanning in src/crypto/stealth.rs)
- [x] RecipientKeys::owns — malformed tx_public identity-forgery rejected, uniform-time path (ADVERSARIAL) (EXISTS: recipient_owns_rejects_malformed_tx_public_forgery in src/crypto/stealth.rs)
- [x] RecipientKeys::scan_outputs — batch scan returns all owned indices (HAPPY) (EXISTS: test_batch_scanning in src/crypto/stealth.rs; ic_101_batch_scan_correct in tests/ic_crypto.rs)
- [ ] RecipientKeys::new — invalid spend public ⇒ Err (ERROR) (MISSING)
- [x] ViewOnlyScanner::scan — main-address output detected with amount (HAPPY) (EXISTS: test_view_only_scanner in src/crypto/stealth.rs)
- [x] ViewOnlyScanner — subaddress output detected via scanner (HAPPY) (EXISTS: test_regression_subaddress_scanner_detection in tests/regression_critical.rs)
- [x] StealthAddress::to_hex/from_hex — round-trips (ROUND-TRIP) (EXISTS: test_hex_serialization in src/crypto/stealth.rs)
- [ ] StealthAddress::from_hex — wrong length rejected (ERROR) (MISSING)
- [ ] StealthAddress::from_hex — non-curve point rejected (ERROR) (MISSING)
- [ ] StealthAddress::from_bytes_checked — invalid/identity point ⇒ None (ADVERSARIAL) (MISSING)
- [ ] StealthAddress::to_bytes/from_bytes — round-trips (ROUND-TRIP) (MISSING)
- [x] StealthAddress methods (is_ours / compute_spending_key) (HAPPY) (EXISTS: test_stealth_address_methods in src/crypto/stealth.rs)
- [x] coinbase_stealth_address — unique per height/output (miner_secret bound) (PROPERTY) (EXISTS: test_regression_coinbase_stealth_uniqueness in tests/regression_critical.rs)
- [ ] coinbase_stealth_address — invalid view/spend public ⇒ Err (ERROR) (MISSING)
- [x] Subaddress::generate — distinct spend &amp; view keys vs main (HAPPY) (EXISTS: test_subaddress_generation in src/crypto/stealth.rs)
- [x] Subaddress — view keys unlinkable across subs and output detectable (PROPERTY) (EXISTS: subaddress_view_keys_are_unlinkable_and_output_is_detectable in src/crypto/stealth.rs; monero_2020_janus_subaddresses_unlinkable in tests/historical_attacks/monero_2020_janus.rs)
- [x] Subaddress — distinct spend keys across indices (no collision) (PROPERTY) (EXISTS: test_subaddress_collision in src/crypto/stealth.rs)
- [ ] Subaddress::generate — invalid spend public ⇒ Err (ERROR) (MISSING)
- [ ] subaddress_scalar — deterministic &amp; domain-separated derivation (PROPERTY) (MISSING)
- [x] generate_stealth_address_for — selects R=r·D_i vs R=r·G by address type (HAPPY) (EXISTS: generate_stealth_address_for_selects_form_by_address_type in src/crypto/stealth.rs)
- [ ] generate_stealth_address_checked — invalid spend/view keys ⇒ Err (ERROR) (MISSING)
- [ ] generate_stealth_outputs — &gt;255 recipients rejected (idx wraparound) (ERROR) (MISSING)
- [x] AuditKey::is_in_range — start/end bounds (EDGE) (EXISTS: test_audit_key in src/crypto/stealth.rs)
- [x] AuditKey::export/import — round-trips (ROUND-TRIP) (EXISTS: test_audit_key in src/crypto/stealth.rs)
- [x] AuditKey::to_scanner — multi-account subaddress sweep finds nonzero-account output, account-0-only misses (HAPPY/EDGE) (EXISTS: audit_key_multi_account_scan_finds_nonzero_account_subaddress in src/crypto/stealth.rs)
- [x] StealthIndex — index_outputs / lookup / len (HAPPY) (EXISTS: test_stealth_index in src/crypto/stealth.rs)
- [ ] SubaddressManager — next/get_or_generate caches &amp; increments (HAPPY) (MISSING)

### src/crypto/bulletproofs.rs

- [x] PedersenCommitment::commit + verify_commitment — opens to value (HAPPY) (EXISTS: test_commitment_creation in src/crypto/bulletproofs.rs)
- [x] verify_commitment — wrong amount ⇒ false (ERROR) (EXISTS: test_commitment_creation in src/crypto/bulletproofs.rs)
- [x] from_bytes_unchecked — non-canonical wedge state (bytewise-eq but decompress-fails) (ADVERSARIAL) (EXISTS: test_regression_pedersen_commitment_from_bytes_unchecked in tests/regression_critical.rs)
- [ ] from_bytes_checked — valid accepted / non-canonical ⇒ None (ERROR) (MISSING)
- [x] checked_add — homomorphic (C1+C2 = commit(v1+v2,b1+b2)) (PROPERTY) (EXISTS: pedersen_commitment_is_homomorphic in tests/crypto_properties.rs; attack_pedersen_homomorphism_no_overflow in tests/tier12_crypto_warfare.rs)
- [ ] checked_add/checked_sub — invalid point operand ⇒ None (ERROR) (MISSING)
- [ ] Add operator (H7) — invalid point ⇒ identity fallback (no panic) (EDGE) (MISSING)
- [x] create_range_proof/verify_range_proof — valid amount round-trips (HAPPY) (EXISTS: test_create_and_verify_range_proof in src/crypto/bulletproofs.rs; range_proof_valid_amount_verifies in tests/crypto_properties.rs)
- [x] verify_range_proof — wrong commitment ⇒ false (ERROR) (EXISTS: test_wrong_commitment_fails in src/crypto/bulletproofs.rs; range_proof_wrong_commitment_fails in tests/crypto_properties.rs)
- [x] verify_range_proof — empty proof ⇒ false (EDGE) (EXISTS: test_empty_proof in src/crypto/bulletproofs.rs; real_crypto_empty_range_proof_rejected in tests/full_pipeline_real_crypto.rs; zcash_2018_empty_proof_rejected in tests/historical_attacks/zcash_2018_proof_forgery.rs)
- [x] range proof — u64::MAX / large value (EDGE) (EXISTS: test_range_proof_prevents_overflow in src/crypto/bulletproofs.rs; range_proof_at_u64_max in tests/crypto_adversarial_corpora.rs)
- [x] range proof — zero amount (EDGE) (EXISTS: range_proof_zero_amount_verifies in tests/crypto_properties.rs; zero_amount_proof_verifies in tests/phase1_critical.rs)
- [x] range proof — power-of-2 and 2^n-1 boundaries (EDGE) (EXISTS: range_proof_at_power_of_2_boundaries, range_proof_at_power_of_2_minus_1 in tests/crypto_adversarial_corpora.rs)
- [x] create_aggregated_range_proof/verify_range_proofs — multi-output round-trip (HAPPY) (EXISTS: test_aggregated_proof in src/crypto/bulletproofs.rs; aggregated_range_proof_multi_output_verifies in tests/crypto_properties.rs)
- [x] aggregated proof — non-power-of-2 (3/5) padding verifies (EDGE) (EXISTS: test_aggregated_proof_three_outputs, test_aggregated_proof_five_outputs, test_power_of_2_padding_boundary in src/crypto/bulletproofs.rs)
- [ ] create_aggregated_range_proof — amounts.len() != blindings.len() ⇒ Err (ERROR) (MISSING)
- [ ] create_aggregated_range_proof — empty amounts ⇒ empty proof (EDGE) (MISSING)
- [ ] create_aggregated_range_proof — &gt; MAX_AGGREGATION ⇒ Err (ERROR) (MISSING)
- [ ] verify_range_proofs — empty commitments ⇔ empty-proof-only accepted (EDGE) (MISSING)
- [x] verify_range_proof — truncated/corrupted proof rejected without panic (ADVERSARIAL) (EXISTS: attack_truncated_range_proof_rejected in tests/tier12_crypto_warfare.rs; ic_093_truncated_proof_no_panic in tests/ic_crypto.rs; real_crypto_corrupted_range_proof_rejected in tests/full_pipeline_real_crypto.rs)
- [x] RangeProof::try_to_bytes/from_bytes — round-trip (ROUND-TRIP) (EXISTS: test_proof_serialization in src/crypto/bulletproofs.rs)
- [x] range proof — not portable across commitments / only proves committed value (ADVERSARIAL) (EXISTS: attack_bulletproof_only_proves_committed_value in tests/tier12_crypto_warfare.rs; tier10_range_proof_not_portable in tests/tier10_integration_adversarial.rs)
- [x] verify_range_proof_dispatch — BP+ active at height accepts v3 (HAPPY) (EXISTS: test_height_dispatch_creation, test_bp_plus_single_proof in src/crypto/bulletproofs.rs)
- [ ] verify_range_proofs_dispatch — wrong version for height gated off (C-2) (ADVERSARIAL) (MISSING)
- [x] verify_range_proof_bp_plus — wrong commitment ⇒ false (ERROR) (EXISTS: test_bp_plus_wrong_commitment_fails in src/crypto/bulletproofs.rs)
- [ ] verify_coinbase_output — zero-blinding commitment match/mismatch (HAPPY/ERROR) (MISSING)
- [ ] BlindingFactor — zeroize-on-drop wipes scalar (PROPERTY) (MISSING)
- [ ] BlindingFactor — add/sub/zero scalar arithmetic (HAPPY) (MISSING)

### src/crypto/ring_selection.rs

- [x] select_decoys — happy path: correct count, excludes real, unique keys, position in range (HAPPY) (EXISTS: test_ring_selection in src/crypto/ring_selection.rs)
- [x] select_decoys — pool smaller than decoy_count ⇒ InvalidRingSize (ERROR) (EXISTS: duplicate_public_keys_pool_rejected_structurally in src/crypto/ring_selection.rs)
- [ ] select_decoys — ring_size &lt; 2 rejected (no underflow) (ERROR) (MISSING)
- [ ] select_decoys — eligible &lt; decoy_count after age filter ⇒ Err (ERROR) (MISSING)
- [x] select_decoys — never selects the real output (ADVERSARIAL) (EXISTS: test_ring_selection in src/crypto/ring_selection.rs)
- [x] RingSelectionPool / select_decoys — duplicate public keys deduplicated, full-key distinguishes shared prefixes (PROPERTY) (EXISTS: duplicate_public_keys_pool_rejected_structurally, full_public_key_distinguishes_shared_u64_prefixes in src/crypto/ring_selection.rs)
- [x] select_decoys — assembler draws uniformly (no double age-bias) over supplied pool (PROPERTY) (EXISTS: test_ring_assembly_is_uniform_over_supplied_pool in src/crypto/ring_selection.rs)
- [ ] select_decoys — young real output relaxes effective_min_age (BUG-5) (EDGE) (MISSING)
- [ ] is_eligible_decoy — min/max decoy age bounds enforced (EDGE) (MISSING)
- [x] verify_ring_quality — produces report for a ring (HAPPY) (EXISTS: test_ring_quality_check in src/crypto/ring_selection.rs)
- [ ] verify_ring_quality — real-age outlier / duplicate-commitment issues flagged (ADVERSARIAL) (MISSING)

Note: the wallet-side pool policy (never picks spent/immature/locked outputs, gamma distribution) is enforced in src/wallet/decoy_selection and covered there (EXISTS: gamma_sampling_is_conditioned_and_unique, lock_height_is_checked_at_the_next_spend_height, minimum_age_is_measured_at_the_next_spend_height, allocation_excludes_identity_point_decoys, allocation_rejects_real_identity_mismatch in src/wallet/decoy_selection/tests.rs); ring_selection.rs itself only enforces real-exclusion and age.

### src/crypto/view_keys.rs

- [x] ViewKey::derive — deterministic key_data &amp; watermark (PROPERTY) (EXISTS: test_view_key_derivation_determinism in src/crypto/view_keys.rs)
- [x] ViewKey::derive — different epochs ⇒ different key_data (PROPERTY) (EXISTS: test_view_key_different_epochs_differ in src/crypto/view_keys.rs; ic_099_forward_secrecy_old_epoch, ic_100_forward_secrecy_new_epoch in tests/ic_crypto.rs)
- [x] is_valid_for_epoch — EpochOnly and TimeRange in/out of range (HAPPY/EDGE) (EXISTS: test_view_key_epoch_validity in src/crypto/view_keys.rs)
- [x] is_valid_for_epoch — fail-closed (false) for AmountCapped/SingleUse (ADVERSARIAL) (EXISTS: is_valid_for_epoch_is_failclosed_for_stateful_scopes in src/crypto/view_keys.rs)
- [x] authorize_scan — AmountCapped consumes budget, denies over-cap (EDGE/ERROR) (EXISTS: is_valid_for_epoch_is_failclosed_for_stateful_scopes in src/crypto/view_keys.rs)
- [x] authorize_scan — SingleUse fires exactly once (EDGE) (EXISTS: is_valid_for_epoch_is_failclosed_for_stateful_scopes in src/crypto/view_keys.rs)
- [ ] authorize_scan — epoch mismatch ⇒ Err for each scope (ERROR) (MISSING)
- [x] Debug — redacts key_data (PROPERTY) (EXISTS: test_view_key_debug_redacts_key_data in src/crypto/view_keys.rs)
- [x] Serialize — excludes key_data, keeps epoch (PROPERTY) (EXISTS: test_view_key_serialize_excludes_key_data in src/crypto/view_keys.rs)
- [ ] Deserialize — key_data set to 0xEE sentinel (re-derive required) (EDGE) (MISSING)
- [ ] ViewKey — ZeroizeOnDrop wipes key_data (not skipped) (PROPERTY) (MISSING)

### src/crypto/disclosure.rs

- [x] create_balance_proof/verify_balance_proof — valid v ≥ threshold (HAPPY) (EXISTS: test_balance_proof_valid in src/crypto/disclosure.rs)
- [x] balance proof — exact threshold (v−threshold=0) (EDGE) (EXISTS: test_balance_proof_exact_threshold in src/crypto/disclosure.rs)
- [x] create_balance_proof — value &lt; threshold ⇒ Err (ERROR) (EXISTS: test_balance_proof_insufficient in src/crypto/disclosure.rs)
- [x] verify_balance_proof — tampered original_commitment ⇒ false (ADVERSARIAL) (EXISTS: test_balance_proof_wrong_commitment in src/crypto/disclosure.rs)
- [x] verify_balance_proof — identity commitment rejected (ADVERSARIAL) (EXISTS: attack_identity_commitment_in_balance in tests/tier12_crypto_warfare.rs)
- [ ] verify_balance_proof — non-canonical/identity schnorr_r rejected (ADVERSARIAL) (MISSING)
- [x] create_ownership_proof/verify_ownership_proof — valid ownership (HAPPY) (EXISTS: test_ownership_proof_valid in src/crypto/disclosure.rs)
- [x] create_ownership_proof — secret not matching stealth address ⇒ Err (ERROR) (EXISTS: test_ownership_proof_wrong_key in src/crypto/disclosure.rs)
- [x] verify_ownership_proof — tampered message ⇒ false (ADVERSARIAL) (EXISTS: test_ownership_proof_different_message in src/crypto/disclosure.rs)
- [ ] verify_ownership_proof — identity Schnorr R rejected (ADVERSARIAL) (MISSING)
- [x] create_sum_proof/verify_sum_proof — homomorphic total matches (HAPPY) (EXISTS: test_sum_proof_valid in src/crypto/disclosure.rs)
- [x] verify_sum_proof — wrong claimed total ⇒ false (ERROR) (EXISTS: test_sum_proof_wrong_total in src/crypto/disclosure.rs)
- [x] verify_sum_proof — wrong/mismatched commitments ⇒ false (ERROR) (EXISTS: test_sum_proof_wrong_commitments in src/crypto/disclosure.rs)
- [x] sum proof — duplicate output refs rejected + ref/transcript tamper rejected (ADVERSARIAL) (EXISTS: test_sum_proof_rejects_duplicate_outputs_and_ref_tampering in src/crypto/disclosure.rs)
- [ ] create_sum_proof — empty outputs / bad height range ⇒ Err (ERROR) (MISSING)
- [x] create_source_proof/verify_source_proof — valid dual-base Schnorr (HAPPY) (EXISTS: test_source_proof_valid in src/crypto/disclosure.rs)
- [x] create_source_proof — secret/public/key-image mismatch ⇒ Err (ERROR) (EXISTS: test_source_proof_wrong_key in src/crypto/disclosure.rs)
- [x] verify_source_proof — tampered message ⇒ false (ADVERSARIAL) (EXISTS: test_source_proof_tampered_message in src/crypto/disclosure.rs)
- [ ] verify_source_proof — identity R1/R2 rejected (ADVERSARIAL) (MISSING)
- [x] DisclosureProof — from_*/to_json/from_json round-trip (ROUND-TRIP) (EXISTS: test_disclosure_serialization in src/crypto/disclosure.rs)
- [x] DisclosureProof — expiry / expired proof rejected (EDGE) (EXISTS: test_disclosure_expiry, test_expired_proof_rejected in src/crypto/disclosure.rs)
- [x] proofs — domain separation prevents cross-proof forgery (ADVERSARIAL) (EXISTS: test_proofs_domain_separated in src/crypto/disclosure.rs)
- [ ] DisclosureProof::verify() — deprecated unanchored entry hard-fails (ERROR) (MISSING)
- [ ] verify_internal_consistency — Sum type ⇒ Err (requires commitments) (ERROR) (MISSING)
- [x] verify_balance_proof_anchored — Valid / AnchorMismatch / CryptoInvalid (HAPPY/ADVERSARIAL/ERROR) (EXISTS: test_balance_anchored_valid, test_balance_anchored_mismatch_is_the_253_attack, test_balance_anchored_crypto_invalid in src/crypto/disclosure.rs)
- [x] verify_ownership_proof_anchored — Valid / mismatch / wrong output_ref (HAPPY/ADVERSARIAL) (EXISTS: test_ownership_anchored_valid, test_ownership_anchored_mismatch_is_the_253_attack, test_ownership_anchored_rejects_wrong_output_ref in src/crypto/disclosure.rs)
- [x] verify_sum_proof_anchored — Valid and AnchorMismatch (HAPPY/ADVERSARIAL) (EXISTS: test_sum_anchored_valid_and_mismatch in src/crypto/disclosure.rs)
- [x] verify_source_proof_anchored — Valid and AnchorMismatch (key image spent) (HAPPY/ADVERSARIAL) (EXISTS: test_source_anchored_valid_and_mismatch in src/crypto/disclosure.rs)

### src/crypto/memo.rs

- [x] encrypt_memo/decrypt_memo — round-trip (HAPPY) (EXISTS: test_encrypt_decrypt_roundtrip in src/crypto/memo.rs; encrypt_decrypt_roundtrip in tests/property_invariants_memo.rs)
- [x] decrypt_memo — wrong view secret ⇒ Err (ERROR) (EXISTS: test_wrong_key_fails in src/crypto/memo.rs; wrong_view_secret_rejected in tests/property_invariants_memo.rs)
- [x] decrypt_memo — wrong tx_public_key ⇒ Err (ERROR) (EXISTS: wrong_tx_public_rejected in tests/property_invariants_memo.rs)
- [x] encrypt/decrypt — empty memo ⇒ empty (EDGE) (EXISTS: test_empty_memo in src/crypto/memo.rs; encrypt_empty_returns_empty, decrypt_empty_returns_empty in tests/property_invariants_memo.rs)
- [x] encrypt/decrypt — max-size memo round-trips (EDGE) (EXISTS: test_max_size_memo in src/crypto/memo.rs)
- [x] encrypt_memo — oversized memo ⇒ Err (ERROR) (EXISTS: test_oversized_memo_rejected in src/crypto/memo.rs; oversize_memo_rejected in tests/property_invariants_memo.rs)
- [x] decrypt_memo — truncated ciphertext ⇒ Err (ERROR) (EXISTS: test_truncated_ciphertext_fails in src/crypto/memo.rs; truncated_ciphertext_rejected in tests/property_invariants_memo.rs)
- [x] decrypt_memo — bit-flipped ciphertext ⇒ AEAD failure (ADVERSARIAL) (EXISTS: bit_flipped_ciphertext_rejected in tests/property_invariants_memo.rs)
- [x] encrypt_memo — fresh random nonce per encryption, still decrypts (PROPERTY) (EXISTS: encrypt_uses_fresh_nonce_but_decrypts_correctly in tests/property_invariants_memo.rs)
- [x] encrypt_memo — encrypted output size = nonce+len+tag (EDGE) (EXISTS: encrypted_output_has_expected_size in tests/property_invariants_memo.rs)
- [ ] encrypt_memo — invalid recipient view public point ⇒ Err (ERROR) (MISSING)
- [ ] decrypt_memo — non-curve tx_public_key ⇒ Err (ERROR) (MISSING)

### src/crypto/batch_verify.rs

- [x] verify_all — empty batch ⇒ zero totals, all_valid (EDGE) (EXISTS: test_batch_verify_empty in src/crypto/batch_verify.rs)
- [x] verify_all — batch with exactly one invalid reports it in invalid_indices (ADVERSARIAL) (EXISTS: cache_does_not_reuse_result_for_different_pseudo_output in src/crypto/batch_verify.rs)
- [x] verify_single — valid CLSAG accepted (HAPPY) (EXISTS: cache_does_not_reuse_result_for_different_pseudo_output in src/crypto/batch_verify.rs)
- [x] verify_single — malformed sig/ring/pseudo bytes ⇒ false (ERROR) (EXISTS: test_concurrent_batch in src/crypto/batch_verify.rs)
- [ ] verify_single — identity pseudo_output rejected (R-29) (ADVERSARIAL) (MISSING)
- [x] verify_all — parallel path above threshold processes full batch (HAPPY) (EXISTS: test_concurrent_batch in src/crypto/batch_verify.rs)
- [x] cache — result not reused for different pseudo_output/statement (ADVERSARIAL) (EXISTS: cache_does_not_reuse_result_for_different_pseudo_output in src/crypto/batch_verify.rs)
- [x] BatchVerifyResult — all_valid / success_rate (HAPPY) (EXISTS: test_batch_result in src/crypto/batch_verify.rs)
- [x] ParallelTxValidator — empty input ⇒ empty (EDGE) (EXISTS: test_parallel_validator in src/crypto/batch_verify.rs)
- [ ] ParallelTxValidator — validate_transactions/filter_valid return correct indices/subset (HAPPY) (MISSING)

### src/crypto/peer_scalars.rs

- [x] PeerScalar::decode — canonical accepted (HAPPY) (EXISTS: scalar_decode_accepts_canonical in src/crypto/peer_scalars.rs)
- [x] PeerScalar::decode — non-canonical (≥ order) rejected (ADVERSARIAL) (EXISTS: scalar_decode_rejects_non_canonical in src/crypto/peer_scalars.rs)
- [x] PeerScalar::zero — canonical zero constant (EDGE) (EXISTS: scalar_zero_roundtrips in src/crypto/peer_scalars.rs)
- [x] PeerPoint::decode — valid Ristretto accepted (incl. identity) (HAPPY) (EXISTS: point_decode_accepts_valid_ristretto in src/crypto/peer_scalars.rs)
- [x] PeerPoint::decode — junk bytes rejected (ADVERSARIAL) (EXISTS: point_decode_rejects_junk in src/crypto/peer_scalars.rs)
- [x] PeerPoint::decode_non_identity — identity rejected, random accepted (ADVERSARIAL) (EXISTS: point_decode_non_identity_rejects_identity, point_decode_non_identity_accepts_random in src/crypto/peer_scalars.rs)
- [x] PeerScalar — borsh round-trip / rejects non-canonical (ROUND-TRIP/ADVERSARIAL) (EXISTS: scalar_borsh_roundtrip_valid, scalar_borsh_rejects_non_canonical in src/crypto/peer_scalars.rs)
- [x] PeerScalar — serde-json round-trip / rejects non-canonical (ROUND-TRIP/ADVERSARIAL) (EXISTS: scalar_serde_json_roundtrip_valid, scalar_serde_json_rejects_non_canonical in src/crypto/peer_scalars.rs)
- [x] PeerPoint — borsh round-trip / rejects identity / rejects junk (ROUND-TRIP/ADVERSARIAL) (EXISTS: point_borsh_roundtrip_valid, point_borsh_rejects_identity_via_non_identity_default, point_borsh_rejects_junk_bytes in src/crypto/peer_scalars.rs)
- [x] PeerPoint — serde-json round-trip / rejects identity (ROUND-TRIP/ADVERSARIAL) (EXISTS: point_serde_json_roundtrip_valid, point_serde_json_rejects_identity in src/crypto/peer_scalars.rs)
- [x] struct field — PeerPoint/PeerScalar in struct rejected at borsh parse (structural) (ADVERSARIAL) (EXISTS: peerpoint_field_in_struct_rejected_at_borsh_parse, peerscalar_field_in_struct_rejected_at_borsh_parse in src/crypto/peer_scalars.rs)

### src/crypto/curve.rs

- [x] SecretScalar::to_public — non-identity for random secret; zero ⇒ identity (HAPPY/ADVERSARIAL) (EXISTS: test_secret_to_public in src/crypto/curve.rs; zero_scalar_produces_identity_public_key in tests/crypto_adversarial_corpora.rs)
- [x] PublicPoint::to_bytes/from_bytes — round-trip (ROUND-TRIP) (EXISTS: test_point_serialization in src/crypto/curve.rs; public_point_roundtrip_1000 in tests/crypto_properties.rs)
- [x] PublicPoint::from_bytes — invalid/off-curve/identity bytes handled (ADVERSARIAL) (EXISTS: all_ff_not_valid_compressed_point, identity_point_not_accepted_as_valid_public_key, random_bytes_usually_not_on_curve in tests/crypto_adversarial_corpora.rs / tests/property_invariants_keys.rs)
- [x] Commitment::commit — deterministic &amp; binding (same in/out; diff blinding differs) (PROPERTY) (EXISTS: test_commitment in src/crypto/curve.rs)
- [x] Commitment — homomorphic add (PROPERTY) (EXISTS: test_commitment_homomorphic in src/crypto/curve.rs; pedersen_commitment_is_homomorphic in tests/crypto_properties.rs)
- [ ] Commitment::from_bytes — invalid point ⇒ None (ADVERSARIAL) (MISSING)
- [x] KeyImage::from_secret — deterministic &amp; unique per secret (PROPERTY) (EXISTS: test_key_image in src/crypto/curve.rs; different_secrets_produce_different_keyimages in tests/crypto_properties.rs)
- [x] KeyImage::from_bytes/to_bytes — round-trip (ROUND-TRIP) (EXISTS: key_image_bytes_roundtrip in tests/property_invariants_keys.rs)
- [ ] KeyImage::from_bytes — invalid point ⇒ None (ADVERSARIAL) (MISSING)
- [x] SecretScalar::derive_child — deterministic &amp; distinct on domain/index (PROPERTY) (EXISTS: test_child_derivation in src/crypto/curve.rs; derive_child_is_deterministic, derive_child_distinct_on_distinct_index/context in tests/property_invariants_keys.rs)
- [x] PublicPoint — identity operations (add/sub/serialize) (EDGE) (EXISTS: test_identity_point_operations in src/crypto/curve.rs)
- [x] hash_to_point — deterministic &amp; collision-distinct inputs (PROPERTY) (EXISTS: hash_to_point_is_deterministic, hash_to_point_different_inputs_different_points in tests/crypto_properties.rs)
- [x] hash_to_point — empty / single-byte input (EDGE) (EXISTS: hash_to_point_with_empty_input, hash_to_point_with_single_zero_byte in tests/crypto_adversarial_corpora.rs)
- [ ] hash_to_scalar — deterministic &amp; domain-separated (PROPERTY) (MISSING)
- [x] generator/generator_h — not identity (PROPERTY) (EXISTS: generators_are_not_identity in tests/crypto_properties.rs)
- [x] SecretScalar arithmetic — add commutative / add identity (PROPERTY) (EXISTS: scalar_add_is_commutative, scalar_add_identity in tests/crypto_properties.rs)
- [x] SecretScalar::from_bytes — mod-order reduction at group order boundary (EDGE) (EXISTS: scalar_from_group_order_wraps_to_zero, scalar_from_group_order_minus_one_is_valid, scalar_one_produces_generator in tests/crypto_adversarial_corpora.rs)
- [x] SecretScalar::from_canonical_bytes — non-canonical all-FF/all-ones handled (ADVERSARIAL) (EXISTS: all_ff_scalar, all_ones_scalar in tests/crypto_adversarial_corpora.rs)
- [ ] PublicPoint borsh/serde Deserialize — invalid point bytes ⇒ Err (ADVERSARIAL) (MISSING)
- [ ] PublicPoint serde human-readable (hex) — round-trip &amp; bad-length reject (ROUND-TRIP) (MISSING)
- [ ] PublicPoint::zeroize — wipes underlying RistrettoPoint (PROPERTY) (MISSING)

### src/crypto/secure.rs

- [x] ct_eq — equal true, unequal false, different length false (HAPPY/EDGE) (EXISTS: test_ct_eq in src/crypto/secure.rs; tier9_ct_eq_returns_correct_results in tests/tier9_timing_sidechannel.rs)
- [x] ct_eq — timing consistent (PROPERTY) (EXISTS: tier9_ct_eq_timing_consistent in tests/tier9_timing_sidechannel.rs)
- [x] ct_cmp — Less/Greater/Equal three-way ordering (HAPPY) (EXISTS: test_ct_cmp in src/crypto/secure.rs)
- [x] ct_copy_if — copies on true, no-op on false (HAPPY) (EXISTS: test_ct_copy_if in src/crypto/secure.rs)
- [ ] ct_select_u8 / ct_select_u64 / ct_select_slice — selection by condition (HAPPY) (MISSING)
- [x] is_zero — all-zero true, nonzero false, empty true (EDGE) (EXISTS: test_is_zero in src/crypto/secure.rs)
- [x] secure_random_32 — distinct &amp; nonzero (PROPERTY) (EXISTS: test_secure_random in src/crypto/secure.rs)
- [ ] secure_random_64 — fills 64 bytes (HAPPY) (MISSING)
- [x] verify_hash — equal/unequal 32-byte hashes (HAPPY/ERROR) (EXISTS: test_verify_hash in src/crypto/secure.rs)
- [ ] verify_mac — equal/unequal MAC (HAPPY/ERROR) (MISSING)
- [x] SecureBytes — manual zeroize wipes data (PROPERTY) (EXISTS: test_secure_bytes_zeroize, test_zeroize_on_drop in src/crypto/secure.rs)
- [x] SecureArray — zeroize on drop (PROPERTY) (EXISTS: test_secure_array_zeroize in src/crypto/secure.rs)
- [ ] secure_zero — zeroizes with compiler fence (PROPERTY) (MISSING)

---

### Per-file coverage counts

| file | total | exist | missing |
|---|---|---|---|
| clsag.rs | 32 | 21 | 11 |
| stealth.rs | 37 | 22 | 15 |
| bulletproofs.rs | 27 | 17 | 10 |
| ring_selection.rs | 11 | 6 | 5 |
| view_keys.rs | 11 | 8 | 3 |
| disclosure.rs | 30 | 24 | 6 |
| memo.rs | 12 | 10 | 2 |
| batch_verify.rs | 10 | 8 | 2 |
| peer_scalars.rs | 11 | 11 | 0 |
| curve.rs | 21 | 15 | 6 |
| secure.rs | 13 | 9 | 4 |
| **AREA TOTAL** | **215** | **151** | **64** |

Notes on the highest-value MISSING gaps (implementation-correctness, ranked): (1) clsag_verify rejects for identity commitment_image, identity ring commitment, non-canonical response/c1 scalars, and zero c1 challenge — every one of these is an explicit reject branch in `clsag_verify` with no dedicated test (the PeerScalar/identity machinery is unit-tested in isolation but never exercised through the CLSAG verifier); (2) `batch_verify::verify_single` identity-pseudo_output reject (R-29) is untested; (3) disclosure identity-nonce rejects (schnorr_r / R / R1,R2) added 2026-09-07 have no tests; (4) bulletproofs aggregation error branches (len mismatch, empty, &gt;MAX_AGGREGATION) and `verify_coinbase_output` are untested; (5) ring_selection ring_size&lt;2 underflow guard and BUG-5 young-real age relaxation are untested at this module level. All EXISTS entries cite a concrete test function that was found in the source; no test names were invented.