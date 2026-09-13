# CoinCync — MINING + PRIMITIVES + MISC test-coverage checklist

Repo (read-only): `C:\Users\unkno\dev\CoinCync-wt-bughunt`. `EXISTS` cites a real found test fn; in-file = a `#[cfg(test)]` test in the same source file; `(ignored)` = behind `#[ignore]`. Categories: HAPPY / EDGE / ERROR / ADVERSARIAL / PROPERTY / ROUND-TRIP.

### src/mining/block_builder.rs
- [x] CandidateBlock::into_block — sets winning nonce on header, returns Block whose merkle root verifies (HAPPY) (EXISTS: candidate_is_consensus_shaped, in-file)
- [x] CandidateBlock::pow_inputs — returns (anchor, tx_root, height) the miner hashes (HAPPY) (EXISTS: build_mine_submit_roundtrip, in-file, ignored)
- [x] build_block_from_template — happy path: 1 coinbase tx, prev_hash/height/miner_pubkey set, coinbase amount == emission reward, tx_root binds coinbase, anchor == compute_full_anchor (HAPPY) (EXISTS: candidate_is_consensus_shaped, in-file)
- [x] build_block_from_template — header.version follows block_version_at_height at V2 activation boundary (EDGE) (EXISTS: candidate_uses_consensus_header_version_at_activation, in-file)
- [ ] build_block_from_template — missing 'height' / 'prev_hash' / 'timestamp' → Error::Internal (ERROR) (MISSING)
- [ ] build_block_from_template — prev_hash not hex / target not hex → Error::Internal (ERROR) (MISSING)
- [ ] build_block_from_template — no 'target', falls back to 'difficulty' string → Hash::from_difficulty (EDGE) (MISSING)
- [ ] build_block_from_template — 'difficulty' not a u64 / both target+difficulty missing → Error::Internal (ERROR) (MISSING)
- [ ] build_block_from_template — coinbase claimable-fees sizing uses final assembled block size (fee-split vs validator) (ADVERSARIAL) (MISSING)
- [x] build_candidate_block — build template + assemble, mine, submit, tip advances (HAPPY) (EXISTS: build_mine_submit_roundtrip, in-file, ignored)
- [x] submit_mined_block — Accepted status removes confirmed txs, advances height (HAPPY) (EXISTS: build_mine_submit_roundtrip, in-file, ignored)
- [ ] submit_mined_block — AcceptedReorg restores orphaned txs; shadow_evict runs (EDGE) (MISSING)
- [ ] submit_mined_block — Invalid/rejected block returns status, no mempool mutation (ERROR) (MISSING)
- [ ] search_nonce — finds nonce meeting target across threads; returns None when stop flag set (EDGE) (MISSING)
- [x] build_coinbase_with_fees — output detectable by owner ECDH scan, tx pubkey unpredictable across two coinbases, outsider cannot claim (ADVERSARIAL) (EXISTS: coinbase_is_detectable_but_not_publicly_linkable, in-file)
- [ ] build_coinbase_with_fees — total_amount = reward + fees (saturating), commitment/view_tag correct (HAPPY) (MISSING)
- [ ] claimable_fees_for_block_size — total_fees==0 → 0; height &lt; fee_distribution_height → all fees; congested → distribute_fee split (EDGE) (MISSING)
- [ ] resolve_network_magic — non-hex magic / wrong length / unknown magic (cross-network) → Error::Internal (ERROR) (MISSING)
- [ ] parse_template_transactions — skips non-hex / non-borsh tx entries silently (EDGE) (MISSING)

### src/mining/template.rs
- [ ] build_template_json — emits height/prev_hash/timestamp/network_magic/target/difficulty/transactions JSON (HAPPY) (EXISTS-adjacent: rpc_get_block_template_returns_result exercises the RPC wrapper, not the fn directly) (MISSING)
- [x] build_template_json (via RPC) — includes network_magic for testnet/mainnet/regtest chains (HAPPY) (EXISTS: rpc_get_block_template_includes_network_magic_for_testnet_chain / _mainnet_chain / _regtest_chain, tests/rpc_endpoints.rs)
- [x] build_template_json (via RPC) — network_magic maps to known network (EDGE) (EXISTS: rpc_get_block_template_network_magic_maps_to_known_network_testnet / _mainnet, tests/rpc_endpoints.rs)
- [ ] build_template_json — skips chain-invalid mempool tx (poison-template guard) (ADVERSARIAL) (MISSING)
- [ ] build_template_json — skips tx below congestion fee floor; fixpoint drop at final block size (ADVERSARIAL) (MISSING)
- [ ] build_template_json — timestamp bumped to ≥ prev.timestamp+1 after difficulty collapse (EDGE) (MISSING)
- [x] congestion_pct_for_size — matches validator integer u128 formula across sizes (PROPERTY) (EXISTS: congestion_pct_matches_validator_formula, in-file)
- [x] dynamic_min_fee — bit-identical to validator's checked_mul floor across buckets (PROPERTY) (EXISTS: builder_and_validator_use_identical_floor, in-file)
- [x] dynamic_min_fee — floor monotonic across congestion buckets (PROPERTY) (EXISTS: floor_is_monotonic_across_buckets, in-file)
- [ ] BlockTemplate::new — copies header sub-fields (supply_commitment, spark_set_root, checkpoint_vote map) (HAPPY) (MISSING)
- [ ] BlockTemplate::update_nonce / update_timestamp — mutate header (HAPPY) (MISSING)

### src/mining/stratum.rs
- [x] downgrade_stale_share — Valid/Block downgraded to Stale when job rotated; passthrough when current; non-valid untouched (ADVERSARIAL) (EXISTS: downgrade_stale_share_treats_rotated_job_results_as_stale, in-file)
- [x] claim_canonical_nonce — stale/non-current job id rejected before ledger touched (no wipe) (ADVERSARIAL) (EXISTS: claim_rejects_stale_job_id_without_clearing_ledger, in-file)
- [x] claim_canonical_nonce — same nonce replayed from second worker → Duplicate (extranonce not part of PoW) (ADVERSARIAL) (EXISTS: claim_dedups_same_nonce_across_workers, in-file)
- [x] claim_canonical_nonce — ledger resets on canonical job rotation; stale old id rejected (EDGE) (EXISTS: claim_resets_on_canonical_job_rotation, in-file)
- [x] canonical_job_unchanged — detects rotation and None-job as not-current (EDGE) (EXISTS: canonical_job_unchanged_detects_rotation, in-file)
- [x] validate_stratum_exposure_policy — public bind requires TLS or proxy-ack (ERROR) (EXISTS: test_public_bind_policy_requires_encrypted_transport_ack_or_native_tls, in-file)
- [x] validate_stratum_exposure_policy — accepts TLS-proxy ack (HAPPY) (EXISTS: test_public_bind_policy_accepts_tls_proxy_ack, in-file)
- [ ] validate_stratum_exposure_policy — public bind without password → refused (ERROR) (MISSING)
- [x] StratumConfig::default — port 3333, pool_fee 1.0 (HAPPY) (EXISTS: test_stratum_config_default, in-file)
- [x] nbits_to_target — sign-bit/negative compact → impossible (zero) target (EDGE) (EXISTS: test_nbits_to_target_rejects_negative_compact, in-file)
- [x] nbits_to_target — over-wide exponent clamps to easiest target (no panic) (EDGE) (EXISTS: test_nbits_to_target_overwide_clamps_to_easiest, in-file)
- [x] difficulty_to_nbits — nonzero result for diff 1 and 1000 (HAPPY) (EXISTS: test_difficulty_to_nbits, in-file)
- [ ] difficulty_to_nbits — diff 0 → Bitcoin default; shift≥24 mantissa guard for diff≥2^32 (EDGE) (MISSING)
- [x] format_mining_notify — contains method + job_id, well-formed params (HAPPY) (EXISTS: test_mining_notify_format, in-file)
- [x] create_coinbase_prefix — version bytes correct, non-empty (HAPPY) (EXISTS: test_coinbase_prefix, in-file)
- [ ] create_coinbase_suffix — sequence/output-count/locktime layout (HAPPY) (MISSING)
- [ ] compute_merkle_branches — empty mempool → empty; branch path from coinbase (EDGE) (MISSING)
- [ ] effective_share_difficulty — clamps share target never harder than block target (issue #44) (ADVERSARIAL) (MISSING)
- [ ] Share::verify — Valid vs Block vs Invalid by target; block-target hit returns Block (HAPPY) (exercised only by ignored e2e) (MISSING)
- [x] load_banlist — corrupt JSON → safe empty map (ERROR) (EXISTS: test_load_banlist_corrupt_json_is_safe_empty, in-file)
- [ ] persist_banlist — write failure logged, does not panic (ERROR) (MISSING)
- [x] register_stratum_strike — score accumulates, ban applied at threshold with banned_until (ADVERSARIAL) (EXISTS: test_stratum_strike_progression_reaches_ban, in-file)
- [x] handle_stratum_message mining.submit — throttle &lt; MIN_SUBMIT_INTERVAL increments streak, deauthorizes at MAX_INVALID_STREAK, registers strike (ADVERSARIAL) (EXISTS: test_submit_throttle_increments_streak_and_can_deauthorize, in-file)
- [x] handle_stratum_message mining.submit — winning nonce assembles candidate, submits block, tip advances, blocks_found++ (HAPPY) (EXISTS: stratum_submit_produces_block, in-file, ignored)
- [x] handle_stratum_message login+submit (native) — login authorizes + returns job, native u64 submit produces block (HAPPY) (EXISTS: cync_login_and_submit_produces_block, in-file, ignored)
- [ ] handle_stratum_message login — wrong password → strike + "unauthorized" (ct_eq) (ERROR) (MISSING)
- [ ] handle_stratum_message submit (native) — unauthenticated worker rejected (ERROR) (MISSING)
- [ ] handle_stratum_message submit (native) — bad nonce hex → "bad nonce" (ERROR) (MISSING)
- [ ] handle_stratum_message submit (native) — duplicate/stale claim → error before PoW recompute (ADVERSARIAL) (MISSING)
- [ ] handle_stratum_message submit (native) — low-difficulty share rejected (EDGE) (MISSING)
- [ ] handle_stratum_message submit (native) — job rotated during hash → stale, not credited (ADVERSARIAL) (MISSING)
- [ ] handle_stratum_message mining.subscribe — returns extranonce1 + notify/set_difficulty tuple (HAPPY) (MISSING)
- [ ] handle_stratum_message mining.authorize — wrong password → strike + [24,Unauthorized] (ERROR) (MISSING)
- [ ] handle_stratum_message mining.submit (legacy) — invalid extranonce2/ntime/nonce hex → [20,...] (ERROR) (MISSING)
- [ ] handle_stratum_message mining.submit (legacy) — unauthorized worker → [24,Not authorized] (ERROR) (MISSING)
- [ ] handle_stratum_message keepalived / mining.extranonce.subscribe → OK responses (HAPPY) (MISSING)
- [ ] handle_stratum_message unknown method → [20,Unknown method] (ERROR) (MISSING)
- [ ] submit_and_broadcast — no stored candidate (shares-only) → returns false, warns (EDGE) (MISSING)
- [ ] StratumServer::share_tally — per-login weighted valid-share tally, skips empty login (HAPPY) (MISSING)
- [ ] StratumServer::start — rejects banned IP, enforces max_connections, TLS handshake path (ADVERSARIAL) (MISSING)

### src/mining/pool.rs (reference design, UNWIRED)
- [x] PoolConfig::default — pool_fee 1.0, target_shares_per_minute 10 (HAPPY) (EXISTS: test_pool_config_default, in-file)
- [x] MinerConnection::new — initial unsubscribed/unauthorized, zero shares (HAPPY) (EXISTS: test_miner_connection_new, in-file)
- [x] difficulty_to_target — higher difficulty → smaller target (PROPERTY) (EXISTS: test_difficulty_to_target, in-file)
- [x] MiningPool::new / miner_count — starts with 0 miners (HAPPY) (EXISTS: test_pool_creation, in-file)
- [x] MiningPool::get_balance — unknown address → zero (EDGE) (EXISTS: test_pool_balance, in-file)
- [ ] on_block_found — PPLNS payout distributed by share-diff ratio, pool fee deducted (HAPPY) (MISSING)
- [ ] on_block_found — empty window / zero total_diff → early return (no payout) (EDGE) (MISSING)
- [ ] on_block_found — prunes shares beyond 2× PPLNS window (EDGE) (MISSING)
- [ ] process_payout — below min_payout → None; at/above → removes balance, updates total_paid (EDGE) (MISSING)
- [ ] create_job — inserts job with random id + initial-difficulty target (HAPPY) (MISSING)
- [ ] process_stratum_request subscribe/authorize(valid) — sets subscribed/authorized (HAPPY) (MISSING)
- [ ] process_stratum_request submit — unauthorized → [24] (ERROR) (MISSING)
- [ ] process_stratum_request submit — job not found → [21] (ERROR) (MISSING)
- [ ] process_stratum_request submit — duplicate (extra_nonce2,nonce) per-job → [22] (ADVERSARIAL) (MISSING)
- [ ] process_stratum_request submit — nonce length ≠ 16 hex → [20] (EDGE) (MISSING)
- [ ] process_stratum_request submit — bad prev_hash / bad coinbase / bad nonce format → [20] (ERROR) (MISSING)
- [ ] process_stratum_request submit — low-difficulty share → [23]; valid share recorded; block target hit logged (HAPPY) (MISSING)
- [ ] process_stratum_request submit — vardiff raises/lowers difficulty within min/max bounds (EDGE) (MISSING)
- [ ] process_stratum_request — unknown method → [-1] (ERROR) (MISSING)
- [ ] handle_miner — oversized line (&gt;16KB, no newline) disconnects (ADVERSARIAL) (MISSING)
- [ ] MiningPool::start — refuses public bind without PUBLIC_BIND_ACK / TLS_PROXY_ACK (ERROR) (MISSING)

### src/mining/miner.rs (1.0 stub)
- [ ] Miner::stats — returns default MiningStats (HAPPY) (MISSING)
- [ ] Miner::start — stub returns Ok, warns (HAPPY) (MISSING)

### src/primitives/address.rs
- [x] to_bytes/from_bytes — byte round-trip preserves address (ROUND-TRIP) (EXISTS: bytes_roundtrip, tests/property_invariants_address.rs)
- [x] from_string/to_string — string round-trip with valid keys, CYNC prefix (ROUND-TRIP) (EXISTS: string_roundtrip_with_valid_keys, tests/property_invariants_address.rs; test_address_roundtrip, in-file)
- [x] from_string — prefix matches network (testnet vs mainnet) (PROPERTY) (EXISTS: string_prefix_matches_network, tests/property_invariants_address.rs)
- [x] from_bytes — flipping any bit → bad checksum rejected (ADVERSARIAL) (EXISTS: flipping_a_bit_invalidates_the_address, tests/property_invariants_address.rs)
- [x] from_bytes — bytes shorter than 70 → "too short" (ERROR) (EXISTS: short_bytes_rejected, tests/property_invariants_address.rs)
- [x] from_bytes — invalid network byte (&gt;1) rejected (ERROR) (EXISTS: invalid_network_byte_rejected, tests/property_invariants_address.rs)
- [x] from_bytes — standard-length payload with integrated type → wrong-length reject (M-3) (ADVERSARIAL) (EXISTS: standard_length_with_integrated_type_is_rejected, tests/property_invariants_address.rs)
- [x] from_bytes_checked — non-curve-point spend/view key rejected (ADVERSARIAL) (EXISTS: test_invalid_curve_point_rejected, in-file; monero_2018_invalid_curve_point_address_rejected, tests/historical_attacks/monero_2018_burning_bug.rs)
- [x] from_string — bad prefix rejected (ERROR) (EXISTS: bad_prefix_string_rejected, tests/property_invariants_address.rs)
- [x] from_string — empty string rejected (ERROR) (EXISTS: empty_string_rejected, tests/property_invariants_address.rs; test_malformed_address_rejected, in-file)
- [x] FromStr — .cync name suffix → "name lookup required" (EDGE) (EXISTS: from_str_rejects_name_suffix, tests/property_invariants_address.rs)
- [x] AddressType::type_byte/from_byte round-trip (ROUND-TRIP) (EXISTS: address_type_byte_roundtrip, tests/property_invariants_address.rs)
- [x] AddressType::from_byte — unknown byte (≥3) → None (ERROR) (EXISTS: address_type_from_byte_rejects_unknown, tests/property_invariants_address.rs)
- [x] Network::prefix — "CYNC"/"tCYNC" strings correct (HAPPY) (EXISTS: network_prefix_strings, tests/property_invariants_address.rs)
- [ ] from_bytes — mainnet Subaddress rejected (unspendable-funds launch gate W-1/W-B) (ADVERSARIAL) (MISSING)
- [ ] from_bytes/to_bytes — Integrated address with 8-byte payment_id round-trip (ROUND-TRIP) (MISSING)
- [ ] from_bytes — integrated payload too short (&lt;74) → error (ERROR) (MISSING)
- [ ] from_bytes — bad address-type byte (≥3) in payload rejected (ERROR) (MISSING)
- [ ] from_string — parsed network != prefix network → "network mismatch" (ADVERSARIAL) (MISSING)
- [ ] Deserialize (binary/non-human-readable) — routes through from_bytes_checked (untrusted-input guard) (ADVERSARIAL) (MISSING)
- [ ] BorshDeserialize — validates spend/view are non-identity Ristretto points (ADVERSARIAL) (MISSING)
- [ ] short — truncates to 12…6 for long addresses (HAPPY) (MISSING)

### src/primitives/amount.rs
- [x] from_atomic/as_atomic round-trip (ROUND-TRIP) (EXISTS: from_atomic_as_atomic_roundtrip, tests/property_invariants_amount.rs)
- [x] checked_add — overflow matches u64 math, commutative (PROPERTY) (EXISTS: checked_add_overflow_matches_math, checked_add_is_commutative, tests/property_invariants_amount.rs)
- [x] checked_sub — rejects underflow (ERROR) (EXISTS: checked_sub_rejects_underflow, tests/property_invariants_amount.rs)
- [x] checked_div — zero divisor → error (ERROR) (EXISTS: checked_div_rejects_zero_divisor, tests/property_invariants_amount.rs)
- [x] add/sub operators — saturating semantics (PROPERTY) (EXISTS: add_operator_is_saturating, tests/property_invariants_amount.rs; test_overflow_boundary, in-file)
- [x] checked_add/sub consistent with saturating variants (PROPERTY) (EXISTS: checked_add_consistent_with_saturating, checked_sub_consistent_with_saturating, tests/property_invariants_amount.rs)
- [x] from_cync — overflow → AmountOverflow (ERROR) (EXISTS: test_amount_overflow, tests/edge_cases.rs &amp; tests/security_critical.rs; amount_overflow_checked, tests/phase1_critical.rs)
- [x] from_float_cync — rejects NaN / infinity / negative (ERROR) (EXISTS: from_float_cync_rejects_nan, _infinity, _negative, tests/property_invariants_amount.rs)
- [x] percentage — 0 bp → 0; 10000 bp → self (rounding) (PROPERTY) (EXISTS: percentage_zero_returns_zero, percentage_100_percent_returns_self, tests/property_invariants_amount.rs)
- [x] percentage_truncate — 0 bp → 0; 10000 bp → self (truncating) (PROPERTY) (EXISTS: percentage_truncate_zero_returns_zero, percentage_truncate_100_percent_returns_self, tests/property_invariants_amount.rs)
- [x] from_str — integer CYNC matches from_cync (PROPERTY) (EXISTS: from_str_integer_cync_matches_from_cync, tests/property_invariants_amount.rs)
- [x] from_str — rejects negative / empty (ERROR) (EXISTS: from_str_rejects_negative, from_str_rejects_empty, tests/property_invariants_amount.rs)
- [x] add_then_sub identity (PROPERTY) (EXISTS: add_then_sub_is_identity, tests/property_invariants_amount.rs)
- [x] Borsh / JSON round-trip identity (ROUND-TRIP) (EXISTS: borsh_roundtrip_is_identity, json_roundtrip_is_identity, tests/property_invariants_amount.rs)
- [x] as_cync — matches atomic/ATOMIC_UNITS division (PROPERTY) (EXISTS: as_cync_matches_atomic_division, tests/property_invariants_amount.rs)
- [x] is_zero iff atomic == 0 (PROPERTY) (EXISTS: is_zero_iff_atomic_zero, tests/property_invariants_amount.rs)
- [x] format / format_in / format_auto — decimal &amp; denomination formatting (HAPPY) (EXISTS: test_format, test_denominations, test_auto_format, in-file)
- [x] Sum / saturating_add — double-MAX saturates, no wrap (ADVERSARIAL) (EXISTS: monero_2019_amount_saturating_add, monero_2019_double_max_saturates, tests/historical_attacks/monero_2019_overflow.rs)
- [ ] from_float_cync — value &gt; u64::MAX/ATOMIC_UNITS → AmountOverflow (ERROR) (MISSING)
- [ ] checked_mul — factor overflow → AmountOverflow (ERROR) (MISSING)
- [ ] Div operator / by-zero returns ZERO (no panic) (EDGE) (MISSING)
- [ ] Mul operator — saturating multiply (PROPERTY) (MISSING)
- [ ] from_str — non-digit fractional chars rejected (ERROR) (MISSING)
- [ ] from_str — integer part &gt; u64::MAX/ATOMIC_UNITS → AmountOverflow (ERROR) (MISSING)
- [ ] from_str — fractional &gt;12 digits truncated exactly (EDGE) (MISSING)
- [ ] from_millicync / from_microcync — NaN/inf/negative/overflow guards (ERROR) (MISSING)
- [ ] as_syncs / from_syncs / as_millicync / as_microcync round-trip (ROUND-TRIP) (MISSING)
- [ ] Amount summation overflow across outputs saturates (ADVERSARIAL) (EXISTS-adjacent: bitcoin_2010_output_sum_overflow_u64 covers tx-output sum, not Amount::sum; MISSING for Amount::Sum)

### src/primitives/hash.rs
- [x] from_bytes/as_bytes round-trip (ROUND-TRIP) (EXISTS: from_bytes_as_bytes_roundtrip, tests/property_invariants_hash.rs)
- [x] from_slice — matches from_bytes; wrong length → None (ERROR) (EXISTS: from_slice_matches_from_bytes, from_slice_rejects_wrong_length, tests/property_invariants_hash.rs)
- [x] to_hex/from_hex round-trip; invalid hex → None (ROUND-TRIP) (EXISTS: hex_roundtrip, tests/property_invariants_hash.rs; test_hex_roundtrip, in-file)
- [x] to_hex — 64 lowercase hex chars (PROPERTY) (EXISTS: to_hex_is_64_lowercase_hex_chars, tests/property_invariants_hash.rs)
- [x] ct_eq — matches == for all inputs (PROPERTY) (EXISTS: ct_eq_matches_eq, tests/property_invariants_hash.rs)
- [x] zero/is_zero — zero is zero; nonzero bytes → nonzero hash (PROPERTY) (EXISTS: zero_is_zero, nonzero_bytes_means_nonzero_hash, tests/property_invariants_hash.rs)
- [x] hash_data / hash_concat / hash_domain — deterministic, order-sensitive, domain-separated (PROPERTY) (EXISTS: hash_data_is_deterministic, hash_concat_is_deterministic, hash_concat_is_order_sensitive, hash_domain_is_deterministic, hash_domain_separates_distinct_domains, tests/property_invariants_hash.rs)
- [x] merkle_root — empty → zero; single leaf domain-separated; deterministic (EDGE/PROPERTY) (EXISTS: merkle_root_empty_is_zero, merkle_root_single_leaf_is_domain_separated, merkle_root_is_deterministic, tests/property_invariants_hash.rs; test_merkle_root, in-file)
- [ ] first_byte — returns byte[0] (HAPPY) (MISSING)
- [ ] meets_difficulty — hash &lt; target true, hash &gt; target false, equal true (EDGE) (MISSING)
- [ ] from_difficulty — difficulty 0 → all-FF max target; from_difficulty(1) == max_target (off-by-one M-2) (EDGE) (MISSING)
- [ ] to_difficulty — leading-zero count; all-zero/near-zero → u64::MAX (checked_shl overflow L7) (EDGE) (MISSING)
- [ ] from_difficulty/to_difficulty round-trip approximation (ROUND-TRIP) (MISSING)
- [ ] FromStr — non-hex / wrong byte length → InvalidHashLength (ERROR) (MISSING)
- [ ] Serialize/Deserialize — human-readable hex vs binary bytes round-trip (ROUND-TRIP) (MISSING)
- [ ] merkle_root — CVE-2012-2459 duplication malleability: root([A,B,C]) == root([A,B,C,C]) (ADVERSARIAL, documented-not-fixed) (MISSING)

### src/primitives/keys.rs
- [x] PublicKey from_bytes/as_bytes round-trip (ROUND-TRIP) (EXISTS: public_key_bytes_roundtrip, tests/property_invariants_keys.rs)
- [x] PublicKey to_hex/from_hex round-trip; invalid hex chars / wrong length rejected (ROUND-TRIP/ERROR) (EXISTS: public_key_hex_roundtrip, public_key_from_hex_rejects_invalid, public_key_from_hex_rejects_wrong_length, tests/property_invariants_keys.rs)
- [x] PublicKey::from_bytes_checked — rejects non-curve bytes and identity element (ADVERSARIAL) (EXISTS: test_checked_deserialization, in-file; identity_point_not_accepted_as_valid_public_key, tests/crypto_adversarial_corpora.rs; random_bytes_usually_not_on_curve, tests/property_invariants_keys.rs)
- [x] SecretKey — bytes round-trip; generate is nonzero (ROUND-TRIP/HAPPY) (EXISTS: secret_key_bytes_roundtrip, tests/property_invariants_keys.rs; test_key_generation, in-file)
- [x] SecretKey::public_key — deterministic EC mult; distinct secrets → distinct publics; zero scalar → identity (PROPERTY/ADVERSARIAL) (EXISTS: public_key_derivation_is_deterministic, distinct_secrets_yield_distinct_publics, tests/property_invariants_keys.rs; zero_scalar_produces_identity_public_key, tests/crypto_adversarial_corpora.rs)
- [x] SecretKey::derive_child — deterministic; distinct on distinct index/context (PROPERTY) (EXISTS: derive_child_is_deterministic, derive_child_distinct_on_distinct_index, derive_child_distinct_on_distinct_context, tests/property_invariants_keys.rs)
- [x] KeyPair::generate/from_secret — seed-deterministic; public matches secret.public_key (PROPERTY) (EXISTS: keypair_generate_is_seed_deterministic, keypair_from_secret_matches_secret_public_key, tests/property_invariants_keys.rs)
- [x] Signature from_bytes/from_slice/to_hex/from_hex round-trip; wrong length rejected (ROUND-TRIP/ERROR) (EXISTS: signature_bytes_roundtrip, signature_hex_roundtrip, signature_from_slice_rejects_wrong_length, signature_from_hex_rejects_wrong_length, tests/property_invariants_keys.rs)
- [x] KeyImage from_bytes/from_slice/to_hex round-trip; wrong length rejected; from_bytes deterministic (ROUND-TRIP/ERROR) (EXISTS: key_image_bytes_roundtrip, key_image_from_slice_rejects_wrong_length, key_image_hex_is_64_chars, tests/property_invariants_keys.rs; test_key_image_from_bytes_deterministic, in-file)
- [ ] PublicKey::validate — rejects non-curve + identity (ADVERSARIAL) (MISSING)
- [ ] PublicKey::from_slice — wrong length → InvalidPublicKey (ERROR) (MISSING)
- [ ] SecretKey::from_slice — wrong length → InvalidSecretKey (ERROR) (MISSING)
- [ ] SecretKey Drop — zeroizes bytes on drop (ADVERSARIAL) (MISSING)
- [ ] Signature Deserialize — binary visit_bytes / visit_seq paths (ROUND-TRIP) (MISSING)

### src/snapshot/mod.rs
- [x] export → import — full round-trip installs DB, manifest verifies, files match (ROUND-TRIP) (EXISTS: export_then_import_round_trips_and_verifies, in-file)
- [x] import — wrong genesis hash → refused, nothing installed (ADVERSARIAL) (EXISTS: import_refuses_wrong_genesis, in-file)
- [x] import — blake3 integrity mismatch (tampered DB) → refused (ADVERSARIAL) (EXISTS: import_detects_corruption, in-file)
- [x] import — backs up existing chaindata to .pre-snapshot-&lt;stamp&gt; (EDGE) (EXISTS: import_backs_up_existing_chaindata, in-file)
- [x] import — real genesis DB + checkpoints accepted, reopens as same chain (HAPPY) (EXISTS: verify_installed_db_accepts_real_genesis_chain, in-file)
- [x] import — bad checkpoint → rejected and rolls back prior chaindata (ADVERSARIAL) (EXISTS: verify_installed_db_rejects_bad_checkpoint_and_rolls_back, in-file)
- [x] import — trusted-signed snapshot accepted (HAPPY) (EXISTS: import_accepts_trusted_signed_snapshot, in-file)
- [x] import — untrusted signer / missing signature under trusted-signers policy → refused, nothing installed (ADVERSARIAL) (EXISTS: import_rejects_untrusted_and_missing_signature, in-file)
- [x] blake3_of_dir/hash_file_streaming — order-independent deterministic, format-preserving (PROPERTY) (EXISTS: streaming_hash_matches_prefix_format_and_is_deterministic, in-file)
- [x] hash_file_streaming — oversized file refused by budget without OOM (ADVERSARIAL) (EXISTS: oversized_snapshot_is_refused_without_oom, in-file)
- [x] recover_interrupted_install — restores original chaindata from backup, clears marker (EDGE) (EXISTS: recover_interrupted_install_restores_from_backup, in-file)
- [x] recover_interrupted_install — no marker → no-op, live data untouched (EDGE) (EXISTS: recover_is_noop_without_marker, in-file)
- [x] sign_snapshot_dir — signs manifest.json bytes, writes manifest.sig (HAPPY) (EXISTS: used by import_accepts_trusted_signed_snapshot, in-file)
- [ ] import — manifest network mismatch → refused (ADVERSARIAL) (MISSING)
- [ ] import — snapshot db/ dir missing → refused (ERROR) (MISSING)
- [ ] import — copy failure triggers loud rollback of backup (ERROR) (MISSING)
- [ ] export — chaindata dir not found / out already has db/ → InvalidState (ERROR) (MISSING)
- [ ] recover_interrupted_install — fresh-install (no backup) removes half-copied snapshot (EDGE) (MISSING)
- [ ] hash_file_streaming — file grows during hash (TOCTOU) → size-changed refuse (ADVERSARIAL) (MISSING)

### src/snapshot/signing.rs
- [x] sign_manifest → verify_manifest_signature — round-trip for trusted signer (ROUND-TRIP) (EXISTS: sign_then_verify_roundtrips_for_trusted_signer, in-file)
- [x] verify_manifest_signature — signer not in allowlist → refused (ADVERSARIAL) (EXISTS: rejects_signer_not_in_allowlist, in-file)
- [x] verify_manifest_signature — empty allowlist → refused (ADVERSARIAL) (EXISTS: rejects_empty_allowlist, in-file)
- [x] verify_manifest_signature — tampered manifest bytes → verification failed (ADVERSARIAL) (EXISTS: rejects_tampered_manifest, in-file)
- [x] verify_manifest_signature — signature from different namespace → refused (ADVERSARIAL) (EXISTS: rejects_signature_from_a_different_namespace, in-file)
- [x] verify_manifest_signature — malformed pubkey / signature hex → refused (ERROR) (EXISTS: rejects_malformed_pubkey_and_sig, in-file)
- [x] pubkey_for_seed — derives allowlist hex pubkey (HAPPY) (EXISTS: used across signing tests, in-file)

### src/snapshot/verify.rs
- [x] verify_chain_binding — tip + checkpoints match → Ok (HAPPY) (EXISTS: accepts_when_tip_and_checkpoints_match, in-file)
- [x] verify_chain_binding — manifest height lie → refused (ADVERSARIAL) (EXISTS: rejects_manifest_height_lie, in-file)
- [x] verify_chain_binding — manifest tip-hash lie → refused (ADVERSARIAL) (EXISTS: rejects_manifest_tip_hash_lie, in-file)
- [x] verify_chain_binding — fabricated history at checkpoint → refused (ADVERSARIAL) (EXISTS: rejects_fabricated_history_at_checkpoint, in-file)
- [x] verify_chain_binding — missing block at checkpoint height → refused (ADVERSARIAL) (EXISTS: rejects_missing_checkpoint_block, in-file)
- [x] verify_chain_binding — checkpoints above snapshot height skipped (EDGE) (EXISTS: skips_checkpoints_above_snapshot_height, in-file)
- [x] verify_chain_binding — empty checkpoints still enforces tip integrity (EDGE) (EXISTS: empty_checkpoints_still_checks_tip_integrity, in-file)
- [x] verify_installed_db — opens real DB, binds genesis checkpoint (HAPPY) (EXISTS: verify_installed_db_accepts_real_genesis_chain, tests via import, in-file)
- [ ] verify_installed_db — Fresh (no chain state) DB → refused (ERROR) (MISSING)
- [ ] verify_installed_db — DB open failure → InvalidState (ERROR) (MISSING)

### net_time (network-adjusted time)
NOTE: There is NO Bitcoin-style network-adjusted-time subsystem in this tree — no peer time samples, no sample-dedup, no reset-on-extreme, no median-offset accumulator (confirmed by grep of `time_offset` / `adjusted_time` / `NetworkTime` / `peer_time` across `src/`; the only hits are unrelated "drift" comments). "Network time" here = the local system clock plus a fixed drift bound, plus block-lineage Median-Time-Past. The three behaviors below are what actually exists; the sample-dedup / reset-on-extreme / median-offset behaviors requested do not exist and are therefore not applicable.
- [x] median_time_past_of_lineage (src/chain.rs) — MTP is the median over the fork lineage (not active-chain-by-height) (EDGE) (EXISTS: mtp_uses_fork_lineage_not_active_chain_by_height, in-file src/chain.rs)
- [x] block validation — timestamp ≤ MTP rejected / &gt; MTP accepted (ADVERSARIAL) (EXISTS: verge_2018_difficulty_resists_timestamp_games, tests/historical_attacks/verge_2018_timestamp.rs; mtp_uses_fork_lineage_not_active_chain_by_height, in-file)
- [x] check_header_future_timestamp (src/consensus/validation.rs) — timestamp == now+MAX_TIMESTAMP_DRIFT accepted, one past rejected (EDGE) (EXISTS: timestamp_exactly_at_drift_boundary_accepted, timestamp_one_past_drift_boundary_rejected, tests/consensus_edges.rs)
- [x] future-timestamp drift bound is enforced (ADVERSARIAL) (EXISTS: verge_2018_timestamp_drift_bounded, tests/historical_attacks/verge_2018_timestamp.rs)
- [x] check_header_future_timestamp — genesis (height 0) exempt from future-time check (EDGE) (EXISTS: covered by genesis structure tests in consensus_edges.rs: genesis_at_height_0_with_zero_prev_accepted_structure) 
- [ ] check_header_future_timestamp — system-clock-before-2020 adds warning; clock error adds error not panic (EDGE) (MISSING)
- [ ] sample dedup / reset-on-extreme / median peer-time offset (feature absent) (N/A — no such code exists) (MISSING)

---

## Per-file counts

| File | Total | Exist | Missing |
|---|---|---|---|
| src/mining/block_builder.rs | 19 | 6 | 13 |
| src/mining/template.rs | 11 | 5 | 6 |
| src/mining/stratum.rs | 35 | 15 | 20 |
| src/mining/pool.rs | 22 | 5 | 17 |
| src/mining/miner.rs | 2 | 0 | 2 |
| src/primitives/address.rs | 22 | 14 | 8 |
| src/primitives/amount.rs | 27 | 17 | 10 |
| src/primitives/hash.rs | 17 | 8 | 9 |
| src/primitives/keys.rs | 14 | 9 | 5 |
| src/snapshot/mod.rs | 20 | 14 | 6 |
| src/snapshot/signing.rs | 7 | 7 | 0 |
| src/snapshot/verify.rs | 10 | 8 | 2 |
| net_time | 7 | 5 | 2 |
| **AREA TOTAL** | **213** | **113** | **100** |

## Key findings / notable gaps

- **net_time**: the requested network-adjusted-time mechanism (peer time samples, sample dedup, reset-on-extreme, median offset) does **not exist** in this tree. Only local-clock drift bound (`check_header_future_timestamp`, MAX_TIMESTAMP_DRIFT=600s) and block-lineage Median-Time-Past (`median_time_past_of_lineage`) exist; both are covered.
- **stratum/pool message handlers are largely untested at unit level**: the pure helpers (`claim_canonical_nonce`, `downgrade_stale_share`, `canonical_job_unchanged`, ban/strike, nbits) are well covered, but the many error/rejection branches of `handle_stratum_message` (login-fail, unauth, bad-nonce, low-diff, stale, subscribe, legacy authorize/submit malformed inputs, unknown method) and every branch of pool.rs `process_stratum_request` / `on_block_found` / `process_payout` are MISSING. The two end-to-end share→block tests are `#[ignore]` (require RandomX).
- **block_builder error branches** (missing/malformed template fields, unknown network magic, difficulty-fallback path, reorg/invalid submit) are MISSING; only the happy candidate-shape and coinbase-privacy paths are covered.
- **Primitives round-trips are strong** (address/amount/hash/keys all have dedicated `property_invariants_*` suites). Concrete gaps: `Hash::from_difficulty`/`to_difficulty`/`meets_difficulty` have no direct tests; Amount `Div`-by-zero, `checked_mul`, `from_millicync/microcync` guards, and non-digit/overflow `from_str` branches are untested; Address mainnet-subaddress gate, Integrated round-trip, binary-serde/Borsh curve-point validation are untested.
- **Documented-but-unfixed adversarial behavior** with no test: `merkle_root` CVE-2012-2459 duplication malleability (`root([A,B,C]) == root([A,B,C,C])`) — consensus-frozen, relies on downstream block checks.
- **Snapshot suite is the best-covered**: signing.rs fully covered; only a few import error branches (network mismatch, db-missing, copy-fail rollback, export precondition errors, fresh-install recovery) are MISSING.

Counts treat one checklist line = one behavior; a line marked EXISTS may be satisfied by an `#[ignore]`d test (noted inline) — if those must run in CI unignored, treat block_builder/stratum e2e happy-paths as effectively uncovered, dropping AREA exist to ~109.