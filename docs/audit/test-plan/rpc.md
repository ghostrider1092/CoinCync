# CoinCync RPC Subsystem — Behavioral Test-Coverage Checklist

Repo (read-only): `C:\Users\unkno\dev\CoinCync-wt-bughunt` · Source under `src/rpc/` · Tests under `tests/` + in-file `#[cfg(test)]` modules.

**Architecture notes that shape this checklist**
- All JSON-RPC methods are registered inline in `server.rs::start_rpc_server` on a `jsonrpsee::RpcModule`. `node_api.rs` is gone; there is no `net_time.rs`.
- **Auth and rate-limiting are transport-global, not per-method.** A single `RpcBearerValidator` (`ValidateRequestHeaderLayer`) runs the rate-limiter then the Bearer check for *every* POST/WS-upgrade before any method dispatches. So per-method "unauth rejection" / "rate-limit trip" is exercised through that one middleware — enumerated in the dedicated **Transport / middleware** subsection. Per-method adversarial rows point there.
- `MAX_RPC_AUDIT_BLOCK_SPAN = 128` bounds the `*_in_range` + `full_chain_audit` methods via `rpc_clamp_audit_range`. `verify_keyimage_uniqueness` is bounded separately by `MAX_RPC_KEYIMAGE_SCAN_CHAIN_HEIGHT = 25_000`.
- `tests/rate_limiter.rs` tests `network::PeerMessageRateTracker`, **not** `rpc::ratelimit::RateLimiter` — it does not count toward RPC coverage.

---

### src/rpc/server.rs

**get_info**
- [x] get_info — returns result payload on happy path (HAPPY) (EXISTS: rpc_get_info_returns_result in tests/rpc_endpoints.rs)
- [x] get_info — payload carries height/network/is_synced/peer_count/mempool_size/difficulty (HAPPY) (EXISTS: rpc_get_info_has_all_fields in tests/rpc_endpoints.rs)
- [x] get_info — reports runtime hardening posture (rpc_auth_enabled/metadata_minimized/stratum_*) (PROPERTY) (EXISTS: rpc_info_reports_runtime_hardening_posture in tests/rpc_endpoints.rs)
- [x] get_info — public bind defaults metadata_minimized=true (PROPERTY) (EXISTS: rpc_public_bind_defaults_to_metadata_minimized in tests/rpc_endpoints.rs)
- [x] get_info — stratum posture hardened when not public / with native TLS; unhardened when public without TLS (EDGE) (EXISTS: rpc_info_reports_stratum_posture_hardened_when_not_public / _hardened_with_native_tls / _unhardened_when_public_without_tls in tests/rpc_endpoints.rs)
- [ ] get_info — tip_age_secs=null + clock_available=false when clock &lt; UNIX_EPOCH (EDGE) (MISSING)
- [ ] get_info — status/health_score bands: syncing/no-peers/stalled(age&gt;300)/low-peers/healthy (PROPERTY) (MISSING)
- [ ] get_info — extra/positional params tolerated (params ignored) (EDGE) (MISSING)

**get_peer_info**
- [x] get_peer_info — redacts addr/user_agent/peer_id/bytes on public (minimize_metadata) bind (ADVERSARIAL) (EXISTS: rpc_public_bind_redacts_real_peer_fixture_fields in tests/rpc_endpoints.rs)
- [x] get_peer_info — exposes real peer fields on loopback when not minimized (HAPPY) (EXISTS: rpc_loopback_exposes_peer_fixture_fields_when_not_minimized in tests/rpc_endpoints.rs)
- [x] get_peer_info — loopback env override forces minimization (EDGE) (EXISTS: rpc_loopback_env_override_forces_metadata_minimization in tests/rpc_endpoints.rs)
- [ ] get_peer_info — empty peer list when p2p is None (EDGE) (MISSING)
- [ ] get_peer_info — divergence summary (max/min/divergence_from_max) computed from reported heights (PROPERTY) (MISSING)

**get_blockchain_info**
- [x] get_blockchain_info — returns result on happy path (HAPPY) (EXISTS: rpc_get_blockchain_info_returns_result in tests/rpc_endpoints.rs)
- [x] get_blockchain_info — reports stratum posture fields (PROPERTY) (EXISTS: rpc_blockchain_info_reports_stratum_posture_fields in tests/rpc_endpoints.rs)
- [ ] get_blockchain_info — total_supply serialized as base-10 string (u128-safe) (PROPERTY) (MISSING)

**get_mempool_info**
- [x] get_mempool_info — returns size/bytes/total_fees/max_size (HAPPY) (EXISTS: rpc_get_mempool_info_returns_result in tests/rpc_endpoints.rs)

**get_mempool_transactions**
- [ ] get_mempool_transactions — returns count + per-tx {hash,kind,inputs,outputs,fee,size} (HAPPY) (MISSING)
- [ ] get_mempool_transactions — caps iteration at 500 txs (EDGE) (MISSING)

**get_supply_info**
- [x] get_supply_info — returns result (HAPPY) (EXISTS: rpc_get_supply_info_returns_result in tests/rpc_endpoints.rs)
- [x] get_supply_info — total_emitted is an exact decimal string (u128-safe) (PROPERTY) (EXISTS: rpc_get_supply_info_has_fields in tests/rpc_endpoints.rs)
- [ ] get_supply_info — circulating = total_supply − total_burned (saturating) (PROPERTY) (MISSING)

**get_block_by_height**
- [x] get_block_by_height — valid height returns serialized block (HAPPY) (EXISTS: rpc_get_block_by_height_valid in tests/rpc_endpoints.rs)
- [x] get_block_by_height — future/unknown height returns -5 not-found (EDGE) (EXISTS: rpc_get_block_by_height_future in tests/rpc_endpoints.rs)
- [x] get_block_by_height — string param rejected (-32602) (ERROR) (EXISTS: rpc_get_block_by_height_string_param in tests/rpc_endpoints.rs)
- [x] get_block_by_height — negative param rejected (-32602) (ERROR) (EXISTS: rpc_get_block_by_height_negative in tests/rpc_endpoints.rs)
- [x] get_block_by_height — missing params rejected (-32602) (ERROR) (EXISTS: rpc_get_block_by_height_no_params in tests/rpc_endpoints.rs)

**find_fork_point** (RPC handler; journal parse + fork selection)
- [x] find_fork_point — parse_journal_hex round-trips &amp; rejects malformed/wrong-length hash (ROUND-TRIP) (EXISTS: parse_journal_hex_roundtrips_and_rejects_malformed in src/rpc/lightwallet.rs)
- [x] find_fork_point — fork_point_in_journal returns deepest canonical ancestor (PROPERTY) (EXISTS: fork_point_journal_returns_last_common_ancestor in src/rpc/lightwallet.rs)
- [ ] find_fork_point — RPC rejects journal &gt; MAX_JOURNAL (4096) with -32602 (ADVERSARIAL) (MISSING)
- [ ] find_fork_point — RPC end-to-end returns {fork_point} for a real chain (HAPPY) (MISSING)
- [ ] find_fork_point — malformed params (not [(u64,String)]) rejected -32602 (ERROR) (MISSING)

**get_block** (by hash)
- [x] get_block — unknown hash returns -5 not-found (EDGE) (EXISTS: rpc_get_block_by_hash_missing in tests/rpc_endpoints.rs)
- [ ] get_block — valid 64-hex hash returns serialized block (HAPPY) (MISSING)
- [ ] get_block — non-hex / wrong-length hash rejected -32602 (ERROR) (MISSING)
- [ ] get_block — `0x` prefix tolerated (EDGE) (MISSING)

**get_block_template**
- [x] get_block_template — returns template on happy path (HAPPY) (EXISTS: rpc_get_block_template_returns_result in tests/rpc_endpoints.rs)
- [x] get_block_template — network_magic present &amp; maps to network (testnet/mainnet/regtest) (PROPERTY) (EXISTS: rpc_get_block_template_includes_network_magic_for_{testnet,mainnet,regtest}_chain + _network_magic_maps_to_known_network_{testnet,mainnet} in tests/rpc_endpoints.rs)
- [ ] get_block_template — accepts both `[]` and `[address]` (address ignored) (EDGE) (MISSING)

**submit_block**
- [x] submit_block — garbage hex rejected (ERROR) (EXISTS: rpc_submit_block_garbage in tests/rpc_endpoints.rs)
- [x] submit_block — empty hex rejected (EDGE) (EXISTS: rpc_submit_block_empty_hex in tests/rpc_endpoints.rs)
- [x] submit_block — garbage borsh block bytes rejected at deserialize (ERROR) (EXISTS: tier8_garbage_block_deserialization in tests/tier8_rpc_security.rs) [primitive-level]
- [ ] submit_block — hex length &gt; 4×MAX_BLOCK_SIZE rejected pre-decode (-32602) (ADVERSARIAL) (MISSING)
- [ ] submit_block — Accepted block → {accepted:true,hash} + mempool remove_confirmed/set_height (HAPPY) (MISSING)
- [ ] submit_block — Orphan → -32001 orphan error (EDGE) (MISSING)
- [ ] submit_block — Invalid(reason) → -32001 with reason (ERROR) (MISSING)
- [ ] submit_block — AlreadyKnown → accepted+status already_known (EDGE) (MISSING)
- [ ] submit_block — AcceptedReorg restores orphaned txs (PROPERTY) (MISSING)

**send_raw_transaction**
- [x] send_raw_transaction — garbage hex rejected (ERROR) (EXISTS: rpc_send_raw_transaction_garbage in tests/rpc_endpoints.rs)
- [x] send_raw_transaction — garbage borsh tx bytes rejected at deserialize (ERROR) (EXISTS: tier8_garbage_tx_deserialization in tests/tier8_rpc_security.rs) [primitive-level]
- [ ] send_raw_transaction — hex length &gt; 4×MAX_TX_SIZE rejected pre-decode (-32602) (ADVERSARIAL) (MISSING)
- [ ] send_raw_transaction — valid tx admitted → {accepted:true,hash} + broadcast (HAPPY) (MISSING)
- [ ] send_raw_transaction — mempool rejection → -32002 with reason (ERROR) (MISSING)

**get_privacy_stats**
- [x] get_privacy_stats — returns result (HAPPY) (EXISTS: rpc_get_privacy_stats_returns_result in tests/rpc_endpoints.rs)
- [x] get_privacy_stats — payload non-empty / has expected fields (PROPERTY) (EXISTS: rpc_get_privacy_stats_has_fields in tests/rpc_endpoints.rs)

**get_shielded_anchor**
- [ ] get_shielded_anchor — returns {anchor,tree_size} (HAPPY) (MISSING)

**get_burn_stats**
- [x] get_burn_stats — circulating_supply string + max_supply == MAX_SUPPLY (HAPPY) (EXISTS: rpc_get_supply_info_has_fields in tests/rpc_endpoints.rs)
- [ ] get_burn_stats — active flag flips at fee_distribution_height (EDGE) (MISSING)
- [ ] get_burn_stats — deflation_threshold_fee_per_block computed (burn_pct==0 → 0) (PROPERTY) (MISSING)

**get_finality_info**
- [ ] get_finality_info — checkpoint math (last/next/blocks_until) + runtime max_reorg_depth (HAPPY) (MISSING)

**get_spark_anchor**
- [ ] get_spark_anchor — returns {root,size} (HAPPY) (MISSING)

**is_nullifier_spent**
- [x] is_nullifier_spent — valid 64-hex nullifier returns {nullifier,spent} (HAPPY) (EXISTS: rpc_is_nullifier_spent_returns_result in tests/rpc_endpoints.rs)
- [ ] is_nullifier_spent — hex &gt; 128 chars rejected pre-decode (ADVERSARIAL) (MISSING)
- [ ] is_nullifier_spent — non-32-byte decoded value rejected -32602 (ERROR) (MISSING)
- [ ] is_nullifier_spent — non-hex rejected -32602 (ERROR) (MISSING)

**is_spark_serial_spent**
- [ ] is_spark_serial_spent — valid serial returns {serial,spent} (HAPPY) (MISSING)
- [ ] is_spark_serial_spent — hex &gt; 128 chars rejected pre-decode (ADVERSARIAL) (MISSING)
- [ ] is_spark_serial_spent — non-32-byte / non-hex rejected -32602 (ERROR) (MISSING)

**get_decoys** (deprecated)
- [x] get_decoys — returns -32004 deprecation error (ERROR) (EXISTS: rpc_get_decoys_returns_deprecation_error in tests/rpc_endpoints.rs)

**get_decoy_distribution**
- [x] get_decoy_distribution — returns snapshot distribution (HAPPY) (EXISTS: rpc_decoy_locators_are_bound_to_snapshot in tests/rpc_endpoints.rs)

**get_outputs_by_locators**
- [x] get_outputs_by_locators — locators bound to snapshot (height,hash,policy_version) enforced (ADVERSARIAL) (EXISTS: rpc_decoy_locators_are_bound_to_snapshot in tests/rpc_endpoints.rs)
- [ ] get_outputs_by_locators — malformed params (bad tuple/types) rejected -32602 (ERROR) (MISSING)
- [ ] get_outputs_by_locators — resolve error surfaces -32000 (ERROR) (MISSING)

**get_network_info**
- [x] get_network_info — returns result (HAPPY) (EXISTS: rpc_get_network_info_returns_result in tests/rpc_endpoints.rs)
- [ ] get_network_info — incoming/outgoing/white/grey serialized as null (not 0) when unavailable (PROPERTY) (MISSING)

**get_sync_status**
- [x] get_sync_status — returns synced/height/target/progress/peers (HAPPY) (EXISTS: rpc_get_sync_status_returns_result in tests/rpc_endpoints.rs)
- [ ] get_sync_status — progress clamps to 1.0 / target==0 path (EDGE) (MISSING)

**get_anonymity_set**
- [x] get_anonymity_set — returns result (HAPPY) (EXISTS: rpc_get_anonymity_set_returns_result in tests/rpc_endpoints.rs)
- [ ] get_anonymity_set — outputs_per_block=0 at height 0 (EDGE) (MISSING)

**get_chain_events**
- [x] get_chain_events — returns result with `[]` params (HAPPY) (EXISTS: rpc_get_chain_events_returns_result in tests/rpc_endpoints.rs)
- [ ] get_chain_events — `[limit]` accepted; limit capped at 500 (EDGE) (MISSING)
- [ ] get_chain_events — malformed params fall back to default 100 (not error) (EDGE) (MISSING)

**get_mining_live**
- [x] get_mining_live — returns is_mining=false + zeroed fields on non-miner node (HAPPY) (EXISTS: rpc_get_mining_live_returns_result in tests/rpc_endpoints.rs)

**get_peers**
- [x] get_peers — returns count+peers on loopback (HAPPY) (EXISTS: rpc_get_peers_returns_result in tests/rpc_endpoints.rs)
- [x] get_peers — response shape privacy-safe on public bind (ADVERSARIAL) (EXISTS: rpc_public_bind_get_peers_response_shape_is_privacy_safe in tests/rpc_endpoints.rs)
- [x] get_peers — **unauthenticated public POST rejected (Bearer)** (ADVERSARIAL) (EXISTS: rpc_public_bind_rejects_missing_bearer_for_get_peers in tests/rpc_endpoints.rs)
- [ ] get_peers — empty list when p2p is None (EDGE) (MISSING)

**get_transaction**
- [x] get_transaction — unknown hash returns not-found (-5) (EDGE) (EXISTS: rpc_get_transaction_missing in tests/rpc_endpoints.rs)
- [x] get_transaction — invalid hex rejected -32602 (ERROR) (EXISTS: rpc_get_transaction_invalid_hex in tests/rpc_endpoints.rs)
- [ ] get_transaction — hash &gt; 64 chars rejected pre-decode (ADVERSARIAL) (MISSING)
- [ ] get_transaction — found tx returns full detail + privacy flags (HAPPY) (MISSING)

**get_asset_info**
- [x] get_asset_info — returns -32601 not-implemented (ERROR) (EXISTS: rpc_get_asset_info_returns_error in tests/rpc_endpoints.rs)

**get_block_range**
- [x] get_block_range — returns result (HAPPY) (EXISTS: rpc_get_block_range_returns_result in tests/rpc_endpoints.rs)
- [x] get_block_range — end &lt; start rejected -32602 (EDGE) (EXISTS: rpc_get_block_range_inverted in tests/rpc_endpoints.rs)
- [ ] get_block_range — span capped at MAX_RANGE=100 (EDGE) (MISSING)
- [ ] get_block_range — u64::MAX bounds saturate (no panic/overflow) (PROPERTY) (MISSING)

**get_output_digests**
- [ ] get_output_digests — valid range returns digests (HAPPY) (MISSING)
- [ ] get_output_digests — end&lt;start rejected; capped at 100 &amp; clamped to chain_height (EDGE) (MISSING)
- [ ] get_output_digests — start&gt;chain_height yields empty (no underflow) (PROPERTY) (MISSING)
- [ ] get_output_digests — malformed params rejected -32602 (ERROR) (MISSING)

**get_sync_checkpoints**
- [ ] get_sync_checkpoints — default stride returns checkpoints (HAPPY) (MISSING)
- [ ] get_sync_checkpoints — stride floored so ≤ MAX_CHECKPOINTS=512 entries (stride=1 DoS bound) (ADVERSARIAL) (MISSING)
- [ ] get_sync_checkpoints — stride clamped to ≤ 50_000 (EDGE) (MISSING)

**get_metrics**
- [x] get_metrics — chain_supply_atomic is string (HAPPY) (EXISTS: rpc_get_supply_info_has_fields in tests/rpc_endpoints.rs)
- [ ] get_metrics — carries chain/mempool/network metric fields (PROPERTY) (MISSING)

**get_health**
- [ ] get_health — healthy iff synced &amp;&amp; peers&gt;0; else degraded (HAPPY) (MISSING)
- [ ] get_health — checks sub-object reflects synced/has_peers/has_tip (PROPERTY) (MISSING)

**get_state_snapshot**
- [x] get_state_snapshot — total_supply is string (HAPPY) (EXISTS: rpc_get_supply_info_has_fields in tests/rpc_endpoints.rs)
- [ ] get_state_snapshot — includes tip_hash/total_difficulty/checkpoints (PROPERTY) (MISSING)

**get_blocks_batch**
- [ ] get_blocks_batch — [from,count] returns ≤100 hex blocks (HAPPY) (MISSING)
- [ ] get_blocks_batch — count capped at 100 (EDGE) (MISSING)
- [ ] get_blocks_batch — from near u64::MAX saturates to empty (PROPERTY) (MISSING)
- [ ] get_blocks_batch — malformed params rejected -32602 (ERROR) (MISSING)

**get_expected_reward**
- [ ] get_expected_reward — returns reward+in_cync for height (HAPPY) (MISSING)
- [ ] get_expected_reward — missing/bad height param rejected -32602 (ERROR) (MISSING)

**verify_keyimage_uniqueness**
- [ ] verify_keyimage_uniqueness — returns valid/duplicates/total on short chain (HAPPY) (MISSING)
- [ ] verify_keyimage_uniqueness — refused (-32003) when chain height &gt; 25_000 (ADVERSARIAL) (MISSING)

**check_zero_commitments_in_range**
- [ ] check_zero_commitments_in_range — detects zero commitment/stealth outputs (HAPPY) (MISSING)
- [ ] check_zero_commitments_in_range — span &gt; MAX_RPC_AUDIT_BLOCK_SPAN (128) rejected -32602 (ADVERSARIAL) (MISSING)
- [ ] check_zero_commitments_in_range — start&gt;end rejected -32602 (ERROR) (MISSING)

**verify_signatures_in_range**
- [ ] verify_signatures_in_range — checks CLSAG per non-coinbase input (HAPPY) (MISSING)
- [ ] verify_signatures_in_range — span &gt; 128 rejected (ADVERSARIAL) (MISSING)
- [ ] verify_signatures_in_range — start&gt;end rejected (ERROR) (MISSING)

**verify_range_proofs_in_range**
- [ ] verify_range_proofs_in_range — checks range proofs per tx (HAPPY) (MISSING)
- [ ] verify_range_proofs_in_range — span &gt; 128 rejected (ADVERSARIAL) (MISSING)
- [ ] verify_range_proofs_in_range — start&gt;end rejected (ERROR) (MISSING)

**verify_commitment_balance_in_range**
- [ ] verify_commitment_balance_in_range — checks balance proof per tx (HAPPY) (MISSING)
- [ ] verify_commitment_balance_in_range — span &gt; 128 rejected (ADVERSARIAL) (MISSING)
- [ ] verify_commitment_balance_in_range — start&gt;end rejected (ERROR) (MISSING)

**full_chain_audit**
- [ ] full_chain_audit — merkle root + coinbase + CLSAG + range + balance checks over range (HAPPY) (MISSING)
- [ ] full_chain_audit — span &gt; 128 rejected (ADVERSARIAL) (MISSING)
- [ ] full_chain_audit — start&gt;end rejected (ERROR) (MISSING)

**Cross-cutting / unknown method**
- [x] dispatch — unknown method returns method-not-found error (ERROR) (EXISTS: rpc_unknown_method_returns_error in tests/rpc_endpoints.rs)

**Transport / middleware (RpcBearerValidator + rate limiter + helpers) — applies to ALL methods**
- [x] validator — non-upgrade GET without auth rejected (ADVERSARIAL) (EXISTS: bearer_validator_rejects_non_upgrade_get_without_auth in src/rpc/server.rs; rpc_public_bind_rejects_plain_get_without_upgrade in tests/rpc_endpoints.rs)
- [x] validator — WS-upgrade GET with valid Bearer accepted (HAPPY) (EXISTS: bearer_validator_accepts_ws_upgrade_get_with_auth in src/rpc/server.rs; rpc_public_bind_ws_upgrade_get_with_bearer_is_not_unauthorized in tests/rpc_endpoints.rs)
- [x] validator — WS-upgrade GET without Bearer rejected (ADVERSARIAL) (EXISTS: rpc_public_bind_rejects_ws_upgrade_get_without_bearer in tests/rpc_endpoints.rs)
- [x] validator — wrong token rejected under hashed compare (even differing length) (ADVERSARIAL) (EXISTS: bearer_validator_rejects_wrong_token_under_hashed_comparison in src/rpc/server.rs)
- [x] validator — plaintext key never retained (only SHA-256 hash) (PROPERTY) (EXISTS: bearer_validator_does_not_retain_plaintext in src/rpc/server.rs)
- [x] validator — accepts current AND previous key during rotation window (EDGE) (EXISTS: bearer_validator_accepts_previous_key_during_rotation in src/rpc/server.rs)
- [x] serialize_peer_info — redacts sensitive fields when minimized (ADVERSARIAL) (EXISTS: peer_serialization_redacts_sensitive_fields_when_minimized in src/rpc/server.rs)
- [x] supply_atomic_decimal — preserves values above u64 (PROPERTY) (EXISTS: aggregate_supply_decimal_preserves_values_above_u64 in src/rpc/server.rs)
- [ ] validator — non-OPTIONS/GET/POST method (PUT/DELETE) → 401 (ADVERSARIAL) (MISSING)
- [ ] validator — OPTIONS preflight exempt from auth AND rate limit (EDGE) (MISSING)
- [ ] rate limiter — jsonrpsee 429 returned when per-IP limit tripped end-to-end (ADVERSARIAL) (MISSING) [RPC layer; REST-proxy layer is covered separately]
- [ ] rate limiter — loopback IP whitelisted (never limited at RPC layer) (EDGE) (MISSING)
- [ ] client_ip_from_request — XFF honored only with COINCYNC_RPC_XFF_PROXY_ACK=1, else loopback (ADVERSARIAL) (MISSING)
- [ ] start_rpc_server — refuses tls_enabled=true (native TLS not wired) (ERROR) (MISSING)
- [ ] start_rpc_server — auth_enabled without api_key refused (ERROR) (MISSING)
- [ ] start_rpc_server — non-loopback bind without api_key refused (ADVERSARIAL) (MISSING)
- [ ] start_rpc_server — non-loopback + no TLS + no COINCYNC_RPC_TLS_PROXY_ACK refused (ADVERSARIAL) (MISSING)
- [ ] start_rpc_server — api_key set but loopback+auth_disabled → unauthenticated (warn path) (EDGE) (MISSING)

---

### src/rpc/lightwallet.rs

*(Handlers are pure `LightWalletServer` API + free fns; no `/wallet/*` route is wired in this build — `is_output_for_keys` is dead code.)*
- [x] fork_point_in_journal — empty journal → None (EDGE) (EXISTS: fork_point_journal_empty_is_none in src/rpc/lightwallet.rs)
- [x] fork_point_in_journal — all-canonical → tip height (HAPPY) (EXISTS: fork_point_journal_all_canonical_returns_tip in src/rpc/lightwallet.rs)
- [x] fork_point_in_journal — divergence → deepest common ancestor (PROPERTY) (EXISTS: fork_point_journal_returns_last_common_ancestor in src/rpc/lightwallet.rs)
- [x] fork_point_in_journal — no entry canonical → None (EDGE) (EXISTS: fork_point_journal_none_when_no_entry_canonical in src/rpc/lightwallet.rs)
- [x] fork_point_in_journal — skips unknown/above-tip heights (EDGE) (EXISTS: fork_point_journal_skips_unknown_heights in src/rpc/lightwallet.rs)
- [x] parse_journal_hex — round-trips valid, tolerates 0x, rejects non-hex/wrong-length (ROUND-TRIP) (EXISTS: parse_journal_hex_roundtrips_and_rejects_malformed in src/rpc/lightwallet.rs)
- [x] COINCYNC_SPEC — coin spec constants correct (ticker/decimals/ring/supply/privacy) (PROPERTY) (EXISTS: coin_spec_is_correct in src/rpc/lightwallet.rs)
- [x] compute_view_tag — deterministic for same inputs (PROPERTY) (EXISTS: view_tag_is_deterministic in src/rpc/lightwallet.rs) [dead-code helper]
- [x] compute_view_tag — different index → (valid) tag (PROPERTY) (EXISTS: different_index_different_tag in src/rpc/lightwallet.rs) [dead-code helper]
- [ ] scan — happy path returns detected outputs + has_more/ownership_verified=false (HAPPY) (MISSING)
- [ ] scan — max_blocks &gt; MAX_SCAN_BLOCKS_PER_REQ (5000) rejected (ADVERSARIAL) (MISSING)
- [ ] scan — output cap MAX_SCAN_OUTPUTS (10_000) → early stop, has_more, resume at scanned_to_height (EDGE) (MISSING)
- [ ] scan — invalid view_public/spend_public hex rejected (ERROR) (MISSING)
- [ ] scan — start_height saturating_add(max_blocks) at u64::MAX (no overflow) (PROPERTY) (MISSING)
- [ ] chain_info — ring_size is height-aware (ring_size_at_height(tip+1)) (PROPERTY) (MISSING)
- [ ] get_digests — capped at 100 blocks (saturating) (EDGE) (MISSING)
- [ ] submit_transaction — valid tx admitted returns hash; bad hex/borsh/mempool-reject errors (HAPPY/ERROR) (MISSING)
- [ ] estimate_fee — size×MIN_FEE_PER_BYTE + 20% buffer (PROPERTY) (MISSING)
- [ ] find_fork_point (single-pair) — canonical known pair → Some(height), else None (v1.0 stub) (EDGE) (MISSING)
- [ ] parse_public_key — rejects non-32-byte / non-hex (ERROR) (MISSING)

---

### src/rpc/websocket.rs

*(`SubscriptionManager` — no integration route in this build; only in-file unit tests.)*
- [x] subscribe/broadcast/unsubscribe — subscribe→receive event→unsubscribe→count 0 (HAPPY) (EXISTS: test_subscription_manager in src/rpc/websocket.rs)
- [x] subscribe — distinct ids, count tracking, double-unsubscribe returns false (HAPPY/EDGE) (EXISTS: test_subscription_creation in src/rpc/websocket.rs)
- [x] Event — new_block serializes with snake_case type + data (ROUND-TRIP) (EXISTS: test_event_serialization in src/rpc/websocket.rs)
- [ ] subscribe — per-client limit MAX_SUBSCRIPTIONS_PER_CLIENT (10) enforced (ADVERSARIAL) (MISSING)
- [ ] subscribe — global limit MAX_TOTAL_SUBSCRIPTIONS (10_000) enforced (ADVERSARIAL) (MISSING)
- [ ] subscribe — TOCTOU: concurrent subscribes can't exceed per-client limit (both locks held) (PROPERTY) (MISSING)
- [ ] broadcast — only delivers to subscribers whose event_types match (PROPERTY) (MISSING)
- [ ] broadcast — event also reaches global_receiver (HAPPY) (MISSING)
- [ ] unsubscribe — decrements per-client count; removes map entry at 0 (EDGE) (MISSING)
- [ ] WsMessage — deserialize subscribe/unsubscribe/ping tagged messages (ROUND-TRIP) (MISSING)
- [ ] WsMessage — bad/unknown message rejected (serde error) (ERROR) (MISSING)
- [ ] broadcast — lagging receiver (channel full &gt; MAX_PENDING_MESSAGES=100) handled (EDGE) (MISSING)

---

### src/rpc/ratelimit.rs

*(`rpc::ratelimit::RateLimiter` — covered ONLY by its own in-file tests; `tests/rate_limiter.rs` tests a different type.)*
- [x] check — allows requests up to max_requests + burst (HAPPY) (EXISTS: test_rate_limiter_allows_requests in src/rpc/ratelimit.rs)
- [x] check — blocks/ban once over limit → RateLimited (ADVERSARIAL) (EXISTS: test_rate_limiter_blocks_excess in src/rpc/ratelimit.rs)
- [x] check — whitelist (127.0.0.1) bypass always allowed (EDGE) (EXISTS: test_whitelist_bypass in src/rpc/ratelimit.rs)
- [x] check — LRU eviction reclaims expired entries to admit new IP (PROPERTY) (EXISTS: test_lru_eviction_with_expired_entries in src/rpc/ratelimit.rs)
- [x] check — at capacity with all-active entries → new IP RateLimited, no active eviction (ADVERSARIAL) (EXISTS: test_lru_eviction_rejects_when_all_active in src/rpc/ratelimit.rs)
- [ ] check — window reset re-allows after window elapses (EDGE) (MISSING)
- [ ] check — ban expiry clears banned_until and re-admits (EDGE) (MISSING)
- [ ] check — ban_count ≥ max_bans → PermanentlyBlocked (ADVERSARIAL) (MISSING)
- [ ] check — PermanentlyBlocked entry survives LRU eviction (P7-Rl1) (PROPERTY) (MISSING)
- [ ] check_sync — fail-CLOSED (RateLimited) on lock contention (try_write fails) (ADVERSARIAL) (MISSING)
- [ ] check_sync — parity with check: ban/permanent/window logic (PROPERTY) (MISSING)
- [ ] check_sync — loopback whitelist bypass (EDGE) (MISSING)
- [ ] remaining — reports remaining quota; u32::MAX for whitelist (HAPPY) (MISSING)
- [ ] ban — manual ban sets banned_until + increments ban_count (HAPPY) (MISSING)
- [ ] unban — clears banned_until (HAPPY) (MISSING)
- [ ] stats — active_ips/banned_ips/tracked_ips/whitelist_size accounting (PROPERTY) (MISSING)
- [ ] cleanup — retains only banned or recently-active entries (PROPERTY) (MISSING)
- [ ] add_whitelist — added IP no longer limited; no duplicates (EDGE) (MISSING)
- [ ] config — strict()/relaxed()/default() thresholds distinct (PROPERTY) (MISSING)
- [ ] concurrency — parallel check() on same IP counts atomically (no lost updates) (PROPERTY) (MISSING)

---

### src/rpc/rest.rs

*(axum router proxying to jsonrpsee; own fixed-window limiters + WS.)*
- [x] GET /api/v1/health — returns 200 (HAPPY) (EXISTS: test_health_endpoint in src/rpc/rest.rs)
- [x] GET /api/v1/health/live — 200 regardless of backend reachability (HAPPY) (EXISTS: test_health_live_returns_200_regardless_of_backend in src/rpc/rest.rs)
- [x] GET /api/v1/health/ready — 503 when backend unreachable (ADVERSARIAL) (EXISTS: test_health_ready_returns_503_when_backend_unreachable in src/rpc/rest.rs)
- [x] param routes (`:hash`/`:height`/`:id`) — match real values, not 404 (axum syntax regression) (PROPERTY) (EXISTS: param_routes_match_real_values_not_404 in src/rpc/rest.rs)
- [x] validate_hex_hash — accepts 64-hex, rejects short/non-hex (ERROR) (EXISTS: test_validate_hex_hash_valid / _too_short / _non_hex in src/rpc/rest.rs)
- [x] Pagination — defaults (page 1, DEFAULT_PAGE_SIZE, offset 0) (EDGE) (EXISTS: test_pagination_defaults in src/rpc/rest.rs)
- [x] Pagination — clamps page≥1, limit≤MAX_PAGE_SIZE (EDGE) (EXISTS: test_pagination_clamp in src/rpc/rest.rs)
- [x] RPC_ALLOWED_METHODS — contains required explorer methods (PROPERTY) (EXISTS: test_rpc_allowlist_has_explorer_methods in src/rpc/rest.rs)
- [x] RPC_ALLOWED_METHODS — blocks sensitive/state-mutating methods (submit_*, transfer, get_mining_live, get_metrics, get_decoys) (ADVERSARIAL) (EXISTS: test_rpc_allowlist_blocks_sensitive in src/rpc/rest.rs)
- [x] circulating supply — u128-safe parse + micro formatting above u64 (PROPERTY) (EXISTS: circulating_formatter_preserves_supply_above_u64 in src/rpc/rest.rs)
- [x] circulating supply — parser rejects numeric/invalid/missing total_emitted (ERROR) (EXISTS: circulating_parser_rejects_lossy_or_invalid_rpc_values in src/rpc/rest.rs)
- [x] POST /rpc — proxy per-second global+IP rate limit → 429 under burst (ADVERSARIAL) (EXISTS: rest_rpc_proxy_rate_limit_returns_429_under_burst in tests/rest_rate_limit.rs)
- [x] GET /api/v1/stats — rate limit → 429 under burst (ADVERSARIAL) (EXISTS: rest_stats_rate_limit_returns_429_under_burst in tests/rest_rate_limit.rs)
- [ ] POST /rpc — disallowed method → 403 Forbidden (ADVERSARIAL) (MISSING)
- [ ] POST /rpc — body &gt; 64KiB → 413 Payload Too Large (ADVERSARIAL) (MISSING)
- [ ] POST /rpc — invalid JSON → 400 (ERROR) (MISSING)
- [ ] POST /rpc — get_info response strips privacy/operator fields on public proxy (ADVERSARIAL) (MISSING)
- [ ] jsonrpc_call — backend error code mapping (-5→404, -32602→400, else→500) (PROPERTY) (MISSING)
- [ ] jsonrpc_call — backend unreachable/invalid → 502, sanitized message (ERROR) (MISSING)
- [ ] jsonrpc_call — forwards Authorization: Bearer when rpc_bearer set (PROPERTY) (MISSING)
- [ ] GET /api/v1/status — curated get_info subset, omits anonymity_set/effective_ring_size (ADVERSARIAL) (MISSING)
- [ ] GET /api/v1/supply(+/circulating,/max) — happy payloads (HAPPY) (MISSING)
- [ ] GET /api/v1/block/hash/:hash — invalid hash → 400 (ERROR) (MISSING)
- [ ] GET /api/v1/block/height/:height — happy + non-numeric → 404/400 (HAPPY/ERROR) (MISSING)
- [ ] GET /api/v1/block/:height/transactions — returns tx list (HAPPY) (MISSING)
- [ ] GET /api/v1/blocks/recent — pagination + rate limit (global+IP) → 429 (ADVERSARIAL) (MISSING)
- [ ] GET /api/v1/transaction/:hash — invalid hash → 400; missing → 404 (ERROR) (MISSING)
- [ ] POST /api/v1/transaction/submit — happy broadcast (HAPPY) (MISSING)
- [ ] POST /api/v1/transaction/submit — non-hex / &gt;1MiB tx_hex → 400 (ADVERSARIAL) (MISSING)
- [ ] POST /api/v1/transaction/submit — rate limit (SUBMIT_MAX_REQ_PER_SEC=5) → 429 (ADVERSARIAL) (MISSING)
- [ ] GET /api/v1/mempool + /stats — happy payloads (HAPPY) (MISSING)
- [ ] GET /api/v1/search — height/hash/tx/asset resolution (HAPPY) (MISSING)
- [ ] GET /api/v1/search — empty q → 400; q&gt;MAX_SEARCH_QUERY_LEN(128) → 400; no-match → 404 (ADVERSARIAL) (MISSING)
- [ ] GET /api/v1/network — curated get_info subset omitting effective_ring_size (ADVERSARIAL) (MISSING)
- [ ] GET /api/v1/anonymity — happy payload (HAPPY) (MISSING)
- [ ] GET /api/v1/peers — count-only, note about auth (privacy) (ADVERSARIAL) (MISSING)
- [ ] GET /api/v1/stats — window aggregation with &lt;2 blocks short-circuit (EDGE) (MISSING)
- [ ] GET /api/v1/emission — curve points capped at MAX_EMISSION_POINTS(1000) + rate limit (EDGE) (MISSING)
- [ ] GET /api/v1/events — happy payload (HAPPY) (MISSING)
- [ ] GET /api/v1/asset/:id + /assets — 410 Gone (ERROR) (MISSING)
- [ ] GET /api/v1/ws — per-IP cap MAX_WS_PER_IP(5) → 429 (ADVERSARIAL) (MISSING)
- [ ] GET /api/v1/ws — global cap MAX_WS_CONNECTIONS(128) → 503, per-IP reservation released (ADVERSARIAL) (MISSING)
- [ ] ws_handler — ping→pong; new_block/mempool/status push; idle timeout(300s) close (HAPPY/EDGE) (MISSING)
- [ ] ws_handler — WsConnGuard decrements global + per-IP counters on drop (PROPERTY) (MISSING)
- [ ] client_ip_from_headers — XFF/X-Real-IP honored only when COINCYNC_TRUST_PROXY_HEADERS set, else "unknown" (ADVERSARIAL) (MISSING)
- [ ] enforce_ip_fixed_window_limit — opportunistic prune at IP_WINDOW_MAX_ENTRIES(4096) (PROPERTY) (MISSING)
- [ ] CORS — restricted to allowed origins + env COINCYNC_CORS_ORIGINS (ADVERSARIAL) (MISSING)
- [ ] run_rest_api — explorer mount only when serve_explorer, warns on non-loopback (EDGE) (MISSING)

---

### src/rpc/types.rs

- [x] BlockInfo — serde round-trip (ROUND-TRIP) (EXISTS: test_block_info_serde_roundtrip in src/rpc/types.rs)
- [x] BalanceInfo — serde round-trip (ROUND-TRIP) (EXISTS: test_balance_info_serde_roundtrip in src/rpc/types.rs)
- [ ] error_codes — constants match JSON-RPC + custom code contract (PROPERTY) (MISSING)
- [ ] NetworkInfo — Option fields serialize null vs 0 distinction (PROPERTY) (MISSING)
- [ ] TransactionInfo/UtxoInfo/TransferRequest/… — serde round-trip (ROUND-TRIP) (MISSING)

---

### src/rpc/tls.rs

- [x] generate_self_signed_cert — creates cert+key, deterministic 64-char fingerprint, reuses existing (HAPPY/PROPERTY) (EXISTS: test_generate_self_signed_cert in src/rpc/tls.rs)
- [x] load_client_tls_config — no fingerprint (accept-any) config builds (EDGE) (EXISTS: test_load_client_config_no_fingerprint in src/rpc/tls.rs)
- [x] load_client_tls_config — valid 64-hex fingerprint config builds (HAPPY) (EXISTS: test_load_client_config_with_fingerprint in src/rpc/tls.rs)
- [x] load_client_tls_config — invalid fingerprint hex/length rejected (ERROR) (EXISTS: test_load_client_config_invalid_fingerprint in src/rpc/tls.rs)
- [x] fingerprint pinning — pin to generated cert's fingerprint (PROPERTY) (EXISTS: test_fingerprint_pinning_verification in src/rpc/tls.rs)
- [x] cert expiry — generated cert loads into server config (validity bounds) (HAPPY) (EXISTS: test_cert_expiry in src/rpc/tls.rs)
- [ ] Blake3CertVerifier — fingerprint MISMATCH rejected in verify_server_cert (ADVERSARIAL) (MISSING)
- [ ] set_restrictive_permissions — key file created owner-only (0o600 unix / readonly win) (ADVERSARIAL) (MISSING)
- [ ] load_pem_cert_and_key — empty/no-cert or no-key PEM rejected (ERROR) (MISSING)
- [ ] load_pem_cert_and_key — PKCS8 / PKCS1 / SEC1 key tags all parsed (EDGE) (MISSING)
- [ ] verify_tls12/tls13_signature — handshake signature verified even in accept-any mode (PROPERTY) (MISSING)

---

## Per-file coverage counts

| file | total | exist | missing |
|---|---:|---:|---:|
| src/rpc/server.rs | 106 | 43 | 63 |
| src/rpc/lightwallet.rs | 20 | 9 | 11 |
| src/rpc/websocket.rs | 12 | 3 | 9 |
| src/rpc/ratelimit.rs | 20 | 5 | 15 |
| src/rpc/rest.rs | 49 | 13 | 36 |
| src/rpc/types.rs | 5 | 2 | 3 |
| src/rpc/tls.rs | 11 | 6 | 5 |
| **AREA TOTAL** | **223** | **81** | **142** |

**Highest-value gaps (adversarial / bounds, entirely untested):** the six chain-audit methods' `MAX_RPC_AUDIT_BLOCK_SPAN=128` rejection and `verify_keyimage_uniqueness` height cap; per-method pre-decode length caps on `submit_block`/`send_raw_transaction`/`is_nullifier_spent`/`is_spark_serial_spent`/`get_transaction`; `get_sync_checkpoints` stride-floor DoS bound; the RPC-layer (jsonrpsee) 429 rate-limit trip and XFF-spoofing path (only the REST-proxy layer is tested); `RateLimiter` window-reset / ban-expiry / permanent-block / `check_sync` fail-closed; websocket per-client &amp; global subscription caps; and the REST `/rpc` 403/413/400 and get_info privacy-stripping paths. `start_rpc_server`'s five fail-safe startup gates (TLS/auth/loopback) are also untested.