# CoinCync P2P Network — Exhaustive Behavioral Test Plan

Legend: category ∈ HAPPY / EDGE / ERROR / ADVERSARIAL / LIVENESS / PROPERTY / ROUND-TRIP. Status = **EXISTS** (found in `#[cfg(test)]` or `tests/`) or **MISSING**. Handler tests need a driver that calls `process_message`/handlers directly with a real `DashMap`/`ChainSync`/`PeerScorer` — almost none of that harness exists today, so most handler-level and all liveness tests are MISSING.

### src/network/protocol.rs
- [ ] HAPPY `Message::ping/version/verack/flare/chain_work/inv_*/blocks/txs` build correct type byte — EXISTS (test_message_creation, test_version_message, flare/chain_work roundtrips)
- [ ] ROUND-TRIP FlareMessage / ChainWorkMessage borsh round-trip — EXISTS
- [ ] PROPERTY `MessageType::try_from` accepts exactly the 30 defined discriminants, rejects all others (incl. gaps 4-9,16-19,25-29,32-39,42-49,52-59,66-69,72-79,82-98,100-255) — PARTIAL (p2p_adversarial header_rejects_unknown/gaps only samples a few; MISSING full sweep)
- [ ] PROPERTY every `MessageType::max_size()` ≤ MAX_MESSAGE_SIZE and ≥ its real serialized min — MISSING
- [ ] PROPERTY `try_from(x as u8) == x` round-trips for all variants (discriminant stability guard) — PARTIAL (only ChainWork==51 guarded; MISSING for rest)
- [ ] EDGE `MessageHeader::validate` rejects wrong magic / length&gt;MAX_MESSAGE_SIZE — MISSING (unit); covered indirectly by fuzz_protocol wrong_magic/oversized — EXISTS(partial)
- [ ] PROPERTY `verify_checksum` false on any single-bit payload flip — MISSING (framing checksum_failure covers one flip)
- [ ] ERROR `VersionMessage::validate` rejects user_agent &gt; 256 bytes — MISSING
- [ ] ERROR `VersionMessage::validate` rejects unsupported protocol version (below MIN, above MAX) — MISSING
- [ ] ADVERSARIAL `VersionMessage` with user_agent at exactly 256 and 257 bytes (boundary) — MISSING
- [ ] ERROR `GetHeadersMessage::validate` rejects locator.len() &gt; MAX_LOCATOR_SIZE(64) — MISSING
- [ ] ERROR `HeadersMessage::validate` rejects headers.len() &gt; 2000 — MISSING
- [ ] ERROR `GetBlocksMessage::validate` rejects hashes.len() &gt; 500 — MISSING
- [ ] ERROR `BlocksMessage::validate` rejects blocks.len() &gt; 500 — MISSING
- [ ] ERROR `NotFoundMessage::validate` rejects hashes.len() &gt; 500 — MISSING
- [ ] ADVERSARIAL `InvMessage::validate` rejects len&gt;500 AND rejects duplicate hashes — EXISTS (dup + distinct cases)
- [ ] EDGE `InvMessage::validate` at exactly MAX_INV_SIZE distinct hashes passes; +1 fails — MISSING
- [ ] ERROR `TxsMessage::validate` rejects transactions.len() &gt; 100 — MISSING
- [ ] ERROR `AddrMessage::validate` rejects addresses.len() &gt; 1000 — MISSING
- [ ] ADVERSARIAL `RejectMessage::validate` rejects oversized message/reason/data fields (all three, incl. the historically-unbounded `message`) — MISSING
- [ ] ADVERSARIAL borsh decode of each Vec-bearing message with an absurd length prefix does not pre-allocate GBs (fuzz decoder) — PARTIAL (fuzz_protocol covers tx/block/header; MISSING for Inv/Addr/Txs/Headers/GetBlocks/NotFound/Reject/Version)
- [ ] PROPERTY `Message::to_bytes` then re-parse header yields identical magic/type/length/checksum — MISSING

### src/network/framing.rs
- [ ] HAPPY legacy read/write round-trip through duplex — EXISTS (legacy_read_api, normalized_round_trip)
- [ ] ROUND-TRIP fragmented header/payload reassembly across multiple reads — MISSING (test_fragmented_message is a stub asserting only HEADER_SIZE==13)
- [ ] LIVENESS cancellation mid-payload preserves partial bytes on `self` (resume yields full message, no "invalid magic") — PARTIAL (cancellation_preserves_partial_payload_reservation covers budgeted path; MISSING for header-phase cancellation and multi-cancel churn)
- [ ] ADVERSARIAL Slowloris: 1 byte per DEFAULT_READ_TIMEOUT stalls → inactivity timeout fires ("read stalled") — MISSING
- [ ] ADVERSARIAL header claims max length but peer never sends payload → only ≤64KB committed, budget/timeout bounds it — MISSING
- [ ] ADVERSARIAL oversized wire length (&gt; MAX_MESSAGE_SIZE) rejected at `validate_wire_header` before payload read — PARTIAL (normalized_reader_enforces_semantic_type_limit; MISSING unnormalized path)
- [ ] ADVERSARIAL per-type wire cap: Ping frame &gt; Ping.max_size() rejected pre-alloc — EXISTS (normalized_reader_enforces_semantic_type_limit)
- [ ] ERROR checksum mismatch → InvalidMessage, reservation released — EXISTS (checksum_failure_releases_payload_reservation)
- [ ] ERROR connection closed (n==0) mid-header and mid-payload → ConnectionFailed, state reset — MISSING
- [ ] ADVERSARIAL budget exhaustion mid-payload → P2pMemoryBudgetExceeded, no leak — EXISTS (payload_growth_over_budget)
- [ ] PROPERTY empty-payload message uses zero budget — EXISTS
- [ ] EDGE reservation held until BudgetedMessage dropped, then released — EXISTS
- [ ] ADVERSARIAL normalized reader rejects non-canonical (unmarked / non-bucket) frame size — EXISTS (rejects_unmarked_payload)
- [ ] ROUND-TRIP normalized framer denormalize recovers exact payload for many sizes — PARTIAL (one size; MISSING boundary/bucket-edge sweep)
- [ ] ERROR `write_message` rejects payload &gt; type max_size — MISSING
- [ ] ADVERSARIAL write of unknown msg_type byte → try_from error before send — MISSING
- [ ] PROPERTY (RateLimiter) token consume/deny/refill/burst — EXISTS (2 tests)
- [ ] PROPERTY (ExponentialBackoff) increasing + reset — EXISTS
- [ ] LIVENESS a peer that stops READING must not freeze the framer's write path (covered at connection layer; note here) — MISSING at framer

### src/network/node/dispatch/mod.rs (process_message router)
- [ ] ADVERSARIAL Verack/Ping/Pong/Flare accepted pre-handshake; all others (Headers, Blocks, GetData, Addr, InvBlock, Txs, …) dropped until PeerState::Connected — MISSING
- [ ] ADVERSARIAL unknown msg_type_id → Err from try_from, processor logs, does not crash processor loop — MISSING
- [ ] EDGE Padding discarded before peer byte-accounting (never reaches unreachable! arm) — MISSING
- [ ] ADVERSARIAL oversized light-query payload (GetFilters/GetOutputDigests/GetFilterCheckpoints/GetKeyImageStatus &gt; 8KB) → OversizedMessage score + drop — MISSING
- [ ] PROPERTY `peer.touch()` + bytes_recv incremented for every accepted type — MISSING
- [ ] LIVENESS a handler that awaits a full peer queue (send_to_peer) must not block the single shared processor for other peers — MISSING (critical C2-class)
- [ ] ADVERSARIAL a message for an unknown peer_id (not in `peers`) is handled without panic (all `.get` are Option) — MISSING

### src/network/node/dispatch/control.rs
- [ ] ADVERSARIAL `handle_verack` — a Verack with no prior Version does NOT reach Connected (state stays, returns early) — MISSING
- [ ] ADVERSARIAL `handle_verack` replay on already-Connected peer is a no-op (does NOT re-run GetHeaders / re-issue nonce / wedge sync) — MISSING
- [ ] HAPPY `handle_verack` VersionReceived→Connected, sends GetAddr, sends GetHeaders only if peer_height&gt;our_height — MISSING
- [ ] EDGE `handle_verack` outbound peer added to Dandelion pool; inbound not — MISSING
- [ ] LIVENESS `handle_verack` when `begin_headers_request` returns None (cycle owned) → no second GetHeaders issued — MISSING
- [ ] EDGE `handle_verack` GetHeaders send fails → `cancel_headers_request` rolls back the nonce/time — MISSING
- [ ] ADVERSARIAL `handle_version` payload &gt; 1024 → OversizedMessage score + disconnect — MISSING
- [ ] ADVERSARIAL `handle_version` self-connection nonce match → disconnect WITHOUT marking address as self (no address-book poison / eclipse) — MISSING
- [ ] ERROR `handle_version` unparseable borsh → ProtocolViolation score + disconnect — MISSING
- [ ] ERROR `handle_version` failing `validate()` (bad version / long UA) → ProtocolViolation + disconnect — MISSING
- [ ] ADVERSARIAL `handle_version` user_agent control chars stripped before store — MISSING
- [ ] HAPPY `handle_version` sets version/height/tip_hash/state=VersionReceived, sends Verack+Flare, marks scorer.validated, updates sync target — MISSING
- [ ] ADVERSARIAL `handle_version` replay (second Version on VersionReceived/Connected peer) does not regress state or duplicate side-effects — MISSING
- [ ] EDGE `handle_flare` stores capabilities; oversized(&gt;32B)/malformed silently ignored (never a disconnect) — MISSING
- [ ] HAPPY `handle_flare` peer with CAP_CHAINWORK triggers immediate ChainWork send — MISSING
- [ ] ADVERSARIAL `handle_chain_work` replay/flood does not wedge sync; advertised work is a claim only, feeds `update_peer_difficulty_for` — MISSING
- [ ] EDGE `handle_chain_work` oversized(&gt;256B)/malformed silently ignored — MISSING
- [ ] ADVERSARIAL `handle_ping` malformed (&lt;8 bytes) → ProtocolViolation score, no pong — MISSING
- [ ] HAPPY `handle_ping` echoes nonce as Pong — MISSING
- [ ] EDGE `handle_reject` adjusts reputation -5 only (never feeds ban scorer) — MISSING
- [ ] PROPERTY `handle_pong` is a no-op — MISSING

### src/network/node/dispatch/chain.rs
- [ ] PROPERTY `invblock_near_tip` regime boundaries — EXISTS (cip019_invblock_near_tip_regime)
- [ ] ADVERSARIAL `handle_blocks` invalid-PoW block → InvalidBlockPoW instant-ban score, block NOT emitted, not credited — PARTIAL (invalid_blocks_are_not_credited covers not-credited/not-emitted via easy target; MISSING explicit ban-score assertion)
- [ ] ADVERSARIAL `handle_blocks` wrong network_magic → WrongNetwork score, block skipped — MISSING
- [ ] ADVERSARIAL `handle_blocks` oversized block / too-many-txs → record_block_failure, skipped — MISSING
- [ ] ADVERSARIAL `handle_blocks` unsolicited valid-PoW block flood → emitted to event bus but NOT stored as orphan before PoW; bounded memory (no per-message unbounded growth) — MISSING
- [ ] EDGE `handle_blocks` empty Blocks reply → record_empty_blocks_response (demote), no state clear — MISSING
- [ ] ADVERSARIAL `handle_blocks` blocks.len()&gt;500 → OversizedMessage — MISSING
- [ ] ERROR `handle_blocks` borsh garbage → ProtocolViolation — PARTIAL (p2p_adversarial block_deserialize_garbage tests parser, not handler)
- [ ] HAPPY `handle_inv_block` post-IBD unknown hashes ≤4 → direct GetBlocks + track_direct_request — MISSING
- [ ] HAPPY `handle_inv_block` post-IBD unknown hashes &gt;4 → trigger_resync — MISSING
- [ ] LIVENESS `handle_inv_block` during IBD sends GetHeaders to refresh peer.height (does NOT freeze target at handshake value) — MISSING
- [ ] LIVENESS `handle_inv_block` near-tip during IBD → trigger_resync or arm_near_tip_catchup (small gap closes, not stuck-behind) — MISSING
- [ ] ADVERSARIAL `handle_inv_block` does NOT speculatively bump peer_height (no best_known latch wedge) — MISSING
- [ ] ADVERSARIAL `handle_inv_block` InvBlock replay/flood does not re-issue unbounded GetHeaders while a request is pending — MISSING
- [ ] ERROR `handle_inv_block` oversized(&gt;64KB)/borsh-err/validate-err scoring paths — MISSING
- [ ] HAPPY `handle_get_blocks` returns found blocks, always responds (even empty) so requester frees slots — MISSING
- [ ] ADVERSARIAL `handle_get_blocks` caps response at MAX_BLOCK_HASHES; oversized payload → OversizedMessage — MISSING
- [ ] LIVENESS `handle_get_blocks` DB read under block_in_place doesn't freeze worker (many-hash request) — MISSING
- [ ] HAPPY `handle_get_data` sends each block as individual BlockData — MISSING
- [ ] ADVERSARIAL `handle_block_data` invalid PoW → InvalidBlockPoW, not credited/emitted — MISSING
- [ ] ADVERSARIAL `handle_block_data` wrong magic → WrongNetwork — MISSING
- [ ] HAPPY `handle_block_data` valid → record_block_success + relay_scores.credit_block + emit — MISSING
- [ ] ERROR `handle_block_data` unparseable → ProtocolViolation — MISSING

### src/network/node/dispatch/headers.rs
- [ ] HAPPY `validate_header_batch` accepts connected valid-PoW header — EXISTS
- [ ] ERROR rejects self-declared easy target after difficulty activates (InvalidBlockPoW) — EXISTS
- [ ] ERROR rejects non-contiguous batch (ProtocolViolation) — EXISTS
- [ ] ERROR rejects header with unknown parent — EXISTS
- [ ] ADVERSARIAL rejects wrong network magic (WrongNetwork) — MISSING
- [ ] ADVERSARIAL rejects non-sequential height / version-downgrade / non-advancing timestamp / MTP violation — MISSING
- [ ] ADVERSARIAL rejects checkpoint-vote referencing future height — MISSING
- [ ] ADVERSARIAL rejects hardcoded-checkpoint mismatch (InvalidBlockPoW) — MISSING
- [ ] ADVERSARIAL rejects invalid PoW at index i, reports correct index/offense — MISSING
- [ ] EDGE `header_history` returns Err on missing ancestor mid-window — MISSING
- [ ] ADVERSARIAL `handle_headers` replay: Headers with a valid but already-consumed nonce → validate_header_nonce false → ignored (no double queue, no sync wedge) — MISSING
- [ ] ADVERSARIAL `handle_headers` cross-peer nonce: nonce issued to peer A sent by peer B → rejected WITHOUT consuming (A's response not griefed) — MISSING
- [ ] ADVERSARIAL `handle_headers` unsolicited Headers (nonce 0 / never issued) → rejected (no eclipse via fabricated target) — MISSING
- [ ] HAPPY `handle_headers` valid batch updates peer_height + queues hashes — MISSING
- [ ] ADVERSARIAL `handle_headers` bad batch → offense scored, sync_guard dropped before scorer await (no deadlock) — MISSING
- [ ] ERROR `handle_headers` oversized(&gt;MAX_MESSAGE_SIZE) / &gt;2000 / borsh-err scoring — MISSING
- [ ] LIVENESS `handle_get_headers` locator scan + up-to-2000 header build under block_in_place doesn't freeze; stop_hash honored — MISSING

### src/network/node/dispatch/relay.rs
- [ ] ADVERSARIAL `handle_txs` invalid tx not credited as relay, invalid_txs incremented, not routed to Dandelion/event — EXISTS (invalid_transactions_are_not_credited)
- [ ] ADVERSARIAL `handle_txs` accept-then-relay: forged-but-structurally-valid tx fails full `validate_transaction` → NOT relayed, scored — MISSING
- [ ] HAPPY `handle_txs` valid tx → Dandelion StemAction::Stem does NOT enter mempool (privacy) — MISSING
- [ ] HAPPY `handle_txs` StemAction::Fluff broadcasts InvTx to all peers + emits TransactionReceived — MISSING
- [ ] LIVENESS `handle_txs` fluff fan-out snapshots senders before await (no DashMap guard across await) — MISSING
- [ ] ADVERSARIAL `handle_txs` oversized(&gt;MAX)/&gt;100 txs/borsh-err scoring ladder — MISSING
- [ ] LIVENESS `handle_txs` full-crypto validation under block_in_place keeps worker schedulable under tx flood — MISSING
- [ ] HAPPY `handle_inv_tx` requests only unknown, non-absent hashes via GetTxs — MISSING
- [ ] ADVERSARIAL `handle_inv_tx` NotFound-absence is per-peer: peer A's NotFound must NOT suppress fetching same hash from peer B — MISSING
- [ ] ADVERSARIAL `handle_inv_tx` oversized(&gt;64KB)/dup(validate)/borsh-err scoring — MISSING
- [ ] HAPPY `handle_get_txs` returns found txs + NotFound for absent — MISSING
- [ ] ADVERSARIAL `handle_get_txs` oversized/invalid scoring; repeated request for absent hash answered by NotFound (no re-lookup storm) — MISSING
- [ ] ADVERSARIAL `handle_not_found` unsolicited NotFound spray marks absence per-peer only (cannot globally suppress relay) — MISSING
- [ ] EDGE `handle_not_found` oversized/invalid/&gt;500 hashes scoring — MISSING

### src/network/node/dispatch/address.rs
- [ ] ADVERSARIAL `handle_get_addr` from plaintext (unencrypted) peer → silently ignored (Veil: no topology leak) — MISSING
- [ ] HAPPY `handle_get_addr` from encrypted peer returns ≤100 addrs — MISSING
- [ ] ADVERSARIAL `handle_addr` flood: 1000 addrs does not evict honest/diverse book entries (netgroup quota) and does not starve dials — MISSING
- [ ] ADVERSARIAL `handle_addr` book-takeover: many addrs from one /16 capped by max_per_group — MISSING
- [ ] EDGE `handle_addr` future-dated (&gt;now+600) and stale (&gt;7d) addresses rejected — MISSING
- [ ] EDGE `handle_addr` unroutable IPs filtered (is_routable) — MISSING
- [ ] ADVERSARIAL `handle_addr` oversized(&gt;256KB) → OversizedMessage; &gt;1000 or borsh-err → InvalidAddress — MISSING
- [ ] PROPERTY `handle_addr` accepted count matches routable+fresh subset — MISSING

### src/network/node/dispatch/query.rs
- [ ] PROPERTY `bounded_height_range` clamps to request+chain limits, rejects reverse/zero/past-tip — EXISTS (3 tests)
- [ ] ADVERSARIAL `handle_get_filters` byte-budget caps response (output-dense range) regardless of count — MISSING
- [ ] EDGE `handle_get_filters` start&gt;end / payload&lt;16 → drop; range clamped to 1000 — MISSING
- [ ] ADVERSARIAL `handle_get_output_digests` byte-budget + 100-block cap; payload&lt;16 dropped — MISSING
- [ ] ADVERSARIAL `handle_get_filter_checkpoints` zero-body request amplification bounded by per-bucket cache + MAX_CHECKPOINTS(1000) — MISSING
- [ ] ADVERSARIAL `handle_get_key_image_status` payload&gt;8KB dropped pre-borsh; take(100) caps query — MISSING
- [ ] PROPERTY `handle_response` no-op on full node — MISSING
- [ ] LIVENESS all four query builders run under block_in_place (many DB reads don't freeze worker) — MISSING

### src/network/node/broadcast.rs
- [ ] LIVENESS `send_to_peer` is non-blocking try_send: full peer queue → returns false, never awaits (single processor not frozen) — EXISTS (send_to_peer_does_not_block_when_queue_is_full)
- [ ] LIVENESS `send_to_peer` awaiting capacity never holds DashMap shard lock — EXISTS (does_not_block_dashmap_insert)
- [ ] HAPPY/EDGE `send_to_peer` true/false on success/missing/closed — EXISTS (3 tests)
- [ ] EDGE `send_to` missing peer Ok, closed peer ConnectionFailed — EXISTS
- [ ] LIVENESS `broadcast_raw` one full slow-peer queue does not block delivery to fast peer — EXISTS (full_peer_queue_does_not_block)
- [ ] ADVERSARIAL `broadcast_raw` peer full for STALL_THRESHOLD(30) consecutive sends → ChronicSendQueueFull score + ban_peer — MISSING
- [ ] EDGE `broadcast_raw` successful send resets consecutive_full to 0 — PARTIAL (asserts count==1; MISSING reset-on-success)
- [ ] EDGE `broadcast_raw` closed channel peer → disconnect_peer cleanup — MISSING
- [ ] HAPPY `announce_chain_work` sends only to CAP_CHAINWORK peers via try_send (congested peer skipped) — MISSING
- [ ] PROPERTY `queue_transaction` returns tx hash, adds to Dandelion local — MISSING

### src/network/node/connection.rs
- [ ] EDGE `cleanup_connection` removes only the entry owned by this connection token/sender — EXISTS
- [ ] ADVERSARIAL `cleanup_connection` skip when a replacement connection exists (no event, keeps new) — EXISTS (stale_cleanup_preserves)
- [ ] EDGE weak sender identity does not keep channel open — EXISTS
- [ ] ADVERSARIAL `denormalize_noise_record` rejects non-canonical wire size — EXISTS
- [ ] ROUND-TRIP normalized Noise record through bridge writer → recv uses bucket size and recovers plaintext — EXISTS
- [ ] LIVENESS write arm WRITE_TIMEOUT: peer that stops reading (fills TCP window) → write times out → stalled peer dropped (does not block shared processor) — MISSING
- [ ] LIVENESS full end-to-end: peer that never reads must not freeze OTHER peers' message processing — MISSING (top-priority gap)
- [ ] ADVERSARIAL Noise handshake timeout (NOISE_HANDSHAKE_TIMEOUT_SECS) → connection closed, Err returned — MISSING
- [ ] ADVERSARIAL Noise handshake failure → stream not reused for plaintext, Err — MISSING
- [ ] ADVERSARIAL untrusted static key with trusted_peers configured → disconnect — MISSING
- [ ] ADVERSARIAL plaintext connection rejected when trusted_peers set or encryption required — MISSING
- [ ] EDGE peer_id canonicalized to Noise remote static key when encrypted; info.id/senders/peers all keyed identically — MISSING
- [ ] LIVENESS noise_bridge uses two independent tasks (nonce never desyncs under concurrent read/write) — MISSING
- [ ] ADVERSARIAL noise_bridge_writer rejects frame payload_len &gt; max_payload — MISSING
- [ ] EDGE failed initial Version write → peer never inserted as live — MISSING
- [ ] EDGE empty-payload outbound (Verack/GetAddr, len==HEADER_SIZE) still framed and sent — MISSING

### src/network/node/runtime.rs
- [ ] ADVERSARIAL message-rate limiter: peer exceeding per-type rate → MessageFlood score + message dropped (reservation released) — MISSING
- [ ] LIVENESS rate_trackers pruned every 1000 msgs for disconnected peers (no unbounded growth under churn) — MISSING
- [ ] EDGE `spawn_message_processor` exits on shutdown signal (biased select) and on channel close — MISSING
- [ ] EDGE processor continues after a `process_message` Err (one bad message doesn't kill the loop) — MISSING
- [ ] EDGE `NodeRuntime::shutdown` joins tasks within deadline, aborts stragglers — MISSING
- [ ] LIVENESS `spawn_padding_broadcast` stops on shutdown; snapshots senders each tick — MISSING

### src/network/sync.rs (ChainSync state machine)
- [ ] PROPERTY SyncState transitions; build_locator exponential backoff — EXISTS (test_sync_state, test_build_locator)
- [ ] PROPERTY `is_synced` = local &gt;= true_best_height — PARTIAL (MISSING dedicated)
- [ ] ADVERSARIAL bogus high peer difficulty claim cannot pin `is_synced=false` after peer proven unreliable (on_timeout drops claim, recompute) — MISSING
- [ ] ADVERSARIAL `recompute_best_difficulty` is a true recompute (shrinks), not a ratchet — MISSING
- [ ] ADVERSARIAL `refresh_best_known` true recompute: high peer disconnect / all peers gone → best_known falls to local (no phantom-target wedge) — MISSING
- [ ] LIVENESS `retain_connected_peers` prunes departed peer's stale height/work → frozen node self-heals — MISSING
- [ ] ADVERSARIAL `begin_headers_request` returns None when a cycle is already in flight (no request flood) — MISSING
- [ ] ADVERSARIAL `validate_header_nonce` single-use: consumed nonce rejected on replay — MISSING
- [ ] ADVERSARIAL `validate_header_nonce` cross-peer/stale-generation rejected without consuming — MISSING
- [ ] ADVERSARIAL nonce 0 never accepted (unsolicited Headers rejected) — MISSING
- [ ] EDGE `cancel_headers_request` only rolls back matching peer+generation — MISSING
- [ ] ADVERSARIAL orphan flood: `mark_block_orphan` LRU-evicts at MAX_ORPHAN_BLOCKS(1000); bounded memory — MISSING
- [ ] ADVERSARIAL orphan per-peer cap behavior (note MAX_ORPHANS_PER_PEER=usize::MAX — verify intended, single flooding peer can fill pool up to global cap) — MISSING (PROPERTY/regression worth locking)
- [ ] EDGE `on_timeout` 3 failures → 5-min sync-ban FROM NOW, drops work claim, recompute — EXISTS (partial via sync tests?) — MISSING explicit
- [ ] PROPERTY stall/stuck-download detection + requeue — EXISTS (test_stall_detection, test_stuck_download_detection, mark_block_failed_requeues)
- [ ] LIVENESS `trigger_resync` from Synced/Idle only; `arm_near_tip_catchup` closes small gap when behind+idle — MISSING
- [ ] EDGE `on_block_processed` re-derives best_known and transitions Headers/ConfirmingSynced correctly — MISSING
- [ ] EDGE `get_blocks_to_request`/`get_blocks_to_retry` timeout + retry ordering — PARTIAL (some sync tests exist; verify coverage)
- [ ] PROPERTY `request_timeout_scaled` and increase/decrease bounds [15,64] — MISSING
- [ ] PROPERTY `headers_timed_out` at 60s; `headers_request_pending` gates re-issue (4Hz flood regression) — PARTIAL (cycle_01_regressions covers flood; MISSING unit)

### src/network/dandelion.rs
- [ ] HAPPY local tx enters stempool — EXISTS
- [ ] ADVERSARIAL stem loop (dup inbound) → immediate fluff — EXISTS
- [ ] HAPPY fluff epoch broadcasts immediately — EXISTS
- [ ] EDGE embargo timeout fail-safe fluff — EXISTS
- [ ] PROPERTY per-inbound-edge relay routing deterministic within epoch — EXISTS
- [ ] PROPERTY epoch rotation changes mode + clears inbound map — EXISTS (2 tests)
- [ ] EDGE diffusion confirmation removes from stempool — EXISTS
- [ ] EDGE no relay peers → fluff fallback — EXISTS
- [ ] ADVERSARIAL stempool limit enforced (flood bound) — EXISTS
- [ ] ADVERSARIAL `add_received_tx` already-fluffed → Ignore (no re-broadcast amplification) — MISSING
- [ ] PROPERTY `has_adequate_privacy` / relay-peer count thresholds — MISSING
- [ ] LIVENESS `tick` on empty router does not panic — EXISTS (network_security tick_does_not_panic)
- [ ] PROPERTY forward delay applied only when a real stem target exists — MISSING
- [ ] Multi-node: stem fans to one peer, eventually fluffs full graph, loop→fluff, embargo, diffusion clears — EXISTS (dandelion_multi_node.rs)

### src/network/bootstrap.rs (AddressManager)
- [ ] HAPPY add/get_next/len/is_empty/for_exchange basics — EXISTS (test_address_manager, _max)
- [ ] ADVERSARIAL netgroup quota: NEW addr in full /16 rejected BEFORE eviction (no honest-entry eviction) — MISSING (explicit anti-eclipse)
- [ ] ADVERSARIAL flood of one /16 cannot take over book (group_count cap) — MISSING
- [ ] EDGE self-address never (re-)admitted; mark_self_address removes + skips in get_next — MISSING
- [ ] HAPPY get_next priority order: manual → anchors → book by last_seen; tried-set clears and retries — MISSING
- [ ] EDGE eviction removes oldest by last_seen at max_addresses; known_addrs dedup consistent — MISSING
- [ ] LIVENESS manual/anchor peer not starved by large stale book — MISSING (regression: 2026-08-16 0-outbound)
- [ ] ROUND-TRIP save_to_file/load_from_file preserves book — PARTIAL (verify existing test)
- [ ] PROPERTY BootstrapConfig / seed_node_parsing — EXISTS
- [ ] EDGE mark_tried/mark_success/clear_tried/mark_noise_capable state — PARTIAL

### src/network/noise.rs
- [ ] HAPPY handshake success + transport round-trip — EXISTS (2 tests)
- [ ] ROUND-TRIP NodeIdentity save/load — EXISTS
- [ ] ADVERSARIAL `read_encrypted` rejects length prefix &gt; MAX_NOISE_PAYLOAD+TAG (frame too large) pre-alloc — MISSING
- [ ] ADVERSARIAL `write_encrypted` rejects plaintext &gt; MAX_NOISE_PAYLOAD — MISSING
- [ ] ADVERSARIAL handshake with unknown version byte → immediate descriptive error before crypto — MISSING
- [ ] ADVERSARIAL truncated/garbage handshake bytes → error, no panic — MISSING
- [ ] ADVERSARIAL tampered ciphertext (MAC fail) → NoiseDecryptionFailed — MISSING
- [ ] LIVENESS split send/recv nonce independence under concurrent use (no desync) — MISSING
- [ ] EDGE `load_or_generate_fresh` stale key detection; clear_identity — MISSING
- [ ] PROPERTY peer_id derived from static public key is stable — MISSING

### src/network/scoring.rs
- [ ] PROPERTY composite_score / defaults / clamp [-100,100] — EXISTS
- [ ] PROPERTY ban threshold exactly -50; should_ban — EXISTS
- [ ] ADVERSARIAL ban logic not gamed: honest peer with occasional failures never banned — EXISTS (good_peer_never_banned, p2p not_banned_after_occasional)
- [ ] ADVERSARIAL each MisbehaviorType penalty degrades score; severe (WrongNetwork/InvalidBlockPoW) → immediate ban — EXISTS (several)
- [ ] ADVERSARIAL empty-Blocks: reputation charged ONLY at/after threshold (honest bystander in speculative IBD not driven past -50 = eclipse defense) — MISSING (critical, subtle)
- [ ] EDGE `is_get_blocks_banned` auto-expires + resets consecutive_empty_blocks — MISSING
- [ ] PROPERTY decay converges toward neutral; recovers after sufficient decay — EXISTS
- [ ] EDGE `record_block_success` clears consecutive_empty_blocks + sets validated — MISSING
- [ ] ADVERSARIAL `PeerMessageRateTracker` flags flood; per-type windows — EXISTS (flags_flood)
- [ ] ADVERSARIAL `OrphanFloodTracker` record/forget/count_for bound — PARTIAL (p2p OrphanFlood misbehavior only)
- [ ] PROPERTY `auto_ban_bad_peers` bans only sub-threshold peers — EXISTS
- [ ] PROPERTY `top_peers_for_download`/`peers_by_latency` filter validated + score — MISSING
- [ ] ROUND-TRIP save/load_bans_to_file — PARTIAL (verify)
- [ ] PROPERTY `classify_invalid_tx_reason`/`classify_invalid_block_reason` mapping — PARTIAL
- [ ] EDGE `ban` prunes expired entries (bounded map under ban flood) — MISSING

### src/network/compact_blocks.rs
- [ ] HAPPY creation / reconstruction from mempool — EXISTS
- [ ] EDGE missing-transaction indices reported — EXISTS
- [ ] PROPERTY short-tx-id derivation + collision handling — EXISTS
- [ ] ADVERSARIAL reconstruct with adversarial short-id collision (two txs same 6-byte id) → correct missing/failure path, no wrong-tx acceptance — MISSING
- [ ] ADVERSARIAL malformed CompactBlock (absurd prefilled index / short_id count) bounded — MISSING
- [ ] PROPERTY savings_estimate arithmetic — MISSING

### src/network/dns_seeds.rs + socks_dns.rs
- [ ] PROPERTY testnet fallback entries parse / match seed_nodes / non-empty / exclude dead IPs — EXISTS (6 tests)
- [ ] ADVERSARIAL `resolve_via_socks5` malformed/oversized SOCKS5 response bounded, no panic — PARTIAL (socks_dns has ~9 tests; verify adversarial response parsing)
- [ ] ADVERSARIAL DNS answer with absurd record count / truncated packet rejected — MISSING
- [ ] EDGE SOCKS5 auth-required / connection-refused error paths — PARTIAL

---

## Counts

- **Total test items:** 168
- **EXISTS (full or clearly present):** 54
- **PARTIAL (some coverage, gap remains — counted separately):** 22
- **MISSING:** 92

Fully-missing + partial-gap = **114 of 168** behaviors lack complete coverage.

## Highest-value gaps (the adversarial/liveness class the current suite omits entirely)
1. **No handler-level harness exists** — every `dispatch/*` handler (verack-without-version, verack/version/headers replay, per-peer NotFound absence scoping, InvBlock no-speculative-bump, accept-then-relay tx gate, Veil GetAddr plaintext refusal) is untested. These are pure-async-fn tests that are cheap to add.
2. **No "peer that stops reading must not freeze others" end-to-end test** — the C2/WRITE_TIMEOUT invariant is only unit-tested at `send_to_peer`, never through `handle_connection` + `spawn_message_processor`.
3. **Sync anti-wedge recomputes** (`refresh_best_known`, `recompute_best_difficulty`, `retain_connected_peers`, nonce single-use/cross-peer) — these encode multiple documented production wedges yet have no direct unit tests.
4. **Per-message `validate()` count/length caps** — only `InvMessage` dup is tested; Headers/Blocks/Addr/Txs/GetBlocks/Reject/NotFound/Version caps are unverified at the message layer.
5. **Noise frame-size caps and handshake-version/tamper rejection** — the DoS-relevant `read_encrypted` length gate and unknown-version fast-fail are untested.
6. **Eclipse-defense scoring subtlety** — empty-Blocks reputation-only-past-threshold (honest-bystander protection) has no regression test despite being an explicit pre-mainnet fix.

Key files (all absolute): handlers under `C:\Users\unkno\dev\CoinCync-wt-bughunt\src\network\node\dispatch\`, framing `...\src\network\framing.rs`, sync state machine `...\src\network\sync.rs`, scoring `...\src\network\scoring.rs`, connection/liveness `...\src\network\node\connection.rs` and `...\node\broadcast.rs`. Existing integration tests: `...\tests\p2p_adversarial.rs`, `network_adversarial.rs`, `network_security.rs`, `fuzz_protocol.rs`, `dandelion_multi_node.rs`.