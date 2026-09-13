//! RPC Endpoint Tests — Phase 2 (method behaviors)
//!
//! Companion to `tests/rpc_endpoints.rs`. Reuses the same in-process
//! server harness (a real `RpcModule`/jsonrpsee server backed by an
//! in-memory `Blockchain` + `Mempool`) to cover the method-level rows
//! left `[ ]` (MISSING) in `docs/audit/test-plan/rpc.md` under
//! `### src/rpc/server.rs`.
//!
//! Focus (per the test plan's "highest-value gaps"):
//! - pre-decode length caps on submit_block / send_raw_transaction /
//!   is_nullifier_spent / is_spark_serial_spent / get_transaction,
//! - range/span bounds on get_block_range / get_output_digests /
//!   get_blocks_batch / get_sync_checkpoints,
//! - the six chain-audit methods' MAX_RPC_AUDIT_BLOCK_SPAN=128 cap and
//!   start>end rejection,
//! - get_info health bands, get_peer_info empty/divergence, and a set of
//!   happy-path shapes that need only a genesis chain (no mining).
//!
//! Bounds/rejection tests only need an empty or genesis chain because the
//! guard fires before any block iteration. Behaviors that genuinely need a
//! mined chain / real proofs are intentionally NOT covered here and are
//! listed as deferred in the accompanying report.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use coincync::chain::{Blockchain, SharedBlockchain};
use coincync::mempool::SharedMempool;
use coincync::network::node::NodeConfig;
use coincync::network::peer::{generate_peer_id, PeerInfo};
use coincync::network::P2PNode;
use coincync::rpc::{start_rpc_server, RpcConfig};
use serde_json::{json, Value};
use tokio::time::sleep;

/// Call a JSON-RPC method and return the full response.
async fn rpc_call(url: &str, method: &str, params: Value) -> Value {
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .build()
        .unwrap();
    let body = json!({
        "jsonrpc": "2.0",
        "method": method,
        "params": params,
        "id": 1,
    });
    let resp = client
        .post(url)
        .json(&body)
        .send()
        .await
        .expect("RPC request failed");
    resp.json::<Value>().await.expect("parse JSON response")
}

/// Start a server on a loopback port backed by an empty (non-genesis) chain.
async fn start_test_server(port: u16) -> (String, coincync::rpc::RpcServer) {
    let shared_chain: SharedBlockchain = Arc::new(Blockchain::new());
    let shared_mempool = SharedMempool::new();
    let addr: SocketAddr = format!("127.0.0.1:{}", port).parse().unwrap();
    let config = RpcConfig {
        listen_addr: addr,
        network_name: "testnet".to_string(),
        ..Default::default()
    };
    let p2p: Option<Arc<P2PNode>> = None;
    let server = start_rpc_server(shared_chain, shared_mempool, p2p, config)
        .await
        .expect("start RPC server");
    sleep(Duration::from_millis(100)).await;
    (format!("http://127.0.0.1:{}", port), server)
}

/// Start a server on a loopback port backed by a genesis-initialized chain.
async fn start_initialized_test_server(port: u16) -> (String, coincync::rpc::RpcServer) {
    let shared_chain: SharedBlockchain = Arc::new(Blockchain::new());
    shared_chain.init_genesis().expect("initialize genesis");
    let shared_mempool = SharedMempool::new();
    let config = RpcConfig {
        listen_addr: format!("127.0.0.1:{port}").parse().unwrap(),
        network_name: "testnet".to_string(),
        ..Default::default()
    };
    let server = start_rpc_server(shared_chain, shared_mempool, None, config)
        .await
        .expect("start RPC server");
    sleep(Duration::from_millis(100)).await;
    (format!("http://127.0.0.1:{port}"), server)
}

/// Start a loopback server carrying a synthetic connected peer fixture.
async fn start_test_server_with_peer_fixture_loopback(
    port: u16,
    peer: PeerInfo,
) -> (String, coincync::rpc::RpcServer) {
    let shared_chain: SharedBlockchain = Arc::new(Blockchain::new());
    let shared_mempool = SharedMempool::new();
    let config = RpcConfig {
        listen_addr: format!("127.0.0.1:{}", port).parse::<SocketAddr>().unwrap(),
        network_name: "testnet".to_string(),
        ..Default::default()
    };
    let mut node_cfg = NodeConfig::default();
    node_cfg.data_dir =
        std::env::temp_dir().join(format!("coincync-rpc-extra-peer-fixture-{}", port));
    let p2p = Arc::new(P2PNode::new(
        node_cfg,
        shared_chain.clone(),
        shared_mempool.clone(),
    ));
    p2p.add_peer_for_testing(peer);
    let server = start_rpc_server(shared_chain, shared_mempool, Some(p2p), config)
        .await
        .expect("start RPC server");
    sleep(Duration::from_millis(100)).await;
    (format!("http://127.0.0.1:{}", port), server)
}

// =============================================================================
// get_info — health bands + params tolerance
// =============================================================================

#[tokio::test(flavor = "multi_thread")]
async fn get_info_status_is_a_known_health_band() {
    let (url, _server) = start_test_server(19400).await;
    let resp = rpc_call(&url, "get_info", json!([])).await;
    let r = &resp["result"];
    let status = r["status"].as_str().expect("status must be a string");
    assert!(
        ["syncing", "no-peers", "stalled", "low-peers", "healthy"].contains(&status),
        "status must be a known health band, got {status:?}"
    );
    let score = r["health_score"]
        .as_f64()
        .expect("health_score must be a float");
    assert!(
        (0.0..=1.0).contains(&score),
        "health_score must be in [0,1], got {score}"
    );
    // Normal system clock ⇒ clock_available true and tip_age_secs numeric.
    assert_eq!(r["clock_available"], true);
    assert!(r["tip_age_secs"].is_u64(), "tip_age_secs must be numeric under a normal clock");
}

#[tokio::test(flavor = "multi_thread")]
async fn get_info_tolerates_extra_positional_params() {
    let (url, _server) = start_test_server(19401).await;
    // get_info ignores params entirely; extra/positional args must not error.
    let resp = rpc_call(&url, "get_info", json!([1, 2, "ignored"])).await;
    assert!(
        resp.get("result").is_some(),
        "get_info must tolerate extra params: {resp}"
    );
}

// =============================================================================
// get_peer_info — empty + divergence
// =============================================================================

#[tokio::test(flavor = "multi_thread")]
async fn get_peer_info_empty_when_p2p_none() {
    let (url, _server) = start_test_server(19402).await;
    let resp = rpc_call(&url, "get_peer_info", json!([])).await;
    let r = &resp["result"];
    assert_eq!(r["peer_count"], 0);
    assert!(r["peers"].as_array().expect("peers array").is_empty());
    assert_eq!(r["max_peer_height"], 0);
    assert_eq!(r["divergence_from_max"], 0);
}

#[tokio::test(flavor = "multi_thread")]
async fn get_peer_info_reports_divergence_summary_from_peer_heights() {
    let mut peer = PeerInfo::new(
        generate_peer_id(),
        "198.51.100.20:30303".parse().expect("socket"),
        true,
    );
    peer.height = 500;
    peer.version = 1;
    let (url, _server) = start_test_server_with_peer_fixture_loopback(19403, peer).await;
    let resp = rpc_call(&url, "get_peer_info", json!([])).await;
    let r = &resp["result"];
    // Local chain is empty (height 0); the single peer reports height 500.
    assert_eq!(r["peer_count"], 1);
    assert_eq!(r["local_height"], 0);
    assert_eq!(r["max_peer_height"], 500);
    assert_eq!(r["min_peer_height"], 500);
    assert_eq!(r["divergence_from_max"], 500);
}

// =============================================================================
// get_mempool_transactions
// =============================================================================

#[tokio::test(flavor = "multi_thread")]
async fn get_mempool_transactions_empty_returns_count_zero() {
    let (url, _server) = start_test_server(19404).await;
    let resp = rpc_call(&url, "get_mempool_transactions", json!([])).await;
    let r = &resp["result"];
    assert_eq!(r["count"], 0);
    assert!(
        r["transactions"].as_array().expect("transactions array").is_empty(),
        "empty mempool must yield an empty transactions array"
    );
}

// =============================================================================
// submit_block
// =============================================================================

#[tokio::test(flavor = "multi_thread")]
async fn submit_block_already_known_returns_already_known() {
    let (url, _server) = start_initialized_test_server(19405).await;
    // Recover the canonical genesis block bytes via get_block_by_height, then
    // resubmit them: process_block sees the block already in the chain and
    // returns AlreadyKnown, which the handler surfaces as accepted+already_known.
    let genesis = rpc_call(&url, "get_block_by_height", json!([0])).await;
    let bytes_hex = genesis["result"]["bytes"]
        .as_str()
        .expect("genesis block must carry raw hex bytes");
    let resp = rpc_call(&url, "submit_block", json!([bytes_hex])).await;
    let r = &resp["result"];
    assert_eq!(r["accepted"], true, "resubmitted genesis must be accepted: {resp}");
    assert_eq!(r["status"], "already_known");
}

#[tokio::test(flavor = "multi_thread")]
async fn submit_block_hex_length_cap_rejected() {
    let (url, _server) = start_test_server(19406).await;
    // 4 × MAX_BLOCK_SIZE hex chars is the pre-decode cap; exceed it by one.
    let max_hex = 2 * 2 * coincync::constants::MAX_BLOCK_SIZE;
    let oversized = "0".repeat(max_hex + 1);
    let resp = rpc_call(&url, "submit_block", json!([oversized])).await;
    assert_eq!(
        resp["error"]["code"], -32602,
        "oversized hex block must be rejected pre-decode: {resp}"
    );
}

// =============================================================================
// send_raw_transaction
// =============================================================================

#[tokio::test(flavor = "multi_thread")]
async fn send_raw_transaction_hex_length_cap_rejected() {
    let (url, _server) = start_test_server(19407).await;
    let max_hex = 2 * 2 * coincync::constants::MAX_TX_SIZE;
    let oversized = "0".repeat(max_hex + 1);
    let resp = rpc_call(&url, "send_raw_transaction", json!([oversized])).await;
    assert_eq!(
        resp["error"]["code"], -32602,
        "oversized hex tx must be rejected pre-decode: {resp}"
    );
}

// =============================================================================
// is_nullifier_spent — hex caps
// =============================================================================

#[tokio::test(flavor = "multi_thread")]
async fn is_nullifier_spent_hex_too_long_rejected() {
    let (url, _server) = start_test_server(19408).await;
    let resp = rpc_call(&url, "is_nullifier_spent", json!(["0".repeat(130)])).await;
    assert_eq!(resp["error"]["code"], -32602, "hex >128 chars must reject: {resp}");
}

#[tokio::test(flavor = "multi_thread")]
async fn is_nullifier_spent_non_32_byte_rejected() {
    let (url, _server) = start_test_server(19409).await;
    // Valid hex, but decodes to 2 bytes rather than 32.
    let resp = rpc_call(&url, "is_nullifier_spent", json!(["dead"])).await;
    assert_eq!(resp["error"]["code"], -32602, "non-32-byte value must reject: {resp}");
}

#[tokio::test(flavor = "multi_thread")]
async fn is_nullifier_spent_non_hex_rejected() {
    let (url, _server) = start_test_server(19410).await;
    let resp = rpc_call(&url, "is_nullifier_spent", json!(["zz_not_hex"])).await;
    assert_eq!(resp["error"]["code"], -32602, "non-hex value must reject: {resp}");
}

// =============================================================================
// is_spark_serial_spent — valid + hex caps
// =============================================================================

#[tokio::test(flavor = "multi_thread")]
async fn is_spark_serial_spent_valid_returns_result() {
    let (url, _server) = start_test_server(19411).await;
    let serial = "cc".repeat(32); // 64 hex chars = 32 bytes
    let resp = rpc_call(&url, "is_spark_serial_spent", json!([serial])).await;
    let r = &resp["result"];
    assert_eq!(r["serial"], serial);
    assert_eq!(r["spent"], false, "an unseen serial must not be spent: {resp}");
}

#[tokio::test(flavor = "multi_thread")]
async fn is_spark_serial_spent_hex_too_long_rejected() {
    let (url, _server) = start_test_server(19412).await;
    let resp = rpc_call(&url, "is_spark_serial_spent", json!(["0".repeat(130)])).await;
    assert_eq!(resp["error"]["code"], -32602, "hex >128 chars must reject: {resp}");
}

#[tokio::test(flavor = "multi_thread")]
async fn is_spark_serial_spent_non_32_byte_rejected() {
    let (url, _server) = start_test_server(19413).await;
    let resp = rpc_call(&url, "is_spark_serial_spent", json!(["beef"])).await;
    assert_eq!(resp["error"]["code"], -32602, "non-32-byte value must reject: {resp}");
}

// =============================================================================
// get_transaction — length cap
// =============================================================================

#[tokio::test(flavor = "multi_thread")]
async fn get_transaction_hex_too_long_rejected() {
    let (url, _server) = start_test_server(19414).await;
    // 65 hex chars (after optional 0x) exceeds the 64-char tx-hash cap.
    let resp = rpc_call(&url, "get_transaction", json!(["0".repeat(65)])).await;
    assert_eq!(
        resp["error"]["code"], -32602,
        "tx hash hex >64 chars must be rejected pre-decode: {resp}"
    );
}

// =============================================================================
// get_block (by hash)
// =============================================================================

#[tokio::test(flavor = "multi_thread")]
async fn get_block_by_valid_hash_returns_block() {
    let (url, _server) = start_initialized_test_server(19415).await;
    let by_height = rpc_call(&url, "get_block_by_height", json!([0])).await;
    let genesis_hash = by_height["result"]["hash"]
        .as_str()
        .expect("genesis hash")
        .to_string();
    let resp = rpc_call(&url, "get_block", json!([genesis_hash.clone()])).await;
    assert!(resp.get("result").is_some(), "valid hash must return a block: {resp}");
    assert_eq!(resp["result"]["hash"], genesis_hash);
    assert_eq!(resp["result"]["height"], 0);
}

#[tokio::test(flavor = "multi_thread")]
async fn get_block_non_hex_hash_rejected() {
    let (url, _server) = start_test_server(19416).await;
    let resp = rpc_call(&url, "get_block", json!(["not_a_hex_hash"])).await;
    assert_eq!(
        resp["error"]["code"], -32602,
        "non-hex / wrong-length hash must reject: {resp}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn get_block_tolerates_0x_prefix() {
    let (url, _server) = start_test_server(19417).await;
    // A `0x`-prefixed, well-formed but unknown 64-hex hash must decode
    // (proving the prefix is stripped) and then miss with -5 not-found,
    // NOT fail param parsing with -32602.
    let hash = format!("0x{}", "0".repeat(64));
    let resp = rpc_call(&url, "get_block", json!([hash])).await;
    assert_eq!(
        resp["error"]["code"], -5,
        "0x-prefixed hash must decode then miss with not-found: {resp}"
    );
}

// =============================================================================
// get_block_range — span cap + saturation
// =============================================================================

#[tokio::test(flavor = "multi_thread")]
async fn get_block_range_span_capped_at_100() {
    let (url, _server) = start_test_server(19418).await;
    let resp = rpc_call(&url, "get_block_range", json!([0, 1000])).await;
    // MAX_RANGE=100 ⇒ inclusive response end is start + 100 - 1 = 99.
    assert_eq!(resp["result"]["start"], 0);
    assert_eq!(
        resp["result"]["end"], 99,
        "span must be capped to 100 blocks: {resp}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn get_block_range_u64_max_bounds_saturate() {
    let (url, _server) = start_test_server(19419).await;
    // Extreme bounds must saturate rather than overflow/panic.
    let resp = rpc_call(&url, "get_block_range", json!([u64::MAX, u64::MAX])).await;
    assert!(
        resp.get("result").is_some(),
        "u64::MAX bounds must not crash: {resp}"
    );
    assert_eq!(resp["result"]["count"], 0);
}

// =============================================================================
// get_output_digests
// =============================================================================

#[tokio::test(flavor = "multi_thread")]
async fn get_output_digests_valid_range_returns_digests() {
    let (url, _server) = start_initialized_test_server(19420).await;
    let resp = rpc_call(&url, "get_output_digests", json!([0, 0])).await;
    let r = &resp["result"];
    assert_eq!(r["start"], 0);
    assert_eq!(r["end"], 0);
    assert!(
        r["digests"].as_array().expect("digests array").len() >= 1,
        "genesis height must yield at least one digest: {resp}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn get_output_digests_inverted_range_rejected() {
    let (url, _server) = start_test_server(19421).await;
    let resp = rpc_call(&url, "get_output_digests", json!([10, 0])).await;
    assert_eq!(resp["error"]["code"], -32602, "end<start must reject: {resp}");
}

#[tokio::test(flavor = "multi_thread")]
async fn get_output_digests_start_above_height_yields_empty() {
    let (url, _server) = start_initialized_test_server(19422).await;
    // start > chain_height (0): the end-clamp drops end below start; the loop
    // must be empty with no underflow.
    let resp = rpc_call(&url, "get_output_digests", json!([100, 100])).await;
    assert_eq!(resp["result"]["count"], 0, "start above tip must yield empty: {resp}");
}

#[tokio::test(flavor = "multi_thread")]
async fn get_output_digests_malformed_params_rejected() {
    let (url, _server) = start_test_server(19423).await;
    let resp = rpc_call(&url, "get_output_digests", json!(["not_a_number"])).await;
    assert_eq!(resp["error"]["code"], -32602, "malformed params must reject: {resp}");
}

// =============================================================================
// get_sync_checkpoints — stride bounds
// =============================================================================

#[tokio::test(flavor = "multi_thread")]
async fn get_sync_checkpoints_default_returns_result() {
    let (url, _server) = start_initialized_test_server(19424).await;
    let resp = rpc_call(&url, "get_sync_checkpoints", json!([])).await;
    let r = &resp["result"];
    // Default stride 10_000; genesis-only chain ⇒ no checkpoints emitted.
    assert_eq!(r["stride"], 10_000);
    assert!(r["checkpoints"].as_array().is_some(), "checkpoints must be an array: {resp}");
}

#[tokio::test(flavor = "multi_thread")]
async fn get_sync_checkpoints_clamps_stride_to_upper_bound() {
    let (url, _server) = start_test_server(19425).await;
    // A huge requested stride is clamped to the 50_000 upper bound.
    let resp = rpc_call(&url, "get_sync_checkpoints", json!([999_999u64])).await;
    assert_eq!(
        resp["result"]["stride"], 50_000,
        "stride must clamp to 50_000: {resp}"
    );
}

// =============================================================================
// get_blocks_batch
// =============================================================================

#[tokio::test(flavor = "multi_thread")]
async fn get_blocks_batch_returns_hex_blocks() {
    let (url, _server) = start_initialized_test_server(19426).await;
    let resp = rpc_call(&url, "get_blocks_batch", json!([0, 10])).await;
    let r = &resp["result"];
    assert_eq!(r["from"], 0);
    let blocks = r["blocks"].as_array().expect("blocks array");
    assert!(!blocks.is_empty(), "genesis must appear in the batch: {resp}");
    assert!(blocks[0]["hex"].is_string(), "each block carries hex bytes");
    assert_eq!(r["count"], blocks.len());
}

#[tokio::test(flavor = "multi_thread")]
async fn get_blocks_batch_from_near_u64_max_saturates_empty() {
    let (url, _server) = start_test_server(19427).await;
    let resp = rpc_call(&url, "get_blocks_batch", json!([u64::MAX, 5])).await;
    assert_eq!(
        resp["result"]["count"], 0,
        "from near u64::MAX must saturate to empty: {resp}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn get_blocks_batch_malformed_params_rejected() {
    let (url, _server) = start_test_server(19428).await;
    let resp = rpc_call(&url, "get_blocks_batch", json!(["nope"])).await;
    assert_eq!(resp["error"]["code"], -32602, "malformed params must reject: {resp}");
}

// =============================================================================
// get_expected_reward
// =============================================================================

#[tokio::test(flavor = "multi_thread")]
async fn get_expected_reward_returns_reward() {
    let (url, _server) = start_test_server(19429).await;
    let resp = rpc_call(&url, "get_expected_reward", json!([100])).await;
    let r = &resp["result"];
    assert_eq!(r["height"], 100);
    assert!(r["reward"].is_u64(), "reward must be a numeric atomic value: {resp}");
    assert!(r["in_cync"].is_number(), "in_cync must be a number: {resp}");
}

#[tokio::test(flavor = "multi_thread")]
async fn get_expected_reward_missing_param_rejected() {
    let (url, _server) = start_test_server(19430).await;
    let resp = rpc_call(&url, "get_expected_reward", json!([])).await;
    assert_eq!(resp["error"]["code"], -32602, "missing height param must reject: {resp}");
}

// =============================================================================
// verify_keyimage_uniqueness — happy on short chain
// =============================================================================

#[tokio::test(flavor = "multi_thread")]
async fn verify_keyimage_uniqueness_valid_on_short_chain() {
    let (url, _server) = start_initialized_test_server(19431).await;
    let resp = rpc_call(&url, "verify_keyimage_uniqueness", json!([])).await;
    let r = &resp["result"];
    assert_eq!(r["valid"], true, "genesis-only chain has no duplicate key images: {resp}");
    assert_eq!(r["duplicates"], 0);
}

// =============================================================================
// Chain-audit methods — MAX_RPC_AUDIT_BLOCK_SPAN=128 + start>end rejects
// =============================================================================
//
// Span 201 (> 128) and inverted [100,0] are both rejected inside
// rpc_clamp_audit_range BEFORE any block iteration, so an empty chain suffices.

#[tokio::test(flavor = "multi_thread")]
async fn check_zero_commitments_in_range_span_too_large_rejected() {
    let (url, _server) = start_test_server(19432).await;
    let resp = rpc_call(&url, "check_zero_commitments_in_range", json!([0, 200])).await;
    assert_eq!(resp["error"]["code"], -32602, "span >128 must reject: {resp}");
}

#[tokio::test(flavor = "multi_thread")]
async fn check_zero_commitments_in_range_inverted_rejected() {
    let (url, _server) = start_test_server(19433).await;
    let resp = rpc_call(&url, "check_zero_commitments_in_range", json!([100, 0])).await;
    assert_eq!(resp["error"]["code"], -32602, "start>end must reject: {resp}");
}

#[tokio::test(flavor = "multi_thread")]
async fn verify_signatures_in_range_span_too_large_rejected() {
    let (url, _server) = start_test_server(19434).await;
    let resp = rpc_call(&url, "verify_signatures_in_range", json!([0, 200])).await;
    assert_eq!(resp["error"]["code"], -32602, "span >128 must reject: {resp}");
}

#[tokio::test(flavor = "multi_thread")]
async fn verify_signatures_in_range_inverted_rejected() {
    let (url, _server) = start_test_server(19435).await;
    let resp = rpc_call(&url, "verify_signatures_in_range", json!([100, 0])).await;
    assert_eq!(resp["error"]["code"], -32602, "start>end must reject: {resp}");
}

#[tokio::test(flavor = "multi_thread")]
async fn verify_range_proofs_in_range_span_too_large_rejected() {
    let (url, _server) = start_test_server(19436).await;
    let resp = rpc_call(&url, "verify_range_proofs_in_range", json!([0, 200])).await;
    assert_eq!(resp["error"]["code"], -32602, "span >128 must reject: {resp}");
}

#[tokio::test(flavor = "multi_thread")]
async fn verify_range_proofs_in_range_inverted_rejected() {
    let (url, _server) = start_test_server(19437).await;
    let resp = rpc_call(&url, "verify_range_proofs_in_range", json!([100, 0])).await;
    assert_eq!(resp["error"]["code"], -32602, "start>end must reject: {resp}");
}

#[tokio::test(flavor = "multi_thread")]
async fn verify_commitment_balance_in_range_span_too_large_rejected() {
    let (url, _server) = start_test_server(19438).await;
    let resp = rpc_call(&url, "verify_commitment_balance_in_range", json!([0, 200])).await;
    assert_eq!(resp["error"]["code"], -32602, "span >128 must reject: {resp}");
}

#[tokio::test(flavor = "multi_thread")]
async fn verify_commitment_balance_in_range_inverted_rejected() {
    let (url, _server) = start_test_server(19439).await;
    let resp = rpc_call(&url, "verify_commitment_balance_in_range", json!([100, 0])).await;
    assert_eq!(resp["error"]["code"], -32602, "start>end must reject: {resp}");
}

#[tokio::test(flavor = "multi_thread")]
async fn full_chain_audit_span_too_large_rejected() {
    let (url, _server) = start_test_server(19440).await;
    let resp = rpc_call(&url, "full_chain_audit", json!([0, 200])).await;
    assert_eq!(resp["error"]["code"], -32602, "span >128 must reject: {resp}");
}

#[tokio::test(flavor = "multi_thread")]
async fn full_chain_audit_inverted_rejected() {
    let (url, _server) = start_test_server(19441).await;
    let resp = rpc_call(&url, "full_chain_audit", json!([100, 0])).await;
    assert_eq!(resp["error"]["code"], -32602, "start>end must reject: {resp}");
}
