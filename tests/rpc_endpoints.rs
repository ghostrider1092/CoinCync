//! RPC Endpoint Tests — Phase 1
//!
//! Spins up a real RPC server backed by an in-memory chain + mempool,
//! then exercises every JSON-RPC method with valid and malformed input.
//!
//! These are integration tests that verify:
//! - Every method responds (no 404 / method-not-found)
//! - Valid calls return structured results
//! - Malformed calls return proper JSON-RPC errors (not crashes)

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::OnceLock;
use std::time::Duration;

use coincync::chain::{Blockchain, SharedBlockchain};
use coincync::config::NetworkType;
use coincync::mempool::SharedMempool;
use coincync::network::P2PNode;
use coincync::network::node::NodeConfig;
use coincync::network::peer::{PeerInfo, generate_peer_id};
use coincync::rpc::{start_rpc_server, RpcConfig};
use serde_json::{json, Value};
use tokio::sync::Mutex as AsyncMutex;
use tokio::time::sleep;

/// Serialise tests that mutate process env vars. Tokio's async Mutex
/// (not std::sync::Mutex) — holding a std MutexGuard across .await is
/// unsound because the guard is !Send and the future may be moved
/// across threads mid-await. tokio::sync::Mutex is designed for this.
fn env_lock() -> &'static AsyncMutex<()> {
    static LOCK: OnceLock<AsyncMutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| AsyncMutex::new(()))
}

/// Helper: call a JSON-RPC method and return the full response.
async fn rpc_call(url: &str, method: &str, params: Value) -> Value {
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(5))
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

/// Helper: call JSON-RPC with optional bearer auth header.
async fn rpc_call_with_auth(url: &str, method: &str, params: Value, bearer: Option<&str>) -> Value {
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(5))
        .build()
        .unwrap();

    let body = json!({
        "jsonrpc": "2.0",
        "method": method,
        "params": params,
        "id": 1,
    });

    let mut req = client.post(url).json(&body);
    if let Some(token) = bearer {
        req = req.bearer_auth(token);
    }
    let resp = req.send().await.expect("RPC request failed");
    resp.json::<Value>().await.expect("parse JSON response")
}

async fn rpc_get_status(
    url: &str,
    connection_hdr: Option<&str>,
    upgrade_hdr: Option<&str>,
    bearer: Option<&str>,
) -> reqwest::StatusCode {
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(5))
        .build()
        .unwrap();

    let mut req = client.get(url);
    if let Some(v) = connection_hdr {
        req = req.header(reqwest::header::CONNECTION, v);
    }
    if let Some(v) = upgrade_hdr {
        req = req.header(reqwest::header::UPGRADE, v);
    }
    if let Some(token) = bearer {
        req = req.bearer_auth(token);
    }
    req.send().await.expect("GET request failed").status()
}

/// Helper: start server on a specific port.
async fn start_test_server(port: u16) -> (String, coincync::rpc::RpcServer) {
    let shared_chain: SharedBlockchain = Arc::new(Blockchain::new());
    let shared_mempool = SharedMempool::new();

    let addr: SocketAddr = format!("127.0.0.1:{}", port).parse().unwrap();
    let config = RpcConfig {
        listen_addr: addr,
        network_name: "testnet".to_string(),
        ..Default::default()
    };

    let p2p: Option<Arc<coincync::network::P2PNode>> = None;
    let server = start_rpc_server(shared_chain, shared_mempool, p2p, config)
        .await
        .expect("start RPC server");

    sleep(Duration::from_millis(100)).await;

    (format!("http://127.0.0.1:{}", port), server)
}

/// Helper: start server with an explicit blockchain network.
async fn start_test_server_for_network(
    port: u16,
    network: NetworkType,
) -> (String, coincync::rpc::RpcServer) {
    let shared_chain: SharedBlockchain = Arc::new(Blockchain::new_with_network(network));
    let shared_mempool = SharedMempool::new();

    let addr: SocketAddr = format!("127.0.0.1:{}", port).parse().unwrap();
    let config = RpcConfig {
        listen_addr: addr,
        network_name: network.name().to_string(),
        ..Default::default()
    };

    let p2p: Option<Arc<coincync::network::P2PNode>> = None;
    let server = start_rpc_server(shared_chain, shared_mempool, p2p, config)
        .await
        .expect("start RPC server");

    sleep(Duration::from_millis(100)).await;

    (format!("http://127.0.0.1:{}", port), server)
}

/// Helper: start server with a custom config (for metadata-mode assertions).
async fn start_test_server_with_config(port: u16, mut config: RpcConfig) -> (String, coincync::rpc::RpcServer) {
    let shared_chain: SharedBlockchain = Arc::new(Blockchain::new());
    let shared_mempool = SharedMempool::new();

    config.listen_addr = format!("0.0.0.0:{}", port).parse::<SocketAddr>().unwrap();
    if config.network_name.is_empty() {
        config.network_name = "testnet".to_string();
    }

    let p2p: Option<Arc<coincync::network::P2PNode>> = None;
    let server = start_rpc_server(shared_chain, shared_mempool, p2p, config)
        .await
        .expect("start RPC server");

    sleep(Duration::from_millis(100)).await;
    (format!("http://127.0.0.1:{}", port), server)
}

/// Helper: start server with a synthetic connected peer fixture.
async fn start_test_server_with_peer_fixture(
    port: u16,
    mut config: RpcConfig,
    peer: PeerInfo,
) -> (String, coincync::rpc::RpcServer) {
    let shared_chain: SharedBlockchain = Arc::new(Blockchain::new());
    let shared_mempool = SharedMempool::new();

    config.listen_addr = format!("0.0.0.0:{}", port).parse::<SocketAddr>().unwrap();
    if config.network_name.is_empty() {
        config.network_name = "testnet".to_string();
    }

    let mut node_cfg = NodeConfig::default();
    node_cfg.data_dir = std::env::temp_dir().join(format!("coincync-rpc-peer-fixture-{}", port));
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

/// Helper: start loopback server with a synthetic connected peer fixture.
async fn start_test_server_with_peer_fixture_loopback(
    port: u16,
    mut config: RpcConfig,
    peer: PeerInfo,
) -> (String, coincync::rpc::RpcServer) {
    let shared_chain: SharedBlockchain = Arc::new(Blockchain::new());
    let shared_mempool = SharedMempool::new();

    config.listen_addr = format!("127.0.0.1:{}", port).parse::<SocketAddr>().unwrap();
    if config.network_name.is_empty() {
        config.network_name = "testnet".to_string();
    }

    let mut node_cfg = NodeConfig::default();
    node_cfg.data_dir = std::env::temp_dir().join(format!("coincync-rpc-peer-fixture-loopback-{}", port));
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
// VALID CALL TESTS — every method returns a proper result
// =============================================================================

#[tokio::test]
async fn rpc_get_info_returns_result() {
    let (url, _server) = start_test_server(19100).await;
    let resp = rpc_call(&url, "get_info", json!([])).await;
    assert!(resp.get("result").is_some(), "get_info must return result: {}", resp);
    let result = &resp["result"];
    assert!(result.get("height").is_some(), "get_info must have height");
    assert!(result.get("network").is_some(), "get_info must have network");
    assert!(result.get("is_synced").is_some(), "get_info must have is_synced");
}

#[tokio::test]
async fn rpc_get_blockchain_info_returns_result() {
    let (url, _server) = start_test_server(19101).await;
    let resp = rpc_call(&url, "get_blockchain_info", json!([])).await;
    assert!(resp.get("result").is_some(), "get_blockchain_info must return result: {}", resp);
}

#[tokio::test]
async fn rpc_get_mempool_info_returns_result() {
    let (url, _server) = start_test_server(19102).await;
    let resp = rpc_call(&url, "get_mempool_info", json!([])).await;
    assert!(resp.get("result").is_some(), "get_mempool_info must return result: {}", resp);
    let result = &resp["result"];
    assert!(result.get("size").is_some(), "mempool_info must have size");
}

#[tokio::test]
async fn rpc_get_supply_info_returns_result() {
    let (url, _server) = start_test_server(19103).await;
    let resp = rpc_call(&url, "get_supply_info", json!([])).await;
    assert!(resp.get("result").is_some(), "get_supply_info must return result: {}", resp);
}

#[tokio::test]
async fn rpc_get_privacy_stats_returns_result() {
    let (url, _server) = start_test_server(19104).await;
    let resp = rpc_call(&url, "get_privacy_stats", json!([])).await;
    assert!(resp.get("result").is_some(), "get_privacy_stats must return result: {}", resp);
}

#[tokio::test]
async fn rpc_get_network_info_returns_result() {
    let (url, _server) = start_test_server(19105).await;
    let resp = rpc_call(&url, "get_network_info", json!([])).await;
    assert!(resp.get("result").is_some(), "get_network_info must return result: {}", resp);
}

#[tokio::test]
async fn rpc_get_sync_status_returns_result() {
    let (url, _server) = start_test_server(19106).await;
    let resp = rpc_call(&url, "get_sync_status", json!([])).await;
    assert!(resp.get("result").is_some(), "get_sync_status must return result: {}", resp);
}

#[tokio::test]
async fn rpc_get_anonymity_set_returns_result() {
    let (url, _server) = start_test_server(19107).await;
    let resp = rpc_call(&url, "get_anonymity_set", json!([])).await;
    assert!(resp.get("result").is_some(), "get_anonymity_set must return result: {}", resp);
}

#[tokio::test]
async fn rpc_get_chain_events_returns_result() {
    let (url, _server) = start_test_server(19108).await;
    let resp = rpc_call(&url, "get_chain_events", json!([10])).await;
    assert!(resp.get("result").is_some(), "get_chain_events must return result: {}", resp);
}

#[tokio::test]
async fn rpc_get_mining_live_returns_result() {
    let (url, _server) = start_test_server(19109).await;
    let resp = rpc_call(&url, "get_mining_live", json!([])).await;
    assert!(resp.get("result").is_some(), "get_mining_live must return result: {}", resp);
}

#[tokio::test]
async fn rpc_get_peers_returns_result() {
    let (url, _server) = start_test_server(19110).await;
    let resp = rpc_call(&url, "get_peers", json!([])).await;
    assert!(resp.get("result").is_some(), "get_peers must return result: {}", resp);
}

#[tokio::test]
async fn rpc_get_block_template_returns_result() {
    let (url, _server) = start_test_server(19111).await;
    let resp = rpc_call(&url, "get_block_template", json!([])).await;
    assert!(resp.get("result").is_some(), "get_block_template must return result: {}", resp);
}

#[tokio::test]
async fn rpc_get_block_template_includes_network_magic_for_testnet_chain() {
    let (url, _server) = start_test_server_for_network(19150, NetworkType::Testnet).await;
    let resp = rpc_call(&url, "get_block_template", json!([])).await;
    let result = &resp["result"];
    let magic = result["network_magic"]
        .as_str()
        .expect("network_magic must be a hex string");

    assert_eq!(magic, hex::encode(NetworkType::Testnet.magic_bytes()));
}

#[tokio::test]
async fn rpc_get_block_template_includes_network_magic_for_mainnet_chain() {
    let (url, _server) = start_test_server_for_network(19151, NetworkType::Mainnet).await;
    let resp = rpc_call(&url, "get_block_template", json!([])).await;
    let result = &resp["result"];
    let magic = result["network_magic"]
        .as_str()
        .expect("network_magic must be a hex string");

    assert_eq!(magic, hex::encode(NetworkType::Mainnet.magic_bytes()));
}

#[tokio::test]
async fn rpc_get_block_template_includes_network_magic_for_regtest_chain() {
    let (url, _server) = start_test_server_for_network(19152, NetworkType::Regtest).await;
    let resp = rpc_call(&url, "get_block_template", json!([])).await;
    let result = &resp["result"];
    let magic = result["network_magic"]
        .as_str()
        .expect("network_magic must be a hex string");

    assert_eq!(magic, hex::encode(NetworkType::Regtest.magic_bytes()));
}

#[tokio::test]
async fn rpc_get_block_template_network_magic_maps_to_known_network_testnet() {
    let (url, _server) = start_test_server_for_network(19153, NetworkType::Testnet).await;
    let resp = rpc_call(&url, "get_block_template", json!([])).await;
    let result = &resp["result"];
    let magic_hex = result["network_magic"]
        .as_str()
        .expect("network_magic must be a hex string");
    let bytes = hex::decode(magic_hex).expect("network_magic must be valid hex");
    assert_eq!(bytes.len(), 4, "network_magic must be exactly 4 bytes");
    let magic = [bytes[0], bytes[1], bytes[2], bytes[3]];
    let parsed = NetworkType::from_magic_bytes(magic);
    assert_eq!(parsed, Some(NetworkType::Testnet));
}

#[tokio::test]
async fn rpc_get_block_template_network_magic_maps_to_known_network_mainnet() {
    let (url, _server) = start_test_server_for_network(19154, NetworkType::Mainnet).await;
    let resp = rpc_call(&url, "get_block_template", json!([])).await;
    let result = &resp["result"];
    let magic_hex = result["network_magic"]
        .as_str()
        .expect("network_magic must be a hex string");
    let bytes = hex::decode(magic_hex).expect("network_magic must be valid hex");
    assert_eq!(bytes.len(), 4, "network_magic must be exactly 4 bytes");
    let magic = [bytes[0], bytes[1], bytes[2], bytes[3]];
    let parsed = NetworkType::from_magic_bytes(magic);
    assert_eq!(parsed, Some(NetworkType::Mainnet));
}

#[tokio::test]
async fn rpc_get_asset_info_returns_error() {
    // CoinCync 1.0 has no asset layer — this method should return an error.
    let (url, _server) = start_test_server(19112).await;
    let resp = rpc_call(&url, "get_asset_info", json!([])).await;
    assert!(resp.get("error").is_some(),
        "get_asset_info must return error in 1.0 (no asset layer): {}", resp);
}

// =============================================================================
// PARAMETERIZED CALL TESTS — methods that take arguments
// =============================================================================

#[tokio::test]
async fn rpc_get_block_by_height_valid() {
    let (url, _server) = start_test_server(19120).await;
    // Height 0 should return genesis (or error if chain is empty)
    let resp = rpc_call(&url, "get_block_by_height", json!([0])).await;
    // Either result (genesis found) or error (no genesis) — but not a crash
    assert!(
        resp.get("result").is_some() || resp.get("error").is_some(),
        "get_block_by_height must return result or error, not crash: {}", resp
    );
}

#[tokio::test]
async fn rpc_get_block_by_height_future() {
    let (url, _server) = start_test_server(19121).await;
    // Height 999999 doesn't exist
    let resp = rpc_call(&url, "get_block_by_height", json!([999999])).await;
    assert!(resp.get("error").is_some(), "nonexistent height must return error: {}", resp);
}

#[tokio::test]
async fn rpc_get_block_by_hash_missing() {
    let (url, _server) = start_test_server(19122).await;
    let fake_hash = "0000000000000000000000000000000000000000000000000000000000000000";
    let resp = rpc_call(&url, "get_block", json!([fake_hash])).await;
    assert!(resp.get("error").is_some(), "nonexistent block hash must return error: {}", resp);
}

#[tokio::test]
async fn rpc_get_transaction_missing() {
    let (url, _server) = start_test_server(19123).await;
    let fake_hash = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    let resp = rpc_call(&url, "get_transaction", json!([fake_hash])).await;
    assert!(resp.get("error").is_some(), "nonexistent tx must return error: {}", resp);
}

#[tokio::test]
async fn rpc_get_decoys_returns_result() {
    let (url, _server) = start_test_server(19124).await;
    let resp = rpc_call(&url, "get_decoys", json!([16, 0])).await;
    assert!(resp.get("result").is_some(), "get_decoys must return result: {}", resp);
}

#[tokio::test]
async fn rpc_get_block_range_returns_result() {
    let (url, _server) = start_test_server(19125).await;
    let resp = rpc_call(&url, "get_block_range", json!([0, 10])).await;
    assert!(resp.get("result").is_some(), "get_block_range must return result: {}", resp);
}

#[tokio::test]
async fn rpc_is_nullifier_spent_returns_result() {
    let (url, _server) = start_test_server(19126).await;
    let fake_null = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    let resp = rpc_call(&url, "is_nullifier_spent", json!([fake_null])).await;
    assert!(resp.get("result").is_some(), "is_nullifier_spent must return result: {}", resp);
}

// =============================================================================
// MALFORMED INPUT TESTS — must return errors, not crash
// =============================================================================

#[tokio::test]
async fn rpc_unknown_method_returns_error() {
    let (url, _server) = start_test_server(19130).await;
    let resp = rpc_call(&url, "nonexistent_method_xyz", json!([])).await;
    assert!(resp.get("error").is_some(), "unknown method must return error: {}", resp);
}

#[tokio::test]
async fn rpc_get_block_by_height_string_param() {
    let (url, _server) = start_test_server(19131).await;
    // Send string instead of number
    let resp = rpc_call(&url, "get_block_by_height", json!(["not_a_number"])).await;
    assert!(resp.get("error").is_some(), "string param for height must return error: {}", resp);
}

#[tokio::test]
async fn rpc_get_block_by_height_negative() {
    let (url, _server) = start_test_server(19132).await;
    let resp = rpc_call(&url, "get_block_by_height", json!([-1])).await;
    assert!(resp.get("error").is_some(), "negative height must return error: {}", resp);
}

#[tokio::test]
async fn rpc_submit_block_garbage() {
    let (url, _server) = start_test_server(19133).await;
    let resp = rpc_call(&url, "submit_block", json!(["not_valid_hex"])).await;
    assert!(resp.get("error").is_some(), "garbage block must return error: {}", resp);
}

#[tokio::test]
async fn rpc_send_raw_transaction_garbage() {
    let (url, _server) = start_test_server(19134).await;
    let resp = rpc_call(&url, "send_raw_transaction", json!(["deadbeef"])).await;
    assert!(resp.get("error").is_some(), "garbage tx must return error: {}", resp);
}

#[tokio::test]
async fn rpc_get_block_by_height_no_params() {
    let (url, _server) = start_test_server(19135).await;
    let resp = rpc_call(&url, "get_block_by_height", json!([])).await;
    assert!(resp.get("error").is_some(), "missing params must return error: {}", resp);
}

#[tokio::test]
async fn rpc_submit_block_empty_hex() {
    let (url, _server) = start_test_server(19136).await;
    let resp = rpc_call(&url, "submit_block", json!([""])).await;
    assert!(resp.get("error").is_some(), "empty hex block must return error: {}", resp);
}

#[tokio::test]
async fn rpc_get_transaction_invalid_hex() {
    let (url, _server) = start_test_server(19137).await;
    let resp = rpc_call(&url, "get_transaction", json!(["zzzz_not_hex"])).await;
    assert!(resp.get("error").is_some(), "invalid hex tx hash must return error: {}", resp);
}

#[tokio::test]
async fn rpc_get_block_range_inverted() {
    let (url, _server) = start_test_server(19138).await;
    // start > end
    let resp = rpc_call(&url, "get_block_range", json!([100, 0])).await;
    // Should return empty result or error — not crash
    assert!(
        resp.get("result").is_some() || resp.get("error").is_some(),
        "inverted range must not crash: {}", resp
    );
}

// =============================================================================
// RESPONSE STRUCTURE TESTS — verify field presence in key responses
// =============================================================================

#[tokio::test]
async fn rpc_get_info_has_all_fields() {
    let (url, _server) = start_test_server(19140).await;
    let resp = rpc_call(&url, "get_info", json!([])).await;
    let r = &resp["result"];

    let required_fields = [
        "height", "network", "is_synced", "peer_count",
        "mempool_size", "difficulty",
    ];
    for field in required_fields {
        assert!(r.get(field).is_some(), "get_info missing field: {}", field);
    }
}

#[tokio::test]
async fn rpc_get_supply_info_has_fields() {
    let (url, _server) = start_test_server(19141).await;
    let resp = rpc_call(&url, "get_supply_info", json!([])).await;
    let r = &resp["result"];
    // Verify at least one supply-related field exists (field names vary)
    assert!(
        r.get("circulating").is_some()
            || r.get("circulating_supply").is_some()
            || r.get("total_supply").is_some()
            || r.get("supply").is_some()
            || r.get("height").is_some(),
        "supply_info must have at least one supply field: {}", r
    );
}

#[tokio::test]
async fn rpc_get_privacy_stats_has_fields() {
    let (url, _server) = start_test_server(19142).await;
    let resp = rpc_call(&url, "get_privacy_stats", json!([])).await;
    let r = &resp["result"];
    // Verify privacy stats has at least one relevant field
    assert!(
        r.get("ring_size").is_some()
            || r.get("mandatory_ring_size").is_some()
            || r.get("privacy_score").is_some()
            || r.get("stealth_addresses").is_some()
            || r.as_object().map(|o| !o.is_empty()).unwrap_or(false),
        "privacy_stats must have at least one field: {}", r
    );
}

#[tokio::test]
async fn rpc_public_bind_defaults_to_metadata_minimized() {
    let config = RpcConfig {
        auth_enabled: false,
        api_key: Some("test-key".to_string()),
        network_name: "testnet".to_string(),
        ..Default::default()
    };
    let (url, _server) = start_test_server_with_config(19143, config).await;
    let resp = rpc_call_with_auth(&url, "get_peers", json!([]), Some("test-key")).await;
    let r = &resp["result"];
    assert_eq!(
        r.get("metadata_minimized").and_then(|v| v.as_bool()),
        Some(true),
        "public-bind posture should default to metadata minimization: {}",
        resp
    );
}

#[tokio::test]
async fn rpc_info_reports_runtime_hardening_posture() {
    let config = RpcConfig {
        auth_enabled: false,
        api_key: Some("test-key".to_string()),
        network_name: "testnet".to_string(),
        ..Default::default()
    };
    let (url, _server) = start_test_server_with_config(19144, config).await;
    let resp = rpc_call_with_auth(&url, "get_info", json!([]), Some("test-key")).await;
    let r = &resp["result"];
    assert_eq!(r.get("rpc_auth_enabled").and_then(|v| v.as_bool()), Some(false));
    assert_eq!(r.get("metadata_minimized").and_then(|v| v.as_bool()), Some(true));
}

#[tokio::test]
async fn rpc_public_bind_rejects_missing_bearer_for_get_peers() {
    let config = RpcConfig {
        auth_enabled: false,
        api_key: Some("test-key".to_string()),
        network_name: "testnet".to_string(),
        ..Default::default()
    };
    let (url, _server) = start_test_server_with_config(19145, config).await;
    let resp = rpc_call(&url, "get_peers", json!([])).await;
    assert_eq!(resp["error"]["code"], 401, "public bind should reject missing bearer auth");
}

#[tokio::test]
async fn rpc_public_bind_rejects_plain_get_without_upgrade() {
    let config = RpcConfig {
        auth_enabled: false,
        api_key: Some("test-key".to_string()),
        network_name: "testnet".to_string(),
        ..Default::default()
    };
    let (url, _server) = start_test_server_with_config(19150, config).await;
    let status = rpc_get_status(&url, None, None, None).await;
    assert_eq!(status, reqwest::StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn rpc_public_bind_rejects_ws_upgrade_get_without_bearer() {
    let config = RpcConfig {
        auth_enabled: false,
        api_key: Some("test-key".to_string()),
        network_name: "testnet".to_string(),
        ..Default::default()
    };
    let (url, _server) = start_test_server_with_config(19151, config).await;
    let status = rpc_get_status(&url, Some("Upgrade"), Some("websocket"), None).await;
    assert_eq!(status, reqwest::StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn rpc_public_bind_ws_upgrade_get_with_bearer_is_not_unauthorized() {
    let config = RpcConfig {
        auth_enabled: false,
        api_key: Some("test-key".to_string()),
        network_name: "testnet".to_string(),
        ..Default::default()
    };
    let (url, _server) = start_test_server_with_config(19152, config).await;
    let status = rpc_get_status(&url, Some("Upgrade"), Some("websocket"), Some("test-key")).await;
    assert_ne!(status, reqwest::StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn rpc_public_bind_get_peers_response_shape_is_privacy_safe() {
    let config = RpcConfig {
        auth_enabled: false,
        api_key: Some("test-key".to_string()),
        network_name: "testnet".to_string(),
        ..Default::default()
    };
    let (url, _server) = start_test_server_with_config(19146, config).await;
    let resp = rpc_call_with_auth(&url, "get_peers", json!([]), Some("test-key")).await;
    let r = &resp["result"];
    assert_eq!(r.get("metadata_minimized").and_then(|v| v.as_bool()), Some(true));
    assert!(r.get("peers").and_then(|v| v.as_array()).is_some(), "peers must be an array");

    if let Some(peers) = r.get("peers").and_then(|v| v.as_array()) {
        for p in peers {
            assert_eq!(p.get("metadata_minimized").and_then(|v| v.as_bool()), Some(true));
            assert_eq!(p.get("addr").and_then(|v| v.as_str()), Some("[redacted]"));
            assert_eq!(p.get("user_agent").and_then(|v| v.as_str()), Some("[redacted]"));
            assert_eq!(p.get("bytes_recv").and_then(|v| v.as_u64()), Some(0));
            assert_eq!(p.get("bytes_sent").and_then(|v| v.as_u64()), Some(0));
        }
    }
}

#[tokio::test]
async fn rpc_public_bind_redacts_real_peer_fixture_fields() {
    let config = RpcConfig {
        auth_enabled: false,
        api_key: Some("test-key".to_string()),
        network_name: "testnet".to_string(),
        ..Default::default()
    };
    let mut peer = PeerInfo::new(
        generate_peer_id(),
        "198.51.100.9:30303".parse().expect("socket"),
        true,
    );
    peer.height = 42;
    peer.version = 7;
    peer.user_agent = "CoinCync/TestFixture".to_string();
    peer.bytes_recv = 12345;
    peer.bytes_sent = 67890;
    peer.reputation = 88;

    let (url, _server) = start_test_server_with_peer_fixture(19147, config, peer).await;
    let resp = rpc_call_with_auth(&url, "get_peers", json!([]), Some("test-key")).await;
    let peers = resp["result"]["peers"].as_array().expect("peers array");
    assert!(!peers.is_empty(), "fixture should produce at least one peer");
    let p = &peers[0];
    assert_eq!(p["addr"], "[redacted]");
    assert_eq!(p["user_agent"], "[redacted]");
    assert_eq!(p["bytes_recv"], 0);
    assert_eq!(p["bytes_sent"], 0);
    assert_eq!(p["metadata_minimized"], true);
}

#[tokio::test]
async fn rpc_loopback_exposes_peer_fixture_fields_when_not_minimized() {
    let config = RpcConfig {
        auth_enabled: false,
        api_key: None,
        network_name: "testnet".to_string(),
        ..Default::default()
    };
    let mut peer = PeerInfo::new(
        generate_peer_id(),
        "198.51.100.10:40404".parse().expect("socket"),
        true,
    );
    peer.height = 99;
    peer.version = 3;
    peer.user_agent = "CoinCync/LoopbackFixture".to_string();
    peer.bytes_recv = 1111;
    peer.bytes_sent = 2222;
    peer.reputation = 55;

    let (url, _server) = start_test_server_with_peer_fixture_loopback(19148, config, peer.clone()).await;
    let resp = rpc_call(&url, "get_peers", json!([])).await;
    let peers = resp["result"]["peers"].as_array().expect("peers array");
    assert!(!peers.is_empty(), "fixture should produce at least one peer");
    let p = &peers[0];
    assert_eq!(resp["result"]["metadata_minimized"], false);
    assert_eq!(p["metadata_minimized"], false);
    assert_eq!(p["addr"], peer.addr.to_string());
    assert_eq!(p["user_agent"], peer.user_agent);
    assert_eq!(p["bytes_recv"], peer.bytes_recv);
    assert_eq!(p["bytes_sent"], peer.bytes_sent);
}

#[tokio::test]
async fn rpc_loopback_env_override_forces_metadata_minimization() {
    let _guard = env_lock().lock().await;
    std::env::set_var("COINCYNC_RPC_MINIMIZE_METADATA", "1");
    let config = RpcConfig {
        auth_enabled: false,
        api_key: None,
        network_name: "testnet".to_string(),
        ..Default::default()
    };
    let mut peer = PeerInfo::new(
        generate_peer_id(),
        "198.51.100.11:50505".parse().expect("socket"),
        true,
    );
    peer.user_agent = "CoinCync/LoopbackOverrideFixture".to_string();
    peer.bytes_recv = 3333;
    peer.bytes_sent = 4444;

    let (url, _server) = start_test_server_with_peer_fixture_loopback(19149, config, peer).await;
    let resp = rpc_call(&url, "get_peers", json!([])).await;
    let peers = resp["result"]["peers"].as_array().expect("peers array");
    assert!(!peers.is_empty(), "fixture should produce at least one peer");
    let p = &peers[0];
    assert_eq!(resp["result"]["metadata_minimized"], true);
    assert_eq!(p["metadata_minimized"], true);
    assert_eq!(p["addr"], "[redacted]");
    assert_eq!(p["user_agent"], "[redacted]");
    assert_eq!(p["bytes_recv"], 0);
    assert_eq!(p["bytes_sent"], 0);
    std::env::remove_var("COINCYNC_RPC_MINIMIZE_METADATA");
}

#[tokio::test]
async fn rpc_info_reports_stratum_posture_hardened_when_not_public() {
    let _guard = env_lock().lock().await;
    std::env::remove_var("COINCYNC_STRATUM_PUBLIC_BIND");
    std::env::remove_var("COINCYNC_STRATUM_PUBLIC_BIND_ACK");
    std::env::remove_var("COINCYNC_STRATUM_TLS_ENABLED");
    std::env::remove_var("COINCYNC_STRATUM_TLS_PROXY_ACK");
    std::env::remove_var("COINCYNC_STRATUM_PASSWORD");

    let (url, _server) = start_test_server(19153).await;
    let resp = rpc_call(&url, "get_info", json!([])).await;
    let r = &resp["result"];
    assert_eq!(r.get("stratum_public_bind_requested").and_then(|v| v.as_bool()), Some(false));
    assert_eq!(r.get("stratum_transport_hardened").and_then(|v| v.as_bool()), Some(true));
}

#[tokio::test]
async fn rpc_info_reports_stratum_posture_unhardened_when_public_without_tls() {
    let _guard = env_lock().lock().await;
    std::env::set_var("COINCYNC_STRATUM_PUBLIC_BIND", "1");
    std::env::set_var("COINCYNC_STRATUM_PUBLIC_BIND_ACK", "1");
    std::env::remove_var("COINCYNC_STRATUM_TLS_ENABLED");
    std::env::remove_var("COINCYNC_STRATUM_TLS_PROXY_ACK");
    std::env::set_var("COINCYNC_STRATUM_PASSWORD", "test-pw");

    let (url, _server) = start_test_server(19154).await;
    let resp = rpc_call(&url, "get_info", json!([])).await;
    let r = &resp["result"];
    assert_eq!(r.get("stratum_public_bind_requested").and_then(|v| v.as_bool()), Some(true));
    assert_eq!(r.get("stratum_public_bind_ack").and_then(|v| v.as_bool()), Some(true));
    assert_eq!(r.get("stratum_native_tls_enabled").and_then(|v| v.as_bool()), Some(false));
    assert_eq!(r.get("stratum_tls_proxy_ack").and_then(|v| v.as_bool()), Some(false));
    assert_eq!(r.get("stratum_transport_hardened").and_then(|v| v.as_bool()), Some(false));

    std::env::remove_var("COINCYNC_STRATUM_PUBLIC_BIND");
    std::env::remove_var("COINCYNC_STRATUM_PUBLIC_BIND_ACK");
    std::env::remove_var("COINCYNC_STRATUM_PASSWORD");
}

#[tokio::test]
async fn rpc_info_reports_stratum_posture_hardened_with_native_tls() {
    let _guard = env_lock().lock().await;
    std::env::set_var("COINCYNC_STRATUM_PUBLIC_BIND", "1");
    std::env::set_var("COINCYNC_STRATUM_PUBLIC_BIND_ACK", "1");
    std::env::set_var("COINCYNC_STRATUM_TLS_ENABLED", "1");
    std::env::remove_var("COINCYNC_STRATUM_TLS_PROXY_ACK");
    std::env::set_var("COINCYNC_STRATUM_PASSWORD", "test-pw");

    let (url, _server) = start_test_server(19155).await;
    let resp = rpc_call(&url, "get_info", json!([])).await;
    let r = &resp["result"];
    assert_eq!(r.get("stratum_public_bind_requested").and_then(|v| v.as_bool()), Some(true));
    assert_eq!(r.get("stratum_public_bind_ack").and_then(|v| v.as_bool()), Some(true));
    assert_eq!(r.get("stratum_native_tls_enabled").and_then(|v| v.as_bool()), Some(true));
    assert_eq!(r.get("stratum_transport_hardened").and_then(|v| v.as_bool()), Some(true));

    std::env::remove_var("COINCYNC_STRATUM_PUBLIC_BIND");
    std::env::remove_var("COINCYNC_STRATUM_PUBLIC_BIND_ACK");
    std::env::remove_var("COINCYNC_STRATUM_TLS_ENABLED");
    std::env::remove_var("COINCYNC_STRATUM_PASSWORD");
}

#[tokio::test]
async fn rpc_blockchain_info_reports_stratum_posture_fields() {
    let _guard = env_lock().lock().await;
    std::env::set_var("COINCYNC_STRATUM_PUBLIC_BIND", "1");
    std::env::set_var("COINCYNC_STRATUM_PUBLIC_BIND_ACK", "1");
    std::env::set_var("COINCYNC_STRATUM_TLS_ENABLED", "1");
    std::env::remove_var("COINCYNC_STRATUM_TLS_PROXY_ACK");
    std::env::set_var("COINCYNC_STRATUM_PASSWORD", "test-pw");

    let (url, _server) = start_test_server(19156).await;
    let resp = rpc_call(&url, "get_blockchain_info", json!([])).await;
    let r = &resp["result"];
    assert_eq!(r.get("stratum_public_bind_requested").and_then(|v| v.as_bool()), Some(true));
    assert_eq!(r.get("stratum_public_bind_ack").and_then(|v| v.as_bool()), Some(true));
    assert_eq!(r.get("stratum_native_tls_enabled").and_then(|v| v.as_bool()), Some(true));
    assert_eq!(r.get("stratum_tls_proxy_ack").and_then(|v| v.as_bool()), Some(false));
    assert_eq!(r.get("stratum_transport_hardened").and_then(|v| v.as_bool()), Some(true));

    std::env::remove_var("COINCYNC_STRATUM_PUBLIC_BIND");
    std::env::remove_var("COINCYNC_STRATUM_PUBLIC_BIND_ACK");
    std::env::remove_var("COINCYNC_STRATUM_TLS_ENABLED");
    std::env::remove_var("COINCYNC_STRATUM_PASSWORD");
}
