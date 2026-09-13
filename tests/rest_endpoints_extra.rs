//! Route-level behavioral tests for the explorer REST API (`src/rpc/rest.rs`).
//!
//! These exercise the live axum router + jsonrpsee backend end-to-end, which
//! the in-module `#[cfg(test)] mod tests` cannot reach (it only unit-tests the
//! pure helpers). The harness mirrors `tests/rest_rate_limit.rs` exactly:
//! spin up a real `start_rpc_server` on a loopback port, then `run_rest_api`
//! proxying to it, and drive requests with `reqwest`.
//!
//! Scope note: the backend is a fresh `Blockchain::new()` (genesis only, height
//! 0). That is enough for every guard / rejection / privacy-stripping / status
//! path here. Behaviors that need a *tall* chain or a *valid signed tx* are
//! marked "deferred" in the accompanying report rather than faked.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use coincync::chain::{Blockchain, SharedBlockchain};
use coincync::mempool::SharedMempool;
use coincync::rpc::{start_rpc_server, RpcConfig};

/// Start a real RPC server + REST proxy, mirroring `tests/rest_rate_limit.rs`.
async fn start_rpc_and_rest(
    rpc_port: u16,
    rest_port: u16,
) -> (coincync::rpc::RpcServer, tokio::task::JoinHandle<()>) {
    start_rpc_and_rest_ex(rpc_port, rest_port, false).await
}

/// Variant that lets a test toggle the embedded-explorer mount.
async fn start_rpc_and_rest_ex(
    rpc_port: u16,
    rest_port: u16,
    serve_explorer: bool,
) -> (coincync::rpc::RpcServer, tokio::task::JoinHandle<()>) {
    let shared_chain: SharedBlockchain = Arc::new(Blockchain::new());
    // Initialize genesis so height 0 exists (matches the rpc harness); the
    // block-by-height / block-transactions / search-by-height tests rely on it.
    shared_chain.init_genesis().expect("initialize genesis");
    let shared_mempool = SharedMempool::new();
    let rpc_addr: SocketAddr = format!("127.0.0.1:{}", rpc_port).parse().unwrap();
    let rest_addr: SocketAddr = format!("127.0.0.1:{}", rest_port).parse().unwrap();

    let rpc_server = start_rpc_server(
        shared_chain,
        shared_mempool,
        None,
        RpcConfig {
            listen_addr: rpc_addr,
            network_name: "testnet".to_string(),
            ..Default::default()
        },
    )
    .await
    .expect("start RPC server");

    let rest_task = tokio::spawn(async move {
        let _ = coincync::rpc::rest::run_rest_api(rest_addr, rpc_addr, serve_explorer).await;
    });

    tokio::time::sleep(Duration::from_millis(250)).await;
    (rpc_server, rest_task)
}

fn client() -> reqwest::Client {
    reqwest::Client::builder()
        .timeout(Duration::from_secs(5))
        .build()
        .unwrap()
}

// ═══════════════════════════════════════════════════════════════════════════
// POST /rpc — allowlist / body-size / JSON guards + privacy stripping
// ═══════════════════════════════════════════════════════════════════════════

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn rest_rpc_proxy_rejects_disallowed_method_403() {
    let (_rpc, rest) = start_rpc_and_rest(19700, 19702).await;
    let resp = client()
        .post("http://127.0.0.1:19702/rpc")
        .json(&serde_json::json!({
            "jsonrpc": "2.0", "id": 1, "method": "send_raw_transaction", "params": []
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), reqwest::StatusCode::FORBIDDEN);
    rest.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn rest_rpc_proxy_rejects_oversize_body_413() {
    let (_rpc, rest) = start_rpc_and_rest(19704, 19706).await;
    // Build a syntactically-plausible JSON body just over the 64 KiB cap.
    let filler = "a".repeat(64 * 1024 + 16);
    let body = format!(
        "{{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"get_info\",\"params\":[\"{}\"]}}",
        filler
    );
    let resp = client()
        .post("http://127.0.0.1:19706/rpc")
        .header("content-type", "application/json")
        .body(body)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), reqwest::StatusCode::PAYLOAD_TOO_LARGE);
    rest.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn rest_rpc_proxy_rejects_invalid_json_400() {
    let (_rpc, rest) = start_rpc_and_rest(19708, 19710).await;
    let resp = client()
        .post("http://127.0.0.1:19710/rpc")
        .header("content-type", "application/json")
        .body("this is not json{".to_string())
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), reqwest::StatusCode::BAD_REQUEST);
    rest.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn rest_rpc_proxy_get_info_strips_privacy_and_operator_fields() {
    let (_rpc, rest) = start_rpc_and_rest(19712, 19714).await;
    let resp = client()
        .post("http://127.0.0.1:19714/rpc")
        .json(&serde_json::json!({
            "jsonrpc": "2.0", "id": 1, "method": "get_info", "params": []
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), reqwest::StatusCode::OK);
    let json: serde_json::Value = resp.json().await.unwrap();
    let result = json.get("result").and_then(|r| r.as_object()).unwrap();
    // Operator/privacy correlators must be stripped by the public proxy.
    for redacted in [
        "peer_count",
        "mempool_size",
        "tx_pool_size",
        "rpc_auth_enabled",
        "metadata_minimized",
        "health_score",
    ] {
        assert!(
            !result.contains_key(redacted),
            "get_info via public /rpc must strip `{redacted}`"
        );
    }
    // But the harmless chain fields survive.
    assert!(result.contains_key("height"), "height must be preserved");
    rest.abort();
}

// ═══════════════════════════════════════════════════════════════════════════
// Curated GET endpoints — privacy subsets + happy payloads
// ═══════════════════════════════════════════════════════════════════════════

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn rest_status_omits_ring_correlators() {
    let (_rpc, rest) = start_rpc_and_rest(19716, 19718).await;
    let json: serde_json::Value = client()
        .get("http://127.0.0.1:19718/api/v1/status")
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let obj = json.as_object().unwrap();
    assert!(!obj.contains_key("anonymity_set"));
    assert!(!obj.contains_key("effective_ring_size"));
    assert!(obj.contains_key("height"));
    rest.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn rest_supply_endpoints_return_happy_payloads() {
    let (_rpc, rest) = start_rpc_and_rest(19720, 19722).await;
    let c = client();

    let supply: serde_json::Value = c
        .get("http://127.0.0.1:19722/api/v1/supply")
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert!(supply.get("total_emitted").is_some());

    // circulating — bare `whole.micro` decimal string.
    let circ = c
        .get("http://127.0.0.1:19722/api/v1/supply/circulating")
        .send()
        .await
        .unwrap();
    assert_eq!(circ.status(), reqwest::StatusCode::OK);
    let circ_body = circ.text().await.unwrap();
    assert!(
        circ_body.contains('.') && circ_body.split('.').nth(1).map(|f| f.len()) == Some(6),
        "circulating supply should be `whole.micro` with 6 fractional digits, got {circ_body}"
    );

    // max — pure constant, no backend.
    let max = c
        .get("http://127.0.0.1:19722/api/v1/supply/max")
        .send()
        .await
        .unwrap();
    assert_eq!(max.status(), reqwest::StatusCode::OK);
    assert!(max.text().await.unwrap().parse::<u128>().is_ok());

    rest.abort();
}

// ═══════════════════════════════════════════════════════════════════════════
// Blocks
// ═══════════════════════════════════════════════════════════════════════════

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn rest_block_by_hash_invalid_returns_400() {
    let (_rpc, rest) = start_rpc_and_rest(19724, 19726).await;
    let resp = client()
        .get("http://127.0.0.1:19726/api/v1/block/hash/not-a-valid-hash")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), reqwest::StatusCode::BAD_REQUEST);
    rest.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn rest_block_by_height_happy_and_non_numeric() {
    let (_rpc, rest) = start_rpc_and_rest(19728, 19730).await;
    let c = client();
    // Genesis at height 0 exists on a fresh chain.
    let ok = c
        .get("http://127.0.0.1:19730/api/v1/block/height/0")
        .send()
        .await
        .unwrap();
    assert_eq!(ok.status(), reqwest::StatusCode::OK);
    // Non-numeric height fails axum's `Path<u64>` extraction → 400.
    let bad = c
        .get("http://127.0.0.1:19730/api/v1/block/height/abc")
        .send()
        .await
        .unwrap();
    assert_eq!(bad.status(), reqwest::StatusCode::BAD_REQUEST);
    rest.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn rest_block_transactions_returns_list_shape() {
    let (_rpc, rest) = start_rpc_and_rest(19732, 19734).await;
    let json: serde_json::Value = client()
        .get("http://127.0.0.1:19734/api/v1/block/0/transactions")
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(json.get("height").and_then(|v| v.as_u64()), Some(0));
    assert!(json.get("transactions").map(|v| v.is_array()).unwrap_or(false));
    assert!(json.get("tx_count").is_some());
    rest.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn rest_recent_blocks_paginates_and_rate_limits() {
    let (_rpc, rest) = start_rpc_and_rest(19736, 19738).await;
    let c = client();

    // Single request: pagination envelope present.
    let json: serde_json::Value = c
        .get("http://127.0.0.1:19738/api/v1/blocks/recent?page=1&limit=10")
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert!(json.get("blocks").map(|v| v.is_array()).unwrap_or(false));
    let pag = json.get("pagination").and_then(|v| v.as_object()).unwrap();
    assert_eq!(pag.get("page").and_then(|v| v.as_u64()), Some(1));
    assert_eq!(pag.get("limit").and_then(|v| v.as_u64()), Some(10));

    // Burst: RECENT_MAX_REQ_PER_SEC=20 → some 429s (global + per-IP window).
    let mut joins = tokio::task::JoinSet::new();
    for _ in 0..80u32 {
        let cc = c.clone();
        joins.spawn(async move {
            cc.get("http://127.0.0.1:19738/api/v1/blocks/recent")
                .send()
                .await
                .unwrap()
                .status()
        });
    }
    let mut too_many = 0usize;
    while let Some(res) = joins.join_next().await {
        if res.unwrap() == reqwest::StatusCode::TOO_MANY_REQUESTS {
            too_many += 1;
        }
    }
    assert!(too_many > 0, "expected some 429 under /blocks/recent burst");
    rest.abort();
}

// ═══════════════════════════════════════════════════════════════════════════
// Transactions
// ═══════════════════════════════════════════════════════════════════════════

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn rest_transaction_invalid_400_and_missing_404() {
    let (_rpc, rest) = start_rpc_and_rest(19740, 19742).await;
    let c = client();
    // Invalid hash → 400 (validated before backend).
    let bad = c
        .get("http://127.0.0.1:19742/api/v1/transaction/zzzz")
        .send()
        .await
        .unwrap();
    assert_eq!(bad.status(), reqwest::StatusCode::BAD_REQUEST);
    // Valid 64-hex but unknown → backend -5 → 404.
    let missing = c
        .get(&format!(
            "http://127.0.0.1:19742/api/v1/transaction/{}",
            "0".repeat(64)
        ))
        .send()
        .await
        .unwrap();
    assert_eq!(missing.status(), reqwest::StatusCode::NOT_FOUND);
    rest.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn rest_submit_transaction_rejects_non_hex_and_oversize_400() {
    let (_rpc, rest) = start_rpc_and_rest(19744, 19746).await;
    let c = client();
    // Non-hex.
    let non_hex = c
        .post("http://127.0.0.1:19746/api/v1/transaction/submit")
        .json(&serde_json::json!({ "tx_hex": "nothex!!" }))
        .send()
        .await
        .unwrap();
    assert_eq!(non_hex.status(), reqwest::StatusCode::BAD_REQUEST);
    // Over the 1 MiB cap (still valid hex chars).
    let oversize = c
        .post("http://127.0.0.1:19746/api/v1/transaction/submit")
        .json(&serde_json::json!({ "tx_hex": "a".repeat(1024 * 1024 + 2) }))
        .send()
        .await
        .unwrap();
    assert_eq!(oversize.status(), reqwest::StatusCode::BAD_REQUEST);
    rest.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn rest_submit_transaction_rate_limits_at_5_per_sec() {
    let (_rpc, rest) = start_rpc_and_rest(19748, 19750).await;
    let c = client();
    // SUBMIT_MAX_REQ_PER_SEC = 5 → a burst well above 5 must yield 429s.
    // Rate limit is checked BEFORE hex validation, so short valid hex is fine.
    let mut joins = tokio::task::JoinSet::new();
    for _ in 0..40u32 {
        let cc = c.clone();
        joins.spawn(async move {
            cc.post("http://127.0.0.1:19750/api/v1/transaction/submit")
                .json(&serde_json::json!({ "tx_hex": "00" }))
                .send()
                .await
                .unwrap()
                .status()
        });
    }
    let mut too_many = 0usize;
    while let Some(res) = joins.join_next().await {
        if res.unwrap() == reqwest::StatusCode::TOO_MANY_REQUESTS {
            too_many += 1;
        }
    }
    assert!(too_many > 0, "expected some 429 under submit burst (5/s cap)");
    rest.abort();
}

// ═══════════════════════════════════════════════════════════════════════════
// Mempool
// ═══════════════════════════════════════════════════════════════════════════

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn rest_mempool_and_stats_happy() {
    let (_rpc, rest) = start_rpc_and_rest(19752, 19754).await;
    let c = client();

    let pool = c
        .get("http://127.0.0.1:19754/api/v1/mempool")
        .send()
        .await
        .unwrap();
    assert_eq!(pool.status(), reqwest::StatusCode::OK);

    let stats: serde_json::Value = c
        .get("http://127.0.0.1:19754/api/v1/mempool/stats")
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    for key in ["count", "bytes", "total_fees", "max_size"] {
        assert!(stats.get(key).is_some(), "mempool/stats missing `{key}`");
    }
    rest.abort();
}

// ═══════════════════════════════════════════════════════════════════════════
// Search — resolution + guards
// ═══════════════════════════════════════════════════════════════════════════

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn rest_search_resolves_height_and_block_hash() {
    let (_rpc, rest) = start_rpc_and_rest(19756, 19758).await;
    let c = client();

    // Height resolution: "0" → genesis block.
    let by_height: serde_json::Value = c
        .get("http://127.0.0.1:19758/api/v1/search?q=0")
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(by_height.get("type").and_then(|v| v.as_str()), Some("block"));

    // Hash resolution: fetch genesis hash from /status, then search it.
    let status: serde_json::Value = c
        .get("http://127.0.0.1:19758/api/v1/status")
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    if let Some(tip_hash) = status.get("tip_hash").and_then(|v| v.as_str()) {
        if tip_hash.len() == 64 {
            let by_hash: serde_json::Value = c
                .get(&format!(
                    "http://127.0.0.1:19758/api/v1/search?q={}",
                    tip_hash
                ))
                .send()
                .await
                .unwrap()
                .json()
                .await
                .unwrap();
            assert_eq!(
                by_hash.get("type").and_then(|v| v.as_str()),
                Some("block"),
                "searching the tip hash should resolve to a block"
            );
        }
    }
    rest.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn rest_search_guards_empty_overlong_and_no_match() {
    let (_rpc, rest) = start_rpc_and_rest(19760, 19762).await;
    let c = client();

    // Empty query.
    let empty = c
        .get("http://127.0.0.1:19762/api/v1/search?q=")
        .send()
        .await
        .unwrap();
    assert_eq!(empty.status(), reqwest::StatusCode::BAD_REQUEST);

    // Over MAX_SEARCH_QUERY_LEN (128).
    let long = c
        .get(&format!(
            "http://127.0.0.1:19762/api/v1/search?q={}",
            "a".repeat(200)
        ))
        .send()
        .await
        .unwrap();
    assert_eq!(long.status(), reqwest::StatusCode::BAD_REQUEST);

    // Well-formed but unresolvable (numeric height far past the tip, not 64-hex).
    let none = c
        .get("http://127.0.0.1:19762/api/v1/search?q=999999999")
        .send()
        .await
        .unwrap();
    assert_eq!(none.status(), reqwest::StatusCode::NOT_FOUND);
    rest.abort();
}

// ═══════════════════════════════════════════════════════════════════════════
// Network / privacy
// ═══════════════════════════════════════════════════════════════════════════

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn rest_network_omits_effective_ring_size() {
    let (_rpc, rest) = start_rpc_and_rest(19764, 19766).await;
    let json: serde_json::Value = client()
        .get("http://127.0.0.1:19766/api/v1/network")
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let obj = json.as_object().unwrap();
    assert!(!obj.contains_key("effective_ring_size"));
    assert!(obj.contains_key("health_score"));
    assert!(obj.contains_key("network"));
    rest.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn rest_anonymity_returns_happy_payload() {
    let (_rpc, rest) = start_rpc_and_rest(19768, 19770).await;
    let resp = client()
        .get("http://127.0.0.1:19770/api/v1/anonymity")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), reqwest::StatusCode::OK);
    rest.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn rest_peers_is_count_only_with_auth_note() {
    let (_rpc, rest) = start_rpc_and_rest(19772, 19774).await;
    let json: serde_json::Value = client()
        .get("http://127.0.0.1:19774/api/v1/peers")
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let obj = json.as_object().unwrap();
    assert!(obj.contains_key("peer_count"));
    assert!(obj.contains_key("note"), "peers must carry the auth/privacy note");
    // No detailed per-peer topology fields leak here.
    assert!(!obj.contains_key("peers"));
    rest.abort();
}

// ═══════════════════════════════════════════════════════════════════════════
// Stats / emission / events
// ═══════════════════════════════════════════════════════════════════════════

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn rest_stats_short_circuits_with_few_blocks() {
    let (_rpc, rest) = start_rpc_and_rest(19776, 19778).await;
    let json: serde_json::Value = client()
        .get("http://127.0.0.1:19778/api/v1/stats")
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    // Fresh chain (height 0 < 2) → the "Insufficient blocks" short-circuit.
    assert_eq!(json.get("window").and_then(|v| v.as_u64()), Some(0));
    assert!(json
        .get("note")
        .and_then(|v| v.as_str())
        .map(|s| s.contains("Insufficient"))
        .unwrap_or(false));
    rest.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn rest_emission_returns_curve_payload() {
    let (_rpc, rest) = start_rpc_and_rest(19780, 19782).await;
    let json: serde_json::Value = client()
        .get("http://127.0.0.1:19782/api/v1/emission")
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert!(json.get("points").map(|v| v.is_array()).unwrap_or(false));
    assert!(json.get("max_supply_cync").is_some());
    assert!(json.get("units_per_cync").is_some());
    rest.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn rest_events_returns_happy_payload() {
    let (_rpc, rest) = start_rpc_and_rest(19784, 19786).await;
    let resp = client()
        .get("http://127.0.0.1:19786/api/v1/events")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), reqwest::StatusCode::OK);
    rest.abort();
}

// ═══════════════════════════════════════════════════════════════════════════
// Assets — removed in 1.0 → 410 Gone
// ═══════════════════════════════════════════════════════════════════════════

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn rest_asset_endpoints_return_410_gone() {
    let (_rpc, rest) = start_rpc_and_rest(19788, 19790).await;
    let c = client();
    let by_id = c
        .get("http://127.0.0.1:19790/api/v1/asset/anything")
        .send()
        .await
        .unwrap();
    assert_eq!(by_id.status(), reqwest::StatusCode::GONE);
    let list = c
        .get("http://127.0.0.1:19790/api/v1/assets")
        .send()
        .await
        .unwrap();
    assert_eq!(list.status(), reqwest::StatusCode::GONE);
    rest.abort();
}

// ═══════════════════════════════════════════════════════════════════════════
// CORS — restricted allow-origin
// ═══════════════════════════════════════════════════════════════════════════

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn rest_cors_allows_known_origin_and_omits_unknown() {
    let (_rpc, rest) = start_rpc_and_rest(19792, 19794).await;
    let c = client();

    // Allowed origin (localhost:3000 is baked into the CORS allowlist) →
    // the response echoes access-control-allow-origin.
    let allowed = c
        .get("http://127.0.0.1:19794/api/v1/health")
        .header("Origin", "http://localhost:3000")
        .send()
        .await
        .unwrap();
    assert_eq!(allowed.status(), reqwest::StatusCode::OK);
    assert_eq!(
        allowed
            .headers()
            .get("access-control-allow-origin")
            .and_then(|v| v.to_str().ok()),
        Some("http://localhost:3000"),
        "known origin must be reflected"
    );

    // Unknown origin → no allow-origin header (browser blocks the read).
    let denied = c
        .get("http://127.0.0.1:19794/api/v1/health")
        .header("Origin", "https://evil.example.com")
        .send()
        .await
        .unwrap();
    assert!(
        denied.headers().get("access-control-allow-origin").is_none(),
        "unknown origin must NOT be reflected in access-control-allow-origin"
    );
    rest.abort();
}

// ═══════════════════════════════════════════════════════════════════════════
// run_rest_api — explorer mount gated on `serve_explorer`
// ═══════════════════════════════════════════════════════════════════════════

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn rest_explorer_mount_present_only_when_enabled() {
    // serve_explorer = false → GET / is not routed.
    let (_rpc_off, rest_off) = start_rpc_and_rest_ex(19796, 19798, false).await;
    let off = client().get("http://127.0.0.1:19798/").send().await.unwrap();
    assert_eq!(off.status(), reqwest::StatusCode::NOT_FOUND);
    rest_off.abort();

    // serve_explorer = true → GET / serves the embedded explorer HTML.
    let (_rpc_on, rest_on) = start_rpc_and_rest_ex(19801, 19803, true).await;
    let on = client().get("http://127.0.0.1:19803/").send().await.unwrap();
    assert_eq!(on.status(), reqwest::StatusCode::OK);
    let ctype = on
        .headers()
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    assert!(ctype.contains("text/html"), "explorer root should be HTML");
    rest_on.abort();
}

// ═══════════════════════════════════════════════════════════════════════════
// WebSocket — ping/pong + per-IP connection cap
// ═══════════════════════════════════════════════════════════════════════════
//
// The per-IP and global WS counters (`ACTIVE_WS_PER_IP` / `ACTIVE_WS_CONNECTIONS`)
// are process-global statics shared across the whole test binary. To keep this
// deterministic this is the ONLY live-WS test: it drives ping/pong and the
// per-IP cap in one sequential body over a single "unknown" bucket (proxy
// headers are untrusted by default, so every connection shares that bucket).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn rest_ws_ping_pong_and_per_ip_cap() {
    use futures::{SinkExt, StreamExt};
    use tokio_tungstenite::tungstenite::Message;

    let (_rpc, rest) = start_rpc_and_rest(19805, 19807).await;
    let url = "ws://127.0.0.1:19807/api/v1/ws";

    // Fill the per-IP cap (MAX_WS_PER_IP = 5). Hold the streams open so the
    // server-side guards are not dropped.
    let mut held = Vec::new();
    for i in 0..5 {
        let (stream, _resp) = tokio_tungstenite::connect_async(url)
            .await
            .unwrap_or_else(|e| panic!("connection {i} under the cap should succeed: {e}"));
        held.push(stream);
    }

    // ping → pong on one of the held connections.
    held[0]
        .send(Message::Text("ping".to_string().into()))
        .await
        .unwrap();
    let mut got_pong = false;
    for _ in 0..3 {
        match tokio::time::timeout(Duration::from_secs(3), held[0].next()).await {
            Ok(Some(Ok(Message::Text(t)))) => {
                if t.as_str().contains("pong") {
                    got_pong = true;
                    break;
                }
                // otherwise it was a periodic status/heartbeat frame — keep reading.
            }
            _ => break,
        }
    }
    assert!(got_pong, "server must answer a `ping` text frame with a pong");

    // The 6th connection from the same (unknown) bucket must be rejected 429.
    match tokio_tungstenite::connect_async(url).await {
        Ok(_) => panic!("6th connection should exceed MAX_WS_PER_IP and be rejected"),
        Err(tokio_tungstenite::tungstenite::Error::Http(resp)) => {
            assert_eq!(
                resp.status().as_u16(),
                429,
                "over-cap WS upgrade must return 429"
            );
        }
        Err(e) => panic!("expected an HTTP 429 rejection, got: {e}"),
    }

    drop(held);
    rest.abort();
}
