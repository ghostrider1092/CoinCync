//! Exercise the assembled server across handler module boundaries.

use super::{env_lock, rpc_call, start_initialized_test_server, start_test_server};
use coincync::chain::Blockchain;
use coincync::mempool::SharedMempool;
use coincync::rpc::{start_rpc_server, RpcConfig, MAX_RPC_AUDIT_BLOCK_SPAN};
use serde_json::{json, Value};
use std::sync::Arc;
use std::time::Duration;

#[tokio::test(flavor = "multi_thread")]
async fn block_queries_and_sync_queries_return_the_same_genesis() {
    let (url, server) = start_initialized_test_server(19180).await;
    let by_height = rpc_call(&url, "get_block_by_height", json!([0])).await;
    let block = &by_height["result"];
    assert_eq!(block["height"], 0);
    assert!(block["bytes"].as_str().is_some());

    let by_hash = rpc_call(&url, "get_block", json!([block["hash"]])).await;
    let range = rpc_call(&url, "get_block_range", json!([0, 0])).await;
    let batch = rpc_call(&url, "get_blocks_batch", json!([0, 1])).await;
    assert_eq!(&by_hash["result"], block);
    assert_eq!(range["result"]["count"], 1);
    assert_eq!(&range["result"]["blocks"][0], block);
    assert_eq!(batch["result"]["count"], 1);
    assert_eq!(batch["result"]["blocks"][0]["hash"], block["hash"]);
    assert_eq!(batch["result"]["blocks"][0]["hex"], block["bytes"]);

    let fork = rpc_call(&url, "find_fork_point", json!([[[0, block["hash"]]]])).await;
    assert_eq!(fork["result"]["fork_point"], 0);
    let digests = rpc_call(&url, "get_output_digests", json!([0, 0])).await;
    assert_eq!(digests["result"]["count"], 1);
    assert_eq!(digests["result"]["digests"].as_array().unwrap().len(), 1);
    let checkpoints = rpc_call(&url, "get_sync_checkpoints", json!([1])).await;
    assert_eq!(checkpoints["result"]["chain_height"], 0);
    assert_eq!(checkpoints["result"]["checkpoints"], json!([]));
    server.stop();
}

#[tokio::test(flavor = "multi_thread")]
async fn status_and_supply_handlers_share_chain_and_mempool_context() {
    let (url, server) = start_initialized_test_server(19181).await;
    let info = rpc_call(&url, "get_info", json!([])).await;
    let chain = rpc_call(&url, "get_blockchain_info", json!([])).await;
    let supply = rpc_call(&url, "get_supply_info", json!([])).await;
    let metrics = rpc_call(&url, "get_metrics", json!([])).await;
    let snapshot = rpc_call(&url, "get_state_snapshot", json!([])).await;
    let burn = rpc_call(&url, "get_burn_stats", json!([])).await;
    let total_supply = &supply["result"]["total_supply"];
    assert!(total_supply.as_str().unwrap().parse::<u128>().is_ok());
    assert_eq!(&chain["result"]["total_supply"], total_supply);
    assert_eq!(&metrics["result"]["chain_supply_atomic"], total_supply);
    assert_eq!(&snapshot["result"]["total_supply"], total_supply);
    assert_eq!(&burn["result"]["circulating_supply"], total_supply);
    assert_eq!(info["result"]["top_hash"], snapshot["result"]["tip_hash"]);

    let peers = rpc_call(&url, "get_peer_info", json!([])).await;
    let health = rpc_call(&url, "get_health", json!([])).await;
    let mempool = rpc_call(&url, "get_mempool_transactions", json!([])).await;
    assert_eq!(
        peers["result"]["local_tip_hash"],
        info["result"]["top_hash"]
    );
    assert_eq!(peers["result"]["peers"], json!([]));
    assert_eq!(health["result"]["status"], "degraded");
    assert_eq!(health["result"]["checks"]["has_peers"], false);
    assert_eq!(mempool["result"], json!({"count": 0, "transactions": []}));
    server.stop();
}

#[tokio::test(flavor = "multi_thread")]
async fn audit_handlers_preserve_responses_and_inclusive_range_limits() {
    let (url, server) = start_test_server(19182).await;
    let expected_responses = [
        (
            "check_zero_commitments_in_range",
            json!({"zero_count": 0, "locations": []}),
        ),
        (
            "verify_signatures_in_range",
            json!({"valid": true, "checked": 0, "failures": 0, "findings": []}),
        ),
        (
            "verify_range_proofs_in_range",
            json!({"valid": true, "checked": 0, "failures": 0, "findings": []}),
        ),
        (
            "verify_commitment_balance_in_range",
            json!({"valid": true, "checked": 0, "failures": 0, "findings": []}),
        ),
        (
            "full_chain_audit",
            json!({"valid": true, "blocks_checked": 0, "txs_checked": 0, "findings": 0, "details": []}),
        ),
    ];
    for (method, expected) in expected_responses {
        for params in [json!([1, 1]), json!([1, MAX_RPC_AUDIT_BLOCK_SPAN])] {
            let response = rpc_call(&url, method, params).await;
            assert_eq!(response["result"], expected, "{method}: {response}");
        }
        for params in [
            json!([]),
            json!([2, 1]),
            json!([1, MAX_RPC_AUDIT_BLOCK_SPAN + 1]),
        ] {
            let response = rpc_call(&url, method, params).await;
            assert_eq!(response["error"]["code"], -32602, "{method}: {response}");
        }
    }
    let uniqueness = rpc_call(&url, "verify_keyimage_uniqueness", json!([])).await;
    assert_eq!(
        uniqueness["result"],
        json!({
            "valid": true, "duplicates": 0, "duplicate_images": [], "total_checked": 0,
        })
    );
    let reward = rpc_call(&url, "get_expected_reward", json!([1])).await;
    assert_eq!(reward["result"]["height"], 1);
    assert_eq!(
        reward["result"]["reward"],
        coincync::emission::calculate_block_reward(1).as_atomic()
    );
    server.stop();
}

#[tokio::test(flavor = "multi_thread")]
async fn bearer_auth_gates_each_assembled_handler_group() {
    let _guard = env_lock().lock().await;
    let chain = Arc::new(Blockchain::new());
    chain.init_genesis().expect("initialize genesis");
    let server = start_rpc_server(
        chain,
        SharedMempool::new(),
        None,
        RpcConfig {
            listen_addr: "127.0.0.1:19183".parse().unwrap(),
            auth_enabled: true,
            api_key: Some("handler-group-test-key".into()),
            ..Default::default()
        },
    )
    .await
    .expect("start authenticated RPC server");
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(5))
        .build()
        .unwrap();
    for (method, params) in [
        ("get_info", json!([])),
        ("get_block_by_height", json!([0])),
        ("get_block_template", json!([])),
        ("get_mempool_info", json!([])),
        ("get_privacy_stats", json!([])),
        ("full_chain_audit", json!([0, 0])),
    ] {
        let body = json!({"jsonrpc": "2.0", "id": 7, "method": method, "params": params});
        for bearer in [None, Some("wrong-test-key")] {
            let mut request = client.post("http://127.0.0.1:19183").json(&body);
            if let Some(token) = bearer {
                request = request.bearer_auth(token);
            }
            let response = request.send().await.expect("unauthorized request");
            assert_eq!(
                response.status(),
                reqwest::StatusCode::UNAUTHORIZED,
                "{method}"
            );
        }
        let response = client
            .post("http://127.0.0.1:19183")
            .bearer_auth("handler-group-test-key")
            .json(&body)
            .send()
            .await
            .expect("authenticated request");
        assert_eq!(response.status(), reqwest::StatusCode::OK, "{method}");
        let response: Value = response.json().await.expect("JSON-RPC response");
        assert_eq!(response["id"], 7);
        assert!(response["result"].is_object(), "{method}: {response}");
        assert!(response.get("error").is_none(), "{method}: {response}");
    }
    server.stop();
}
