use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use coincync::chain::{Blockchain, SharedBlockchain};
use coincync::mempool::SharedMempool;
use coincync::rpc::{start_rpc_server, RpcConfig};

async fn start_rpc_and_rest(
    rpc_port: u16,
    rest_port: u16,
) -> (coincync::rpc::RpcServer, tokio::task::JoinHandle<()>) {
    let shared_chain: SharedBlockchain = Arc::new(Blockchain::new());
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
        let _ = coincync::rpc::rest::run_rest_api(rest_addr, rpc_addr, false).await;
    });

    tokio::time::sleep(Duration::from_millis(250)).await;
    (rpc_server, rest_task)
}

#[tokio::test]
async fn rest_rpc_proxy_rate_limit_returns_429_under_burst() {
    let (_rpc_server, rest_task) = start_rpc_and_rest(19600, 19602).await;
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(5))
        .build()
        .unwrap();

    let mut joins = tokio::task::JoinSet::new();
    for _ in 0..220u32 {
        let c = client.clone();
        joins.spawn(async move {
            c.post("http://127.0.0.1:19602/rpc")
                .json(&serde_json::json!({
                    "jsonrpc": "2.0",
                    "id": 1,
                    "method": "get_info",
                    "params": []
                }))
                .send()
                .await
                .expect("request should succeed at HTTP level")
                .status()
        });
    }

    let mut too_many = 0usize;
    while let Some(res) = joins.join_next().await {
        let status = res.expect("join should succeed");
        if status == reqwest::StatusCode::TOO_MANY_REQUESTS {
            too_many += 1;
        }
    }
    rest_task.abort();

    assert!(
        too_many > 0,
        "expected some 429 responses under /rpc burst load"
    );
}

#[tokio::test]
async fn rest_stats_rate_limit_returns_429_under_burst() {
    let (_rpc_server, rest_task) = start_rpc_and_rest(19610, 19612).await;
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(5))
        .build()
        .unwrap();

    let mut joins = tokio::task::JoinSet::new();
    for _ in 0..80u32 {
        let c = client.clone();
        joins.spawn(async move {
            c.get("http://127.0.0.1:19612/api/v1/stats")
                .send()
                .await
                .expect("request should succeed at HTTP level")
                .status()
        });
    }

    let mut too_many = 0usize;
    while let Some(res) = joins.join_next().await {
        let status = res.expect("join should succeed");
        if status == reqwest::StatusCode::TOO_MANY_REQUESTS {
            too_many += 1;
        }
    }
    rest_task.abort();

    assert!(
        too_many > 0,
        "expected some 429 responses under /api/v1/stats burst load"
    );
}
