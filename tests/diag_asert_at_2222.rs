//! Diagnostic: compute the expected ASERT target for testnet block 2222
//! using the CURRENT code in this tree, against canonical history
//! pulled from the live fleet RPC. Compare to the canonical target.
//!
//! If our calc matches `0x00153b2a...` → the fleet's running this code,
//! and the bug barns is hitting is on his side.
//!
//! If our calc gives something else (e.g. `0x0015d888...`) → our code
//! is the FIXED ASERT but the fleet was mined with the BUGGY pre-S1-fix
//! formula. The fleet binary is missing the S1 fix.
//!
//! Run with: `cargo test --release --test diag_asert_at_2222 -- --ignored --nocapture`

use coincync::consensus::difficulty::{calculate_difficulty, DifficultyBlock};
use coincync::primitives::Hash;

const RPC_URL: &str = "https://api.coincync.network/rpc/testnet";
const TARGET_HEIGHT: u64 = 2222;
const LONG_WINDOW: u64 = 144;

#[tokio::test(flavor = "current_thread")]
#[ignore]
async fn diagnose_block_2222_target() {
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(15))
        .build()
        .unwrap();

    let start = TARGET_HEIGHT.saturating_sub(LONG_WINDOW);
    let mut blocks: Vec<DifficultyBlock> = Vec::with_capacity(LONG_WINDOW as usize);
    for h in start..TARGET_HEIGHT {
        let body = serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "get_block_by_height",
            "params": [h],
        });
        let resp = client.post(RPC_URL).json(&body).send().await
            .expect("RPC request failed");
        let json: serde_json::Value = resp.json().await.expect("RPC response not JSON");
        let result = json.get("result").expect("RPC error response");
        let timestamp = result["timestamp"].as_u64().expect("missing timestamp");
        let target_hex = result["target"].as_str().expect("missing target");
        let target = Hash::from_hex(target_hex).expect("invalid target hex");
        blocks.push(DifficultyBlock { height: h, timestamp, target });
    }

    let computed = calculate_difficulty(&blocks, TARGET_HEIGHT);

    let canonical_body = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "get_block_by_height",
        "params": [TARGET_HEIGHT],
    });
    let resp = client.post(RPC_URL).json(&canonical_body).send().await.unwrap();
    let json: serde_json::Value = resp.json().await.unwrap();
    let canonical_target_hex = json["result"]["target"].as_str().unwrap().to_string();
    let canonical = Hash::from_hex(&canonical_target_hex).unwrap();

    println!();
    println!("=== ASERT diagnostic for block {} ===", TARGET_HEIGHT);
    println!("computed (this tree): {}", computed.to_hex());
    println!("canonical (fleet):    {}", canonical_target_hex);
    println!("match: {}", computed == canonical);
    println!();
    println!("Window used: heights {}..{}", start, TARGET_HEIGHT);
    println!("Parent (height {}): ts={} target={}",
             blocks.last().unwrap().height,
             blocks.last().unwrap().timestamp,
             blocks.last().unwrap().target.to_hex());

    if computed != canonical {
        println!("DIVERGENCE: this tree's code does NOT produce the canonical chain target.");
        println!("Either this code has the FIXED S1 ASERT formula and the fleet doesn't,");
        println!("OR vice versa. Check `let denominator = ...` in difficulty.rs::apply_asert.");
    }
}
