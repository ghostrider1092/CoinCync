//! Load / stress tests for the "small hidden things" batch.
//!
//! Marked `#[ignore]` (like the real-PoW reorg suite) because they bind real
//! ports and run tight high-volume loops — run explicitly:
//!   cargo test --test stress_small_things --features testnet -- --ignored --nocapture
//!
//! Two dimensions:
//!   1. `rpc_concurrent_load` — many concurrent clients hammering the new
//!      observability endpoints (get_vitals, get_info, get_difficulty_health)
//!      through the real JSON-RPC server. Measures throughput, latency
//!      percentiles, and error count under concurrency (exercises the blocking
//!      pool + chain read-lock contention + per-request health/fingerprint work).
//!   2. `empirical_decoy_sampler_throughput` — the #2 empirical sampler at volume
//!      over a large, skewed output-age histogram: confirms it scales, stays
//!      unique, and does not degrade.

use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use coincync::chain::{Blockchain, SharedBlockchain};
use coincync::mempool::SharedMempool;
use coincync::rpc::{start_rpc_server, RpcConfig};

async fn start_server(rpc_port: u16, seed_blocks: u64) -> coincync::rpc::RpcServer {
    let chain: SharedBlockchain = Arc::new(Blockchain::new());
    chain.init_genesis().expect("init genesis");
    if seed_blocks > 0 {
        // Seed a mature chain (no real PoW) so get_difficulty_health exercises a
        // full 144-block window scan under load. 120s spacing = TARGET_BLOCK_TIME.
        chain.seed_linear_chain_for_testing(seed_blocks, 120);
    }
    let mempool = SharedMempool::new();
    let addr: SocketAddr = format!("127.0.0.1:{rpc_port}").parse().unwrap();
    let server = start_rpc_server(
        chain,
        mempool,
        None,
        RpcConfig {
            listen_addr: addr,
            network_name: "testnet".to_string(),
            ..Default::default()
        },
    )
    .await
    .expect("start RPC server");
    tokio::time::sleep(Duration::from_millis(300)).await;
    server
}

fn body(method: &str) -> String {
    format!("{{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"{method}\",\"params\":[]}}")
}

async fn hammer_rpc(rpc_port: u16, label: &str) {
    const WORKERS: usize = 64;
    const REQS_PER_WORKER: usize = 150;
    const TOTAL: usize = WORKERS * REQS_PER_WORKER;

    let url = format!("http://127.0.0.1:{rpc_port}/");
    let methods = ["get_vitals", "get_info", "get_difficulty_health"];

    let errors = Arc::new(AtomicU64::new(0));
    let latencies = Arc::new(Mutex::new(Vec::<u128>::with_capacity(TOTAL)));

    let start = Instant::now();
    let mut handles = Vec::with_capacity(WORKERS);
    for w in 0..WORKERS {
        let url = url.clone();
        let errors = errors.clone();
        let latencies = latencies.clone();
        handles.push(tokio::spawn(async move {
            let client = reqwest::Client::builder()
                .timeout(Duration::from_secs(10))
                .build()
                .unwrap();
            let mut local = Vec::with_capacity(REQS_PER_WORKER);
            for i in 0..REQS_PER_WORKER {
                let method = methods[(w + i) % methods.len()];
                let t0 = Instant::now();
                let resp = client
                    .post(&url)
                    .body(body(method))
                    .header("content-type", "application/json")
                    .send()
                    .await;
                let ok = match resp {
                    Ok(r) if r.status().is_success() => match r.text().await {
                        Ok(txt) => txt.contains("\"result\"") && !txt.contains("\"error\""),
                        Err(_) => false,
                    },
                    _ => false,
                };
                if !ok {
                    errors.fetch_add(1, Ordering::Relaxed);
                }
                local.push(t0.elapsed().as_micros());
            }
            latencies.lock().unwrap().extend(local);
        }));
    }
    for h in handles {
        h.await.unwrap();
    }
    let elapsed = start.elapsed();

    let errs = errors.load(Ordering::Relaxed);
    let mut lat = latencies.lock().unwrap().clone();
    lat.sort_unstable();
    let pct =
        |p: f64| -> f64 { lat[((lat.len() as f64 * p) as usize).min(lat.len() - 1)] as f64 / 1000.0 };
    let rps = TOTAL as f64 / elapsed.as_secs_f64();

    println!("\n=== rpc_concurrent_load [{label}] ===");
    println!("requests   : {TOTAL} ({WORKERS} workers x {REQS_PER_WORKER})");
    println!("methods    : get_vitals / get_info / get_difficulty_health (round-robin)");
    println!("wall time  : {:.2}s", elapsed.as_secs_f64());
    println!("throughput : {rps:.0} req/s");
    println!(
        "latency ms : p50={:.2} p90={:.2} p99={:.2} max={:.2}",
        pct(0.50),
        pct(0.90),
        pct(0.99),
        pct(1.0)
    );
    println!("errors     : {errs}");

    assert_eq!(errs, 0, "all requests should succeed under load [{label}]");
    assert!(rps > 200.0, "throughput {rps:.0} req/s unexpectedly low [{label}]");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
#[ignore = "load test; run with --ignored"]
async fn rpc_concurrent_load_genesis() {
    let port = 19860u16;
    let _server = start_server(port, 0).await;
    hammer_rpc(port, "genesis height 0").await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
#[ignore = "load test; run with --ignored"]
async fn rpc_concurrent_load_mature_chain() {
    // Seed a mature chain so get_difficulty_health scans a full 144-block window
    // on every call — the heaviest new endpoint under load.
    let port = 19862u16;
    let _server = start_server(port, 200).await;
    hammer_rpc(port, "mature height 200 (full 144-block difficulty scan)").await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "load test; run with --ignored"]
async fn empirical_decoy_sampler_throughput() {
    use coincync::decoy::{DecoyDistributionSnapshot, HeightOutputCount, DECOY_LOCATOR_POLICY_VERSION};
    use coincync::primitives::Hash;
    use coincync::wallet::decoy_selection::{
        sample_candidate_locators_empirical, ValidatedDecoySnapshot,
    };
    use rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;
    use std::collections::HashSet;

    // Large, skewed histogram: 20k heights, output counts varying by height so
    // the empirical weighting has real work to do.
    let n_heights = 20_000u64;
    let heights: Vec<HeightOutputCount> = (0..=n_heights)
        .map(|h| HeightOutputCount {
            height: h,
            // skew: some heights hold many more outputs than others
            count: 1 + ((h * 2654435761) % 37) as u32,
        })
        .collect();
    let raw = DecoyDistributionSnapshot {
        snapshot_height: n_heights,
        snapshot_hash: Hash::from_bytes([7; 32]),
        policy_version: DECOY_LOCATOR_POLICY_VERSION,
        heights,
    };
    let snap = ValidatedDecoySnapshot::try_from(raw).expect("valid snapshot");

    const RINGS: usize = 20_000;
    const RING_DECOYS: usize = 15; // ring size 16 minus the real
    let mut rng = ChaCha20Rng::seed_from_u64(0xC0FFEE);
    let excluded: HashSet<coincync::decoy::OutputLocator> = HashSet::new();

    let start = Instant::now();
    let mut total_decoys = 0usize;
    let mut non_unique_rings = 0usize;
    for _ in 0..RINGS {
        let picked = sample_candidate_locators_empirical(&snap, 10, RING_DECOYS, &excluded, &mut rng)
            .expect("sufficient decoys");
        assert_eq!(picked.len(), RING_DECOYS);
        let uniq: HashSet<_> = picked.iter().collect();
        if uniq.len() != RING_DECOYS {
            non_unique_rings += 1;
        }
        total_decoys += picked.len();
    }
    let elapsed = start.elapsed();
    let rings_per_sec = RINGS as f64 / elapsed.as_secs_f64();

    println!("\n=== empirical_decoy_sampler_throughput ===");
    println!("histogram  : {} heights", n_heights + 1);
    println!("rings       : {RINGS} x {RING_DECOYS} decoys = {total_decoys} draws");
    println!("wall time  : {:.2}s", elapsed.as_secs_f64());
    println!("throughput : {rings_per_sec:.0} rings/s ({:.0} decoys/s)", total_decoys as f64 / elapsed.as_secs_f64());
    println!("non-unique rings: {non_unique_rings}");

    assert_eq!(non_unique_rings, 0, "every ring must have unique decoys");
    assert!(rings_per_sec > 100.0, "sampler throughput {rings_per_sec:.0} rings/s unexpectedly low");
}
