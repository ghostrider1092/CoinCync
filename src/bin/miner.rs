//! CoinCync Standalone Miner
//!
//! Connects to a running cyncd node via RPC, fetches block templates,
//! performs Proof-of-Work, and submits found blocks.
//!
//! Usage: cync-miner [OPTIONS]
//!
//! Options:
//!   --address <ADDR>    Mining reward address (full tCYNC.../CYNC... wallet address)
//!   --threads <N>       Number of mining threads (default: CPU cores)
//!   --node <HOST:PORT>  Node RPC endpoint (default: 127.0.0.1:28081)
//!   --testnet           Use testnet
//!   --demo              Run UI demo mode (no actual mining)

use std::io::{Read, Write};
use std::net::TcpStream;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use std::thread;

use coincync::mining::{
    MinerDisplay, MinerDisplayConfig, MiningMode,
    NetworkState, LiveMetrics, MinerWarning,
};
use coincync::consensus::{BlockHeader, Block, PowAlgorithm, compute_pow_hash, compute_full_anchor};
use coincync::crypto::{PedersenCommitment, BlindingFactor};
use coincync::primitives::{Hash, PublicKey, Amount};
use coincync::transaction::{Transaction, TxType, TxOutput};

use clap::Parser;
use colored::Colorize;
use coincync::cli::{
    print_colored_banner, print_success, print_error, print_warning, print_info,
    print_labeled,
};

#[derive(Parser)]
#[command(name = "cync-miner")]
#[command(about = "CoinCync 2.0 Standalone Miner")]
#[command(version = coincync::VERSION)]
struct Args {
    /// Mining reward address (full tCYNC.../CYNC... wallet address)
    #[arg(long)]
    address: Option<String>,

    /// Number of mining threads (0 = auto-detect)
    #[arg(long, default_value = "0")]
    threads: usize,

    /// Node RPC endpoint (host:port)
    #[arg(long, default_value = "127.0.0.1:28081")]
    node: String,

    /// RPC bearer API key (overrides COINCYNC_RPC_API_KEY env if set)
    #[arg(long)]
    rpc_api_key: Option<String>,

    /// Use testnet
    #[arg(long)]
    testnet: bool,

    /// Run UI demo mode (no actual mining)
    #[arg(long)]
    demo: bool,

}

fn resolve_rpc_api_key(cli_value: Option<&str>) -> Option<String> {
    if let Some(v) = cli_value {
        let t = v.trim();
        if !t.is_empty() {
            return Some(t.to_string());
        }
    }
    std::env::var("COINCYNC_RPC_API_KEY")
        .ok()
        .and_then(|v| {
            let t = v.trim();
            if t.is_empty() {
                None
            } else {
                Some(t.to_string())
            }
        })
}

/// Minimal JSON-RPC client over raw TCP
fn rpc_call(
    endpoint: &str,
    method: &str,
    params: &str,
    rpc_api_key: Option<&str>,
) -> Result<serde_json::Value, String> {
    let body = format!(
        r#"{{"jsonrpc":"2.0","method":"{}","params":{},"id":1}}"#,
        method, params
    );

    // Strip http:// or https:// prefix — TcpStream needs host:port only
    let host_port = endpoint
        .trim_start_matches("http://")
        .trim_start_matches("https://");

    let mut stream = TcpStream::connect(host_port)
        .map_err(|e| format!("Connection failed: {}", e))?;
    stream.set_read_timeout(Some(Duration::from_secs(5)))
        .map_err(|e| format!("Set timeout failed: {}", e))?;

    let auth_line = rpc_api_key
        .map(|k| format!("Authorization: Bearer {}\r\n", k))
        .unwrap_or_default();

    let request = format!(
        "POST / HTTP/1.1\r\nHost: {}\r\nContent-Type: application/json\r\n{}Content-Length: {}\r\nConnection: close\r\n\r\n{}",
        endpoint, auth_line, body.len(), body
    );

    stream.write_all(request.as_bytes())
        .map_err(|e| format!("Write failed: {}", e))?;

    let mut response = String::new();
    stream.read_to_string(&mut response)
        .map_err(|e| format!("Read failed: {}", e))?;

    // Extract JSON body from HTTP response
    let body_start = response.find("\r\n\r\n")
        .or_else(|| response.find("\n\n"))
        .map(|i| if response[i..].starts_with("\r\n\r\n") { i + 4 } else { i + 2 })
        .ok_or("Invalid HTTP response")?;

    let json_body = &response[body_start..];

    // Handle chunked transfer encoding
    let json_str = if response.contains("Transfer-Encoding: chunked") {
        // Parse chunked encoding: skip chunk size lines
        let mut decoded = String::new();
        let mut remaining = json_body;
        loop {
            let line_end = remaining.find("\r\n").unwrap_or(remaining.len());
            let chunk_size_str = remaining[..line_end].trim();
            if chunk_size_str.is_empty() {
                break;
            }
            let chunk_size = usize::from_str_radix(chunk_size_str, 16).unwrap_or(0);
            if chunk_size == 0 {
                break;
            }
            let chunk_start = line_end + 2;
            let chunk_end = (chunk_start + chunk_size).min(remaining.len());
            decoded.push_str(&remaining[chunk_start..chunk_end]);
            remaining = if chunk_end + 2 <= remaining.len() {
                &remaining[chunk_end + 2..]
            } else {
                break;
            };
        }
        decoded
    } else {
        json_body.to_string()
    };

    let parsed: serde_json::Value = serde_json::from_str(json_str.trim())
        .map_err(|e| format!("JSON parse failed: {} (body: {})", e, &json_str[..json_str.len().min(200)]))?;

    if let Some(error) = parsed.get("error") {
        return Err(format!("RPC error: {}", error));
    }

    parsed.get("result").cloned()
        .ok_or_else(|| "No result in RPC response".to_string())
}

/// Build a block header from template data
/// Parse mempool transactions from the block template
fn parse_template_transactions(template: &serde_json::Value) -> Vec<Transaction> {
    let mut txs = Vec::new();
    if let Some(tx_array) = template["transactions"].as_array() {
        for tx_hex_val in tx_array {
            if let Some(tx_hex) = tx_hex_val.as_str() {
                if let Ok(tx_bytes) = hex::decode(tx_hex) {
                    if let Ok(tx) = borsh::from_slice::<Transaction>(&tx_bytes) {
                        txs.push(tx);
                    }
                }
            }
        }
    }
    txs
}

fn build_header_from_template(
    template: &serde_json::Value,
    miner_spend_pub: &PublicKey,
    miner_view_pub: &PublicKey,
    fallback_network: coincync::config::NetworkType,
) -> Result<(BlockHeader, Vec<Transaction>), String> {
    let height = template["height"].as_u64()
        .ok_or("Missing height")?;
    let prev_hash_hex = template["prev_hash"].as_str()
        .ok_or("Missing prev_hash")?;
    let timestamp = template["timestamp"].as_i64()
        .ok_or("Missing timestamp")? as u64;

    let prev_hash = Hash::from_hex(prev_hash_hex)
        .ok_or_else(|| format!("Invalid prev_hash: {}", prev_hash_hex))?;

    // Use the exact target from the node (ASERT-computed) instead of deriving from difficulty
    let target = if let Some(target_hex) = template["target"].as_str() {
        Hash::from_hex(target_hex)
            .ok_or_else(|| format!("Invalid target hex: {}", target_hex))?
    } else {
        // Fallback for older nodes that don't send target
        let difficulty_str = template["difficulty"].as_str()
            .ok_or("Missing both target and difficulty")?;
        let difficulty: u64 = difficulty_str.parse()
            .map_err(|e| format!("Invalid difficulty: {}", e))?;
        Hash::from_difficulty(difficulty)
    };

    // Compute full anchor (VDF + Yescrypt) — must match verifier exactly
    let anchor_result = compute_full_anchor(&prev_hash, height, timestamp)
        .map_err(|e| format!("Anchor computation failed: {}", e))?;

    // Parse mempool transactions from template
    let mempool_txs = parse_template_transactions(template);

    // Calculate fees: miner share after burn (Constitution Article II)
    // Must match the node's congestion check exactly (validation.rs line 280)
    let total_fees: u64 = mempool_txs.iter().map(|tx| tx.fee.as_atomic()).sum();
    let claimable_fees = if total_fees > 0 {
        let block_size: usize = mempool_txs.iter().map(|tx| borsh::to_vec(tx).map(|v| v.len()).unwrap_or(0)).sum();
        let congestion_pct = (block_size as u128 * 100) / coincync::constants::MAX_BLOCK_SIZE as u128;
        let congested = congestion_pct >= coincync::constants::CONGESTION_THRESHOLD as u128;
        let dist = coincync::consensus::fee_market::distribute_fee(
            coincync::primitives::Amount::from_atomic(total_fees), congested,
        );
        dist.to_miner.as_atomic()
    } else {
        0
    };
    let coinbase = create_mining_coinbase_with_fees(height, miner_spend_pub, miner_view_pub, claimable_fees)?;

    // Build full transaction list: coinbase + mempool txs
    let mut all_txs = vec![coinbase];
    all_txs.extend(mempool_txs);

    // Compute merkle root from all transactions
    let tx_hashes: Vec<Hash> = all_txs.iter().map(|tx| tx.hash()).collect();
    let tx_root = coincync::primitives::merkle_root(&tx_hashes);

    let network_magic = resolve_network_magic(template, fallback_network)?;

    Ok((BlockHeader {
        network_magic,
        version: 1,
        height,
        timestamp,
        prev_hash,
        tx_root,
        anchor: anchor_result.mixed_hash,
        algorithm: anchor_result.algorithm as u8,
        nonce: 0,
        target,
        miner_pubkey: *miner_spend_pub,
        supply_commitment: [0u8; 32],
        checkpoint_vote: None,
        spark_set_root: [0u8; 32],
        mw_kernel_root: [0u8; 32],
    }, all_txs))
}

fn resolve_network_magic(
    template: &serde_json::Value,
    fallback_network: coincync::config::NetworkType,
) -> Result<[u8; 4], String> {
    if let Some(magic_hex) = template["network_magic"].as_str() {
        let bytes = hex::decode(magic_hex)
            .map_err(|e| format!("Invalid network_magic hex: {}", e))?;
        if bytes.len() != 4 {
            return Err(format!("Invalid network_magic length: expected 4, got {}", bytes.len()));
        }
        let magic = [bytes[0], bytes[1], bytes[2], bytes[3]];
        if coincync::config::NetworkType::from_magic_bytes(magic).is_none() {
            return Err(format!(
                "Unknown network_magic: {}",
                hex::encode(magic)
            ));
        }
        Ok(magic)
    } else {
        // Backward-compat fallback for older nodes/templates.
        Ok(fallback_network.magic_bytes())
    }
}

/// Create coinbase transaction for mining (reward + fees) with proper ECDH stealth addresses
fn create_mining_coinbase_with_fees(
    height: u64,
    miner_spend_pub: &PublicKey,
    miner_view_pub: &PublicKey,
    total_fees: u64,
) -> Result<Transaction, String> {
    let reward = coincync::emission::calculate_block_reward(height);
    let total_amount = reward.as_atomic().saturating_add(total_fees);

    // Coinbase uses zero blinding factor since the reward is publicly known.
    let commitment = PedersenCommitment::commit(total_amount, &BlindingFactor::zero());

    // Generate proper ECDH stealth address so the recipient wallet can detect this output
    let miner_secret: [u8; 32] = *blake3::hash(miner_view_pub.as_bytes()).as_bytes();
    let (stealth_addr, _tx_secret) = coincync::crypto::coinbase_stealth_address(
        miner_spend_pub, miner_view_pub, height, 0, &miner_secret,
    ).map_err(|e| format!("Failed to generate coinbase stealth address: {}", e))?;

    // View tag from the stealth address tx_public_key (matches scanner expectation)
    let view_tag = {
        let shared = coincync::primitives::hash_domain(
            b"COINCYNC_VIEW_TAG",
            &[stealth_addr.tx_public_key.as_bytes().as_slice(), &[0u8]].concat(),
        );
        shared.as_bytes()[0]
    };

    let output = TxOutput {
        stealth_address: stealth_addr.public_key,
        tx_public_key: stealth_addr.tx_public_key,
        encrypted_amount: total_amount.to_le_bytes().to_vec(),
        commitment: commitment.to_bytes(),
        view_tag,
        lock_height: None,
        encrypted_memo: vec![],
    };

    Ok(Transaction {
        version: 1,
        tx_type: TxType::Coinbase,
        inputs: vec![],
        outputs: vec![output],
        fee: Amount::ZERO,
        range_proof: vec![],
        extra: height.to_le_bytes().to_vec(),
    })
}

fn main() {
    // Initialize tracing so RandomX VM creation / FULL_MEM fallback
    // warnings are visible. Default log level is INFO, overridable via
    // RUST_LOG. Emitted to stderr so systemd captures them in the unit
    // journal alongside the animated progress display on stdout.
    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info".into()),
        )
        .with_target(false)
        .init();

    let args = Args::parse();
    let rpc_api_key = resolve_rpc_api_key(args.rpc_api_key.as_deref());

    let threads = if args.threads == 0 { num_cpus::get() } else { args.threads };
    let address_str = args.address.clone().unwrap_or_default();
    let network = if args.testnet { "testnet" } else { "mainnet" };

    // Create display config
    let config = MinerDisplayConfig {
        mining_address: if address_str.is_empty() { "(not set)".to_string() } else { address_str.clone() },
        network: network.to_string(),
        node_endpoint: args.node.clone(),
        mode: MiningMode::Solo,
        threads,
        algorithm: "SHA3-512 (CPU)".to_string(),
        pool_url: None,
        use_colors: true,
    };

    let mut display = MinerDisplay::new(config);

    if args.demo {
        display.update_network(NetworkState {
            block_height: 847_523,
            difficulty: 2_500_000_000,
            network_hashrate: 1_250_000.0,
            block_time: 30,
            peer_count: 8,
            is_synced: true,
        });
        display.set_connected(true);
        display.print_startup_banner();
        run_demo(&mut display);
        return;
    }

    // Parse mining address — requires full wallet address for stealth address generation
    let (miner_spend_pub, miner_view_pub) = if address_str.is_empty() {
        print_error("--address is required for mining");
        print_info("Get your mining address with: cync-wallet mining-address");
        print_info("Usage: cync-miner --address <tCYNC.../CYNC... wallet address>");
        std::process::exit(1);
    } else if address_str.starts_with("tCYNC") || address_str.starts_with("CYNC") {
        match coincync::primitives::Address::from_string(&address_str) {
            Ok(addr) => (addr.spend_public_key, addr.view_public_key),
            Err(e) => {
                print_error(&format!("Invalid wallet address: {}", e));
                std::process::exit(1);
            }
        }
    } else {
        // Reject raw hex — it lacks the view key needed for stealth addresses
        print_error("Raw hex mining addresses are no longer supported.");
        print_warning("Hex-only addresses lack the view key, making mining rewards invisible to your wallet.");
        print_info("Get your full mining address with: cync-wallet mining-address");
        std::process::exit(1);
    };

    // Try initial connection
    print_colored_banner();
    print_info(&format!("Connecting to node at {}...", args.node.bright_cyan()));

    let template = match rpc_call(
        &args.node,
        "get_block_template",
        &format!("[\"{}\"]", address_str),
        rpc_api_key.as_deref(),
    ) {
        Ok(t) => t,
        Err(e) => {
            print_error(&format!("Failed to connect to node: {}", e));
            print_info("Make sure cyncd is running with RPC enabled.");
            std::process::exit(1);
        }
    };

    let initial_height = template["height"].as_u64().unwrap_or(0);
    let initial_difficulty = template["difficulty"].as_str()
        .and_then(|s| s.parse::<u64>().ok())
        .unwrap_or(1);

    display.update_network(NetworkState {
        block_height: initial_height,
        difficulty: initial_difficulty as u128,
        network_hashrate: 0.0,
        block_time: 120,
        peer_count: 0,
        is_synced: true,
    });
    display.set_connected(true);
    display.print_startup_banner();

    print_labeled("Mining to height", &initial_height.to_string());
    println!();

    // Shared state
    let running = Arc::new(AtomicBool::new(true));
    let total_hashes = Arc::new(AtomicU64::new(0));
    let blocks_found = Arc::new(AtomicU64::new(0));
    let hashrate = Arc::new(AtomicU64::new(0));

    // Note: Ctrl+C will terminate the process directly.
    // For graceful shutdown, run cyncd with integrated mining (--mine flag).

    // Spawn mining threads
    let mut handles = Vec::new();

    for thread_id in 0..threads {
        let running = running.clone();
        let total_hashes = total_hashes.clone();
        let blocks_found = blocks_found.clone();
        let hashrate = hashrate.clone();
        let node = args.node.clone();
        let address_str = address_str.clone();
        let rpc_api_key = rpc_api_key.clone();

        let handle = thread::spawn(move || {
            let mut nonce = thread_id as u64 * (u64::MAX / threads as u64);
            let mut template_refresh = Instant::now();
            let mut current_header: Option<BlockHeader> = None;
            let mut current_txs: Vec<Transaction> = Vec::new();

            while running.load(Ordering::Relaxed) {
                // Refresh template every 5 seconds
                if current_header.is_none() || template_refresh.elapsed() > Duration::from_secs(5) {
                    match rpc_call(
                        &node,
                        "get_block_template",
                        &format!("[\"{}\"]", address_str),
                        rpc_api_key.as_deref(),
                    ) {
                        Ok(template) => {
                            let fallback_network = if args.testnet {
                                coincync::config::NetworkType::Testnet
                            } else {
                                coincync::config::NetworkType::Mainnet
                            };
                            match build_header_from_template(
                                &template,
                                &miner_spend_pub,
                                &miner_view_pub,
                                fallback_network,
                            ) {
                                Ok((header, txs)) => {
                                    current_header = Some(header);
                                    current_txs = txs;
                                    template_refresh = Instant::now();
                                }
                                Err(e) => {
                                    if thread_id == 0 {
                                        print_error(&format!("Template build error: {}", e));
                                    }
                                    thread::sleep(Duration::from_secs(2));
                                    continue;
                                }
                            }
                        }
                        Err(e) => {
                            if thread_id == 0 {
                                print_warning(&format!("RPC error: {} (retrying...)", e));
                            }
                            thread::sleep(Duration::from_secs(2));
                            continue;
                        }
                    }
                }

                let Some(header) = current_header.as_mut() else { continue };

                // Mine a batch
                let batch_start = Instant::now();
                let batch_size = 500u64;

                for _ in 0..batch_size {
                    if !running.load(Ordering::Relaxed) {
                        break;
                    }

                    header.nonce = nonce;
                    nonce = nonce.wrapping_add(1);

                    let algo = PowAlgorithm::from_index(header.algorithm);
                    let pow_hash = match compute_pow_hash(algo, &header.anchor, header.nonce, &header.tx_root, header.height) {
                        Ok(h) => h,
                        Err(_) => continue,
                    };

                    if pow_hash.meets_difficulty(&header.target) {
                        // Guardrail: run the same verifier used by the node before submit.
                        // If this fails locally, we have a miner-side precheck mismatch.
                        if let Err(e) = coincync::consensus::verify_pow(
                            &header.prev_hash,
                            header.height,
                            header.timestamp,
                            header.nonce,
                            &header.tx_root,
                            &header.target,
                            &header.anchor,
                            header.algorithm,
                        ) {
                            print_error(&format!(
                                "Local verify_pow failed before submit: {} (h={}, nonce={}, target={}, pow={})",
                                e,
                                header.height,
                                header.nonce,
                                hex::encode(&header.target.as_bytes()[..8]),
                                hex::encode(&pow_hash.as_bytes()[..8]),
                            ));
                            current_header = None;
                            current_txs.clear();
                            break;
                        }

                        // Found a block! Build with all transactions (coinbase + mempool)
                        blocks_found.fetch_add(1, Ordering::Relaxed);

                        let block = Block::new(header.clone(), current_txs.clone());

                        // Submit via RPC
                        let block_hex = hex::encode(borsh::to_vec(&block).expect("Block serialization must not fail"));
                        match rpc_call(
                            &node,
                            "submit_block",
                            &format!("[\"{}\"]", block_hex),
                            rpc_api_key.as_deref(),
                        ) {
                            Ok(_) => {
                                let tx_count = current_txs.len() - 1; // Subtract coinbase
                                if tx_count > 0 {
                                    print_success(&format!("BLOCK FOUND at height {} ({} txs)!", header.height, tx_count));
                                } else {
                                    print_success(&format!("BLOCK FOUND at height {}!", header.height));
                                }
                            }
                            Err(e) => {
                                print_error(&format!(
                                    "Block submission failed: {} (h={}, nonce={}, target={}, pow={}, prev={})",
                                    e,
                                    header.height,
                                    header.nonce,
                                    hex::encode(&header.target.as_bytes()[..8]),
                                    hex::encode(&pow_hash.as_bytes()[..8]),
                                    hex::encode(&header.prev_hash.as_bytes()[..8]),
                                ));
                                // Force immediate template refresh after a rejected submit.
                                // Prevents repeatedly resubmitting a stale header (e.g. timestamp race).
                                current_header = None;
                                current_txs.clear();
                            }
                        }

                        // Force template refresh
                        current_header = None;
                        current_txs.clear();
                        break;
                    }
                }

                total_hashes.fetch_add(batch_size, Ordering::Relaxed);

                // Update hashrate (only from thread 0 to avoid contention)
                if thread_id == 0 {
                    let elapsed = batch_start.elapsed().as_secs_f64();
                    if elapsed > 0.0 {
                        let hr = (batch_size as f64 / elapsed) * threads as f64;
                        hashrate.store(hr.to_bits(), Ordering::Relaxed);
                    }
                }
            }
        });

        handles.push(handle);
    }

    // Display loop on main thread
    let start = Instant::now();
    while running.load(Ordering::Relaxed) {
        thread::sleep(Duration::from_millis(500));

        let hr = f64::from_bits(hashrate.load(Ordering::Relaxed));
        let total = total_hashes.load(Ordering::Relaxed);
        let blocks = blocks_found.load(Ordering::Relaxed);

        display.record_hashrate(hr);

        let metrics = LiveMetrics {
            hashrate: hr,
            shares: 0,
            blocks_found: blocks,
            uptime: start.elapsed(),
            total_hashes: total,
            rejected_shares: 0,
            last_block_time: None,
            hashrate_history: vec![],
        };
        display.update_metrics(metrics);
        display.tick_animation();
        display.print_live_update();

        // Periodically refresh network state
        if start.elapsed().as_secs() % 30 == 0 {
            if let Ok(info) = rpc_call(&args.node, "get_info", "[]", rpc_api_key.as_deref()) {
                let height = info["height"].as_u64().unwrap_or(0);
                let synced = info["synced"].as_bool().unwrap_or(true);

                display.update_network(NetworkState {
                    block_height: height,
                    difficulty: 1,
                    network_hashrate: hr,
                    block_time: 120,
                    peer_count: 0,
                    is_synced: synced,
                });
            }
        }
    }

    println!();
    print_warning("Shutting down mining threads...");

    for handle in handles {
        let _ = handle.join();
    }

    print_labeled("Total hashes", &coincync::mining::format_large_number(total_hashes.load(Ordering::Relaxed)));
    display.print_detailed_stats();
    print_success("Mining stopped.");
}

/// Run demo mode to showcase UI
fn run_demo(display: &mut MinerDisplay) {
    println!("\n  Running UI demo... Press Ctrl+C to stop.\n");

    let start = Instant::now();
    let mut hashrate = 15000.0;
    let mut shares = 0u64;
    let mut blocks = 0u64;
    let mut total_hashes = 0u64;

    loop {
        // Simulate hashrate fluctuation
        hashrate += (rand_simple() - 0.5) * 1000.0;
        hashrate = hashrate.max(10000.0).min(25000.0);

        display.record_hashrate(hashrate);

        total_hashes += (hashrate * 0.5) as u64;

        let metrics = LiveMetrics {
            hashrate,
            shares,
            blocks_found: blocks,
            uptime: start.elapsed(),
            total_hashes,
            rejected_shares: 0,
            last_block_time: None,
            hashrate_history: vec![],
        };
        display.update_metrics(metrics);
        display.tick_animation();
        display.print_live_update();

        if rand_simple() < 0.02 {
            shares += 1;
        }

        if start.elapsed() > Duration::from_secs(15) && blocks == 0 && rand_simple() < 0.01 {
            blocks += 1;
            println!();
            display.print_block_found(
                847_524,
                "0000000000000a1b2c3d4e5f6789abcdef0123456789abcdef0123456789abcd",
                Amount::from_atomic(1_000_000_000_000),
            );
            display.print_detailed_stats();
        }

        if start.elapsed() > Duration::from_secs(30) && start.elapsed() < Duration::from_secs(31) {
            display.add_warning(MinerWarning::LowHashrate {
                current: hashrate,
                expected: 50000.0,
            });
            display.print_warning(&MinerWarning::LowHashrate {
                current: hashrate,
                expected: 50000.0,
            });
        }

        thread::sleep(Duration::from_millis(500));

        if start.elapsed() > Duration::from_secs(60) {
            println!();
            println!();
            print_success(&format!("Demo complete! Total runtime: {}",
                coincync::mining::format_duration(start.elapsed())));
            display.print_detailed_stats();
            break;
        }
    }
}

/// Simple pseudo-random number (0.0 to 1.0) for demo mode
fn rand_simple() -> f64 {
    use std::time::SystemTime;
    let nanos = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap()
        .subsec_nanos();
    (nanos as f64 % 1000.0) / 1000.0
}

#[cfg(test)]
mod tests {
    use super::{resolve_network_magic, resolve_rpc_api_key};
    use coincync::config::NetworkType;
    use serde_json::json;

    #[test]
    fn cli_key_takes_precedence_and_trims() {
        let got = resolve_rpc_api_key(Some("  abc123  "));
        assert_eq!(got.as_deref(), Some("abc123"));
    }

    #[test]
    fn empty_cli_value_uses_env_when_present() {
        unsafe { std::env::set_var("COINCYNC_RPC_API_KEY", " envkey "); }
        let got = resolve_rpc_api_key(Some("   "));
        assert_eq!(got.as_deref(), Some("envkey"));
        unsafe { std::env::remove_var("COINCYNC_RPC_API_KEY"); }
    }

    #[test]
    fn template_network_magic_overrides_fallback() {
        let tpl = json!({
            "network_magic": hex::encode(NetworkType::Mainnet.magic_bytes())
        });
        let magic = resolve_network_magic(&tpl, NetworkType::Testnet).expect("parse magic");
        assert_eq!(magic, NetworkType::Mainnet.magic_bytes());
    }

    #[test]
    fn template_network_magic_falls_back_when_missing() {
        let tpl = json!({});
        let magic = resolve_network_magic(&tpl, NetworkType::Regtest).expect("fallback magic");
        assert_eq!(magic, NetworkType::Regtest.magic_bytes());
    }

    #[test]
    fn template_network_magic_rejects_wrong_length() {
        let tpl = json!({ "network_magic": "abcd" });
        let err = resolve_network_magic(&tpl, NetworkType::Testnet).unwrap_err();
        assert!(err.contains("Invalid network_magic length"));
    }

    #[test]
    fn template_network_magic_rejects_unknown_magic() {
        let tpl = json!({ "network_magic": "01020304" });
        let err = resolve_network_magic(&tpl, NetworkType::Testnet).unwrap_err();
        assert!(err.contains("Unknown network_magic"));
    }
}
