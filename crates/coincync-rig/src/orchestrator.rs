// Phase 4b — solo mining orchestrator.
#![allow(dead_code)]

//! # Solo mining orchestrator.
//!
//! Loop:
//!   1. Pull `get_block_template` from the daemon.
//!   2. Construct the coinbase tx that pays `--address`.
//!   3. Build the full block header (anchor, target, tx_root over
//!      `[coinbase] ++ mempool_txs`) with nonce = 0.
//!   4. Search for a nonce where `compute_pow_hash(...)` meets target.
//!   5. On found: serialize block (Borsh) → hex → `submit_block`.
//!   6. On timeout (no nonce found in `--poll-interval-secs`):
//!      go to step 1 (fresh template, prev_hash may have advanced).
//!
//! ## Why every consensus-critical primitive comes from the parent crate
//!
//! Everything in this file that affects what makes a valid block — the
//! anchor function, the coinbase shape, the stealth address derivation,
//! the fee-burn split, the merkle root function, the network magic
//! lookup, the PoW hash — comes through `coincync::*` re-exports. If
//! the parent crate ever changes any of these (e.g. a hard-fork
//! adjusts the reward curve or coinbase format), this file inherits
//! the change automatically. **The only consensus invariant defined in
//! this file is "we rebuild after each daemon poll"** — everything
//! else is delegation to the validator-side code.
//!
//! ## What this loop is NOT
//!
//! - Multi-threaded. The hash search is single-threaded today.
//!   Multi-thread requires nonce-range splitting + atomic stop signal,
//!   which is Phase 5 worker-pool work. At testnet difficulty (~5K)
//!   one thread finds blocks in seconds, so single-thread is fine to
//!   ship.
//! - Stale-template-aware. We poll on a timer; if the chain advances
//!   mid-search, our submission gets rejected and we restart. That's
//!   the same posture the existing `coincync-miner` ships with.

use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{anyhow, Context, Result};
use serde_json::Value;
use tracing::{info, warn};

use coincync::config::NetworkType;
use coincync::consensus::{
    bind_randomx_genesis_for_network, compute_full_anchor, BlockHeader, PowAlgorithm,
    Block,
};
use coincync::crypto::{coinbase_stealth_address, BlindingFactor, PedersenCommitment};
use coincync::primitives::{merkle_root, hash_domain, Address, Amount, Hash, PublicKey};
use coincync::transaction::{Transaction, TxOutput, TxType};

use crate::daemon::DaemonClient;
use crate::hasher::{HashInput, Hasher};

/// One run of the solo mining loop. Returns when the daemon connection
/// permanently fails or the operator sends ctrl-c (via tokio signal —
/// tracked outside this function).
///
/// `threads` controls how many parallel nonce-search threads run on
/// each template. 1 = single thread (good for 1-vCPU boxes); 0 was
/// resolved to a real count by the caller.
///
/// Auto-reconnect: on `get_block_template` or `submit_block` errors we
/// log and retry with exponential backoff (1s, 2s, 4s, ..., capped at
/// 60s). The loop never bails — the operator decides when to stop.
pub async fn run_solo(
    daemon: &DaemonClient,
    address_str: &str,
    network: NetworkType,
    poll_interval_secs: u64,
    threads: usize,
) -> Result<()> {
    bind_randomx_genesis_for_network(network);

    let addr = Address::from_string(address_str)
        .map_err(|e| anyhow!("invalid mining address {address_str:?}: {e}"))?;
    let miner_spend_pub = addr.spend_public_key;
    let miner_view_pub = addr.view_public_key;

    let hasher = Hasher::new();
    let mut blocks_found: u64 = 0;
    let mut backoff = BackoffState::new();

    info!(
        address = %short_hex(addr.spend_public_key.as_bytes()),
        threads,
        "orchestrator: solo mining loop starting"
    );

    loop {
        // 1. Get current template (with backoff on failure)
        let template = match daemon.get_block_template().await {
            Ok(t) => {
                backoff.reset();
                t
            }
            Err(e) => {
                let wait = backoff.next();
                warn!(
                    error = %e,
                    retry_in_secs = wait.as_secs(),
                    "orchestrator: get_block_template failed, backing off"
                );
                tokio::time::sleep(wait).await;
                continue;
            }
        };

        // 2-3. Build the candidate block from template + coinbase
        let (mut header, txs) = match build_header_from_template(
            &template,
            &miner_spend_pub,
            &miner_view_pub,
            network,
        ) {
            Ok(p) => p,
            Err(e) => {
                let wait = backoff.next();
                warn!(error = %e, retry_in_secs = wait.as_secs(), "orchestrator: header build failed, backing off");
                tokio::time::sleep(wait).await;
                continue;
            }
        };

        let height = header.height;
        let target = header.target.clone();
        let input = HashInput {
            anchor: header.anchor,
            tx_root: header.tx_root,
            height,
        };

        // 4. Multi-thread nonce search until found OR poll interval elapsed
        let started = Instant::now();
        let deadline = started + Duration::from_secs(poll_interval_secs);
        let result = mine_parallel(hasher, input, target, threads, deadline).await;

        // 5. Submit if found
        match result {
            MineResult::Found { nonce: n, total_attempts } => {
                header.nonce = n;
                let block = Block { header, transactions: txs };
                let block_bytes = borsh::to_vec(&block).context("serializing found block")?;
                let block_hex = hex::encode(&block_bytes);
                let elapsed = started.elapsed();
                let hps = total_attempts as f64 / elapsed.as_secs_f64().max(0.001);
                info!(
                    height,
                    nonce = format!("{:#018x}", n),
                    attempts = total_attempts,
                    hashrate_hps = format!("{:.0}", hps),
                    "orchestrator: BLOCK FOUND, submitting"
                );

                match daemon.submit_block(&block_hex).await {
                    Ok(_) => {
                        blocks_found = blocks_found.saturating_add(1);
                        info!(blocks_found, "orchestrator: block accepted");
                    }
                    Err(e) => {
                        warn!(error = %e, "orchestrator: block submit rejected (likely lost race)");
                    }
                }
            }
            MineResult::Timeout { total_attempts } => {
                let elapsed = started.elapsed().as_secs_f64();
                let hps = if elapsed > 0.0 { total_attempts as f64 / elapsed } else { 0.0 };
                info!(
                    height,
                    attempts = total_attempts,
                    hashrate_hps = format!("{:.0}", hps),
                    "orchestrator: poll interval elapsed without finding a nonce, refreshing template"
                );
            }
        }
    }
}

/// Result of one nonce-search round.
enum MineResult {
    Found { nonce: u64, total_attempts: u64 },
    Timeout { total_attempts: u64 },
}

/// Multi-threaded nonce search. Each thread owns a slice of the u64
/// nonce space and hashes (input, nonce) until either:
///  - it finds a nonce that meets target (signals via channel), or
///  - the shared `stop` flag goes true (some other thread won, or
///    the poll deadline elapsed), or
///  - it exhausts its slice (shouldn't happen at testnet difficulty
///    inside one poll interval — slice is u64::MAX/threads).
///
/// CPU-bound RandomX work runs on dedicated OS threads, NOT tokio
/// tasks — running RandomX in `tokio::spawn` would block the runtime
/// for milliseconds per hash, which is exactly what async runtimes
/// hate. Keeping them as `std::thread::spawn` lets the tokio runtime
/// stay responsive (the timeout race below depends on it).
async fn mine_parallel(
    hasher: Hasher,
    input: HashInput,
    target: Hash,
    threads: usize,
    deadline: Instant,
) -> MineResult {
    use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

    let stop = Arc::new(AtomicBool::new(false));
    let attempts = Arc::new(AtomicU64::new(0));
    let (found_tx, mut found_rx) = tokio::sync::mpsc::unbounded_channel::<u64>();

    let n_threads = threads.max(1);
    let slice = u64::MAX / n_threads as u64;

    let mut handles = Vec::with_capacity(n_threads);
    for tid in 0..n_threads {
        let stop = stop.clone();
        let attempts = attempts.clone();
        let found_tx = found_tx.clone();
        let target = target.clone();
        let input = input.clone();
        let start_nonce = (tid as u64).saturating_mul(slice);
        let end_nonce = if tid + 1 == n_threads {
            u64::MAX
        } else {
            start_nonce.saturating_add(slice)
        };
        handles.push(std::thread::spawn(move || {
            let mut nonce = start_nonce;
            let mut local: u64 = 0;
            while !stop.load(Ordering::Relaxed) && nonce < end_nonce {
                if let Ok(h) = hasher.hash(&input, nonce) {
                    if hasher.meets_target(&h, &target) {
                        let _ = found_tx.send(nonce);
                        break;
                    }
                }
                nonce = nonce.saturating_add(1);
                local = local.saturating_add(1);
                // Flush our local counter to the shared counter every
                // 1024 hashes — too often = atomic contention; never =
                // stats lag behind reality on cancel.
                if local.is_multiple_of(1024) {
                    attempts.fetch_add(1024, Ordering::Relaxed);
                    local = 0;
                }
            }
            attempts.fetch_add(local, Ordering::Relaxed);
        }));
    }
    // Drop our extra sender so the channel closes when all workers stop.
    drop(found_tx);

    // Race: a worker finds a nonce, or the deadline fires.
    let timeout = deadline.saturating_duration_since(Instant::now());
    let outcome = tokio::time::timeout(timeout, found_rx.recv()).await;

    // Always tell workers to stop, then join. Joining is fast since
    // the loop checks `stop` every iteration.
    stop.store(true, Ordering::Relaxed);
    for h in handles {
        let _ = h.join();
    }

    let total = attempts.load(Ordering::Relaxed);
    match outcome {
        Ok(Some(n)) => MineResult::Found { nonce: n, total_attempts: total },
        _ => MineResult::Timeout { total_attempts: total },
    }
}

/// Exponential backoff: 1, 2, 4, 8, 16, 32, 60 (capped). Resets to 1
/// on the first successful op after a streak of failures.
struct BackoffState {
    next_secs: u64,
}
impl BackoffState {
    fn new() -> Self {
        Self { next_secs: 1 }
    }
    fn next(&mut self) -> Duration {
        let d = Duration::from_secs(self.next_secs);
        self.next_secs = (self.next_secs.saturating_mul(2)).min(60);
        d
    }
    fn reset(&mut self) {
        self.next_secs = 1;
    }
}

/// Build the full BlockHeader + transaction list from a daemon template.
///
/// Every field in the returned header must match what the validator
/// expects byte-for-byte; see `src/consensus/header.rs`.
fn build_header_from_template(
    template: &Value,
    miner_spend_pub: &PublicKey,
    miner_view_pub: &PublicKey,
    fallback_network: NetworkType,
) -> Result<(BlockHeader, Vec<Transaction>)> {
    let height = template["height"]
        .as_u64()
        .ok_or_else(|| anyhow!("template missing 'height'"))?;
    let prev_hash_hex = template["prev_hash"]
        .as_str()
        .ok_or_else(|| anyhow!("template missing 'prev_hash'"))?;
    let timestamp = template["timestamp"]
        .as_i64()
        .ok_or_else(|| anyhow!("template missing 'timestamp'"))?
        as u64;

    let prev_hash = Hash::from_hex(prev_hash_hex)
        .ok_or_else(|| anyhow!("template prev_hash {prev_hash_hex} is not valid hex"))?;

    // Use the exact target the daemon computed (ASERT difficulty
    // adjustment) instead of re-deriving from a difficulty number.
    let target = if let Some(target_hex) = template["target"].as_str() {
        Hash::from_hex(target_hex)
            .ok_or_else(|| anyhow!("template target {target_hex} is not valid hex"))?
    } else {
        let difficulty_str = template["difficulty"]
            .as_str()
            .ok_or_else(|| anyhow!("template missing both 'target' and 'difficulty'"))?;
        let difficulty: u64 = difficulty_str
            .parse()
            .with_context(|| format!("difficulty {difficulty_str:?} is not a u64"))?;
        Hash::from_difficulty(difficulty)
    };

    // VDF + Yescrypt anchor — must match validator exactly.
    let anchor_result = compute_full_anchor(&prev_hash, height, timestamp)
        .map_err(|e| anyhow!("compute_full_anchor failed: {e}"))?;

    let mempool_txs = parse_template_transactions(template);

    // Fee-burn split per Constitution Article II — congestion-aware.
    let claimable_fees = calculate_claimable_fees(&mempool_txs);
    let coinbase = create_mining_coinbase_with_fees(
        height,
        miner_spend_pub,
        miner_view_pub,
        claimable_fees,
    )?;

    // tx_root = merkle root over [coinbase, ...mempool_txs]
    let mut all_txs = Vec::with_capacity(mempool_txs.len() + 1);
    all_txs.push(coinbase);
    all_txs.extend(mempool_txs);
    let tx_hashes: Vec<Hash> = all_txs.iter().map(|tx| tx.hash()).collect();
    let tx_root = merkle_root(&tx_hashes);

    let network_magic = resolve_network_magic(template, fallback_network)?;

    Ok((
        BlockHeader {
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
        },
        all_txs,
    ))
}

fn parse_template_transactions(template: &Value) -> Vec<Transaction> {
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

/// Per Constitution Article II: when the block is congested, a portion
/// of the fee is burned; the miner only collects the un-burned share.
/// Must match validator-side `validation.rs` exactly or the daemon
/// rejects our coinbase.
fn calculate_claimable_fees(mempool_txs: &[Transaction]) -> u64 {
    let total_fees: u64 = mempool_txs.iter().map(|tx| tx.fee.as_atomic()).sum();
    if total_fees == 0 {
        return 0;
    }
    let block_size: usize = mempool_txs
        .iter()
        .map(|tx| borsh::to_vec(tx).map(|v| v.len()).unwrap_or(0))
        .sum();
    let congestion_pct = (block_size as u128 * 100) / coincync::constants::MAX_BLOCK_SIZE as u128;
    let congested = congestion_pct >= coincync::constants::CONGESTION_THRESHOLD as u128;
    let dist = coincync::consensus::fee_market::distribute_fee(
        Amount::from_atomic(total_fees),
        congested,
    );
    dist.to_miner.as_atomic()
}

/// Build the coinbase tx — emission reward + fees, paid to a fresh
/// stealth address derived from (miner_spend_pub, miner_view_pub,
/// height, output_index=0).
fn create_mining_coinbase_with_fees(
    height: u64,
    miner_spend_pub: &PublicKey,
    miner_view_pub: &PublicKey,
    total_fees: u64,
) -> Result<Transaction> {
    let reward = coincync::emission::calculate_block_reward(height);
    let total_amount = reward.as_atomic().saturating_add(total_fees);

    // Coinbase commitment uses zero blinding factor: the reward is
    // publicly verifiable, so nothing to hide.
    let commitment = PedersenCommitment::commit(total_amount, &BlindingFactor::zero());

    // Same per-output secret derivation the existing miner uses — the
    // wallet recognises a coinbase output by view-tag matching against
    // its view key, so this derivation must be deterministic in
    // (view_pub, height, output_index).
    let miner_secret: [u8; 32] = *blake3::hash(miner_view_pub.as_bytes()).as_bytes();
    let (stealth_addr, _tx_secret) =
        coinbase_stealth_address(miner_spend_pub, miner_view_pub, height, 0, &miner_secret)
            .map_err(|e| anyhow!("coinbase_stealth_address failed: {e}"))?;

    let view_tag = {
        let shared = hash_domain(
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

fn resolve_network_magic(template: &Value, fallback_network: NetworkType) -> Result<[u8; 4]> {
    if let Some(magic_hex) = template["network_magic"].as_str() {
        let bytes = hex::decode(magic_hex)
            .with_context(|| format!("network_magic {magic_hex:?} is not valid hex"))?;
        if bytes.len() != 4 {
            return Err(anyhow!(
                "network_magic length: expected 4 bytes, got {}",
                bytes.len()
            ));
        }
        let magic = [bytes[0], bytes[1], bytes[2], bytes[3]];
        if NetworkType::from_magic_bytes(magic).is_none() {
            return Err(anyhow!(
                "unknown network_magic {} — daemon and miner are on different networks",
                hex::encode(magic)
            ));
        }
        Ok(magic)
    } else {
        Ok(fallback_network.magic_bytes())
    }
}

fn short_hex(bytes: &[u8]) -> String {
    hex::encode(&bytes[..bytes.len().min(8)])
}

// PowAlgorithm import is needed by Block construction in compute_full_anchor's
// path, but we only reference it implicitly through `header.algorithm = anchor_result.algorithm as u8`.
// Keep the import alive so future refactors don't have to chase it down.
#[allow(unused_imports)]
use PowAlgorithm as _PowAlgorithmStillUsedTransitively;
