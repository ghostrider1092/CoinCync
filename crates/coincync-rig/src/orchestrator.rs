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

/// How many blocks the local tip may lead the best peer's advertised
/// height before we treat it as a private fork and refuse to mine.
/// A healthy solo miner leads by 0–2 blocks (peers adopt each block
/// within a beat); a sustained lead this large means peers are NOT
/// adopting our blocks — the 2026-07-08 runaway-fork signature.
const FORK_DIVERGENCE_MARGIN: u64 = 25;

/// Pure predicate for the miner's fork-divergence gate.
///
/// Returns `true` when the local tip has run so far ahead of every peer
/// that our blocks are provably not being adopted — i.e. we are mining a
/// private fork and must stop. `peer_target == 0` means "no peer height
/// reported yet", which is NOT divergence (the separate peer-count gate
/// covers the empty-mesh case); we return `false` so we don't wedge a
/// genuinely-fresh node that simply hasn't heard a peer height.
fn fork_diverged(local_height: u64, peer_target: u64, margin: u64) -> bool {
    peer_target > 0 && local_height > peer_target.saturating_add(margin)
}

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
    metrics: Option<std::sync::Arc<crate::metrics::MetricsState>>,
    signal_bits: coincync::consensus::fork_signal::SignalBits,
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

    let mut last_get_info: Option<Instant> = None;

    // Sync gate state (added 2026-06-03 in response to barns1253 report).
    // Mining against an out-of-sync local node produces blocks on a
    // private fork — the rest of the network rejects them, the operator
    // sees coinbase rewards in their local wallet, but the coins are
    // worthless to anyone else. The fix is simply to refuse mining when
    // the local node reports !synced. Cached for SYNC_CACHE_SECS so a
    // long unsynced period doesn't hammer the daemon on every iteration.
    let mut last_sync_check: Option<Instant> = None;
    let mut cached_synced: bool = false;
    const SYNC_CACHE_SECS: u64 = 30;
    const SYNC_WAIT_SECS: u64 = 30; // sleep this long when unsynced before re-checking

    loop {
        // 0. Honor TUI-driven pause flag — don't poll the daemon, don't
        // mine. Wake every 250 ms to re-check (cheap, never hits the
        // hot path).
        if let Some(m) = metrics.as_ref() {
            if m.paused.load(std::sync::atomic::Ordering::Relaxed) {
                tokio::time::sleep(Duration::from_millis(250)).await;
                continue;
            }
        }

        // 0.5. Periodic get_info to populate the TUI's tip-age + network
        // hashrate stats. Runs every ~10s, asynchronously to the mining
        // loop (we don't gate on its result). Latency of this call also
        // doubles as our RPC-quality reading.
        if let Some(m) = metrics.as_ref() {
            let due = match last_get_info {
                None => true,
                Some(t) => t.elapsed() >= Duration::from_secs(10),
            };
            if due {
                let started = Instant::now();
                if let Ok(info) = daemon.get_info().await {
                    let latency_ms = started.elapsed().as_millis() as u64;
                    m.rpc_latency_ms
                        .store(latency_ms, std::sync::atomic::Ordering::Relaxed);
                    if let Some(age) = info.get("tip_age_secs").and_then(|v| v.as_u64()) {
                        m.tip_age_secs.store(age, std::sync::atomic::Ordering::Relaxed);
                    }
                    // Network hashrate may show up under different keys
                    // depending on daemon version — try both.
                    let net = info
                        .get("network_hashrate")
                        .and_then(|v| v.as_u64())
                        .or_else(|| info.get("hashrate_hps").and_then(|v| v.as_u64()))
                        .unwrap_or(0);
                    if net > 0 {
                        m.network_hashrate_hps
                            .store(net, std::sync::atomic::Ordering::Relaxed);
                    }
                }
                last_get_info = Some(Instant::now());
            }
        }

        // 0.7. Sync gate — refuse to mine when the local node is not
        // synced to the network. Without this guard, the rig will
        // happily build templates against the local node's stale tip
        // and submit valid-but-orphan blocks that fork off the
        // canonical chain. Operator sees coinbase rewards in their
        // local wallet (because their local node accepts the blocks
        // it served the template for), but the network rejects every
        // one. Caught in production by barns1253 on 2026-06-02 —
        // confused-looking situation where his node was unsynced,
        // his wallet showed rewards from mined blocks, but those
        // blocks never propagated to peers.
        //
        // 2026-06-28 strengthening (Bug B fix): is_synced alone is
        // insufficient when the daemon is recovering from a fresh
        // restart. During UTXO rebuild + IBD catch-up, the daemon
        // may briefly report is_synced=true based on a transient
        // empty peer_heights map (best_known == local because no
        // peer has reported a height yet). Rig then starts mining,
        // finds a block, submits to daemon → daemon RPC is flaky
        // mid-recovery → rig sees HTTP error and mislabels as
        // "block rejected." Observed 2026-06-28 01:27 UTC after a
        // watchdog-driven node restart.
        //
        // Three-part gate now:
        //   - is_synced == true               (legacy check)
        //   - tip_age_secs < 300              (chain producing recently,
        //                                      not a stale single peer)
        //   - peer_count >= 3                 (real mesh established,
        //                                      not an empty-peers
        //                                      false is_synced=true)
        //
        // Cached for SYNC_CACHE_SECS to avoid hammering get_info when
        // unsynced state is persistent. Recheck rate of every 30s
        // means up to 30s of mining wasted after sync is achieved
        // (we'll re-check then proceed), which is negligible cost.
        let (synced_now, gate_reason) = {
            let stale = match last_sync_check {
                None => true,
                Some(t) => t.elapsed() >= Duration::from_secs(SYNC_CACHE_SECS),
            };
            if stale {
                match daemon.get_info().await {
                    Ok(info) => {
                        let is_synced = info
                            .get("synced")
                            .and_then(|v| v.as_bool())
                            .or_else(|| info.get("is_synced").and_then(|v| v.as_bool()))
                            .unwrap_or(false);
                        let tip_age = info
                            .get("tip_age_secs")
                            .and_then(|v| v.as_u64())
                            .unwrap_or(u64::MAX);
                        let peers = info
                            .get("peer_count")
                            .and_then(|v| v.as_u64())
                            .unwrap_or(0);
                        // BOTH conditions must hold. Empty mesh with
                        // synced=true is the false-positive case from
                        // 2026-06-28 — don't trust it. peer_count >= 3
                        // is the actual signal that catches the
                        // fresh-restart-mid-IBD scenario (peers haven't
                        // reconnected yet → peer_heights is empty →
                        // best_known=local → is_synced=true even
                        // though daemon is still catching up).
                        //
                        // We deliberately do NOT check tip_age here.
                        // A high tip_age during normal operation just
                        // means we're in a slow-block stretch (PoW
                        // variance). Refusing to mine in that case
                        // causes a deadlock: rigs won't mine because
                        // chain is slow, chain stays slow because
                        // rigs aren't mining. tip_age tracks SYMPTOM,
                        // peer_count tracks CAUSE (mesh established
                        // vs not). Use the cause.
                        let _ = tip_age; // intentionally unused; see above

                        // Fork-divergence gate (2026-07-08 runaway-fork
                        // incident). `is_synced` is HEIGHT-based: the daemon
                        // reports synced whenever local_height >=
                        // peer_target_height. A node briefly isolated at
                        // restart mines alone, its difficulty collapses, and
                        // it races hundreds of blocks ahead of the real
                        // network — yet still reports synced (its tip is
                        // "ahead" of every peer) with a full peer_count. Both
                        // legacy conditions passed while randomx2 produced a
                        // worthless low-work private fork. The tell: NO peer
                        // adopts the blocks, so our height runs far ahead of
                        // every peer's advertised height and stays there. If
                        // our blocks were valid, peers would follow within a
                        // block or two. peer_target==0 means "no peer height
                        // reported yet" → don't evaluate divergence (the
                        // peers>=3 gate covers the empty-mesh case).
                        let local_height = info
                            .get("height")
                            .and_then(|v| v.as_u64())
                            .unwrap_or(0);
                        let peer_target = info
                            .get("peer_target_height")
                            .and_then(|v| v.as_u64())
                            .unwrap_or(0);
                        let diverged =
                            fork_diverged(local_height, peer_target, FORK_DIVERGENCE_MARGIN);

                        // Regtest is an isolated, single-operator rehearsal
                        // network (see main.rs: "local end-to-end mine + send
                        // rehearsals against an isolated coincync-node --network
                        // regtest instance"). The >=3-peer mesh gate and the
                        // fork-divergence gate exist to prevent private-fork
                        // mining on the SHARED testnet/mainnet — a failure mode
                        // that cannot occur on an isolated regtest chain. Exempt
                        // regtest so a local rig can mine with <3 peers. This
                        // NEVER relaxes testnet or mainnet: `is_regtest` is false
                        // for every non-regtest network, so their gate is byte-
                        // for-byte unchanged.
                        let is_regtest = matches!(network, NetworkType::Regtest);
                        let ok = is_synced && (is_regtest || (peers >= 3 && !diverged));
                        let reason = if !is_synced {
                            "is_synced=false".to_string()
                        } else if is_regtest {
                            "OK (regtest: mesh/fork gates exempt for isolated rehearsal)".to_string()
                        } else if peers < 3 {
                            format!("peer_count={} (<3; mesh not established, possibly mid-restart)", peers)
                        } else if diverged {
                            format!(
                                "fork-divergence: local height {} runs >{} blocks ahead of best peer height {} — blocks not being adopted, likely a private fork",
                                local_height, FORK_DIVERGENCE_MARGIN, peer_target
                            )
                        } else {
                            "OK".to_string()
                        };
                        cached_synced = ok;
                        last_sync_check = Some(Instant::now());
                        (ok, reason)
                    }
                    Err(e) => {
                        // Daemon unreachable for get_info — assume unsynced
                        // (same backoff treatment as get_block_template
                        // failure below). Conservative: don't mine into
                        // a daemon we can't talk to.
                        warn!(
                            error = %e,
                            "orchestrator: sync-gate get_info failed, treating as unsynced \
                             (daemon may be restarting or unreachable)"
                        );
                        cached_synced = false;
                        last_sync_check = Some(Instant::now());
                        (false, format!("get_info HTTP error: {}", e))
                    }
                }
            } else {
                (cached_synced, "(cached)".to_string())
            }
        };
        if !synced_now {
            warn!(
                sleep_secs = SYNC_WAIT_SECS,
                reason = %gate_reason,
                "orchestrator: local node not ready to mine — refusing to mine to avoid \
                 producing blocks on a private fork. Will recheck after sleep."
            );
            tokio::time::sleep(Duration::from_secs(SYNC_WAIT_SECS)).await;
            continue;
        }

        // 1. Get current template (with backoff on failure)
        let rpc_started = Instant::now();
        let template = match daemon.get_block_template().await {
            Ok(t) => {
                backoff.reset();
                if let Some(m) = metrics.as_ref() {
                    m.rpc_latency_ms.store(
                        rpc_started.elapsed().as_millis() as u64,
                        std::sync::atomic::Ordering::Relaxed,
                    );
                }
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

        // 2-3. Build the candidate block from template + coinbase.
        // signal_bits is passed through to the coinbase builder so the
        // operator's --signal-v1012 opt-in lands as the trailing 4 bytes
        // of coinbase.extra (see fork_signal::encode_coinbase_extra).
        let (mut header, txs) = match build_header_from_template(
            &template,
            &miner_spend_pub,
            &miner_view_pub,
            network,
            signal_bits,
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
        if let Some(m) = metrics.as_ref() {
            m.current_template_height
                .store(height, std::sync::atomic::Ordering::Relaxed);
        }
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
            MineResult::Found { nonce: n, total_attempts, per_thread_hps } => {
                header.nonce = n;
                let block = Block { header, transactions: txs };
                let block_bytes = borsh::to_vec(&block).context("serializing found block")?;
                let block_hex = hex::encode(&block_bytes);
                let elapsed = started.elapsed();
                let hps = total_attempts as f64 / elapsed.as_secs_f64().max(0.001);
                if let Some(m) = metrics.as_ref() {
                    m.hashes_total.fetch_add(total_attempts, std::sync::atomic::Ordering::Relaxed);
                    m.current_hashrate_hps.store(hps as u64, std::sync::atomic::Ordering::Relaxed);
                    m.record_hashrate_sample(hps as u64);
                    m.record_per_thread_hashrate(per_thread_hps);
                    m.blocks_found_total.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                }
                let (hr_digits, hr_unit) = crate::tui_blockfont::format_hashrate(hps.round() as u64);
                info!(
                    height,
                    nonce = format!("{:#018x}", n),
                    attempts = total_attempts,
                    hashrate_hps = format!("{:.0}", hps),
                    hashrate = format!("{} {}", hr_digits, hr_unit),
                    "orchestrator: BLOCK FOUND, submitting"
                );

                match daemon.submit_block(&block_hex).await {
                    Ok(_) => {
                        blocks_found = blocks_found.saturating_add(1);
                        if let Some(m) = metrics.as_ref() {
                            m.blocks_accepted_total.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                            // Record the find timestamp for the TUI's
                            // 24h timeline strip + ETA-since-last anchor.
                            let now = std::time::SystemTime::now()
                                .duration_since(std::time::SystemTime::UNIX_EPOCH)
                                .map(|d| d.as_secs())
                                .unwrap_or(0);
                            m.record_block_find(now);
                        }
                        info!(blocks_found, "orchestrator: block accepted");
                    }
                    Err(e) => {
                        if let Some(m) = metrics.as_ref() {
                            m.blocks_rejected_total.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                        }
                        warn!(error = %e, "orchestrator: block submit rejected (likely lost race)");
                    }
                }
            }
            MineResult::Timeout { total_attempts, per_thread_hps } => {
                let elapsed = started.elapsed().as_secs_f64();
                let hps = if elapsed > 0.0 { total_attempts as f64 / elapsed } else { 0.0 };
                if let Some(m) = metrics.as_ref() {
                    m.hashes_total.fetch_add(total_attempts, std::sync::atomic::Ordering::Relaxed);
                    m.current_hashrate_hps.store(hps as u64, std::sync::atomic::Ordering::Relaxed);
                    m.record_hashrate_sample(hps as u64);
                    m.record_per_thread_hashrate(per_thread_hps);
                }
                let (hr_digits, hr_unit) = crate::tui_blockfont::format_hashrate(hps.round() as u64);
                info!(
                    height,
                    attempts = total_attempts,
                    hashrate_hps = format!("{:.0}", hps),
                    hashrate = format!("{} {}", hr_digits, hr_unit),
                    "orchestrator: poll interval elapsed without finding a nonce, refreshing template"
                );
            }
        }
    }
}

/// Result of one nonce-search round.
enum MineResult {
    Found {
        nonce: u64,
        total_attempts: u64,
        /// Per-thread hashrate (H/s) for the iteration, indexed by
        /// thread id. Length equals the active thread count.
        per_thread_hps: Vec<u64>,
    },
    Timeout {
        total_attempts: u64,
        per_thread_hps: Vec<u64>,
    },
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
    // Per-thread attempt counters. Each thread owns one Arc<AtomicU64>
    // and updates only its own — no contention. The aggregate is
    // computed at the end. The TUI's worker heatmap reads from these
    // (via metrics) to surface thermal throttling on individual cores.
    let n_threads = threads.max(1);
    let per_thread_attempts: Vec<Arc<AtomicU64>> =
        (0..n_threads).map(|_| Arc::new(AtomicU64::new(0))).collect();
    let (found_tx, mut found_rx) = tokio::sync::mpsc::unbounded_channel::<u64>();

    let slice = u64::MAX / n_threads as u64;

    let mut handles = Vec::with_capacity(n_threads);
    for tid in 0..n_threads {
        let stop = stop.clone();
        let my_attempts = per_thread_attempts[tid].clone();
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
                // Flush our local counter to our per-thread atomic
                // every 1024 hashes — same trade-off as before, but
                // now there's no contention because each thread owns
                // a separate atomic.
                if local % 1024 == 0 {
                    my_attempts.fetch_add(1024, Ordering::Relaxed);
                    local = 0;
                }
            }
            my_attempts.fetch_add(local, Ordering::Relaxed);
        }));
    }
    // Drop our extra sender so the channel closes when all workers stop.
    drop(found_tx);

    // Race: a worker finds a nonce, or the deadline fires.
    //
    // Defensive: if the deadline is already in the past (worker setup +
    // template build burned more than poll_interval_secs, OR caller
    // handed us a stale deadline), `saturating_duration_since` would
    // return Duration::ZERO, which `tokio::time::timeout(0, recv)`
    // returns from immediately with Elapsed — the rig would loop
    // straight back to template fetch without giving threads a chance
    // to find a nonce. Detect this and yield a real minimum window
    // (50 ms) so the worker threads at least submit one nonce attempt
    // before the timeout, which preserves the operator-visible signal
    // of "rig is making progress" vs the indistinguishable hang state.
    //
    // Reference: Bitcoin Core's `getblocktemplate` retry loop computes
    // the wait window AT THE MOMENT of waiting, never from a pre-
    // stored deadline (see `node/miner.cpp`).
    let started = Instant::now();
    let now = Instant::now();
    let timeout = if deadline <= now {
        tracing::warn!(
            target: "rig::orchestrator",
            "mine_parallel called with deadline already in the past \
             (overran setup window) — granting minimum 50 ms mining \
             slice instead of returning Timeout immediately"
        );
        Duration::from_millis(50)
    } else {
        deadline.saturating_duration_since(now)
    };
    let outcome = tokio::time::timeout(timeout, found_rx.recv()).await;

    // Always tell workers to stop, then join. Joining is fast since
    // the loop checks `stop` every iteration.
    stop.store(true, Ordering::Relaxed);
    for h in handles {
        let _ = h.join();
    }

    let elapsed_secs = started.elapsed().as_secs_f64().max(0.001);
    let per_thread: Vec<u64> = per_thread_attempts
        .iter()
        .map(|a| a.load(Ordering::Relaxed))
        .collect();
    let total: u64 = per_thread.iter().sum();
    // Per-thread hashrate (H/s) = thread_attempts / wall_elapsed.
    let per_thread_hps: Vec<u64> = per_thread
        .iter()
        .map(|&a| (a as f64 / elapsed_secs) as u64)
        .collect();

    match outcome {
        Ok(Some(n)) => MineResult::Found { nonce: n, total_attempts: total, per_thread_hps },
        _ => MineResult::Timeout { total_attempts: total, per_thread_hps },
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
    signal_bits: coincync::consensus::fork_signal::SignalBits,
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
        signal_bits,
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
    signal_bits: coincync::consensus::fork_signal::SignalBits,
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
        // Coinbase extra carries the height (8 bytes) plus optional
        // BIP-9 signal bits (4 bytes) when the operator opts in via
        // --signal-v1012. encode_coinbase_extra preserves byte-for-byte
        // compatibility with the pre-CIP-012 format when signal_bits == 0.
        extra: coincync::consensus::fork_signal::encode_coinbase_extra(height, signal_bits),
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

#[cfg(test)]
mod tests {
    use super::{fork_diverged, FORK_DIVERGENCE_MARGIN};

    #[test]
    fn no_peer_height_is_not_divergence() {
        // peer_target == 0 means "no peer height reported yet" — a fresh
        // node, not a fork. Must NOT trip, or we'd wedge honest startup.
        assert!(!fork_diverged(10_544, 0, FORK_DIVERGENCE_MARGIN));
        assert!(!fork_diverged(0, 0, FORK_DIVERGENCE_MARGIN));
    }

    #[test]
    fn healthy_solo_miner_leading_by_a_few_blocks_is_ok() {
        // A solo miner is transiently a block or two ahead of peers while
        // they ingest its latest block. That is normal, not a fork.
        assert!(!fork_diverged(10_043, 10_042, FORK_DIVERGENCE_MARGIN));
        assert!(!fork_diverged(10_044, 10_042, FORK_DIVERGENCE_MARGIN));
        // Exactly at the margin boundary is still allowed (strictly-greater).
        assert!(!fork_diverged(10_042 + FORK_DIVERGENCE_MARGIN, 10_042, FORK_DIVERGENCE_MARGIN));
    }

    #[test]
    fn runaway_private_fork_trips_the_gate() {
        // The 2026-07-08 signature: local tip hundreds of blocks past every
        // peer, which stays put because it rejects our low-work blocks.
        assert!(fork_diverged(10_544, 10_042, FORK_DIVERGENCE_MARGIN));
        // One block past the margin is enough to trip.
        assert!(fork_diverged(10_042 + FORK_DIVERGENCE_MARGIN + 1, 10_042, FORK_DIVERGENCE_MARGIN));
    }

    #[test]
    fn behind_or_level_with_peers_never_diverges() {
        // Being behind the network is handled by is_synced, not this gate.
        assert!(!fork_diverged(10_000, 10_042, FORK_DIVERGENCE_MARGIN));
        assert!(!fork_diverged(10_042, 10_042, FORK_DIVERGENCE_MARGIN));
    }
}
