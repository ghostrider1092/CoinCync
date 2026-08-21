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
use coincync::consensus::{bind_randomx_genesis_for_network, Block, BlockHeader, PowAlgorithm};
use coincync::primitives::{Address, Hash, PublicKey};
use coincync::transaction::Transaction;

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
                        m.tip_age_secs
                            .store(age, std::sync::atomic::Ordering::Relaxed);
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
                        let peers = info.get("peer_count").and_then(|v| v.as_u64()).unwrap_or(0);
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
                        let local_height = info.get("height").and_then(|v| v.as_u64()).unwrap_or(0);
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
                            "OK (regtest: mesh/fork gates exempt for isolated rehearsal)"
                                .to_string()
                        } else if peers < 3 {
                            format!(
                                "peer_count={peers} (<3; mesh not established, possibly mid-restart)"
                            )
                        } else if diverged {
                            format!(
                                "fork-divergence: local height {local_height} runs >{FORK_DIVERGENCE_MARGIN} blocks ahead of best peer height {peer_target} — blocks not being adopted, likely a private fork"
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
                        (false, format!("get_info HTTP error: {e}"))
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
        // Approaching a RandomX key-epoch boundary? Build the next epoch's
        // dataset in the background now, so the flip promotes it instantly
        // instead of stalling this miner for the 30-60s (full-mem) build.
        coincync::consensus::prewarm_next_epoch_if_near(height);
        let target = header.target;
        let input = HashInput {
            anchor: header.anchor,
            tx_root: header.tx_root,
            height,
        };

        // 4. Multi-thread nonce search until found OR poll interval elapsed
        let started = Instant::now();
        let deadline = started + Duration::from_secs(poll_interval_secs);
        let result = mine_parallel(hasher, input, target, threads, deadline, 0).await;

        // 5. Submit if found
        match result {
            MineResult::Found {
                nonce: n,
                total_attempts,
                per_thread_hps,
            } => {
                header.nonce = n;
                let block = Block {
                    header,
                    transactions: txs,
                };
                let block_bytes = borsh::to_vec(&block).context("serializing found block")?;
                let block_hex = hex::encode(&block_bytes);
                let elapsed = started.elapsed();
                let hps = total_attempts as f64 / elapsed.as_secs_f64().max(0.001);
                if let Some(m) = metrics.as_ref() {
                    m.hashes_total
                        .fetch_add(total_attempts, std::sync::atomic::Ordering::Relaxed);
                    m.current_hashrate_hps
                        .store(hps as u64, std::sync::atomic::Ordering::Relaxed);
                    m.record_hashrate_sample(hps as u64);
                    m.record_per_thread_hashrate(per_thread_hps);
                    m.blocks_found_total
                        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                }
                let (hr_digits, hr_unit) =
                    crate::tui_blockfont::format_hashrate(hps.round() as u64);
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
                            m.blocks_accepted_total
                                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
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
                            m.blocks_rejected_total
                                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                        }
                        warn!(error = %e, "orchestrator: block submit rejected (likely lost race)");
                    }
                }
            }
            MineResult::Timeout {
                total_attempts,
                per_thread_hps,
            } => {
                let elapsed = started.elapsed().as_secs_f64();
                let hps = if elapsed > 0.0 {
                    total_attempts as f64 / elapsed
                } else {
                    0.0
                };
                if let Some(m) = metrics.as_ref() {
                    m.hashes_total
                        .fetch_add(total_attempts, std::sync::atomic::Ordering::Relaxed);
                    m.current_hashrate_hps
                        .store(hps as u64, std::sync::atomic::Ordering::Relaxed);
                    m.record_hashrate_sample(hps as u64);
                    m.record_per_thread_hashrate(per_thread_hps);
                }
                let (hr_digits, hr_unit) =
                    crate::tui_blockfont::format_hashrate(hps.round() as u64);
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
    // Offset added to each thread's slice start. 0 for solo (every template is
    // a fresh input, so restarting from the slice start is fine). The stratum
    // pool client advances this each call so repeated searches of the SAME job
    // don't re-test identical nonces. It grows far slower than the slice size
    // (u64::MAX / threads), so threads never cross into each other's slices.
    nonce_base: u64,
) -> MineResult {
    use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

    let stop = Arc::new(AtomicBool::new(false));
    // Per-thread attempt counters. Each thread owns one Arc<AtomicU64>
    // and updates only its own — no contention. The aggregate is
    // computed at the end. The TUI's worker heatmap reads from these
    // (via metrics) to surface thermal throttling on individual cores.
    let n_threads = threads.max(1);
    let per_thread_attempts: Vec<Arc<AtomicU64>> = (0..n_threads)
        .map(|_| Arc::new(AtomicU64::new(0)))
        .collect();
    let (found_tx, mut found_rx) = tokio::sync::mpsc::unbounded_channel::<u64>();

    let slice = u64::MAX / n_threads as u64;

    let mut handles = Vec::with_capacity(n_threads);
    for (tid, thread_attempts) in per_thread_attempts.iter().enumerate() {
        let stop = stop.clone();
        let my_attempts = thread_attempts.clone();
        let found_tx = found_tx.clone();
        let input = input.clone();
        let slice_start = (tid as u64).saturating_mul(slice);
        let start_nonce = slice_start.wrapping_add(nonce_base);
        // End at the NEXT slice boundary (independent of nonce_base), so the
        // base only shifts where within the slice we search, never the slice's
        // extent.
        let end_nonce = if tid + 1 == n_threads {
            u64::MAX
        } else {
            ((tid + 1) as u64).saturating_mul(slice)
        };
        handles.push(std::thread::spawn(move || {
            // Hash nonces in small batches through the pipelined RandomX
            // path (`hash_batch`), which overlaps VM execution of one input
            // with the next input's setup. BATCH is kept small so the
            // `stop` flag is still checked frequently (8 hashes is a few ms
            // in full-mem mode, ~50 ms in light mode — well inside the poll
            // interval) and so a winning nonce is reported promptly.
            const BATCH: u64 = 8;
            let mut nonce = start_nonce;
            let mut local: u64 = 0;
            while !stop.load(Ordering::Relaxed) && nonce < end_nonce {
                let batch_end = nonce.saturating_add(BATCH).min(end_nonce);
                let batch: Vec<u64> = (nonce..batch_end).collect();
                if batch.is_empty() {
                    break;
                }
                let mut found = false;
                // A batch hash error (e.g. VM reinit backoff) is tolerated
                // exactly like the single-shot path's `if let Ok` — skip and
                // keep searching.
                if let Ok(hashes) = hasher.hash_batch(&input, &batch) {
                    for (k, h) in hashes.iter().enumerate() {
                        if hasher.meets_target(h, &target) {
                            let _ = found_tx.send(batch[k]);
                            stop.store(true, Ordering::Relaxed);
                            found = true;
                            break;
                        }
                    }
                }
                let n = batch.len() as u64;
                local = local.saturating_add(n);
                // Flush our local counter to our per-thread atomic roughly
                // every 1024 hashes — same trade-off as before, but now
                // there's no contention because each thread owns a separate
                // atomic.
                if local >= 1024 {
                    my_attempts.fetch_add(local, Ordering::Relaxed);
                    local = 0;
                }
                if found {
                    break;
                }
                nonce = nonce.saturating_add(n);
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
        Ok(Some(n)) => MineResult::Found {
            nonce: n,
            total_attempts: total,
            per_thread_hps,
        },
        _ => MineResult::Timeout {
            total_attempts: total,
            per_thread_hps,
        },
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

/// A job as pushed by a CoinCync stratum pool (`login` result / `job` message).
#[derive(Clone)]
struct PoolJob {
    job_id: String,
    anchor: Hash,
    tx_root: Hash,
    target: Hash,
    height: u64,
}

/// Parse the CoinCync `job` object: `{job_id, anchor, tx_root, seed_hash,
/// target, height}` (all hashes hex). `seed_hash` is ignored — `compute_pow_hash`
/// re-derives the RandomX key from `height`.
fn parse_pool_job(v: &Value) -> Option<PoolJob> {
    Some(PoolJob {
        job_id: v.get("job_id")?.as_str()?.to_string(),
        anchor: Hash::from_hex(v.get("anchor")?.as_str()?)?,
        tx_root: Hash::from_hex(v.get("tx_root")?.as_str()?)?,
        target: Hash::from_hex(v.get("target")?.as_str()?)?,
        height: v.get("height")?.as_u64()?,
    })
}

/// Connect to a CoinCync stratum pool, log in, and mine the jobs it pushes,
/// submitting winning nonces. Reuses the SAME `mine_parallel` engine as solo
/// mining — only the job source differs (the pool's `job` messages instead of
/// the daemon's `get_block_template`). The pool builds the coinbase (to its own
/// payout address) and does block assembly/submission server-side, so this
/// client only searches nonces and submits.
pub async fn run_pool(
    pool_addr: &str,
    login: &str,
    password: &str,
    network: NetworkType,
    threads: usize,
) -> Result<()> {
    use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
    use tokio::net::TcpStream;

    bind_randomx_genesis_for_network(network);
    let n_threads = if threads == 0 {
        std::thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(1)
    } else {
        threads
    };

    let stream = TcpStream::connect(pool_addr)
        .await
        .with_context(|| format!("connecting to pool {pool_addr}"))?;
    let (read_half, mut write_half) = stream.into_split();
    let mut reader = BufReader::new(read_half);

    // Log in (also delivers the first job in the response).
    let login_msg = serde_json::json!({
        "id": 1, "method": "login",
        "params": {"login": login, "pass": password, "agent": "coincync-rig", "algo": ["cync/rx"]}
    })
    .to_string();
    write_half.write_all(login_msg.as_bytes()).await?;
    write_half.write_all(b"\n").await?;
    write_half.flush().await?;
    info!("pool: logged in to {} as {}", pool_addr, login);

    // Latest job, updated by the reader task; the mining loop reads it.
    let job_slot: Arc<tokio::sync::Mutex<Option<PoolJob>>> = Arc::new(tokio::sync::Mutex::new(None));
    let job_slot_r = job_slot.clone();
    tokio::spawn(async move {
        // Cap each line like the server does. A malicious or compromised pool
        // could otherwise stream unbounded bytes with no newline; read_line
        // grows the String until \n or EOF and would OOM the miner.
        const MAX_LINE_LENGTH: u64 = 16 * 1024;
        let mut line = String::new();
        loop {
            line.clear();
            let mut limited = (&mut reader).take(MAX_LINE_LENGTH);
            match limited.read_line(&mut line).await {
                Ok(0) => {
                    warn!("pool: connection closed by pool");
                    break;
                }
                Ok(_) if !line.ends_with('\n') => {
                    warn!(
                        "pool: oversized message (>{} bytes) from pool, disconnecting",
                        MAX_LINE_LENGTH
                    );
                    break;
                }
                Ok(_) => {
                    let v: Value = match serde_json::from_str(line.trim()) {
                        Ok(v) => v,
                        Err(_) => continue,
                    };
                    // First job arrives in login's result.job; later jobs are
                    // pushed as {"method":"job","params":{...}}.
                    let job_val = v
                        .get("result")
                        .and_then(|r| r.get("job"))
                        .or_else(|| {
                            if v.get("method").and_then(|m| m.as_str()) == Some("job") {
                                v.get("params")
                            } else {
                                None
                            }
                        });
                    if let Some(jv) = job_val {
                        if let Some(job) = parse_pool_job(jv) {
                            info!("pool: new job {} (height {})", job.job_id, job.height);
                            *job_slot_r.lock().await = Some(job);
                        }
                    } else if v.get("error").map(|e| !e.is_null()).unwrap_or(false) {
                        warn!("pool: server error: {}", v.get("error").unwrap());
                    }
                }
                Err(e) => {
                    warn!("pool: read error: {}", e);
                    break;
                }
            }
        }
    });

    let hasher = Hasher::new();
    let mut nonce_base: u64 = 0;
    let mut submit_id: u64 = 2;
    loop {
        let job = { job_slot.lock().await.clone() };
        let Some(job) = job else {
            tokio::time::sleep(Duration::from_millis(250)).await;
            continue;
        };
        let input = HashInput {
            anchor: job.anchor,
            tx_root: job.tx_root,
            height: job.height,
        };
        // Short deadline so we pick up newly-pushed jobs promptly.
        let deadline = Instant::now() + Duration::from_secs(4);
        let result = mine_parallel(hasher, input, job.target, n_threads, deadline, nonce_base).await;
        let attempts = match &result {
            MineResult::Found { total_attempts, .. } => *total_attempts,
            MineResult::Timeout { total_attempts, .. } => *total_attempts,
        };
        nonce_base = nonce_base.wrapping_add(attempts).wrapping_add(1);

        if let MineResult::Found { nonce, .. } = result {
            // Don't submit against a job the pool has already superseded.
            let still_current = job_slot
                .lock()
                .await
                .as_ref()
                .map(|j| j.job_id == job.job_id)
                .unwrap_or(false);
            if !still_current {
                continue;
            }
            let submit = serde_json::json!({
                "id": submit_id, "method": "submit",
                "params": {"id": "x", "job_id": job.job_id, "nonce": format!("{:x}", nonce)}
            })
            .to_string();
            submit_id = submit_id.wrapping_add(1);
            if write_half.write_all(submit.as_bytes()).await.is_err() {
                warn!("pool: write failed; connection lost");
                break;
            }
            let _ = write_half.write_all(b"\n").await;
            let _ = write_half.flush().await;
            info!("pool: submitted nonce {:x} for job {}", nonce, job.job_id);
        }
    }
    Ok(())
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
    // Single source of truth: the consensus-correct coinbase/anchor/tx_root
    // logic lives in the library's block_builder (proven by its
    // build_mine_submit_roundtrip test). The rig delegates so a rig-mined
    // block and an in-node-produced block are byte-identical.
    let candidate = coincync::mining::block_builder::build_block_from_template(
        template,
        miner_spend_pub,
        miner_view_pub,
        fallback_network,
        signal_bits,
    )
    .map_err(|e| anyhow!("build_block_from_template failed: {e}"))?;
    Ok((candidate.header, candidate.transactions))
}

// build_header_from_template's coinbase/anchor/tx_root/network-magic helpers
// moved to the library (`coincync::mining::block_builder`) — the single source
// of truth for consensus-correct block construction, shared with the in-node
// mining servers. The rig delegates above.

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
        assert!(!fork_diverged(
            10_042 + FORK_DIVERGENCE_MARGIN,
            10_042,
            FORK_DIVERGENCE_MARGIN
        ));
    }

    #[test]
    fn runaway_private_fork_trips_the_gate() {
        // The 2026-07-08 signature: local tip hundreds of blocks past every
        // peer, which stays put because it rejects our low-work blocks.
        assert!(fork_diverged(10_544, 10_042, FORK_DIVERGENCE_MARGIN));
        // One block past the margin is enough to trip.
        assert!(fork_diverged(
            10_042 + FORK_DIVERGENCE_MARGIN + 1,
            10_042,
            FORK_DIVERGENCE_MARGIN
        ));
    }

    #[test]
    fn behind_or_level_with_peers_never_diverges() {
        // Being behind the network is handled by is_synced, not this gate.
        assert!(!fork_diverged(10_000, 10_042, FORK_DIVERGENCE_MARGIN));
        assert!(!fork_diverged(10_042, 10_042, FORK_DIVERGENCE_MARGIN));
    }

    // Build a minimal non-coinbase tx carrying only a fee — enough for the
    // fee-accounting path, which reads `tx.fee` and the serialized size.
    fn tx_with_fee(fee: u64) -> coincync::transaction::Transaction {
        use coincync::primitives::Amount;
        use coincync::transaction::{Transaction, TxType};
        Transaction {
            version: 1,
            tx_type: TxType::Transfer,
            inputs: vec![],
            outputs: vec![],
            fee: Amount::from_atomic(fee),
            range_proof: vec![],
            extra: vec![],
        }
    }

    #[test]
    fn claimable_fees_track_the_validator_activation_gate() {
        use coincync::mining::block_builder::calculate_claimable_fees;
        use coincync::constants::FEE_DISTRIBUTION_HEIGHT;
        use coincync::primitives::Amount;

        // No fees → nothing claimable, regardless of height.
        assert_eq!(calculate_claimable_fees(FEE_DISTRIBUTION_HEIGHT, &[]), 0);
        assert_eq!(calculate_claimable_fees(0, &[tx_with_fee(0)]), 0);

        let fee = 7_160_000u64;
        let txs = [tx_with_fee(fee)];

        // At/after activation the burn split applies: the miner claims only
        // `distribute_fee(...).to_miner`. A lone tiny tx is far from the
        // congestion threshold, so the split is the non-congested one.
        let expected_after = coincync::consensus::fee_market::distribute_fee(
            Amount::from_atomic(fee),
            false,
        )
        .to_miner
        .as_atomic();
        assert_eq!(
            calculate_claimable_fees(FEE_DISTRIBUTION_HEIGHT, &txs),
            expected_after,
            "at/after activation the miner claims only the un-burned share"
        );

        // Before activation the validator lets the miner claim the WHOLE fee
        // (backward compatible). This window only exists when the activation
        // height is non-zero — i.e. testnet builds. On mainnet it is 0, so
        // there is no pre-activation block to test and the split is always on.
        if FEE_DISTRIBUTION_HEIGHT > 0 {
            let before = calculate_claimable_fees(FEE_DISTRIBUTION_HEIGHT - 1, &txs);
            assert_eq!(
                before, fee,
                "below activation the miner claims the full fee, no burn"
            );
            assert!(
                before > expected_after,
                "the burn split must reduce the miner's share once active"
            );
        }
    }
}
