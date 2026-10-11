//! ## Audit map
//! Each `§` is a code section below; it states the INVARIANT it guarantees, the
//! THREAT it defends, and the TESTS that prove it.
//!
//! - **§1 `spawn_maintenance` panic/clean-exit supervisor** — INVARIANT: if
//!   the inner maintenance loop ever exits (panic, clean return, or
//!   cancellation not caused by shutdown), a CRITICAL log line fires so the
//!   condition is externally observable; it never fails silently.
//!   THREAT: a poisoned lock or panic inside the loop killing ping/dandelion
//!   /scoring/ban-flush while `systemd is-active` still reports healthy — the
//!   2026-06-19 production silent-hang incident this comment documents.
//!   TESTS: (gap — no test panics the inner loop and asserts the supervisor
//!   logs CRITICAL rather than exiting quietly).
//! - **§2 `run_ping_tick`** — INVARIANT: every ping interval, a keepalive is
//!   sent to all current senders and expired tx-absence entries are pruned,
//!   using a best-effort send (dead channels don't abort the tick).
//!   THREAT: without periodic pings, `PEER_TIMEOUT`-based liveness on the
//!   remote side evicts us even on a healthy link; without pruning, the
//!   tx-absence cache grows unbounded between hard-cap evictions.
//!   TESTS: (gap in this file — `TxAbsenceCache::prune`'s bound is exercised
//!   indirectly by `evicts_oldest_entry_at_the_hard_cap` in tx_absence.rs,
//!   but no test drives this tick's TTL-based prune path specifically).
//! - **§3 `run_dandelion_tick`** — INVARIANT: locally-queued transactions are
//!   drained into the stem pool, the live outbound peer set is refreshed
//!   before each tick, and `stem_relay`/`fluff` actions are sent to exactly
//!   the target peer (stem) or all peers (fluff) with no duplication.
//!   THREAT: stalled or misrouted Dandelion++ actions would either leak the
//!   originating peer (broken stem privacy) or fail to propagate a
//!   transaction at all.
//!   TESTS: `local_tx_enters_stempool`, `embargo_timeout_produces_actions`,
//!   `diffusion_confirmation_removes_from_stempool`,
//!   `multiple_txs_tracked_independently` (network_security.rs; these prove
//!   the underlying `DandelionRouter` state machine this tick drives).
//! - **§4 `run_cleanup_tick`** — INVARIANT: peers idle past `PEER_TIMEOUT` are
//!   fully torn down (tracker/sync/orphan-flood/event) each cleanup interval,
//!   and peer scores decay/auto-ban/expire on the same cadence.
//!   THREAT: a peer that silently stopped responding but never explicitly
//!   disconnected would occupy a connection slot indefinitely, and unbounded
//!   score/ban-list growth would eventually exhaust memory.
//!   TESTS: (gap — no test drives a stale peer through this tick and asserts
//!   full teardown, or asserts `decay_all`/`auto_ban_bad_peers` firing here).
//! - **§5 `run_tip_announce_tick`** — INVARIANT: the current tip is
//!   re-announced via `InvBlock` on a fixed interval, and is a no-op when the
//!   tip is still the zero hash (no chain yet).
//!   THREAT: the 2026-06-27 gossip bug this fixes — peers that missed the
//!   original tip announcement (e.g. connected after it fired) would never
//!   learn the current tip and stall in sync.
//!   TESTS: (gap — no test asserts periodic re-announcement or the
//!   zero-hash no-op guard).
//! - **§6 `flush_ban_list`** — INVARIANT: the ban list is persisted to disk
//!   every interval regardless of whether it changed; a save failure is
//!   logged, never panics the maintenance loop.
//!   THREAT: an unpersisted ban list is lost on restart, letting a
//!   previously-banned peer reconnect immediately after a crash.
//!   TESTS: (gap — no test exercises this tick's periodic flush or its
//!   failure-logging path).
//! - **§7 `rotate_outbound_peer`** — INVARIANT: when more than 3 outbound
//!   peers are connected, the single longest-connected outbound peer is
//!   dropped each rotation interval; 3 or fewer outbound peers is a no-op.
//!   THREAT: a patient eclipse attacker holding long-lived outbound slots
//!   indefinitely; periodic forced churn bounds how long any one outbound
//!   peer set can persist. Closes audit MEDIUM #28.
//!   TESTS: (gap — no test asserts the oldest-outbound selection or the
//!   `<= 3` no-op threshold).
//! - **§8 `emit_heartbeat`** — INVARIANT: one INFO line per tick reporting a
//!   monotonically increasing counter and current peer/outbound counts, so an
//!   external watchdog can detect a frozen maintenance loop.
//!   THREAT: the silent-hang failure mode from §1 going undetected for hours
//!   (17h in the referenced production incident) instead of ~30s.
//!   TESTS: (gap — no test asserts heartbeat emission or its counter
//!   monotonicity).
//! - **§9 `run_self_heal_tick` / `self_heal_decision`** — INVARIANT: a node
//!   whose local height has not advanced for `SELF_HEAL_STALL_SECS` WHILE a
//!   higher sync target exists and it is not synced performs a SOFT recovery
//!   (purge phantom peer-height entries, expire stale work claims, re-trigger
//!   sync), rate-limited to once per `SELF_HEAL_MIN_GAP`; a synced, caught-up,
//!   or still-progressing node, or one with nobody ahead, does nothing.
//!   THREAT: the 2026-10-10 IBD wedge the external
//!   `deploy/fleet/coincync-sync-watchdog.sh` restarts a node for — height
//!   frozen while peers are far ahead, a departed peer's stale target pinning
//!   `is_synced` false — internalized as a no-restart recovery. The detection
//!   is deliberately conservative: a false trigger would purge peer caches
//!   fleet-wide at once (network-wide outage), so it errs toward doing nothing.
//!   TESTS: `self_heal_*` in `self_heal_tests` cover healthy/synced,
//!   behind-but-progressing, nobody-ahead, stalled→recover, and the rate-limit.

use std::collections::HashSet;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

use dashmap::DashMap;
use tokio::sync::{broadcast, mpsc, watch, RwLock};
use tokio::task::JoinHandle;
use tokio::time::interval;
use tracing::{debug, info, warn};

use crate::mempool::SharedMempool;
use crate::primitives::Hash;
use crate::transaction::Transaction;

use super::super::connection_tracker::ConnectionTracker;
use super::super::dandelion::{DandelionRouter, DANDELION_MONITOR_INTERVAL_SECS};
use super::super::peer::{PeerId, PeerInfo, PeerState};
use super::super::protocol::Message;
use super::super::relay_score::RelayScoreMap;
use super::super::scoring::{OrphanFloodTracker, PeerScorer};
use super::super::sync::ChainSync;
use super::chain_state::ChainStateReader;
use super::constants::{
    MESH_FLOOR_PEERS, MESH_FLOOR_SUSTAIN_TICKS, PEER_TIMEOUT, PING_INTERVAL,
    SELF_HEAL_HEIGHT_SLACK, SELF_HEAL_INTERVAL, SELF_HEAL_MIN_GAP, SELF_HEAL_STALL_SECS,
    TIP_REBROADCAST_INTERVAL_SECS,
};
use super::runtime::wait_for_shutdown;
use super::types::NodeEvent;
use super::TxAbsenceCache;

pub(super) struct MaintenanceContext {
    pub peers: Arc<DashMap<PeerId, PeerInfo>>,
    pub dandelion: Arc<RwLock<DandelionRouter>>,
    pub sync: Arc<RwLock<ChainSync>>,
    pub senders: Arc<DashMap<PeerId, mpsc::Sender<Vec<u8>>>>,
    pub event_tx: broadcast::Sender<NodeEvent>,
    pub mempool: SharedMempool,
    pub tracker: Arc<ConnectionTracker>,
    pub tx_absence_cache: Arc<parking_lot::RwLock<TxAbsenceCache>>,
    pub scorer: Arc<RwLock<PeerScorer>>,
    pub orphan_flood: Arc<RwLock<OrphanFloodTracker>>,
    pub relay_scores: Arc<RwLock<RelayScoreMap>>,
    pub ban_list_path: PathBuf,
    pub chain_state: ChainStateReader,
    pub broadcast_rx: mpsc::Receiver<Transaction>,
    pub magic: [u8; 4],
    /// Sustained mesh-floor flag, updated by the heartbeat tick.
    pub mesh_degraded: std::sync::Arc<std::sync::atomic::AtomicBool>,
}

struct CleanupTick<'a> {
    peers: &'a DashMap<PeerId, PeerInfo>,
    senders: &'a DashMap<PeerId, mpsc::Sender<Vec<u8>>>,
    dandelion: &'a RwLock<DandelionRouter>,
    sync: &'a RwLock<ChainSync>,
    event_tx: &'a broadcast::Sender<NodeEvent>,
    mempool: &'a SharedMempool,
    tracker: &'a ConnectionTracker,
    scorer: &'a RwLock<PeerScorer>,
    orphan_flood: &'a RwLock<OrphanFloodTracker>,
}

/// The watcher distinguishes an expected runtime cancellation from an
/// unexpected clean exit, while preserving immediate panic visibility.
pub(super) fn spawn_maintenance(
    context: MaintenanceContext,
    mut shutdown: watch::Receiver<bool>,
) -> JoinHandle<()> {
    let MaintenanceContext {
        peers: maint_peers,
        dandelion: maint_dandelion,
        sync: maint_sync,
        senders: maint_senders,
        event_tx: maint_event_tx,
        mempool: maint_mempool,
        tracker: maint_tracker,
        tx_absence_cache: maint_tx_absence_cache,
        scorer: maint_scorer,
        orphan_flood: maint_orphan_flood,
        relay_scores: maint_relay_scores,
        ban_list_path: maint_ban_list_path,
        chain_state: maint_chain_state,
        mut broadcast_rx,
        magic,
        mesh_degraded: maint_mesh_degraded,
    } = context;

    // Spawn the maintenance task with panic supervision. Previously
    // a panic inside this task (e.g., a poisoned RwLock during
    // `.write().await`) would terminate the task silently — the node
    // would keep its TCP listeners but stop pinging peers, draining
    // the broadcast queue, and persisting bans. systemd would still
    // report `active`. The production silent-hang on 2026-06-19
    // matched this signature.
    //
    // We wrap the loop body in an outer task that simply logs at
    // ERROR if the inner work-loop ever returns. A real fix would
    // also auto-restart the loop, but auto-restart of a task that
    // holds shared mutable state (peers, scorer, dandelion) is
    // risky if those structures are mid-mutation; safer to log
    // loudly and let the operator restart the process. (Prior
    // comment invoked zebrad's actor-model supervisor pattern and
    // Bitcoin Core's `scheduler` thread as prior art; those
    // specific characterisations were not re-verified this session
    // and are dropped. The log-loudly / no-auto-restart choice
    // stands on its own reasoning above.)
    let supervisor_shutdown = shutdown.clone();
    let maint_handle = tokio::spawn(async move {
        let mut ping_interval = interval(PING_INTERVAL);
        let mut cleanup_interval = interval(Duration::from_secs(60));
        let mut relay_score_interval = interval(Duration::from_secs(10));
        // Dandelion++ monitor runs every DANDELION_MONITOR_INTERVAL_SECS
        let mut dandelion_interval = interval(Duration::from_secs(DANDELION_MONITOR_INTERVAL_SECS));
        // Periodic ban-list flush. (Prior comment claimed "same
        // cadence as Bitcoin Core's `DumpBanlist()` — every 15 min
        // via CScheduler". That specific identifier + cadence
        // pairing was not re-verified against upstream this
        // session and is dropped.) 900s (15 min) picked locally.
        // Cheap to call: writes a small JSON file even when the
        // ban list is empty. Cost-benefit favors always flushing
        // over tracking a dirty flag.
        let mut ban_flush_interval = interval(Duration::from_secs(900));
        // Outbound peer rotation. (Prior comment cited Bitcoin
        // Core's "block-relay-only" outbound peer rotation with a
        // ~22.5 min cadence, a `MaybePickEvictionCandidate` helper
        // in net_processing.cpp, and an `EXTRA_PEER_CHECK_INTERVAL`
        // constant defaulting to 45 min. Those specific identifiers
        // and cadence numbers were not re-verified against upstream
        // this session and are dropped.) 45 min picked locally to
        // balance churn against eclipse-defense — too aggressive
        // and we waste bandwidth on Noise handshakes; too slow and
        // a patient eclipse holds. Closes audit MEDIUM #28.
        let mut outbound_rotate_interval = interval(Duration::from_secs(45 * 60));
        // Heartbeat / liveness signal. Emits a single INFO line every
        // 30 seconds with a monotonically-increasing tick counter +
        // current peer count. External watchdogs (or operator `tail
        // -f`) can detect silent-hang within 30 s instead of the 17
        // hours observed in the production incident where the
        // maintenance task froze and `systemd is-active` kept
        // reporting `active`. If the heartbeat stops, the maintenance
        // loop is dead — restart the service. Reference: Bitcoin
        // Core's `scheduler` thread emits periodic LogPrintf at TRACE
        // level for similar reason. Cheap: one log line per 30 s.
        let mut heartbeat_interval = interval(Duration::from_secs(30));
        let mut heartbeat_ticks: u64 = 0;
        // Consecutive heartbeats with connected peers below MESH_FLOOR_PEERS.
        let mut mesh_below_streak: u32 = 0;
        // 2026-06-27 gossip-bug fix: periodic InvBlock re-announce of our
        // current tip to all peers. See TIP_REBROADCAST_INTERVAL_SECS docs
        // (from PR #123).
        let mut tip_announce_interval =
            interval(Duration::from_secs(TIP_REBROADCAST_INTERVAL_SECS));
        // §9 self-heal: internalizes the external IBD-stall watchdog as a SOFT
        // (no-restart) recovery. State is owned by the loop (wall-clock progress
        // tracking must NOT live in ChainSync); seeded to the current local
        // height so the stall clock starts fresh at boot and never false-fires
        // on a node that is simply still bootstrapping.
        let mut self_heal_interval = interval(Duration::from_secs(SELF_HEAL_INTERVAL));
        let mut self_heal_state = SelfHealState::new(maint_chain_state.snapshot().await.0);

        loop {
            tokio::select! {
                // Biased polling: under sustained load, the default
                // `select!` randomization can starve low-frequency
                // branches. PING_INTERVAL (120 s) is the most safety-
                // critical (peers evict us after PEER_TIMEOUT=300 s
                // of no activity), so it must run on schedule even
                // if cleanup_interval is also ready. Listed in
                // priority order. Reference: tokio docs on `biased;`
                // ordering — "evaluates branches in declared order;
                // skip random branch selection entirely." Bitcoin
                // Core's scheduler similarly prioritizes ping/health
                // ticks over background maintenance.
                biased;
                _ = wait_for_shutdown(&mut shutdown) => break,
                _ = ping_interval.tick() => {
                    run_ping_tick(&maint_senders, &maint_tx_absence_cache, magic).await;
                }

                _ = relay_score_interval.tick() => {
                    evaporate_relay_scores(&maint_relay_scores).await;
                }

                _ = dandelion_interval.tick() => {
                    run_dandelion_tick(
                        &mut broadcast_rx,
                        &maint_dandelion,
                        &maint_peers,
                        &maint_senders,
                        &maint_event_tx,
                        magic,
                    ).await;
                }

                _ = tip_announce_interval.tick() => {
                    run_tip_announce_tick(&maint_chain_state, &maint_senders, magic).await;
                }

                _ = cleanup_interval.tick() => {
                    run_cleanup_tick(CleanupTick {
                        peers: &maint_peers,
                        senders: &maint_senders,
                        dandelion: &maint_dandelion,
                        sync: &maint_sync,
                        event_tx: &maint_event_tx,
                        mempool: &maint_mempool,
                        tracker: &maint_tracker,
                        scorer: &maint_scorer,
                        orphan_flood: &maint_orphan_flood,
                    }).await;
                }
                _ = ban_flush_interval.tick() => {
                    flush_ban_list(&maint_scorer, &maint_ban_list_path).await;
                }
                _ = outbound_rotate_interval.tick() => {
                    rotate_outbound_peer(&maint_peers, &maint_senders, &maint_tracker);
                }
                _ = heartbeat_interval.tick() => {
                    heartbeat_ticks = heartbeat_ticks.saturating_add(1);
                    emit_heartbeat(&maint_peers, heartbeat_ticks);
                    update_mesh_floor(&maint_peers, &maint_mesh_degraded, &mut mesh_below_streak);
                }
                _ = self_heal_interval.tick() => {
                    run_self_heal_tick(
                        &maint_peers,
                        &maint_sync,
                        &maint_chain_state,
                        &mut self_heal_state,
                    ).await;
                }
            }
        }
    });

    // Supervisor watcher: detect maintenance-task panic / clean exit.
    // If the maintenance task ever terminates (panic, clean break, or
    // task abort), this watcher logs CRITICAL. Operator must restart
    // the service — auto-restart of a task holding shared mutable
    // state is unsafe without a full lock-reset protocol.
    tokio::spawn(async move {
        match maint_handle.await {
            Ok(()) if *supervisor_shutdown.borrow() => {
                debug!(target: "node::supervisor", "Maintenance task stopped with node runtime");
            }
            Ok(()) => {
                tracing::error!(
                    target: "node::supervisor",
                    "CRITICAL: maintenance task exited cleanly (no panic). \
                     This should never happen — the loop is unbounded. \
                     Node is now running WITHOUT ping/dandelion/peer-scoring/ban-flush. \
                     Restart the service immediately."
                );
            }
            Err(e) if e.is_panic() => {
                tracing::error!(
                    target: "node::supervisor",
                    "CRITICAL: maintenance task PANICKED ({:?}). \
                     Node is now running WITHOUT background maintenance. \
                     Heartbeat will stop. Restart the service immediately.",
                    e
                );
            }
            Err(e) if e.is_cancelled() && *supervisor_shutdown.borrow() => {
                debug!(
                    target: "node::supervisor",
                    "Maintenance task cancelled with node runtime."
                );
            }
            Err(e) => {
                tracing::error!(
                    target: "node::supervisor",
                    "CRITICAL: maintenance task ended with JoinError: {:?}",
                    e
                );
            }
        }
    })
}

async fn run_ping_tick(
    senders: &DashMap<PeerId, mpsc::Sender<Vec<u8>>>,
    tx_absence_cache: &parking_lot::RwLock<TxAbsenceCache>,
    magic: [u8; 4],
) {
    if let Ok(data) = Message::ping(magic).to_bytes() {
        let snapshot: Vec<mpsc::Sender<Vec<u8>>> = senders
            .iter()
            .map(|sender| sender.value().clone())
            .collect();
        for sender in snapshot {
            let _ = sender.send(data.clone()).await;
        }
    }

    let pruned = tx_absence_cache.write().prune();
    if pruned > 0 {
        tracing::trace!("pruned {} expired tx-absence entries", pruned);
    }
}

async fn run_dandelion_tick(
    broadcast_rx: &mut mpsc::Receiver<Transaction>,
    dandelion: &RwLock<DandelionRouter>,
    peers: &DashMap<PeerId, PeerInfo>,
    senders: &DashMap<PeerId, mpsc::Sender<Vec<u8>>>,
    event_tx: &broadcast::Sender<NodeEvent>,
    magic: [u8; 4],
) {
    let now = chrono::Utc::now().timestamp() as u64;
    while let Ok(transaction) = broadcast_rx.try_recv() {
        debug!(
            "STEM: Local transaction {} entering Dandelion++",
            transaction.hash()
        );
        dandelion.write().await.add_local_tx(transaction, now);
    }

    let outbound: Vec<PeerId> = peers
        .iter()
        .filter(|peer| peer.outbound && peer.state == PeerState::Connected)
        .map(|peer| peer.id)
        .collect();
    dandelion.write().await.set_outbound_peers(outbound);
    let actions = dandelion.write().await.tick(now);

    for (_, transaction, target_peer) in &actions.stem_relay {
        let sender = senders.get(target_peer).map(|entry| entry.value().clone());
        if let Some(sender) = sender {
            if let Ok(message) = Message::txs(magic, vec![transaction.clone()]) {
                if let Ok(data) = message.to_bytes() {
                    let _ = sender.send(data).await;
                }
            }
        }
        crate::metrics::dandelion::STEM_RELAYS_TOTAL.inc();
    }

    for (transaction_hash, transaction, source) in &actions.fluff {
        if let Ok(message) = Message::inv_tx(magic, *transaction_hash) {
            if let Ok(data) = message.to_bytes() {
                let snapshot: Vec<mpsc::Sender<Vec<u8>>> = senders
                    .iter()
                    .map(|sender| sender.value().clone())
                    .collect();
                for sender in snapshot {
                    let _ = sender.send(data.clone()).await;
                }
            }
        }
        let _ = event_tx.send(NodeEvent::TransactionReceived(transaction.clone(), *source));
        crate::metrics::dandelion::FLUFF_BROADCASTS_TOTAL.inc();
    }

    crate::metrics::dandelion::STEMPOOL_SIZE.set(dandelion.read().await.stempool_size() as i64);
}

async fn run_cleanup_tick(context: CleanupTick<'_>) {
    let CleanupTick {
        peers,
        senders,
        dandelion,
        sync,
        event_tx,
        mempool,
        tracker,
        scorer,
        orphan_flood,
    } = context;
    let stale: Vec<PeerId> = peers
        .iter()
        .filter(|peer| peer.is_stale(PEER_TIMEOUT))
        .map(|peer| peer.id)
        .collect();
    for peer_id in stale {
        if let Some(peer) = peers.get(&peer_id) {
            tracker.untrack_connection(&peer.addr);
        }
        peers.remove(&peer_id);
        senders.remove(&peer_id);
        sync.write().await.on_peer_disconnected(&peer_id);
        orphan_flood.write().await.forget(&peer_id);
        let _ = event_tx.send(NodeEvent::PeerDisconnected(peer_id));
    }

    let outbound: Vec<PeerId> = peers
        .iter()
        .filter(|peer| peer.outbound && peer.state == PeerState::Connected)
        .map(|peer| peer.id)
        .collect();
    dandelion.write().await.set_outbound_peers(outbound);

    let expired = mempool.expire_old(72 * 3600);
    if expired > 0 {
        debug!("Expired {} old mempool transactions", expired);
    }

    // Connected peer addresses — entries the score sweep must retain.
    let connected: std::collections::HashSet<std::net::SocketAddr> =
        peers.iter().map(|peer| peer.addr).collect();

    let mut scorer = scorer.write().await;
    scorer.decay_all(50);
    scorer.auto_ban_bad_peers();
    scorer.cleanup_bans();
    // Prune the scores map (previously unbounded — disconnect never removed the
    // entry, so it grew per unique source address forever + slowed every tick).
    let pruned = scorer.prune_scores(&connected);
    if pruned > 0 {
        debug!("Pruned {} stale peer score entries", pruned);
    }
}

async fn run_tip_announce_tick(
    chain_state: &ChainStateReader,
    senders: &DashMap<PeerId, mpsc::Sender<Vec<u8>>>,
    magic: [u8; 4],
) {
    let (_, tip) = chain_state.snapshot().await;
    if tip == Hash::zero() {
        return;
    }
    let Ok(message) = Message::inv_block(magic, tip) else {
        return;
    };
    let Ok(data) = message.to_bytes() else {
        return;
    };

    let mut sent = 0usize;
    let mut full = 0usize;
    for sender in senders.iter() {
        match sender.try_send(data.clone()) {
            Ok(()) => sent += 1,
            Err(mpsc::error::TrySendError::Full(_)) => full += 1,
            Err(mpsc::error::TrySendError::Closed(_)) => {}
        }
    }
    if full > 0 {
        debug!(
            "tip_announce: sent InvBlock to {} peers ({} channels full, retry in {}s)",
            sent, full, TIP_REBROADCAST_INTERVAL_SECS,
        );
    } else {
        tracing::trace!("tip_announce: sent InvBlock {} to {} peers", tip, sent);
    }
}

async fn flush_ban_list(scorer: &RwLock<PeerScorer>, path: &std::path::Path) {
    if let Err(error) = scorer.read().await.save_bans_to_file(path) {
        warn!("Periodic ban-list save failed: {}", error);
    }
}

/// Track the sustained mesh-floor state with hysteresis. Increments a
/// below-floor streak each heartbeat that connected peers are under
/// `MESH_FLOOR_PEERS`; once the streak reaches `MESH_FLOOR_SUSTAIN_TICKS` the
/// `mesh_degraded` flag is set. Any heartbeat at/above the floor resets the
/// streak and clears the flag immediately (slow to enter, fast to recover).
///
/// This is observational — it does not itself change mining or peering
/// behavior. Enforcement (e.g. pausing mining while degraded) is opt-in; see
/// docs/design/runtime-mesh-floor.md.
fn update_mesh_floor(
    peers: &DashMap<PeerId, PeerInfo>,
    mesh_degraded: &std::sync::atomic::AtomicBool,
    below_streak: &mut u32,
) {
    use std::sync::atomic::Ordering;
    let connected = peers
        .iter()
        .filter(|peer| peer.state == PeerState::Connected)
        .count();
    if connected < MESH_FLOOR_PEERS {
        *below_streak = below_streak.saturating_add(1);
        if *below_streak >= MESH_FLOOR_SUSTAIN_TICKS
            && !mesh_degraded.swap(true, Ordering::Relaxed)
        {
            warn!(
                target: "node::heartbeat",
                "mesh-floor: connected peers={} below floor={} for {} ticks — entering mesh_degraded",
                connected, MESH_FLOOR_PEERS, below_streak,
            );
        }
    } else {
        *below_streak = 0;
        if mesh_degraded.swap(false, Ordering::Relaxed) {
            info!(
                target: "node::heartbeat",
                "mesh-floor: connected peers={} at/above floor={} — clearing mesh_degraded",
                connected, MESH_FLOOR_PEERS,
            );
        }
    }
}

fn emit_heartbeat(peers: &DashMap<PeerId, PeerInfo>, tick: u64) {
    let outbound = peers
        .iter()
        .filter(|peer| peer.outbound && peer.state == PeerState::Connected)
        .count();
    info!(
        target: "node::heartbeat",
        "maintenance tick={} peers={} outbound={}",
        tick,
        peers.len(),
        outbound
    );
}

fn rotate_outbound_peer(
    peers: &DashMap<PeerId, PeerInfo>,
    senders: &DashMap<PeerId, mpsc::Sender<Vec<u8>>>,
    tracker: &ConnectionTracker,
) {
    let outbound: Vec<(PeerId, std::time::Instant, std::net::SocketAddr)> = peers
        .iter()
        .filter(|peer| peer.outbound && peer.state == PeerState::Connected)
        .map(|peer| (peer.id, peer.connected_at, peer.addr))
        .collect();
    if outbound.len() <= 3 {
        return;
    }
    let Some((peer_id, _, addr)) = outbound
        .into_iter()
        .min_by_key(|(_, connected_at, _)| *connected_at)
    else {
        return;
    };

    debug!(
        "Rotating outbound peer {} (longest-connected) to disrupt potential eclipse hold",
        addr
    );
    senders.remove(&peer_id);
    if let Some((_, peer)) = peers.remove(&peer_id) {
        tracker.untrack_connection(&peer.addr);
    }
}

async fn evaporate_relay_scores(relay_scores: &RwLock<RelayScoreMap>) {
    let mut scores = relay_scores.write().await;
    scores.evaporate();
    if !scores.is_empty() {
        debug!(
            "inbound relay-score: {} peers currently scored",
            scores.len()
        );
    }
}

// ─────────────────────────── §9 self-heal ───────────────────────────
//
// Internalizes `deploy/fleet/coincync-sync-watchdog.sh`: a node wedged in IBD
// (height frozen while peers are far ahead) is recovered WITHOUT a process
// restart. The external watchdog's SOFT equivalent is: purge phantom/stale
// peer-height entries (the `retain_connected_peers` connection-lifecycle fix),
// expire stale work claims, and nudge the sync driver to re-request. No
// connected peers are dropped, no process exits, no new channels/seeds — the
// SAFEST actions only. Detection is deliberately conservative because a false
// trigger would purge peer caches across the whole fleet simultaneously.

/// Decision for the self-heal tick. Kept a pure function (no I/O, no clocks)
/// so the detection logic is unit-testable without a live node.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SelfHealAction {
    /// Node is healthy, caught up, still progressing, has nobody ahead, or is
    /// inside the rate-limit window — do nothing.
    None,
    /// Node is demonstrably wedged in IBD — perform the soft recovery.
    Recover,
}

/// Wall-clock progress state owned by the maintenance loop. Deliberately NOT
/// stored in `ChainSync` (which holds no wall-clock state).
struct SelfHealState {
    /// Highest local height observed so far (monotonic high-water mark).
    last_height: u64,
    /// Instant `last_height` last increased — the stall clock's zero.
    last_progress_at: Instant,
    /// Instant the last soft recovery fired, for rate-limiting; `None` until
    /// the first recovery.
    last_heal_at: Option<Instant>,
}

impl SelfHealState {
    fn new(local_height: u64) -> Self {
        Self {
            last_height: local_height,
            last_progress_at: Instant::now(),
            last_heal_at: None,
        }
    }
}

/// Pure detection. CONSERVATIVE — returns `Recover` only when the node is
/// demonstrably stalled: behind a known-higher target, not synced, and its
/// height has not advanced for at least `SELF_HEAL_STALL_SECS`, and it is not
/// inside the `SELF_HEAL_MIN_GAP` rate-limit window.
///
/// Mirrors `coincync-sync-watchdog.sh`: do NOTHING when synced, caught up, or
/// merely slow-but-progressing, and NEVER "recover" when nobody is ahead
/// (`target <= local_height + slack`) — there would be no one to sync from.
fn self_heal_decision(
    local_height: u64,
    last_height: u64,
    since_progress: Duration,
    target: u64,
    is_synced: bool,
    since_last_heal: Option<Duration>,
) -> SelfHealAction {
    // Synced => healthy, never recover.
    if is_synced {
        return SelfHealAction::None;
    }
    // Nobody is meaningfully ahead of us => no sync source, never recover.
    // (Guards the isolated false-synced / caught-up cases the watchdog skips.)
    if target <= local_height.saturating_add(SELF_HEAL_HEIGHT_SLACK) {
        return SelfHealAction::None;
    }
    // Height advanced since the last sample => still progressing, keep waiting.
    if local_height > last_height {
        return SelfHealAction::None;
    }
    // Behind and not progressing — but only a stall once it has persisted.
    if since_progress < Duration::from_secs(SELF_HEAL_STALL_SECS) {
        return SelfHealAction::None;
    }
    // Rate-limit: a recovery within the last SELF_HEAL_MIN_GAP suppresses
    // another (edge-triggered), so the soft recovery can never hot-loop.
    if let Some(gap) = since_last_heal {
        if gap < Duration::from_secs(SELF_HEAL_MIN_GAP) {
            return SelfHealAction::None;
        }
    }
    SelfHealAction::Recover
}

/// Self-heal maintenance tick. Samples local height + sync target, runs the
/// pure decision, and on `Recover` performs the SOFT recovery. Logs loudly at
/// WARN on recovery; silent when healthy.
/// Soft self-heal recovery actions on a wedged `ChainSync`, extracted so the
/// behavior is unit-testable without a live node or `ChainStateReader`:
///   1. purge peer-height/work entries for peers no longer connected (the
///      phantom-IBD wedge fix — always safe),
///   2. expire stale work claims so `is_synced`/target recompute,
///   3. re-arm a header pull via `arm_near_tip_catchup`, which re-arms from ANY
///      sync state ONLY when the node is idle (nothing in flight) AND `!synced`
///      — exactly the behind-and-stuck wedge. (`trigger_resync` would no-op
///      here; it only fires from Synced/Idle.) The idle guard means it can
///      never disrupt an actively-progressing download.
/// Returns `(pruned, expired, retriggered)`. SAFE: no peer drops, no restart.
fn self_heal_recover(
    sync: &mut ChainSync,
    connected: &HashSet<PeerId>,
    unix_now: u64,
) -> (usize, usize, bool) {
    let pruned = sync.retain_connected_peers(connected);
    let expired = sync.expire_stale_work_claims(unix_now, 0);
    let retriggered = sync.arm_near_tip_catchup();
    (pruned, expired, retriggered)
}

async fn run_self_heal_tick(
    peers: &DashMap<PeerId, PeerInfo>,
    sync: &RwLock<ChainSync>,
    chain_state: &ChainStateReader,
    state: &mut SelfHealState,
) {
    let now = Instant::now();
    let (local_height, _tip) = chain_state.snapshot().await;

    let (target, is_synced) = {
        let guard = sync.read().await;
        (guard.true_best_height(), guard.is_synced())
    };

    let since_progress = now.saturating_duration_since(state.last_progress_at);
    let since_last_heal = state
        .last_heal_at
        .map(|t| now.saturating_duration_since(t));

    let action = self_heal_decision(
        local_height,
        state.last_height,
        since_progress,
        target,
        is_synced,
        since_last_heal,
    );

    // Advance the progress clock AFTER the decision (so a tick that observes an
    // advance is classified as progressing, then records the new high-water).
    if local_height > state.last_height {
        state.last_height = local_height;
        state.last_progress_at = now;
    }

    if action == SelfHealAction::Recover {
        let stalled_secs = since_progress.as_secs();
        // Unix seconds for the work-claim expiry. Use the CANONICAL clock
        // (src/clock.rs, the E1 single source of truth) — the same clock the
        // work-claim timestamps were recorded with — so the expiry cutoff can
        // never drift from the timestamps it is compared against (a plain
        // chrono wall-clock could, under a mocked/offset clock).
        let unix_now = crate::clock::unix_now();
        // Connected-peer set drives the phantom/stale peer-height purge.
        let connected: HashSet<PeerId> = peers.iter().map(|p| *p.key()).collect();

        let (pruned, expired, retriggered) = {
            let mut guard = sync.write().await;
            self_heal_recover(&mut guard, &connected, unix_now)
        };

        warn!(
            target: "node::self_heal",
            "IBD stall self-heal: local height {} frozen {}s below target {} \
             (not synced) — soft recovery: pruned {} phantom peer-height entries, \
             expired {} stale work claims, resync re-triggered={}",
            local_height, stalled_secs, target, pruned, expired, retriggered,
        );

        state.last_heal_at = Some(now);
        // Reset the stall clock so the next recovery must re-accumulate a full
        // stall window (belt-and-braces alongside the MIN_GAP rate-limit).
        state.last_progress_at = now;
    }
}

#[cfg(test)]
mod mesh_floor_tests {
    use super::*;
    use std::sync::atomic::{AtomicBool, Ordering};

    fn connected_outbound(n: u8) -> (PeerId, PeerInfo) {
        let id = [n; 32];
        let addr = format!("127.0.0.1:{}", 20000 + n as u16).parse().unwrap();
        let mut p = PeerInfo::new(id, addr, true);
        p.state = PeerState::Connected;
        (id, p)
    }

    #[test]
    fn enters_after_sustained_ticks_and_recovers_immediately() {
        let peers = DashMap::new();
        // One connected peer — below MESH_FLOOR_PEERS (3).
        let (id, p) = connected_outbound(1);
        peers.insert(id, p);
        let degraded = AtomicBool::new(false);
        let mut streak = 0u32;

        // Below floor for SUSTAIN-1 ticks: not yet degraded (hysteresis).
        for _ in 0..(MESH_FLOOR_SUSTAIN_TICKS - 1) {
            update_mesh_floor(&peers, &degraded, &mut streak);
            assert!(!degraded.load(Ordering::Relaxed));
        }
        // The SUSTAIN-th consecutive sub-floor tick flips it on.
        update_mesh_floor(&peers, &degraded, &mut streak);
        assert!(degraded.load(Ordering::Relaxed));

        // Reach the floor (3 connected) — immediate recovery, streak reset.
        for n in 2..=3u8 {
            let (i, pp) = connected_outbound(n);
            peers.insert(i, pp);
        }
        update_mesh_floor(&peers, &degraded, &mut streak);
        assert!(!degraded.load(Ordering::Relaxed));
        assert_eq!(streak, 0);
    }

    #[test]
    fn non_connected_peers_do_not_count_toward_floor() {
        let peers = DashMap::new();
        // Three peers present but only handshaking (not Connected) => below floor.
        for n in 1..=3u8 {
            let id = [n; 32];
            let addr = format!("127.0.0.1:{}", 21000 + n as u16).parse().unwrap();
            peers.insert(id, PeerInfo::new(id, addr, true)); // default state != Connected
        }
        let degraded = AtomicBool::new(false);
        let mut streak = 0u32;
        for _ in 0..MESH_FLOOR_SUSTAIN_TICKS {
            update_mesh_floor(&peers, &degraded, &mut streak);
        }
        assert!(degraded.load(Ordering::Relaxed));
    }
}

#[cfg(test)]
mod self_heal_tests {
    use super::*;

    const STALL: Duration = Duration::from_secs(SELF_HEAL_STALL_SECS);

    // (a) A synced node never recovers, even if it looks behind by the numbers.
    #[test]
    fn synced_node_does_not_recover() {
        let action = self_heal_decision(
            100,          // local_height
            100,          // last_height (no advance)
            STALL,        // long since progress
            200,          // target far ahead
            true,         // is_synced
            None,         // never healed
        );
        assert_eq!(action, SelfHealAction::None);
    }

    // (b) Behind but progressing (height advanced since last sample) => wait.
    #[test]
    fn behind_but_progressing_does_not_recover() {
        let action = self_heal_decision(
            150,          // local_height advanced...
            100,          // ...past last_height
            STALL,        // even though wall-clock says long (stale sample)
            200,
            false,
            None,
        );
        assert_eq!(action, SelfHealAction::None);
    }

    // (c) Nobody ahead (target within slack of local) => never recover; there
    //     would be no one to sync from.
    #[test]
    fn nobody_ahead_does_not_recover() {
        // target == local
        assert_eq!(
            self_heal_decision(100, 100, STALL, 100, false, None),
            SelfHealAction::None
        );
        // target within slack (local + 2)
        assert_eq!(
            self_heal_decision(100, 100, STALL, 100 + SELF_HEAL_HEIGHT_SLACK, false, None),
            SelfHealAction::None
        );
        // target below local (post-reorg transient)
        assert_eq!(
            self_heal_decision(100, 100, STALL, 90, false, None),
            SelfHealAction::None
        );
    }

    // Not stalled long enough => wait (conservative detection).
    #[test]
    fn behind_but_not_long_enough_does_not_recover() {
        let action = self_heal_decision(
            100,
            100,
            Duration::from_secs(SELF_HEAL_STALL_SECS - 1),
            200,
            false,
            None,
        );
        assert_eq!(action, SelfHealAction::None);
    }

    // (d) Stalled: behind, not synced, no progress for >= STALL => recover.
    #[test]
    fn stalled_and_behind_recovers() {
        let action = self_heal_decision(
            100,          // local frozen
            100,          // no advance
            STALL,        // for the full window
            200,          // peers far ahead
            false,        // not synced
            None,         // first recovery
        );
        assert_eq!(action, SelfHealAction::Recover);
        // Exactly at the boundary (target == local + slack + 1) still recovers.
        assert_eq!(
            self_heal_decision(
                100,
                100,
                STALL,
                100 + SELF_HEAL_HEIGHT_SLACK + 1,
                false,
                None
            ),
            SelfHealAction::Recover
        );
    }

    // (e) Rate-limit: a second stall within MIN_GAP does not recover again.
    #[test]
    fn rate_limited_within_min_gap_does_not_recover() {
        // Just healed (0s ago) and stalled again: suppressed.
        assert_eq!(
            self_heal_decision(
                100,
                100,
                STALL,
                200,
                false,
                Some(Duration::from_secs(0))
            ),
            SelfHealAction::None
        );
        // Still inside the window (MIN_GAP - 1): suppressed.
        assert_eq!(
            self_heal_decision(
                100,
                100,
                STALL,
                200,
                false,
                Some(Duration::from_secs(SELF_HEAL_MIN_GAP - 1))
            ),
            SelfHealAction::None
        );
        // Past the window: allowed to recover again.
        assert_eq!(
            self_heal_decision(
                100,
                100,
                STALL,
                200,
                false,
                Some(Duration::from_secs(SELF_HEAL_MIN_GAP))
            ),
            SelfHealAction::Recover
        );
    }

    // --- Recovery behavior: self_heal_recover against a constructed wedge -----

    // A departed peer's stale height pins the target up; the real connected peer
    // is still genuinely ahead. Recovery must purge the phantom (target shrinks)
    // yet keep us behind the real peer and re-arm the header pull.
    #[test]
    fn recover_purges_phantom_height_and_rearms_when_still_behind() {
        use std::collections::HashSet;
        let mut sync = ChainSync::new(100, Hash::from_bytes([0u8; 32]));
        let connected_peer: PeerId = [1u8; 32];
        let phantom_peer: PeerId = [2u8; 32];
        sync.update_peer_height_for(connected_peer, 200);
        sync.update_peer_height_for(phantom_peer, 300); // phantom pins target up
        assert_eq!(sync.true_best_height(), 300, "phantom pins target pre-heal");
        let connected: HashSet<PeerId> = [connected_peer].into_iter().collect();

        let (pruned, _expired, retriggered) = self_heal_recover(&mut sync, &connected, 1_000_000);

        assert_eq!(pruned, 1, "the phantom (disconnected) peer-height is purged");
        assert_eq!(sync.true_best_height(), 200, "target shrinks to the real peer");
        assert!(!sync.is_synced(), "still behind the connected peer -> not synced");
        assert!(retriggered, "behind + idle -> header pull re-armed");
    }

    // If the ONLY ahead-peer was a phantom, purging it leaves nobody ahead ->
    // the node is correctly synced and the re-arm is a (safe) no-op.
    #[test]
    fn recover_does_not_rearm_when_purge_leaves_nobody_ahead() {
        use std::collections::HashSet;
        let mut sync = ChainSync::new(100, Hash::from_bytes([0u8; 32]));
        sync.update_peer_height_for([9u8; 32], 150); // phantom, departed
        assert!(!sync.is_synced(), "phantom pins us behind pre-heal");
        let connected: HashSet<PeerId> = HashSet::new();

        let (pruned, _expired, retriggered) = self_heal_recover(&mut sync, &connected, 1_000_000);

        assert_eq!(pruned, 1, "phantom height purged");
        assert!(sync.is_synced(), "nobody ahead after purge -> synced");
        assert!(!retriggered, "synced -> no re-arm needed");
    }
}
