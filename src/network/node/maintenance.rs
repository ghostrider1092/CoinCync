use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

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
use super::constants::{PEER_TIMEOUT, PING_INTERVAL, TIP_REBROADCAST_INTERVAL_SECS};
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
        // 2026-06-27 gossip-bug fix: periodic InvBlock re-announce of our
        // current tip to all peers. See TIP_REBROADCAST_INTERVAL_SECS docs
        // (from PR #123).
        let mut tip_announce_interval =
            interval(Duration::from_secs(TIP_REBROADCAST_INTERVAL_SECS));

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

    let mut scorer = scorer.write().await;
    scorer.decay_all(50);
    scorer.auto_ban_bad_peers();
    scorer.cleanup_bans();
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
