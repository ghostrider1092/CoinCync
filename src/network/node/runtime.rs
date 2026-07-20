use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use dashmap::DashMap;
use tokio::sync::{broadcast, mpsc, watch, RwLock};
use tokio::task::JoinHandle;
use tokio::time::{timeout_at, Duration, Instant};
use tracing::{debug, error, warn};

use crate::chain::SharedBlockchain;
use crate::mempool::SharedMempool;

use super::super::bootstrap::AddressManager;
use super::super::dandelion::DandelionRouter;
use super::super::peer::{PeerId, PeerInfo};
use super::super::relay_score::RelayScoreMap;
use super::super::scoring::PeerScorer;
use super::super::sync::ChainSync;
use super::super::traffic_shaping::TrafficShaper;
use super::dispatch::process_message;
use super::types::NodeEvent;
use super::{PeerMessage, TxAbsenceCache};

struct RuntimeTask {
    name: &'static str,
    handle: JoinHandle<()>,
}

pub(super) struct NodeRuntime {
    shutdown_tx: watch::Sender<bool>,
    tasks: Vec<RuntimeTask>,
}

impl NodeRuntime {
    pub(super) fn new() -> Self {
        let (shutdown_tx, _) = watch::channel(false);
        Self {
            shutdown_tx,
            tasks: Vec::new(),
        }
    }

    pub(super) fn shutdown_receiver(&self) -> watch::Receiver<bool> {
        self.shutdown_tx.subscribe()
    }

    pub(super) fn track(&mut self, name: &'static str, handle: JoinHandle<()>) {
        self.tasks.push(RuntimeTask { name, handle });
    }

    pub(super) async fn shutdown(mut self) {
        let _ = self.shutdown_tx.send(true);
        let deadline = Instant::now() + Duration::from_secs(5);
        for task in self.tasks.drain(..) {
            let mut handle = task.handle;
            match timeout_at(deadline, &mut handle).await {
                Ok(Ok(())) => {}
                Ok(Err(join_error)) if join_error.is_cancelled() => {
                    debug!(task = task.name, "node runtime task cancelled");
                }
                Ok(Err(join_error)) => {
                    error!(task = task.name, error = ?join_error, "node runtime task failed");
                }
                Err(_) => {
                    warn!(
                        task = task.name,
                        "node runtime task exceeded shutdown deadline; aborting"
                    );
                    handle.abort();
                    let _ = handle.await;
                }
            }
        }
    }
}

pub(super) async fn wait_for_shutdown(shutdown: &mut watch::Receiver<bool>) {
    if *shutdown.borrow() {
        return;
    }
    let _ = shutdown.changed().await;
}

pub(super) fn spawn_upnp_setup(port: u16, mut shutdown: watch::Receiver<bool>) -> JoinHandle<()> {
    tokio::spawn(async move {
        tokio::select! {
            result = super::super::bootstrap::setup_upnp(port, port) => {
                if let Err(error) = result {
                    debug!(
                        "UPnP setup failed (non-fatal — node works without it): {}",
                        error
                    );
                }
            }
            _ = wait_for_shutdown(&mut shutdown) => {}
        }
    })
}

pub(super) fn spawn_padding_broadcast(
    shaper: Arc<TrafficShaper>,
    senders: Arc<DashMap<PeerId, mpsc::Sender<Vec<u8>>>>,
    magic: [u8; 4],
    shutdown: watch::Receiver<bool>,
) -> JoinHandle<()> {
    let mut shutdown_rx = shutdown;
    let shutdown = Arc::new(AtomicBool::new(false));
    tokio::spawn(async move {
        let padding_loop = shaper.run_padding_loop_broadcast(
            magic,
            move || {
                senders
                    .iter()
                    .map(|entry| entry.value().clone())
                    .collect::<Vec<_>>()
            },
            shutdown.clone(),
        );
        tokio::pin!(padding_loop);

        tokio::select! {
            _ = &mut padding_loop => {}
            _ = wait_for_shutdown(&mut shutdown_rx) => {
                shutdown.store(true, Ordering::Relaxed);
            }
        }
    })
}

pub(super) struct MessageProcessorContext {
    pub peers: Arc<DashMap<PeerId, PeerInfo>>,
    pub dandelion: Arc<RwLock<DandelionRouter>>,
    pub sync: Arc<RwLock<ChainSync>>,
    pub event_tx: broadcast::Sender<NodeEvent>,
    pub senders: Arc<DashMap<PeerId, mpsc::Sender<Vec<u8>>>>,
    pub nonce: u64,
    pub chain: SharedBlockchain,
    pub mempool: SharedMempool,
    pub addresses: Arc<RwLock<AddressManager>>,
    pub scorer: Arc<RwLock<PeerScorer>>,
    pub tx_absence_cache: Arc<parking_lot::RwLock<TxAbsenceCache>>,
    pub relay_scores: Arc<RwLock<RelayScoreMap>>,
    pub magic: [u8; 4],
}

/// The processor exits as soon as the node runtime is cancelled or every
/// producer closes the channel.
pub(super) fn spawn_message_processor(
    mut msg_rx: mpsc::Receiver<PeerMessage>,
    context: MessageProcessorContext,
    mut shutdown: watch::Receiver<bool>,
) -> JoinHandle<()> {
    let MessageProcessorContext {
        peers: processor_peers,
        dandelion: processor_dandelion,
        sync: processor_sync,
        event_tx: processor_event_tx,
        senders: processor_senders,
        nonce: processor_nonce,
        chain: processor_chain,
        mempool: processor_mempool,
        addresses: processor_addresses,
        scorer: processor_scorer,
        tx_absence_cache: processor_tx_absence_cache,
        relay_scores: processor_relay_scores,
        magic,
    } = context;

    tokio::spawn(async move {
        // Phase D (audit fix): per-peer message rate tracking.
        // PeerMessageRateTracker was built (scoring.rs) but never wired.
        // This HashMap lives for the lifetime of the processor task and
        // tracks each peer's per-message-type rate. When a peer exceeds
        // the configured limit, they get a MessageFlood misbehavior score.
        //
        // P5-N3 SURGICAL FIX (2026-07-03): the pre-fix HashMap grew
        // WITHOUT BOUND — entries were inserted on first message per
        // peer but never removed when peers disconnected. Over a
        // long-running node with churn, this leaked memory. Now we
        // prune every 1000 messages by dropping any tracker whose
        // peer_id is no longer in `processor_peers`. Cheap: 1000-msg
        // cadence keeps the O(N) sweep amortized to a few µs per
        // message.
        let mut rate_trackers: std::collections::HashMap<
            super::super::peer::PeerId,
            super::super::scoring::PeerMessageRateTracker,
        > = std::collections::HashMap::new();
        let mut rate_prune_ctr: u64 = 0;
        const RATE_PRUNE_EVERY: u64 = 1000;

        loop {
            let received = tokio::select! {
                biased;
                _ = wait_for_shutdown(&mut shutdown) => break,
                received = msg_rx.recv() => received,
            };
            match received {
                Some(msg) => {
                    // P5-N3: periodic prune of dead peers.
                    rate_prune_ctr = rate_prune_ctr.wrapping_add(1);
                    if rate_prune_ctr.is_multiple_of(RATE_PRUNE_EVERY) {
                        rate_trackers.retain(|pid, _| processor_peers.contains_key(pid));
                    }
                    // Rate-limit check (before expensive processing)
                    let tracker = rate_trackers
                        .entry(msg.peer_id)
                        .or_insert_with(super::super::scoring::PeerMessageRateTracker::new);
                    if tracker.record(msg.msg_type) {
                        warn!(
                            "Peer {:?} exceeded message rate limit for type 0x{:02x}, penalizing",
                            &msg.peer_id[..4],
                            msg.msg_type,
                        );
                        if let Some(peer_addr) = processor_peers.get(&msg.peer_id).map(|p| p.addr) {
                            let mut scorer = processor_scorer.write().await;
                            scorer.get_or_create(peer_addr).record_misbehavior(
                                super::super::scoring::MisbehaviorType::MessageFlood,
                            );
                        }
                        continue; // Drop the message and release its reservation
                    }

                    if let Err(e) = process_message(
                        msg.peer_id,
                        msg.msg_type,
                        &msg.payload,
                        magic,
                        processor_nonce,
                        processor_peers.as_ref(),
                        processor_senders.as_ref(),
                        processor_dandelion.as_ref(),
                        processor_sync.as_ref(),
                        &processor_event_tx,
                        &processor_chain,
                        &processor_mempool,
                        processor_addresses.as_ref(),
                        processor_scorer.as_ref(),
                        processor_tx_absence_cache.as_ref(),
                        processor_relay_scores.as_ref(),
                    )
                    .await
                    {
                        warn!("Message processing error: {}", e);
                    }
                }
                None => break,
            }
        }
    })
}
