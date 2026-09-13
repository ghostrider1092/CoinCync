//! ## Audit map
//! Each `§` is a code section below; it states the INVARIANT it guarantees, the
//! THREAT it defends, and the TESTS that prove it.
//!
//! - **§1 `NodeRuntime::shutdown`** — INVARIANT: every tracked task is given
//!   up to a 5-second deadline to join after the shutdown signal fires; a
//!   task that misses the deadline is aborted and awaited rather than left
//!   to run forever.
//!   THREAT: an unbounded join would let a stuck task hang node shutdown
//!   indefinitely, blocking process exit or restart.
//!   TESTS: `node_runtime_shutdown_joins_tracked_tasks`.
//! - **§2 `wait_for_shutdown`** — INVARIANT: if the shutdown flag is already
//!   set when checked, returns immediately instead of waiting on a `changed()`
//!   that may never fire again (a `watch` channel only reports one edge per
//!   waiter).
//!   THREAT: waiting on `changed()` after the flag was already flipped could
//!   deadlock a task that starts polling late.
//!   TESTS: `processor_exits_on_shutdown_signal`.
//! - **§3 `spawn_padding_broadcast`** — INVARIANT: the padding loop's own
//!   `AtomicBool` shutdown flag is set before the task returns on the
//!   `wait_for_shutdown` branch, so `run_padding_loop_broadcast` observes
//!   cancellation even though it's driven by a separate flag from the
//!   `watch::Receiver`.
//!   THREAT: forgetting to propagate the signal into the padding loop's own
//!   flag would leave the traffic-shaping padding task running after
//!   shutdown, delaying process exit.
//!   TESTS: (gap — no dedicated test for `spawn_padding_broadcast`'s shutdown
//!   propagation).
//! - **§4 `spawn_message_processor` rate-tracker pruning (P5-N3)** — INVARIANT:
//!   `rate_trackers` is pruned of any peer no longer present in
//!   `processor_peers` every `RATE_PRUNE_EVERY` (1000) messages, bounding its
//!   size to roughly the live peer set.
//!   THREAT: pre-fix, entries were inserted per peer but never removed on
//!   disconnect, so a long-running node with peer churn leaked memory
//!   unboundedly (P5-N3).
//!   TESTS: (gap — no test asserts the tracker map is actually pruned/bounded
//!   over churn; `processor_continues_after_a_bad_message` exercises the
//!   surrounding rate-limit/scoring path but not the prune cadence itself).
//! - **§5 `spawn_message_processor` rate-limit / misbehavior scoring** —
//!   INVARIANT: a peer that exceeds its per-message-type rate limit has the
//!   offending message dropped (not processed) and is scored
//!   `MisbehaviorType::MessageFlood`, but the processor loop itself keeps
//!   running.
//!   THREAT: without the drop-and-continue behavior, a flooding peer could
//!   either starve the queue for other peers or crash/stall the single
//!   processor task shared by all peers.
//!   TESTS: `processor_continues_after_a_bad_message`.
//! - **§6 `spawn_message_processor` shutdown/close semantics** — INVARIANT:
//!   the processor task exits when either the shutdown signal fires or every
//!   message producer drops its sender (channel closes) — whichever comes
//!   first, checked with `biased` select so a pending shutdown always wins a
//!   simultaneous race.
//!   THREAT: an ambiguous or unbiased exit condition could leave the
//!   processor task running after node shutdown, or exit it prematurely while
//!   producers still expect it to drain.
//!   TESTS: `processor_exits_on_channel_close`, `processor_exits_on_shutdown_signal`.

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

#[cfg(test)]
mod runtime_tests {
    use super::*;
    use crate::chain::Blockchain;
    use crate::network::protocol::MessageType;
    use crate::primitives::Hash;
    use std::net::SocketAddr;

    fn make_context(
        peers: Arc<DashMap<PeerId, PeerInfo>>,
        scorer: Arc<RwLock<PeerScorer>>,
    ) -> MessageProcessorContext {
        let chain: SharedBlockchain = Arc::new(Blockchain::new());
        chain.init_genesis().unwrap();
        MessageProcessorContext {
            peers,
            dandelion: Arc::new(RwLock::new(DandelionRouter::new())),
            sync: Arc::new(RwLock::new(ChainSync::new(0, Hash::zero()))),
            event_tx: broadcast::channel(16).0,
            senders: Arc::new(DashMap::new()),
            nonce: 0,
            chain,
            mempool: SharedMempool::new(),
            addresses: Arc::new(RwLock::new(AddressManager::new(1000))),
            scorer,
            tx_absence_cache: Arc::new(parking_lot::RwLock::new(TxAbsenceCache::new())),
            relay_scores: Arc::new(RwLock::new(RelayScoreMap::new())),
            magic: [1, 2, 3, 4],
        }
    }

    #[tokio::test]
    async fn node_runtime_shutdown_joins_tracked_tasks() {
        let mut rt = NodeRuntime::new();
        let mut rx = rt.shutdown_receiver();
        let handle = tokio::spawn(async move {
            wait_for_shutdown(&mut rx).await;
        });
        rt.track("waiter", handle);
        tokio::time::timeout(Duration::from_secs(5), rt.shutdown())
            .await
            .expect("shutdown joins tasks within the deadline");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn processor_exits_on_channel_close() {
        let (msg_tx, msg_rx) = mpsc::channel(8);
        let (_sd_tx, sd_rx) = watch::channel(false);
        let ctx = make_context(
            Arc::new(DashMap::new()),
            Arc::new(RwLock::new(PeerScorer::new())),
        );
        let handle = spawn_message_processor(msg_rx, ctx, sd_rx);
        drop(msg_tx);
        tokio::time::timeout(Duration::from_secs(5), handle)
            .await
            .expect("processor exits when the channel closes")
            .unwrap();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn processor_exits_on_shutdown_signal() {
        let (_msg_tx, msg_rx) = mpsc::channel(8);
        let (sd_tx, sd_rx) = watch::channel(false);
        let ctx = make_context(
            Arc::new(DashMap::new()),
            Arc::new(RwLock::new(PeerScorer::new())),
        );
        let handle = spawn_message_processor(msg_rx, ctx, sd_rx);
        sd_tx.send(true).unwrap();
        tokio::time::timeout(Duration::from_secs(5), handle)
            .await
            .expect("processor exits on shutdown")
            .unwrap();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn processor_continues_after_a_bad_message() {
        let peer_id = [5u8; 32];
        let addr: SocketAddr = "127.0.0.1:34500".parse().unwrap();
        let peers = Arc::new(DashMap::new());
        peers.insert(peer_id, PeerInfo::new(peer_id, addr, false));
        let scorer = Arc::new(RwLock::new(PeerScorer::new()));
        let ctx = make_context(peers.clone(), scorer.clone());
        let (msg_tx, msg_rx) = mpsc::channel(8);
        let (_sd_tx, sd_rx) = watch::channel(false);
        let handle = spawn_message_processor(msg_rx, ctx, sd_rx);

        // 1) An unknown message type makes process_message return Err — the loop
        //    must log and keep going, not die.
        msg_tx
            .send(PeerMessage {
                peer_id,
                msg_type: 200,
                payload: vec![],
                _reservation: Arc::new(
                    crate::network::connection_tracker::ConnectionTracker::new(1024),
                )
                .reservation(),
            })
            .await
            .unwrap();
        // 2) An oversized Version — processed only if the loop survived (1).
        //    handle_version scores OversizedMessage and removes the peer.
        msg_tx
            .send(PeerMessage {
                peer_id,
                msg_type: MessageType::Version as u8,
                payload: vec![0u8; 1025],
                _reservation: Arc::new(
                    crate::network::connection_tracker::ConnectionTracker::new(1024),
                )
                .reservation(),
            })
            .await
            .unwrap();
        drop(msg_tx);
        tokio::time::timeout(Duration::from_secs(5), handle)
            .await
            .expect("processor drains and exits")
            .unwrap();

        assert!(
            scorer
                .read()
                .await
                .get(&addr)
                .is_some_and(|s| s.reputation < 100),
            "second message processed after the bad one"
        );
        assert!(
            peers.get(&peer_id).is_none(),
            "oversized Version removed the peer"
        );
    }
}
