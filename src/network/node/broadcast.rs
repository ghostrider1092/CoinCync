use std::sync::atomic::Ordering;

use dashmap::DashMap;
use tokio::sync::{broadcast as event_broadcast, mpsc, RwLock};
use tracing::warn;

use crate::chain::SharedBlockchain;
use crate::consensus::Block;
use crate::error::{Error, Result};
use crate::network::connection_tracker::ConnectionTracker;
use crate::network::dandelion::DandelionRouter;
use crate::network::peer::{PeerId, PeerInfo};
use crate::network::protocol::Message;
use crate::network::scoring::{OrphanFloodTracker, PeerScorer};
use crate::network::sync::ChainSync;
use crate::network::traffic_shaping::TrafficShaper;
use crate::primitives::Hash;
use crate::transaction::Transaction;

use super::peer_manager::{self, BanPeerContext, DisconnectPeerContext};
use super::types::NodeEvent;

const STALL_THRESHOLD: u32 = 30;

/// State used only by the best-effort broadcast path and its peer cleanup.
pub(super) struct BroadcastContext<'a> {
    pub traffic_shaper: &'a TrafficShaper,
    pub peers: &'a DashMap<PeerId, PeerInfo>,
    pub senders: &'a DashMap<PeerId, mpsc::Sender<Vec<u8>>>,
    pub tracker: &'a ConnectionTracker,
    pub scorer: &'a RwLock<PeerScorer>,
    pub dandelion: &'a RwLock<DandelionRouter>,
    pub sync: &'a RwLock<ChainSync>,
    pub orphan_flood: &'a RwLock<OrphanFloodTracker>,
    pub event_tx: &'a event_broadcast::Sender<NodeEvent>,
}

impl BroadcastContext<'_> {
    fn ban_context(&self) -> BanPeerContext<'_> {
        BanPeerContext {
            peers: self.peers,
            senders: self.senders,
            tracker: self.tracker,
            scorer: self.scorer,
            dandelion: self.dandelion,
            orphan_flood: self.orphan_flood,
            event_tx: self.event_tx,
        }
    }

    fn disconnect_context(&self) -> DisconnectPeerContext<'_> {
        DisconnectPeerContext {
            peers: self.peers,
            senders: self.senders,
            tracker: self.tracker,
            dandelion: self.dandelion,
            sync: self.sync,
            event_tx: self.event_tx,
        }
    }
}

pub(super) async fn queue_transaction(
    dandelion: &RwLock<DandelionRouter>,
    tx: Transaction,
) -> Hash {
    let now = chrono::Utc::now().timestamp() as u64;
    dandelion.write().await.add_local_tx(tx, now)
}

pub(super) async fn broadcast_block(
    magic: [u8; 4],
    block: &Block,
    context: &BroadcastContext<'_>,
) -> Result<()> {
    broadcast_inv_block(magic, block.hash(), context).await
}

#[allow(dead_code)]
pub(super) async fn broadcast_inv_tx(
    magic: [u8; 4],
    hash: Hash,
    context: &BroadcastContext<'_>,
) -> Result<()> {
    let data = Message::inv_tx(magic, hash)?.to_bytes()?;
    broadcast_raw(data, context).await
}

async fn broadcast_inv_block(
    magic: [u8; 4],
    hash: Hash,
    context: &BroadcastContext<'_>,
) -> Result<()> {
    let data = Message::inv_block(magic, hash)?.to_bytes()?;
    broadcast_raw(data, context).await
}

/// Advertise the current cumulative chain work to CAP_CHAINWORK peers.
pub(super) fn announce_chain_work(
    chain: &SharedBlockchain,
    magic: [u8; 4],
    peers: &DashMap<PeerId, PeerInfo>,
    senders: &DashMap<PeerId, mpsc::Sender<Vec<u8>>>,
) {
    use crate::network::firework::{has_cap, CAP_CHAINWORK};

    let stats = chain.stats();
    let data = match Message::chain_work(
        magic,
        stats.total_difficulty,
        chain.height(),
        chain.tip_hash(),
    )
    .and_then(|message| message.to_bytes())
    {
        Ok(bytes) => bytes,
        Err(error) => {
            warn!(
                "announce_chain_work: failed to build/encode ChainWork: {}",
                error
            );
            return;
        }
    };

    let capable: Vec<PeerId> = peers
        .iter()
        .filter(|entry| has_cap(entry.value().capabilities, CAP_CHAINWORK))
        .map(|entry| *entry.key())
        .collect();
    for peer_id in capable {
        if let Some(sender) = peer_sender(senders, &peer_id) {
            // A congested peer receives the next tip advertisement instead.
            let _ = sender.try_send(data.clone());
        }
    }
}

/// Broadcast without allowing one bounded peer queue to stall all peers.
async fn broadcast_raw(data: Vec<u8>, context: &BroadcastContext<'_>) -> Result<()> {
    context.traffic_shaper.apply_jitter().await;

    let mut sent = 0usize;
    let mut full = 0usize;
    let mut closed = 0usize;
    let mut to_ban = Vec::new();
    let mut to_remove_closed = Vec::new();

    // No await occurs while a DashMap iterator or entry guard is live.
    for entry in context.senders.iter() {
        let peer_id = *entry.key();
        match entry.value().try_send(data.clone()) {
            Ok(()) => {
                sent += 1;
                if let Some(peer) = context.peers.get(&peer_id) {
                    peer.consecutive_full.store(0, Ordering::Relaxed);
                }
            }
            Err(mpsc::error::TrySendError::Full(_)) => {
                full += 1;
                let count = context
                    .peers
                    .get(&peer_id)
                    .map(|peer| peer.consecutive_full.fetch_add(1, Ordering::Relaxed) + 1)
                    .unwrap_or(0);
                if count >= STALL_THRESHOLD {
                    to_ban.push((peer_id, count));
                }
                tracing::trace!(
                    peer_id = ?peer_id,
                    consecutive_full = count,
                    "broadcast_raw: peer channel full, dropping (peer will catch up via IBD)"
                );
            }
            Err(mpsc::error::TrySendError::Closed(_)) => {
                closed += 1;
                to_remove_closed.push(peer_id);
                tracing::trace!(
                    peer_id = ?peer_id,
                    "broadcast_raw: peer channel closed (peer disconnected) - cleaning up"
                );
            }
        }
    }

    if full > 0 || closed > 0 {
        tracing::warn!(sent, full, closed, "broadcast_raw partial delivery");
    }

    for (peer_id, count) in to_ban {
        tracing::warn!(
            peer_id = %hex::encode(&peer_id[..8]),
            consecutive_full = count,
            "broadcast_raw: disconnecting chronic-slow peer (channel full {count} consecutive sends)"
        );
        if let Some(peer) = context.peers.get(&peer_id) {
            let addr = peer.addr;
            drop(peer);
            context
                .scorer
                .write()
                .await
                .get_or_create(addr)
                .record_misbehavior(crate::network::scoring::MisbehaviorType::ChronicSendQueueFull);
        }
        peer_manager::ban_peer(&peer_id, context.ban_context()).await;
    }

    if !to_remove_closed.is_empty() {
        let count = to_remove_closed.len();
        for peer_id in &to_remove_closed {
            peer_manager::disconnect_peer(peer_id, context.disconnect_context()).await;
        }
        tracing::info!(
            cleaned = count,
            "broadcast_raw: cleaned up {} closed-channel peer(s) (sync-stall fix)",
            count
        );
    }

    Ok(())
}

fn peer_sender(
    senders: &DashMap<PeerId, mpsc::Sender<Vec<u8>>>,
    peer_id: &PeerId,
) -> Option<mpsc::Sender<Vec<u8>>> {
    senders.get(peer_id).map(|entry| entry.value().clone())
}

/// Send without holding the DashMap shard across the bounded-channel await.
pub(super) async fn send_to_peer(
    senders: &DashMap<PeerId, mpsc::Sender<Vec<u8>>>,
    peer_id: &PeerId,
    data: Vec<u8>,
) -> bool {
    match peer_sender(senders, peer_id) {
        Some(sender) => sender.send(data).await.is_ok(),
        None => false,
    }
}

pub(super) async fn send_to(
    senders: &DashMap<PeerId, mpsc::Sender<Vec<u8>>>,
    peer_id: &PeerId,
    data: Vec<u8>,
) -> Result<()> {
    if let Some(sender) = peer_sender(senders, peer_id) {
        sender
            .send(data)
            .await
            .map_err(|_| Error::ConnectionFailed("peer disconnected".into()))?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::time::Duration;

    use super::*;

    #[tokio::test]
    async fn send_to_peer_returns_true_when_send_succeeds() {
        let senders = DashMap::new();
        let (tx, mut rx) = mpsc::channel::<Vec<u8>>(4);
        let peer_id = [1u8; 32];
        senders.insert(peer_id, tx);

        assert!(send_to_peer(&senders, &peer_id, vec![0xAA, 0xBB]).await);
        assert_eq!(rx.recv().await, Some(vec![0xAA, 0xBB]));
    }

    #[tokio::test]
    async fn send_to_peer_returns_false_when_peer_missing() {
        let senders = DashMap::new();
        let peer_id = [7u8; 32];

        assert!(!send_to_peer(&senders, &peer_id, vec![0]).await);
    }

    #[tokio::test]
    async fn send_to_peer_returns_false_when_channel_closed() {
        let senders = DashMap::new();
        let (tx, rx) = mpsc::channel::<Vec<u8>>(1);
        let peer_id = [3u8; 32];
        senders.insert(peer_id, tx);
        drop(rx);

        assert!(!send_to_peer(&senders, &peer_id, vec![0]).await);
    }

    #[tokio::test]
    async fn send_to_preserves_missing_and_closed_peer_contracts() {
        let senders = DashMap::new();
        let missing = [5u8; 32];
        assert!(send_to(&senders, &missing, vec![0]).await.is_ok());

        let closed = [6u8; 32];
        let (tx, rx) = mpsc::channel(1);
        senders.insert(closed, tx);
        drop(rx);
        assert!(matches!(
            send_to(&senders, &closed, vec![0]).await,
            Err(Error::ConnectionFailed(_))
        ));
    }

    /// A send parked on channel capacity must not retain a DashMap shard lock.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn send_to_peer_does_not_block_dashmap_insert_on_full_channel() {
        let senders = Arc::new(DashMap::new());
        let (tx, mut rx) = mpsc::channel::<Vec<u8>>(1);
        let slow_peer = [9u8; 32];
        senders.insert(slow_peer, tx.clone());
        tx.send(vec![0]).await.unwrap();

        let senders_for_task = Arc::clone(&senders);
        let send_task = tokio::spawn(async move {
            send_to_peer(&senders_for_task, &slow_peer, vec![1, 2, 3]).await
        });
        tokio::time::sleep(Duration::from_millis(20)).await;

        let (other_tx, _other_rx) = mpsc::channel::<Vec<u8>>(1);
        let started = std::time::Instant::now();
        senders.insert([42u8; 32], other_tx);
        assert!(
            started.elapsed() < Duration::from_millis(500),
            "DashMap insert blocked while send_to_peer awaited capacity"
        );

        let _ = rx.recv().await;
        tokio::time::timeout(Duration::from_secs(1), send_task)
            .await
            .expect("send task must finish after capacity is available")
            .unwrap();
    }

    #[tokio::test]
    async fn full_peer_queue_does_not_block_other_broadcast_delivery() {
        let shaper = TrafficShaper::default_enabled();
        shaper.set_enabled(false);
        let peers = DashMap::new();
        let senders = DashMap::new();
        let slow_peer = [11u8; 32];
        let fast_peer = [12u8; 32];
        peers.insert(
            slow_peer,
            PeerInfo::new(slow_peer, "127.0.0.1:11001".parse().unwrap(), true),
        );
        peers.insert(
            fast_peer,
            PeerInfo::new(fast_peer, "127.0.0.1:11002".parse().unwrap(), true),
        );

        let (slow_tx, mut slow_rx) = mpsc::channel(1);
        let (fast_tx, mut fast_rx) = mpsc::channel(1);
        slow_tx.send(vec![0]).await.unwrap();
        senders.insert(slow_peer, slow_tx);
        senders.insert(fast_peer, fast_tx);

        let tracker = ConnectionTracker::new(1024);
        let scorer = RwLock::new(PeerScorer::new());
        let dandelion = RwLock::new(DandelionRouter::new());
        let sync = RwLock::new(ChainSync::new(0, Hash::zero()));
        let orphan_flood = RwLock::new(OrphanFloodTracker::new());
        let (event_tx, _) = event_broadcast::channel(4);
        let context = BroadcastContext {
            traffic_shaper: &shaper,
            peers: &peers,
            senders: &senders,
            tracker: &tracker,
            scorer: &scorer,
            dandelion: &dandelion,
            sync: &sync,
            orphan_flood: &orphan_flood,
            event_tx: &event_tx,
        };

        broadcast_raw(vec![9], &context).await.unwrap();

        assert_eq!(fast_rx.recv().await, Some(vec![9]));
        assert_eq!(slow_rx.recv().await, Some(vec![0]));
        assert_eq!(
            peers
                .get(&slow_peer)
                .unwrap()
                .consecutive_full
                .load(Ordering::Relaxed),
            1
        );
    }
}
