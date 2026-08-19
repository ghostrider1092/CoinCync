use dashmap::DashMap;
use parking_lot::RwLock as ParkingRwLock;
use tokio::sync::{broadcast, mpsc, RwLock};
use tracing::{debug, warn};

use crate::error::Result;
use crate::mempool::SharedMempool;
use crate::network::dandelion::{DandelionRouter, StemAction};
use crate::network::peer::{PeerId, PeerInfo};
use crate::network::protocol::{GetBlocksMessage, InvMessage, Message, MessageType};
use crate::network::scoring::PeerScorer;

use super::super::broadcast::send_to_peer;
use super::super::types::NodeEvent;
use super::super::TxAbsenceCache;

pub(super) async fn handle_inv_tx(
    peer_id: PeerId,
    payload: &[u8],
    magic: [u8; 4],
    peers: &DashMap<PeerId, PeerInfo>,
    senders: &DashMap<PeerId, mpsc::Sender<Vec<u8>>>,
    mempool: &SharedMempool,
    scorer: &RwLock<PeerScorer>,
    tx_absence_cache: &ParkingRwLock<TxAbsenceCache>,
) -> Result<()> {
    // Transaction inventory - request txs we don't have.
    // P5-N8 + P5-N-CLASS-A fix: tight size cap + score borsh Err.
    if payload.len() > crate::network::protocol::MAX_INV_PAYLOAD {
        warn!("InvTx message too large from peer {:?}", &peer_id[..4]);
        if let Some(addr) = peers.get(&peer_id).map(|p| p.addr) {
            scorer
                .write()
                .await
                .get_or_create(addr)
                .record_misbehavior(crate::network::scoring::MisbehaviorType::OversizedMessage);
        }
        return Ok(());
    }
    match borsh::from_slice::<InvMessage>(payload) {
        Ok(inv_msg) => {
            if let Err(e) = inv_msg.validate() {
                warn!("Invalid InvTx from peer {:?}: {}", &peer_id[..4], e);
                if let Some(addr) = peers.get(&peer_id).map(|p| p.addr) {
                    scorer.write().await.get_or_create(addr).record_misbehavior(
                        crate::network::scoring::MisbehaviorType::ProtocolViolation,
                    );
                }
                return Ok(());
            }
            let mut needed = Vec::new();
            {
                // v1.0.13 #2 — single read-lock to filter both
                // mempool presence AND tx-absence cache (so we
                // don't re-request hashes a peer recently said
                // they don't have).
                let absence = tx_absence_cache.read();
                for inv in &inv_msg.inventory {
                    // N-1: absence is scoped to THIS peer — a NotFound from some
                    // other peer must not stop us fetching what this peer offers.
                    if !mempool.contains(&inv.hash)
                        && !absence.is_known_absent(&peer_id, &inv.hash)
                    {
                        needed.push(inv.hash);
                    }
                }
            }
            // Request missing transactions via GetTxs
            if !needed.is_empty() {
                // Reuse GetBlocksMessage format for tx hashes
                let get_msg = GetBlocksMessage { hashes: needed };
                if let Ok(payload_bytes) = borsh::to_vec(&get_msg) {
                    let msg = Message::new(magic, MessageType::GetTxs, payload_bytes);
                    let _ = send_to_peer(senders, &peer_id, msg.to_bytes()?).await;
                }
            }
        }
        Err(e) => {
            // P5-N7 fix: score borsh parse failure.
            warn!(
                "Failed to deserialize InvTx from peer {:?}: {}",
                &peer_id[..4],
                e
            );
            if let Some(addr) = peers.get(&peer_id).map(|p| p.addr) {
                scorer.write().await.get_or_create(addr).record_misbehavior(
                    crate::network::scoring::MisbehaviorType::ProtocolViolation,
                );
            }
        }
    }
    Ok(())
}

pub(super) async fn handle_not_found(
    peer_id: PeerId,
    payload: &[u8],
    peers: &DashMap<PeerId, PeerInfo>,
    scorer: &RwLock<PeerScorer>,
    tx_absence_cache: &ParkingRwLock<TxAbsenceCache>,
) -> Result<()> {
    // v1.0.13 #2 — peer told us they don't have a set of
    // hashes we asked for. Mark each in the absence cache
    // so the InvTx handler skips re-requesting them via
    // GetTxs for the TTL window (60s).
    if payload.len() > crate::network::protocol::MAX_MESSAGE_SIZE {
        warn!("NotFound message too large from peer {:?}", &peer_id[..4]);
        if let Some(addr) = peers.get(&peer_id).map(|p| p.addr) {
            scorer
                .write()
                .await
                .get_or_create(addr)
                .record_misbehavior(crate::network::scoring::MisbehaviorType::OversizedMessage);
        }
        return Ok(());
    }
    if let Ok(nf) = borsh::from_slice::<crate::network::protocol::NotFoundMessage>(payload) {
        if let Err(e) = nf.validate() {
            warn!("Invalid NotFound from peer {:?}: {}", &peer_id[..4], e);
            if let Some(addr) = peers.get(&peer_id).map(|p| p.addr) {
                scorer.write().await.get_or_create(addr).record_misbehavior(
                    crate::network::scoring::MisbehaviorType::ProtocolViolation,
                );
            }
            return Ok(());
        }
        let n = nf.hashes.len();
        {
            let mut cache = tx_absence_cache.write();
            for h in nf.hashes {
                // N-1: record absence scoped to the peer that reported it, so an
                // unsolicited NotFound spray cannot suppress relay from others.
                cache.mark_absent(peer_id, h);
            }
        }
        debug!(
            "NotFound from peer {:?}: cached {} absent tx hash(es)",
            &peer_id[..4],
            n
        );
    }
    Ok(())
}

pub(super) async fn handle_get_txs(
    peer_id: PeerId,
    payload: &[u8],
    magic: [u8; 4],
    peers: &DashMap<PeerId, PeerInfo>,
    senders: &DashMap<PeerId, mpsc::Sender<Vec<u8>>>,
    mempool: &SharedMempool,
    scorer: &RwLock<PeerScorer>,
) -> Result<()> {
    // Peer is requesting transactions by hash.
    // P5-N-CLASS-A fix: tight per-type cap.
    if payload.len() > crate::network::protocol::MAX_GETTXS_PAYLOAD {
        warn!("GetTxs message too large from peer {:?}", &peer_id[..4]);
        if let Some(addr) = peers.get(&peer_id).map(|p| p.addr) {
            scorer
                .write()
                .await
                .get_or_create(addr)
                .record_misbehavior(crate::network::scoring::MisbehaviorType::OversizedMessage);
        }
        return Ok(());
    }
    // P5-N7 fix: match with Err scoring instead of silent-Ok.
    match borsh::from_slice::<GetBlocksMessage>(payload) {
        Ok(msg) => {
            if let Err(e) = msg.validate() {
                warn!("Invalid GetTxs from peer {:?}: {}", &peer_id[..4], e);
                if let Some(addr) = peers.get(&peer_id).map(|p| p.addr) {
                    scorer.write().await.get_or_create(addr).record_misbehavior(
                        crate::network::scoring::MisbehaviorType::ProtocolViolation,
                    );
                }
                return Ok(());
            }
            let mut txs = Vec::new();
            // Explicit misses prevent peers from repeatedly requesting absent data.
            let mut absent = Vec::new();
            for hash in &msg.hashes {
                if let Some(tx) = mempool.get(hash) {
                    txs.push(tx);
                } else {
                    absent.push(*hash);
                }
            }
            if !txs.is_empty() {
                if let Ok(resp) = Message::txs(magic, txs) {
                    let _ = send_to_peer(senders, &peer_id, resp.to_bytes()?).await;
                }
            }
            if !absent.is_empty() {
                if let Ok(resp) = Message::not_found(magic, absent) {
                    let _ = send_to_peer(senders, &peer_id, resp.to_bytes()?).await;
                }
            }
        }
        Err(e) => {
            warn!(
                "Failed to deserialize GetTxs from peer {:?}: {}",
                &peer_id[..4],
                e
            );
            if let Some(addr) = peers.get(&peer_id).map(|p| p.addr) {
                scorer.write().await.get_or_create(addr).record_misbehavior(
                    crate::network::scoring::MisbehaviorType::ProtocolViolation,
                );
            }
        }
    }
    Ok(())
}

pub(super) async fn handle_txs(
    peer_id: PeerId,
    payload: &[u8],
    magic: [u8; 4],
    peers: &DashMap<PeerId, PeerInfo>,
    senders: &DashMap<PeerId, mpsc::Sender<Vec<u8>>>,
    dandelion: &RwLock<DandelionRouter>,
    event_tx: &broadcast::Sender<NodeEvent>,
    scorer: &RwLock<PeerScorer>,
) -> Result<()> {
    // Bound deserialization work and classify excess volume separately from malformed data.
    if payload.len() > crate::network::protocol::MAX_MESSAGE_SIZE {
        warn!(
            "Txs message too large from peer {}",
            hex::encode(&peer_id[..8])
        );
        if let Some(addr) = peers.get(&peer_id).map(|p| p.addr) {
            scorer
                .write()
                .await
                .get_or_create(addr)
                .record_misbehavior(crate::network::scoring::MisbehaviorType::OversizedMessage);
        }
        return Ok(());
    }
    // Parse transactions.
    // P5-N7 fix: match with Err scoring.
    match borsh::from_slice::<crate::network::protocol::TxsMessage>(payload) {
        Ok(txs_msg) => {
            // SECURITY: Validate message before processing
            if let Err(e) = txs_msg.validate() {
                warn!(
                    "Invalid TxsMessage from peer {}: {}",
                    hex::encode(&peer_id[..8]),
                    e
                );
                if let Some(addr) = peers.get(&peer_id).map(|p| p.addr) {
                    scorer.write().await.get_or_create(addr).record_invalid_tx();
                }
                return Ok(());
            }
            for tx in txs_msg.transactions {
                // SECURITY: Quick-validate transaction structure before relay.
                // Prevents garbage txs from consuming CPU across the network.
                if let Err(e) = crate::consensus::validate_transaction_basic(&tx) {
                    let reason = e.to_string();
                    warn!(
                        "Rejecting invalid tx from peer {}: {}",
                        hex::encode(&peer_id[..8]),
                        reason
                    );
                    if let Some(addr) = peers.get(&peer_id).map(|p| p.addr) {
                        // Score using the unified MisbehaviorType ladder
                        // (InvalidTransaction = 25 pts, 2-3 offenses → ban).
                        // The previous `record_invalid_tx()` path only
                        // deducted 5 pts, requiring ~10 strikes to ban.
                        // Active disconnect is handled by the maintenance
                        // loop's `auto_ban_bad_peers()` maintenance tick
                        // (within ~10s of crossing the ban threshold).
                        let offense = crate::network::scoring::classify_invalid_tx_reason(&reason);
                        let mut s = scorer.write().await;
                        let score = s.get_or_create(addr);
                        score.record_misbehavior(offense);
                        // Keep legacy counter in sync for stats/reporting.
                        score.invalid_txs += 1;
                    }
                    continue;
                }
                if let Some(addr) = peers.get(&peer_id).map(|p| p.addr) {
                    scorer.write().await.get_or_create(addr).record_tx_success();
                }
                // Route through Dandelion++ (stem/fluff/ignore)
                let now = super::unix_now();
                let action = dandelion
                    .write()
                    .await
                    .add_received_tx(tx.clone(), peer_id, now);
                match action {
                    StemAction::Fluff(fluff_tx) => {
                        // Fluff epoch or loop detected — broadcast to all peers
                        if let Ok(msg) = Message::inv_tx(magic, fluff_tx.hash()) {
                            if let Ok(data) = msg.to_bytes() {
                                // Snapshot first so an awaited send never holds a DashMap guard.
                                let senders_snapshot: Vec<tokio::sync::mpsc::Sender<Vec<u8>>> =
                                    senders.iter().map(|s| s.value().clone()).collect();
                                for sender in senders_snapshot {
                                    let _ = sender.send(data.clone()).await;
                                }
                            }
                        }
                        // Immediate-fluff (loop detection or fluff epoch).
                        // `peer_id` is the peer that just relayed this tx
                        // to us — they're the responsible party if mempool
                        // admit fails on full-crypto validation.
                        let _ =
                            event_tx.send(NodeEvent::TransactionReceived(fluff_tx, Some(peer_id)));
                    }
                    StemAction::Stem => {
                        // Stem mode: tx is in stempool, will be relayed by tick()
                        // Do NOT add to local mempool — that would defeat Dandelion++ privacy.
                        // The tx will enter the mempool only when it is fluffed.
                    }
                    StemAction::Ignore => {
                        // Already known — skip
                    }
                }
            }
        }
        Err(e) => {
            warn!(
                "Failed to deserialize TxsMessage from peer {}: {}",
                hex::encode(&peer_id[..8]),
                e
            );
            if let Some(addr) = peers.get(&peer_id).map(|p| p.addr) {
                // F2 fix: migrate to unified record_misbehavior for
                // consistent observability. Borsh decode failure is
                // a genuine ProtocolViolation.
                scorer.write().await.get_or_create(addr).record_misbehavior(
                    crate::network::scoring::MisbehaviorType::ProtocolViolation,
                );
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::primitives::Amount;
    use crate::transaction::{Transaction, TxType};
    use std::net::SocketAddr;

    #[tokio::test]
    async fn invalid_transactions_are_not_credited_as_successful_relays() {
        let peer_id = [7; 32];
        let addr: SocketAddr = "127.0.0.1:28080".parse().unwrap();
        let peers = DashMap::new();
        peers.insert(peer_id, PeerInfo::new(peer_id, addr, false));
        let senders = DashMap::new();
        let dandelion = RwLock::new(DandelionRouter::new());
        let (event_tx, mut event_rx) = broadcast::channel(4);
        let scorer = RwLock::new(PeerScorer::new());
        let invalid = Transaction {
            version: 0,
            tx_type: TxType::Transfer,
            inputs: Vec::new(),
            outputs: Vec::new(),
            fee: Amount::ZERO,
            range_proof: Vec::new(),
            extra: Vec::new(),
        };
        let payload = borsh::to_vec(&crate::network::protocol::TxsMessage {
            transactions: vec![invalid],
        })
        .unwrap();

        handle_txs(
            peer_id,
            &payload,
            [1, 2, 3, 4],
            &peers,
            &senders,
            &dandelion,
            &event_tx,
            &scorer,
        )
        .await
        .unwrap();

        let guard = scorer.read().await;
        let score = guard.get(&addr).unwrap();
        assert_eq!(score.txs_relayed, 0);
        assert_eq!(score.invalid_txs, 1);
        assert!(matches!(
            event_rx.try_recv(),
            Err(broadcast::error::TryRecvError::Empty)
        ));
    }
}
