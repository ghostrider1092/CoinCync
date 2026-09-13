//! ## Audit map
//! Each `§` is a code section below; it states the INVARIANT it guarantees, the
//! THREAT it defends, and the TESTS that prove it.
//!
//! - **§1 `handle_inv_tx` (oversized payload gate)** — INVARIANT: an `InvTx`
//!   payload over `MAX_INV_PAYLOAD` is dropped and scored `OversizedMessage`
//!   before any borsh decode is attempted.
//!   THREAT: unbounded deserialization work from an oversized inventory
//!   message (P5-N8 / P5-N-CLASS-A).
//!   TESTS: (gap — no dedicated unit test for the oversized-payload branch of
//!   `handle_inv_tx` in this file).
//! - **§2 `handle_inv_tx` (per-peer absence scoping)** — INVARIANT: a
//!   tx-absence record is only consulted for the peer that reported it; one
//!   peer's `NotFound` never stops requesting the same hash from another peer.
//!   THREAT: an attacker suppressing network-wide tx propagation by claiming
//!   absence on hashes other peers actually have (N-1).
//!   TESTS: `handle_inv_tx_absence_is_scoped_per_peer`.
//! - **§3 `handle_not_found` (per-peer absence marking)** — INVARIANT:
//!   `NotFound` hashes are recorded as absent only against the reporting
//!   peer's id, never globally.
//!   THREAT: an unsolicited `NotFound` spray from one peer suppressing relay
//!   from honest peers.
//!   TESTS: `handle_not_found_marks_absence_per_peer_only`.
//! - **§4 `handle_get_txs`** — INVARIANT: every requested hash not present in
//!   the mempool is echoed back via an explicit `NotFound` response instead of
//!   silently omitted.
//!   THREAT: peers repeatedly re-requesting the same absent hashes, wasting
//!   bandwidth/CPU on both sides.
//!   TESTS: (gap — no dedicated unit test for `handle_get_txs` in this file).
//! - **§5 `handle_txs` (accept-then-relay validation gate)** — INVARIANT: a
//!   transaction is routed to Dandelion/relay only after it passes both the
//!   cheap structural check (`validate_transaction_basic`) and the full
//!   UTXO-backed `chain.validate_transaction`; a failure at either gate is
//!   scored and the tx is never relayed or credited as a successful relay.
//!   THREAT: a cryptographically forged (structurally valid) tx being fluffed
//!   to every peer before any node fully validates it — network-wide invalid
//!   tx amplification.
//!   TESTS: `invalid_transactions_are_not_credited_as_successful_relays`.
//! - **§6 `handle_txs` (Dandelion stem/fluff routing)** — INVARIANT: a
//!   `StemAction::Stem` result never inserts the tx into the local mempool;
//!   only `StemAction::Fluff` broadcasts an `InvTx` to all peers and emits
//!   `NodeEvent::TransactionReceived`.
//!   THREAT: a stem-phase tx entering the mempool prematurely, defeating
//!   Dandelion++ origin-hiding.
//!   TESTS: (gap — no unit test asserts the stem path leaves the mempool
//!   untouched).
//! - **§7 message-size gates (`handle_not_found`, `handle_get_txs`,
//!   `handle_txs`)** — INVARIANT: each handler rejects and scores payloads
//!   above its own size cap (`MAX_MESSAGE_SIZE` / `MAX_GETTXS_PAYLOAD`) before
//!   parsing.
//!   THREAT: unbounded borsh decode of an oversized wire message.
//!   TESTS: (gap — no dedicated unit test for the size-cap branches; only the
//!   downstream validation/scoring paths are covered above).

use dashmap::DashMap;
use parking_lot::RwLock as ParkingRwLock;
use tokio::sync::{broadcast, mpsc, RwLock};
use tracing::{debug, warn};

use crate::chain::SharedBlockchain;
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
    chain: &SharedBlockchain,
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

                // FULL validation BEFORE relay ("accept-then-relay"). The
                // structural gate above is cheap and does NOT verify ring
                // signatures, range proofs, or the balance proof (those need
                // the UTXO set). Without this gate a structurally-valid but
                // cryptographically-forged tx would be routed into Dandelion
                // and its INV broadcast to every peer on the fluff path BEFORE
                // any node fully validated it — network-wide amplification of
                // invalid txs. chain.validate_transaction runs the full
                // consensus validator against the live UTXO set WITHOUT
                // inserting into the mempool, so Dandelion stem privacy is
                // preserved (received txs still never enter our mempool on the
                // stem — see the StemAction::Stem arm below; the fluff path
                // admits via the NodeEvent consumer as before). The crypto is
                // CPU-heavy, so run it under block_in_place to keep the tokio
                // worker schedulable (same treatment server.rs gives this work).
                if let Err(e) = tokio::task::block_in_place(|| chain.validate_transaction(&tx)) {
                    let reason = e.to_string();
                    warn!(
                        "Rejecting invalid tx (full validation) from peer {}: {}",
                        hex::encode(&peer_id[..8]),
                        reason
                    );
                    if let Some(addr) = peers.get(&peer_id).map(|p| p.addr) {
                        // A peer that relayed a fully-invalid tx to us amplified
                        // it — score them on the same ladder as the structural
                        // rejection above.
                        let offense = crate::network::scoring::classify_invalid_tx_reason(&reason);
                        let mut s = scorer.write().await;
                        let score = s.get_or_create(addr);
                        score.record_misbehavior(offense);
                        score.invalid_txs += 1;
                    }
                    continue; // NOT relayed — the whole point of the fix
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
    use crate::chain::Blockchain;
    use crate::primitives::Amount;
    use crate::transaction::{Transaction, TxType};
    use std::net::SocketAddr;
    use std::sync::Arc;

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
        // A `version: 0` tx fails the cheap structural gate
        // (validate_transaction_basic) and short-circuits before the full
        // chain-validation gate, so an empty in-memory chain is sufficient
        // here — chain.validate_transaction is never reached on this input.
        let chain: SharedBlockchain = Arc::new(Blockchain::new());
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
            &chain,
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

    fn addr_for(port: u16) -> SocketAddr {
        format!("127.0.0.1:{port}").parse().unwrap()
    }

    #[tokio::test]
    async fn handle_inv_tx_absence_is_scoped_per_peer() {
        // N-1: peer A's NotFound (recorded absence) must NOT stop us fetching
        // the same hash when peer B advertises it.
        let peer_a = [1u8; 32];
        let peer_b = [2u8; 32];
        let peers = DashMap::new();
        peers.insert(peer_a, PeerInfo::new(peer_a, addr_for(32001), false));
        peers.insert(peer_b, PeerInfo::new(peer_b, addr_for(32002), false));
        let senders: DashMap<PeerId, mpsc::Sender<Vec<u8>>> = DashMap::new();
        let (tx_a, mut rx_a) = mpsc::channel::<Vec<u8>>(4);
        let (tx_b, mut rx_b) = mpsc::channel::<Vec<u8>>(4);
        senders.insert(peer_a, tx_a);
        senders.insert(peer_b, tx_b);
        let mempool = SharedMempool::new();
        let scorer = RwLock::new(PeerScorer::new());
        let cache = ParkingRwLock::new(TxAbsenceCache::new());

        let hash = crate::primitives::Hash::from_bytes([7; 32]);
        cache.write().mark_absent(peer_a, hash);

        let inv = InvMessage {
            inventory: vec![crate::network::protocol::InvVector {
                inv_type: 0,
                hash,
            }],
        };
        let payload = borsh::to_vec(&inv).unwrap();

        // Peer B advertises it — absence is scoped to A, so we DO request (GetTxs).
        handle_inv_tx(
            peer_b, &payload, [1, 2, 3, 4], &peers, &senders, &mempool, &scorer, &cache,
        )
        .await
        .unwrap();
        assert!(rx_b.try_recv().is_ok(), "GetTxs sent to peer B");

        // Peer A itself reported absence — we do NOT re-request from A.
        handle_inv_tx(
            peer_a, &payload, [1, 2, 3, 4], &peers, &senders, &mempool, &scorer, &cache,
        )
        .await
        .unwrap();
        assert!(rx_a.try_recv().is_err(), "no GetTxs to the peer that said absent");
    }

    #[tokio::test]
    async fn handle_not_found_marks_absence_per_peer_only() {
        // An unsolicited NotFound spray from one peer must not suppress relay of
        // the same hash from other peers.
        let attacker = [1u8; 32];
        let honest = [2u8; 32];
        let peers = DashMap::new();
        peers.insert(attacker, PeerInfo::new(attacker, addr_for(32003), false));
        let scorer = RwLock::new(PeerScorer::new());
        let cache = ParkingRwLock::new(TxAbsenceCache::new());

        let hash = crate::primitives::Hash::from_bytes([9; 32]);
        let nf = crate::network::protocol::NotFoundMessage { hashes: vec![hash] };
        let payload = borsh::to_vec(&nf).unwrap();

        handle_not_found(attacker, &payload, &peers, &scorer, &cache)
            .await
            .unwrap();

        assert!(cache.read().is_known_absent(&attacker, &hash));
        assert!(
            !cache.read().is_known_absent(&honest, &hash),
            "absence must not leak to other peers"
        );
    }
}
