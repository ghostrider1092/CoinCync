//! ## Audit map
//! Each `§` is a code section below; it states the INVARIANT it guarantees, the
//! THREAT it defends, and the TESTS that prove it.
//!
//! - **§1 `unix_now`** — INVARIANT: returns whole seconds since the Unix
//!   epoch and never panics under a normal system clock.
//!   THREAT: a `duration_since` panic (clock set before the epoch) crashing
//!   the router on every message that needs a timestamp (e.g. Dandelion
//!   routing).
//!   TESTS: (gap — no dedicated unit test in this file for `unix_now`).
//! - **§2 `process_message` (Padding short-circuit)** — INVARIANT: a
//!   `Padding` message is discarded before peer activity/byte accounting or
//!   scoring ever sees it.
//!   THREAT: cover-traffic packets polluting peer stats or being misrouted
//!   into a real handler.
//!   TESTS: `padding_is_discarded_before_peer_accounting`.
//! - **§3 `process_message` (light-query payload gate)** — INVARIANT:
//!   `GetFilters`/`GetOutputDigests`/`GetFilterCheckpoints`/
//!   `GetKeyImageStatus` payloads over `MAX_LIGHT_QUERY_PAYLOAD` are dropped
//!   and scored `OversizedMessage` before reaching the per-handler backstop
//!   in `query.rs`.
//!   THREAT: DoS amplification via oversized DHT/light-client queries on a
//!   path with no framing-level per-type cap (audit R3-4).
//!   TESTS: `oversized_light_query_payloads_are_dropped_and_scored`.
//! - **§4 `process_message` (pre-handshake gate)** — INVARIANT: any message
//!   type other than the handshake set (`Version`/`Verack`/`Ping`/`Pong`/
//!   `Flare`) is ignored for a peer that hasn't reached `PeerState::Connected`.
//!   THREAT: pre-auth attack surface exploitation by an unauthenticated peer
//!   (H-3).
//!   TESTS: (gap — no dedicated unit test in this file for the
//!   pre-handshake reject branch).
//! - **§5 `process_message` (message routing dispatch)** — INVARIANT: every
//!   known `MessageType` discriminant routes to exactly one handler, and an
//!   unrecognized discriminant fails via `MessageType::try_from` rather than
//!   panicking or falling through.
//!   THREAT: an unhandled or misrouted message type crashing the connection
//!   loop or reaching the wrong handler.
//!   TESTS: `unknown_msg_type_returns_err_without_crashing`.

use dashmap::DashMap;
use tokio::sync::{broadcast, mpsc, RwLock};
use tracing::trace;

use crate::chain::SharedBlockchain;
use crate::error::Result;
use crate::mempool::SharedMempool;
use crate::network::bootstrap::AddressManager;
use crate::network::dandelion::DandelionRouter;
use crate::network::peer::{PeerId, PeerInfo, PeerState};
use crate::network::protocol::MessageType;
use crate::network::relay_score::RelayScoreMap;
use crate::network::scoring::PeerScorer;
use crate::network::sync::ChainSync;

use super::types::NodeEvent;
use super::TxAbsenceCache;

mod address;
mod chain;
mod control;
mod headers;
mod query;
mod relay;

fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system clock must be after the Unix epoch")
        .as_secs()
}

/// Process received message
/// The header has already been validated and stripped by the message framer;
/// type and payload arrive separately to avoid another payload-sized copy.
pub(super) async fn process_message(
    peer_id: PeerId,
    msg_type_id: u8,
    payload: &[u8],
    magic: [u8; 4],
    our_nonce: u64,
    peers: &DashMap<PeerId, PeerInfo>,
    senders: &DashMap<PeerId, mpsc::Sender<Vec<u8>>>,
    dandelion: &RwLock<DandelionRouter>,
    sync: &RwLock<ChainSync>,
    event_tx: &broadcast::Sender<NodeEvent>,
    chain: &SharedBlockchain,
    mempool: &SharedMempool,
    addresses: &RwLock<AddressManager>,
    scorer: &RwLock<PeerScorer>,
    // v1.0.13 #2 — tx-absence cache, populated by NotFound-receive,
    // consulted by InvTx-receive.
    tx_absence_cache: &parking_lot::RwLock<TxAbsenceCache>,
    // Node-internal inbound block-relay scores. Credited in the BlockData
    // handler when this peer delivers a valid block. Phase 1: measured
    // only — not yet consulted by eviction.
    relay_scores: &RwLock<RelayScoreMap>,
) -> Result<()> {
    let msg_type = MessageType::try_from(msg_type_id)?;

    // Traffic shaping: cover-traffic packets carry no semantic content and
    // are discarded silently. Phase 2 moved padding from the pre-launch
    // 0xDEADBEEF magic hack to a proper `MessageType::Padding` discriminant
    // routed through the framer like any other message.
    if matches!(msg_type, MessageType::Padding) {
        trace!("Discarded Padding packet from peer {:?}", &peer_id[..4]);
        return Ok(());
    }

    // Cheap payload-size gate for the light-client / DHT query types (audit
    // R3-4). Their requests are tiny (filters/digests = 16 bytes; ki-status
    // <= ~3.2 KiB) and there is no framing-level per-type cap on this path, so
    // drop oversized payloads before any handler allocates or parses.
    const MAX_LIGHT_QUERY_PAYLOAD: usize = 8 * 1024;
    if matches!(
        msg_type,
        MessageType::GetFilters
            | MessageType::GetOutputDigests
            | MessageType::GetFilterCheckpoints
            | MessageType::GetKeyImageStatus
    ) && payload.len() > MAX_LIGHT_QUERY_PAYLOAD
    {
        tracing::warn!(
            "Oversized {:?} payload ({} bytes) from peer {:?} — dropping",
            msg_type,
            payload.len(),
            &peer_id[..4]
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

    trace!("Received {:?} from peer {:?}", msg_type, &peer_id[..4]);

    // Update peer activity
    if let Some(mut peer) = peers.get_mut(&peer_id) {
        peer.touch();
        peer.bytes_recv = peer
            .bytes_recv
            .saturating_add(payload.len().saturating_add(1) as u64);
    }

    // SECURITY (H-3): Reject non-handshake messages from peers that haven't
    // completed the Version/Verack handshake.
    // This reduces pre-auth attack surface and aligns with production P2P posture.
    let is_allowed_pre_handshake = matches!(
        msg_type,
        // Handshake sequence
        MessageType::Version
            | MessageType::Verack
            | MessageType::Ping
            | MessageType::Pong
            | MessageType::Flare
    );
    if !is_allowed_pre_handshake {
        let is_connected = peers
            .get(&peer_id)
            .map(|p| p.state == PeerState::Connected)
            .unwrap_or(false);
        if !is_connected {
            tracing::trace!(
                "Ignoring {:?} from peer {:?} (handshake in progress)",
                msg_type,
                &peer_id[..4]
            );
            return Ok(());
        }
    }

    match msg_type {
        MessageType::Version => {
            control::handle_version(
                peer_id, payload, magic, our_nonce, peers, senders, sync, event_tx, chain, scorer,
            )
            .await?;
        }

        MessageType::Flare => {
            control::handle_flare(peer_id, payload, magic, peers, senders, chain).await?;
        }

        MessageType::ChainWork => {
            control::handle_chain_work(peer_id, payload, peers, sync, chain).await?;
        }

        MessageType::Verack => {
            control::handle_verack(peer_id, magic, peers, senders, dandelion, sync, chain).await?;
        }

        MessageType::Ping => {
            control::handle_ping(peer_id, payload, magic, peers, senders, scorer).await?;
        }

        MessageType::Pong => control::handle_pong(),

        MessageType::GetHeaders => {
            headers::handle_get_headers(peer_id, payload, magic, peers, senders, chain, scorer)
                .await?;
        }

        MessageType::GetBlocks => {
            chain::handle_get_blocks(peer_id, payload, magic, peers, senders, chain, scorer)
                .await?;
        }

        MessageType::InvTx => {
            relay::handle_inv_tx(
                peer_id,
                payload,
                magic,
                peers,
                senders,
                mempool,
                scorer,
                tx_absence_cache,
            )
            .await?;
        }

        MessageType::NotFound => {
            relay::handle_not_found(peer_id, payload, peers, scorer, tx_absence_cache).await?;
        }

        MessageType::InvBlock => {
            chain::handle_inv_block(peer_id, payload, magic, peers, senders, sync, chain, scorer)
                .await?;
        }

        MessageType::GetTxs => {
            relay::handle_get_txs(peer_id, payload, magic, peers, senders, mempool, scorer).await?;
        }

        MessageType::Txs => {
            relay::handle_txs(
                peer_id, payload, magic, peers, senders, dandelion, event_tx, scorer, chain,
            )
            .await?;
        }

        MessageType::Blocks => {
            chain::handle_blocks(peer_id, payload, magic, peers, event_tx, scorer).await?;
        }

        MessageType::Headers => {
            headers::handle_headers(peer_id, payload, peers, sync, chain, scorer).await?;
        }

        MessageType::GetAddr => {
            address::handle_get_addr(peer_id, magic, peers, senders, addresses).await?;
        }

        MessageType::Addr => {
            address::handle_addr(peer_id, payload, peers, addresses, scorer).await?;
        }

        MessageType::GetData => {
            chain::handle_get_data(peer_id, payload, magic, peers, senders, chain, scorer).await?;
        }

        MessageType::BlockData => {
            chain::handle_block_data(
                peer_id,
                payload,
                magic,
                peers,
                event_tx,
                scorer,
                relay_scores,
            )
            .await?;
        }

        MessageType::Reject => control::handle_reject(peer_id, peers),

        // ─── Personal Node (Tier 1) Protocol ─────────────────────────────
        MessageType::GetFilters => {
            query::handle_get_filters(peer_id, payload, magic, chain, senders).await?;
        }

        MessageType::GetOutputDigests => {
            query::handle_get_output_digests(peer_id, payload, magic, chain, senders).await?;
        }

        MessageType::GetFilterCheckpoints => {
            query::handle_get_filter_checkpoints(peer_id, magic, chain, senders).await?;
        }

        // ─── Network Node (Tier 2) DHT Protocol ─────────────────────────
        MessageType::GetKeyImageStatus => {
            query::handle_get_key_image_status(peer_id, payload, magic, chain, senders).await?;
        }

        // Responses handled by the requesting side (personal node)
        MessageType::Filters
        | MessageType::OutputDigests
        | MessageType::FilterCheckpoints
        | MessageType::KeyImageStatus => {
            query::handle_response(msg_type);
        }

        MessageType::Alert | MessageType::AnchorRequest | MessageType::AnchorResponse => {
            trace!("Ignoring unsupported message type: {:?}", msg_type);
        }

        MessageType::Padding => unreachable!("padding is discarded before peer accounting"),
    }

    Ok(())
}

#[cfg(test)]
mod router_tests {
    use super::*;
    use crate::chain::Blockchain;
    use crate::primitives::Hash;
    use std::net::SocketAddr;
    use std::sync::Arc;

    /// Drive `process_message` end-to-end against real state; returns the router
    /// result and the peer's post-call reputation (None if never scored).
    async fn run_one(
        peer_id: PeerId,
        addr: SocketAddr,
        msg_type_id: u8,
        payload: Vec<u8>,
    ) -> (Result<()>, Option<i32>) {
        let peers = DashMap::new();
        peers.insert(peer_id, PeerInfo::new(peer_id, addr, false));
        let senders: DashMap<PeerId, mpsc::Sender<Vec<u8>>> = DashMap::new();
        let dandelion = RwLock::new(DandelionRouter::new());
        let sync = RwLock::new(ChainSync::new(0, Hash::zero()));
        let (event_tx, _event_rx) = broadcast::channel(8);
        let chain: SharedBlockchain = Arc::new(Blockchain::new());
        chain.init_genesis().unwrap();
        let mempool = SharedMempool::new();
        let addresses = RwLock::new(AddressManager::new(1000));
        let scorer = RwLock::new(PeerScorer::new());
        let cache = parking_lot::RwLock::new(TxAbsenceCache::new());
        let relay = RwLock::new(RelayScoreMap::new());

        let res = process_message(
            peer_id,
            msg_type_id,
            &payload,
            [1, 2, 3, 4],
            0,
            &peers,
            &senders,
            &dandelion,
            &sync,
            &event_tx,
            &chain,
            &mempool,
            &addresses,
            &scorer,
            &cache,
            &relay,
        )
        .await;
        let rep = scorer.read().await.get(&addr).map(|s| s.reputation);
        (res, rep)
    }

    #[tokio::test]
    async fn unknown_msg_type_returns_err_without_crashing() {
        // 200 falls in an unused discriminant gap → try_from errors → the
        // processor loop logs and continues (it doesn't panic).
        let (res, rep) = run_one([9u8; 32], "127.0.0.1:34001".parse().unwrap(), 200, vec![]).await;
        assert!(res.is_err());
        assert!(rep.is_none());
    }

    #[tokio::test]
    async fn padding_is_discarded_before_peer_accounting() {
        let (res, rep) = run_one(
            [9u8; 32],
            "127.0.0.1:34002".parse().unwrap(),
            MessageType::Padding as u8,
            vec![],
        )
        .await;
        assert!(res.is_ok());
        assert!(rep.is_none(), "padding never reaches scoring");
    }

    #[tokio::test]
    async fn oversized_light_query_payloads_are_dropped_and_scored() {
        let oversized = vec![0u8; 8 * 1024 + 1]; // > MAX_LIGHT_QUERY_PAYLOAD
        for (i, ty) in [
            MessageType::GetFilters,
            MessageType::GetOutputDigests,
            MessageType::GetFilterCheckpoints,
            MessageType::GetKeyImageStatus,
        ]
        .into_iter()
        .enumerate()
        {
            let addr: SocketAddr = format!("127.0.0.1:{}", 34100 + i as u16).parse().unwrap();
            let (res, rep) = run_one([9u8; 32], addr, ty as u8, oversized.clone()).await;
            assert!(res.is_ok(), "{ty:?} dropped cleanly");
            assert!(
                rep.is_some_and(|r| r < 100),
                "{ty:?} oversized payload scored OversizedMessage"
            );
        }
    }
}
