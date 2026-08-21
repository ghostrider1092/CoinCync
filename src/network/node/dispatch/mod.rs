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
            control::handle_chain_work(peer_id, payload, peers, sync).await?;
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
                peer_id, payload, magic, peers, senders, dandelion, event_tx, scorer,
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
