use dashmap::DashMap;
use tokio::sync::{mpsc, RwLock};
use tracing::{debug, warn};

use crate::chain::SharedBlockchain;
use crate::error::Result;
use crate::network::peer::{PeerId, PeerInfo};
use crate::network::protocol::{GetHeadersMessage, Message, MAX_HEADERS_RESPONSE};
use crate::network::scoring::PeerScorer;
use crate::network::sync::ChainSync;
use crate::primitives::Hash;

use super::super::broadcast::send_to_peer;

pub(super) async fn handle_get_headers(
    peer_id: PeerId,
    payload: &[u8],
    magic: [u8; 4],
    peers: &DashMap<PeerId, PeerInfo>,
    senders: &DashMap<PeerId, mpsc::Sender<Vec<u8>>>,
    chain: &SharedBlockchain,
    scorer: &RwLock<PeerScorer>,
) -> Result<()> {
    if payload.len() > crate::network::protocol::MAX_GETHEADERS_PAYLOAD {
        warn!("GetHeaders message too large from peer {:?}", &peer_id[..4]);
        if let Some(addr) = peers.get(&peer_id).map(|p| p.addr) {
            scorer
                .write()
                .await
                .get_or_create(addr)
                .record_misbehavior(crate::network::scoring::MisbehaviorType::OversizedMessage);
        }
        return Ok(());
    }
    if let Ok(msg) = borsh::from_slice::<GetHeadersMessage>(payload) {
        if let Err(e) = msg.validate() {
            warn!("Invalid GetHeaders from peer {:?}: {}", &peer_id[..4], e);
            if let Some(addr) = peers.get(&peer_id).map(|p| p.addr) {
                scorer.write().await.get_or_create(addr).record_misbehavior(
                    crate::network::scoring::MisbehaviorType::ProtocolViolation,
                );
            }
            return Ok(());
        }

        // Database reads can stall without yielding to other async tasks.
        let headers = tokio::task::block_in_place(|| {
            let mut start_height = 0u64;
            for hash in &msg.locator {
                if let Some(block) = chain.get_block(hash) {
                    start_height = block.height() + 1;
                    break;
                }
            }
            let mut headers = Vec::new();
            for h in start_height..start_height + MAX_HEADERS_RESPONSE as u64 {
                if let Some(block) = chain.get_block_by_height(h) {
                    let block_hash = block.hash();
                    headers.push(block.header.clone());
                    if block_hash == msg.stop_hash {
                        break;
                    }
                } else {
                    break;
                }
            }
            headers
        });

        if let Ok(resp) = Message::headers_with_nonce(magic, headers, msg.nonce) {
            let _ = send_to_peer(senders, &peer_id, resp.to_bytes()?).await;
        }
    }
    Ok(())
}

pub(super) async fn handle_headers(
    peer_id: PeerId,
    payload: &[u8],
    peers: &DashMap<PeerId, PeerInfo>,
    sync: &RwLock<ChainSync>,
    scorer: &RwLock<PeerScorer>,
) -> Result<()> {
    if payload.len() > crate::network::protocol::MAX_MESSAGE_SIZE {
        warn!(
            "Headers message too large from peer {}",
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
    match borsh::from_slice::<crate::network::protocol::HeadersMessage>(payload) {
        Ok(headers_msg) => {
            if let Err(e) = headers_msg.validate() {
                warn!(
                    "Invalid HeadersMessage from peer {}: {}",
                    hex::encode(&peer_id[..8]),
                    e
                );
                if let Some(addr) = peers.get(&peer_id).map(|p| p.addr) {
                    scorer.write().await.get_or_create(addr).record_misbehavior(
                        crate::network::scoring::MisbehaviorType::ProtocolViolation,
                    );
                }
                return Ok(());
            }
            let max_header_height = headers_msg
                .headers
                .iter()
                .map(|h| h.height)
                .max()
                .unwrap_or(0);

            let mut sync_guard = sync.write().await;
            if !sync_guard.validate_header_nonce(headers_msg.nonce, &peer_id) {
                debug!(
                    "Ignoring Headers nonce={} from peer {:?}: not outstanding for this peer \
                     (cross-peer, stale generation, or already consumed)",
                    headers_msg.nonce,
                    &peer_id[..4]
                );
                return Ok(());
            }

            // A forged anchor is cheap to identify before it can occupy the
            // attributed pending-header pool.
            let bad_anchor_at = headers_msg.headers.iter().enumerate().find_map(|(i, hdr)| {
                match crate::consensus::pow::compute_full_anchor(
                    &hdr.prev_hash,
                    hdr.height,
                    hdr.timestamp,
                ) {
                    Ok(anchor) if anchor.mixed_hash == hdr.anchor => None,
                    _ => Some(i),
                }
            });
            if let Some(idx) = bad_anchor_at {
                warn!(
                    "Headers pre-PoW reject: header[{}] anchor mismatch from peer {:?} \
                 (h={}). Dropping batch + scoring peer.",
                    idx,
                    &peer_id[..4],
                    headers_msg.headers[idx].height,
                );
                drop(sync_guard);
                if let Some(addr) = peers.get(&peer_id).map(|p| p.addr) {
                    scorer.write().await.get_or_create(addr).record_misbehavior(
                        crate::network::scoring::MisbehaviorType::ProtocolViolation,
                    );
                }
                return Ok(());
            }

            let hashes: Vec<Hash> = headers_msg.headers.iter().map(|h| h.hash()).collect();
            sync_guard.update_peer_height(max_header_height);
            sync_guard.update_peer_height_for(peer_id, max_header_height);
            sync_guard.reset_headers_timeout();
            debug!(
                "Accepted Headers nonce={} count={} max_height={} from peer {:?}",
                headers_msg.nonce,
                hashes.len(),
                max_header_height,
                &peer_id[..4]
            );
            sync_guard.queue_headers_from_peer(peer_id, hashes);
        }
        Err(e) => {
            warn!(
                "Failed to deserialize HeadersMessage from peer {}: {}",
                hex::encode(&peer_id[..8]),
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
