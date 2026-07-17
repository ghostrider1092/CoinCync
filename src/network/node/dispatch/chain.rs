use std::time::Duration;

use dashmap::DashMap;
use tokio::sync::{broadcast, mpsc, RwLock};
use tracing::{debug, info, warn};

use crate::chain::SharedBlockchain;
use crate::consensus::Block;
use crate::error::Result;
use crate::network::peer::{PeerId, PeerInfo};
use crate::network::protocol::{
    GetBlocksMessage, InvMessage, Message, MessageType, MAX_BLOCK_HASHES,
};
use crate::network::relay_score::RelayScoreMap;
use crate::network::scoring::PeerScorer;
use crate::network::sync::{build_locator, ChainSync};
use crate::primitives::Hash;

use super::super::broadcast::send_to_peer;
use super::super::constants::NEAR_TIP_INV_WINDOW;
use super::super::types::NodeEvent;

/// Keep a near-tip node on prompt block fetching while deep IBD avoids orphan
/// accumulation. The inclusive boundary preserves the observed recovery case.
#[inline]
fn invblock_near_tip(synced: bool, gap: u64, window: u64) -> bool {
    synced || gap <= window
}

pub(super) async fn handle_get_blocks(
    peer_id: PeerId,
    payload: &[u8],
    magic: [u8; 4],
    peers: &DashMap<PeerId, PeerInfo>,
    senders: &DashMap<PeerId, mpsc::Sender<Vec<u8>>>,
    chain: &SharedBlockchain,
    scorer: &RwLock<PeerScorer>,
) -> Result<()> {
    // Peer is requesting full blocks by hash.
    // P5-N-CLASS-A fix: tight per-type cap.
    if payload.len() > crate::network::protocol::MAX_GETBLOCKS_PAYLOAD {
        warn!("GetBlocks message too large from peer {:?}", &peer_id[..4]);
        if let Some(addr) = peers.get(&peer_id).map(|p| p.addr) {
            scorer
                .write()
                .await
                .get_or_create(addr)
                .record_misbehavior(crate::network::scoring::MisbehaviorType::OversizedMessage);
        }
        return Ok(());
    }
    match borsh::from_slice::<GetBlocksMessage>(payload) {
        Ok(msg) => {
            if let Err(e) = msg.validate() {
                warn!("Invalid GetBlocks from peer {:?}: {}", &peer_id[..4], e);
                if let Some(addr) = peers.get(&peer_id).map(|p| p.addr) {
                    scorer.write().await.get_or_create(addr).record_misbehavior(
                        crate::network::scoring::MisbehaviorType::ProtocolViolation,
                    );
                }
                return Ok(());
            }

            let requested = msg.hashes.len();
            // Layer 2: pull full blocks from the chain DB inside
            // block_in_place so a slow DB read doesn't freeze the
            // worker thread mid-response.
            let blocks = tokio::task::block_in_place(|| {
                let mut blocks = Vec::new();
                for hash in &msg.hashes {
                    if let Some(block) = chain.get_block(hash) {
                        blocks.push(block);
                        if blocks.len() >= MAX_BLOCK_HASHES {
                            break;
                        }
                    }
                }
                blocks
            });

            debug!(
                "GetBlocks from {:?}: {} requested, {} found",
                &peer_id[..4],
                requested,
                blocks.len()
            );

            // Always respond (even with empty blocks) so the requester
            // can free download slots instead of waiting for timeout.
            if let Ok(resp) = Message::blocks(magic, blocks) {
                let _ = send_to_peer(senders, &peer_id, resp.to_bytes()?).await;
            }
        }
        Err(e) => {
            warn!(
                "Failed to deserialize GetBlocks from peer {:?}: {}",
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

pub(super) async fn handle_inv_block(
    peer_id: PeerId,
    payload: &[u8],
    magic: [u8; 4],
    peers: &DashMap<PeerId, PeerInfo>,
    senders: &DashMap<PeerId, mpsc::Sender<Vec<u8>>>,
    sync: &RwLock<ChainSync>,
    chain: &SharedBlockchain,
    scorer: &RwLock<PeerScorer>,
) -> Result<()> {
    // Block inventory - check if we're missing blocks.
    // P5-N8 + P5-N-CLASS-A fix: tight size cap + Err scoring.
    if payload.len() > crate::network::protocol::MAX_INV_PAYLOAD {
        warn!("InvBlock message too large from peer {:?}", &peer_id[..4]);
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
                warn!("Invalid InvBlock from peer {:?}: {}", &peer_id[..4], e);
                if let Some(addr) = peers.get(&peer_id).map(|p| p.addr) {
                    scorer.write().await.get_or_create(addr).record_misbehavior(
                        crate::network::scoring::MisbehaviorType::ProtocolViolation,
                    );
                }
                return Ok(());
            }

            // During IBD, skip the block-body fetch (a new-tip InvBlock hash
            // generally won't chain off our current IBD position and would
            // pile up orphans). BUT — send a GetHeaders to this peer first
            // so peer.height refreshes from real header.height values in the
            // response. Without this, peer.height stays frozen at the handshake-
            // time value: when the source mines past handshake, our sync
            // target never rises, IBD declares done at the stale tip, and the
            // node stays permanently behind (this was the launch-day stall).
            if !sync.read().await.is_synced() {
                let our_height = chain.height();
                // CIP-019: a node only a few blocks behind (near tip) must keep
                // catching up promptly. The old gate treated near-tip like deep
                // IBD, trapping such a node on slow catch-up so it stayed
                // permanently a few blocks behind and its miner's sync gate
                // never cleared (observed live 2026-07-11). Refresh headers
                // either way; for a near-tip node ALSO nudge a prompt resync so
                // the small gap closes to the exact tip. Deep-IBD behavior
                // (skip the body fetch to avoid orphan pileup) is unchanged.
                let near_tip = invblock_near_tip(
                    false,
                    chain.peer_advertised_height().saturating_sub(our_height),
                    NEAR_TIP_INV_WINDOW,
                );
                let locator = build_locator(our_height, |h| chain.get_block_hash(h));
                if !locator.is_empty() {
                    let nonce = sync.write().await.allocate_header_nonce();
                    if let Ok(msg) =
                        Message::get_headers_with_nonce(magic, locator, Hash::zero(), nonce)
                    {
                        if let Ok(data) = msg.to_bytes() {
                            // Clone before awaiting so a full queue cannot hold a map guard.
                            let sender = senders.get(&peer_id).map(|s| s.value().clone());
                            if let Some(sender) = sender {
                                let _ = sender.send(data).await;
                                debug!(
                                "InvBlock during IBD: sent GetHeaders nonce={} to peer {:?} to refresh tip (our_h={})",
                                nonce, &peer_id[..4], our_height
                            );
                            }
                        }
                    }
                }
                if near_tip {
                    // Near tip: pull the small gap promptly rather than waiting on
                    // the slow tick. trigger_resync only fires from Synced/Idle;
                    // a node actively (but slowly) catching up sits in Headers/
                    // Blocks, where trigger_resync is a no-op — so it would stay
                    // stuck a few blocks behind forever (the randomx-2 case). Fall
                    // back to arm_near_tip_catchup, which re-arms a header pull when
                    // we're behind AND idle (nothing in flight), closing the gap.
                    let mut sg = sync.write().await;
                    if !sg.trigger_resync() {
                        sg.arm_near_tip_catchup();
                    }
                }
                return Ok(());
            }

            // Post-IBD: peer has blocks we don't. Fetch them directly
            // via GetBlocks (below). We do NOT speculatively bump
            // peer_heights[peer_id] here — the bump used to be:
            //
            //     update_peer_height_for(peer_id, our_h + 1)
            //
            // as a "lower bound" estimate. In practice that was a
            // permanent latch: if the peer never delivered the
            // announced block (stale orphan-fork remnant, peer with
            // a phantom hash in its known set, etc.), peer_heights
            // stayed at our_h+1 forever. best_known_height latched
            // to our_h+1. is_synced() returned false. coincync-rig's
            // sync gate flipped — "refusing to mine to avoid
            // producing blocks on a private fork" — and the chain
            // wedged until somebody restarted the offending peer.
            // This was the production failure mode observed
            // 2026-06-27 (multiple wedges, including one 42-min
            // stall that required an emergency
            // COINCYNC_RIG_SKIP_SYNC_CHECK=1 bypass to recover).
            //
            // The rc5 refresh_best_known fix (PR #125) made the
            // peer-disconnect path self-clear correctly. But a
            // STILL-CONNECTED peer with a latched bump kept
            // best_known pinned regardless. The bump itself is
            // the bug — remove it.
            //
            // Correct peer_height updates still come from Version and
            // validated Headers messages.
            // Both of those use ACTUAL heights, not speculation.
            // When we successfully receive and process the block
            // requested below, refresh_best_known runs on
            // on_block_processed (rc5 fix) and recomputes
            // best_known from current peer_heights + local. No
            // speculation needed.
            let mut needed = Vec::new();
            for inv in &inv_msg.inventory {
                if chain.get_block(&inv.hash).is_none() {
                    needed.push(inv.hash);
                }
            }
            if !needed.is_empty() {
                if needed.len() <= 4 {
                    // Small number of missing blocks — request them directly
                    // (fast path: avoids full header re-sync round-trip).
                    let get_blocks = crate::network::protocol::GetBlocksMessage {
                        hashes: needed.clone(),
                    };
                    if let Ok(payload) = borsh::to_vec(&get_blocks) {
                        let msg_out = Message::new(magic, MessageType::GetBlocks, payload);
                        if let Ok(data) = msg_out.to_bytes() {
                            // Both following awaits must run without a DashMap guard.
                            let sender = senders.get(&peer_id).map(|s| s.value().clone());
                            if let Some(sender) = sender {
                                if sender.send(data).await.is_ok() {
                                    // Track so timeout/retry works
                                    let now = super::unix_now();
                                    let mut sg = sync.write().await;
                                    for hash in &needed {
                                        sg.track_direct_request(*hash, peer_id, now);
                                    }
                                    debug!(
                                        "InvBlock: directly requesting {} blocks from peer {:?}",
                                        needed.len(),
                                        &peer_id[..4]
                                    );
                                }
                            }
                        }
                    }
                } else {
                    // Many missing blocks — full header re-sync (Bitcoin-style).
                    let triggered = sync.write().await.trigger_resync();
                    if triggered {
                        debug!(
                        "InvBlock from peer {:?} has {} unknown blocks, triggered header re-sync",
                        &peer_id[..4], needed.len()
                    );
                    }
                }
            }
        }
        Err(e) => {
            // P5-N7 fix: score borsh parse failure.
            warn!(
                "Failed to deserialize InvBlock from peer {:?}: {}",
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

pub(super) async fn handle_blocks(
    peer_id: PeerId,
    payload: &[u8],
    magic: [u8; 4],
    peers: &DashMap<PeerId, PeerInfo>,
    event_tx: &broadcast::Sender<NodeEvent>,
    scorer: &RwLock<PeerScorer>,
) -> Result<()> {
    // SECURITY: Limit payload size before deserialization to prevent CPU exhaustion.
    // F12 fix: OversizedMessage (10pt), not ProtocolViolation (20pt).
    if payload.len() > crate::network::protocol::MAX_MESSAGE_SIZE {
        warn!(
            "Blocks message too large from peer {}",
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
    // Parse blocks. P5-N7 fix: match with Err scoring.
    match borsh::from_slice::<crate::network::protocol::BlocksMessage>(payload) {
        Ok(blocks_msg) => {
            // SECURITY: Limit number of blocks per message.
            // F12 fix: "too many items in one message" is OversizedMessage
            // semantically — the peer is sending too much data in one frame,
            // not sending malformed data.
            if blocks_msg.blocks.len() > crate::network::protocol::MAX_BLOCK_HASHES {
                warn!(
                    "Too many blocks in message from peer {}",
                    hex::encode(&peer_id[..8])
                );
                if let Some(addr) = peers.get(&peer_id).map(|p| p.addr) {
                    scorer.write().await.get_or_create(addr).record_misbehavior(
                        crate::network::scoring::MisbehaviorType::OversizedMessage,
                    );
                }
                return Ok(());
            }
            info!(
                "[IBD] Received Blocks message: {} blocks from peer {:?}",
                blocks_msg.blocks.len(),
                &peer_id[..4]
            );

            // If peer responds with 0 blocks, the hashes we requested don't
            // exist on their chain (different fork). DON'T clear sync state —
            // that destroys all progress. Instead, mark this peer as
            // incompatible and continue with other peers.
            if blocks_msg.blocks.is_empty() {
                debug!(
                    "[IBD] Got 0 blocks from peer {:?} — empty Blocks reply, demoting",
                    &peer_id[..4]
                );
                // Record an empty-Blocks response so the scorer can ban
                // this peer from `GetBlocks` selection after N consecutive
                // empties. Closes the "stall pathology" wedge pattern
                // (peer accepts requests but never delivers).
                if let Some(addr) = peers.get(&peer_id).map(|p| p.addr) {
                    scorer
                        .write()
                        .await
                        .get_or_create(addr)
                        .record_empty_blocks_response();
                }
                return Ok(());
            }

            for (bi, block) in blocks_msg.blocks.into_iter().enumerate() {
                debug!(
                    "  block[{}]: height={} algo={} size={} txs={}",
                    bi,
                    block.header.height,
                    block.header.algorithm,
                    block.size(),
                    block.transactions.len()
                );

                // SECURITY (NetworkTag): FIRST CHECK — reject wrong-network blocks
                // before any expensive validation. Costs 4 bytes comparison.
                // Instant-bans the peer (MisbehaviorType::WrongNetwork = -100).
                if block.header.network_magic != magic {
                    warn!(
                        "Rejecting block from wrong network (magic {:?} != {:?}) from peer {}",
                        block.header.network_magic,
                        magic,
                        hex::encode(&peer_id[..8])
                    );
                    if let Some(addr) = peers.get(&peer_id).map(|p| p.addr) {
                        scorer.write().await.get_or_create(addr).record_misbehavior(
                            crate::network::scoring::MisbehaviorType::WrongNetwork,
                        );
                    }
                    continue;
                }

                // SECURITY: Quick-validate block before relay to prevent
                // garbage blocks from consuming CPU across the network.
                // Check size, tx count, and basic header sanity. Full PoW
                // verification happens in chain.add_block() (requires prev block).
                let size = block.size();
                if size > crate::constants::MAX_BLOCK_SIZE {
                    warn!(
                        "Rejecting oversized block ({} bytes) from peer {}",
                        size,
                        hex::encode(&peer_id[..8])
                    );
                    if let Some(addr) = peers.get(&peer_id).map(|p| p.addr) {
                        scorer
                            .write()
                            .await
                            .get_or_create(addr)
                            .record_block_failure();
                    }
                    continue;
                }
                if block.transactions.len() > crate::constants::MAX_TXS_PER_BLOCK {
                    warn!(
                        "Rejecting block with too many txs ({}) from peer {}",
                        block.transactions.len(),
                        hex::encode(&peer_id[..8])
                    );
                    if let Some(addr) = peers.get(&peer_id).map(|p| p.addr) {
                        scorer
                            .write()
                            .await
                            .get_or_create(addr)
                            .record_block_failure();
                    }
                    continue;
                }
                // Recompute failure may be local, but a computed sub-target hash
                // proves the relayed block invalid and warrants immediate scoring.
                let pow_hash = match crate::consensus::compute_pow_hash(
                    crate::consensus::PowAlgorithm::from_index(block.header.algorithm),
                    &block.header.anchor,
                    block.header.nonce,
                    &block.header.tx_root,
                    block.header.height,
                ) {
                    Ok(h) => h,
                    Err(_) => {
                        warn!(
                            "PoW hash computation failed for block from peer {}",
                            hex::encode(&peer_id[..8])
                        );
                        if let Some(addr) = peers.get(&peer_id).map(|p| p.addr) {
                            scorer
                                .write()
                                .await
                                .get_or_create(addr)
                                .record_block_failure();
                        }
                        continue;
                    }
                };
                if !pow_hash.meets_difficulty(&block.header.target) {
                    warn!(
                        "Instant-banning peer {} — provably-invalid PoW: \
                       block hash {:?} does not meet claimed target {:?}",
                        hex::encode(&peer_id[..8]),
                        pow_hash,
                        block.header.target
                    );
                    if let Some(addr) = peers.get(&peer_id).map(|p| p.addr) {
                        scorer.write().await.get_or_create(addr).record_misbehavior(
                            crate::network::scoring::MisbehaviorType::InvalidBlockPoW,
                        );
                    }
                    continue;
                }
                if let Some(addr) = peers.get(&peer_id).map(|p| p.addr) {
                    scorer
                        .write()
                        .await
                        .get_or_create(addr)
                        .record_block_success(Duration::from_millis(100));
                }
                let _ = event_tx.send(NodeEvent::BlockReceived(block, peer_id));
            }
        }
        Err(e) => {
            warn!(
                "Failed to deserialize BlocksMessage from peer {}: {}",
                hex::encode(&peer_id[..8]),
                e
            );
            if let Some(addr) = peers.get(&peer_id).map(|p| p.addr) {
                // F2 fix: unified record_misbehavior for observability.
                scorer.write().await.get_or_create(addr).record_misbehavior(
                    crate::network::scoring::MisbehaviorType::ProtocolViolation,
                );
            }
        }
    }
    Ok(())
}

pub(super) async fn handle_get_data(
    peer_id: PeerId,
    payload: &[u8],
    magic: [u8; 4],
    peers: &DashMap<PeerId, PeerInfo>,
    senders: &DashMap<PeerId, mpsc::Sender<Vec<u8>>>,
    chain: &SharedBlockchain,
    scorer: &RwLock<PeerScorer>,
) -> Result<()> {
    // Peer requests specific blocks by hash (individual block responses).
    // P5-N-CLASS-A fix: tight per-type cap.
    // F12 fix: OversizedMessage, not ProtocolViolation.
    if payload.len() > crate::network::protocol::MAX_GETDATA_PAYLOAD {
        warn!("GetData message too large from peer {:?}", &peer_id[..4]);
        if let Some(addr) = peers.get(&peer_id).map(|p| p.addr) {
            scorer
                .write()
                .await
                .get_or_create(addr)
                .record_misbehavior(crate::network::scoring::MisbehaviorType::OversizedMessage);
        }
        return Ok(());
    }
    // P5-N7 fix: match with Err scoring.
    match borsh::from_slice::<GetBlocksMessage>(payload) {
        Ok(msg) => {
            if let Err(e) = msg.validate() {
                warn!("Invalid GetData from peer {:?}: {}", &peer_id[..4], e);
                if let Some(addr) = peers.get(&peer_id).map(|p| p.addr) {
                    scorer.write().await.get_or_create(addr).record_misbehavior(
                        crate::network::scoring::MisbehaviorType::ProtocolViolation,
                    );
                }
                return Ok(());
            }
            // Send each block individually as BlockData.
            // Layer 2: pre-fetch + serialize all blocks under
            // block_in_place, then do the async per-peer sends after.
            // This keeps the sync DB reads + borsh serialization off
            // the worker thread for the duration of the request.
            let payloads: Vec<Vec<u8>> = tokio::task::block_in_place(|| {
                msg.hashes
                    .iter()
                    .filter_map(|hash| chain.get_block(hash))
                    .filter_map(|block| borsh::to_vec(&block).ok())
                    .collect()
            });
            for block_bytes in payloads {
                let m = Message::new(magic, MessageType::BlockData, block_bytes);
                if let Ok(data) = m.to_bytes() {
                    let _ = send_to_peer(senders, &peer_id, data).await;
                }
            }
        }
        Err(e) => {
            warn!(
                "Failed to deserialize GetData from peer {:?}: {}",
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

pub(super) async fn handle_block_data(
    peer_id: PeerId,
    payload: &[u8],
    magic: [u8; 4],
    peers: &DashMap<PeerId, PeerInfo>,
    event_tx: &broadcast::Sender<NodeEvent>,
    scorer: &RwLock<PeerScorer>,
    relay_scores: &RwLock<RelayScoreMap>,
) -> Result<()> {
    // Peer sends us a single block.
    // F12 fix: OversizedMessage, not ProtocolViolation.
    if payload.len() > crate::network::protocol::MAX_MESSAGE_SIZE {
        warn!("BlockData message too large from peer {:?}", &peer_id[..4]);
        if let Some(addr) = peers.get(&peer_id).map(|p| p.addr) {
            scorer
                .write()
                .await
                .get_or_create(addr)
                .record_misbehavior(crate::network::scoring::MisbehaviorType::OversizedMessage);
        }
        return Ok(());
    }
    if let Ok(block) = borsh::from_slice::<Block>(payload) {
        // SECURITY (NetworkTag): reject wrong-network blocks instantly
        if block.header.network_magic != magic {
            warn!(
                "BlockData from wrong network (magic {:?}) from peer {:?}",
                block.header.network_magic,
                &peer_id[..4]
            );
            if let Some(addr) = peers.get(&peer_id).map(|p| p.addr) {
                scorer
                    .write()
                    .await
                    .get_or_create(addr)
                    .record_misbehavior(crate::network::scoring::MisbehaviorType::WrongNetwork);
            }
            return Ok(());
        }
        // Success is recorded only after cheap PoW verification so invalid
        // relays cannot build reputation before full chain validation.
        let pow_hash = match crate::consensus::compute_pow_hash(
            crate::consensus::PowAlgorithm::from_index(block.header.algorithm),
            &block.header.anchor,
            block.header.nonce,
            &block.header.tx_root,
            block.header.height,
        ) {
            Ok(h) => h,
            Err(_) => {
                // A recompute failure can be local, so keep the low-weight penalty.
                warn!(
                    "BlockData: PoW hash recompute failed for block from peer {:?}",
                    &peer_id[..4]
                );
                if let Some(addr) = peers.get(&peer_id).map(|p| p.addr) {
                    scorer
                        .write()
                        .await
                        .get_or_create(addr)
                        .record_block_failure();
                }
                return Ok(());
            }
        };
        if !pow_hash.meets_difficulty(&block.header.target) {
            warn!(
                "Instant-banning peer {:?} — BlockData block with provably-invalid PoW",
                &peer_id[..4]
            );
            if let Some(addr) = peers.get(&peer_id).map(|p| p.addr) {
                scorer
                    .write()
                    .await
                    .get_or_create(addr)
                    .record_misbehavior(crate::network::scoring::MisbehaviorType::InvalidBlockPoW);
            }
            return Ok(());
        }
        // Now record success and hand off to the event pipeline.
        if let Some(addr) = peers.get(&peer_id).map(|p| p.addr) {
            scorer
                .write()
                .await
                .get_or_create(addr)
                .record_block_success(Duration::from_millis(100));
        }
        // Credit this peer's inbound block-relay score (Phase 1: measure
        // only — not yet consulted by eviction). Public block delivery is
        // the sole input; no transaction is observed. Credits valid
        // delivery; a new-block-only refinement is a follow-up.
        relay_scores.write().await.credit_block(peer_id);
        let _ = event_tx.send(NodeEvent::BlockReceived(block, peer_id));
    } else {
        warn!(
            "Failed to deserialize BlockData from peer {:?}",
            &peer_id[..4]
        );
        if let Some(addr) = peers.get(&peer_id).map(|p| p.addr) {
            // Unparseable bytes are a protocol violation, not a block verdict.
            scorer
                .write()
                .await
                .get_or_create(addr)
                .record_misbehavior(crate::network::scoring::MisbehaviorType::ProtocolViolation);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::consensus::BlockHeader;
    use crate::network::protocol::BlocksMessage;
    use crate::primitives::PublicKey;
    use std::net::SocketAddr;

    #[test]
    fn cip019_invblock_near_tip_regime() {
        let window = NEAR_TIP_INV_WINDOW;
        assert!(invblock_near_tip(true, 9_999, window));
        assert!(invblock_near_tip(false, 0, window));
        assert!(invblock_near_tip(false, 3, window));
        assert!(invblock_near_tip(false, window, window));
        assert!(!invblock_near_tip(false, window + 1, window));
        assert!(!invblock_near_tip(false, 3_000, window));
    }

    #[tokio::test]
    async fn invalid_blocks_are_not_credited_as_successful_deliveries() {
        let peer_id = [8; 32];
        let addr: SocketAddr = "127.0.0.1:28081".parse().unwrap();
        let peers = DashMap::new();
        peers.insert(peer_id, PeerInfo::new(peer_id, addr, false));
        let (event_tx, mut event_rx) = broadcast::channel(4);
        let scorer = RwLock::new(PeerScorer::new());
        let block = Block::new(
            BlockHeader {
                network_magic: [4, 3, 2, 1],
                version: 1,
                height: 1,
                timestamp: 1,
                prev_hash: Hash::zero(),
                tx_root: Hash::zero(),
                anchor: Hash::zero(),
                algorithm: 0,
                nonce: 0,
                target: Hash::from_bytes([0xff; 32]),
                miner_pubkey: PublicKey::from_bytes([0; 32]),
                supply_commitment: [0; 32],
                checkpoint_vote: None,
                spark_set_root: [0; 32],
                mw_kernel_root: [0; 32],
            },
            Vec::new(),
        );
        let payload = borsh::to_vec(&BlocksMessage {
            blocks: vec![block],
        })
        .unwrap();

        handle_blocks(peer_id, &payload, [1, 2, 3, 4], &peers, &event_tx, &scorer)
            .await
            .unwrap();

        let guard = scorer.read().await;
        let score = guard.get(&addr).unwrap();
        assert_eq!(score.blocks_delivered, 0);
        assert!(matches!(
            event_rx.try_recv(),
            Err(broadcast::error::TryRecvError::Empty)
        ));
    }
}
