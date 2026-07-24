use dashmap::DashMap;
use tokio::sync::{broadcast, mpsc, RwLock};
use tracing::{debug, info, trace, warn};

use crate::chain::SharedBlockchain;
use crate::error::Result;
use crate::network::dandelion::DandelionRouter;
use crate::network::peer::{PeerId, PeerInfo, PeerState};
use crate::network::protocol::{
    ChainWorkMessage, FlareMessage, Message, MessageType, VersionMessage,
};
use crate::network::scoring::PeerScorer;
use crate::network::sync::{build_locator, ChainSync};
use crate::primitives::Hash;

use super::super::broadcast::send_to_peer;
use super::super::types::NodeEvent;

pub(super) async fn handle_version(
    peer_id: PeerId,
    payload: &[u8],
    magic: [u8; 4],
    our_nonce: u64,
    peers: &DashMap<PeerId, PeerInfo>,
    senders: &DashMap<PeerId, mpsc::Sender<Vec<u8>>>,
    sync: &RwLock<ChainSync>,
    event_tx: &broadcast::Sender<NodeEvent>,
    chain: &SharedBlockchain,
    scorer: &RwLock<PeerScorer>,
) -> Result<()> {
    // SECURITY (M5): Limit payload size before deserializing VersionMessage
    // to prevent OOM from unbounded user_agent strings.
    const MAX_VERSION_MSG_SIZE: usize = 1024;
    if payload.len() > MAX_VERSION_MSG_SIZE {
        warn!(
            "Version message too large ({} bytes) from peer {:?}",
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
        peers.remove(&peer_id);
        senders.remove(&peer_id);
        let _ = event_tx.send(NodeEvent::PeerDisconnected(peer_id));
        return Ok(());
    }
    // Parse version and validate before accepting
    let version: VersionMessage = match borsh::from_slice(payload) {
        Ok(v) => v,
        Err(e) => {
            warn!(
                "Failed to deserialize Version from peer {:?}: {}",
                &peer_id[..4],
                e
            );
            if let Some(addr) = peers.get(&peer_id).map(|p| p.addr) {
                scorer.write().await.get_or_create(addr).record_misbehavior(
                    crate::network::scoring::MisbehaviorType::ProtocolViolation,
                );
            }
            peers.remove(&peer_id);
            senders.remove(&peer_id);
            let _ = event_tx.send(NodeEvent::PeerDisconnected(peer_id));
            return Ok(());
        }
    };
    {
        // SECURITY (NET-001 + eclipse-attack defense): Detect
        // self-connection via nonce match — but DON'T permanently
        // ban the peer's address.
        //
        // The previous code marked any address that sent us
        // `our_nonce` as "ours" and permanently skipped it. But
        // `our_nonce` is a per-node-lifetime u64; any peer who
        // received our Version (every peer we've dialed or been
        // dialed by) knows it and can replay it. An attacker
        // spins up a peer, reads our_nonce from our outbound
        // Version, then connects FROM A DIFFERENT ADDRESS sending
        // our_nonce back. With the old code we permanently banned
        // that address. Repeat → the attacker can blacklist
        // arbitrary IPs from our address book = eclipse attack
        // surface.
        //
        // The nonce is not bound to the dialed address, so a match may
        // disconnect but must not poison the address book as "self".
        if version.nonce == our_nonce {
            warn!(
                "Self-connection nonce match from peer {:?} \
                 — disconnecting. NOT marking as self-address \
                 because the nonce is replayable; if this fires \
                 repeatedly for legitimately-yours addresses, \
                 check that --addnode doesn't list this node's \
                 own IP.",
                &peer_id[..4],
            );
            peers.remove(&peer_id);
            senders.remove(&peer_id);
            let _ = event_tx.send(NodeEvent::PeerDisconnected(peer_id));
            return Ok(());
        }

        // SECURITY: Validate version message (protocol version, user agent length)
        if let Err(e) = version.validate() {
            warn!("Rejecting peer {:?}: invalid version: {}", &peer_id[..4], e);
            if let Some(addr) = peers.get(&peer_id).map(|p| p.addr) {
                scorer.write().await.get_or_create(addr).record_misbehavior(
                    crate::network::scoring::MisbehaviorType::ProtocolViolation,
                );
            }
            // Disconnect the peer
            peers.remove(&peer_id);
            senders.remove(&peer_id);
            let _ = event_tx.send(NodeEvent::PeerDisconnected(peer_id));
            return Ok(());
        }

        // Clone before awaiting so a full queue cannot hold a map guard.
        let sender = senders.get(&peer_id).map(|s| s.value().clone());
        if let Some(sender) = sender {
            let verack = Message::verack(magic);
            if let Err(e) = sender.send(verack.to_bytes()?).await {
                warn!("Failed to send Verack to peer {:?}: {}", &peer_id[..4], e);
            }
            // Firework: advertise our capabilities immediately after
            // Verack. A peer predating the capability layer receives
            // a valid-but-unhandled Flare (type 50) and simply drops
            // it via the dispatch catch-all — no disconnect — so this
            // is safe to send to every peer. Its capabilities stay 0
            // and each capability-gated feature falls back gracefully.
            let flare = Message::flare(magic, crate::network::firework::local_capabilities())?;
            if let Err(e) = sender.send(flare.to_bytes()?).await {
                warn!("Failed to send Flare to peer {:?}: {}", &peer_id[..4], e);
            }
        } else {
            warn!("No sender for peer {:?} when sending Verack", &peer_id[..4]);
        }

        if let Some(mut peer) = peers.get_mut(&peer_id) {
            peer.version = version.version;
            peer.user_agent = version.user_agent;
            peer.height = version.start_height;
            peer.tip_hash = version.best_hash;
            peer.state = PeerState::VersionReceived;
        }

        // Mark peer as validated in scorer
        if let Some(addr) = peers.get(&peer_id).map(|p| p.addr) {
            scorer.write().await.get_or_create(addr).validated = true;
        }

        // Update sync manager and propagate target_height to chain.
        // Do NOT send GetHeaders here — peer is still VersionReceived,
        // not Connected. Headers response would be dropped by the
        // dispatch handshake gate. GetHeaders fires in the Verack handler.
        {
            let mut s = sync.write().await;
            s.update_peer_height_for(peer_id, version.start_height);
            let stats = s.stats();
            let true_best = s.true_best_height();
            drop(s);
            chain.set_sync_info(stats.local_height >= true_best, true_best);
        }
    }
    Ok(())
}

pub(super) async fn handle_flare(
    peer_id: PeerId,
    payload: &[u8],
    magic: [u8; 4],
    peers: &DashMap<PeerId, PeerInfo>,
    senders: &DashMap<PeerId, mpsc::Sender<Vec<u8>>>,
    chain: &SharedBlockchain,
) -> Result<()> {
    // Firework capability advertisement. Store the peer's bitfield
    // into PeerInfo::capabilities; unknown bits are ignored by
    // consumers (which test specific CAP_* bits via has_cap). This
    // message is ADVISORY — an oversized or malformed payload is
    // dropped silently and is never a disconnect reason.
    const MAX_FLARE_MSG_SIZE: usize = 32;
    if payload.len() > MAX_FLARE_MSG_SIZE {
        trace!(
            "Oversized Flare ({} bytes) from peer {:?}, ignoring",
            payload.len(),
            &peer_id[..4]
        );
    } else {
        match borsh::from_slice::<FlareMessage>(payload) {
            Ok(flare) => {
                if let Some(mut peer) = peers.get_mut(&peer_id) {
                    peer.capabilities = flare.capabilities;
                }
                trace!(
                    "Peer {:?} advertised capabilities {:#x}",
                    &peer_id[..4],
                    flare.capabilities
                );
                // Firework Phase 2: if the peer supports CAP_CHAINWORK,
                // send our current cumulative work immediately so it
                // can evaluate our chain during handshake, not only on
                // our next tip advance.
                if crate::network::firework::has_cap(
                    flare.capabilities,
                    crate::network::firework::CAP_CHAINWORK,
                ) {
                    let sender = senders.get(&peer_id).map(|s| s.value().clone());
                    if let Some(sender) = sender {
                        match Message::chain_work(
                            magic,
                            chain.stats().total_difficulty,
                            chain.height(),
                            chain.tip_hash(),
                        )
                        .and_then(|m| m.to_bytes())
                        {
                            Ok(bytes) => {
                                let _ = sender.send(bytes).await;
                            }
                            Err(e) => warn!(
                                "Flare: failed to build ChainWork for peer {:?}: {}",
                                &peer_id[..4],
                                e
                            ),
                        }
                    }
                }
            }
            Err(e) => {
                trace!(
                    "Malformed Flare from peer {:?}: {} (ignoring)",
                    &peer_id[..4],
                    e
                );
            }
        }
    }
    Ok(())
}

pub(super) async fn handle_chain_work(
    peer_id: PeerId,
    payload: &[u8],
    peers: &DashMap<PeerId, PeerInfo>,
    sync: &RwLock<ChainSync>,
) -> Result<()> {
    // Firework Phase 2: a CAP_CHAINWORK peer told us its cumulative
    // work + tip. Feed it into the sync manager's peer-work table so
    // we can recognize a heavier chain even when it is shorter in
    // height. The advertised work is a CLAIM, not proof — it only
    // influences which peer we request headers from; adoption still
    // recomputes summed PoW in fork choice. update_peer_difficulty_for
    // already caps bogus over-claims. Advisory: malformed/oversized
    // payloads are dropped silently, never a disconnect reason.
    const MAX_CHAINWORK_MSG_SIZE: usize = 256;
    if payload.len() > MAX_CHAINWORK_MSG_SIZE {
        trace!(
            "Oversized ChainWork ({} bytes) from peer {:?}, ignoring",
            payload.len(),
            &peer_id[..4]
        );
    } else {
        match borsh::from_slice::<ChainWorkMessage>(payload) {
            Ok(cw) => {
                if let Some(mut peer) = peers.get_mut(&peer_id) {
                    peer.height = cw.height;
                    peer.tip_hash = cw.best_hash;
                }
                {
                    let mut s = sync.write().await;
                    s.update_peer_difficulty_for(peer_id, cw.total_difficulty);
                    s.update_peer_height_for(peer_id, cw.height);
                }
                trace!(
                    "Peer {:?} ChainWork: td={} h={}",
                    &peer_id[..4],
                    cw.total_difficulty,
                    cw.height
                );
            }
            Err(e) => {
                trace!(
                    "Malformed ChainWork from peer {:?}: {} (ignoring)",
                    &peer_id[..4],
                    e
                );
            }
        }
    }
    Ok(())
}

pub(super) async fn handle_verack(
    peer_id: PeerId,
    magic: [u8; 4],
    peers: &DashMap<PeerId, PeerInfo>,
    senders: &DashMap<PeerId, mpsc::Sender<Vec<u8>>>,
    dandelion: &RwLock<DandelionRouter>,
    sync: &RwLock<ChainSync>,
    chain: &SharedBlockchain,
) -> Result<()> {
    let is_outbound = peers.get(&peer_id).map(|p| p.outbound).unwrap_or(false);

    // Phase 1 #6: handshake complete — observe wall-time from
    // PeerInfo::connected_at (set at peers.insert) to now.
    if let Some(p) = peers.get(&peer_id) {
        let elapsed = p.connected_at.elapsed().as_secs_f64();
        crate::metrics::PEER_HANDSHAKE.observe(elapsed);
    }

    if let Some(mut peer) = peers.get_mut(&peer_id) {
        peer.state = PeerState::Connected;
    }

    // Register outbound peers for Dandelion++ relay selection
    if is_outbound {
        dandelion.write().await.add_outbound_peer(peer_id);
        debug!(
            "Added outbound peer {:?} to Dandelion++ pool",
            &peer_id[..4]
        );
    }

    // Send GetAddr to discover more peers after handshake
    let getaddr = Message::new(magic, MessageType::GetAddr, vec![]);
    if let Ok(data) = getaddr.to_bytes() {
        let _ = send_to_peer(senders, &peer_id, data).await;
    }

    // Handshake complete — if this peer is ahead, send GetHeaders with nonce.
    let peer_height = peers.get(&peer_id).map(|p| p.height).unwrap_or(0);
    let our_height = chain.height();
    if peer_height > our_height {
        let locator = build_locator(our_height, |h| chain.get_block_hash(h));
        if !locator.is_empty() {
            let now = chrono::Utc::now().timestamp() as u64;
            if let Some(nonce) = sync.write().await.begin_headers_request(peer_id, now) {
                let sent =
                    match Message::get_headers_with_nonce(magic, locator, Hash::zero(), nonce) {
                        Ok(message) => match message.to_bytes() {
                            Ok(data) => send_to_peer(senders, &peer_id, data).await,
                            Err(_) => false,
                        },
                        Err(_) => false,
                    };
                if sent {
                    info!(
                        "Handshake complete — GetHeaders nonce={} to peer {:?} (h={}, we={})",
                        nonce,
                        &peer_id[..4],
                        peer_height,
                        our_height
                    );
                } else {
                    sync.write().await.cancel_headers_request(nonce, &peer_id);
                }
            }
        }
    }
    Ok(())
}

pub(super) async fn handle_ping(
    peer_id: PeerId,
    payload: &[u8],
    magic: [u8; 4],
    peers: &DashMap<PeerId, PeerInfo>,
    senders: &DashMap<PeerId, mpsc::Sender<Vec<u8>>>,
    scorer: &RwLock<PeerScorer>,
) -> Result<()> {
    // Parse nonce and respond with pong.
    // P5-N5 fix: score malformed pings (< 8 bytes) as protocol violation.
    if payload.len() < 8 {
        warn!("Malformed Ping (<8 bytes) from peer {:?}", &peer_id[..4]);
        if let Some(addr) = peers.get(&peer_id).map(|p| p.addr) {
            scorer
                .write()
                .await
                .get_or_create(addr)
                .record_misbehavior(crate::network::scoring::MisbehaviorType::ProtocolViolation);
        }
        return Ok(());
    }
    let nonce = u64::from_le_bytes(payload[..8].try_into().expect("ping length was validated"));
    let pong = Message::pong(magic, nonce);
    let _ = send_to_peer(senders, &peer_id, pong.to_bytes()?).await;
    Ok(())
}

pub(super) fn handle_pong() {}

pub(super) fn handle_reject(peer_id: PeerId, peers: &DashMap<PeerId, PeerInfo>) {
    // Reject can reflect benign disagreement, so it must not feed the ban scorer.
    if let Some(mut peer) = peers.get_mut(&peer_id) {
        peer.adjust_reputation(-5);
    }
}
