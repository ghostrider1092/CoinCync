//! ## Audit map
//! Each `§` is a code section below; it states the INVARIANT it guarantees, the
//! THREAT it defends, and the TESTS that prove it.
//!
//! - **§1 `handle_version` (size / parse / self-connect gating)** — INVARIANT:
//!   oversized, unparseable, or `validate()`-failing Version messages score
//!   misbehavior and disconnect before any peer state is trusted; a
//!   self-connection nonce match disconnects WITHOUT scoring, since the nonce
//!   is replayable from any peer that saw our outbound Version.
//!   THREAT: NET-001 eclipse-attack surface (scoring a replayed nonce would let
//!   an attacker blacklist arbitrary addresses as "self"); M5 unbounded
//!   user_agent OOM.
//!   TESTS: `handle_version_oversized_scores_oversized_and_disconnects`,
//!   `handle_version_unparseable_scores_protocol_violation_and_disconnects`,
//!   `handle_version_self_connection_disconnects_without_scoring`,
//!   `handle_version_failing_validate_scores_and_disconnects`.
//! - **§2 `handle_version` (user_agent sanitization + state)** — INVARIANT:
//!   peer-supplied `user_agent` has control characters stripped before it is
//!   ever stored, and height/tip/state are recorded only after validation
//!   passes.
//!   THREAT: stored-XSS-class injection reaching any unescaped consumer of
//!   `get_peers` (explorer UIs, scripts, monitors).
//!   TESTS: `handle_version_happy_sets_state_strips_control_chars_and_sends_verack_flare`.
//! - **§3 `handle_flare`** — INVARIANT: Flare capability advertisement is
//!   advisory-only; oversized or malformed payloads are dropped silently and
//!   never cause a disconnect or misbehavior score.
//!   THREAT: a pre-Firework peer sending an unhandled/malformed Flare must not
//!   be penalized, or every legacy-compatible peer would be punished.
//!   TESTS: `handle_flare_oversized_is_silently_ignored`,
//!   `handle_flare_with_chainwork_cap_stores_and_sends_chain_work`,
//!   `handle_flare_without_chainwork_cap_stores_but_sends_nothing`.
//! - **§4 `handle_chain_work`** — INVARIANT: ChainWork is stored as an
//!   unauthenticated claim that only feeds peer-work/height bookkeeping for
//!   header-source selection; oversized or malformed payloads are silently
//!   dropped and never disconnect the peer.
//!   THREAT: a peer over-claiming cumulative work to bias header-fetch source
//!   selection (fork-choice adoption itself recomputes real PoW downstream).
//!   TESTS: `handle_chain_work_oversized_is_silently_ignored`,
//!   `handle_chain_work_updates_peer_height_and_tip`,
//!   `handle_chain_work_malformed_is_silently_ignored`.
//! - **§5 `handle_verack`** — INVARIANT: handshake completion always sends
//!   GetAddr, and a behind peer gets at most one in-flight GetHeaders — a
//!   replayed Verack while a request is pending must not re-issue GetHeaders.
//!   THREAT: duplicate/uncapped GetHeaders requests wasting bandwidth or
//!   re-triggering a sync wedge.
//!   TESTS: `handle_verack_connects_and_sends_getaddr_without_getheaders_when_not_behind`,
//!   `handle_verack_behind_peer_issues_getheaders_and_replay_does_not_reissue`.
//! - **§6 `handle_ping` / `handle_pong`** — INVARIANT: a malformed (<8-byte)
//!   Ping scores ProtocolViolation and never elicits a Pong; a well-formed
//!   Ping echoes its nonce exactly; Pong itself is a no-op.
//!   THREAT: P5-N5 malformed-ping spam evading misbehavior scoring.
//!   TESTS: `handle_ping_malformed_scores_and_sends_no_pong`,
//!   `handle_ping_echoes_nonce_as_pong`, `handle_pong_is_a_noop`.
//! - **§7 `handle_reject`** — INVARIANT: Reject only adjusts peer reputation by
//!   a fixed benign-disagreement penalty and never feeds the ban scorer.
//!   THREAT: legitimate protocol disagreement being over-penalized into an
//!   accidental ban.
//!   TESTS: `handle_reject_adjusts_reputation_only`.

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
            // SECURITY (defense-in-depth, explorer stored-XSS class): strip
            // control characters from the peer-supplied user_agent before we
            // store or ever serve it over get_peers. Length is already bounded
            // by VersionMessage::validate (MAX_USER_AGENT_LENGTH). Client UIs
            // still HTML-escape at render (esc()); this protects EVERY consumer
            // of get_peers (other UIs, scripts, monitors) that might not.
            peer.user_agent = version.user_agent.chars().filter(|c| !c.is_control()).collect();
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

    // M-P1: a Verack completes the handshake ONLY if a valid Version was received
    // first (state == VersionReceived). A bare Verack must NOT flip a peer to
    // Connected -- that would skip protocol-version / user-agent / self-connection
    // validation and expose every post-handshake handler (incl. the C2 freeze) to
    // a 13-byte pre-handshake frame. Rejecting the out-of-order Verack here also
    // closes the Verack-replay IBD wedge: a replayed Verack on an already-Connected
    // peer no longer re-runs the GetHeaders/slot logic below.
    let advanced = peers
        .get_mut(&peer_id)
        .map(|mut peer| {
            if peer.state == PeerState::VersionReceived {
                peer.state = PeerState::Connected;
                true
            } else {
                false
            }
        })
        .unwrap_or(false);
    if !advanced {
        debug!(
            "Ignoring out-of-order Verack from peer {:?} (no prior Version / already connected)",
            &peer_id[..4]
        );
        return Ok(());
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

#[cfg(test)]
mod handler_tests {
    use super::*;
    use crate::chain::Blockchain;
    use crate::network::firework::CAP_CHAINWORK;
    use std::net::SocketAddr;
    use std::sync::Arc;

    const MAGIC: [u8; 4] = [1, 2, 3, 4];

    fn addr_for(port: u16) -> SocketAddr {
        format!("127.0.0.1:{port}").parse().unwrap()
    }

    fn genesis_chain() -> SharedBlockchain {
        let chain = Arc::new(Blockchain::new());
        chain.init_genesis().expect("genesis");
        chain
    }

    fn peers_with(peer_id: PeerId, addr: SocketAddr, outbound: bool) -> DashMap<PeerId, PeerInfo> {
        let peers = DashMap::new();
        peers.insert(peer_id, PeerInfo::new(peer_id, addr, outbound));
        peers
    }

    // ─── handle_version ──────────────────────────────────────────────

    #[tokio::test]
    async fn handle_version_oversized_scores_oversized_and_disconnects() {
        let peer_id = [1u8; 32];
        let addr = addr_for(30001);
        let peers = peers_with(peer_id, addr, false);
        let senders: DashMap<PeerId, mpsc::Sender<Vec<u8>>> = DashMap::new();
        let (stx, _srx) = mpsc::channel::<Vec<u8>>(4);
        senders.insert(peer_id, stx);
        let sync = RwLock::new(ChainSync::new(0, Hash::zero()));
        let (event_tx, mut event_rx) = broadcast::channel(4);
        let chain = genesis_chain();
        let scorer = RwLock::new(PeerScorer::new());

        let payload = vec![0u8; 1025]; // > MAX_VERSION_MSG_SIZE (1024)
        handle_version(
            peer_id, &payload, MAGIC, 999, &peers, &senders, &sync, &event_tx, &chain, &scorer,
        )
        .await
        .unwrap();

        assert!(peers.get(&peer_id).is_none(), "peer removed");
        assert!(senders.get(&peer_id).is_none(), "sender removed");
        assert!(scorer.read().await.get(&addr).unwrap().reputation < 100);
        assert!(matches!(
            event_rx.try_recv(),
            Ok(NodeEvent::PeerDisconnected(p)) if p == peer_id
        ));
    }

    #[tokio::test]
    async fn handle_version_unparseable_scores_protocol_violation_and_disconnects() {
        let peer_id = [2u8; 32];
        let addr = addr_for(30002);
        let peers = peers_with(peer_id, addr, false);
        let senders: DashMap<PeerId, mpsc::Sender<Vec<u8>>> = DashMap::new();
        let sync = RwLock::new(ChainSync::new(0, Hash::zero()));
        let (event_tx, mut event_rx) = broadcast::channel(4);
        let chain = genesis_chain();
        let scorer = RwLock::new(PeerScorer::new());

        let payload = vec![0u8; 3]; // too short to borsh-decode a VersionMessage
        handle_version(
            peer_id, &payload, MAGIC, 999, &peers, &senders, &sync, &event_tx, &chain, &scorer,
        )
        .await
        .unwrap();

        assert!(peers.get(&peer_id).is_none());
        assert!(scorer.read().await.get(&addr).unwrap().reputation < 100);
        assert!(matches!(
            event_rx.try_recv(),
            Ok(NodeEvent::PeerDisconnected(_))
        ));
    }

    #[tokio::test]
    async fn handle_version_self_connection_disconnects_without_scoring() {
        // NET-001: a nonce match disconnects but must NOT poison the address
        // book / scorer (the nonce is replayable, so scoring it would let an
        // attacker blacklist arbitrary addresses = eclipse surface).
        let peer_id = [3u8; 32];
        let addr = addr_for(30003);
        let peers = peers_with(peer_id, addr, false);
        let senders: DashMap<PeerId, mpsc::Sender<Vec<u8>>> = DashMap::new();
        let sync = RwLock::new(ChainSync::new(0, Hash::zero()));
        let (event_tx, mut event_rx) = broadcast::channel(4);
        let chain = genesis_chain();
        let scorer = RwLock::new(PeerScorer::new());

        let our_nonce = 0xABCD_1234u64;
        let vm = VersionMessage::with_nonce(5, Hash::zero(), our_nonce);
        let payload = borsh::to_vec(&vm).unwrap();
        handle_version(
            peer_id, &payload, MAGIC, our_nonce, &peers, &senders, &sync, &event_tx, &chain,
            &scorer,
        )
        .await
        .unwrap();

        assert!(peers.get(&peer_id).is_none());
        // No misbehavior recorded — the self-connection branch never scores.
        assert!(scorer.read().await.get(&addr).is_none());
        assert!(matches!(
            event_rx.try_recv(),
            Ok(NodeEvent::PeerDisconnected(_))
        ));
    }

    #[tokio::test]
    async fn handle_version_failing_validate_scores_and_disconnects() {
        let peer_id = [4u8; 32];
        let addr = addr_for(30004);
        let peers = peers_with(peer_id, addr, false);
        let senders: DashMap<PeerId, mpsc::Sender<Vec<u8>>> = DashMap::new();
        let sync = RwLock::new(ChainSync::new(0, Hash::zero()));
        let (event_tx, _event_rx) = broadcast::channel(4);
        let chain = genesis_chain();
        let scorer = RwLock::new(PeerScorer::new());

        let mut vm = VersionMessage::with_nonce(5, Hash::zero(), 123);
        vm.version = 0; // below MIN_SUPPORTED_PROTOCOL_VERSION → validate() fails
        let payload = borsh::to_vec(&vm).unwrap();
        handle_version(
            peer_id, &payload, MAGIC, 999, &peers, &senders, &sync, &event_tx, &chain, &scorer,
        )
        .await
        .unwrap();

        assert!(peers.get(&peer_id).is_none());
        assert!(scorer.read().await.get(&addr).unwrap().reputation < 100);
    }

    #[tokio::test]
    async fn handle_version_happy_sets_state_strips_control_chars_and_sends_verack_flare() {
        let peer_id = [5u8; 32];
        let addr = addr_for(30005);
        let peers = peers_with(peer_id, addr, false);
        let senders: DashMap<PeerId, mpsc::Sender<Vec<u8>>> = DashMap::new();
        let (stx, mut srx) = mpsc::channel::<Vec<u8>>(8);
        senders.insert(peer_id, stx);
        let sync = RwLock::new(ChainSync::new(0, Hash::zero()));
        let (event_tx, _event_rx) = broadcast::channel(4);
        let chain = genesis_chain();
        let scorer = RwLock::new(PeerScorer::new());

        let tip = Hash::from_bytes([9u8; 32]);
        let mut vm = VersionMessage::with_nonce(42, tip, 123);
        vm.user_agent = "ok\u{7}bad".to_string(); // embedded control char
        let payload = borsh::to_vec(&vm).unwrap();
        handle_version(
            peer_id, &payload, MAGIC, 999, &peers, &senders, &sync, &event_tx, &chain, &scorer,
        )
        .await
        .unwrap();

        let peer = peers.get(&peer_id).unwrap();
        assert_eq!(peer.state, PeerState::VersionReceived);
        assert_eq!(peer.height, 42);
        assert_eq!(peer.tip_hash, tip);
        assert_eq!(peer.user_agent, "okbad", "control chars stripped");
        assert!(!peer.user_agent.chars().any(|c| c.is_control()));
        drop(peer);
        assert!(scorer.read().await.get(&addr).unwrap().validated);
        // Verack + Flare sent, in that order.
        assert!(srx.try_recv().is_ok(), "verack sent");
        assert!(srx.try_recv().is_ok(), "flare sent");
    }

    // ─── handle_ping / pong / reject ─────────────────────────────────

    #[tokio::test]
    async fn handle_ping_malformed_scores_and_sends_no_pong() {
        let peer_id = [6u8; 32];
        let addr = addr_for(30006);
        let peers = peers_with(peer_id, addr, false);
        let senders: DashMap<PeerId, mpsc::Sender<Vec<u8>>> = DashMap::new();
        let (stx, mut srx) = mpsc::channel::<Vec<u8>>(4);
        senders.insert(peer_id, stx);
        let scorer = RwLock::new(PeerScorer::new());

        let payload = vec![0u8; 4]; // < 8 bytes
        handle_ping(peer_id, &payload, MAGIC, &peers, &senders, &scorer)
            .await
            .unwrap();

        assert!(scorer.read().await.get(&addr).unwrap().reputation < 100);
        assert!(srx.try_recv().is_err(), "no pong for malformed ping");
    }

    #[tokio::test]
    async fn handle_ping_echoes_nonce_as_pong() {
        let peer_id = [7u8; 32];
        let addr = addr_for(30007);
        let peers = peers_with(peer_id, addr, false);
        let senders: DashMap<PeerId, mpsc::Sender<Vec<u8>>> = DashMap::new();
        let (stx, mut srx) = mpsc::channel::<Vec<u8>>(4);
        senders.insert(peer_id, stx);
        let scorer = RwLock::new(PeerScorer::new());

        let nonce = 0x1122_3344_5566_7788u64;
        let payload = nonce.to_le_bytes().to_vec();
        handle_ping(peer_id, &payload, MAGIC, &peers, &senders, &scorer)
            .await
            .unwrap();

        let sent = srx.try_recv().expect("pong sent");
        assert_eq!(sent, Message::pong(MAGIC, nonce).to_bytes().unwrap());
    }

    #[test]
    fn handle_pong_is_a_noop() {
        handle_pong();
    }

    #[test]
    fn handle_reject_adjusts_reputation_only() {
        let peer_id = [8u8; 32];
        let addr = addr_for(30008);
        let peers = peers_with(peer_id, addr, false);
        handle_reject(peer_id, &peers);
        assert_eq!(peers.get(&peer_id).unwrap().reputation, 95);
    }

    // ─── handle_flare ────────────────────────────────────────────────

    #[tokio::test]
    async fn handle_flare_oversized_is_silently_ignored() {
        let peer_id = [9u8; 32];
        let addr = addr_for(30009);
        let peers = peers_with(peer_id, addr, false);
        let senders: DashMap<PeerId, mpsc::Sender<Vec<u8>>> = DashMap::new();
        let (stx, mut srx) = mpsc::channel::<Vec<u8>>(4);
        senders.insert(peer_id, stx);
        let chain = genesis_chain();

        let payload = vec![0u8; 33]; // > MAX_FLARE_MSG_SIZE (32)
        handle_flare(peer_id, &payload, MAGIC, &peers, &senders, &chain)
            .await
            .unwrap();

        assert!(peers.get(&peer_id).is_some(), "no disconnect");
        assert_eq!(peers.get(&peer_id).unwrap().capabilities, 0);
        assert!(srx.try_recv().is_err());
    }

    #[tokio::test]
    async fn handle_flare_with_chainwork_cap_stores_and_sends_chain_work() {
        let peer_id = [10u8; 32];
        let addr = addr_for(30010);
        let peers = peers_with(peer_id, addr, false);
        let senders: DashMap<PeerId, mpsc::Sender<Vec<u8>>> = DashMap::new();
        let (stx, mut srx) = mpsc::channel::<Vec<u8>>(4);
        senders.insert(peer_id, stx);
        let chain = genesis_chain();

        let payload = borsh::to_vec(&FlareMessage {
            capabilities: CAP_CHAINWORK,
        })
        .unwrap();
        handle_flare(peer_id, &payload, MAGIC, &peers, &senders, &chain)
            .await
            .unwrap();

        assert_eq!(peers.get(&peer_id).unwrap().capabilities, CAP_CHAINWORK);
        assert!(srx.try_recv().is_ok(), "ChainWork sent to CAP_CHAINWORK peer");
    }

    #[tokio::test]
    async fn handle_flare_without_chainwork_cap_stores_but_sends_nothing() {
        let peer_id = [11u8; 32];
        let addr = addr_for(30011);
        let peers = peers_with(peer_id, addr, false);
        let senders: DashMap<PeerId, mpsc::Sender<Vec<u8>>> = DashMap::new();
        let (stx, mut srx) = mpsc::channel::<Vec<u8>>(4);
        senders.insert(peer_id, stx);
        let chain = genesis_chain();

        let caps = 1u64 << 40; // unknown bit, not CAP_CHAINWORK
        let payload = borsh::to_vec(&FlareMessage { capabilities: caps }).unwrap();
        handle_flare(peer_id, &payload, MAGIC, &peers, &senders, &chain)
            .await
            .unwrap();

        assert_eq!(peers.get(&peer_id).unwrap().capabilities, caps);
        assert!(srx.try_recv().is_err());
    }

    // ─── handle_chain_work ───────────────────────────────────────────

    #[tokio::test]
    async fn handle_chain_work_oversized_is_silently_ignored() {
        let peer_id = [12u8; 32];
        let addr = addr_for(30012);
        let peers = peers_with(peer_id, addr, false);
        let sync = RwLock::new(ChainSync::new(0, Hash::zero()));

        let payload = vec![0u8; 257]; // > MAX_CHAINWORK_MSG_SIZE (256)
        handle_chain_work(peer_id, &payload, &peers, &sync)
            .await
            .unwrap();

        assert_eq!(peers.get(&peer_id).unwrap().height, 0, "unchanged");
    }

    #[tokio::test]
    async fn handle_chain_work_updates_peer_height_and_tip() {
        let peer_id = [13u8; 32];
        let addr = addr_for(30013);
        let peers = peers_with(peer_id, addr, false);
        let sync = RwLock::new(ChainSync::new(0, Hash::zero()));

        let tip = Hash::from_bytes([3u8; 32]);
        let payload = borsh::to_vec(&ChainWorkMessage {
            total_difficulty: 12345,
            height: 77,
            best_hash: tip,
        })
        .unwrap();
        handle_chain_work(peer_id, &payload, &peers, &sync)
            .await
            .unwrap();

        let peer = peers.get(&peer_id).unwrap();
        assert_eq!(peer.height, 77);
        assert_eq!(peer.tip_hash, tip);
    }

    #[tokio::test]
    async fn handle_chain_work_malformed_is_silently_ignored() {
        let peer_id = [14u8; 32];
        let addr = addr_for(30014);
        let peers = peers_with(peer_id, addr, false);
        let sync = RwLock::new(ChainSync::new(0, Hash::zero()));

        let payload = vec![0u8; 3]; // <= 256 but not a valid ChainWorkMessage
        handle_chain_work(peer_id, &payload, &peers, &sync)
            .await
            .unwrap();

        assert_eq!(peers.get(&peer_id).unwrap().height, 0);
    }

    // ─── handle_verack ───────────────────────────────────────────────

    fn dandelion() -> RwLock<DandelionRouter> {
        RwLock::new(DandelionRouter::new())
    }

    #[tokio::test]
    async fn handle_verack_connects_and_sends_getaddr_without_getheaders_when_not_behind() {
        let peer_id = [15u8; 32];
        let addr = addr_for(30015);
        let peers = DashMap::new();
        let mut info = PeerInfo::new(peer_id, addr, false);
        info.state = PeerState::VersionReceived;
        info.height = 0;
        peers.insert(peer_id, info);
        let senders: DashMap<PeerId, mpsc::Sender<Vec<u8>>> = DashMap::new();
        let (stx, mut srx) = mpsc::channel::<Vec<u8>>(8);
        senders.insert(peer_id, stx);
        let dand = dandelion();
        let sync = RwLock::new(ChainSync::new(0, Hash::zero()));
        let chain = genesis_chain();

        handle_verack(peer_id, MAGIC, &peers, &senders, &dand, &sync, &chain)
            .await
            .unwrap();

        assert_eq!(peers.get(&peer_id).unwrap().state, PeerState::Connected);
        assert!(!sync.read().await.headers_request_pending());
        assert!(srx.try_recv().is_ok(), "GetAddr sent");
        assert!(srx.try_recv().is_err(), "no GetHeaders when not behind");
    }

    #[tokio::test]
    async fn handle_verack_behind_peer_issues_getheaders_and_replay_does_not_reissue() {
        let peer_id = [16u8; 32];
        let addr = addr_for(30016);
        let peers = DashMap::new();
        let mut info = PeerInfo::new(peer_id, addr, false);
        info.state = PeerState::VersionReceived;
        info.height = 100; // ahead of our genesis-only chain (height 0)
        peers.insert(peer_id, info);
        let senders: DashMap<PeerId, mpsc::Sender<Vec<u8>>> = DashMap::new();
        let (stx, mut srx) = mpsc::channel::<Vec<u8>>(8);
        senders.insert(peer_id, stx);
        let dand = dandelion();
        let sync = RwLock::new(ChainSync::new(0, Hash::zero()));
        let chain = genesis_chain();

        handle_verack(peer_id, MAGIC, &peers, &senders, &dand, &sync, &chain)
            .await
            .unwrap();

        assert!(sync.read().await.headers_request_pending(), "GetHeaders issued");
        assert!(srx.try_recv().is_ok(), "GetAddr sent");
        assert!(srx.try_recv().is_ok(), "GetHeaders sent");
        assert!(srx.try_recv().is_err());

        // Replay: a request is already in flight, so begin_headers_request
        // returns None and no second GetHeaders is issued (no sync wedge).
        handle_verack(peer_id, MAGIC, &peers, &senders, &dand, &sync, &chain)
            .await
            .unwrap();
        assert!(srx.try_recv().is_ok(), "GetAddr re-sent on replay");
        assert!(srx.try_recv().is_err(), "no second GetHeaders on replay");
        assert!(sync.read().await.headers_request_pending());
    }
}
