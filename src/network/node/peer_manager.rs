use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use dashmap::DashMap;
use tokio::net::TcpListener;
use tokio::sync::{broadcast, mpsc, watch, RwLock};
use tokio::task::{JoinHandle, JoinSet};
use tokio::time::interval;
use tracing::{debug, info, trace, warn};

use crate::config::{P2PEncryptionConfig, ProxyConfig};

use super::super::bootstrap::AddressManager;
use super::super::connection_tracker::{ConnectionTracker, OutboundSubnetSlot};
use super::super::dandelion::DandelionRouter;
use super::super::noise::NodeIdentity;
use super::super::peer::{generate_peer_id, PeerId, PeerInfo, PeerState};
use super::super::relay_score::RelayScoreMap;
use super::super::scoring::{OrphanFloodTracker, PeerScorer};
use super::super::sync::ChainSync;
use super::chain_state::ChainStateReader;
use super::connection::handle_connection;
use super::constants::{CONNECT_TIMEOUT, MAX_INBOUND};
use super::runtime::wait_for_shutdown;
use super::types::NodeEvent;
use super::PeerMessage;

type BackoffMap = Arc<
    tokio::sync::Mutex<
        std::collections::HashMap<
            SocketAddr,
            (
                std::time::Instant,
                super::super::framing::ExponentialBackoff,
            ),
        >,
    >,
>;
type LastAttemptMap =
    Arc<tokio::sync::Mutex<std::collections::HashMap<SocketAddr, std::time::Instant>>>;

struct OutboundAttempt {
    addr: SocketAddr,
    peers: Arc<DashMap<PeerId, PeerInfo>>,
    senders: Arc<DashMap<PeerId, mpsc::Sender<Vec<u8>>>>,
    addresses: Arc<RwLock<AddressManager>>,
    event_tx: broadcast::Sender<NodeEvent>,
    msg_tx: mpsc::Sender<PeerMessage>,
    height: u64,
    tip: crate::primitives::Hash,
    proxy: Option<ProxyConfig>,
    backoffs: BackoffMap,
    identity: Arc<NodeIdentity>,
    encryption: P2PEncryptionConfig,
    tracker: Arc<ConnectionTracker>,
    outbound_slot: Arc<OutboundSubnetSlot>,
    magic: [u8; 4],
    our_nonce: u64,
}

pub(super) struct AcceptorContext {
    pub peers: Arc<DashMap<PeerId, PeerInfo>>,
    pub event_tx: broadcast::Sender<NodeEvent>,
    pub msg_tx: mpsc::Sender<PeerMessage>,
    pub senders: Arc<DashMap<PeerId, mpsc::Sender<Vec<u8>>>>,
    pub chain_state: ChainStateReader,
    pub tracker: Arc<ConnectionTracker>,
    pub scorer: Arc<RwLock<PeerScorer>>,
    pub identity: Arc<NodeIdentity>,
    pub relay_scores: Arc<RwLock<RelayScoreMap>>,
    pub encryption: P2PEncryptionConfig,
    pub onion_only: bool,
    pub magic: [u8; 4],
    pub our_nonce: u64,
}

pub(super) fn spawn_listener_acceptor(
    listener: TcpListener,
    context: AcceptorContext,
    mut shutdown: watch::Receiver<bool>,
) -> JoinHandle<()> {
    let AcceptorContext {
        peers: acceptor_peers,
        event_tx: acceptor_event_tx,
        msg_tx: acceptor_msg_tx,
        senders: acceptor_senders,
        chain_state: acceptor_chain_state,
        tracker: acceptor_tracker,
        scorer: acceptor_scorer,
        identity: acceptor_identity,
        relay_scores: acceptor_relay_scores,
        encryption: acceptor_encryption,
        onion_only,
        magic,
        our_nonce,
    } = context;

    tokio::spawn(async move {
        let mut connections = JoinSet::new();
        loop {
            let accepted = tokio::select! {
                biased;
                _ = wait_for_shutdown(&mut shutdown) => break,
                Some(result) = connections.join_next(), if !connections.is_empty() => {
                    log_connection_task_result("inbound", result);
                    continue;
                }
                accepted = listener.accept() => accepted,
            };
            match accepted {
                Ok((stream, addr)) => {
                    // SECURITY (M-9): In onion-only mode, reject non-localhost
                    // inbound connections to prevent clearnet IP exposure.
                    if onion_only && !addr.ip().is_loopback() {
                        debug!(
                            "Rejecting non-local inbound in onion-only mode from {}",
                            addr
                        );
                        continue;
                    }

                    // Check if peer is banned by scorer
                    if acceptor_scorer.read().await.is_banned(&addr) {
                        debug!("Rejecting banned peer {}", addr);
                        continue;
                    }

                    // SECURITY: Atomic check-and-track to prevent TOCTOU race
                    // where two connections from the same IP could both pass can_accept()
                    // before either calls track_connection()
                    if !acceptor_tracker.try_track_connection(&addr) {
                        debug!("Per-IP limit reached for {}, rejecting", addr.ip());
                        continue;
                    }

                    let inbound_count = acceptor_peers.iter().filter(|p| !p.outbound).count();

                    if inbound_count >= MAX_INBOUND {
                        // Saturation. Before rejecting, try to evict
                        // a more-evictable peer per the Bitcoin Core
                        // `CConnman::AttemptToEvictConnection`
                        // algorithm (VERIFIED at net.cpp:1694 in
                        // the master read this session; candidate
                        // selection delegated to node/eviction.cpp,
                        // see network/eviction.rs for details). This
                        // closes the eclipse vector where an attacker
                        // fills all 64 slots from one /16 and pins us.
                        //
                        // Snapshot the inbound peers, hand them to the
                        // selector, then disconnect the chosen victim
                        // (if any) by dropping its sender and removing
                        // it from the peers table.
                        let snapshot: Vec<crate::network::peer::PeerInfo> = acceptor_peers
                            .iter()
                            .filter(|p| !p.outbound)
                            .map(|p| p.clone())
                            .collect();
                        let now = std::time::Instant::now();
                        let victim_ref: Vec<&crate::network::peer::PeerInfo> =
                            snapshot.iter().collect();
                        let relay_guard = acceptor_relay_scores.read().await;
                        match crate::network::eviction::select_inbound_to_evict(
                            victim_ref,
                            now,
                            &relay_guard,
                        ) {
                            Some(victim_id) => {
                                debug!(
                                "Inbound saturated ({}); evicting peer {:?} per AttemptToEvictConnection to admit {}",
                                inbound_count, &victim_id[..4], addr
                            );
                                // Drop the sender first so the peer's
                                // write task unwinds; then remove
                                // from peers + untrack the IP.
                                // (The prior comment claimed this
                                // order matches Bitcoin Core's
                                // CConnman eviction sequence; the
                                // specific upstream ordering was
                                // not re-verified this session, so
                                // the parity claim is downgraded to
                                // qualitative.)
                                acceptor_senders.remove(&victim_id);
                                if let Some((_, victim)) = acceptor_peers.remove(&victim_id) {
                                    acceptor_tracker.untrack_connection(&victim.addr);
                                }
                                // Slot freed; fall through to accept.
                            }
                            None => {
                                debug!(
                                "Max inbound connections reached ({}) and no evictable peer; rejecting {}",
                                inbound_count, addr
                            );
                                acceptor_tracker.untrack_connection(&addr);
                                continue;
                            }
                        }
                    }

                    debug!(
                        "Incoming connection from {} (IP has {} connections)",
                        addr,
                        acceptor_tracker.connections_from(&addr.ip())
                    );

                    let peer_id = generate_peer_id();
                    let peers = acceptor_peers.clone();
                    let senders = acceptor_senders.clone();
                    let event_tx = acceptor_event_tx.clone();
                    let msg_tx = acceptor_msg_tx.clone();
                    let (height, tip) = acceptor_chain_state.snapshot().await;
                    let tracker = acceptor_tracker.clone();
                    let addr_clone = addr;
                    let conn_identity = acceptor_identity.clone();
                    let conn_encryption = acceptor_encryption.clone();

                    connections.spawn(async move {
                        let result = handle_connection(
                            stream,
                            peer_id,
                            false,
                            magic,
                            our_nonce,
                            height,
                            tip,
                            peers,
                            senders,
                            event_tx,
                            msg_tx,
                            tracker.clone(),
                            conn_identity,
                            conn_encryption,
                            None, // inbound — no per-/16 slot to track
                        )
                        .await;

                        // Untrack connection when done
                        tracker.untrack_connection(&addr_clone);

                        if let Err(e) = result {
                            warn!("Inbound connection error: {}", e);
                        }
                    });
                }
                Err(e) => {
                    warn!("Accept error: {}", e);
                }
            }
        }

        connections.abort_all();
        while let Some(result) = connections.join_next().await {
            log_connection_task_result("inbound", result);
        }
    })
}

pub(super) struct OutboundContext {
    pub peers: Arc<DashMap<PeerId, PeerInfo>>,
    pub addresses: Arc<RwLock<AddressManager>>,
    pub event_tx: broadcast::Sender<NodeEvent>,
    pub msg_tx: mpsc::Sender<PeerMessage>,
    pub senders: Arc<DashMap<PeerId, mpsc::Sender<Vec<u8>>>>,
    pub chain_state: ChainStateReader,
    pub proxy: Option<ProxyConfig>,
    pub scorer: Arc<RwLock<PeerScorer>>,
    pub identity: Arc<NodeIdentity>,
    pub encryption: P2PEncryptionConfig,
    pub listen_port: u16,
    pub tracker: Arc<ConnectionTracker>,
    pub data_dir: PathBuf,
    pub max_outbound: usize,
    pub magic: [u8; 4],
    pub our_nonce: u64,
}

/// The connector wakes on its interval and then observes `running`, preserving
/// the existing shutdown latency and connection-attempt ordering.
pub(super) fn spawn_outbound_connector(
    context: OutboundContext,
    mut shutdown: watch::Receiver<bool>,
) -> JoinHandle<()> {
    let OutboundContext {
        peers: connector_peers,
        addresses: connector_addresses,
        event_tx: connector_event_tx,
        msg_tx: connector_msg_tx,
        senders: connector_senders,
        chain_state: connector_chain_state,
        proxy: connector_proxy,
        scorer: connector_scorer,
        identity: connector_identity,
        encryption: connector_encryption,
        listen_port: connector_listen_port,
        tracker: connector_tracker,
        data_dir: connector_data_dir,
        max_outbound,
        magic,
        our_nonce,
    } = context;

    tokio::spawn(async move {
        let mut connections = JoinSet::new();
        let mut interval = interval(Duration::from_secs(10));
        // ANCHORS: persist known-good outbound peers roughly every 60s
        // (every 6th 10s tick) so a hard kill (SIGKILL, OOM, power loss)
        // still leaves a recent anchor set for fast reconnect. Graceful
        // shutdown also saves in stop().
        let mut anchor_save_tick: u32 = 0;
        // Per-address exponential backoff for failed connections
        let backoffs: BackoffMap =
            Arc::new(tokio::sync::Mutex::new(std::collections::HashMap::new()));
        // CHANGE 3: Per-address last-attempt timestamp for minimum 30s reconnect delay
        // (Bitcoin CConnman uses 30s between attempts to the same address).
        // This prevents rapid connect/disconnect cycles that waste Noise handshake slots.
        let last_attempt: LastAttemptMap =
            Arc::new(tokio::sync::Mutex::new(std::collections::HashMap::new()));
        const MIN_RECONNECT_DELAY: Duration = Duration::from_secs(30);

        // Log proxy status on startup
        if let Some(ref proxy) = connector_proxy {
            if proxy.is_active() {
                info!(
                    "Outbound connections will use {} proxy at {}:{}",
                    match proxy.proxy_type {
                        crate::config::ProxyType::Socks5 => "SOCKS5",
                        crate::config::ProxyType::Socks4 => "SOCKS4",
                        crate::config::ProxyType::Http => "HTTP",
                    },
                    proxy.address,
                    proxy.port
                );
                if proxy.onion_only {
                    info!("Onion-only mode enabled - will only connect to .onion peers");
                }
            }
        }

        loop {
            tokio::select! {
                biased;
                _ = wait_for_shutdown(&mut shutdown) => break,
                Some(result) = connections.join_next(), if !connections.is_empty() => {
                    log_connection_task_result("outbound", result);
                    continue;
                }
                _ = interval.tick() => {}
            }

            // ANCHORS: persist known-good outbound peers ~every 60s so a
            // hard kill still leaves a recent set to reconnect to.
            anchor_save_tick = anchor_save_tick.wrapping_add(1);
            if anchor_save_tick % 6 == 0 {
                save_anchors_to_disk(&connector_peers, &connector_data_dir);
            }

            let outbound_count =
                observe_outbound_health(&connector_peers, &connector_addresses, &connector_tracker)
                    .await;

            // Enforce the global outbound peer ceiling.
            // Eclipse protection (per-/16 diversity) is now handled
            // atomically by ConnectionTracker::try_track_outbound_subnet_owned
            // below; the ad-hoc HashSet diversity check that used to
            // live here was deleted in favor of the hard-cap
            // primitive — single source of truth, no TOCTOU window,
            // and a Drop-guard that releases the slot on every exit
            // path.
            if outbound_count >= max_outbound {
                continue;
            }

            // Get next address to try
            let addr = {
                let mut addresses = connector_addresses.write().await;
                addresses.get_next()
            };

            if let Some(addr) = addr {
                // Skip non-onion addresses if onion_only mode is enabled
                if let Some(ref proxy) = connector_proxy {
                    if proxy.onion_only {
                        // In onion_only mode, we need .onion addresses
                        // Regular SocketAddrs are skipped
                        debug!("Skipping {} in onion-only mode", addr);
                        continue;
                    }
                }

                // CHANGE 1: Self-connection prevention (Bitcoin CConnman::ConnectNode pattern).
                // Skip addresses that point back to our own listen port on a local IP.
                // This catches 127.0.0.1:port, 0.0.0.0:port, and any local interface IP.
                // Done BEFORE the TCP connect to avoid wasting time and Noise handshake slots.
                if is_self_dial(addr, connector_listen_port) {
                    debug!("Skipping self-connection to {} (our listen port)", addr);
                    continue;
                }

                // Check if peer is banned by scorer
                if connector_scorer.read().await.is_banned(&addr) {
                    debug!("Skipping banned peer {}", addr);
                    continue;
                }

                // Skip if we already have an active peer at this exact
                // address. The connector previously dialed the same
                // address whenever MIN_RECONNECT_DELAY had elapsed,
                // even when the prior connection was still alive —
                // surfaced as eclipse-defense drift "sum=2 but
                // outbound_count=1" in 2026-05-09 sandbox testing.
                //
                // We ALSO mark the address as `tried` so get_next
                // rotates to a different address on the next tick.
                // Without this, mark_success on a freshly-connected
                // peer keeps that address at the top of the
                // last_seen-sorted list, get_next returns it again,
                // we skip it again, and the connector loops forever
                // on a single peer (regression caught when cap=1
                // testing showed "0 cap fires" instead of one — the
                // node never tried the 2nd 207.148/16 address). The
                // tried set self-clears once all addresses have
                // been tried, so this isn't permanent exclusion.
                if connector_peers.iter().any(|p| p.addr == addr) {
                    trace!(
                        "Skipping {} — already have an active peer at this address",
                        addr
                    );
                    connector_addresses.write().await.mark_tried(addr);
                    continue;
                }

                if connection_attempt_deferred(addr, &last_attempt, &backoffs, MIN_RECONNECT_DELAY)
                    .await
                {
                    continue;
                }

                // HARDENING (Layer 4): Atomic per-/16 outbound cap with
                // RAII Drop-guard semantics. The owned slot is moved
                // into the spawned task; whenever the task exits — clean
                // return, error path, panic, tokio cancellation — the
                // slot drops and the counter decrements. There is no
                // explicit untrack call to forget. Hard cap: an attacker
                // controlling a /16 cannot saturate beyond
                // MAX_OUTBOUND_PER_SUBNET regardless of address-book
                // ordering or race timing.
                let outbound_slot = match connector_tracker.try_track_outbound_subnet_owned(&addr) {
                    Some(slot) => Arc::new(slot),
                    None => {
                        debug!(
                            "Eclipse cap: /16 of {} is at MAX_OUTBOUND_PER_SUBNET, skipping",
                            addr
                        );
                        // Mark as tried so the connector rotates to a
                        // different /16 next tick, instead of burning
                        // ticks repeatedly hitting the cap on the same
                        // address. Symmetric with the dup-dial skip
                        // above. The tried set self-clears once all
                        // addresses are exhausted, so this isn't a
                        // permanent block — if the cap clears later
                        // (peer drops), the address becomes eligible
                        // again on the next round.
                        connector_addresses.write().await.mark_tried(addr);
                        continue;
                    }
                };

                debug!("Attempting outbound connection to {}", addr);

                // CHANGE 3: Record attempt timestamp before spawning
                last_attempt
                    .lock()
                    .await
                    .insert(addr, std::time::Instant::now());

                let (height, tip) = connector_chain_state.snapshot().await;
                connections.spawn(run_outbound_attempt(OutboundAttempt {
                    addr,
                    peers: connector_peers.clone(),
                    senders: connector_senders.clone(),
                    addresses: connector_addresses.clone(),
                    event_tx: connector_event_tx.clone(),
                    msg_tx: connector_msg_tx.clone(),
                    height,
                    tip,
                    proxy: connector_proxy.clone(),
                    backoffs: backoffs.clone(),
                    identity: connector_identity.clone(),
                    encryption: connector_encryption.clone(),
                    tracker: connector_tracker.clone(),
                    outbound_slot,
                    magic,
                    our_nonce,
                }));
            }
        }

        connections.abort_all();
        while let Some(result) = connections.join_next().await {
            log_connection_task_result("outbound", result);
        }
    })
}

async fn observe_outbound_health(
    peers: &DashMap<PeerId, PeerInfo>,
    addresses: &RwLock<AddressManager>,
    tracker: &ConnectionTracker,
) -> usize {
    let outbound_count = peers.iter().filter(|peer| peer.outbound).count();
    let total_peers = peers.len();
    let address_count = addresses.read().await.len();
    if total_peers < 3 {
        info!(
            "Peer maintenance: {} total peers ({} outbound), {} known addresses",
            total_peers, outbound_count, address_count
        );
    }

    let snapshot = tracker.outbound_subnet_snapshot();
    let subnet_sum: usize = snapshot.iter().map(|(_, count)| *count).sum();
    if snapshot.is_empty() {
        debug!(
            "eclipse-defense: outbound_per_subnet empty (outbound_count={})",
            outbound_count
        );
        return outbound_count;
    }

    let pretty: Vec<String> = snapshot
        .iter()
        .map(|(subnet, count)| {
            let hi = (*subnet >> 8) as u8;
            let lo = (*subnet & 0xff) as u8;
            format!("{}.{}/16={}", hi, lo, count)
        })
        .collect();
    let drift = (subnet_sum as i64 - outbound_count as i64).abs();
    if drift >= 2 {
        let live_outbound: Vec<SocketAddr> = peers
            .iter()
            .filter(|peer| peer.outbound)
            .map(|peer| peer.addr)
            .collect();
        let (old_sum, new_sum) = tracker.reconcile_outbound_subnets(&live_outbound);
        warn!(
            "eclipse-defense: significant drift — subnet_sum={} but outbound_count={} (diff={}) :: {} :: RECONCILED {}→{} from {} live outbound",
            subnet_sum,
            outbound_count,
            drift,
            pretty.join(", "),
            old_sum,
            new_sum,
            live_outbound.len()
        );
    } else if drift == 1 {
        debug!(
            "eclipse-defense: minor drift (cosmetic) — subnet_sum={} but outbound_count={} :: {}",
            subnet_sum,
            outbound_count,
            pretty.join(", ")
        );
    } else {
        debug!(
            "eclipse-defense: subnets={} sum={} :: {}",
            snapshot.len(),
            subnet_sum,
            pretty.join(", ")
        );
    }

    outbound_count
}

async fn run_outbound_attempt(attempt: OutboundAttempt) {
    let OutboundAttempt {
        addr,
        peers,
        senders,
        addresses,
        event_tx,
        msg_tx,
        height,
        tip,
        proxy,
        backoffs,
        identity,
        encryption,
        tracker,
        outbound_slot,
        magic,
        our_nonce,
    } = attempt;

    match super::super::proxy::connect_peer(addr, proxy.as_ref(), CONNECT_TIMEOUT).await {
        Ok(stream) => {
            backoffs.lock().await.remove(&addr);
            let result = handle_connection(
                stream,
                generate_peer_id(),
                true,
                magic,
                our_nonce,
                height,
                tip,
                peers,
                senders,
                event_tx,
                msg_tx,
                tracker,
                identity,
                encryption,
                Some(outbound_slot),
            )
            .await;
            if let Err(error) = result {
                warn!("Outbound connection error: {}", error);
                addresses.write().await.mark_tried(addr);
            } else {
                addresses.write().await.mark_success(addr);
            }
        }
        Err(error) => {
            debug!("Connection to {} failed: {}", addr, error);
            addresses.write().await.mark_tried(addr);
            let mut backoffs = backoffs.lock().await;
            let (next_attempt, backoff) = backoffs.entry(addr).or_insert_with(|| {
                (
                    std::time::Instant::now(),
                    super::super::framing::ExponentialBackoff::new(),
                )
            });
            let delay = backoff.next_delay();
            *next_attempt = std::time::Instant::now() + delay;
            debug!("Backoff for {}: next retry in {:?}", addr, delay);
        }
    }
}

async fn connection_attempt_deferred(
    addr: SocketAddr,
    last_attempt: &LastAttemptMap,
    backoffs: &BackoffMap,
    minimum_delay: Duration,
) -> bool {
    if let Some(attempted_at) = last_attempt.lock().await.get(&addr) {
        if attempted_at.elapsed() < minimum_delay {
            trace!(
                "Skipping {} — last attempt was {:?} ago (min {:?})",
                addr,
                attempted_at.elapsed(),
                minimum_delay
            );
            return true;
        }
    }

    backoffs
        .lock()
        .await
        .get(&addr)
        .map(|(next_attempt, _)| std::time::Instant::now() < *next_attempt)
        .unwrap_or(false)
}

fn is_self_dial(addr: SocketAddr, listen_port: u16) -> bool {
    if addr.port() != listen_port {
        return false;
    }

    addr.ip().is_loopback()
        || addr.ip().is_unspecified()
        || match addr.ip() {
            std::net::IpAddr::V4(ip) => {
                ip.is_loopback()
                    || ip.is_unspecified()
                    || ip == std::net::Ipv4Addr::new(127, 0, 0, 1)
            }
            std::net::IpAddr::V6(ip) => {
                ip.is_loopback()
                    || ip.is_unspecified()
                    || ip
                        .to_ipv4_mapped()
                        .map(|v4| v4.is_loopback() || v4.is_unspecified())
                        .unwrap_or(false)
            }
        }
}

fn log_connection_task_result(direction: &'static str, result: Result<(), tokio::task::JoinError>) {
    if let Err(error) = result {
        if error.is_cancelled() {
            trace!(direction, "connection task cancelled during shutdown");
        } else {
            warn!(direction, error = ?error, "connection task failed");
        }
    }
}

/// Pick a connected peer using composite-score weighted randomness.
pub(super) fn pick_scored_peer(
    peers: &Arc<DashMap<PeerId, PeerInfo>>,
    scorer: &Arc<RwLock<PeerScorer>>,
) -> Option<PeerId> {
    let connected: Vec<(PeerId, SocketAddr)> = peers
        .iter()
        .filter(|peer| peer.state == PeerState::Connected)
        .map(|peer| (peer.id, peer.addr))
        .collect();
    if connected.is_empty() {
        return None;
    }

    if let Ok(scorer) = scorer.try_read() {
        let weights: Vec<f64> = connected
            .iter()
            .map(|(_, addr)| {
                scorer
                    .get(addr)
                    .map(|score| score.composite_score().max(0.05))
                    .unwrap_or(0.5)
            })
            .collect();
        let total: f64 = weights.iter().sum();
        if total > 0.0 {
            use rand::Rng;

            let mut rng = rand::rngs::OsRng;
            let mut pick = rng.gen_range(0.0..total);
            for (index, weight) in weights.iter().enumerate() {
                pick -= weight;
                if pick <= 0.0 {
                    return Some(connected[index].0);
                }
            }
        }
    }

    use rand::Rng;

    let mut rng = rand::rngs::OsRng;
    Some(connected[rng.gen_range(0..connected.len())].0)
}

/// Pick a connected peer uniformly when no scoring policy is needed.
#[allow(dead_code)]
pub(super) fn pick_random_peer(peers: &Arc<DashMap<PeerId, PeerInfo>>) -> Option<PeerId> {
    let connected: Vec<PeerId> = peers
        .iter()
        .filter(|peer| peer.state == PeerState::Connected)
        .map(|peer| peer.id)
        .collect();
    if connected.is_empty() {
        return None;
    }

    use rand::Rng;

    let mut rng = rand::rngs::OsRng;
    Some(connected[rng.gen_range(0..connected.len())])
}

/// Persist connected outbound peers so restart can prefer known-good anchors.
pub(super) fn save_anchors_to_disk(peers: &DashMap<PeerId, PeerInfo>, data_dir: &std::path::Path) {
    let anchors: Vec<SocketAddr> = peers
        .iter()
        .filter(|peer| peer.outbound && peer.state == PeerState::Connected)
        .map(|peer| peer.addr)
        .collect();
    if anchors.is_empty() {
        return;
    }

    let path = data_dir.join("anchors.json");
    match serde_json::to_string(&anchors) {
        Ok(json) => {
            if let Err(error) = std::fs::write(&path, json) {
                warn!("Failed to save anchors: {}", error);
            }
        }
        Err(error) => warn!("Failed to serialize anchors: {}", error),
    }
}

/// Missing or malformed anchor files fall back to normal bootstrap.
pub(super) fn load_anchors_from_disk(data_dir: &std::path::Path) -> Vec<SocketAddr> {
    let path = data_dir.join("anchors.json");
    match std::fs::read_to_string(&path) {
        Ok(contents) => serde_json::from_str::<Vec<SocketAddr>>(&contents).unwrap_or_default(),
        Err(_) => Vec::new(),
    }
}

pub(super) struct BanPeerContext<'a> {
    pub(super) peers: &'a DashMap<PeerId, PeerInfo>,
    pub(super) senders: &'a DashMap<PeerId, mpsc::Sender<Vec<u8>>>,
    pub(super) tracker: &'a ConnectionTracker,
    pub(super) scorer: &'a RwLock<PeerScorer>,
    pub(super) dandelion: &'a RwLock<DandelionRouter>,
    pub(super) orphan_flood: &'a RwLock<OrphanFloodTracker>,
    pub(super) event_tx: &'a broadcast::Sender<NodeEvent>,
}

/// Ban visibility is committed before disconnect state is removed so a
/// reconnect racing the cleanup observes the ban.
pub(super) async fn ban_peer(peer_id: &PeerId, context: BanPeerContext<'_>) {
    let peer_addr = context.peers.get(peer_id).map(|peer| peer.addr);
    if let Some(addr) = peer_addr {
        context.tracker.untrack_connection(&addr);
        context.scorer.write().await.ban(addr);
    }
    if let Some(mut peer) = context.peers.get_mut(peer_id) {
        peer.reputation = -100;
    }
    context
        .dandelion
        .write()
        .await
        .remove_outbound_peer(peer_id);
    context.peers.remove(peer_id);
    context.senders.remove(peer_id);
    context.orphan_flood.write().await.forget(peer_id);
    let _ = context.event_tx.send(NodeEvent::PeerDisconnected(*peer_id));
}

pub(super) struct DisconnectPeerContext<'a> {
    pub(super) peers: &'a DashMap<PeerId, PeerInfo>,
    pub(super) senders: &'a DashMap<PeerId, mpsc::Sender<Vec<u8>>>,
    pub(super) tracker: &'a ConnectionTracker,
    pub(super) dandelion: &'a RwLock<DandelionRouter>,
    pub(super) sync: &'a RwLock<ChainSync>,
    pub(super) event_tx: &'a broadcast::Sender<NodeEvent>,
}

/// Remove a normally disconnected peer without applying a reputation penalty.
pub(super) async fn disconnect_peer(peer_id: &PeerId, context: DisconnectPeerContext<'_>) {
    if let Some(peer) = context.peers.get(peer_id) {
        context.tracker.untrack_connection(&peer.addr);
    }
    context.senders.remove(peer_id);
    context.peers.remove(peer_id);
    context
        .dandelion
        .write()
        .await
        .remove_outbound_peer(peer_id);
    context.sync.write().await.on_peer_disconnected(peer_id);
    let _ = context.event_tx.send(NodeEvent::PeerDisconnected(*peer_id));
}

pub(super) fn disconnect_all(
    peers: &DashMap<PeerId, PeerInfo>,
    senders: &DashMap<PeerId, mpsc::Sender<Vec<u8>>>,
    event_tx: &broadcast::Sender<NodeEvent>,
) {
    for peer in peers.iter() {
        let _ = event_tx.send(NodeEvent::PeerDisconnected(peer.id));
    }
    peers.clear();
    senders.clear();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn anchor_round_trip_keeps_only_connected_outbound_peers() {
        let data_dir = tempfile::tempdir().unwrap();
        let peers = DashMap::new();

        let outbound_id = [1u8; 32];
        let outbound_addr = "127.0.0.1:12001".parse().unwrap();
        let mut outbound = PeerInfo::new(outbound_id, outbound_addr, true);
        outbound.state = PeerState::Connected;
        peers.insert(outbound_id, outbound);

        let inbound_id = [2u8; 32];
        let mut inbound = PeerInfo::new(inbound_id, "127.0.0.1:12002".parse().unwrap(), false);
        inbound.state = PeerState::Connected;
        peers.insert(inbound_id, inbound);
        peers.insert(
            [3u8; 32],
            PeerInfo::new([3u8; 32], "127.0.0.1:12003".parse().unwrap(), true),
        );

        save_anchors_to_disk(&peers, data_dir.path());

        assert_eq!(load_anchors_from_disk(data_dir.path()), vec![outbound_addr]);
    }

    #[tokio::test]
    async fn ban_updates_scorer_and_removes_peer_state() {
        let peers = DashMap::new();
        let senders = DashMap::new();
        let peer_id = [4u8; 32];
        let addr = "127.0.0.1:12004".parse().unwrap();
        peers.insert(peer_id, PeerInfo::new(peer_id, addr, true));
        let (sender, _receiver) = mpsc::channel(1);
        senders.insert(peer_id, sender);

        let tracker = ConnectionTracker::new(1024);
        assert!(tracker.try_track_connection(&addr));
        let scorer = RwLock::new(PeerScorer::new());
        let dandelion = RwLock::new(DandelionRouter::new());
        let orphan_flood = RwLock::new(OrphanFloodTracker::new());
        let (event_tx, mut event_rx) = broadcast::channel(1);

        ban_peer(
            &peer_id,
            BanPeerContext {
                peers: &peers,
                senders: &senders,
                tracker: &tracker,
                scorer: &scorer,
                dandelion: &dandelion,
                orphan_flood: &orphan_flood,
                event_tx: &event_tx,
            },
        )
        .await;

        assert!(scorer.read().await.is_banned(&addr));
        assert!(peers.get(&peer_id).is_none());
        assert!(senders.get(&peer_id).is_none());
        assert_eq!(tracker.connections_from(&addr.ip()), 0);
        assert!(matches!(
            event_rx.try_recv(),
            Ok(NodeEvent::PeerDisconnected(id)) if id == peer_id
        ));
    }
}
