//! ## Audit map
//! Each `§` is a code section below; it states the INVARIANT it guarantees, the
//! THREAT it defends, and the TESTS that prove it.
//!
//! - **§1 `handle_get_addr`** — INVARIANT: address-book responses (Addr) are
//!   sent only to Noise-encrypted (authenticated) peers; a plaintext peer's
//!   GetAddr is silently ignored.
//!   THREAT: Firework Veil — a passive/unauthenticated observer mapping P2P
//!   topology without ever completing an authenticated connection.
//!   TESTS: `handle_get_addr_from_plaintext_peer_is_ignored`.
//! - **§2 `handle_addr` (oversized / malformed)** — INVARIANT: oversized Addr
//!   payloads are rejected before deserialization and score OversizedMessage;
//!   nothing is added to the book.
//!   THREAT: P5-N-CLASS-A payload-size DoS / malformed-message spam poisoning
//!   the address book.
//!   TESTS: `handle_addr_oversized_scores_and_stores_nothing`.
//! - **§3 `handle_addr` (freshness)** — INVARIANT: future-dated (`timestamp >
//!   now+600`) and stale (`age > 7d`) addresses are rejected and never enter
//!   the book.
//!   THREAT: clock-manipulation / stale-address pollution used to starve
//!   honest dial slots or resurrect dead peers.
//!   TESTS: `handle_addr_filters_future_stale_and_unroutable_entries`.
//! - **§4 `handle_addr` (routability)** — INVARIANT: unroutable IPs (e.g.
//!   loopback) are rejected and never enter the book.
//!   THREAT: an attacker padding the book with unroutable entries to waste
//!   dial slots and poison onward gossip.
//!   TESTS: `handle_addr_filters_future_stale_and_unroutable_entries`.
//! - **§5 `handle_addr` (H7 last_seen clamp)** — INVARIANT: an accepted address's
//!   `last_seen` is clamped to `min(claimed_timestamp, receive_time)`, so a
//!   peer-relayed address can never appear fresher than the moment we heard it.
//!   THREAT: H7 (dial starvation / eclipse) — a near-future timestamp (within
//!   the accepted `now+600` window) sorting ahead of honestly-observed peers
//!   for dial order and dodging last_seen-based eviction.
//!   TESTS: `handle_addr_clamps_future_last_seen_to_receive_time_h7`.
//! - **§6 `handle_addr` (H7 port-0 rejection)** — INVARIANT: an address with
//!   port 0 is undialable and must never be added to the book.
//!   THREAT: H7 — a port-0 entry occupying a book slot and padding an
//!   attacker's per-/16 netgroup quota without ever being dialable.
//!   TESTS: `handle_addr_rejects_port_zero_h7`.

use dashmap::DashMap;
use tokio::sync::{mpsc, RwLock};
use tracing::{debug, warn};

use crate::error::Result;
use crate::network::bootstrap::{AddressManager, PeerAddress};
use crate::network::peer::{PeerId, PeerInfo};
use crate::network::protocol::{Message, MessageType};
use crate::network::scoring::PeerScorer;

use super::super::address_policy::{is_routable, to_socket_addr};
use super::super::broadcast::send_to_peer;

pub(super) async fn handle_get_addr(
    peer_id: PeerId,
    magic: [u8; 4],
    peers: &DashMap<PeerId, PeerInfo>,
    senders: &DashMap<PeerId, mpsc::Sender<Vec<u8>>>,
    addresses: &RwLock<AddressManager>,
) -> Result<()> {
    // ── Firework: Veil ───────────────────────────────────────────────
    // Only respond to Noise-encrypted peers. A plaintext peer has not
    // proven its identity, so sharing our address book with it lets a
    // passive observer map P2P topology without making a single
    // authenticated connection. Silently ignore the request instead of
    // sending an error so non-Veil nodes don't see a protocol fault.
    let peer_encrypted = peers.get(&peer_id).map(|p| p.encrypted).unwrap_or(false);
    if !peer_encrypted {
        debug!(
            "Veil: ignoring GetAddr from plaintext peer {:?}",
            &peer_id[..4]
        );
        return Ok(());
    }

    let addrs = addresses.read().await;
    // #303: gossip ONLY verified/trusted addresses (never raw untried book
    // entries) so we don't leak an inbound-only peer's unconfirmed (ip, port).
    let peer_addrs = addrs.get_for_gossip(100);
    drop(addrs);

    if !peer_addrs.is_empty() {
        let net_addrs: Vec<crate::network::protocol::NetAddr> = peer_addrs
            .iter()
            .map(|pa| {
                let ip_bytes = match pa.addr.ip() {
                    std::net::IpAddr::V4(v4) => v4.to_ipv6_mapped().octets(),
                    std::net::IpAddr::V6(v6) => v6.octets(),
                };
                crate::network::protocol::NetAddr {
                    services: pa.services,
                    ip: ip_bytes,
                    port: pa.addr.port(),
                    timestamp: pa.last_seen,
                }
            })
            .collect();

        let addr_msg = crate::network::protocol::AddrMessage {
            addresses: net_addrs,
        };
        if let Ok(payload_bytes) = borsh::to_vec(&addr_msg) {
            let msg = Message::new(magic, MessageType::Addr, payload_bytes);
            let _ = send_to_peer(senders, &peer_id, msg.to_bytes()?).await;
        }
    }
    Ok(())
}

pub(super) async fn handle_addr(
    peer_id: PeerId,
    payload: &[u8],
    peers: &DashMap<PeerId, PeerInfo>,
    addresses: &RwLock<AddressManager>,
    scorer: &RwLock<PeerScorer>,
) -> Result<()> {
    // SECURITY: Validate addr messages.
    // P5-N-CLASS-A fix: tight per-type cap.
    if payload.len() > crate::network::protocol::MAX_ADDR_PAYLOAD {
        warn!(
            "Addr message too large from peer {}",
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
    // P5-N7 fix: match with Err scoring.
    match borsh::from_slice::<crate::network::protocol::AddrMessage>(payload) {
        Ok(addr_msg) => {
            if let Err(e) = addr_msg.validate() {
                warn!(
                    "Invalid AddrMessage from peer {}: {}",
                    hex::encode(&peer_id[..8]),
                    e
                );
                if let Some(addr) = peers.get(&peer_id).map(|p| p.addr) {
                    scorer.write().await.get_or_create(addr).record_misbehavior(
                        crate::network::scoring::MisbehaviorType::InvalidAddress,
                    );
                }
                return Ok(());
            }

            let now = super::unix_now();
            let max_future = now + 600; // Allow 10 minutes of clock skew
                                        // A week preserves discovery after downtime without retaining
                                        // stale addresses indefinitely.
            let max_age = 7 * 24 * 3600; // Reject addresses older than 7 days

            let mut addrs = addresses.write().await;
            let mut accepted = 0usize;
            for net_addr in &addr_msg.addresses {
                // Freshness check: reject stale or future-dated addresses
                if net_addr.timestamp > max_future {
                    continue; // Future timestamp — clock manipulation
                }
                if now.saturating_sub(net_addr.timestamp) > max_age {
                    continue; // Stale address — too old
                }
                if let Some(socket_addr) = to_socket_addr(net_addr) {
                    // Unroutable entries waste dial slots and poison onward gossip.
                    if !is_routable(socket_addr.ip()) {
                        continue;
                    }
                    let mut pa = PeerAddress::new(socket_addr);
                    // H7 (dial starvation / eclipse): cap the relayed last_seen
                    // at our own receive time. A peer-relayed address can never
                    // be fresher than the moment we heard of it — otherwise a
                    // near-future timestamp (anything up to now+600) sorts ahead
                    // of honestly-observed peers for dial order AND dodges
                    // last_seen-based eviction, letting one Addr flood of
                    // future-dated entries starve honest outbound dials and take
                    // over the book. The >now+600 rejection above still stands;
                    // this clamps the accepted-but-future window.
                    pa.last_seen = net_addr.timestamp.min(now);
                    pa.services = net_addr.services;
                    addrs.add(pa);
                    accepted += 1;
                }
            }
            if accepted > 0 {
                debug!(
                    "Added {} peer addresses from {}",
                    accepted,
                    hex::encode(&peer_id[..8])
                );
            }
        }
        Err(e) => {
            warn!(
                "Failed to deserialize AddrMessage from peer {}: {}",
                hex::encode(&peer_id[..8]),
                e
            );
            if let Some(addr) = peers.get(&peer_id).map(|p| p.addr) {
                scorer
                    .write()
                    .await
                    .get_or_create(addr)
                    .record_misbehavior(crate::network::scoring::MisbehaviorType::InvalidAddress);
            }
        }
    }
    Ok(())
}

/// Receive-side handler for `AddrV2`: ingest a peer's typed addresses. IPv4/IPv6
/// entries feed the hardened IP book (routability + last_seen clamp, exactly like
/// [`handle_addr`]); onion/I2P entries go to the addrv2 side store. Same freshness
/// and size guards as `handle_addr`.
pub(super) async fn handle_addr_v2(
    peer_id: PeerId,
    payload: &[u8],
    peers: &DashMap<PeerId, PeerInfo>,
    addresses: &RwLock<AddressManager>,
    scorer: &RwLock<PeerScorer>,
) -> Result<()> {
    use crate::network::protocol::AddrV2Message;

    // Per-type size cap bounds the borsh allocation (256 KB, same as the frame).
    if payload.len() > MessageType::AddrV2.max_size() {
        warn!(
            "AddrV2 message too large from peer {}",
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

    match borsh::from_slice::<AddrV2Message>(payload) {
        Ok(msg) => {
            if let Err(e) = msg.validate() {
                warn!(
                    "Invalid AddrV2Message from peer {}: {}",
                    hex::encode(&peer_id[..8]),
                    e
                );
                if let Some(addr) = peers.get(&peer_id).map(|p| p.addr) {
                    scorer.write().await.get_or_create(addr).record_misbehavior(
                        crate::network::scoring::MisbehaviorType::InvalidAddress,
                    );
                }
                return Ok(());
            }

            let now = super::unix_now();
            let max_future = now + 600;
            let max_age = 7 * 24 * 3600;

            let mut addrs = addresses.write().await;
            let mut accepted = 0usize;
            for a in &msg.addresses {
                // Freshness (same policy as handle_addr) + undialable guard.
                if a.timestamp > max_future || now.saturating_sub(a.timestamp) > max_age {
                    continue;
                }
                if a.port == 0 {
                    continue;
                }
                match a.to_net_addr() {
                    // IPv4/IPv6 → the hardened IP book.
                    Some(na) => {
                        if let Some(socket_addr) = to_socket_addr(&na) {
                            if !is_routable(socket_addr.ip()) {
                                continue;
                            }
                            let mut pa = PeerAddress::new(socket_addr);
                            pa.last_seen = a.timestamp.min(now);
                            pa.services = a.services;
                            addrs.add(pa);
                            accepted += 1;
                        }
                    }
                    // onion / i2p → the addrv2 side store (routable net_id only).
                    // Tag with the SOURCE peer so the per-source cap can bound a
                    // Sybil flood of cheap onion/.b32.i2p identities from one peer.
                    None if a.is_routable() => {
                        let mut v2 = a.clone();
                        v2.timestamp = a.timestamp.min(now);
                        let mut src = [0u8; 8];
                        src.copy_from_slice(&peer_id[..8]);
                        addrs.add_v2(v2, src);
                        accepted += 1;
                    }
                    // unknown net_id → dropped (forward-compat relay is future work).
                    None => {}
                }
            }
            if accepted > 0 {
                debug!(
                    "Added {} addrv2 addresses from {}",
                    accepted,
                    hex::encode(&peer_id[..8])
                );
            }
        }
        Err(e) => {
            warn!(
                "Failed to deserialize AddrV2Message from peer {}: {}",
                hex::encode(&peer_id[..8]),
                e
            );
            if let Some(addr) = peers.get(&peer_id).map(|p| p.addr) {
                scorer
                    .write()
                    .await
                    .get_or_create(addr)
                    .record_misbehavior(crate::network::scoring::MisbehaviorType::InvalidAddress);
            }
        }
    }
    Ok(())
}

/// Respond to `GetAddrV2` with our known addresses as addrv2 — the verified IP
/// book (mapped to addrv2) plus the onion/I2P side store. Veil: only to
/// authenticated (Noise-encrypted) peers.
pub(super) async fn handle_get_addr_v2(
    peer_id: PeerId,
    magic: [u8; 4],
    peers: &DashMap<PeerId, PeerInfo>,
    senders: &DashMap<PeerId, mpsc::Sender<Vec<u8>>>,
    addresses: &RwLock<AddressManager>,
) -> Result<()> {
    use crate::network::protocol::{AddrV2Message, NetAddr, NetAddrV2};

    let peer_encrypted = peers.get(&peer_id).map(|p| p.encrypted).unwrap_or(false);
    if !peer_encrypted {
        debug!(
            "Veil: ignoring GetAddrV2 from plaintext peer {:?}",
            &peer_id[..4]
        );
        return Ok(());
    }

    let now = super::unix_now();
    let addrs = addresses.read().await;
    // Our OWN advertised onion/i2p addresses first (timestamp refreshed to now).
    let mut out: Vec<NetAddrV2> = addrs
        .self_v2()
        .into_iter()
        .map(|mut a| {
            a.timestamp = now;
            a
        })
        .collect();
    // Then the verified IP book (mapped to addrv2) — but NEVER in onion-only
    // mode: advertising our clearnet peer set over an onion/I2P link would hand
    // an anonymity-network peer our clearnet contacts (app-layer IP leak). In
    // onion-only we gossip ONLY onion/I2P addresses.
    if !crate::network::proxy::is_onion_only() {
        out.extend(addrs.get_for_gossip(100).iter().map(|pa| {
            let na = NetAddr {
                services: pa.services,
                ip: match pa.addr.ip() {
                    std::net::IpAddr::V4(v4) => v4.to_ipv6_mapped().octets(),
                    std::net::IpAddr::V6(v6) => v6.octets(),
                },
                port: pa.addr.port(),
                timestamp: pa.last_seen,
            };
            NetAddrV2::from(&na)
        }));
    }
    // Learned onion/I2P peers are always safe to gossip.
    out.extend(addrs.get_v2(100));
    drop(addrs);

    if !out.is_empty() {
        let msg = AddrV2Message { addresses: out };
        if let Ok(payload) = borsh::to_vec(&msg) {
            let m = Message::new(magic, MessageType::AddrV2, payload);
            let _ = send_to_peer(senders, &peer_id, m.to_bytes()?).await;
        }
    }
    Ok(())
}

#[cfg(test)]
mod handler_tests {
    use super::*;
    use crate::network::protocol::{AddrMessage, NetAddr};
    use std::net::{Ipv4Addr, SocketAddr};

    const MAGIC: [u8; 4] = [1, 2, 3, 4];

    fn addr_for(port: u16) -> SocketAddr {
        format!("127.0.0.1:{port}").parse().unwrap()
    }

    fn now_secs() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
    }

    fn net_addr(ip: [u8; 4], timestamp: u64) -> NetAddr {
        NetAddr {
            services: 1,
            ip: Ipv4Addr::new(ip[0], ip[1], ip[2], ip[3])
                .to_ipv6_mapped()
                .octets(),
            port: 30333,
            timestamp,
        }
    }

    #[tokio::test]
    async fn handle_get_addr_from_plaintext_peer_is_ignored() {
        // Veil: never share the address book with an unauthenticated (plaintext)
        // peer — a passive observer could map P2P topology otherwise.
        let peer_id = [1u8; 32];
        let peers = DashMap::new();
        peers.insert(peer_id, PeerInfo::new(peer_id, addr_for(33001), false)); // encrypted=false
        let senders: DashMap<PeerId, mpsc::Sender<Vec<u8>>> = DashMap::new();
        let (stx, mut srx) = mpsc::channel::<Vec<u8>>(4);
        senders.insert(peer_id, stx);
        let addresses = RwLock::new(AddressManager::new(1000));

        handle_get_addr(peer_id, MAGIC, &peers, &senders, &addresses)
            .await
            .unwrap();

        assert!(srx.try_recv().is_err(), "no Addr sent to plaintext peer");
    }

    #[tokio::test]
    async fn handle_addr_filters_future_stale_and_unroutable_entries() {
        let peer_id = [2u8; 32];
        let addr = addr_for(33002);
        let peers = DashMap::new();
        peers.insert(peer_id, PeerInfo::new(peer_id, addr, false));
        let addresses = RwLock::new(AddressManager::new(1000));
        let scorer = RwLock::new(PeerScorer::new());

        let now = now_secs();
        let msg = AddrMessage {
            addresses: vec![
                net_addr([8, 8, 8, 8], now - 100),               // good: routable + fresh
                net_addr([8, 8, 4, 4], now + 10_000),            // future-dated → rejected
                net_addr([9, 9, 9, 9], now - 8 * 24 * 3600),     // stale (>7d) → rejected
                net_addr([127, 0, 0, 1], now - 100),             // unroutable → rejected
            ],
        };
        let payload = borsh::to_vec(&msg).unwrap();

        handle_addr(peer_id, &payload, &peers, &addresses, &scorer)
            .await
            .unwrap();

        assert_eq!(
            addresses.read().await.len(),
            1,
            "only the routable+fresh address is accepted"
        );
    }

    /// H7 (dial starvation / eclipse): a relayed address whose timestamp is in
    /// the accepted-but-future window (≤ now+600) has its last_seen clamped to
    /// our receive time, so it cannot sort ahead of honestly-observed peers for
    /// dial order (AddressManager dials highest last_seen first) or dodge
    /// last_seen-based eviction.
    #[tokio::test]
    async fn handle_addr_clamps_future_last_seen_to_receive_time_h7() {
        let peer_id = [7u8; 32];
        let addr = addr_for(33007);
        let peers = DashMap::new();
        peers.insert(peer_id, PeerInfo::new(peer_id, addr, false));
        let addresses = RwLock::new(AddressManager::new(1000));
        let scorer = RwLock::new(PeerScorer::new());

        let now = now_secs();
        // Near-future but accepted (< now+600). Pre-fix this becomes the freshest
        // book entry and dials first / never gets evicted.
        let msg = AddrMessage {
            addresses: vec![net_addr([8, 8, 8, 9], now + 500)],
        };
        let payload = borsh::to_vec(&msg).unwrap();
        handle_addr(peer_id, &payload, &peers, &addresses, &scorer)
            .await
            .unwrap();

        let book = addresses.read().await;
        assert_eq!(book.len(), 1, "the routable addr is accepted");
        let entries = book.get_for_exchange(10);
        assert_eq!(entries.len(), 1);
        assert!(
            entries[0].last_seen <= now,
            "H7: relayed last_seen must be clamped to <= receive time, got {} (now {})",
            entries[0].last_seen,
            now
        );
    }

    /// H7: a port-0 address is undialable and must not enter the book — it would
    /// occupy a slot and pad an attacker's per-/16 netgroup quota.
    #[tokio::test]
    async fn handle_addr_rejects_port_zero_h7() {
        let peer_id = [8u8; 32];
        let addr = addr_for(33018);
        let peers = DashMap::new();
        peers.insert(peer_id, PeerInfo::new(peer_id, addr, false));
        let addresses = RwLock::new(AddressManager::new(1000));
        let scorer = RwLock::new(PeerScorer::new());

        let now = now_secs();
        let mut na = net_addr([8, 8, 8, 8], now - 10); // routable + fresh, but…
        na.port = 0; // …undialable
        let msg = AddrMessage {
            addresses: vec![na],
        };
        let payload = borsh::to_vec(&msg).unwrap();
        handle_addr(peer_id, &payload, &peers, &addresses, &scorer)
            .await
            .unwrap();

        assert_eq!(
            addresses.read().await.len(),
            0,
            "H7: port-0 address must be rejected, not added to the book"
        );
    }

    #[tokio::test]
    async fn handle_addr_oversized_scores_and_stores_nothing() {
        let peer_id = [3u8; 32];
        let addr = addr_for(33003);
        let peers = DashMap::new();
        peers.insert(peer_id, PeerInfo::new(peer_id, addr, false));
        let addresses = RwLock::new(AddressManager::new(1000));
        let scorer = RwLock::new(PeerScorer::new());

        let payload = vec![0u8; crate::network::protocol::MAX_ADDR_PAYLOAD + 1];
        handle_addr(peer_id, &payload, &peers, &addresses, &scorer)
            .await
            .unwrap();

        assert!(scorer.read().await.get(&addr).unwrap().reputation < 100);
        assert_eq!(addresses.read().await.len(), 0);
    }

    /// REAL RESULT: a node that receives an `AddrV2` from a peer actually stores
    /// the peer's `.onion` and `.i2p` addresses in its address manager (and the
    /// routable IPv4 in the IP book), while rejecting unroutable / future-dated
    /// entries — the whole real receive path (`handle_addr_v2` → `AddressManager`).
    #[tokio::test]
    async fn handle_addr_v2_stores_onion_and_i2p_from_a_received_message() {
        use crate::network::protocol::{net_id, AddrV2Message, NetAddrV2};

        let peer_id = [9u8; 32];
        let peers = DashMap::new();
        peers.insert(peer_id, PeerInfo::new(peer_id, addr_for(33009), false));
        let addresses = RwLock::new(AddressManager::new(1000));
        let scorer = RwLock::new(PeerScorer::new());

        let now = now_secs();
        let onion_key = [0x33u8; 32];
        let i2p_dest = [0x44u8; 32];
        let mk = |nid: u8, addr: Vec<u8>, ts: u64, port: u16| NetAddrV2 {
            services: 1,
            timestamp: ts,
            net_id: nid,
            addr,
            port,
        };
        let msg = AddrV2Message {
            addresses: vec![
                mk(net_id::IPV4, vec![8, 8, 8, 8], now - 10, 30333), // routable IP → IP book
                mk(net_id::ONION_V3, onion_key.to_vec(), now - 10, 28080), // onion → side store
                mk(net_id::I2P, i2p_dest.to_vec(), now - 10, 28080), // i2p → side store
                mk(net_id::IPV4, vec![127, 0, 0, 1], now - 10, 30333), // loopback → rejected
                mk(net_id::ONION_V3, vec![0x55u8; 32], now + 10_000, 28080), // future → rejected
            ],
        };
        let payload = borsh::to_vec(&msg).unwrap();

        handle_addr_v2(peer_id, &payload, &peers, &addresses, &scorer)
            .await
            .unwrap();

        let book = addresses.read().await;
        // The node now actually holds the peer's onion + i2p addresses.
        assert_eq!(
            book.v2_len(),
            2,
            "onion + i2p stored; the future-dated onion was rejected"
        );
        assert!(
            book.contains_v2(net_id::ONION_V3, &onion_key),
            "the exact .onion key the peer sent is in the store"
        );
        assert!(
            book.contains_v2(net_id::I2P, &i2p_dest),
            "the exact .i2p destination is in the store"
        );
        // The routable IPv4 went to the IP book; loopback was rejected.
        assert_eq!(book.len(), 1, "routable IPv4 accepted, loopback rejected");
    }

    /// Self-advertising: a node with its own configured `.onion` injects it into
    /// its `GetAddrV2` response, so peers can reach it over Tor.
    #[tokio::test]
    async fn get_addr_v2_advertises_our_own_configured_onion() {
        use crate::network::protocol::{net_id, AddrV2Message, NetAddrV2};

        let peer_id = [5u8; 32];
        let peers = DashMap::new();
        // Veil only shares with an authenticated (Noise-encrypted) peer.
        // NB: PeerInfo::new's 3rd arg is `outbound`, not `encrypted` — set it directly.
        let mut pi = PeerInfo::new(peer_id, addr_for(33055), false);
        pi.encrypted = true;
        peers.insert(peer_id, pi);
        let senders: DashMap<PeerId, mpsc::Sender<Vec<u8>>> = DashMap::new();
        let (stx, mut srx) = mpsc::channel::<Vec<u8>>(4);
        senders.insert(peer_id, stx);
        let addresses = RwLock::new(AddressManager::new(1000));

        // Configure our own onion self-address and register it. Build a host
        // with a valid version + checksum (parse now verifies both).
        let onion_host = crate::network::protocol::onion_v3_host_from_pubkey(&[0x42u8; 32]);
        let self_na = NetAddrV2::onion_v3_self(&onion_host, 28080, 0).unwrap();
        let onion_key = self_na.addr.clone();
        addresses.write().await.add_self_v2(self_na);

        handle_get_addr_v2(peer_id, MAGIC, &peers, &senders, &addresses)
            .await
            .unwrap();

        // We sent an AddrV2 frame; strip the 13-byte header and decode the payload.
        let frame = srx.try_recv().expect("an AddrV2 response was sent");
        let payload = &frame[crate::network::framing::HEADER_SIZE..];
        let msg: AddrV2Message = borsh::from_slice(payload).unwrap();
        assert!(
            msg.addresses
                .iter()
                .any(|a| a.net_id == net_id::ONION_V3 && a.addr == onion_key),
            "our own onion address is advertised in the GetAddrV2 response"
        );
    }

    /// App-layer IP-scrub: in onion-only mode the GetAddrV2 response must carry
    /// ONLY onion/I2P addresses — never the clearnet IP book (which would hand an
    /// anonymity-network peer our clearnet contacts).
    #[tokio::test]
    async fn onion_only_response_omits_the_clearnet_ip_book() {
        use crate::network::protocol::{net_id, AddrV2Message, NetAddrV2};

        let peer_id = [6u8; 32];
        let peers = DashMap::new();
        let mut pi = PeerInfo::new(peer_id, addr_for(33066), false);
        pi.encrypted = true;
        peers.insert(peer_id, pi);
        let senders: DashMap<PeerId, mpsc::Sender<Vec<u8>>> = DashMap::new();
        let (stx, mut srx) = mpsc::channel::<Vec<u8>>(4);
        senders.insert(peer_id, stx);
        let addresses = RwLock::new(AddressManager::new(1000));
        {
            let mut book = addresses.write().await;
            // A routable clearnet peer in the IP book + our own onion.
            book.add(crate::network::bootstrap::PeerAddress::new(
                "45.33.2.2:28080".parse().unwrap(),
            ));
            let onion_host = crate::network::protocol::onion_v3_host_from_pubkey(&[0x55u8; 32]);
            book.add_self_v2(NetAddrV2::onion_v3_self(&onion_host, 28080, 0).unwrap());
        }

        crate::network::proxy::set_onion_only(true);
        handle_get_addr_v2(peer_id, MAGIC, &peers, &senders, &addresses)
            .await
            .unwrap();
        crate::network::proxy::set_onion_only(false); // reset the process-global

        let frame = srx.try_recv().expect("an AddrV2 response was sent");
        let payload = &frame[crate::network::framing::HEADER_SIZE..];
        let msg: AddrV2Message = borsh::from_slice(payload).unwrap();
        assert!(
            msg.addresses.iter().any(|a| a.net_id == net_id::ONION_V3),
            "our onion is still advertised in onion-only mode"
        );
        assert!(
            !msg.addresses
                .iter()
                .any(|a| a.net_id == net_id::IPV4 || a.net_id == net_id::IPV6),
            "onion-only must NOT advertise the clearnet IP book"
        );
    }

    /// FULL REAL two-node result: node A sends an `AddrV2` carrying its `.onion`
    /// over a REAL OS `TcpStream`; node B reads it off the socket through the real
    /// framing and its real `handle_addr_v2` stores A's onion in B's address book.
    #[tokio::test]
    async fn two_sockets_exchange_addrv2_and_receiver_stores_onion() {
        use crate::network::framing::MessageFramer;
        use crate::network::protocol::{net_id, AddrV2Message, NetAddrV2};
        use tokio::net::{TcpListener, TcpStream};

        let magic = MAGIC;
        let onion_key = [0x77u8; 32];

        // A real OS socket pair.
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (a_stream, accepted) = tokio::join!(TcpStream::connect(addr), listener.accept());
        let a_stream = a_stream.unwrap();
        let (b_stream, _) = accepted.unwrap();

        // Node A writes an AddrV2 frame carrying its .onion over the real socket.
        let (ar, aw) = tokio::io::split(a_stream);
        let mut a_framer = MessageFramer::new(ar, aw, magic);
        let now = now_secs();
        let msg = AddrV2Message {
            addresses: vec![NetAddrV2 {
                services: 1,
                timestamp: now,
                net_id: net_id::ONION_V3,
                addr: onion_key.to_vec(),
                port: 28080,
            }],
        };
        let payload = borsh::to_vec(&msg).unwrap();
        a_framer
            .write_message(MessageType::AddrV2 as u8, &payload)
            .await
            .unwrap();

        // Node B reads the frame off the real socket via the real framing.
        let (br, bw) = tokio::io::split(b_stream);
        let mut b_framer = MessageFramer::new(br, bw, magic);
        let (ty, got) = b_framer.read_message_timeout().await.unwrap();
        assert_eq!(MessageType::try_from(ty).unwrap(), MessageType::AddrV2);

        // B routes it through the REAL receive handler into its REAL address book.
        let peer_id = [1u8; 32];
        let peers = DashMap::new();
        peers.insert(peer_id, PeerInfo::new(peer_id, addr, false));
        let addresses = RwLock::new(AddressManager::new(1000));
        let scorer = RwLock::new(PeerScorer::new());
        handle_addr_v2(peer_id, &got, &peers, &addresses, &scorer)
            .await
            .unwrap();

        // Real two-node result: B now holds A's onion after a real socket exchange.
        assert!(
            addresses.read().await.contains_v2(net_id::ONION_V3, &onion_key),
            "B stored A's .onion after receiving it over a real TCP socket"
        );
    }
}
