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
    let peer_addrs = addrs.get_for_exchange(100);
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
}
