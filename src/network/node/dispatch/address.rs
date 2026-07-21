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
                    pa.last_seen = net_addr.timestamp;
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
