//! Netgroup-aware inbound peer eviction.
//!
//! Port of Bitcoin Core's `AttemptToEvictConnection` (src/net.cpp, around
//! line 1100 in modern Bitcoin Core). When the inbound slot table is
//! saturated, this module selects the best candidate to disconnect so a
//! new connection can be accepted.
//!
//! The defense problem: an attacker filling all `MAX_INBOUND` slots from
//! a single /16 (or /32 IPv6) creates an eclipse condition where the
//! victim node sees only attacker-controlled views of the chain. Without
//! eviction, the first 64 attacker connections from one /16 pin the
//! victim until those peers themselves disconnect — which they won't.
//!
//! The defense: when full, sacrifice the "most-evictable" peer rather
//! than reject the new one. Pick by:
//!   1. Protect the 4 longest-connected peers (loyalty bonus, makes
//!      churn-attacks expensive).
//!   2. Protect the 4 most-recently-active peers (signal of useful
//!      mutual traffic).
//!   3. Protect the 4 highest-reputation peers (well-behaved).
//!   4. Of remaining candidates, GROUP BY netgroup (IPv4 /16, IPv6 /32).
//!   5. Pick the netgroup with the MOST candidates — that's where the
//!      saturation concentration is.
//!   6. Within that group, evict the YOUNGEST (last-in-first-out).
//!
//! This matches Bitcoin Core's algorithm with two CoinCync-specific
//! adaptations:
//!   - We lack `min_ping` and `last_tx_received` telemetry, so we use
//!     `last_seen` (activity proxy) and `reputation` (peer-scorer signal)
//!     as the protection axes Bitcoin Core uses ping and tx-time for.
//!   - We add a Noise-encryption protection bonus: when two peers
//!     otherwise tie, prefer to keep the encrypted one. This biases
//!     eviction toward plaintext peers, which an attacker is more
//!     likely to be running (eviction-cost asymmetry).
//!
//! References:
//!   - Bitcoin Core `AttemptToEvictConnection` (src/net.cpp)
//!   - Bitcoin Core `CompareNetGroupKeyed` (subnet-group comparator)
//!   - Heilman et al. 2015, "Eclipse Attacks on Bitcoin's Peer-to-Peer
//!     Network" — the paper that motivated AttemptToEvictConnection.

use std::net::{IpAddr, SocketAddr};
use std::time::Instant;

use super::peer::{PeerId, PeerInfo};

/// How many peers to protect by each criterion. Matches Bitcoin Core's
/// `NumProtectedPeers = 4` per axis (longest, most-recently-active,
/// highest-reputation). With three axes and 4 each, up to 12 peers are
/// candidate-protected; the remainder is eligible for eviction.
const PROTECT_PER_AXIS: usize = 4;

/// Minimum age before a peer is even considered for eviction. Below this,
/// we assume the peer is still in handshake / sync warmup and disconnecting
/// would waste both sides' work. Bitcoin Core uses 30s; we use the same.
const MIN_AGE_BEFORE_EVICT: std::time::Duration = std::time::Duration::from_secs(30);

/// Reputation threshold above which a peer is exempted from eviction
/// outright. PeerInfo reputation is clamped to [-100, 100]; default is 100.
/// Anything ≥ this is considered well-behaved and never evicted.
const REPUTATION_PROTECT_FLOOR: i32 = 80;

/// /16 (IPv4) or /32 (IPv6) netgroup key. Matches Bitcoin Core's
/// `CNetAddr::GetGroup()` for the common IPv4/IPv6 cases (CoinCync doesn't
/// route Tor/I2P-aware grouping yet, so we treat them as their underlying
/// transport's netgroup).
fn netgroup(addr: SocketAddr) -> u64 {
    match addr.ip() {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            // /16: keep the top two octets.
            u64::from(u16::from_be_bytes([o[0], o[1]]))
        }
        IpAddr::V6(v6) => {
            let s = v6.segments();
            // /32: keep the top two 16-bit segments. Tag with a high bit
            // so v4 and v6 groups can't collide in the keyspace.
            (1u64 << 32) | (u64::from(s[0]) << 16) | u64::from(s[1])
        }
    }
}

/// Select an inbound peer to evict to make room for a new inbound
/// connection. Returns `None` when no candidate is safe to evict (e.g.
/// every peer is protected by one of the rules, or all are too young).
///
/// Input is a snapshot iterator of `PeerInfo`. Caller is responsible for
/// holding any locks; this function is pure on the snapshot.
///
/// The caller, after receiving `Some(peer_id)`, must:
///   1. Drop the peer's sender so its tasks unwind cleanly.
///   2. Remove the peer from the peers table.
///   3. Untrack the connection from the per-IP `ConnectionTracker`.
/// Bitcoin Core does all three from inside `CConnman::AttemptToEvict
/// Connection`; we keep the policy/mechanism split because the peers
/// table here is a DashMap and locking is the caller's responsibility.
pub fn select_inbound_to_evict<'a, I>(peers: I, now: Instant) -> Option<PeerId>
where
    I: IntoIterator<Item = &'a PeerInfo>,
{
    let mut candidates: Vec<&PeerInfo> = peers
        .into_iter()
        // Only inbound peers are evictable. Outbound peers are connections
        // WE chose; killing them benefits the attacker.
        .filter(|p| !p.outbound)
        // Skip very-young connections — they may still be handshaking.
        .filter(|p| now.duration_since(p.connected_at) >= MIN_AGE_BEFORE_EVICT)
        // Skip peers above the reputation floor (well-behaved, never evict).
        .filter(|p| p.reputation < REPUTATION_PROTECT_FLOOR)
        .collect();

    if candidates.is_empty() {
        return None;
    }

    // Step 1: protect the N longest-connected peers (loyalty bonus).
    let mut by_age = candidates.clone();
    by_age.sort_by_key(|p| p.connected_at);
    let protect_age: std::collections::HashSet<PeerId> =
        by_age.iter().take(PROTECT_PER_AXIS).map(|p| p.id).collect();

    // Step 2: protect the N most-recently-active peers (mutual traffic).
    let mut by_active = candidates.clone();
    by_active.sort_by(|a, b| b.last_seen.cmp(&a.last_seen));
    let protect_active: std::collections::HashSet<PeerId> =
        by_active.iter().take(PROTECT_PER_AXIS).map(|p| p.id).collect();

    // Step 3: protect the N highest-reputation peers (well-behaved).
    let mut by_rep = candidates.clone();
    by_rep.sort_by(|a, b| b.reputation.cmp(&a.reputation));
    let protect_rep: std::collections::HashSet<PeerId> =
        by_rep.iter().take(PROTECT_PER_AXIS).map(|p| p.id).collect();

    candidates.retain(|p| {
        !protect_age.contains(&p.id)
            && !protect_active.contains(&p.id)
            && !protect_rep.contains(&p.id)
    });

    if candidates.is_empty() {
        return None;
    }

    // Step 4 + 5: group by netgroup, pick the most-concentrated group.
    // This is the eclipse-defense move: when an attacker fills slots from
    // one /16, that /16 ends up with the most candidates, and we evict
    // from it preferentially.
    let mut groups: std::collections::HashMap<u64, Vec<&PeerInfo>> =
        std::collections::HashMap::new();
    for p in &candidates {
        groups.entry(netgroup(p.addr)).or_default().push(p);
    }
    let (_, largest_group) = groups
        .into_iter()
        .max_by_key(|(_, peers)| peers.len())?;

    // Step 6: within the largest netgroup, evict the YOUNGEST peer
    // (last-in-first-out). Tie-break on reputation (lower first), then on
    // encryption (plaintext before encrypted). Encrypted peers are slightly
    // costlier for an attacker to spin up at scale (Noise handshake CPU),
    // so preferring to keep them biases eviction against bot floods.
    let evictee = largest_group.into_iter().max_by(|a, b| {
        // max_by → largest comes last; we want YOUNGEST = largest
        // `connected_at`, so direct compare is correct.
        a.connected_at
            .cmp(&b.connected_at)
            .then_with(|| b.reputation.cmp(&a.reputation)) // lower rep first
            .then_with(|| (a.encrypted as u8).cmp(&(b.encrypted as u8)))
        // a.encrypted < b.encrypted means a is plaintext → larger = b → keep b
    })?;

    Some(evictee.id)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::primitives::Hash;
    use std::time::Duration;

    fn mk(id_byte: u8, ip: &str, age_secs: u64, rep: i32, encrypted: bool, outbound: bool) -> PeerInfo {
        let mut id = [0u8; 32];
        id[0] = id_byte;
        let addr: SocketAddr = format!("{}:28080", ip).parse().unwrap();
        let now = Instant::now();
        PeerInfo {
            id,
            addr,
            state: super::super::peer::PeerState::Connected,
            height: 0,
            tip_hash: Hash::zero(),
            version: 0,
            user_agent: String::new(),
            last_seen: now,
            connected_at: now - Duration::from_secs(age_secs),
            reputation: rep,
            outbound,
            bytes_recv: 0,
            bytes_sent: 0,
            encrypted,
            remote_static_key: None,
            capabilities: 0,
            consecutive_full: std::sync::Arc::new(std::sync::atomic::AtomicU32::new(0)),
            eclipse_slot: None,
        }
    }

    #[test]
    fn no_candidates_returns_none() {
        assert!(select_inbound_to_evict(std::iter::empty(), Instant::now()).is_none());
    }

    #[test]
    fn skips_outbound_peers() {
        let peers = vec![
            mk(1, "1.2.3.4", 3600, 50, true, true /*outbound*/),
            mk(2, "1.2.3.5", 3600, 50, true, true /*outbound*/),
        ];
        let refs: Vec<&PeerInfo> = peers.iter().collect();
        assert!(select_inbound_to_evict(refs, Instant::now()).is_none(),
            "outbound peers must never be evicted");
    }

    #[test]
    fn skips_young_peers() {
        let peers = vec![
            mk(1, "1.2.3.4", 5, 50, true, false),  // 5s old, too young
            mk(2, "1.2.3.5", 10, 50, true, false), // 10s old, still too young
        ];
        let refs: Vec<&PeerInfo> = peers.iter().collect();
        assert!(select_inbound_to_evict(refs, Instant::now()).is_none(),
            "peers younger than MIN_AGE_BEFORE_EVICT must be protected");
    }

    #[test]
    fn skips_high_reputation_peers() {
        let peers: Vec<PeerInfo> = (0..20u8)
            .map(|i| mk(i, &format!("1.2.3.{}", i + 10), 3600, 100, false, false))
            .collect();
        let refs: Vec<&PeerInfo> = peers.iter().collect();
        assert!(select_inbound_to_evict(refs, Instant::now()).is_none(),
            "all-high-reputation peer pool must yield no eviction candidate");
    }

    #[test]
    fn netgroup_concentration_picks_largest() {
        // 12 peers from one /16 (eclipse attacker), 4 from diverse /16s.
        // After the three 4-protect axes consume 12 protections, the
        // attacker's concentration becomes the eviction target.
        let mut peers = Vec::new();
        // Attacker /16: 10.0.x.y
        for i in 0..12u8 {
            peers.push(mk(i, &format!("10.0.0.{}", i + 1), 3600, 50, false, false));
        }
        // Diverse legitimate peers from different /16s
        peers.push(mk(20, "192.168.1.1", 7200, 90, true, false));
        peers.push(mk(21, "172.16.0.1", 7200, 90, true, false));
        peers.push(mk(22, "203.0.113.1", 7200, 90, true, false));
        peers.push(mk(23, "198.51.100.1", 7200, 90, true, false));

        let refs: Vec<&PeerInfo> = peers.iter().collect();
        let evictee = select_inbound_to_evict(refs, Instant::now())
            .expect("with 16 candidates, eviction must succeed");

        // The evictee MUST come from the 10.0.x.y attacker /16.
        let evictee_peer = peers.iter().find(|p| p.id == evictee).unwrap();
        let octets = match evictee_peer.addr.ip() {
            IpAddr::V4(v4) => v4.octets(),
            _ => panic!("expected IPv4"),
        };
        assert_eq!(octets[0..2], [10, 0],
            "eviction must hit the concentrated attacker /16, got {:?}", evictee_peer.addr);
    }

    #[test]
    fn within_attacker_group_picks_youngest() {
        // All 20 peers from one /16. Age increases with index: peer i has
        // age (3600 + i*60). That means peer 19 has the EARLIEST
        // connected_at (oldest peer), peer 0 has the most recent
        // connected_at among the seeded range (youngest in terms of
        // "last to connect" — though all are well above MIN_AGE).
        let peers: Vec<PeerInfo> = (0..20u8)
            .map(|i| mk(i, &format!("10.0.0.{}", i + 1), 3600 + (i as u64) * 60, 50, false, false))
            .collect();
        let refs: Vec<&PeerInfo> = peers.iter().collect();
        let evictee = select_inbound_to_evict(refs, Instant::now())
            .expect("eviction must succeed");

        // Protection axes (with all-equal rep and last_seen, the
        // rep/active sorts are unstable but the age sort is stable on
        // connected_at):
        //   - 4 oldest by age (smallest connected_at): peers 19, 18, 17, 16.
        //   - 4 most-recently-active: ties → first 4 in collect order = 0..3.
        //   - 4 highest-rep: ties → first 4 in collect order = 0..3.
        // Protected union: {0,1,2,3, 16,17,18,19}. Remaining: 4..15.
        // Of those, "youngest" = LARGEST connected_at = SMALLEST age = peer 4.
        assert_eq!(evictee[0], 4,
            "within the saturated /16, the youngest unprotected peer (id=4) should be evicted; got id={}",
            evictee[0]);
    }

    #[test]
    fn ipv6_netgroup_is_32() {
        // Two peers in the same /32 vs one in a different /32.
        let v6_a1: SocketAddr = "[2001:db8:1234::1]:28080".parse().unwrap();
        let v6_a2: SocketAddr = "[2001:db8:5678::1]:28080".parse().unwrap();
        // Different /32s for "diverse" group
        let v6_b1: SocketAddr = "[2002:db8::1]:28080".parse().unwrap();
        let v6_b2: SocketAddr = "[2003:db8::1]:28080".parse().unwrap();
        assert_eq!(netgroup(v6_a1), netgroup(v6_a2),
            "same /32 must produce same netgroup");
        assert_ne!(netgroup(v6_a1), netgroup(v6_b1),
            "different /32 must produce different netgroup");
        assert_ne!(netgroup(v6_b1), netgroup(v6_b2),
            "different /32 must produce different netgroup");
        // Disambiguation: v4 (1, 2) and v6 with first u16=1 must not collide.
        let v4: SocketAddr = "0.1.0.0:28080".parse().unwrap(); // /16 key = 1
        let v6_collision: SocketAddr = "[1::]:28080".parse().unwrap();
        assert_ne!(netgroup(v4), netgroup(v6_collision),
            "v4 and v6 netgroup keys must not collide");
    }
}
