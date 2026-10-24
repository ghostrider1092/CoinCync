//! Live wiring of the P2P breaker into the node's maintenance **heartbeat tick**
//! — a **feed adapter into the universal [`fuse`](crate::fuse) box**.
//!
//! Every heartbeat (~30s) the node calls [`observe_from_addrs`] with the REAL
//! set of connected-peer socket addresses. This derives the live anti-eclipse
//! signals — peer count, netgroup (/16, /32) diversity, per-IP concentration —
//! runs the pure [`p2p_breaker`](crate::p2p_breaker) detector, and feeds the
//! result to the one process-wide fuse box ([`crate::fuse::observe`]) under
//! [`BreakerSurface::P2p`]. The breaker state lives in the shared box.
//!
//! **Observe-mode: it logs, it does not drop peers.** Node-local, no consensus
//! effect, gated OFF by default (`p2p-breaker` + `breaker-recovery`). Actually
//! quarantining peers would be a later, explicit step.
//!
//! Scope note: the eclipse / per-IP signals come straight from the live peer
//! map. The deeper signals (phantom-IBD target, handshake-lane starvation, sync
//! stall) need hooks into the sync/IBD layer and are left non-tripping here — a
//! documented follow-up. See `docs/design/cip-circuit-breakers.md`.

use std::net::{IpAddr, SocketAddr};

use crate::breaker_recovery::{BreakerState, BreakerSurface};
use crate::fuse::{self, FaultReport};
use crate::p2p_breaker::{detect, PeerObservation};

fn env_usize(name: &str, default: usize) -> usize {
    std::env::var(name).ok().and_then(|v| v.parse().ok()).unwrap_or(default)
}

/// Anti-eclipse netgroup bucket: IPv4 by /16, IPv6 by /32, in disjoint
/// namespaces (matches `AddressManager::addr_netgroup`'s intent).
fn netgroup(addr: &SocketAddr) -> u64 {
    match addr.ip() {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            (o[0] as u64) << 8 | (o[1] as u64)
        }
        IpAddr::V6(v6) => {
            let s = v6.segments();
            // high bit set to keep the IPv6 namespace disjoint from IPv4.
            (1u64 << 40) | ((s[0] as u64) << 16) | (s[1] as u64)
        }
    }
}

/// Observe the live connected-peer set and advance the P2P breaker in the shared
/// fuse box. Returns the new breaker state.
pub fn observe_from_addrs(connected: &[SocketAddr]) -> BreakerState {
    let total_peers = connected.len();
    let mut groups = std::collections::HashSet::new();
    let mut per_ip: std::collections::HashMap<IpAddr, usize> = std::collections::HashMap::new();
    for a in connected {
        groups.insert(netgroup(a));
        *per_ip.entry(a.ip()).or_insert(0) += 1;
    }
    let obs = PeerObservation {
        total_peers,
        min_peers: env_usize("COINCYNC_P2P_BREAKER_MIN_PEERS", 3),
        distinct_netgroups: groups.len(),
        min_netgroups: env_usize("COINCYNC_P2P_BREAKER_MIN_NETGROUPS", 2),
        worst_ip_conns: per_ip.values().copied().max().unwrap_or(0),
        max_conns_per_ip: env_usize("COINCYNC_P2P_BREAKER_MAX_CONNS_PER_IP", 2),
        // Deeper signals need sync/IBD hooks — non-tripping here (follow-up).
        ibd_target_from_banned: false,
        blocks_since_progress: 0,
        max_stall_blocks: u64::MAX,
        handshake_queue_depth: 0,
        handshake_completions: 1,
    };
    let report = FaultReport::from_labels(detect(&obs).iter().map(|f| format!("{f:?}")));
    fuse::observe(BreakerSurface::P2p, &report)
}

/// The current live P2P breaker state from the shared box, or `None` if the
/// surface isn't installed.
pub fn state() -> Option<BreakerState> {
    fuse::surface_state(BreakerSurface::P2p)
}

/// Reset the P2P breaker in the shared box (test isolation / fresh window).
pub fn reset() {
    fuse::reset_surface(BreakerSurface::P2p);
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    // These tests drive the process-wide fuse box, so serialize them (the lib
    // test binary runs tests in parallel) and reset the P2p surface each time.
    static SERIAL: Mutex<()> = Mutex::new(());

    fn a(s: &str) -> SocketAddr {
        s.parse().unwrap()
    }

    #[test]
    fn diverse_peerset_is_healthy() {
        let _g = SERIAL.lock().unwrap_or_else(|p| p.into_inner());
        reset();
        std::env::remove_var("COINCYNC_P2P_BREAKER_MIN_PEERS");
        let peers = [
            a("1.2.3.4:28080"),
            a("5.6.7.8:28080"),
            a("9.10.11.12:28080"),
            a("13.14.15.16:28080"),
        ];
        assert_eq!(observe_from_addrs(&peers), BreakerState::Closed);
    }

    #[test]
    fn single_netgroup_is_eclipse_risk() {
        let _g = SERIAL.lock().unwrap_or_else(|p| p.into_inner());
        reset();
        // Four peers, all in the same /16 (1.2.x.x) → 1 netgroup → eclipse risk.
        let peers = [
            a("1.2.0.1:28080"),
            a("1.2.5.9:28080"),
            a("1.2.200.4:28080"),
            a("1.2.99.99:28080"),
        ];
        // Breaker trips (detected); observe-mode logs it, the node wouldn't act.
        assert_eq!(observe_from_addrs(&peers), BreakerState::Open);
    }

    #[test]
    fn too_few_peers_is_eclipse_risk() {
        let _g = SERIAL.lock().unwrap_or_else(|p| p.into_inner());
        reset();
        std::env::remove_var("COINCYNC_P2P_BREAKER_MIN_PEERS");
        let peers = [a("1.2.3.4:28080")]; // 1 peer < min 3
        assert_eq!(observe_from_addrs(&peers), BreakerState::Open);
    }

    #[test]
    fn recovers_after_diversity_returns() {
        let _g = SERIAL.lock().unwrap_or_else(|p| p.into_inner());
        reset();
        std::env::remove_var("COINCYNC_P2P_BREAKER_MIN_PEERS");
        let bad = [a("1.2.0.1:28080"), a("1.2.0.2:28080"), a("1.2.0.3:28080")];
        let good = [
            a("1.2.3.4:28080"),
            a("5.6.7.8:28080"),
            a("9.10.11.12:28080"),
            a("13.14.15.16:28080"),
        ];
        assert_eq!(observe_from_addrs(&bad), BreakerState::Open);
        // AutoReset: needs a healthy streak (heal_streak=3) + a probe tick.
        for _ in 0..3 {
            observe_from_addrs(&good);
        }
        assert_eq!(state(), Some(BreakerState::HalfOpen));
        assert_eq!(observe_from_addrs(&good), BreakerState::Closed);
    }
}
