//! Peer-set security detail — the P2P **eclipse / partition / isolation**
//! surface. The peer set is node-LOCAL (not consensus), so every alert is
//! **operational** (page, never halt): being under-connected is a risk to
//! *this* node's view, not a chain-wide invariant. Read-only, O(peers).
//!
//! Two signals:
//! - **count** ([`peer_health`]): too few peers → isolation/partition risk.
//! - **diversity** ([`peer_diversity`]): a peer set whose *count* looks healthy
//!   but is concentrated in few `/16` netgroups → a **sybil-eclipse** the count
//!   alone cannot see (all N peers could be one adversary's subnet). Uses the
//!   same [`crate::network::eviction::netgroup`] keying as the connection-level
//!   eclipse defenses (per-`/16` outbound cap + netgroup-aware eviction), so
//!   the observability signal and the enforcement agree on what a group is.

use std::collections::HashMap;
use std::net::SocketAddr;

use crate::security::{SecurityDetail, SecurityReport, Severity};

/// Pure peer-health signal (testable in isolation): too few peers is an
/// eclipse/partition risk. Zero peers is the sharpest signal (fully isolated —
/// this node sees no network); below the healthy minimum is a softer warning.
pub fn peer_health(count: usize, min_healthy: usize) -> Option<(Severity, &'static str, String)> {
    if count == 0 {
        Some((
            Severity::Critical,
            "no-peers",
            "0 connected peers — this node is isolated (eclipse/partition risk)".to_string(),
        ))
    } else if count < min_healthy {
        Some((
            Severity::Warning,
            "low-peers",
            format!("{count} connected peers < healthy minimum {min_healthy} — eclipse risk"),
        ))
    } else {
        None
    }
}

/// Minimum peer count before netgroup concentration is even worth flagging —
/// below this the count signal ([`peer_health`]) already dominates.
const MIN_PEERS_FOR_DIVERSITY: usize = 2;
/// Above this many peers, a single `/16` holding a strict majority is flagged as
/// a partial-eclipse concentration warning.
const CONCENTRATION_MIN_PEERS: usize = 4;

/// Pure netgroup-diversity signal: does a peer set whose *count* looks healthy
/// hide a **sybil-eclipse** — all (or most) peers in one `/16` netgroup?
///
/// - **All** peers in a single netgroup (≥ 2 peers) → `Critical`: a healthy
///   peer count can still be a single adversary's subnet.
/// - A single netgroup holding a **strict majority** (with ≥ 4 peers) →
///   `Warning`: partial-eclipse concentration.
/// - Otherwise `None`.
///
/// Netgroups use [`crate::network::eviction::netgroup`] (IPv4 `/16`, IPv6 `/32`)
/// — the same keying the eviction/outbound eclipse defenses use. Output is
/// order-independent (counts + max size), so the signal is deterministic.
pub fn peer_diversity(addrs: &[SocketAddr]) -> Option<(Severity, &'static str, String)> {
    let n = addrs.len();
    if n < MIN_PEERS_FOR_DIVERSITY {
        // 0/1 peers: isolation is peer_health's job, not diversity's.
        return None;
    }
    let mut counts: HashMap<u64, usize> = HashMap::new();
    for a in addrs {
        *counts.entry(crate::network::eviction::netgroup(*a)).or_default() += 1;
    }
    let distinct = counts.len();
    let max_size = counts.values().copied().max().unwrap_or(0);

    if distinct == 1 {
        return Some((
            Severity::Critical,
            "single-netgroup",
            format!(
                "all {n} connected peers share a single /16 netgroup — eclipse risk \
                 (a healthy-looking peer count can still be one adversary's subnet)"
            ),
        ));
    }
    if n >= CONCENTRATION_MIN_PEERS && max_size * 2 > n {
        return Some((
            Severity::Warning,
            "netgroup-concentration",
            format!(
                "{max_size} of {n} connected peers share one /16 netgroup \
                 ({distinct} distinct netgroups) — partial-eclipse risk"
            ),
        ));
    }
    None
}

/// A [`SecurityDetail`] over the connected peer set. Flags under-connection
/// (count) and — when peer addresses are supplied — netgroup concentration
/// (diversity). Snapshot-based (never borrows the live P2P node). All alerts
/// operational.
pub struct PeerSecurityDetail {
    peer_count: usize,
    min_healthy: usize,
    /// Connected peer addresses for the diversity signal. `None` → count-only
    /// (back-compat); `Some` → also run [`peer_diversity`].
    peers: Option<Vec<SocketAddr>>,
}

impl PeerSecurityDetail {
    /// Healthy-minimum default: matches the rig's ≥3-peer mesh gate — below a
    /// small mesh, an adversary controlling the few peers can eclipse the node.
    pub const DEFAULT_MIN_HEALTHY: usize = 3;

    pub fn new(peer_count: usize) -> Self {
        Self { peer_count, min_healthy: Self::DEFAULT_MIN_HEALTHY, peers: None }
    }

    pub fn with_min_healthy(peer_count: usize, min_healthy: usize) -> Self {
        Self { peer_count, min_healthy, peers: None }
    }

    /// Build from the connected peer addresses: count is derived from the slice
    /// and the diversity (netgroup-concentration) signal is enabled.
    pub fn with_peers(addrs: Vec<SocketAddr>) -> Self {
        Self {
            peer_count: addrs.len(),
            min_healthy: Self::DEFAULT_MIN_HEALTHY,
            peers: Some(addrs),
        }
    }
}

impl SecurityDetail for PeerSecurityDetail {
    fn label(&self) -> &'static str {
        "peer-set"
    }

    fn sweep(&self) -> SecurityReport {
        let mut r = SecurityReport::clean();
        if let Some((sev, code, msg)) = peer_health(self.peer_count, self.min_healthy) {
            // Operational only — an under-connected node must page its operator,
            // never halt the chain.
            r.raise_operational("peer-set", sev, code, msg);
        }
        // Diversity signal (only when addresses were supplied). Also operational:
        // netgroup concentration is a risk to THIS node's view, never a
        // chain-wide invariant, so it pages and never halts.
        if let Some(addrs) = &self.peers {
            if let Some((sev, code, msg)) = peer_diversity(addrs) {
                r.raise_operational("peer-set", sev, code, msg);
            }
        }
        r
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn peer_health_pure_signal() {
        assert!(matches!(peer_health(0, 3), Some((Severity::Critical, "no-peers", _))));
        assert!(matches!(peer_health(2, 3), Some((Severity::Warning, "low-peers", _))));
        assert!(peer_health(3, 3).is_none(), "at the minimum is healthy");
        assert!(peer_health(50, 3).is_none());
    }

    #[test]
    fn peer_detail_is_operational_never_consensus() {
        // Even full isolation (0 peers, a Critical) must not be a consensus halt.
        let report = PeerSecurityDetail::new(0).sweep();
        assert!(report.has_critical(), "isolation is visible");
        assert!(!report.has_consensus_halt(), "but P2P alerts never halt consensus");
        // A well-connected node is clean.
        assert!(PeerSecurityDetail::new(8).sweep().is_clean());
    }

    fn addr(s: &str) -> SocketAddr {
        s.parse().unwrap()
    }

    #[test]
    fn diversity_flags_all_peers_in_one_netgroup() {
        // 6 peers, healthy COUNT, but all in 203.0.x.y (one /16) — sybil eclipse.
        let peers: Vec<SocketAddr> = (1..=6)
            .map(|i| addr(&format!("203.0.{i}.10:28080")))
            .collect();
        let sig = peer_diversity(&peers).expect("single-netgroup must flag");
        assert!(matches!(sig, (Severity::Critical, "single-netgroup", _)), "got {sig:?}");
    }

    #[test]
    fn diversity_clean_when_spread_across_netgroups() {
        // 6 peers across 6 distinct /16s — well diversified.
        let peers: Vec<SocketAddr> = [
            "203.0.1.1", "198.51.2.2", "192.0.3.3", "10.20.4.4", "172.16.5.5", "8.8.6.6",
        ]
        .iter()
        .map(|ip| addr(&format!("{ip}:28080")))
        .collect();
        assert!(peer_diversity(&peers).is_none(), "diverse peer set must be clean");
    }

    #[test]
    fn diversity_warns_on_majority_concentration() {
        // 5 peers: 3 in one /16 (majority), 2 elsewhere → Warning, not Critical.
        let peers: Vec<SocketAddr> = [
            "45.66.1.1", "45.66.2.2", "45.66.3.3", // 45.66.0.0/16 (majority)
            "8.8.8.8", "1.1.1.1",
        ]
        .iter()
        .map(|ip| addr(&format!("{ip}:28080")))
        .collect();
        let sig = peer_diversity(&peers).expect("majority concentration must flag");
        assert!(matches!(sig, (Severity::Warning, "netgroup-concentration", _)), "got {sig:?}");
    }

    #[test]
    fn diversity_ignores_tiny_or_even_split_sets() {
        // A single peer: diversity is not meaningful (isolation is peer_health's job).
        assert!(peer_diversity(&[addr("203.0.1.1:28080")]).is_none());
        // 4 peers, 2+2 even split: no single /16 majority → clean.
        let even: Vec<SocketAddr> = ["45.66.1.1", "45.66.2.2", "8.8.8.8", "8.8.9.9"]
            .iter()
            .map(|ip| addr(&format!("{ip}:28080")))
            .collect();
        assert!(peer_diversity(&even).is_none(), "even 2/2 split is not a majority");
    }

    #[test]
    fn diversity_detail_is_operational_never_consensus() {
        // A single-netgroup Critical must page but never halt consensus.
        let peers: Vec<SocketAddr> = (1..=5)
            .map(|i| addr(&format!("100.64.{i}.1:28080")))
            .collect();
        let report = PeerSecurityDetail::with_peers(peers).sweep();
        assert!(
            report.alerts.iter().any(|a| a.code == "single-netgroup"),
            "single-netgroup must be raised"
        );
        assert!(!report.has_consensus_halt(), "peer diversity never halts consensus");
        // A diverse, well-connected set sweeps clean.
        let diverse: Vec<SocketAddr> = ["1.2.3.4", "5.6.7.8", "9.10.11.12", "13.14.15.16"]
            .iter()
            .map(|ip| addr(&format!("{ip}:28080")))
            .collect();
        assert!(PeerSecurityDetail::with_peers(diverse).sweep().is_clean());
    }
}
