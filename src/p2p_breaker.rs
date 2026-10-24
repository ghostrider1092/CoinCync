//! CoinCync P2P / IBD **circuit breaker** — the networking bulkhead.
//!
//! Protects a node from peer-layer attacks and sync pathologies by
//! **quarantining the offending peer(s) and forcing re-selection** (feelers /
//! fresh dials) while the node keeps serving and syncing. Seal off the bad
//! peer path; stay connected.
//!
//! Targets the real failure modes this chain has seen or guards against:
//!   - **eclipse** — too few peers / all from one netgroup (attacker owns your
//!     view),
//!   - **phantom-IBD target** — a banned/dead peer's advertised height still
//!     driving the sync target (the `remove_peer_height`-on-drop regression:
//!     permanent `fork_stuck`),
//!   - **per-IP flood** — one address hogging connection slots,
//!   - **sync stall** — IBD making no progress for too long,
//!   - **handshake starvation** — the handshake lane backed up with zero
//!     completions (the cold-start mesh bug).
//!
//! Like the mempool breaker, **peer management is node-local policy, not
//! consensus** — quarantining a peer cannot fork the chain — so this breaker is
//! safe to arm per-node on the live net. Same build bar as the others: pure,
//! fail-closed, feature-gated, declared from `lib.rs` (not the hash-locked
//! consensus core), default policy `Observe`.

/// A peer-layer / IBD safety breach.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PeerFault {
    /// Too few peers or too few distinct netgroups — eclipse-attack exposure.
    EclipseRisk,
    /// The IBD sync target is anchored on a banned/dropped peer's height (the
    /// phantom-target `fork_stuck` class).
    PhantomIbdTarget,
    /// A single IP holds more connection slots than allowed.
    PerIpFlood,
    /// Initial sync made no block progress within the stall window.
    SyncStall,
    /// The handshake lane is backed up with zero completions — starvation.
    HandshakeStarvation,
}

/// What the node observed about its peer set / sync over one interval.
#[derive(Clone, Copy, Debug, Default)]
pub struct PeerObservation {
    /// Current peer count and the floor below which we're eclipse-prone.
    pub total_peers: usize,
    pub min_peers: usize,
    /// Distinct netgroups (subnet buckets) and the floor for diversity.
    pub distinct_netgroups: usize,
    pub min_netgroups: usize,
    /// Connections held by the single busiest IP and the per-IP cap.
    pub worst_ip_conns: usize,
    pub max_conns_per_ip: usize,
    /// Whether the active IBD target traces to a banned/dropped peer.
    pub ibd_target_from_banned: bool,
    /// Blocks of no sync progress and the stall tolerance.
    pub blocks_since_progress: u64,
    pub max_stall_blocks: u64,
    /// Handshake lane queue depth and completions this interval.
    pub handshake_queue_depth: usize,
    pub handshake_completions: u64,
}

/// Collect every peer-layer breach (empty = healthy). Pure.
pub fn detect(o: &PeerObservation) -> Vec<PeerFault> {
    let mut f = Vec::new();
    if o.total_peers < o.min_peers || o.distinct_netgroups < o.min_netgroups {
        f.push(PeerFault::EclipseRisk);
    }
    if o.ibd_target_from_banned {
        f.push(PeerFault::PhantomIbdTarget);
    }
    if o.worst_ip_conns > o.max_conns_per_ip {
        f.push(PeerFault::PerIpFlood);
    }
    if o.blocks_since_progress > o.max_stall_blocks {
        f.push(PeerFault::SyncStall);
    }
    if o.handshake_queue_depth > 0 && o.handshake_completions == 0 {
        f.push(PeerFault::HandshakeStarvation);
    }
    f
}

/// Breaker policy. **Default `Observe`** — detect + log, never quarantine.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BreakerPolicy {
    /// Detect + log only; never quarantine. Default.
    Observe,
    /// Quarantine offending peers + force re-selection on any breach. Safe to
    /// set per-node on the live net — peer management is local, not consensus.
    Armed,
}

impl Default for BreakerPolicy {
    fn default() -> Self {
        BreakerPolicy::Observe
    }
}

/// The breaker's decision. Isolation scope = the peer set; consensus/chain state
/// is never in scope.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum BreakerAction {
    /// Keep the current peer set as-is.
    KeepPeers,
    /// Quarantine the offending peers and force re-selection (feelers / fresh
    /// dials). The chain and consensus are unaffected.
    QuarantinePeers { faults: Vec<PeerFault> },
}

impl BreakerAction {
    /// Whether the node should quarantine peers + re-select.
    pub fn quarantines_peers(&self) -> bool {
        matches!(self, BreakerAction::QuarantinePeers { .. })
    }

    /// The bulkhead guarantee: peer churn never affects consensus / chain state.
    /// Always false.
    pub fn affects_consensus(&self) -> bool {
        false
    }
}

/// Evaluate: detect breaches, then apply policy. `Observe` always keeps peers
/// (logs); `Armed` quarantines iff any breach is present.
pub fn evaluate(policy: BreakerPolicy, o: &PeerObservation) -> BreakerAction {
    let faults = detect(o);
    match policy {
        BreakerPolicy::Observe => BreakerAction::KeepPeers,
        BreakerPolicy::Armed if faults.is_empty() => BreakerAction::KeepPeers,
        BreakerPolicy::Armed => BreakerAction::QuarantinePeers { faults },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A well-connected, diverse, progressing node.
    fn healthy() -> PeerObservation {
        PeerObservation {
            total_peers: 12,
            min_peers: 3,
            distinct_netgroups: 8,
            min_netgroups: 3,
            worst_ip_conns: 1,
            max_conns_per_ip: 2,
            ibd_target_from_banned: false,
            blocks_since_progress: 0,
            max_stall_blocks: 120,
            handshake_queue_depth: 0,
            handshake_completions: 5,
        }
    }

    #[test]
    fn default_policy_is_observe() {
        assert_eq!(BreakerPolicy::default(), BreakerPolicy::Observe);
    }

    #[test]
    fn healthy_peerset_keeps_peers_in_both_modes() {
        assert!(detect(&healthy()).is_empty());
        assert_eq!(evaluate(BreakerPolicy::Observe, &healthy()), BreakerAction::KeepPeers);
        assert_eq!(evaluate(BreakerPolicy::Armed, &healthy()), BreakerAction::KeepPeers);
    }

    #[test]
    fn eclipse_risk_from_low_netgroups() {
        let mut o = healthy();
        o.distinct_netgroups = 1; // all peers one subnet
        assert!(detect(&o).contains(&PeerFault::EclipseRisk));
        let a = evaluate(BreakerPolicy::Armed, &o);
        assert!(a.quarantines_peers());
        assert!(!a.affects_consensus());
    }

    #[test]
    fn phantom_ibd_target_is_caught() {
        let mut o = healthy();
        o.ibd_target_from_banned = true; // the fork_stuck regression signal
        assert!(detect(&o).contains(&PeerFault::PhantomIbdTarget));
        assert!(evaluate(BreakerPolicy::Armed, &o).quarantines_peers());
        // Observe never acts.
        assert!(!evaluate(BreakerPolicy::Observe, &o).quarantines_peers());
    }

    #[test]
    fn per_ip_flood_stall_and_handshake_starvation() {
        let mut o = healthy();
        o.worst_ip_conns = 50;
        assert!(detect(&o).contains(&PeerFault::PerIpFlood));

        let mut o2 = healthy();
        o2.blocks_since_progress = 1_000; // > 120
        assert!(detect(&o2).contains(&PeerFault::SyncStall));

        let mut o3 = healthy();
        o3.handshake_queue_depth = 10;
        o3.handshake_completions = 0; // starved lane
        assert!(detect(&o3).contains(&PeerFault::HandshakeStarvation));
    }

    #[test]
    fn multiple_breaches_all_reported() {
        let mut o = healthy();
        o.ibd_target_from_banned = true;
        o.distinct_netgroups = 1;
        o.blocks_since_progress = 10_000;
        if let BreakerAction::QuarantinePeers { faults } = evaluate(BreakerPolicy::Armed, &o) {
            assert!(faults.len() >= 3);
        } else {
            panic!("expected QuarantinePeers");
        }
    }
}
