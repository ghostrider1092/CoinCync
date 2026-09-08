//! Diversity-floor guard.
//!
//! Implements the colony's hard rule that no Act may collapse outbound peer or
//! netgroup diversity below a minimum (README rule D.3 + invariant B.3, "a
//! caste may add margin; it may not remove a guarantee"). The census is
//! sourced from the node's `ConnectionTracker` outbound-subnet snapshot; the
//! floor is deliberately **conservative** — a diversity-affecting Act is
//! refused whenever the node is already *at or below* the floor, so the colony
//! can never be the thing that pushes an eclipse-vulnerable node over the edge.

use super::{ColonyAction, ColonyActionKind};

/// A snapshot of the node's current outbound diversity. `Default` is 0/0 — the
/// conservative "no diversity" census, under which the floor denies every
/// diversity-affecting action.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct NetgroupCensus {
    /// Number of *distinct* netgroups (e.g. /16 IPv4 groups) among outbound peers.
    pub distinct_netgroups: usize,
    /// Total outbound connections.
    pub total_outbound: usize,
}

/// The minimum diversity the colony must never breach.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DiversityFloor {
    pub min_netgroups: usize,
    pub min_outbound: usize,
}

impl Default for DiversityFloor {
    fn default() -> Self {
        // Matches the centipede/army_ant "several diverse legs" posture: keep at
        // least 4 distinct netgroups and 4 outbound peers before the colony may
        // narrow, tarpit, or rewire anything.
        Self {
            min_netgroups: 4,
            min_outbound: 4,
        }
    }
}

impl DiversityFloor {
    pub fn new(min_netgroups: usize, min_outbound: usize) -> Self {
        Self {
            min_netgroups,
            min_outbound,
        }
    }

    /// Whether `action` is permitted given the current `census`.
    ///
    /// Non-diversity actions (cover pulses, wire profile, housekeeping) are
    /// always permitted here — they don't touch peer topology. A
    /// diversity-affecting action is permitted only if the node is **strictly
    /// above** both floors, so applying it cannot bring the node to or below
    /// the minimum.
    pub fn permits(&self, census: &NetgroupCensus, action: &ColonyAction) -> bool {
        if !action.kind.affects_diversity() {
            return true;
        }
        census.distinct_netgroups > self.min_netgroups && census.total_outbound > self.min_outbound
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn diversity_action() -> ColonyAction {
        ColonyAction::new(ColonyActionKind::BridgeReconnect, "reconnect")
    }
    fn neutral_action() -> ColonyAction {
        ColonyAction::new(ColonyActionKind::CoverPulse, "pulse")
    }

    #[test]
    fn permits_diversity_action_when_above_floor() {
        let floor = DiversityFloor::default();
        let census = NetgroupCensus {
            distinct_netgroups: 6,
            total_outbound: 6,
        };
        assert!(floor.permits(&census, &diversity_action()));
    }

    #[test]
    fn refuses_diversity_action_at_floor() {
        let floor = DiversityFloor::default(); // min 4/4
        let at = NetgroupCensus {
            distinct_netgroups: 4,
            total_outbound: 4,
        };
        assert!(!floor.permits(&at, &diversity_action()));
        let below = NetgroupCensus {
            distinct_netgroups: 2,
            total_outbound: 10,
        };
        assert!(!floor.permits(&below, &diversity_action()));
    }

    #[test]
    fn neutral_action_always_permitted() {
        let floor = DiversityFloor::default();
        let below = NetgroupCensus {
            distinct_netgroups: 1,
            total_outbound: 1,
        };
        assert!(floor.permits(&below, &neutral_action()));
    }
}
