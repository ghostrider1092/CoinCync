//! centipede — multipath, netgroup-diverse block-relay leg selection.
//!
//! A centipede keeps moving even when several legs are lost — redundancy
//! through many independent supports. This caste applies that to **block
//! propagation**: relaying a freshly-accepted block over a *single* path is
//! both a reliability single-point-of-failure and an eclipse foothold (an
//! attacker who controls that one path can delay or drop our blocks). The
//! centipede instead picks several relay "legs" spread across **distinct
//! netgroups**, so a block still reaches the honest network even if some
//! legs are slow, dead, or adversarial.
//!
//! ## Why netgroup diversity (rules D.3 eclipse / D.2 DoS)
//!
//! Peers in the same netgroup (e.g. the same routable `/16`) are cheap for
//! one actor to control en masse. Choosing legs that maximise *netgroup*
//! spread means no single IP range can be the sole path our blocks take —
//! the same principle the inbound-eviction logic uses defensively, applied
//! here to the outbound relay fan-out. This mirrors Bitcoin Core's
//! anti-eclipse "prefer diverse netgroups" posture.
//!
//! ## Scope: pure selection core (observe-first)
//!
//! This module only *chooses* legs from a candidate list the caller
//! supplies. It performs no I/O, opens no connections, and never sees a
//! transaction — a relayed *block* is public data, and only block relay is
//! in scope (transaction propagation stays under Dandelion++, never here).
//! Wiring the chosen legs into the actual block-announce path is a later,
//! separately-reviewed phase.
//!
//! Deterministic selection (stable sort, tie-broken by id) — same
//! rationale as [`super::pheromone`]: reproducible and trivially testable.

use std::collections::BTreeMap;

/// A candidate relay leg: a peer identity plus the netgroup it belongs to.
///
/// `netgroup` is an opaque diversity bucket the caller computes (typically
/// the peer's routable `/16` for IPv4 or `/32` for IPv6, matching the
/// eviction module's grouping). Two legs with the same `netgroup` count as
/// "the same direction" for diversity purposes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Leg {
    pub id: String,
    pub netgroup: u16,
}

impl Leg {
    pub fn new(id: impl Into<String>, netgroup: u16) -> Self {
        Self { id: id.into(), netgroup }
    }
}

/// Choose up to `max_legs` relay legs from `candidates`, maximising
/// netgroup diversity.
///
/// Strategy: round-robin across netgroups. One leg from each distinct
/// netgroup is taken before any netgroup contributes a second, so the
/// selected set covers `min(max_legs, distinct_netgroups)` different
/// netgroups — the maximum diversity achievable for that budget. Within a
/// netgroup, legs are taken in `id` order; across netgroups, in `netgroup`
/// order. Fully deterministic.
///
/// Boundaries:
/// - `max_legs == 0` or empty `candidates` → empty result.
/// - `max_legs >= candidates.len()` → every candidate returned (still in
///   the diversity-first order).
pub fn select_legs(candidates: &[Leg], max_legs: usize) -> Vec<Leg> {
    if max_legs == 0 || candidates.is_empty() {
        return Vec::new();
    }

    // Deterministic base order: (netgroup, id).
    let mut sorted = candidates.to_vec();
    sorted.sort_by(|a, b| a.netgroup.cmp(&b.netgroup).then_with(|| a.id.cmp(&b.id)));

    // Annotate each leg with its rank *within* its netgroup (0 = first
    // pick from that group, 1 = second, …).
    let mut rank_in_group: BTreeMap<u16, usize> = BTreeMap::new();
    let mut annotated: Vec<(usize, Leg)> = Vec::with_capacity(sorted.len());
    for leg in sorted {
        let rank = rank_in_group.entry(leg.netgroup).or_insert(0);
        annotated.push((*rank, leg));
        *rank += 1;
    }

    // Sort by (intra-group rank, netgroup, id): all rank-0 legs first (one
    // per netgroup, in netgroup order), then all rank-1, etc. Taking the
    // first `max_legs` therefore spreads across netgroups before doubling
    // up on any one.
    annotated.sort_by(|a, b| {
        a.0.cmp(&b.0)
            .then_with(|| a.1.netgroup.cmp(&b.1.netgroup))
            .then_with(|| a.1.id.cmp(&b.1.id))
    });

    annotated.into_iter().take(max_legs).map(|(_, leg)| leg).collect()
}

/// Number of distinct netgroups represented in a leg set. A diversity
/// metric the caller can log/alert on — a low count for a healthy peer
/// table is an eclipse warning sign.
pub fn distinct_netgroups(legs: &[Leg]) -> usize {
    legs.iter().map(|l| l.netgroup).collect::<std::collections::BTreeSet<_>>().len()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn legs(spec: &[(&str, u16)]) -> Vec<Leg> {
        spec.iter().map(|(id, ng)| Leg::new(*id, *ng)).collect()
    }

    #[test]
    fn empty_or_zero_budget_selects_nothing() {
        assert!(select_legs(&[], 3).is_empty());
        assert!(select_legs(&legs(&[("a", 1)]), 0).is_empty());
    }

    #[test]
    fn prefers_one_per_netgroup_before_doubling_up() {
        // Three netgroups; two peers in group 1. With budget 3 we must get
        // one from EACH group, never two from group 1.
        let c = legs(&[("a1", 1), ("a2", 1), ("b1", 2), ("c1", 3)]);
        let sel = select_legs(&c, 3);
        assert_eq!(sel.len(), 3);
        assert_eq!(distinct_netgroups(&sel), 3, "must cover all three netgroups");
    }

    #[test]
    fn caps_at_max_legs() {
        let c = legs(&[("a", 1), ("b", 2), ("c", 3), ("d", 4), ("e", 5)]);
        assert_eq!(select_legs(&c, 2).len(), 2);
    }

    #[test]
    fn diversity_is_maximised_for_the_budget() {
        // 4 netgroups available, budget 4 -> 4 distinct netgroups.
        let c = legs(&[
            ("a", 10), ("b", 10), ("c", 20), ("d", 30), ("e", 40), ("f", 40),
        ]);
        let sel = select_legs(&c, 4);
        assert_eq!(sel.len(), 4);
        assert_eq!(
            distinct_netgroups(&sel),
            4,
            "budget 4 across 4 netgroups must pick 4 distinct netgroups"
        );
    }

    #[test]
    fn single_netgroup_returns_capped_subset() {
        // All same netgroup: no diversity possible; return min(max,count).
        let c = legs(&[("a", 7), ("b", 7), ("c", 7)]);
        let sel = select_legs(&c, 2);
        assert_eq!(sel.len(), 2);
        assert_eq!(distinct_netgroups(&sel), 1);
        // Deterministic: id order within the group -> a, b.
        assert_eq!(sel[0].id, "a");
        assert_eq!(sel[1].id, "b");
    }

    #[test]
    fn budget_exceeding_candidates_returns_all() {
        let c = legs(&[("a", 1), ("b", 2)]);
        let sel = select_legs(&c, 10);
        assert_eq!(sel.len(), 2);
    }

    #[test]
    fn selection_is_deterministic() {
        let c = legs(&[("z", 3), ("a", 1), ("m", 2), ("b", 1), ("y", 3)]);
        let first = select_legs(&c, 3);
        for _ in 0..20 {
            assert_eq!(select_legs(&c, 3), first, "selection must be stable across runs");
        }
        // First round picks the id-least leg of each netgroup, in netgroup
        // order: group1->a, group2->m, group3->y.
        assert_eq!(
            first.iter().map(|l| l.id.as_str()).collect::<Vec<_>>(),
            vec!["a", "m", "y"]
        );
    }

    #[test]
    fn second_leg_per_group_only_after_all_groups_covered() {
        // budget 5, groups {1:[a,b,c], 2:[d]} -> round1: a,d ; round2: b ;
        // round3: c. Group 2 exhausted after one. Order: a,d,b,c (then
        // nothing). Assert group coverage happened before group-1 doubled.
        let c = legs(&[("a", 1), ("b", 1), ("c", 1), ("d", 2)]);
        let sel = select_legs(&c, 5);
        assert_eq!(sel.len(), 4);
        // 'd' (the only group-2 leg) must appear before the 2nd group-1 leg.
        let d_pos = sel.iter().position(|l| l.id == "d").unwrap();
        let b_pos = sel.iter().position(|l| l.id == "b").unwrap();
        assert!(d_pos < b_pos, "diverse netgroup must be covered before doubling up");
    }
}
