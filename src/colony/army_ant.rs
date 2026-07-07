//! army-ant — living-bridge partition recovery.
//!
//! Army ants link their own bodies into a living bridge to span a gap so
//! the colony keeps moving. This caste picks the peers a node should reach
//! for to **bridge a suspected partition** — when the spider senses a split
//! forming, the node needs to re-establish paths to the far side. Rather
//! than reconnect blindly, army-ant chooses a small set of **netgroup-diverse,
//! recently-seen** bridge candidates, so the rebuilt links span different
//! routable groups (a single hostile group can't re-eclipse us during
//! recovery) and favour peers most likely to still be alive.
//!
//! ## Relationship to centipede
//!
//! [`super::centipede`] fans a *block* across diverse legs during normal
//! operation; army-ant selects *reconnection targets* during a partition
//! event. Both value netgroup diversity, but army-ant additionally weights
//! **freshness** (a bridge to a peer last seen 10s ago is worth far more
//! than one last seen an hour ago) because the goal is to re-link *now*.
//!
//! ## Scope: selection core (form: mode of colony healing)
//!
//! Chooses from a caller-supplied candidate list; opens no connections and
//! sees no transactions (reconnection is topology, not payload). Wiring the
//! chosen bridges into the reconnect path is the healing phase's job.
//! Deterministic selection — same discipline as [`super::pheromone`].

use std::collections::BTreeMap;

/// A candidate peer to bridge toward: identity, netgroup, and how long ago
/// it was last seen alive.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BridgeCandidate {
    pub id: String,
    pub netgroup: u16,
    /// Seconds since this peer was last confirmed reachable. Smaller is
    /// fresher / more likely still alive.
    pub last_seen_secs_ago: u32,
}

impl BridgeCandidate {
    pub fn new(id: impl Into<String>, netgroup: u16, last_seen_secs_ago: u32) -> Self {
        Self { id: id.into(), netgroup, last_seen_secs_ago }
    }
}

/// Choose up to `max_bridges` reconnection targets, maximising netgroup
/// diversity and, within a netgroup, preferring the freshest peer.
///
/// Strategy (deterministic): within each netgroup, order candidates by
/// `(last_seen_secs_ago, id)` — freshest first. Then round-robin across
/// netgroups so the first `max_bridges` span as many distinct groups as
/// possible before doubling up on any one. The result therefore covers
/// `min(max_bridges, distinct_netgroups)` groups, each represented by its
/// freshest peer first.
///
/// Boundaries: `max_bridges == 0` or empty input → empty; `max_bridges >=
/// candidates.len()` → all candidates, in diversity-then-freshness order.
pub fn select_bridges(candidates: &[BridgeCandidate], max_bridges: usize) -> Vec<BridgeCandidate> {
    if max_bridges == 0 || candidates.is_empty() {
        return Vec::new();
    }

    // Freshest-first, deterministic within a netgroup.
    let mut sorted = candidates.to_vec();
    sorted.sort_by(|a, b| {
        a.netgroup
            .cmp(&b.netgroup)
            .then_with(|| a.last_seen_secs_ago.cmp(&b.last_seen_secs_ago))
            .then_with(|| a.id.cmp(&b.id))
    });

    // Rank within netgroup (0 = freshest of that group).
    let mut rank_in_group: BTreeMap<u16, usize> = BTreeMap::new();
    let mut annotated: Vec<(usize, BridgeCandidate)> = Vec::with_capacity(sorted.len());
    for cand in sorted {
        let rank = rank_in_group.entry(cand.netgroup).or_insert(0);
        annotated.push((*rank, cand));
        *rank += 1;
    }

    // (rank, netgroup, freshness, id): all rank-0 first (one per netgroup),
    // then rank-1, etc. Taking the first `max_bridges` spreads across
    // netgroups before doubling up.
    annotated.sort_by(|a, b| {
        a.0.cmp(&b.0)
            .then_with(|| a.1.netgroup.cmp(&b.1.netgroup))
            .then_with(|| a.1.last_seen_secs_ago.cmp(&b.1.last_seen_secs_ago))
            .then_with(|| a.1.id.cmp(&b.1.id))
    });

    annotated.into_iter().take(max_bridges).map(|(_, c)| c).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn c(id: &str, ng: u16, age: u32) -> BridgeCandidate {
        BridgeCandidate::new(id, ng, age)
    }

    #[test]
    fn empty_or_zero_selects_nothing() {
        assert!(select_bridges(&[], 3).is_empty());
        assert!(select_bridges(&[c("a", 1, 5)], 0).is_empty());
    }

    #[test]
    fn spans_distinct_netgroups_first() {
        // Two candidates in group 1, one each in 2 and 3. Budget 3 must
        // touch all three netgroups, not two from group 1.
        let cands = [c("a1", 1, 5), c("a2", 1, 2), c("b", 2, 9), c("d", 3, 1)];
        let sel = select_bridges(&cands, 3);
        assert_eq!(sel.len(), 3);
        let groups: std::collections::BTreeSet<u16> = sel.iter().map(|x| x.netgroup).collect();
        assert_eq!(groups.len(), 3, "must bridge three distinct netgroups");
    }

    #[test]
    fn prefers_freshest_within_a_netgroup() {
        // Same netgroup: the freshest (smallest age) must be picked first.
        let cands = [c("stale", 7, 3_600), c("fresh", 7, 5), c("mid", 7, 300)];
        let sel = select_bridges(&cands, 1);
        assert_eq!(sel.len(), 1);
        assert_eq!(sel[0].id, "fresh", "freshest peer in the group wins");
    }

    #[test]
    fn caps_at_max_bridges() {
        let cands = [c("a", 1, 1), c("b", 2, 1), c("c", 3, 1), c("d", 4, 1)];
        assert_eq!(select_bridges(&cands, 2).len(), 2);
    }

    #[test]
    fn budget_exceeding_candidates_returns_all() {
        let cands = [c("a", 1, 1), c("b", 2, 1)];
        assert_eq!(select_bridges(&cands, 10).len(), 2);
    }

    #[test]
    fn diverse_group_covered_before_doubling_up() {
        // groups {1:[a(fresh),b(stale)], 2:[d]}. Budget 3 -> round1: a,d ;
        // round2: b. 'd' (only group-2) must precede the 2nd group-1 peer.
        let cands = [c("a", 1, 5), c("b", 1, 500), c("d", 2, 50)];
        let sel = select_bridges(&cands, 3);
        assert_eq!(sel.len(), 3);
        let d_pos = sel.iter().position(|x| x.id == "d").unwrap();
        let b_pos = sel.iter().position(|x| x.id == "b").unwrap();
        assert!(d_pos < b_pos, "diverse netgroup covered before a second same-group bridge");
    }

    #[test]
    fn selection_is_deterministic() {
        let cands = [c("z", 3, 10), c("a", 1, 10), c("m", 2, 10), c("b", 1, 5)];
        let first = select_bridges(&cands, 3);
        for _ in 0..20 {
            assert_eq!(select_bridges(&cands, 3), first, "must be stable across runs");
        }
        // group1 freshest is 'b' (age 5 < 10), then group2 'm', group3 'z'.
        assert_eq!(
            first.iter().map(|x| x.id.as_str()).collect::<Vec<_>>(),
            vec!["b", "m", "z"]
        );
    }
}
