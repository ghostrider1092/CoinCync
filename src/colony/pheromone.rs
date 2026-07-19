//! Pheromone map for the colony forager (Ant Colony Optimization).
//!
//! A peer→score table. Foragers **deposit** pheromone on peers that relay
//! well; the map **evaporates** every round so stale-good peers decay and
//! the scores track *current* conditions. Highest-scored peers are the
//! forager's relay/connection recommendation.
//!
//! Deliberately **integer and deterministic** (fixed-point scores, ordered
//! map, tie-broken by key). This is non-consensus ops state, but integer
//! math keeps it free of float non-determinism and clippy cast noise, and
//! makes it trivially testable.

use std::collections::BTreeMap;

/// Maximum pheromone a peer can accumulate (fixed-point integer). Deposits
/// saturate here so one very-good peer can't run away unboundedly.
pub const SCORE_MAX: u32 = 10_000;

/// Evaporation factor applied every round: `score = score * 9 / 10` (keep
/// 90%). `SCORE_MAX * 9 = 90_000` fits in `u32`, so this never overflows.
const EVAP_NUM: u32 = 9;
const EVAP_DEN: u32 = 10;

/// Stable identity for a peer in the pheromone map — its fleet-config
/// `name`. Ordered so map iteration and ranking are deterministic.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct PeerKey(pub String);

/// The pheromone map: peer → current score.
#[derive(Clone, Debug, Default)]
pub struct PheromoneMap {
    scores: BTreeMap<PeerKey, u32>,
}

impl PheromoneMap {
    pub fn new() -> Self {
        Self::default()
    }

    /// Deposit `amount` pheromone on `peer`, saturating at [`SCORE_MAX`].
    pub fn deposit(&mut self, peer: PeerKey, amount: u32) {
        let e = self.scores.entry(peer).or_insert(0);
        *e = e.saturating_add(amount).min(SCORE_MAX);
    }

    /// Evaporate every score by the decay factor; drop entries that reach 0
    /// so an unreachable peer eventually falls out of the map entirely.
    pub fn evaporate(&mut self) {
        for v in self.scores.values_mut() {
            // score <= SCORE_MAX (10_000), so `* EVAP_NUM` <= 90_000 < u32::MAX.
            *v = *v * EVAP_NUM / EVAP_DEN;
        }
        self.scores.retain(|_, v| *v > 0);
    }

    /// Peers ranked by score, highest first. Deterministic: ties are broken
    /// by `PeerKey` order, so the ranking is stable across runs.
    pub fn ranked(&self) -> Vec<(PeerKey, u32)> {
        let mut v: Vec<(PeerKey, u32)> = self.scores.iter().map(|(k, s)| (k.clone(), *s)).collect();
        v.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
        v
    }

    /// Current score for a peer (0 if unknown).
    pub fn score(&self, peer: &PeerKey) -> u32 {
        self.scores.get(peer).copied().unwrap_or(0)
    }

    pub fn len(&self) -> usize {
        self.scores.len()
    }

    pub fn is_empty(&self) -> bool {
        self.scores.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn k(s: &str) -> PeerKey {
        PeerKey(s.to_string())
    }

    #[test]
    fn deposit_accumulates_and_saturates() {
        let mut m = PheromoneMap::new();
        m.deposit(k("a"), 100);
        m.deposit(k("a"), 250);
        assert_eq!(m.score(&k("a")), 350);
        // Saturates at SCORE_MAX no matter how much is deposited.
        m.deposit(k("a"), SCORE_MAX);
        assert_eq!(m.score(&k("a")), SCORE_MAX);
    }

    #[test]
    fn evaporate_decays_by_ten_percent() {
        let mut m = PheromoneMap::new();
        m.deposit(k("a"), 1000);
        m.evaporate();
        assert_eq!(m.score(&k("a")), 900); // 1000 * 9 / 10
        m.evaporate();
        assert_eq!(m.score(&k("a")), 810); // 900 * 9 / 10
    }

    #[test]
    fn evaporate_drops_peers_that_reach_zero() {
        let mut m = PheromoneMap::new();
        m.deposit(k("gone"), 5);
        // 5 -> 4 -> 3 -> 2 -> 1 -> 0 ; once 0 the entry is removed.
        for _ in 0..8 {
            m.evaporate();
        }
        assert!(
            m.is_empty(),
            "a decayed-to-zero peer must fall out of the map"
        );
    }

    #[test]
    fn ranked_is_score_descending_then_key_stable() {
        let mut m = PheromoneMap::new();
        m.deposit(k("low"), 100);
        m.deposit(k("high"), 900);
        m.deposit(k("mid_b"), 500);
        m.deposit(k("mid_a"), 500); // tie with mid_b
        let r = m.ranked();
        assert_eq!(r[0].0, k("high"));
        // Tie broken by key order: mid_a before mid_b.
        assert_eq!(r[1], (k("mid_a"), 500));
        assert_eq!(r[2], (k("mid_b"), 500));
        assert_eq!(r[3].0, k("low"));
    }

    #[test]
    fn evaporate_does_not_overflow_at_max() {
        let mut m = PheromoneMap::new();
        m.deposit(k("a"), SCORE_MAX);
        m.evaporate(); // SCORE_MAX * 9 = 90_000, well within u32
        assert_eq!(m.score(&k("a")), SCORE_MAX * 9 / 10);
    }
}
