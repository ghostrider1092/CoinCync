//! Node-internal inbound block-relay scoring (ACO, un-poisonable).
//!
//! The node credits an inbound peer when it delivers a valid block, and the
//! score **evaporates** each maintenance round so it tracks *current* relay
//! usefulness. See `docs/architecture/inbound-relay-eviction.md`.
//!
//! This is the node-internal, inbound counterpart to the sidecar colony
//! forager (which scores outbound/fleet peers over RPC). Because the node
//! measures relay itself, the score **cannot be poisoned** by anything
//! external — a peer must *actually relay blocks* to earn it.
//!
//! **Prime Invariant:** the only input is block delivery (public data). No
//! transaction is observed. Crediting is called from the block-receive path
//! only; there is no code path from a transaction to a relay-score deposit.
//!
//! Phase 1 (this module + its wiring): **measure only** — the score is
//! tracked and exposed; it does **not** yet affect eviction. Phase 2 feeds
//! it into `eviction.rs` as a bounded, eclipse-safe protection axis.

use std::collections::BTreeMap;

use super::peer::PeerId;

/// Score cap per peer (fixed-point integer); deposits saturate here.
pub const RELAY_SCORE_MAX: u32 = 10_000;

/// Credit for delivering one valid block.
const DEPOSIT_PER_BLOCK: u32 = 1_000;

/// Evaporation each round: `score = score * 9 / 10` (keep 90%).
/// `RELAY_SCORE_MAX * 9 = 90_000` fits in `u32`.
const EVAP_NUM: u32 = 9;
const EVAP_DEN: u32 = 10;

/// Per-inbound-peer block-relay scores. Ordered by `PeerId` for
/// deterministic iteration/ranking.
#[derive(Clone, Debug, Default)]
pub struct RelayScoreMap {
    scores: BTreeMap<PeerId, u32>,
}

impl RelayScoreMap {
    pub fn new() -> Self {
        Self::default()
    }

    /// Credit `peer` for delivering a valid block (saturating at cap).
    /// Called from the block-receive path only — never from any tx path.
    pub fn credit_block(&mut self, peer: PeerId) {
        let e = self.scores.entry(peer).or_insert(0);
        *e = e.saturating_add(DEPOSIT_PER_BLOCK).min(RELAY_SCORE_MAX);
    }

    /// Evaporate all scores; drop peers that reach 0 so a peer that stops
    /// relaying (or disconnects) falls out of the map.
    pub fn evaporate(&mut self) {
        for v in self.scores.values_mut() {
            *v = *v * EVAP_NUM / EVAP_DEN;
        }
        self.scores.retain(|_, v| *v > 0);
    }

    /// Drop a peer's score outright (e.g. on disconnect).
    pub fn forget(&mut self, peer: &PeerId) {
        self.scores.remove(peer);
    }

    /// Current score for a peer (0 if unknown).
    pub fn score(&self, peer: &PeerId) -> u32 {
        self.scores.get(peer).copied().unwrap_or(0)
    }

    /// The top `n` peers by relay score, highest first. Deterministic: ties
    /// broken by `PeerId`. Phase 2's eviction axis will protect this set.
    pub fn top(&self, n: usize) -> Vec<PeerId> {
        let mut v: Vec<(PeerId, u32)> = self.scores.iter().map(|(k, s)| (*k, *s)).collect();
        v.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
        v.into_iter().take(n).map(|(k, _)| k).collect()
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

    fn pid(b: u8) -> PeerId {
        let mut id = [0u8; 32];
        id[0] = b;
        id
    }

    #[test]
    fn credit_accumulates_and_saturates() {
        let mut m = RelayScoreMap::new();
        m.credit_block(pid(1));
        m.credit_block(pid(1));
        assert_eq!(m.score(&pid(1)), 2 * DEPOSIT_PER_BLOCK);
        for _ in 0..20 {
            m.credit_block(pid(1));
        }
        assert_eq!(m.score(&pid(1)), RELAY_SCORE_MAX, "saturates at cap");
    }

    #[test]
    fn evaporate_decays_and_drops_zero() {
        let mut m = RelayScoreMap::new();
        m.credit_block(pid(1)); // 1000
        m.evaporate();
        assert_eq!(m.score(&pid(1)), 900);
        // A peer that stops relaying eventually falls out entirely.
        for _ in 0..200 {
            m.evaporate();
        }
        assert!(m.is_empty());
    }

    #[test]
    fn top_is_score_descending_then_stable_by_id() {
        let mut m = RelayScoreMap::new();
        m.credit_block(pid(3)); // 1000
        m.credit_block(pid(1));
        m.credit_block(pid(1)); // 2000 — highest
        m.credit_block(pid(2)); // 1000, ties pid(3)
        let top = m.top(2);
        assert_eq!(top[0], pid(1), "highest score first");
        // pid(2) and pid(3) tie at 1000; id order breaks the tie -> pid(2).
        assert_eq!(top[1], pid(2));
    }

    #[test]
    fn forget_removes_a_peer() {
        let mut m = RelayScoreMap::new();
        m.credit_block(pid(1));
        m.forget(&pid(1));
        assert_eq!(m.score(&pid(1)), 0);
        assert!(m.is_empty());
    }

    #[test]
    fn evaporate_does_not_overflow_at_max() {
        let mut m = RelayScoreMap::new();
        for _ in 0..20 {
            m.credit_block(pid(1));
        }
        assert_eq!(m.score(&pid(1)), RELAY_SCORE_MAX);
        m.evaporate(); // 10_000 * 9 = 90_000, within u32
        assert_eq!(m.score(&pid(1)), RELAY_SCORE_MAX * 9 / 10);
    }
}
