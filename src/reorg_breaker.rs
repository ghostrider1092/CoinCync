//! CoinCync reorg / finality **circuit breaker** — the chain-history bulkhead.
//!
//! Defends against history-rewrite attacks and chain instability by **refusing a
//! dangerous reorg** — keeping the current tip rather than switching to an
//! attacking fork. The failure it guards is the worst one a PoW chain faces: a
//! deep reorg that double-spends confirmed money.
//!
//! Faults it isolates:
//!   - **deep reorg** — the switch would disconnect more blocks than the safe
//!     (soft-finality) window allows,
//!   - **below finalized** — the fork point is at/under the soft-finalized
//!     height (the CIP-011 rolling-finality rule),
//!   - **reorg churn** — too many reorgs in a short window (instability / grind),
//!   - **work anomaly** — the competing chain's work jumped implausibly (a sudden
//!     hashpower spike, the signature of a rented-51% attack).
//!
//! ## Consensus, not node-local
//!
//! Unlike the mempool / P2P breakers, **reorg acceptance IS consensus** — a
//! node-local refusal that peers don't share would fork the chain. So this
//! breaker's live arming is a **coordinated, activation-gated** decision (it
//! aligns with CIP-011 rolling finality), the same discipline as the shielded
//! and supply breakers. Built the same way: pure, fail-closed, feature-gated,
//! declared from `lib.rs` (not the hash-locked consensus core), default policy
//! `Observe`. See `docs/design/cip-circuit-breakers.md`.

/// A reorg / finality safety breach.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReorgFault {
    /// The reorg would disconnect more blocks than the safe window permits.
    DeepReorg,
    /// The fork point is at or below the soft-finalized height (CIP-011).
    BelowFinalized,
    /// Too many reorgs within the observation window — instability / grinding.
    ReorgChurn,
    /// The competing chain's cumulative-work ratio jumped implausibly high.
    WorkAnomaly,
}

/// What the node observed about a candidate reorg.
#[derive(Clone, Copy, Debug, Default)]
pub struct ReorgObservation {
    /// How many blocks the switch would disconnect, and the safe ceiling.
    pub reorg_depth: u64,
    pub max_safe_depth: u64,
    /// The fork-point height and the current soft-finalized height.
    pub fork_point_height: u64,
    pub finalized_height: u64,
    /// Reorgs seen in the observation window, and the churn ceiling.
    pub reorgs_in_window: u32,
    pub max_reorgs_in_window: u32,
    /// Competing-chain work as a percentage of the current chain's work
    /// (e.g. 400 = 4x), and the implausible-jump ceiling.
    pub incoming_work_ratio_pct: u32,
    pub max_work_ratio_pct: u32,
}

/// Collect every reorg-safety breach (empty = the reorg is safe to accept). Pure.
pub fn detect(o: &ReorgObservation) -> Vec<ReorgFault> {
    let mut f = Vec::new();
    if o.reorg_depth > o.max_safe_depth {
        f.push(ReorgFault::DeepReorg);
    }
    if o.fork_point_height <= o.finalized_height {
        f.push(ReorgFault::BelowFinalized);
    }
    if o.reorgs_in_window > o.max_reorgs_in_window {
        f.push(ReorgFault::ReorgChurn);
    }
    if o.incoming_work_ratio_pct > o.max_work_ratio_pct {
        f.push(ReorgFault::WorkAnomaly);
    }
    f
}

/// Breaker policy. **Default `Observe`** — detect + log, never refuse.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BreakerPolicy {
    /// Detect + log only; never refuse a reorg. Default.
    Observe,
    /// Refuse a dangerous reorg on any breach. CONSENSUS — live arming must be
    /// coordinated + activation-gated across nodes (see module docs).
    Armed,
}

impl Default for BreakerPolicy {
    fn default() -> Self {
        BreakerPolicy::Observe
    }
}

/// The breaker's decision over a candidate reorg.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum BreakerAction {
    /// The reorg is safe; accept the chain switch.
    AcceptReorg,
    /// Refuse the reorg — keep the current tip. Carries the triggering faults.
    RejectReorg { faults: Vec<ReorgFault> },
}

impl BreakerAction {
    /// Whether the candidate reorg must be refused.
    pub fn rejects_reorg(&self) -> bool {
        matches!(self, BreakerAction::RejectReorg { .. })
    }
}

/// Evaluate: detect breaches, then apply policy. `Observe` always accepts (logs);
/// `Armed` refuses the reorg iff any breach is present. Fail-closed: a detected
/// deep / below-finalized reorg under `Armed` is always refused.
pub fn evaluate(policy: BreakerPolicy, o: &ReorgObservation) -> BreakerAction {
    let faults = detect(o);
    match policy {
        BreakerPolicy::Observe => BreakerAction::AcceptReorg,
        BreakerPolicy::Armed if faults.is_empty() => BreakerAction::AcceptReorg,
        BreakerPolicy::Armed => BreakerAction::RejectReorg { faults },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A shallow, honest reorg above finality with normal work.
    fn healthy() -> ReorgObservation {
        ReorgObservation {
            reorg_depth: 2,
            max_safe_depth: 100,
            fork_point_height: 10_000,
            finalized_height: 9_800, // fork is well above finality
            reorgs_in_window: 1,
            max_reorgs_in_window: 10,
            incoming_work_ratio_pct: 101, // ~even work
            max_work_ratio_pct: 300,
        }
    }

    #[test]
    fn default_policy_is_observe() {
        assert_eq!(BreakerPolicy::default(), BreakerPolicy::Observe);
    }

    #[test]
    fn shallow_honest_reorg_is_accepted_both_modes() {
        assert!(detect(&healthy()).is_empty());
        assert_eq!(evaluate(BreakerPolicy::Observe, &healthy()), BreakerAction::AcceptReorg);
        assert_eq!(evaluate(BreakerPolicy::Armed, &healthy()), BreakerAction::AcceptReorg);
    }

    #[test]
    fn deep_reorg_is_refused_when_armed() {
        let mut o = healthy();
        o.reorg_depth = 500; // > 100
        assert!(detect(&o).contains(&ReorgFault::DeepReorg));
        // Observe logs only.
        assert!(!evaluate(BreakerPolicy::Observe, &o).rejects_reorg());
        // Armed refuses the history rewrite.
        assert!(evaluate(BreakerPolicy::Armed, &o).rejects_reorg());
    }

    #[test]
    fn reorg_below_finality_is_refused() {
        let mut o = healthy();
        o.fork_point_height = 9_700; // <= finalized 9_800
        assert!(detect(&o).contains(&ReorgFault::BelowFinalized));
        assert!(evaluate(BreakerPolicy::Armed, &o).rejects_reorg());
    }

    #[test]
    fn churn_and_work_anomaly_detected() {
        let mut o = healthy();
        o.reorgs_in_window = 50; // > 10
        assert!(detect(&o).contains(&ReorgFault::ReorgChurn));

        let mut o2 = healthy();
        o2.incoming_work_ratio_pct = 5_000; // 50x sudden jump
        assert!(detect(&o2).contains(&ReorgFault::WorkAnomaly));
    }

    #[test]
    fn multiple_breaches_all_reported() {
        let mut o = healthy();
        o.reorg_depth = 10_000;
        o.fork_point_height = 1; // below finality
        o.incoming_work_ratio_pct = 9_999;
        if let BreakerAction::RejectReorg { faults } = evaluate(BreakerPolicy::Armed, &o) {
            assert!(faults.len() >= 3);
        } else {
            panic!("expected RejectReorg");
        }
    }
}
