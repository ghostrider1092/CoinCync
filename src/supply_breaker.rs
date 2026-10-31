//! CoinCync supply / emission **circuit breaker** — the monetary bulkhead.
//!
//! Where the shielded breaker seals one *compartment* of the chain, a supply
//! fault is **block-fatal**: a block that mints more than it may, or that breaks
//! the supply identity, is simply invalid and must be rejected. So this breaker's
//! isolation scope is "reject the offending block." It is the explicit,
//! fail-closed, *tested* guard against the single worst failure for anything that
//! handles money — **silent inflation**.
//!
//! Same connector discipline as [`crate::shielded_circuit_breaker`] and the
//! Rung-2 state-root connector: a pure detect+decide policy slot that reaches
//! into no chain state (so it can't perturb the hash-locked consensus core),
//! declared from `lib.rs`, feature-gated, **default policy `Observe`** (detect +
//! log, never reject), wired into nothing until a coordinated post-audit
//! activation. See `docs/design/cip-circuit-breakers.md`.
//!
//! Invariants enforced (CoinCync monetary rules):
//!   - a coinbase may pay out **at most** the scheduled base emission + the
//!     block's fees (no over-mint),
//!   - the supply identity **`circulating == total_emitted − total_burned`**
//!     holds,
//!   - circulating is non-negative and never exceeds the cap,
//!   - any committed supply value matches the reconstructed circulating supply.

/// A monetary-safety invariant violation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SupplyFault {
    /// Coinbase paid out more than `allowed_emission + block_fees` — a miner
    /// minted coins it was not owed. The canonical inflation bug.
    OverEmission,
    /// `total_emitted − total_burned != circulating` — the supply identity broke.
    CirculatingMismatch,
    /// Circulating supply went negative (accounting corruption).
    NegativeSupply,
    /// Circulating supply exceeded the hard cap / scheduled ceiling.
    SupplyCeilingExceeded,
    /// A committed supply value disagrees with the reconstructed circulating
    /// supply (e.g. the Rung-2 / header supply commitment).
    CommittedSupplyMismatch,
}

/// What the node observed about supply for one block. All already computed by
/// the caller; the breaker only reasons over it. Signed (`i128`) so underflows
/// surface as negatives rather than wrapping.
#[derive(Clone, Copy, Debug, Default)]
pub struct SupplyObservation {
    /// Total value paid out by this block's coinbase outputs.
    pub coinbase_payout: i128,
    /// The scheduled base emission (block reward) at this height.
    pub allowed_emission: i128,
    /// Fees available to the coinbase for this block.
    pub block_fees: i128,
    /// Cumulative emitted supply (base emission only, per the schedule).
    pub total_emitted: i128,
    /// Cumulative burned supply.
    pub total_burned: i128,
    /// The claimed circulating supply.
    pub circulating: i128,
    /// Hard cap / scheduled supply ceiling at this height.
    pub max_supply: i128,
    /// A committed supply value, if the block carries one. `None` is not itself
    /// a fault here (the state-root/supply commitment connector owns presence).
    pub committed_supply: Option<i128>,
}

/// Collect every monetary invariant violation (empty = healthy). Pure.
pub fn detect(o: &SupplyObservation) -> Vec<SupplyFault> {
    let mut f = Vec::new();
    if o.coinbase_payout > o.allowed_emission.saturating_add(o.block_fees) {
        f.push(SupplyFault::OverEmission);
    }
    if o.total_emitted - o.total_burned != o.circulating {
        f.push(SupplyFault::CirculatingMismatch);
    }
    if o.circulating < 0 {
        f.push(SupplyFault::NegativeSupply);
    }
    if o.circulating > o.max_supply {
        f.push(SupplyFault::SupplyCeilingExceeded);
    }
    if let Some(c) = o.committed_supply {
        if c != o.circulating {
            f.push(SupplyFault::CommittedSupplyMismatch);
        }
    }
    f
}

/// Breaker policy. **Default `Observe`** — detect + log, never reject.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BreakerPolicy {
    /// Detect + log only; never reject. Safe default for the live chain.
    Observe,
    /// Reject the block on any detected monetary fault. Live arming is a
    /// coordinated, activation-gated decision made outside this connector.
    Armed,
}

impl Default for BreakerPolicy {
    fn default() -> Self {
        BreakerPolicy::Observe
    }
}

/// The breaker's decision. A supply fault is block-fatal, so the isolation scope
/// is the block itself.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum BreakerAction {
    /// The block's supply accounting is sound (or Observe mode).
    AllowBlock,
    /// Reject the block — its coinbase/supply broke a monetary invariant.
    RejectBlock { faults: Vec<SupplyFault> },
}

impl BreakerAction {
    /// Whether the block must be rejected.
    pub fn rejects_block(&self) -> bool {
        matches!(self, BreakerAction::RejectBlock { .. })
    }
}

/// Evaluate: detect faults, then apply policy. `Observe` always allows (logs);
/// `Armed` rejects the block iff any fault is present. Fail-closed: a detected
/// over-emission under `Armed` always rejects — inflation is never let through.
pub fn evaluate(policy: BreakerPolicy, o: &SupplyObservation) -> BreakerAction {
    let faults = detect(o);
    match policy {
        BreakerPolicy::Observe => BreakerAction::AllowBlock,
        BreakerPolicy::Armed if faults.is_empty() => BreakerAction::AllowBlock,
        BreakerPolicy::Armed => BreakerAction::RejectBlock { faults },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A sound block: coinbase ≤ emission+fees, identity holds, within cap.
    fn healthy() -> SupplyObservation {
        SupplyObservation {
            coinbase_payout: 50 + 2, // emission + fees
            allowed_emission: 50,
            block_fees: 2,
            total_emitted: 1_000,
            total_burned: 100,
            circulating: 900, // 1000 - 100
            max_supply: 21_000_000,
            committed_supply: Some(900),
        }
    }

    #[test]
    fn default_policy_is_observe() {
        assert_eq!(BreakerPolicy::default(), BreakerPolicy::Observe);
    }

    #[test]
    fn healthy_block_passes_both_modes() {
        assert!(detect(&healthy()).is_empty());
        assert_eq!(evaluate(BreakerPolicy::Observe, &healthy()), BreakerAction::AllowBlock);
        assert_eq!(evaluate(BreakerPolicy::Armed, &healthy()), BreakerAction::AllowBlock);
    }

    #[test]
    fn over_emission_is_the_headline_catch() {
        let mut o = healthy();
        o.coinbase_payout = 100; // > 50 + 2
        assert!(detect(&o).contains(&SupplyFault::OverEmission));
        // Observe logs but keeps sailing (consensus-neutral default).
        assert_eq!(evaluate(BreakerPolicy::Observe, &o), BreakerAction::AllowBlock);
        // Armed rejects the inflationary block.
        assert!(evaluate(BreakerPolicy::Armed, &o).rejects_block());
    }

    #[test]
    fn coinbase_may_claim_exactly_emission_plus_fees() {
        let mut o = healthy();
        o.coinbase_payout = o.allowed_emission + o.block_fees; // boundary: allowed
        assert!(!detect(&o).contains(&SupplyFault::OverEmission));
    }

    #[test]
    fn circulating_identity_and_cap_and_negative() {
        let mut o = healthy();
        o.circulating = 901; // != 1000 - 100
        assert!(detect(&o).contains(&SupplyFault::CirculatingMismatch));

        let mut o2 = healthy();
        o2.total_emitted = 0;
        o2.total_burned = 1;
        o2.circulating = -1;
        let f = detect(&o2);
        assert!(f.contains(&SupplyFault::NegativeSupply));

        let mut o3 = healthy();
        o3.total_emitted = o3.max_supply + 100;
        o3.total_burned = 0;
        o3.circulating = o3.max_supply + 100;
        assert!(detect(&o3).contains(&SupplyFault::SupplyCeilingExceeded));
    }

    #[test]
    fn committed_supply_mismatch_detected() {
        let mut o = healthy();
        o.committed_supply = Some(12345); // != circulating 900
        assert!(detect(&o).contains(&SupplyFault::CommittedSupplyMismatch));
        assert!(evaluate(BreakerPolicy::Armed, &o).rejects_block());
    }

    #[test]
    fn multiple_faults_all_reported() {
        let mut o = healthy();
        o.coinbase_payout = 10_000; // OverEmission
        o.circulating = -5; // NegativeSupply + CirculatingMismatch
        if let BreakerAction::RejectBlock { faults } = evaluate(BreakerPolicy::Armed, &o) {
            assert!(faults.contains(&SupplyFault::OverEmission));
            assert!(faults.contains(&SupplyFault::NegativeSupply));
            assert!(faults.len() >= 3);
        } else {
            panic!("expected RejectBlock");
        }
    }
}
