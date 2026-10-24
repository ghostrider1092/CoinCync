//! CoinCync shielded-pool **circuit breaker** — the "watertight bulkhead" that
//! compartmentalizes the Spark shielded pool from the transparent chain.
//!
//! ## The idea, CoinCync-shaped
//!
//! A submarine seals a breached compartment so the rest of the hull stays dry
//! and moving. The CoinCync analogue: if a **pool-safety invariant** is ever
//! violated (inflation, a reused linking tag, a proof that shouldn't have
//! verified, a supply divergence — the exact failure classes that have bitten
//! real shielded pools like Zcash/Firo), the breaker can **isolate the shielded
//! pool** — stop accepting `TxType::Shielded` transactions — while the
//! **transparent chain keeps producing blocks unaffected**. Seal the hatch; keep
//! sailing.
//!
//! ## Why a connector (same discipline as the Rung-2 state-root connector)
//!
//! Auto-halting is consensus behaviour, and a node-local halt that peers don't
//! agree with would itself fork the chain. So this is a **pure, fail-closed
//! detection + policy slot**, not a patch to the locked validation path:
//!
//!   - It reaches into no chain state — it decides from a [`PoolObservation`] the
//!     caller already has, so it cannot perturb the tuned/locked consensus core
//!     (`validation.rs`, `consensus/mod.rs`, `constants.rs`).
//!   - **Default policy is [`Observe`](BreakerPolicy::Observe)** — detect + log,
//!     **never isolate**. Consensus-neutral.
//!   - **Isolation only ever scopes the shielded pool.** A trip rejects shielded
//!     txs; it is structurally incapable of rejecting a transparent tx — that is
//!     what makes it a *bulkhead* and not a kill switch.
//!   - Live, autonomous arming on the net is a **coordinated, activation-gated**
//!     decision (so all nodes agree and no fork results) — done elsewhere, not
//!     in this module.
//!
//! This complements the pool's existing guards (the `value_balance` inflation
//! guard, fail-closed verify, the `security` detail scan): those *detect*;
//! this packages the *isolation response*.

/// A pool-safety invariant violation. These mirror the shielded pool's "money
/// antibodies" (no inflation, pool non-negative, pool ≤ shielded-in) plus the
/// spend/proof/supply guards.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PoolFault {
    /// `pool_value < 0` — the pool went negative (accounting corruption).
    PoolNegative,
    /// `pool_value > total_shielded_in` — more value in the pool than ever
    /// entered it: the hard inflation ceiling was breached.
    InflationCeiling,
    /// `pool_value != Σ(−value_balance)` of accepted txs — the pool value and
    /// the transparent value-bridge disagree.
    BalanceMismatch,
    /// A shielded linking tag (nullifier) was observed twice — a double-spend.
    DoubleSpend,
    /// A shielded proof failed verification where the block was otherwise
    /// accepted — the crypto did not hold.
    ProofInvalid,
    /// The committed supply diverged from the reconstructed supply.
    SupplyDivergence,
}

/// What the node observed about the shielded pool for one block/epoch. All the
/// caller already computes; the breaker only reasons over it.
#[derive(Clone, Copy, Debug, Default)]
pub struct PoolObservation {
    /// Current shielded pool value (atomic units).
    pub pool_value: i128,
    /// Total value that has ever entered the pool (shield-in), the hard ceiling.
    pub total_shielded_in: i128,
    /// Σ(−value_balance) over accepted shielded txs — the value-bridge's view of
    /// what the pool value should be.
    pub expected_from_balance: i128,
    /// A linking tag was seen more than once on-chain.
    pub duplicate_linking_tag: bool,
    /// A shielded proof verification failed on an accepted block.
    pub proof_verify_failed: bool,
    /// Committed supply != reconstructed supply.
    pub supply_divergence: bool,
}

/// Collect every invariant violation in an observation (empty = healthy). Pure.
pub fn detect(o: &PoolObservation) -> Vec<PoolFault> {
    let mut f = Vec::new();
    if o.pool_value < 0 {
        f.push(PoolFault::PoolNegative);
    }
    if o.pool_value > o.total_shielded_in {
        f.push(PoolFault::InflationCeiling);
    }
    if o.pool_value != o.expected_from_balance {
        f.push(PoolFault::BalanceMismatch);
    }
    if o.duplicate_linking_tag {
        f.push(PoolFault::DoubleSpend);
    }
    if o.proof_verify_failed {
        f.push(PoolFault::ProofInvalid);
    }
    if o.supply_divergence {
        f.push(PoolFault::SupplyDivergence);
    }
    f
}

/// Breaker policy. **Default is [`Observe`](Self::Observe)** — consensus-neutral.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BreakerPolicy {
    /// Detect + log only; **never isolate**. The safe default for the live chain
    /// pre-activation.
    Observe,
    /// Isolate the shielded pool on any detected fault. Arming on the live net is
    /// a coordinated, activation-gated decision made outside this connector.
    Armed,
}

impl Default for BreakerPolicy {
    fn default() -> Self {
        BreakerPolicy::Observe
    }
}

/// The breaker's decision. By construction it can only ever gate the **shielded**
/// pool; the transparent chain is never in scope.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum BreakerAction {
    /// Shielded transactions continue (no fault, or Observe mode).
    AllowShielded,
    /// Seal the hatch: reject further shielded transactions. Transparent txs are
    /// unaffected. Carries the faults that tripped it.
    IsolateShielded { faults: Vec<PoolFault> },
}

impl BreakerAction {
    /// Whether shielded transactions must be rejected.
    pub fn rejects_shielded(&self) -> bool {
        matches!(self, BreakerAction::IsolateShielded { .. })
    }

    /// The bulkhead guarantee: a breaker action **never** rejects transparent
    /// transactions, regardless of outcome. Always false — stated explicitly so
    /// callers (and reviewers) can rely on the compartmentalization.
    pub fn rejects_transparent(&self) -> bool {
        false
    }
}

/// Evaluate the breaker: detect faults, then apply the policy. `Observe` always
/// allows (log the faults, keep sailing); `Armed` isolates the shielded pool iff
/// any fault is present. Fail-closed in the sense that any detected fault under
/// `Armed` trips the breaker — it never "allows through" a known violation.
pub fn evaluate(policy: BreakerPolicy, o: &PoolObservation) -> BreakerAction {
    let faults = detect(o);
    match policy {
        BreakerPolicy::Observe => BreakerAction::AllowShielded,
        BreakerPolicy::Armed if faults.is_empty() => BreakerAction::AllowShielded,
        BreakerPolicy::Armed => BreakerAction::IsolateShielded { faults },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A healthy pool: value equals the bridge's expectation and is within the
    /// shield-in ceiling.
    fn healthy() -> PoolObservation {
        PoolObservation {
            pool_value: 1_000,
            total_shielded_in: 1_000,
            expected_from_balance: 1_000,
            ..Default::default()
        }
    }

    #[test]
    fn default_policy_is_observe() {
        assert_eq!(BreakerPolicy::default(), BreakerPolicy::Observe);
    }

    #[test]
    fn healthy_pool_passes_in_both_modes() {
        assert!(detect(&healthy()).is_empty());
        assert_eq!(evaluate(BreakerPolicy::Observe, &healthy()), BreakerAction::AllowShielded);
        assert_eq!(evaluate(BreakerPolicy::Armed, &healthy()), BreakerAction::AllowShielded);
    }

    #[test]
    fn inflation_is_detected_but_observe_never_isolates() {
        let mut o = healthy();
        o.pool_value = 5_000; // > total_shielded_in (1000) AND != expected
        assert!(detect(&o).contains(&PoolFault::InflationCeiling));
        // Observe: logs the fault, keeps sailing (consensus-neutral).
        assert_eq!(evaluate(BreakerPolicy::Observe, &o), BreakerAction::AllowShielded);
    }

    #[test]
    fn armed_isolates_shielded_on_inflation_but_not_transparent() {
        let mut o = healthy();
        o.pool_value = 5_000;
        let a = evaluate(BreakerPolicy::Armed, &o);
        assert!(a.rejects_shielded(), "shielded must be sealed off");
        assert!(!a.rejects_transparent(), "transparent chain keeps running");
        if let BreakerAction::IsolateShielded { faults } = a {
            assert!(faults.contains(&PoolFault::InflationCeiling));
        } else {
            panic!("expected IsolateShielded");
        }
    }

    #[test]
    fn negative_pool_and_balance_mismatch_detected() {
        let mut o = healthy();
        o.pool_value = -1;
        let f = detect(&o);
        assert!(f.contains(&PoolFault::PoolNegative));
        assert!(f.contains(&PoolFault::BalanceMismatch)); // -1 != 1000
    }

    #[test]
    fn spend_proof_supply_faults_each_trip_armed() {
        let sets: [fn(&mut PoolObservation); 3] = [
            |o| o.duplicate_linking_tag = true,
            |o| o.proof_verify_failed = true,
            |o| o.supply_divergence = true,
        ];
        for set in sets {
            let mut o = healthy();
            set(&mut o);
            assert!(evaluate(BreakerPolicy::Armed, &o).rejects_shielded());
            assert!(!evaluate(BreakerPolicy::Observe, &o).rejects_shielded());
        }
    }

    #[test]
    fn multiple_faults_all_reported() {
        let mut o = healthy();
        o.pool_value = -5; // PoolNegative + BalanceMismatch
        o.duplicate_linking_tag = true; // DoubleSpend
        if let BreakerAction::IsolateShielded { faults } = evaluate(BreakerPolicy::Armed, &o) {
            assert!(faults.len() >= 3);
        } else {
            panic!("expected isolation with all faults");
        }
    }
}
