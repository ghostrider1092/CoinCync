//! Supply-integrity security detail — the chain's **inflation** surface, the
//! deepest value invariant. Snapshot-based (constructed from the current
//! `total_supply` / `total_burned`, so it never borrows chain internals) and
//! read-only.
//!
//! The guard is chosen to be **sound with zero false-positive risk**, because a
//! consensus-critical guard that can misfire is itself a DoS:
//! - **Guard (consensus-critical):** `total_burned ≤ total_supply`. You cannot
//!   burn more value than was ever emitted; a violation is accounting
//!   corruption / inflation of the burn counter. Always true honestly → safe to
//!   halt on.
//! - **Scan (operational):** `total_supply > MAX_SUPPLY`. Flagged as a
//!   *warning*, not a halt — tail emission could legitimately approach the cap,
//!   and a false halt must never wedge the chain; the operator reviews it.
//! - **Reconciliation (operational, Critical):** `total_supply ==
//!   cumulative_emission(tip)`. The chain maintains `total_supply` as the
//!   running inclusive sum of the per-block reward; this independently recomputes
//!   that sum from the deterministic schedule and flags any divergence. It closes
//!   the threat-model's named "*exact adherence to the emission schedule / no
//!   cheap cumulative-emission function exists*" gap by making the previously
//!   test-only supply-conservation invariant a live, auditor-verifiable check. It
//!   is **operational, never a halt**: the recompute is O(tip) (off the hot path,
//!   not per-block-cheap) and shares the `base_reward` primitive with the counter
//!   it checks, so — conservatively — it pages rather than wedges. Promoting it to
//!   a consensus halt would take an O(1) independently-maintained accumulator
//!   (see the module's follow-up note). It does NOT catch crypto inflation at the
//!   scheduled coin count — that remains the external audit's job.

use crate::security::{SecurityDetail, SecurityReport, Severity};

/// Pure supply invariants (testable in isolation). Returns
/// `(consensus_violation, operational_warning)`.
#[allow(clippy::type_complexity)]
pub fn supply_violations(
    total_supply: u128,
    total_burned: u128,
) -> (Option<(&'static str, String)>, Option<(&'static str, String)>) {
    let consensus = if total_burned > total_supply {
        Some((
            "burned-exceeds-supply",
            format!(
                "total_burned {total_burned} exceeds total_supply {total_supply} — \
                 accounting corruption / burn inflation"
            ),
        ))
    } else {
        None
    };
    let operational = if total_supply > crate::constants::MAX_SUPPLY {
        Some((
            "supply-over-cap",
            format!(
                "total_supply {total_supply} exceeds MAX_SUPPLY {} — review emission",
                crate::constants::MAX_SUPPLY
            ),
        ))
    } else {
        None
    };
    (consensus, operational)
}

/// Independent supply-schedule reconciliation. Returns `Some((code, msg))`
/// when the recorded gross `total_supply` diverges from the deterministic
/// emission schedule recomputed at `tip_height` — i.e. accounting drift in
/// the incremental `+=` / `-=` bookkeeping across connects, disconnects,
/// reorgs, or restart replay. `None` when they agree.
///
/// This is exact (no estimator tolerance): the chain maintains
/// `total_supply` as exactly `Σ_{h=0}^{tip} calculate_block_reward(h)`, so an
/// honest chain reconciles bit-for-bit. See
/// [`crate::emission::supply::cumulative_emission`] for the recompute and its
/// limits (it does not catch crypto inflation at the scheduled coin count).
pub fn supply_reconciliation(
    total_supply: u128,
    tip_height: u64,
) -> Option<(&'static str, String)> {
    let expected = crate::emission::supply::cumulative_emission(tip_height);
    if total_supply != expected {
        Some((
            "supply-schedule-mismatch",
            format!(
                "total_supply {total_supply} != Σ reward(0..={tip_height}) {expected} \
                 (diff {}) — accounting drift from the emission schedule",
                total_supply.abs_diff(expected)
            ),
        ))
    } else {
        None
    }
}

/// A [`SecurityDetail`] over the chain's monetary supply, built from a snapshot.
///
/// `tip_height` is optional: when present, the sweep additionally runs the
/// [`supply_reconciliation`] check against the deterministic schedule. Callers
/// that only have the supply counters (no tip) construct with [`Self::new`] and
/// get the burn / over-cap checks only.
pub struct SupplySecurityDetail {
    total_supply: u128,
    total_burned: u128,
    tip_height: Option<u64>,
}

impl SupplySecurityDetail {
    /// Snapshot with the burn-inflation guard + over-cap warning only.
    pub fn new(total_supply: u128, total_burned: u128) -> Self {
        Self { total_supply, total_burned, tip_height: None }
    }

    /// Snapshot that also reconciles `total_supply` against the emission
    /// schedule recomputed at `tip_height`.
    pub fn with_tip(total_supply: u128, total_burned: u128, tip_height: u64) -> Self {
        Self { total_supply, total_burned, tip_height: Some(tip_height) }
    }
}

impl SecurityDetail for SupplySecurityDetail {
    fn label(&self) -> &'static str {
        "supply"
    }

    fn sweep(&self) -> SecurityReport {
        let mut r = SecurityReport::clean();
        let (consensus, operational) = supply_violations(self.total_supply, self.total_burned);
        if let Some((code, msg)) = consensus {
            r.raise_consensus("supply", Severity::Critical, code, msg);
        }
        if let Some((code, msg)) = operational {
            r.raise_operational("supply", Severity::Warning, code, msg);
        }
        // Schedule reconciliation — operational (Critical severity), never a
        // halt: the recompute is O(tip) and defense-in-depth over per-tx
        // validation, so a mismatch pages loudly rather than wedging the chain.
        if let Some(tip) = self.tip_height {
            if let Some((code, msg)) = supply_reconciliation(self.total_supply, tip) {
                r.raise_operational("supply", Severity::Critical, code, msg);
            }
        }
        r
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn supply_invariant_burn_cannot_exceed_supply() {
        // Honest: burned <= supply → no consensus violation.
        let (c, _) = supply_violations(1_000, 400);
        assert!(c.is_none());
        // Corruption: burned > supply → consensus violation.
        let (c, _) = supply_violations(400, 1_000);
        assert!(c.is_some());
    }

    #[test]
    fn over_cap_is_operational_never_a_halt() {
        use crate::security::Disposition;
        let over = crate::constants::MAX_SUPPLY + 1;
        let report = SupplySecurityDetail::new(over, 0).sweep();
        // Visible, but only a warning — never a consensus halt (tail emission
        // could legitimately near the cap; a false halt must not wedge the chain).
        assert!(report.has_critical() == false);
        assert!(report.alerts.iter().any(|a| a.code == "supply-over-cap"));
        assert_ne!(report.disposition(), Disposition::Halt);
    }

    #[test]
    fn healthy_supply_is_clean() {
        assert!(SupplySecurityDetail::new(crate::constants::MAX_SUPPLY / 2, 100).sweep().is_clean());
    }

    #[test]
    fn reconciliation_passes_on_the_honest_schedule() {
        // An honest total_supply is exactly the recomputed schedule sum.
        let tip = 3_000u64;
        let honest = crate::emission::supply::cumulative_emission(tip);
        assert!(
            supply_reconciliation(honest, tip).is_none(),
            "honest total_supply must reconcile against the schedule"
        );
    }

    #[test]
    fn reconciliation_flags_over_and_under_emission() {
        let tip = 3_000u64;
        let honest = crate::emission::supply::cumulative_emission(tip);
        // A single extra atomic unit (inflation) is caught.
        assert!(
            supply_reconciliation(honest + 1, tip).is_some(),
            "over-emission by 1 atomic unit must be flagged"
        );
        // A missing unit (lost/under-counted supply) is caught too.
        assert!(
            supply_reconciliation(honest - 1, tip).is_some(),
            "under-emission by 1 atomic unit must be flagged"
        );
    }

    #[test]
    fn schedule_mismatch_pages_but_never_halts() {
        use crate::security::Disposition;
        let tip = 1_500u64;
        let honest = crate::emission::supply::cumulative_emission(tip);

        // Honest chain with a tip: reconciliation is clean.
        assert!(
            SupplySecurityDetail::with_tip(honest, 0, tip).sweep().is_clean(),
            "honest chain must sweep clean including the reconciliation"
        );

        // Inflated supply: surfaced as a Critical operational alert, but the
        // disposition must not be a consensus halt (a false wedge is worse).
        let report = SupplySecurityDetail::with_tip(honest + 1_000, 0, tip).sweep();
        assert!(
            report.alerts.iter().any(|a| a.code == "supply-schedule-mismatch"),
            "inflated supply must raise the schedule-mismatch alert"
        );
        // It IS Critical severity (page now), but it is class Operational, so it
        // must never be a consensus halt and its disposition is not Halt.
        assert!(
            !report.has_consensus_halt(),
            "reconciliation is operational — must never be a consensus halt"
        );
        assert_ne!(report.disposition(), Disposition::Halt);
    }

    #[test]
    fn new_without_tip_skips_reconciliation() {
        // Callers that only hold the counters (no tip) get burn / over-cap
        // checks only — an arbitrary supply must not trip the schedule check.
        let report = SupplySecurityDetail::new(12_345, 0).sweep();
        assert!(
            !report.alerts.iter().any(|a| a.code == "supply-schedule-mismatch"),
            "no tip => no schedule reconciliation"
        );
    }
}
