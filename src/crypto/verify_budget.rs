//! # Heavy-verify DoS budget (Warren Phase 0 — §3.8 DoS bounds)
//!
//! The [`Sluice`](crate::crypto::heavy_verify::Sluice) bounds how WIDE
//! verification fans out. This bounds how much heavy-verify WORK a single block
//! may impose in the first place. Without it, the valve is a faster way to do an
//! unbounded amount of work — an attacker fills a block with maximally
//! expensive privacy txs (huge rings, many range proofs, large Spend bundles)
//! and every node burns the whole pool on one block. The two together give the
//! guarantee that matters: bounded work, done on a bounded pool, off the mining
//! cores.
//!
//! ## Model
//! Everything is priced in abstract **verify units** — roughly one
//! variable-base scalar multiplication, the dominant cost across CLSAG rings,
//! Bulletproof range proofs, and Spark one-of-many proofs. A block's total must
//! stay under [`MAX_BLOCK_VERIFY_WEIGHT`]; a tx over [`MAX_TX_VERIFY_WEIGHT`] is
//! rejected on its own so one tx can't monopolise the budget.
//!
//! ## Status / safety
//! Phase-0 **sketch**, non-gated (pure arithmetic, no backend) and NOT wired
//! into validation — current relay/consensus fee and size rules are unchanged
//! (the live relay floor stays `size × MIN_FEE_PER_BYTE`; see the shielded-arc
//! notes). The constants here are provisional and MUST be calibrated against
//! real verify benchmarks before any activation. Takes primitive counts, not a
//! `Transaction`, so the eventual wiring is a thin extractor and this core stays
//! trivially testable and backend-free. Fail-closed: an arithmetic overflow in
//! weight accumulation is treated as "over budget", never as "free".

/// Abstract verification cost, in "verify units" (~one variable-base scalar
/// multiplication). Newtype so weights can't be silently confused with bytes or
/// atomic amounts.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Default)]
pub struct VerifyWeight(pub u64);

impl VerifyWeight {
    pub const ZERO: VerifyWeight = VerifyWeight(0);

    /// Saturating add — overflow pins at `u64::MAX`, which is always over any
    /// finite budget, so an overflow can never read as "cheap".
    #[must_use]
    pub fn saturating_add(self, other: VerifyWeight) -> VerifyWeight {
        VerifyWeight(self.0.saturating_add(other.0))
    }

    #[must_use]
    pub fn get(self) -> u64 {
        self.0
    }
}

// ── Provisional unit costs (TODO: calibrate from `benches/`) ────────────────
/// One CLSAG ring member (one scalar-mult + hash in the ring loop).
pub const COST_PER_RING_MEMBER: u64 = 1;
/// One Bulletproof(+) range-proofed output. A 64-bit single-output proof is
/// ~128 scalar-mults; batching amortises, so this is the per-output marginal.
pub const COST_PER_RANGE_OUTPUT: u64 = 128;
/// Per-byte cost of a Spark Spend bundle (one-of-many proof over the cover set).
/// Dominated by the anon-set size the bundle commits to; priced by size as a
/// conservative proxy until the bundle exposes its set size directly.
pub const COST_PER_SPARK_BUNDLE_BYTE: u64 = 1;

/// Per-tx ceiling: no single tx may exceed this, so it can't eat the whole
/// block budget. Provisional.
pub const MAX_TX_VERIFY_WEIGHT: u64 = 500_000;
/// Per-block ceiling on total heavy-verify work. Provisional — set so a full
/// block of ordinary txs is comfortably under it, but a block stuffed with
/// worst-case privacy txs is rejected.
pub const MAX_BLOCK_VERIFY_WEIGHT: u64 = 8_000_000;

/// Why a budget check failed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BudgetError {
    /// A single tx exceeds [`MAX_TX_VERIFY_WEIGHT`].
    TxTooHeavy { index: usize, weight: u64, limit: u64 },
    /// The block's total verify work exceeds [`MAX_BLOCK_VERIFY_WEIGHT`].
    BlockTooHeavy { total: u64, limit: u64 },
}

impl std::fmt::Display for BudgetError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BudgetError::TxTooHeavy { index, weight, limit } => write!(
                f,
                "tx {index} verify weight {weight} exceeds per-tx limit {limit}"
            ),
            BudgetError::BlockTooHeavy { total, limit } => write!(
                f,
                "block verify weight {total} exceeds per-block limit {limit}"
            ),
        }
    }
}

/// Provisional price of one verify unit in atomic fee, for the
/// verification-weighted fee floor. TODO: calibrate jointly with
/// `COST_PER_*` against real verify benchmarks and the fee market.
pub const FEE_PER_VERIFY_UNIT: u64 = 2;

/// The verification-weighted MINIMUM fee for a transaction — the economic half
/// of the DoS guard (§3.8). A tx that is cheap on the wire but expensive to
/// verify (a huge ring, many range proofs, a large Spark Spend bundle) must not
/// ride the plain size-based relay floor while forcing that verify cost on every
/// node. The floor is `max(size_floor, verify_floor)`:
///
/// * `size_floor  = size_bytes × min_fee_per_byte` (the EXISTING relay floor)
/// * `verify_floor = weight × FEE_PER_VERIFY_UNIT`
///
/// Because it is a `max`, an ordinary transaction — whose verify floor sits well
/// below its size floor — pays EXACTLY the current rule, unchanged; only a
/// verify-disproportionate tx is lifted. Saturating, so a pathological weight
/// can't wrap the floor down to something cheap.
///
/// Phase-0 **sketch**: NOT wired into relay/consensus (the live shielded floor
/// stays `size × MIN_FEE_PER_BYTE`, uniform with transparent — see the shielded
/// arc). This is the proposed guard for a future CIP, and it only ever raises,
/// never lowers, the existing floor.
#[must_use]
pub fn verify_weighted_min_fee(
    size_bytes: u64,
    weight: VerifyWeight,
    min_fee_per_byte: u64,
) -> u64 {
    let size_floor = size_bytes.saturating_mul(min_fee_per_byte);
    let verify_floor = weight.get().saturating_mul(FEE_PER_VERIFY_UNIT);
    size_floor.max(verify_floor)
}

/// Price one transaction's heavy-verify cost from its structural counts.
/// Saturating throughout, so a pathological input saturates to `u64::MAX`
/// (→ rejected) rather than wrapping to a small number.
#[must_use]
pub fn tx_verify_weight(
    ring_members: u64,
    range_proof_outputs: u64,
    spark_bundle_bytes: u64,
) -> VerifyWeight {
    let rings = ring_members.saturating_mul(COST_PER_RING_MEMBER);
    let ranges = range_proof_outputs.saturating_mul(COST_PER_RANGE_OUTPUT);
    let spark = spark_bundle_bytes.saturating_mul(COST_PER_SPARK_BUNDLE_BYTE);
    VerifyWeight(rings.saturating_add(ranges).saturating_add(spark))
}

/// Check a block's per-tx and total verify budget. `weights` is each tx's
/// [`VerifyWeight`] in block order. Returns the total on success.
pub fn check_block_budget(weights: &[VerifyWeight]) -> Result<VerifyWeight, BudgetError> {
    let mut total = VerifyWeight::ZERO;
    for (index, &w) in weights.iter().enumerate() {
        if w.0 > MAX_TX_VERIFY_WEIGHT {
            return Err(BudgetError::TxTooHeavy {
                index,
                weight: w.0,
                limit: MAX_TX_VERIFY_WEIGHT,
            });
        }
        total = total.saturating_add(w);
    }
    if total.0 > MAX_BLOCK_VERIFY_WEIGHT {
        return Err(BudgetError::BlockTooHeavy {
            total: total.0,
            limit: MAX_BLOCK_VERIFY_WEIGHT,
        });
    }
    Ok(total)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ordinary_block_is_under_budget() {
        // ~100 txs, 11-member rings, 2 range outputs each: realistic transparent.
        let one = tx_verify_weight(11, 2, 0);
        let block = vec![one; 100];
        let total = check_block_budget(&block).expect("under budget");
        assert!(total.0 < MAX_BLOCK_VERIFY_WEIGHT);
    }

    #[test]
    fn a_single_oversized_tx_is_rejected() {
        let heavy = tx_verify_weight(0, MAX_TX_VERIFY_WEIGHT / COST_PER_RANGE_OUTPUT + 1, 0);
        let err = check_block_budget(&[heavy]).unwrap_err();
        assert!(matches!(err, BudgetError::TxTooHeavy { index: 0, .. }));
    }

    #[test]
    fn many_max_txs_bust_the_block_budget() {
        let maxed = VerifyWeight(MAX_TX_VERIFY_WEIGHT);
        let n = (MAX_BLOCK_VERIFY_WEIGHT / MAX_TX_VERIFY_WEIGHT) + 2;
        let block = vec![maxed; n as usize];
        let err = check_block_budget(&block).unwrap_err();
        assert!(matches!(err, BudgetError::BlockTooHeavy { .. }));
    }

    #[test]
    fn ordinary_tx_pays_the_unchanged_size_floor() {
        // A normal transparent tx: small verify weight, so the size floor wins —
        // the verify-weighted rule must not change what it pays.
        let size_bytes = 2_000u64;
        let min_fee_per_byte = 100u64;
        let w = tx_verify_weight(11, 2, 0); // 11 + 256 = 267 units
        let floor = verify_weighted_min_fee(size_bytes, w, min_fee_per_byte);
        assert_eq!(floor, size_bytes * min_fee_per_byte, "ordinary tx pays exactly the size floor");
    }

    #[test]
    fn verify_heavy_small_tx_is_lifted_above_the_size_floor() {
        // Small on the wire, cheap per-byte, but a huge ring + many range proofs
        // → the verify floor dominates and the sender pays for the work imposed.
        // size_floor = 250*10 = 2_500; weight = 200 + 16*128 + 4096 = 6_344;
        // verify_floor = 6_344*2 = 12_688 > 2_500.
        let size_bytes = 250u64;
        let min_fee_per_byte = 10u64;
        let w = tx_verify_weight(200, 16, 4096);
        let floor = verify_weighted_min_fee(size_bytes, w, min_fee_per_byte);
        assert!(floor > size_bytes * min_fee_per_byte, "verify-heavy tx is lifted above the size floor");
        assert_eq!(floor, w.get() * FEE_PER_VERIFY_UNIT);
    }

    #[test]
    fn weight_saturates_instead_of_wrapping() {
        // Pathological counts must saturate to u64::MAX (→ over budget), not wrap.
        let w = tx_verify_weight(u64::MAX, u64::MAX, u64::MAX);
        assert_eq!(w.0, u64::MAX);
        let err = check_block_budget(&[w]).unwrap_err();
        assert!(matches!(err, BudgetError::TxTooHeavy { .. }));
    }
}
