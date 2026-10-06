//! Supply tracking for CoinCync 1.0.
//!
//! `SupplyStats` snapshots cumulative emission, burns, and circulating
//! supply at a given height. `calculate_supply_commitment` produces a
//! deterministic hash of the stats, used by the `get_supply_info` RPC
//! so auditors can independently verify the chain's supply invariant.
//!
//! ## Audit map
//! Each `§` is a code section below; it states the INVARIANT it guarantees, the
//! THREAT it defends, and the TESTS that prove it. (Renders in `cargo doc`.)
//!
//! - **§1 `SupplyStats` (snapshot struct + `Default`)** — INVARIANT: the five
//!   fields form a self-consistent point-in-time supply snapshot; `Default` is
//!   all-zero / not-in-tail. THREAT: an uninitialized or partial snapshot
//!   misreporting supply to auditors. TESTS: `test_supply_stats_default`.
//! - **§2 `SupplyStats::new` (circulating invariant)** — INVARIANT:
//!   `circulating = emitted.saturating_sub(burned)`; burned > emitted clamps to
//!   zero, never underflows. THREAT: an underflow wrapping circulating supply to
//!   a near-`u64::MAX` phantom balance. TESTS: `test_supply_stats_new`,
//!   `supply_stats_new_burned_exceeds_emitted_saturates_to_zero`.
//! - **§3 `calculate_supply_commitment` (deterministic digest)** — INVARIANT:
//!   the commitment is a pure function of the stats — identical stats always
//!   hash to identical bytes. THREAT: nondeterminism defeating independent
//!   auditor verification of the supply invariant. TESTS:
//!   `test_supply_commitment_deterministic`.
//! - **§4 `calculate_supply_commitment` (field coverage + domain separation)** —
//!   INVARIANT: the digest covers emitted / burned / circulating /
//!   emission_remaining (changing any one changes the digest) and is
//!   domain-separated by the `COINCYNC_SUPPLY_COMMITMENT` tag; `in_tail` is NOT
//!   hashed. THREAT: a supply field silently tampered without changing the
//!   commitment. TESTS: `supply_commitment_sensitive_to_each_hashed_field`.

use crate::primitives::Amount;
use borsh::{BorshDeserialize, BorshSerialize};

#[derive(Debug, Clone, Default, BorshSerialize, BorshDeserialize)]
pub struct SupplyStats {
    pub total_emitted: Amount,
    pub total_burned: Amount,
    pub circulating: Amount,
    pub emission_remaining: Amount,
    pub in_tail: bool,
}

impl SupplyStats {
    pub fn new(emitted: Amount, burned: Amount, remaining: Amount, in_tail: bool) -> Self {
        SupplyStats {
            total_emitted: emitted,
            total_burned: burned,
            circulating: emitted.saturating_sub(burned),
            emission_remaining: remaining,
            in_tail,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_supply_stats_new() {
        let stats = SupplyStats::new(
            Amount::from_atomic(1000),
            Amount::from_atomic(100),
            Amount::from_atomic(500),
            false,
        );
        assert_eq!(stats.total_emitted, Amount::from_atomic(1000));
        assert_eq!(stats.total_burned, Amount::from_atomic(100));
        assert_eq!(stats.circulating, Amount::from_atomic(900)); // 1000 - 100
        assert!(!stats.in_tail);
    }

    #[test]
    fn test_supply_stats_default() {
        let stats = SupplyStats::default();
        assert_eq!(stats.total_emitted, Amount::ZERO);
        assert_eq!(stats.circulating, Amount::ZERO);
        assert!(!stats.in_tail);
    }

    /// Independent reference: the naive inclusive sum of per-height
    /// rewards, exactly the recompute `tests/invariant_pipeline.rs` and
    /// `tests/common/simkit.rs` run against `total_supply`.
    fn ref_cumulative(tip: u64) -> u128 {
        (0..=tip)
            .map(|h| crate::emission::base_reward(h).as_atomic() as u128)
            .sum()
    }

    #[test]
    fn cumulative_emission_at_genesis_is_one_reward() {
        // tip 0 => just the genesis block's reward (50 CYNC).
        assert_eq!(
            cumulative_emission(0),
            50 * crate::constants::COIN as u128,
            "cumulative emission at tip 0 must equal the genesis reward"
        );
    }

    #[test]
    fn cumulative_emission_matches_naive_sum() {
        // Exact agreement with the block-by-block inclusive sum across a
        // range of testnet-scale tips. This is the invariant the guard
        // reconciles `total_supply` against, so exactness (no estimator
        // drift) is what keeps the guard free of false positives.
        for &tip in &[0u64, 1, 2, 10, 100, 999, 2_500, 5_000] {
            assert_eq!(
                cumulative_emission(tip),
                ref_cumulative(tip),
                "cumulative_emission({tip}) diverged from the naive inclusive sum"
            );
        }
    }

    #[test]
    fn cumulative_emission_is_strictly_increasing_in_the_distribution_phase() {
        // Every block in the distribution phase pays a positive reward, so
        // the cumulative sum strictly increases with the tip height.
        let mut prev = cumulative_emission(0);
        for tip in [1u64, 50, 500, 5_000] {
            let cur = cumulative_emission(tip);
            assert!(
                cur > prev,
                "cumulative_emission must increase: tip {tip} gave {cur} <= {prev}"
            );
            prev = cur;
        }
    }

    #[test]
    fn cumulative_emission_equals_total_supply_accounting_identity() {
        // The block-connect path maintains total_supply as
        // `+= calculate_block_reward(height)` per block, which is exactly
        // this inclusive sum. Prove the two definitions coincide for a
        // simulated tip, mirroring the runtime guard's comparison.
        let tip = 1_234u64;
        let simulated_total_supply: u128 = (0..=tip)
            .map(|h| crate::emission::calculate_block_reward(h).as_atomic() as u128)
            .sum();
        assert_eq!(
            cumulative_emission(tip),
            simulated_total_supply,
            "cumulative_emission must equal the running total_supply the chain maintains"
        );
    }

    #[test]
    fn test_supply_commitment_deterministic() {
        let stats = SupplyStats::new(
            Amount::from_atomic(1000),
            Amount::from_atomic(100),
            Amount::from_atomic(500),
            false,
        );
        let c1 = calculate_supply_commitment(&stats);
        let c2 = calculate_supply_commitment(&stats);
        assert_eq!(c1, c2);
    }

    #[test]
    fn supply_stats_new_burned_exceeds_emitted_saturates_to_zero() {
        // circulating = emitted - burned is saturating; burned > emitted must
        // clamp circulating to zero rather than underflow.
        let stats = SupplyStats::new(
            Amount::from_atomic(100),
            Amount::from_atomic(500),
            Amount::from_atomic(0),
            false,
        );
        assert_eq!(
            stats.circulating,
            Amount::ZERO,
            "burned > emitted must saturate circulating to zero"
        );
    }

    #[test]
    fn supply_commitment_sensitive_to_each_hashed_field() {
        // The commitment digests emitted, burned, circulating and remaining.
        // Changing any one of those must change the digest; in_tail is NOT
        // hashed, so toggling it must leave the digest unchanged. Fields are
        // set directly (bypassing `new`) so circulating varies independently.
        let base = SupplyStats {
            total_emitted: Amount::from_atomic(1000),
            total_burned: Amount::from_atomic(100),
            circulating: Amount::from_atomic(900),
            emission_remaining: Amount::from_atomic(500),
            in_tail: false,
        };
        let base_digest = calculate_supply_commitment(&base);

        let mut s = base.clone();
        s.total_emitted = Amount::from_atomic(1001);
        assert_ne!(
            calculate_supply_commitment(&s),
            base_digest,
            "digest must be sensitive to total_emitted"
        );

        let mut s = base.clone();
        s.total_burned = Amount::from_atomic(101);
        assert_ne!(
            calculate_supply_commitment(&s),
            base_digest,
            "digest must be sensitive to total_burned"
        );

        let mut s = base.clone();
        s.circulating = Amount::from_atomic(901);
        assert_ne!(
            calculate_supply_commitment(&s),
            base_digest,
            "digest must be sensitive to circulating"
        );

        let mut s = base.clone();
        s.emission_remaining = Amount::from_atomic(501);
        assert_ne!(
            calculate_supply_commitment(&s),
            base_digest,
            "digest must be sensitive to emission_remaining"
        );

        // in_tail is not part of the hashed data — digest must be unchanged.
        let mut s = base.clone();
        s.in_tail = true;
        assert_eq!(
            calculate_supply_commitment(&s),
            base_digest,
            "in_tail is not hashed; digest must be unchanged"
        );
    }

    // ── consensus (u128) commitment ──────────────────────────────────────

    #[test]
    fn supply_commitment_consensus_is_deterministic() {
        let a = supply_commitment_consensus(1_000, 100, 500);
        let b = supply_commitment_consensus(1_000, 100, 500);
        assert_eq!(a, b, "identical inputs must hash identically");
    }

    #[test]
    fn supply_commitment_consensus_is_exact_above_u64_max() {
        // THE POINT of the u128 variant: cumulative emitted reaches ~1e20,
        // which overflows u64 (~1.84e19). Values past u64::MAX must be
        // representable and must change the digest — a u64-based commitment
        // would truncate/wrap here and alias distinct supply states.
        let over = (u64::MAX as u128) + 1;
        let d_over = supply_commitment_consensus(over, 0, 0);
        // A distinct value one atomic unit higher must produce a distinct digest
        // (no truncation to a common u64 residue).
        let d_over_plus = supply_commitment_consensus(over + 1, 0, 0);
        assert_ne!(
            d_over, d_over_plus,
            "distinct >u64::MAX emitted values must not collide"
        );
        // And the low 64 bits matching a smaller value must NOT alias it.
        let d_low = supply_commitment_consensus(1, 0, 0);
        assert_ne!(
            d_over_plus, d_low,
            "over-u64 value must not alias its low-64-bit residue"
        );
    }

    #[test]
    fn supply_commitment_consensus_sensitive_to_each_field() {
        let base = supply_commitment_consensus(1_000, 100, 500);
        assert_ne!(
            supply_commitment_consensus(1_001, 100, 500),
            base,
            "sensitive to total_emitted"
        );
        assert_ne!(
            supply_commitment_consensus(1_000, 101, 500),
            base,
            "sensitive to total_burned (also moves circulating)"
        );
        assert_ne!(
            supply_commitment_consensus(1_000, 100, 501),
            base,
            "sensitive to emission_remaining"
        );
    }

    #[test]
    fn supply_commitment_consensus_circulating_saturates() {
        // burned > emitted must clamp circulating to zero, never underflow-wrap.
        let a = supply_commitment_consensus(100, 500, 0);
        let b = supply_commitment_consensus(100, 100, 0); // circulating 0 both
        // Different burned totals still differ (burned is hashed directly), but
        // neither panics / wraps — the call returning is the assertion.
        assert_ne!(a, b);
    }

    #[test]
    fn supply_commitment_consensus_domain_separated_from_u64_helper() {
        // The two digests must not collide even on numerically-equal small
        // inputs, thanks to the distinct domain tag + width.
        let stats = SupplyStats::new(
            Amount::from_atomic(1_000),
            Amount::from_atomic(100),
            Amount::from_atomic(500),
            false,
        );
        let u64_digest = calculate_supply_commitment(&stats);
        // emitted=1000, burned=100, remaining=500 — same numbers, u128 path.
        let consensus_digest = supply_commitment_consensus(1_000, 100, 500);
        assert_ne!(
            u64_digest, consensus_digest,
            "consensus (u128) and RPC (u64) commitments must be domain-separated"
        );
    }
}

/// Exact cumulative **gross** emission through `tip_height`, inclusive:
/// `Σ_{h=0}^{tip_height} base_reward(h)` in atomic units, saturating.
///
/// This is the independent recompute of the chain's `total_supply`
/// counter. The block-connect path maintains `total_supply` as exactly
/// this running sum (`total_supply += calculate_block_reward(height)` on
/// connect, `-=` on disconnect — see `chain.rs`), so for an honest chain
/// `total_supply == cumulative_emission(tip)` holds bit-for-bit.
///
/// Reconciling the two — see
/// [`crate::security::supply::supply_reconciliation`] — turns the
/// previously *test-only* supply-conservation invariant
/// (`tests/invariant_pipeline.rs`, `tests/common/simkit.rs`) into a
/// **live** guard and an auditor-verifiable RPC value. It catches drift
/// in the incremental `+=` / `-=` bookkeeping across connects,
/// disconnects, reorgs, and restart replay — i.e. a recorded supply that
/// diverges from the deterministic emission schedule.
///
/// It does **NOT** re-derive value from the cryptography: a block that
/// emits exactly its scheduled reward while the *coins themselves* are
/// inflated by a balance/range proof that verifies-but-shouldn't is
/// invisible to this check. That residual is the external audit's job
/// (see `docs/design/cip-security-threat-model.md`). It also shares the
/// `base_reward` primitive with the counter it reconciles, so a bug
/// *inside* `base_reward` is not caught — only accounting-path drift is.
///
/// Cost: O(min(tip_height, tail-onset)). `base_reward` is monotone
/// non-increasing and floored at `TAIL_EMISSION`; once it reaches that
/// floor every further block contributes exactly `TAIL_EMISSION`, summed
/// in O(1). Intended to be called with the real chain tip (bounded by
/// chain length), not with arbitrary caller-supplied heights.
pub fn cumulative_emission(tip_height: u64) -> u128 {
    use crate::constants::TAIL_EMISSION;

    let tail = TAIL_EMISSION as u128;
    let mut total: u128 = 0;
    let mut h: u64 = 0;
    loop {
        let reward = crate::emission::base_reward(h).as_atomic();
        // Tail fast-path: `base_reward` is monotone non-increasing and
        // floored at TAIL_EMISSION (curve.rs §3/§4). Reaching the floor
        // is absorbing — the estimated supply only grows — so every
        // remaining block `h..=tip_height` contributes exactly the tail.
        if reward == TAIL_EMISSION {
            let remaining_inclusive = (tip_height - h) as u128 + 1;
            total = total.saturating_add(tail.saturating_mul(remaining_inclusive));
            break;
        }
        total = total.saturating_add(reward as u128);
        if h == tip_height {
            break;
        }
        h += 1;
    }
    total
}

/// Calculate Pedersen commitment to supply (for auditing)
pub fn calculate_supply_commitment(stats: &SupplyStats) -> [u8; 32] {
    use crate::primitives::hash_concat;

    let data = [
        stats.total_emitted.as_atomic().to_le_bytes(),
        stats.total_burned.as_atomic().to_le_bytes(),
        stats.circulating.as_atomic().to_le_bytes(),
        stats.emission_remaining.as_atomic().to_le_bytes(),
    ]
    .concat();

    *hash_concat(&[&data, b"COINCYNC_SUPPLY_COMMITMENT"]).as_bytes()
}

/// **Consensus** supply commitment — the value bound into
/// `BlockHeader.supply_commitment` (see
/// `docs/design/cip-supply-commitment-enforcement.md`). GATED OFF until an
/// activation height is cleared; producing/validating it is a no-op below the
/// `supply_commitment_enforce_height`.
///
/// ## Why a SEPARATE function from `calculate_supply_commitment` above
/// That helper hashes `SupplyStats`' `Amount` (u64) fields. Cumulative emitted
/// supply reaches MAX_SUPPLY = 100M CYNC × 10^12 = 10^20 atomic, which OVERFLOWS
/// u64 (~1.8×10^19) at ~18.4M CYNC (height ~408k) — the exact reason
/// `ChainStats::total_supply`/`total_burned` are `u128`. A consensus commitment
/// MUST be exact across the whole supply range, so it hashes the `u128`
/// cumulative values directly and is domain-separated by a DISTINCT tag
/// (`…_CONSENSUS_V1`) so it can never collide with the u64 RPC/audit digest.
///
/// ## What it binds (post-apply)
/// The cumulative supply as the block LEAVES it: `total_emitted` and
/// `total_burned` are the running totals AFTER this block's coinbase emission
/// and fee burns are applied. `circulating = total_emitted - total_burned`
/// (saturating); `emission_remaining = MAX_SUPPLY - total_emitted`. Producer and
/// validator MUST feed identical inputs for an identical block or honest blocks
/// self-reject — see the CIP.
pub fn supply_commitment_consensus(
    total_emitted: u128,
    total_burned: u128,
    emission_remaining: u128,
) -> [u8; 32] {
    use crate::primitives::hash_concat;

    let circulating = total_emitted.saturating_sub(total_burned);
    let mut data = Vec::with_capacity(64);
    data.extend_from_slice(&total_emitted.to_le_bytes());
    data.extend_from_slice(&total_burned.to_le_bytes());
    data.extend_from_slice(&circulating.to_le_bytes());
    data.extend_from_slice(&emission_remaining.to_le_bytes());

    *hash_concat(&[&data, b"COINCYNC_SUPPLY_COMMITMENT_CONSENSUS_V1"]).as_bytes()
}
