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
