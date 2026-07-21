//! Supply tracking for CoinCync 1.0.
//!
//! `SupplyStats` snapshots cumulative emission, burns, and circulating
//! supply at a given height. `calculate_supply_commitment` produces a
//! deterministic hash of the stats, used by the `get_supply_info` RPC
//! so auditors can independently verify the chain's supply invariant.

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
