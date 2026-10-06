//! Property-based invariants for `coincync::consensus::fee_market::distribute_fee`.
//!
//! Fee distribution is money-conservation code: every atomic unit of a
//! transaction fee must be accounted for as either miner reward or burn, with
//! **zero** rounding loss and **no** overflow, for any fee value a block could
//! carry (up to `u64::MAX`). Two shipped audit fixes live here and must never
//! regress:
//!
//! - **A8-DIST-01** — `distribute_fee` computes the last bucket as the exact
//!   remainder (`fee - to_miner`), so `to_miner + burned + to_protocol == total`
//!   holds with a tolerance of exactly 0 (see `FeeDistribution::is_valid`).
//! - **A7-2** — the split uses a `u128` intermediate, so a fee near `u64::MAX`
//!   cannot trigger the multiplication-overflow panic that a `u64` product would
//!   in a release (`panic = abort`) build.
//!
//! These properties are grounded in the actual impl at
//! `src/consensus/fee_market.rs:100-160` and the constants at
//! `src/constants.rs:507-528` (normal 70/30, congested 50/50 miner/burn split;
//! `to_protocol` is always 0 per Constitution Article II — 0% dev tax).

#![cfg(not(miri))]

use proptest::prelude::*;

use coincync::consensus::fee_market::distribute_fee;
use coincync::primitives::Amount;

fn total_atomic(total: u64, congested: bool) -> u128 {
    let d = distribute_fee(Amount::from_atomic(total), congested);
    d.to_miner.as_atomic() as u128 + d.burned.as_atomic() as u128 + d.to_protocol.as_atomic() as u128
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 1024, .. ProptestConfig::default() })]

    /// CONSERVATION (A8-DIST-01): the three buckets sum to exactly `total`,
    /// for any fee and either congestion state. No atomic unit is created or lost.
    #[test]
    fn distribute_fee_conserves_total(total in any::<u64>(), congested in any::<bool>()) {
        let d = distribute_fee(Amount::from_atomic(total), congested);
        prop_assert!(d.is_valid(), "is_valid() must hold: {d:?}");
        prop_assert_eq!(total_atomic(total, congested), total as u128, "buckets must sum to total");
        prop_assert_eq!(d.total.as_atomic(), total, "total field must echo the input");
    }

    /// NO OVERFLOW (A7-2): the split never panics even at the u64 ceiling, and
    /// each bucket stays within the fee. A `u64` product would overflow here.
    #[test]
    fn distribute_fee_no_overflow_and_bounded(total in any::<u64>(), congested in any::<bool>()) {
        let d = distribute_fee(Amount::from_atomic(total), congested);
        prop_assert!(d.to_miner.as_atomic() <= total, "miner share cannot exceed the fee");
        prop_assert!(d.burned.as_atomic() <= total, "burn cannot exceed the fee");
    }

    /// 0% DEV TAX (Constitution Article II): `to_protocol` is always zero.
    #[test]
    fn distribute_fee_never_pays_protocol(total in any::<u64>(), congested in any::<bool>()) {
        let d = distribute_fee(Amount::from_atomic(total), congested);
        prop_assert_eq!(d.to_protocol.as_atomic(), 0, "protocol/dev tax must be 0");
    }

    /// DETERMINISM: identical inputs yield identical splits (consensus-critical —
    /// the coinbase reward depends on this exact value).
    #[test]
    fn distribute_fee_is_deterministic(total in any::<u64>(), congested in any::<bool>()) {
        let a = distribute_fee(Amount::from_atomic(total), congested);
        let b = distribute_fee(Amount::from_atomic(total), congested);
        prop_assert_eq!(a.to_miner.as_atomic(), b.to_miner.as_atomic());
        prop_assert_eq!(a.burned.as_atomic(), b.burned.as_atomic());
    }

    /// CONGESTION SHIFTS SHARE TO BURN: for the same fee, congestion never
    /// increases the miner's share and never decreases the burn (70/30 → 50/50).
    #[test]
    fn distribute_fee_congestion_burns_at_least_as_much(total in any::<u64>()) {
        let normal = distribute_fee(Amount::from_atomic(total), false);
        let congested = distribute_fee(Amount::from_atomic(total), true);
        prop_assert!(
            congested.to_miner.as_atomic() <= normal.to_miner.as_atomic(),
            "congested miner share must be <= normal"
        );
        prop_assert!(
            congested.burned.as_atomic() >= normal.burned.as_atomic(),
            "congested burn must be >= normal"
        );
    }
}

/// Concrete spot-checks anchoring the percentages (defense against a silent
/// constant edit): 1000 atomic units splits 700/300 normal, 500/500 congested.
#[test]
fn distribute_fee_reference_splits() {
    let n = distribute_fee(Amount::from_atomic(1000), false);
    assert_eq!(n.to_miner.as_atomic(), 700);
    assert_eq!(n.burned.as_atomic(), 300);

    let c = distribute_fee(Amount::from_atomic(1000), true);
    assert_eq!(c.to_miner.as_atomic(), 500);
    assert_eq!(c.burned.as_atomic(), 500);

    // u64::MAX must not panic and must still conserve.
    let big = distribute_fee(Amount::from_atomic(u64::MAX), true);
    assert!(big.is_valid());
}
