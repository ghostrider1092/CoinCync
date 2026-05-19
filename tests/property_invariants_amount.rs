//! Property-based invariants for `coincync::primitives::Amount`.
//!
//! Targets the arithmetic, overflow, percentage, parse, and serde
//! surfaces of the `Amount` type — the load-bearing money primitive.
//! A regression in this type ripples through every transaction, every
//! fee calculation, every balance check.
//!
//! Coverage target: take `src/primitives/amount.rs` from the baseline
//! 52.29% region coverage measured 2026-05-19 up to 80%+.
//!
//! ## What each property defends against
//!
//! - **Roundtrip / conservation:** sums and differences of amounts
//!   are exact when no overflow is hit. A regression here is a
//!   "money creation" or "money destruction" bug at the wallet level.
//!
//! - **Checked vs saturating consistency:** when arithmetic succeeds
//!   under checked semantics, it produces the same result under
//!   saturating semantics. A regression here means the two code paths
//!   silently disagree on the same input.
//!
//! - **Overflow rejection:** any operation whose true mathematical
//!   result exceeds `u64::MAX` returns `Err` under checked semantics
//!   and saturates to `MAX` under saturating semantics. A regression
//!   here is a free-money bug.
//!
//! - **Percentage at boundaries:** 100% returns the original; 0%
//!   returns zero. A regression means fee math is wrong by orders
//!   of magnitude.
//!
//! - **Float edge cases rejected:** NaN, infinity, negative all
//!   return errors from the float constructors. A regression here
//!   lets garbage float inputs become valid `Amount` values.

#![cfg(not(miri))]

use proptest::prelude::*;

use coincync::primitives::Amount;

proptest! {
    #![proptest_config(ProptestConfig {
        cases: 256,
        .. ProptestConfig::default()
    })]

    // ─── Roundtrip ────────────────────────────────────────────────

    /// `Amount::from_atomic(x).as_atomic() == x` for any `u64 x`.
    /// Sanity foundation — without this every other property is moot.
    #[test]
    fn from_atomic_as_atomic_roundtrip(atomic in any::<u64>()) {
        prop_assert_eq!(Amount::from_atomic(atomic).as_atomic(), atomic);
    }

    // ─── Arithmetic — checked ─────────────────────────────────────

    /// `checked_add` is commutative: `a + b == b + a`.
    #[test]
    fn checked_add_is_commutative(a in any::<u64>(), b in any::<u64>()) {
        let amt_a = Amount::from_atomic(a);
        let amt_b = Amount::from_atomic(b);
        let ab = amt_a.checked_add(amt_b);
        let ba = amt_b.checked_add(amt_a);
        match (ab, ba) {
            (Ok(x), Ok(y)) => prop_assert_eq!(x, y),
            (Err(_), Err(_)) => {} // both overflowed: fine
            _ => prop_assert!(false, "checked_add asymmetric overflow on ({}, {})", a, b),
        }
    }

    /// `(a + b) - b == a` when the intermediate doesn't overflow.
    /// This is the no-money-creation/no-money-destruction property.
    #[test]
    fn add_then_sub_is_identity(a in any::<u64>(), b in any::<u64>()) {
        let amt_a = Amount::from_atomic(a);
        let amt_b = Amount::from_atomic(b);
        match amt_a.checked_add(amt_b) {
            Ok(sum) => {
                let back: Amount = sum.checked_sub(amt_b)
                    .expect("a + b succeeded, so (a + b) - b must succeed");
                prop_assert_eq!(back, amt_a,
                    "add+sub not identity: {} + {} - {} = {}", a, b, b, back.as_atomic());
            }
            Err(_) => {} // overflow — skip
        }
    }

    /// `checked_add` rejects iff the mathematical sum exceeds u64::MAX.
    #[test]
    fn checked_add_overflow_matches_math(a in any::<u64>(), b in any::<u64>()) {
        let math_overflows = u128::from(a) + u128::from(b) > u64::MAX as u128;
        let result = Amount::from_atomic(a).checked_add(Amount::from_atomic(b));
        prop_assert_eq!(result.is_err(), math_overflows);
    }

    /// `checked_sub` rejects iff `b > a`.
    #[test]
    fn checked_sub_rejects_underflow(a in any::<u64>(), b in any::<u64>()) {
        let result = Amount::from_atomic(a).checked_sub(Amount::from_atomic(b));
        prop_assert_eq!(result.is_err(), b > a);
    }

    /// `checked_div(0)` rejects on any amount.
    #[test]
    fn checked_div_rejects_zero_divisor(a in any::<u64>()) {
        prop_assert!(Amount::from_atomic(a).checked_div(0).is_err());
    }

    // ─── Checked vs saturating consistency ────────────────────────

    /// When `checked_add` succeeds, `saturating_add` returns the same value.
    /// When `checked_add` fails (overflow), `saturating_add` returns MAX.
    #[test]
    fn checked_add_consistent_with_saturating(a in any::<u64>(), b in any::<u64>()) {
        let amt_a = Amount::from_atomic(a);
        let amt_b = Amount::from_atomic(b);
        let sat = amt_a.saturating_add(amt_b);
        match amt_a.checked_add(amt_b) {
            Ok(checked) => {
                let c: Amount = checked;
                prop_assert_eq!(c, sat,
                    "checked_add succeeded but saturating disagreed: {} vs {}",
                    c.as_atomic(), sat.as_atomic());
            }
            Err(_) => prop_assert_eq!(sat, Amount::MAX,
                "checked_add failed but saturating didn't saturate: {}", sat.as_atomic()),
        }
    }

    /// When `checked_sub` succeeds, `saturating_sub` returns the same value.
    /// When `checked_sub` fails (underflow), `saturating_sub` returns ZERO.
    #[test]
    fn checked_sub_consistent_with_saturating(a in any::<u64>(), b in any::<u64>()) {
        let amt_a = Amount::from_atomic(a);
        let amt_b = Amount::from_atomic(b);
        let sat = amt_a.saturating_sub(amt_b);
        match amt_a.checked_sub(amt_b) {
            Ok(checked) => {
                let c: Amount = checked;
                prop_assert_eq!(c, sat);
            }
            Err(_) => prop_assert_eq!(sat, Amount::ZERO,
                "checked_sub failed but saturating didn't zero: {}", sat.as_atomic()),
        }
    }

    /// `Add` operator (saturating) matches `saturating_add`.
    #[test]
    fn add_operator_is_saturating(a in any::<u64>(), b in any::<u64>()) {
        let amt_a = Amount::from_atomic(a);
        let amt_b = Amount::from_atomic(b);
        prop_assert_eq!(amt_a + amt_b, amt_a.saturating_add(amt_b));
    }

    // ─── Percentage ───────────────────────────────────────────────

    /// `percentage(0)` always returns ZERO regardless of amount.
    #[test]
    fn percentage_zero_returns_zero(a in any::<u64>()) {
        prop_assert_eq!(Amount::from_atomic(a).percentage(0), Amount::ZERO);
    }

    /// `percentage(10000)` returns the original amount (100% — within
    /// rounding of the half-divisor add). For values where the
    /// computation cleanly divides, this is exact.
    ///
    /// NOTE: `percentage` uses round-half-up via `(num + 5000) / 10000`.
    /// For any `a`, `(a * 10000 + 5000) / 10000 == a` exactly because
    /// `5000 < 10000` and the numerator is `10000*a + 5000`, which
    /// floor-divides to `a`. So the property is exact at 10000 bps.
    #[test]
    fn percentage_100_percent_returns_self(a in 0u64..(u64::MAX / 10000)) {
        // Restrict to amounts where a * 10000 doesn't overflow u128.
        // u128 max is far larger than u64, so this is just being conservative.
        let amt = Amount::from_atomic(a);
        prop_assert_eq!(amt.percentage(10000), amt);
    }

    /// `percentage_truncate(0)` always returns ZERO.
    #[test]
    fn percentage_truncate_zero_returns_zero(a in any::<u64>()) {
        prop_assert_eq!(Amount::from_atomic(a).percentage_truncate(0), Amount::ZERO);
    }

    /// `percentage_truncate(10000)` returns the original amount exactly
    /// (no rounding; integer math `a*10000/10000 == a`).
    #[test]
    fn percentage_truncate_100_percent_returns_self(a in any::<u64>()) {
        let amt = Amount::from_atomic(a);
        prop_assert_eq!(amt.percentage_truncate(10000), amt);
    }

    // ─── Float conversions — edge cases ───────────────────────────

    /// `from_float_cync(NaN)` returns Err.
    #[test]
    fn from_float_cync_rejects_nan(_unused in 0u8..1) {
        prop_assert!(Amount::from_float_cync(f64::NAN).is_err());
    }

    /// `from_float_cync(+inf)` and `(-inf)` both return Err.
    #[test]
    fn from_float_cync_rejects_infinity(_unused in 0u8..1) {
        prop_assert!(Amount::from_float_cync(f64::INFINITY).is_err());
        prop_assert!(Amount::from_float_cync(f64::NEG_INFINITY).is_err());
    }

    /// `from_float_cync` rejects negative finite floats.
    #[test]
    fn from_float_cync_rejects_negative(neg in proptest::num::f64::NEGATIVE) {
        // proptest::num::f64::NEGATIVE generates finite negative floats.
        prop_assume!(neg.is_finite() && neg < 0.0);
        prop_assert!(Amount::from_float_cync(neg).is_err());
    }

    // ─── FromStr — basic roundtrip ────────────────────────────────

    /// For any non-fractional integer u64 value within the
    /// CYNC-decimal range, parsing `"<int>"` yields `from_cync(int)`.
    /// (Restricted to values where `int * ATOMIC_UNITS` fits in u64.)
    #[test]
    fn from_str_integer_cync_matches_from_cync(n in 0u64..1_000_000_u64) {
        let s = n.to_string();
        let parsed: Amount = s.parse().expect("integer parse must succeed");
        let from_cync = Amount::from_cync(n).expect("small n must not overflow");
        prop_assert_eq!(parsed, from_cync,
            "FromStr({}) != from_cync({}): parsed={}, fc={}",
            n, n, parsed.as_atomic(), from_cync.as_atomic());
    }

    /// FromStr rejects negative-prefixed input.
    #[test]
    fn from_str_rejects_negative(n in 1u64..u64::MAX) {
        let s = format!("-{}", n);
        let result: Result<Amount, _> = s.parse();
        prop_assert!(result.is_err(), "FromStr should reject {}", s);
    }

    /// FromStr rejects empty string.
    #[test]
    fn from_str_rejects_empty(_unused in 0u8..1) {
        let result: Result<Amount, _> = "".parse();
        prop_assert!(result.is_err());
        let result: Result<Amount, _> = "   ".parse();
        prop_assert!(result.is_err());
    }

    // ─── Serde / Borsh roundtrip ──────────────────────────────────

    /// Borsh serialize + deserialize is identity.
    #[test]
    fn borsh_roundtrip_is_identity(atomic in any::<u64>()) {
        let amt = Amount::from_atomic(atomic);
        let bytes = borsh::to_vec(&amt).expect("borsh serialize");
        let back: Amount = borsh::from_slice(&bytes).expect("borsh deserialize");
        prop_assert_eq!(back, amt);
    }

    /// JSON (serde) roundtrip is identity.
    #[test]
    fn json_roundtrip_is_identity(atomic in any::<u64>()) {
        let amt = Amount::from_atomic(atomic);
        let s = serde_json::to_string(&amt).expect("json serialize");
        let back: Amount = serde_json::from_str(&s).expect("json deserialize");
        prop_assert_eq!(back, amt);
    }

    // ─── as_atomic / as_cync / is_zero consistency ────────────────

    /// `as_atomic() / ATOMIC_UNITS == as_cync()` for any amount.
    #[test]
    fn as_cync_matches_atomic_division(atomic in any::<u64>()) {
        let amt = Amount::from_atomic(atomic);
        let expected_cync = atomic / 1_000_000_000_000u64; // ATOMIC_UNITS
        prop_assert_eq!(amt.as_cync(), expected_cync);
    }

    /// `is_zero` iff atomic value is 0.
    #[test]
    fn is_zero_iff_atomic_zero(atomic in any::<u64>()) {
        let amt = Amount::from_atomic(atomic);
        prop_assert_eq!(amt.is_zero(), atomic == 0);
    }

    // (Denomination invariants moved to in-crate unit tests; the
    // Denomination type isn't re-exported, so external integration
    // tests can't reach it. The in-crate test module covers it.)
}
