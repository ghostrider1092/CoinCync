//! Difficulty-scalar newtype (F1: make illegal states unrepresentable).
//!
//! A difficulty is the integer work-factor derived from a block target
//! (`target_to_difficulty`), not an arbitrary `u128` — making it a distinct type
//! stops a height, an amount, or a raw target from being passed where a
//! difficulty is expected. Difficulties ADD (cumulative chain work is the sum of
//! per-block difficulties); that is the one arithmetic this exposes.
//!
//! WIRE-TRANSPARENT: `#[serde(transparent)]` + a single-field Borsh tuple struct
//! serialize byte-identically to the inner `u128`, so if a cumulative-work field
//! is ever persisted, migrating it onto this type does not change the layout.
//! Adoption (making `target_to_difficulty` return `Difficulty`, `MIN_DIFFICULTY`
//! a `Difficulty`, etc.) touches the lock-protected `consensus/difficulty.rs` and
//! is a separate, lock-regenerating migration — this increment adds ONLY the type.

use borsh::{BorshDeserialize, BorshSerialize};
use serde::{Deserialize, Serialize};

#[derive(
    Clone,
    Copy,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    Debug,
    Default,
    Serialize,
    Deserialize,
    BorshSerialize,
    BorshDeserialize,
)]
#[serde(transparent)]
pub struct Difficulty(u128);

impl Difficulty {
    /// The lowest meaningful work-factor (one unit).
    pub const MIN: Difficulty = Difficulty(1);
    /// Zero work — the cumulative work before genesis.
    pub const ZERO: Difficulty = Difficulty(0);

    #[inline]
    pub const fn new(d: u128) -> Self {
        Difficulty(d)
    }

    #[inline]
    pub const fn as_u128(self) -> u128 {
        self.0
    }

    /// Accumulate block work, saturating at `u128::MAX` (cumulative chain work
    /// never wraps, so a crafted run of blocks cannot overflow it to a small
    /// value and fake a lower total).
    #[inline]
    pub const fn saturating_add(self, other: Difficulty) -> Difficulty {
        Difficulty(self.0.saturating_add(other.0))
    }
}

// Conversions at the boundaries keep the eventual migration mechanical.
impl From<u128> for Difficulty {
    #[inline]
    fn from(d: u128) -> Self {
        Difficulty(d)
    }
}
impl From<Difficulty> for u128 {
    #[inline]
    fn from(d: Difficulty) -> Self {
        d.0
    }
}

// Difficulties sum into cumulative work. No Sub/Mul — a difference or product of
// two work-factors is not itself a meaningful difficulty.
impl std::ops::Add for Difficulty {
    type Output = Difficulty;
    #[inline]
    fn add(self, other: Difficulty) -> Difficulty {
        self.saturating_add(other)
    }
}
impl std::iter::Sum for Difficulty {
    fn sum<I: Iterator<Item = Difficulty>>(iter: I) -> Difficulty {
        iter.fold(Difficulty::ZERO, |acc, d| acc + d)
    }
}

impl std::fmt::Display for Difficulty {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_and_accessors() {
        let d = Difficulty::new(500);
        assert_eq!(d.as_u128(), 500);
        assert_eq!(u128::from(d), 500);
        assert_eq!(Difficulty::from(42u128).as_u128(), 42);
        assert_eq!(Difficulty::ZERO.as_u128(), 0);
        assert_eq!(Difficulty::MIN.as_u128(), 1);
    }

    #[test]
    fn cumulative_work_sums_and_saturates() {
        let work: Difficulty = [Difficulty::new(10), Difficulty::new(20), Difficulty::new(30)]
            .into_iter()
            .sum();
        assert_eq!(work, Difficulty::new(60));
        assert_eq!(Difficulty::new(5) + Difficulty::new(7), Difficulty::new(12));
        // Saturates instead of wrapping — a cumulative-work total can never roll
        // over to a small value.
        assert_eq!(
            Difficulty::new(u128::MAX).saturating_add(Difficulty::new(100)),
            Difficulty::new(u128::MAX)
        );
    }

    #[test]
    fn ordering_compares_work() {
        assert!(Difficulty::new(100) > Difficulty::new(99));
        assert!(Difficulty::ZERO < Difficulty::MIN);
    }

    #[test]
    fn borsh_is_wire_transparent_vs_u128() {
        let n: u128 = 0x0123_4567_89AB_CDEF_FEDC_BA98_7654_3210;
        let d = Difficulty::new(n);
        assert_eq!(
            borsh::to_vec(&d).unwrap(),
            borsh::to_vec(&n).unwrap(),
            "Difficulty must serialize byte-identically to u128"
        );
    }

    #[test]
    fn serde_is_transparent() {
        let d = Difficulty::new(500);
        assert_eq!(serde_json::to_string(&d).unwrap(), "500");
        let back: Difficulty = serde_json::from_str("500").unwrap();
        assert_eq!(back, d);
    }
}
