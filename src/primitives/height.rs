//! Block-height newtype (F1: make illegal states unrepresentable).
//!
//! A block height is a position in the chain, not an arbitrary `u64` — making it
//! a distinct type stops a `Timestamp`, an amount, a count, or a difficulty from
//! being passed where a height is expected (and vice-versa). Arithmetic is
//! deliberately typed: `Height + N` / `Height - N` offsets by a block COUNT and
//! stays a `Height`, while `Height - Height` is the count BETWEEN two heights.
//!
//! WIRE-TRANSPARENT: `#[serde(transparent)]` + a single-field Borsh tuple struct
//! serialize EXACTLY as the inner `u64`, so migrating a serialized field
//! (`BlockHeader.height`, …) does NOT change the byte layout or any block hash.
//! This is a pure type-safety change, not a consensus/format change. The
//! migration onto this type is a separate, incremental, per-module effort (the
//! consensus module first); this increment adds ONLY the type.

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
pub struct Height(u64);

impl Height {
    /// The genesis block's height.
    pub const GENESIS: Height = Height(0);

    #[inline]
    pub const fn new(h: u64) -> Self {
        Height(h)
    }

    #[inline]
    pub const fn as_u64(self) -> u64 {
        self.0
    }

    /// The next height (saturating at `u64::MAX`).
    #[inline]
    pub const fn next(self) -> Self {
        Height(self.0.saturating_add(1))
    }

    /// The previous height (saturating at `0`, i.e. genesis).
    #[inline]
    pub const fn prev(self) -> Self {
        Height(self.0.saturating_sub(1))
    }

    /// Whether this is the genesis height.
    #[inline]
    pub const fn is_genesis(self) -> bool {
        self.0 == 0
    }

    /// Block count from an `earlier` height to `self`, saturating to 0 if
    /// `self < earlier` (never panics / underflows).
    #[inline]
    pub const fn saturating_blocks_since(self, earlier: Height) -> u64 {
        self.0.saturating_sub(earlier.0)
    }

    /// This height minus `blocks`, saturating at genesis (0). Method form of the
    /// `Sub<u64>` operator, for call sites that read like `h.saturating_sub(n)`.
    #[inline]
    pub const fn saturating_sub(self, blocks: u64) -> Height {
        Height(self.0.saturating_sub(blocks))
    }

    /// This height plus `blocks`, saturating at `u64::MAX`.
    #[inline]
    pub const fn saturating_add(self, blocks: u64) -> Height {
        Height(self.0.saturating_add(blocks))
    }

    /// This height plus `blocks`, or `None` on overflow. Mirrors
    /// `u64::checked_add`; returns a `Height`.
    #[inline]
    pub const fn checked_add(self, blocks: u64) -> Option<Height> {
        match self.0.checked_add(blocks) {
            Some(h) => Some(Height(h)),
            None => None,
        }
    }
}

// Conversions at the boundaries keep the migration mechanical.
impl From<u64> for Height {
    #[inline]
    fn from(h: u64) -> Self {
        Height(h)
    }
}
impl From<Height> for u64 {
    #[inline]
    fn from(h: Height) -> Self {
        h.0
    }
}

// Height ± a block COUNT stays a Height; Height − Height is the count between.
// Deliberately NO ops that treat a bare `u64` as another height.
impl std::ops::Add<u64> for Height {
    type Output = Height;
    #[inline]
    fn add(self, blocks: u64) -> Height {
        Height(self.0.saturating_add(blocks))
    }
}
impl std::ops::Sub<u64> for Height {
    type Output = Height;
    #[inline]
    fn sub(self, blocks: u64) -> Height {
        Height(self.0.saturating_sub(blocks))
    }
}
impl std::ops::Sub<Height> for Height {
    type Output = u64;
    #[inline]
    fn sub(self, earlier: Height) -> u64 {
        self.0.saturating_sub(earlier.0)
    }
}

impl std::fmt::Display for Height {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_and_accessors() {
        let h = Height::new(10_833);
        assert_eq!(h.as_u64(), 10_833);
        assert_eq!(u64::from(h), 10_833);
        assert_eq!(Height::from(42u64).as_u64(), 42);
        assert!(Height::GENESIS.is_genesis());
        assert!(!h.is_genesis());
    }

    #[test]
    fn next_prev_saturate() {
        assert_eq!(Height::new(5).next(), Height::new(6));
        assert_eq!(Height::new(5).prev(), Height::new(4));
        assert_eq!(Height::GENESIS.prev(), Height::GENESIS); // no underflow
        assert_eq!(Height::new(u64::MAX).next(), Height::new(u64::MAX)); // no overflow
    }

    #[test]
    fn arithmetic_is_count_typed() {
        let a = Height::new(100);
        let b = a + 50; // offset by a block count
        assert_eq!(b, Height::new(150));
        assert_eq!(b - 50u64, a);
        assert_eq!(b - a, 50u64); // count BETWEEN heights
        assert_eq!(b.saturating_blocks_since(a), 50);
        assert_eq!(a.saturating_blocks_since(b), 0); // no underflow
        assert_eq!(a - 1000u64, Height::GENESIS); // saturating
    }

    #[test]
    fn ordering() {
        assert!(Height::new(1) < Height::new(2));
        assert!(Height::GENESIS < Height::new(1));
        let mut v = [Height::new(3), Height::new(1), Height::new(2)];
        v.sort();
        assert_eq!(v, [Height::new(1), Height::new(2), Height::new(3)]);
    }

    #[test]
    fn borsh_is_wire_transparent_vs_u64() {
        let n: u64 = 0x0123_4567_89AB_CDEF;
        let h = Height::new(n);
        assert_eq!(
            borsh::to_vec(&h).unwrap(),
            borsh::to_vec(&n).unwrap(),
            "Height must serialize byte-identically to u64"
        );
    }

    #[test]
    fn serde_is_transparent() {
        let h = Height::new(99);
        assert_eq!(serde_json::to_string(&h).unwrap(), "99");
        let back: Height = serde_json::from_str("99").unwrap();
        assert_eq!(back, h);
    }
}
