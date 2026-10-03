//! Unix-seconds timestamp newtype (F1: make illegal states unrepresentable).
//!
//! A block/peer timestamp is unix SECONDS, not an arbitrary `u64` — making it a
//! distinct type stops a `Height`, a count, or a duration from being passed
//! where a timestamp is expected (and vice-versa).
//!
//! WIRE-TRANSPARENT: `#[serde(transparent)]` + a single-field Borsh tuple struct
//! serialize EXACTLY as the inner `u64`, so migrating a serialized field
//! (`BlockHeader.timestamp`, …) does NOT change the byte layout or any block
//! hash. This is a pure type-safety change, not a consensus/format change.

use borsh::{BorshDeserialize, BorshSerialize};
use serde::{Deserialize, Serialize};
use std::time::Duration;

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
pub struct Timestamp(u64);

impl Timestamp {
    pub const ZERO: Timestamp = Timestamp(0);

    #[inline]
    pub const fn from_secs(secs: u64) -> Self {
        Timestamp(secs)
    }

    #[inline]
    pub const fn as_secs(self) -> u64 {
        self.0
    }

    /// Non-panicking difference in seconds (0 if `self < earlier`).
    #[inline]
    pub const fn saturating_secs_since(self, earlier: Timestamp) -> u64 {
        self.0.saturating_sub(earlier.0)
    }

    /// Current wall-clock timestamp via the canonical clock (E1), so the
    /// simulation harness can make it deterministic. See `crate::clock`.
    #[inline]
    pub fn now() -> Self {
        Timestamp(crate::clock::unix_now())
    }
}

// Conversions at the boundaries keep the migration mechanical.
impl From<u64> for Timestamp {
    #[inline]
    fn from(secs: u64) -> Self {
        Timestamp(secs)
    }
}
impl From<Timestamp> for u64 {
    #[inline]
    fn from(t: Timestamp) -> Self {
        t.0
    }
}

// Timestamp ± a duration-in-seconds stays a Timestamp; Timestamp − Timestamp is a
// Duration. Deliberately NO ops that mix Timestamp with a bare `u64` as if it were
// another timestamp — that's the confusion this removes.
impl std::ops::Add<Duration> for Timestamp {
    type Output = Timestamp;
    #[inline]
    fn add(self, d: Duration) -> Timestamp {
        Timestamp(self.0.saturating_add(d.as_secs()))
    }
}
impl std::ops::Sub<Duration> for Timestamp {
    type Output = Timestamp;
    #[inline]
    fn sub(self, d: Duration) -> Timestamp {
        Timestamp(self.0.saturating_sub(d.as_secs()))
    }
}
impl std::ops::Sub<Timestamp> for Timestamp {
    type Output = Duration;
    #[inline]
    fn sub(self, earlier: Timestamp) -> Duration {
        Duration::from_secs(self.0.saturating_sub(earlier.0))
    }
}

impl std::fmt::Display for Timestamp {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_and_accessors() {
        let t = Timestamp::from_secs(1_788_480_000);
        assert_eq!(t.as_secs(), 1_788_480_000);
        assert_eq!(u64::from(t), 1_788_480_000);
        assert_eq!(Timestamp::from(42u64).as_secs(), 42);
    }

    #[test]
    fn arithmetic_is_duration_typed() {
        let a = Timestamp::from_secs(1000);
        let b = a + Duration::from_secs(120);
        assert_eq!(b.as_secs(), 1120);
        assert_eq!((b - a), Duration::from_secs(120));
        assert_eq!(b.saturating_secs_since(a), 120);
        assert_eq!(a.saturating_secs_since(b), 0); // no underflow
    }

    #[test]
    fn borsh_is_wire_transparent_vs_u64() {
        // A single-field Borsh tuple struct serializes exactly as the inner u64,
        // so migrating a serialized field does not change the block layout/hash.
        let secs: u64 = 0x0123_4567_89AB_CDEF;
        let t = Timestamp::from_secs(secs);
        assert_eq!(
            borsh::to_vec(&t).unwrap(),
            borsh::to_vec(&secs).unwrap(),
            "Timestamp must serialize byte-identically to u64"
        );
    }

    #[test]
    fn serde_is_transparent() {
        let t = Timestamp::from_secs(99);
        assert_eq!(serde_json::to_string(&t).unwrap(), "99");
        let back: Timestamp = serde_json::from_str("99").unwrap();
        assert_eq!(back, t);
    }
}
