//! Untrusted-telemetry handling.
//!
//! Every colony signal derived from *peer-supplied* data (a peer's advertised
//! tip, a sentinel reading assembled from remote behavior) is wrapped in
//! [`Untrusted`] at ingest. There is no `Deref`, no `into_inner`, and no public
//! field — the **only** way to get the value out is through a clamping
//! sanitizer in this module. This makes "treat peer input as adversarial" a
//! type-level requirement rather than a convention (colony README §Prime
//! Privacy Invariant / B.3): a caste core cannot be handed raw, unclamped peer
//! telemetry even by mistake.

use crate::colony::spider::SentinelReading;
use tick::ChainTipState;

/// A value carrying unvalidated, peer-influenced data. Opaque by design.
pub struct Untrusted<T>(T);

impl<T> Untrusted<T> {
    /// Wrap raw peer-supplied telemetry. This is the only constructor and the
    /// value can leave only via a sanitizer below.
    pub fn new(raw: T) -> Self {
        Self(raw)
    }
}

/// Absolute ceilings a well-behaved node could never exceed; anything larger is
/// a lying or broken peer and is clamped rather than trusted.
const MAX_INBOUND_PER_MIN: u32 = 100_000;
const MAX_TIP_AGE_SECS: u64 = 60 * 60 * 24 * 30; // 30 days
const MAX_PEER_COUNT: u32 = 100_000;

/// Clamp a peer-derived [`SentinelReading`] into valid ranges before it reaches
/// the spider core: percentages to `0..=100`, inbound rate to a sane cap. A
/// peer that reports `duplicate_msg_pct = 250` to fake a flood is clamped to
/// 100, so it can at most report the *maximum* honest value — never an
/// out-of-band one that could skew a threshold.
pub fn sanitize_reading(raw: Untrusted<SentinelReading>) -> SentinelReading {
    let r = raw.0;
    SentinelReading {
        inbound_new_per_min: r.inbound_new_per_min.min(MAX_INBOUND_PER_MIN),
        largest_netgroup_pct: r.largest_netgroup_pct.min(100),
        duplicate_msg_pct: r.duplicate_msg_pct.min(100),
        unreachable_sentinel_pct: r.unreachable_sentinel_pct.min(100),
    }
}

/// Clamp the colony-relevant fields of a peer-advertised tip state. Height and
/// cumulative difficulty are left untouched — fork choice validates those; the
/// colony only reads `tip_age_secs`/`peer_count`, so those are the fields a
/// caste could be skewed by and the ones bounded here.
pub fn sanitize_tip<Id>(raw: Untrusted<ChainTipState<Id>>) -> ChainTipState<Id> {
    let mut t = raw.0;
    t.tip_age_secs = t.tip_age_secs.min(MAX_TIP_AGE_SECS);
    t.peer_count = t.peer_count.min(MAX_PEER_COUNT);
    t
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn out_of_range_reading_is_clamped() {
        let bogus = SentinelReading {
            inbound_new_per_min: u32::MAX,
            largest_netgroup_pct: 250,
            duplicate_msg_pct: 200,
            unreachable_sentinel_pct: 101,
        };
        let clean = sanitize_reading(Untrusted::new(bogus));
        assert_eq!(clean.inbound_new_per_min, MAX_INBOUND_PER_MIN);
        assert_eq!(clean.largest_netgroup_pct, 100);
        assert_eq!(clean.duplicate_msg_pct, 100);
        assert_eq!(clean.unreachable_sentinel_pct, 100);
    }

    #[test]
    fn in_range_reading_is_unchanged() {
        let ok = SentinelReading {
            inbound_new_per_min: 42,
            largest_netgroup_pct: 30,
            duplicate_msg_pct: 5,
            unreachable_sentinel_pct: 12,
        };
        let clean = sanitize_reading(Untrusted::new(ok.clone()));
        assert_eq!(clean, ok);
    }

    #[test]
    fn tip_age_and_peer_count_capped() {
        let t = ChainTipState {
            height: 100,
            difficulty: 5,
            tip_id: [0u8; 32],
            is_synced: true,
            peer_count: u32::MAX,
            tip_age_secs: u64::MAX,
        };
        let clean = sanitize_tip(Untrusted::new(t));
        assert_eq!(clean.tip_age_secs, MAX_TIP_AGE_SECS);
        assert_eq!(clean.peer_count, MAX_PEER_COUNT);
        assert_eq!(clean.height, 100); // untouched
    }
}
