//! spider — sentinel web (attack-signature detection).
//!
//! A spider doesn't chase; it reads the vibrations in its web. This caste
//! reads **public network vibrations** — inbound-connection rate, how
//! concentrated inbound peers are in one netgroup, duplicate-message churn,
//! sentinel-peer reachability — and classifies them into coarse **attack
//! signatures**: eclipse pressure, flood pattern, partition onset. It is
//! the *sensory organ* the colony's termite-healing acts on.
//!
//! ## Reads public signals only
//!
//! Every input here is a count or a percentage of **connection/topology**
//! facts. The spider never inspects message *content* and never sees a
//! transaction — it feels the shape of the traffic, not what it carries.
//! Same Prime Privacy Invariant as the rest of the suite (see `mod.rs`).
//!
//! ## Detection ≠ action (rule D.5)
//!
//! A tripped signature is a *hint*, not a verdict. It feeds healing
//! (add diverse peers) and telemetry — it is never on its own a ban or
//! tarpit reason. False positives here cost a redundant reconnect, not a
//! disconnected honest peer.
//!
//! Integer / deterministic thresholds — same style as [`super::sensor`],
//! but cast-clean (all comparisons in the widest input type).

/// A reading off the sentinel web — public connection/topology metrics.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SentinelReading {
    /// New inbound connections accepted in the last minute.
    pub inbound_new_per_min: u32,
    /// Share of inbound peers concentrated in the single largest netgroup,
    /// as a percentage `0..=100`. High concentration is the eclipse tell.
    pub largest_netgroup_pct: u8,
    /// Percentage `0..=100` of recently-received messages that were
    /// duplicates. A flood/amplification signature.
    pub duplicate_msg_pct: u8,
    /// Percentage `0..=100` of long-lived sentinel peers currently
    /// unreachable. A rising value is the partition-onset tell.
    pub unreachable_sentinel_pct: u8,
}

/// A detected attack signature. Absence of any is "calm".
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum ThreatSignature {
    /// Inbound peers concentrated in one netgroup — classic eclipse setup.
    EclipsePressure,
    /// Excess new connections and/or duplicate-message churn — flooding.
    FloodPattern,
    /// Many sentinel peers gone dark — a split may be forming.
    PartitionOnset,
}

/// Inbound peers this concentrated in one netgroup trip eclipse pressure
/// (percent). Half of inbound from a single routable group is well past
/// what an honest topology produces.
pub const ECLIPSE_NETGROUP_PCT: u8 = 50;
/// New inbound connections per minute above this trip a flood signature.
pub const FLOOD_CONN_PER_MIN: u32 = 120;
/// Duplicate-message percentage above this also trips a flood signature.
pub const FLOOD_DUPLICATE_PCT: u8 = 60;
/// Unreachable-sentinel percentage above this trips partition onset.
pub const PARTITION_UNREACHABLE_PCT: u8 = 50;

/// Classify a [`SentinelReading`] into the set of tripped signatures,
/// deterministically ordered (so the result is stable and easy to assert
/// on). An empty result means "calm".
pub fn assess(r: &SentinelReading) -> Vec<ThreatSignature> {
    let mut out = Vec::new();
    if r.largest_netgroup_pct >= ECLIPSE_NETGROUP_PCT {
        out.push(ThreatSignature::EclipsePressure);
    }
    if r.inbound_new_per_min >= FLOOD_CONN_PER_MIN || r.duplicate_msg_pct >= FLOOD_DUPLICATE_PCT {
        out.push(ThreatSignature::FloodPattern);
    }
    if r.unreachable_sentinel_pct >= PARTITION_UNREACHABLE_PCT {
        out.push(ThreatSignature::PartitionOnset);
    }
    out
}

/// Convenience: is the reading free of any tripped signature?
pub fn is_calm(r: &SentinelReading) -> bool {
    assess(r).is_empty()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quiet_web_is_calm() {
        let r = SentinelReading {
            inbound_new_per_min: 10,
            largest_netgroup_pct: 20,
            duplicate_msg_pct: 5,
            unreachable_sentinel_pct: 10,
        };
        assert!(is_calm(&r));
        assert!(assess(&r).is_empty());
    }

    #[test]
    fn netgroup_concentration_trips_eclipse_pressure() {
        let r = SentinelReading { largest_netgroup_pct: ECLIPSE_NETGROUP_PCT, ..Default::default() };
        assert_eq!(assess(&r), vec![ThreatSignature::EclipsePressure]);
    }

    #[test]
    fn high_conn_rate_trips_flood() {
        let r = SentinelReading { inbound_new_per_min: FLOOD_CONN_PER_MIN, ..Default::default() };
        assert_eq!(assess(&r), vec![ThreatSignature::FloodPattern]);
    }

    #[test]
    fn duplicate_churn_also_trips_flood() {
        let r = SentinelReading { duplicate_msg_pct: FLOOD_DUPLICATE_PCT, ..Default::default() };
        assert_eq!(assess(&r), vec![ThreatSignature::FloodPattern]);
    }

    #[test]
    fn dark_sentinels_trip_partition_onset() {
        let r =
            SentinelReading { unreachable_sentinel_pct: PARTITION_UNREACHABLE_PCT, ..Default::default() };
        assert_eq!(assess(&r), vec![ThreatSignature::PartitionOnset]);
    }

    #[test]
    fn thresholds_are_inclusive_but_below_is_calm() {
        let just_below = SentinelReading {
            inbound_new_per_min: FLOOD_CONN_PER_MIN - 1,
            largest_netgroup_pct: ECLIPSE_NETGROUP_PCT - 1,
            duplicate_msg_pct: FLOOD_DUPLICATE_PCT - 1,
            unreachable_sentinel_pct: PARTITION_UNREACHABLE_PCT - 1,
        };
        assert!(is_calm(&just_below), "one below every threshold must be calm");
    }

    #[test]
    fn combined_attack_reports_all_signatures_in_order() {
        let r = SentinelReading {
            inbound_new_per_min: 500,
            largest_netgroup_pct: 90,
            duplicate_msg_pct: 80,
            unreachable_sentinel_pct: 70,
        };
        // Deterministic order: Eclipse, Flood, Partition.
        assert_eq!(
            assess(&r),
            vec![
                ThreatSignature::EclipsePressure,
                ThreatSignature::FloodPattern,
                ThreatSignature::PartitionOnset
            ]
        );
    }
}
