//! Colony sensor — the "spider/termite" sensing layer, **Phase 1 (observe)**.
//!
//! Classifies the fleet's [`AggregateFleetHealth`] — **public topology and
//! health facts** (tip divergence, stalled hosts, peer connectivity) — into
//! a coarse network-state signal, and (in observe mode) logs it. This is the
//! detection input that a future termite-healing phase would act on.
//!
//! Read-only, non-consensus, and — like every colony caste — it consumes
//! **no transaction data**: `AggregateFleetHealth` carries per-host counts
//! and difficulty only, never anything transaction-derived.

use tick::AggregateFleetHealth;

/// Coarse network-state read from the aggregate fleet health.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum NetSignal {
    /// No thresholds tripped.
    Healthy,
    /// Some concern, but not a split (reasons attached).
    Degraded(Vec<&'static str>),
    /// Widespread tip divergence — a possible network partition.
    PartitionSuspected(Vec<&'static str>),
}

// Thresholds as a percentage of total hosts (integer math, deterministic).
const DIVERGENT_PCT_ALERT: u16 = 34; // > 1/3 of hosts on a divergent tip
const STALLED_PCT_ALERT: u16 = 34; // > 1/3 of hosts stalled
const LOW_PEER_PCT_ALERT: u16 = 50; // >= 1/2 of hosts low on peers

/// Classify aggregate fleet health into a [`NetSignal`].
///
/// Widespread tip divergence is the partition signature; stalled hosts and
/// low peer connectivity are degradation signals. With no hosts (personal
/// mode / empty fleet) the result is `Healthy` by definition.
pub fn classify(agg: &AggregateFleetHealth) -> NetSignal {
    if agg.total_hosts == 0 {
        return NetSignal::Healthy;
    }
    let pct = |n: u16| -> u16 {
        // n, total_hosts are small u16 counts; the product fits u32.
        (u32::from(n) * 100 / u32::from(agg.total_hosts)) as u16
    };

    let divergent = pct(agg.divergent_count);
    let stalled = pct(agg.stalled_count);
    let low_peer = pct(agg.low_peer_count);

    let mut reasons: Vec<&'static str> = Vec::new();
    if divergent >= DIVERGENT_PCT_ALERT {
        reasons.push("divergent-tips");
    }
    if stalled >= STALLED_PCT_ALERT {
        reasons.push("stalled-hosts");
    }
    if low_peer >= LOW_PEER_PCT_ALERT {
        reasons.push("low-peer-connectivity");
    }

    if divergent >= DIVERGENT_PCT_ALERT {
        NetSignal::PartitionSuspected(reasons)
    } else if reasons.is_empty() {
        NetSignal::Healthy
    } else {
        NetSignal::Degraded(reasons)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn agg(total: u16, divergent: u16, stalled: u16, low_peer: u16) -> AggregateFleetHealth {
        AggregateFleetHealth {
            total_hosts: total,
            stalled_count: stalled,
            low_peer_count: low_peer,
            divergent_count: divergent,
            median_difficulty: 1,
            high_ram_count: 0,
            high_disk_count: 0,
        }
    }

    #[test]
    fn empty_fleet_is_healthy() {
        assert_eq!(classify(&agg(0, 0, 0, 0)), NetSignal::Healthy);
    }

    #[test]
    fn all_good_is_healthy() {
        assert_eq!(classify(&agg(6, 0, 0, 0)), NetSignal::Healthy);
    }

    #[test]
    fn widespread_divergence_is_partition() {
        // 3 of 6 hosts divergent = 50% >= 34% -> partition suspected.
        match classify(&agg(6, 3, 0, 0)) {
            NetSignal::PartitionSuspected(r) => assert!(r.contains(&"divergent-tips")),
            other => panic!("expected PartitionSuspected, got {:?}", other),
        }
    }

    #[test]
    fn stalled_without_divergence_is_degraded() {
        match classify(&agg(6, 0, 3, 0)) {
            NetSignal::Degraded(r) => assert!(r.contains(&"stalled-hosts")),
            other => panic!("expected Degraded, got {:?}", other),
        }
    }

    #[test]
    fn low_peer_majority_is_degraded() {
        match classify(&agg(6, 0, 0, 3)) {
            NetSignal::Degraded(r) => assert!(r.contains(&"low-peer-connectivity")),
            other => panic!("expected Degraded, got {:?}", other),
        }
    }

    #[test]
    fn one_divergent_of_six_is_not_partition() {
        // 1/6 = 16% < 34% -> not a partition, not degraded on that axis.
        assert_eq!(classify(&agg(6, 1, 0, 0)), NetSignal::Healthy);
    }
}
