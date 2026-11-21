//! Catalog-backed `CYNC-POW` diagnostics for the Observe phase.
//!
//! Turns the Observe telemetry ([`BobtailObservation`] / [`ViewDivergence`]) into
//! `crate::diagnostics::Report`s drawn from the stable catalog, so the Observe
//! phase surfaces the two risks that must be understood before Enforce — slot
//! concentration (`CYNC-POW-004`) and partial-view divergence (`CYNC-POW-005`) —
//! on the same diagnostics bus as every other subsystem. Detection-only: a Report
//! is a log line / `coincync-diag` entry, never a rejection.

use super::{BobtailObservation, ViewDivergence};
use crate::diagnostics::{Report, CYNC_POW_004, CYNC_POW_005};

/// A slot-concentration report when one miner holds a **majority** of the `K`
/// slots in the current canonical set. `None` below quorum or when the set is
/// adequately spread.
pub fn concentration_report(obs: &BobtailObservation) -> Option<Report> {
    let h = obs.health.as_ref()?;
    if h.max_owner_slots.saturating_mul(2) > obs.k {
        return Some(
            Report::new(CYNC_POW_004)
                .at(format!("share pool: {} shares, K={}", obs.pool_size, obs.k))
                .expected(format!("<= {} of {} slots per miner", obs.k / 2, obs.k))
                .got(format!(
                    "{} of {} slots to one miner ({} distinct owners)",
                    h.max_owner_slots, obs.k, h.distinct_owners
                )),
        );
    }
    None
}

/// A view-divergence report when a block omits a share this node ranks
/// canonically lower (it would reject the block under Enforce), or uses shares
/// this node never saw. `None` when the views agree. Wired at Enforce (a block
/// carries a share set); provided + tested now for completeness.
pub fn divergence_report(div: &ViewDivergence) -> Option<Report> {
    if div.omitted_lower > 0 || div.unseen_in_pool > 0 {
        return Some(
            Report::new(CYNC_POW_005)
                .expected("block uses the globally K-lowest shares this node holds")
                .got(format!(
                    "{} lower share(s) omitted, {} block share(s) unseen locally",
                    div.omitted_lower, div.unseen_in_pool
                )),
        );
    }
    None
}

/// Throttle gate: true at most once per [`MIN_INTERVAL_SECS`], so the Observe
/// diagnostic is computed/emitted at a bounded rate rather than per share batch.
pub fn observe_due() -> bool {
    use std::sync::atomic::{AtomicU64, Ordering};
    const MIN_INTERVAL_SECS: u64 = 60;
    static LAST: AtomicU64 = AtomicU64::new(0);
    let now = crate::clock::unix_now();
    let last = LAST.load(Ordering::Relaxed);
    if now.saturating_sub(last) < MIN_INTERVAL_SECS {
        return false;
    }
    // CAS so two concurrent callers don't both emit for the same window.
    LAST.compare_exchange(last, now, Ordering::Relaxed, Ordering::Relaxed)
        .is_ok()
}

#[cfg(test)]
mod tests {
    use super::super::health::BobtailHealth;
    use super::*;

    fn obs_with(k: usize, max_owner_slots: usize, distinct_owners: usize) -> BobtailObservation {
        BobtailObservation {
            k,
            pool_size: k + 3,
            canonical_set: Vec::new(),
            meets_bar: true,
            proposer: None,
            lottery_winner: None,
            health: Some(BobtailHealth {
                distinct_owners,
                max_owner_slots,
                bar_fill_bps: 5000,
            }),
        }
    }

    #[test]
    fn concentration_fires_on_a_majority_only() {
        // 11 of 20 slots to one miner → majority → fires.
        assert!(concentration_report(&obs_with(20, 11, 5)).is_some());
        // 10 of 20 (exactly half) → not a majority → silent.
        assert!(concentration_report(&obs_with(20, 10, 6)).is_none());
        // well spread → silent.
        assert!(concentration_report(&obs_with(20, 3, 12)).is_none());
    }

    #[test]
    fn concentration_silent_below_quorum() {
        let mut obs = obs_with(20, 20, 1);
        obs.health = None; // below quorum
        assert!(concentration_report(&obs).is_none());
    }

    #[test]
    fn divergence_fires_on_omission_or_unseen() {
        assert!(divergence_report(&ViewDivergence {
            agrees: false,
            omitted_lower: 1,
            unseen_in_pool: 0,
        })
        .is_some());
        assert!(divergence_report(&ViewDivergence {
            agrees: false,
            omitted_lower: 0,
            unseen_in_pool: 2,
        })
        .is_some());
        assert!(divergence_report(&ViewDivergence {
            agrees: true,
            omitted_lower: 0,
            unseen_in_pool: 0,
        })
        .is_none());
    }

    #[test]
    fn reports_render_their_catalog_code() {
        let r = concentration_report(&obs_with(20, 15, 3)).unwrap();
        assert_eq!(r.diagnostic().code, CYNC_POW_004);
        assert!(r.to_string().contains("CYNC-POW-004"));
    }
}
