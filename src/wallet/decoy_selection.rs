//! Typed wallet-owned decoy selection.
//!
//! Raw node snapshots and responses are accepted only at this module's
//! boundary. Each successful stage returns a type that carries the invariants
//! required by the next stage, preventing snapshot, request, response and ring
//! metadata from being recombined arbitrarily.

pub const COVERED_LOOKUP_SIZE: usize = 128;
pub const DECOY_GAMMA_SHAPE: f64 = 19.28;
pub const DECOY_GAMMA_SCALE: f64 = 1.0 / 1.61;
const DECOY_GAMMA_MAX_RESAMPLES: usize = 128;

/// Result of auditing a just-built ring's decoy age distribution.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RingAudit {
    /// False when the ring looks weak/fingerprintable.
    pub ok: bool,
    /// Number of distinct age "decades" (orders of magnitude) the members span.
    pub distinct_age_decades: usize,
    /// max age − min age, in blocks.
    pub age_spread: u64,
    /// Why the ring was flagged, if it was.
    pub reason: Option<&'static str>,
}

/// Post-build ring self-audit (advisory, wallet-side): flag a ring whose decoy
/// ages cluster in a single order of magnitude — a weak ring that makes the
/// real spend easier to distinguish. Consensus never inspects selection quality
/// (only membership/size/maturity), so this is purely a wallet lint the caller
/// can use to warn or rebuild. Heuristic; rings smaller than 3 are treated as
/// OK (bootstrap). See docs/design/ring-self-audit.md.
pub fn audit_ring_ages(member_heights: &[u64], spend_height: u64) -> RingAudit {
    if member_heights.len() < 3 {
        return RingAudit {
            ok: true,
            distinct_age_decades: 0,
            age_spread: 0,
            reason: None,
        };
    }
    let ages: Vec<u64> = member_heights
        .iter()
        .map(|h| spend_height.saturating_sub(*h))
        .collect();
    let min = *ages.iter().min().unwrap();
    let max = *ages.iter().max().unwrap();
    let age_spread = max - min;
    let mut decades = std::collections::BTreeSet::new();
    for a in &ages {
        // Order-of-magnitude bucket of the age (age 0 → bucket 0).
        decades.insert((*a as f64 + 1.0).log10() as u32);
    }
    let distinct_age_decades = decades.len();
    let (ok, reason) = if distinct_age_decades < 2 {
        (false, Some("ring decoy ages cluster in a single order of magnitude"))
    } else {
        (true, None)
    };
    RingAudit {
        ok,
        distinct_age_decades,
        age_spread,
        reason,
    }
}

mod allocation;
mod error;
mod sampling;
mod snapshot;
mod types;
mod validation;

pub use allocation::allocate_unique_rings;
pub use error::{DecoySelectionError, DecoySelectionResult};
pub use sampling::{
    build_covered_request, sample_candidate_locators, sample_candidate_locators_empirical,
};
pub use types::{
    AllocatedRing, AllocatedRings, CoveredRequest, RealOutputIdentity, SnapshotId,
    ValidatedCoveredResponse, ValidatedDecoySnapshot,
};
pub use validation::validate_covered_response;

#[cfg(test)]
mod tests;
