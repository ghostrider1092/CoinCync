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

mod allocation;
mod error;
mod sampling;
mod snapshot;
mod types;
mod validation;

pub use allocation::allocate_unique_rings;
pub use error::{DecoySelectionError, DecoySelectionResult};
pub use sampling::{build_covered_request, sample_candidate_locators};
pub use types::{
    AllocatedRing, AllocatedRings, CoveredRequest, RealOutputIdentity, SnapshotId,
    ValidatedCoveredResponse, ValidatedDecoySnapshot,
};
pub use validation::validate_covered_response;

#[cfg(test)]
mod tests;
