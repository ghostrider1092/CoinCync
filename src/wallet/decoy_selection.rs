use crate::decoy::OutputLocator;
use crate::primitives::PublicKey;
use crate::transaction::DecoyOutput;

#[cfg(test)]
use crate::decoy::{DecoyDistributionSnapshot, HeightOutputCount, ResolvedDecoySnapshot};
#[cfg(test)]
use rand_distr::{Distribution, Gamma};
#[cfg(test)]
use std::collections::HashSet;

pub const COVERED_LOOKUP_SIZE: usize = 128;
pub const DECOY_GAMMA_SHAPE: f64 = 19.28;
pub const DECOY_GAMMA_SCALE: f64 = 1.0 / 1.61;
const DECOY_GAMMA_MAX_RESAMPLES: usize = 128;

#[derive(Clone)]
pub struct AllocatedRing {
    pub decoys: Vec<DecoyOutput>,
    pub real_position: usize,
}

#[derive(Clone, Copy)]
pub struct RealOutputIdentity {
    pub locator: OutputLocator,
    pub public_key: PublicKey,
    pub commitment: [u8; 32],
}

mod allocation;
mod sampling;
mod snapshot;
mod validation;

pub use allocation::allocate_unique_rings;
pub use sampling::{build_covered_request, sample_candidate_locators};
pub use validation::validate_covered_response;

#[cfg(test)]
mod tests;
