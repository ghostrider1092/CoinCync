use crate::decoy::{
    DecoyDistributionSnapshot, HeightOutputCount, OutputLocator, ResolvedDecoySnapshot,
    DECOY_LOCATOR_POLICY_VERSION,
};
use crate::error::{Error, Result};
use crate::primitives::PublicKey;
use crate::transaction::DecoyOutput;
use rand::seq::SliceRandom;
use rand::{CryptoRng, Rng, RngCore};
use rand_distr::{Distribution, Gamma};
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


// These implementation fragments share this module's private scope. Keeping
// sampling, response validation, and allocation separate makes the privacy
// boundaries easier to audit without widening helper visibility.
include!("decoy_selection/sampling_and_validation.rs");
include!("decoy_selection/allocation_and_helpers.rs");

#[cfg(test)]
mod tests;
