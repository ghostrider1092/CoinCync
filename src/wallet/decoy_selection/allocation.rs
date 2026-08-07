use super::snapshot::snapshot_spend_height;
use super::validation::validate_covered_response;
use super::{AllocatedRing, RealOutputIdentity};
use crate::decoy::{DecoyDistributionSnapshot, OutputLocator, ResolvedDecoySnapshot};
use crate::error::{Error, Result};
use crate::transaction::DecoyOutput;
use rand::seq::SliceRandom;
use rand::{CryptoRng, Rng, RngCore};
use std::collections::HashSet;

pub fn allocate_unique_rings<R: RngCore + CryptoRng + ?Sized>(
    snapshot: &DecoyDistributionSnapshot,
    requested: &[OutputLocator],
    response: &ResolvedDecoySnapshot,
    real_outputs: &[RealOutputIdentity],
    ring_size: usize,
    min_age: u64,
    rng: &mut R,
) -> Result<Vec<AllocatedRing>> {
    validate_covered_response(snapshot, requested, response)?;
    if ring_size < 2 {
        return Err(Error::InvalidRingSize {
            expected: 2,
            got: ring_size,
        });
    }

    let real_set: HashSet<_> = real_outputs.iter().map(|output| output.locator).collect();
    if real_set.len() != real_outputs.len() {
        return Err(Error::InvalidParams("duplicate real output locator".into()));
    }

    let response_set: HashSet<_> = response
        .outputs
        .iter()
        .map(|output| output.locator)
        .collect();
    if !real_set.is_subset(&response_set) {
        return Err(Error::InvalidState(
            "covered response is missing a real output locator".into(),
        ));
    }

    for real in real_outputs {
        let resolved = response
            .outputs
            .iter()
            .find(|output| output.locator == real.locator)
            .expect("real locator subset checked above");
        if resolved.public_key != real.public_key || resolved.commitment != real.commitment {
            return Err(Error::InvalidState(
                "real output locator resolved to unexpected output".into(),
            ));
        }
    }

    let spend_height = snapshot_spend_height(snapshot)?;
    let max_height = spend_height.saturating_sub(min_age);
    let mut public_keys: HashSet<_> = real_outputs
        .iter()
        .map(|output| *output.public_key.as_bytes())
        .collect();
    let mut candidates: Vec<_> = response
        .outputs
        .iter()
        .filter(|output| !real_set.contains(&output.locator))
        .filter(|output| output.height <= max_height)
        .filter(|output| {
            output
                .lock_height
                .map_or(true, |height| spend_height >= height)
        })
        .filter(|output| public_keys.insert(*output.public_key.as_bytes()))
        .collect();

    let decoys_per_ring = ring_size - 1;
    let needed = real_outputs
        .len()
        .checked_mul(decoys_per_ring)
        .ok_or_else(|| Error::InvalidParams("ring allocation size overflow".into()))?;
    if candidates.len() < needed {
        return Err(Error::InsufficientDecoys {
            available: candidates.len(),
            needed,
        });
    }
    candidates.shuffle(rng);

    Ok((0..real_outputs.len())
        .map(|ring_index| {
            let start = ring_index * decoys_per_ring;
            let decoys = candidates[start..start + decoys_per_ring]
                .iter()
                .map(|output| DecoyOutput {
                    public_key: output.public_key,
                    commitment: output.commitment,
                    height: output.height,
                })
                .collect();
            AllocatedRing {
                decoys,
                real_position: rng.gen_range(0..ring_size),
            }
        })
        .collect())
}
