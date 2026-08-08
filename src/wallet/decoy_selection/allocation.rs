use super::error::{DecoySelectionError, DecoySelectionResult};
use super::types::{
    AllocatedRing, AllocatedRings, RealOutputIdentity, ValidatedCoveredResponse,
};
use crate::transaction::DecoyOutput;
use rand::seq::SliceRandom;
use rand::{CryptoRng, Rng, RngCore};
use std::collections::HashSet;

pub fn allocate_unique_rings<R: RngCore + CryptoRng + ?Sized>(
    response: ValidatedCoveredResponse,
    real_outputs: &[RealOutputIdentity],
    rng: &mut R,
) -> DecoySelectionResult<AllocatedRings> {
    let request = response.request();
    if real_outputs.len() != request.real_locators().len()
        || !real_outputs
            .iter()
            .map(|output| output.locator())
            .eq(request.real_locators().iter().copied())
    {
        return Err(DecoySelectionError::RealOutputSetMismatch);
    }

    let mut used_public_keys = HashSet::with_capacity(real_outputs.len());
    for real in real_outputs {
        let resolved = response
            .resolved(&real.locator())
            .ok_or(DecoySelectionError::MissingRealOutput(real.locator()))?;
        if resolved.public_key != real.public_key()
            || resolved.commitment != real.commitment()
        {
            return Err(DecoySelectionError::RealOutputIdentityMismatch(
                real.locator(),
            ));
        }
        if !used_public_keys.insert(*real.public_key().as_bytes()) {
            return Err(DecoySelectionError::DuplicateRealPublicKey);
        }
    }

    let spend_height = request.spend_height();
    let max_decoy_height = request.max_decoy_height();
    let mut candidates: Vec<_> = response
        .outputs()
        .iter()
        .filter(|output| !request.real_locator_set().contains(&output.locator))
        .filter(|output| {
            max_decoy_height.is_some_and(|height| output.locator.height <= height)
        })
        .filter(|output| {
            output
                .lock_height
                .map_or(true, |height| spend_height >= height)
        })
        .filter(|output| used_public_keys.insert(*output.public_key.as_bytes()))
        .collect();

    let ring_size = request.ring_size();
    let decoys_per_ring = ring_size - 1;
    let needed = real_outputs
        .len()
        .checked_mul(decoys_per_ring)
        .ok_or(DecoySelectionError::RingAllocationSizeOverflow {
            input_count: real_outputs.len(),
            ring_size,
        })?;
    if candidates.len() < needed {
        return Err(DecoySelectionError::InsufficientDecoys {
            available: candidates.len(),
            needed,
        });
    }
    candidates.shuffle(rng);

    let rings = (0..real_outputs.len())
        .map(|ring_index| {
            let start = ring_index * decoys_per_ring;
            let decoys = candidates[start..start + decoys_per_ring]
                .iter()
                .map(|output| DecoyOutput {
                    public_key: output.public_key,
                    commitment: output.commitment,
                    height: output.locator.height,
                })
                .collect();
            AllocatedRing::new(decoys, rng.gen_range(0..ring_size))
        })
        .collect();

    Ok(AllocatedRings::new(
        ring_size,
        real_outputs.to_vec(),
        rings,
    ))
}
