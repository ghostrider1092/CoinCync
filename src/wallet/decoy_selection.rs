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

pub fn sample_candidate_locators<R: Rng + ?Sized>(
    snapshot: &DecoyDistributionSnapshot,
    min_age: u64,
    count: usize,
    excluded: &HashSet<OutputLocator>,
    rng: &mut R,
) -> Result<Vec<OutputLocator>> {
    if count == 0 {
        return Ok(Vec::new());
    }
    if snapshot.policy_version != DECOY_LOCATOR_POLICY_VERSION {
        return Err(Error::InvalidState(format!(
            "unsupported decoy locator policy version {}",
            snapshot.policy_version
        )));
    }
    let eligible = eligible_heights(snapshot, min_age)?;
    let available = eligible
        .iter()
        .map(|height| height.count as usize)
        .sum::<usize>()
        .saturating_sub(
            excluded
                .iter()
                .filter(|locator| locator_is_in(locator, &eligible))
                .count(),
        );
    if available < count {
        return Err(Error::InsufficientDecoys {
            available,
            needed: count,
        });
    }

    if available == count {
        return Ok(eligible
            .iter()
            .flat_map(|height| {
                (0..height.count).map(move |ordinal| OutputLocator {
                    height: height.height,
                    ordinal,
                })
            })
            .filter(|locator| !excluded.contains(locator))
            .collect());
    }

    let youngest_age = snapshot.snapshot_height - eligible.last().unwrap().height;
    let oldest_age = snapshot.snapshot_height - eligible.first().unwrap().height;
    let gamma = Gamma::new(DECOY_GAMMA_SHAPE, DECOY_GAMMA_SCALE)
        .expect("fixed positive gamma policy parameters");
    let block_time = crate::constants::TARGET_BLOCK_TIME.max(1) as f64;
    let mut selected = HashSet::with_capacity(count);
    let mut result = Vec::with_capacity(count);

    while result.len() < count {
        let sampled_age = (0..DECOY_GAMMA_MAX_RESAMPLES).find_map(|_| {
            let seconds = gamma.sample(rng).exp();
            if !seconds.is_finite() {
                return None;
            }
            let blocks = (seconds / block_time) as u64;
            (youngest_age..=oldest_age)
                .contains(&blocks)
                .then_some(blocks)
        });
        let Some(age) = sampled_age else {
            return Err(Error::InsufficientDecoys {
                available: result.len(),
                needed: count,
            });
        };
        let target_height = snapshot.snapshot_height - age;
        let Some(locator) =
            pick_nearest_locator(target_height, &eligible, excluded, &selected, rng)
        else {
            return Err(Error::InsufficientDecoys {
                available: result.len(),
                needed: count,
            });
        };
        selected.insert(locator);
        result.push(locator);
    }

    Ok(result)
}

pub fn build_covered_request<R: RngCore + CryptoRng + ?Sized>(
    snapshot: &DecoyDistributionSnapshot,
    real_locators: &[OutputLocator],
    ring_size: usize,
    min_age: u64,
    rng: &mut R,
) -> Result<Vec<OutputLocator>> {
    let excluded: HashSet<_> = real_locators.iter().copied().collect();
    if excluded.len() != real_locators.len() {
        return Err(Error::InvalidParams("duplicate real output locator".into()));
    }
    if ring_size < 2 {
        return Err(Error::InvalidRingSize {
            expected: 2,
            got: ring_size,
        });
    }
    let required_slots = real_locators
        .len()
        .checked_mul(ring_size)
        .ok_or_else(|| Error::InvalidParams("covered lookup size overflow".into()))?;
    if required_slots > COVERED_LOOKUP_SIZE {
        return Err(Error::InvalidParams(format!(
            "{} inputs with ring size {} exceed covered lookup size {COVERED_LOOKUP_SIZE}",
            real_locators.len(),
            ring_size
        )));
    }
    if real_locators
        .iter()
        .any(|locator| locator.height > snapshot.snapshot_height)
    {
        return Err(Error::InvalidState(
            "real output locator is above the decoy snapshot".into(),
        ));
    }

    let mut request = real_locators.to_vec();
    request.extend(sample_candidate_locators(
        snapshot,
        min_age,
        COVERED_LOOKUP_SIZE - request.len(),
        &excluded,
        rng,
    )?);
    request.shuffle(rng);
    Ok(request)
}

pub fn validate_covered_response(
    snapshot: &DecoyDistributionSnapshot,
    requested: &[OutputLocator],
    response: &ResolvedDecoySnapshot,
) -> Result<()> {
    if response.snapshot_height != snapshot.snapshot_height
        || response.snapshot_hash != snapshot.snapshot_hash
        || response.policy_version != snapshot.policy_version
    {
        return Err(Error::InvalidState(
            "decoy response snapshot metadata mismatch".into(),
        ));
    }
    if response.outputs.len() != requested.len() {
        return Err(Error::InvalidState(format!(
            "decoy response returned {} outputs for {} locators",
            response.outputs.len(),
            requested.len()
        )));
    }
    if requested.iter().copied().collect::<HashSet<_>>().len() != requested.len() {
        return Err(Error::InvalidState(
            "covered request contains duplicate locators".into(),
        ));
    }
    for (locator, output) in requested.iter().zip(&response.outputs) {
        if output.locator != *locator || output.height != locator.height {
            return Err(Error::InvalidState(
                "decoy response does not preserve requested locator order".into(),
            ));
        }
    }
    Ok(())
}

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

    let max_height = snapshot.snapshot_height.saturating_sub(min_age);
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
                .map_or(true, |height| snapshot.snapshot_height >= height)
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

fn eligible_heights(
    snapshot: &DecoyDistributionSnapshot,
    min_age: u64,
) -> Result<Vec<HeightOutputCount>> {
    let max_height = snapshot
        .snapshot_height
        .checked_sub(min_age)
        .ok_or_else(|| Error::InsufficientDecoys {
            available: 0,
            needed: 1,
        })?;
    let mut previous = None;
    for height in &snapshot.heights {
        if height.count == 0 || previous.is_some_and(|value| height.height <= value) {
            return Err(Error::InvalidState(
                "decoy distribution heights must be strictly increasing and non-empty".into(),
            ));
        }
        if height.height > snapshot.snapshot_height {
            return Err(Error::InvalidState(
                "decoy distribution contains a height above its snapshot".into(),
            ));
        }
        previous = Some(height.height);
    }
    Ok(snapshot
        .heights
        .iter()
        .take_while(|height| height.height <= max_height)
        .cloned()
        .collect())
}

fn locator_is_in(locator: &OutputLocator, heights: &[HeightOutputCount]) -> bool {
    heights
        .binary_search_by_key(&locator.height, |height| height.height)
        .ok()
        .is_some_and(|index| locator.ordinal < heights[index].count)
}

fn pick_nearest_locator<R: Rng + ?Sized>(
    target: u64,
    heights: &[HeightOutputCount],
    excluded: &HashSet<OutputLocator>,
    selected: &HashSet<OutputLocator>,
    rng: &mut R,
) -> Option<OutputLocator> {
    let split = heights.partition_point(|height| height.height <= target);
    let mut lower = split.checked_sub(1);
    let mut upper = split;

    loop {
        let take_lower = match (lower, heights.get(upper)) {
            (Some(low), Some(high)) => {
                let low_distance = target.abs_diff(heights[low].height);
                let high_distance = high.height.abs_diff(target);
                low_distance < high_distance || (low_distance == high_distance && rng.gen_bool(0.5))
            }
            (Some(_), None) => true,
            (None, Some(_)) => false,
            (None, None) => return None,
        };
        let index = if take_lower { lower.unwrap() } else { upper };
        if let Some(locator) = pick_ordinal(&heights[index], excluded, selected, rng) {
            return Some(locator);
        }
        if take_lower {
            lower = index.checked_sub(1);
        } else {
            upper += 1;
        }
    }
}

fn pick_ordinal<R: Rng + ?Sized>(
    height: &HeightOutputCount,
    excluded: &HashSet<OutputLocator>,
    selected: &HashSet<OutputLocator>,
    rng: &mut R,
) -> Option<OutputLocator> {
    for _ in 0..DECOY_GAMMA_MAX_RESAMPLES {
        let locator = OutputLocator {
            height: height.height,
            ordinal: rng.gen_range(0..height.count),
        };
        if !excluded.contains(&locator) && !selected.contains(&locator) {
            return Some(locator);
        }
    }
    (0..height.count)
        .map(|ordinal| OutputLocator {
            height: height.height,
            ordinal,
        })
        .find(|locator| !excluded.contains(locator) && !selected.contains(locator))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::decoy::{ResolvedDecoyOutput, DECOY_LOCATOR_POLICY_VERSION};
    use crate::primitives::{Hash, PublicKey};
    use rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;

    fn snapshot(height: u64, count_per_height: u32) -> DecoyDistributionSnapshot {
        DecoyDistributionSnapshot {
            snapshot_height: height,
            snapshot_hash: Hash::from_bytes([7; 32]),
            policy_version: DECOY_LOCATOR_POLICY_VERSION,
            heights: (0..=height)
                .map(|height| HeightOutputCount {
                    height,
                    count: count_per_height,
                })
                .collect(),
        }
    }

    fn resolved(locator: OutputLocator) -> ResolvedDecoyOutput {
        let mut bytes = [0u8; 32];
        bytes[..8].copy_from_slice(&locator.height.to_le_bytes());
        bytes[8..12].copy_from_slice(&locator.ordinal.to_le_bytes());
        ResolvedDecoyOutput {
            locator,
            public_key: PublicKey::from_bytes(bytes),
            commitment: bytes,
            height: locator.height,
            is_coinbase: false,
            lock_height: None,
        }
    }

    #[test]
    fn gamma_sampling_is_conditioned_and_unique() {
        let snapshot = snapshot(30_000, 1);
        let mut rng = ChaCha20Rng::seed_from_u64(2);
        let mut observed = Vec::with_capacity(2_000);
        for _ in 0..125 {
            let selected =
                sample_candidate_locators(&snapshot, 100, 16, &HashSet::new(), &mut rng).unwrap();
            assert_eq!(selected.iter().copied().collect::<HashSet<_>>().len(), 16);
            assert!(selected.iter().all(|locator| locator.height <= 29_900));
            observed.extend(
                selected
                    .iter()
                    .map(|locator| snapshot.snapshot_height - locator.height),
            );
        }

        let gamma = Gamma::new(DECOY_GAMMA_SHAPE, DECOY_GAMMA_SCALE).unwrap();
        let block_time = crate::constants::TARGET_BLOCK_TIME as f64;
        let mut target_rng = ChaCha20Rng::seed_from_u64(3);
        let mut expected = Vec::with_capacity(observed.len());
        while expected.len() < observed.len() {
            let age = (gamma.sample(&mut target_rng).exp() / block_time) as u64;
            if (100..=30_000).contains(&age) {
                expected.push(age);
            }
        }
        observed.sort_unstable();
        expected.sort_unstable();
        for percentile in [10, 50, 90] {
            let index = (observed.len() - 1) * percentile / 100;
            let actual = observed[index] as f64;
            let target = expected[index] as f64;
            assert!((actual.ln() - target.ln()).abs() < 0.20);
        }
        assert!(observed.iter().filter(|age| **age == 100).count() < 20);
    }

    #[test]
    fn covered_lookup_allocates_transaction_wide_unique_decoys() {
        let snapshot = snapshot(1_000, 1);
        let real = [
            OutputLocator {
                height: 100,
                ordinal: 0,
            },
            OutputLocator {
                height: 200,
                ordinal: 0,
            },
        ];
        let mut rng = ChaCha20Rng::seed_from_u64(5);
        let request = build_covered_request(&snapshot, &real, 16, 10, &mut rng).unwrap();
        assert_eq!(request.len(), COVERED_LOOKUP_SIZE);
        assert!(real.iter().all(|locator| request.contains(locator)));
        assert_eq!(
            request.iter().copied().collect::<HashSet<_>>().len(),
            request.len()
        );

        let mut response = ResolvedDecoySnapshot {
            snapshot_height: snapshot.snapshot_height,
            snapshot_hash: snapshot.snapshot_hash,
            policy_version: snapshot.policy_version,
            outputs: request.iter().copied().map(resolved).collect(),
        };
        let real_outputs: Vec<_> = real
            .iter()
            .copied()
            .map(|locator| {
                let output = resolved(locator);
                RealOutputIdentity {
                    locator,
                    public_key: output.public_key,
                    commitment: output.commitment,
                }
            })
            .collect();
        let colliding = response
            .outputs
            .iter_mut()
            .find(|output| !real.contains(&output.locator))
            .unwrap();
        colliding.public_key = real_outputs[0].public_key;
        let rings = allocate_unique_rings(
            &snapshot,
            &request,
            &response,
            &real_outputs,
            16,
            10,
            &mut rng,
        )
        .unwrap();
        assert_eq!(rings.len(), 2);
        assert!(rings.iter().all(|ring| ring.decoys.len() == 15));
        let left: HashSet<_> = rings[0]
            .decoys
            .iter()
            .map(|decoy| *decoy.public_key.as_bytes())
            .collect();
        let right: HashSet<_> = rings[1]
            .decoys
            .iter()
            .map(|decoy| *decoy.public_key.as_bytes())
            .collect();
        assert!(left.is_disjoint(&right));
        assert!(rings.iter().flat_map(|ring| &ring.decoys).all(|decoy| {
            real_outputs
                .iter()
                .all(|real| decoy.public_key != real.public_key)
        }));
    }

    #[test]
    fn covered_response_rejects_mismatch_and_unusable_request_shape() {
        let snapshot = snapshot(1_000, 1);
        let mut unsupported = snapshot.clone();
        unsupported.policy_version += 1;
        let mut rng = ChaCha20Rng::seed_from_u64(8);
        assert!(sample_candidate_locators(&unsupported, 10, 1, &HashSet::new(), &mut rng).is_err());

        let real: Vec<_> = (0..9)
            .map(|ordinal| OutputLocator {
                height: ordinal,
                ordinal: 0,
            })
            .collect();
        assert!(build_covered_request(&snapshot, &real, 16, 10, &mut rng).is_err());

        let real = [OutputLocator {
            height: 100,
            ordinal: 0,
        }];
        let request = build_covered_request(&snapshot, &real, 16, 10, &mut rng).unwrap();
        let mut response = ResolvedDecoySnapshot {
            snapshot_height: snapshot.snapshot_height,
            snapshot_hash: snapshot.snapshot_hash,
            policy_version: snapshot.policy_version,
            outputs: request.iter().copied().map(resolved).collect(),
        };
        response.outputs.swap(0, 1);
        assert!(validate_covered_response(&snapshot, &request, &response).is_err());

        response.outputs = request.iter().copied().map(resolved).collect();
        let expected = resolved(real[0]);
        let real_identity = [RealOutputIdentity {
            locator: real[0],
            public_key: expected.public_key,
            commitment: expected.commitment,
        }];
        let real_output = response
            .outputs
            .iter_mut()
            .find(|output| output.locator == real[0])
            .unwrap();
        real_output.public_key = PublicKey::from_bytes([0xFF; 32]);
        assert!(allocate_unique_rings(
            &snapshot,
            &request,
            &response,
            &real_identity,
            16,
            10,
            &mut rng,
        )
        .is_err());
    }
}
