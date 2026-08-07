use super::snapshot::{
    eligible_heights, locator_is_in, snapshot_spend_height, validate_policy_version,
};
use super::{
    COVERED_LOOKUP_SIZE, DECOY_GAMMA_MAX_RESAMPLES, DECOY_GAMMA_SCALE, DECOY_GAMMA_SHAPE,
};
use crate::decoy::{DecoyDistributionSnapshot, HeightOutputCount, OutputLocator};
use crate::error::{Error, Result};
use rand::seq::SliceRandom;
use rand::{CryptoRng, Rng, RngCore};
use rand_distr::{Distribution, Gamma};
use std::collections::HashSet;

pub fn sample_candidate_locators<R: Rng + ?Sized>(
    snapshot: &DecoyDistributionSnapshot,
    min_age: u64,
    count: usize,
    excluded: &HashSet<OutputLocator>,
    rng: &mut R,
) -> Result<Vec<OutputLocator>> {
    if count == 0 {
        validate_policy_version(snapshot)?;
        return Ok(Vec::new());
    }

    let eligible = eligible_heights(snapshot, min_age)?;
    let spend_height = snapshot_spend_height(snapshot)?;
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

    let youngest_age = spend_height - eligible.last().expect("eligible pool is non-empty").height;
    let oldest_age = spend_height - eligible.first().expect("eligible pool is non-empty").height;
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
        let target_height = spend_height - age;
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

    let all_heights = eligible_heights(snapshot, 0)?;
    if real_locators
        .iter()
        .any(|locator| !locator_is_in(locator, &all_heights))
    {
        return Err(Error::InvalidState(
            "real output locator is not present in the decoy snapshot".into(),
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
        let index = if take_lower { lower? } else { upper };
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
