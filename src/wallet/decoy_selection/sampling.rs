//! Decoy candidate sampling and covered-request construction.
//!
//! ## Audit map
//! Each `§` is a code section below; it states the INVARIANT it guarantees, the
//! THREAT it defends, and the TESTS that prove it.
//!
//! - **§1 `sample_candidate_locators`** — INVARIANT: decoy ages are drawn from
//!   the Gamma(19.28, 1/1.61) log-seconds age distribution (converted to blocks),
//!   so the real spend's age is statistically indistinguishable from its decoys.
//!   THREAT: biased age sampling makes the real input identifiable by age;
//!   ring-selection determinism regressions (incident 1d27d3c8).
//!   TESTS: `gamma_sampling_is_conditioned_and_unique`,
//!   `decoy_age_distribution_matches_independent_gamma_reference_wallet_c1`.
//! - **§2 `min_age eligibility`** — INVARIANT: only outputs at least `min_age`
//!   blocks old, measured at the next spend height, are eligible as decoys.
//!   THREAT: too-young decoys shrink the anonymity set and leak spend timing.
//!   TESTS: `minimum_age_is_measured_at_the_next_spend_height`.
//! - **§3 `build_covered_request`** — INVARIANT: real locators are padded with
//!   unique decoys up to `COVERED_LOOKUP_SIZE`, shuffled, and bound to the
//!   snapshot id and ring policy. THREAT: unbound or duplicated locators reveal
//!   which ring member is real. TESTS: `covered_request_binds_snapshot_and_policy`,
//!   `covered_lookup_allocates_transaction_wide_unique_decoys`.
//! - **§4 `request bounds`** — INVARIANT: real locators must exist in the
//!   snapshot and required slots must not exceed `COVERED_LOOKUP_SIZE`.
//!   THREAT: out-of-snapshot or overflowing requests yield malformed rings.
//!   TESTS: `covered_request_rejects_a_real_locator_outside_the_snapshot`,
//!   `covered_request_rejects_capacity_overflow`.
//! - **§5 `pick_nearest_locator`** — INVARIANT: a sampled target age maps to the
//!   nearest eligible height, breaking ties uniformly at random.
//!   THREAT: deterministic tie-breaking biases decoy positions.
//!   TESTS: `gamma_sampling_is_conditioned_and_unique`.
//! - **§6 `pick_ordinal`** — INVARIANT: every chosen decoy is unique — never a
//!   real, excluded, or already-selected output. THREAT: duplicate/real reuse
//!   links the transaction's inputs. TESTS:
//!   `covered_lookup_allocates_transaction_wide_unique_decoys`,
//!   `gamma_sampling_is_conditioned_and_unique`.

use super::error::{DecoySelectionError, DecoySelectionResult};
use super::types::{CoveredRequest, RingPolicy, ValidatedDecoySnapshot};
use super::{
    COVERED_LOOKUP_SIZE, DECOY_GAMMA_MAX_RESAMPLES, DECOY_GAMMA_SCALE,
    DECOY_GAMMA_SHAPE,
};
use crate::decoy::{HeightOutputCount, OutputLocator};
use rand::seq::SliceRandom;
use rand::{CryptoRng, Rng, RngCore};
use rand_distr::{Distribution, Gamma};
use std::collections::HashSet;

pub fn sample_candidate_locators<R: Rng + ?Sized>(
    snapshot: &ValidatedDecoySnapshot,
    min_age: u64,
    count: usize,
    excluded: &HashSet<OutputLocator>,
    rng: &mut R,
) -> DecoySelectionResult<Vec<OutputLocator>> {
    if count == 0 {
        return Ok(Vec::new());
    }

    let eligible = snapshot.eligible_heights(min_age);
    let available = snapshot.eligible_output_count(min_age).saturating_sub(
        excluded
            .iter()
            .filter(|locator| locator_is_in(locator, eligible))
            .count(),
    );
    if available < count {
        return Err(DecoySelectionError::InsufficientDecoys {
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

    let spend_height = snapshot.spend_height();
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
            return Err(DecoySelectionError::InsufficientDecoys {
                available: result.len(),
                needed: count,
            });
        };
        let target_height = spend_height - age;
        let Some(locator) =
            pick_nearest_locator(target_height, eligible, excluded, &selected, rng)
        else {
            return Err(DecoySelectionError::InsufficientDecoys {
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
    snapshot: &ValidatedDecoySnapshot,
    real_locators: &[OutputLocator],
    ring_size: usize,
    min_age: u64,
    rng: &mut R,
) -> DecoySelectionResult<CoveredRequest> {
    if real_locators.is_empty() {
        return Err(DecoySelectionError::MissingRealOutputs);
    }
    let policy = RingPolicy::try_new(ring_size, min_age)?;

    let mut excluded = HashSet::with_capacity(real_locators.len());
    for locator in real_locators {
        if !excluded.insert(*locator) {
            return Err(DecoySelectionError::DuplicateRealLocator(*locator));
        }
        if !snapshot.contains_locator(locator) {
            return Err(DecoySelectionError::RealLocatorOutsideSnapshot(*locator));
        }
    }

    let required_slots = real_locators
        .len()
        .checked_mul(ring_size)
        .ok_or(DecoySelectionError::CoveredLookupSizeOverflow {
            input_count: real_locators.len(),
            ring_size,
        })?;
    if required_slots > COVERED_LOOKUP_SIZE {
        return Err(DecoySelectionError::CoveredLookupCapacityExceeded {
            input_count: real_locators.len(),
            ring_size,
            required_slots,
            capacity: COVERED_LOOKUP_SIZE,
        });
    }

    let mut locators = real_locators.to_vec();
    locators.extend(sample_candidate_locators(
        snapshot,
        min_age,
        COVERED_LOOKUP_SIZE - locators.len(),
        &excluded,
        rng,
    )?);
    locators.shuffle(rng);

    Ok(CoveredRequest::new(
        snapshot,
        policy,
        real_locators.to_vec(),
        locators,
    ))
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
