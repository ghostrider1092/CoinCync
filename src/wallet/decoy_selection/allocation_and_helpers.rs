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

fn snapshot_spend_height(snapshot: &DecoyDistributionSnapshot) -> Result<u64> {
    snapshot.snapshot_height.checked_add(1).ok_or_else(|| {
        Error::InvalidState("decoy snapshot cannot advance to a spend height".into())
    })
}

fn eligible_heights(
    snapshot: &DecoyDistributionSnapshot,
    min_age: u64,
) -> Result<Vec<HeightOutputCount>> {
    let max_height = snapshot_spend_height(snapshot)?
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

