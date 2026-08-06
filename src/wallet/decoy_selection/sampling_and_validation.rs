pub fn sample_candidate_locators<R: Rng + ?Sized>(
    snapshot: &DecoyDistributionSnapshot,
    min_age: u64,
    count: usize,
    excluded: &HashSet<OutputLocator>,
    rng: &mut R,
) -> Result<Vec<OutputLocator>> {
    if snapshot.policy_version != DECOY_LOCATOR_POLICY_VERSION {
        return Err(Error::InvalidState(format!(
            "unsupported decoy locator policy version {}",
            snapshot.policy_version
        )));
    }
    if count == 0 {
        return Ok(Vec::new());
    }
    let spend_height = snapshot_spend_height(snapshot)?;
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

    let youngest_age = spend_height - eligible.last().unwrap().height;
    let oldest_age = spend_height - eligible.first().unwrap().height;
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
    if snapshot.policy_version != DECOY_LOCATOR_POLICY_VERSION {
        return Err(Error::InvalidState(format!(
            "unsupported decoy locator policy version {}",
            snapshot.policy_version
        )));
    }
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

pub fn validate_covered_response(
    snapshot: &DecoyDistributionSnapshot,
    requested: &[OutputLocator],
    response: &ResolvedDecoySnapshot,
) -> Result<()> {
    if snapshot.policy_version != DECOY_LOCATOR_POLICY_VERSION {
        return Err(Error::InvalidState(format!(
            "unsupported decoy locator policy version {}",
            snapshot.policy_version
        )));
    }
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
    let all_heights = eligible_heights(snapshot, 0)?;
    if requested
        .iter()
        .any(|locator| !locator_is_in(locator, &all_heights))
    {
        return Err(Error::InvalidState(
            "covered request contains a locator outside the decoy snapshot".into(),
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

