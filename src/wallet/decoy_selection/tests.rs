use super::*;
use crate::decoy::{
    DecoyDistributionSnapshot, HeightOutputCount, OutputLocator, ResolvedDecoyOutput,
    ResolvedDecoySnapshot, DECOY_LOCATOR_POLICY_VERSION,
};
use crate::primitives::{Hash, PublicKey};
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
use rand_distr::{Distribution, Gamma};
use std::collections::HashSet;

fn raw_snapshot(height: u64, count_per_height: u32) -> DecoyDistributionSnapshot {
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

fn snapshot(height: u64, count_per_height: u32) -> ValidatedDecoySnapshot {
    ValidatedDecoySnapshot::try_from(raw_snapshot(height, count_per_height)).unwrap()
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

fn response_for(request: &CoveredRequest) -> ResolvedDecoySnapshot {
    let snapshot = request.snapshot_id();
    ResolvedDecoySnapshot {
        snapshot_height: snapshot.height(),
        snapshot_hash: snapshot.hash(),
        policy_version: snapshot.policy_version(),
        outputs: request.locators().iter().copied().map(resolved).collect(),
    }
}

fn real_identity(locator: OutputLocator) -> RealOutputIdentity {
    let output = resolved(locator);
    RealOutputIdentity::new(locator, output.public_key, output.commitment)
}

#[test]
fn validated_snapshot_rejects_unsupported_policy() {
    let mut raw = raw_snapshot(10, 1);
    raw.policy_version += 1;

    assert!(matches!(
        ValidatedDecoySnapshot::try_from(raw),
        Err(DecoySelectionError::UnsupportedPolicyVersion { .. })
    ));
}

#[test]
fn validated_snapshot_rejects_invalid_height_buckets() {
    let mut zero = raw_snapshot(10, 1);
    zero.heights[3].count = 0;
    assert!(matches!(
        ValidatedDecoySnapshot::try_from(zero),
        Err(DecoySelectionError::EmptyHeightBucket { height: 3 })
    ));

    let mut unsorted = raw_snapshot(10, 1);
    unsorted.heights.swap(3, 4);
    assert!(matches!(
        ValidatedDecoySnapshot::try_from(unsorted),
        Err(DecoySelectionError::NonIncreasingHeight { .. })
    ));

    let mut above_tip = raw_snapshot(10, 1);
    above_tip.heights.push(HeightOutputCount {
        height: 11,
        count: 1,
    });
    assert!(matches!(
        ValidatedDecoySnapshot::try_from(above_tip),
        Err(DecoySelectionError::HeightAboveSnapshot { .. })
    ));
}

#[test]
fn gamma_sampling_is_conditioned_and_unique() {
    let snapshot = snapshot(30_000, 1);
    let spend_height = snapshot.spend_height();
    let mut rng = ChaCha20Rng::seed_from_u64(2);
    let mut observed = Vec::with_capacity(2_000);
    for _ in 0..125 {
        let selected =
            sample_candidate_locators(&snapshot, 100, 16, &HashSet::new(), &mut rng).unwrap();
        assert_eq!(selected.iter().copied().collect::<HashSet<_>>().len(), 16);
        assert!(selected.iter().all(|locator| locator.height <= 29_901));
        observed.extend(
            selected
                .iter()
                .map(|locator| spend_height - locator.height),
        );
    }

    let gamma = Gamma::new(DECOY_GAMMA_SHAPE, DECOY_GAMMA_SCALE).unwrap();
    let block_time = crate::constants::TARGET_BLOCK_TIME as f64;
    let mut target_rng = ChaCha20Rng::seed_from_u64(3);
    let mut expected = Vec::with_capacity(observed.len());
    while expected.len() < observed.len() {
        let age = (gamma.sample(&mut target_rng).exp() / block_time) as u64;
        if (100..=30_001).contains(&age) {
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

/// AUDIT (wallet C1 — decoy indistinguishability, NON-circular): the sibling
/// test above compares the sampler to a re-sampling of the SAME
/// `Gamma(DECOY_GAMMA_SHAPE, DECOY_GAMMA_SCALE)` constants, so it can only prove
/// "the sampler samples the distribution it samples" — it cannot catch WRONG
/// gamma parameters, which is exactly the deanonymization vector (if the decoy
/// age law ≠ the real-spend age law, the real member is the statistical outlier
/// in every ring).
///
/// This test pins the realized decoy-age distribution to an INDEPENDENT
/// reference: percentiles of `age = ⌊exp(Gamma(19.28, 1/1.61))/120⌋` truncated
/// to the eligible block-age range `[100, 30000]`, precomputed offline with a
/// DIFFERENT gamma implementation (Python `random.gammavariate`, 2M samples,
/// seed 12345). Because the reference is a second, independent implementation of
/// the SAME parameters under the SAME truncation, a match proves the sampler
/// really draws `Gamma(19.28, 1/1.61)` — and a wrong shape/scale is caught:
/// under this truncation, `shape 19.28→17` shifts the median 1243→711 (−43%),
/// `scale 1/1.61→1/1.50` shifts it to 1768 (+42%), and `shape→21` to 1945
/// (+56%), all far outside the ±25% tolerance the correct sampler sits inside.
#[test]
fn decoy_age_distribution_matches_independent_gamma_reference_wallet_c1() {
    // Same dense uniform chain + eligibility as the sibling test: every height
    // populated (so target height is always present and snapping is exact) and
    // min_age = 100 ⇒ eligible block-age range [100, 30000].
    let snapshot = snapshot(30_000, 1);
    let spend_height = snapshot.spend_height();
    let mut rng = ChaCha20Rng::seed_from_u64(0xC0FFEE);

    let mut ages: Vec<u64> = Vec::with_capacity(10_000);
    // Independent draws (count small vs pool ⇒ negligible without-replacement
    // depletion); repeat to accumulate a stable sample.
    for _ in 0..200 {
        let selected =
            sample_candidate_locators(&snapshot, 100, 50, &HashSet::new(), &mut rng).unwrap();
        ages.extend(selected.iter().map(|l| spend_height - l.height));
    }
    ages.sort_unstable();
    let pct = |p: usize| -> f64 { ages[(ages.len() - 1) * p / 100] as f64 };

    // Independent reference percentiles (Python gammavariate, see doc-comment).
    // (percentile, reference age, relative tolerance)
    let reference: &[(usize, f64, f64)] = &[
        (10, 178.0, 0.30),
        (25, 382.0, 0.25),
        (50, 1243.0, 0.25),
        (75, 4548.0, 0.25),
        (90, 12276.0, 0.28),
    ];
    for &(p, want, tol) in reference {
        let got = pct(p);
        let rel = (got - want).abs() / want;
        assert!(
            rel <= tol,
            "decoy age p{p} = {got} deviates {:.1}% from the independent gamma reference {want} \
             (tol {:.0}%) — the sampler's decoy-age distribution does not match Gamma(19.28, 1/1.61); \
             a mis-set DECOY_GAMMA_SHAPE/SCALE would deanonymize the real spend",
            rel * 100.0,
            tol * 100.0
        );
    }
}

#[test]
fn minimum_age_is_measured_at_the_next_spend_height() {
    let snapshot = ValidatedDecoySnapshot::try_from(DecoyDistributionSnapshot {
        snapshot_height: 100,
        snapshot_hash: Hash::from_bytes([7; 32]),
        policy_version: DECOY_LOCATOR_POLICY_VERSION,
        heights: vec![HeightOutputCount {
            height: 91,
            count: 1,
        }],
    })
    .unwrap();
    let mut rng = ChaCha20Rng::seed_from_u64(4);
    let selected =
        sample_candidate_locators(&snapshot, 10, 1, &HashSet::new(), &mut rng).unwrap();
    assert_eq!(
        selected,
        vec![OutputLocator {
            height: 91,
            ordinal: 0,
        }]
    );
}

#[test]
fn covered_request_binds_snapshot_and_policy() {
    let snapshot = snapshot(1_000, 1);
    let real = [OutputLocator {
        height: 100,
        ordinal: 0,
    }];
    let mut rng = ChaCha20Rng::seed_from_u64(12);
    let request = build_covered_request(&snapshot, &real, 16, 10, &mut rng).unwrap();

    assert_eq!(request.snapshot_id(), snapshot.snapshot_id());
    assert_eq!(request.spend_height(), snapshot.spend_height());
    assert_eq!(request.ring_size(), 16);
    assert_eq!(request.min_output_age(), 10);
}

#[test]
fn lock_height_is_checked_at_the_next_spend_height() {
    let snapshot = snapshot(200, 1);
    let real_locator = OutputLocator {
        height: 50,
        ordinal: 0,
    };
    let real_outputs = [real_identity(real_locator)];
    let mut rng = ChaCha20Rng::seed_from_u64(9);
    let request = build_covered_request(&snapshot, &[real_locator], 2, 10, &mut rng).unwrap();
    let mut response = response_for(&request);
    for output in &mut response.outputs {
        if output.locator != real_locator {
            output.lock_height = Some(201);
        }
    }

    let validated = validate_covered_response(request.clone(), response.clone()).unwrap();
    assert!(allocate_unique_rings(validated, &real_outputs, &mut rng).is_ok());

    for output in &mut response.outputs {
        if output.locator != real_locator {
            output.lock_height = Some(202);
        }
    }
    let validated = validate_covered_response(request, response).unwrap();
    assert!(matches!(
        allocate_unique_rings(validated, &real_outputs, &mut rng),
        Err(DecoySelectionError::InsufficientDecoys {
            available: 0,
            needed: 1
        })
    ));
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
    assert_eq!(request.locators().len(), COVERED_LOOKUP_SIZE);
    assert!(real
        .iter()
        .all(|locator| request.locators().contains(locator)));
    assert_eq!(
        request
            .locators()
            .iter()
            .copied()
            .collect::<HashSet<_>>()
            .len(),
        request.locators().len()
    );

    let mut response = response_for(&request);
    let real_outputs: Vec<_> = real.iter().copied().map(real_identity).collect();
    let colliding = response
        .outputs
        .iter_mut()
        .find(|output| !real.contains(&output.locator))
        .unwrap();
    colliding.public_key = real_outputs[0].public_key();

    let validated = validate_covered_response(request, response).unwrap();
    let rings = allocate_unique_rings(validated, &real_outputs, &mut rng).unwrap();
    assert_eq!(rings.len(), 2);
    assert_eq!(rings.ring_size(), 16);
    assert_eq!(rings.real_outputs(), real_outputs.as_slice());
    assert!(rings
        .rings()
        .iter()
        .all(|ring| ring.decoys().len() == 15));

    let left: HashSet<_> = rings.rings()[0]
        .decoys()
        .iter()
        .map(|decoy| *decoy.public_key.as_bytes())
        .collect();
    let right: HashSet<_> = rings.rings()[1]
        .decoys()
        .iter()
        .map(|decoy| *decoy.public_key.as_bytes())
        .collect();
    assert!(left.is_disjoint(&right));
    assert!(rings
        .rings()
        .iter()
        .flat_map(|ring| ring.decoys().iter())
        .all(|decoy| real_outputs
            .iter()
            .all(|real| decoy.public_key != real.public_key())));
}

#[test]
fn covered_request_rejects_a_real_locator_outside_the_snapshot() {
    let snapshot = snapshot(1_000, 1);
    let real = [OutputLocator {
        height: 1_000,
        ordinal: 1,
    }];
    let mut rng = ChaCha20Rng::seed_from_u64(7);

    assert!(matches!(
        build_covered_request(&snapshot, &real, 16, 10, &mut rng),
        Err(DecoySelectionError::RealLocatorOutsideSnapshot(locator)) if locator == real[0]
    ));
}

#[test]
fn covered_request_rejects_capacity_overflow() {
    let snapshot = snapshot(1_000, 1);
    let real: Vec<_> = (0..9)
        .map(|height| OutputLocator { height, ordinal: 0 })
        .collect();
    let mut rng = ChaCha20Rng::seed_from_u64(8);

    assert!(matches!(
        build_covered_request(&snapshot, &real, 16, 10, &mut rng),
        Err(DecoySelectionError::CoveredLookupCapacityExceeded { .. })
    ));
}

#[test]
fn covered_response_rejects_snapshot_order_and_height_mismatches() {
    let snapshot = snapshot(1_000, 1);
    let real = [OutputLocator {
        height: 100,
        ordinal: 0,
    }];
    let mut rng = ChaCha20Rng::seed_from_u64(10);
    let request = build_covered_request(&snapshot, &real, 16, 10, &mut rng).unwrap();

    let mut wrong_snapshot = response_for(&request);
    wrong_snapshot.snapshot_height += 1;
    assert!(matches!(
        validate_covered_response(request.clone(), wrong_snapshot),
        Err(DecoySelectionError::ResponseSnapshotMismatch { .. })
    ));

    let mut wrong_order = response_for(&request);
    wrong_order.outputs.swap(0, 1);
    assert!(matches!(
        validate_covered_response(request.clone(), wrong_order),
        Err(DecoySelectionError::ResponseLocatorMismatch { .. })
    ));

    let mut wrong_height = response_for(&request);
    wrong_height.outputs[0].height += 1;
    assert!(matches!(
        validate_covered_response(request, wrong_height),
        Err(DecoySelectionError::ResponseHeightMismatch { .. })
    ));
}

#[test]
fn allocation_rejects_real_identity_mismatch() {
    let snapshot = snapshot(1_000, 1);
    let real = OutputLocator {
        height: 100,
        ordinal: 0,
    };
    let mut rng = ChaCha20Rng::seed_from_u64(11);
    let request = build_covered_request(&snapshot, &[real], 16, 10, &mut rng).unwrap();
    let mut response = response_for(&request);
    response
        .outputs
        .iter_mut()
        .find(|output| output.locator == real)
        .unwrap()
        .public_key = PublicKey::from_bytes([0xFF; 32]);
    let validated = validate_covered_response(request, response).unwrap();

    assert!(matches!(
        allocate_unique_rings(validated, &[real_identity(real)], &mut rng),
        Err(DecoySelectionError::RealOutputIdentityMismatch(locator)) if locator == real
    ));
}

// Regression: the genesis coinbase is a placeholder with an all-zero
// (identity-point) public key and commitment, and it is added to the canonical
// output catalog like any other output. If the sampler places it in a ring, the
// CLSAG verifier rejects that input with "Ring signature verification failed"
// (crypto/clsag.rs identity-member guard). allocate_unique_rings must therefore
// exclude identity-point outputs from the decoy candidate set. Here every
// non-real candidate is an identity-point output, so none are eligible and the
// allocation must fail with InsufficientDecoys rather than silently building a
// ring around a poison decoy.
#[test]
fn allocation_excludes_identity_point_decoys() {
    let snapshot = snapshot(200, 1);
    let real_locator = OutputLocator {
        height: 50,
        ordinal: 0,
    };
    let real_outputs = [real_identity(real_locator)];
    let mut rng = ChaCha20Rng::seed_from_u64(21);
    let request = build_covered_request(&snapshot, &[real_locator], 2, 10, &mut rng).unwrap();
    let mut response = response_for(&request);
    // Turn every non-real candidate into the genesis-style identity placeholder
    // (all-zero pubkey AND commitment).
    for output in &mut response.outputs {
        if output.locator != real_locator {
            output.public_key = PublicKey::from_bytes([0u8; 32]);
            output.commitment = [0u8; 32];
        }
    }
    let validated = validate_covered_response(request, response).unwrap();
    assert!(matches!(
        allocate_unique_rings(validated, &real_outputs, &mut rng),
        Err(DecoySelectionError::InsufficientDecoys {
            available: 0,
            needed: 1
        })
    ));
}

// Funds-correctness: spending a ring requires the real member to actually
// occupy the chosen secret index. `allocate_unique_rings` reserves that slot by
// emitting `real_position` alongside `ring_size - 1` decoys; the transaction
// builder later inserts the real output there. Reconstruct that insertion and
// prove every ring ends up with the real key at exactly its secret index and
// nowhere else.
#[test]
fn allocation_places_real_member_at_the_secret_index_in_every_ring() {
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
    let mut rng = ChaCha20Rng::seed_from_u64(101);
    let request = build_covered_request(&snapshot, &real, 16, 10, &mut rng).unwrap();
    let response = response_for(&request);
    let real_outputs: Vec<_> = real.iter().copied().map(real_identity).collect();
    let validated = validate_covered_response(request, response).unwrap();
    let rings = allocate_unique_rings(validated, &real_outputs, &mut rng).unwrap();

    assert_eq!(rings.len(), real_outputs.len());
    for (index, ring) in rings.rings().iter().enumerate() {
        let position = ring.real_position();
        assert!(position < rings.ring_size());
        assert_eq!(ring.decoys().len(), rings.ring_size() - 1);

        let real_key = real_outputs[index].public_key();
        let mut members: Vec<_> = ring.decoys().iter().map(|decoy| decoy.public_key).collect();
        members.insert(position, real_key);
        assert_eq!(members.len(), rings.ring_size());
        assert_eq!(members[position], real_key);
        assert_eq!(
            members.iter().filter(|key| **key == real_key).count(),
            1,
            "the real member must appear exactly once in the reconstructed ring"
        );
    }
}

// Every ring's secret index must land inside the ring so the real member has a
// valid slot to occupy.
#[test]
fn allocation_places_the_real_index_within_ring_bounds() {
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
    let mut rng = ChaCha20Rng::seed_from_u64(110);
    let request = build_covered_request(&snapshot, &real, 16, 10, &mut rng).unwrap();
    let response = response_for(&request);
    let real_outputs: Vec<_> = real.iter().copied().map(real_identity).collect();
    let validated = validate_covered_response(request, response).unwrap();
    let rings = allocate_unique_rings(validated, &real_outputs, &mut rng).unwrap();

    for ring in rings.rings() {
        assert!(ring.real_position() < rings.ring_size());
    }
}

// The real outputs passed to allocation must be in the exact order the covered
// request bound them; a reordered set is rejected fail-closed.
#[test]
fn allocation_rejects_real_output_order_mismatch() {
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
    let mut rng = ChaCha20Rng::seed_from_u64(102);
    let request = build_covered_request(&snapshot, &real, 16, 10, &mut rng).unwrap();
    let response = response_for(&request);
    let validated = validate_covered_response(request, response).unwrap();

    let reversed = vec![real_identity(real[1]), real_identity(real[0])];
    assert!(matches!(
        allocate_unique_rings(validated, &reversed, &mut rng),
        Err(DecoySelectionError::RealOutputSetMismatch)
    ));
}

// Two selected inputs that resolve to the same public key would let one output
// stand in for another; the duplicate-key guard must reject them.
#[test]
fn allocation_rejects_duplicate_real_public_key() {
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
    let mut rng = ChaCha20Rng::seed_from_u64(103);
    let request = build_covered_request(&snapshot, &real, 16, 10, &mut rng).unwrap();
    let mut response = response_for(&request);

    // Make both reals resolve to the SAME identity so the per-real checks pass
    // but the transaction-wide duplicate guard fires.
    let shared = resolved(real[0]);
    for output in &mut response.outputs {
        if output.locator == real[1] {
            output.public_key = shared.public_key;
            output.commitment = shared.commitment;
        }
    }
    let real_outputs = vec![
        real_identity(real[0]),
        RealOutputIdentity::new(real[1], shared.public_key, shared.commitment),
    ];
    let validated = validate_covered_response(request, response).unwrap();
    assert!(matches!(
        allocate_unique_rings(validated, &real_outputs, &mut rng),
        Err(DecoySelectionError::DuplicateRealPublicKey)
    ));
}

// Defense-in-depth: the validated happy path guarantees every requested locator
// (including reals) is present in the response, so `MissingRealOutput` can only
// be reached by assembling a validated response whose index omits a real. Build
// one directly to exercise allocation's fail-closed lookup.
#[test]
fn allocation_reports_missing_real_output_when_response_index_omits_it() {
    let snapshot = snapshot(1_000, 1);
    let real = OutputLocator {
        height: 100,
        ordinal: 0,
    };
    let mut rng = ChaCha20Rng::seed_from_u64(104);
    let request = build_covered_request(&snapshot, &[real], 16, 10, &mut rng).unwrap();

    let outputs: Vec<_> = request.locators().iter().copied().map(resolved).collect();
    let output_index: std::collections::HashMap<_, _> = outputs
        .iter()
        .enumerate()
        .filter(|(_, output)| output.locator != real)
        .map(|(index, output)| (output.locator, index))
        .collect();
    let validated = ValidatedCoveredResponse::new(request, outputs, output_index);

    assert!(matches!(
        allocate_unique_rings(validated, &[real_identity(real)], &mut rng),
        Err(DecoySelectionError::MissingRealOutput(locator)) if locator == real
    ));
}

// When the eligible candidate pool is smaller than the rings need, allocation
// must fail with an exact accounting rather than build short rings.
#[test]
fn allocation_reports_insufficient_decoys_when_candidate_pool_too_small() {
    let snapshot = snapshot(1_000, 1);
    let real = OutputLocator {
        height: 100,
        ordinal: 0,
    };
    let mut rng = ChaCha20Rng::seed_from_u64(105);
    let request = build_covered_request(&snapshot, &[real], 16, 10, &mut rng).unwrap();
    let spend_height = snapshot.spend_height();
    let mut response = response_for(&request);

    // Leave exactly five spendable, non-identity decoys; a ring size of 16
    // needs fifteen. (Height 0 is the only identity-point output, so keeping
    // height > 0 guarantees the survivors survive every other filter too.)
    let mut kept = 0;
    for output in &mut response.outputs {
        if output.locator == real {
            continue;
        }
        if output.locator.height != 0 && kept < 5 {
            kept += 1;
        } else {
            output.lock_height = Some(spend_height + 1);
        }
    }
    assert_eq!(kept, 5, "test setup must leave exactly five usable decoys");

    let validated = validate_covered_response(request, response).unwrap();
    assert!(matches!(
        allocate_unique_rings(validated, &[real_identity(real)], &mut rng),
        Err(DecoySelectionError::InsufficientDecoys {
            available: 5,
            needed: 15
        })
    ));
}

// Defense-in-depth overflow guard: `input_count * (ring_size - 1)` is bounded to
// at most COVERED_LOOKUP_SIZE on the validated path, so reaching the checked-mul
// overflow requires building a request with a pathological ring size directly.
#[test]
fn allocation_reports_ring_allocation_size_overflow() {
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
    let mut rng = ChaCha20Rng::seed_from_u64(106);
    // Harvest a valid, snapshot-consistent 128-locator set (reals included).
    let seed_request = build_covered_request(&snapshot, &real, 2, 10, &mut rng).unwrap();
    let locators = seed_request.locators().to_vec();

    let policy = super::types::RingPolicy::try_new(usize::MAX, 10).unwrap();
    let request = CoveredRequest::new(&snapshot, policy, real.to_vec(), locators.clone());
    let outputs: Vec<_> = locators.iter().copied().map(resolved).collect();
    let output_index: std::collections::HashMap<_, _> = outputs
        .iter()
        .enumerate()
        .map(|(index, output)| (output.locator, index))
        .collect();
    let validated = ValidatedCoveredResponse::new(request, outputs, output_index);
    let real_outputs: Vec<_> = real.iter().copied().map(real_identity).collect();

    assert!(matches!(
        allocate_unique_rings(validated, &real_outputs, &mut rng),
        Err(DecoySelectionError::RingAllocationSizeOverflow {
            input_count: 2,
            ring_size,
        }) if ring_size == usize::MAX
    ));
}

// A decoy whose height exceeds `max_decoy_height` (spend_height - min_output_age)
// must be filtered before it can be placed in a ring. Such a decoy cannot appear
// on the validated path, so inject one via a directly-built request.
#[test]
fn allocation_filters_decoys_above_the_max_decoy_height() {
    let snapshot = snapshot(200, 1);
    let real = OutputLocator {
        height: 50,
        ordinal: 0,
    };
    let mut rng = ChaCha20Rng::seed_from_u64(107);
    let seed_request = build_covered_request(&snapshot, &[real], 2, 10, &mut rng).unwrap();
    let spend_height = snapshot.spend_height();
    let max_decoy_height = spend_height - 10;
    let above = OutputLocator {
        height: max_decoy_height + 5,
        ordinal: 0,
    };

    let mut locators = seed_request.locators().to_vec();
    let slot = locators
        .iter()
        .position(|locator| *locator != real && *locator != above)
        .unwrap();
    locators[slot] = above;
    assert_eq!(
        locators.iter().copied().collect::<HashSet<_>>().len(),
        locators.len(),
        "the injected locator must keep the set unique"
    );

    let policy = super::types::RingPolicy::try_new(2, 10).unwrap();
    let request = CoveredRequest::new(&snapshot, policy, vec![real], locators.clone());
    let outputs: Vec<_> = locators.iter().copied().map(resolved).collect();
    let output_index: std::collections::HashMap<_, _> = outputs
        .iter()
        .enumerate()
        .map(|(index, output)| (output.locator, index))
        .collect();
    let validated = ValidatedCoveredResponse::new(request, outputs, output_index);

    let above_key = resolved(above).public_key;
    let rings = allocate_unique_rings(validated, &[real_identity(real)], &mut rng).unwrap();
    assert!(
        rings
            .rings()
            .iter()
            .flat_map(|ring| ring.decoys())
            .all(|decoy| decoy.public_key != above_key),
        "a decoy above max_decoy_height must never be placed in a ring"
    );
}

// A decoy locked beyond the spend height is unspendable and must be excluded,
// while the allocation still succeeds from the remaining pool.
#[test]
fn allocation_filters_a_locked_decoy_but_still_allocates() {
    let snapshot = snapshot(1_000, 1);
    let real = OutputLocator {
        height: 100,
        ordinal: 0,
    };
    let mut rng = ChaCha20Rng::seed_from_u64(108);
    let request = build_covered_request(&snapshot, &[real], 4, 10, &mut rng).unwrap();
    let spend_height = snapshot.spend_height();
    let mut response = response_for(&request);

    let locked_locator = response
        .outputs
        .iter()
        .map(|output| output.locator)
        .find(|locator| *locator != real)
        .unwrap();
    for output in &mut response.outputs {
        if output.locator == locked_locator {
            output.lock_height = Some(spend_height + 1);
        }
    }
    let locked_key = resolved(locked_locator).public_key;
    let validated = validate_covered_response(request, response).unwrap();
    let rings = allocate_unique_rings(validated, &[real_identity(real)], &mut rng).unwrap();

    assert!(
        rings
            .rings()
            .iter()
            .flat_map(|ring| ring.decoys())
            .all(|decoy| decoy.public_key != locked_key),
        "a decoy locked beyond the spend height must never be placed in a ring"
    );
}

// No decoy public key may repeat anywhere in the transaction: reuse across rings
// links inputs together and destroys the anonymity set.
#[test]
fn allocation_uses_no_repeated_decoy_public_key_across_rings() {
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
        OutputLocator {
            height: 300,
            ordinal: 0,
        },
    ];
    let mut rng = ChaCha20Rng::seed_from_u64(109);
    let request = build_covered_request(&snapshot, &real, 8, 10, &mut rng).unwrap();
    let response = response_for(&request);
    let real_outputs: Vec<_> = real.iter().copied().map(real_identity).collect();
    let validated = validate_covered_response(request, response).unwrap();
    let rings = allocate_unique_rings(validated, &real_outputs, &mut rng).unwrap();

    let mut all_keys = HashSet::new();
    let mut total = 0;
    for ring in rings.rings() {
        for decoy in ring.decoys() {
            total += 1;
            assert!(
                all_keys.insert(*decoy.public_key.as_bytes()),
                "decoy public keys must be unique across the whole transaction"
            );
        }
    }
    assert_eq!(total, rings.len() * (rings.ring_size() - 1));
}

// Each error variant must render a message that names the failure, so operators
// get an actionable diagnostic rather than an opaque state.
#[test]
fn decoy_selection_error_messages_are_actionable() {
    let cases = [
        (
            DecoySelectionError::InsufficientDecoys {
                available: 3,
                needed: 15,
            },
            "insufficient decoy outputs",
        ),
        (DecoySelectionError::RealOutputSetMismatch, "does not match"),
        (
            DecoySelectionError::DuplicateRealPublicKey,
            "duplicate real output public key",
        ),
        (
            DecoySelectionError::MissingRealOutput(OutputLocator {
                height: 7,
                ordinal: 2,
            }),
            "missing real output locator",
        ),
        (
            DecoySelectionError::RingAllocationSizeOverflow {
                input_count: 2,
                ring_size: usize::MAX,
            },
            "ring allocation size overflow",
        ),
        (
            DecoySelectionError::InvalidRingSize { got: 1 },
            "invalid ring size",
        ),
        (
            DecoySelectionError::RealLocatorOutsideSnapshot(OutputLocator {
                height: 9,
                ordinal: 0,
            }),
            "not present in the validated snapshot",
        ),
    ];
    for (error, needle) in cases {
        let message = error.to_string();
        assert!(
            message.contains(needle),
            "message {message:?} should contain {needle:?}"
        );
        assert!(!message.is_empty());
    }
}
