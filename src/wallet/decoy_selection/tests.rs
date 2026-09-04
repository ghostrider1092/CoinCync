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
