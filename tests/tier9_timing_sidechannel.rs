//! # Tier 9 — Timing & Side-Channel Resistance Tests
//!
//! Tests that cryptographic operations don't leak secrets through timing.
//! NO MOCKS. Real crypto operations measured for timing variance.

use coincync::crypto::{
    clsag_sign, clsag_verify, ct_eq, BlindingFactor, ClsagRingMember, EcCommitment, KeyImage,
    PedersenCommitment, PublicPoint, SecretScalar,
};
use rand::rngs::OsRng;
use std::time::{Duration, Instant};

/// Number of independent timing runs whose median we take per measurement.
const TIMING_RUNS: usize = 5;

/// Robustly time `iterations` calls to `op`, returning the MEDIAN of
/// [`TIMING_RUNS`] independent measurements taken after a discarded warmup.
///
/// Why median-of-runs and not a single measurement: on a shared CI runner
/// one scheduler preemption or a CPU-frequency step can blow a single
/// wall-clock measurement out by >2x even when the operation is genuinely
/// constant-time, producing a spurious side-channel "failure" (this is what
/// intermittently reddened the tier9 job). The median across several runs
/// — plus a discarded warmup that primes caches / lets frequency settle —
/// rejects those one-off outliers.
///
/// Crucially this does NOT weaken the security assertion: a real
/// secret-dependent timing difference is *systematic*, so it shifts the
/// median too and is still caught by the same ratio bound. We remove false
/// positives from measurement noise, never true positives from real leakage.
fn median_time<F: FnMut()>(mut op: F, iterations: usize) -> Duration {
    // Warmup — prime instruction/data caches and let CPU frequency settle;
    // this run's timing is discarded.
    for _ in 0..iterations {
        op();
    }
    let mut samples = [Duration::ZERO; TIMING_RUNS];
    for slot in &mut samples {
        let start = Instant::now();
        for _ in 0..iterations {
            op();
        }
        *slot = start.elapsed();
    }
    samples.sort_unstable();
    samples[TIMING_RUNS / 2]
}

// =============================================================================
// TEST 1: Constant-time equality comparison
// =============================================================================

#[test]
fn tier9_ct_eq_returns_correct_results() {
    let a = [0xAA; 32];
    let b = [0xAA; 32];
    let c = [0xBB; 32];
    let mut d = [0xAA; 32];
    d[31] = 0xBB;

    assert!(ct_eq(&a, &b), "Equal slices must be equal");
    assert!(!ct_eq(&a, &c), "Different slices must not be equal");
    assert!(
        !ct_eq(&a, &d),
        "Slices differing at last byte must not be equal"
    );
}

#[test]
fn tier9_ct_eq_timing_consistent() {
    let a = [0xAA; 32];
    let b = [0xAA; 32]; // same
    let c = [0xBB; 32]; // different everywhere
    let mut d = [0xAA; 32];
    d[31] = 0xBB; // different only last byte

    let iterations = 10_000;

    let t_equal = median_time(
        || {
            let _ = ct_eq(&a, &b);
        },
        iterations,
    );
    let t_diff_first = median_time(
        || {
            let _ = ct_eq(&a, &c);
        },
        iterations,
    );
    let t_diff_last = median_time(
        || {
            let _ = ct_eq(&a, &d);
        },
        iterations,
    );

    let max_t = t_equal.max(t_diff_first).max(t_diff_last);
    let min_t = t_equal.min(t_diff_first).min(t_diff_last);

    assert!(
        max_t < min_t * 3,
        "Timing variance too large! Equal: {:?}, Diff@0: {:?}, Diff@31: {:?}",
        t_equal,
        t_diff_first,
        t_diff_last
    );
}

// =============================================================================
// TEST 2: Scalar multiplication timing independent of scalar value
// =============================================================================

#[test]
fn tier9_scalar_mul_timing_consistent() {
    let iterations = 5_000;
    let scalars: Vec<SecretScalar> = (0..5).map(|_| SecretScalar::random(&mut OsRng)).collect();

    let times: Vec<Duration> = scalars
        .iter()
        .map(|scalar| {
            median_time(
                || {
                    let _ = scalar.to_public();
                },
                iterations,
            )
        })
        .collect();

    let max_t = times.iter().max().unwrap();
    let min_t = times.iter().min().unwrap();

    assert!(
        *max_t < *min_t * 2,
        "Scalar * G timing varies too much: {:?}. Suggests secret-dependent branching.",
        times
    );
}

// =============================================================================
// TEST 3: Key image computation timing consistent
// =============================================================================

#[test]
fn tier9_key_image_timing_consistent() {
    let iterations = 5_000;
    let secrets: Vec<SecretScalar> = (0..5).map(|_| SecretScalar::random(&mut OsRng)).collect();

    let times: Vec<Duration> = secrets
        .iter()
        .map(|secret| {
            median_time(
                || {
                    let _ = KeyImage::from_secret(secret);
                },
                iterations,
            )
        })
        .collect();

    let max_t = times.iter().max().unwrap();
    let min_t = times.iter().min().unwrap();

    assert!(
        *max_t < *min_t * 2,
        "Key image timing varies: {:?}. Different secrets shouldn't take different time.",
        times
    );
}

// =============================================================================
// TEST 4: Pedersen commitment timing independent of amount
// =============================================================================

#[test]
fn tier9_pedersen_commit_timing_consistent() {
    let iterations = 5_000;
    let bf = BlindingFactor::random(&mut OsRng);
    let amounts = [0u64, 1, u64::MAX / 2, u64::MAX - 1, 1_000_000_000];

    let times: Vec<Duration> = amounts
        .iter()
        .map(|&amount| {
            median_time(
                || {
                    let _ = PedersenCommitment::commit(amount, &bf);
                },
                iterations,
            )
        })
        .collect();

    let max_t = times.iter().max().unwrap();
    let min_t = times.iter().min().unwrap();

    assert!(
        *max_t < *min_t * 2,
        "Pedersen commit timing varies with amount: {:?}. Could leak amounts.",
        times
    );
}

// =============================================================================
// TEST 5: CLSAG verify doesn't reveal signer index
// =============================================================================

#[test]
fn tier9_clsag_verify_timing_independent_of_signer() {
    let ring_size = 11;
    let message = b"timing_test_signer_position";
    let iterations = 50;

    let mut verify_times = Vec::new();

    for real_idx in [0usize, 5, 10] {
        let real_secret = SecretScalar::random(&mut OsRng);
        let real_blinding = BlindingFactor::random(&mut OsRng);
        let pseudo_blinding = BlindingFactor::random(&mut OsRng);

        let mut ring: Vec<ClsagRingMember> = Vec::new();
        for i in 0..ring_size {
            let (pk, commit) = if i == real_idx {
                (
                    real_secret.to_public(),
                    PedersenCommitment::commit(1_000_000_000, &real_blinding),
                )
            } else {
                let s = SecretScalar::random(&mut OsRng);
                let bf = BlindingFactor::random(&mut OsRng);
                (
                    s.to_public(),
                    PedersenCommitment::commit(1_000_000_000, &bf),
                )
            };
            ring.push(ClsagRingMember::new(
                pk,
                EcCommitment::from_point(PublicPoint::from_bytes(commit.to_bytes()).unwrap()),
            ));
        }

        let pseudo_output = EcCommitment::from_point(
            PublicPoint::from_bytes(
                PedersenCommitment::commit(1_000_000_000, &pseudo_blinding).to_bytes(),
            )
            .unwrap(),
        );
        let blinding_diff =
            SecretScalar::from_bytes(real_blinding.sub(&pseudo_blinding).to_bytes());

        let sig = clsag_sign(
            message,
            &ring,
            real_idx,
            &real_secret,
            &blinding_diff,
            &pseudo_output,
            &mut OsRng,
        )
        .expect("sign");

        let elapsed = median_time(
            || {
                let _ = clsag_verify(message, &ring, &pseudo_output, &sig);
            },
            iterations,
        );
        verify_times.push((real_idx, elapsed));
    }

    let max_t = verify_times.iter().map(|(_, t)| t).max().unwrap();
    let min_t = verify_times.iter().map(|(_, t)| t).min().unwrap();

    assert!(
        *max_t < *min_t * 2,
        "CLSAG verify timing depends on signer position! {:?}. Leaks real signer.",
        verify_times
    );
}

// =============================================================================
// TEST 6: Invalid signature not significantly faster to verify
// =============================================================================

#[test]
fn tier9_invalid_sig_not_faster_than_valid() {
    let ring_size = 11;
    let message = b"valid_vs_invalid_timing";
    let iterations = 50;

    let real_secret = SecretScalar::random(&mut OsRng);
    let real_blinding = BlindingFactor::random(&mut OsRng);
    let pseudo_blinding = BlindingFactor::random(&mut OsRng);

    let mut ring: Vec<ClsagRingMember> = Vec::new();
    for i in 0..ring_size {
        let (pk, commit) = if i == 0 {
            (
                real_secret.to_public(),
                PedersenCommitment::commit(1_000_000_000, &real_blinding),
            )
        } else {
            let s = SecretScalar::random(&mut OsRng);
            let bf = BlindingFactor::random(&mut OsRng);
            (
                s.to_public(),
                PedersenCommitment::commit(1_000_000_000, &bf),
            )
        };
        ring.push(ClsagRingMember::new(
            pk,
            EcCommitment::from_point(PublicPoint::from_bytes(commit.to_bytes()).unwrap()),
        ));
    }

    let pseudo_output = EcCommitment::from_point(
        PublicPoint::from_bytes(
            PedersenCommitment::commit(1_000_000_000, &pseudo_blinding).to_bytes(),
        )
        .unwrap(),
    );
    let blinding_diff = SecretScalar::from_bytes(real_blinding.sub(&pseudo_blinding).to_bytes());

    let valid_sig = clsag_sign(
        message,
        &ring,
        0,
        &real_secret,
        &blinding_diff,
        &pseudo_output,
        &mut OsRng,
    )
    .unwrap();
    let mut invalid_sig = valid_sig.clone();
    invalid_sig.c1[0] ^= 0xFF;

    let t_valid = median_time(
        || {
            let _ = clsag_verify(message, &ring, &pseudo_output, &valid_sig);
        },
        iterations,
    );
    let t_invalid = median_time(
        || {
            let _ = clsag_verify(message, &ring, &pseudo_output, &invalid_sig);
        },
        iterations,
    );

    // Invalid should not be >4x faster (some early return OK for DoS protection)
    assert!(
        t_invalid > t_valid / 4,
        "Invalid sig ({:?}) is >4x faster than valid ({:?}). Timing oracle risk.",
        t_invalid,
        t_valid
    );
}

// =============================================================================
// TEST 7: clsag_verify returns bool (no index leakage)
// =============================================================================

#[test]
fn tier9_verify_returns_bool_no_index_info() {
    // The fact that clsag_verify returns bool (not Result with index info)
    // is itself the side-channel protection. Verify this contract holds.
    let ring_size = 11;
    let message = b"no_index_leak";

    let ring: Vec<ClsagRingMember> = (0..ring_size)
        .map(|_| {
            let s = SecretScalar::random(&mut OsRng);
            let bf = BlindingFactor::random(&mut OsRng);
            let commit = PedersenCommitment::commit(1_000_000_000, &bf);
            ClsagRingMember::new(
                s.to_public(),
                EcCommitment::from_point(PublicPoint::from_bytes(commit.to_bytes()).unwrap()),
            )
        })
        .collect();

    let pseudo_output = EcCommitment::from_point(
        PublicPoint::from_bytes(
            PedersenCommitment::commit(1_000_000_000, &BlindingFactor::random(&mut OsRng))
                .to_bytes(),
        )
        .unwrap(),
    );

    let fake_ki = KeyImage::from_secret(&SecretScalar::random(&mut OsRng));
    let fake_sig = coincync::crypto::ClsagSignature {
        key_image: fake_ki,
        commitment_image: SecretScalar::random(&mut OsRng).to_public(),
        c1: [0x42; 32],
        responses: vec![[0x13; 32]; ring_size],
    };

    let result = clsag_verify(message, &ring, &pseudo_output, &fake_sig);
    assert!(!result, "Fake signature must not verify");
    // If we got here, the function returned bool without panicking or
    // revealing which index failed — side-channel resistant by design.
}
