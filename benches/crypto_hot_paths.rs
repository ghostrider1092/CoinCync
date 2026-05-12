//! # Crypto hot-path benchmarks
//!
//! Baselines for the three CPU-bound primitives that dominate block- and
//! transaction-validation time. Run with:
//!
//! ```text
//! cargo bench --features "randomx testnet" --bench crypto_hot_paths
//! ```
//!
//! These benches feed Phase 1 of the post-launch campaign — establishing
//! measured baselines so any future "optimization" can be evaluated on
//! ROI rather than guesswork. The 2026-05-12 api-box hang post-mortem
//! identified these three calls as the most expensive synchronous work
//! the node does per block + per tx; Layer 2 routes them through
//! `spawn_blocking` / `block_in_place` so they can't freeze the runtime,
//! but the underlying cost is still real and worth measuring.
//!
//! Each bench runs the primitive in isolation with pre-built inputs;
//! setup time (proof construction, ring generation, VM initialization)
//! is excluded via `iter_batched` so we measure verify-time only.
//!
//! ## Reading the output
//!
//! Criterion prints a median time per call and a 95% confidence interval.
//! Baseline numbers captured 2026-05-12 on commodity x86-64 (single core):
//!
//! | bench                          | median  | per block(10 in/10 out) |
//! |--------------------------------|---------|-------------------------|
//! | randomx_hash                   |  22.94 ms |               22.94 ms |
//! | bulletproof_plus_verify_64bit  |   3.28 ms |               32.80 ms |
//! | clsag_verify_ring16            |   5.64 ms |               56.40 ms |
//! |                                |  TOTAL    |              112.14 ms |
//!
//! At a 120-second block target, validation cost on a quiet block is
//! ~0.1% of the inter-block window. Plenty of headroom; any future
//! optimization claim should be measured against these numbers.
//!
//! Re-run with `cargo bench --features "randomx testnet" --bench crypto_hot_paths`
//! when comparing against changes — criterion auto-detects regressions
//! versus the last run.

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use rand::rngs::OsRng;

use coincync::consensus::pow::{compute_pow_hash, PowAlgorithm};
use coincync::crypto::{
    clsag_sign, clsag_verify, commit, create_range_proof, verify_range_proof,
    ClsagRingMember as RingMember, EcCommitment as Commitment, SecretScalar,
};
use coincync::primitives::{Amount, Hash};

// ─── RandomX hash ─────────────────────────────────────────────────────
//
// The hash function every miner and every validator runs once per block.
// VM init costs ~1.5-2s but is amortized via a process-wide cache (see
// `src/consensus/pow.rs:303` VM_CACHE); after the first call within an
// epoch, subsequent hashes are fast.

fn bench_randomx_hash(c: &mut Criterion) {
    // Inputs are stable across iterations — only the timed work varies.
    let anchor = Hash::from_bytes([0xAA; 32]);
    let tx_root = Hash::from_bytes([0xBB; 32]);
    let height: u64 = 1000;

    // Warm up the VM cache once outside the benchmark loop so we measure
    // hash time, not VM init time. The 2-second one-time cost is paid
    // here and never charged to the per-iteration measurement.
    let _ = compute_pow_hash(PowAlgorithm::RandomX, &anchor, 0, &tx_root, height);

    c.bench_function("randomx_hash", |b| {
        let mut nonce: u64 = 1;
        b.iter(|| {
            nonce = nonce.wrapping_add(1);
            black_box(
                compute_pow_hash(
                    PowAlgorithm::RandomX,
                    black_box(&anchor),
                    black_box(nonce),
                    black_box(&tx_root),
                    black_box(height),
                )
                .expect("randomx hash failed"),
            )
        });
    });
}

// ─── Bulletproof+ range-proof verify ──────────────────────────────────
//
// Verify cost for a single 64-bit range proof. Tx admission verifies
// one proof per output; an aggregated proof verifies once for N
// outputs but with a slightly higher per-proof cost. We measure the
// single-output case as the baseline.

fn bench_bulletproof_verify(c: &mut Criterion) {
    let amount = Amount::from_atomic(123_456_789);
    let (commitment, blinding) = commit(&mut OsRng, amount);
    let proof = create_range_proof(amount, &blinding, &mut OsRng)
        .expect("create_range_proof failed");

    c.bench_function("bulletproof_plus_verify_64bit", |b| {
        b.iter(|| {
            black_box(verify_range_proof(black_box(&commitment), black_box(&proof)));
        });
    });
}

// ─── CLSAG ring-signature verify (Ring-16) ────────────────────────────
//
// CoinCync's mandatory ring size on mature chain (post block 10,000).
// Verify is linear in ring size; this measures the most expensive case
// the chain will ever produce.

fn bench_clsag_verify_ring16(c: &mut Criterion) {
    const RING_SIZE: usize = 16;

    // Real signer + commitment with blinding z_real
    let secret = SecretScalar::random(&mut OsRng);
    let public = secret.to_public();
    let z_real = SecretScalar::random(&mut OsRng);
    let value: u64 = 1000;
    let real_commitment = Commitment::commit(value, &z_real);

    // Pseudo output with different blinding
    let z_pseudo = SecretScalar::random(&mut OsRng);
    let pseudo_output = Commitment::commit(value, &z_pseudo);
    let blinding_diff =
        SecretScalar::from_scalar(z_real.as_scalar() - z_pseudo.as_scalar());

    // Build the ring: real signer at index 0, then 15 decoys
    let mut ring = vec![RingMember::new(public, real_commitment)];
    for _ in 1..RING_SIZE {
        let decoy_sk = SecretScalar::random(&mut OsRng);
        let decoy_commitment =
            Commitment::commit(value, &SecretScalar::random(&mut OsRng));
        ring.push(RingMember::new(decoy_sk.to_public(), decoy_commitment));
    }

    let message = b"benchmark message for clsag verify";

    let sig = clsag_sign(
        message,
        &ring,
        0,
        &secret,
        &blinding_diff,
        &pseudo_output,
        &mut OsRng,
    )
    .expect("clsag_sign failed during bench setup");

    // Sanity: setup produced a valid signature. If this fails the bench
    // is timing rejection (constant-time short-circuit), not real verify.
    assert!(
        clsag_verify(message, &ring, &pseudo_output, &sig),
        "bench setup produced an invalid signature",
    );

    c.bench_function("clsag_verify_ring16", |b| {
        b.iter(|| {
            black_box(clsag_verify(
                black_box(message),
                black_box(&ring),
                black_box(&pseudo_output),
                black_box(&sig),
            ))
        });
    });
}

criterion_group!(
    crypto_hot_paths,
    bench_randomx_hash,
    bench_bulletproof_verify,
    bench_clsag_verify_ring16,
);
criterion_main!(crypto_hot_paths);
