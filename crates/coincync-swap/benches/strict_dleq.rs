//! Benchmarks for the Noether 2018 strict-binding cross-curve DLEQ
//! proof system. Audit-relevant numbers requested in
//! `docs/cyncswap-audit-prep.md` §8 bullet 3 ("performance bounds —
//! no published numbers").
//!
//! Run:
//!     cargo bench -p coincync-swap --features strict-dleq
//!
//! What these measure:
//!
//! - `prove`  — full `prove_cross_curve_strict` for one secret. Costs
//!   one fast-floor proof + STRICT_BIT_COUNT (252) bit-OR proofs +
//!   two linear-combination openings. Heavy: ~500 EC scalar muls.
//!
//! - `verify` — full `verify_cross_curve_strict` for one proof. Costs
//!   one fast-floor verify + 252 bit-pair verifies + two linear-combo
//!   verifies. Slightly cheaper than prove.
//!
//! Numbers are platform-dependent; what the audit cares about is the
//! ORDER OF MAGNITUDE. If `verify` is >1 sec, the protocol has a DoS
//! exposure on the verify path. Currently expected: tens to low
//! hundreds of milliseconds on a 2-3 GHz modern x86.

#![cfg(feature = "strict-dleq")]

use coincync_swap::adaptor::AdaptorSecret;
use coincync_swap::strict_dleq::{
    prove_cross_curve_strict, verify_cross_curve_strict,
};
use criterion::{black_box, criterion_group, criterion_main, Criterion};
use curve25519_dalek::constants::RISTRETTO_BASEPOINT_TABLE;
use curve25519_dalek::scalar::Scalar as Curve25519Scalar;

/// Build a deterministic input fixture: the same shape as
/// `honest_strict_proof_fixture` in the unit tests. A small scalar
/// (value = 66) so it's canonical on both curves.
fn fixture() -> (AdaptorSecret, [u8; 33], [u8; 32]) {
    // Pick a small secret with bits well within STRICT_BIT_COUNT.
    // 0x0000...0042 (little-endian) = 66 — same value on both curves.
    let mut secret_le = [0u8; 32];
    secret_le[0] = 0x42;
    let secret = AdaptorSecret::from_ristretto_bytes(secret_le)
        .expect("fixture secret must be canonical on Ristretto");

    // T_btc = secret · G_btc (secp256k1 wants big-endian bytes).
    let secp = secp256k1::Secp256k1::new();
    let secret_be = secret.secp256k1_bytes();
    let sk = secp256k1::SecretKey::from_slice(&secret_be).unwrap();
    let t_btc = secp256k1::PublicKey::from_secret_key(&secp, &sk).serialize();

    // T_cync = secret · G_cync (Ristretto, little-endian).
    let t_cync_scalar =
        Curve25519Scalar::from_canonical_bytes(secret.ristretto_bytes()).unwrap();
    let t_cync = (&t_cync_scalar * RISTRETTO_BASEPOINT_TABLE)
        .compress()
        .to_bytes();

    (secret, t_btc, t_cync)
}

fn bench_prove(c: &mut Criterion) {
    let (secret, t_btc, t_cync) = fixture();
    let seed = [0x77u8; 32];
    c.bench_function("strict_dleq::prove", |b| {
        b.iter(|| {
            prove_cross_curve_strict(
                black_box(&secret),
                black_box(&t_btc),
                black_box(&t_cync),
                black_box(&seed),
            )
            .expect("prove")
        });
    });
}

fn bench_verify(c: &mut Criterion) {
    let (secret, t_btc, t_cync) = fixture();
    let seed = [0x77u8; 32];
    let proof = prove_cross_curve_strict(&secret, &t_btc, &t_cync, &seed)
        .expect("setup: prove");
    c.bench_function("strict_dleq::verify", |b| {
        b.iter(|| {
            verify_cross_curve_strict(
                black_box(&proof),
                black_box(&t_btc),
                black_box(&t_cync),
            )
            .expect("verify")
        });
    });
}

criterion_group!(benches, bench_prove, bench_verify);
criterion_main!(benches);
