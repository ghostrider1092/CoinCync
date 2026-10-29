//! Benchmarks for the v2 cross-curve DLEQ (`coincync_swap::cross_curve_dleq`).
//!
//! Run:
//!     cargo bench -p coincync-swap --bench cross_curve_dleq
//!
//! - `prove`  — 252 joint bit commitments and OR proofs plus the two link
//!   proofs.
//! - `verify` — decoding a 56,608-byte proof and recomputing every
//!   announcement. This is the path a peer can make us run; it bounds the
//!   verify-side DoS cost per received proof.

use coincync_swap::adaptor::{cync_adaptor_point, AdaptorSecret};
use coincync_swap::cross_curve_dleq::{prove, verify, CrossCurveProof, CrossCurveStatement};
use criterion::{criterion_group, criterion_main, Criterion};
use rand::rngs::StdRng;
use rand::SeedableRng;
use std::hint::black_box;

fn fixture() -> (AdaptorSecret, CrossCurveStatement) {
    let mut secret_le = [0x5au8; 32];
    secret_le[31] = 0x05; // below 2^252
    let secret = AdaptorSecret::from_ristretto_bytes(secret_le).expect("canonical fixture");
    let btc = secret.public_point().serialize();
    let cync = cync_adaptor_point(&secret).expect("fixture point");
    let statement = CrossCurveStatement::new(&btc, &cync, b"bench").expect("valid fixture");
    (secret, statement)
}

fn bench_prove(c: &mut Criterion) {
    let (secret, statement) = fixture();
    let mut rng = StdRng::seed_from_u64(1);
    c.bench_function("cross_curve_dleq/prove", |b| {
        b.iter(|| {
            black_box(prove(black_box(&secret), black_box(&statement), &mut rng).unwrap());
        });
    });
}

fn bench_verify(c: &mut Criterion) {
    let (secret, statement) = fixture();
    let bytes = prove(&secret, &statement, &mut StdRng::seed_from_u64(2))
        .unwrap()
        .to_bytes();
    c.bench_function("cross_curve_dleq/decode_and_verify", |b| {
        b.iter(|| {
            let proof = CrossCurveProof::from_bytes(black_box(&bytes)).unwrap();
            verify(&proof, black_box(&statement)).unwrap();
        });
    });
}

criterion_group!(benches, bench_prove, bench_verify);
criterion_main!(benches);
