//! # Sluice parallel-verify speedup benchmark (Warren Phase 0 — §3.7)
//!
//! Quantifies the throughput of the unified heavy-verify valve
//! (`crypto::heavy_verify::Sluice`) across widths, over a batch of real
//! Bulletproof range proofs, so the parallel speedup is MEASURED (not assumed)
//! and a regression — e.g. accidental serialization, or pool oversubscription —
//! shows up against criterion's stored baseline.
//!
//! Run:
//! ```text
//! cargo bench --features testnet --bench sluice_verify
//! ```
//!
//! Width `1` is the serial valve (the baseline); `2/4/8` fan out on the
//! dedicated pool. Throughput is reported in elements/s (proofs verified per
//! second), so the speedup is read directly off the ratio. Setup (proof
//! construction) is excluded — only the batch verify is timed.

use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use rand::rngs::OsRng;
use std::hint::black_box;

use coincync::crypto::transparent_sluice::{verify_range_proofs_via_sluice, RangeProofItem};
use coincync::crypto::{commit, create_range_proof, Sluice};
use coincync::primitives::Amount;

/// Pre-build `n` valid (commitment, range-proof) items once, outside the timed
/// section.
fn build_items(n: usize) -> Vec<RangeProofItem> {
    (0..n)
        .map(|i| {
            let amount = Amount::from_atomic(100_000 + i as u64);
            let (commitment, blinding) = commit(&mut OsRng, amount);
            let proof =
                create_range_proof(amount, &blinding, &mut OsRng).expect("create_range_proof");
            RangeProofItem {
                commitment: commitment.to_bytes(),
                proof_bytes: proof.try_to_bytes().expect("proof bytes"),
            }
        })
        .collect()
}

fn bench_sluice_widths(c: &mut Criterion) {
    const N: usize = 64;
    let items = build_items(N);

    let mut group = c.benchmark_group("sluice_range_verify");
    group.throughput(Throughput::Elements(N as u64));
    for width in [1usize, 2, 4, 8] {
        // width 1 = the serial valve baseline; >1 fans out on the pool.
        let valve = if width == 1 {
            Sluice::serial()
        } else {
            Sluice::with_threads(width)
        };
        group.bench_with_input(BenchmarkId::from_parameter(width), &width, |b, _| {
            b.iter(|| black_box(verify_range_proofs_via_sluice(black_box(&items), &valve)));
        });
    }
    group.finish();
}

criterion_group!(sluice_verify, bench_sluice_widths);
criterion_main!(sluice_verify);
