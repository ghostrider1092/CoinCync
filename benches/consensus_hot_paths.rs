//! # Consensus hot-path benchmarks
//!
//! Companion to `crypto_hot_paths.rs`. Those measure the CPU-bound *crypto*
//! primitives (RandomX, Bulletproofs+, CLSAG); this file measures the
//! non-crypto consensus arithmetic that runs on the block-connect path but was
//! previously unmeasured:
//!
//!   * the dual-window ASERT difficulty adjustment (once per block), and
//!   * the emission / supply-commitment math (once per block).
//!
//! Run with:
//!
//! ```text
//! cargo bench --features "randomx testnet" --bench consensus_hot_paths
//! ```
//!
//! These are pure integer functions, so they should be orders of magnitude
//! cheaper than the crypto path — the point of the baseline is to *prove* that
//! (so any future change that accidentally makes difficulty or emission
//! expensive is caught) and to guard against regressions in the fixed-point
//! `u128` math, which is deliberately branch-light for cross-arch determinism.

use criterion::{criterion_group, criterion_main, Criterion};
use std::hint::black_box;

use coincync::consensus::{calculate_difficulty, max_target, DifficultyBlock};
use coincync::emission::{
    base_reward, base_reward_from_supply, calculate_supply_commitment, SupplyStats,
};
use coincync::primitives::Amount;

/// Target inter-block time (seconds). Matches `constants::TARGET_BLOCK_TIME`.
const TARGET_BLOCK_TIME: u64 = 120;

/// Build a synthetic difficulty window of `n` evenly-spaced blocks. `n` must
/// exceed `DIFFICULTY_LONG_WINDOW` (144) so `calculate_difficulty` exercises
/// both the short and long ASERT anchors, i.e. the real per-block cost.
fn build_difficulty_window(n: usize) -> Vec<DifficultyBlock> {
    let target = max_target();
    (0..n)
        .map(|i| DifficultyBlock {
            height: i as u64,
            timestamp: 1_600_000_000 + (i as u64) * TARGET_BLOCK_TIME,
            target,
        })
        .collect()
}

// ─── Dual-window ASERT difficulty adjustment ──────────────────────────
//
// Runs once per block during validation and once per template during mining.
fn bench_difficulty_asert(c: &mut Criterion) {
    let blocks = build_difficulty_window(200); // > 144 long window
    let current_height = blocks.len() as u64;
    c.bench_function("difficulty_asert_dual_window", |b| {
        b.iter(|| {
            black_box(calculate_difficulty(
                black_box(&blocks),
                black_box(current_height),
            ))
        });
    });
}

// ─── Emission: canonical supply-based reward ──────────────────────────
//
// `base_reward_from_supply` is the consensus-authoritative subsidy path (u128
// cumulative supply to avoid 10^20 overflow). Runs once per block.
fn bench_emission_base_reward_from_supply(c: &mut Criterion) {
    // Illustrative mid-curve cumulative supply in atomic units (~well below the
    // 100M cap). The value only shapes which branch of the curve is taken; the
    // arithmetic is effectively constant-time regardless.
    let supply: u128 = 50_000_000_000_000_000_000;
    c.bench_function("emission_base_reward_from_supply", |b| {
        b.iter(|| black_box(base_reward_from_supply(black_box(supply))));
    });
}

// ─── Emission: height-based reward (templates / display) ──────────────
fn bench_emission_base_reward_by_height(c: &mut Criterion) {
    c.bench_function("emission_base_reward_by_height", |b| {
        b.iter(|| black_box(base_reward(black_box(1_000_000u64))));
    });
}

// ─── Supply commitment hash ───────────────────────────────────────────
//
// Folded into the per-block supply accounting; a cheap hash but on the hot path.
fn bench_supply_commitment(c: &mut Criterion) {
    let stats = SupplyStats::new(
        Amount::from_atomic(50_000_000_000_000),
        Amount::from_atomic(1_000_000_000),
        Amount::from_atomic(50_000_000_000_000),
        false,
    );
    c.bench_function("supply_commitment", |b| {
        b.iter(|| black_box(calculate_supply_commitment(black_box(&stats))));
    });
}

criterion_group!(
    consensus_hot_paths,
    bench_difficulty_asert,
    bench_emission_base_reward_from_supply,
    bench_emission_base_reward_by_height,
    bench_supply_commitment,
);
criterion_main!(consensus_hot_paths);
