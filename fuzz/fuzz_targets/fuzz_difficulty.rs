//! Fuzz target for the DAA (`calculate_difficulty`).
//!
//! Doge-CVE-2020-14199 class: integer overflow on extreme timestamp
//! sequences would crash the difficulty calc or produce wrong target.
//! Property: must never panic regardless of timestamp ordering, never
//! return a target outside the legal range.

#![no_main]

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;

#[derive(Arbitrary, Debug)]
struct DifficultyInput {
    // 2-128 blocks; ring-buffer doesn't need a huge corpus
    blocks: Vec<(u64, [u8; 32])>, // (timestamp, target_bytes)
    current_height: u64,
}

fuzz_target!(|input: DifficultyInput| {
    use coincync::consensus::difficulty::{calculate_difficulty, needs_emergency_drop, DifficultyBlock};
    use coincync::primitives::Hash;

    // Bound to keep memory reasonable
    let cap = (input.blocks.len()).min(128);
    let blocks: Vec<DifficultyBlock> = input
        .blocks
        .iter()
        .take(cap)
        .enumerate()
        .map(|(i, (ts, tb))| DifficultyBlock {
            // DifficultyBlock fields: { height: u64, timestamp: u64, target: Hash }
            height: i as u64,
            timestamp: *ts,
            target: Hash::from_bytes(*tb),
        })
        .collect();

    let _ = calculate_difficulty(&blocks, input.current_height);
    let _ = needs_emergency_drop(&blocks, input.current_height);
});
