//! Fuzz target for PoW hashing (`src/consensus/pow.rs`).
//!
//! Wraps the RandomX FFI — the only `unsafe` boundary in the tree.
//! ASAN earns its keep here: heap-overflow in the C++ RandomX library
//! would surface as an ASAN report. Random `mixed_hash` / `nonce` /
//! `height` arguments stress the FFI marshalling.

#![no_main]

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;

#[derive(Arbitrary, Debug)]
struct PowInput {
    prev_hash: [u8; 32],
    height: u64,
    timestamp: u64,
    nonce: u64,
    tx_root: [u8; 32],
    algorithm_idx: u8,
}

fuzz_target!(|input: PowInput| {
    use coincync::consensus::pow;
    use coincync::primitives::Hash;

    // Build the anchor; compute_full_anchor takes prev_hash + height + ts.
    let prev = Hash::from_bytes(input.prev_hash);
    let tx_root = Hash::from_bytes(input.tx_root);
    let _anchor = pow::compute_full_anchor(&prev, input.height, input.timestamp);

    // Real signature: compute_pow_hash(algo: PowAlgorithm, anchor: &Hash,
    //   nonce: u64, tx_root: &Hash, height: u64) -> Result<Hash>
    let algo = pow::PowAlgorithm::from_index(input.algorithm_idx);
    let _ = pow::compute_pow_hash(algo, &prev, input.nonce, &tx_root, input.height);
});
