//! Fuzz target for Bulletproofs range proofs.
//!
//! Range proofs ride alongside every confidential transaction output.
//! A peer-crafted proof byte sequence reaches `RangeProof::from_bytes`
//! before any verification — a panic there is a remote DoS vector.

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = coincync::crypto::RangeProof::from_bytes(data);
});
