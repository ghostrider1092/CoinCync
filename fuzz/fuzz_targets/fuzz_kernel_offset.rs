//! Fuzz target for MimbleWimble kernel-offset operations.
//!
//! `KernelOffset::as_scalar` + `aggregate` are reachable from peer-
//! supplied offset bytes. Property: scalar parsing should fail
//! gracefully (return None) for invalid bytes, never panic.

#![no_main]

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;

#[derive(Arbitrary, Debug)]
struct KernelOffsetInput {
    a: [u8; 32],
    b: [u8; 32],
}

fuzz_target!(|input: KernelOffsetInput| {
    use coincync::crypto::kernel_offset::KernelOffset;

    let k1 = KernelOffset(input.a);
    let k2 = KernelOffset(input.b);

    // Each of these must short-circuit on invalid bytes, never panic.
    let _ = k1.as_scalar();
    let _ = k2.as_scalar();
    let _ = k1.aggregate(k2);
});
