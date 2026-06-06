//! Fuzz target for MimbleWimble cut-through kernel-set verification.
//!
//! `verify_kernel_set` enforces the kernel-excess invariant that defends
//! against the MW kernel-inflation class (Grin near-miss 2019). A panic
//! here = consensus-halt blast radius.

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // The MwKernel type is wire-format-serializable; feed bytes through
    // its borsh decoder + the verify path.
    // Actual type is `CutThroughEngine`, not `MwCutThrough`
    // (src/crypto/mw_cutthrough.rs line 111).
    if let Ok(kernels) = borsh::from_slice::<Vec<coincync::crypto::mw_cutthrough::MwKernel>>(data) {
        let _ = coincync::crypto::mw_cutthrough::CutThroughEngine::verify_kernel_set(&kernels);
    }
});
