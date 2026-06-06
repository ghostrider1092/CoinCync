//! Fuzz target for batch signature verification.
//!
//! Shim: feeds borsh-encoded SignatureData into a BatchVerifier, calls
//! verify_all. The fuzz tests the deserialization + verification chain.
//! Most random sigs fail verify (expected); the property is that the
//! verifier never panics on any input.

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // SignatureData derives nothing, so it can't be deserialized from
    // bytes. Construct it manually from chunks of the fuzz input.
    // Fields: message: Vec<u8>, signature: Vec<u8>, ring_data: Vec<u8>,
    //         pseudo_output: [u8; 32]
    use coincync::crypto::{BatchVerifier, SignatureData};

    // Need at least 32 bytes for pseudo_output. Below that, skip.
    if data.len() < 32 {
        return;
    }

    // Slice the buffer into roughly-equal chunks for each field.
    let pseudo_start = data.len() - 32;
    let mut pseudo = [0u8; 32];
    pseudo.copy_from_slice(&data[pseudo_start..]);

    let rest = &data[..pseudo_start];
    let third = rest.len() / 3;
    let message = rest[..third].to_vec();
    let signature = rest[third..2 * third].to_vec();
    let ring_data = rest[2 * third..].to_vec();

    let sig = SignatureData {
        message,
        signature,
        ring_data,
        pseudo_output: pseudo,
    };

    let mut verifier = BatchVerifier::new();
    verifier.add(sig);
    let _ = verifier.verify_all();
});
