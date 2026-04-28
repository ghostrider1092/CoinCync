//! Fuzz target for CLSAG ring signatures
//!
//! Tests that CLSAG verification handles malformed inputs without panicking.

#![no_main]

use libfuzzer_sys::fuzz_target;
use arbitrary::Arbitrary;

/// Fuzz input for CLSAG verification
#[derive(Arbitrary, Debug)]
struct ClsagFuzzInput {
    /// Message to sign
    message: Vec<u8>,
    /// Raw signature bytes
    signature_data: Vec<u8>,
    /// Ring size (1-32)
    ring_size: u8,
    /// Random data for ring members
    ring_data: Vec<u8>,
}

fuzz_target!(|input: ClsagFuzzInput| {
    // Limit ring size to prevent OOM
    let ring_size = (input.ring_size % 32).max(2) as usize;

    // Skip if not enough data for ring
    if input.ring_data.len() < ring_size * 64 {
        return;
    }

    // Try to parse signature
    if let Ok(sig) = coincync::crypto::ClsagSignature::from_bytes(&input.signature_data) {
        // Verify ring_size matches
        if sig.ring_size() != ring_size {
            return;
        }

        // Create dummy ring members from fuzz data
        // This tests that verification handles invalid rings gracefully
        let mut ring = Vec::with_capacity(ring_size);
        for i in 0..ring_size {
            let offset = i * 64;
            if offset + 64 > input.ring_data.len() {
                return;
            }

            let mut pk_bytes = [0u8; 32];
            let mut commitment_bytes = [0u8; 32];
            pk_bytes.copy_from_slice(&input.ring_data[offset..offset + 32]);
            commitment_bytes.copy_from_slice(&input.ring_data[offset + 32..offset + 64]);

            // Create ring member with potentially invalid point data
            let pk = coincync::crypto::curve::PublicPoint::from_bytes(pk_bytes);
            let commitment = coincync::crypto::curve::Commitment::from_bytes(commitment_bytes);
            ring.push(coincync::crypto::ClsagRingMember::new(pk, commitment));
        }

        // Create pseudo-output commitment
        let pseudo_bytes = if input.ring_data.len() >= 32 {
            let mut b = [0u8; 32];
            b.copy_from_slice(&input.ring_data[..32]);
            b
        } else {
            [0u8; 32]
        };
        let pseudo = coincync::crypto::curve::Commitment::from_bytes(pseudo_bytes);

        // This should not panic regardless of input
        let _ = coincync::crypto::clsag_verify(&input.message, &ring, &pseudo, &sig);
    }
});
