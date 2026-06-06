//! Fuzz target for cyncswap adaptor-signature byte parsing.
//!
//! Three byte-array constructors: `from_bytes`, `from_secp256k1_bytes`,
//! `from_ristretto_bytes`. All reachable from peer-controlled input
//! during the cyncswap handshake. A panic = swap-mid-flight DoS.

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    use coincync_swap::adaptor::AdaptorSecret;

    if data.len() >= 32 {
        let mut b = [0u8; 32];
        b.copy_from_slice(&data[..32]);

        let _ = AdaptorSecret::from_bytes(b);
        let _ = AdaptorSecret::from_secp256k1_bytes(b);
        let _ = AdaptorSecret::from_ristretto_bytes(b);
    }
});
