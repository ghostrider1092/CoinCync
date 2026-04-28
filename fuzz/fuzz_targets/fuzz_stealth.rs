//! Fuzz target for stealth address operations
//!
//! Tests stealth address generation and output scanning with malformed inputs.

#![no_main]

use libfuzzer_sys::fuzz_target;
use arbitrary::Arbitrary;

/// Fuzz input for stealth address operations
#[derive(Arbitrary, Debug)]
struct StealthFuzzInput {
    /// View key bytes
    view_key: [u8; 32],
    /// Spend key bytes
    spend_key: [u8; 32],
    /// Transaction public key bytes
    tx_public_key: [u8; 32],
    /// Stealth address bytes
    stealth_address: [u8; 32],
    /// Output index
    output_index: u8,
    /// Epoch for key rotation
    epoch: u32,
}

fuzz_target!(|input: StealthFuzzInput| {
    use coincync::crypto::stealth;
    use coincync::primitives::{SecretKey, PublicKey};

    // Try to create view key from bytes
    let view_secret = SecretKey::from_bytes(input.view_key);

    // Try to create spend public key
    let spend_public = PublicKey::from_bytes(input.spend_key);

    // Try to create tx public key
    let tx_public = PublicKey::from_bytes(input.tx_public_key);

    // Try to create stealth address
    let stealth = PublicKey::from_bytes(input.stealth_address);

    // Test is_output_ours - should not panic
    let _ = stealth::is_output_ours(
        &view_secret,
        &spend_public,
        &tx_public,
        &stealth,
        input.output_index as usize,
    );

    // Test with epoch
    let _ = stealth::is_output_ours_with_epoch(
        &view_secret,
        &spend_public,
        &tx_public,
        &stealth,
        input.output_index as usize,
        input.epoch,
    );
});
