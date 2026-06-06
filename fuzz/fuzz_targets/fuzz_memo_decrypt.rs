//! Fuzz target for encrypted memo decryption.
//!
//! Every tx with an encrypted memo runs through `decrypt_memo`. A panic
//! on attacker-crafted ciphertext + AD = remote DoS via crafted memo
//! delivered to any wallet that scans the tx.

#![no_main]

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;

#[derive(Arbitrary, Debug)]
struct MemoInput {
    ciphertext: Vec<u8>,
    view_secret: [u8; 32],
    tx_public: [u8; 32],
}

fuzz_target!(|input: MemoInput| {
    use coincync::crypto::memo::decrypt_memo;

    // decrypt_memo signature: (encrypted: &[u8], view_secret_bytes: &[u8; 32],
    // tx_public_key_bytes: &[u8; 32]) — takes raw byte arrays, not SecretKey.
    let _ = decrypt_memo(&input.ciphertext, &input.view_secret, &input.tx_public);
});
