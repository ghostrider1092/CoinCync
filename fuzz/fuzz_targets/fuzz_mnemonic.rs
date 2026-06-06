//! Fuzz target for BIP-39 mnemonic parsing.
//!
//! Every wallet onboarding rides through `Mnemonic::from_phrase`. NFKD
//! normalization, wordlist boundary, checksum — every BIP-39 impl that
//! ever shipped had a bug in one of these.

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // `coincync::wallet::mnemonic::Mnemonic` is internal — the wallet
    // wrapper just re-exposes `bip39::Mnemonic`. Fuzz the underlying
    // crate directly so we hit the same parse path the wallet uses.
    use bip39::{Language, Mnemonic};

    if let Ok(s) = std::str::from_utf8(data) {
        // Mnemonic::parse_in is the canonical entrypoint (handles NFKD
        // normalization, wordlist + checksum verification). English is
        // the only wordlist the wallet wires; matches production.
        let _ = Mnemonic::parse_in(Language::English, s);
    }
});
