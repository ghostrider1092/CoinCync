//! Fuzz target for wallet-file deserialization.
//!
//! Uses `load_wallet_from_bytes` directly (skips file I/O) — same parser
//! as `load_wallet` but no tempfile thrash, faster fuzz.

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // load_wallet_from_bytes(bytes: &[u8], password: Option<&str>) -> Result<WalletData>
    let _ = coincync::wallet::persistence::load_wallet_from_bytes(data, None);
    let _ = coincync::wallet::persistence::load_wallet_from_bytes(data, Some("fuzz-passphrase"));
});
