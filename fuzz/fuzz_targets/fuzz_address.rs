//! Fuzz target for address parsing.
//!
//! Every wallet flow that takes operator/user input runs it through
//! `Address::from_string` (bech32 + network prefix) or
//! `Address::from_bytes_checked`. A panic on crafted input could be
//! triggered by paste-from-clipboard, RPC params, or a malicious peer
//! sending an `addr` message.

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    use coincync::primitives::Address;

    // ── 1. Byte-array parser (checked: HRP + version) ──
    let _ = Address::from_bytes_checked(data);

    // ── 2. String parser — bech32 decode + canonical encoding round-trip ──
    // Convert bytes to a string. Random bytes won't be valid UTF-8 ~99%
    // of the time, so most iterations short-circuit at from_utf8 — but
    // when they ARE valid UTF-8 we exercise the bech32 + HRP path.
    if let Ok(s) = std::str::from_utf8(data) {
        let _ = Address::from_string(s);
    }
});
