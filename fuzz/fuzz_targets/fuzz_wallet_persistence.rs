//! Fuzz target for wallet-file deserialization.
//!
//! Uses `load_wallet_from_bytes` directly (skips file I/O) — same parser
//! as `load_wallet` but no tempfile thrash, faster fuzz.
//!
//! STEP 7 of wallet-v4 implementation (2026-05-25):
//! - Existing `load_wallet_from_bytes` calls already exercise v4 framing
//!   indirectly via the version-byte auto-detect (when fuzz input has
//!   bytes[8] == 0x04, dispatch routes to load_v4_from_bytes).
//! - Added an EXPLICIT `load_v4_from_bytes` call so the v4 parser
//!   surface is fuzzed even when libfuzzer happens not to produce a
//!   bytes[8] == 0x04 input via the dispatch path.
//! - Both calls receive the same input — the v4 call exercises the
//!   HMAC parse + verify path, the v3 call exercises the v3 framing.
//!   Each catches a different bug class.

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // v3 path (also catches v4 via auto-detect when bytes[8] == 0x04).
    // No-password and with-password to exercise both branches —
    // unencrypted wallets skip Argon2 + AEAD entirely.
    let _ = coincync::wallet::persistence::load_wallet_from_bytes(data, None);
    let _ = coincync::wallet::persistence::load_wallet_from_bytes(data, Some("fuzz-passphrase"));

    // v4 path — direct call. Catches:
    //   - Framing-parse bugs in the v4 prelude reader (hdr_len, ct_len)
    //   - WalletHeader::validate() crash classes specific to v4 (the
    //     v4 path runs validate() too, after the framing parse)
    //   - HMAC-prelude length-calc bugs (e.g., off-by-one on the
    //     V4_HMAC_BYTES suffix)
    //
    // Any panic here is a parser bug — the load path must reject
    // malformed input via Result, not unwrap.
    //
    // NOTE: this call ALWAYS does an Argon2 run (~150-600ms in
    // light-mode) when the framing parse passes. That makes the fuzz
    // exec/s look slower than the v3 path for the same input, but
    // it's the only way to exercise the v4 HMAC-verify code path
    // post-Argon2. Worth it.
    let _ = coincync::wallet::persistence::load_v4_from_bytes(data, "fuzz-passphrase");
});
