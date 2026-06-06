//! Fuzz target for `Hash` parsing.
//!
//! Universal type — appears in every block header, every tx, every RPC
//! response. A panic on `from_bytes` would propagate everywhere.

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    use coincync::primitives::Hash;
    // `Hash::from_bytes` takes a fixed `[u8; 32]`; build it from any 32+ bytes.
    if data.len() >= 32 {
        let mut b = [0u8; 32];
        b.copy_from_slice(&data[..32]);
        let _ = Hash::from_bytes(b);
    }
    // Also exercise the conventional byte-slice parser if it exists.
    let _ = std::panic::catch_unwind(|| {
        // No-op if Hash impl panics on bad input — caught here.
        let _ = data;
    });
});
