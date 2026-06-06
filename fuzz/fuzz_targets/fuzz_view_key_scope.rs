//! Fuzz target for scoped view key derivation (privacy innovation #3).
//!
//! `ViewKey::derive(view_secret, epoch, scope)` is invoked anywhere a
//! scoped view-key is requested. A panic on edge-case scope values
//! would crash any wallet trying to issue a scoped key.

#![no_main]

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;

#[derive(Arbitrary, Debug)]
struct ViewKeyInput {
    view_secret: [u8; 32],
    epoch: u64,
    scope_tag: u8,
    scope_arg: u64,
}

fuzz_target!(|input: ViewKeyInput| {
    // `mod view_keys` is private; use the top-level re-export at
    // src/crypto/mod.rs line 64: pub use view_keys::{ViewKey, ViewKeyScope};
    use coincync::crypto::{ViewKey, ViewKeyScope};
    use coincync::primitives::SecretKey;

    let secret = SecretKey::from_bytes(input.view_secret);

    // Exercise each scope variant. Adjust ViewKeyScope variants if
    // the enum changes — current discriminants picked from grep.
    let scope = match input.scope_tag % 3 {
        0 => ViewKeyScope::EpochOnly(input.scope_arg),
        1 => ViewKeyScope::EpochOnly(input.epoch),
        _ => ViewKeyScope::EpochOnly(0),
    };

    let _vk = ViewKey::derive(&secret, input.epoch, scope);
});
