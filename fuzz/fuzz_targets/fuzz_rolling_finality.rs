//! Fuzz target for ed25519-based rolling-finality attestation verification.
//!
//! Consensus-critical: a panic in the verifier = consensus halt across
//! every node that sees the malformed attestation. The verifier is small
//! enough to fuzz to saturation in an hour.
//!
//! Public types: `FinalityAttestation`, `RecordedAttestation`,
//! `MinerPubkey`, `BlockHash` are re-exported from `crates/coincync-rolling-
//! finality/src/lib.rs` (line 82) via `pub use types::{...}`. The Ed25519
//! verifier sits behind `#[cfg(feature = "ed25519")]`.

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // The canonical wire-format decoder, gated behind the `wire-codec`
    // feature (enabled in fuzz/Cargo.toml). It's the borsh-based
    // entrypoint used on inbound bytes — exactly what an attacker
    // would deliver. FinalityAttestation itself only derives serde,
    // not borsh, so this is the right entrypoint to fuzz.
    let _ = coincync_rolling_finality::decode(data);
});
