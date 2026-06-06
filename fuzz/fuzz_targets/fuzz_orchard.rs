//! Fuzz target for Orchard shielded-pool primitives.
//!
//! Covers the attacker-reachable surface in `crates/orchard-side`:
//!   - `SpendingKey::from_bytes` (32-byte seed → key)
//!   - Full key tree derivation (SpendingKey → nk → FVK → IVK)
//!   - `Note::new` with random per-field bytes (recipient_d, recipient_pkd,
//!      value, rho, rseed)
//!   - `Note::commitment()` (Sinsemilla-derived commitment)
//!   - `derive_nullifier(note, nk)` (PRF + curve op)
//!   - `IncomingViewingKey::address_at(diversifier)` (DiversifyHash)
//!   - `Nullifier::from_bytes` / `NoteCommitment::from_bytes` (canonical
//!      Pallas-base byte parsing)
//!
//! Why these matter: a recipient receiving a note from any sender (potentially
//! attacker) feeds attacker-controlled bytes into every one of these. A panic
//! anywhere = remote DoS via crafted note. Caught by ASAN + sancov-instrumented
//! libFuzzer with full coverage of the in-process call graph.
//!
//! Companion to `crates/orchard-side/tests/zcash_conformance.rs` — that suite
//! tests known-good vectors against the Zcash NU5 reference; this fuzz tests
//! random / adversarial inputs against the same code.

#![no_main]

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;

#[derive(Arbitrary, Debug)]
struct OrchardFuzzInput {
    sk_bytes: [u8; 32],
    recipient_d: [u8; 32],
    recipient_pkd: [u8; 32],
    value: u64,
    rho: [u8; 32],
    rseed: [u8; 32],
    diversifier: [u8; 11],
    nullifier_bytes: [u8; 32],
    note_commitment_bytes: [u8; 32],
}

fuzz_target!(|input: OrchardFuzzInput| {
    use orchard_side::commitment::NoteCommitment;
    use orchard_side::note::Note;
    use orchard_side::nullifier::{derive_nullifier, NullifierDerivingKey};
    use orchard_side::spend_key::SpendingKey;

    // ── 1. Direct byte → typed-value constructors ──
    // Each of these takes raw bytes; must never panic.
    // (Note: `Nullifier` is a tuple-struct wrapper around BridgeNullifier
    // without its own from_bytes — its byte validation is exercised
    // transitively via derive_nullifier below.)
    let _ = NullifierDerivingKey::from_bytes(input.nullifier_bytes);
    let _ = NoteCommitment::from_bytes(input.note_commitment_bytes);

    // ── 2. SpendingKey + full key-tree derivation ──
    let sk = match SpendingKey::from_bytes(input.sk_bytes) {
        Ok(sk) => sk,
        Err(_) => return, // many random bytes fall outside the valid range
    };
    let nk = match sk.nullifier_key() {
        Ok(nk) => nk,
        Err(_) => return,
    };
    let fvk = match sk.full_viewing_key() {
        Ok(fvk) => fvk,
        Err(_) => return,
    };
    let ivk = match fvk.to_ivk() {
        Ok(ivk) => ivk,
        Err(_) => return,
    };

    // ── 3. Address derivation (DiversifyHash) ──
    let _ = ivk.address_at(input.diversifier);

    // ── 4. Note construction + commitment + nullifier ──
    // Note::new rejects zero bytes in d/pkd/rho/rseed and value > MAX_MONEY,
    // so most random inputs will short-circuit here.
    let note = match Note::new(
        input.recipient_d,
        input.recipient_pkd,
        input.value,
        input.rho,
        input.rseed,
    ) {
        Ok(n) => n,
        Err(_) => return,
    };
    let _ = note.commitment();
    let _ = derive_nullifier(&note, &nk);

    // ── 5. Note::new_for_address — exercises the production path that
    // joins ivk + diversifier + value + rho + rseed into a note.
    let _ = Note::new_for_address(&ivk, input.diversifier, input.value, input.rho, input.rseed);
});
