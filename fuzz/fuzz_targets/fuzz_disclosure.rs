//! Fuzz target for selective-disclosure proof verification.
//!
//! `verify_balance_proof` + `verify_ownership_proof` + `verify_sum_proof`
//! are reachable when a wallet hands a proof to a verifier (e.g.,
//! exchange audit). Peer-supplied proofs reach the verifier; panic =
//! verifier DoS.

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // `mod disclosure` is private — types come through the top-level
    // re-export at src/crypto/mod.rs. `BalanceProof` collides so it's
    // re-exported as `DisclosureBalanceProof`.
    use coincync::crypto::{
        verify_balance_proof, verify_ownership_proof,
        DisclosureBalanceProof, OwnershipProof,
    };

    // BalanceProof + OwnershipProof derive serde only (not borsh).
    if let Ok(p) = serde_json::from_slice::<DisclosureBalanceProof>(data) {
        let _ = verify_balance_proof(&p);
    }
    if let Ok(p) = serde_json::from_slice::<OwnershipProof>(data) {
        let _ = verify_ownership_proof(&p);
    }
});
