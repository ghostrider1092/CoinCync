//! Property-based invariants for cyncswap cryptographic primitives.
//!
//! This file complements `external_vectors.rs` (which validates against
//! published reference vectors) and the fuzz suite (which proves no input
//! crashes the code). Property tests close the third gap: they assert
//! that the math actually *holds* on every well-formed input, not just
//! that it doesn't crash.
//!
//! ## What each property defends against
//!
//! - `btc_adaptor_roundtrip` / `cync_adaptor_roundtrip` — a regression
//!   that broke the `create → verify → decrypt → recover` cycle would
//!   silently fail to extract the adaptor secret on the other chain.
//!   That's the "Bob can't claim CYNC after Alice claims BTC" failure
//!   mode (Step 9 of the user flow). The cap caps user loss, but the
//!   trade-completion rate would collapse without this invariant.
//!
//! - `btc_adaptor_binding` — the most important property. A bug in the
//!   binding would let an attacker complete the swap with the *wrong*
//!   adaptor secret and broadcast a sig that nevertheless verifies under
//!   Bitcoin's consensus. That's the principal-loss vector that the cap
//!   *cannot* fully cap because the bug applies to every swap. This
//!   property explicitly bounces the wrong-secret case off the actual
//!   `secp256k1::Schnorr` verifier — if it ever passes that check, we
//!   have a critical bug.
//!
//! - `dleq_roundtrip` — DLEQ proofs constructed honestly must verify.
//!   A regression here breaks every swap (the swap state machine refuses
//!   to lock without a verified cross-curve proof).
//!
//! ## Why properties + fuzz + vectors are all needed
//!
//! | Threat | Fuzz | Vectors | Properties |
//! | --- | --- | --- | --- |
//! | Crash on bad input | ✓ | — | — |
//! | Output differs from reference impl | — | ✓ | — |
//! | Math holds on every valid input | — | — | ✓ |
//!
//! Each catches a class the others miss. None substitutes for the
//! external audit, but together they make the audit firm's job tractable
//! (and cheaper).
//!
//! ## Reproducing a failure
//!
//! proptest prints a minimized failing input and writes it to
//! `proptest-regressions/property_invariants.txt`. To re-run only the
//! failing case after a fix:
//!
//! ```sh
//! cargo test --test property_invariants -- <failing_test_name>
//! ```
//!
//! See [`docs/property-testing.md`](../../../docs/property-testing.md)
//! for the project-wide discipline (when to add new properties, how to
//! triage failures, expected runtime budgets).

#![cfg(not(miri))]

use proptest::prelude::*;
use secp256k1::{PublicKey, Secp256k1, SecretKey};

use coincync_swap::adaptor::{
    create_pre_sig_bip340, cync_adaptor_point, cync_create_pre_sig, cync_decrypt_adaptor,
    cync_recover_secret, cync_verify_pre_sig, decrypt_btc_adaptor, prove_cross_curve,
    recover_secret_from_btc_sig, verify_cross_curve_proof, verify_pre_sig, AdaptorSecret,
};

// ─── Strategies ───────────────────────────────────────────────

/// A secp256k1 secret key — uniform over the (1..n) scalar range.
///
/// The probability that random 32 bytes are NOT a valid secp256k1
/// scalar is ~2^-224, so prop_filter rejects almost nothing.
fn arb_secp_seckey() -> impl Strategy<Value = SecretKey> {
    any::<[u8; 32]>().prop_filter_map("valid secp scalar", |bytes| {
        SecretKey::from_slice(&bytes).ok()
    })
}

/// 32-byte Ristretto-canonical scalar (i.e., < ℓ).
///
/// About 1 in 8 random byte sequences are non-canonical (rejected by
/// `AdaptorSecret::from_ristretto_bytes`), so `prop_filter_map` retries
/// transparently.
fn arb_adaptor_secret() -> impl Strategy<Value = AdaptorSecret> {
    any::<[u8; 32]>().prop_filter_map(
        "Ristretto-canonical scalar (valid in both fields)",
        |bytes| AdaptorSecret::from_ristretto_bytes(bytes).ok(),
    )
}

/// Same shape as `arb_adaptor_secret` but exposes the raw bytes so
/// they can be passed to functions like `cync_create_pre_sig` that take
/// `[u8; 32]` directly. We re-roll the strategy rather than expose
/// the bytes from `AdaptorSecret` so the property reads natively.
fn arb_ristretto_canonical_bytes() -> impl Strategy<Value = [u8; 32]> {
    any::<[u8; 32]>().prop_filter("Ristretto-canonical", |bytes| {
        AdaptorSecret::from_ristretto_bytes(*bytes).is_ok()
    })
}

// ─── Properties ───────────────────────────────────────────────

proptest! {
    #![proptest_config(ProptestConfig {
        // 256 cases per property is the proptest default. The crypto
        // primitives are expensive (full Schnorr sig + verify), so this
        // gives ~10 sec/property in release mode. Tune up via the
        // `PROPTEST_CASES` env var if running locally with budget.
        cases: 256,
        .. ProptestConfig::default()
    })]

    /// **BTC adaptor roundtrip:** for any valid (signer key, adaptor
    /// secret, message, aux randomness), the cycle
    ///
    ///   create_pre_sig_bip340 → verify_pre_sig → decrypt_btc_adaptor
    ///                         → recover_secret_from_btc_sig
    ///
    /// returns the *original* adaptor secret, byte-for-byte.
    ///
    /// This is the load-bearing invariant for Step 9 of the swap user
    /// flow: when Alice broadcasts her claim sig, Bob extracts `t`
    /// from it and uses `t` to claim CYNC. If extraction ever returns
    /// the wrong scalar, the swap doesn't complete (Bob's claim sig
    /// won't verify on the CYNC side).
    #[test]
    fn btc_adaptor_roundtrip(
        signer_sk in arb_secp_seckey(),
        secret in arb_adaptor_secret(),
        msg in any::<[u8; 32]>(),
        aux_rand in any::<[u8; 32]>(),
    ) {
        let secp = Secp256k1::new();
        let t_sk = SecretKey::from_slice(&secret.secp256k1_bytes())
            .expect("AdaptorSecret bytes are always valid secp scalars");
        let t_pub = PublicKey::from_secret_key(&secp, &t_sk);

        // create_pre_sig_bip340 can fail in ~0.4% of cases when 8
        // consecutive nonce candidates all have odd-y (R + T). That
        // failure mode is benign at the protocol level (caller rotates
        // aux_rand and retries), so we treat it as "skip this case".
        let (adaptor_sig, signer_x) = match create_pre_sig_bip340(
            &signer_sk, &msg, &t_pub, &aux_rand
        ) {
            Ok(v) => v,
            Err(_) => return Ok(()),
        };

        // The pre-sig must verify against the signer's pubkey + the adaptor point.
        verify_pre_sig(&adaptor_sig, &signer_x, &t_pub, &msg)
            .expect("pre-signature created by create_pre_sig_bip340 must verify");

        // Decrypting with the correct secret yields a 64-byte BIP-340 signature.
        let final_sig = decrypt_btc_adaptor(&adaptor_sig, &secret, &t_pub)
            .expect("decrypt must succeed with the correct secret + adaptor point");

        // Recovering from the final sig + pre-sig yields the original secret.
        let recovered = recover_secret_from_btc_sig(&adaptor_sig, &final_sig)
            .expect("recover from a well-formed final sig must succeed");

        prop_assert_eq!(
            &recovered, &secret,
            "BTC adaptor extraction returned a different secret than was used to decrypt"
        );
    }

    /// **BTC adaptor binding (the principal-loss-class property):**
    /// "decrypting" the pre-sig with the *wrong* adaptor secret must
    /// produce a 64-byte signature that does NOT verify under the
    /// actual BIP-340 Schnorr verifier.
    ///
    /// A bug here would let a malicious counterparty complete the swap
    /// with an arbitrary `t'`, then broadcast a sig that nevertheless
    /// verifies on Bitcoin. The user can't extract `t` from such a sig
    /// (because there is no `t` to extract), so the CYNC-side adaptor
    /// is never unlockable — but the BTC was already taken. That's
    /// the principal-loss scenario the user safety stack tries to
    /// bound; this property is what closes the gap at the protocol
    /// layer rather than just at the wallet-cap layer.
    #[test]
    fn btc_adaptor_binding(
        signer_sk in arb_secp_seckey(),
        secret in arb_adaptor_secret(),
        wrong_secret in arb_adaptor_secret(),
        msg in any::<[u8; 32]>(),
        aux_rand in any::<[u8; 32]>(),
    ) {
        // If the two secrets accidentally collide (Ristretto-canonical
        // → secp256k1 bytes match), the property is vacuous; skip it.
        prop_assume!(secret != wrong_secret);

        let secp = Secp256k1::new();
        let t_sk = SecretKey::from_slice(&secret.secp256k1_bytes())
            .expect("AdaptorSecret bytes are always valid secp scalars");
        let t_pub = PublicKey::from_secret_key(&secp, &t_sk);

        let (adaptor_sig, signer_x) = match create_pre_sig_bip340(
            &signer_sk, &msg, &t_pub, &aux_rand
        ) {
            Ok(v) => v,
            Err(_) => return Ok(()),
        };

        // Decrypt with the WRONG secret. The arithmetic completes but
        // produces a "signature" that should not be a valid Schnorr sig
        // for (signer, msg).
        let bad_final = match decrypt_btc_adaptor(&adaptor_sig, &wrong_secret, &t_pub) {
            Ok(v) => v,
            // Decryption may fail on a degenerate combination; that's
            // already not a successful forgery, so skip.
            Err(_) => return Ok(()),
        };

        // Drive the bytes through the real BIP-340 Schnorr verifier.
        // If this returns Ok(), we have a critical bug.
        let bad_sig = match secp256k1::schnorr::Signature::from_slice(&bad_final) {
            Ok(s) => s,
            Err(_) => return Ok(()),  // Not a parseable Schnorr sig; trivially rejected.
        };
        let msg_obj = secp256k1::Message::from_digest(msg);
        let verifies = secp.verify_schnorr(&bad_sig, &msg_obj, &signer_x).is_ok();

        prop_assert!(
            !verifies,
            "CRITICAL: wrong-secret completion produced a BIP-340 Schnorr signature \
             that verifies. This is the adaptor-binding bug class — principal-loss \
             vector. Reproduce with: signer_sk={:?} secret={:?} wrong_secret={:?} \
             msg={:?} aux_rand={:?}",
            signer_sk, secret, wrong_secret, msg, aux_rand
        );
    }

    /// **CYNC adaptor roundtrip:** same as `btc_adaptor_roundtrip` on
    /// the CYNC (Ristretto255) side. Closes the symmetric "Alice can't
    /// extract `t` from Bob's CYNC-side claim" failure mode.
    #[test]
    fn cync_adaptor_roundtrip(
        signer_sk_bytes in arb_ristretto_canonical_bytes(),
        secret in arb_adaptor_secret(),
        msg in any::<[u8; 32]>(),
        nonce_bytes in arb_ristretto_canonical_bytes(),
    ) {
        let t_point = cync_adaptor_point(&secret)
            .expect("adaptor point derivation must succeed for any valid secret");

        let (adaptor_sig, signer_pub) = cync_create_pre_sig(
            &signer_sk_bytes, &msg, &t_point, &nonce_bytes
        ).expect("CYNC pre-sig creation must succeed for valid inputs");

        cync_verify_pre_sig(&adaptor_sig, &signer_pub, &t_point, &msg)
            .expect("CYNC pre-sig must verify after creation");

        let final_sig = cync_decrypt_adaptor(&adaptor_sig, &secret, &t_point)
            .expect("CYNC decrypt must succeed with the correct secret");

        let recovered = cync_recover_secret(&adaptor_sig, &final_sig)
            .expect("CYNC recover must succeed on the well-formed final sig");

        prop_assert_eq!(
            &recovered, &secret,
            "CYNC adaptor extraction returned a different secret than was used to decrypt"
        );
    }

    /// **Cross-curve DLEQ roundtrip:** for any valid (adaptor secret,
    /// nonce), the proof
    ///
    ///   prove_cross_curve(secret, T_btc, T_cync, k)
    ///   → verify_cross_curve_proof(proof, T_btc, T_cync)
    ///
    /// must verify. This invariant ensures the swap state machine
    /// always accepts proofs the protocol actually produced. A
    /// regression here would silently break every CYNC↔BTC swap (the
    /// state machine refuses to lock if the DLEQ doesn't verify).
    #[test]
    fn dleq_roundtrip(
        secret in arb_adaptor_secret(),
        nonce_k_bytes in arb_ristretto_canonical_bytes(),
    ) {
        let secp = Secp256k1::new();

        // Derive T_btc = t·G_btc and T_cync = t·G_cync from the same secret.
        let t_sk = SecretKey::from_slice(&secret.secp256k1_bytes())
            .expect("AdaptorSecret bytes are always valid secp scalars");
        let t_btc_bytes: [u8; 33] = PublicKey::from_secret_key(&secp, &t_sk).serialize();
        let t_cync_bytes: [u8; 32] = cync_adaptor_point(&secret)
            .expect("adaptor point derivation");

        let proof = prove_cross_curve(&secret, &t_btc_bytes, &t_cync_bytes, &nonce_k_bytes)
            .expect("honest DLEQ proof construction must succeed");

        verify_cross_curve_proof(&proof, &t_btc_bytes, &t_cync_bytes)
            .expect("honestly-constructed DLEQ proof must verify against its inputs");
    }
}
