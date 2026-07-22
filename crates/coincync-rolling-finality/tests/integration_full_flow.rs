//! Integration tests — full rolling-finality composition.
//!
//! Mirrors the FROST coordinator and atomic-swap integration
//! tests (commits 0e94dea + c98e898). Exercises every layer of
//! the rolling-finality crate composed together: ActiveMinerSet
//! + FinalityTracker + Ed25519Verifier + wire codec.
//!
//! Phase 5-equivalent for this crate. Phase 3 is the
//! `validate_block` integration which lives in the main coincync
//! crate behind a feature flag and an activation height; this
//! test exercises everything BELOW that integration boundary.
//!
//! ## Crypto note
//!
//! Unlike the FROST and swap integration tests, this one uses
//! REAL ed25519 signing via `ed25519-dalek` for every
//! attestation. The verifier path is exercised end-to-end:
//! sign → encode → decode → verify → apply → optionally
//! finalize. Real cryptography matters here because the
//! rolling-finality protocol's security depends on signature
//! verification — opaque-byte testing wouldn't catch a bug in
//! the verifier hooking up to the codec.

use coincync_rolling_finality::{
    decode, encode,
    finality::{ApplyOutcome, DEFAULT_LAG, DEFAULT_MIN_QUORUM, DEFAULT_WINDOW},
    types::{RejectAllVerifier, SIGNATURE_LEN},
    AttestationVerifier, BlockHash, Ed25519Verifier, FinalityAttestation, FinalityError,
    FinalityTracker, MinerPubkey, NoopVerifier, WireError,
};
use ed25519_dalek::{Signer, SigningKey};
use rand::rngs::OsRng;

// ────────────────────────────────────────────────────────────────
// Test helpers
// ────────────────────────────────────────────────────────────────

/// Generate a fresh ed25519 keypair, returning the signing key
/// and its corresponding pubkey bytes.
fn fresh_miner() -> (SigningKey, MinerPubkey) {
    let signing = SigningKey::generate(&mut OsRng);
    let pubkey = signing.verifying_key().to_bytes();
    (signing, pubkey)
}

/// Construct a real signed attestation. Sign over the canonical
/// signing_bytes() with the miner's signing key.
fn signed_attestation(
    signing: &SigningKey,
    pubkey: MinerPubkey,
    target_height: u64,
    target_hash: BlockHash,
) -> FinalityAttestation {
    // Build a placeholder attestation with the right structure
    // so we can compute its signing_bytes(); then attach the
    // real signature.
    let mut att = FinalityAttestation {
        miner_pubkey: pubkey,
        target_height,
        target_hash,
        signature: vec![0u8; SIGNATURE_LEN],
    };
    let sig = signing.sign(&att.signing_bytes());
    att.signature = sig.to_bytes().to_vec();
    att
}

/// Build a tracker with `n` active miners, all having mined a
/// block at heights [50..50+n). Chain tip set so all miners are
/// active at the test's target heights.
fn tracker_with_n_miners(n: usize) -> (FinalityTracker, Vec<(SigningKey, MinerPubkey)>) {
    let mut tracker = FinalityTracker::with_params(
        /* window */ 100, /* lag */ 10, /* min_quorum */ 5,
        /* stale_horizon */ 50,
    );
    let miners: Vec<_> = (0..n).map(|_| fresh_miner()).collect();
    for (i, (_, pubkey)) in miners.iter().enumerate() {
        tracker.record_block(*pubkey, 50 + i as u64);
    }
    // Bump chain tip to 60 so all miners (mined 50..50+n) are
    // still within the window of any target_height in [50, 60].
    let (_, sentinel_pubkey) = fresh_miner();
    tracker.record_block(sentinel_pubkey, 60);
    (tracker, miners)
}

const TARGET_HEIGHT: u64 = 55;
const TARGET_HASH_A: BlockHash = [0xAA; 32];
const TARGET_HASH_B: BlockHash = [0xBB; 32];

// ────────────────────────────────────────────────────────────────
// Happy path: real-ed25519 round-trip + soft-finalization
// ────────────────────────────────────────────────────────────────

/// PROPERTY: a 2/3-threshold of REAL signed attestations
/// finalizes the (height, hash). Round-trip via the wire codec
/// in between to exercise the full path the consensus integration
/// will use.
#[test]
fn full_composition_finalizes_at_threshold_with_real_crypto() {
    let (mut tracker, miners) = tracker_with_n_miners(5);
    // 5 active miners + 1 sentinel; quorum at TARGET_HEIGHT(=55)
    // is the original 5 (sentinel mined at height 60, so it's
    // active at any height >= 60 - window=100 = -40 i.e. all).
    // Actually all 6 are active at TARGET_HEIGHT=55.
    let active = tracker.active_set().active_count(TARGET_HEIGHT);
    assert!(
        active >= 5,
        "test fixture wants >= 5 active miners, got {active}"
    );
    // Threshold = ceil(2/3 * active). For 5: 4. For 6: 4.
    let threshold = (active * 2).div_ceil(3);
    let verifier = Ed25519Verifier::new();

    for (i, (signing, pubkey)) in miners.iter().enumerate() {
        let att = signed_attestation(signing, *pubkey, TARGET_HEIGHT, TARGET_HASH_A);

        // Round-trip via wire codec — exactly what the consensus
        // layer will do post-activation: encode for inclusion in
        // coinbase extra, decode at validation time.
        let bytes = encode(&att);
        let decoded = decode(&bytes).expect("decoding own encoded attestation must succeed");
        assert_eq!(decoded, att, "wire round-trip preserves attestation");

        // Verify cryptographically.
        assert!(
            verifier.verify(&decoded),
            "real-signed attestation must verify"
        );

        // Apply to tracker.
        let outcome = tracker
            .apply_attestation(&decoded, &verifier)
            .expect("real-signed attestation must be accepted");

        // Before threshold: still Accepted (no finalization).
        // At threshold: NewlyFinalized.
        let n_signers = i + 1;
        if n_signers < threshold {
            assert!(
                matches!(outcome, ApplyOutcome::Accepted),
                "below threshold ({n_signers}/{threshold}): expected Accepted, got {outcome:?}"
            );
        } else if n_signers == threshold {
            match outcome {
                ApplyOutcome::NewlyFinalized { height, hash } => {
                    assert_eq!(height, TARGET_HEIGHT);
                    assert_eq!(hash, TARGET_HASH_A);
                }
                other => panic!(
                    "at threshold ({n_signers}/{threshold}): expected NewlyFinalized, got {other:?}"
                ),
            }
        }
        // Past threshold: still Accepted (height is already
        // soft-final; further attestations don't re-fire the
        // event).
    }

    assert_eq!(tracker.soft_final_height(), Some(TARGET_HEIGHT));
}

/// PROPERTY: a soft-final height blocks reorgs at-or-below it.
/// Standalone reorg-rule check.
#[test]
fn soft_finalized_height_blocks_reorgs() {
    let (mut tracker, miners) = tracker_with_n_miners(5);
    let verifier = Ed25519Verifier::new();
    // Push enough attestations to finalize TARGET_HEIGHT
    for (signing, pubkey) in &miners {
        let att = signed_attestation(signing, *pubkey, TARGET_HEIGHT, TARGET_HASH_A);
        let _ = tracker.apply_attestation(&att, &verifier);
    }
    let soft_final = tracker.soft_final_height().expect("should have finalized");
    assert_eq!(soft_final, TARGET_HEIGHT);

    // Reorgs AT or BEFORE soft_final are rejected.
    assert!(tracker.would_reorg_violate_finality(soft_final));
    assert!(tracker.would_reorg_violate_finality(soft_final - 1));
    // Reorgs AFTER soft_final are allowed.
    assert!(!tracker.would_reorg_violate_finality(soft_final + 1));
}

// ────────────────────────────────────────────────────────────────
// Adversarial: forged signatures
// ────────────────────────────────────────────────────────────────

/// PROPERTY: an attestation signed by a DIFFERENT key than its
/// claimed `miner_pubkey` is rejected at the verifier. The
/// tracker never accepts it.
#[test]
fn cross_signed_attestation_rejected() {
    let (mut tracker, miners) = tracker_with_n_miners(5);
    let verifier = Ed25519Verifier::new();
    // Miner 0 signs with their key but claims to be miner 1.
    let (signing0, _pubkey0) = &miners[0];
    let (_signing1, pubkey1) = &miners[1];
    let mut att = FinalityAttestation {
        miner_pubkey: *pubkey1,
        target_height: TARGET_HEIGHT,
        target_hash: TARGET_HASH_A,
        signature: vec![0u8; SIGNATURE_LEN],
    };
    let sig = signing0.sign(&att.signing_bytes());
    att.signature = sig.to_bytes().to_vec();
    // Verifier rejects (signature was made by signing0 but
    // pubkey claims signing1).
    assert!(!verifier.verify(&att));
    let result = tracker.apply_attestation(&att, &verifier);
    assert!(matches!(result, Err(FinalityError::InvalidSignature)));
}

/// PROPERTY: tampering ANY field of a signed attestation breaks
/// the signature. Verifier rejects; tracker doesn't accept.
#[test]
fn tampered_attestation_fields_rejected() {
    let (mut tracker, miners) = tracker_with_n_miners(5);
    let verifier = Ed25519Verifier::new();
    let (signing, pubkey) = &miners[0];
    let original = signed_attestation(signing, *pubkey, TARGET_HEIGHT, TARGET_HASH_A);

    // Tamper target_height
    let mut t = original.clone();
    t.target_height = TARGET_HEIGHT + 1;
    assert!(!verifier.verify(&t));
    assert!(matches!(
        tracker.apply_attestation(&t, &verifier),
        Err(FinalityError::InvalidSignature)
    ));

    // Tamper target_hash
    let mut t = original.clone();
    t.target_hash = TARGET_HASH_B;
    assert!(!verifier.verify(&t));

    // Tamper signature byte
    let mut t = original.clone();
    t.signature[0] ^= 1;
    assert!(!verifier.verify(&t));

    // Original still verifies (sanity)
    assert!(verifier.verify(&original));
}

// ────────────────────────────────────────────────────────────────
// Adversarial: wire-format manipulation
// ────────────────────────────────────────────────────────────────

/// PROPERTY: bytes that aren't a valid CIP9 wire payload are
/// rejected at the codec layer, BEFORE the verifier ever sees
/// them. Defense in depth.
#[test]
fn malformed_wire_bytes_rejected_before_verification() {
    // Empty
    assert!(matches!(decode(&[]), Err(WireError::TooShort)));
    // Wrong magic
    let mut bad = b"NOT9".to_vec();
    bad.push(1);
    assert!(matches!(decode(&bad), Err(WireError::BadMagic)));
    // Right magic, unknown version
    let mut bad = b"CIP9".to_vec();
    bad.push(99);
    assert!(matches!(decode(&bad), Err(WireError::UnknownVersion(99))));
}

/// PROPERTY: a real signed attestation's wire bytes round-trip
/// to bit-identical form. Idempotency under encode-decode.
#[test]
fn wire_roundtrip_is_idempotent() {
    let (signing, pubkey) = fresh_miner();
    let att = signed_attestation(&signing, pubkey, 100, [0xCC; 32]);
    let bytes1 = encode(&att);
    let decoded = decode(&bytes1).unwrap();
    let bytes2 = encode(&decoded);
    assert_eq!(bytes1, bytes2);
    assert_eq!(decoded, att);
}

// ────────────────────────────────────────────────────────────────
// Quorum dynamics
// ────────────────────────────────────────────────────────────────

/// PROPERTY: below MIN_QUORUM active miners, NO finalization
/// fires regardless of how many sign. The 2/3 threshold means
/// nothing if the active set is too small to be representative.
#[test]
fn below_min_quorum_never_finalizes() {
    // tracker_with_n_miners adds a sentinel that's INACTIVE at
    // TARGET_HEIGHT (its last_seen=60 > query height=55), so its
    // count for active(55) doesn't include the sentinel. But to
    // be 100% explicit about the "exactly 4 active miners" setup,
    // construct manually.
    let mut tracker = FinalityTracker::with_params(100, 10, 5, 50);
    let miners: Vec<_> = (0..4).map(|_| fresh_miner()).collect();
    for (i, (_, pubkey)) in miners.iter().enumerate() {
        tracker.record_block(*pubkey, 50 + i as u64);
    }
    // Bump chain tip past TARGET_HEIGHT with a distinct
    // sentinel miner mined at height 60. is_active is
    // forward-only — a miner whose last_seen is 60 is INACTIVE
    // at any query height < 60. So this sentinel doesn't bump
    // active_count(55) past 4.
    let (_, sentinel_pubkey) = fresh_miner();
    tracker.record_block(sentinel_pubkey, 60);
    assert_eq!(tracker.active_set().active_count(TARGET_HEIGHT), 4);

    let verifier = Ed25519Verifier::new();
    for (signing, pubkey) in &miners {
        let att = signed_attestation(signing, *pubkey, TARGET_HEIGHT, TARGET_HASH_A);
        let outcome = tracker.apply_attestation(&att, &verifier).unwrap();
        // Never finalizes despite all 4 signing
        assert!(matches!(outcome, ApplyOutcome::Accepted));
    }
    assert_eq!(tracker.soft_final_height(), None);
}

/// PROPERTY: a miner who signs both sides of a fork at the same
/// height contributes ONE vote to each fork, not two to either.
/// The 2/3 threshold is per-(height, hash) so a single miner
/// cannot single-handedly tip both sides toward finalization.
#[test]
fn fork_double_voting_does_not_double_count() {
    let (mut tracker, miners) = tracker_with_n_miners(5);
    let verifier = Ed25519Verifier::new();

    // Miner 0 signs BOTH HASH_A and HASH_B at TARGET_HEIGHT.
    let (signing0, pubkey0) = &miners[0];
    let att_a = signed_attestation(signing0, *pubkey0, TARGET_HEIGHT, TARGET_HASH_A);
    let att_b = signed_attestation(signing0, *pubkey0, TARGET_HEIGHT, TARGET_HASH_B);
    tracker.apply_attestation(&att_a, &verifier).unwrap();
    tracker.apply_attestation(&att_b, &verifier).unwrap();

    // Each fork has 1 signer: miner 0.
    assert_eq!(tracker.signer_count(TARGET_HEIGHT, &TARGET_HASH_A), 1);
    assert_eq!(tracker.signer_count(TARGET_HEIGHT, &TARGET_HASH_B), 1);
    // Neither fork has finalized yet (need ceil(2/3 * 6) = 4).
    assert_eq!(tracker.soft_final_height(), None);
}

/// PROPERTY: an attestation from an INACTIVE miner (not in the
/// active set) is rejected. The miner could be a miner who has
/// never produced a block, or one whose last block is outside
/// the window.
#[test]
fn inactive_miner_attestation_rejected() {
    let (mut tracker, _miners) = tracker_with_n_miners(5);
    let verifier = Ed25519Verifier::new();
    // A fresh miner the tracker has never seen
    let (signing, pubkey) = fresh_miner();
    let att = signed_attestation(&signing, pubkey, TARGET_HEIGHT, TARGET_HASH_A);
    // Signature is valid (we signed it correctly), but the
    // miner isn't in the active set.
    assert!(verifier.verify(&att));
    let result = tracker.apply_attestation(&att, &verifier);
    assert!(matches!(result, Err(FinalityError::MinerNotActive { .. })));
}

// ────────────────────────────────────────────────────────────────
// Verifier-substitution check
// ────────────────────────────────────────────────────────────────

/// PROPERTY: the verifier trait is the substitution point for
/// real vs. stub crypto. NoopVerifier accepts everything;
/// RejectAllVerifier rejects everything; Ed25519Verifier accepts
/// only real signatures. This test exercises all three to make
/// sure the trait dispatch works correctly.
#[test]
fn verifier_substitution_works_across_implementations() {
    let (mut tracker, miners) = tracker_with_n_miners(5);
    let (signing, pubkey) = &miners[0];
    let att = signed_attestation(signing, *pubkey, TARGET_HEIGHT, TARGET_HASH_A);

    // RejectAllVerifier: rejects even a valid signature
    let result = tracker.apply_attestation(&att, &RejectAllVerifier);
    assert!(matches!(result, Err(FinalityError::InvalidSignature)));

    // NoopVerifier: accepts (would accept even unsigned bytes)
    let result = tracker.apply_attestation(&att, &NoopVerifier);
    assert!(matches!(result, Ok(ApplyOutcome::Accepted)));

    // Ed25519Verifier: accepts because signature is valid.
    // Note: we already accepted this attestation under
    // NoopVerifier above, so a re-apply is a duplicate.
    let result = tracker.apply_attestation(&att, &Ed25519Verifier::new());
    assert!(matches!(
        result,
        Err(FinalityError::DuplicateAttestation { .. })
    ));
}

// ────────────────────────────────────────────────────────────────
// Constants surface
// ────────────────────────────────────────────────────────────────

/// PROPERTY: the public default constants match the values
/// CIP-009.D specifies. Catch-all guard against accidental
/// tuning that drifts from the spec.
#[test]
fn defaults_match_cip_009_d_spec() {
    assert_eq!(DEFAULT_WINDOW, 10_000);
    assert_eq!(DEFAULT_LAG, 100);
    assert_eq!(DEFAULT_MIN_QUORUM, 5);
}
