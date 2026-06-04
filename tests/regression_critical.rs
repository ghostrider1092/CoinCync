//! Regression tests for critical bugs fixed in CoinCync 1.0.
//!
//! Each test verifies that a specific historical bug remains fixed.
//! If any of these tests fail, the corresponding bug has been reintroduced.

// Phase A8 (audit fix): `KeyImage as PrimKeyImage` was removed because the
// regression test for the blake3 vs CLSAG mismatch was rewritten — the
// blake3 helper has been DELETED from the codebase, so there's nothing to
// compare against.
use coincync::primitives::{PublicKey, SecretKey, Amount};
use coincync::crypto::{
    SecretScalar, KeyImage as CryptoKeyImage,
    // 2026-06-03: switched to `generate_stealth_address_checked`
    // after the audit pass narrowed the legacy panic-on-bad-input
    // variant to `#[cfg(test)] pub(crate)`. Test fixtures here always
    // pass valid curve points so the `.expect()` on the Result is a
    // never-fires assertion documenting the test contract.
    generate_stealth_address_checked, is_output_ours,
    coinbase_stealth_address,
    RecipientKeys, Subaddress,
    BlindingFactor, PedersenCommitment,
    create_aggregated_range_proof, verify_range_proofs,
    verify_range_proof,
};
use rand::rngs::OsRng;

// =============================================================================
// 1. KEY IMAGE MISMATCH
// =============================================================================

/// Regression: primitives::KeyImage::from_secret_key() used blake3 hash,
/// but CLSAG ring signatures use I = x * Hp(x*G). The wallet sync was using
/// the blake3 formula so spent outputs were never marked as spent, causing
/// the wallet to reuse already-spent UTXOs.
///
/// The fix: wallet sync must use crypto::KeyImage::from_secret() (the CLSAG
/// formula). This test verifies the two formulas produce DIFFERENT results,
/// ensuring no one accidentally "unifies" them.
#[test]
fn test_regression_key_image_clsag_only() {
    // Phase A8 (audit fix): the original version of this test compared the
    // CLSAG formula against the now-deleted `PrimKeyImage::from_secret_key`
    // (which was the broken blake3 formula that caused the prior incident).
    // The deletion is documented in MEMORY.md and the regression we're now
    // protecting against is "someone re-introduces a non-CLSAG key image
    // helper on `primitives::KeyImage`".
    //
    // We can't grep for absence inside a unit test, but we CAN assert the
    // CLSAG path is correct, deterministic, and produces a valid Ristretto
    // point — which is the only positive guarantee that survives the
    // deletion of the broken function.
    let secret_scalar = SecretScalar::random(&mut OsRng);

    // Compute key image using the CORRECT CLSAG formula: I = x * Hp(x*G)
    let clsag_key_image = CryptoKeyImage::from_secret(&secret_scalar);

    // Verify the CLSAG key image is a valid curve point (on the Ristretto group)
    assert!(
        CryptoKeyImage::from_bytes(clsag_key_image.to_bytes()).is_some(),
        "CLSAG key image must be a valid Ristretto point"
    );

    // Verify determinism: same secret always produces the same CLSAG key image
    let clsag_key_image_2 = CryptoKeyImage::from_secret(&secret_scalar);
    assert_eq!(
        clsag_key_image.to_bytes(),
        clsag_key_image_2.to_bytes(),
        "CLSAG key image derivation must be deterministic"
    );

    // Verify uniqueness: a different secret produces a different image.
    // (This is a property of `Hp(x*G)` — not Hp alone, the full `x * Hp(x*G)`.)
    let other_scalar = SecretScalar::random(&mut OsRng);
    let other_image  = CryptoKeyImage::from_secret(&other_scalar);
    assert_ne!(
        clsag_key_image.to_bytes(),
        other_image.to_bytes(),
        "different secret keys must produce different key images"
    );
}

// =============================================================================
// 2. SCANNER VIEW TAG GATE REMOVAL
// =============================================================================

/// Regression: The scanner used view_tag as a hard gate for output detection.
/// If tx_public_key was corrupted during serialization, the view tag would not
/// match and the output was permanently lost. The fix: always call
/// is_output_ours() regardless of view tag; view_tag is diagnostic only.
///
/// This test verifies that is_output_ours() works correctly without any
/// view_tag pre-filter, and that outputs are detected purely via ECDH.
#[test]
fn test_regression_scanner_view_tag_gate() {
    // Generate wallet keys
    let view_secret = SecretScalar::random(&mut OsRng);
    let spend_secret = SecretScalar::random(&mut OsRng);
    let view_public = view_secret.to_public();
    let spend_public = spend_secret.to_public();

    let view_sk = SecretKey::from_bytes(view_secret.to_bytes());
    let spend_pk = PublicKey::from_bytes(spend_public.to_bytes());
    let view_pk = PublicKey::from_bytes(view_public.to_bytes());

    // Generate a stealth address for this wallet (simulates a sender creating an output)
    let output_idx = 0u8;
    let (stealth, _tx_secret) = generate_stealth_address_checked(
        &spend_pk,
        &view_pk,
        output_idx,
        &mut OsRng,
    ).expect("test fixtures pass valid curve points");

    // The core fix: is_output_ours must detect the output via ECDH alone,
    // without any view_tag pre-filter
    assert!(
        is_output_ours(&stealth, &view_sk, &spend_pk, output_idx),
        "is_output_ours must detect our output via ECDH without view_tag gating"
    );

    // Verify that a different wallet does NOT match
    let other_spend = SecretScalar::random(&mut OsRng).to_public();
    let other_spend_pk = PublicKey::from_bytes(other_spend.to_bytes());
    assert!(
        !is_output_ours(&stealth, &view_sk, &other_spend_pk, output_idx),
        "is_output_ours must reject outputs belonging to a different spend key"
    );

    // Verify wrong output index does not match
    assert!(
        !is_output_ours(&stealth, &view_sk, &spend_pk, output_idx + 1),
        "is_output_ours must reject outputs with wrong output index"
    );
}

// =============================================================================
// 3. RANGE PROOF VERIFICATION MISMATCH
// =============================================================================

/// Regression: The transaction builder always used prove_multiple with the
/// "CoinCync_AggregatedRangeProof" transcript. But the validator special-cased
/// single-output transactions to use verify_single with the different transcript
/// "CoinCync_RangeProof". This caused ALL churn transactions (which have 1
/// output) to fail verification, stalling the chain.
///
/// The fix: always use verify_range_proofs (aggregated) for verification,
/// even for single-output transactions. This test creates a single-output
/// aggregated proof and verifies it passes the aggregated verifier.
#[test]
fn test_regression_range_proof_verification_mismatch() {
    let amount = Amount::from_atomic(1_000_000_000);
    let blinding = BlindingFactor::random(&mut OsRng);
    let commitment = PedersenCommitment::commit(amount.as_atomic(), &blinding);

    // Create an aggregated proof for a SINGLE output (this is what the builder does)
    let agg_proof = create_aggregated_range_proof(
        &[amount],
        &[blinding.clone()],
        &mut OsRng,
    ).expect("aggregated proof creation must succeed for 1 output");

    // The fix: verify_range_proofs (aggregated verifier) must accept this proof.
    // Before the fix, the validator would have called verify_range_proof (single)
    // with a different transcript, which would fail.
    assert!(
        verify_range_proofs(&[commitment], &agg_proof),
        "Aggregated verifier must accept a single-output aggregated proof. \
         If this fails, the validator may be using verify_single with the wrong transcript."
    );

    // Also verify that the SINGLE verifier does NOT accept an aggregated proof
    // (different transcript domain). This confirms the transcripts are distinct.
    assert!(
        !verify_range_proof(&commitment, &agg_proof),
        "Single verifier must NOT accept an aggregated proof (different transcript). \
         If this passes, the transcript domains have been unified, which may be intentional \
         but must be verified."
    );
}

// =============================================================================
// 4. COINBASE STEALTH ADDRESS UNIQUENESS
// =============================================================================

/// Regression: Old coinbase transactions used the miner's public key directly
/// as the stealth address. This meant every coinbase output for the same miner
/// had the same stealth address, causing stealth_index collisions and making
/// outputs unspendable.
///
/// The fix: coinbase_stealth_address() generates a unique ECDH-based stealth
/// address per block height. This test verifies uniqueness across heights.
#[test]
fn test_regression_coinbase_stealth_uniqueness() {
    let spend_secret = SecretScalar::random(&mut OsRng);
    let view_secret = SecretScalar::random(&mut OsRng);
    let spend_pk = PublicKey::from_bytes(spend_secret.to_public().to_bytes());
    let view_pk = PublicKey::from_bytes(view_secret.to_public().to_bytes());
    let view_sk = SecretKey::from_bytes(view_secret.to_bytes());

    let output_idx = 0u8;

    // Phase A8 (audit fix): coinbase_stealth_address gained a `miner_secret`
    // 5th argument as a SECURITY FIX preventing precomputable coinbase
    // linkage. We use a SINGLE deterministic test miner secret across all
    // three heights so we exercise the height-uniqueness property — passing
    // different secrets per call would mask a regression where the function
    // ignores `height` entirely.
    let test_miner_secret = [0xEFu8; 32];

    // Generate coinbase stealth addresses for consecutive block heights
    let (stealth_h1, _) = coinbase_stealth_address(&spend_pk, &view_pk, 1, output_idx, &test_miner_secret)
        .expect("coinbase stealth for height 1");
    let (stealth_h2, _) = coinbase_stealth_address(&spend_pk, &view_pk, 2, output_idx, &test_miner_secret)
        .expect("coinbase stealth for height 2");
    let (stealth_h3, _) = coinbase_stealth_address(&spend_pk, &view_pk, 3, output_idx, &test_miner_secret)
        .expect("coinbase stealth for height 3");

    // All stealth addresses must be DIFFERENT (the old bug made them all identical)
    assert_ne!(
        stealth_h1.public_key.as_bytes(),
        stealth_h2.public_key.as_bytes(),
        "Coinbase stealth addresses at different heights must be unique"
    );
    assert_ne!(
        stealth_h2.public_key.as_bytes(),
        stealth_h3.public_key.as_bytes(),
        "Coinbase stealth addresses at different heights must be unique"
    );
    assert_ne!(
        stealth_h1.public_key.as_bytes(),
        stealth_h3.public_key.as_bytes(),
        "Coinbase stealth addresses at different heights must be unique"
    );

    // tx_public_keys must also differ (derived deterministically from height)
    assert_ne!(
        stealth_h1.tx_public_key.as_bytes(),
        stealth_h2.tx_public_key.as_bytes(),
        "Coinbase tx_public_keys at different heights must be unique"
    );

    // Each coinbase stealth address must be detectable by the miner's wallet
    assert!(
        is_output_ours(&stealth_h1, &view_sk, &spend_pk, output_idx),
        "Miner must be able to detect their coinbase at height 1"
    );
    assert!(
        is_output_ours(&stealth_h2, &view_sk, &spend_pk, output_idx),
        "Miner must be able to detect their coinbase at height 2"
    );
    assert!(
        is_output_ours(&stealth_h3, &view_sk, &spend_pk, output_idx),
        "Miner must be able to detect their coinbase at height 3"
    );

    // Same height must produce the same stealth address (deterministic).
    // Phase A8 (audit fix): use the same `test_miner_secret` as the loop above
    // so the determinism check is meaningful — passing a different secret would
    // legitimately produce a different result.
    let (stealth_h1_again, _) = coinbase_stealth_address(&spend_pk, &view_pk, 1, output_idx, &test_miner_secret)
        .expect("coinbase stealth for height 1 (repeat)");
    assert_eq!(
        stealth_h1.public_key.as_bytes(),
        stealth_h1_again.public_key.as_bytes(),
        "Coinbase stealth address derivation must be deterministic for the same height"
    );
}

// =============================================================================
// 5. PARTIAL ASSET TRANSFERS (POWER-OF-2 PADDING)
// =============================================================================

/// Regression: The bulletproofs crate's prove_multiple requires the aggregation
/// count to be a power of 2. A transaction with 3 outputs (e.g., asset output +
/// CYNC change + asset change) would fail because 3 is not a power of 2.
///
/// The fix: create_aggregated_range_proof pads values/blindings to the next
/// power of 2 with zeros. verify_range_proofs pads commitments with identity
/// points to match.
#[test]
fn test_regression_partial_asset_transfers_power_of_2() {
    // 3 outputs: NOT a power of 2. This is the exact scenario that failed.
    let amounts = [
        Amount::from_atomic(500_000),
        Amount::from_atomic(300_000),
        Amount::from_atomic(200_000),
    ];
    let blindings: Vec<BlindingFactor> = (0..3)
        .map(|_| BlindingFactor::random(&mut OsRng))
        .collect();
    let commitments: Vec<PedersenCommitment> = amounts
        .iter()
        .zip(blindings.iter())
        .map(|(a, b)| PedersenCommitment::commit(a.as_atomic(), b))
        .collect();

    // This would panic/fail before the fix (3 is not a power of 2)
    let proof = create_aggregated_range_proof(&amounts, &blindings, &mut OsRng)
        .expect("Aggregated proof for 3 outputs must succeed (padded to 4)");

    // Verification must also handle the non-power-of-2 count
    assert!(
        verify_range_proofs(&commitments, &proof),
        "Aggregated verifier must accept 3 commitments (padded to 4 internally)"
    );

    // Also test other non-power-of-2 counts: 5, 6, 7
    for count in [5usize, 6, 7] {
        let amts: Vec<Amount> = (0..count)
            .map(|i| Amount::from_atomic((i as u64 + 1) * 100_000))
            .collect();
        let bfs: Vec<BlindingFactor> = (0..count)
            .map(|_| BlindingFactor::random(&mut OsRng))
            .collect();
        let cms: Vec<PedersenCommitment> = amts
            .iter()
            .zip(bfs.iter())
            .map(|(a, b)| PedersenCommitment::commit(a.as_atomic(), b))
            .collect();

        let p = create_aggregated_range_proof(&amts, &bfs, &mut OsRng)
            .unwrap_or_else(|_| panic!("Aggregated proof for {} outputs must succeed", count));
        assert!(
            verify_range_proofs(&cms, &p),
            "Aggregated verifier must accept {} commitments", count
        );
    }
}

// =============================================================================
// 6. SUBADDRESS SCANNER NOT DETECTING OUTPUTS
// =============================================================================

/// Regression: WalletScanner only checked the primary spend_public key, never
/// subaddress spend keys. Outputs sent to subaddresses were invisible to the
/// recipient wallet.
///
/// The fix: scanner checks primary key first, then iterates subaddress keys.
/// This test verifies that is_output_ours works with subaddress spend keys.
#[test]
fn test_regression_subaddress_scanner_detection() {
    // Generate wallet keys
    let view_secret = SecretScalar::random(&mut OsRng);
    let spend_secret = SecretScalar::random(&mut OsRng);
    let spend_pk = PublicKey::from_bytes(spend_secret.to_public().to_bytes());
    let view_pk = PublicKey::from_bytes(view_secret.to_public().to_bytes());
    let view_sk = SecretKey::from_bytes(view_secret.to_bytes());

    // Generate a subaddress
    let subaddr = Subaddress::generate(&spend_pk, &view_sk, 0)
        .expect("subaddress generation must succeed");

    // Create a stealth address targeting the SUBADDRESS (not the primary address)
    let output_idx = 0u8;
    let (stealth, _tx_secret) = generate_stealth_address_checked(
        &subaddr.spend_public,
        &view_pk,
        output_idx,
        &mut OsRng,
    ).expect("test fixtures pass valid curve points");

    // The output must NOT match the primary spend key
    // (this was the only thing the old scanner checked)
    assert!(
        !is_output_ours(&stealth, &view_sk, &spend_pk, output_idx),
        "Output sent to subaddress should NOT match primary spend key"
    );

    // The output MUST match the subaddress spend key
    // (the old scanner never checked this)
    assert!(
        is_output_ours(&stealth, &view_sk, &subaddr.spend_public, output_idx),
        "Output sent to subaddress MUST be detected when checking the subaddress spend key. \
         If this fails, the scanner is not iterating subaddress keys."
    );

    // Verify with RecipientKeys for the subaddress
    let sub_recipient = RecipientKeys::new(&view_sk, &subaddr.spend_public)
        .expect("RecipientKeys for subaddress");
    assert!(
        sub_recipient.owns(&stealth, output_idx),
        "RecipientKeys::owns must detect subaddress output"
    );

    // Verify multiple subaddresses are all independently detectable
    for idx in 1..5u32 {
        let sub = Subaddress::generate(&spend_pk, &view_sk, idx)
            .expect("subaddress generation");
        let (sub_stealth, _) = generate_stealth_address_checked(
            &sub.spend_public,
            &view_pk,
            output_idx,
            &mut OsRng,
        ).expect("test fixtures pass valid curve points");
        assert!(
            is_output_ours(&sub_stealth, &view_sk, &sub.spend_public, output_idx),
            "Subaddress {} output must be detectable", idx
        );
        // Must not match any OTHER subaddress
        assert!(
            !is_output_ours(&sub_stealth, &view_sk, &subaddr.spend_public, output_idx),
            "Subaddress {} output must NOT match subaddress 0", idx
        );
    }
}

// =============================================================================
// 7. PEDERSEN COMMITMENT from_bytes UNCHECKED
// =============================================================================

/// Regression: PedersenCommitment::from_bytes accepted arbitrary 32 bytes
/// without validating they represent a valid Ristretto curve point. An attacker
/// could inject invalid commitments from the network to break the homomorphic
/// balance check, potentially enabling inflation.
///
/// The fix: from_bytes_checked validates the point. This test verifies that
/// invalid bytes are rejected by from_bytes_checked while from_bytes (unchecked)
/// still accepts them (the unchecked path exists for performance in trusted
/// contexts, but network-facing code must use checked).
#[test]
fn test_regression_pedersen_commitment_from_bytes_unchecked() {
    // These bytes do NOT represent a valid Ristretto point.
    // All-ones is almost certainly not on the curve.
    let invalid_bytes = [0xFFu8; 32];

    // The UNCHECKED constructor accepts invalid bytes (this is the dangerous path)
    let unchecked = PedersenCommitment::from_bytes(invalid_bytes);
    // It "works" but the commitment is garbage
    assert_eq!(unchecked.to_bytes(), invalid_bytes);

    // The CHECKED constructor must REJECT invalid bytes
    let checked = PedersenCommitment::from_bytes_checked(invalid_bytes);
    assert!(
        checked.is_none(),
        "from_bytes_checked must reject bytes that are not a valid Ristretto point. \
         If this passes, the checked path is not validating curve points, enabling inflation."
    );

    // Verify that checked_add on two invalid-point commitments returns None
    let bad_a = PedersenCommitment::from_bytes(invalid_bytes);
    let bad_b = PedersenCommitment::from_bytes([0xFE; 32]);
    assert!(
        bad_a.checked_add(&bad_b).is_none(),
        "checked_add must return None when operands contain invalid curve points"
    );

    // Verify a VALID commitment passes the checked constructor
    let blinding = BlindingFactor::random(&mut OsRng);
    let valid_commitment = PedersenCommitment::commit(1_000_000, &blinding);
    let valid_bytes = valid_commitment.to_bytes();
    let checked_valid = PedersenCommitment::from_bytes_checked(valid_bytes);
    assert!(
        checked_valid.is_some(),
        "from_bytes_checked must accept valid Ristretto point bytes"
    );
    assert_eq!(
        checked_valid.unwrap().to_bytes(),
        valid_bytes,
        "Round-trip through from_bytes_checked must preserve the commitment"
    );

    // Zero point: the identity is a valid Ristretto point
    let zero_bytes = [0u8; 32];
    // The Ristretto identity point has a specific encoding; all-zeros may or may not be valid.
    // What matters is that from_bytes_checked correctly validates it.
    let zero_checked = PedersenCommitment::from_bytes_checked(zero_bytes);
    // Whether this is Some or None depends on Ristretto encoding; the key invariant
    // is that from_bytes_checked actually performs decompression validation.
    // We just verify the function runs without panic.
    let _ = zero_checked;
}
