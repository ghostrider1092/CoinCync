//! ## Zcash Counterfeiting Vulnerability (March 2018, disclosed February 2019)
//!
//! A flaw in the Groth16 proving system meant that proofs were not fully
//! commitment-bound. An attacker could forge proofs allowing infinite
//! counterfeiting of shielded ZEC — undetectable because shielded balances
//! are hidden. Fixed before exploitation.
//!
//! CoinCync uses Bulletproofs+ (not Groth16), but the lesson applies:
//! range proofs MUST be bound to their specific commitments. A proof valid
//! for commitment C1 must NOT verify against commitment C2.
//!
//! Citation: https://electriccoin.co/blog/zcash-counterfeiting-vulnerability-successfully-remediated/
//! Chain: Zcash
//! Impact: Undetectable infinite inflation (patched before exploitation)

use coincync::primitives::Amount;
use coincync::crypto::{
    BlindingFactor, PedersenCommitment,
    create_aggregated_range_proof_for_height, verify_range_proofs_dispatch, RangeProof,
};
use rand::rngs::OsRng;

/// Test: Range proof is commitment-bound (cannot transplant to different commitment)
#[test]
fn zcash_2018_proof_not_transplantable() {
    let mut rng = OsRng;
    let amount = Amount::from_atomic(1_000_000_000);
    let bf = BlindingFactor::random(&mut rng);
    let correct_commit = PedersenCommitment::commit(amount.as_atomic(), &bf);

    let proof = create_aggregated_range_proof_for_height(&[amount], &[bf], &mut rng, 0).unwrap();
    let proof_ref = RangeProof::from_bytes(&proof.to_bytes()).unwrap();

    // Correct commitment verifies
    assert!(verify_range_proofs_dispatch(&[correct_commit], &proof_ref, 0),
        "Proof must verify with correct commitment");

    // 50 random wrong commitments must all fail
    for _ in 0..50 {
        let wrong_bf = BlindingFactor::random(&mut rng);
        let wrong_amount = rand::random::<u64>() % 10_000_000_000;
        let wrong_commit = PedersenCommitment::commit(wrong_amount, &wrong_bf);
        assert!(
            !verify_range_proofs_dispatch(&[wrong_commit], &proof_ref, 0),
            "ZCASH 2018 REPRODUCED: Proof valid for 1 CYNC also verifies for {}! \
             Infinite counterfeiting possible.",
            wrong_amount
        );
    }
}

/// Test: Proof for amount X doesn't verify for amount X with different blinding
#[test]
fn zcash_2018_different_blinding_different_commitment() {
    let mut rng = OsRng;
    let amount = Amount::from_atomic(5_000_000_000);
    let bf1 = BlindingFactor::random(&mut rng);
    let bf2 = BlindingFactor::random(&mut rng);

    let commit1 = PedersenCommitment::commit(amount.as_atomic(), &bf1);
    let commit2 = PedersenCommitment::commit(amount.as_atomic(), &bf2); // same amount, different blinding

    let proof = create_aggregated_range_proof_for_height(&[amount], &[bf1], &mut rng, 0).unwrap();
    let proof_ref = RangeProof::from_bytes(&proof.to_bytes()).unwrap();

    assert!(verify_range_proofs_dispatch(&[commit1], &proof_ref, 0), "Original must verify");
    assert!(
        !verify_range_proofs_dispatch(&[commit2], &proof_ref, 0),
        "ZCASH 2018: Same amount but different blinding accepted! \
         Proof is not fully commitment-bound — attacker can substitute commitments."
    );
}

/// Test: Empty proof never verifies
#[test]
fn zcash_2018_empty_proof_rejected() {
    let bf = BlindingFactor::random(&mut OsRng);
    let _commit = PedersenCommitment::commit(1_000_000_000, &bf);

    let empty_result = RangeProof::from_bytes(&[]);
    assert!(
        empty_result.is_err(),
        "ZCASH 2018 VARIANT: Empty proof bytes parsed successfully!"
    );
}
