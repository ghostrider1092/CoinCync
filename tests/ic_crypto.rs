//! IC-084 through IC-102: Cryptographic Layer Integration Tests

use coincync::crypto::{
    compute_one_time_secret, generate_stealth_address_checked, is_output_ours, scan_outputs,
    ViewKey, ViewKeyScope,
};
use coincync::primitives::SecretKey;
use rand::rngs::OsRng;

fn random_secret() -> SecretKey {
    SecretKey::generate(&mut OsRng)
}

// ===========================================================================
// IC-084: CLSAG key image roundtrip — deterministic
// ===========================================================================

#[test]
fn ic_084_clsag_roundtrip() {
    use coincync::crypto::{KeyImage as CryptoKeyImage, SecretScalar};

    let secret = SecretScalar::random(&mut OsRng);
    let ki = CryptoKeyImage::from_secret(&secret);

    // Key image should be deterministic
    let ki2 = CryptoKeyImage::from_secret(&secret);
    assert_eq!(
        ki.to_bytes(),
        ki2.to_bytes(),
        "Same secret must produce same key image"
    );

    // Key image should be a valid point (not all zeros)
    assert!(
        !ki.to_bytes().iter().all(|&b| b == 0),
        "Key image must not be zero"
    );
}

// ===========================================================================
// IC-086: Key image — different secret → different key image
// ===========================================================================

#[test]
fn ic_086_key_image_bit_flip() {
    use coincync::crypto::{KeyImage as CryptoKeyImage, SecretScalar};

    let secret = SecretScalar::random(&mut OsRng);
    let ki = CryptoKeyImage::from_secret(&secret);

    let secret2 = SecretScalar::random(&mut OsRng);
    let ki2 = CryptoKeyImage::from_secret(&secret2);

    assert_ne!(
        ki.to_bytes(),
        ki2.to_bytes(),
        "Different secrets must produce different key images"
    );
}

// ===========================================================================
// IC-087: Key image equality detection
// ===========================================================================

#[test]
fn ic_087_key_image_uniqueness() {
    use coincync::primitives::KeyImage;

    let ki_bytes = [42u8; 32];
    let ki1 = KeyImage::from_bytes(ki_bytes);
    let ki2 = KeyImage::from_bytes(ki_bytes);

    assert_eq!(ki1, ki2, "Same bytes must produce same key image");

    let mut different = [42u8; 32];
    different[0] = 43;
    let ki3 = KeyImage::from_bytes(different);
    assert_ne!(ki1, ki3, "Different bytes must produce different key image");
}

// ===========================================================================
// IC-088: Key image reuse across blocks — detectable via is_spent
// DISABLED: uses removed SoloMiner API. Rewrite against mining template.
// ===========================================================================

#[cfg(any())]
#[test]
fn ic_088_key_image_cross_block() {
    use coincync::chain::Blockchain;
    use coincync::mempool::SharedMempool;
    use coincync::mining::SoloMiner;
    use coincync::primitives::{KeyImage, PublicKey};
    use std::sync::Arc;

    let chain = Arc::new(Blockchain::new());
    chain.init_genesis().unwrap();

    let miner = SoloMiner::new(PublicKey::from_bytes([1u8; 32]));
    let mempool = SharedMempool::new();
    for _ in 0..5 {
        let b = miner.mine_block(&chain, &mempool, 1_000_000).unwrap();
        chain.add_block(b).unwrap();
    }

    let ki = KeyImage::from_bytes([99u8; 32]);
    assert!(!chain.is_spent(&ki), "Fresh key image should not be spent");
}

// ===========================================================================
// IC-093: Bulletproof: truncated proof → no panic
// ===========================================================================

#[test]
fn ic_093_truncated_proof_no_panic() {
    use coincync::crypto::{verify_range_proofs_dispatch, PedersenCommitment, RangeProof};

    let commitment = PedersenCommitment::zero();

    // Truncated proof — should return false, not panic
    let truncated = RangeProof {
        data: vec![0u8; 16],
        version: 1,
    };
    let result = verify_range_proofs_dispatch(&[commitment], &truncated, 100000);
    assert!(!result, "Truncated proof should fail verification");
}

// ===========================================================================
// IC-094: Bulletproof: randomly corrupted bytes → no panic
// ===========================================================================

#[test]
fn ic_094_corrupted_proof_no_panic() {
    use coincync::crypto::{verify_range_proofs_dispatch, PedersenCommitment, RangeProof};

    let commitment = PedersenCommitment::zero();

    // Random garbage of realistic proof length
    let garbage: Vec<u8> = (0..672).map(|i| (i * 37 + 13) as u8).collect();
    let proof = RangeProof {
        data: garbage,
        version: 1,
    };
    let result = verify_range_proofs_dispatch(&[commitment], &proof, 100000);
    assert!(!result, "Corrupted proof should fail verification");
}

// ===========================================================================
// IC-096: Stealth: two senders to same recipient → outputs unlinkable
// ===========================================================================

#[test]
fn ic_096_stealth_unlinkable() {
    let spend_pub = random_secret().public_key();
    let view_pub = random_secret().public_key();

    let (s1, _) = generate_stealth_address_checked(&spend_pub, &view_pub, 0, &mut OsRng).unwrap();
    let (s2, _) = generate_stealth_address_checked(&spend_pub, &view_pub, 0, &mut OsRng).unwrap();

    assert_ne!(
        s1.public_key, s2.public_key,
        "Two sends to same recipient must produce different stealth addresses"
    );
}

// ===========================================================================
// IC-097: Stealth: recipient recovers both outputs with view key
// ===========================================================================

#[test]
fn ic_097_recipient_recovers_both() {
    let spend_secret = random_secret();
    let view_secret = random_secret();
    let spend_pub = spend_secret.public_key();
    let view_pub = view_secret.public_key();

    let (s1, _) = generate_stealth_address_checked(&spend_pub, &view_pub, 0, &mut OsRng).unwrap();
    let (s2, _) = generate_stealth_address_checked(&spend_pub, &view_pub, 1, &mut OsRng).unwrap();

    assert!(
        is_output_ours(&s1, &view_secret, &spend_pub, 0),
        "Must find output 0"
    );
    assert!(
        is_output_ours(&s2, &view_secret, &spend_pub, 1),
        "Must find output 1"
    );
}

// ===========================================================================
// IC-098: Stealth: wrong view key finds no outputs
// ===========================================================================

#[test]
fn ic_098_wrong_view_key() {
    let spend = random_secret();
    let view = random_secret();
    let (stealth, _) =
        generate_stealth_address_checked(&spend.public_key(), &view.public_key(), 0, &mut OsRng)
            .unwrap();

    let wrong = random_secret();
    assert!(
        !is_output_ours(&stealth, &wrong, &random_secret().public_key(), 0),
        "Wrong view key must find nothing"
    );
}

// ===========================================================================
// IC-099: Forward-secret view key: old key sees old outputs only
// ===========================================================================

#[test]
fn ic_099_forward_secrecy_old_epoch() {
    let view_secret = random_secret();

    let vk_epoch5 = ViewKey::derive(&view_secret, 5, ViewKeyScope::EpochOnly(5));
    assert!(vk_epoch5.is_valid_for_epoch(5), "Should see epoch 5");
    assert!(!vk_epoch5.is_valid_for_epoch(6), "Should NOT see epoch 6");
    assert!(!vk_epoch5.is_valid_for_epoch(4), "Should NOT see epoch 4");
}

// ===========================================================================
// IC-100: Forward-secret view key: new key sees new outputs only
// ===========================================================================

#[test]
fn ic_100_forward_secrecy_new_epoch() {
    let view_secret = random_secret();

    let vk_epoch10 = ViewKey::derive(&view_secret, 10, ViewKeyScope::EpochOnly(10));
    assert!(vk_epoch10.is_valid_for_epoch(10), "Should see epoch 10");
    assert!(
        !vk_epoch10.is_valid_for_epoch(5),
        "Should NOT see old epoch 5"
    );
    assert!(
        !vk_epoch10.is_valid_for_epoch(11),
        "Should NOT see future epoch 11"
    );
}

// ===========================================================================
// IC-101: Batch scan finds correct outputs
// ===========================================================================

#[test]
fn ic_101_batch_scan_correct() {
    let spend_secret = random_secret();
    let view_secret = random_secret();
    let spend_pub = spend_secret.public_key();
    let view_pub = view_secret.public_key();

    let mut outputs = Vec::new();
    for i in 0..5u8 {
        let (s, _) =
            generate_stealth_address_checked(&spend_pub, &view_pub, i, &mut OsRng).unwrap();
        outputs.push((s, i));
    }

    let other_spend = random_secret().public_key();
    let other_view = random_secret().public_key();
    for i in 0..5u8 {
        let (s, _) =
            generate_stealth_address_checked(&other_spend, &other_view, i, &mut OsRng).unwrap();
        outputs.push((s, i));
    }

    let found = scan_outputs(&outputs, &view_secret, &spend_pub).unwrap();
    assert_eq!(
        found.len(),
        5,
        "Should find exactly our 5 outputs, found {}",
        found.len()
    );
}

// ===========================================================================
// IC-102: One-time secret derives correctly
// ===========================================================================

#[test]
fn ic_102_one_time_secret() {
    let spend_secret = random_secret();
    let view_secret = random_secret();
    let spend_pub = spend_secret.public_key();
    let view_pub = view_secret.public_key();

    let (stealth, _) =
        generate_stealth_address_checked(&spend_pub, &view_pub, 0, &mut OsRng).unwrap();
    let result = compute_one_time_secret(&stealth, &view_secret, &spend_secret, 0);
    assert!(
        result.is_ok(),
        "Should derive one-time secret: {:?}",
        result.err()
    );
}
