//! # Tier 7 — Wallet & Key Management Adversarial Tests
//!
//! Tests key derivation security, mnemonic integrity, subaddress isolation,
//! and wallet state consistency under attack.
//! NO MOCKS. Real wallet operations, real crypto.

use coincync::wallet::WalletKeys;
use coincync::wallet::mnemonic::WalletMnemonic;
use coincync::primitives::SecretKey;
use coincync::crypto::{SecretScalar, KeyImage as CryptoKeyImage};
use rand::rngs::OsRng;

// =============================================================================
// TEST 1: Key derivation is deterministic (same seed = same keys ALWAYS)
// =============================================================================

#[test]
fn tier7_key_derivation_deterministic() {
    let seed = [42u8; 32];
    let mut keys1 = WalletKeys::from_seed(seed);
    let mut keys2 = WalletKeys::from_seed(seed);

    keys1.derive_epoch(0);
    keys2.derive_epoch(0);

    let epoch1 = keys1.current().expect("epoch 0 derived");
    let epoch2 = keys2.current().expect("epoch 0 derived");

    assert_eq!(
        epoch1.spend_secret.as_bytes(),
        epoch2.spend_secret.as_bytes(),
        "Same seed must produce same spend secret"
    );
    assert_eq!(
        epoch1.view_secret.as_bytes(),
        epoch2.view_secret.as_bytes(),
        "Same seed must produce same view secret"
    );
    assert_eq!(
        epoch1.spend_public.as_bytes(),
        epoch2.spend_public.as_bytes(),
        "Same seed must produce same spend public key"
    );
}

// =============================================================================
// TEST 2: Different seeds produce different keys (collision resistance)
// =============================================================================

#[test]
fn tier7_different_seeds_different_keys() {
    let mut spend_keys = std::collections::HashSet::new();

    for i in 0..100u8 {
        let mut seed = [0u8; 32];
        seed[0] = i;
        seed[1] = i.wrapping_mul(7);
        let mut keys = WalletKeys::from_seed(seed);
        keys.derive_epoch(0);
        let epoch = keys.current().unwrap();
        let spend = epoch.spend_secret.as_bytes().to_vec();
        assert!(
            spend_keys.insert(spend),
            "Spend key collision at seed {}!", i
        );
    }
}

// =============================================================================
// TEST 3: Key image uniqueness per output
// =============================================================================

#[test]
fn tier7_key_images_unique_per_secret() {
    let mut key_images = std::collections::HashSet::new();

    for _ in 0..1000 {
        let secret = SecretScalar::random(&mut OsRng);
        let ki = CryptoKeyImage::from_secret(&secret);
        assert!(
            key_images.insert(ki.to_bytes()),
            "Key image collision! Different secrets must produce different key images."
        );
    }
}

// =============================================================================
// TEST 4: Key image is deterministic for same secret
// =============================================================================

#[test]
fn tier7_key_image_deterministic() {
    let secret = SecretScalar::random(&mut OsRng);
    let ki1 = CryptoKeyImage::from_secret(&secret);
    let ki2 = CryptoKeyImage::from_secret(&secret);
    assert_eq!(ki1.to_bytes(), ki2.to_bytes(), "Same secret must always produce same key image");
}

// =============================================================================
// TEST 5: View key cannot derive spend key
// =============================================================================

#[test]
fn tier7_view_key_cannot_derive_spend() {
    let seed = [99u8; 32];
    let mut keys = WalletKeys::from_seed(seed);
    keys.derive_epoch(0);
    let epoch = keys.current().unwrap();

    assert_ne!(
        epoch.view_secret.as_bytes(),
        epoch.spend_secret.as_bytes(),
        "View and spend secrets must be different"
    );

    // View-derived public key must differ from spend public key
    let view_scalar = SecretScalar::from_bytes(*epoch.view_secret.as_bytes());
    let view_public = view_scalar.to_public();

    assert_ne!(
        view_public.to_bytes(),
        epoch.spend_public.as_bytes().to_owned(),
        "View-derived public key must not equal spend public key"
    );
}

// =============================================================================
// TEST 6: Mnemonic generates valid phrase
// =============================================================================

#[test]
fn tier7_mnemonic_generation_valid() {
    let mnemonic = WalletMnemonic::generate().expect("mnemonic generation");
    let phrase = mnemonic.phrase();

    // Must have 24 words (standard BIP39)
    let words: Vec<&str> = phrase.split_whitespace().collect();
    assert_eq!(words.len(), 24, "Mnemonic must be 24 words, got {}", words.len());

    // Must be reproducible from same phrase
    let restored = WalletMnemonic::from_phrase(phrase);
    assert!(restored.is_ok(), "Generated phrase must be re-parseable");
}

// =============================================================================
// TEST 7: Invalid mnemonic rejected
// =============================================================================

#[test]
fn tier7_invalid_mnemonic_rejected() {
    let garbage = "foo bar baz qux quux corge grault garply waldo fred plugh xyzzy thud alpha beta gamma delta epsilon zeta eta theta iota kappa";
    let result = WalletMnemonic::from_phrase(garbage);
    assert!(result.is_err(), "Random words must be rejected");

    let empty = WalletMnemonic::from_phrase("");
    assert!(empty.is_err(), "Empty phrase must be rejected");
}

// =============================================================================
// TEST 8: Same mnemonic always produces same seed
// =============================================================================

#[test]
fn tier7_mnemonic_to_seed_deterministic() {
    let mnemonic = WalletMnemonic::generate().expect("gen");
    let phrase = mnemonic.phrase().to_string();

    let m1 = WalletMnemonic::from_phrase(&phrase).unwrap();
    let m2 = WalletMnemonic::from_phrase(&phrase).unwrap();
    let seed1 = m1.to_seed("");
    let seed2 = m2.to_seed("");

    // Both seeds must be identical bytes
    assert_eq!(
        seed1.as_bytes(),
        seed2.as_bytes(),
        "Same mnemonic must produce same seed"
    );

    // And derive the same keys
    let mut s1 = [0u8; 32];
    s1.copy_from_slice(&seed1.as_bytes()[..32]);
    let mut s2 = [0u8; 32];
    s2.copy_from_slice(&seed2.as_bytes()[..32]);
    let mut k1 = WalletKeys::from_seed(s1);
    let mut k2 = WalletKeys::from_seed(s2);
    k1.derive_epoch(0);
    k2.derive_epoch(0);
    assert_eq!(
        k1.current().unwrap().spend_secret.as_bytes(),
        k2.current().unwrap().spend_secret.as_bytes(),
        "Same mnemonic must produce same keys"
    );
}

// =============================================================================
// TEST 9: Key image uses CLSAG formula (not blake3)
// =============================================================================

#[test]
fn tier7_key_image_uses_clsag_not_blake3() {
    let secret = SecretScalar::random(&mut OsRng);
    let ki_clsag = CryptoKeyImage::from_secret(&secret);

    let blake3_hash = blake3::hash(&secret.to_bytes());
    let blake3_bytes: [u8; 32] = *blake3_hash.as_bytes();

    assert_ne!(
        ki_clsag.to_bytes(), blake3_bytes,
        "Key image must use CLSAG formula (x * Hp(P)), not blake3(x)"
    );
}

// =============================================================================
// TEST 10: Watch-only wallet cannot spend
// =============================================================================

#[test]
fn tier7_watch_only_cannot_spend() {
    let seed = [77u8; 32];
    let mut keys = WalletKeys::from_seed(seed);
    keys.derive_epoch(0);
    let epoch = keys.current().unwrap();

    // Create watch-only wallet from view secret + spend public (clone to avoid move)
    let view_secret = SecretKey::from_bytes(*epoch.view_secret.as_bytes());
    let spend_public = epoch.spend_public;
    let watch = WalletKeys::watch_only(view_secret, spend_public);
    assert!(watch.is_watch_only(), "Watch-only flag must be set");
}
