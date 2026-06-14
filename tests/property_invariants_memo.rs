//! Property-based invariants for `coincync::crypto::memo`.
//!
//! Every transaction can carry an encrypted memo (up to 256 bytes).
//! The encryption uses ChaCha20-Poly1305 with a key + nonce derived
//! deterministically from the ECDH shared point between tx_secret
//! and view_public. The AEAD construction means tampering is detected
//! by Poly1305 — bit-flipping the ciphertext makes decryption fail.
//!
//! These properties exercise:
//!
//! - **Roundtrip:** decrypt(encrypt(m, tx_sk, view_pk), view_sk, tx_pk) == m
//! - **AEAD tamper-detection:** flipping any bit in the ciphertext
//!   makes decryption fail
//! - **Empty memo:** encrypt([]) == [], decrypt([]) == []
//! - **Size limit:** encrypt rejects memos > MAX_MEMO_SIZE
//! - **Truncated ciphertext:** decrypt rejects bytes shorter than the
//!   nonce + tag overhead
//! - **Wrong key:** decrypting with a different view_secret returns Err
//! - **Determinism:** encrypt is deterministic (nonce derived from ECDH)
//!
//! Per `src/crypto/memo.rs:57-92` (encrypt) and `:103-131` (decrypt).

#![cfg(not(miri))]

use proptest::prelude::*;
use rand::rngs::StdRng;
use rand::SeedableRng;

use coincync::crypto::memo::{decrypt_memo, encrypt_memo, MAX_MEMO_SIZE, MEMO_OVERHEAD};
use coincync::crypto::SecretScalar;

// ─── Helpers ─────────────────────────────────────────────────────

/// Deterministic keypair from a seed. Returns (secret_bytes, public_bytes).
fn keypair_from_seed(seed: u64) -> ([u8; 32], [u8; 32]) {
    let mut rng = StdRng::seed_from_u64(seed);
    let s = SecretScalar::random(&mut rng);
    let p = s.to_public();
    (s.to_bytes(), p.to_bytes())
}

proptest! {
    #![proptest_config(ProptestConfig {
        cases: 128,  // ChaCha20-Poly1305 + ECDH per case ~ 64 cases/sec
        .. ProptestConfig::default()
    })]

    // ─── Empty memo edge case ─────────────────────────────────────

    /// `encrypt_memo([])` returns empty Vec (per `memo.rs:62-64`).
    #[test]
    fn encrypt_empty_returns_empty(
        tx_seed in any::<u64>(),
        view_seed in any::<u64>(),
    ) {
        let (tx_secret, _) = keypair_from_seed(tx_seed);
        let (_, view_public) = keypair_from_seed(view_seed);
        let result = encrypt_memo(&[], &tx_secret, &view_public)
            .expect("empty memo must succeed");
        prop_assert!(result.is_empty());
    }

    /// `decrypt_memo([])` returns empty Vec (per `memo.rs:108-110`).
    #[test]
    fn decrypt_empty_returns_empty(
        view_seed in any::<u64>(),
        tx_seed in any::<u64>(),
    ) {
        let (view_secret, _) = keypair_from_seed(view_seed);
        let (_, tx_public) = keypair_from_seed(tx_seed);
        let result = decrypt_memo(&[], &view_secret, &tx_public)
            .expect("empty ciphertext must succeed");
        prop_assert!(result.is_empty());
    }

    // ─── Roundtrip (the core property) ────────────────────────────

    /// For any (memo, tx_keypair, view_keypair):
    ///   decrypt(encrypt(memo, tx_sk, view_pk), view_sk, tx_pk) == memo
    ///
    /// This is the load-bearing invariant — every encrypted memo
    /// must be recoverable by its intended recipient.
    #[test]
    fn encrypt_decrypt_roundtrip(
        memo in proptest::collection::vec(any::<u8>(), 1..=MAX_MEMO_SIZE),
        tx_seed in any::<u64>(),
        view_seed in any::<u64>(),
    ) {
        prop_assume!(tx_seed != view_seed);
        let (tx_secret, tx_public) = keypair_from_seed(tx_seed);
        let (view_secret, view_public) = keypair_from_seed(view_seed);

        let encrypted = encrypt_memo(&memo, &tx_secret, &view_public)
            .expect("encrypt must succeed for valid keys + sized memo");
        let decrypted = decrypt_memo(&encrypted, &view_secret, &tx_public)
            .expect("decrypt with correct keys must succeed");
        prop_assert_eq!(decrypted, memo);
    }

    // ─── Size limit ───────────────────────────────────────────────

    /// Memos larger than MAX_MEMO_SIZE are rejected with an error
    /// (per `memo.rs:65-71`).
    #[test]
    fn oversize_memo_rejected(
        excess in 1usize..512usize,
        tx_seed in any::<u64>(),
        view_seed in any::<u64>(),
    ) {
        let memo = vec![0u8; MAX_MEMO_SIZE + excess];
        let (tx_secret, _) = keypair_from_seed(tx_seed);
        let (_, view_public) = keypair_from_seed(view_seed);
        let result = encrypt_memo(&memo, &tx_secret, &view_public);
        prop_assert!(result.is_err(),
            "encrypt accepted {}-byte memo (max: {})", memo.len(), MAX_MEMO_SIZE);
    }

    // ─── Truncated ciphertext rejected ────────────────────────────

    /// Encrypted blobs shorter than `MEMO_OVERHEAD` (nonce + tag = 28
    /// bytes) are rejected (per `memo.rs:111-113`).
    #[test]
    fn truncated_ciphertext_rejected(
        len in 1usize..MEMO_OVERHEAD,
        view_seed in any::<u64>(),
        tx_seed in any::<u64>(),
    ) {
        let (view_secret, _) = keypair_from_seed(view_seed);
        let (_, tx_public) = keypair_from_seed(tx_seed);
        let truncated = vec![0u8; len];
        let result = decrypt_memo(&truncated, &view_secret, &tx_public);
        prop_assert!(result.is_err(),
            "decrypt accepted {}-byte ciphertext (min: {})", len, MEMO_OVERHEAD);
    }

    // ─── AEAD tamper detection ────────────────────────────────────

    /// Flipping any single bit in a valid encrypted memo makes
    /// decryption fail. The Poly1305 authentication tag must catch
    /// every modification. **This is the AEAD security guarantee.**
    #[test]
    fn bit_flipped_ciphertext_rejected(
        memo in proptest::collection::vec(any::<u8>(), 1..=64),
        tx_seed in any::<u64>(),
        view_seed in any::<u64>(),
        byte_idx in any::<usize>(),
        bit_idx in 0u8..8,
    ) {
        prop_assume!(tx_seed != view_seed);
        let (tx_secret, tx_public) = keypair_from_seed(tx_seed);
        let (view_secret, view_public) = keypair_from_seed(view_seed);

        let mut encrypted = encrypt_memo(&memo, &tx_secret, &view_public)
            .expect("encrypt");
        // Pick a byte to corrupt within the encrypted blob.
        let idx = byte_idx % encrypted.len();
        encrypted[idx] ^= 1u8 << bit_idx;

        let result = decrypt_memo(&encrypted, &view_secret, &tx_public);
        prop_assert!(result.is_err(),
            "AEAD failed to catch bit-flip at byte={} bit={}", idx, bit_idx);
    }

    // ─── Wrong key rejected ───────────────────────────────────────

    /// Decryption with a view_secret that doesn't match the encrypting
    /// view_public fails. (The shared ECDH point differs ⇒ wrong key
    /// ⇒ Poly1305 tag check fails.)
    #[test]
    fn wrong_view_secret_rejected(
        memo in proptest::collection::vec(any::<u8>(), 1..=64),
        tx_seed in any::<u64>(),
        correct_view_seed in any::<u64>(),
        wrong_view_seed in any::<u64>(),
    ) {
        prop_assume!(correct_view_seed != wrong_view_seed);
        prop_assume!(tx_seed != correct_view_seed);
        prop_assume!(tx_seed != wrong_view_seed);

        let (tx_secret, tx_public) = keypair_from_seed(tx_seed);
        let (_, correct_view_public) = keypair_from_seed(correct_view_seed);
        let (wrong_view_secret, _) = keypair_from_seed(wrong_view_seed);

        let encrypted = encrypt_memo(&memo, &tx_secret, &correct_view_public)
            .expect("encrypt");
        let result = decrypt_memo(&encrypted, &wrong_view_secret, &tx_public);
        prop_assert!(result.is_err(),
            "decrypt with wrong view_secret succeeded");
    }

    // ─── Wrong tx_public rejected ────────────────────────────────

    /// Decryption with a tx_public that doesn't match the encrypting
    /// tx_secret fails. (Symmetric to wrong-view-secret.)
    #[test]
    fn wrong_tx_public_rejected(
        memo in proptest::collection::vec(any::<u8>(), 1..=64),
        correct_tx_seed in any::<u64>(),
        wrong_tx_seed in any::<u64>(),
        view_seed in any::<u64>(),
    ) {
        prop_assume!(correct_tx_seed != wrong_tx_seed);
        prop_assume!(correct_tx_seed != view_seed);
        prop_assume!(wrong_tx_seed != view_seed);

        let (correct_tx_secret, _) = keypair_from_seed(correct_tx_seed);
        let (_, wrong_tx_public) = keypair_from_seed(wrong_tx_seed);
        let (view_secret, view_public) = keypair_from_seed(view_seed);

        let encrypted = encrypt_memo(&memo, &correct_tx_secret, &view_public)
            .expect("encrypt");
        let result = decrypt_memo(&encrypted, &view_secret, &wrong_tx_public);
        prop_assert!(result.is_err(),
            "decrypt with wrong tx_public succeeded");
    }

    // ─── Determinism (the nonce is ECDH-derived) ─────────────────

    /// `encrypt_memo` is deterministic — same (memo, tx_sk, view_pk)
    /// produces byte-identical output every call. This is because the
    /// nonce is derived from the ECDH shared point, not from random
    /// entropy. (Per `memo.rs:78`: nonce is part of `derive_memo_key_and_nonce`.)
    ///
    /// Determinism here is a TRADE-OFF: it enables stateless encryption
    /// without requiring fresh randomness per memo, but it means
    /// encrypting the same memo to the same recipient twice yields
    /// identical ciphertexts. That's safe ONLY because tx_secret is
    /// fresh per transaction (so two different txs with identical memo
    /// content have different ciphertexts via different tx_secrets).
    ///
    /// Property: encrypt_memo MUST be non-deterministic — a fresh
    /// nonce is generated per call.
    ///
    /// Updated 2026-06-14 to match the security fix in commit
    /// 79b2625e ("crypto/memo: random nonce per encryption — close
    /// nonce-reuse hazard"). Pre-fix the encryption derived its
    /// nonce from (tx_sk, view_pk), making the output deterministic
    /// — and exposing every output's memo to anyone who saw two
    /// memos encrypted under the same key pair (XChaCha20 nonce
    /// reuse leaks the keystream → plaintext XOR is recoverable).
    /// The fix randomizes the nonce; this test would have caught
    /// any regression that reverted it.
    ///
    /// The decryption side is unaffected: receiver reads the
    /// nonce from the wire-format prefix and derives the key from
    /// (tx_pk, view_sk).
    #[test]
    fn encrypt_uses_fresh_nonce_per_call(
        memo in proptest::collection::vec(any::<u8>(), 1..=64),
        tx_seed in any::<u64>(),
        view_seed in any::<u64>(),
    ) {
        let (tx_secret, _) = keypair_from_seed(tx_seed);
        let (_, view_public) = keypair_from_seed(view_seed);
        let e1 = encrypt_memo(&memo, &tx_secret, &view_public).expect("e1");
        let e2 = encrypt_memo(&memo, &tx_secret, &view_public).expect("e2");
        prop_assert_ne!(&e1, &e2,
            "encrypt_memo MUST produce different ciphertexts on re-call \
             (nonce-reuse hazard would let a passive observer XOR two \
             same-key ciphertexts to recover plaintext xor)");
    }

    // ─── Encrypted output structure ──────────────────────────────

    /// For any non-empty memo, `encrypt_memo` produces output of length
    /// `memo.len() + MEMO_OVERHEAD` (12-byte nonce + ciphertext + 16-byte tag).
    /// Per the wire-format documentation at `memo.rs:55-56`.
    #[test]
    fn encrypted_output_has_expected_size(
        memo in proptest::collection::vec(any::<u8>(), 1..=MAX_MEMO_SIZE),
        tx_seed in any::<u64>(),
        view_seed in any::<u64>(),
    ) {
        let (tx_secret, _) = keypair_from_seed(tx_seed);
        let (_, view_public) = keypair_from_seed(view_seed);
        let encrypted = encrypt_memo(&memo, &tx_secret, &view_public)
            .expect("encrypt");
        prop_assert_eq!(encrypted.len(), memo.len() + MEMO_OVERHEAD);
    }
}
