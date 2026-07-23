//! # Encrypted Transaction Memos
//!
//! ECDH-encrypted memos attached to transaction outputs.
//! Uses ChaCha20-Poly1305 with keys derived from ECDH shared secret.
//!
//! Protocol:
//! 1. Sender computes shared_point = tx_secret * recipient_view_public
//! 2. Key = BLAKE3("COINCYNC_MEMO_v1" || shared_point)
//! 3. Nonce = BLAKE3("COINCYNC_MEMO_NONCE_v1" || shared_point)[0..12]
//! 4. Ciphertext = ChaCha20-Poly1305(key, nonce, memo)
//! 5. Wire format: nonce (12 bytes) || ciphertext || tag (16 bytes)
//!
//! Recipient decrypts with: shared_point = view_secret * tx_public_key

use chacha20poly1305::{
    aead::{Aead, KeyInit},
    ChaCha20Poly1305, Key, Nonce,
};
use rand::{rngs::OsRng, RngCore};
use zeroize::Zeroize;

use crate::crypto::{PublicPoint, SecretScalar};
use crate::error::{Error, Result};
use crate::primitives::hash_domain;

/// Maximum plaintext memo size (bytes)
pub const MAX_MEMO_SIZE: usize = 256;

/// Poly1305 authentication tag size
pub const MEMO_TAG_SIZE: usize = 16;

/// ChaCha20 nonce size
pub const MEMO_NONCE_SIZE: usize = 12;

/// Total overhead: nonce + tag
pub const MEMO_OVERHEAD: usize = MEMO_NONCE_SIZE + MEMO_TAG_SIZE;

/// Maximum encrypted memo size on the wire
pub const MAX_ENCRYPTED_MEMO_SIZE: usize = MAX_MEMO_SIZE + MEMO_OVERHEAD;

/// Derive the ChaCha20-Poly1305 key from the ECDH shared point.
///
/// The nonce is NOT derived here — it is generated freshly per encryption
/// (random 12 bytes) and placed on the wire so the recipient can read it
/// back. See the long-form comment on `encrypt_memo` for the rationale.
fn derive_memo_key(shared_point_bytes: &[u8]) -> [u8; 32] {
    let key_hash = hash_domain(b"COINCYNC_MEMO_v1", shared_point_bytes);
    *key_hash.as_bytes()
}

/// Encrypt a memo for a specific recipient.
///
/// # Arguments
/// * `memo` — plaintext memo bytes (max 256)
/// * `tx_secret_bytes` — ephemeral tx secret key (32 bytes)
/// * `recipient_view_public_bytes` — recipient's view public key (32 bytes)
///
/// # Returns
/// Encrypted memo: nonce (12) || ciphertext+tag (len + 16)
pub fn encrypt_memo(
    memo: &[u8],
    tx_secret_bytes: &[u8; 32],
    recipient_view_public_bytes: &[u8; 32],
) -> Result<Vec<u8>> {
    if memo.is_empty() {
        return Ok(Vec::new());
    }
    if memo.len() > MAX_MEMO_SIZE {
        return Err(Error::InvalidTransaction(format!(
            "memo too large: {} bytes (max {})",
            memo.len(),
            MAX_MEMO_SIZE
        )));
    }

    let tx_scalar = SecretScalar::from_bytes(*tx_secret_bytes);
    let view_point = PublicPoint::from_bytes(*recipient_view_public_bytes).ok_or(
        Error::CryptoError("invalid view public key for memo encryption".into()),
    )?;
    let mut shared_point = view_point.mul(&tx_scalar);

    // R-16 (R-7 class site) + R-17 fixes (2026-07-02):
    //   - `shared_point_bytes` is the ECDH shared secret and must be
    //     wiped after use. Prior code passed
    //     `shared_point.to_bytes().as_slice()` directly to
    //     `derive_memo_key`, leaving the temporary [u8; 32] on the
    //     stack unzeroized after the call.
    //   - `key_bytes` is the AEAD encryption key. Prior code let it
    //     drop as a plain `[u8; 32]` without zeroization, leaving
    //     ChaCha20-Poly1305 key material on the stack for the caller's
    //     lifetime. Now we bind it as `mut` and zeroize before return.
    //
    // R-7 CLASS + R-80 (2026-07-03): also zeroize the `shared_point:
    // PublicPoint` itself once we're done. This wipes the
    // RistrettoPoint's internal field elements via
    // curve25519-dalek 4.1's Zeroize impl.
    let mut shared_point_bytes = shared_point.to_bytes();
    let mut key_bytes = derive_memo_key(shared_point_bytes.as_slice());
    shared_point_bytes.zeroize();
    shared_point.zeroize();

    // 2026-06-03 nonce-reuse defense: generate a fresh random nonce per
    // encryption instead of deriving it deterministically from the ECDH
    // shared point. The previous derivation was
    //
    //   nonce = H("COINCYNC_MEMO_NONCE_v1", shared_point)[..12]
    //
    // which means TWO calls to encrypt_memo with the same (tx_secret,
    // recipient_view_public) pair would produce identical (key, nonce)
    // pairs. ChaCha20-Poly1305 nonce reuse is catastrophic — observing
    // both ciphertexts lets an attacker XOR them to recover
    // plaintext_a ⊕ plaintext_b, and the Poly1305 MAC is forgeable.
    //
    // In the current production wallet flow this never happens — the
    // builder attaches at most one memo per tx (see transaction/
    // builder.rs:516-529, `break` after the first recipient match), and
    // each tx has a fresh random tx_secret. So this was a *latent* API-
    // misuse hazard, not an active exploit: a future caller (a multi-
    // memo extension, a library user who reuses tx_secret across memos,
    // a test that loops calling encrypt_memo) would silently produce
    // catastrophically broken ciphertexts.
    //
    // The wire format already carries the nonce explicitly (next 12
    // bytes after the prefix), and decryption reads it directly from
    // the wire (see decrypt_memo at line ~122 — note the underscore
    // on the unused derived nonce). So switching to a random nonce on
    // the sender side is a pure-improvement change: existing memos
    // already on the chain decrypt unchanged because they carry their
    // own nonce on the wire; new memos get a per-encryption-fresh
    // nonce that eliminates the reuse class entirely.
    //
    // 12 bytes from OsRng: probability of collision across all CoinCync
    // memos ever sent is bounded by birthday √(2^96) ≈ 2^48 memos
    // before a single collision is expected. The actual quantity will
    // be many orders of magnitude lower, and even a collision only
    // matters within the same (key) — i.e. within memos to the same
    // recipient from the same tx_secret, which is already at most-one
    // by the builder convention above. Safe by overwhelming margin.
    let mut nonce_bytes = [0u8; MEMO_NONCE_SIZE];
    OsRng.fill_bytes(&mut nonce_bytes);

    let cipher = ChaCha20Poly1305::new(Key::from_slice(&key_bytes));
    let nonce = Nonce::from_slice(&nonce_bytes);

    let ciphertext = cipher
        .encrypt(nonce, memo)
        .map_err(|e| Error::CryptoError(format!("memo encryption failed: {}", e)))?;

    // R-17: zeroize the AEAD key now that the ciphertext is built.
    key_bytes.zeroize();

    // Wire format: nonce || ciphertext (includes 16-byte Poly1305 tag)
    let mut result = Vec::with_capacity(MEMO_NONCE_SIZE + ciphertext.len());
    result.extend_from_slice(&nonce_bytes);
    result.extend_from_slice(&ciphertext);
    Ok(result)
}

/// Decrypt an encrypted memo using the recipient's view secret key.
///
/// # Arguments
/// * `encrypted` — wire format: nonce (12) || ciphertext+tag
/// * `view_secret_bytes` — recipient's view secret key (32 bytes)
/// * `tx_public_key_bytes` — the output's tx_public_key (32 bytes)
///
/// # Returns
/// Decrypted plaintext memo bytes, or error if decryption fails.
pub fn decrypt_memo(
    encrypted: &[u8],
    view_secret_bytes: &[u8; 32],
    tx_public_key_bytes: &[u8; 32],
) -> Result<Vec<u8>> {
    if encrypted.is_empty() {
        return Ok(Vec::new());
    }
    if encrypted.len() < MEMO_NONCE_SIZE + MEMO_TAG_SIZE {
        return Err(Error::CryptoError("encrypted memo too short".into()));
    }

    let view_scalar = SecretScalar::from_bytes(*view_secret_bytes);
    let tx_point = PublicPoint::from_bytes(*tx_public_key_bytes).ok_or(Error::CryptoError(
        "invalid tx public key for memo decryption".into(),
    ))?;
    let mut shared_point = tx_point.mul(&view_scalar);

    // Key derived from shared point; nonce read from the wire — see the
    // long-form comment in `encrypt_memo` for why the nonce is sender-
    // chosen (random) rather than deterministically derived.
    //
    // R-16 (R-7 class) + R-17 (2026-07-02): wipe both the shared
    // point bytes and the derived AEAD key from the stack before
    // returning. See encrypt_memo for the full rationale.
    // R-7 CLASS + R-80 (2026-07-03): also zeroize the RistrettoPoint
    // shared_point after use.
    let mut shared_point_bytes = shared_point.to_bytes();
    let mut key_bytes = derive_memo_key(shared_point_bytes.as_slice());
    shared_point_bytes.zeroize();
    shared_point.zeroize();

    let nonce_bytes = &encrypted[..MEMO_NONCE_SIZE];
    let ciphertext = &encrypted[MEMO_NONCE_SIZE..];

    let cipher = ChaCha20Poly1305::new(Key::from_slice(&key_bytes));
    let nonce = Nonce::from_slice(nonce_bytes);

    let result = cipher
        .decrypt(nonce, ciphertext)
        .map_err(|_| Error::CryptoError("memo decryption failed (wrong key or corrupted)".into()));

    // R-17: wipe AEAD key after decrypt completes (success or failure).
    key_bytes.zeroize();
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::SecretScalar;
    use rand::rngs::OsRng;

    fn random_keypair() -> ([u8; 32], [u8; 32]) {
        let secret = SecretScalar::random(&mut OsRng);
        let public = secret.to_public();
        (secret.to_bytes(), public.to_bytes())
    }

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let (tx_secret, _tx_public) = random_keypair();
        let (view_secret, view_public) = random_keypair();

        // tx_public_key = tx_secret * G
        let tx_scalar = SecretScalar::from_bytes(tx_secret);
        let tx_public_bytes = tx_scalar.to_public().to_bytes();

        let memo = b"Payment for coffee";
        let encrypted = encrypt_memo(memo, &tx_secret, &view_public).unwrap();

        assert!(encrypted.len() > memo.len());
        assert_eq!(
            encrypted.len(),
            MEMO_NONCE_SIZE + memo.len() + MEMO_TAG_SIZE
        );

        let decrypted = decrypt_memo(&encrypted, &view_secret, &tx_public_bytes).unwrap();
        assert_eq!(decrypted, memo);
    }

    #[test]
    fn test_wrong_key_fails() {
        let (tx_secret, _) = random_keypair();
        let (_, view_public) = random_keypair();
        let (wrong_secret, _) = random_keypair();

        let tx_scalar = SecretScalar::from_bytes(tx_secret);
        let tx_public_bytes = tx_scalar.to_public().to_bytes();

        let memo = b"Secret message";
        let encrypted = encrypt_memo(memo, &tx_secret, &view_public).unwrap();

        let result = decrypt_memo(&encrypted, &wrong_secret, &tx_public_bytes);
        assert!(result.is_err());
    }

    #[test]
    fn test_empty_memo() {
        let (tx_secret, _) = random_keypair();
        let (_, view_public) = random_keypair();

        let encrypted = encrypt_memo(b"", &tx_secret, &view_public).unwrap();
        assert!(encrypted.is_empty());
    }

    #[test]
    fn test_max_size_memo() {
        let (tx_secret, _) = random_keypair();
        let (view_secret, view_public) = random_keypair();

        let tx_scalar = SecretScalar::from_bytes(tx_secret);
        let tx_public_bytes = tx_scalar.to_public().to_bytes();

        let memo = vec![0x42u8; MAX_MEMO_SIZE];
        let encrypted = encrypt_memo(&memo, &tx_secret, &view_public).unwrap();
        assert_eq!(encrypted.len(), MAX_ENCRYPTED_MEMO_SIZE);

        let decrypted = decrypt_memo(&encrypted, &view_secret, &tx_public_bytes).unwrap();
        assert_eq!(decrypted, memo);
    }

    #[test]
    fn test_oversized_memo_rejected() {
        let (tx_secret, _) = random_keypair();
        let (_, view_public) = random_keypair();

        let memo = vec![0u8; MAX_MEMO_SIZE + 1];
        let result = encrypt_memo(&memo, &tx_secret, &view_public);
        assert!(result.is_err());
    }

    #[test]
    fn test_truncated_ciphertext_fails() {
        let (tx_secret, _) = random_keypair();
        let (view_secret, view_public) = random_keypair();

        let tx_scalar = SecretScalar::from_bytes(tx_secret);
        let tx_public_bytes = tx_scalar.to_public().to_bytes();

        let encrypted = encrypt_memo(b"test", &tx_secret, &view_public).unwrap();
        let truncated = &encrypted[..encrypted.len() - 1];

        let result = decrypt_memo(truncated, &view_secret, &tx_public_bytes);
        assert!(result.is_err());
    }
}
