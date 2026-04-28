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

use crate::primitives::hash_domain;
use crate::crypto::{SecretScalar, PublicPoint};
use crate::error::{Error, Result};

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

/// Derive ChaCha20-Poly1305 key and nonce from ECDH shared point.
fn derive_memo_key_and_nonce(shared_point_bytes: &[u8]) -> ([u8; 32], [u8; 12]) {
    let key_hash = hash_domain(b"COINCYNC_MEMO_v1", shared_point_bytes);
    let nonce_hash = hash_domain(b"COINCYNC_MEMO_NONCE_v1", shared_point_bytes);
    let mut nonce = [0u8; 12];
    nonce.copy_from_slice(&nonce_hash.as_bytes()[..12]);
    (*key_hash.as_bytes(), nonce)
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
    let view_point = PublicPoint::from_bytes(*recipient_view_public_bytes)
        .ok_or(Error::CryptoError("invalid view public key for memo encryption".into()))?;
    let shared_point = view_point.mul(&tx_scalar);

    let (key_bytes, nonce_bytes) = derive_memo_key_and_nonce(shared_point.to_bytes().as_slice());

    let cipher = ChaCha20Poly1305::new(Key::from_slice(&key_bytes));
    let nonce = Nonce::from_slice(&nonce_bytes);

    let ciphertext = cipher
        .encrypt(nonce, memo)
        .map_err(|e| Error::CryptoError(format!("memo encryption failed: {}", e)))?;

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
    let tx_point = PublicPoint::from_bytes(*tx_public_key_bytes)
        .ok_or(Error::CryptoError("invalid tx public key for memo decryption".into()))?;
    let shared_point = tx_point.mul(&view_scalar);

    let (key_bytes, _) = derive_memo_key_and_nonce(shared_point.to_bytes().as_slice());

    let nonce_bytes = &encrypted[..MEMO_NONCE_SIZE];
    let ciphertext = &encrypted[MEMO_NONCE_SIZE..];

    let cipher = ChaCha20Poly1305::new(Key::from_slice(&key_bytes));
    let nonce = Nonce::from_slice(nonce_bytes);

    cipher
        .decrypt(nonce, ciphertext)
        .map_err(|_| Error::CryptoError("memo decryption failed (wrong key or corrupted)".into()))
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
        assert_eq!(encrypted.len(), MEMO_NONCE_SIZE + memo.len() + MEMO_TAG_SIZE);

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
