//! # Encrypted Transaction Memos
//!
//! ECDH-encrypted memos attached to transaction outputs.
//! Uses ChaCha20-Poly1305 with keys derived from ECDH shared secret.
//!
//! Protocol:
//! 1. Sender computes shared_point = tx_secret * recipient_view_public
//! 2. Key = BLAKE3("COINCYNC_MEMO_v1" || shared_point)
//! 3. Nonce = 12 fresh random bytes from the OS RNG, per encryption
//! 4. Plaintext is PADDED to a constant size: [len: u16 LE][memo][zero fill]
//! 5. Ciphertext = ChaCha20-Poly1305(key, nonce, padded)
//! 6. Wire format: nonce (12 bytes) || ciphertext || tag (16 bytes)
//!
//! Every encrypted memo is therefore exactly `MAX_OUTPUT_MEMO_SIZE` bytes, so
//! memo LENGTH is not observable on chain. Memo PRESENCE still is — an output
//! without a memo carries an empty field. See `encrypt_memo`.
//!
//! Recipient decrypts with: shared_point = view_secret * tx_public_key,
//! reading the nonce back off the wire.
//!
//! NOTE (2026-06-03): step 3 previously derived the nonce deterministically
//! as `BLAKE3("COINCYNC_MEMO_NONCE_v1" || shared_point)[0..12]`. That is a
//! nonce-reuse bug — two memos under the same (tx_secret, recipient) pair
//! share a (key, nonce) pair, which is catastrophic for ChaCha20-Poly1305.
//! It was replaced by the random nonce above; see the long-form comment in
//! `encrypt_memo`. This header still described the old derivation until
//! 2026-09-04.

use chacha20poly1305::{
    aead::{Aead, KeyInit},
    ChaCha20Poly1305, Key, Nonce,
};
use rand::{rngs::OsRng, RngCore};
use zeroize::Zeroize;

use crate::crypto::{PublicPoint, SecretScalar};
use crate::error::{Error, Result};
use crate::primitives::hash_domain;

/// Poly1305 authentication tag size
pub const MEMO_TAG_SIZE: usize = 16;

/// ChaCha20 nonce size
pub const MEMO_NONCE_SIZE: usize = 12;

/// Total overhead: nonce + tag
pub const MEMO_OVERHEAD: usize = MEMO_NONCE_SIZE + MEMO_TAG_SIZE;

/// Plaintext size every memo is padded to before encryption.
///
/// **Derived from the consensus cap, never hardcoded.** Consensus rejects any
/// `encrypted_memo` longer than `MAX_OUTPUT_MEMO_SIZE`
/// (`consensus/validation.rs`), and encryption adds [`MEMO_OVERHEAD`], so the
/// largest plaintext that can ever reach the chain is exactly this. Deriving it
/// means the two can never drift apart.
///
/// This corrects a real builder/verifier asymmetry (WP-009 §2.3): `MAX_MEMO_SIZE`
/// used to be a hardcoded 256, so the wallet happily built a 256-byte memo that
/// encrypted to 284 bytes and consensus refused — verified live, a 240-byte memo
/// was rejected with `encrypted_memo too large: 268 bytes (max 256)`. The
/// documented maximum memo size was unusable.
pub const MEMO_PADDED_PLAINTEXT: usize =
    crate::constants::MAX_OUTPUT_MEMO_SIZE - MEMO_OVERHEAD;

/// Bytes reserved for the little-endian `u16` length prefix inside the padded
/// plaintext. Padding must be reversible, so the true length travels with it.
const MEMO_LEN_PREFIX: usize = 2;

/// Maximum plaintext memo a caller may supply.
///
/// Smaller than it once was, and honestly so: the old 256 could not be spent.
pub const MAX_MEMO_SIZE: usize = MEMO_PADDED_PLAINTEXT - MEMO_LEN_PREFIX;

// A padded memo must land exactly on the consensus cap. If someone retunes
// MAX_OUTPUT_MEMO_SIZE or the AEAD overhead, fail the build rather than start
// emitting transactions the network rejects.
const _: () = assert!(
    MEMO_PADDED_PLAINTEXT + MEMO_OVERHEAD == crate::constants::MAX_OUTPUT_MEMO_SIZE,
    "padded memo must encrypt to exactly MAX_OUTPUT_MEMO_SIZE"
);

/// Encrypted memo size on the wire.
///
/// Not a maximum any more — an INVARIANT. Every non-empty memo is padded to
/// [`MEMO_PADDED_PLAINTEXT`] before encryption, so every encrypted memo that
/// reaches the chain is exactly this many bytes and memo length is not
/// observable. Equal to the consensus cap by construction (see the static
/// assertion above).
pub const MAX_ENCRYPTED_MEMO_SIZE: usize = MEMO_PADDED_PLAINTEXT + MEMO_OVERHEAD;

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
/// The plaintext is **padded to a constant size** before encryption, so every
/// encrypted memo on chain is exactly `MAX_OUTPUT_MEMO_SIZE` bytes regardless of
/// what the user wrote.
///
/// # Why padding is mandatory, not a nicety
///
/// A memo's ciphertext length is attacker-visible. Unpadded, a 6-byte invoice
/// reference and a 200-byte note are trivially distinguishable, which sorts
/// users by *content class* — the anonymity-set partitioning WP-011 §1 exists to
/// prevent, and which the project's own design charter commits against under
/// "mandatory uniformity: fixed ring size, uniform fees, **padded sizes**".
///
/// This was previously unimplemented while three separate documents asserted it
/// was done (`constants.rs`, WP-014 §3.4, WP-011 §3.3). Live check: a 27-byte
/// memo produced 55 wire bytes.
///
/// # What padding still does NOT hide
///
/// Memo **presence**. An output with no memo carries an empty field; one with a
/// memo now carries 256 bytes. Closing that requires a fixed-size memo field on
/// *every* output — a consensus rule with a real per-transaction size cost, and
/// a separate decision. Padding removes the length leak; it does not remove the
/// presence leak, and this comment exists so nobody later assumes it did.
///
/// # Padded layout
///
/// `[len: u16 LE][memo bytes][zero fill]`, totalling [`MEMO_PADDED_PLAINTEXT`].
///
/// # Arguments
/// * `memo` — plaintext memo bytes (max [`MAX_MEMO_SIZE`])
/// * `tx_secret_bytes` — ephemeral tx secret key (32 bytes)
/// * `recipient_view_public_bytes` — recipient's view public key (32 bytes)
///
/// # Returns
/// Encrypted memo: nonce (12) || ciphertext+tag — always `MAX_OUTPUT_MEMO_SIZE`.
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

    // Pad to a constant size. `memo.len()` is bounded above, so the cast and the
    // slice writes below cannot overflow or panic.
    let mut padded = vec![0u8; MEMO_PADDED_PLAINTEXT];
    padded[..MEMO_LEN_PREFIX].copy_from_slice(&(memo.len() as u16).to_le_bytes());
    padded[MEMO_LEN_PREFIX..MEMO_LEN_PREFIX + memo.len()].copy_from_slice(memo);
    let memo: &[u8] = &padded;

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

    result.map(unpad_memo)
}

/// Recover the original memo from a padded plaintext.
///
/// A padded memo is *always* exactly [`MEMO_PADDED_PLAINTEXT`] bytes, so that
/// length is the discriminator — no version byte needed. Anything else is a
/// pre-padding memo and is returned unchanged, so memos written before padding
/// existed still read correctly rather than decoding to garbage.
///
/// A declared length that does not fit the buffer means corruption or a
/// hostile-but-authenticated payload; return the raw bytes rather than panicking
/// on a slice, since this runs on data the sender chose.
fn unpad_memo(plaintext: Vec<u8>) -> Vec<u8> {
    if plaintext.len() != MEMO_PADDED_PLAINTEXT {
        return plaintext; // legacy unpadded memo
    }
    let declared =
        u16::from_le_bytes([plaintext[0], plaintext[1]]) as usize;
    if declared > MEMO_PADDED_PLAINTEXT - MEMO_LEN_PREFIX {
        return plaintext;
    }
    plaintext[MEMO_LEN_PREFIX..MEMO_LEN_PREFIX + declared].to_vec()
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

    /// THE uniformity property: memo length must not be observable on chain.
    ///
    /// Every encrypted memo is exactly `MAX_OUTPUT_MEMO_SIZE`, whatever the user
    /// wrote. Before padding, a 27-byte memo produced 55 wire bytes and a
    /// 200-byte one produced 228 — sorting users by content class, the
    /// anonymity-set partitioning WP-011 §1 exists to prevent.
    #[test]
    fn every_encrypted_memo_is_the_same_size() {
        let (tx_secret, _) = random_keypair();
        let (_, view_public) = random_keypair();

        let mut seen = std::collections::HashSet::new();
        for len in [1usize, 6, 27, 100, 200, MAX_MEMO_SIZE] {
            let memo = vec![b'x'; len];
            let ct = encrypt_memo(&memo, &tx_secret, &view_public).expect("encrypt");
            assert_eq!(
                ct.len(),
                crate::constants::MAX_OUTPUT_MEMO_SIZE,
                "memo of {len} bytes must still encrypt to the constant wire size"
            );
            seen.insert(ct.len());
        }
        assert_eq!(seen.len(), 1, "all memo sizes must collapse to one wire length");
    }

    /// Padding must be reversible for every length, including the edges.
    #[test]
    fn padded_memo_round_trips_at_every_length() {
        let tx_secret_scalar = SecretScalar::random(&mut OsRng);
        let tx_secret = tx_secret_scalar.to_bytes();
        let tx_public = tx_secret_scalar.to_public().to_bytes();
        let view_secret_scalar = SecretScalar::random(&mut OsRng);
        let view_secret = view_secret_scalar.to_bytes();
        let view_public = view_secret_scalar.to_public().to_bytes();

        for len in [1usize, 2, 27, 225, MAX_MEMO_SIZE] {
            let memo: Vec<u8> = (0..len).map(|i| (i % 251) as u8).collect();
            let ct = encrypt_memo(&memo, &tx_secret, &view_public).expect("encrypt");
            let out = decrypt_memo(&ct, &view_secret, &tx_public).expect("decrypt");
            assert_eq!(out, memo, "round-trip failed at {len} bytes");
        }
    }

    /// The builder must not accept what the verifier will reject (WP-009 §2.3).
    ///
    /// `MAX_MEMO_SIZE` was a hardcoded 256 while consensus capped the ENCRYPTED
    /// field at 256, so a max-size memo encrypted to 284 and the network refused
    /// it. Verified live: a 240-byte memo was rejected with `encrypted_memo too
    /// large: 268 bytes (max 256)`. Deriving the cap makes that unrepresentable.
    #[test]
    fn max_memo_cannot_exceed_the_consensus_cap() {
        let (tx_secret, _) = random_keypair();
        let (_, view_public) = random_keypair();

        let at_max = vec![b'x'; MAX_MEMO_SIZE];
        let ct = encrypt_memo(&at_max, &tx_secret, &view_public).expect("max memo must encrypt");
        assert!(
            ct.len() <= crate::constants::MAX_OUTPUT_MEMO_SIZE,
            "a maximum-size memo must be acceptable to consensus, got {} > {}",
            ct.len(),
            crate::constants::MAX_OUTPUT_MEMO_SIZE
        );

        assert!(
            encrypt_memo(&vec![b'x'; MAX_MEMO_SIZE + 1], &tx_secret, &view_public).is_err(),
            "over-cap memo must be refused by the builder, not by the network"
        );
    }

    /// Memos written before padding existed must still decode, not turn to
    /// garbage: the padded form is always exactly MEMO_PADDED_PLAINTEXT, so any
    /// other length is unambiguously legacy.
    #[test]
    fn legacy_unpadded_plaintext_is_returned_unchanged() {
        let legacy = b"written before padding".to_vec();
        assert_ne!(legacy.len(), MEMO_PADDED_PLAINTEXT);
        assert_eq!(unpad_memo(legacy.clone()), legacy);
    }

    /// A padded buffer whose declared length overruns it is corrupt or hostile.
    /// It must not panic on the slice.
    #[test]
    fn corrupt_length_prefix_does_not_panic() {
        let mut bad = vec![0u8; MEMO_PADDED_PLAINTEXT];
        bad[..2].copy_from_slice(&u16::MAX.to_le_bytes());
        let _ = unpad_memo(bad); // must simply not panic
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

        // Ciphertext length must NOT track memo length — that was the leak.
        // This assertion previously read
        //     encrypted.len() == MEMO_NONCE_SIZE + memo.len() + MEMO_TAG_SIZE
        // which pinned the bug in place: it required the wire size to reveal how
        // long the memo was.
        assert!(encrypted.len() > memo.len());
        assert_eq!(encrypted.len(), MAX_ENCRYPTED_MEMO_SIZE);

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
