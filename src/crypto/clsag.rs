//! # CLSAG Ring Signatures
//!
//! Compact Linkable Spontaneous Anonymous Group signatures.
//! Based on the Monero CLSAG specification with proper curve operations.

use curve25519_dalek::{
    ristretto::RistrettoPoint,
    scalar::Scalar,
};
use rand_core::{CryptoRng, RngCore};
use sha3::{Digest, Sha3_512};
use serde::{Serialize, Deserialize};
use borsh::{BorshSerialize, BorshDeserialize};
use zeroize::Zeroize;
use std::fmt;

use super::curve::{
    SecretScalar, PublicPoint, KeyImage, Commitment,
    generator, hash_to_point,
};
use super::secure::ct_eq;
use crate::error::{Error, Result};

/// Ring member containing public key and commitment
#[derive(Clone, Debug, Serialize, Deserialize, BorshSerialize, BorshDeserialize)]
pub struct RingMember {
    /// Public key P = x*G
    pub public_key: PublicPoint,
    /// Pedersen commitment C = v*H + r*G
    pub commitment: Commitment,
}

impl RingMember {
    pub fn new(public_key: PublicPoint, commitment: Commitment) -> Self {
        RingMember { public_key, commitment }
    }
}

/// CLSAG signature
#[derive(Clone, Serialize, Deserialize, BorshSerialize, BorshDeserialize)]
pub struct ClsagSignature {
    /// Key image I = x * Hp(P)
    pub key_image: KeyImage,
    /// Commitment to zero key image (for amount verification)
    pub commitment_image: PublicPoint,
    /// Challenge scalar c_1
    pub c1: [u8; 32],
    /// Response scalars s_0, s_1, ..., s_{n-1}
    pub responses: Vec<[u8; 32]>,
}

impl ClsagSignature {
    pub fn ring_size(&self) -> usize {
        self.responses.len()
    }

    /// Serialize signature to bytes
    ///
    /// Returns empty vec on serialization failure (should never happen for valid
    /// signatures). Logs an error so the issue is visible without crashing the node.
    pub fn to_bytes(&self) -> Vec<u8> {
        borsh::to_vec(self).unwrap_or_else(|e| {
            tracing::error!("ClsagSignature serialization failed (bug): {}", e);
            Vec::new()
        })
    }

    /// Try to serialize signature to bytes, returning Result
    pub fn try_to_bytes(&self) -> Result<Vec<u8>> {
        borsh::to_vec(self).map_err(|e| Error::SerializationError(e.to_string()))
    }

    pub fn from_bytes(data: &[u8]) -> Result<Self> {
        borsh::from_slice(data)
            .map_err(|e| Error::InvalidSignature(e.to_string()))
    }
}

impl fmt::Debug for ClsagSignature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ClsagSignature")
            .field("key_image", &self.key_image)
            .field("ring_size", &self.ring_size())
            .finish()
    }
}

/// Aggregate hash for CLSAG
fn clsag_hash(
    prefix: &[u8],
    ring: &[RingMember],
    key_image: &KeyImage,
    commitment_image: &PublicPoint,
    message: &[u8],
    l: &RistrettoPoint,
    r: &RistrettoPoint,
) -> Scalar {
    let mut hasher = Sha3_512::new();
    hasher.update(b"CLSAG_");
    hasher.update(prefix);

    // Ring members
    for member in ring {
        hasher.update(member.public_key.to_bytes());
        hasher.update(member.commitment.to_bytes());
    }

    // Key image and commitment image
    hasher.update(key_image.to_bytes());
    hasher.update(commitment_image.to_bytes());

    // Message
    hasher.update(message);

    // L and R values
    hasher.update(l.compress().as_bytes());
    hasher.update(r.compress().as_bytes());

    Scalar::from_bytes_mod_order_wide(&hasher.finalize().into())
}

/// Round hash for CLSAG
fn clsag_round_hash(
    ring: &[RingMember],
    key_image: &KeyImage,
    pseudo_output: &Commitment,
    message: &[u8],
) -> Scalar {
    let mut hasher = Sha3_512::new();
    hasher.update(b"CLSAG_round");

    for member in ring {
        hasher.update(member.public_key.to_bytes());
        hasher.update(member.commitment.to_bytes());
    }

    hasher.update(key_image.to_bytes());
    hasher.update(pseudo_output.to_bytes());
    hasher.update(message);

    Scalar::from_bytes_mod_order_wide(&hasher.finalize().into())
}

/// Compute aggregate key coefficients
fn compute_aggregate_coefficients(
    ring: &[RingMember],
    key_image: &KeyImage,
    pseudo_output: &Commitment,
    message: &[u8],
) -> (Scalar, Scalar) {
    let mu_p = clsag_round_hash(ring, key_image, pseudo_output, message);

    let mut hasher = Sha3_512::new();
    hasher.update(b"CLSAG_agg_1");
    hasher.update(mu_p.as_bytes());
    let mu_c = Scalar::from_bytes_mod_order_wide(&hasher.finalize().into());

    (mu_p, mu_c)
}

/// Sign a message with CLSAG
///
/// # Parameters
/// - `message`: The message to sign
/// - `ring`: Ring of public keys and commitments (including the real one)
/// - `real_index`: Index of the real signer in the ring
/// - `secret_key`: Secret key corresponding to `ring[real_index].public_key`
/// - `blinding_diff`: The difference `z_real - z_pseudo` where:
///   - `z_real` is the blinding factor of `ring[real_index].commitment`
///   - `z_pseudo` is the blinding factor of `pseudo_output`
/// - `pseudo_output`: Commitment to the same value as the real input
pub fn clsag_sign<R: RngCore + CryptoRng>(
    message: &[u8],
    ring: &[RingMember],
    real_index: usize,
    secret_key: &SecretScalar,
    blinding_diff: &SecretScalar,
    pseudo_output: &Commitment,
    rng: &mut R,
) -> Result<ClsagSignature> {
    let n = ring.len();

    if n < 2 {
        return Err(Error::InvalidRingSize { expected: 2, got: n });
    }
    if real_index >= n {
        // SECURITY (L3): Use saturating_add to prevent overflow in error message
        return Err(Error::InvalidRingSize { expected: n, got: real_index.saturating_add(1) });
    }

    // Verify the secret key matches the public key at real_index
    let expected_public = secret_key.to_public();
    if expected_public != ring[real_index].public_key {
        // SECURITY: Use generic error message to prevent information leakage
        return Err(Error::InvalidSignature("invalid signing parameters".into()));
    }

    // Compute key image I = x * Hp(P)
    let key_image = KeyImage::from_secret(secret_key);

    // Compute commitment to zero key image
    // D = z * Hp(P) where z = blinding_diff
    let hp = hash_to_point(&expected_public.to_bytes());
    let commitment_image = PublicPoint::from_point(blinding_diff.as_scalar() * hp);

    // Compute aggregate coefficients
    let (mu_p, mu_c) = compute_aggregate_coefficients(ring, &key_image, pseudo_output, message);

    // Generate random alpha
    let alpha = SecretScalar::random(rng);

    // Initialize responses with random values
    let mut responses: Vec<Scalar> = (0..n)
        .map(|_| {
            let mut bytes = [0u8; 64];
            rng.fill_bytes(&mut bytes);
            let scalar = Scalar::from_bytes_mod_order_wide(&bytes);
            use zeroize::Zeroize;
            bytes.zeroize();
            scalar
        })
        .collect();

    // Compute aggregate public keys for each ring member
    // W_i = mu_p * P_i + mu_c * (C_i - C')
    // Using commitment difference ensures the value components cancel
    let aggregate_keys: Vec<RistrettoPoint> = ring.iter()
        .map(|m| {
            let p = m.public_key.as_point();
            let c_diff = m.commitment.sub(pseudo_output);
            mu_p * p + mu_c * c_diff.as_point().as_point()
        })
        .collect();

    // For the real signer, the commitment difference is:
    // C_real - C' = (v*H + z*G) - (v*H + z'*G) = (z - z')*G
    // The aggregate secret becomes: mu_p * x + mu_c * (z - z')
    let _c_diff_real = ring[real_index].commitment.sub(pseudo_output);

    // Compute L and R for the real signer
    let l_real = alpha.as_scalar() * generator();
    let r_real = alpha.as_scalar() * hp;

    // Start the challenge chain
    let mut challenges = vec![Scalar::ZERO; n];
    challenges[(real_index + 1) % n] = clsag_hash(
        b"c",
        ring,
        &key_image,
        &commitment_image,
        message,
        &l_real,
        &r_real,
    );

    // Compute challenges for the rest of the ring
    for offset in 1..n {
        let i = (real_index + offset) % n;
        let next = (i + 1) % n;

        let hp_i = hash_to_point(&ring[i].public_key.to_bytes());

        // L_i = s_i * G + c_i * W_i
        let l_i = responses[i] * generator() + challenges[i] * aggregate_keys[i];

        // R_i = s_i * Hp(P_i) + c_i * (I + mu_c * D)
        // Aggregate key image: mu_p * I + mu_c * D
        let aggregate_key_image = mu_p * key_image.as_point().as_point() + mu_c * commitment_image.as_point();
        let r_i = responses[i] * hp_i + challenges[i] * aggregate_key_image;

        challenges[next] = clsag_hash(
            b"c",
            ring,
            &key_image,
            &commitment_image,
            message,
            &l_i,
            &r_i,
        );
    }

    // Compute the real response
    // s_real = alpha - c_real * (mu_p * x + mu_c * z)
    let mut aggregate_secret = mu_p * secret_key.as_scalar() + mu_c * blinding_diff.as_scalar();
    responses[real_index] = alpha.as_scalar() - challenges[real_index] * aggregate_secret;

    // SECURITY (L-1): Zeroize the Scalar directly, not just a byte copy.
    // Scalar implements Zeroize in curve25519-dalek v4.
    aggregate_secret.zeroize();

    Ok(ClsagSignature {
        key_image,
        commitment_image,
        c1: challenges[1].to_bytes(), // n >= 2 is enforced by ring size check above
        responses: responses.iter().map(|s| s.to_bytes()).collect(),
    })
}

/// Verify a CLSAG signature
///
/// SECURITY: Validates that key_image is not the identity point (which would be invalid)
/// and uses constant-time comparison for the final challenge check.
pub fn clsag_verify(
    message: &[u8],
    ring: &[RingMember],
    pseudo_output: &Commitment,
    signature: &ClsagSignature,
) -> bool {
    use curve25519_dalek::traits::Identity;

    let n = ring.len();

    if signature.responses.len() != n || n < 2 {
        return false;
    }

    // SECURITY: Reject identity point key images (would indicate invalid/forged signature)
    // The identity point is the zero element of the group and cannot be a valid key image
    if signature.key_image.as_point().as_point() == &RistrettoPoint::identity() {
        return false;
    }

    // SECURITY: Also reject identity commitment_image (same reasoning)
    if signature.commitment_image.as_point() == &RistrettoPoint::identity() {
        return false;
    }

    // SECURITY: Parse responses, silently dropping any non-canonical
    // scalars (those whose byte representation exceeds the curve order ℓ
    // — RFC 8032 §5.1.7). The `len() != n` check on the next line then
    // rejects the whole signature if even one was dropped. This prevents
    // signature-malleability attacks where an adversary substitutes an
    // unreduced byte form of a valid scalar to mint a second on-chain
    // signature that hashes/verifies to the same logical signature but
    // differs bit-for-bit (would otherwise enable double-spend via
    // tx-id confusion or break uniqueness invariants downstream).
    let responses: Vec<Scalar> = signature.responses.iter()
        .filter_map(|b| {
            let opt: Option<Scalar> = Scalar::from_canonical_bytes(*b).into();
            opt
        })
        .collect();

    if responses.len() != n {
        return false;
    }

    // Parse c1
    let c1_opt: Option<Scalar> = Scalar::from_canonical_bytes(signature.c1).into();
    let c1 = match c1_opt {
        Some(s) => s,
        None => return false,
    };

    // SECURITY (A6-ZERO-CHALLENGE): Reject zero challenge to maintain binding between
    // key image and signer's secret key. A zero challenge eliminates the key image's
    // contribution to the verification equation, potentially enabling double-spends
    // with fabricated key images.
    if c1 == Scalar::ZERO {
        return false;
    }

    // Compute aggregate coefficients
    let (mu_p, mu_c) = compute_aggregate_coefficients(ring, &signature.key_image, pseudo_output, message);

    // Compute aggregate public keys (must match signing formulation)
    // W_i = mu_p * P_i + mu_c * (C_i - C')
    let aggregate_keys: Vec<RistrettoPoint> = ring.iter()
        .map(|m| {
            let p = m.public_key.as_point();
            let c_diff = m.commitment.sub(pseudo_output);
            mu_p * p + mu_c * c_diff.as_point().as_point()
        })
        .collect();

    // Verify the challenge chain by computing all challenges and checking closure
    // The ring signature forms a closed loop: c[1] -> c[2] -> ... -> c[n-1] -> c[0] -> c[1]
    let mut current_challenge = c1;

    // Start from index 1 and go through all ring members
    for i in 0..n {
        // Compute the index we're verifying (starts at 1 since c1 is given)
        let idx = (i + 1) % n;

        let hp_idx = hash_to_point(&ring[idx].public_key.to_bytes());

        // L_idx = s_idx * G + c_idx * W_idx
        let l_idx = responses[idx] * generator() + current_challenge * aggregate_keys[idx];

        // R_idx = s_idx * Hp(P_idx) + c_idx * J where J = mu_p * I + mu_c * D
        let aggregate_key_image = mu_p * signature.key_image.as_point().as_point() +
                        mu_c * signature.commitment_image.as_point();
        let r_idx = responses[idx] * hp_idx + current_challenge * aggregate_key_image;

        current_challenge = clsag_hash(
            b"c",
            ring,
            &signature.key_image,
            &signature.commitment_image,
            message,
            &l_idx,
            &r_idx,
        );
    }

    // After going through all n elements, the challenge chain should close back to c1
    // SECURITY: Use constant-time comparison to prevent timing attacks
    ct_eq(current_challenge.as_bytes(), c1.as_bytes())
}

/// Simple ring signature (without commitment linking)
/// Used for basic transaction authorization
#[derive(Clone, Serialize, Deserialize, BorshSerialize, BorshDeserialize)]
pub struct SimpleRingSignature {
    pub key_image: KeyImage,
    pub c0: [u8; 32],
    pub responses: Vec<[u8; 32]>,
}

impl SimpleRingSignature {
    pub fn ring_size(&self) -> usize {
        self.responses.len()
    }
}

impl fmt::Debug for SimpleRingSignature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SimpleRingSignature")
            .field("key_image", &self.key_image)
            .field("ring_size", &self.ring_size())
            .finish()
    }
}

/// Sign with a simple ring signature (no commitment)
pub fn simple_ring_sign<R: RngCore + CryptoRng>(
    message: &[u8],
    public_keys: &[PublicPoint],
    real_index: usize,
    secret_key: &SecretScalar,
    rng: &mut R,
) -> Result<SimpleRingSignature> {
    let n = public_keys.len();

    if n < 2 {
        return Err(Error::InvalidRingSize { expected: 2, got: n });
    }
    if real_index >= n {
        // SECURITY (L3): Use saturating_add to prevent overflow in error message
        return Err(Error::InvalidRingSize { expected: n, got: real_index.saturating_add(1) });
    }

    // Verify secret key
    let expected = secret_key.to_public();
    if expected != public_keys[real_index] {
        // SECURITY: Use generic error message to prevent information leakage
        return Err(Error::InvalidSignature("invalid signing parameters".into()));
    }

    // Key image
    let key_image = KeyImage::from_secret(secret_key);

    // Random alpha
    let alpha = SecretScalar::random(rng);

    // Random responses
    let mut responses: Vec<Scalar> = (0..n)
        .map(|_| {
            let mut bytes = [0u8; 64];
            rng.fill_bytes(&mut bytes);
            let scalar = Scalar::from_bytes_mod_order_wide(&bytes);
            use zeroize::Zeroize;
            bytes.zeroize();
            scalar
        })
        .collect();

    // L = alpha * G
    let l_real = alpha.as_scalar() * generator();
    // R = alpha * Hp(P)
    let hp = hash_to_point(&expected.to_bytes());
    let r_real = alpha.as_scalar() * hp;

    // Initial challenge
    let mut challenges = vec![Scalar::ZERO; n];
    challenges[(real_index + 1) % n] = simple_hash(message, public_keys, &key_image, &l_real, &r_real);

    // Build challenge chain
    for offset in 1..n {
        let i = (real_index + offset) % n;
        let next = (i + 1) % n;

        let hp_i = hash_to_point(&public_keys[i].to_bytes());
        let l_i = responses[i] * generator() + challenges[i] * public_keys[i].as_point();
        let r_i = responses[i] * hp_i + challenges[i] * key_image.as_point().as_point();

        challenges[next] = simple_hash(message, public_keys, &key_image, &l_i, &r_i);
    }

    // Compute real response
    responses[real_index] = alpha.as_scalar() - challenges[real_index] * secret_key.as_scalar();

    Ok(SimpleRingSignature {
        key_image,
        c0: challenges[0].to_bytes(),
        responses: responses.iter().map(|s| s.to_bytes()).collect(),
    })
}

/// Verify a simple ring signature
pub fn simple_ring_verify(
    message: &[u8],
    public_keys: &[PublicPoint],
    signature: &SimpleRingSignature,
) -> bool {
    use curve25519_dalek::traits::Identity;

    let n = public_keys.len();

    if signature.responses.len() != n || n < 2 {
        return false;
    }

    // SECURITY: Reject identity point key images (would indicate invalid/forged signature)
    if signature.key_image.as_point().as_point() == &RistrettoPoint::identity() {
        return false;
    }

    let responses: Vec<Scalar> = signature.responses.iter()
        .filter_map(|b| {
            let opt: Option<Scalar> = Scalar::from_canonical_bytes(*b).into();
            opt
        })
        .collect();

    if responses.len() != n {
        return false;
    }

    let c0_opt: Option<Scalar> = Scalar::from_canonical_bytes(signature.c0).into();
    let c0 = match c0_opt {
        Some(s) => s,
        None => return false,
    };

    // SECURITY (A6-ZERO-CHALLENGE): Reject zero challenge in simple ring signature
    if c0 == Scalar::ZERO {
        return false;
    }

    let mut c = c0;

    for i in 0..n {
        let hp_i = hash_to_point(&public_keys[i].to_bytes());
        let l_i = responses[i] * generator() + c * public_keys[i].as_point();
        let r_i = responses[i] * hp_i + c * signature.key_image.as_point().as_point();

        c = simple_hash(message, public_keys, &signature.key_image, &l_i, &r_i);
    }

    // SECURITY: Use constant-time comparison to prevent timing attacks
    ct_eq(c.as_bytes(), c0.as_bytes())
}

fn simple_hash(
    message: &[u8],
    public_keys: &[PublicPoint],
    key_image: &KeyImage,
    l: &RistrettoPoint,
    r: &RistrettoPoint,
) -> Scalar {
    let mut hasher = Sha3_512::new();
    hasher.update(b"CoinCync_ring_v1");
    hasher.update(message);
    for pk in public_keys {
        hasher.update(pk.to_bytes());
    }
    hasher.update(key_image.to_bytes());
    hasher.update(l.compress().as_bytes());
    hasher.update(r.compress().as_bytes());
    Scalar::from_bytes_mod_order_wide(&hasher.finalize().into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::OsRng;

    #[test]
    fn test_simple_ring_signature() {
        let secret = SecretScalar::random(&mut OsRng);
        let public = secret.to_public();

        // Create decoy keys
        let decoy1 = SecretScalar::random(&mut OsRng).to_public();
        let decoy2 = SecretScalar::random(&mut OsRng).to_public();

        let ring = vec![public, decoy1, decoy2];
        let message = b"test transaction";

        let sig = simple_ring_sign(message, &ring, 0, &secret, &mut OsRng).unwrap();

        assert_eq!(sig.ring_size(), 3);
        assert!(simple_ring_verify(message, &ring, &sig));
    }

    #[test]
    fn test_simple_ring_wrong_message() {
        let secret = SecretScalar::random(&mut OsRng);
        let public = secret.to_public();
        let decoy = SecretScalar::random(&mut OsRng).to_public();

        let ring = vec![public, decoy];
        let message = b"correct";
        let wrong = b"wrong";

        let sig = simple_ring_sign(message, &ring, 0, &secret, &mut OsRng).unwrap();

        assert!(simple_ring_verify(message, &ring, &sig));
        assert!(!simple_ring_verify(wrong, &ring, &sig));
    }

    #[test]
    fn test_key_image_linkability() {
        let secret = SecretScalar::random(&mut OsRng);
        let public = secret.to_public();
        let decoy = SecretScalar::random(&mut OsRng).to_public();

        let ring = vec![public, decoy];

        // Sign two different messages with same key
        let sig1 = simple_ring_sign(b"msg1", &ring, 0, &secret, &mut OsRng).unwrap();
        let sig2 = simple_ring_sign(b"msg2", &ring, 0, &secret, &mut OsRng).unwrap();

        // Key images should be the same (linkable)
        assert_eq!(sig1.key_image, sig2.key_image);
    }

    #[test]
    fn test_different_real_index() {
        let secret = SecretScalar::random(&mut OsRng);
        let public = secret.to_public();
        let decoy1 = SecretScalar::random(&mut OsRng).to_public();
        let decoy2 = SecretScalar::random(&mut OsRng).to_public();

        let ring = vec![decoy1, public, decoy2];
        let message = b"test";

        let sig = simple_ring_sign(message, &ring, 1, &secret, &mut OsRng).unwrap();
        assert!(simple_ring_verify(message, &ring, &sig));
    }

    #[test]
    fn test_clsag_sign_verify() {
        // Real signer
        let secret = SecretScalar::random(&mut OsRng);
        let public = secret.to_public();

        // Commitment for real input: C_real = v*H + z_real*G
        let z_real = SecretScalar::random(&mut OsRng);
        let value = 1000u64;
        let real_commitment = Commitment::commit(value, &z_real);

        // Pseudo output with DIFFERENT blinding: C' = v*H + z_pseudo*G
        let z_pseudo = SecretScalar::random(&mut OsRng);
        let pseudo_output = Commitment::commit(value, &z_pseudo);

        // Blinding difference: z_real - z_pseudo
        let blinding_diff = SecretScalar::from_scalar(
            z_real.as_scalar() - z_pseudo.as_scalar()
        );

        // Create ring with decoys
        let decoy1_secret = SecretScalar::random(&mut OsRng);
        let decoy1_commitment = Commitment::commit(value, &SecretScalar::random(&mut OsRng));

        let decoy2_secret = SecretScalar::random(&mut OsRng);
        let decoy2_commitment = Commitment::commit(value, &SecretScalar::random(&mut OsRng));

        let ring = vec![
            RingMember::new(public, real_commitment),
            RingMember::new(decoy1_secret.to_public(), decoy1_commitment),
            RingMember::new(decoy2_secret.to_public(), decoy2_commitment),
        ];

        let message = b"CLSAG test transaction";

        // Sign
        let sig = clsag_sign(
            message,
            &ring,
            0, // real index
            &secret,
            &blinding_diff,
            &pseudo_output,
            &mut OsRng,
        ).unwrap();

        // Verify
        assert!(clsag_verify(message, &ring, &pseudo_output, &sig));

        // Wrong message should fail
        assert!(!clsag_verify(b"wrong message", &ring, &pseudo_output, &sig));

        // Wrong pseudo_output should fail
        let wrong_pseudo = Commitment::commit(value + 1, &SecretScalar::random(&mut OsRng));
        assert!(!clsag_verify(message, &ring, &wrong_pseudo, &sig));
    }

    #[test]
    fn test_clsag_serialization() {
        let secret = SecretScalar::random(&mut OsRng);
        let public = secret.to_public();

        // Real commitment with blinding z_real
        let z_real = SecretScalar::random(&mut OsRng);
        let real_commitment = Commitment::commit(100, &z_real);

        // Pseudo output with different blinding z_pseudo
        let z_pseudo = SecretScalar::random(&mut OsRng);
        let pseudo_output = Commitment::commit(100, &z_pseudo);

        // Blinding difference
        let blinding_diff = SecretScalar::from_scalar(
            z_real.as_scalar() - z_pseudo.as_scalar()
        );

        let decoy = SecretScalar::random(&mut OsRng);
        let decoy_commitment = Commitment::commit(100, &SecretScalar::random(&mut OsRng));

        let ring = vec![
            RingMember::new(public, real_commitment),
            RingMember::new(decoy.to_public(), decoy_commitment),
        ];

        let message = b"test";

        let sig = clsag_sign(message, &ring, 0, &secret, &blinding_diff, &pseudo_output, &mut OsRng).unwrap();

        // Serialize and deserialize
        let bytes = sig.to_bytes();
        let sig2 = ClsagSignature::from_bytes(&bytes).unwrap();

        // Should still verify
        assert!(clsag_verify(message, &ring, &pseudo_output, &sig2));
    }

    #[test]
    fn test_key_image_uniqueness() {
        let secret1 = SecretScalar::random(&mut OsRng);
        let secret2 = SecretScalar::random(&mut OsRng);

        let ki1 = KeyImage::from_secret(&secret1);
        let ki2 = KeyImage::from_secret(&secret2);

        assert_ne!(
            ki1.to_bytes(),
            ki2.to_bytes(),
            "Different keys must produce different key images"
        );
    }
}
