//! # Elliptic Curve Operations
//!
//! Real elliptic curve cryptography using curve25519-dalek.
//! This module provides the foundational EC operations for CoinCync.

use curve25519_dalek::{
    constants::RISTRETTO_BASEPOINT_POINT,
    ristretto::{CompressedRistretto, RistrettoPoint},
    scalar::Scalar,
    traits::Identity,
};
use rand_core::{CryptoRng, RngCore};
use sha3::{Digest, Sha3_512};
use zeroize::{Zeroize, ZeroizeOnDrop};
use serde::{Serialize, Deserialize, Serializer, Deserializer};
use borsh::{BorshSerialize, BorshDeserialize};
use std::fmt;


/// Generator point G (Ristretto basepoint)
pub fn generator() -> RistrettoPoint {
    RISTRETTO_BASEPOINT_POINT
}

/// Alternative generator H for Pedersen commitments (value generator)
///
/// Hardcoded compressed Ristretto point. This is the standard bulletproofs H:
/// SHA-512(compressed_basepoint) mapped to Ristretto via from_uniform_bytes.
/// Previously extracted at runtime from bulletproofs::PedersenGens; now hardcoded
/// to eliminate the dalek-ng transitive dependency.
///
/// Convention: C = v*H + r*G (Monero). Value on H, blinding on G.
pub fn generator_h() -> RistrettoPoint {
    use once_cell::sync::Lazy;
    // Extracted from bulletproofs::PedersenGens::default().B_blinding
    const H_BYTES: [u8; 32] = [
        0x8c, 0x92, 0x40, 0xb4, 0x56, 0xa9, 0xe6, 0xdc,
        0x65, 0xc3, 0x77, 0xa1, 0x04, 0x8d, 0x74, 0x5f,
        0x94, 0xa0, 0x8c, 0xdb, 0x7f, 0x44, 0xcb, 0xcd,
        0x7b, 0x46, 0xf3, 0x40, 0x48, 0x87, 0x11, 0x34,
    ];
    static H_POINT: Lazy<RistrettoPoint> = Lazy::new(|| {
        CompressedRistretto::from_slice(&H_BYTES)
            .expect("H_BYTES is valid compressed Ristretto")
            .decompress()
            .expect("H generator must decompress")
    });
    *H_POINT
}

/// Hash arbitrary data to a curve point
pub fn hash_to_point(data: &[u8]) -> RistrettoPoint {
    let mut hasher = Sha3_512::new();
    hasher.update(b"CoinCync_hash_to_point_v1");
    hasher.update(data);
    RistrettoPoint::from_uniform_bytes(&hasher.finalize().into())
}

/// Hash data to a scalar
pub fn hash_to_scalar(data: &[u8]) -> Scalar {
    let mut hasher = Sha3_512::new();
    hasher.update(b"CoinCync_hash_to_scalar_v1");
    hasher.update(data);
    Scalar::from_bytes_mod_order_wide(&hasher.finalize().into())
}

/// A secret scalar (private key component)
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct SecretScalar(Scalar);

impl SecretScalar {
    /// Generate a random secret scalar
    pub fn random<R: RngCore + CryptoRng>(rng: &mut R) -> Self {
        let mut bytes = [0u8; 64];
        rng.fill_bytes(&mut bytes);
        let scalar = Scalar::from_bytes_mod_order_wide(&bytes);
        // SECURITY: Zeroize raw entropy immediately — prevents crash dump / cold-boot recovery
        use zeroize::Zeroize;
        bytes.zeroize();
        SecretScalar(scalar)
    }

    /// Create from bytes (reduced mod group order l)
    ///
    /// WARNING: This performs modular reduction. If the input bytes represent
    /// a value >= l (the Ristretto group order), the resulting scalar will
    /// differ from the input. This is intentional for key derivation from
    /// arbitrary bytes. For canonical (non-reducing) construction, use
    /// `from_canonical_bytes()` instead.
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        SecretScalar(Scalar::from_bytes_mod_order(bytes))
    }

    /// Create from canonical bytes
    pub fn from_canonical_bytes(bytes: [u8; 32]) -> Option<Self> {
        let opt: Option<Scalar> = Scalar::from_canonical_bytes(bytes).into();
        opt.map(SecretScalar)
    }

    /// Create from an existing Scalar
    pub fn from_scalar(scalar: Scalar) -> Self {
        SecretScalar(scalar)
    }

    /// Get the underlying scalar
    pub fn as_scalar(&self) -> &Scalar {
        &self.0
    }

    /// Convert to bytes
    pub fn to_bytes(&self) -> [u8; 32] {
        self.0.to_bytes()
    }

    /// Compute the public point: P = s * G
    pub fn to_public(&self) -> PublicPoint {
        PublicPoint(self.0 * generator())
    }

    /// Derive a child scalar using domain separation
    pub fn derive_child(&self, domain: &[u8], index: u64) -> Self {
        let mut hasher = Sha3_512::new();
        hasher.update(b"CoinCync_child_scalar_v1");
        hasher.update(self.to_bytes());
        hasher.update(domain);
        hasher.update(&index.to_le_bytes());
        SecretScalar(Scalar::from_bytes_mod_order_wide(&hasher.finalize().into()))
    }

    /// Add two secret scalars
    pub fn add(&self, other: &SecretScalar) -> SecretScalar {
        SecretScalar(self.0 + other.0)
    }

    /// Subtract two secret scalars
    pub fn sub(&self, other: &SecretScalar) -> SecretScalar {
        SecretScalar(self.0 - other.0)
    }

    /// Multiply by another scalar
    pub fn mul(&self, other: &SecretScalar) -> SecretScalar {
        SecretScalar(self.0 * other.0)
    }
}

impl fmt::Debug for SecretScalar {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SecretScalar([REDACTED])")
    }
}

/// A public curve point
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct PublicPoint(RistrettoPoint);

impl PublicPoint {
    /// Identity point (zero)
    pub fn identity() -> Self {
        PublicPoint(RistrettoPoint::identity())
    }

    /// Create from a RistrettoPoint
    pub fn from_point(point: RistrettoPoint) -> Self {
        PublicPoint(point)
    }

    /// Decompress from bytes
    pub fn from_bytes(bytes: [u8; 32]) -> Option<Self> {
        CompressedRistretto(bytes)
            .decompress()
            .map(PublicPoint)
    }

    /// Compress to bytes
    pub fn to_bytes(&self) -> [u8; 32] {
        self.0.compress().to_bytes()
    }

    /// Get the underlying point
    pub fn as_point(&self) -> &RistrettoPoint {
        &self.0
    }

    /// Check if this is the identity point
    pub fn is_identity(&self) -> bool {
        self.0 == RistrettoPoint::identity()
    }

    /// Add two points
    pub fn add(&self, other: &PublicPoint) -> PublicPoint {
        PublicPoint(self.0 + other.0)
    }

    /// Subtract two points
    pub fn sub(&self, other: &PublicPoint) -> PublicPoint {
        PublicPoint(self.0 - other.0)
    }

    /// Multiply by a scalar
    pub fn mul(&self, scalar: &SecretScalar) -> PublicPoint {
        PublicPoint(scalar.0 * self.0)
    }

    /// Multiply by a public scalar value
    pub fn mul_scalar(&self, scalar: &Scalar) -> PublicPoint {
        PublicPoint(scalar * self.0)
    }

    /// Compute hash of the point for key image
    pub fn hash_to_point(&self) -> PublicPoint {
        hash_to_point(&self.to_bytes()).into()
    }

    /// R-7 CLASS + R-80 SURGICAL FIX (2026-07-03): explicitly
    /// zeroize the underlying RistrettoPoint. curve25519-dalek 4.1
    /// implements `Zeroize` for RistrettoPoint at ristretto.rs:1266
    /// under the `zeroize` feature (which our Cargo.toml now enables
    /// explicitly). Callers holding a `PublicPoint` that carries
    /// secret material (e.g. the ECDH shared point) MUST call
    /// this on the point before it goes out of scope. We do NOT
    /// impl Drop for PublicPoint because that conflicts with the
    /// `Copy` derive that many callers rely on; instead callers
    /// zero explicitly at the site where the shared-point value
    /// is used, then let the Copy'd stack slot go.
    pub fn zeroize(&mut self) {
        use zeroize::Zeroize as _;
        self.0.zeroize();
    }
}

impl zeroize::Zeroize for PublicPoint {
    fn zeroize(&mut self) {
        Self::zeroize(self);
    }
}

impl From<RistrettoPoint> for PublicPoint {
    fn from(point: RistrettoPoint) -> Self {
        PublicPoint(point)
    }
}

impl fmt::Debug for PublicPoint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "PublicPoint({})", hex::encode(&self.to_bytes()[..8]))
    }
}

impl fmt::Display for PublicPoint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", hex::encode(self.to_bytes()))
    }
}

impl Serialize for PublicPoint {
    fn serialize<S: Serializer>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error> {
        if serializer.is_human_readable() {
            serializer.serialize_str(&hex::encode(self.to_bytes()))
        } else {
            serializer.serialize_bytes(&self.to_bytes())
        }
    }
}

impl<'de> Deserialize<'de> for PublicPoint {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> std::result::Result<Self, D::Error> {
        if deserializer.is_human_readable() {
            let s = <String as serde::Deserialize>::deserialize(deserializer)?;
            let bytes = hex::decode(&s).map_err(serde::de::Error::custom)?;
            if bytes.len() != 32 {
                return Err(serde::de::Error::custom("invalid point length"));
            }
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&bytes);
            PublicPoint::from_bytes(arr)
                .ok_or_else(|| serde::de::Error::custom("invalid curve point"))
        } else {
            let bytes = <[u8; 32] as Deserialize>::deserialize(deserializer)?;
            PublicPoint::from_bytes(bytes)
                .ok_or_else(|| serde::de::Error::custom("invalid curve point"))
        }
    }
}

impl BorshSerialize for PublicPoint {
    fn serialize<W: std::io::Write>(&self, writer: &mut W) -> std::io::Result<()> {
        writer.write_all(&self.to_bytes())
    }
}

impl BorshDeserialize for PublicPoint {
    fn deserialize_reader<R: std::io::Read>(reader: &mut R) -> std::io::Result<Self> {
        let mut bytes = [0u8; 32];
        reader.read_exact(&mut bytes)?;
        PublicPoint::from_bytes(bytes)
            .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::InvalidData, "invalid curve point"))
    }
}

impl std::hash::Hash for PublicPoint {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.to_bytes().hash(state);
    }
}

/// Pedersen commitment: C = v*H + r*G (Monero convention)
///
/// - Value generator: H = generator_h() (SHA3-512 hash of compressed basepoint)
/// - Blinding generator: G = generator() (Ristretto basepoint)
///
/// This convention is required by CLSAG ring signatures: the blinding factor
/// must be on the same generator as public keys (G), so that the aggregate
/// key trick `W = mu_p*P + mu_c*(C-C')` works correctly.
///
/// The bulletproofs module uses custom PedersenGens with swapped generators
/// to match this convention, ensuring byte-compatible commitments.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Commitment(PublicPoint);

impl Commitment {
    /// Create a Pedersen commitment to a value: C = v*H + r*G
    pub fn commit(value: u64, blinding: &SecretScalar) -> Self {
        let v = Scalar::from(value);
        let point = v * generator_h() + blinding.as_scalar() * generator();
        Commitment(PublicPoint(point))
    }

    /// Create from a public point
    pub fn from_point(point: PublicPoint) -> Self {
        Commitment(point)
    }

    /// Get the underlying point
    pub fn as_point(&self) -> &PublicPoint {
        &self.0
    }

    /// Convert to bytes
    pub fn to_bytes(&self) -> [u8; 32] {
        self.0.to_bytes()
    }

    /// Create from bytes
    pub fn from_bytes(bytes: [u8; 32]) -> Option<Self> {
        PublicPoint::from_bytes(bytes).map(Commitment)
    }

    /// Add two commitments
    pub fn add(&self, other: &Commitment) -> Commitment {
        Commitment(self.0.add(&other.0))
    }

    /// Subtract two commitments
    pub fn sub(&self, other: &Commitment) -> Commitment {
        Commitment(self.0.sub(&other.0))
    }
}

impl fmt::Debug for Commitment {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Commitment({})", hex::encode(&self.to_bytes()[..8]))
    }
}

impl Serialize for Commitment {
    fn serialize<S: Serializer>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error> {
        <PublicPoint as serde::Serialize>::serialize(&self.0, serializer)
    }
}

impl<'de> Deserialize<'de> for Commitment {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> std::result::Result<Self, D::Error> {
        <PublicPoint as serde::Deserialize>::deserialize(deserializer).map(Commitment)
    }
}

impl BorshSerialize for Commitment {
    fn serialize<W: std::io::Write>(&self, writer: &mut W) -> std::io::Result<()> {
        <PublicPoint as BorshSerialize>::serialize(&self.0, writer)
    }
}

impl BorshDeserialize for Commitment {
    fn deserialize_reader<R: std::io::Read>(reader: &mut R) -> std::io::Result<Self> {
        PublicPoint::deserialize_reader(reader).map(Commitment)
    }
}

/// Key image for preventing double spends: I = x * Hp(P)
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct KeyImage(PublicPoint);

impl KeyImage {
    /// Compute key image from secret key
    /// I = x * Hp(P) where P = x*G
    pub fn from_secret(secret: &SecretScalar) -> Self {
        let public = secret.to_public();
        let hp = hash_to_point(&public.to_bytes());
        KeyImage(PublicPoint(secret.as_scalar() * hp))
    }

    /// Create from bytes
    pub fn from_bytes(bytes: [u8; 32]) -> Option<Self> {
        PublicPoint::from_bytes(bytes).map(KeyImage)
    }

    /// Convert to bytes
    pub fn to_bytes(&self) -> [u8; 32] {
        self.0.to_bytes()
    }

    /// Get the underlying point
    pub fn as_point(&self) -> &PublicPoint {
        &self.0
    }
}

impl fmt::Debug for KeyImage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "KeyImage({})", hex::encode(&self.to_bytes()[..8]))
    }
}

impl fmt::Display for KeyImage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", hex::encode(self.to_bytes()))
    }
}

impl Serialize for KeyImage {
    fn serialize<S: Serializer>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error> {
        <PublicPoint as serde::Serialize>::serialize(&self.0, serializer)
    }
}

impl<'de> Deserialize<'de> for KeyImage {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> std::result::Result<Self, D::Error> {
        <PublicPoint as serde::Deserialize>::deserialize(deserializer).map(KeyImage)
    }
}

impl BorshSerialize for KeyImage {
    fn serialize<W: std::io::Write>(&self, writer: &mut W) -> std::io::Result<()> {
        <PublicPoint as BorshSerialize>::serialize(&self.0, writer)
    }
}

impl BorshDeserialize for KeyImage {
    fn deserialize_reader<R: std::io::Read>(reader: &mut R) -> std::io::Result<Self> {
        PublicPoint::deserialize_reader(reader).map(KeyImage)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::OsRng;

    #[test]
    fn test_secret_to_public() {
        let secret = SecretScalar::random(&mut OsRng);
        let public = secret.to_public();
        assert!(!public.is_identity());
    }

    #[test]
    fn test_point_serialization() {
        let secret = SecretScalar::random(&mut OsRng);
        let public = secret.to_public();

        let bytes = public.to_bytes();
        let recovered = PublicPoint::from_bytes(bytes).unwrap();
        assert_eq!(public, recovered);
    }

    #[test]
    fn test_commitment() {
        let value = 1000u64;
        let blinding = SecretScalar::random(&mut OsRng);
        let commitment = Commitment::commit(value, &blinding);

        // Same value and blinding should give same commitment
        let commitment2 = Commitment::commit(value, &blinding);
        assert_eq!(commitment, commitment2);

        // Different blinding should give different commitment
        let blinding2 = SecretScalar::random(&mut OsRng);
        let commitment3 = Commitment::commit(value, &blinding2);
        assert_ne!(commitment, commitment3);
    }

    #[test]
    fn test_commitment_homomorphic() {
        let v1 = 100u64;
        let v2 = 200u64;
        let b1 = SecretScalar::random(&mut OsRng);
        let b2 = SecretScalar::random(&mut OsRng);

        let c1 = Commitment::commit(v1, &b1);
        let c2 = Commitment::commit(v2, &b2);
        let c_sum = c1.add(&c2);

        // C1 + C2 should equal commit(v1+v2, b1+b2)
        let b_sum = b1.add(&b2);
        let c_expected = Commitment::commit(v1 + v2, &b_sum);
        assert_eq!(c_sum, c_expected);
    }

    #[test]
    fn test_key_image() {
        let secret = SecretScalar::random(&mut OsRng);
        let ki1 = KeyImage::from_secret(&secret);
        let ki2 = KeyImage::from_secret(&secret);

        // Same secret should give same key image
        assert_eq!(ki1, ki2);

        // Different secret should give different key image
        let secret2 = SecretScalar::random(&mut OsRng);
        let ki3 = KeyImage::from_secret(&secret2);
        assert_ne!(ki1, ki3);
    }

    #[test]
    fn test_child_derivation() {
        let parent = SecretScalar::random(&mut OsRng);
        let child1 = parent.derive_child(b"test", 0);
        let child2 = parent.derive_child(b"test", 1);
        let child3 = parent.derive_child(b"test", 0);

        // Same derivation should give same result
        assert_eq!(child1.to_bytes(), child3.to_bytes());

        // Different index should give different result
        assert_ne!(child1.to_bytes(), child2.to_bytes());
    }

    #[test]
    fn test_identity_point_operations() {
        let identity = PublicPoint::identity();
        assert!(identity.is_identity());

        // identity + P = P
        let secret = SecretScalar::random(&mut OsRng);
        let p = secret.to_public();
        let sum = identity.add(&p);
        assert_eq!(sum, p);

        // P - P = identity
        let diff = p.sub(&p);
        assert!(diff.is_identity());

        // identity serialization roundtrip
        let bytes = identity.to_bytes();
        let recovered = PublicPoint::from_bytes(bytes).unwrap();
        assert!(recovered.is_identity());
    }
}
