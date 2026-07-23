//! # Key Types for CoinCync 1.0
//!
//! ## Security Notes:
//! - `SecretKey` is securely zeroized on drop using the `zeroize` crate
//! - `derive_child()` uses simple BLAKE3-based derivation (NOT BIP32 hardened)
//!   - Does not provide key separation guarantees of HD wallets
//!   - Parent key compromise reveals all child keys
//!   - For HD wallet functionality, use the `mnemonic` module instead
//! - `public_key()` uses proper EC multiplication: P = s * G (Ristretto)
//! - For advanced EC operations, use the `crypto::curve` module
//! - For real transaction signatures, use CLSAG in `crypto::clsag` module

use crate::error::{Error, Result};
use borsh::{BorshDeserialize, BorshSerialize};
use curve25519_dalek::{constants::RISTRETTO_BASEPOINT_POINT, scalar::Scalar};
use rand::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};
use std::fmt;
use zeroize::Zeroize;

/// A 32-byte public key
#[derive(Clone, Copy, PartialEq, Eq, Hash, BorshSerialize, BorshDeserialize)]
pub struct PublicKey([u8; 32]);

impl PublicKey {
    pub const LEN: usize = 32;
    // H-3 FIX: Restrict unchecked constructors to crate-internal use only.
    // External callers must use from_bytes_checked() which validates the curve point.
    /// Unchecked constructor. Use `from_bytes_checked()` for untrusted input.
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        PublicKey(bytes)
    }
    pub(crate) fn from_slice(slice: &[u8]) -> Result<Self> {
        if slice.len() != 32 {
            return Err(Error::InvalidPublicKey("wrong length".into()));
        }
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(slice);
        Ok(PublicKey(bytes))
    }
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
    pub fn as_slice(&self) -> &[u8] {
        &self.0
    }
    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }
    pub fn from_hex(s: &str) -> Result<Self> {
        let bytes = hex::decode(s).map_err(|e| Error::InvalidPublicKey(e.to_string()))?;
        Self::from_slice(&bytes)
    }

    /// Construct from bytes with Ristretto curve point validation.
    ///
    /// SECURITY (CR-003 + Phase A7-7): Verifies the bytes decompress to a
    /// valid NON-IDENTITY Ristretto point.
    ///
    /// The identity check is critical: in Ristretto255 the all-zeros byte
    /// string `[0; 32]` IS a valid encoding of the identity element. Without
    /// the explicit identity rejection, any caller using `from_bytes_checked`
    /// for untrusted input (network, RPC, deserialization) will accept the
    /// identity point as a valid public key. This enables:
    ///
    ///   - Linkable signatures (CLSAG with an identity ring member is
    ///     trivially distinguishable)
    ///   - Stealth-address attacks (ECDH with identity = always 0; the
    ///     "shared secret" is publicly computable)
    ///   - Pedersen commitment forgery (commitment to identity factors
    ///     out of the balance equation)
    ///
    /// Use this for untrusted input only. `from_bytes()` remains unchecked
    /// for internal/genesis use where the source is the codebase itself.
    pub fn from_bytes_checked(bytes: [u8; 32]) -> Result<Self> {
        use curve25519_dalek::ristretto::CompressedRistretto;
        let point = CompressedRistretto(bytes)
            .decompress()
            .ok_or_else(|| Error::InvalidPublicKey("not a valid Ristretto point".into()))?;
        // Reject the identity element. Even though Ristretto's identity is
        // a "valid" curve point, accepting it as a public key breaks every
        // protocol layer above this one.
        if point == curve25519_dalek::ristretto::RistrettoPoint::default() {
            return Err(Error::InvalidPublicKey(
                "identity point not allowed as public key".into(),
            ));
        }
        Ok(PublicKey(bytes))
    }

    /// Validate that these bytes represent a valid non-identity Ristretto
    /// curve point.
    ///
    /// Phase A7-7 (audit fix): now also rejects the identity element, for
    /// the same reasons documented in `from_bytes_checked`.
    pub fn validate(&self) -> Result<()> {
        use curve25519_dalek::ristretto::CompressedRistretto;
        let point = CompressedRistretto(self.0)
            .decompress()
            .ok_or_else(|| Error::InvalidPublicKey("not a valid Ristretto point".into()))?;
        if point == curve25519_dalek::ristretto::RistrettoPoint::default() {
            return Err(Error::InvalidPublicKey(
                "identity point not allowed as public key".into(),
            ));
        }
        Ok(())
    }
}

impl fmt::Debug for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "PublicKey({}...)", &self.to_hex()[..8])
    }
}
impl fmt::Display for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_hex())
    }
}
impl AsRef<[u8]> for PublicKey {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}
impl From<[u8; 32]> for PublicKey {
    fn from(bytes: [u8; 32]) -> Self {
        PublicKey(bytes)
    }
}

impl Serialize for PublicKey {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        if serializer.is_human_readable() {
            serializer.serialize_str(&self.to_hex())
        } else {
            serializer.serialize_bytes(&self.0)
        }
    }
}
impl<'de> Deserialize<'de> for PublicKey {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        if deserializer.is_human_readable() {
            let s = <String as Deserialize>::deserialize(deserializer)?;
            PublicKey::from_hex(&s).map_err(serde::de::Error::custom)
        } else {
            let bytes = <[u8; 32] as Deserialize>::deserialize(deserializer)?;
            Ok(PublicKey(bytes))
        }
    }
}

/// A 32-byte secret key (zeroized on drop)
#[derive(Eq, PartialEq, BorshSerialize, BorshDeserialize)]
pub struct SecretKey([u8; 32]);

impl SecretKey {
    pub const LEN: usize = 32;
    pub fn generate<R: RngCore + CryptoRng>(rng: &mut R) -> Self {
        let mut bytes = [0u8; 32];
        rng.fill_bytes(&mut bytes);
        SecretKey(bytes)
    }
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        SecretKey(bytes)
    }
    pub fn from_slice(slice: &[u8]) -> Result<Self> {
        if slice.len() != 32 {
            return Err(Error::InvalidSecretKey("wrong length".into()));
        }
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(slice);
        Ok(SecretKey(bytes))
    }
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
    /// Derive the public key using proper elliptic curve multiplication: P = s * G
    pub fn public_key(&self) -> PublicKey {
        let scalar = Scalar::from_bytes_mod_order(self.0);
        let point = &scalar * RISTRETTO_BASEPOINT_POINT;
        PublicKey::from_bytes(point.compress().to_bytes())
    }
    /// Derive a child key using BLAKE3 (simple hash-based derivation)
    ///
    /// SECURITY WARNING: This is NOT BIP32-style hardened derivation.
    /// - Parent key compromise reveals ALL child keys
    /// - No key separation guarantees
    /// - For HD wallet functionality, use `crate::wallet::mnemonic` module
    pub fn derive_child(&self, context: &[u8], index: u64) -> SecretKey {
        let mut hasher = blake3::Hasher::new();
        hasher.update(&self.0);
        hasher.update(context);
        hasher.update(&index.to_le_bytes());
        SecretKey::from_bytes(*hasher.finalize().as_bytes())
    }
}

impl Clone for SecretKey {
    fn clone(&self) -> Self {
        SecretKey(self.0)
    }
}
impl fmt::Debug for SecretKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SecretKey([REDACTED])")
    }
}
impl Drop for SecretKey {
    fn drop(&mut self) {
        // Use zeroize for secure memory clearing (prevents compiler optimization)
        self.0.zeroize();
    }
}

/// A key pair
pub struct KeyPair {
    pub secret: SecretKey,
    pub public: PublicKey,
}

impl KeyPair {
    pub fn generate<R: RngCore + CryptoRng>(rng: &mut R) -> Self {
        let secret = SecretKey::generate(rng);
        let public = secret.public_key();
        KeyPair { secret, public }
    }
    pub fn from_secret(secret: SecretKey) -> Self {
        let public = secret.public_key();
        KeyPair { secret, public }
    }
}

impl fmt::Debug for KeyPair {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("KeyPair")
            .field("public", &self.public)
            .finish()
    }
}

/// A 64-byte signature
#[derive(Clone, Copy, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct Signature([u8; 64]);

impl Signature {
    pub const LEN: usize = 64;
    pub fn from_bytes(bytes: [u8; 64]) -> Self {
        Signature(bytes)
    }
    pub fn from_slice(slice: &[u8]) -> Result<Self> {
        if slice.len() != 64 {
            return Err(Error::InvalidSignature("wrong length".into()));
        }
        let mut bytes = [0u8; 64];
        bytes.copy_from_slice(slice);
        Ok(Signature(bytes))
    }
    pub fn as_bytes(&self) -> &[u8; 64] {
        &self.0
    }
    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }
    pub fn from_hex(s: &str) -> Result<Self> {
        let bytes = hex::decode(s).map_err(|e| Error::InvalidSignature(e.to_string()))?;
        Self::from_slice(&bytes)
    }
}

impl Serialize for Signature {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        if serializer.is_human_readable() {
            serializer.serialize_str(&self.to_hex())
        } else {
            serializer.serialize_bytes(&self.0)
        }
    }
}

impl<'de> Deserialize<'de> for Signature {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        if deserializer.is_human_readable() {
            let s = <&str as Deserialize>::deserialize(deserializer)?;
            Signature::from_hex(s).map_err(serde::de::Error::custom)
        } else {
            struct ByteVisitor;
            impl<'de> serde::de::Visitor<'de> for ByteVisitor {
                type Value = Signature;
                fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                    write!(f, "64 bytes")
                }
                fn visit_bytes<E: serde::de::Error>(
                    self,
                    v: &[u8],
                ) -> std::result::Result<Self::Value, E> {
                    Signature::from_slice(v).map_err(E::custom)
                }
                fn visit_seq<A: serde::de::SeqAccess<'de>>(
                    self,
                    mut seq: A,
                ) -> std::result::Result<Self::Value, A::Error> {
                    let mut bytes = [0u8; 64];
                    for (i, b) in bytes.iter_mut().enumerate() {
                        *b = seq
                            .next_element()?
                            .ok_or_else(|| serde::de::Error::invalid_length(i, &self))?;
                    }
                    Ok(Signature(bytes))
                }
            }
            deserializer.deserialize_bytes(ByteVisitor)
        }
    }
}

impl fmt::Debug for Signature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Signature({}...)", &self.to_hex()[..16])
    }
}

/// A key image (prevents double-spending)
#[derive(
    Clone, Copy, PartialEq, Eq, Hash, BorshSerialize, BorshDeserialize, Serialize, Deserialize,
)]
pub struct KeyImage([u8; 32]);

impl KeyImage {
    pub const LEN: usize = 32;
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        KeyImage(bytes)
    }
    pub fn from_slice(slice: &[u8]) -> Result<Self> {
        if slice.len() != 32 {
            return Err(Error::InvalidSignature("wrong key image length".into()));
        }
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(slice);
        Ok(KeyImage(bytes))
    }
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }

    // DELETED (C10): blake3-based from_secret_key() removed entirely.
    // Was incompatible with CLSAG key image formula I = x * Hp(x*G).
    // All callers now use crypto::KeyImage::from_secret() instead.
}

impl fmt::Debug for KeyImage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "KeyImage({}...)", &self.to_hex()[..16])
    }
}
impl fmt::Display for KeyImage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_hex())
    }
}

// NOTE: Broken sign/verify stubs were removed. CoinCync uses CLSAG ring
// signatures for all transaction signing — see crypto::clsag::{clsag_sign, clsag_verify}.

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::OsRng;

    #[test]
    fn test_key_generation() {
        let kp = KeyPair::generate(&mut OsRng);
        assert_ne!(kp.secret.as_bytes(), &[0u8; 32]);
    }

    #[test]
    fn test_key_image_from_bytes_deterministic() {
        let bytes = [42u8; 32];
        let img1 = KeyImage::from_bytes(bytes);
        let img2 = KeyImage::from_bytes(bytes);
        assert_eq!(img1, img2);
    }

    #[test]
    fn test_checked_deserialization() {
        // All-zero bytes are not a valid Ristretto curve point
        assert!(PublicKey::from_bytes_checked([0u8; 32]).is_err());
        // Random garbage bytes should also fail
        assert!(PublicKey::from_bytes_checked([0xAB; 32]).is_err());
        // A valid key should succeed
        let kp = KeyPair::generate(&mut OsRng);
        assert!(PublicKey::from_bytes_checked(*kp.public.as_bytes()).is_ok());
    }
}
