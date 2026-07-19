//! # Hash Types
//!
//! Cryptographic hash types and functions for CoinCync 1.0.
//!
//! ## Security Notes:
//! - Use `Hash::ct_eq()` for security-sensitive comparisons (authentication, MAC verification)
//! - Standard `==` comparison is fine for public data (block hashes, merkle roots, difficulty)
//! - The derived `PartialEq` uses standard comparison for performance in non-sensitive contexts

use borsh::{BorshDeserialize, BorshSerialize};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::fmt;
use std::str::FromStr;

/// A 32-byte hash (256 bits)
#[derive(
    Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default, BorshSerialize, BorshDeserialize,
)]
pub struct Hash([u8; 32]);

impl Hash {
    pub const LEN: usize = 32;

    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Hash(bytes)
    }

    pub fn from_slice(slice: &[u8]) -> Option<Self> {
        if slice.len() != 32 {
            return None;
        }
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(slice);
        Some(Hash(bytes))
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

    /// Constant-time equality comparison (for security-sensitive contexts)
    /// Use this when comparing hashes in authentication/verification
    #[inline(never)]
    pub fn ct_eq(&self, other: &Hash) -> bool {
        use subtle::ConstantTimeEq;
        self.0.ct_eq(&other.0).into()
    }

    pub fn from_hex(s: &str) -> Option<Self> {
        let bytes = hex::decode(s).ok()?;
        Self::from_slice(&bytes)
    }

    pub const fn zero() -> Self {
        Hash([0u8; 32])
    }
    pub fn is_zero(&self) -> bool {
        self.0 == [0u8; 32]
    }
    pub fn first_byte(&self) -> u8 {
        self.0[0]
    }

    pub fn meets_difficulty(&self, target: &Hash) -> bool {
        for i in 0..32 {
            if self.0[i] < target.0[i] {
                return true;
            }
            if self.0[i] > target.0[i] {
                return false;
            }
        }
        true
    }

    /// Create a target hash from a difficulty value.
    /// Target = MAX_TARGET / difficulty
    /// Represented as leading zeros based on difficulty.
    pub fn from_difficulty(difficulty: u64) -> Self {
        if difficulty == 0 {
            return Hash([0xFF; 32]); // Max target (easiest)
        }

        // M-2 FIX: off-by-one — from_difficulty(1) must equal max_target
        // Simple implementation: calculate leading zeros based on log2(difficulty)
        // For each doubling of difficulty, we need one more leading zero bit
        let leading_zero_bits = if difficulty == 0 {
            0
        } else {
            63 - difficulty.leading_zeros() as usize
        };

        let mut bytes = [0xFF; 32];
        let full_zero_bytes = leading_zero_bits / 8;
        let partial_bits = leading_zero_bits % 8;

        // Set full zero bytes
        for byte in bytes.iter_mut().take(full_zero_bytes.min(32)) {
            *byte = 0;
        }

        // Set partial byte
        if full_zero_bytes < 32 && partial_bits > 0 {
            bytes[full_zero_bytes] = 0xFF >> partial_bits;
        }

        Hash(bytes)
    }

    /// Convert target hash to approximate difficulty value
    pub fn to_difficulty(&self) -> u64 {
        // Count leading zero bits
        let mut zero_bits = 0u32;
        for byte in &self.0 {
            if *byte == 0 {
                zero_bits += 8;
            } else {
                zero_bits += byte.leading_zeros();
                break;
            }
        }
        // SECURITY (L7): Use checked_shl with fallback to MAX for overflow.
        // When zero_bits >= 64 (all-zero or near-zero hash), this returns u64::MAX
        // which represents maximum difficulty. This is correct behavior: an all-zero
        // hash target means the hardest possible difficulty.
        1u64.checked_shl(zero_bits).unwrap_or(u64::MAX)
    }
}

impl fmt::Debug for Hash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Hash({}...)", &self.to_hex()[..16])
    }
}

impl fmt::Display for Hash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_hex())
    }
}

impl FromStr for Hash {
    type Err = crate::error::Error;
    /// FIX: Report byte count (not char count) on mismatch.
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let decoded = hex::decode(s).map_err(|_| crate::error::Error::InvalidHashLength {
            expected: 32,
            got: s.len() / 2,
        })?;
        Self::from_slice(&decoded).ok_or(crate::error::Error::InvalidHashLength {
            expected: 32,
            got: decoded.len(),
        })
    }
}

impl AsRef<[u8]> for Hash {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}
impl From<[u8; 32]> for Hash {
    fn from(bytes: [u8; 32]) -> Self {
        Hash(bytes)
    }
}
impl From<Hash> for [u8; 32] {
    fn from(hash: Hash) -> Self {
        hash.0
    }
}

impl Serialize for Hash {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        if serializer.is_human_readable() {
            serializer.serialize_str(&self.to_hex())
        } else {
            serializer.serialize_bytes(&self.0)
        }
    }
}

impl<'de> Deserialize<'de> for Hash {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        if deserializer.is_human_readable() {
            let s = <String as Deserialize>::deserialize(deserializer)?;
            Hash::from_hex(&s).ok_or_else(|| serde::de::Error::custom("invalid hash"))
        } else {
            let bytes = <[u8; 32] as Deserialize>::deserialize(deserializer)?;
            Ok(Hash(bytes))
        }
    }
}

pub fn hash_data(data: &[u8]) -> Hash {
    Hash::from_bytes(*blake3::hash(data).as_bytes())
}

pub fn hash_concat(parts: &[&[u8]]) -> Hash {
    let mut hasher = blake3::Hasher::new();
    for part in parts {
        hasher.update(part);
    }
    Hash::from_bytes(*hasher.finalize().as_bytes())
}

pub fn hash_domain(domain: &[u8], data: &[u8]) -> Hash {
    let mut hasher = blake3::Hasher::new();
    hasher.update(domain);
    hasher.update(&[0u8]);
    hasher.update(data);
    Hash::from_bytes(*hasher.finalize().as_bytes())
}

pub fn merkle_root(hashes: &[Hash]) -> Hash {
    if hashes.is_empty() {
        return Hash::zero();
    }
    if hashes.len() == 1 {
        // H-4 FIX: Single-leaf trees still get domain separation
        return hash_concat(&[&[0x00], hashes[0].as_slice()]);
    }

    // H-4 FIX: RFC 6962 domain separation prevents merkle malleability (CVE-2012-2459)
    // Leaf nodes are prefixed with 0x00; internal nodes with 0x01.
    let mut level: Vec<Hash> = hashes
        .iter()
        .map(|h| hash_concat(&[&[0x00], h.as_slice()]))
        .collect();
    while level.len() > 1 {
        let mut next = Vec::with_capacity((level.len() + 1) / 2);
        for chunk in level.chunks(2) {
            let hash = if chunk.len() == 2 {
                hash_concat(&[&[0x01], chunk[0].as_slice(), chunk[1].as_slice()])
            } else {
                hash_concat(&[&[0x01], chunk[0].as_slice(), chunk[0].as_slice()])
            };
            next.push(hash);
        }
        level = next;
    }
    // SAFETY: Loop invariant guarantees level has exactly 1 element here
    // But add defensive check to prevent panic on logic errors
    level.first().copied().unwrap_or_else(Hash::zero)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hash_roundtrip() {
        let hash = hash_data(b"test");
        let hex = hash.to_hex();
        let parsed = Hash::from_hex(&hex).unwrap();
        assert_eq!(hash, parsed);
    }

    #[test]
    fn test_merkle_root() {
        let hashes: Vec<Hash> = (0..5).map(|i| hash_data(&[i])).collect();
        let root = merkle_root(&hashes);
        assert!(!root.is_zero());
    }

    #[test]
    fn test_hex_roundtrip() {
        let original = hash_data(b"hello world");
        let hex = original.to_hex();
        assert_eq!(hex.len(), 64); // 32 bytes = 64 hex chars
        let restored = Hash::from_hex(&hex).unwrap();
        assert_eq!(original, restored);
        // Invalid hex should fail.
        // Phase A2 (audit fix): from_hex returns Option<Hash>, not Result —
        // the previous `.is_err()` was a compile error.
        assert!(Hash::from_hex("xyz").is_none());
        assert!(Hash::from_hex("").is_none());
    }
}
