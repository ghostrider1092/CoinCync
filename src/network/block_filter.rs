//! # Compact Block Filters (BIP158-inspired for CoinCync)
//!
//! Enables personal (Tier 1) nodes to determine which blocks contain outputs
//! relevant to them WITHOUT downloading full blocks. Based on Bitcoin's BIP158
//! Golomb-coded set (GCS) filters, adapted for CoinCync's privacy model.
//!
//! ## How It Works
//!
//! 1. Network/Archive nodes build a small filter (~100-200 bytes) for each block
//! 2. The filter encodes all stealth address public keys in the block
//! 3. Personal nodes download filters and test their own addresses against them
//! 4. If a filter matches, the personal node downloads the full block digest
//! 5. False positive rate ~1/2^P ≈ 1/524288 (negligible bandwidth waste)
//!
//! ## Privacy
//!
//! Filters are the same for all personal nodes — no per-client leakage.
//! A network node cannot tell which addresses a personal node is interested in.
//! The personal node downloads the same filter chain as everyone else.
//!
//! ## References
//! - Bitcoin BIP 158: Compact Block Filters
//! - `bitcoin-master/src/blockfilter.{h,cpp}` — GCS implementation

use crate::primitives::{Hash, hash_domain};
use crate::consensus::Block;
use serde::{Serialize, Deserialize};
use borsh::{BorshSerialize, BorshDeserialize};

/// Golomb-Rice coding parameter P.
/// Higher P = smaller filter but more CPU to decode.
/// Bitcoin uses P=19; we use P=19 for same false positive rate ~1/524288.
const GCS_P: u8 = 19;

/// Inverse false positive rate M = 2^P.
const GCS_M: u64 = 1 << GCS_P;

/// SipHash key derivation domain for filter hashing.
#[allow(dead_code)] // Reserved for filter key derivation when GCS upgrades to keyed SipHash
const FILTER_HASH_DOMAIN: &[u8] = b"CYNC_BLOCK_FILTER";

// =============================================================================
// BLOCK FILTER
// =============================================================================

/// A compact block filter that encodes all stealth addresses in a block.
///
/// Size: ~100-200 bytes for a typical block with 20-50 outputs.
/// Compare to full block: 50-200 KB.
#[derive(Clone, Debug, Serialize, Deserialize, BorshSerialize, BorshDeserialize)]
pub struct BlockFilter {
    /// Block hash this filter covers.
    pub block_hash: Hash,
    /// Block height.
    pub height: u64,
    /// Number of elements encoded in the filter.
    pub n_elements: u32,
    /// Golomb-coded set data (compressed).
    pub filter_data: Vec<u8>,
    /// Hash of the previous block's filter (chain integrity).
    pub prev_filter_hash: Hash,
}

impl BlockFilter {
    /// Build a block filter from a block's outputs.
    ///
    /// Encodes all output stealth addresses into a GCS filter.
    /// Network nodes call this when they process a new block.
    pub fn from_block(block: &Block, prev_filter_hash: Hash) -> Self {
        let block_hash = block.hash();

        // Collect all output stealth addresses (the element set)
        let mut elements: Vec<[u8; 32]> = Vec::new();
        for tx in &block.transactions {
            for output in &tx.outputs {
                elements.push(*output.stealth_address.as_bytes());
            }
        }

        // Derive SipHash keys from block hash (deterministic per block)
        let sip_key = derive_sip_key(&block_hash);

        // Build GCS filter
        let filter_data = gcs_encode(&elements, sip_key, GCS_P);

        BlockFilter {
            block_hash,
            height: block.height(),
            n_elements: elements.len() as u32,
            filter_data,
            prev_filter_hash,
        }
    }

    /// Test whether any of the given public keys might be in this block.
    ///
    /// Returns true if ANY key matches (with false positive rate ~1/2^P).
    /// Personal nodes call this with their own stealth address set.
    pub fn match_any(&self, addresses: &[[u8; 32]]) -> bool {
        if self.n_elements == 0 || addresses.is_empty() {
            return false;
        }

        let sip_key = derive_sip_key(&self.block_hash);
        gcs_match_any(&self.filter_data, self.n_elements, addresses, sip_key, GCS_P)
    }

    /// Compute this filter's hash (for chaining).
    pub fn filter_hash(&self) -> Hash {
        hash_domain(b"BLOCK_FILTER_HASH", &self.filter_data)
    }

    /// Estimated size in bytes.
    pub fn estimated_size(&self) -> usize {
        32 + 8 + 4 + self.filter_data.len() + 32
    }
}

// =============================================================================
// FILTER CHAIN — for verifying filter integrity
// =============================================================================

/// A checkpoint in the filter chain, used for fast verification.
#[derive(Clone, Debug, Serialize, Deserialize, BorshSerialize, BorshDeserialize)]
pub struct FilterCheckpoint {
    pub height: u64,
    pub block_hash: Hash,
    pub filter_hash: Hash,
}

// =============================================================================
// GCS ENCODING / DECODING (Golomb-coded sets)
// =============================================================================

/// Derive SipHash key from block hash for deterministic hashing.
fn derive_sip_key(block_hash: &Hash) -> (u64, u64) {
    let bytes = block_hash.as_bytes();
    // SAFETY: Hash is always 32 bytes; [0..8] and [8..16] are always valid 8-byte slices
    let k0 = u64::from_le_bytes(bytes[0..8].try_into().expect("hash is 32 bytes"));
    let k1 = u64::from_le_bytes(bytes[8..16].try_into().expect("hash is 32 bytes"));
    (k0, k1)
}

/// Hash an element into the filter's range [0, N*M) using SipHash.
fn hash_element(element: &[u8; 32], sip_key: (u64, u64), n: u32) -> u64 {
    // Use blake3 keyed hash for deterministic element hashing
    let mut key_bytes = [0u8; 32];
    key_bytes[0..8].copy_from_slice(&sip_key.0.to_le_bytes());
    key_bytes[8..16].copy_from_slice(&sip_key.1.to_le_bytes());
    let hash_bytes = blake3::keyed_hash(&key_bytes, element);
    // SAFETY: blake3 output is always 32 bytes; [0..8] is a valid 8-byte slice
    let hash = u64::from_le_bytes(hash_bytes.as_bytes()[0..8].try_into().expect("blake3 is 32 bytes"));

    // Map into range [0, F) where F = N * M
    let f = n as u64 * GCS_M;
    // Fast range reduction: (hash * F) >> 64
    ((hash as u128 * f as u128) >> 64) as u64
}

/// Encode a set of elements into a Golomb-coded set.
///
/// 1. Hash each element into [0, N*M)
/// 2. Sort the hashed values
/// 3. Compute deltas between consecutive values
/// 4. Golomb-Rice encode each delta with parameter P
fn gcs_encode(elements: &[[u8; 32]], sip_key: (u64, u64), p: u8) -> Vec<u8> {
    if elements.is_empty() {
        return Vec::new();
    }

    let n = elements.len() as u32;

    // Step 1-2: Hash and sort
    let mut hashed: Vec<u64> = elements.iter()
        .map(|e| hash_element(e, sip_key, n))
        .collect();
    hashed.sort_unstable();
    hashed.dedup();

    // Step 3-4: Delta-encode with Golomb-Rice
    let mut writer = BitWriter::new();
    let mut prev = 0u64;

    for &val in &hashed {
        let delta = val - prev;
        prev = val;
        golomb_rice_encode(&mut writer, delta, p);
    }

    writer.finish()
}

/// Test if any of the given addresses match the filter.
fn gcs_match_any(
    filter_data: &[u8],
    n_elements: u32,
    addresses: &[[u8; 32]],
    sip_key: (u64, u64),
    p: u8,
) -> bool {
    if filter_data.is_empty() || n_elements == 0 {
        return false;
    }

    // Hash the query addresses and sort them
    let mut query_hashes: Vec<u64> = addresses.iter()
        .map(|a| hash_element(a, sip_key, n_elements))
        .collect();
    query_hashes.sort_unstable();
    query_hashes.dedup();

    // Decode the filter and check for intersection (merge-join style)
    let mut reader = BitReader::new(filter_data);
    let mut filter_val = 0u64;
    let mut query_idx = 0;
    let mut decoded = 0u32;

    while query_idx < query_hashes.len() && decoded < n_elements {
        let delta = match golomb_rice_decode(&mut reader, p) {
            Some(d) => d,
            None => break,
        };
        filter_val += delta;
        decoded += 1;

        // Advance query pointer past values smaller than current filter value
        while query_idx < query_hashes.len() && query_hashes[query_idx] < filter_val {
            query_idx += 1;
        }

        // Check for match
        if query_idx < query_hashes.len() && query_hashes[query_idx] == filter_val {
            return true;
        }
    }

    false
}

// =============================================================================
// GOLOMB-RICE CODING
// =============================================================================

/// Encode a value using Golomb-Rice coding with parameter P.
/// Quotient encoded in unary (q ones + zero), remainder in P bits.
fn golomb_rice_encode(writer: &mut BitWriter, value: u64, p: u8) {
    let m = 1u64 << p;
    let q = value / m;
    let r = value % m;

    // Unary: q ones followed by a zero
    for _ in 0..q.min(64) {
        writer.write_bit(1);
    }
    writer.write_bit(0);

    // Remainder: P bits
    writer.write_bits(r, p);
}

/// Decode a Golomb-Rice coded value.
fn golomb_rice_decode(reader: &mut BitReader<'_>, p: u8) -> Option<u64> {
    // Count ones (unary quotient)
    let mut q = 0u64;
    loop {
        match reader.read_bit() {
            Some(1) => q += 1,
            Some(0) => break,
            _ => return None,
        }
        if q > 64 {
            return None; // Sanity limit
        }
    }

    // Read P-bit remainder
    let r = reader.read_bits(p)?;

    Some(q * (1u64 << p) + r)
}

// =============================================================================
// BIT-LEVEL I/O
// =============================================================================

struct BitWriter {
    data: Vec<u8>,
    current_byte: u8,
    bits_written: u8,
}

impl BitWriter {
    fn new() -> Self {
        BitWriter {
            data: Vec::new(),
            current_byte: 0,
            bits_written: 0,
        }
    }

    fn write_bit(&mut self, bit: u8) {
        self.current_byte = (self.current_byte << 1) | (bit & 1);
        self.bits_written += 1;
        if self.bits_written == 8 {
            self.data.push(self.current_byte);
            self.current_byte = 0;
            self.bits_written = 0;
        }
    }

    fn write_bits(&mut self, value: u64, count: u8) {
        for i in (0..count).rev() {
            self.write_bit(((value >> i) & 1) as u8);
        }
    }

    fn finish(mut self) -> Vec<u8> {
        if self.bits_written > 0 {
            // Pad remaining bits with zeros
            self.current_byte <<= 8 - self.bits_written;
            self.data.push(self.current_byte);
        }
        self.data
    }
}

struct BitReader<'a> {
    data: &'a [u8],
    byte_pos: usize,
    bit_pos: u8,
}

impl<'a> BitReader<'a> {
    fn new(data: &'a [u8]) -> Self {
        BitReader {
            data,
            byte_pos: 0,
            bit_pos: 0,
        }
    }

    fn read_bit(&mut self) -> Option<u8> {
        if self.byte_pos >= self.data.len() {
            return None;
        }
        let bit = (self.data[self.byte_pos] >> (7 - self.bit_pos)) & 1;
        self.bit_pos += 1;
        if self.bit_pos == 8 {
            self.bit_pos = 0;
            self.byte_pos += 1;
        }
        Some(bit)
    }

    fn read_bits(&mut self, count: u8) -> Option<u64> {
        let mut value = 0u64;
        for _ in 0..count {
            let bit = self.read_bit()?;
            value = (value << 1) | bit as u64;
        }
        Some(value)
    }
}

// =============================================================================
// TESTS
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_golomb_rice_roundtrip() {
        // Encode and decode various values
        for &value in &[0, 1, 5, 100, 1000, 65535, 1_000_000] {
            let mut writer = BitWriter::new();
            golomb_rice_encode(&mut writer, value, GCS_P);
            let data = writer.finish();

            let mut reader = BitReader::new(&data);
            let decoded = golomb_rice_decode(&mut reader, GCS_P).unwrap();
            assert_eq!(value, decoded, "Golomb-Rice roundtrip failed for {}", value);
        }
    }

    #[test]
    fn test_gcs_encode_decode_match() {
        let sip_key = (0x0706050403020100u64, 0x0f0e0d0c0b0a0908u64);

        // Create some test elements
        let elements: Vec<[u8; 32]> = (0..20u8)
            .map(|i| {
                let mut e = [0u8; 32];
                e[0] = i;
                e
            })
            .collect();

        // Encode
        let filter = gcs_encode(&elements, sip_key, GCS_P);
        assert!(!filter.is_empty());

        // Match: element that IS in the set should match
        let query = vec![elements[5]];
        assert!(
            gcs_match_any(&filter, elements.len() as u32, &query, sip_key, GCS_P),
            "Element in set should match"
        );

        // No-match: random element should NOT match (with high probability)
        let mut random_elem = [0xFFu8; 32];
        random_elem[0] = 0xAB;
        let query_miss = vec![random_elem];
        // With P=19, false positive rate is ~1/524288, so this should almost never match
        // (but it's probabilistic, so we don't assert — just verify the function runs)
        let _ = gcs_match_any(&filter, elements.len() as u32, &query_miss, sip_key, GCS_P);
    }

    #[test]
    fn test_empty_filter() {
        let sip_key = (1u64, 2u64);
        let empty: Vec<[u8; 32]> = Vec::new();
        let filter = gcs_encode(&empty, sip_key, GCS_P);
        assert!(filter.is_empty());

        let query = vec![[1u8; 32]];
        assert!(!gcs_match_any(&filter, 0, &query, sip_key, GCS_P));
    }

    #[test]
    fn test_bit_writer_reader_roundtrip() {
        let mut writer = BitWriter::new();
        writer.write_bits(0b1010_1100, 8);
        writer.write_bits(0b110, 3);
        let data = writer.finish();

        let mut reader = BitReader::new(&data);
        assert_eq!(reader.read_bits(8), Some(0b1010_1100));
        assert_eq!(reader.read_bits(3), Some(0b110));
    }
}
