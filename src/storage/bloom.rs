//! Bloom filter for fast UTXO existence checks.
//!
//! Standard bloom filter delegates to the `bloomfilter` crate.
//! Counting bloom filter remains hand-rolled (crate doesn't provide one).
//!
//! AUDIT (R-58 SURGICAL FIX, 2026-07-03): the `StableHasher` below is
//! FNV-1a, which has known collision-generation attacks
//! (Bar-Yosef 2015) that let an attacker craft inputs colliding into
//! the same bucket, degrading the filter to O(n) lookups. Prior
//! version used a FIXED FNV offset basis, so an attacker who knew
//! the constant could pre-compute a collision set OFFLINE, then
//! feed it in ONLINE to force worst-case FP rate.
//!
//! Fix: the offset basis is now a per-instance RANDOM u64 seeded
//! at filter construction from OsRng. Collision pre-computation is
//! keyed to a value the attacker can't observe or guess (2^64
//! keyspace, refreshed on every filter creation). This is the
//! classic "SipHash-key-per-instance" pattern applied to FNV.
//!
//! FNV-1a itself remains — the algorithm is fast, deterministic,
//! and adequate as a bucket selector once keyed. If a future
//! caller needs cryptographic collision resistance, migrate to
//! `blake3::keyed_hash` per-instance.

use std::hash::{Hash, Hasher};

/// Stable FNV-1a hasher with per-instance random seed.
///
/// R-58 fix: the initial state is now the caller-provided seed (a
/// random u64 generated at filter construction time). This blocks
/// offline collision-generation attacks against the filter — an
/// attacker who wants to force collisions must first observe or
/// guess the 64-bit seed for a specific filter instance.
struct StableHasher {
    state: u64,
}

impl StableHasher {
    fn with_seed(seed: u64) -> Self {
        StableHasher { state: seed }
    }
}

impl Hasher for StableHasher {
    fn finish(&self) -> u64 {
        self.state
    }

    fn write(&mut self, bytes: &[u8]) {
        const FNV_PRIME: u64 = 0x100000001b3;
        for &byte in bytes {
            self.state ^= byte as u64;
            self.state = self.state.wrapping_mul(FNV_PRIME);
        }
    }
}

/// Bloom filter with configurable size and hash count
///
/// Wraps `bloomfilter::Bloom` with the same public API as before.
pub struct BloomFilter {
    inner: bloomfilter::Bloom<[u8]>,
    /// Number of bits in the filter
    num_bits: usize,
    /// Number of hash functions
    num_hashes: u32,
    /// Number of items inserted
    count: usize,
    /// R-58: per-instance random seed for StableHasher. Blocks
    /// offline collision-generation attacks against the filter.
    hasher_seed: u64,
}

impl BloomFilter {
    /// Create a new bloom filter optimized for expected items and false positive rate
    pub fn new(expected_items: usize, false_positive_rate: f64) -> Self {
        use rand::RngCore;
        let expected_items = expected_items.max(1);
        // SECURITY: Clamp FP rate to at most 0.001 (0.1%)
        let fpr = false_positive_rate.clamp(0.0001, 0.001);

        let inner = bloomfilter::Bloom::new_for_fp_rate(expected_items, fpr);
        let num_bits = inner.number_of_bits() as usize;
        let num_hashes = inner.number_of_hash_functions() as u32;

        BloomFilter {
            inner,
            num_bits,
            num_hashes,
            count: 0,
            hasher_seed: rand::rngs::OsRng.next_u64(),
        }
    }

    /// Create with explicit parameters
    pub fn with_params(num_bits: usize, num_hashes: u32) -> Self {
        use rand::RngCore;
        let num_bits = num_bits.max(1024);
        let num_hashes = num_hashes.clamp(1, 16);

        // bloomfilter::Bloom::new takes (bitmap_size_bytes, items_count).
        // We approximate items_count from the desired bits and hash count.
        let bitmap_bytes = (num_bits + 7) / 8;
        let estimated_items = (num_bits as f64 / num_hashes as f64 * std::f64::consts::LN_2) as usize;
        let estimated_items = estimated_items.max(1);
        let inner = bloomfilter::Bloom::new(bitmap_bytes, estimated_items);

        BloomFilter {
            inner,
            num_bits,
            num_hashes,
            count: 0,
            hasher_seed: rand::rngs::OsRng.next_u64(),
        }
    }

    /// Insert an item into the filter
    pub fn insert<T: Hash>(&mut self, item: &T) {
        // Hash item to bytes for the bloomfilter crate's [u8] key type
        let mut hasher = StableHasher::with_seed(self.hasher_seed);
        item.hash(&mut hasher);
        let bytes = hasher.finish().to_le_bytes();
        self.inner.set(&bytes);
        self.count += 1;
    }

    /// Check if an item may be in the filter
    pub fn may_contain<T: Hash>(&self, item: &T) -> bool {
        let mut hasher = StableHasher::with_seed(self.hasher_seed);
        item.hash(&mut hasher);
        let bytes = hasher.finish().to_le_bytes();
        self.inner.check(&bytes)
    }

    /// Clear all bits
    pub fn clear(&mut self) {
        self.inner.clear();
        self.count = 0;
    }

    /// Get number of items inserted
    pub fn count(&self) -> usize {
        self.count
    }

    /// Get current estimated false positive rate
    pub fn estimated_fpr(&self) -> f64 {
        if self.count == 0 {
            return 0.0;
        }

        let k = self.num_hashes as f64;
        let n = self.count as f64;
        let m = self.num_bits as f64;

        (1.0 - (-k * n / m).exp()).powf(k)
    }

    /// Get memory usage in bytes
    pub fn memory_usage(&self) -> usize {
        (self.num_bits + 7) / 8 + std::mem::size_of::<Self>()
    }
}

/// Counting bloom filter for dynamic sets (supports removal)
///
/// Hand-rolled with 4-bit counters; the bloomfilter crate does not provide counting.
pub struct CountingBloomFilter {
    /// Counter array (4-bit counters packed into bytes)
    counters: Vec<u8>,
    /// Number of counters
    num_counters: usize,
    /// Number of hash functions
    num_hashes: u32,
    /// Number of items inserted
    count: usize,
    /// R-58: per-instance random seed for StableHasher.
    hasher_seed: u64,
}

impl CountingBloomFilter {
    /// Create a new counting bloom filter
    pub fn new(expected_items: usize, false_positive_rate: f64) -> Self {
        use rand::RngCore;
        let expected_items = expected_items.max(1);
        // SECURITY: Clamp FP rate to at most 0.001 to prevent flooding via false positives.
        let fpr = false_positive_rate.clamp(0.0001, 0.001);

        let ln2 = std::f64::consts::LN_2;
        let ln2_sq = ln2 * ln2;

        let num_counters = (-(expected_items as f64) * fpr.ln() / ln2_sq).ceil() as usize;
        let num_counters = num_counters.max(1024);

        let num_hashes = ((num_counters as f64 / expected_items as f64) * ln2).ceil() as u32;
        let num_hashes = num_hashes.clamp(1, 16);

        // 4-bit counters: 2 per byte
        let num_bytes = (num_counters + 1) / 2;

        CountingBloomFilter {
            counters: vec![0u8; num_bytes],
            num_counters,
            num_hashes,
            count: 0,
            hasher_seed: rand::rngs::OsRng.next_u64(),
        }
    }

    /// Insert an item
    pub fn insert<T: Hash>(&mut self, item: &T) {
        for i in 0..self.num_hashes {
            let index = self.hash_index(item, i);
            self.increment_counter(index);
        }
        self.count += 1;
    }

    /// Remove an item (decrement counters)
    pub fn remove<T: Hash>(&mut self, item: &T) {
        for i in 0..self.num_hashes {
            let index = self.hash_index(item, i);
            self.decrement_counter(index);
        }
        self.count = self.count.saturating_sub(1);
    }

    /// Check if item may be present
    pub fn may_contain<T: Hash>(&self, item: &T) -> bool {
        for i in 0..self.num_hashes {
            let index = self.hash_index(item, i);
            if self.get_counter(index) == 0 {
                return false;
            }
        }
        true
    }

    /// Get number of items
    pub fn count(&self) -> usize {
        self.count
    }

    fn hash_index<T: Hash>(&self, item: &T, seed: u32) -> usize {
        let mut hasher = StableHasher::with_seed(self.hasher_seed);
        seed.hash(&mut hasher);
        item.hash(&mut hasher);
        (hasher.finish() as usize) % self.num_counters
    }

    fn get_counter(&self, index: usize) -> u8 {
        let byte_index = index / 2;
        let is_high = index % 2 == 1;
        if byte_index < self.counters.len() {
            if is_high {
                self.counters[byte_index] >> 4
            } else {
                self.counters[byte_index] & 0x0F
            }
        } else {
            0
        }
    }

    fn increment_counter(&mut self, index: usize) {
        let byte_index = index / 2;
        let is_high = index % 2 == 1;
        if byte_index < self.counters.len() {
            let current = self.get_counter(index);
            if current < 15 {
                if is_high {
                    self.counters[byte_index] = (self.counters[byte_index] & 0x0F) | ((current + 1) << 4);
                } else {
                    self.counters[byte_index] = (self.counters[byte_index] & 0xF0) | (current + 1);
                }
            } else {
                tracing::debug!("Counting bloom filter counter saturated at index {}", index);
            }
        }
    }

    fn decrement_counter(&mut self, index: usize) {
        let byte_index = index / 2;
        let is_high = index % 2 == 1;
        if byte_index < self.counters.len() {
            let current = self.get_counter(index);
            if current > 0 {
                if is_high {
                    self.counters[byte_index] = (self.counters[byte_index] & 0x0F) | ((current - 1) << 4);
                } else {
                    self.counters[byte_index] = (self.counters[byte_index] & 0xF0) | (current - 1);
                }
            }
        }
    }
}

/// Key image bloom filter for fast double-spend checking
pub struct KeyImageFilter {
    filter: BloomFilter,
}

impl KeyImageFilter {
    /// Create filter for expected number of key images
    pub fn new(expected_key_images: usize) -> Self {
        // Use 0.0001 (0.01%) false positive rate for security
        KeyImageFilter {
            filter: BloomFilter::new(expected_key_images, 0.0001),
        }
    }

    /// Insert a key image
    pub fn insert(&mut self, key_image: &[u8; 32]) {
        self.filter.insert(key_image);
    }

    /// Check if key image might be spent
    pub fn may_be_spent(&self, key_image: &[u8; 32]) -> bool {
        self.filter.may_contain(key_image)
    }

    /// Get statistics
    pub fn stats(&self) -> (usize, f64, usize) {
        (self.filter.count(), self.filter.estimated_fpr(), self.filter.memory_usage())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bloom_filter_basic() {
        let mut filter = BloomFilter::new(1000, 0.01);

        // Insert items
        for i in 0..100 {
            filter.insert(&i);
        }

        // Check inserted items
        for i in 0..100 {
            assert!(filter.may_contain(&i), "Should contain {}", i);
        }

        // Check non-inserted items (some false positives expected)
        let mut false_positives = 0;
        for i in 1000..2000 {
            if filter.may_contain(&i) {
                false_positives += 1;
            }
        }

        // Should be below ~1% false positive rate
        assert!(false_positives < 20, "Too many false positives: {}", false_positives);
    }

    #[test]
    fn test_counting_bloom_filter() {
        let mut filter = CountingBloomFilter::new(1000, 0.01);

        // Insert and remove
        filter.insert(&42);
        assert!(filter.may_contain(&42));

        filter.remove(&42);
        assert!(!filter.may_contain(&42));
    }

    #[test]
    fn test_key_image_filter() {
        let mut filter = KeyImageFilter::new(10000);

        let ki1 = [1u8; 32];
        let ki2 = [2u8; 32];
        let _ki3 = [3u8; 32];

        filter.insert(&ki1);
        filter.insert(&ki2);

        assert!(filter.may_be_spent(&ki1));
        assert!(filter.may_be_spent(&ki2));
        // ki3 should likely return false (not guaranteed due to FP)
    }

    #[test]
    fn test_false_positive_rate() {
        let mut filter = BloomFilter::new(10_000, 0.01);
        for i in 0u32..1000 {
            filter.insert(&i);
        }
        let mut fp = 0;
        for i in 100_000u32..110_000 {
            if filter.may_contain(&i) {
                fp += 1;
            }
        }
        // FP rate should be roughly <= 1% (allow 2% margin)
        assert!(fp < 200, "False positive count {} exceeds 2% of 10000", fp);
    }
}
