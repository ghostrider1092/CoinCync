//! # Cryptographic Verification Cache
//!
//! Caches verification results for expensive cryptographic operations.
//! This provides 10-50x speedup during block sync when the same proofs
//! are verified repeatedly.
//!
//! ## Security
//! - Cache keys are cryptographic hashes of proof data
//! - Only positive verification results are cached
//! - Cache is thread-safe using DashMap
//! - LRU eviction prevents unbounded memory growth

use dashmap::DashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

/// Maximum cache entries before eviction
const MAX_CACHE_SIZE: usize = 100_000;

/// Cache entry with timestamp for LRU eviction
#[derive(Clone)]
struct CacheEntry {
    /// When this entry was last accessed
    last_access: Instant,
    /// Verification result (only true results are cached)
    valid: bool,
}

/// Verification cache for bulletproofs and ring signatures
pub struct VerificationCache {
    /// Bulletproof verification results: proof_hash -> valid
    bulletproof_cache: DashMap<[u8; 32], CacheEntry>,
    /// Ring signature verification results: sig_hash -> valid
    ring_sig_cache: DashMap<[u8; 32], CacheEntry>,
    /// Cache statistics
    hits: AtomicU64,
    misses: AtomicU64,
}

impl VerificationCache {
    /// Create a new verification cache
    pub fn new() -> Self {
        VerificationCache {
            bulletproof_cache: DashMap::with_capacity(10_000),
            ring_sig_cache: DashMap::with_capacity(10_000),
            hits: AtomicU64::new(0),
            misses: AtomicU64::new(0),
        }
    }

    /// Check if a bulletproof has been verified
    /// Returns Some(true) if verified valid, None if not in cache
    pub fn check_bulletproof(&self, proof_hash: &[u8; 32]) -> Option<bool> {
        match self.bulletproof_cache.get_mut(proof_hash) { Some(mut entry) => {
            entry.last_access = Instant::now();
            self.hits.fetch_add(1, Ordering::Relaxed);
            Some(entry.valid)
        } _ => {
            self.misses.fetch_add(1, Ordering::Relaxed);
            None
        }}
    }

    /// Cache a bulletproof verification result
    /// Only caches positive results to prevent cache poisoning
    pub fn cache_bulletproof(&self, proof_hash: [u8; 32], valid: bool) {
        // Only cache valid proofs
        if !valid {
            return;
        }

        // Evict old entries if cache is too large
        if self.bulletproof_cache.len() >= MAX_CACHE_SIZE {
            self.evict_old_entries_bulletproof();
        }

        self.bulletproof_cache.insert(proof_hash, CacheEntry {
            last_access: Instant::now(),
            valid,
        });
    }

    /// Check if a ring signature has been verified
    pub fn check_ring_sig(&self, sig_hash: &[u8; 32]) -> Option<bool> {
        match self.ring_sig_cache.get_mut(sig_hash) { Some(mut entry) => {
            entry.last_access = Instant::now();
            self.hits.fetch_add(1, Ordering::Relaxed);
            Some(entry.valid)
        } _ => {
            self.misses.fetch_add(1, Ordering::Relaxed);
            None
        }}
    }

    /// Cache a ring signature verification result
    pub fn cache_ring_sig(&self, sig_hash: [u8; 32], valid: bool) {
        if !valid {
            return;
        }

        if self.ring_sig_cache.len() >= MAX_CACHE_SIZE {
            self.evict_old_entries_ring_sig();
        }

        self.ring_sig_cache.insert(sig_hash, CacheEntry {
            last_access: Instant::now(),
            valid,
        });
    }

    /// Evict old bulletproof entries (LRU)
    fn evict_old_entries_bulletproof(&self) {
        let threshold = Instant::now() - Duration::from_secs(3600); // 1 hour
        self.bulletproof_cache.retain(|_, entry| entry.last_access > threshold);

        // If still too large, remove 10% oldest
        if self.bulletproof_cache.len() >= MAX_CACHE_SIZE {
            let to_remove = MAX_CACHE_SIZE / 10;
            let mut entries: Vec<_> = self.bulletproof_cache.iter()
                .map(|e| (*e.key(), e.value().last_access))
                .collect();
            entries.sort_by_key(|(_, time)| *time);

            for (key, _) in entries.into_iter().take(to_remove) {
                self.bulletproof_cache.remove(&key);
            }
        }
    }

    /// Evict old ring signature entries (LRU)
    fn evict_old_entries_ring_sig(&self) {
        let threshold = Instant::now() - Duration::from_secs(3600);
        self.ring_sig_cache.retain(|_, entry| entry.last_access > threshold);

        if self.ring_sig_cache.len() >= MAX_CACHE_SIZE {
            let to_remove = MAX_CACHE_SIZE / 10;
            let mut entries: Vec<_> = self.ring_sig_cache.iter()
                .map(|e| (*e.key(), e.value().last_access))
                .collect();
            entries.sort_by_key(|(_, time)| *time);

            for (key, _) in entries.into_iter().take(to_remove) {
                self.ring_sig_cache.remove(&key);
            }
        }
    }

    /// Get cache statistics
    pub fn stats(&self) -> CacheStats {
        let hits = self.hits.load(Ordering::Relaxed);
        let misses = self.misses.load(Ordering::Relaxed);
        CacheStats {
            hits,
            misses,
            bulletproof_entries: self.bulletproof_cache.len(),
            ring_sig_entries: self.ring_sig_cache.len(),
            hit_rate: if hits + misses > 0 {
                hits as f64 / (hits + misses) as f64
            } else {
                0.0
            },
        }
    }

    /// Clear all cache entries
    pub fn clear(&self) {
        self.bulletproof_cache.clear();
        self.ring_sig_cache.clear();
        self.hits.store(0, Ordering::Relaxed);
        self.misses.store(0, Ordering::Relaxed);
    }
}

impl Default for VerificationCache {
    fn default() -> Self {
        Self::new()
    }
}

/// Cache statistics
#[derive(Debug, Clone)]
pub struct CacheStats {
    pub hits: u64,
    pub misses: u64,
    pub bulletproof_entries: usize,
    pub ring_sig_entries: usize,
    pub hit_rate: f64,
}

/// Compute hash of proof data for cache key
pub fn proof_cache_key(proof_data: &[u8], commitment_data: &[u8]) -> [u8; 32] {
    use blake3::Hasher;
    let mut hasher = Hasher::new();
    hasher.update(b"COINCYNC_PROOF_CACHE_v1");
    hasher.update(proof_data);
    hasher.update(commitment_data);
    *hasher.finalize().as_bytes()
}

/// Compute hash of ring signature for cache key
pub fn ring_sig_cache_key(message: &[u8], sig_data: &[u8]) -> [u8; 32] {
    use blake3::Hasher;
    let mut hasher = Hasher::new();
    hasher.update(b"COINCYNC_RINGSIG_CACHE_v1");
    hasher.update(message);
    hasher.update(sig_data);
    *hasher.finalize().as_bytes()
}

/// Global verification cache instance
static GLOBAL_CACHE: once_cell::sync::Lazy<VerificationCache> =
    once_cell::sync::Lazy::new(VerificationCache::new);

/// Get the global verification cache
pub fn global_cache() -> &'static VerificationCache {
    &GLOBAL_CACHE
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cache_bulletproof() {
        let cache = VerificationCache::new();
        let hash = [1u8; 32];

        // Initially not in cache
        assert!(cache.check_bulletproof(&hash).is_none());

        // Cache valid result
        cache.cache_bulletproof(hash, true);
        assert_eq!(cache.check_bulletproof(&hash), Some(true));

        // Stats should show hit
        let stats = cache.stats();
        assert_eq!(stats.hits, 1);
        assert_eq!(stats.misses, 1);
    }

    #[test]
    fn test_cache_invalid_not_stored() {
        let cache = VerificationCache::new();
        let hash = [2u8; 32];

        // Invalid results should not be cached
        cache.cache_bulletproof(hash, false);
        assert!(cache.check_bulletproof(&hash).is_none());
    }

    #[test]
    fn test_proof_cache_key() {
        let proof1 = [1u8; 64];
        let proof2 = [2u8; 64];
        let commitment = [0u8; 32];

        let key1 = proof_cache_key(&proof1, &commitment);
        let key2 = proof_cache_key(&proof2, &commitment);

        // Different proofs should have different keys
        assert_ne!(key1, key2);

        // Same proof should have same key
        assert_eq!(key1, proof_cache_key(&proof1, &commitment));
    }

    #[test]
    fn test_cache_eviction() {
        let cache = VerificationCache::new();

        // Fill cache with MAX_CACHE_SIZE + 1 entries to trigger eviction
        for i in 0..=(MAX_CACHE_SIZE) {
            let mut hash = [0u8; 32];
            hash[..8].copy_from_slice(&(i as u64).to_le_bytes());
            cache.cache_bulletproof(hash, true);
        }

        // Cache should not exceed MAX_CACHE_SIZE (eviction should have fired)
        let stats = cache.stats();
        assert!(
            stats.bulletproof_entries <= MAX_CACHE_SIZE,
            "Cache should not exceed max: got {}",
            stats.bulletproof_entries
        );
    }
}
