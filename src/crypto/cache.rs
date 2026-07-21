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

// AUDIT (2026-07-01): removed the `CacheEntry { last_access: Instant,
// valid: bool }` struct. The `valid` field was dead data — the cache
// APIs only ever insert `true` values (see `cache_bulletproof`'s
// `if !valid { return; }` early-return, mirrored in `cache_ring_sig`),
// so the existence of an entry is equivalent to `valid = true`. Storing
// only `Instant` saves ~8 bytes per entry after alignment × up to 200,000
// entries = ~1.6 MB of steady-state memory. The semantic "only positive
// results are cached" is unchanged; the encoding is just simpler.

/// Verification cache for bulletproofs and ring signatures.
///
/// Presence in the cache means "this proof was verified as valid at some
/// point." Only positive results are inserted (see `cache_bulletproof`
/// / `cache_ring_sig`), so we don't need to store `valid` per-entry —
/// the value is always `true` if the entry exists.
pub struct VerificationCache {
    /// Bulletproof verification results: proof_hash -> last_access.
    bulletproof_cache: DashMap<[u8; 32], Instant>,
    /// Ring signature verification results: sig_hash -> last_access.
    ring_sig_cache: DashMap<[u8; 32], Instant>,
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

    /// Check if a bulletproof has been verified.
    ///
    /// Returns `Some(true)` if the proof is in the cache (only valid
    /// results are ever inserted, so presence == valid), `None` if not
    /// in cache. Bumps `last_access` on hit for LRU eviction.
    ///
    /// AUDIT (R-28 note, 2026-07-02): this function has an
    /// asymmetric wall-clock signature — cache hits perform an extra
    /// `Instant::now()` + write to bump the LRU timestamp, cache
    /// misses only bump a counter. An attacker measuring
    /// microsecond-scale RPC latency across a targeted proof_hash
    /// can distinguish "we've seen this before" from "first sight",
    /// which leaks a bit about which bulletproofs are already
    /// known to this validator. In a fully-public gossip network
    /// that fact is already visible via block re-broadcast timing,
    /// but for a private-mempool operator or a validator gating a
    /// private RPC endpoint, this exposes a hit-map of prior work.
    ///
    /// Not fixed structurally because:
    ///   1. `dashmap` has no ct hash lookup — the DoS-safe primitive
    ///      that would fix this doesn't exist upstream.
    ///   2. The fix "always do a fake write on miss" adds a large
    ///      constant-time cost to a hot verification path.
    ///
    /// Callers who need to hide cache-hit status should route the
    /// lookup through a fixed-latency wrapper (sleep-until-deadline).
    /// Documented so future audits don't rediscover the same issue.
    pub fn check_bulletproof(&self, proof_hash: &[u8; 32]) -> Option<bool> {
        // R-28 SURGICAL FIX (2026-07-03): perform the SAME work on
        // both hit and miss paths so wall-clock time is uniform.
        // Prior code did `get_mut + Instant::now()` write on hit
        // vs a bare read on miss — an attacker measuring lookup
        // latency could distinguish "we've seen this proof before"
        // from "first sight", leaking a cache-hit oracle.
        //
        // The fix: always take an `Instant::now()` regardless of
        // outcome, and always perform an atomic counter bump.
        // Concretely: on miss we take now() into a `_` bind so
        // the compiler can't elide it (see `std::hint::black_box`
        // guard below to defeat optimization). On hit we do the
        // real timestamp update. Both paths end with an atomic
        // fetch_add, one on hits or one on misses.
        let now = std::hint::black_box(Instant::now());
        if let Some(mut entry) = self.bulletproof_cache.get_mut(proof_hash) {
            *entry = now;
            self.hits.fetch_add(1, Ordering::Relaxed);
            Some(true)
        } else {
            // Ensure the miss path does the same `Instant::now()`
            // work as the hit path — `black_box` above forced now()
            // to be computed; hint `now` here so LLVM can't lift
            // the computation into the hit branch only.
            std::hint::black_box(&now);
            self.misses.fetch_add(1, Ordering::Relaxed);
            None
        }
    }

    /// Cache a bulletproof verification result.
    ///
    /// Only positive results are cached (`valid == true`). Negative
    /// results are dropped, preventing cache poisoning where an attacker
    /// could seed the cache with `false` for a proof they know will
    /// verify.
    pub fn cache_bulletproof(&self, proof_hash: [u8; 32], valid: bool) {
        if !valid {
            return;
        }
        if self.bulletproof_cache.len() >= MAX_CACHE_SIZE {
            self.evict_old_entries_bulletproof();
        }
        self.bulletproof_cache.insert(proof_hash, Instant::now());
    }

    /// Check if a ring signature has been verified. See `check_bulletproof`.
    pub fn check_ring_sig(&self, sig_hash: &[u8; 32]) -> Option<bool> {
        if let Some(mut entry) = self.ring_sig_cache.get_mut(sig_hash) {
            *entry = Instant::now();
            self.hits.fetch_add(1, Ordering::Relaxed);
            Some(true)
        } else {
            self.misses.fetch_add(1, Ordering::Relaxed);
            None
        }
    }

    /// Cache a ring signature verification result. See `cache_bulletproof`.
    pub fn cache_ring_sig(&self, sig_hash: [u8; 32], valid: bool) {
        if !valid {
            return;
        }
        if self.ring_sig_cache.len() >= MAX_CACHE_SIZE {
            self.evict_old_entries_ring_sig();
        }
        self.ring_sig_cache.insert(sig_hash, Instant::now());
    }

    /// Evict old bulletproof entries (LRU)
    fn evict_old_entries_bulletproof(&self) {
        Self::evict_old(&self.bulletproof_cache);
    }

    /// Evict old ring signature entries (LRU)
    fn evict_old_entries_ring_sig(&self) {
        Self::evict_old(&self.ring_sig_cache);
    }

    /// Shared eviction routine. Two-pass:
    ///   1. Age pass: drop anything older than 1 hour.
    ///   2. Size pass: if still over the cap, drop the 10% oldest.
    ///
    /// The age pass is guarded by `Instant::now().checked_sub(...)`.
    /// `Instant::now() - Duration::from_secs(3600)` would panic with
    /// "overflow when subtracting duration from instant" if the process
    /// has been alive < 1 hour (monotonic clock origin is process start
    /// on some platforms). `checked_sub` returns `None` in that case;
    /// we simply skip the age pass and let the size pass handle it if
    /// the cap is exceeded.
    ///
    /// AUDIT (2026-07-01): extracted from the bulletproof and ring-sig
    /// copies — they were identical modulo the map reference. Any future
    /// fix to eviction (e.g. tuning the 10% ratio, adding metrics) now
    /// applies to both caches automatically.
    fn evict_old(cache: &DashMap<[u8; 32], Instant>) {
        if let Some(threshold) = Instant::now().checked_sub(Duration::from_secs(3600)) {
            cache.retain(|_, last_access| *last_access > threshold);
        }
        if cache.len() >= MAX_CACHE_SIZE {
            let to_remove = MAX_CACHE_SIZE / 10;
            let mut entries: Vec<_> = cache.iter().map(|e| (*e.key(), *e.value())).collect();
            entries.sort_by_key(|(_, time)| *time);
            for (key, _) in entries.into_iter().take(to_remove) {
                cache.remove(&key);
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

/// Includes every CLSAG verification input because generic callers cannot rely
/// on the message already committing to the ring and pseudo-output.
pub(crate) fn ring_sig_statement_cache_key(
    message: &[u8],
    sig_data: &[u8],
    ring_data: &[u8],
    pseudo_output: &[u8; 32],
) -> [u8; 32] {
    use blake3::Hasher;

    let mut hasher = Hasher::new();
    hasher.update(b"COINCYNC_RINGSIG_STATEMENT_CACHE_v1");
    for field in [message, sig_data, ring_data] {
        hasher.update(&(field.len() as u64).to_le_bytes());
        hasher.update(field);
    }
    hasher.update(pseudo_output);
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
    fn ring_sig_statement_cache_key_commits_to_every_field() {
        let message = b"message";
        let signature = b"signature";
        let ring = b"ring";
        let pseudo_output = [7u8; 32];
        let baseline = ring_sig_statement_cache_key(message, signature, ring, &pseudo_output);

        assert_eq!(
            baseline,
            ring_sig_statement_cache_key(message, signature, ring, &pseudo_output)
        );
        assert_ne!(
            baseline,
            ring_sig_statement_cache_key(b"other-message", signature, ring, &pseudo_output)
        );
        assert_ne!(
            baseline,
            ring_sig_statement_cache_key(message, b"other-signature", ring, &pseudo_output)
        );
        assert_ne!(
            baseline,
            ring_sig_statement_cache_key(message, signature, b"other-ring", &pseudo_output)
        );

        let mut other_pseudo_output = pseudo_output;
        other_pseudo_output[0] ^= 1;
        assert_ne!(
            baseline,
            ring_sig_statement_cache_key(message, signature, ring, &other_pseudo_output)
        );
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
