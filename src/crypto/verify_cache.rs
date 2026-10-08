//! # Verify-result cache seam (Warren Phase 0 — §3.7)
//!
//! A proof verified in the mempool should not be re-verified when its tx lands
//! in a block, nor again on a reorg replay. This is the cache the Sluice
//! consults (via [`Sluice::verify_valid_cached`](crate::crypto::heavy_verify::Sluice::verify_valid_cached))
//! so any heavy path behind `HeavyVerify` gets that skip uniformly.
//!
//! It generalizes the existing split `crypto::cache::VerificationCache`
//! (separate bulletproof / ring-sig maps, used by the current block validator)
//! into one trait keyed by a statement hash. The two converge when the Sluice
//! replaces the ad-hoc batch paths; until then this serves the Sluice seam and
//! the existing cache serves the live validator.
//!
//! ## Safety — the two invariants that make a verify cache sound
//! 1. **Positive-only.** Only `true` (valid) verdicts are stored. A miss
//!    re-verifies; a hit means "this exact statement verified before". A `false`
//!    is never cached, so a cache can never poison a later honest check into a
//!    wrong negative.
//! 2. **The key commits to everything the verdict depends on.** A path is
//!    cacheable ONLY if its [`HeavyVerify::cache_key`] returns `Some` key that
//!    uniquely binds every input the verdict is a function of. A path whose
//!    verdict depends on state OUTSIDE the item — e.g. the Spark spend path,
//!    valid before its linking tag is spent and invalid after — returns `None`
//!    and is never cached. Caching such a path by item hash would return a stale
//!    verdict; the `None` default makes "not cacheable" the safe fallback.
//!
//! Bounded (size-capped LRU) so proof flooding cannot grow it without limit.

use std::time::Instant;

use dashmap::DashMap;

/// A verify-result cache the Sluice can consult. Thread-safe (the valve may hit
/// it from the serial cache pass on any thread). Only known-valid statements are
/// ever present.
pub trait VerifyResultCache: Sync {
    /// `true` iff this exact statement was recorded valid before. A `false`
    /// return means "unknown" — the caller must re-verify.
    fn is_known_valid(&self, key: &[u8; 32]) -> bool;
    /// Record that this statement verified VALID. Callers must never call this
    /// for an invalid verdict (the positive-only invariant).
    fn record_valid(&self, key: [u8; 32]);
    /// Current entry count (observability / tests).
    fn len(&self) -> usize;
    fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// Default bounded LRU implementation. Presence ⇒ valid (mirrors the existing
/// `VerificationCache`: an entry is just its last-access `Instant`).
pub struct LruVerifyCache {
    map: DashMap<[u8; 32], Instant>,
    max: usize,
}

impl LruVerifyCache {
    /// Default cap, matching the existing cache's `MAX_CACHE_SIZE`.
    pub const DEFAULT_MAX: usize = 100_000;

    pub fn new(max: usize) -> Self {
        Self { map: DashMap::new(), max: max.max(1) }
    }

    /// When at capacity, drop the oldest ~10% by last-access (same strategy as
    /// `crypto::cache`'s size pass). Cheap amortised: fires only at the cap.
    fn evict_if_full(&self) {
        if self.map.len() < self.max {
            return;
        }
        let mut entries: Vec<([u8; 32], Instant)> =
            self.map.iter().map(|e| (*e.key(), *e.value())).collect();
        entries.sort_by_key(|(_, t)| *t); // oldest first
        let drop_n = (self.max / 10).max(1);
        for (k, _) in entries.into_iter().take(drop_n) {
            self.map.remove(&k);
        }
    }
}

impl Default for LruVerifyCache {
    fn default() -> Self {
        Self::new(Self::DEFAULT_MAX)
    }
}

impl VerifyResultCache for LruVerifyCache {
    fn is_known_valid(&self, key: &[u8; 32]) -> bool {
        if let Some(mut e) = self.map.get_mut(key) {
            *e = Instant::now(); // bump for LRU
            true
        } else {
            false
        }
    }

    fn record_valid(&self, key: [u8; 32]) {
        self.evict_if_full();
        self.map.insert(key, Instant::now());
    }

    fn len(&self) -> usize {
        self.map.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn miss_then_hit() {
        let c = LruVerifyCache::default();
        let k = [9u8; 32];
        assert!(!c.is_known_valid(&k), "unknown statement is a miss");
        c.record_valid(k);
        assert!(c.is_known_valid(&k), "recorded statement is a hit");
        assert_eq!(c.len(), 1);
    }

    #[test]
    fn distinct_keys_do_not_alias() {
        let c = LruVerifyCache::default();
        c.record_valid([1u8; 32]);
        assert!(!c.is_known_valid(&[2u8; 32]));
    }

    #[test]
    fn bounded_eviction_keeps_size_near_cap() {
        let c = LruVerifyCache::new(50);
        for i in 0..200u64 {
            let mut k = [0u8; 32];
            k[..8].copy_from_slice(&i.to_le_bytes());
            c.record_valid(k);
        }
        assert!(c.len() <= 50, "cache stays bounded under flooding (got {})", c.len());
    }
}
