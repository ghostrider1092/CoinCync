//! LRU Cache for blocks and other frequently accessed data
//!
//! Thin wrapper around the `lru` crate with cache statistics tracking.

use hashlink::LruCache as HashlinkLruCache;
use std::collections::HashMap;
use std::hash::Hash;

/// Generic LRU cache with O(1) operations
///
/// Wraps `lru::LruCache` and adds hit/miss statistics.
pub struct LruCache<K, V> {
    inner: HashlinkLruCache<K, V>,
    hits: u64,
    misses: u64,
}

impl<K: Clone + Hash + Eq, V> LruCache<K, V> {
    /// Create a new LRU cache with given capacity
    pub fn new(capacity: usize) -> Self {
        LruCache {
            inner: HashlinkLruCache::new(capacity.max(1)),
            hits: 0,
            misses: 0,
        }
    }

    /// Get a value from the cache, updating access order
    pub fn get(&mut self, key: &K) -> Option<&V> {
        match self.inner.get(key) {
            Some(v) => {
                self.hits += 1;
                Some(v)
            }
            None => {
                self.misses += 1;
                None
            }
        }
    }

    /// Get a value without updating access order (for peek operations)
    pub fn peek(&self, key: &K) -> Option<&V> {
        self.inner.peek(key)
    }

    /// Insert a value, evicting LRU entry if at capacity.
    /// Returns the evicted (key, value) pair if eviction occurred.
    pub fn insert(&mut self, key: K, value: V) -> Option<(K, V)> {
        if self.inner.contains_key(&key) {
            self.inner.insert(key, value);
            return None;
        }

        let evicted = if self.inner.len() >= self.inner.capacity() {
            self.inner.remove_lru()
        } else {
            None
        };

        self.inner.insert(key, value);
        evicted
    }

    /// Remove a key from the cache
    pub fn remove(&mut self, key: &K) -> Option<V> {
        self.inner.remove(key)
    }

    /// Check if key exists
    pub fn contains(&self, key: &K) -> bool {
        self.inner.contains_key(key)
    }

    /// Get current size
    pub fn len(&self) -> usize {
        self.inner.len()
    }

    /// Check if empty
    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }

    /// Get capacity
    pub fn capacity(&self) -> usize {
        self.inner.capacity()
    }

    /// Clear all entries
    pub fn clear(&mut self) {
        self.inner.clear();
    }

    /// Get cache statistics
    pub fn stats(&self) -> CacheStats {
        let hits = self.hits;
        let misses = self.misses;
        let total = hits + misses;
        let hit_rate = if total > 0 {
            hits as f64 / total as f64
        } else {
            0.0
        };

        CacheStats {
            hits,
            misses,
            hit_rate,
            size: self.len(),
            capacity: self.capacity(),
        }
    }

    /// Reset statistics
    pub fn reset_stats(&mut self) {
        self.hits = 0;
        self.misses = 0;
    }

    /// Evict the least recently used entry (used by SizedLruCache)
    fn evict_lru(&mut self) -> Option<(K, V)> {
        self.inner.remove_lru()
    }
}

/// Cache statistics
#[derive(Debug, Clone)]
pub struct CacheStats {
    pub hits: u64,
    pub misses: u64,
    pub hit_rate: f64,
    pub size: usize,
    pub capacity: usize,
}

/// Size-bounded LRU cache that tracks memory usage
pub struct SizedLruCache<K, V> {
    cache: LruCache<K, V>,
    /// Current memory usage in bytes
    current_size: usize,
    /// Maximum memory usage in bytes
    max_size: usize,
    /// Function to compute value size
    size_fn: fn(&V) -> usize,
    /// Size of each value (cached)
    sizes: HashMap<K, usize>,
}

impl<K: Clone + Hash + Eq, V> SizedLruCache<K, V> {
    /// Create a new size-bounded cache
    ///
    /// # Arguments
    /// * `max_size` - Maximum total size in bytes
    /// * `size_fn` - Function to compute size of each value
    pub fn new(max_size: usize, size_fn: fn(&V) -> usize) -> Self {
        SizedLruCache {
            cache: LruCache::new(max_size / 1024), // Rough estimate
            current_size: 0,
            max_size,
            size_fn,
            sizes: HashMap::new(),
        }
    }

    /// Insert a value, evicting entries until under size limit.
    ///
    /// AUDIT (R-57 fix, 2026-07-03): pre-fix code called
    /// `self.cache.insert(key.clone(), value);` — that inner call
    /// returns `Option<(K, V)>` for entries evicted by the inner
    /// LRU's capacity check (bounded at `max_size / 1024`), but the
    /// outer wrapper DISCARDED the return value. Consequence: an
    /// auto-eviction happens inside `LruCache::insert`, but the
    /// outer `sizes` HashMap and `current_size` byte counter never
    /// see it. Each auto-eviction leaves a phantom entry in
    /// `sizes` and inflates `current_size` by the phantom entry's
    /// bytes forever. Over time `current_size` monotonically
    /// drifts UP, the outer eviction loop at L171 evicts every
    /// entry on every insert, and the cache degrades into a
    /// single-entry churn (hit rate → 0).
    ///
    /// Fix: capture the returned evicted entry from the inner
    /// `insert()` call and clean up `sizes` + `current_size`
    /// accordingly. Add a debug assertion that current_size
    /// matches the sum of sizes values in test mode, catching any
    /// future drift immediately.
    pub fn insert(&mut self, key: K, value: V) {
        let value_size = (self.size_fn)(&value);

        // Evict until we have space (outer eviction — driven by
        // byte-size limits, not entry count).
        while self.current_size + value_size > self.max_size && !self.cache.is_empty() {
            match self.cache.evict_lru() {
                Some((evicted_key, _)) => {
                    if let Some(evicted_size) = self.sizes.remove(&evicted_key) {
                        self.current_size = self.current_size.saturating_sub(evicted_size);
                    }
                }
                _ => break,
            }
        }

        // Remove old size if updating (rare — usually a fresh key).
        if let Some(old_size) = self.sizes.remove(&key) {
            self.current_size = self.current_size.saturating_sub(old_size);
        }

        // R-57: capture the inner-LRU auto-eviction. When the inner
        // capacity (max_size / 1024 entries) is exceeded, the inner
        // `insert` returns the evicted entry — clean up our shadow
        // accounting for it.
        let inner_evicted = self.cache.insert(key.clone(), value);
        if let Some((evicted_key, _)) = inner_evicted {
            if let Some(evicted_size) = self.sizes.remove(&evicted_key) {
                self.current_size = self.current_size.saturating_sub(evicted_size);
            }
        }
        self.sizes.insert(key, value_size);
        self.current_size += value_size;

        // Debug assertion: shadow accounting must match sizes sum.
        // Skipped in release builds.
        debug_assert_eq!(
            self.current_size,
            self.sizes.values().sum::<usize>(),
            "R-57: current_size drift detected — inner auto-eviction untracked"
        );
    }

    /// Get a value
    pub fn get(&mut self, key: &K) -> Option<&V> {
        self.cache.get(key)
    }

    /// Remove a value
    pub fn remove(&mut self, key: &K) -> Option<V> {
        if let Some(size) = self.sizes.remove(key) {
            self.current_size = self.current_size.saturating_sub(size);
        }
        self.cache.remove(key)
    }

    /// Get current memory usage
    pub fn current_size(&self) -> usize {
        self.current_size
    }

    /// Get max size
    pub fn max_size(&self) -> usize {
        self.max_size
    }

    /// Get statistics
    pub fn stats(&self) -> CacheStats {
        self.cache.stats()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_lru_basic() {
        let mut cache = LruCache::new(3);

        cache.insert("a", 1);
        cache.insert("b", 2);
        cache.insert("c", 3);

        assert_eq!(cache.get(&"a"), Some(&1));
        assert_eq!(cache.get(&"b"), Some(&2));
        assert_eq!(cache.get(&"c"), Some(&3));
    }

    #[test]
    fn test_lru_eviction() {
        let mut cache = LruCache::new(2);

        cache.insert("a", 1);
        cache.insert("b", 2);
        cache.insert("c", 3); // Should evict "a"

        assert_eq!(cache.get(&"a"), None);
        assert_eq!(cache.get(&"b"), Some(&2));
        assert_eq!(cache.get(&"c"), Some(&3));
    }

    #[test]
    fn test_lru_access_order() {
        let mut cache = LruCache::new(2);

        cache.insert("a", 1);
        cache.insert("b", 2);
        cache.get(&"a"); // Access "a" to make it recent
        cache.insert("c", 3); // Should evict "b" (least recently used)

        assert_eq!(cache.get(&"a"), Some(&1));
        assert_eq!(cache.get(&"b"), None);
        assert_eq!(cache.get(&"c"), Some(&3));
    }

    #[test]
    fn test_cache_stats() {
        let mut cache = LruCache::<&str, i32>::new(10);

        cache.insert("a", 1);
        cache.get(&"a"); // Hit
        cache.get(&"b"); // Miss
        cache.get(&"a"); // Hit

        let stats = cache.stats();
        assert_eq!(stats.hits, 2);
        assert_eq!(stats.misses, 1);
    }

    #[test]
    fn test_concurrent_lru() {
        let mut cache = LruCache::new(10);
        for round in 0..100usize {
            let key = format!("k{}", round);
            cache.insert(key.clone(), round);
            // Access older key to shuffle LRU order
            let _ = cache.get(&format!("k{}", round.saturating_sub(5)));
        }
        // Should have at most 10 entries
        assert!(cache.len() <= 10);
    }
}
