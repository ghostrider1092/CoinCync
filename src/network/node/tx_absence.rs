use std::collections::HashMap;
use std::time::{Duration, Instant};

use crate::primitives::Hash;

const DEFAULT_TTL: Duration = Duration::from_secs(60);
const DEFAULT_MAX_SIZE: usize = 10_000;

/// Bounded TTL cache of transaction hashes peers reported as unavailable.
pub struct TxAbsenceCache {
    inner: HashMap<Hash, Instant>,
    ttl: Duration,
    max_size: usize,
}

impl TxAbsenceCache {
    pub fn new() -> Self {
        Self {
            inner: HashMap::new(),
            ttl: DEFAULT_TTL,
            max_size: DEFAULT_MAX_SIZE,
        }
    }

    pub fn mark_absent(&mut self, hash: Hash) {
        if self.inner.len() >= self.max_size {
            self.prune();
            if self.inner.len() >= self.max_size {
                if let Some(oldest) = self
                    .inner
                    .iter()
                    .min_by_key(|(_, timestamp)| *timestamp)
                    .map(|(hash, _)| *hash)
                {
                    self.inner.remove(&oldest);
                }
            }
        }

        self.inner.insert(hash, Instant::now());
    }

    pub fn is_known_absent(&self, hash: &Hash) -> bool {
        match self.inner.get(hash) {
            Some(timestamp) => timestamp.elapsed() < self.ttl,
            None => false,
        }
    }

    pub fn prune(&mut self) -> usize {
        let before = self.inner.len();
        let ttl = self.ttl;
        self.inner.retain(|_, timestamp| timestamp.elapsed() < ttl);
        before.saturating_sub(self.inner.len())
    }

    pub fn len(&self) -> usize {
        self.inner.len()
    }

    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }
}

impl Default for TxAbsenceCache {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn marks_and_reports_absent_transactions() {
        let mut cache = TxAbsenceCache::new();
        let first = Hash::from_bytes([1; 32]);
        let second = Hash::from_bytes([2; 32]);

        assert!(!cache.is_known_absent(&first));
        cache.mark_absent(first);

        assert!(cache.is_known_absent(&first));
        assert!(!cache.is_known_absent(&second));
        assert_eq!(cache.len(), 1);
    }

    #[test]
    fn evicts_oldest_entry_at_the_hard_cap() {
        let mut cache = TxAbsenceCache::new();

        for i in 0..11_000u32 {
            cache.mark_absent(hash_from_counter(i));
        }

        assert_eq!(cache.len(), DEFAULT_MAX_SIZE);
        assert!(!cache.is_known_absent(&hash_from_counter(0)));
        assert!(cache.is_known_absent(&hash_from_counter(10_999)));
    }

    fn hash_from_counter(counter: u32) -> Hash {
        let mut bytes = [0; 32];
        bytes[..4].copy_from_slice(&counter.to_be_bytes());
        Hash::from_bytes(bytes)
    }
}
