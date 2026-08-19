use std::collections::HashMap;
use std::time::{Duration, Instant};

use crate::network::peer::PeerId;
use crate::primitives::Hash;

const DEFAULT_TTL: Duration = Duration::from_secs(60);
const DEFAULT_MAX_SIZE: usize = 10_000;

/// Bounded TTL cache of `(peer, transaction hash)` pairs a peer reported as
/// unavailable — keyed PER PEER.
///
/// SECURITY (N-1, 2026-08-18): keyed by `(PeerId, Hash)`, not by `Hash` alone.
/// A `NotFound` is accepted from any handshake-completed peer and is not
/// authenticated against an outstanding request, so a global-by-hash cache let
/// a single malicious peer spray unsolicited `NotFound` messages to suppress
/// relay of a targeted transaction from ALL honest peers for the TTL window
/// (refreshable indefinitely) — a targeted mempool-censorship primitive.
/// Keying per peer confines a peer's "I don't have X" to that peer: an
/// attacker's `NotFound` suppresses only its own (useless) future relay of X to
/// us, while we still fetch X from any honest peer that advertises it. This
/// also matches the stated intent — "a peer recently said they don't have".
pub struct TxAbsenceCache {
    inner: HashMap<(PeerId, Hash), Instant>,
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

    pub fn mark_absent(&mut self, peer: PeerId, hash: Hash) {
        if self.inner.len() >= self.max_size {
            self.prune();
            if self.inner.len() >= self.max_size {
                if let Some(oldest) = self
                    .inner
                    .iter()
                    .min_by_key(|(_, timestamp)| *timestamp)
                    .map(|(key, _)| *key)
                {
                    self.inner.remove(&oldest);
                }
            }
        }

        self.inner.insert((peer, hash), Instant::now());
    }

    pub fn is_known_absent(&self, peer: &PeerId, hash: &Hash) -> bool {
        match self.inner.get(&(*peer, *hash)) {
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

    fn peer(n: u8) -> PeerId {
        [n; 32]
    }

    #[test]
    fn marks_and_reports_absent_transactions() {
        let mut cache = TxAbsenceCache::new();
        let p = peer(9);
        let first = Hash::from_bytes([1; 32]);
        let second = Hash::from_bytes([2; 32]);

        assert!(!cache.is_known_absent(&p, &first));
        cache.mark_absent(p, first);

        assert!(cache.is_known_absent(&p, &first));
        assert!(!cache.is_known_absent(&p, &second));
        assert_eq!(cache.len(), 1);
    }

    #[test]
    fn absence_is_scoped_per_peer() {
        // N-1: one peer's NotFound must NOT suppress the same hash for another
        // peer — otherwise an unsolicited NotFound spray becomes targeted
        // mempool-relay censorship.
        let mut cache = TxAbsenceCache::new();
        let attacker = peer(1);
        let honest = peer(2);
        let h = Hash::from_bytes([7; 32]);

        cache.mark_absent(attacker, h);
        assert!(cache.is_known_absent(&attacker, &h));
        // The honest peer's advertisement of the same hash is NOT suppressed.
        assert!(!cache.is_known_absent(&honest, &h));
    }

    #[test]
    fn evicts_oldest_entry_at_the_hard_cap() {
        let mut cache = TxAbsenceCache::new();
        let p = peer(3);

        for i in 0..11_000u32 {
            cache.mark_absent(p, hash_from_counter(i));
        }

        assert_eq!(cache.len(), DEFAULT_MAX_SIZE);
        assert!(!cache.is_known_absent(&p, &hash_from_counter(0)));
        assert!(cache.is_known_absent(&p, &hash_from_counter(10_999)));
    }

    fn hash_from_counter(counter: u32) -> Hash {
        let mut bytes = [0; 32];
        bytes[..4].copy_from_slice(&counter.to_be_bytes());
        Hash::from_bytes(bytes)
    }
}
