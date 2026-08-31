//! Preimage-keyed RandomX verify cache — amplification defense (audit R3-2).
//!
//! `block.hash()` commits to fields (`target`, `miner_pubkey`,
//! `supply_commitment`, `checkpoint_vote`, spark/mw roots, `version`,
//! `network_magic`) that are NOT part of the RandomX input. The RandomX input
//! is a pure function of `(prev_hash, height, timestamp, nonce, tx_root)` (the
//! anchor is recomputed from `prev_hash/height/timestamp`). So an attacker can
//! take ONE mined block and mutate a non-preimage field (e.g. `target` →
//! `[0xFF;32]`) to produce unlimited hash-distinct "new" blocks that all share
//! the SAME RandomX input. The relay path (dispatch) ran `compute_pow_hash` on
//! each variant with no preimage cache → one mined solution forced unbounded
//! memory-hard RandomX across the network.
//!
//! This caches the RandomX OUTPUT keyed on the true preimage, so every variant
//! of one solution collapses to a SINGLE RandomX run. The cheap-target-floor
//! half of the finding is inert while `max_target()` is `[0xFF;32]` (nothing is
//! "easier than max"), so the cache is the load-bearing fix; the malleability
//! itself (one solution ↔ one block) is a separate, hf-gated PoW-preimage change.
//!
//! Placed here (not in the hash-locked `pow.rs`) so the relay path is fixed
//! without a critical-file re-lock. Routing `verify_pow` (block validation)
//! through this cache is a follow-up that requires the `pow.rs` edit.

use once_cell::sync::Lazy;
use parking_lot::Mutex;
use std::collections::{HashMap, VecDeque};

use crate::consensus::pow::{compute_full_anchor, compute_pow_hash, PowVerifyError};
use crate::error::{Error, Result};
use crate::primitives::{hash_concat, Hash};

/// Domain-separated key over EXACTLY the fields that determine the RandomX
/// input. Fields in `block.hash()` but not here do not change the RandomX
/// input, so all of their variants share this key and collapse to one result.
pub fn pow_preimage_key(
    prev_hash: &Hash,
    height: u64,
    timestamp: u64,
    nonce: u64,
    tx_root: &Hash,
) -> [u8; 32] {
    let h = hash_concat(&[
        b"coincync/pow-preimage/v1",
        prev_hash.as_bytes(),
        &height.to_le_bytes(),
        &timestamp.to_le_bytes(),
        &nonce.to_le_bytes(),
        tx_root.as_bytes(),
    ]);
    *h.as_bytes()
}

const POW_VERIFY_CACHE_MAX: usize = 8_192;

/// Bounded FIFO cache of RandomX OUTPUT hashes keyed by [`pow_preimage_key`].
/// Stores the raw output (NOT pass/fail) because `target` is not part of the
/// key — the difficulty compare is done per-variant by the caller.
struct PowVerifyCache {
    map: HashMap<[u8; 32], Hash>,
    order: VecDeque<[u8; 32]>,
}

impl PowVerifyCache {
    fn new() -> Self {
        PowVerifyCache {
            map: HashMap::with_capacity(POW_VERIFY_CACHE_MAX),
            order: VecDeque::with_capacity(POW_VERIFY_CACHE_MAX),
        }
    }
    fn get(&self, key: &[u8; 32]) -> Option<Hash> {
        self.map.get(key).copied()
    }
    fn insert(&mut self, key: [u8; 32], hash: Hash) {
        if self.map.contains_key(&key) {
            return;
        }
        if self.map.len() >= POW_VERIFY_CACHE_MAX {
            if let Some(old) = self.order.pop_front() {
                self.map.remove(&old);
            }
        }
        self.order.push_back(key);
        self.map.insert(key, hash);
    }
}

static POW_VERIFY_CACHE: Lazy<Mutex<PowVerifyCache>> =
    Lazy::new(|| Mutex::new(PowVerifyCache::new()));

/// Compute the RandomX PoW hash for a header, using the preimage cache so that
/// hash-distinct malleated variants of one solution cost a single RandomX.
/// Recomputes and binds the anchor first (like `verify_pow`), so a forged
/// `claimed_anchor`/`claimed_algo` is rejected free, before any hashing. Returns
/// the RandomX output; the caller compares it against the (context-validated)
/// target — this intentionally does NOT take `target` (that is what lets all
/// target-variants share one cache entry).
pub fn pow_hash_cached(
    prev_hash: &Hash,
    height: u64,
    timestamp: u64,
    nonce: u64,
    tx_root: &Hash,
    claimed_anchor: &Hash,
    claimed_algo: u8,
) -> Result<Hash> {
    let anchor = compute_full_anchor(prev_hash, height, timestamp)?;
    if anchor.mixed_hash != *claimed_anchor {
        return Err(Error::PowValidation(
            PowVerifyError::AnchorMismatch {
                expected: anchor.mixed_hash,
                claimed: *claimed_anchor,
            }
            .to_string(),
        ));
    }
    if anchor.algorithm as u8 != claimed_algo {
        return Err(Error::PowValidation(
            PowVerifyError::AlgorithmMismatch {
                expected: anchor.algorithm as u8,
                claimed: claimed_algo,
            }
            .to_string(),
        ));
    }

    let key = pow_preimage_key(prev_hash, height, timestamp, nonce, tx_root);
    if let Some(h) = POW_VERIFY_CACHE.lock().get(&key) {
        return Ok(h); // cache hit → NO RandomX (all variants of this solution collapse here)
    }

    let pow_hash = {
        let _timer = crate::metrics::RANDOMX_HASH.start_timer();
        compute_pow_hash(anchor.algorithm, &anchor.mixed_hash, nonce, tx_root, height)?
    };
    POW_VERIFY_CACHE.lock().insert(key, pow_hash);
    Ok(pow_hash)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn preimage_key_is_target_independent_and_field_sensitive() {
        let ph = Hash::from_bytes([1u8; 32]);
        let txr = Hash::from_bytes([2u8; 32]);
        // The key does not even take target/miner_pubkey/etc., so every variant
        // of one solution shares it — the amplification-collapse property.
        let k = pow_preimage_key(&ph, 5, 1000, 42, &txr);
        assert_eq!(k, pow_preimage_key(&ph, 5, 1000, 42, &txr), "deterministic");
        // Each genuine RandomX-input field MUST change the key (else we'd cache
        // across truly different solutions).
        assert_ne!(k, pow_preimage_key(&ph, 5, 1001, 42, &txr), "timestamp");
        assert_ne!(k, pow_preimage_key(&ph, 5, 1000, 43, &txr), "nonce");
        assert_ne!(k, pow_preimage_key(&ph, 6, 1000, 42, &txr), "height");
        assert_ne!(k, pow_preimage_key(&Hash::from_bytes([9u8; 32]), 5, 1000, 42, &txr), "prev_hash");
        assert_ne!(k, pow_preimage_key(&ph, 5, 1000, 42, &Hash::from_bytes([9u8; 32])), "tx_root");
    }

    #[test]
    fn cache_is_fifo_bounded_and_collapses_variants() {
        let mut c = PowVerifyCache::new();
        let k = [7u8; 32];
        let h = Hash::from_bytes([8u8; 32]);
        c.insert(k, h);
        assert_eq!(c.get(&k), Some(h));
        // Re-insert is a no-op (a hit never re-runs RandomX).
        c.insert(k, Hash::from_bytes([0xEE; 32]));
        assert_eq!(c.get(&k), Some(h), "existing entry is not overwritten");
        // FIFO eviction stays bounded.
        for i in 0..(POW_VERIFY_CACHE_MAX as u64 + 10) {
            let mut kk = [0u8; 32];
            kk[..8].copy_from_slice(&i.to_le_bytes());
            c.insert(kk, Hash::from_bytes([1u8; 32]));
        }
        assert!(c.map.len() <= POW_VERIFY_CACHE_MAX, "cache stays bounded");
    }
}
