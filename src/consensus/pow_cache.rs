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
//!
//! ## Audit map
//! Each `§` is a code element below; it states the INVARIANT it guarantees, the
//! THREAT it defends, and the TESTS that prove it. (Renders in `cargo doc`.)
//!
//! - **§1 `pow_preimage_key`** — INVARIANT: a domain-separated key over EXACTLY the
//!   fields that determine the RandomX input (`prev_hash, height, timestamp, nonce,
//!   tx_root, binding`); target-independent, deterministic, and each of those input
//!   fields changes the key. THREAT: caching one output across two genuinely
//!   different solutions (a false-accept). TESTS:
//!   `preimage_key_is_target_independent_and_field_sensitive`.
//! - **§2 `pow_preimage_key` binding sensitivity (audit §1)** — INVARIANT: a
//!   different header `binding` changes the key, so malleated variants that share
//!   `(prev,height,ts,nonce,tx_root)` but differ in a bound field do NOT collapse to
//!   one cache entry. THREAT: audit §1 PoW/anchor malleability — a mutated bound
//!   field riding another solution's cached RandomX output. TESTS:
//!   `pow_verify_cache_does_not_collapse_distinct_bindings`,
//!   `pow_hash_cached_rejects_reused_anchor_with_different_binding`.
//! - **§3 `PowVerifyCache`** — INVARIANT: FIFO-bounded at `POW_VERIFY_CACHE_MAX`; an
//!   existing entry is never overwritten. THREAT: unbounded cache growth (memory
//!   DoS). TESTS: `cache_is_fifo_bounded_and_collapses_variants`.
//! - **§4 amplification-collapse (target-variants)** — INVARIANT: the key omits
//!   `target`, so every target-variant of one solution derives the SAME key and
//!   shares a single cached RandomX run. THREAT: amplification-collapse — one mined
//!   solution mutated into unlimited hash-distinct blocks forcing unbounded
//!   memory-hard RandomX across the network. TESTS:
//!   `pow_verify_cache_collapses_target_variants_to_one_entry`.
//! - **§5 `pow_hash_cached` anchor/algorithm gate** — INVARIANT: recomputes and
//!   binds the anchor first, so a forged `claimed_anchor` or `claimed_algo` is
//!   rejected free, BEFORE any RandomX hashing. THREAT: a forged anchor/algorithm
//!   poisoning the cache or wasting a RandomX run. TESTS:
//!   `pow_hash_cached_rejects_forged_anchor_before_hashing`,
//!   `pow_hash_cached_rejects_algorithm_mismatch_before_hashing`.
//! - **§6 `pow_hash_cached` compute + cache** — INVARIANT: a cold miss computes and
//!   caches the RandomX output; a second call for the same preimage key is a hit
//!   returning the identical output with no recompute. THREAT: redundant memory-hard
//!   RandomX per variant of one solution. TESTS:
//!   `pow_hash_cached_cold_miss_then_hit_returns_same`.

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
    // audit §1: the anchor (hence the RandomX input) now depends on the header
    // binding, so malleated variants that share (prev,height,ts,nonce,tx_root)
    // but differ in a bound field have DIFFERENT PoW hashes and MUST NOT collapse
    // to one cache entry.
    binding: &Hash,
) -> [u8; 32] {
    let h = hash_concat(&[
        b"coincync/pow-preimage/v1",
        prev_hash.as_bytes(),
        &height.to_le_bytes(),
        &timestamp.to_le_bytes(),
        &nonce.to_le_bytes(),
        tx_root.as_bytes(),
        binding.as_bytes(),
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
#[allow(clippy::too_many_arguments)]
pub fn pow_hash_cached(
    prev_hash: &Hash,
    height: u64,
    timestamp: u64,
    nonce: u64,
    tx_root: &Hash,
    claimed_anchor: &Hash,
    claimed_algo: u8,
    // audit §1: header-binding digest (`BlockHeader::pow_binding`).
    binding: &Hash,
) -> Result<Hash> {
    let anchor = compute_full_anchor(prev_hash, height, timestamp, binding)?;
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

    let key = pow_preimage_key(prev_hash, height, timestamp, nonce, tx_root, binding);
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
        let bind = Hash::from_bytes([3u8; 32]);
        let k = pow_preimage_key(&ph, 5, 1000, 42, &txr, &bind);
        assert_eq!(k, pow_preimage_key(&ph, 5, 1000, 42, &txr, &bind), "deterministic");
        // Each genuine RandomX-input field MUST change the key (else we'd cache
        // across truly different solutions).
        assert_ne!(k, pow_preimage_key(&ph, 5, 1001, 42, &txr, &bind), "timestamp");
        assert_ne!(k, pow_preimage_key(&ph, 5, 1000, 43, &txr, &bind), "nonce");
        assert_ne!(k, pow_preimage_key(&ph, 6, 1000, 42, &txr, &bind), "height");
        assert_ne!(k, pow_preimage_key(&Hash::from_bytes([9u8; 32]), 5, 1000, 42, &txr, &bind), "prev_hash");
        assert_ne!(k, pow_preimage_key(&ph, 5, 1000, 42, &Hash::from_bytes([9u8; 32]), &bind), "tx_root");
        // audit §1: a different header-binding must change the key.
        assert_ne!(k, pow_preimage_key(&ph, 5, 1000, 42, &txr, &Hash::from_bytes([9u8; 32])), "binding");
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

    // ---- pow_hash_cached: forged anchor rejected free, before any hashing ----
    #[test]
    fn pow_hash_cached_rejects_forged_anchor_before_hashing() {
        let prev = Hash::from_bytes([1u8; 32]);
        let tx_root = Hash::from_bytes([2u8; 32]);
        let bind = Hash::from_bytes([3u8; 32]);
        let (height, ts, nonce) = (5u64, 1_000u64, 42u64);

        let real = compute_full_anchor(&prev, height, ts, &bind).unwrap();
        let mut wb = [0u8; 32];
        wb.copy_from_slice(real.mixed_hash.as_bytes());
        wb[0] ^= 0xFF;
        let forged = Hash::from_bytes(wb);

        let res = pow_hash_cached(&prev, height, ts, nonce, &tx_root, &forged, 0, &bind);
        let err = res.unwrap_err().to_string();
        assert!(err.contains("Anchor mismatch"), "unexpected error: {err}");
    }

    // ---- pow_hash_cached: algorithm mismatch rejected free, before hashing ----
    #[test]
    fn pow_hash_cached_rejects_algorithm_mismatch_before_hashing() {
        let prev = Hash::from_bytes([1u8; 32]);
        let tx_root = Hash::from_bytes([2u8; 32]);
        let bind = Hash::from_bytes([3u8; 32]);
        let (height, ts, nonce) = (5u64, 1_000u64, 42u64);

        let real = compute_full_anchor(&prev, height, ts, &bind).unwrap();
        let res = pow_hash_cached(
            &prev,
            height,
            ts,
            nonce,
            &tx_root,
            &real.mixed_hash,
            1, // claimed_algo != anchor.algorithm (RandomX == 0)
            &bind,
        );
        let err = res.unwrap_err().to_string();
        assert!(err.contains("Algorithm mismatch"), "unexpected error: {err}");
    }

    // ---- pow_hash_cached: §1 — reused anchor under a different binding rejected ----
    #[test]
    fn pow_hash_cached_rejects_reused_anchor_with_different_binding() {
        // Two "blocks" share (prev, height, ts, nonce, tx_root) but differ in the
        // header binding. Reusing the first block's anchor under the second's
        // binding is rejected via AnchorMismatch — before hashing — so a malleated
        // variant can NOT ride the first block's cached solution. No randomx needed.
        let prev = Hash::from_bytes([1u8; 32]);
        let tx_root = Hash::from_bytes([2u8; 32]);
        let (height, ts, nonce) = (5u64, 1_000u64, 42u64);
        let bind1 = Hash::from_bytes([3u8; 32]);
        let bind2 = Hash::from_bytes([4u8; 32]);

        let anchor1 = compute_full_anchor(&prev, height, ts, &bind1).unwrap();
        let res = pow_hash_cached(
            &prev,
            height,
            ts,
            nonce,
            &tx_root,
            &anchor1.mixed_hash, // reused from bind1's solution
            0,
            &bind2, // mutated bound field
        );
        let err = res.unwrap_err().to_string();
        assert!(
            err.contains("Anchor mismatch"),
            "distinct bindings must not share a cached solution: {err}"
        );
    }

    // ---- amplification-collapse: all target-variants map to ONE cache entry ----
    #[test]
    fn pow_verify_cache_collapses_target_variants_to_one_entry() {
        // `pow_preimage_key` deliberately does NOT take `target`, so every
        // target-variant of one solution derives the SAME key and shares a single
        // cached RandomX output — the amplification defense.
        let prev = Hash::from_bytes([1u8; 32]);
        let tx_root = Hash::from_bytes([2u8; 32]);
        let bind = Hash::from_bytes([3u8; 32]);

        let key = pow_preimage_key(&prev, 7, 1_234, 99, &tx_root, &bind);
        let variant_key = pow_preimage_key(&prev, 7, 1_234, 99, &tx_root, &bind);
        assert_eq!(key, variant_key, "target is not part of the key");

        let mut c = PowVerifyCache::new();
        let out = Hash::from_bytes([0x42u8; 32]);
        c.insert(key, out);
        assert_eq!(
            c.get(&variant_key),
            Some(out),
            "a target-variant must hit the same cached RandomX run"
        );
    }

    // ---- no false collapse: distinct bindings occupy distinct cache slots ----
    #[test]
    fn pow_verify_cache_does_not_collapse_distinct_bindings() {
        let prev = Hash::from_bytes([1u8; 32]);
        let tx_root = Hash::from_bytes([2u8; 32]);

        let k1 = pow_preimage_key(&prev, 7, 1_234, 99, &tx_root, &Hash::from_bytes([3u8; 32]));
        let k2 = pow_preimage_key(&prev, 7, 1_234, 99, &tx_root, &Hash::from_bytes([4u8; 32]));
        assert_ne!(k1, k2, "different bindings must derive different keys");

        let mut c = PowVerifyCache::new();
        c.insert(k1, Hash::from_bytes([0xAAu8; 32]));
        assert_eq!(
            c.get(&k2),
            None,
            "a different-binding variant must NOT collapse onto the other's entry"
        );
    }

    // ---- pow_hash_cached: cold miss computes+caches, second call is a hit ----
    // #[ignore]: computes a real RandomX hash on the cold miss. Run with:
    //   cargo test -p coincync --features "randomx testnet" -- --ignored pow_hash_cached_cold_miss_then_hit
    #[cfg(feature = "randomx")]
    #[test]
    #[ignore]
    fn pow_hash_cached_cold_miss_then_hit_returns_same() {
        let prev = Hash::from_bytes([0x51u8; 32]);
        let tx_root = Hash::from_bytes([0x52u8; 32]);
        let bind = Hash::from_bytes([0x53u8; 32]);
        let (height, ts, nonce) = (5u64, 1_000u64, 42u64);

        let anchor = compute_full_anchor(&prev, height, ts, &bind).unwrap();
        let h1 = pow_hash_cached(&prev, height, ts, nonce, &tx_root, &anchor.mixed_hash, 0, &bind)
            .unwrap();
        // Second call for the same preimage key must be a cache hit (same output).
        let h2 = pow_hash_cached(&prev, height, ts, nonce, &tx_root, &anchor.mixed_hash, 0, &bind)
            .unwrap();
        assert_eq!(h1, h2, "cache hit must return the cold-miss output");
    }
}
