//! Verification-strategy slot for block range proofs — a connector seam.
//!
//! A single swap point, [`active_strategy`], selects HOW a set of range proofs is
//! verified. The default is [`RangeProofStrategy::SerialCached`] — today's
//! behaviour (per-item, cache-first), so wiring this seam in is **inert /
//! historical** until a non-default strategy is explicitly enabled behind a
//! reviewed gate. Every strategy MUST return the identical accept/reject verdict
//! as `SerialCached`; a strategy that diverges is a consensus split, so the
//! determinism contract is property-tested (`strategies_agree_with_ground_truth`).
//!
//! NOT wired into consensus. `verify_output_range_proofs` stays the per-tx path;
//! this is where a block-level batch/parallel verify would plug in **once proven
//! on regtest + benchmarked**. The cache-aware benchmark showed batch wins only on
//! cache-MISSES and loses ~500× on cache-HITS (the sync hot path), so the only
//! sound batch form is [`RangeProofStrategy::BatchOnMiss`]: cache-first, then batch
//! exactly the misses. It composes the cache with batch instead of replacing it.
//!
//! Same single-swap-point discipline as `consensus::shielded_connector::backend`.

use crate::crypto::{
    global_cache, proof_cache_key, verify_range_proofs, verify_range_proofs_batch,
    PedersenCommitment, RangeProof,
};

/// A range-proof item: a commitment set and its (aggregated) proof — the unit a
/// block validator would hand the strategy (one per non-coinbase tx).
pub type RangeItem<'a> = (&'a [PedersenCommitment], &'a RangeProof);

/// Pluggable range-proof verification strategy. Each must be verdict-identical to
/// `SerialCached` (determinism contract).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RangeProofStrategy {
    /// Historical default: per-item, cache-first. The baseline every other
    /// strategy is proven equal to.
    SerialCached,
    /// Cache-first, then batch the cache-MISSES in one BP+ multiexp — the only
    /// batch form that doesn't regress the warm/sync path (see module docs).
    BatchOnMiss,
}

/// THE SWAP POINT. Returns the historical default. Flipping it is a consensus
/// change requiring review + a re-soak; nothing selects a non-default strategy on
/// any current build.
#[inline]
pub fn active_strategy() -> RangeProofStrategy {
    RangeProofStrategy::SerialCached
}

/// The bulletproof-cache key for an item, identical to `verify_output_range_proofs`.
fn cache_key_for(item: &RangeItem) -> [u8; 32] {
    let commitment_bytes: Vec<u8> = item.0.iter().flat_map(|c| c.to_bytes()).collect();
    proof_cache_key(&item.1.data, &commitment_bytes)
}

/// Verify a whole set of range-proof items under `strategy`. Returns `true` iff
/// EVERY item verifies (all-or-nothing — a block is invalid if any range proof is).
pub fn verify_set(strategy: RangeProofStrategy, items: &[RangeItem]) -> bool {
    match strategy {
        RangeProofStrategy::SerialCached => items.iter().all(|it| verify_one_cached(it)),
        RangeProofStrategy::BatchOnMiss => verify_batch_on_miss(items),
    }
}

/// Verify a set under the active (swap-point) strategy.
pub fn verify_active(items: &[RangeItem]) -> bool {
    verify_set(active_strategy(), items)
}

/// One item, cache-first — the per-item path `verify_output_range_proofs` uses.
fn verify_one_cached(item: &RangeItem) -> bool {
    let key = cache_key_for(item);
    let cache = global_cache();
    if let Some(hit) = cache.check_bulletproof(&key) {
        return hit;
    }
    let valid = verify_range_proofs(item.0, item.1);
    cache.cache_bulletproof(key, valid);
    valid
}

/// Cache-first for the whole set, then batch the misses in one multiexp. Verdict-
/// identical to `SerialCached`: cache holds only correct positives, so a hit is a
/// proven-valid item; every not-yet-seen (hence possibly-invalid) item is a miss
/// and goes into the batch, which fails the whole set if any miss is invalid.
fn verify_batch_on_miss(items: &[RangeItem]) -> bool {
    let cache = global_cache();
    let mut miss_keys: Vec<[u8; 32]> = Vec::new();
    let mut miss_items: Vec<RangeItem> = Vec::new();
    for it in items {
        let key = cache_key_for(it);
        match cache.check_bulletproof(&key) {
            Some(true) => {}              // cached-valid → free
            Some(false) => return false,  // defensive: the cache only stores positives
            None => {
                miss_keys.push(key);
                miss_items.push(*it);
            }
        }
    }
    if miss_items.is_empty() {
        return true; // every item was a cache hit — nothing to batch
    }
    if !verify_range_proofs_batch(&miss_items) {
        return false; // a miss failed → set invalid; do NOT cache failures
    }
    for key in miss_keys {
        cache.cache_bulletproof(key, true);
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::{create_aggregated_range_proof, BlindingFactor};
    use crate::primitives::Amount;
    use proptest::prelude::*;
    use rand::rngs::OsRng;

    #[test]
    fn default_strategy_is_serial_cached() {
        assert_eq!(active_strategy(), RangeProofStrategy::SerialCached);
    }

    proptest! {
        #![proptest_config(ProptestConfig { cases: 16, ..ProptestConfig::default() })]

        /// Determinism contract: on every random set (valid or with a corrupted
        /// proof), BOTH strategies return the uncached ground-truth verdict. Items
        /// are freshly generated each case, so BatchOnMiss sees all cache-misses
        /// and actually exercises the batch path.
        #[test]
        fn strategies_agree_with_ground_truth(
            specs in prop::collection::vec(
                prop::collection::vec(0u64..1_000_000u64, 1..=2usize),
                1..=5usize,
            ),
            corrupt in prop::option::of(0usize..8usize),
        ) {
            let mut rng = OsRng;
            let mut owned: Vec<(Vec<PedersenCommitment>, RangeProof)> = Vec::new();
            for amounts in &specs {
                let blindings: Vec<BlindingFactor> =
                    amounts.iter().map(|_| BlindingFactor::random(&mut rng)).collect();
                let commitments: Vec<PedersenCommitment> = amounts
                    .iter()
                    .zip(&blindings)
                    .map(|(a, b)| PedersenCommitment::commit(*a, b))
                    .collect();
                let amts: Vec<Amount> = amounts.iter().map(|a| Amount::from_atomic(*a)).collect();
                let proof = create_aggregated_range_proof(&amts, &blindings, &mut rng).unwrap();
                owned.push((commitments, proof));
            }
            if let Some(i) = corrupt {
                let idx = i % owned.len();
                if let Some(b) = owned[idx].1.data.last_mut() {
                    *b ^= 0x01;
                }
            }
            let items: Vec<(&[PedersenCommitment], &RangeProof)> =
                owned.iter().map(|(c, p)| (&c[..], p)).collect();

            // Uncached per-item aggregated verify = the ground truth.
            let ground = items.iter().all(|it| verify_range_proofs(it.0, it.1));
            // BatchOnMiss on cold items (fresh → all misses → batch path exercised).
            prop_assert_eq!(verify_set(RangeProofStrategy::BatchOnMiss, &items), ground);
            // SerialCached — same verdict (may now hit the cache populated above).
            prop_assert_eq!(verify_set(RangeProofStrategy::SerialCached, &items), ground);
        }
    }
}
