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
//! ## Matching the per-tx path exactly (two consensus-correctness requirements)
//!
//! 1. **Verdict oracle = `verify_range_proofs_dispatch(_, _, height)`.** Consensus
//!    gates a proof by BOTH its version byte and the activation height
//!    (`verify_output_range_proofs` → `verify_range_proofs_dispatch`), so this seam
//!    threads `height` through every entry point and verifies through `dispatch`,
//!    never the raw `verify_range_proofs`. `BatchOnMiss` additionally refuses any
//!    miss whose version `dispatch` would reject at that height, so the batch can
//!    never accept a proof the per-item path rejects.
//! 2. **Cache key = the on-wire bytes.** `verify_output_range_proofs` keys the
//!    bulletproof cache on `tx.range_proof` — the proof's canonical borsh bytes
//!    (`RangeProof::try_to_bytes`). To share cache entries with it (the whole point
//!    of cache-first), this seam keys on the SAME on-wire bytes, carried alongside
//!    the decoded proof in [`RangeItem`]. We carry the source-of-truth bytes rather
//!    than re-serialize the decoded proof: identical for canonical input, and there
//!    is nothing to drift.
//!
//! The cache key deliberately omits `height` — to stay byte-identical to the per-tx
//! path. That is sound only because the version→verdict map is height-stable
//! (`BULLETPROOFS_PLUS_HEIGHT = 0`, BP+ active from genesis): a given proof's verdict
//! does not change with height. This is a PRE-EXISTING property of the per-tx cache,
//! not introduced here; if that constant ever moves on some network, BOTH caches
//! must be revisited together.
//!
//! Same single-swap-point discipline as `consensus::shielded_connector::backend`.

use crate::constants::{BULLETPROOFS_PLUS_HEIGHT, RANGE_PROOF_VERSION_BP_PLUS};
use crate::crypto::{
    global_cache, proof_cache_key, verify_range_proofs_batch, verify_range_proofs_dispatch,
    PedersenCommitment, RangeProof,
};

/// A range-proof item the way a block validator holds it: a commitment set, the
/// decoded (aggregated) proof, and the proof's **on-wire bytes** (`tx.range_proof`,
/// i.e. `RangeProof::try_to_bytes`) — the exact bytes `verify_output_range_proofs`
/// keys the cache on. One per non-coinbase tx.
pub type RangeItem<'a> = (&'a [PedersenCommitment], &'a RangeProof, &'a [u8]);

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

/// The bulletproof-cache key for an item: the proof's on-wire bytes + the
/// commitment bytes — byte-identical to `verify_output_range_proofs`'s key, so the
/// two paths share cache entries.
fn cache_key_for(item: &RangeItem) -> [u8; 32] {
    let commitment_bytes: Vec<u8> = item.0.iter().flat_map(|c| c.to_bytes()).collect();
    proof_cache_key(item.2, &commitment_bytes)
}

/// Verify a whole set of range-proof items under `strategy`, at `height`. Returns
/// `true` iff EVERY item verifies (all-or-nothing — a block is invalid if any range
/// proof is). `height` is the connecting block's height, used for the exact
/// version+height gate consensus applies.
pub fn verify_set(strategy: RangeProofStrategy, items: &[RangeItem], height: u64) -> bool {
    match strategy {
        RangeProofStrategy::SerialCached => items.iter().all(|it| verify_one_cached(it, height)),
        RangeProofStrategy::BatchOnMiss => verify_batch_on_miss(items, height),
    }
}

/// Verify a set under the active (swap-point) strategy, at `height`.
pub fn verify_active(items: &[RangeItem], height: u64) -> bool {
    verify_set(active_strategy(), items, height)
}

/// One item, cache-first — the per-item path `verify_output_range_proofs` uses.
/// The uncached verdict is the height-gated `verify_range_proofs_dispatch`.
fn verify_one_cached(item: &RangeItem, height: u64) -> bool {
    let key = cache_key_for(item);
    let cache = global_cache();
    if let Some(hit) = cache.check_bulletproof(&key) {
        return hit;
    }
    let valid = verify_range_proofs_dispatch(item.0, item.1, height);
    cache.cache_bulletproof(key, valid); // cache stores positives only (drops false)
    valid
}

/// Cache-first for the whole set, then batch the misses in one multiexp. Verdict-
/// identical to `SerialCached`: cache holds only correct positives, so a hit is a
/// proven-valid item; every not-yet-seen (hence possibly-invalid) item is a miss
/// and goes into the batch, which fails the whole set if any miss is invalid.
///
/// The batch multiexp (`verify_range_proofs_batch`) only validates BP+ (v3) proofs,
/// so it must never see a proof `dispatch` would reject at this height:
///  - pre-activation (`height < BULLETPROOFS_PLUS_HEIGHT`) there are no BP+-eligible
///    proofs — fall back to per-item `dispatch` (no batch benefit there anyway);
///  - at/after activation, a miss whose version isn't BP+ is an immediate reject
///    (exactly what `dispatch` returns), and only the v3 misses are batched.
fn verify_batch_on_miss(items: &[RangeItem], height: u64) -> bool {
    // Pre-activation: dispatch routes v2 to the legacy serial verifier and rejects
    // v3, so there is nothing to batch — verify each item through dispatch.
    if height < BULLETPROOFS_PLUS_HEIGHT {
        return items.iter().all(|it| verify_one_cached(it, height));
    }
    let cache = global_cache();
    let mut miss_keys: Vec<[u8; 32]> = Vec::new();
    let mut miss_pairs: Vec<(&[PedersenCommitment], &RangeProof)> = Vec::new();
    for it in items {
        let key = cache_key_for(it);
        match cache.check_bulletproof(&key) {
            Some(true) => {}             // cached-valid → free
            Some(false) => return false, // defensive: the cache only stores positives
            None => {
                // dispatch rejects a non-BP+ proof at an active height, so a miss
                // with the wrong version fails the whole set — never batched.
                if it.1.version != RANGE_PROOF_VERSION_BP_PLUS {
                    return false;
                }
                miss_keys.push(key);
                miss_pairs.push((it.0, it.1));
            }
        }
    }
    if miss_pairs.is_empty() {
        return true; // every item was a cache hit — nothing to batch
    }
    if !verify_range_proofs_batch(&miss_pairs) {
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

    /// The version+height gate: a proof whose version `dispatch` would reject at
    /// `height` (here a v2 proof once BP+ is active) must be rejected by BOTH
    /// strategies, not batched. Proves `BatchOnMiss` can't accept what the per-item
    /// path rejects.
    #[test]
    fn wrong_version_for_height_rejected_by_both() {
        let mut rng = OsRng;
        let b = [BlindingFactor::random(&mut rng)];
        let c = [PedersenCommitment::commit(1_000, &b[0])];
        let mut proof =
            create_aggregated_range_proof(&[Amount::from_atomic(1_000)], &b, &mut rng).unwrap();
        // Downgrade to a pre-BP+ (legacy v2) version, which the height gate rejects
        // once BP+ (v3) is active at height 0.
        proof.version = RANGE_PROOF_VERSION_BP_PLUS - 1;
        let bytes = proof.try_to_bytes().unwrap();
        let items: Vec<RangeItem> = vec![(&c[..], &proof, &bytes[..])];

        // Sanity: dispatch itself rejects this at an active height.
        assert!(!verify_range_proofs_dispatch(&c, &proof, 0));
        assert!(!verify_set(RangeProofStrategy::SerialCached, &items, 0));
        assert!(!verify_set(RangeProofStrategy::BatchOnMiss, &items, 0));
    }

    proptest! {
        #![proptest_config(ProptestConfig { cases: 16, ..ProptestConfig::default() })]

        /// Determinism contract: on every random set (valid or with a corrupted
        /// proof), BOTH strategies return the uncached ground-truth verdict — and
        /// the ground truth is `verify_range_proofs_dispatch` at the block height,
        /// exactly what consensus uses. Items are freshly generated each case, so
        /// BatchOnMiss sees all cache-misses and actually exercises the batch path.
        #[test]
        fn strategies_agree_with_ground_truth(
            specs in prop::collection::vec(
                prop::collection::vec(0u64..1_000_000u64, 1..=2usize),
                1..=5usize,
            ),
            corrupt in prop::option::of(0usize..8usize),
        ) {
            const HEIGHT: u64 = 0; // BP+ active from genesis (BULLETPROOFS_PLUS_HEIGHT = 0)
            let mut rng = OsRng;
            let mut owned: Vec<(Vec<PedersenCommitment>, RangeProof, Vec<u8>)> = Vec::new();
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
                owned.push((commitments, proof, Vec::new()));
            }
            if let Some(i) = corrupt {
                let idx = i % owned.len();
                if let Some(b) = owned[idx].1.data.last_mut() {
                    *b ^= 0x01;
                }
            }
            // On-wire bytes AFTER any corruption, so the cache key tracks the proof
            // the validator would actually see (same as tx.range_proof).
            for row in &mut owned {
                row.2 = row.1.try_to_bytes().unwrap();
            }
            let items: Vec<RangeItem> =
                owned.iter().map(|(c, p, b)| (&c[..], p, &b[..])).collect();

            // Ground truth = the exact consensus oracle at this height.
            let ground = items.iter().all(|it| verify_range_proofs_dispatch(it.0, it.1, HEIGHT));
            // BatchOnMiss on cold items (fresh → all misses → batch path exercised).
            prop_assert_eq!(verify_set(RangeProofStrategy::BatchOnMiss, &items, HEIGHT), ground);
            // SerialCached — same verdict (may now hit the cache populated above).
            prop_assert_eq!(verify_set(RangeProofStrategy::SerialCached, &items, HEIGHT), ground);
        }
    }
}
