//! Proof-shares, the canonical K-lowest set, and the reward mechanisms.
//!
//! A **proof-share** is a RandomX sample an owner found below the gossip
//! threshold `tau_share` (`bobtail-spec.md` §3). A block is built from the `K`
//! lowest shares in the network's gossiped pool. This module holds the pure
//! logic that decides *which* shares form a block and *who* is paid — the parts
//! the design's grinding-resistance proof (`bobtail-spec.md` §6) pins down.
//!
//! No RandomX here: the verifier recomputes each share's hash via the existing
//! `compute_pow_hash` and hands us the resolved `(share, hash)` pairs.

use super::kmean::k_mean_meets_target;
use crate::primitives::{hash_domain, Hash, PublicKey};
use borsh::{BorshDeserialize, BorshSerialize};
use serde::{Deserialize, Serialize};
use std::cmp::Ordering;
use std::collections::HashSet;

/// Domain tag for the fallback single-winner lottery (see [`lottery_index`]).
const BOBTAIL_LOTTERY_DOMAIN: &[u8] = b"coincync/bobtail/lottery/v1";

/// The gossip unit: a RandomX sample's owner and nonce. `h` is recomputed by
/// verifiers as `RandomX(prev_hash || miner_pubkey || nonce)`, so it is not
/// carried on the wire (`bobtail-spec.md` §3).
#[derive(
    Clone, Debug, PartialEq, Eq, Serialize, Deserialize, BorshSerialize, BorshDeserialize,
)]
pub struct ShareProof {
    pub miner_pubkey: PublicKey,
    pub nonce: u64,
}

/// A proof-share paired with the RandomX hash the verifier recomputed for it.
/// This is the unit the consensus logic below reasons about.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ResolvedShare {
    pub share: ShareProof,
    pub hash: Hash,
}

impl ResolvedShare {
    pub fn new(miner_pubkey: PublicKey, nonce: u64, hash: Hash) -> Self {
        Self {
            share: ShareProof {
                miner_pubkey,
                nonce,
            },
            hash,
        }
    }

    /// Owner identity used for set membership (pubkey bytes + nonce uniquely
    /// name a share; a given owner may hold several distinct shares).
    fn ident(&self) -> ([u8; 32], u64) {
        (*self.share.miner_pubkey.as_bytes(), self.share.nonce)
    }
}

/// The canonical total-order key: hash (big-endian numeric, so "lowest" = best
/// PoW), then owner pubkey, then nonce. This is the single source of truth for
/// "lower" everywhere in the module — [`canonical_k_lowest`] sorts by it and
/// [`omits_lower_share`] compares against it — so two shares with the *same*
/// hash still have a strict, deterministic order and cannot be swapped to steer
/// the set (the equal-hash grinding gap a hash-only comparison would leave open).
fn canon_key(s: &ResolvedShare) -> (Hash, [u8; 32], u64) {
    (s.hash, *s.share.miner_pubkey.as_bytes(), s.share.nonce)
}

/// Total order over shares, by [`canon_key`]. Deterministic across nodes, so
/// every validator derives the same canonical set and the same tie-breaks.
fn cmp_canonical(a: &ResolvedShare, b: &ResolvedShare) -> Ordering {
    canon_key(a).cmp(&canon_key(b))
}

/// The canonical `K`-lowest shares of `pool`, ascending (the block's `shares`
/// field, `bobtail-spec.md` §4). If `pool` holds fewer than `k`, returns all of
/// them sorted. Deduplicates identical shares (same owner + nonce) first so a
/// replayed gossip entry can't occupy two slots.
pub fn canonical_k_lowest(pool: &[ResolvedShare], k: usize) -> Vec<ResolvedShare> {
    let mut seen = HashSet::new();
    let mut v: Vec<ResolvedShare> = pool
        .iter()
        .filter(|s| seen.insert(s.ident()))
        .cloned()
        .collect();
    v.sort_by(cmp_canonical);
    v.truncate(k);
    v
}

/// The core anti-grinding predicate — `bobtail-spec.md` §5.5 / §6.2.
///
/// Returns `true` (⇒ the block is INVALID) iff the validator's `pool` contains a
/// share strictly lower than the block's largest included share (`h_{K-1}`) that
/// the block omitted. Enforcing "not `omits_lower_share`" forces every block to
/// carry the globally `K`-lowest set, which collapses the proposer's set-choice
/// freedom to zero (the grinding vector proven in §6): with the set fixed, the
/// equal split cannot be padded and the lottery index cannot be resampled.
///
/// `pool` is the validator's own gossiped view; an honestly-withheld *own* share
/// simply isn't in anyone's pool and costs its owner the slot (§6.3.1), it does
/// not make a block that omits a *seen* lower share valid.
///
/// The comparison is over the full [`canon_key`] total order, not hash alone: a
/// share that ties the block's greatest included share on hash but sorts below
/// it on (pubkey, nonce) is still a lower *canonical* share, and omitting it is
/// still grinding. A hash-only check would let a proposer swap between
/// equal-hash shares to steer the proposer slot / lottery winner.
pub fn omits_lower_share(chosen: &[ResolvedShare], pool: &[ResolvedShare]) -> bool {
    // The block's canonical-greatest included share (its "h_{K-1}" slot).
    let Some(max_key) = chosen.iter().map(canon_key).max() else {
        // An empty chosen set carries no PoW at all; "omits a lower share" is
        // not the rule that rejects it (the k-mean bar does). Not an omission.
        return false;
    };
    let included: HashSet<([u8; 32], u64)> = chosen.iter().map(|s| s.ident()).collect();
    pool.iter()
        .any(|p| canon_key(p) < max_key && !included.contains(&p.ident()))
}

/// Full PoW-axis validity of a block's share set — the single predicate the
/// Enforce path checks (`bobtail-spec.md` §5): exactly `k` distinct shares, the
/// canonical `k`-lowest (no canonically-lower seen share omitted, §5.5/§6), and
/// the k-mean clears `τ = T·(K+1)/2` (§5.4). Pure: the caller resolves each
/// share's RandomX hash (via `compute_pow_hash`) and that every share is below
/// `tau_share` before calling; this does not re-derive RandomX.
pub fn block_shares_valid(
    chosen: &[ResolvedShare],
    pool: &[ResolvedShare],
    k: usize,
    target: &Hash,
) -> bool {
    if chosen.len() != k {
        return false;
    }
    // No duplicate slots (same owner + nonce used twice).
    let mut idents = HashSet::with_capacity(k);
    if !chosen.iter().all(|s| idents.insert(s.ident())) {
        return false;
    }
    if omits_lower_share(chosen, pool) {
        return false;
    }
    let hashes: Vec<Hash> = chosen.iter().map(|s| s.hash).collect();
    k_mean_meets_target(&hashes, target)
}

/// Grinding-resistant single-winner index for the **fallback** one-output
/// coinbase (`bobtail-spec.md` §8 fallback, §6.2): `idx = H(canonical set) mod K`.
///
/// Because the set is forced to the canonical `K`-lowest (`omits_lower_share`
/// enforced), `idx` is a function of a fixed set — the proposer cannot resample
/// it without doing fresh sub-`tau_share` work to change the set, which is
/// EV-negative (§6.3.2). The digest commits to each slot's `(hash, pubkey,
/// nonce)` in canonical order and is reduced modulo `K` over the full 256 bits.
///
/// Callers must pass the set already in canonical order (as
/// [`canonical_k_lowest`] returns it); the index refers into that ordering.
pub fn lottery_index(canonical_set: &[ResolvedShare]) -> usize {
    let n = canonical_set.len();
    if n == 0 {
        return 0;
    }
    let digest = lottery_digest(canonical_set);
    let d = super::biguint::U512::from_big_endian(digest.as_bytes());
    (d % super::biguint::U512::from(n as u64)).low_u64() as usize
}

/// Domain-separated digest the lottery index is reduced from. Commits to every
/// slot's `(hash, pubkey, nonce)` in canonical order, so any change to the set
/// changes the digest (hence the index) — the binding §6.2 relies on.
fn lottery_digest(canonical_set: &[ResolvedShare]) -> Hash {
    let mut data = Vec::with_capacity(canonical_set.len() * (32 + 32 + 8));
    for s in canonical_set {
        data.extend_from_slice(s.hash.as_bytes());
        data.extend_from_slice(s.share.miner_pubkey.as_bytes());
        data.extend_from_slice(&s.share.nonce.to_le_bytes());
    }
    hash_domain(BOBTAIL_LOTTERY_DOMAIN, &data)
}

/// Safety factor for the retained share pool: a node keeps only the lowest
/// `BOBTAIL_POOL_SAFETY · C_SHARE · K` shares per parent (see [`max_pool_size`]).
/// `4` leaves ample headroom above the expected `C_SHARE·K = 3K` arrivals so a
/// legitimate burst is never evicted, while still bounding memory.
pub const BOBTAIL_POOL_SAFETY: usize = 4;

/// Cap on shares retained per parent. Only the `K`-lowest can ever enter a block,
/// so retaining `SAFETY · C_SHARE · K` is far more than enough; anything above
/// the cap is evicted. This bounds memory and **neutralizes pool-flooding**: a
/// spam share above the retained floor is dropped on arrival — and it still cost
/// the spammer real sub-`tau_share` RandomX work to produce, so the flood is
/// work-bounded and pointless.
pub fn max_pool_size(k: usize, c_share: u64) -> usize {
    BOBTAIL_POOL_SAFETY.saturating_mul(c_share as usize).saturating_mul(k)
}

/// Evict all but the canonically-lowest `cap` shares from `pool` (deduplicating
/// by identity first). Because `cap ≫ K`, the true `K`-lowest always survive, so
/// canonicality (`canonical_k_lowest` / `omits_lower_share`) is preserved while
/// the pool's memory footprint and flood exposure stay bounded. A no-op when the
/// pool is already within `cap`.
pub fn retain_lowest(pool: &mut Vec<ResolvedShare>, cap: usize) {
    let mut seen = HashSet::with_capacity(pool.len());
    pool.retain(|s| seen.insert(s.ident()));
    if pool.len() > cap {
        pool.sort_by(cmp_canonical);
        pool.truncate(cap);
    }
}

/// Equal split of `reward` across `count` slots (`bobtail-spec.md` §8 / §11).
///
/// Returns one amount per slot, in canonical order, summing to **exactly**
/// `reward` (emission-exact — the coinbase must not create or destroy value).
/// The indivisible remainder `reward % count` is assigned to slot 0 — the
/// proposer (global minimum) — a deterministic, consensus-agreed rule every
/// validator reproduces. Owner-level dedup (one coinbase output per distinct
/// owner) sums the slots an owner holds; that grouping lives in the coinbase
/// builder, not here.
pub fn equal_split(reward: u64, count: usize) -> Vec<u64> {
    if count == 0 {
        return Vec::new();
    }
    let n = count as u64;
    let base = reward / n;
    let remainder = reward % n;
    let mut out = vec![base; count];
    out[0] += remainder; // proposer absorbs the indivisible unit(s)
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pk(b: u8) -> PublicKey {
        PublicKey::from_bytes([b; 32])
    }
    fn hh(b0: u8, b1: u8) -> Hash {
        let mut b = [0u8; 32];
        b[0] = b0;
        b[1] = b1;
        Hash::from_bytes(b)
    }
    fn rs(owner: u8, nonce: u64, b0: u8, b1: u8) -> ResolvedShare {
        ResolvedShare::new(pk(owner), nonce, hh(b0, b1))
    }

    #[test]
    fn canonical_picks_the_k_lowest_ascending() {
        let pool = vec![
            rs(1, 0, 0x30, 0),
            rs(2, 0, 0x10, 0),
            rs(3, 0, 0x20, 0),
            rs(4, 0, 0x05, 0),
        ];
        let set = canonical_k_lowest(&pool, 3);
        let firsts: Vec<u8> = set.iter().map(|s| s.hash.as_bytes()[0]).collect();
        assert_eq!(firsts, vec![0x05, 0x10, 0x20], "K-lowest, ascending");
    }

    #[test]
    fn canonical_dedups_replayed_shares() {
        let dup = rs(1, 7, 0x10, 0);
        let pool = vec![dup.clone(), dup.clone(), rs(2, 0, 0x20, 0)];
        let set = canonical_k_lowest(&pool, 2);
        assert_eq!(set.len(), 2);
        assert_ne!(set[0].ident(), set[1].ident(), "no duplicate slot");
    }

    #[test]
    fn canonical_tiebreak_is_deterministic() {
        // Equal hashes → broken by (pubkey, nonce); two orders of the same pool
        // must yield the same canonical set.
        let a = rs(1, 0, 0x10, 0);
        let b = rs(2, 0, 0x10, 0);
        let s1 = canonical_k_lowest(&[a.clone(), b.clone()], 2);
        let s2 = canonical_k_lowest(&[b, a], 2);
        assert_eq!(s1, s2);
    }

    /// §5.5: a block omitting a seen lower share is rejected; the exact
    /// canonical set is accepted.
    #[test]
    fn omission_of_a_lower_seen_share_is_caught() {
        let pool = vec![
            rs(1, 0, 0x05, 0), // lowest
            rs(2, 0, 0x10, 0),
            rs(3, 0, 0x20, 0),
        ];
        // Honest block = canonical K-lowest.
        let honest = canonical_k_lowest(&pool, 2); // {0x05, 0x10}
        assert!(
            !omits_lower_share(&honest, &pool),
            "canonical set must be accepted",
        );

        // Grinding attempt: swap the 0x05 slot out for the higher 0x20, trying a
        // different set (and thus a different lottery idx / slot mix).
        let grind = vec![rs(2, 0, 0x10, 0), rs(3, 0, 0x20, 0)]; // omits 0x05 < 0x20
        assert!(
            omits_lower_share(&grind, &pool),
            "omitting a seen lower share must be rejected",
        );
    }

    /// An honestly-withheld OWN share (not in anyone's pool) does not retroactively
    /// invalidate a block — the owner just loses that slot (§6.3.1).
    #[test]
    fn withheld_own_share_absent_from_pool_is_not_an_omission() {
        let pool = vec![rs(2, 0, 0x10, 0), rs(3, 0, 0x20, 0)];
        let chosen = canonical_k_lowest(&pool, 2);
        assert!(!omits_lower_share(&chosen, &pool));
    }

    /// The equal-hash grinding gap: two shares share a hash but differ by owner.
    /// The canonical k-lowest (k=1) is the lower-pubkey one; picking the OTHER
    /// equal-hash share (to steer the proposer / lottery) must be rejected even
    /// though the hashes are equal — the check is over the full canonical order,
    /// not hash alone.
    #[test]
    fn equal_hash_tiebreak_omission_is_caught() {
        let a = rs(1, 0, 0x10, 0); // canonically lower (pubkey 1)
        let b = rs(2, 0, 0x10, 0); // same hash, pubkey 2
        let pool = vec![a.clone(), b.clone()];

        assert_eq!(canonical_k_lowest(&pool, 1), vec![a.clone()], "A is canonical");
        assert!(
            !omits_lower_share(&[a], &pool),
            "the canonical equal-hash share is accepted",
        );
        assert!(
            omits_lower_share(&[b], &pool),
            "picking the higher equal-hash share omits a canonically-lower one",
        );
    }

    #[test]
    fn block_shares_valid_accepts_the_canonical_clearing_set() {
        let target = hh(0x40, 0); // lenient enough that low samples clear τ
        let pool = vec![rs(1, 0, 0x05, 0), rs(2, 0, 0x08, 0), rs(3, 0, 0x30, 0)];
        let chosen = canonical_k_lowest(&pool, 2); // {0x05, 0x08}
        assert!(block_shares_valid(&chosen, &pool, 2, &target));
    }

    #[test]
    fn block_shares_valid_rejects_wrong_k_dupes_omission_and_overbar() {
        let target = hh(0x40, 0);
        let pool = vec![rs(1, 0, 0x05, 0), rs(2, 0, 0x08, 0), rs(3, 0, 0x30, 0)];

        // wrong length
        assert!(!block_shares_valid(&canonical_k_lowest(&pool, 1), &pool, 2, &target));

        // duplicate slot (same share twice)
        let dup = rs(1, 0, 0x05, 0);
        assert!(!block_shares_valid(&[dup.clone(), dup], &pool, 2, &target));

        // omits a seen lower share (grinding set {0x08, 0x30} drops 0x05)
        let grind = vec![rs(2, 0, 0x08, 0), rs(3, 0, 0x30, 0)];
        assert!(!block_shares_valid(&grind, &pool, 2, &target));

        // canonical set, but target too hard → k-mean over τ
        let hard = hh(0x01, 0);
        let highs = vec![rs(4, 0, 0x80, 0), rs(5, 0, 0x90, 0)];
        assert!(!block_shares_valid(&highs, &highs, 2, &hard));
    }

    /// With the canonical set FIXED, the lottery index is deterministic and
    /// reproducible — the property §6.2 relies on (no resampling without
    /// changing the set).
    #[test]
    fn lottery_index_is_deterministic_and_in_range() {
        let set = canonical_k_lowest(
            &[rs(1, 0, 0x05, 0), rs(2, 0, 0x10, 0), rs(3, 0, 0x20, 0)],
            3,
        );
        let i1 = lottery_index(&set);
        let i2 = lottery_index(&set);
        assert_eq!(i1, i2, "deterministic");
        assert!(i1 < set.len(), "index in range");
    }

    /// Changing the set (what a grinder would need to do) changes the committed
    /// digest the index is drawn from — so the index is genuinely bound to the
    /// whole set, not a free parameter. Tested at the digest level: an index
    /// collision over a small K is chance, a digest collision is negligible.
    #[test]
    fn lottery_digest_binds_to_the_set() {
        let set_a = canonical_k_lowest(&[rs(1, 0, 0x05, 0), rs(2, 0, 0x10, 0)], 2);
        let set_b = canonical_k_lowest(&[rs(1, 0, 0x05, 0), rs(2, 1, 0x10, 0)], 2);
        assert_ne!(
            lottery_digest(&set_a),
            lottery_digest(&set_b),
            "a one-share change must change the committed digest",
        );
    }

    /// The core invariant linking the two functions: the canonical `k`-lowest of
    /// a pool, by construction, never omits a canonically-lower share of that
    /// pool. If this ever fails, `canonical_k_lowest` and `omits_lower_share`
    /// have drifted apart and the anti-grinding guarantee is broken.
    #[test]
    fn canonical_set_never_omits_a_lower_share() {
        let pool: Vec<ResolvedShare> = (0..12u8)
            .map(|i| rs(i + 1, i as u64, i.wrapping_mul(7), i))
            .collect();
        for k in 1..=pool.len() {
            let set = canonical_k_lowest(&pool, k);
            assert!(
                !omits_lower_share(&set, &pool),
                "k={k}: the canonical set must never omit a lower share",
            );
        }
    }

    #[test]
    fn retain_lowest_keeps_the_k_lowest_and_caps() {
        let mut pool: Vec<ResolvedShare> =
            (0..50u8).map(|i| rs(i + 1, i as u64, i, 0)).collect();
        let cap = 10;
        retain_lowest(&mut pool, cap);
        assert_eq!(pool.len(), cap, "pool capped to `cap`");
        // The true 3-lowest (hashes 0x00,0x01,0x02) must survive eviction.
        let k3: Vec<u8> = canonical_k_lowest(&pool, 3)
            .iter()
            .map(|s| s.hash.as_bytes()[0])
            .collect();
        assert_eq!(k3, vec![0, 1, 2], "the K-lowest are never evicted");
    }

    #[test]
    fn retain_lowest_dedups_even_under_cap() {
        let a = rs(1, 0, 0x10, 0);
        let mut pool = vec![a.clone(), a.clone(), rs(2, 0, 0x20, 0)];
        retain_lowest(&mut pool, 100);
        assert_eq!(pool.len(), 2, "replayed share deduped even when under cap");
    }

    #[test]
    fn max_pool_size_has_headroom_over_expected_arrivals() {
        use super::super::{BOBTAIL_C_SHARE, BOBTAIL_K};
        let cap = max_pool_size(BOBTAIL_K, BOBTAIL_C_SHARE);
        let expected = BOBTAIL_C_SHARE as usize * BOBTAIL_K; // 3K
        assert!(cap > expected, "cap must exceed the expected C_SHARE·K arrivals");
    }

    #[test]
    fn equal_split_is_emission_exact() {
        // 100 across 7 slots: 14 each, remainder 2 to the proposer.
        let split = equal_split(100, 7);
        assert_eq!(split.len(), 7);
        assert_eq!(split.iter().sum::<u64>(), 100, "must sum to exactly reward");
        assert_eq!(split[0], 14 + 2, "proposer absorbs remainder");
        assert!(split[1..].iter().all(|&a| a == 14));
    }

    #[test]
    fn equal_split_divides_evenly_when_it_can() {
        let split = equal_split(60, 20);
        assert!(split.iter().all(|&a| a == 3));
        assert_eq!(split.iter().sum::<u64>(), 60);
    }

    #[test]
    fn equal_split_zero_count_is_empty() {
        assert!(equal_split(100, 0).is_empty());
    }
}
