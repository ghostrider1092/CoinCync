//! Detection-only health telemetry for the Observe phase (`CYNC-POW-*`).
//!
//! Multi-sample PoW adds two risks that are invisible to single-sample PoW and
//! that a flag-day Enforce switch must not be flipped while blind to:
//!
//! 1. **Partial-view consensus splits** (`bobtail-spec.md` §6.3.3) — if nodes
//!    disagree on the canonical `K`-lowest set, Enforce would fork the chain.
//! 2. **Slot concentration** — one miner holding most of the `K` slots erodes
//!    the decentralization the multi-sample scheme is meant to broaden.
//!
//! This module measures both from data a node already has — purely, enforcing
//! nothing. A `CYNC-POW-*` diagnostic renders these verdicts during Observe so
//! the Enforce decision is made on evidence (view agreement across the fleet,
//! healthy slot spread, comfortable bar margin), per the fuse-box posture:
//! detection-only until a reviewed post-audit arming.

use super::kmean::bar_fill_bps;
use super::shares::{canonical_k_lowest, count_omitted_lower, ResolvedShare};
use crate::primitives::Hash;
use std::collections::{HashMap, HashSet};

/// Health of a Bobtail candidate's canonical set. Detection-only.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BobtailHealth {
    /// Distinct miners among the `K` slots (higher = more decentralized).
    pub distinct_owners: usize,
    /// Largest slot-count a single miner holds (`== K` ⇒ one miner owns the
    /// whole block; a concentration red flag).
    pub max_owner_slots: usize,
    /// How full the k-mean bar is, in basis points (`10000` = exactly at `τ`;
    /// `< 10000` = headroom below `τ`; `> 10000` = over the bar). See
    /// [`super::kmean::bar_fill_bps`].
    pub bar_fill_bps: u64,
}

/// Compute the [`BobtailHealth`] of a canonical set against the per-height
/// target. Pure; call with the set [`canonical_k_lowest`] returns.
pub fn health(canonical_set: &[ResolvedShare], target: &Hash) -> BobtailHealth {
    let mut by_owner: HashMap<[u8; 32], usize> = HashMap::new();
    for s in canonical_set {
        *by_owner
            .entry(*s.share.miner_pubkey.as_bytes())
            .or_insert(0) += 1;
    }
    let hashes: Vec<Hash> = canonical_set.iter().map(|s| s.hash).collect();
    BobtailHealth {
        distinct_owners: by_owner.len(),
        max_owner_slots: by_owner.values().copied().max().unwrap_or(0),
        bar_fill_bps: bar_fill_bps(&hashes, target),
    }
}

/// Divergence between THIS node's view and a block's claimed share set — the
/// early warning for a partial-view consensus split (`bobtail-spec.md` §6.3.3).
/// Detection-only: it never rejects a block, it reports how far the views are
/// apart so the Observe phase can size the inclusion-deadline grace and confirm
/// fleet agreement before Enforce.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ViewDivergence {
    /// This node's own canonical `K`-lowest equals the block's set exactly.
    pub agrees: bool,
    /// Shares this node holds that are canonically-lower than the block's
    /// greatest included share yet the block omitted — i.e. slots this node
    /// would REJECT under Enforce. `> 0` ⇒ a real split risk at this height.
    pub omitted_lower: usize,
    /// Shares the block used that this node has not gossiped yet — i.e. this
    /// node is behind on share propagation. High ⇒ slow/partitioned gossip.
    pub unseen_in_pool: usize,
}

/// Compare the node's local pool's canonical set to a block's claimed `block_set`.
pub fn view_divergence(
    local_pool: &[ResolvedShare],
    block_set: &[ResolvedShare],
    k: usize,
) -> ViewDivergence {
    let local_canon = canonical_k_lowest(local_pool, k);
    let local_ids: HashSet<([u8; 32], u64)> = local_canon.iter().map(|s| s.ident()).collect();
    let block_ids: HashSet<([u8; 32], u64)> = block_set.iter().map(|s| s.ident()).collect();
    let pool_ids: HashSet<([u8; 32], u64)> = local_pool.iter().map(|s| s.ident()).collect();

    ViewDivergence {
        agrees: local_ids == block_ids,
        omitted_lower: count_omitted_lower(block_set, local_pool),
        unseen_in_pool: block_set
            .iter()
            .filter(|s| !pool_ids.contains(&s.ident()))
            .count(),
    }
}

#[cfg(test)]
mod tests {
    use super::super::shares::canonical_k_lowest;
    use super::*;
    use crate::primitives::PublicKey;

    fn rs(owner: u8, nonce: u64, b0: u8) -> ResolvedShare {
        let mut b = [0u8; 32];
        b[0] = b0;
        ResolvedShare::new(
            PublicKey::from_bytes([owner; 32]),
            nonce,
            Hash::from_bytes(b),
        )
    }
    fn target(b0: u8) -> Hash {
        let mut b = [0u8; 32];
        b[0] = b0;
        Hash::from_bytes(b)
    }

    #[test]
    fn health_counts_owners_and_concentration() {
        // 4 slots, owner 1 holds 3 of them, owner 2 holds 1.
        let set = canonical_k_lowest(
            &[
                rs(1, 0, 0x02),
                rs(1, 1, 0x04),
                rs(1, 2, 0x06),
                rs(2, 0, 0x08),
            ],
            4,
        );
        let h = health(&set, &target(0x40));
        assert_eq!(h.distinct_owners, 2);
        assert_eq!(h.max_owner_slots, 3, "owner 1 holds 3 of 4 slots");
        assert!(h.bar_fill_bps < 10_000, "low samples sit under τ");
    }

    #[test]
    fn health_flags_full_monopoly() {
        let set = canonical_k_lowest(&[rs(9, 0, 0x01), rs(9, 1, 0x02)], 2);
        let h = health(&set, &target(0x40));
        assert_eq!(h.distinct_owners, 1);
        assert_eq!(h.max_owner_slots, 2, "one miner owns the whole block");
    }

    #[test]
    fn view_divergence_agrees_on_identical_view() {
        let pool = vec![rs(1, 0, 0x05), rs(2, 0, 0x10), rs(3, 0, 0x20)];
        let block = canonical_k_lowest(&pool, 2);
        let d = view_divergence(&pool, &block, 2);
        assert!(d.agrees);
        assert_eq!(d.omitted_lower, 0);
        assert_eq!(d.unseen_in_pool, 0);
    }

    #[test]
    fn view_divergence_flags_a_rejectable_omission() {
        // The node holds 0x05 (lowest); the block omitted it for 0x20.
        let pool = vec![rs(1, 0, 0x05), rs(2, 0, 0x10), rs(3, 0, 0x20)];
        let block = vec![rs(2, 0, 0x10), rs(3, 0, 0x20)];
        let d = view_divergence(&pool, &block, 2);
        assert!(!d.agrees);
        assert_eq!(
            d.omitted_lower, 1,
            "0x05 is a lower share the block dropped"
        );
        assert_eq!(d.unseen_in_pool, 0, "the node had both block shares");
    }

    #[test]
    fn view_divergence_flags_unseen_block_shares() {
        // The block used 0x01 which this node never gossiped.
        let pool = vec![rs(2, 0, 0x10), rs(3, 0, 0x20)];
        let block = vec![rs(9, 7, 0x01), rs(2, 0, 0x10)];
        let d = view_divergence(&pool, &block, 2);
        assert_eq!(d.unseen_in_pool, 1, "0x01 is not in the local pool");
    }
}
