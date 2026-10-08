//! # Surface commitment accumulator (Warren Phase 0 — §3.1)
//!
//! The "Surface" is the thin commitment layer that binds the shielded-pool
//! state into the PoW header. `BlockHeader` already RESERVES the field for it —
//! `spark_set_root` — zero before the shielded fork and bound into the PoW once
//! active. This module computes the value that goes there.
//!
//! ## Construction: a chained append-only accumulator (NOT a sorted Merkle tree)
//! The shielded pool is append-only and insertion-ordered (Spark membership
//! proofs reference a coin by its position), so the Surface root chains each new
//! leaf into the running root in pool order:
//!
//! ```text
//! root₀      = H(DOMAIN_EMPTY)
//! rootₙ₊₁    = H(DOMAIN_leaf ‖ rootₙ ‖ indexₙ ‖ leaf_bytes)
//! ```
//!
//! This is deliberately **not** `merkle_root`: that construction carries the
//! documented CVE-2012-2459 duplication malleability (`root([A,B,C]) ==
//! root([A,B,C,C])`). A chained accumulator binds each leaf's position via the
//! prior root and an explicit index, so a duplicated or reordered set yields a
//! different root — the property a DA commitment must have. Distinct domain tags
//! per leaf type stop a coin commitment from ever being read as a tag.
//!
//! ## Determinism = consensus safety (§3.8)
//! The root binds into the PoW, so it MUST be identical byte-for-byte on every
//! node: same leaves, same order, same bytes. Everything here is pure
//! blake3 over `to_le_bytes` with no floats, map iteration, or platform types.
//!
//! ## Status / safety
//! Phase-0 **sketch**, gated `sketch-gk-proof`, NOT wired into header
//! construction or validation — `spark_set_root` stays zero in every shipping
//! build. [`spark_set_root_for_header`] is **fail-closed**: it returns the
//! zero sentinel (exactly what the header carries pre-fork) until the caller's
//! activation height, so wiring it in early can never fabricate a non-zero DA
//! claim before the pool is live.

#![cfg(feature = "sketch-gk-proof")]

use crate::primitives::{hash_concat, hash_data, Hash};

const DOMAIN_EMPTY: &[u8] = b"coincync.surface.v0/empty";
const DOMAIN_COIN: &[u8] = b"coincync.surface.v0/coin";
const DOMAIN_TAG: &[u8] = b"coincync.surface.v0/tag";

/// An incremental, insertion-ordered commitment to the shielded set (minted
/// coins + spent linking tags). Cheap to carry and advance as the pool grows.
#[derive(Debug, Clone)]
pub struct SurfaceAccumulator {
    root: Hash,
    coins: u64,
    tags: u64,
}

impl SurfaceAccumulator {
    /// The empty-pool root — a fixed domain-separated constant, never the zero
    /// hash (the zero hash is reserved as the pre-fork "no Surface" sentinel, so
    /// an empty-but-active pool is distinguishable from an inactive one).
    pub fn empty() -> Self {
        Self { root: hash_data(DOMAIN_EMPTY), coins: 0, tags: 0 }
    }

    /// Fold a newly minted coin commitment into the root, at the next coin index.
    pub fn absorb_coin(&mut self, commitment: &[u8]) {
        self.root = hash_concat(&[
            DOMAIN_COIN,
            self.root.as_slice(),
            &self.coins.to_le_bytes(),
            commitment,
        ]);
        self.coins += 1;
    }

    /// Fold a newly spent linking tag into the root, at the next tag index.
    pub fn absorb_tag(&mut self, tag: &[u8]) {
        self.root = hash_concat(&[
            DOMAIN_TAG,
            self.root.as_slice(),
            &self.tags.to_le_bytes(),
            tag,
        ]);
        self.tags += 1;
    }

    /// The current accumulator root.
    pub fn root(&self) -> Hash {
        self.root
    }

    /// `(coins_absorbed, tags_absorbed)` — bound into the root via the indices.
    pub fn counts(&self) -> (u64, u64) {
        (self.coins, self.tags)
    }
}

impl Default for SurfaceAccumulator {
    fn default() -> Self {
        Self::empty()
    }
}

/// The value to bind into the header's reserved `spark_set_root` at `height`.
///
/// **Fail-closed**: before `activation_height` the shielded pool is not live, so
/// this returns the zero sentinel — identical to what the header carries today —
/// no matter what the accumulator holds. At and after activation it returns the
/// real root. The caller passes the network's shielded activation height
/// (`u64::MAX` on testnet/mainnet today, the regtest height under regtest), so
/// wiring this in ahead of a real fork changes nothing in a shipping build.
pub fn spark_set_root_for_header(
    height: u64,
    activation_height: u64,
    acc: &SurfaceAccumulator,
) -> Hash {
    if height < activation_height {
        Hash::zero()
    } else {
        acc.root()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_root_is_stable_and_nonzero() {
        assert_eq!(SurfaceAccumulator::empty().root(), SurfaceAccumulator::empty().root());
        assert!(!SurfaceAccumulator::empty().root().is_zero());
    }

    #[test]
    fn same_sequence_same_root_order_matters() {
        let mut a = SurfaceAccumulator::empty();
        a.absorb_coin(b"coin-A");
        a.absorb_coin(b"coin-B");

        let mut b = SurfaceAccumulator::empty();
        b.absorb_coin(b"coin-A");
        b.absorb_coin(b"coin-B");
        assert_eq!(a.root(), b.root(), "same order → same root (determinism)");

        let mut c = SurfaceAccumulator::empty();
        c.absorb_coin(b"coin-B");
        c.absorb_coin(b"coin-A");
        assert_ne!(a.root(), c.root(), "reorder → different root");
    }

    #[test]
    fn duplication_changes_the_root_unlike_merkle() {
        // The CVE-2012-2459 property a sorted Merkle tree fails: appending a
        // duplicate MUST move the root.
        let mut base = SurfaceAccumulator::empty();
        base.absorb_coin(b"A");
        base.absorb_coin(b"B");
        base.absorb_coin(b"C");

        let mut dup = base.clone();
        dup.absorb_coin(b"C"); // [A,B,C,C]
        assert_ne!(base.root(), dup.root());
        assert_eq!(dup.counts(), (4, 0));
    }

    #[test]
    fn coin_and_tag_domains_do_not_collide() {
        let mut as_coin = SurfaceAccumulator::empty();
        as_coin.absorb_coin(b"X");
        let mut as_tag = SurfaceAccumulator::empty();
        as_tag.absorb_tag(b"X");
        assert_ne!(as_coin.root(), as_tag.root(), "domain separation holds");
    }

    #[test]
    fn header_binding_is_fail_closed_pre_activation() {
        let mut acc = SurfaceAccumulator::empty();
        acc.absorb_coin(b"live-coin");
        // Pre-activation: zero sentinel regardless of accumulator contents.
        assert!(spark_set_root_for_header(50, 100, &acc).is_zero());
        // At/after activation: the real root.
        assert_eq!(spark_set_root_for_header(100, 100, &acc), acc.root());
        assert!(!spark_set_root_for_header(100, 100, &acc).is_zero());
    }
}
