//! # Bobtail multi-sample PoW — reference module (Phase D, Observe-only)
//!
//! Additive, **feature-gated** (`bobtail`, off by default), **Observe-only**
//! reference implementation of the multi-sample PoW design in
//! `docs/design/bobtail-multisample-pow.md` and `docs/design/bobtail-spec.md`.
//!
//! A multi-sample block is valid (on the PoW axis) iff the mean of its `K`
//! lowest sample hashes clears `τ = T·(K+1)/2` **and** that `K`-set is the
//! globally-lowest in the gossiped pool (the anti-grinding rule, §5.5 / §6).
//! This module computes exactly that — `what a Bobtail block would be` — as pure,
//! deterministic functions:
//!
//! - [`kmean::k_mean_meets_target`] — the work-preserving k-mean bar.
//! - [`shares::canonical_k_lowest`] / [`shares::omits_lower_share`] — the
//!   canonical set and the grinding-resistance predicate.
//! - [`shares::lottery_index`] / [`shares::equal_split`] — the two reward rules.
//! - [`observe`] — bundles them into a read-only [`BobtailObservation`], the
//!   value a `CYNC-POW-00x` diagnostic would surface during the Observe rollout.
//!
//! ## What this module deliberately does NOT do
//!
//! - It never edits the hash-locked core (`pow.rs`, `difficulty.rs`, `header.rs`)
//!   and never changes block validity: with the `bobtail` feature off, the build
//!   is byte-identical and the consensus fingerprint is unchanged.
//! - It does not recompute RandomX. The verifier resolves each share's hash with
//!   the existing `compute_pow_hash` and passes resolved shares in, so the pure
//!   logic is testable without the RandomX VM.
//! - It carries no network wiring yet. Proof-share gossip (`bobtail-spec.md` §3)
//!   and the `CYNC-POW-00x` diagnostic hookup are the next Phase-D increment;
//!   this slice is the consensus-math heart those will call.
//!
//! The Enforce step (flipping validity to the k-mean + canonical-set rule) is a
//! coordinated post-audit hard fork; see `bobtail-spec.md` §10.

pub mod biguint;
pub mod gossip;
pub mod health;
pub mod kmean;
pub mod mining;
pub mod shares;

pub use gossip::{Admit, ProofShareBatch, SharePool, CAP_BOBTAIL_SHARES, PROOF_SHARES_MSG_TYPE};
pub use mining::collect_shares;
pub use health::{BobtailHealth, ViewDivergence};
pub use kmean::{bar_fill_bps, k_mean_meets_target, tau_share_target};
pub use shares::{
    block_shares_valid, canonical_k_lowest, count_omitted_lower, equal_split, lottery_index,
    max_pool_size, omits_lower_share, retain_lowest, ResolvedShare, ShareProof,
    BOBTAIL_POOL_SAFETY,
};

use crate::primitives::{Hash, PublicKey};

/// Samples per block — the settled value (`bobtail-spec.md` §1): the 95 %-in-band
/// knee, block-time CV ≈ 0.26. `K = 1` would recover ordinary single-sample PoW.
pub const BOBTAIL_K: usize = 20;

/// Share safety factor: the gossip threshold is set so the pool holds
/// `E[shares]/block = C_SHARE · K` (`bobtail-spec.md` §1).
pub const BOBTAIL_C_SHARE: u64 = 3;

/// Height at which nodes START computing the shadow Bobtail observation
/// (Observe). `u64::MAX` = not armed; a finite value is chosen at rollout.
///
/// Observe is read-only: past this height a node computes what a Bobtail block
/// would be and exposes it via diagnostics, but blocks are still validated by
/// the single-hash rule. Placeholder-off until a testnet rollout height is set,
/// mirroring [`crate::constants::shielded_activation_height`]'s posture.
pub const BOBTAIL_OBSERVE_HEIGHT: u64 = u64::MAX;

/// Height at which the k-mean + canonical-set rule becomes **consensus**
/// (Enforce). `u64::MAX` = not armed. Flipping this is a coordinated post-audit
/// hard fork and changes the fingerprint (intended); see `bobtail-spec.md` §10.
pub const BOBTAIL_ACTIVATION_HEIGHT: u64 = u64::MAX;

/// Whether the shadow Observe computation runs at `height` (fail-closed: off
/// until a finite [`BOBTAIL_OBSERVE_HEIGHT`] is set and reached).
pub const fn bobtail_observe_active_at(height: u64) -> bool {
    height >= BOBTAIL_OBSERVE_HEIGHT
}

/// Whether the Bobtail validity rule is ENFORCED at `height` (fail-closed: off
/// until a finite [`BOBTAIL_ACTIVATION_HEIGHT`] is set and reached).
pub const fn bobtail_enforce_active_at(height: u64) -> bool {
    height >= BOBTAIL_ACTIVATION_HEIGHT
}

/// A read-only snapshot of `what a Bobtail block would be` for the current
/// gossiped share pool — the value the Observe-phase diagnostic surfaces. Pure
/// data; computing it changes no state and enforces nothing.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BobtailObservation {
    /// Samples required (`K`).
    pub k: usize,
    /// Shares the node currently holds for this parent.
    pub pool_size: usize,
    /// The canonical `K`-lowest set, ascending (empty if `pool_size < k`).
    pub canonical_set: Vec<ResolvedShare>,
    /// Does the canonical set's k-mean clear `τ = T·(K+1)/2`? (Would this be a
    /// valid Bobtail block right now?)
    pub meets_bar: bool,
    /// The proposer: owner of the global minimum (`canonical_set[0]`).
    pub proposer: Option<PublicKey>,
    /// The fallback single-output lottery winner's index into `canonical_set`.
    pub lottery_winner: Option<usize>,
    /// Detection-only health of the candidate (distinct owners, slot
    /// concentration, bar margin). `None` until the pool reaches `k`.
    pub health: Option<BobtailHealth>,
}

/// Compute the shadow [`BobtailObservation`] for a gossiped share `pool` against
/// the per-height ASERT target `target` and the given `k`.
///
/// Returns an observation with `meets_bar = false` and no proposer while the
/// pool holds fewer than `k` shares (not yet a candidate block). This is the
/// pure computation an Observe-phase node runs each tick; it enforces nothing.
pub fn observe(pool: &[ResolvedShare], target: &Hash, k: usize) -> BobtailObservation {
    let canonical_set = canonical_k_lowest(pool, k);
    if canonical_set.len() < k {
        return BobtailObservation {
            k,
            pool_size: pool.len(),
            canonical_set,
            meets_bar: false,
            proposer: None,
            lottery_winner: None,
            health: None,
        };
    }
    let hashes: Vec<Hash> = canonical_set.iter().map(|s| s.hash).collect();
    let meets_bar = k_mean_meets_target(&hashes, target);
    let proposer = Some(canonical_set[0].share.miner_pubkey);
    let lottery_winner = Some(lottery_index(&canonical_set));
    let set_health = Some(health::health(&canonical_set, target));
    BobtailObservation {
        k,
        pool_size: pool.len(),
        canonical_set,
        meets_bar,
        proposer,
        lottery_winner,
        health: set_health,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rs(owner: u8, nonce: u64, b0: u8) -> ResolvedShare {
        let mut b = [0u8; 32];
        b[0] = b0;
        ResolvedShare::new(PublicKey::from_bytes([owner; 32]), nonce, Hash::from_bytes(b))
    }

    /// K=1 recovers single-sample PoW: the observation's bar equals
    /// `meets_difficulty` of the single lowest share.
    #[test]
    fn observe_k1_is_single_sample() {
        let target = {
            let mut b = [0u8; 32];
            b[0] = 0x80;
            Hash::from_bytes(b)
        };
        let pool = vec![rs(1, 0, 0x40), rs(2, 0, 0x90)];
        let obs = observe(&pool, &target, 1);
        assert_eq!(obs.canonical_set.len(), 1);
        assert_eq!(obs.canonical_set[0].hash.as_bytes()[0], 0x40, "the minimum");
        assert!(obs.meets_bar, "0x40 ≤ 0x80 target");
        assert!(obs.proposer.is_some());
        assert_eq!(obs.lottery_winner, Some(0));
    }

    /// Below the quorum of `k` shares, the observation is inert (not a block yet).
    #[test]
    fn observe_below_quorum_is_inert() {
        let target = Hash::from_bytes([0x10; 32]);
        let pool = vec![rs(1, 0, 0x01), rs(2, 0, 0x02)];
        let obs = observe(&pool, &target, 4);
        assert_eq!(obs.pool_size, 2);
        assert!(!obs.meets_bar);
        assert!(obs.proposer.is_none());
        assert!(obs.lottery_winner.is_none());
        assert!(obs.health.is_none(), "no health below quorum");
    }

    /// A full, low pool yields a candidate: canonical set of size k, proposer =
    /// the global minimum, a lottery winner in range.
    #[test]
    fn observe_full_pool_is_a_candidate() {
        let target = {
            let mut b = [0u8; 32];
            b[0] = 0x40;
            Hash::from_bytes(b)
        };
        let mut pool = Vec::new();
        for i in 0..6u8 {
            pool.push(rs(i + 1, 0, 0x05 + i)); // 0x05..0x0A, all well below τ
        }
        let obs = observe(&pool, &target, 4);
        assert_eq!(obs.canonical_set.len(), 4);
        assert_eq!(obs.canonical_set[0].hash.as_bytes()[0], 0x05, "minimum first");
        assert!(obs.meets_bar);
        assert_eq!(obs.proposer, Some(PublicKey::from_bytes([1u8; 32])));
        assert!(obs.lottery_winner.unwrap() < 4);
        let h = obs.health.expect("a full pool carries health");
        assert_eq!(h.distinct_owners, 4, "4 distinct owners in the set");
        assert_eq!(h.max_owner_slots, 1, "no slot concentration");
        assert!(h.bar_fill_bps < 10_000, "cleared τ with headroom");
    }

    /// The gate is fail-closed: with the placeholder heights, nothing is armed.
    #[test]
    fn gates_fail_closed_by_default() {
        assert_eq!(BOBTAIL_OBSERVE_HEIGHT, u64::MAX);
        assert_eq!(BOBTAIL_ACTIVATION_HEIGHT, u64::MAX);
        assert!(!bobtail_observe_active_at(1_000_000));
        assert!(!bobtail_enforce_active_at(u64::MAX - 1));
    }
}
