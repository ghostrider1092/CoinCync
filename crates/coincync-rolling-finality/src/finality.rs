//! The `FinalityTracker` — main state machine for CIP-009.D.
//!
//! Accumulates per-block attestations from miners. When a (height,
//! hash) pair has been signed by at least `ceil(2/3 * |active_set|)`
//! distinct miners (and `|active_set| >= MIN_QUORUM`), that height
//! becomes **soft-final** and the validator should refuse any reorg
//! whose fork-point is at or below it.
//!
//! ## Invariants enforced here
//!
//! 1. **Monotonic soft-final tip.** `soft_final_height` only ever
//!    increases. Once a height is soft-final, the tracker never
//!    walks it back, regardless of further attestations or
//!    re-applies.
//! 2. **Per-miner uniqueness per (height, hash).** A miner can sign
//!    a (height, hash) at most once. Re-submission is rejected
//!    with `DuplicateAttestation`.
//! 3. **Dual-fork tolerance.** A miner CAN sign two DIFFERENT hashes
//!    at the same height (one per fork they observed). Each side
//!    counts that miner once for its own quorum. The miner gets one
//!    vote per (height, hash), not one vote per height.
//! 4. **Active-set gating.** Attestations from inactive miners are
//!    rejected. Inactive = no block in the last `WINDOW`.
//! 5. **Quorum gate.** No height is finalized until at least
//!    `MIN_QUORUM` distinct miners are active.
//!
//! ## What this module DOES NOT do
//!
//! - It does NOT call ed25519 directly. It calls the
//!   `AttestationVerifier` trait. Phase 2+ wires real ed25519 in.
//! - It does NOT know about the chain. The tracker has no notion
//!   of "what the canonical block at height H is." That's the
//!   consensus layer's responsibility — when the chain extends to
//!   height H, the consensus layer calls `record_block` to update
//!   the active set, and `apply_attestation` for every attestation
//!   in that block.
//! - It does NOT rotate keys. CIP-009.D §6 specifies key rotation
//!   via a coinbase rotation message; phase 1 carries the type
//!   shape but no rotation handler.

use std::collections::{BTreeMap, BTreeSet};

use crate::active_set::ActiveMinerSet;
use crate::error::{FinalityError, Result};
use crate::types::{AttestationVerifier, BlockHash, FinalityAttestation, MinerPubkey};

// ────────────────────────────────────────────────────────────────
// Defaults
// ────────────────────────────────────────────────────────────────

/// CIP-009.D default `WINDOW` = 10000 blocks (~14 days at 120s).
pub const DEFAULT_WINDOW: u64 = 10_000;

/// CIP-009.D default `LAG` = 100 blocks. Miners attest to
/// `current_height - LAG`, matching `MIN_OUTPUT_AGE`.
pub const DEFAULT_LAG: u64 = 100;

/// CIP-009.D default `MIN_QUORUM` = 5. Below this, the active set
/// is too small to make a 2/3 vote meaningful.
pub const DEFAULT_MIN_QUORUM: usize = 5;

/// How far in the past we accept attestations. Older-than-this
/// targets are rejected with `StaleTarget`. Same value as `WINDOW`
/// by default — beyond that, the chain has moved on and the
/// attestation would be operationally useless.
pub const DEFAULT_STALE_HORIZON: u64 = 10_000;

// ────────────────────────────────────────────────────────────────
// Stats / observability
// ────────────────────────────────────────────────────────────────

/// Snapshot of the tracker's state. Used by metrics / status page.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FinalityStats {
    pub current_chain_tip: u64,
    pub soft_final_height: Option<u64>,
    pub active_miner_count: usize,
    pub total_miner_count: usize,
    pub total_attestations_recorded: usize,
    pub min_quorum: usize,
    pub lag: u64,
    pub window: u64,
}

// ────────────────────────────────────────────────────────────────
// Outcome of applying an attestation
// ────────────────────────────────────────────────────────────────

/// Result of `apply_attestation`. The tracker is updated for
/// `Accepted` and `NewlyFinalized`; on any `Err`, the tracker is
/// unchanged.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ApplyOutcome {
    /// Attestation recorded; soft-final tip did NOT advance.
    Accepted,
    /// Attestation recorded AND the soft-final tip advanced to
    /// `height` with hash `hash`. This is the consensus layer's
    /// signal to lock in finality at that height.
    NewlyFinalized { height: u64, hash: BlockHash },
}

// ────────────────────────────────────────────────────────────────
// The tracker
// ────────────────────────────────────────────────────────────────

/// Per-(height, hash) signer set. We want "set of distinct
/// signers" which is exactly `BTreeSet<MinerPubkey>`.
type SignerSet = BTreeSet<MinerPubkey>;

/// Per-height: which hashes have which signer-sets.
type HashSigners = BTreeMap<BlockHash, SignerSet>;

/// The main state machine.
#[derive(Clone, Debug)]
pub struct FinalityTracker {
    pub min_quorum: usize,
    pub lag: u64,
    pub stale_horizon: u64,
    pub active_set: ActiveMinerSet,

    /// Highest chain height the tracker is aware of. Updated by
    /// `record_block`. Used for `FutureTarget` checks and stale
    /// horizon.
    chain_tip: u64,

    /// Per-(height, hash) attested-by-set. Indexed first by height
    /// for fast pruning.
    attestations: BTreeMap<u64, HashSigners>,

    /// The current soft-final height — the largest height for which
    /// the threshold is met on the canonical chain. Monotonically
    /// non-decreasing.
    soft_final_height: Option<u64>,

    /// Total raw attestations accepted (for stats). Note: this counts
    /// (miner, height, hash) triples; a single miner attesting to two
    /// fork-sides counts as 2.
    total_recorded: usize,
}

impl FinalityTracker {
    /// Construct a tracker with the CIP-009.D defaults.
    pub fn new_default() -> Self {
        FinalityTracker {
            min_quorum: DEFAULT_MIN_QUORUM,
            lag: DEFAULT_LAG,
            stale_horizon: DEFAULT_STALE_HORIZON,
            active_set: ActiveMinerSet::new(DEFAULT_WINDOW),
            chain_tip: 0,
            attestations: BTreeMap::new(),
            soft_final_height: None,
            total_recorded: 0,
        }
    }

    /// Construct with explicit parameters. For tests and any
    /// future tuning.
    pub fn with_params(window: u64, lag: u64, min_quorum: usize, stale_horizon: u64) -> Self {
        FinalityTracker {
            min_quorum,
            lag,
            stale_horizon,
            active_set: ActiveMinerSet::new(window),
            chain_tip: 0,
            attestations: BTreeMap::new(),
            soft_final_height: None,
            total_recorded: 0,
        }
    }

    /// Notify the tracker that the canonical chain has extended to
    /// `block_height`, mined by `miner`. Updates the active set and
    /// the chain tip. Idempotent for the same (miner, height) pair.
    pub fn record_block(&mut self, miner: MinerPubkey, block_height: u64) {
        self.active_set.record_block(miner, block_height);
        if block_height > self.chain_tip {
            self.chain_tip = block_height;
        }
    }

    /// Apply an attestation. Returns:
    ///   - `Ok(Accepted)` if the attestation was recorded but the
    ///     soft-final tip did not advance
    ///   - `Ok(NewlyFinalized { height, hash })` if the
    ///     soft-final tip advanced
    ///   - `Err(FinalityError)` if the attestation was rejected
    ///     (state unchanged in this case)
    pub fn apply_attestation<V: AttestationVerifier>(
        &mut self,
        attestation: &FinalityAttestation,
        verifier: &V,
    ) -> Result<ApplyOutcome> {
        // 1. Signature must verify. Phase 1 uses the trait; phase 2
        //    wires real ed25519.
        if !verifier.verify(attestation) {
            return Err(FinalityError::InvalidSignature);
        }

        // 2. The target_height must be sane: not in the future
        //    relative to what we know, not too far in the past.
        if attestation.target_height > self.chain_tip {
            return Err(FinalityError::FutureTarget {
                target_height: attestation.target_height,
                tracker_tip: self.chain_tip,
            });
        }

        let earliest_accepted = self.chain_tip.saturating_sub(self.stale_horizon);
        if attestation.target_height < earliest_accepted {
            return Err(FinalityError::StaleTarget {
                target_height: attestation.target_height,
                earliest_accepted,
            });
        }

        // 3. The miner must be in the active set AT THE TARGET HEIGHT.
        //    Active-set membership is evaluated at `target_height`
        //    (not at the current chain tip) so an attestation
        //    submitted late by a miner who has since lapsed still
        //    counts — what matters is that they were active when the
        //    block being attested to was canonical.
        if !self
            .active_set
            .is_active(&attestation.miner_pubkey, attestation.target_height)
        {
            return Err(FinalityError::MinerNotActive {
                height: attestation.target_height,
            });
        }

        // 4. Record. Idempotent on (miner, height, hash); duplicate
        //    is rejected.
        let height_entry = self
            .attestations
            .entry(attestation.target_height)
            .or_default();
        let hash_entry = height_entry.entry(attestation.target_hash).or_default();
        if !hash_entry.insert(attestation.miner_pubkey) {
            return Err(FinalityError::DuplicateAttestation {
                target_height: attestation.target_height,
            });
        }
        self.total_recorded += 1;

        // 5. Did this attestation push (height, hash) over threshold?
        //    Compute against the active set AS OF target_height —
        //    the active set we're voting on, not the present.
        let active_count = self.active_set.active_count(attestation.target_height);
        if active_count < self.min_quorum {
            return Ok(ApplyOutcome::Accepted);
        }
        let threshold = ceil_two_thirds(active_count);
        let signer_count = hash_entry.len();
        if signer_count >= threshold {
            // Threshold met. Update soft-final iff this height is
            // beyond the current soft-final tip (monotonic).
            let advances = match self.soft_final_height {
                Some(current) => attestation.target_height > current,
                None => true,
            };
            if advances {
                self.soft_final_height = Some(attestation.target_height);
                return Ok(ApplyOutcome::NewlyFinalized {
                    height: attestation.target_height,
                    hash: attestation.target_hash,
                });
            }
        }

        Ok(ApplyOutcome::Accepted)
    }

    /// The reorg-rule query the consensus layer uses. Returns `true`
    /// if reorganizing the chain such that the fork point is at
    /// `proposed_fork_height` would walk back a soft-final block
    /// (i.e., violate the rule and therefore must be rejected).
    pub fn would_reorg_violate_finality(&self, proposed_fork_height: u64) -> bool {
        match self.soft_final_height {
            Some(soft_final) => proposed_fork_height <= soft_final,
            None => false,
        }
    }

    /// Current soft-final height, if any.
    pub fn soft_final_height(&self) -> Option<u64> {
        self.soft_final_height
    }

    /// Current view of the chain tip the tracker has been told
    /// about.
    pub fn chain_tip(&self) -> u64 {
        self.chain_tip
    }

    /// Snapshot stats.
    pub fn stats(&self) -> FinalityStats {
        FinalityStats {
            current_chain_tip: self.chain_tip,
            soft_final_height: self.soft_final_height,
            active_miner_count: self.active_set.active_count(self.chain_tip),
            total_miner_count: self.active_set.total_count(),
            total_attestations_recorded: self.total_recorded,
            min_quorum: self.min_quorum,
            lag: self.lag,
            window: self.active_set.window(),
        }
    }

    /// Borrow the active set (for diagnostics / serialization).
    pub fn active_set(&self) -> &ActiveMinerSet {
        &self.active_set
    }

    /// Number of distinct signers for a (height, hash) pair. Used
    /// by tests and observability.
    pub fn signer_count(&self, height: u64, hash: &BlockHash) -> usize {
        self.attestations
            .get(&height)
            .and_then(|h| h.get(hash))
            .map(|s| s.len())
            .unwrap_or(0)
    }
}

impl Default for FinalityTracker {
    fn default() -> Self {
        Self::new_default()
    }
}

/// Compute `ceil(2/3 * n)` without floats. The 2/3 Byzantine
/// threshold pattern: `(2*n + 2) / 3` rounds up correctly for all
/// `n >= 0`.
fn ceil_two_thirds(n: usize) -> usize {
    n.saturating_mul(2).saturating_add(2) / 3
}

// ────────────────────────────────────────────────────────────────
// Tests
// ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{NoopVerifier, RejectAllVerifier};

    fn pk(byte: u8) -> MinerPubkey {
        [byte; 32]
    }

    fn hash(byte: u8) -> BlockHash {
        [byte; 32]
    }

    fn att(miner_byte: u8, target_height: u64, target_hash_byte: u8) -> FinalityAttestation {
        FinalityAttestation {
            miner_pubkey: pk(miner_byte),
            target_height,
            target_hash: hash(target_hash_byte),
            signature: vec![0u8; 64],
        }
    }

    /// Build a tracker with 5 active miners (= MIN_QUORUM exactly)
    /// who have all mined recently. Use small WINDOW for fast tests.
    fn five_miner_tracker() -> FinalityTracker {
        let mut t = FinalityTracker::with_params(
            /* window */ 100, /* lag */ 10, /* min_quorum */ 5, /* stale */ 50,
        );
        // Each miner mines a block at heights 50..55. Then we set the
        // chain tip to 60 (so all 5 are active at height 60).
        for i in 0..5u8 {
            t.record_block(pk(i + 1), 50 + i as u64);
        }
        t.record_block(pk(99), 60); // pk(99) just to advance chain_tip
        t
    }

    #[test]
    fn ceil_two_thirds_correctness() {
        assert_eq!(ceil_two_thirds(0), 0);
        assert_eq!(ceil_two_thirds(1), 1); // ceil(0.67) = 1
        assert_eq!(ceil_two_thirds(2), 2); // ceil(1.33) = 2
        assert_eq!(ceil_two_thirds(3), 2); // ceil(2.00) = 2
        assert_eq!(ceil_two_thirds(4), 3); // ceil(2.67) = 3
        assert_eq!(ceil_two_thirds(5), 4); // ceil(3.33) = 4
        assert_eq!(ceil_two_thirds(6), 4); // ceil(4.00) = 4
        assert_eq!(ceil_two_thirds(9), 6); // ceil(6.00) = 6
        assert_eq!(ceil_two_thirds(10), 7); // ceil(6.67) = 7
        assert_eq!(ceil_two_thirds(100), 67);
    }

    #[test]
    fn reject_all_verifier_blocks_acceptance() {
        let mut t = five_miner_tracker();
        let result = t.apply_attestation(&att(1, 55, 0xAA), &RejectAllVerifier);
        assert!(matches!(result, Err(FinalityError::InvalidSignature)));
    }

    #[test]
    fn future_target_rejected() {
        let mut t = five_miner_tracker();
        // chain_tip is 60; target=100 is future
        let result = t.apply_attestation(&att(1, 100, 0xAA), &NoopVerifier);
        assert!(matches!(result, Err(FinalityError::FutureTarget { .. })));
    }

    #[test]
    fn stale_target_rejected() {
        let mut t = five_miner_tracker();
        // chain_tip 60, stale_horizon 50 -> earliest = 10. target=5 is stale.
        let result = t.apply_attestation(&att(1, 5, 0xAA), &NoopVerifier);
        assert!(matches!(result, Err(FinalityError::StaleTarget { .. })));
    }

    #[test]
    fn unknown_miner_rejected() {
        let mut t = five_miner_tracker();
        // pk(200) was never recorded as a block producer
        let result = t.apply_attestation(&att(200, 55, 0xAA), &NoopVerifier);
        assert!(matches!(result, Err(FinalityError::MinerNotActive { .. })));
    }

    #[test]
    fn quorum_advances_soft_final_tip() {
        let mut t = five_miner_tracker();
        // 5 active miners -> threshold = ceil(2/3 * 5) = 4
        // First 3 attestations: still below threshold
        for i in 1..=3u8 {
            let r = t
                .apply_attestation(&att(i, 55, 0xAA), &NoopVerifier)
                .unwrap();
            assert_eq!(r, ApplyOutcome::Accepted);
        }
        // 4th attestation: hits threshold, finalizes
        let r = t
            .apply_attestation(&att(4, 55, 0xAA), &NoopVerifier)
            .unwrap();
        match r {
            ApplyOutcome::NewlyFinalized { height, hash: h } => {
                assert_eq!(height, 55);
                assert_eq!(h, hash(0xAA));
            }
            other => panic!("expected NewlyFinalized, got {:?}", other),
        }
        assert_eq!(t.soft_final_height(), Some(55));
        // 5th attestation: already past threshold, but height is
        // ALREADY soft-final, so this is just Accepted (no advance)
        let r = t
            .apply_attestation(&att(5, 55, 0xAA), &NoopVerifier)
            .unwrap();
        assert_eq!(r, ApplyOutcome::Accepted);
    }

    #[test]
    fn duplicate_attestation_rejected() {
        let mut t = five_miner_tracker();
        t.apply_attestation(&att(1, 55, 0xAA), &NoopVerifier)
            .unwrap();
        let r = t.apply_attestation(&att(1, 55, 0xAA), &NoopVerifier);
        assert!(matches!(r, Err(FinalityError::DuplicateAttestation { .. })));
    }

    #[test]
    fn dual_fork_attestation_does_not_double_count() {
        // Miner 1 signs both fork sides at height 55. Each side has
        // threshold = 4 distinct signers; miner 1 contributes 1
        // vote to each, NOT 2 to either.
        let mut t = five_miner_tracker();
        // Miner 1 signs both (55, 0xAA) and (55, 0xBB).
        t.apply_attestation(&att(1, 55, 0xAA), &NoopVerifier)
            .unwrap();
        t.apply_attestation(&att(1, 55, 0xBB), &NoopVerifier)
            .unwrap();
        assert_eq!(t.signer_count(55, &hash(0xAA)), 1);
        assert_eq!(t.signer_count(55, &hash(0xBB)), 1);
        // Miners 2, 3, 4 sign 0xAA only. Now 0xAA has 4 signers ->
        // finalized.
        for i in 2..=4u8 {
            let _ = t.apply_attestation(&att(i, 55, 0xAA), &NoopVerifier);
        }
        assert_eq!(t.soft_final_height(), Some(55));
    }

    #[test]
    fn quorum_gate_blocks_finalization_below_min_quorum() {
        // 4 miners only; MIN_QUORUM = 5. Even if all 4 sign the
        // same hash, no finalization.
        let mut t = FinalityTracker::with_params(100, 10, 5, 50);
        for i in 0..4u8 {
            t.record_block(pk(i + 1), 50 + i as u64);
        }
        t.record_block(pk(99), 60);
        for i in 1..=4u8 {
            let _ = t.apply_attestation(&att(i, 55, 0xAA), &NoopVerifier);
        }
        assert_eq!(t.soft_final_height(), None);
    }

    #[test]
    fn would_reorg_violate_finality_rule() {
        let mut t = five_miner_tracker();
        // No finality yet -> any reorg is allowed
        assert!(!t.would_reorg_violate_finality(55));
        assert!(!t.would_reorg_violate_finality(0));
        // Finalize height 55
        for i in 1..=4u8 {
            t.apply_attestation(&att(i, 55, 0xAA), &NoopVerifier)
                .unwrap();
        }
        // Reorg with fork point AT 55 = violates (== soft_final)
        assert!(t.would_reorg_violate_finality(55));
        // Reorg with fork point BEFORE 55 = violates
        assert!(t.would_reorg_violate_finality(54));
        // Reorg with fork point AFTER 55 = ok (didn't walk past final)
        assert!(!t.would_reorg_violate_finality(56));
    }

    // ────────────────────────────────────────────────────────────
    // Property tests — the heart of phase 1's correctness story
    // ────────────────────────────────────────────────────────────

    use proptest::prelude::*;

    // PROPERTY: the soft-final tip is monotonically non-decreasing.
    // No sequence of attestations can lower it once set.
    proptest! {
        #[test]
        fn prop_soft_final_monotonic(
            heights in proptest::collection::vec(50u64..60, 1..30),
            hashes in proptest::collection::vec(any::<u8>(), 1..30),
            miners in proptest::collection::vec(1u8..=5, 1..30),
        ) {
            let mut t = five_miner_tracker();
            let mut last_seen: Option<u64> = None;
            let n = heights.len().min(hashes.len()).min(miners.len());
            for i in 0..n {
                let a = att(miners[i], heights[i], hashes[i]);
                let _ = t.apply_attestation(&a, &NoopVerifier);
                if let Some(h) = t.soft_final_height() {
                    if let Some(prev) = last_seen {
                        prop_assert!(h >= prev, "soft_final regressed: {} -> {}", prev, h);
                    }
                    last_seen = Some(h);
                }
            }
        }
    }

    // PROPERTY: a (height, hash) is finalized exactly when it
    // accumulates >= ceil(2/3 * active_count) distinct signers
    // AND active_count >= MIN_QUORUM.
    proptest! {
        #[test]
        fn prop_threshold_is_exact(
            n_signers in 0u8..=5,
        ) {
            let mut t = five_miner_tracker();
            // 5 miners total, all active. Threshold = ceil(2/3 * 5) = 4.
            for i in 1..=n_signers {
                let _ = t.apply_attestation(&att(i, 55, 0xAA), &NoopVerifier);
            }
            let expected_finalized = n_signers as usize >= 4;
            prop_assert_eq!(t.soft_final_height().is_some(), expected_finalized);
        }
    }

    // PROPERTY: signing the SAME (height, hash) twice from the
    // same miner is idempotent. Specifically, the signer-count for
    // that (height, hash) increases by 1 on first acceptance and
    // by 0 on every subsequent rejection.
    proptest! {
        #[test]
        fn prop_duplicate_attestations_idempotent(
            attempts in 1u8..=10,
        ) {
            let mut t = five_miner_tracker();
            for _ in 0..attempts {
                let _ = t.apply_attestation(&att(1, 55, 0xAA), &NoopVerifier);
            }
            prop_assert_eq!(t.signer_count(55, &hash(0xAA)), 1);
        }
    }

    // PROPERTY: dual-fork attestations from the same miner give one
    // vote per (height, hash) — never more.
    proptest! {
        #[test]
        fn prop_dual_fork_one_vote_per_fork(
            n_miners_signing_both in 1u8..=5,
        ) {
            let mut t = five_miner_tracker();
            // Each miner signs BOTH 0xAA and 0xBB at height 55
            for i in 1..=n_miners_signing_both {
                let _ = t.apply_attestation(&att(i, 55, 0xAA), &NoopVerifier);
                let _ = t.apply_attestation(&att(i, 55, 0xBB), &NoopVerifier);
            }
            prop_assert_eq!(t.signer_count(55, &hash(0xAA)), n_miners_signing_both as usize);
            prop_assert_eq!(t.signer_count(55, &hash(0xBB)), n_miners_signing_both as usize);
        }
    }
}
