//! # Proof pruning after finality (Warren Phase 0 — §3.7/§6)
//!
//! The finality-triggered policy that decides which **prunable proof bytes** a
//! node may drop. Per the §3.0 inventory, the heavy verify payloads (Bulletproof
//! range proofs, CLSAG ring signatures, Spark Spend bundles) are only needed to
//! *verify* a block; once a block is final they can be dropped while the
//! commitments and nullifiers — the data needed to keep validating new blocks —
//! are kept. Bounded storage without weakening validation.
//!
//! ## The one safety rule: never prune inside the reorg window
//! A block may only be pruned once it is beyond any possible reorg. The caller
//! passes the consensus finality depth, which MUST be `>= max_reorg_depth` (it
//! is `CHECKPOINT_INTERVAL` today). A chain shorter than the finality window
//! prunes nothing (`checked_sub` → `None`), and an archival node opts out
//! entirely — both fail SAFE (keep data) rather than risk dropping something
//! still needed.
//!
//! ## Distinct from `storage::pruning::ChainPruner`
//! That existing pruner drops WHOLE old blocks (KeepRecent / Archive / Custom
//! modes, with checkpoint protection) to save disk. This is FINER-GRAINED: it
//! keeps every block (and its commitments/nullifiers, so validation is
//! unaffected) and drops only the re-verifiable heavy proof BYTES once a block
//! is final. The two compose. The wiring should reuse `ChainPruner`'s
//! checkpoint-protection and treat `PruningMode::Archive` as this hook's
//! `archival` opt-out, not reinvent either.
//!
//! ## Status
//! Phase-0 **sketch**, non-gated, pure policy. This computes the horizon; the
//! actual byte-dropping is a storage-layer hook wired at that height (TODO). It
//! lives in `crypto::` with the other Warren Phase-0 sketches; its eventual home
//! is the storage/finality layer.

/// Provisional default finality depth — mirrors `CHECKPOINT_INTERVAL` (144).
/// The real wiring passes the consensus constant; this is for standalone use.
pub const DEFAULT_FINALITY_DEPTH: u64 = 144;

/// What the pruning hook decided.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PrunePlan {
    /// Prunable proof bytes for blocks at height `<=` this may be dropped.
    /// `None` = prune nothing (archival node, or chain shorter than the finality
    /// window). Commitments/nullifiers are kept regardless of this value.
    pub prune_at_or_below: Option<u64>,
}

impl PrunePlan {
    /// Whether a block at `height` is beyond the finality window and so its
    /// prunable proof bytes may be dropped under this plan.
    #[must_use]
    pub fn is_prunable(&self, height: u64) -> bool {
        matches!(self.prune_at_or_below, Some(floor) if height <= floor)
    }

    /// The archival / nothing-to-prune plan.
    #[must_use]
    pub fn keep_all() -> Self {
        Self { prune_at_or_below: None }
    }
}

/// Decide the pruning horizon for a chain tipped at `tip_height`.
///
/// Fail-safe: `archival` keeps everything; a chain shorter than `finality_depth`
/// keeps everything (`checked_sub` underflows to `None`); otherwise the floor is
/// `tip_height - finality_depth`, so only blocks strictly beyond the reorg
/// window are ever marked prunable.
#[must_use]
pub fn plan_pruning(tip_height: u64, finality_depth: u64, archival: bool) -> PrunePlan {
    if archival {
        return PrunePlan::keep_all();
    }
    PrunePlan { prune_at_or_below: tip_height.checked_sub(finality_depth) }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prunes_only_below_the_finality_floor() {
        let plan = plan_pruning(1000, DEFAULT_FINALITY_DEPTH, false);
        assert_eq!(plan.prune_at_or_below, Some(856));
        assert!(plan.is_prunable(856), "the floor itself is final → prunable");
        assert!(plan.is_prunable(0));
        assert!(!plan.is_prunable(857), "within the reorg window → kept");
        assert!(!plan.is_prunable(1000), "the tip is never prunable");
    }

    #[test]
    fn short_chain_prunes_nothing() {
        // Chain shorter than the finality window: nothing is final yet.
        let plan = plan_pruning(100, DEFAULT_FINALITY_DEPTH, false);
        assert_eq!(plan.prune_at_or_below, None);
        assert!(!plan.is_prunable(0));
    }

    #[test]
    fn archival_node_keeps_everything() {
        let plan = plan_pruning(1_000_000, DEFAULT_FINALITY_DEPTH, true);
        assert_eq!(plan, PrunePlan::keep_all());
        assert!(!plan.is_prunable(1));
    }

    #[test]
    fn floor_never_enters_the_reorg_window() {
        // For any tip, the prune floor is at least `finality_depth` below the tip.
        for tip in [200u64, 500, 5000, u64::MAX] {
            if let Some(floor) = plan_pruning(tip, DEFAULT_FINALITY_DEPTH, false).prune_at_or_below {
                assert!(tip - floor >= DEFAULT_FINALITY_DEPTH);
            }
        }
    }
}
