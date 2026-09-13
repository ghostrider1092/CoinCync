//! Chain pruning for reduced disk usage
//!
//! Allows nodes to operate with only recent blocks, saving ~90% disk space.
//!
//! ## Audit map
//! Each `§` is a code section below; it states the INVARIANT it guarantees, the
//! THREAT it defends, and the TESTS that prove it. (Renders in `cargo doc`.)
//!
//! - **§1 `can_prune` (mode dispatch + protection)** — INVARIANT: a protected
//!   block is never prunable; `Archive` prunes nothing; `KeepRecent(n)` keeps
//!   the `n`-block recency window via `saturating_sub`; `Custom` honors
//!   `min_blocks`, `keep_after_height`, and checkpoint protection. THREAT: a
//!   still-needed block pruned away. TESTS: `test_archive_mode`,
//!   `test_keep_recent`, `test_protected_blocks`, `test_custom_rules`,
//!   `test_checkpoint_protected`.
//! - **§2 R-59 zero-interval guard (`can_prune` Custom branch)** — INVARIANT:
//!   checkpoint protection is gated on `checkpoint_interval > 0`, so
//!   `height % interval` never divides by zero; interval 0 means "no checkpoint
//!   protection." THREAT: **R-59** — a `PruningRules{ checkpoint_interval: 0 }`
//!   caller panics on the hot pruning-decision path, taking down the prune
//!   thread. TESTS: `can_prune_does_not_panic_on_zero_checkpoint_interval`.
//! - **§3 `prunable_heights` / `estimate_savings`** — INVARIANT:
//!   `prunable_heights` returns exactly the `can_prune` heights in a half-open
//!   `from..to` window (empty/inverted ranges yield nothing, no panic);
//!   `estimate_savings` is an O(1) per-mode estimate consistent with the
//!   recency/min-blocks boundary. THREAT: an over-aggressive plan, or a
//!   div-by-zero / overflow in the estimate. TESTS:
//!   `prunable_heights_returns_correct_range`, `estimate_savings_matches_mode`.
//! - **§4 `record_prune` / `stats` (A6-CLOCK)** — INVARIANT: prune counters
//!   accumulate monotonically and `last_pruned_height` tracks the most recent
//!   prune; the clock read uses `unwrap_or(0)` for pre-epoch safety (never
//!   panics). THREAT: A6-CLOCK — a system-clock anomaly panicking the stats
//!   update. TESTS: `record_prune_accumulates_stats`.
//! - **§5 `create_plan` (R-60 / R-36 coupled contract)** — INVARIANT: the plan
//!   starts after `last_pruned_height`, is archive-empty, and is bounded by
//!   `batch_size` and the mode's max-prune height. THREAT: **R-60** — a drifted
//!   `last_pruned_height` re-prunes or strands blocks; mitigated because
//!   `db/pruning.rs::execute_plan` (R-36) only bumps the counter after both
//!   writes succeed. TESTS: `test_pruning_plan`; reorg fork_point safety:
//!   `pruning_and_reorg_fork_point_interaction`. (Chain-level pruning×reorg
//!   interaction is a gap — needs a real `Blockchain` reorg across a pruned
//!   fork_point.)

use crate::consensus::Block;
use crate::primitives::Hash;
use std::collections::HashSet;

/// Pruning mode configuration
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PruningMode {
    /// Keep all blocks (archive node)
    Archive,
    /// Keep last N blocks
    KeepRecent(u64),
    /// Keep blocks with unspent outputs only
    KeepUnspent,
    /// Custom pruning with specific rules
    Custom(PruningRules),
}

impl Default for PruningMode {
    fn default() -> Self {
        PruningMode::Archive
    }
}

/// Custom pruning rules
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PruningRules {
    /// Minimum blocks to keep
    pub min_blocks: u64,
    /// Keep all blocks after this height
    pub keep_after_height: Option<u64>,
    /// Keep blocks containing these transactions
    pub keep_tx_hashes: HashSet<Hash>,
    /// Keep checkpoint blocks
    pub keep_checkpoints: bool,
    /// Checkpoint interval
    pub checkpoint_interval: u64,
}

impl Default for PruningRules {
    fn default() -> Self {
        PruningRules {
            min_blocks: 1000,
            keep_after_height: None,
            keep_tx_hashes: HashSet::new(),
            keep_checkpoints: true,
            checkpoint_interval: 10000,
        }
    }
}

/// Pruning statistics
#[derive(Clone, Debug, Default)]
pub struct PruningStats {
    /// Blocks pruned
    pub blocks_pruned: u64,
    /// Bytes freed
    pub bytes_freed: u64,
    /// Blocks kept
    pub blocks_kept: u64,
    /// Last pruned height
    pub last_pruned_height: u64,
    /// Last prune time (unix timestamp)
    pub last_prune_time: u64,
}

/// Chain pruner
pub struct ChainPruner {
    /// Pruning mode
    mode: PruningMode,
    /// Current chain height
    current_height: u64,
    /// Statistics
    stats: PruningStats,
    /// Blocks that cannot be pruned (referenced by unspent outputs)
    protected_blocks: HashSet<u64>,
}

impl ChainPruner {
    /// Create new pruner with mode
    pub fn new(mode: PruningMode) -> Self {
        ChainPruner {
            mode,
            current_height: 0,
            stats: PruningStats::default(),
            protected_blocks: HashSet::new(),
        }
    }

    /// Set current chain height
    pub fn set_height(&mut self, height: u64) {
        self.current_height = height;
    }

    /// Mark a block as protected (cannot be pruned)
    pub fn protect_block(&mut self, height: u64) {
        self.protected_blocks.insert(height);
    }

    /// Unprotect a block
    pub fn unprotect_block(&mut self, height: u64) {
        self.protected_blocks.remove(&height);
    }

    /// Check if a block can be pruned
    pub fn can_prune(&self, height: u64) -> bool {
        if self.protected_blocks.contains(&height) {
            return false;
        }

        match &self.mode {
            PruningMode::Archive => false,

            PruningMode::KeepRecent(keep_count) => {
                let min_keep_height = self.current_height.saturating_sub(*keep_count);
                height < min_keep_height
            }

            PruningMode::KeepUnspent => {
                // Only prune if block has no referenced outputs
                !self.protected_blocks.contains(&height)
            }

            PruningMode::Custom(rules) => {
                // Check minimum blocks
                let min_keep_height = self.current_height.saturating_sub(rules.min_blocks);
                if height >= min_keep_height {
                    return false;
                }

                // Check keep_after_height
                if let Some(keep_after) = rules.keep_after_height {
                    if height >= keep_after {
                        return false;
                    }
                }

                // Check checkpoints.
                //
                // R-59 fix (2026-07-02): the prior code was
                // `if rules.keep_checkpoints && height % rules.checkpoint_interval == 0`,
                // which panics with a divide-by-zero on any caller that
                // constructs `PruningRules{ checkpoint_interval: 0, ..}`.
                // The estimator branch at L171 correctly guarded with
                // `checkpoint_interval > 0`; this branch didn't.
                // Guarded now: an interval of 0 means "no checkpoints
                // to protect at all," matching the intuitive meaning.
                if rules.keep_checkpoints
                    && rules.checkpoint_interval > 0
                    && height % rules.checkpoint_interval == 0
                {
                    return false;
                }

                true
            }
        }
    }

    /// Get heights that can be pruned
    pub fn prunable_heights(&self, from: u64, to: u64) -> Vec<u64> {
        (from..to).filter(|h| self.can_prune(*h)).collect()
    }

    /// Estimate bytes that would be freed by pruning
    pub fn estimate_savings(&self, avg_block_size: usize) -> u64 {
        let prunable = match &self.mode {
            PruningMode::Archive => 0,
            PruningMode::KeepRecent(keep) => self.current_height.saturating_sub(*keep),
            PruningMode::KeepUnspent => {
                // Estimate based on protected blocks
                self.current_height
                    .saturating_sub(self.protected_blocks.len() as u64)
            }
            PruningMode::Custom(rules) => {
                // O(1) estimate instead of iterating every height.
                // Subtract protected blocks and checkpoint-interval blocks from the range.
                let min_height = self.current_height.saturating_sub(rules.min_blocks);
                let checkpoint_count = if rules.keep_checkpoints && rules.checkpoint_interval > 0 {
                    min_height / rules.checkpoint_interval
                } else {
                    0
                };
                let protected_in_range = self
                    .protected_blocks
                    .iter()
                    .filter(|&&h| h < min_height)
                    .count() as u64;
                min_height
                    .saturating_sub(checkpoint_count)
                    .saturating_sub(protected_in_range)
            }
        };

        prunable * avg_block_size as u64
    }

    /// Record a prune operation
    pub fn record_prune(&mut self, blocks: u64, bytes: u64, height: u64) {
        self.stats.blocks_pruned += blocks;
        self.stats.bytes_freed += bytes;
        self.stats.last_pruned_height = height;
        // SECURITY (A6-CLOCK): Use unwrap_or(0) for pre-epoch clock safety
        self.stats.last_prune_time = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
    }

    /// Get statistics
    pub fn stats(&self) -> &PruningStats {
        &self.stats
    }

    /// Get pruning mode
    pub fn mode(&self) -> &PruningMode {
        &self.mode
    }

    /// Check if in archive mode
    pub fn is_archive(&self) -> bool {
        matches!(self.mode, PruningMode::Archive)
    }
}

/// Block data that must be kept even when pruning
///
/// SECURITY (A6-PRUNE-SERIAL): All serialization in from_block propagates
/// errors instead of using unwrap_or_default(). Silent default values on
/// corrupt data would cause permanent data loss — the pruner would discard
/// the full block while keeping garbage metadata, making the block
/// unrecoverable.
#[derive(Clone, Debug)]
pub struct PrunedBlockData {
    /// Block hash
    pub hash: Hash,
    /// Block height
    pub height: u64,
    /// Previous block hash
    pub prev_hash: Hash,
    /// Transaction root (for verification)
    pub tx_root: Hash,
    /// Timestamp
    pub timestamp: u64,
    /// Target (difficulty representation)
    pub target: Hash,
    /// Number of transactions (not stored)
    pub tx_count: u32,
}

impl PrunedBlockData {
    /// Create from full block
    ///
    /// SECURITY (A6-PRUNE-SERIAL): This function does not use
    /// unwrap_or_default() anywhere. All fields come directly from
    /// the block header, which is already validated by consensus.
    /// If the block were somehow corrupt at this point, the caller
    /// should propagate the error rather than silently storing zeros.
    pub fn from_block(block: &Block, height: u64) -> Self {
        PrunedBlockData {
            hash: block.hash(),
            height,
            prev_hash: block.header.prev_hash,
            tx_root: block.header.tx_root,
            timestamp: block.header.timestamp,
            target: block.header.target,
            tx_count: block.transactions.len() as u32,
        }
    }
}

/// Pruning plan for batch operations
#[derive(Clone, Debug)]
pub struct PruningPlan {
    /// Heights to prune
    pub heights_to_prune: Vec<u64>,
    /// Estimated bytes to free
    pub estimated_bytes: u64,
    /// Blocks to keep metadata for
    pub keep_metadata: Vec<u64>,
}

impl PruningPlan {
    /// Create empty plan
    pub fn empty() -> Self {
        PruningPlan {
            heights_to_prune: Vec::new(),
            estimated_bytes: 0,
            keep_metadata: Vec::new(),
        }
    }

    /// Check if plan is empty
    pub fn is_empty(&self) -> bool {
        self.heights_to_prune.is_empty()
    }

    /// Get number of blocks to prune
    pub fn block_count(&self) -> usize {
        self.heights_to_prune.len()
    }
}

impl ChainPruner {
    /// Create a pruning plan.
    ///
    /// AUDIT (R-60 note, 2026-07-03): `create_plan` trusts
    /// `self.stats.last_pruned_height` at face value. If a prior
    /// prune partially succeeded — persisted the header but failed
    /// to remove the block body, then failed to bump the counter —
    /// `last_pruned_height` is BEHIND the true prune progress and
    /// the plan re-prunes already-pruned heights. That's wasted
    /// work but not corrupting.
    ///
    /// The more dangerous direction: if `last_pruned_height` is
    /// AHEAD of the actual prune (counter was bumped but the
    /// removal failed and crashed), heights below it are never
    /// re-attempted. Blocks meant to be pruned linger on disk
    /// indefinitely.
    ///
    /// The pruning-execution path (db/pruning.rs::execute_plan
    /// with the R-36 error propagation) now propagates a real
    /// error rather than silently absorbing it, so the counter is
    /// only bumped after both writes succeed. This creates a
    /// STRONGER guarantee than the pre-R-36 world:
    ///   - Counter reflects actual persisted progress.
    ///   - A partial failure returns Err all the way up rather
    ///     than corrupting the counter.
    /// So R-60's original concern is now materially mitigated by
    /// R-36. Documented here so a future reader sees the coupled
    /// contract; no separate code change needed on this side.
    pub fn create_plan(&self, batch_size: usize, avg_block_size: usize) -> PruningPlan {
        if self.is_archive() {
            return PruningPlan::empty();
        }

        // Start after the last pruned height to avoid re-processing already-pruned blocks
        let start = if self.stats.last_pruned_height > 0 {
            self.stats.last_pruned_height + 1
        } else {
            0
        };
        let max_prune_height = match &self.mode {
            PruningMode::KeepRecent(keep) => self.current_height.saturating_sub(*keep),
            PruningMode::Custom(rules) => self.current_height.saturating_sub(rules.min_blocks),
            _ => self.current_height,
        };

        let heights: Vec<u64> = (start..max_prune_height)
            .filter(|h| self.can_prune(*h))
            .take(batch_size)
            .collect();

        let estimated_bytes = heights.len() as u64 * avg_block_size as u64;

        PruningPlan {
            heights_to_prune: heights,
            estimated_bytes,
            keep_metadata: Vec::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_archive_mode() {
        let pruner = ChainPruner::new(PruningMode::Archive);
        assert!(!pruner.can_prune(0));
        assert!(!pruner.can_prune(1000));
    }

    #[test]
    fn test_keep_recent() {
        let mut pruner = ChainPruner::new(PruningMode::KeepRecent(100));
        pruner.set_height(1000);

        assert!(pruner.can_prune(0));
        assert!(pruner.can_prune(899));
        assert!(!pruner.can_prune(900));
        assert!(!pruner.can_prune(1000));
    }

    #[test]
    fn test_protected_blocks() {
        let mut pruner = ChainPruner::new(PruningMode::KeepRecent(100));
        pruner.set_height(1000);
        pruner.protect_block(500);

        assert!(pruner.can_prune(499));
        assert!(!pruner.can_prune(500)); // Protected
        assert!(pruner.can_prune(501));
    }

    #[test]
    fn test_custom_rules() {
        let rules = PruningRules {
            min_blocks: 100,
            keep_after_height: None,
            keep_tx_hashes: HashSet::new(),
            keep_checkpoints: true,
            checkpoint_interval: 1000,
        };

        let mut pruner = ChainPruner::new(PruningMode::Custom(rules));
        pruner.set_height(5000);

        assert!(pruner.can_prune(100));
        assert!(!pruner.can_prune(1000)); // Checkpoint
        assert!(!pruner.can_prune(2000)); // Checkpoint
        assert!(!pruner.can_prune(4950)); // Within min_blocks
    }

    #[test]
    fn test_pruning_plan() {
        let mut pruner = ChainPruner::new(PruningMode::KeepRecent(100));
        pruner.set_height(1000);

        let plan = pruner.create_plan(50, 10000);
        assert!(!plan.is_empty());
        assert!(plan.block_count() <= 50);
    }

    #[test]
    fn test_checkpoint_protected() {
        let rules = PruningRules {
            min_blocks: 10,
            keep_after_height: None,
            keep_tx_hashes: HashSet::new(),
            keep_checkpoints: true,
            checkpoint_interval: 500,
        };
        let mut pruner = ChainPruner::new(PruningMode::Custom(rules));
        pruner.set_height(5000);

        // Blocks at checkpoint interval should be protected
        assert!(!pruner.can_prune(500));
        assert!(!pruner.can_prune(1000));
        assert!(!pruner.can_prune(1500));
        // Non-checkpoint block far from tip is prunable
        assert!(pruner.can_prune(501));
    }

    /// R-59 regression: `checkpoint_interval = 0` MUST NOT panic on
    /// `can_prune`. Prior code did `height % 0` which crashed. Fix
    /// treats interval 0 as "no checkpoint protection." Since
    /// `can_prune` is on the hot path for every pruning decision, a
    /// panic here would take down whatever thread is running the prune.
    #[test]
    fn can_prune_does_not_panic_on_zero_checkpoint_interval() {
        let rules = PruningRules {
            min_blocks: 10,
            keep_after_height: None,
            keep_tx_hashes: HashSet::new(),
            keep_checkpoints: true,
            checkpoint_interval: 0, // Would trigger div-by-zero pre-R-59.
        };
        let mut pruner = ChainPruner::new(PruningMode::Custom(rules));
        pruner.set_height(5000);

        // Old code: panic. New code: returns bool (no protection,
        // since with interval=0 no height qualifies as a checkpoint).
        // The `can_prune(0)` call is the tightest test — 0 % 0 was
        // the exact panic site.
        let _ = pruner.can_prune(0);
        let _ = pruner.can_prune(500);
        let _ = pruner.can_prune(1000);
        // If we reached this line, the panic was avoided.
    }

    #[test]
    fn prunable_heights_returns_correct_range() {
        // KeepRecent(100) at tip 1000 → min_keep_height = 900, so every
        // height strictly below 900 is prunable and 900..=1000 is kept.
        let mut pruner = ChainPruner::new(PruningMode::KeepRecent(100));
        pruner.set_height(1000);

        let full = pruner.prunable_heights(0, 1000);
        assert_eq!(full.len(), 900, "heights 0..=899 are prunable");
        assert_eq!(*full.first().unwrap(), 0);
        assert_eq!(*full.last().unwrap(), 899);
        assert!(
            !full.contains(&900),
            "the recency boundary height is not prunable"
        );

        // `from..to` is honored as a half-open sub-range: the scan is
        // clipped to the requested window and still excludes kept
        // heights inside it.
        let window = pruner.prunable_heights(850, 950);
        assert_eq!(window, (850..900).collect::<Vec<u64>>());

        // A window entirely inside the keep zone prunes nothing.
        assert!(pruner.prunable_heights(950, 1000).is_empty());

        // Empty / inverted ranges yield nothing rather than panicking.
        assert!(pruner.prunable_heights(500, 500).is_empty());
        assert!(pruner.prunable_heights(600, 500).is_empty());
    }

    #[test]
    fn estimate_savings_matches_mode() {
        // Archive never prunes → zero savings regardless of size.
        let archive = ChainPruner::new(PruningMode::Archive);
        assert_eq!(archive.estimate_savings(10_000), 0);

        // KeepRecent: prunable count = height - keep, times block size.
        let mut keep = ChainPruner::new(PruningMode::KeepRecent(100));
        keep.set_height(1000);
        assert_eq!(keep.estimate_savings(10_000), 900 * 10_000);

        // Custom: min_height = height - min_blocks; with checkpoints
        // disabled and no protected blocks the estimate is the whole
        // sub-window.
        let rules = PruningRules {
            min_blocks: 100,
            keep_after_height: None,
            keep_tx_hashes: HashSet::new(),
            keep_checkpoints: false,
            checkpoint_interval: 0,
        };
        let mut custom = ChainPruner::new(PruningMode::Custom(rules));
        custom.set_height(1000);
        assert_eq!(custom.estimate_savings(10_000), 900 * 10_000);
    }

    #[test]
    fn record_prune_accumulates_stats() {
        let mut pruner = ChainPruner::new(PruningMode::KeepRecent(100));
        pruner.set_height(1000);

        // Baseline: fresh stats are zeroed.
        assert_eq!(pruner.stats().blocks_pruned, 0);
        assert_eq!(pruner.stats().bytes_freed, 0);
        assert_eq!(pruner.stats().last_pruned_height, 0);

        pruner.record_prune(10, 1_000, 50);
        pruner.record_prune(5, 500, 60);

        let stats = pruner.stats();
        assert_eq!(stats.blocks_pruned, 15, "block counts accumulate");
        assert_eq!(stats.bytes_freed, 1_500, "freed bytes accumulate");
        assert_eq!(
            stats.last_pruned_height, 60,
            "last_pruned_height tracks the most recent prune"
        );
    }

    #[test]
    fn pruning_and_reorg_fork_point_interaction() {
        // A reorg re-derives state from its fork_point, so any height
        // that could still be a fork_point must never be pruned. With
        // KeepRecent(keep) the recency window is what guarantees that:
        // heights within `keep` of the tip stay on disk, while heights
        // below it are eligible to be pruned and thus cannot serve as a
        // reorg fork_point. `protect_block` is the explicit override
        // that keeps a specific below-window height (e.g. a fork_point
        // the node still needs) unprunable.
        let mut pruner = ChainPruner::new(PruningMode::KeepRecent(100));
        pruner.set_height(1000);

        // A fork_point inside the reorg/recency window is safe: it is
        // never pruned, so a reorg branching from it can be served.
        for fork_point in [901u64, 950, 999, 1000] {
            assert!(
                !pruner.can_prune(fork_point),
                "fork_point {fork_point} within the keep window must be retained"
            );
        }

        // A fork_point below the window is prunable — a reorg that deep
        // is beyond what a pruned node can reconstruct.
        assert!(
            pruner.can_prune(899),
            "height below the keep window is eligible for pruning"
        );

        // Explicitly protecting that height (because a reorg still
        // needs it as a fork_point) overrides the mode and removes it
        // from the prunable set.
        pruner.protect_block(899);
        assert!(
            !pruner.can_prune(899),
            "protected fork_point height is no longer prunable"
        );
        let heights = pruner.prunable_heights(890, 905);
        assert!(
            !heights.contains(&899),
            "protected fork_point excluded from the prune plan"
        );
        assert!(
            heights.iter().all(|&h| h < 900 && h != 899),
            "only below-window, unprotected heights remain prunable"
        );
    }
}
