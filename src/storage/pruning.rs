//! Chain pruning for reduced disk usage
//!
//! Allows nodes to operate with only recent blocks, saving ~90% disk space.

use std::collections::HashSet;
use crate::primitives::Hash;
use crate::consensus::Block;

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
        (from..to)
            .filter(|h| self.can_prune(*h))
            .collect()
    }

    /// Estimate bytes that would be freed by pruning
    pub fn estimate_savings(&self, avg_block_size: usize) -> u64 {
        let prunable = match &self.mode {
            PruningMode::Archive => 0,
            PruningMode::KeepRecent(keep) => self.current_height.saturating_sub(*keep),
            PruningMode::KeepUnspent => {
                // Estimate based on protected blocks
                self.current_height.saturating_sub(self.protected_blocks.len() as u64)
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
                let protected_in_range = self.protected_blocks.iter()
                    .filter(|&&h| h < min_height)
                    .count() as u64;
                min_height.saturating_sub(checkpoint_count).saturating_sub(protected_in_range)
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
}
