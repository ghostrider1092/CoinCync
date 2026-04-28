//! # Database Pruning Operations
//!
//! Executes pruning plans against the sled database, removing full block data
//! and storing compact `PrunedBlockData` headers in their place.

use serde::{Serialize, Deserialize};
use borsh::{BorshSerialize, BorshDeserialize};

use crate::db::Database;
use crate::error::Result;
use crate::storage::{PruningPlan, PrunedBlockData};

/// Result of a pruning operation
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PruneResult {
    /// Number of blocks pruned
    pub blocks_pruned: u64,
    /// Estimated bytes freed
    pub bytes_freed: u64,
    /// Height range pruned
    pub from_height: u64,
    pub to_height: u64,
}

/// Execute a pruning plan against the database.
///
/// For each height in the plan:
/// 1. Read the full block from `blocks` tree
/// 2. Store a `PrunedBlockData` header in `pruned_blocks` tree
/// 3. Remove the full block from `blocks` tree
///
/// Returns the number of blocks pruned and bytes freed.
pub fn prune_blocks(db: &Database, plan: &PruningPlan) -> Result<PruneResult> {
    if plan.is_empty() {
        return Ok(PruneResult {
            blocks_pruned: 0,
            bytes_freed: 0,
            from_height: 0,
            to_height: 0,
        });
    }

    let mut blocks_pruned = 0u64;
    let mut bytes_freed = 0u64;
    let from_height = plan.heights_to_prune.first().copied().unwrap_or(0);
    let to_height = plan.heights_to_prune.last().copied().unwrap_or(0);

    for &height in &plan.heights_to_prune {
        // Try to get the block from the database
        if let Some(block) = db.blocks.get_by_height(height)? {
            // Create compact header
            let pruned_data = PrunedBlockData::from_block(&block, height);

            // Serialize the pruned header
            let header_bytes = borsh::to_vec(&PrunedBlockRecord {
                hash: pruned_data.hash.as_bytes().to_vec(),
                height: pruned_data.height,
                prev_hash: pruned_data.prev_hash.as_bytes().to_vec(),
                tx_root: pruned_data.tx_root.as_bytes().to_vec(),
                timestamp: pruned_data.timestamp,
                target: pruned_data.target.as_bytes().to_vec(),
                tx_count: pruned_data.tx_count,
            }).unwrap_or_default();

            // Store pruned header
            db.blocks.store_pruned_header(height, &header_bytes)?;

            // Get original block size for stats
            let block_bytes = borsh::to_vec(&block).unwrap_or_default();
            bytes_freed += block_bytes.len() as u64;

            // Remove full block data
            db.blocks.remove_by_height(height)?;

            blocks_pruned += 1;
        }
    }

    Ok(PruneResult {
        blocks_pruned,
        bytes_freed,
        from_height,
        to_height,
    })
}

/// Check if a block at the given height has been pruned.
pub fn is_pruned(db: &Database, height: u64) -> bool {
    db.blocks.has_pruned_header(height)
}

/// Serializable pruned block record for sled storage.
#[derive(Clone, Debug, BorshSerialize, BorshDeserialize)]
struct PrunedBlockRecord {
    hash: Vec<u8>,
    height: u64,
    prev_hash: Vec<u8>,
    tx_root: Vec<u8>,
    timestamp: u64,
    target: Vec<u8>,
    tx_count: u32,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_empty_plan() {
        let plan = PruningPlan::empty();
        let db = Database::open_temp().unwrap();
        let result = prune_blocks(&db, &plan).unwrap();
        assert_eq!(result.blocks_pruned, 0);
        assert_eq!(result.bytes_freed, 0);
    }

    #[test]
    fn test_partial_prune() {
        // Pruning heights that don't exist in the DB should succeed with 0 pruned
        let db = Database::open_temp().unwrap();
        let mut plan = PruningPlan::empty();
        plan.heights_to_prune = vec![100, 200, 300];
        let result = prune_blocks(&db, &plan).unwrap();
        // No blocks at those heights, so nothing pruned
        assert_eq!(result.blocks_pruned, 0);
    }
}
