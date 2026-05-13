//! # Blockchain State Machine
//!
//! Core blockchain state management.

use std::collections::HashMap;
use std::sync::Arc;
use parking_lot::RwLock;

use crate::primitives::{Hash, Amount, KeyImage};
use crate::transaction::{DecoyOutput, Transaction};
use crate::consensus::{Block, calculate_difficulty, DifficultyBlock, max_target};
use crate::emission::calculate_block_reward;
use crate::error::{Error, Result};
use crate::db::{Database, ChainStateData, OutputIndexEntry};
use crate::storage::UtxoSet;
use crate::config::NetworkType;

/// Auto-checkpoint interval: record a checkpoint every N blocks
/// Checkpoint interval: every 5 blocks (~10 minutes at 120s block time).
/// C-5 FIX: Auto-checkpoint interval. Was 5 (10 minutes at 120s blocks) which
/// caused permanent chain splits on network partitions > 10 minutes.
/// Set to 144 (~5 hours) — absorbs realistic partitions while still protecting
/// against long-range reorg attacks. The local constant was removed to prevent
/// shadowing the global `constants::CHECKPOINT_INTERVAL`.
///
/// Uses the global constant from constants.rs instead of a local shadow.
// Previously: const CHECKPOINT_INTERVAL: u64 = 5;  // REMOVED — see C-5 fix

/// Returns the max reorg depth for a given network.
/// Absolute maximum reorg depth. Beyond this, reorg is rejected outright.
/// This is the final safety net — hard finality.
pub fn max_reorg_depth_for(network: NetworkType) -> u64 {
    match network {
        NetworkType::Testnet | NetworkType::Regtest => 1000,
        NetworkType::Mainnet => 100,
    }
}

/// Returns the absolute maximum reorg depth for the current network.
pub fn max_reorg_depth() -> u64 {
    #[cfg(feature = "testnet")]
    { 1000 }
    #[cfg(not(feature = "testnet"))]
    { 100 }
}

// ═══ HYBRID REORG DEFENSE (H-16 FIX) ═══════════════════════════════════════
//
// Three-tier defense against deep chain reorganizations:
//
// Tier 1 (depth ≤ 10): Unconditional acceptance if fork has more work.
//   Normal network jitter, race conditions, brief connectivity issues.
//   Standard Nakamoto longest-chain rule applies.
//
// Tier 2 (depth 11-100): MESS-style exponential cost multiplier.
//   Fork must demonstrate SIGNIFICANTLY more cumulative work to be accepted.
//   Required work multiplier = 2^((depth - 10) / 20)
//   At depth 30: fork needs 2x honest chain's work
//   At depth 50: fork needs 4x
//   At depth 70: fork needs 8x
//   At depth 90: fork needs 16x
//   This makes rental-hashrate attacks economically infeasible at depth.
//
// Tier 3 (depth > 100): Hard reject. Absolute finality.
//   No amount of work can reorg past this depth.
//   Combined with rolling checkpoints for defense in depth.
//
// Historical precedent:
//   - ETC 2019: 100+ block reorg, $1.1M double-spend
//   - Bitcoin Gold 2018: deep reorg, $18M stolen
//   - Horizen 2018: deep reorg, $550K stolen
//   All were low-hashrate PoW chains without progressive reorg resistance.
//
// Reference: Ethereum Classic MESS (EIP-ECIP-1100)

/// The depth below which reorgs are unconditionally accepted (standard Nakamoto rule).
pub const REORG_UNCONDITIONAL_DEPTH: u64 = 10;

/// The exponent divisor for MESS-style cost scaling.
/// Work multiplier = 2^((depth - REORG_UNCONDITIONAL_DEPTH) / MESS_EXPONENT_DIVISOR)
/// Higher divisor = gentler curve. 20 means doubling every 20 blocks above threshold.
pub const MESS_EXPONENT_DIVISOR: u64 = 20;

/// Tier-2 MESS is disabled below this tip height. During chain bootstrap every
/// box that boots independently can mine its own h=1 at floor difficulty, and
/// the work-multiplier defense would permanently lock those parallel forks in
/// place because none of them can ever satisfy 2^x of the others. Matches the
/// shape of the ring-size bootstrap relaxation (`BOOTSTRAP_MIN_RING_SIZE`): a
/// young chain has too little cumulative work for MESS to be meaningful, and
/// the per-DB checkpoint plus Tier-3 hard cap still bound how far an attacker
/// can reach.
pub const BOOTSTRAP_MESS_HEIGHT: u64 = 1000;

/// Evaluate whether a reorg at `depth` with `fork_work` cumulative work should
/// be accepted given `honest_work` on the current chain. `current_height` is the
/// caller's current tip; below `BOOTSTRAP_MESS_HEIGHT` we skip Tier-2 MESS.
///
/// Returns `Ok(())` if the reorg is acceptable, `Err(reason)` if rejected.
pub fn evaluate_reorg_acceptability(
    depth: u64,
    fork_work: u128,
    honest_work: u128,
    current_height: u64,
) -> std::result::Result<(), String> {
    // Tier 3: Hard reject beyond absolute max depth
    let max = max_reorg_depth();
    if depth > max {
        return Err(format!(
            "Reorg depth {} exceeds absolute maximum {} (hard finality)",
            depth, max
        ));
    }

    // Tier 1: Unconditional acceptance for shallow reorgs
    if depth <= REORG_UNCONDITIONAL_DEPTH {
        if fork_work > honest_work {
            return Ok(());
        } else {
            return Err(format!(
                "Fork at depth {} has less work ({} <= {})",
                depth, fork_work, honest_work
            ));
        }
    }

    // Bootstrap phase: skip Tier-2 MESS, fall back to plain longest-chain.
    if current_height < BOOTSTRAP_MESS_HEIGHT {
        if fork_work > honest_work {
            return Ok(());
        } else {
            return Err(format!(
                "Fork at depth {} has less work ({} <= {}) (bootstrap phase, MESS disabled)",
                depth, fork_work, honest_work
            ));
        }
    }

    // Tier 2: MESS — exponential cost multiplier
    // Required: fork_work > honest_work * 2^((depth - 10) / 20)
    let exponent = (depth - REORG_UNCONDITIONAL_DEPTH) / MESS_EXPONENT_DIVISOR;
    // Cap exponent to prevent overflow (2^40 is already absurdly high)
    let capped_exponent = exponent.min(40);
    let multiplier: u128 = 1u128 << capped_exponent;

    let required_work = honest_work.saturating_mul(multiplier);

    if fork_work > required_work {
        tracing::warn!(
            "MESS: Accepting deep reorg at depth {} (fork_work {} > required {} = honest {} * 2^{})",
            depth, fork_work, required_work, honest_work, capped_exponent
        );
        Ok(())
    } else {
        Err(format!(
            "MESS rejection: depth {} requires {}x work (2^{}). Fork has {} but needs {} (honest={})",
            depth, multiplier, capped_exponent, fork_work, required_work, honest_work
        ))
    }
}

/// Shared blockchain type for concurrent access
pub type SharedBlockchain = Arc<Blockchain>;

/// Block validation status
#[derive(Debug, Clone)]
pub enum BlockStatus {
    /// Block accepted as new tip
    Accepted,
    /// Block accepted but caused a reorg
    AcceptedFork,
    /// Block accepted after reorg. Contains non-coinbase txs from disconnected blocks
    /// that should be returned to the mempool.
    AcceptedReorg {
        /// Non-coinbase transactions from orphaned blocks, for mempool restoration
        orphaned_txs: Vec<crate::transaction::Transaction>,
    },
    /// Block already known
    AlreadyKnown,
    /// Block is orphan (missing parent)
    Orphan,
    /// Block is invalid
    Invalid(String),
}

/// Chain tip information
#[derive(Debug, Clone)]
pub struct ChainTip {
    pub hash: Hash,
    pub height: u64,
    pub difficulty: u128,
    pub timestamp: u64,
}

/// Chain statistics
#[derive(Debug, Clone, Default)]
pub struct ChainStats {
    pub height: u64,
    pub total_blocks: u64,
    pub total_transactions: u64,
    pub total_supply: Amount,
    pub difficulty: u128,
    pub tip_hash: Hash,
    pub total_difficulty: u128,
}

/// Maximum chain events to keep in the ring buffer
const MAX_CHAIN_EVENTS: usize = 500;

/// A recorded chain event for the explorer convergence timeline.
#[derive(Debug, Clone, serde::Serialize)]
pub struct ChainEvent {
    /// Event type
    pub event_type: ChainEventType,
    /// Block height related to event
    pub height: u64,
    /// Block hash related to event
    pub hash: String,
    /// Unix timestamp when the event occurred
    pub timestamp: u64,
    /// Additional details
    pub details: serde_json::Value,
}

/// Types of chain events tracked for the explorer.
#[derive(Debug, Clone, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ChainEventType {
    /// New block accepted on main chain
    BlockAccepted,
    /// Fork block received (not yet heavier)
    ForkDetected,
    /// Chain reorganization performed
    Reorg,
    /// Orphan block received (missing parent)
    OrphanReceived,
    /// Invalid block rejected
    BlockRejected,
    /// Checkpoint recorded
    CheckpointRecorded,
}

/// Maximum number of blocks to keep in the in-memory cache.
/// Older blocks are evicted (LRU by height) and fall back to database lookup.
const MAX_BLOCK_CACHE: usize = 500;

/// Internal mutable state
struct BlockchainInner {
    /// Block storage by hash (in-memory cache, bounded to MAX_BLOCK_CACHE)
    blocks: HashMap<Hash, Block>,
    /// Height to hash mapping (in-memory cache)
    height_to_hash: HashMap<u64, Hash>,
    /// Current chain tip
    tip: ChainTip,
    /// Chain statistics
    stats: ChainStats,
    /// Genesis hash
    genesis_hash: Option<Hash>,
    /// UTXO set for validation (SECURITY C-1)
    utxos: UtxoSet,
    /// Ring buffer of recent chain events for the explorer
    events: std::collections::VecDeque<ChainEvent>,
}

impl BlockchainInner {
    /// Evict blocks from the in-memory cache to stay within MAX_BLOCK_CACHE.
    /// Keeps the most recent blocks (by height) and always retains genesis.
    fn evict_block_cache(&mut self) {
        if self.blocks.len() <= MAX_BLOCK_CACHE {
            return;
        }

        let mut entries: Vec<(u64, Hash)> = self.height_to_hash.iter()
            .map(|(&h, &hash)| (h, hash))
            .collect();
        entries.sort_by_key(|(h, _)| *h);

        let to_evict = self.blocks.len() - MAX_BLOCK_CACHE;
        let mut evicted = 0;
        for (height, hash) in entries {
            if evicted >= to_evict {
                break;
            }
            if height == 0 {
                continue;
            }
            if height + 200 >= self.tip.height {
                continue;
            }
            self.blocks.remove(&hash);
            self.height_to_hash.remove(&height);
            evicted += 1;
        }

        if evicted > 0 {
            tracing::debug!(
                "Block cache eviction: removed {} blocks, cache size now {}",
                evicted, self.blocks.len()
            );
        }
    }
}

/// Blockchain state machine with interior mutability
pub struct Blockchain {
    /// Internal mutable state protected by RwLock
    inner: RwLock<BlockchainInner>,
    /// Database reference (optional)
    db: Option<Arc<Database>>,
    /// Runtime network type — determines genesis, reorg depth, seed nodes
    network: NetworkType,
    /// Sync status from P2P layer (atomic for lock-free reads from RPC)
    synced: std::sync::atomic::AtomicBool,
    /// Target height from P2P peers (0 = no peer info available)
    peer_target_height: std::sync::atomic::AtomicU64,
    /// Unix timestamp of the last block accepted from the P2P layer.
    /// Used by phantom-stall detection in the miner's IBD gate.
    last_block_received_at: std::sync::atomic::AtomicU64,

    // ── Phase 2 privacy stores ──────────────────────────────────────
    // Wrapped in Option — None when Phase 2 is not active.
    // Returns [0u8; 32] roots and no-ops when None.
    pub spark_store: Option<Arc<crate::storage::SparkStore>>,
    pub shielded_store: Option<Arc<crate::storage::ShieldedStore>>,
    pub kernel_store: Option<Arc<crate::storage::KernelStore>>,
    pub cut_through: Option<Arc<parking_lot::Mutex<crate::crypto::mw_cutthrough::CutThroughEngine>>>,
}

/// Extract stats snapshot for structured logging without holding lock in tracing macro.
fn inner_stats_for_log(inner: &RwLock<BlockchainInner>) -> (u128, u64) {
    let guard = inner.read();
    (guard.stats.total_difficulty, guard.stats.total_supply.as_atomic())
}

impl Blockchain {
    /// Create new blockchain with network type
    pub fn new() -> Self {
        Self::new_with_network(NetworkType::Testnet)
    }

    /// Create new blockchain with explicit network type
    pub fn new_with_network(network: NetworkType) -> Self {
        Blockchain {
            inner: RwLock::new(BlockchainInner {
                blocks: HashMap::new(),
                height_to_hash: HashMap::new(),
                tip: ChainTip {
                    hash: Hash::zero(),
                    height: 0,
                    difficulty: 1,
                    timestamp: 0,
                },
                stats: ChainStats::default(),
                genesis_hash: None,
                utxos: UtxoSet::new(),
                events: std::collections::VecDeque::with_capacity(MAX_CHAIN_EVENTS),
            }),
            db: None,
            network,
            synced: std::sync::atomic::AtomicBool::new(true),
            peer_target_height: std::sync::atomic::AtomicU64::new(0),
            last_block_received_at: std::sync::atomic::AtomicU64::new(0),
            // Phase 2 stores: None until Phase 2 activation
            spark_store: None,
            shielded_store: None,
            kernel_store: None,
            cut_through: None,
        }
    }

    /// Create blockchain with database and network type
    pub fn with_database(db: Arc<Database>, network: NetworkType) -> Self {
        Blockchain {
            inner: RwLock::new(BlockchainInner {
                blocks: HashMap::new(),
                height_to_hash: HashMap::new(),
                tip: ChainTip {
                    hash: Hash::zero(),
                    height: 0,
                    difficulty: 1,
                    timestamp: 0,
                },
                stats: ChainStats::default(),
                genesis_hash: None,
                utxos: {
                    let mut u = UtxoSet::new();
                    u.set_database(Arc::clone(&db));
                    u
                },
                events: std::collections::VecDeque::with_capacity(MAX_CHAIN_EVENTS),
            }),
            db: Some(db),
            network,
            synced: std::sync::atomic::AtomicBool::new(true),
            peer_target_height: std::sync::atomic::AtomicU64::new(0),
            last_block_received_at: std::sync::atomic::AtomicU64::new(0),
            // Phase 2 stores: None until Phase 2 activation
            spark_store: None,
            shielded_store: None,
            kernel_store: None,
            cut_through: None,
        }
    }

    /// Returns the network type this blockchain is configured for
    pub fn network(&self) -> NetworkType {
        self.network
    }

    // ── Phase 2 privacy store accessors ─────────────────────────────
    // Returns [0u8; 32] when Phase 2 stores are not initialized (None).

    pub fn shielded_root(&self) -> [u8; 32] {
        self.shielded_store.as_ref().map(|s| s.current_root()).unwrap_or([0u8; 32])
    }

    pub fn spark_root(&self) -> [u8; 32] {
        self.spark_store.as_ref().map(|s| s.current_root()).unwrap_or([0u8; 32])
    }

    pub fn mw_kernel_root(&self) -> [u8; 32] {
        self.kernel_store.as_ref().map(|s| s.current_root()).unwrap_or([0u8; 32])
    }

    pub fn register_cut_through_candidate(
        &self,
        spent_commitment: [u8; 32],
        input_commitment: [u8; 32],
        created_at: u64,
        spent_at: u64,
        kernel: crate::crypto::mw_cutthrough::MwKernel,
    ) {
        if let Some(ref ct) = self.cut_through {
            ct.lock().register_spend(spent_commitment, input_commitment, created_at, spent_at, kernel);
        }
    }

    pub fn cut_through_stats(&self) -> crate::crypto::mw_cutthrough::CutThroughStats {
        self.cut_through.as_ref()
            .map(|ct| ct.lock().stats())
            .unwrap_or_default()
    }

    /// Initialize genesis block
    pub fn init_genesis(&self) -> Result<Hash> {
        let genesis = create_genesis_block_for(self.network);
        let hash = genesis.hash();

        // SECURITY: Verify genesis hash matches the hardcoded constant.
        // This catches accidental genesis block changes that would cause chain forks.
        let expected = match self.network {
            NetworkType::Testnet | NetworkType::Regtest => crate::testnet::expected_genesis_hash(),
            NetworkType::Mainnet => crate::mainnet::expected_genesis_hash(),
        };
        if hash != expected {
            return Err(Error::InvalidState(format!(
                "Genesis hash mismatch! Computed {} but expected {}. \
                 The genesis block definition may have been altered.",
                hash.to_hex(), expected.to_hex()
            )));
        }

        {
            let mut inner = self.inner.write();
            inner.blocks.insert(hash, genesis.clone());
            inner.height_to_hash.insert(0, hash);
            inner.genesis_hash = Some(hash);

            inner.tip = ChainTip {
                hash,
                height: 0,
                difficulty: 1,
                timestamp: genesis.header.timestamp,
            };

            inner.stats.height = 0;
            inner.stats.total_blocks = 1;
            inner.stats.total_transactions = genesis.transactions.len() as u64;
            inner.stats.tip_hash = hash;
            inner.stats.total_supply = calculate_block_reward(0);

            // SECURITY (CC-001): Apply genesis block transactions to UTXO set
            let batch = UtxoSet::batch_from_block(0, &genesis.transactions);
            inner.utxos.apply_batch(batch);
        }

        // Persist output index for genesis block
        self.persist_output_index(&genesis.transactions, 0);

        // Save to database if available
        if let Some(ref db) = self.db {
            db.blocks.insert(&genesis)?;
            db.blocks.set_height_hash(0, &hash)?;
            db.state.set_genesis_hash(&hash)?;
            let state = ChainStateData {
                tip_hash: hash,
                height: 0,
                total_difficulty: 1,
                total_supply: calculate_block_reward(0).as_atomic(),
                total_burned: 0,
                last_checkpoint: 0,
            };
            db.state.save_state(&state)?;

            // Record genesis as the first checkpoint
            let _ = db.state.add_checkpoint(0, &hash);
        }

        tracing::info!("Genesis block initialized: {}", hash.to_hex());
        Ok(hash)
    }

    /// Verify chain tip integrity after recovering from a poisoned lock.
    /// Compares in-memory tip hash against the database to detect corruption.
    /// Can also be called periodically from the maintenance loop as a health check.
    pub fn verify_tip_integrity(&self) -> Result<()> {
        if let Some(ref db) = self.db {
            if let Some(state) = db.state.get_state()? {
                let inner = self.inner.read();
                if inner.tip.hash != state.tip_hash && inner.tip.height > 0 {
                    tracing::error!(
                        "TIP INTEGRITY MISMATCH: in-memory tip {} (height {}) != DB tip {} (height {}). \
                         Reloading from database.",
                        inner.tip.hash.to_hex()[..16].to_string(),
                        inner.tip.height,
                        state.tip_hash.to_hex()[..16].to_string(),
                        state.height,
                    );
                    drop(inner);
                    return self.load_from_database();
                }
            }
        }
        Ok(())
    }

    /// Load chain state from database
    pub fn load_from_database(&self) -> Result<()> {
        if let Some(ref db) = self.db {
            if let Some(state) = db.state.get_state()? {
                // Load tip block
                if let Some(tip_block) = db.blocks.get(&state.tip_hash)? {
                    let difficulty = calculate_difficulty_from_target(&tip_block.header.target);
                    {
                        let mut inner = self.inner.write();
                        inner.tip = ChainTip {
                            hash: state.tip_hash,
                            height: state.height,
                            difficulty,
                            timestamp: tip_block.header.timestamp,
                        };
                        inner.stats.height = state.height;
                        inner.stats.total_supply = Amount::from_atomic(state.total_supply);
                        inner.stats.tip_hash = state.tip_hash;
                        inner.stats.total_difficulty = state.total_difficulty;
                    }
                    tracing::info!("Loaded chain state: height={}, tip={}", state.height, state.tip_hash.to_hex());

                    // Rebuild UTXO set from stored blocks so that key image
                    // checks and decoy selection work immediately after restart.
                    self.rebuild_utxo_set(state.height)?;

                    // Rebuild tx index if empty (migration for existing chains)
                    if let Some(ref db) = self.db {
                        if db.tx_index_is_empty() && state.height > 0 {
                            tracing::info!("Building tx index for {} blocks...", state.height + 1);
                            let start = std::time::Instant::now();
                            let mut indexed = 0u64;
                            for h in 0..=state.height {
                                if let Some(block) = self.get_block_by_height(h) {
                                    for (idx, tx) in block.transactions.iter().enumerate() {
                                        let _ = db.index_tx(tx.hash().as_bytes(), h, idx as u32);
                                        indexed += 1;
                                    }
                                }
                            }
                            tracing::info!("Tx index built: {} txs in {:.2}s", indexed, start.elapsed().as_secs_f64());
                        }
                    }

                    // Verify tip integrity after loading (catches poisoned lock corruption)
                    self.verify_tip_integrity()?;

                    return Ok(());
                }
            }
        }
        Ok(())
    }

    /// Rebuild in-memory UTXO set by replaying all blocks from the database.
    ///
    /// Called on startup after loading chain state to ensure the UTXO set
    /// (key images, outputs, height index) is fully populated. Without this,
    /// `validate_transaction()` would miss pre-restart key images, allowing
    /// double-spends during the window before re-sync completes.
    fn rebuild_utxo_set(&self, tip_height: u64) -> Result<()> {
        let db = match self.db.as_ref() {
            Some(db) => db,
            None => return Ok(()),
        };

        tracing::info!("Rebuilding UTXO set from {} blocks...", tip_height + 1);
        let start = std::time::Instant::now();

        let mut inner = self.inner.write();
        inner.utxos = UtxoSet::new();
        // Wire up on-disk fallback for output_index cache misses
        if let Some(ref db) = self.db {
            inner.utxos.set_database(Arc::clone(db));
        }

        // Also rebuild in-memory block caches for recent blocks (needed by
        // get_difficulty_blocks, find_fork_point, etc.)
        let cache_depth = 200u64;
        let cache_start = tip_height.saturating_sub(cache_depth);

        let mut prev_hash = Hash::zero(); // genesis prev_hash
        for height in 0..=tip_height {
            match db.blocks.get_by_height(height) {
                Ok(Some(block)) => {
                    // Verify chain link integrity
                    if height > 0 && block.header.prev_hash != prev_hash {
                        tracing::error!(
                            "CHAIN CORRUPTION at height {}: prev_hash {} != expected {}. \
                             Truncating chain to height {}.",
                            height,
                            block.header.prev_hash.to_hex()[..16].to_string(),
                            prev_hash.to_hex()[..16].to_string(),
                            height - 1
                        );
                        // Fix: truncate the tip to the last good height
                        let good_height = height - 1;
                        inner.stats.height = good_height;
                        if let Some(&good_hash) = inner.height_to_hash.get(&good_height) {
                            inner.tip.height = good_height;
                            inner.tip.hash = good_hash;
                            inner.stats.tip_hash = good_hash;
                        }
                        // Remove broken height entries from DB
                        for h in height..=tip_height {
                            let _ = db.blocks.remove_height_hash(h);
                        }
                        // Save corrected state
                        let last_checkpoint = db
                            .state
                            .get_state()
                            .ok()
                            .flatten()
                            .map(|s| s.last_checkpoint)
                            .unwrap_or(0);
                        let state = crate::db::ChainStateData {
                            tip_hash: inner.stats.tip_hash,
                            height: good_height,
                            total_difficulty: inner.stats.total_difficulty,
                            total_supply: inner.stats.total_supply.as_atomic(),
                            total_burned: 0,
                            last_checkpoint,
                        };
                        let _ = db.state.save_state(&state);
                        tracing::warn!(
                            "Chain truncated to height {}. Node will re-sync missing blocks.",
                            good_height
                        );
                        break;
                    }

                    let hash = block.hash();
                    prev_hash = hash;

                    let batch = UtxoSet::batch_from_block(height, &block.transactions);
                    inner.utxos.apply_batch(batch);

                    // Cache recent blocks in memory for fast access
                    if height >= cache_start {
                        inner.height_to_hash.insert(height, hash);
                        inner.blocks.insert(hash, block);
                    }

                    if height > 0 && height % 10000 == 0 {
                        tracing::info!("  UTXO rebuild: {}/{} blocks processed", height, tip_height);
                    }
                }
                Ok(None) => {
                    tracing::warn!("Block at height {} missing during UTXO rebuild", height);
                }
                Err(e) => {
                    tracing::error!("Failed to read block at height {}: {}", height, e);
                    return Err(e);
                }
            }
        }

        // Migration: if the persistent output_index sled tree is empty but we
        // have blocks, bulk-insert from the in-memory output_index that was
        // populated during the replay above.
        if let Some(ref db) = self.db {
            if db.output_index.is_empty() && tip_height > 0 {
                tracing::info!("Migrating output index to persistent storage...");
                let mut migrated = 0u64;
                for (stealth, entry) in inner.utxos.output_index_iter() {
                    if let Err(e) = db.output_index.insert(stealth, entry) {
                        tracing::error!("Failed to migrate output index entry: {}", e);
                    } else {
                        migrated += 1;
                    }
                }
                tracing::info!("Migrated {} output index entries to sled", migrated);
            }
        }

        // Evict old output_index entries to bound memory (~1000 blocks in RAM).
        // Older entries fall back to the on-disk OutputIndexDb.
        inner.utxos.evict_old_outputs(tip_height, 1000);

        let elapsed = start.elapsed();
        tracing::info!(
            "UTXO set rebuilt: {} outputs, {} spent key images, {} blocks in {:.2}s",
            inner.utxos.output_count(),
            inner.utxos.total_outputs_ever(),
            tip_height + 1,
            elapsed.as_secs_f64()
        );

        Ok(())
    }

    /// Persist output index entries for a block's transactions to sled.
    ///
    /// Called after applying a block's UTXO batch. Writes one entry per output
    /// using oldest-wins semantics (matching the in-memory output_index).
    fn persist_output_index(&self, transactions: &[crate::transaction::Transaction], height: u64) {
        if let Some(ref db) = self.db {
            for tx in transactions {
                let is_coinbase = tx.is_coinbase();
                for output in &tx.outputs {
                    let stealth = output.stealth_address.as_bytes();
                    let entry = OutputIndexEntry {
                        commitment: output.commitment,
                        height,
                        is_coinbase,
                        lock_height: output.lock_height,
                    };
                    if let Err(e) = db.output_index.insert(stealth, &entry) {
                        tracing::error!("Failed to persist output index entry: {}", e);
                    }
                }
            }
        }
    }

    /// Remove output index entries for a block's transactions from sled (reorg only).
    fn remove_output_index(&self, transactions: &[crate::transaction::Transaction]) {
        if let Some(ref db) = self.db {
            for tx in transactions {
                for output in &tx.outputs {
                    let stealth = output.stealth_address.as_bytes();
                    if let Err(e) = db.output_index.remove(stealth) {
                        tracing::error!("Failed to remove output index entry: {}", e);
                    }
                }
            }
        }
    }

    /// Get current height
    pub fn height(&self) -> u64 {
        self.inner.read().tip.height
    }

    /// Get current tip
    pub fn tip(&self) -> ChainTip {
        self.inner.read().tip.clone()
    }

    /// Look up a transaction's block height and index via the tx_index.
    pub fn get_tx_location(&self, tx_hash: &[u8]) -> Option<(u64, u32)> {
        self.db.as_ref().and_then(|db| db.get_tx_location(tx_hash))
    }

    /// Get tip hash
    pub fn tip_hash(&self) -> Hash {
        self.inner.read().tip.hash
    }

    /// Get the number of available (unspent) outputs in the UTXO set
    pub fn available_output_count(&self) -> usize {
        self.inner.read().utxos.output_count()
    }

    /// Validate a transaction against the current UTXO set
    /// Used by the miner to pre-validate mempool txs before including in blocks.
    pub fn validate_transaction(&self, tx: &Transaction) -> Result<()> {
        let inner = self.inner.read();
        crate::consensus::validate_transaction(tx, &inner.utxos, inner.tip.height + 1)
    }

    /// Get current difficulty
    pub fn difficulty(&self) -> u128 {
        self.inner.read().tip.difficulty
    }

    /// Get next difficulty (placeholder)
    pub fn next_difficulty(&self) -> u128 {
        self.inner.read().tip.difficulty
    }

    /// Compute the exact target hash for the next block using ASERT difficulty adjustment.
    /// This is the authoritative target that the validator will enforce.
    pub fn next_target(&self) -> Hash {
        let height = self.height() + 1;
        let diff_blocks = self.get_difficulty_blocks(height);
        if diff_blocks.len() >= 2 {
            calculate_difficulty(&diff_blocks, height)
        } else if diff_blocks.len() == 1 {
            // Only genesis exists: maintain genesis difficulty until ASERT has enough data
            diff_blocks[0].target
        } else {
            max_target()
        }
    }

    /// Check if chain is synced (updated by P2P layer via set_sync_info).
    ///
    /// Three conditions, any one of which is sufficient:
    ///   1. The P2P layer flagged us synced explicitly.
    ///   2. We're at or above the highest peer-advertised height.
    ///   3. We're within 2 blocks of that target AND the tip itself is
    ///      recent (younger than 3× the target block time = 6 min).
    ///
    /// Condition 3 covers the steady-state case where a peer announces
    /// a new block (bumping `peer_target_height` by 1) a beat before
    /// we've ingested it. Without this, a chain producing blocks at the
    /// target rate is reported as "syncing" forever — which is what
    /// users of the explorer kept reporting as "the chain stalled".
    /// A fresh tip + tiny overshoot is the textbook "essentially synced"
    /// state; reporting it as such matches user reality.
    pub fn is_synced(&self) -> bool {
        let flag = self.synced.load(std::sync::atomic::Ordering::Relaxed);
        if flag { return true; }
        let h = self.height();
        if h == 0 { return false; }
        let target = self.peer_target_height.load(std::sync::atomic::Ordering::Relaxed);
        if h >= target { return true; }
        // Tolerance for in-flight peer advertisements: ≤2 blocks behind
        // the peer-advertised target, AND tip is fresh enough that the
        // chain is clearly producing blocks (not actually stalled).
        if target.saturating_sub(h) <= 2 {
            let tip_timestamp = self.inner.read().tip.timestamp;
            if let Ok(d) = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
            {
                let now_secs = d.as_secs();
                let age = now_secs.saturating_sub(tip_timestamp);
                // 3× testnet target block time. Same threshold is fine
                // for mainnet (also 120s target).
                const FRESH_TIP_SECS: u64 = 3 * crate::constants::TARGET_BLOCK_TIME;
                if age <= FRESH_TIP_SECS {
                    return true;
                }
            }
        }
        false
    }

    /// Get chain statistics
    pub fn stats(&self) -> ChainStats {
        self.inner.read().stats.clone()
    }

    /// Get block by hash
    pub fn get_block(&self, hash: &Hash) -> Option<Block> {
        // Try in-memory first
        {
            let inner = self.inner.read();
            if let Some(block) = inner.blocks.get(hash) {
                return Some(block.clone());
            }
        }
        // Try database
        if let Some(ref db) = self.db {
            if let Ok(Some(block)) = db.blocks.get(hash) {
                return Some(block);
            }
        }
        None
    }

    /// Get block hash by height
    pub fn get_block_hash(&self, height: u64) -> Option<Hash> {
        // Try in-memory first
        {
            let inner = self.inner.read();
            if let Some(hash) = inner.height_to_hash.get(&height) {
                return Some(*hash);
            }
        }
        // Try database
        if let Some(ref db) = self.db {
            if let Ok(Some(hash)) = db.blocks.get_hash_by_height(height) {
                return Some(hash);
            }
        }
        None
    }

    /// Get block by height
    pub fn get_block_by_height(&self, height: u64) -> Option<Block> {
        if let Some(hash) = self.get_block_hash(height) {
            return self.get_block(&hash);
        }
        None
    }

    /// Restore state from database
    pub fn restore_state(&self, height: u64, tip_hash: Hash, total_difficulty: u128) -> Result<()> {
        {
            let mut inner = self.inner.write();
            inner.tip.height = height;
            inner.tip.hash = tip_hash;
            inner.stats.height = height;
            inner.stats.tip_hash = tip_hash;
            inner.stats.total_difficulty = total_difficulty;
        }
        self.load_from_database()
    }

    /// Rollback the chain to a given height, disconnecting all blocks above it.
    /// Used for deep partition recovery when the sync engine detects a longer
    /// chain that diverges beyond max_reorg_depth().
    ///
    /// Returns the list of non-coinbase transactions from disconnected blocks
    /// (for mempool restoration).
    pub fn rollback_to_height(&self, target_height: u64) -> Result<Vec<Transaction>> {
        let current_height = self.height();
        if target_height >= current_height {
            return Ok(Vec::new());
        }

        // FINALITY: Refuse to rollback past a checkpoint.
        // Checkpoints are final — no amount of hashpower can undo them.
        if let Some(ref db) = self.db {
            if let Ok(Some(state)) = db.state.get_state() {
                if target_height < state.last_checkpoint {
                    tracing::error!(
                        "FINALITY VIOLATION: attempted rollback to {} but checkpoint at {} is final",
                        target_height, state.last_checkpoint
                    );
                    return Err(Error::InvalidState(format!(
                        "Cannot rollback past checkpoint at height {} (finality enforced)",
                        state.last_checkpoint
                    )));
                }
            }
        }

        let depth = current_height - target_height;
        tracing::warn!(
            "Rolling back chain from height {} to {} (depth: {})",
            current_height, target_height, depth
        );

        let mut all_orphaned_txs = Vec::new();
        {
            let mut inner = self.inner.write();

            // Disconnect blocks in reverse height order
            for h in (target_height + 1..=current_height).rev() {
                let orphan_hash = inner.height_to_hash.get(&h).copied();
                if let Some(oh) = orphan_hash {
                    let orphan_txs = inner.blocks.get(&oh)
                        .map(|b| b.transactions.clone());
                    if let Some(txs) = orphan_txs {
                        let disconnect_batch = UtxoSet::batch_disconnect_block(&txs);
                        inner.utxos.apply_batch(disconnect_batch);
                        // Collect non-coinbase txs
                        for tx in &txs {
                            if !tx.is_coinbase() {
                                all_orphaned_txs.push(tx.clone());
                            }
                        }
                        // Subtract emission
                        let emission = calculate_block_reward(h);
                        // C-4/H-11 FIX: checked_sub instead of saturating_sub — underflow = corruption
inner.stats.total_supply = match inner.stats.total_supply.checked_sub(emission) {
    Ok(v) => v,
    Err(_) => { tracing::error!("CORRUPTION: supply underflow on rollback — subtract {} from {}", emission, inner.stats.total_supply); Amount::from_atomic(0) }
};
                    }
                }
                inner.height_to_hash.remove(&h);
            }

            // Update tip to the block at target_height
            if let Some(new_tip_hash) = inner.height_to_hash.get(&target_height).copied() {
                if let Some(tip_block) = inner.blocks.get(&new_tip_hash) {
                    inner.tip = ChainTip {
                        hash: new_tip_hash,
                        height: target_height,
                        difficulty: calculate_difficulty_from_target(&tip_block.header.target),
                        timestamp: tip_block.header.timestamp,
                    };
                } else {
                    // Block not in memory cache, just update height/hash
                    inner.tip.hash = new_tip_hash;
                    inner.tip.height = target_height;
                }
                inner.stats.height = target_height;
                inner.stats.tip_hash = new_tip_hash;
            } else if target_height == 0 {
                // Genesis fallback — height_to_hash may not have it
                if let Some(genesis) = inner.genesis_hash {
                    inner.tip.hash = genesis;
                    inner.tip.height = 0;
                    inner.stats.height = 0;
                    inner.stats.tip_hash = genesis;
                }
            }
        }

        // Remove from database and persist state (db is on Blockchain, not inner)
        if let Some(ref db) = self.db {
            // Clean all stale height entries above target
            if let Err(e) = db.blocks.remove_heights_above(target_height) {
                tracing::error!("Failed to clean heights during rollback: {}", e);
            }
            let inner = self.inner.read();
            let last_checkpoint = db
                .state
                .get_state()
                .ok()
                .flatten()
                .map(|s| s.last_checkpoint)
                .unwrap_or(0);
            let state = ChainStateData {
                height: inner.stats.height,
                tip_hash: inner.stats.tip_hash,
                total_difficulty: inner.stats.total_difficulty,
                total_supply: inner.stats.total_supply.as_atomic(),
                total_burned: 0,
                last_checkpoint,
            };
            let _ = db.state.save_state(&state);
        }

        tracing::info!(
            "Rollback complete: chain at height {}, {} orphaned txs returned",
            target_height, all_orphaned_txs.len()
        );

        Ok(all_orphaned_txs)
    }

    /// Record a chain event in the ring buffer (bounded, lock-free for readers).
    fn record_event(&self, event_type: ChainEventType, height: u64, hash: &Hash, details: serde_json::Value) {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let event = ChainEvent {
            event_type,
            height,
            hash: hash.to_hex(),
            timestamp: now,
            details,
        };
        let mut inner = self.inner.write();
        if inner.events.len() >= MAX_CHAIN_EVENTS {
            inner.events.pop_front();
        }
        inner.events.push_back(event);
    }

    /// Get recent chain events (for explorer).
    pub fn get_events(&self, limit: usize) -> Vec<ChainEvent> {
        let inner = self.inner.read();
        let limit = limit.min(inner.events.len());
        inner.events.iter().rev().take(limit).cloned().collect()
    }

    /// Process/add block to chain
    pub fn process_block(&self, block: Block) -> Result<BlockStatus> {
        self.add_block(block)
    }

    /// Add block to chain
    pub fn add_block(&self, block: Block) -> Result<BlockStatus> {
        let hash = block.hash();

        // Check if already known
        {
            let inner = self.inner.read();
            if inner.blocks.contains_key(&hash) {
                return Ok(BlockStatus::AlreadyKnown);
            }
        }
        if let Some(ref db) = self.db {
            if db.blocks.contains(&hash)? {
                return Ok(BlockStatus::AlreadyKnown);
            }
        }

        // Check parent exists
        let parent_hash = block.header.prev_hash;
        let parent = self.get_block(&parent_hash);

        if parent.is_none() && block.header.height > 0 {
            self.record_event(ChainEventType::OrphanReceived, block.header.height, &hash, serde_json::json!({}));
            return Ok(BlockStatus::Orphan);
        }

        // Validate block height
        let expected_height = if block.header.height == 0 {
            0
        } else {
            parent.as_ref().map(|p| p.header.height + 1).unwrap_or(0)
        };

        if block.header.height != expected_height {
            return Ok(BlockStatus::Invalid(format!(
                "Invalid height: expected {}, got {}",
                expected_height, block.header.height
            )));
        }

        let tip_hash = self.tip_hash();
        let is_main_chain = parent_hash == tip_hash || block.header.height == 0;

        // SECURITY: Enforce hardcoded + recorded checkpoints.
        // If we know the hash at this height, reject blocks that don't match.
        //
        // DB-recorded checkpoints are only enforced once the block is at least
        // RECENT_REORG_DEPTH blocks deep from the tip. This avoids the failure
        // mode that broke the 2026-05-10 launch: every fleet box commits to
        // its first-seen block at every height, so when 5 boxes get blocks
        // from different peers concurrently they record 5 incompatible
        // checkpoint sets and can never accept each other's blocks. By only
        // enforcing once the block is deep enough that reorg is implausible,
        // standard longest-chain fork resolution gets to run first and the
        // fleet converges naturally.
        const RECENT_REORG_DEPTH: u64 = 10;
        let current_tip_height = self.height();
        let too_recent_for_db_checkpoint =
            block.header.height + RECENT_REORG_DEPTH > current_tip_height;
        if let Some(ref db) = self.db {
            if !too_recent_for_db_checkpoint {
                if let Ok(Some(expected_hash)) = db.state.get_checkpoint(block.header.height) {
                    if hash != expected_hash {
                        return Ok(BlockStatus::Invalid(format!(
                            "Checkpoint mismatch at height {}: expected {}, got {}",
                            block.header.height,
                            expected_hash.to_hex()[..16].to_string(),
                            hash.to_hex()[..16].to_string(),
                        )));
                    }
                }
            }
        }
        // Also check hardcoded checkpoints for the active runtime network.
        let hardcoded_checkpoint_match = match self.network {
            crate::config::NetworkType::Mainnet => {
                crate::mainnet::verify_checkpoint(block.header.height, &hash)
            }
            crate::config::NetworkType::Testnet | crate::config::NetworkType::Regtest => {
                crate::testnet::verify_checkpoint(block.header.height, &hash)
            }
        };
        if let Some(false) = hardcoded_checkpoint_match {
            return Ok(BlockStatus::Invalid(format!(
                "Hardcoded checkpoint mismatch at height {}",
                block.header.height,
            )));
        }

        // SECURITY (C-1): Run full consensus validation before accepting blocks.
        // Previously validate_block() was never called, allowing blocks with no PoW,
        // inflated coinbase, forged signatures, and duplicate key images.
        {
            let inner = self.inner.read();
            // During IBD, skip expensive VDF verification for blocks below
            // the last checkpoint (Bitcoin-style "assume-valid"). This makes
            // initial sync 10-100x faster.
            let cp = self.db.as_ref()
                .and_then(|db| db.state.get_state().ok().flatten())
                .and_then(|s| if s.last_checkpoint > 0 { Some(s.last_checkpoint) } else { None });
            let validation = crate::consensus::validate_block_with_checkpoint_for_network(
                &block,
                parent.as_ref(),
                &inner.utxos,
                cp,
                self.network,
            ).map_err(|e| Error::InvalidState(format!("Block validation error: {}", e)))?;
            if !validation.valid {
                let errors = validation.errors.join("; ");
                tracing::warn!("Block {} rejected: {}", &hash.to_hex()[..16], errors);
                drop(inner);
                self.record_event(ChainEventType::BlockRejected, block.header.height, &hash, serde_json::json!({"reason": &errors}));
                return Ok(BlockStatus::Invalid(errors));
            }
        }

        // SECURITY: Median-Time-Past (MTP) validation.
        // Block timestamp must be greater than the median of the last 11 blocks.
        // This prevents miners from backdating blocks to manipulate difficulty.
        if block.header.height >= 11 {
            let mut timestamps: Vec<u64> = Vec::with_capacity(11);
            for h in (block.header.height.saturating_sub(11)..block.header.height).rev() {
                if let Some(ancestor) = self.get_block_by_height(h) {
                    timestamps.push(ancestor.header.timestamp);
                }
                if timestamps.len() >= 11 {
                    break;
                }
            }
            if timestamps.len() >= 11 {
                timestamps.sort_unstable();
                let mtp = timestamps[timestamps.len() / 2];
                if block.header.timestamp <= mtp {
                    return Ok(BlockStatus::Invalid(format!(
                        "Block timestamp {} is not greater than median-time-past {} (median of last 11 blocks)",
                        block.header.timestamp, mtp
                    )));
                }
            }
        }

        // SECURITY (C-2 + C20-FIX): Verify difficulty target matches ASERT calculation.
        // For main-chain blocks, use main-chain history via get_difficulty_blocks().
        // For fork blocks, build a mixed difficulty window: main-chain blocks below
        // the fork point, plus fork-chain blocks above it. This prevents an attacker
        // from constructing a fork with trivially easy targets (the old code used
        // main-chain history for ALL blocks, which could produce wrong expectations
        // for fork blocks OR allow fork blocks to bypass proper difficulty validation).
        if block.header.height >= 1 {
            let difficulty_blocks = if is_main_chain {
                self.get_difficulty_blocks(block.header.height)
            } else {
                // SECURITY (C20-FIX): Build fork-aware difficulty window.
                // Walk the fork chain backwards to find the fork point, then mix
                // main-chain blocks (below fork) with fork blocks (above fork).
                let inner = self.inner.read();
                let window = 144u64; // DIFFICULTY_LONG_WINDOW
                let start = block.header.height.saturating_sub(window);

                // Trace fork chain backwards to find fork point and collect fork blocks
                let mut fork_chain: Vec<(u64, u64, Hash)> = Vec::new(); // (height, timestamp, target)
                let mut cursor_hash = block.header.prev_hash;
                let mut fork_point = 0u64;

                loop {
                    // Check if this hash is on the main chain
                    if let Some(blk) = inner.blocks.get(&cursor_hash) {
                        let h = blk.header.height;
                        // If this block's height has a main-chain mapping that matches,
                        // we've found the fork point
                        if let Some(main_hash) = inner.height_to_hash.get(&h) {
                            if *main_hash == cursor_hash {
                                fork_point = h;
                                break;
                            }
                        }
                        // This is a fork block — add it to our fork chain
                        fork_chain.push((h, blk.header.timestamp, blk.header.target));
                        if h == 0 {
                            break;
                        }
                        cursor_hash = blk.header.prev_hash;
                    } else {
                        // Parent not found — can't validate, use main chain as fallback
                        break;
                    }
                }
                fork_chain.reverse(); // oldest first

                // Build mixed difficulty window
                let mut diff_blocks = Vec::new();
                for h in start..block.header.height {
                    if h <= fork_point {
                        // Below fork point: use main-chain blocks
                        if let Some(hash) = inner.height_to_hash.get(&h) {
                            if let Some(b) = inner.blocks.get(hash) {
                                diff_blocks.push(DifficultyBlock {
                                    height: h,
                                    timestamp: b.header.timestamp,
                                    target: b.header.target,
                                });
                            }
                        }
                    } else {
                        // Above fork point: use fork blocks
                        let offset = (h - fork_point - 1) as usize;
                        if let Some(&(fh, ts, tgt)) = fork_chain.get(offset) {
                            diff_blocks.push(DifficultyBlock {
                                height: fh,
                                timestamp: ts,
                                target: tgt,
                            });
                        }
                    }
                }
                drop(inner);
                diff_blocks
            };

            if difficulty_blocks.len() >= 2 {
                let expected_target = calculate_difficulty(&difficulty_blocks, block.header.height);
                if block.header.target != expected_target {
                    return Ok(BlockStatus::Invalid(format!(
                        "Difficulty target mismatch: expected {}, got {}",
                        expected_target.to_hex()[..16].to_string(),
                        block.header.target.to_hex()[..16].to_string(),
                    )));
                }
            }
        }

        // Store block data (but NOT height index — that's deferred until after
        // the race-condition check for main-chain blocks).
        {
            let mut inner = self.inner.write();
            inner.blocks.insert(hash, block.clone());
            // Fork blocks get height_to_hash here; main-chain defers to after race check.
            if !is_main_chain {
                // Fork blocks never get height mappings (they don't extend the main chain)
            }
        }

        // Save block data to database (height index deferred for main chain)
        if let Some(ref db) = self.db {
            db.blocks.insert(&block)?;
        }

        if is_main_chain {
            // Update tip — but first re-check for race conditions.
            let difficulty = calculate_difficulty_from_target(&block.header.target);
            let race_detected = {
                let mut inner = self.inner.write();

                // SECURITY (RACE-R7): Re-check that tip hasn't changed since our read
                // above. Between reading tip_hash and acquiring this write lock, another
                // thread may have advanced the chain. If so, our is_main_chain decision
                // is stale — the block is now a fork, not a main-chain extension.
                // We do NOT update height_to_hash or DB height index, since the block
                // lost the race. It falls through to the fork-evaluation path below.
                if inner.tip.hash != tip_hash && block.header.height > 0 {
                    tracing::warn!(
                        "Tip changed during block processing (was {}, now {}), re-evaluating block {}",
                        tip_hash.to_hex()[..8].to_string(),
                        inner.tip.hash.to_hex()[..8].to_string(),
                        hash.to_hex()[..8].to_string(),
                    );
                    true
                } else {
                    // Race check passed — safe to apply as main chain.
                    inner.height_to_hash.insert(block.header.height, hash);
                    inner.tip = ChainTip {
                        hash,
                        height: block.header.height,
                        difficulty,
                        timestamp: block.header.timestamp,
                    };
                    inner.stats.height = block.header.height;
                    inner.stats.total_blocks += 1;
                    inner.stats.total_transactions += block.transactions.len() as u64;
                    inner.stats.difficulty = difficulty;
                    inner.stats.tip_hash = hash;
                    inner.stats.total_difficulty += difficulty;

                    // Track supply: new emission (net of burns) enters circulation
                    let emission = calculate_block_reward(block.header.height);
                    inner.stats.total_supply = inner.stats.total_supply.saturating_add(emission);

                    // SECURITY (CC-001): Apply block's UTXO mutations to track spent/unspent
                    let batch = UtxoSet::batch_from_block(block.header.height, &block.transactions);
                    inner.utxos.apply_batch(batch);

                    // Bound memory: evict output_index entries older than 1000 blocks
                    inner.utxos.evict_old_outputs(block.header.height, 1000);

                    // SECURITY: Evict old blocks from in-memory cache to prevent
                    // unbounded RAM growth. Older blocks fall back to database lookup.
                    inner.evict_block_cache();

                    false
                }
            }; // write lock released

            if race_detected {
                // Fall through to the fork-evaluation path below.
                // The block is stored but not applied. The fork path will check
                // cumulative work and perform a reorg if this block's chain is heavier.
            } else {
                // Post-lock work: persist to database, record checkpoints.
                self.persist_output_index(&block.transactions, block.header.height);

                // Index transactions for O(1) lookup by hash
                if let Some(ref db) = self.db {
                    for (idx, tx) in block.transactions.iter().enumerate() {
                        let _ = db.index_tx(tx.hash().as_bytes(), block.header.height, idx as u32);
                    }
                }

                // Update database height index (only after race check passes)
                if let Some(ref db) = self.db {
                    db.blocks.set_height_hash(block.header.height, &hash)?;

                    // Auto-record checkpoint every CHECKPOINT_INTERVAL blocks
                    let mut last_checkpoint_height = 0u64;
                    if block.header.height > 0 && block.header.height % crate::constants::CHECKPOINT_INTERVAL == 0 {
                        if let Err(e) = db.state.add_checkpoint(block.header.height, &hash) {
                            tracing::error!("Failed to record checkpoint at height {}: {}", block.header.height, e);
                        } else {
                            last_checkpoint_height = block.header.height;
                            tracing::info!(
                                "Auto-checkpoint recorded: height={}, hash={}",
                                block.header.height,
                                hash.to_hex()[..16].to_string()
                            );
                            self.record_event(ChainEventType::CheckpointRecorded, block.header.height, &hash, serde_json::json!({}));
                        }
                    }

                    // Compute last_checkpoint from DB if we didn't just set one
                    if last_checkpoint_height == 0 {
                        if let Ok(Some(prev_state)) = db.state.get_state() {
                            last_checkpoint_height = prev_state.last_checkpoint;
                        }
                    }

                    let stats = self.stats();
                    let state = ChainStateData {
                        tip_hash: hash,
                        height: block.header.height,
                        total_difficulty: stats.total_difficulty,
                        total_supply: stats.total_supply.as_atomic(),
                        total_burned: 0,
                        last_checkpoint: last_checkpoint_height,
                    };
                    db.state.save_state(&state)?;
                }

                // ── Phase 2 privacy store wire-up (P3d) ─────────────────
                //
                // After a block is accepted on the main chain, checkpoint
                // the shielded commitment tree so a future reorg can
                // rewind it, and run the MW cut-through engine to emit
                // any commitments eligible for pruning.
                if let Some(ref store) = self.shielded_store {
                    store.checkpoint_at_height(block.header.height);
                }
                if let Some(ref ct) = self.cut_through {
                    let mut engine = ct.lock();
                    let prunable = engine.process(block.header.height);
                    if !prunable.is_empty() {
                        tracing::debug!(
                            "MW cut-through: {} commitments prunable at height {}",
                            prunable.len(),
                            block.header.height
                        );
                    }
                }

                // Phase D (audit fix): sync all sled trees to disk before
                // announcing "Accepted" to the network. Without this, a crash
                // in the 1-second async flush window loses the accepted block
                // while peers already believe it is confirmed, causing a fork.
                if let Some(ref db) = self.db {
                    if let Err(e) = db.flush() {
                        tracing::error!("Failed to flush DB after block accept: {}", e);
                    }
                }

                // Structured divergence detection log — compare across nodes to spot forks
                let stats_snapshot = inner_stats_for_log(&self.inner);
                tracing::info!(
                    target: "chain::commit",
                    height = block.header.height,
                    block_hash = %hash.to_hex(),
                    difficulty = difficulty,
                    total_difficulty = stats_snapshot.0,
                    tip = %hash.to_hex(),
                    supply_atomic = stats_snapshot.1,
                    "BLOCK_COMMIT"
                );

                self.record_event(ChainEventType::BlockAccepted, block.header.height, &hash, serde_json::json!({
                    "tx_count": block.transactions.len(),
                    "difficulty": difficulty,
                }));

                return Ok(BlockStatus::Accepted);
            }
        }

        // Fork evaluation path — reached for natural fork blocks AND race-detected blocks.
        {
            // Fork block - check if this fork has more cumulative work
            let fork_difficulty = calculate_difficulty_from_target(&block.header.target);
            let fork_cumulative = self.calculate_fork_cumulative_work(&block);

            let current_total_difficulty = {
                let inner = self.inner.read();
                inner.stats.total_difficulty
            };

            if fork_cumulative > current_total_difficulty {
                // Fork has more work - perform chain reorganization (standard Nakamoto rule)

                // Find the common ancestor (fork point)
                let fork_point = self.find_fork_point(&block);

                // SECURITY (H-16 FIX): Hybrid reorg defense — three tiers.
                // Tier 1 (≤10): unconditional. Tier 2 (11-100): MESS exponential cost.
                // Tier 3 (>100): hard reject.
                let reorg_depth = block.header.height.saturating_sub(fork_point);
                if let Err(reason) = evaluate_reorg_acceptability(
                    reorg_depth, fork_cumulative, current_total_difficulty, self.height()
                ) {
                    tracing::error!(
                        "Rejecting reorg at depth {}: {}",
                        reorg_depth, reason
                    );
                    return Err(Error::ReorgTooDeep {
                        depth: reorg_depth,
                        max: max_reorg_depth(),
                    });
                }

                // SECURITY: Reject reorgs that would revert past the last rolling
                // checkpoint. This prevents long-range reorganization attacks where
                // an attacker builds a hidden chain from far in the past.
                if let Some(ref db) = self.db {
                    let last_cp = db.state.get_state()
                        .ok()
                        .flatten()
                        .map(|s| s.last_checkpoint)
                        .unwrap_or(0);
                    if last_cp > 0 && fork_point < last_cp {
                        tracing::error!(
                            "Rejecting reorg: fork point {} is before last checkpoint at height {}",
                            fork_point, last_cp
                        );
                        return Ok(BlockStatus::Invalid(format!(
                            "Reorg rejected: fork point {} is before checkpoint at height {}",
                            fork_point, last_cp
                        )));
                    }
                }

                tracing::warn!(
                    "Fork at height {} has more work ({} > {}), performing reorg (depth: {})",
                    block.header.height, fork_cumulative, current_total_difficulty, reorg_depth
                );

                // Save pre-reorg state for rollback on fork validation failure
                let pre_reorg_tip = {
                    let inner = self.inner.read();
                    inner.tip.clone()
                };
                let pre_reorg_stats = self.stats();

                // SECURITY (CC-002): Rewind main chain UTXO state to the fork point
                let mut disconnected_blocks: u64 = 0;
                let mut disconnected_txs: u64 = 0;
                let mut disconnected_tx_lists: Vec<Vec<crate::transaction::Transaction>> = Vec::new();
                let mut disconnected_heights: Vec<(u64, Hash)> = Vec::new();
                {
                    let mut inner = self.inner.write();
                    let current_height = inner.tip.height;

                    // Disconnect orphaned blocks in reverse height order
                    for h in (fork_point + 1..=current_height).rev() {
                        let orphan_hash = inner.height_to_hash.get(&h).copied();
                        if let Some(oh) = orphan_hash {
                            // Clone transactions to avoid borrow conflict with utxos
                            let orphan_txs = inner.blocks.get(&oh)
                                .map(|b| b.transactions.clone());
                            if let Some(txs) = orphan_txs {
                                disconnected_blocks += 1;
                                disconnected_txs += txs.len() as u64;
                                // SECURITY (BUG-1): Remove outputs added by the orphaned
                                // block AND un-mark key images spent by its inputs.
                                // batch_disconnect_block now includes key_image_removals.
                                let disconnect_batch = UtxoSet::batch_disconnect_block(&txs);
                                inner.utxos.apply_batch(disconnect_batch);
                                // Phase 2 store rewind. checkpoint_at_height is taken
                                // per-block on the forward path (see ~line 1407); each
                                // rewind() pops the most recent checkpoint, undoing one
                                // block of shielded-tree state. Inert today (the store
                                // is wired as Option=None for the testnet build) but
                                // forward-compatible for the day Phase 2 stores light
                                // up — without this, the shielded tree would diverge
                                // from the UTXO set on every reorg.
                                if let Some(ref s) = self.shielded_store {
                                    if !s.rewind() {
                                        tracing::warn!(
                                            "shielded_store.rewind() returned false at h={} — state may be inconsistent",
                                            h
                                        );
                                    }
                                }
                                // Collect for output index removal
                                disconnected_tx_lists.push(txs);
                                // Subtract this block's emission from supply
                                let emission = calculate_block_reward(h);
                                // C-4/H-11 FIX: checked_sub instead of saturating_sub — underflow = corruption
inner.stats.total_supply = match inner.stats.total_supply.checked_sub(emission) {
    Ok(v) => v,
    Err(_) => { tracing::error!("CORRUPTION: supply underflow on rollback — subtract {} from {}", emission, inner.stats.total_supply); Amount::from_atomic(0) }
};
                            }
                        }
                        if let Some(removed_hash) = inner.height_to_hash.remove(&h) {
                            disconnected_heights.push((h, removed_hash));
                        }
                    }
                }

                // H1 (atomicity fix): The persistent output_index removal that
                // used to live here ran BEFORE fork validation, so a failed
                // reorg left the index missing entries with no rollback path
                // to restore them. The removal is now deferred until AFTER
                // success determination (see the symmetric `persist_output_index`
                // calls below). With this, the persistent output_index transition
                // is all-or-nothing: either the reorg commits and both removals
                // and additions land, or nothing changes on disk.
                //
                // The in-memory utxos are still mutated here (via the disconnect
                // loop above) and restored in the rollback paths below — that
                // part of the architecture was already correct; only the disk
                // persistence was racing validation.

                // SECURITY (A6-REORG-VALIDATE): Validate each fork block before applying.
                // Previously fork blocks were applied to the UTXO set without any
                // validation, allowing blocks with inflated coinbase, forged signatures,
                // or duplicate key images to corrupt the chain state.
                let fork_blocks = self.collect_fork_chain(&block, fork_point);
                let mut reorg_error: Option<String> = None;
                {
                    let mut inner = self.inner.write();

                    for (fork_idx, fork_block) in fork_blocks.iter().enumerate() {
                        // Validate fork block against current UTXO state
                        let parent = inner.blocks.get(&fork_block.header.prev_hash).cloned();
                        let validation = match crate::consensus::validate_block_with_checkpoint_for_network(
                            fork_block,
                            parent.as_ref(),
                            &inner.utxos,
                            None,
                            self.network,
                        ) {
                            Ok(v) => v,
                            Err(e) => {
                                reorg_error = Some(format!("Fork block validation error: {}", e));
                                break;
                            }
                        };
                        if !validation.valid {
                            let errors = validation.errors.join("; ");
                            tracing::warn!("Fork block {} rejected during reorg: {}", fork_block.hash().to_hex(), errors);
                            reorg_error = Some(format!("Invalid fork block: {}", errors));
                            break;
                        }

                        // SECURITY (A6-REORG-DIFFICULTY): Verify fork block difficulty
                        // against fork-chain history. We build DifficultyBlock entries
                        // from main-chain blocks below the fork point, plus already-
                        // validated fork blocks above the fork point.
                        if fork_block.header.height >= 1 {
                            let window = 144u64;
                            let start = fork_block.header.height.saturating_sub(window);
                            let mut diff_blocks = Vec::new();

                            for h in start..fork_block.header.height {
                                if h <= fork_point {
                                    // Below fork point: use main-chain blocks
                                    if let Some(hash) = inner.height_to_hash.get(&h) {
                                        if let Some(b) = inner.blocks.get(hash) {
                                            diff_blocks.push(DifficultyBlock {
                                                height: h,
                                                timestamp: b.header.timestamp,
                                                target: b.header.target,
                                            });
                                        }
                                    }
                                } else {
                                    // Above fork point: use already-validated fork blocks
                                    let offset = (h - fork_point - 1) as usize;
                                    if offset < fork_idx {
                                        let fb = &fork_blocks[offset];
                                        diff_blocks.push(DifficultyBlock {
                                            height: fb.header.height,
                                            timestamp: fb.header.timestamp,
                                            target: fb.header.target,
                                        });
                                    }
                                }
                            }

                            if diff_blocks.len() >= 2 {
                                let expected_target = calculate_difficulty(&diff_blocks, fork_block.header.height);
                                if fork_block.header.target != expected_target {
                                    tracing::warn!(
                                        "Fork block {} at height {} has wrong difficulty target",
                                        fork_block.hash().to_hex(), fork_block.header.height
                                    );
                                    reorg_error = Some(format!(
                                        "Fork block difficulty mismatch at height {}: expected {}, got {}",
                                        fork_block.header.height,
                                        expected_target.to_hex()[..16].to_string(),
                                        fork_block.header.target.to_hex()[..16].to_string(),
                                    ));
                                    break;
                                }
                            }
                        }

                        let fork_hash = fork_block.hash();
                        inner.height_to_hash.insert(fork_block.header.height, fork_hash);
                        if let Some(ref db) = self.db {
                            if let Err(e) = db.blocks.set_height_hash(fork_block.header.height, &fork_hash) {
                                tracing::error!("CRITICAL: Failed to persist reorg height mapping at height {}: {}", fork_block.header.height, e);
                                reorg_error = Some(format!("DB error during reorg: {}", e));
                                break;
                            }
                        }
                        // Apply fork block's UTXO mutations
                        let batch = UtxoSet::batch_from_block(fork_block.header.height, &fork_block.transactions);
                        inner.utxos.apply_batch(batch);

                        // Add this fork block's emission to supply
                        let emission = calculate_block_reward(fork_block.header.height);
                        inner.stats.total_supply = inner.stats.total_supply.saturating_add(emission);
                    }

                    // SECURITY (BUG-2/BUG-4): If fork validation failed, rollback to pre-reorg state.
                    // Without this, a failed reorg leaves the chain in a corrupted state:
                    // main-chain blocks disconnected but fork blocks not applied.
                    if reorg_error.is_some() {
                        tracing::error!(
                            "Reorg failed — rolling back to pre-reorg state (tip={}, height={})",
                            pre_reorg_tip.hash.to_hex()[..16].to_string(),
                            pre_reorg_tip.height,
                        );

                        // SECURITY (BUG-2): Undo partially-applied fork blocks' UTXO mutations.
                        // Previously only height mappings were removed, leaving fork outputs
                        // and key images in the UTXO set, corrupting state.
                        for fork_block in fork_blocks.iter().rev() {
                            if inner.height_to_hash.get(&fork_block.header.height)
                                .map_or(false, |h| *h == fork_block.hash())
                            {
                                let disconnect = UtxoSet::batch_disconnect_block(&fork_block.transactions);
                                inner.utxos.apply_batch(disconnect);
                                // Subtract the emission we added for this fork block
                                let emission = calculate_block_reward(fork_block.header.height);
                                // C-4/H-11 FIX: checked_sub instead of saturating_sub — underflow = corruption
inner.stats.total_supply = match inner.stats.total_supply.checked_sub(emission) {
    Ok(v) => v,
    Err(_) => { tracing::error!("CORRUPTION: supply underflow on rollback — subtract {} from {}", emission, inner.stats.total_supply); Amount::from_atomic(0) }
};
                            }
                        }

                        // Remove fork block height mappings above fork point
                        for h in (fork_point + 1..=inner.tip.height.max(pre_reorg_tip.height)).rev() {
                            inner.height_to_hash.remove(&h);
                        }

                        // Re-apply disconnected main-chain blocks in forward order
                        // (disconnected_tx_lists is in reverse height order, so reverse it)
                        for (h, oh) in disconnected_heights.iter().rev() {
                            inner.height_to_hash.insert(*h, *oh);
                            if let Some(orphan_block) = inner.blocks.get(oh) {
                                let batch = UtxoSet::batch_from_block(*h, &orphan_block.transactions);
                                inner.utxos.apply_batch(batch);
                            }
                        }

                        // Restore tip and stats
                        inner.tip = pre_reorg_tip.clone();
                        inner.stats = pre_reorg_stats.clone();

                        // Restore DB height mappings and remove stale fork entries
                        if let Some(ref db) = self.db {
                            // Remove stale height entries above pre-reorg tip
                            for h in (pre_reorg_tip.height + 1)..=(inner.tip.height.max(pre_reorg_tip.height) + 1) {
                                let _ = db.blocks.remove_height_hash(h);
                            }
                            // Re-set the main chain height mappings
                            for (h, oh) in &disconnected_heights {
                                let _ = db.blocks.set_height_hash(*h, oh);
                            }
                        }
                    }

                    // Only continue if fork blocks validated successfully
                    if reorg_error.is_none() {
                        // SECURITY (A6-REORG-DIFFICULTY): Also validate triggering block's difficulty
                        if block.header.height >= 1 {
                            let window = 144u64;
                            let start = block.header.height.saturating_sub(window);
                            let mut diff_blocks = Vec::new();

                            for h in start..block.header.height {
                                if h <= fork_point {
                                    if let Some(hash) = inner.height_to_hash.get(&h) {
                                        if let Some(b) = inner.blocks.get(hash) {
                                            diff_blocks.push(DifficultyBlock {
                                                height: h,
                                                timestamp: b.header.timestamp,
                                                target: b.header.target,
                                            });
                                        }
                                    }
                                } else {
                                    let offset = (h - fork_point - 1) as usize;
                                    if offset < fork_blocks.len() {
                                        let fb = &fork_blocks[offset];
                                        diff_blocks.push(DifficultyBlock {
                                            height: fb.header.height,
                                            timestamp: fb.header.timestamp,
                                            target: fb.header.target,
                                        });
                                    }
                                }
                            }

                            if diff_blocks.len() >= 2 {
                                let expected_target = calculate_difficulty(&diff_blocks, block.header.height);
                                if block.header.target != expected_target {
                                    tracing::warn!(
                                        "Reorg tip block {} at height {} has wrong difficulty target",
                                        hash.to_hex(), block.header.height
                                    );
                                    reorg_error = Some(format!(
                                        "Reorg tip difficulty mismatch at height {}: expected {}, got {}",
                                        block.header.height,
                                        expected_target.to_hex()[..16].to_string(),
                                        block.header.target.to_hex()[..16].to_string(),
                                    ));
                                }
                            }
                        }
                    }

                    // If triggering block validation also failed, rollback
                    if reorg_error.is_some() && inner.tip.hash != pre_reorg_tip.hash {
                        tracing::error!(
                            "Reorg tip validation failed — rolling back to pre-reorg state (tip={}, height={})",
                            pre_reorg_tip.hash.to_hex()[..16].to_string(),
                            pre_reorg_tip.height,
                        );

                        // SECURITY (BUG-2): Undo ALL applied fork blocks' UTXO mutations
                        for fork_block in fork_blocks.iter().rev() {
                            let disconnect = UtxoSet::batch_disconnect_block(&fork_block.transactions);
                            inner.utxos.apply_batch(disconnect);
                            let emission = calculate_block_reward(fork_block.header.height);
                            // C-4/H-11 FIX: checked_sub instead of saturating_sub — underflow = corruption
inner.stats.total_supply = match inner.stats.total_supply.checked_sub(emission) {
    Ok(v) => v,
    Err(_) => { tracing::error!("CORRUPTION: supply underflow on rollback — subtract {} from {}", emission, inner.stats.total_supply); Amount::from_atomic(0) }
};
                        }

                        // Remove fork block height mappings
                        for h in (fork_point + 1..=pre_reorg_tip.height.max(block.header.height)).rev() {
                            inner.height_to_hash.remove(&h);
                        }

                        // Re-apply disconnected main-chain blocks
                        for (h, oh) in disconnected_heights.iter().rev() {
                            inner.height_to_hash.insert(*h, *oh);
                            if let Some(orphan_block) = inner.blocks.get(oh) {
                                let batch = UtxoSet::batch_from_block(*h, &orphan_block.transactions);
                                inner.utxos.apply_batch(batch);
                            }
                        }

                        inner.tip = pre_reorg_tip.clone();
                        inner.stats = pre_reorg_stats.clone();

                        if let Some(ref db) = self.db {
                            // Remove stale height entries above pre-reorg tip
                            let max_h = block.header.height.max(pre_reorg_tip.height);
                            for h in (pre_reorg_tip.height + 1)..=(max_h + 1) {
                                let _ = db.blocks.remove_height_hash(h);
                            }
                            // Re-set the main chain height mappings
                            for (h, oh) in &disconnected_heights {
                                let _ = db.blocks.set_height_hash(*h, oh);
                            }
                        }
                    }

                    if reorg_error.is_none() {
                        // Apply the new tip block (the triggering block)
                        let tip_batch = UtxoSet::batch_from_block(block.header.height, &block.transactions);
                        inner.utxos.apply_batch(tip_batch);

                        // Add triggering block's emission to supply
                        let tip_emission = calculate_block_reward(block.header.height);
                        inner.stats.total_supply = inner.stats.total_supply.saturating_add(tip_emission);

                        // Update tip to the new fork head
                        inner.tip = ChainTip {
                            hash,
                            height: block.header.height,
                            difficulty: fork_difficulty,
                            timestamp: block.header.timestamp,
                        };
                        inner.stats.height = block.header.height;
                        inner.stats.difficulty = fork_difficulty;
                        inner.stats.tip_hash = hash;
                        inner.stats.total_difficulty = fork_cumulative;

                        // Fix stats drift: account for disconnected vs reconnected blocks
                        let reconnected_blocks = fork_blocks.len() as u64 + 1; // +1 for triggering block
                        let reconnected_txs: u64 = fork_blocks.iter()
                            .map(|b| b.transactions.len() as u64)
                            .sum::<u64>() + block.transactions.len() as u64;
                        inner.stats.total_blocks = inner.stats.total_blocks
                            .saturating_sub(disconnected_blocks)
                            .saturating_add(reconnected_blocks);
                        inner.stats.total_transactions = inner.stats.total_transactions
                            .saturating_sub(disconnected_txs)
                            .saturating_add(reconnected_txs);

                        inner.height_to_hash.insert(block.header.height, hash);

                        // Persist triggering block's height→hash to DB and
                        // clean up stale height entries above new tip.
                        if let Some(ref db) = self.db {
                            if let Err(e) = db.blocks.set_height_hash(block.header.height, &hash) {
                                tracing::error!("Failed to persist reorg tip height mapping: {}", e);
                            }
                            // Remove ALL stale DB height entries above new tip.
                            // After a reorg to a shorter chain, old heights remain
                            // pointing to orphaned blocks — causes broken chain
                            // links after restart.
                            if let Err(e) = db.blocks.remove_heights_above(block.header.height) {
                                tracing::error!("Failed to clean stale heights after reorg: {}", e);
                            }
                        }
                    }
                }

                // Return early if reorg failed (rollback already done above)
                if let Some(err) = reorg_error {
                    return Ok(BlockStatus::Invalid(err));
                }

                // SECURITY (REORG-ATOMIC): All persistent state changes during a
                // reorg are now applied in a single sled multi-tree transaction.
                // output_index removals + additions, height→hash updates,
                // chain state, and tx_index mutations all land atomically.
                // A crash at ANY point during this block either commits everything
                // or nothing — no partial state visible after restart.
                if let Some(ref db) = self.db {
                    // 1. Collect output_index removals (disconnected blocks)
                    let mut oi_removals: Vec<[u8; 32]> = Vec::new();
                    let mut ti_removes: Vec<[u8; 32]> = Vec::new();
                    for txs in &disconnected_tx_lists {
                        for tx in txs {
                            for output in &tx.outputs {
                                oi_removals.push(*output.stealth_address.as_bytes());
                            }
                            ti_removes.push(*tx.hash().as_bytes());
                        }
                    }

                    // 2. Collect output_index additions (fork blocks + tip)
                    let mut oi_additions: Vec<([u8; 32], Vec<u8>)> = Vec::new();
                    let mut height_sets: Vec<(u64, [u8; 32])> = Vec::new();
                    let mut ti_adds: Vec<([u8; 32], u64, u32)> = Vec::new();

                    let collect_block_outputs = |b: &crate::consensus::Block,
                                                  oi: &mut Vec<([u8; 32], Vec<u8>)>,
                                                  hs: &mut Vec<(u64, [u8; 32])>,
                                                  ti: &mut Vec<([u8; 32], u64, u32)>| {
                        let h = b.header.height;
                        hs.push((h, *b.hash().as_bytes()));
                        for (idx, tx) in b.transactions.iter().enumerate() {
                            let is_coinbase = tx.is_coinbase();
                            for output in &tx.outputs {
                                let entry = crate::db::OutputIndexEntry {
                                    commitment: output.commitment,
                                    height: h,
                                    is_coinbase,
                                    lock_height: output.lock_height,
                                };
                                if let Ok(data) = crate::db::serialize(&entry) {
                                    oi.push((*output.stealth_address.as_bytes(), data));
                                }
                            }
                            ti.push((*tx.hash().as_bytes(), h, idx as u32));
                        }
                    };

                    for fork_block in &fork_blocks {
                        collect_block_outputs(fork_block, &mut oi_additions, &mut height_sets, &mut ti_adds);
                    }
                    collect_block_outputs(&block, &mut oi_additions, &mut height_sets, &mut ti_adds);

                    // 3. Compute stale heights to remove (above new tip)
                    let new_tip_height = block.header.height;
                    let height_removals: Vec<u64> = (new_tip_height + 1..=new_tip_height + 100)
                        .collect(); // Clean up to 100 stale entries

                    // 4. Serialize new chain state
                    let last_checkpoint = db
                        .state
                        .get_state()
                        .ok()
                        .flatten()
                        .map(|s| s.last_checkpoint)
                        .unwrap_or(0);
                    let new_state = ChainStateData {
                        tip_hash: hash,
                        height: new_tip_height,
                        total_difficulty: fork_cumulative,
                        total_supply: self.stats().total_supply.as_atomic(),
                        total_burned: 0,
                        last_checkpoint,
                    };
                    let state_bytes = crate::db::serialize(&new_state)?;

                    // 5. Apply everything atomically
                    db.apply_reorg_atomic(
                        &oi_removals,
                        &oi_additions,
                        &height_sets,
                        &height_removals,
                        &state_bytes,
                        &ti_adds,
                        &ti_removes,
                    )?;

                    tracing::info!(
                        "Reorg atomic commit: {} outputs removed, {} added, {} heights set",
                        oi_removals.len(), oi_additions.len(), height_sets.len()
                    );
                } else {
                    // No DB — in-memory only mode (tests). Still do the non-atomic path.
                    for txs in &disconnected_tx_lists {
                        self.remove_output_index(txs);
                    }
                    for fork_block in &fork_blocks {
                        self.persist_output_index(&fork_block.transactions, fork_block.header.height);
                    }
                    self.persist_output_index(&block.transactions, block.header.height);
                }

                // Structured divergence detection log — reorg completed
                let stats_snapshot = inner_stats_for_log(&self.inner);
                tracing::warn!(
                    target: "chain::commit",
                    height = block.header.height,
                    block_hash = %hash.to_hex(),
                    reorg_depth = block.header.height.saturating_sub(fork_point),
                    total_difficulty = stats_snapshot.0,
                    tip = %hash.to_hex(),
                    supply_atomic = stats_snapshot.1,
                    "REORG_COMMIT"
                );

                // SECURITY (A6-REORG-MEMPOOL): Collect non-coinbase txs from
                // disconnected blocks for mempool restoration. Without this, user
                // transactions that were mined in orphaned blocks simply vanish.
                let orphaned_txs: Vec<crate::transaction::Transaction> = disconnected_tx_lists
                    .into_iter()
                    .flatten()
                    .filter(|tx| !tx.is_coinbase())
                    .collect();

                self.record_event(ChainEventType::Reorg, block.header.height, &hash, serde_json::json!({
                    "reorg_depth": reorg_depth,
                    "fork_point": fork_point,
                }));

                Ok(BlockStatus::AcceptedReorg { orphaned_txs })
            } else {
                // Fork has less work - store but don't switch
                tracing::warn!(
                    "Block {} at height {} is a fork (less work: {} <= {})",
                    hash.to_hex()[..16].to_string(),
                    block.header.height,
                    fork_cumulative,
                    current_total_difficulty
                );
                self.record_event(ChainEventType::ForkDetected, block.header.height, &hash, serde_json::json!({
                    "fork_difficulty": fork_cumulative,
                }));
                Ok(BlockStatus::AcceptedFork)
            }
        }
    }

    /// Get recent blocks as DifficultyBlock entries for ASERT calculation
    pub fn get_difficulty_blocks(&self, up_to_height: u64) -> Vec<DifficultyBlock> {
        let window = 144u64; // DIFFICULTY_LONG_WINDOW
        let start = up_to_height.saturating_sub(window);
        let inner = self.inner.read();
        let mut blocks = Vec::new();
        for h in start..up_to_height {
            if let Some(hash) = inner.height_to_hash.get(&h) {
                if let Some(block) = inner.blocks.get(hash) {
                    blocks.push(DifficultyBlock {
                        height: h,
                        timestamp: block.header.timestamp,
                        target: block.header.target,
                    });
                }
            }
        }
        blocks
    }

    /// Check if a key image has been spent
    ///
    /// Returns true if the key image exists in the spent key images set,
    /// meaning the associated output has already been spent.
    ///
    /// SECURITY (A6-DUAL-UTXO): Check the in-memory UTXO set first, since it
    /// is always kept up-to-date by add_block(). The persistent DB may not be
    /// synchronized. Falls back to DB only if in-memory set has no key images
    /// tracked (fresh startup edge case).
    pub fn is_spent(&self, key_image: &KeyImage) -> bool {
        // Primary: check in-memory UTXO set (always up-to-date)
        let inner = self.inner.read();
        if inner.utxos.output_count() > 0 || inner.utxos.contains_key_image(key_image) {
            return inner.utxos.contains_key_image(key_image);
        }
        drop(inner);

        // Fallback: check persistent DB (for fresh startup before UTXO rebuild)
        if let Some(ref db) = self.db {
            match db.utxos.is_spent(key_image) {
                Ok(spent) => spent,
                Err(e) => {
                    tracing::error!("Failed to check key image: {}", e);
                    // SECURITY: Fail closed - treat DB errors as "spent" to prevent
                    // double-spend attacks when database is unavailable
                    true
                }
            }
        } else {
            false
        }
    }

    /// Get decoy outputs for ring signatures
    ///
    /// Selects random outputs from the UTXO set to use as ring members,
    /// providing unlinkability for the real input being spent.
    pub fn get_decoy_outputs(&self, count: usize, min_age: u64) -> Vec<DecoyOutput> {
        let inner = self.inner.read();
        let current_height = inner.tip.height;
        // SECURITY: ring decoy selection — OsRng, not thread_rng. See the
        // matching comment in db::utxos::select_decoys.
        let mut rng = rand::rngs::OsRng;
        inner.utxos.select_decoys(current_height, min_age, count, &mut rng)
            .into_iter()
            .map(|oref| DecoyOutput {
                public_key: oref.output.stealth_address,
                commitment: oref.output.commitment,
                height: oref.height,
            })
            .collect()
    }

    /// Get target height (for sync progress, updated by P2P layer)
    pub fn target_height(&self) -> u64 {
        let peer_target = self.peer_target_height.load(std::sync::atomic::Ordering::Relaxed);
        if peer_target > 0 { peer_target } else { self.height() }
    }

    /// Update sync info from P2P layer
    pub fn set_sync_info(&self, synced: bool, target_height: u64) {
        self.synced.store(synced, std::sync::atomic::Ordering::Relaxed);
        self.peer_target_height.store(target_height, std::sync::atomic::Ordering::Relaxed);
    }

    /// Record that a block was accepted from the P2P layer right now.
    /// Called from `add_block` whenever a peer-sourced block is accepted so
    /// phantom-stall detection can measure the gap since the last real arrival.
    pub fn record_block_received(&self) {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        self.last_block_received_at
            .store(now, std::sync::atomic::Ordering::Relaxed);
    }

    /// FIX #17: single source of truth for tip staleness. Previously
    /// `AutoHeal::last_tip_change`, `IronConsensus::last_advance`, and the
    /// phantom-stall timer all tracked this independently and disagreed with
    /// each other — three stall detectors firing at different times with
    /// conflicting recovery actions. This method exposes the shared
    /// `last_block_received_at` atomic so all three can read from the same
    /// timestamp. Returns `None` if we've never received a block from a peer
    /// since startup (in which case the caller should use its own clock).
    pub fn secs_since_last_block(&self) -> Option<u64> {
        let last = self.last_block_received_at
            .load(std::sync::atomic::Ordering::Relaxed);
        if last == 0 { return None; }
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        Some(now.saturating_sub(last))
    }

    /// Returns true when the node is in a phantom-advertisement stall:
    ///   - `synced == false` (miner IBD gate is blocking)
    ///   - `target_height == local_height + 1` (only one block behind)
    ///   - no peer block has arrived in the last `stall_secs` seconds
    ///
    /// In that state the "missing" block does not exist yet — it needs to be
    /// mined locally, not fetched. The miner uses this to relax the IBD gate.
    pub fn is_phantom_stall(&self, stall_secs: u64) -> bool {
        use std::sync::atomic::Ordering::Relaxed;
        if self.synced.load(Relaxed) {
            return false;
        }
        let local_h = self.height();
        let target_h = self.peer_target_height.load(Relaxed);
        if target_h != local_h + 1 {
            return false;
        }
        let last = self.last_block_received_at.load(Relaxed);
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        // If `last` is 0 we have never accepted a peer block since startup;
        // treat that as "long ago" so a phantom detected at boot still fires.
        now.saturating_sub(last) >= stall_secs
    }

    /// Clear the phantom target — reset `synced=true` and align target_height
    /// with local_height so the miner IBD gate unblocks. If a real peer has
    /// the next block, it will arrive via `add_block` and the P2P layer will
    /// correct the sync info again on its next `set_sync_info` call.
    pub fn clear_phantom_target(&self) {
        use std::sync::atomic::Ordering::Relaxed;
        let h = self.height();
        self.peer_target_height.store(h, Relaxed);
        self.synced.store(true, Relaxed);
        tracing::info!("Phantom target cleared — synced=true h={}", h);
    }

    // ─── Asset policy helpers ─────────────────────────────────────────────

    /// Look up a registered asset policy by ID.  Returns `None` if the asset
    /// has not been issued on this chain (or no database is attached).
    /// Export all recorded checkpoints (hardcoded + auto-recorded from DB).
    pub fn export_checkpoints(&self) -> Vec<(u64, Hash)> {
        let mut checkpoints: Vec<(u64, Hash)> = crate::testnet::testnet_checkpoints()
            .into_iter()
            .map(|cp| (cp.height, cp.hash))
            .collect();

        if let Some(ref db) = self.db {
            if let Ok(db_checkpoints) = db.state.get_checkpoints() {
                for (height, hash) in db_checkpoints {
                    if !checkpoints.iter().any(|(h, _)| *h == height) {
                        checkpoints.push((height, hash));
                    }
                }
            }
        }

        checkpoints.sort_by_key(|(h, _)| *h);
        checkpoints
    }

    /// Calculate cumulative work for a fork chain ending at the given block.
    ///
    /// Walks backwards from the block through its parents, summing difficulty
    /// until reaching the genesis block or a block not in our storage.
    fn calculate_fork_cumulative_work(&self, block: &Block) -> u128 {
        let mut total_work = calculate_difficulty_from_target(&block.header.target);
        let mut current_hash = block.header.prev_hash;

        loop {
            if let Some(parent) = self.get_block(&current_hash) {
                let prev_work = total_work;
                total_work = total_work.saturating_add(
                    calculate_difficulty_from_target(&parent.header.target)
                );
                // SECURITY (H-7): Detect u128 saturation during deep reorgs.
                // saturating_add silently caps at u128::MAX, which could cause
                // incorrect chain selection if both forks saturate.
                if total_work == u128::MAX && prev_work != u128::MAX {
                    tracing::warn!(
                        "Cumulative work saturated at u128::MAX during fork calculation at height {}",
                        parent.header.height
                    );
                }
                if parent.header.height == 0 {
                    break; // Reached genesis
                }
                current_hash = parent.header.prev_hash;
            } else {
                break; // Parent not found
            }
        }

        total_work
    }

    /// Find the common ancestor (fork point) between the current main chain
    /// and a fork block.
    fn find_fork_point(&self, fork_block: &Block) -> u64 {
        let mut current_hash = fork_block.header.prev_hash;
        // Guard against infinite loops from DB corruption (cyclic prev_hash references)
        let mut visited = std::collections::HashSet::new();

        loop {
            if !visited.insert(current_hash) {
                tracing::error!("Cycle detected in block chain during fork point search");
                return 0;
            }
            // Check if this block is on the main chain
            if let Some(parent) = self.get_block(&current_hash) {
                let height = parent.header.height;
                if let Some(main_hash) = self.get_block_hash(height) {
                    if main_hash == current_hash {
                        return height; // Found common ancestor
                    }
                }
                if height == 0 {
                    return 0; // Genesis is always common
                }
                current_hash = parent.header.prev_hash;
            } else {
                return 0; // Can't find parent, assume genesis
            }
        }
    }

    /// Collect the fork chain from fork_point+1 to the given block (exclusive).
    /// Returns blocks in ascending height order.
    fn collect_fork_chain(&self, fork_tip: &Block, fork_point: u64) -> Vec<Block> {
        let mut chain = Vec::new();
        let mut current_hash = fork_tip.header.prev_hash;
        let mut visited = std::collections::HashSet::new();

        // Walk back from fork tip to fork point, collecting blocks.
        // SECURITY: Track visited hashes to detect cycles and prevent infinite loops.
        loop {
            if !visited.insert(current_hash) {
                tracing::error!("Cycle detected in fork chain at hash {}", current_hash.to_hex());
                break;
            }
            if let Some(block) = self.get_block(&current_hash) {
                if block.header.height <= fork_point {
                    break;
                }
                current_hash = block.header.prev_hash;
                chain.push(block.clone());
            } else {
                break;
            }
        }

        chain.reverse(); // Return in ascending order
        chain
    }
}

// ════════════════════════════════════════════════════════════════════
// Async wrappers (Phase 2 of the post-launch runtime-resilience refactor)
// ════════════════════════════════════════════════════════════════════
//
// The sync methods above acquire `parking_lot::RwLock`s and run RocksDB
// I/O. When called from async context they block whichever tokio worker
// thread happens to pick up the task. On the single-vCPU fleet boxes
// that's enough to freeze the entire runtime — observed live 2026-05-12
// 16:18 UTC, 13-minute RPC outage. Phase 2 #9 introduced these `*_async`
// companions that move the sync call onto tokio's blocking thread pool
// via `spawn_blocking`, leaving worker threads free to keep scheduling.
//
// USE FROM ASYNC CONTEXTS. The sync versions remain for:
//   - RPC handlers using `block_in_place` (jsonrpsee register_method
//     closures are sync; `block_in_place` is the right primitive there)
//   - Truly synchronous code (mining loop, tests, validator unit tests)
//   - Internal helpers themselves called from inside spawn_blocking
//
// All wrappers take `self: Arc<Self>` so the caller passes an Arc clone
// — required for `spawn_blocking`'s `'static + Send` bound. Cheap:
// atomic refcount bump only.

impl Blockchain {
    /// Async wrapper around [`Blockchain::add_block`]. Runs full block
    /// validation + DB write on `tokio::task::spawn_blocking`.
    pub async fn add_block_async(self: Arc<Self>, block: Block) -> Result<BlockStatus> {
        tokio::task::spawn_blocking(move || self.add_block(block))
            .await
            .map_err(|e| Error::Internal(format!("spawn_blocking join error in add_block: {}", e)))?
    }

    /// Async wrapper around [`Blockchain::process_block`]. Equivalent to
    /// `add_block_async` (process_block is a thin alias today).
    pub async fn process_block_async(self: Arc<Self>, block: Block) -> Result<BlockStatus> {
        tokio::task::spawn_blocking(move || self.process_block(block))
            .await
            .map_err(|e| Error::Internal(format!("spawn_blocking join error in process_block: {}", e)))?
    }

    /// Async wrapper around [`Blockchain::get_block`]. Hash-keyed DB read.
    pub async fn get_block_async(self: Arc<Self>, hash: Hash) -> Option<Block> {
        tokio::task::spawn_blocking(move || self.get_block(&hash))
            .await
            .unwrap_or(None)
    }

    /// Async wrapper around [`Blockchain::get_block_by_height`].
    pub async fn get_block_by_height_async(self: Arc<Self>, height: u64) -> Option<Block> {
        tokio::task::spawn_blocking(move || self.get_block_by_height(height))
            .await
            .unwrap_or(None)
    }

    /// Async wrapper around [`Blockchain::validate_transaction`]. Runs full
    /// crypto verify (ring sig + range proof + key-image dedup).
    pub async fn validate_transaction_async(self: Arc<Self>, tx: Transaction) -> Result<()> {
        tokio::task::spawn_blocking(move || self.validate_transaction(&tx))
            .await
            .map_err(|e| Error::Internal(format!(
                "spawn_blocking join error in validate_transaction: {}", e
            )))?
    }

    /// Async wrapper around [`Blockchain::is_spent`]. Key-image lookup.
    pub async fn is_spent_async(self: Arc<Self>, key_image: KeyImage) -> bool {
        tokio::task::spawn_blocking(move || self.is_spent(&key_image))
            .await
            .unwrap_or(false)
    }
}

/// Calculate difficulty from target using `2^128 / target` for precision.
///
/// This matches Bitcoin's work calculation where difficulty is inversely
/// proportional to the target hash. Using leading-zero bits was imprecise
/// (only distinguished power-of-2 difficulties). The new formula uses the
/// first 16 bytes of the target as a u128 and computes u128::MAX / target_value,
/// which provides smooth difficulty gradients for accurate chain selection.
fn calculate_difficulty_from_target(target: &Hash) -> u128 {
    let bytes = target.as_bytes();

    // Convert first 16 bytes to u128 (big-endian) for precision
    let mut buf = [0u8; 16];
    buf.copy_from_slice(&bytes[..16]);
    let target_value = u128::from_be_bytes(buf);

    // Avoid division by zero for impossible targets
    if target_value == 0 {
        return u128::MAX;
    }

    // Work = 2^128 / target_value (using the top 128 bits of the 256-bit target).
    // This is equivalent to 2^256 / (target_value << 128), preserving the ratio.
    u128::MAX / target_value
}

impl Default for Blockchain {
    fn default() -> Self {
        Self::new()
    }
}

// =============================================================================
// Genesis Block
// =============================================================================

/// Create the genesis block for a specific network (runtime selection).
pub fn create_genesis_block_for(network: NetworkType) -> Block {
    match network {
        NetworkType::Testnet | NetworkType::Regtest => crate::testnet::testnet_genesis(),
        NetworkType::Mainnet => crate::mainnet::mainnet_genesis(),
    }
}

/// Create the genesis block (backwards-compatible, defaults to testnet).
///
/// Prefers `create_genesis_block_for(network)` for explicit network selection.
pub fn create_genesis_block() -> Block {
    // Default to testnet for backwards compatibility with tests
    crate::testnet::testnet_genesis()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_genesis_block() {
        let genesis = create_genesis_block();
        assert_eq!(genesis.header.height, 0);
        assert_eq!(genesis.header.prev_hash, Hash::zero());
        assert!(!genesis.transactions.is_empty());
    }

    #[test]
    fn test_blockchain_init() {
        let chain = Blockchain::new();
        let genesis_hash = chain.init_genesis().unwrap();
        assert_eq!(chain.height(), 0);
        assert_eq!(chain.tip().hash, genesis_hash);
    }

    #[test]
    fn test_reorg_acceptability_shallow_requires_more_work() {
        // Shallow reorgs still require strict cumulative-work superiority.
        let h = BOOTSTRAP_MESS_HEIGHT + 1; // post-bootstrap, full rules apply
        assert!(evaluate_reorg_acceptability(3, 101, 100, h).is_ok());
        assert!(evaluate_reorg_acceptability(3, 100, 100, h).is_err());
    }

    #[test]
    fn test_reorg_acceptability_mess_multiplier() {
        // At depth 50, exponent = (50-10)/20 = 2 => required multiplier 4x.
        let h = BOOTSTRAP_MESS_HEIGHT + 1; // post-bootstrap
        let err = evaluate_reorg_acceptability(50, 399, 100, h).unwrap_err();
        assert!(err.contains("requires 4x work"));
        assert!(evaluate_reorg_acceptability(50, 401, 100, h).is_ok());
    }

    #[test]
    fn test_reorg_acceptability_hard_depth_cap() {
        let max = max_reorg_depth();
        let err = evaluate_reorg_acceptability(max + 1, u128::MAX, 1, BOOTSTRAP_MESS_HEIGHT + 1).unwrap_err();
        assert!(err.contains("exceeds absolute maximum"));
    }

    #[test]
    fn test_reorg_acceptability_bootstrap_bypass() {
        // Below BOOTSTRAP_MESS_HEIGHT, Tier-2 MESS is skipped and only the
        // longest-chain rule applies even at deep reorg depths. This is the
        // launch convergence fix: a young fleet whose nodes diverge at low
        // heights must be able to converge once one chain pulls ahead.
        let bootstrap_h = BOOTSTRAP_MESS_HEIGHT / 2;
        // Depth 50 with only slightly-more work: rejected post-bootstrap,
        // accepted during bootstrap.
        assert!(evaluate_reorg_acceptability(50, 101, 100, bootstrap_h).is_ok());
        // Equal work still loses (longest chain must strictly exceed).
        let err = evaluate_reorg_acceptability(50, 100, 100, bootstrap_h).unwrap_err();
        assert!(err.contains("bootstrap phase"));
        // Tier-3 hard cap still enforced during bootstrap.
        let max = max_reorg_depth();
        assert!(evaluate_reorg_acceptability(max + 1, u128::MAX, 1, bootstrap_h).is_err());
    }
}
