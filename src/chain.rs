//! # Blockchain State Machine
//!
//! Core blockchain state management.

use parking_lot::RwLock;
use std::collections::HashMap;
use std::sync::Arc;

use crate::config::NetworkType;
use crate::consensus::{calculate_difficulty, max_target, Block, DifficultyBlock};
use crate::db::{ChainStateData, Database, OutputIndexEntry};
use crate::emission::calculate_block_reward;
use crate::error::{Error, Result};
use crate::primitives::{Hash, KeyImage};
use crate::storage::UtxoSet;
use crate::transaction::{DecoyOutput, Transaction};

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
///
/// SECURITY (2026-07-05 audit F31 — SEV-A): The previous implementation
/// used `#[cfg(feature = "testnet")]` (compile-time) to select 1000 vs
/// 100. But **network selection is a runtime decision** — the `network:
/// NetworkType` field on `Blockchain` is set from the `--network` CLI
/// flag / config, not from the build's feature flags. Result: a binary
/// built without `--features testnet` would use the 100-block mainnet
/// hard-finality cap EVEN WHEN CONFIGURED TO RUN ON TESTNET. That
/// misconfiguration contributed to the 2026-07-04 partition where the
/// fleet was running on testnet but hitting the 100-block cap that
/// belongs to mainnet — the ideal testnet cap is 1000, deliberately
/// higher so testnet can survive stress-test deep reorgs like the
/// 628-block one randomx-2 delivered.
///
/// Post-fix: the free-function version is deprecated in favor of
/// `max_reorg_depth_for(NetworkType)` which is unambiguous. This
/// wrapper still exists (and defaults to the safer Testnet=1000
/// interpretation) so any pre-audit caller compiles, but new code
/// should ALWAYS pass the actual network explicitly.
///
/// See `project_hard_finality_partition_2026_07_04.md` in the memory
/// index for the incident this closes.
#[deprecated(
    since = "1.0.11",
    note = "Uses compile-time feature flags for what should be a runtime \
            decision. Callers with access to a `Blockchain` should use \
            `blockchain.max_reorg_depth()` (method); free-function callers \
            should use `max_reorg_depth_for(network)` explicitly."
)]
pub fn max_reorg_depth() -> u64 {
    // Fall back to the safer testnet interpretation (1000) rather than
    // the pre-fix cfg-based mix. Callers who need the actual value MUST
    // migrate to the network-taking variant.
    max_reorg_depth_for(NetworkType::Testnet)
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
/// `max_depth` is the network-specific hard-finality cap. Callers who have a
/// `Blockchain` should use `blockchain.max_reorg_depth()`; callers without
/// should compute `max_reorg_depth_for(network)` from the runtime network.
///
/// SECURITY (2026-07-05 audit F31 — SEV-A): The pre-fix signature omitted
/// `max_depth` and internally called `max_reorg_depth()` which used
/// compile-time cfg feature flags. Runtime network vs compile-time features
/// could diverge (see doc-comment on `max_reorg_depth`). The 2026-07-04
/// partition trap was exacerbated by this: fleet binary compiled without
/// `--features testnet` used max=100 (mainnet) even though runtime network
/// was testnet — testnet is supposed to allow 1000-deep reorgs so it can
/// survive the exact 628-block reorg that got trapped.
///
/// Returns `Ok(())` if the reorg is acceptable, `Err(reason)` if rejected.
pub fn evaluate_reorg_acceptability(
    depth: u64,
    fork_work: u128,
    honest_work: u128,
    current_height: u64,
    max_depth: u64,
) -> std::result::Result<(), String> {
    // Tier 3: Hard reject beyond absolute max depth
    if depth > max_depth {
        return Err(format!(
            "Reorg depth {} exceeds absolute maximum {} (hard finality)",
            depth, max_depth
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

/// Prevents startup callers from treating a load failure as a fresh database.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChainLoadOutcome {
    Fresh,
    Loaded,
}

/// Chain statistics
#[derive(Debug, Clone, Default)]
pub struct ChainStats {
    pub height: u64,
    pub total_blocks: u64,
    pub total_transactions: u64,
    /// Cumulative emitted supply, in atomic units.
    ///
    /// `u128`, not `Amount` (`u64`): MAX_SUPPLY = 100M CYNC × 10^12 = 10^20 >
    /// `u64::MAX` (~18.4M CYNC). A `u64` aggregate overflowed and panicked the
    /// `checked_add` on block connect at ~18.4M CYNC cumulative (height ~408k).
    /// Individual `Amount`s stay `u64`; only this running total widened.
    pub total_supply: u128,
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

        let mut entries: Vec<(u64, Hash)> = self
            .height_to_hash
            .iter()
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
                evicted,
                self.blocks.len()
            );
        }
    }
}

/// Blockchain state machine with interior mutability
pub struct Blockchain {
    /// Internal mutable state protected by RwLock
    inner: RwLock<BlockchainInner>,
    /// Monotonic marker for canonical-state changes observed by mempool admission.
    state_generation: std::sync::atomic::AtomicU64,
    /// Non-zero while one or more canonical-state updates are in progress.
    state_updates_in_progress: std::sync::atomic::AtomicU32,
    /// Database reference (optional)
    db: Option<Arc<Database>>,
    /// Runtime network type — determines genesis, reorg depth, seed nodes
    network: NetworkType,
    /// Sync status from P2P layer (atomic for lock-free reads from RPC)
    synced: std::sync::atomic::AtomicBool,
    /// Firework Phase 2 (I6): set true by the P2P layer when a peer
    /// advertises a verifiably-heavier chain (more cumulative work) that we
    /// have not matched. A veto over `is_synced()`: we must not report
    /// synced — and the miner must not mine — while a heavier chain exists,
    /// even if we are taller in block height. Cleared by the sync layer's
    /// anti-wedge machinery (expire/ban/prune) so an unsubstantiated claim
    /// cannot pin it. Default false / inert for peers without CAP_CHAINWORK.
    work_behind: std::sync::atomic::AtomicBool,
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
    pub cut_through:
        Option<Arc<parking_lot::Mutex<crate::crypto::mw_cutthrough::CutThroughEngine>>>,

    /// CIP-009.D rolling soft-finality adapter — see
    /// `src/consensus/rolling_finality.rs`. `None` (or feature off)
    /// means the soft-finality reorg rule is dormant; setting it to
    /// `Some(_)` and reaching `ROLLING_FINALITY_ENFORCE_HEIGHT`
    /// activates the rule live. Field is feature-gated so default
    /// builds are byte-identical to a build without it.
    #[cfg(feature = "rolling-finality")]
    pub rolling_finality: Option<Arc<crate::consensus::rolling_finality::RollingFinality>>,
}

struct StateUpdate<'a> {
    chain: &'a Blockchain,
}

impl Drop for StateUpdate<'_> {
    fn drop(&mut self) {
        use std::sync::atomic::Ordering;

        self.chain.state_generation.fetch_add(1, Ordering::Release);
        self.chain
            .state_updates_in_progress
            .fetch_sub(1, Ordering::Release);
    }
}

/// Extract stats snapshot for structured logging without holding lock in tracing macro.
fn inner_stats_for_log(inner: &RwLock<BlockchainInner>) -> (u128, String) {
    let guard = inner.read();
    // Decimal text preserves the full accumulator while remaining accepted by
    // tracing subscribers that do not implement a native u128 value.
    (
        guard.stats.total_difficulty,
        guard.stats.total_supply.to_string(),
    )
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
            state_generation: std::sync::atomic::AtomicU64::new(0),
            state_updates_in_progress: std::sync::atomic::AtomicU32::new(0),
            db: None,
            network,
            synced: std::sync::atomic::AtomicBool::new(true),
            work_behind: std::sync::atomic::AtomicBool::new(false),
            peer_target_height: std::sync::atomic::AtomicU64::new(0),
            last_block_received_at: std::sync::atomic::AtomicU64::new(0),
            // Phase 2 stores: None until Phase 2 activation
            spark_store: None,
            shielded_store: None,
            kernel_store: None,
            cut_through: None,
            // CIP-009.D rolling finality: dormant until the operator
            // wires an adapter and `ROLLING_FINALITY_ENFORCE_HEIGHT`
            // is reached.
            #[cfg(feature = "rolling-finality")]
            rolling_finality: None,
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
            state_generation: std::sync::atomic::AtomicU64::new(0),
            state_updates_in_progress: std::sync::atomic::AtomicU32::new(0),
            db: Some(db),
            network,
            synced: std::sync::atomic::AtomicBool::new(true),
            work_behind: std::sync::atomic::AtomicBool::new(false),
            peer_target_height: std::sync::atomic::AtomicU64::new(0),
            last_block_received_at: std::sync::atomic::AtomicU64::new(0),
            // Phase 2 stores: None until Phase 2 activation
            spark_store: None,
            shielded_store: None,
            kernel_store: None,
            cut_through: None,
            // CIP-009.D rolling finality: dormant until the operator
            // wires an adapter and `ROLLING_FINALITY_ENFORCE_HEIGHT`
            // is reached.
            #[cfg(feature = "rolling-finality")]
            rolling_finality: None,
        }
    }

    /// Returns the network type this blockchain is configured for
    pub fn network(&self) -> NetworkType {
        self.network
    }

    /// Returns the network-specific max reorg depth (hard-finality cap).
    ///
    /// SECURITY (2026-07-05 audit F31 — SEV-A): This method reads the
    /// RUNTIME network from `self.network`, avoiding the compile-time
    /// feature-flag pitfall of the deprecated free-function
    /// `chain::max_reorg_depth()`. All in-file reorg-check paths and
    /// the RPC exposure should route through this method rather than
    /// the free function so a build without `--features testnet` still
    /// picks the correct testnet-1000 cap when configured for testnet
    /// at runtime.
    pub fn max_reorg_depth(&self) -> u64 {
        max_reorg_depth_for(self.network)
    }

    // ── Phase 2 privacy store accessors ─────────────────────────────
    // Returns [0u8; 32] when Phase 2 stores are not initialized (None).

    pub fn shielded_root(&self) -> [u8; 32] {
        self.shielded_store
            .as_ref()
            .map(|s| s.current_root())
            .unwrap_or([0u8; 32])
    }

    pub fn spark_root(&self) -> [u8; 32] {
        self.spark_store
            .as_ref()
            .map(|s| s.current_root())
            .unwrap_or([0u8; 32])
    }

    pub fn mw_kernel_root(&self) -> [u8; 32] {
        self.kernel_store
            .as_ref()
            .map(|s| s.current_root())
            .unwrap_or([0u8; 32])
    }

    // ── Phase 2 privacy store reorg checkpoint/rewind helpers ───────
    //
    // The shielded / spark / kernel stores each carry a reorg
    // checkpoint stack (CIP-009.D Interp-B contract: a checkpoint is
    // taken *before* a block's state is applied; `rewind` undoes one
    // block). These two helpers wire that discipline uniformly into
    // every connect / disconnect site in the block-acceptance and
    // reorg machinery, so the three stores stay in lock-step with the
    // UTXO set across reorgs.
    //
    // Both are inert while the stores are `None` (the current testnet
    // build wires them as `Option::None`). They become load-bearing
    // when Phase 2 activation instantiates the stores and wires their
    // per-block appends.

    /// Checkpoint every initialized Phase-2 store for the block at
    /// `height`. Call **before** the block's state is applied to the
    /// chain, so a later `rewind_phase2_stores` rolls each store back
    /// to exactly this pre-block boundary.
    ///
    /// CROSS-STORE INVARIANT (Phase-2 only): after this returns, all
    /// THREE initialized stores must report the same `checkpoint_count`.
    /// They were checkpointed in lock-step under the chain's write
    /// lock, with the same height, so their stack lengths must agree.
    /// If they diverge, a later reorg would unwind them unevenly and
    /// the chain would end up with one store at height H and another
    /// at height H ± k — a fatal state divergence that's hard to
    /// detect after the fact. Catching it here at the moment of
    /// divergence makes the bug class shallow.
    ///
    /// The check is `debug_assert!` because in production the only
    /// way it could fire is a programming bug (one of the stores
    /// silently no-op'd, or a developer added a fourth store without
    /// updating the cross-store walk). debug_assert is dead in
    /// release. Also gated on "all three stores initialized" because
    /// during the v1.0 ship → Phase 2 activation window some stores
    /// will be `None`; that's expected, not a bug.
    fn checkpoint_phase2_stores(&self, height: u64) {
        if let Some(ref s) = self.shielded_store {
            s.checkpoint_at_height(height);
        }
        if let Some(ref s) = self.spark_store {
            s.checkpoint_at_height(height);
        }
        if let Some(ref s) = self.kernel_store {
            s.checkpoint_at_height(height);
        }

        // Cross-store invariant — only meaningful when all three are
        // initialized (Phase 2 activated). The shielded store's
        // checkpoint may have been skipped if the BridgeTree declined
        // it (non-monotonic height; warned in storage::shielded), in
        // which case our cross-store count check would fail — but
        // that's exactly the bug class this assertion is meant to
        // surface, so we don't suppress it.
        #[cfg(debug_assertions)]
        if let (Some(sh), Some(sp), Some(kr)) =
            (&self.shielded_store, &self.spark_store, &self.kernel_store)
        {
            let (n_sh, n_sp, n_kr) = (
                sh.checkpoint_count(),
                sp.checkpoint_count(),
                kr.checkpoint_count(),
            );
            if !(n_sh == n_sp && n_sp == n_kr) {
                debug_assert_eq!(
                    (n_sh, n_sp, n_kr),
                    (n_sh, n_sh, n_sh),
                    "Phase-2 stores diverged at height {}: shielded={} spark={} kernel={} \
                     — the three stores were checkpointed in lock-step but their stack \
                     lengths disagree, meaning one of them silently skipped (likely a \
                     BridgeTree-declined checkpoint or a code path that bypassed \
                     checkpoint_phase2_stores). A reorg from this state would unwind \
                     the stores unevenly.",
                    height,
                    n_sh,
                    n_sp,
                    n_kr
                );
            }
        }
    }

    /// Rewind every initialized Phase-2 store by one checkpoint — i.e.
    /// disconnect one block during a reorg. Call once per disconnected
    /// block, in the same reverse-height order the UTXO disconnect
    /// uses. `height` is only for the diagnostic emitted if a store
    /// reports it could not roll back (an empty checkpoint stack —
    /// e.g. a rewind attempted past a node restart).
    fn rewind_phase2_stores(&self, height: u64) {
        for (name, outcome) in [
            ("shielded", self.shielded_store.as_ref().map(|s| s.rewind())),
            ("spark", self.spark_store.as_ref().map(|s| s.rewind())),
            ("kernel", self.kernel_store.as_ref().map(|s| s.rewind())),
        ] {
            if outcome == Some(false) {
                tracing::warn!(
                    "{}_store.rewind() returned false at h={} — store could not \
                     be rolled back; tree/UTXO state may be inconsistent",
                    name,
                    height
                );
            }
        }
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
            ct.lock().register_spend(
                spent_commitment,
                input_commitment,
                created_at,
                spent_at,
                kernel,
            );
        }
    }

    pub fn cut_through_stats(&self) -> crate::crypto::mw_cutthrough::CutThroughStats {
        self.cut_through
            .as_ref()
            .map(|ct| ct.lock().stats())
            .unwrap_or_default()
    }

    /// Initialize genesis block
    pub fn init_genesis(&self) -> Result<Hash> {
        let _state_update = self.begin_state_update();
        let genesis = create_genesis_block_for(self.network);
        let hash = genesis.hash();

        // SECURITY: Verify genesis hash matches the hardcoded constant.
        // This catches accidental genesis block changes that would cause chain forks.
        let expected = self.expected_genesis_hash();
        if hash != expected {
            return Err(Error::InvalidState(format!(
                "Genesis hash mismatch! Computed {} but expected {}. \
                 The genesis block definition may have been altered.",
                hash.to_hex(),
                expected.to_hex()
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
            inner.stats.total_supply = calculate_block_reward(0).as_atomic() as u128;

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
                total_supply: calculate_block_reward(0).as_atomic() as u128,
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

    fn expected_genesis_hash(&self) -> Hash {
        match self.network {
            NetworkType::Testnet | NetworkType::Regtest => crate::testnet::expected_genesis_hash(),
            NetworkType::Mainnet => crate::mainnet::expected_genesis_hash(),
        }
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
        self.load_from_database_with_outcome().map(|_| ())
    }

    /// Genesis initialization requires an explicit fresh-database result.
    pub fn load_from_database_with_outcome(&self) -> Result<ChainLoadOutcome> {
        let _state_update = self.begin_state_update();
        if let Some(ref db) = self.db {
            let state = match db.state.get_state()? {
                Some(state) => state,
                None if !db.blocks.has_any_chain_data() => return Ok(ChainLoadOutcome::Fresh),
                None => {
                    return Err(Error::DatabaseError(
                        "persisted block data exists without chain state; refusing to initialize genesis"
                            .into(),
                    ));
                }
            };

            let actual_genesis = db.blocks.get_hash_by_height(0)?.ok_or_else(|| {
                Error::DatabaseError(
                    "chain state exists but the block height index has no genesis entry".into(),
                )
            })?;
            let expected_genesis = self.expected_genesis_hash();
            if actual_genesis != expected_genesis {
                return Err(Error::DatabaseError(format!(
                    "database genesis {} does not match the expected {} genesis {}",
                    actual_genesis, self.network, expected_genesis,
                )));
            }

            return match db.blocks.get(&state.tip_hash)? {
                Some(tip_block) => {
                    if tip_block.header.height != state.height {
                        return Err(Error::DatabaseError(format!(
                            "chain state height {} does not match tip block height {}",
                            state.height, tip_block.header.height,
                        )));
                    }
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
                        inner.stats.total_supply = state.total_supply;
                        inner.stats.tip_hash = state.tip_hash;
                        inner.stats.total_difficulty = state.total_difficulty;
                        // Sync stats.difficulty with the loaded tip. Without this,
                        // stats.difficulty stays at ChainStats::default() (= 0) until
                        // a new block lands via the main-chain add path (chain.rs:1490).
                        // The RPC `get_info` "difficulty" field reads from
                        // stats.difficulty (src/rpc/server.rs:511), so the bug surfaces
                        // as `"difficulty":"0"` in get_info after every node restart
                        // until the first non-fork block arrives. Observed on the
                        // testnet api box 2026-06-01 after the fleet upgrade.
                        inner.stats.difficulty = difficulty;
                    }
                    tracing::info!(
                        "Loaded chain state: height={}, tip={}",
                        state.height,
                        state.tip_hash.to_hex()
                    );

                    // Self-heal total_difficulty from the active chain.
                    //
                    // The stored value can drift from the deterministic
                    // `1 + Σ dft(1..=height)` when the node has taken the
                    // (pre-fix) reorg path, which accumulated against a
                    // `dft(genesis)` base or stored a partial fork walk. A
                    // drifted value makes this node advertise a `ChainWorkMessage`
                    // that disagrees with peers on the SAME tip's work, which
                    // false-positives their `work_behind` veto and locks their
                    // (follower) miners out. Recompute the canonical value and
                    // overwrite in memory; the corrected value persists on the
                    // next block commit. If any block is missing we keep the
                    // stored value rather than store a wrong partial.
                    if let Some(recomputed) = self.recompute_total_difficulty(state.height) {
                        let mut inner = self.inner.write();
                        if inner.stats.total_difficulty != recomputed {
                            tracing::warn!(
                                "total_difficulty self-heal on load: stored={} recomputed={} delta={} \
                                 — converging to the deterministic 1 + Σ dft(1..=height)",
                                inner.stats.total_difficulty,
                                recomputed,
                                (recomputed as i128) - (inner.stats.total_difficulty as i128),
                            );
                            inner.stats.total_difficulty = recomputed;
                        }
                    }

                    // Rebuild UTXO set from stored blocks so that key image
                    // checks and decoy selection work immediately after restart.
                    self.rebuild_utxo_set(state.height)?;

                    // Rebuild tx index if empty (migration for existing chains)
                    if let Some(ref db) = self.db {
                        if db.tx_index_is_empty() && state.height > 0 {
                            tracing::info!("Building tx index for {} blocks...", state.height + 1);
                            let start = std::time::Instant::now();
                            let mut indexed = 0u64;
                            let mut failed = 0u64;
                            for h in 0..=state.height {
                                if let Some(block) = self.get_block_by_height(h) {
                                    for (idx, tx) in block.transactions.iter().enumerate() {
                                        if let Err(e) =
                                            db.index_tx(tx.hash().as_bytes(), h, idx as u32)
                                        {
                                            failed += 1;
                                            // Log per-failure at DEBUG to avoid log
                                            // spam during a corrupt-DB rebuild, but
                                            // a non-zero `failed` count at the end
                                            // surfaces the issue at WARN.
                                            tracing::debug!(
                                                target: "chain::tx_index_rebuild",
                                                "index_tx failed at h={} idx={}: {}",
                                                h, idx, e
                                            );
                                        } else {
                                            indexed += 1;
                                        }
                                    }
                                }
                            }
                            if failed > 0 {
                                tracing::warn!(
                                    "Tx index rebuild: {} indexed, {} FAILED in {:.2}s. \
                                     Failed lookups will return None until next rebuild.",
                                    indexed,
                                    failed,
                                    start.elapsed().as_secs_f64()
                                );
                            } else {
                                tracing::info!(
                                    "Tx index built: {} txs in {:.2}s",
                                    indexed,
                                    start.elapsed().as_secs_f64()
                                );
                            }
                        }
                    }

                    // Verify tip integrity after loading (catches poisoned lock corruption)
                    self.verify_tip_integrity()?;

                    Ok(ChainLoadOutcome::Loaded)
                }
                None => Err(Error::DatabaseError(format!(
                    "chain state references missing tip block {} at height {}",
                    state.tip_hash, state.height,
                ))),
            };
        }
        Ok(ChainLoadOutcome::Fresh)
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
                        // Fix: truncate the tip to the last good height.
                        //
                        // 2026-06-03 bug fix: previously the tip-restore branch
                        // only ran if `height_to_hash.get(&good_height)`
                        // returned Some — but that in-memory map is populated
                        // only for blocks in the cache window (last ~200
                        // heights, see line ~803-806). For corruption detected
                        // at any height BELOW the cache window, the lookup
                        // returned None and `inner.tip` was never reset. The
                        // node would restart looking healthy (stats.height
                        // dropped to good_height, but tip.height stayed at the
                        // state-claimed pre-corruption value), then reject
                        // every subsequent new block with "invalid height:
                        // expected <state_tip+1>, got <good_height+1>", and
                        // the chain would be stuck until manual intervention.
                        //
                        // `prev_hash` already holds the hash of the previous
                        // good block (set at line ~796-797 each iteration), so
                        // use it directly — no cache dependency. stats.height,
                        // tip.height, and tip.hash now ALWAYS move together.
                        let good_height = height - 1;
                        let good_hash = prev_hash;
                        inner.stats.height = good_height;
                        inner.tip.height = good_height;
                        inner.tip.hash = good_hash;
                        inner.stats.tip_hash = good_hash;
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
                            total_supply: inner.stats.total_supply,
                            total_burned: 0,
                            last_checkpoint,
                        };
                        if let Err(e) = db.state.save_state(&state) {
                            // Surfacing this previously-silent error closes the
                            // audit finding "let _ = save_state drops critical
                            // persistence error." If save_state fails after a
                            // truncation, the on-disk tip will be ahead of the
                            // in-memory truncated state — on restart the chain
                            // re-loads the stale tip, masking the truncation.
                            // We can't abort here (we're mid-truncation, the
                            // in-memory state is correct), but at least the
                            // operator gets a CRITICAL log line. Reference:
                            // Bitcoin Core reports comparable post-flush
                            // failures through `FatalError()` (validation.h:104
                            // in the master read this session; the previous
                            // `AbortNode()` identifier was renamed).
                            tracing::error!(
                                target: "chain::persistence",
                                "CRITICAL: save_state failed after truncation to height {} ({}). \
                                 Restart will reload stale on-disk tip. Manual operator \
                                 intervention required.",
                                good_height, e
                            );
                        }
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
                        tracing::info!(
                            "  UTXO rebuild: {}/{} blocks processed",
                            height,
                            tip_height
                        );
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
        crate::consensus::validate_transaction_for_network(
            tx,
            &inner.utxos,
            inner.tip.height + 1,
            self.network,
        )
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
        // Firework Phase 2 (I6): a peer advertising a verifiably-heavier
        // chain vetoes "synced" regardless of block height — this is what
        // stops a node on a higher-block/lower-work fork from reporting
        // synced (and its miner from mining). Inert for height-only peers
        // (no CAP_CHAINWORK), and cleared by the sync layer's anti-wedge
        // machinery (expire/ban/prune) once an unsubstantiated claim is
        // dropped, so it can never wedge us permanently.
        if self.work_behind.load(std::sync::atomic::Ordering::Relaxed) {
            return false;
        }
        let flag = self.synced.load(std::sync::atomic::Ordering::Relaxed);
        if flag {
            return true;
        }
        let h = self.height();
        if h == 0 {
            return false;
        }
        let target = self
            .peer_target_height
            .load(std::sync::atomic::Ordering::Relaxed);
        if h >= target {
            return true;
        }
        // Tolerance for in-flight peer advertisements: ≤2 blocks behind
        // the peer-advertised target, AND tip is fresh enough that the
        // chain is clearly producing blocks (not actually stalled).
        if target.saturating_sub(h) <= 2 {
            let tip_timestamp = self.inner.read().tip.timestamp;
            if let Ok(d) = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH) {
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

    /// Count blocks in `[window_start, window_end)` whose coinbase signals
    /// the given BIP-9 deployment bit.
    ///
    /// Provides the `signal_count_fn` callback that `ForkSignaler::state()`
    /// (see `src/consensus/fork_signal.rs`) consumes. Walks the main-chain
    /// blocks in the half-open range, inspects each block's coinbase
    /// transaction's `extra` field, decodes the trailing 4 bytes as
    /// `SignalBits` (via `fork_signal::decode_signal_bits`), and counts the
    /// blocks where the queried bit is set.
    ///
    /// ## Backward compatibility
    ///
    /// Blocks mined by a pre-CIP-012 rig binary have an 8-byte coinbase
    /// `extra` (height only, no trailing signal bytes). `decode_signal_bits`
    /// returns `SignalBits(0)` for those, so they contribute 0 to the count
    /// — same as a v1.0.12-aware rig that didn't pass `--signal-v1012`.
    /// New miners that DO opt in produce 12-byte extras with the bit set,
    /// and contribute 1 to the count.
    ///
    /// ## Performance
    ///
    /// `get_block_by_height` is amortized O(1): two `HashMap` lookups in
    /// the in-memory cache (`blocks` + `height_to_hash`) for blocks within
    /// the cache window, with a sled-disk fallback for older blocks. The
    /// signal-window scan is 2016 blocks, which fits well within the
    /// in-memory cache for any block within `2 × MAX_BLOCK_CACHE` of the
    /// tip — i.e., the entire BIP-9 window is almost certainly hot. If
    /// every block in the window were uncached (worst case during a deep
    /// reorg-replay), each lookup adds ~one sled `get()` of <1 ms, capping
    /// the full scan at ~2 seconds — still acceptable for a once-per-block
    /// invocation, but worth noting that the "O(1) per lookup" claim
    /// assumes hot cache.
    ///
    /// No memoization yet; if profiling shows this on a hot path, the
    /// per-window count is trivially memoizable since it only changes by
    /// ±1 when a new block lands (or a reorg unwinds + replays). A
    /// single read-lock-held-across-the-whole-scan variant would also
    /// shave ~300 µs vs the current per-block acquire pattern. Both
    /// optimizations are YAGNI right now — BIP-9 query is one-per-block
    /// at most, dwarfed by the RandomX + Bulletproof costs of validation.
    ///
    /// ## Missing-block handling
    ///
    /// A height that maps to no block (gap in the chain, e.g. during
    /// reorg-rollback) is skipped without error — counts as 0 contribution.
    /// A block whose coinbase is missing (impossible by construction, but
    /// defensive) is similarly skipped. The point of the BIP-9 state
    /// machine is to be robust against partial state; an aggressive panic
    /// here would convert a transient DB-gap into a node halt.
    ///
    /// ## Prior art
    ///
    /// - **Bitcoin Core `AbstractThresholdConditionChecker::GetStateStatisticsFor`**
    ///   at versionbits.cpp:119 in the master read this session does the
    ///   equivalent count by walking `CBlockIndex` pointers. The prior
    ///   comment misattributed the method to `ThresholdConditionCache`
    ///   (which is a `std::map` typedef at versionbits.h:33, not the
    ///   owner of the method).
    /// - Other BIP-9-derived chains (Bitcoin Cash / Litecoin / Dogecoin)
    ///   inherit the walk-block-index-counting shape; specific per-fork
    ///   identifiers UNVERIFIED this session.
    pub fn count_signaling_blocks_in_window(
        &self,
        window_start: u64,
        window_end: u64,
        bit: u32,
    ) -> u64 {
        use crate::consensus::fork_signal::decode_signal_bits;

        // Early-out on degenerate/inverted ranges. saturating_sub guards
        // against the (window_end < window_start) case — a caller bug
        // that shouldn't happen but won't underflow a u64 if it does.
        // Inlined into the check (no variable) per review feedback —
        // the value isn't used elsewhere.
        if window_end.saturating_sub(window_start) == 0 {
            return 0;
        }

        let mut count: u64 = 0;
        for h in window_start..window_end {
            let Some(block) = self.get_block_by_height(h) else {
                continue; // gap; contributes 0
            };
            let Some(coinbase) = block.coinbase() else {
                continue; // structurally impossible; defensive
            };
            if decode_signal_bits(&coinbase.extra).signals(bit) {
                count = count.saturating_add(1);
            }
        }
        count
    }

    /// Restore state from database
    pub fn restore_state(&self, height: u64, tip_hash: Hash, total_difficulty: u128) -> Result<()> {
        let _state_update = self.begin_state_update();
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
        let _state_update = self.begin_state_update();
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
            current_height,
            target_height,
            depth
        );

        let mut all_orphaned_txs = Vec::new();
        {
            let mut inner = self.inner.write();

            // Disconnect blocks in reverse height order
            for h in (target_height + 1..=current_height).rev() {
                let orphan_hash = inner.height_to_hash.get(&h).copied();
                if let Some(oh) = orphan_hash {
                    let orphan_txs = inner.blocks.get(&oh).map(|b| b.transactions.clone());
                    if let Some(txs) = orphan_txs {
                        let disconnect_batch = UtxoSet::batch_disconnect_block(&txs);
                        inner.utxos.apply_batch(disconnect_batch);
                        // Phase 2 store rewind (site 2: rollback_to_height
                        // deep-partition recovery). One rewind per
                        // disconnected block, in the same reverse-height
                        // order as the UTXO disconnect. Inert while stores
                        // are None.
                        self.rewind_phase2_stores(h);
                        // Collect non-coinbase txs
                        for tx in &txs {
                            if !tx.is_coinbase() {
                                all_orphaned_txs.push(tx.clone());
                            }
                        }
                        // Subtract emission
                        let emission = calculate_block_reward(h);
                        // C-4/H-11 FIX: checked_sub instead of saturating_sub — underflow = corruption.
                        //
                        // AUDIT (2026-07-02): third site of the self-defeating supply-
                        // underflow gate. Two sibling sites (~L2002 and ~L2228) were
                        // fixed in the 2026-07-01 pass; a `replace_all` used at the
                        // time missed this one (and the one at ~L2352) because the
                        // whitespace indentation differed (24 spaces here vs 32
                        // at the fixed sites). Doc-vs-code drift audit flagged the
                        // miss on the second pass. Same rationale as the fixed
                        // sites: `.unwrap_or_else(|_| panic!(...))` instead of a
                        // match with an `Amount::from_atomic(0)` error arm — the
                        // silent clamp defeats the point of `checked_sub` and
                        // corrupts every downstream supply read. See fixed sites'
                        // audit block for the full rationale + prior art citations
                        // (specific upstream identifiers UNVERIFIED this session
                        // — see the updated block above).
                        inner.stats.total_supply = inner
                            .stats
                            .total_supply
                            .checked_sub(emission.as_atomic() as u128)
                            .unwrap_or_else(|| {
                                panic!(
                                    "CONSENSUS CORRUPTION: supply underflow on reorg rollback — \
         tried to subtract emission={} from total_supply={} at height being disconnected. \
         In-memory supply state is unrecoverable; halting to preserve on-disk state \
         (SIGTERM handler will flush RocksDB cleanly). Restart the node — the persisted \
         chain will re-derive supply correctly. If this recurs on restart, the on-disk \
         chain state is corrupt and requires a reindex.",
                                    emission, inner.stats.total_supply
                                )
                            });
                    }
                }
                inner.height_to_hash.remove(&h);
            }

            // Update tip to the block at target_height.
            //
            // 2026-06-03 robustness fix (parity with rebuild_utxo_set Bug
            // #8 at chain.rs:751): the in-memory `height_to_hash` map is
            // bounded by the cache window (~200 blocks). For deep
            // rollbacks where `target_height` falls outside the cache
            // (theoretically bounded by CHECKPOINT_INTERVAL=144 + the
            // finality check above, but only as long as last_checkpoint
            // recording is healthy), the lookup misses and we never reset
            // `inner.tip`. That leaves `stats.height` and `tip.height`
            // pointing at different values — the same split-state bug
            // pattern Bug #8 fixed in rebuild_utxo_set.
            //
            // Cascade lookup: in-memory cache → DB by height (single
            // sled get, cheap even under inner.write()) → genesis
            // fallback for h=0 → log + leave tip alone. tip.height,
            // tip.hash, stats.height, stats.tip_hash now ALL move
            // together in every branch.
            let cached_hash = inner.height_to_hash.get(&target_height).copied();
            let db_hash = cached_hash.or_else(|| {
                self.db
                    .as_ref()
                    .and_then(|db| db.blocks.get_hash_by_height(target_height).ok().flatten())
            });
            if let Some(new_tip_hash) = db_hash {
                // Pull the block for difficulty/timestamp where possible;
                // a cache miss is non-fatal (tip moves on hash + height
                // alone, difficulty/timestamp recompute on next block).
                let cached_block = inner.blocks.get(&new_tip_hash).cloned();
                let db_block = cached_block.or_else(|| {
                    self.db
                        .as_ref()
                        .and_then(|db| db.blocks.get(&new_tip_hash).ok().flatten())
                });
                if let Some(tip_block) = db_block {
                    inner.tip = ChainTip {
                        hash: new_tip_hash,
                        height: target_height,
                        difficulty: calculate_difficulty_from_target(&tip_block.header.target),
                        timestamp: tip_block.header.timestamp,
                    };
                } else {
                    inner.tip.hash = new_tip_hash;
                    inner.tip.height = target_height;
                }
                inner.stats.height = target_height;
                inner.stats.tip_hash = new_tip_hash;
            } else if target_height == 0 {
                // Genesis fallback — DB may have been pruned of height 0
                if let Some(genesis) = inner.genesis_hash {
                    inner.tip.hash = genesis;
                    inner.tip.height = 0;
                    inner.stats.height = 0;
                    inner.stats.tip_hash = genesis;
                }
            } else {
                // Truly nothing found — neither cache nor DB nor genesis.
                // Log loudly; leaving tip unchanged is safer than guessing.
                tracing::error!(
                    "rollback_to_height: could not locate block at target {} \
                     in cache OR DB. Tip left unchanged at {} (h={}). \
                     Manual intervention required; chain may need full resync.",
                    target_height,
                    inner.tip.hash.to_hex()[..16].to_string(),
                    inner.tip.height,
                );
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
                total_supply: inner.stats.total_supply,
                total_burned: 0,
                last_checkpoint,
            };
            if let Err(e) = db.state.save_state(&state) {
                // Surface previously-silent error after rollback. The
                // in-memory tip is correct; the on-disk tip is now stale.
                // Restart would reload stale state. See sibling error
                // path above for the same pattern + the corrected
                // Bitcoin Core `FatalError` reference (formerly
                // `AbortNode`).
                tracing::error!(
                    target: "chain::persistence",
                    "CRITICAL: save_state failed after rollback to height {} ({}). \
                     Restart will reload stale tip. Manual intervention required.",
                    inner.stats.height, e
                );
            }
        }

        tracing::info!(
            "Rollback complete: chain at height {}, {} orphaned txs returned",
            target_height,
            all_orphaned_txs.len()
        );

        Ok(all_orphaned_txs)
    }

    /// Record a chain event in the ring buffer (bounded, lock-free for readers).
    fn record_event(
        &self,
        event_type: ChainEventType,
        height: u64,
        hash: &Hash,
        details: serde_json::Value,
    ) {
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
        let _state_update = self.begin_state_update();
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
            self.record_event(
                ChainEventType::OrphanReceived,
                block.header.height,
                &hash,
                serde_json::json!({}),
            );
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
            let cp = self
                .db
                .as_ref()
                .and_then(|db| db.state.get_state().ok().flatten())
                .and_then(|s| {
                    if s.last_checkpoint > 0 {
                        Some(s.last_checkpoint)
                    } else {
                        None
                    }
                });
            let validation = crate::consensus::validate_block_with_checkpoint_for_network(
                &block,
                parent.as_ref(),
                &inner.utxos,
                cp,
                self.network,
            )
            .map_err(|e| Error::InvalidState(format!("Block validation error: {}", e)))?;
            if !validation.valid {
                let errors = validation.errors.join("; ");
                tracing::warn!("Block {} rejected: {}", &hash.to_hex()[..16], errors);
                drop(inner);
                self.record_event(
                    ChainEventType::BlockRejected,
                    block.header.height,
                    &hash,
                    serde_json::json!({"reason": &errors}),
                );
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
                    // AUDIT (2026-07-01): checked_add + panic for symmetry with the
                    // reorg-rollback path's checked_sub + panic (fixed same day).
                    // saturating_add silently clamps at u64::MAX; if emission ever
                    // returns a corrupt large value (bug in calculate_block_reward),
                    // the silent clamp hides it and every subsequent supply query
                    // returns u64::MAX until the process is bounced. Panicking on
                    // overflow surfaces the corruption exactly once, at the site.
                    // Prior art matches the SEV-A rollback fix comment above.
                    inner.stats.total_supply = inner
                        .stats
                        .total_supply
                        .checked_add(emission.as_atomic() as u128)
                        .unwrap_or_else(|| {
                            panic!(
                                "CONSENSUS CORRUPTION: supply overflow on block connect — \
                             tried to add emission={} to total_supply={}. Emission is \
                             deterministic from height and cannot be attacker-controlled; \
                             this indicates a bug in calculate_block_reward or on-disk \
                             corruption. Halting for RocksDB flush + operator triage.",
                                emission, inner.stats.total_supply
                            )
                        });

                    // ── Phase 2 store reorg checkpoint (site 1: clean tip-extend) ──
                    // CIP-009.D Interp-B contract: checkpoint each Phase-2
                    // store BEFORE this block's state is applied, so a later
                    // reorg `rewind` rolls them back to exactly this
                    // pre-block boundary. Inert while the stores are None.
                    self.checkpoint_phase2_stores(block.header.height);

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

                // Index transactions for O(1) lookup by hash.
                //
                // Audit fix: previously `let _ =` silently dropped index
                // errors, so a transient DB error here could leave the
                // tx_index missing entries even though the block was
                // accepted to the chain. The on-chain tx becomes
                // unfindable by hash (explorer + wallet sync break).
                // We now log warn per-failure so an operator notices.
                //
                // The deeper fix (move index_tx INSIDE the block-apply
                // RocksDB WriteBatch) is deferred — it requires
                // refactoring `commit_block_to_db` to take the entire
                // tx_index update set as a batch parameter. Reference:
                // Bitcoin Core keeps tx→block indexing inside the block-
                // apply atomic batch (see `ConnectBlock` flow in
                // src/validation.cpp). The prior comment cited
                // `LookupBlockIndex` for this purpose; `LookupBlockIndex`
                // exists (validation.cpp:135 in the master read this
                // session) but it's the block-hash→pindex lookup, not
                // the tx→block writer. Reference kept qualitative rather
                // than perpetuate a mis-named identifier.
                if let Some(ref db) = self.db {
                    for (idx, tx) in block.transactions.iter().enumerate() {
                        if let Err(e) =
                            db.index_tx(tx.hash().as_bytes(), block.header.height, idx as u32)
                        {
                            tracing::warn!(
                                target: "chain::tx_index",
                                "tx_index insert failed for tx {} at height {}: {} \
                                 (block accepted; explorer/wallet may miss this tx by hash)",
                                hex::encode(tx.hash().as_bytes()), block.header.height, e
                            );
                        }
                    }
                }

                // Update database height index (only after race check passes)
                if let Some(ref db) = self.db {
                    db.blocks.set_height_hash(block.header.height, &hash)?;

                    // Auto-record checkpoint every CHECKPOINT_INTERVAL blocks
                    let mut last_checkpoint_height = 0u64;
                    if block.header.height > 0
                        && block.header.height % crate::constants::CHECKPOINT_INTERVAL == 0
                    {
                        if let Err(e) = db.state.add_checkpoint(block.header.height, &hash) {
                            tracing::error!(
                                "Failed to record checkpoint at height {}: {}",
                                block.header.height,
                                e
                            );
                        } else {
                            last_checkpoint_height = block.header.height;
                            tracing::info!(
                                "Auto-checkpoint recorded: height={}, hash={}",
                                block.header.height,
                                hash.to_hex()[..16].to_string()
                            );
                            self.record_event(
                                ChainEventType::CheckpointRecorded,
                                block.header.height,
                                &hash,
                                serde_json::json!({}),
                            );
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
                        total_supply: stats.total_supply,
                        total_burned: 0,
                        last_checkpoint: last_checkpoint_height,
                    };
                    db.state.save_state(&state)?;
                }

                // ── Phase 2 privacy store wire-up (P3d) ─────────────────
                //
                // The Phase-2 store reorg checkpoint is taken earlier, at
                // site 1 (just before this block's UTXO mutations are
                // applied) per the CIP-009.D Interp-B contract — see
                // `checkpoint_phase2_stores`. It is intentionally NOT
                // re-taken here. This block now only runs the MW
                // cut-through engine to emit commitments eligible for
                // pruning.
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

                // CIP-011 Phase-3: feed accepted blocks to the rolling-
                // finality adapter so it records attestations + advances
                // the soft-final tip. The adapter handles "no attestation
                // in coinbase extra" internally as a no-op, which matches
                // the CIP-011 ENABLE-phase contract (attestations
                // permitted, rule does NOT fire). Inert when the field
                // is `None` or the feature is off.
                #[cfg(feature = "rolling-finality")]
                if let Some(ref rf) = self.rolling_finality {
                    if block.header.height >= crate::constants::ROLLING_FINALITY_ENABLE_HEIGHT {
                        // CIP-009.D attestations live in the coinbase
                        // transaction's `extra` field. Pre-activation
                        // miners typically have no coinbase or an empty
                        // extra — the adapter's `find_attestation` scans
                        // for the `CIP9` magic and returns
                        // `NoAttestation` otherwise.
                        let coinbase_extra: &[u8] = block
                            .transactions
                            .first()
                            .filter(|tx| tx.is_coinbase())
                            .map_or(&[][..], |tx| &tx.extra);
                        let _ = rf.on_accepted_block(block.header.height, coinbase_extra);
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
                    supply_atomic = %stats_snapshot.1,
                    "BLOCK_COMMIT"
                );

                self.record_event(
                    ChainEventType::BlockAccepted,
                    block.header.height,
                    &hash,
                    serde_json::json!({
                        "tx_count": block.transactions.len(),
                        "difficulty": difficulty,
                    }),
                );

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

            // Fork choice: cumulative work first (Nakamoto), then a
            // deterministic tiebreak on equal work. Without a tiebreak, two
            // chains of identical work never reorg, and a withheld
            // equal-work fork can sit forever.
            //
            // Tiebreak: prefer the tip whose hash is lexicographically
            // SMALLER (i.e. more leading zeros = "luckier" PoW). This is
            // independent of network arrival timing, so honest nodes
            // converge to the same tie-winning chain regardless of which
            // half of the partition they're in. It also resists
            // "fresher-timestamp" tiebreaks that incentivize timestamp
            // manipulation. Reference (VERIFIED against upstream master
            // this session): Bitcoin Core's `Chainstate::FindMostWorkChain`
            // (validation.cpp:3128 — note the class is `Chainstate`, not
            // `ChainstateManager` as the prior comment said) uses
            // `nSequenceId` (arrival-order tie-breaker; assigned at
            // validation.cpp:3819 via `nBlockSequenceId++`, and referenced
            // by fork-choice ordering at validation.cpp:3167 / :3516),
            // which is a per-node value and non-deterministic across the
            // network. Our hash-lex tiebreak is network-deterministic —
            // any honest node sees the same winner regardless of arrival
            // order. (The prior comment also claimed zebrad uses
            // hash-as-tiebreak in its non-finalized state; that specific
            // Zebra behaviour was not re-confirmed against source this
            // session, so it's not asserted.)
            let take_fork = if fork_cumulative > current_total_difficulty {
                true
            } else if fork_cumulative == current_total_difficulty {
                let current_tip_hash = self.tip().hash;
                let fork_tip = block.hash();
                fork_tip.as_bytes() < current_tip_hash.as_bytes()
            } else {
                false
            };
            if take_fork {
                // Fork has more work (or wins the deterministic tiebreak) —
                // perform chain reorganization (standard Nakamoto rule).

                // Find the common ancestor (fork point). `None` means DB
                // corruption (cycle or missing parent during walk); reject
                // the reorg attempt outright rather than masking it as a
                // ReorgTooDeep — the log inside find_fork_point already
                // explains the corruption with diagnostic context.
                let fork_point = match self.find_fork_point(&block) {
                    Some(h) => h,
                    None => {
                        return Err(Error::Corruption(
                            "fork-point search aborted by DB corruption (cycle or missing parent); reorg rejected".into(),
                        ));
                    }
                };

                // SECURITY (H-16 FIX): Hybrid reorg defense — three tiers.
                // Tier 1 (≤10): unconditional. Tier 2 (11-100): MESS exponential cost.
                // Tier 3 (>100): hard reject.
                let reorg_depth = block.header.height.saturating_sub(fork_point);
                // F31 SEV-A fix: pass the RUNTIME network's max reorg depth,
                // not the compile-time-feature-derived value. See
                // Blockchain::max_reorg_depth doc-comment for the 2026-07-04
                // partition context that motivated this change.
                let net_max = self.max_reorg_depth();
                if let Err(reason) = evaluate_reorg_acceptability(
                    reorg_depth,
                    fork_cumulative,
                    current_total_difficulty,
                    self.height(),
                    net_max,
                ) {
                    tracing::error!("Rejecting reorg at depth {}: {}", reorg_depth, reason);
                    return Err(Error::ReorgTooDeep {
                        depth: reorg_depth,
                        max: net_max,
                    });
                }

                // CIP-011 Phase-3: soft-finality reorg gate. After the
                // enforce height, refuse any reorg whose fork point sits
                // at or below the miner-attested soft-final tip — the
                // miner-signed rolling-checkpoint rule from CIP-009.D.
                // Layers on top of the 3-tier MESS hybrid above, so a
                // reorg must beat *both* tests. Inert when the adapter
                // is `None` or the feature is off.
                #[cfg(feature = "rolling-finality")]
                if let Some(ref rf) = self.rolling_finality {
                    if block.header.height >= crate::constants::ROLLING_FINALITY_ENFORCE_HEIGHT
                        && rf.would_reorg_violate_finality(fork_point)
                    {
                        let soft_final = rf.current_soft_final_height().unwrap_or(0);
                        tracing::error!(
                            "Rejecting reorg: fork point {} <= soft-final tip {} (CIP-009.D)",
                            fork_point,
                            soft_final
                        );
                        // The implied "shallowest acceptable reorg" is one
                        // whose fork point is strictly above the soft-final
                        // tip. Express the rejection in `ReorgTooDeep`'s
                        // existing shape rather than adding a new error
                        // variant; the log line carries the precise reason.
                        return Err(Error::ReorgTooDeep {
                            depth: reorg_depth,
                            max: block
                                .header
                                .height
                                .saturating_sub(soft_final)
                                .saturating_sub(1),
                        });
                    }
                }

                // SECURITY: Reject reorgs that would revert past the last rolling
                // checkpoint. This prevents long-range reorganization attacks where
                // an attacker builds a hidden chain from far in the past.
                if let Some(ref db) = self.db {
                    let last_cp = db
                        .state
                        .get_state()
                        .ok()
                        .flatten()
                        .map(|s| s.last_checkpoint)
                        .unwrap_or(0);
                    if last_cp > 0 && fork_point < last_cp {
                        tracing::error!(
                            "Rejecting reorg: fork point {} is before last checkpoint at height {}",
                            fork_point,
                            last_cp
                        );
                        return Ok(BlockStatus::Invalid(format!(
                            "Reorg rejected: fork point {} is before checkpoint at height {}",
                            fork_point, last_cp
                        )));
                    }
                }

                tracing::warn!(
                    "Fork at height {} has more work ({} > {}), performing reorg (depth: {})",
                    block.header.height,
                    fork_cumulative,
                    current_total_difficulty,
                    reorg_depth
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
                let mut disconnected_tx_lists: Vec<Vec<crate::transaction::Transaction>> =
                    Vec::new();
                let mut disconnected_heights: Vec<(u64, Hash)> = Vec::new();
                {
                    let mut inner = self.inner.write();
                    let current_height = inner.tip.height;

                    // Disconnect orphaned blocks in reverse height order
                    for h in (fork_point + 1..=current_height).rev() {
                        let orphan_hash = inner.height_to_hash.get(&h).copied();
                        if let Some(oh) = orphan_hash {
                            // Clone transactions to avoid borrow conflict with utxos
                            let orphan_txs = inner.blocks.get(&oh).map(|b| b.transactions.clone());
                            if let Some(txs) = orphan_txs {
                                disconnected_blocks += 1;
                                disconnected_txs += txs.len() as u64;
                                // SECURITY (BUG-1): Remove outputs added by the orphaned
                                // block AND un-mark key images spent by its inputs.
                                // batch_disconnect_block now includes key_image_removals.
                                let disconnect_batch = UtxoSet::batch_disconnect_block(&txs);
                                inner.utxos.apply_batch(disconnect_batch);
                                // Phase 2 store rewind (site 3: reorg
                                // disconnect of main-chain blocks). One
                                // rewind per disconnected block, popping the
                                // checkpoint site 1 took before that block.
                                // All three stores — shielded, spark, kernel
                                // — rewind together so none diverges from the
                                // UTXO set on a reorg. Inert while the stores
                                // are None.
                                self.rewind_phase2_stores(h);
                                // Collect for output index removal
                                disconnected_tx_lists.push(txs);
                                // Subtract this block's emission from supply
                                let emission = calculate_block_reward(h);
                                // C-4/H-11 FIX: checked_sub instead of saturating_sub — underflow = corruption.
                                //
                                // AUDIT (2026-07-01): the previous error arm zeroed the supply
                                // (`Amount::from_atomic(0)`) and continued. That defeated the whole
                                // point of the checked_sub: the "checked" branch, when it fires,
                                // was doing saturating-to-zero with an extra log line. If
                                // `total_supply < emission_of_block_being_rolled_back`, the
                                // in-memory state is proven corrupt (we're rolling back more
                                // coinbase than we ever minted). Continuing from a zeroed supply
                                // is worse than halting: every downstream check against the supply
                                // cap becomes wrong, and any RPC reader gets a fabricated answer.
                                //
                                // Prior art:
                                //   (Specific upstream identifiers UNVERIFIED this session.)
                                //   The prior comment cited Bitcoin Core asserts
                                //   `nBitsCurrent > 0` / `nMoneySupply >= 0`, a Monero
                                //   `verification_context.h` defensive panic, and
                                //   zebrad `expect("chain state invariant")`. None of
                                //   those exact identifiers were re-confirmed against
                                //   current upstream this session, so the specific
                                //   citations are removed. The "silent corruption is a
                                //   stop condition, not a warning" principle stands on
                                //   its own reasoning above.
                                //
                                // Halting via panic is safe here because the SIGTERM/SIGINT
                                // handlers on this node flush RocksDB cleanly on shutdown
                                // (the tokio signal handler installed for the 2026-06 zombie-
                                // state fix). See operator rule `no self-defeating gates`.
                                inner.stats.total_supply = inner
                                    .stats
                                    .total_supply
                                    .checked_sub(emission.as_atomic() as u128)
                                    .unwrap_or_else(|| {
                                        panic!(
        "CONSENSUS CORRUPTION: supply underflow on reorg rollback — \
         tried to subtract emission={} from total_supply={} at height being disconnected. \
         In-memory supply state is unrecoverable; halting to preserve on-disk state \
         (SIGTERM handler will flush RocksDB cleanly). Restart the node — the persisted \
         chain will re-derive supply correctly. If this recurs on restart, the on-disk \
         chain state is corrupt and requires a reindex.",
        emission, inner.stats.total_supply
    )
                                    });
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
                        let validation =
                            match crate::consensus::validate_block_with_checkpoint_for_network(
                                fork_block,
                                parent.as_ref(),
                                &inner.utxos,
                                None,
                                self.network,
                            ) {
                                Ok(v) => v,
                                Err(e) => {
                                    reorg_error =
                                        Some(format!("Fork block validation error: {}", e));
                                    break;
                                }
                            };
                        if !validation.valid {
                            let errors = validation.errors.join("; ");
                            tracing::warn!(
                                "Fork block {} rejected during reorg: {}",
                                fork_block.hash().to_hex(),
                                errors
                            );
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
                                let expected_target =
                                    calculate_difficulty(&diff_blocks, fork_block.header.height);
                                if fork_block.header.target != expected_target {
                                    tracing::warn!(
                                        "Fork block {} at height {} has wrong difficulty target",
                                        fork_block.hash().to_hex(),
                                        fork_block.header.height
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
                        inner
                            .height_to_hash
                            .insert(fork_block.header.height, fork_hash);

                        // Phase 2 store reorg checkpoint (site 4: reorg
                        // connect of fork blocks). Checkpoint each store
                        // BEFORE applying this fork block's state, so if a
                        // *future* reorg disconnects it, `rewind` has a
                        // boundary to roll back to. Without this, fork
                        // blocks adopted by a reorg would be un-rewindable.
                        //
                        // Placement is load-bearing: this MUST sit
                        // immediately after the `height_to_hash` insert and
                        // BEFORE the DB-persist `break` below. The site-5a
                        // rollback guard keys on `height_to_hash`; if the
                        // checkpoint were taken after the DB-persist break
                        // point, a DB error would leave this block
                        // height-mapped but un-checkpointed, and site 5a
                        // would rewind one checkpoint too many — popping a
                        // checkpoint belonging to a different block. Keeping
                        // "height-mapped" and "checkpointed" inseparable
                        // makes the site-5a guard exact. Still satisfies the
                        // Interp-B "checkpoint before state applied"
                        // contract — the UTXO mutations are applied below.
                        // Inert while stores are None.
                        self.checkpoint_phase2_stores(fork_block.header.height);

                        if let Some(ref db) = self.db {
                            if let Err(e) = db
                                .blocks
                                .set_height_hash(fork_block.header.height, &fork_hash)
                            {
                                tracing::error!("CRITICAL: Failed to persist reorg height mapping at height {}: {}", fork_block.header.height, e);
                                reorg_error = Some(format!("DB error during reorg: {}", e));
                                break;
                            }
                        }

                        // Apply fork block's UTXO mutations
                        let batch = UtxoSet::batch_from_block(
                            fork_block.header.height,
                            &fork_block.transactions,
                        );
                        inner.utxos.apply_batch(batch);

                        // Add this fork block's emission to supply
                        let emission = calculate_block_reward(fork_block.header.height);
                        // AUDIT (2026-07-01): checked_add + panic for symmetry with the
                        // reorg-rollback path's checked_sub + panic (fixed same day).
                        // saturating_add silently clamps at u64::MAX; if emission ever
                        // returns a corrupt large value (bug in calculate_block_reward),
                        // the silent clamp hides it and every subsequent supply query
                        // returns u64::MAX until the process is bounced. Panicking on
                        // overflow surfaces the corruption exactly once, at the site.
                        // Prior art matches the SEV-A rollback fix comment above.
                        inner.stats.total_supply = inner
                            .stats
                            .total_supply
                            .checked_add(emission.as_atomic() as u128)
                            .unwrap_or_else(|| {
                                panic!(
                                    "CONSENSUS CORRUPTION: supply overflow on block connect — \
                             tried to add emission={} to total_supply={}. Emission is \
                             deterministic from height and cannot be attacker-controlled; \
                             this indicates a bug in calculate_block_reward or on-disk \
                             corruption. Halting for RocksDB flush + operator triage.",
                                    emission, inner.stats.total_supply
                                )
                            });
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
                            if inner
                                .height_to_hash
                                .get(&fork_block.header.height)
                                .map_or(false, |h| *h == fork_block.hash())
                            {
                                let disconnect =
                                    UtxoSet::batch_disconnect_block(&fork_block.transactions);
                                inner.utxos.apply_batch(disconnect);
                                // Phase 2 store rewind (site 5: failed-reorg
                                // rollback, undoing partially-applied fork
                                // blocks). Pairs with the site-4 checkpoint
                                // taken when each fork block was connected
                                // just above. Inert while stores are None.
                                self.rewind_phase2_stores(fork_block.header.height);
                                // Subtract the emission we added for this fork block
                                let emission = calculate_block_reward(fork_block.header.height);
                                // C-4/H-11 FIX: checked_sub instead of saturating_sub — underflow = corruption.
                                //
                                // AUDIT (2026-07-01): the previous error arm zeroed the supply
                                // (`Amount::from_atomic(0)`) and continued. That defeated the whole
                                // point of the checked_sub: the "checked" branch, when it fires,
                                // was doing saturating-to-zero with an extra log line. If
                                // `total_supply < emission_of_block_being_rolled_back`, the
                                // in-memory state is proven corrupt (we're rolling back more
                                // coinbase than we ever minted). Continuing from a zeroed supply
                                // is worse than halting: every downstream check against the supply
                                // cap becomes wrong, and any RPC reader gets a fabricated answer.
                                //
                                // Prior art:
                                //   (Specific upstream identifiers UNVERIFIED this session.)
                                //   The prior comment cited Bitcoin Core asserts
                                //   `nBitsCurrent > 0` / `nMoneySupply >= 0`, a Monero
                                //   `verification_context.h` defensive panic, and
                                //   zebrad `expect("chain state invariant")`. None of
                                //   those exact identifiers were re-confirmed against
                                //   current upstream this session, so the specific
                                //   citations are removed. The "silent corruption is a
                                //   stop condition, not a warning" principle stands on
                                //   its own reasoning above.
                                //
                                // Halting via panic is safe here because the SIGTERM/SIGINT
                                // handlers on this node flush RocksDB cleanly on shutdown
                                // (the tokio signal handler installed for the 2026-06 zombie-
                                // state fix). See operator rule `no self-defeating gates`.
                                inner.stats.total_supply = inner
                                    .stats
                                    .total_supply
                                    .checked_sub(emission.as_atomic() as u128)
                                    .unwrap_or_else(|| {
                                        panic!(
        "CONSENSUS CORRUPTION: supply underflow on reorg rollback — \
         tried to subtract emission={} from total_supply={} at height being disconnected. \
         In-memory supply state is unrecoverable; halting to preserve on-disk state \
         (SIGTERM handler will flush RocksDB cleanly). Restart the node — the persisted \
         chain will re-derive supply correctly. If this recurs on restart, the on-disk \
         chain state is corrupt and requires a reindex.",
        emission, inner.stats.total_supply
    )
                                    });
                            }
                        }

                        // Remove fork block height mappings above fork point
                        for h in (fork_point + 1..=inner.tip.height.max(pre_reorg_tip.height)).rev()
                        {
                            inner.height_to_hash.remove(&h);
                        }

                        // Re-apply disconnected main-chain blocks in forward order
                        // (disconnected_tx_lists is in reverse height order, so reverse it)
                        for (h, oh) in disconnected_heights.iter().rev() {
                            inner.height_to_hash.insert(*h, *oh);
                            if let Some(orphan_block) = inner.blocks.get(oh) {
                                // Phase 2 store reorg checkpoint (site 6a:
                                // failed-reorg rollback path A — re-applying
                                // the original main-chain blocks. Checkpoint
                                // before re-applying each block's state so
                                // the stores end consistent with the
                                // restored pre-reorg chain). Inert while
                                // stores are None.
                                self.checkpoint_phase2_stores(*h);
                                let batch =
                                    UtxoSet::batch_from_block(*h, &orphan_block.transactions);
                                inner.utxos.apply_batch(batch);
                            }
                        }

                        // Restore tip and stats
                        inner.tip = pre_reorg_tip.clone();
                        inner.stats = pre_reorg_stats.clone();

                        // Restore DB height mappings and remove stale fork entries
                        if let Some(ref db) = self.db {
                            // Remove stale height entries above pre-reorg tip
                            for h in (pre_reorg_tip.height + 1)
                                ..=(inner.tip.height.max(pre_reorg_tip.height) + 1)
                            {
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
                                let expected_target =
                                    calculate_difficulty(&diff_blocks, block.header.height);
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
                            let disconnect =
                                UtxoSet::batch_disconnect_block(&fork_block.transactions);
                            inner.utxos.apply_batch(disconnect);
                            // Phase 2 store rewind (site 5b: failed-reorg
                            // rollback path B — triggering-block validation
                            // failed after the full fork was connected, so
                            // every fork block was checkpointed at site 4
                            // and every one is rewound here, unguarded).
                            // Inert while stores are None.
                            self.rewind_phase2_stores(fork_block.header.height);
                            let emission = calculate_block_reward(fork_block.header.height);
                            // C-4/H-11 FIX: checked_sub instead of saturating_sub — underflow = corruption.
                            //
                            // AUDIT (2026-07-02): fourth (and final located) site of
                            // the self-defeating supply-underflow gate. Missed by the
                            // 2026-07-01 `replace_all` pass because the surrounding
                            // whitespace indentation was 28 spaces here vs the 32
                            // spaces at the sites that DID get fixed then (~L2002 /
                            // ~L2228). Doc-vs-code drift audit picked this up on the
                            // second pass. Same rationale + prior art as the fixed
                            // sites' audit blocks.
                            inner.stats.total_supply = inner
                                .stats
                                .total_supply
                                .checked_sub(emission.as_atomic() as u128)
                                .unwrap_or_else(|| {
                                    panic!(
        "CONSENSUS CORRUPTION: supply underflow on reorg rollback — \
         tried to subtract emission={} from total_supply={} at fork block being disconnected. \
         In-memory supply state is unrecoverable; halting to preserve on-disk state \
         (SIGTERM handler will flush RocksDB cleanly). Restart the node — the persisted \
         chain will re-derive supply correctly. If this recurs on restart, the on-disk \
         chain state is corrupt and requires a reindex.",
        emission, inner.stats.total_supply
    )
                                });
                        }

                        // Remove fork block height mappings
                        for h in
                            (fork_point + 1..=pre_reorg_tip.height.max(block.header.height)).rev()
                        {
                            inner.height_to_hash.remove(&h);
                        }

                        // Re-apply disconnected main-chain blocks
                        for (h, oh) in disconnected_heights.iter().rev() {
                            inner.height_to_hash.insert(*h, *oh);
                            if let Some(orphan_block) = inner.blocks.get(oh) {
                                // Phase 2 store reorg checkpoint (site 6b:
                                // failed-reorg rollback path B — re-applying
                                // the original main-chain blocks, same as
                                // site 6a but for the triggering-block-failed
                                // rollback path). Inert while stores are None.
                                self.checkpoint_phase2_stores(*h);
                                let batch =
                                    UtxoSet::batch_from_block(*h, &orphan_block.transactions);
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
                        let tip_batch =
                            UtxoSet::batch_from_block(block.header.height, &block.transactions);
                        inner.utxos.apply_batch(tip_batch);

                        // Add triggering block's emission to supply.
                        //
                        // AUDIT (2026-07-02): third and final site of the
                        // supply-add symmetry fix. Wave 3 (commit 27ba4385)
                        // claimed to switch all three connect-path
                        // `saturating_add` sites to `checked_add + panic`,
                        // but that pass only reached 2 of 3 (the sites at
                        // ~L1644 and ~L2188). This third one — the
                        // triggering-block emission add applied after a
                        // successful reorg — was missed by the same
                        // replace_all-vs-indentation drift that also missed
                        // 2 SEV-A subtract sites on this file. Both categories
                        // are now uniform. Grep-verified: 0 remaining
                        // `total_supply.saturating_add` in this file.
                        let tip_emission = calculate_block_reward(block.header.height);
                        inner.stats.total_supply = inner
                            .stats
                            .total_supply
                            .checked_add(tip_emission.as_atomic() as u128)
                            .unwrap_or_else(|| {
                                panic!(
                                    "CONSENSUS CORRUPTION: supply overflow on reorg tip apply — \
                                 tried to add tip_emission={} to total_supply={}. Emission is \
                                 deterministic from height and cannot be attacker-controlled; \
                                 this indicates a bug in calculate_block_reward or on-disk \
                                 corruption. Halting for RocksDB flush + operator triage.",
                                    tip_emission, inner.stats.total_supply
                                )
                            });

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

                        // Fix stats drift: account for disconnected vs reconnected blocks.
                        //
                        // T1F1 (2026-07-05 audit, TIER 1 chain.rs pass):
                        // Pre-audit these two accounting math lines used
                        // `saturating_sub` + `saturating_add`. Same silent-clamp
                        // anti-pattern the sibling H-11 audit note above
                        // (~L2400 / L2183 for `total_supply`) explicitly PANICS on
                        // when it fires — because a supply-underflow proves the
                        // state was already corrupt, so clamping to 0 and
                        // continuing gives every downstream query a fabricated
                        // answer.
                        //
                        // For `total_blocks` / `total_transactions` the same
                        // invariant argument holds (`disconnected_blocks` can only
                        // exceed `stats.total_blocks` if the state was already
                        // corrupt from a prior reorg pass), but these fields are
                        // stats-only (surfaced via `chain.stats()` for the RPC
                        // `get_info` "total_blocks" / "total_transactions"
                        // fields), not consensus-load-bearing. So we don't PANIC
                        // — a corrupted counter should not halt block processing
                        // — but we surface the corruption via a CRITICAL log
                        // line so the operator sees it, and we saturate as the
                        // fallback (the RPC field being wrong is better than the
                        // node crashing).
                        //
                        // Prior art (specific per-project identifiers
                        // partially UNVERIFIED this session):
                        //   * Bitcoin Core: DisconnectBlock lives at
                        //     validation.cpp:2185 in the master read this
                        //     session as `Chainstate::DisconnectBlock`
                        //     (NOT `main.cpp::DisconnectBlock` — main.cpp
                        //     was refactored out long ago). The prior
                        //     comment additionally invoked an
                        //     `assert(nBlockTx > 0)` claim which is not
                        //     asserted here without a specific line
                        //     receipt.
                        //   * Monero `blockchain.cpp::rollback` behaviour
                        //     and zebrad `state::write::block::finalize`
                        //     specifics were not re-fetched this session;
                        //     the "stats-only counters saturate rather
                        //     than halt" pattern below is retained on its
                        //     own reasoning.
                        let reconnected_blocks = fork_blocks.len() as u64 + 1; // +1 for triggering block
                        let reconnected_txs: u64 = fork_blocks
                            .iter()
                            .map(|b| b.transactions.len() as u64)
                            .sum::<u64>()
                            + block.transactions.len() as u64;
                        inner.stats.total_blocks =
                            match inner.stats.total_blocks.checked_sub(disconnected_blocks) {
                                Some(v) => v.saturating_add(reconnected_blocks),
                                None => {
                                    tracing::error!(
                                        target: "chain::stats_invariant",
                                        "STATS INVARIANT VIOLATION: disconnected_blocks={} > \
                                         stats.total_blocks={} on reorg accounting. This means \
                                         the counter was already corrupt (a prior reorg silently \
                                         saturated). Recomputing floor as reconnected_blocks={} \
                                         so this reorg's addition is preserved. RPC \
                                         `get_info` `total_blocks` will be wrong until a full \
                                         rebuild. See T1F1 audit note in chain.rs for detail.",
                                        disconnected_blocks,
                                        inner.stats.total_blocks,
                                        reconnected_blocks,
                                    );
                                    reconnected_blocks
                                }
                            };
                        inner.stats.total_transactions =
                            match inner.stats.total_transactions.checked_sub(disconnected_txs) {
                                Some(v) => v.saturating_add(reconnected_txs),
                                None => {
                                    tracing::error!(
                                        target: "chain::stats_invariant",
                                        "STATS INVARIANT VIOLATION: disconnected_txs={} > \
                                         stats.total_transactions={} on reorg accounting. Same \
                                         pattern as T1F1. Recomputing floor.",
                                        disconnected_txs,
                                        inner.stats.total_transactions,
                                    );
                                    reconnected_txs
                                }
                            };

                        inner.height_to_hash.insert(block.header.height, hash);

                        // Persist triggering block's height→hash to DB and
                        // clean up stale height entries above new tip.
                        if let Some(ref db) = self.db {
                            if let Err(e) = db.blocks.set_height_hash(block.header.height, &hash) {
                                tracing::error!(
                                    "Failed to persist reorg tip height mapping: {}",
                                    e
                                );
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
                //
                // R-34 fix (2026-07-03): re-acquire the chain write lock
                // for the diff-collect + apply_reorg_atomic window. Prior
                // code released the write guard at the closing `}` of the
                // earlier scope (~L2501) and ran apply_reorg_atomic without
                // any lock; a concurrent apply_block from another ingester
                // path could race the "already-present" pre-read that
                // apply_reorg_atomic does at db/mod.rs:411 to implement
                // oldest-wins on output_index. Holding the write lock here
                // structurally serialises reorg-commit against every other
                // chain mutator.
                //
                // The guard is bound inside an INNER SCOPE so it drops
                // before the post-commit `inner_stats_for_log(&self.inner)`
                // call below (which takes a read lock — a still-held
                // write guard would deadlock it under parking_lot's
                // non-re-entrant RwLock).
                {
                    let _reorg_commit_guard = self.inner.write();
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

                        let collect_block_outputs =
                            |b: &crate::consensus::Block,
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
                            collect_block_outputs(
                                fork_block,
                                &mut oi_additions,
                                &mut height_sets,
                                &mut ti_adds,
                            );
                        }
                        collect_block_outputs(
                            &block,
                            &mut oi_additions,
                            &mut height_sets,
                            &mut ti_adds,
                        );

                        // 3. Compute stale heights to remove (above new tip)
                        let new_tip_height = block.header.height;
                        let height_removals: Vec<u64> =
                            (new_tip_height + 1..=new_tip_height + 100).collect(); // Clean up to 100 stale entries

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
                            total_supply: self.stats().total_supply,
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
                            oi_removals.len(),
                            oi_additions.len(),
                            height_sets.len()
                        );
                    } else {
                        // No DB — in-memory only mode (tests). Still do the non-atomic path.
                        for txs in &disconnected_tx_lists {
                            self.remove_output_index(txs);
                        }
                        for fork_block in &fork_blocks {
                            self.persist_output_index(
                                &fork_block.transactions,
                                fork_block.header.height,
                            );
                        }
                        self.persist_output_index(&block.transactions, block.header.height);
                    }
                } // R-34: close the write-guard scope so
                  // inner_stats_for_log below can take a read lock.

                // Structured divergence detection log — reorg completed
                let stats_snapshot = inner_stats_for_log(&self.inner);
                tracing::warn!(
                    target: "chain::commit",
                    height = block.header.height,
                    block_hash = %hash.to_hex(),
                    reorg_depth = block.header.height.saturating_sub(fork_point),
                    total_difficulty = stats_snapshot.0,
                    tip = %hash.to_hex(),
                    supply_atomic = %stats_snapshot.1,
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

                self.record_event(
                    ChainEventType::Reorg,
                    block.header.height,
                    &hash,
                    serde_json::json!({
                        "reorg_depth": reorg_depth,
                        "fork_point": fork_point,
                    }),
                );

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
                self.record_event(
                    ChainEventType::ForkDetected,
                    block.header.height,
                    &hash,
                    serde_json::json!({
                        "fork_difficulty": fork_cumulative,
                    }),
                );
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
        // SECURITY: ring decoy selection uses OsRng and the canonical V1
        // policy in storage::UtxoSet::select_decoys.
        let mut rng = rand::rngs::OsRng;
        inner
            .utxos
            .select_decoys(current_height, min_age, count, &mut rng)
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
        let peer_target = self
            .peer_target_height
            .load(std::sync::atomic::Ordering::Relaxed);
        if peer_target > 0 {
            peer_target
        } else {
            self.height()
        }
    }

    /// Raw peer-advertised target height (0 = no peer height info yet).
    ///
    /// Unlike [`Chain::target_height`], this does NOT fall back to the local
    /// height when no peer info is available. Callers detecting fork
    /// divergence must distinguish "no peer height reported yet" (0) from
    /// "peers agree we're at the tip". Used by the miner's fork-divergence
    /// gate (2026-07-08 runaway-fork incident): a local tip running far
    /// ahead of every peer's advertised height means our blocks aren't
    /// being adopted — we're mining a worthless private fork.
    pub fn peer_advertised_height(&self) -> u64 {
        self.peer_target_height
            .load(std::sync::atomic::Ordering::Relaxed)
    }

    /// Update sync info from P2P layer
    pub fn set_sync_info(&self, synced: bool, target_height: u64) {
        self.synced
            .store(synced, std::sync::atomic::Ordering::Relaxed);
        self.peer_target_height
            .store(target_height, std::sync::atomic::Ordering::Relaxed);
    }

    /// Firework Phase 2 (I6): update the "a heavier chain exists" veto (see
    /// the `work_behind` field). Called by the P2P layer whenever peer work
    /// claims or our own cumulative work change, so `is_synced()` reflects
    /// cumulative work and not just block height.
    pub fn set_work_behind(&self, behind: bool) {
        self.work_behind
            .store(behind, std::sync::atomic::Ordering::Relaxed);
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
        let last = self
            .last_block_received_at
            .load(std::sync::atomic::Ordering::Relaxed);
        if last == 0 {
            return None;
        }
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
    ///
    /// SECURITY: bounded by `block.header.height + 1` (max walk = genesis →
    /// block, plus the starting block itself). A corrupt DB with a cycle
    /// in `prev_hash` would otherwise loop forever consuming CPU. Matching
    /// the visited-set pattern in `find_fork_point` (lines 2533+) would
    /// also catch cycles but costs an allocation; the height-derived cap
    /// is allocation-free and serves the same purpose because the walk
    /// can only legitimately visit at most `block.height` distinct heights.
    fn calculate_fork_cumulative_work(&self, block: &Block) -> u128 {
        let mut total_work = calculate_difficulty_from_target(&block.header.target);
        let mut current_hash = block.header.prev_hash;
        // +1 covers the starting block; +100 absorbs height-key off-by-one
        // edge cases and is still vanishingly cheap if exercised.
        let max_steps = block.header.height.saturating_add(100);
        let mut steps: u64 = 0;

        loop {
            steps = steps.saturating_add(1);
            if steps > max_steps {
                tracing::error!(
                    "calculate_fork_cumulative_work walked {} steps from block height {} \
                     without reaching genesis — possible prev_hash cycle in DB. Returning \
                     partial work; caller's IronConsensus classifier will reject the fork.",
                    steps,
                    block.header.height
                );
                break;
            }
            if let Some(parent) = self.get_block(&current_hash) {
                // Genesis contributes the fixed base `1`, NOT its
                // `dft(genesis_target)`. This matches the extend path, which
                // starts from `total_difficulty = 1` at construction
                // (chain.rs genesis init) and does `+= dft(block)` for each
                // block height ≥ 1. Adding `dft(genesis)` here instead made
                // this from-scratch fork walk exceed the incrementally
                // accumulated `current total_difficulty` by
                // `dft(genesis) - 1`, so an EQUAL-work fork looked heavier and
                // triggered a spurious reorg — and every reorg then latched
                // the higher base into the stored value, producing the
                // fleet-wide `total_difficulty` divergence (nodes on the
                // identical tip disagreeing on cumulative work) that
                // false-positived the `work_behind` veto and locked follower
                // miners out. See recompute_total_difficulty for the canonical
                // definition this must agree with.
                if parent.header.height == 0 {
                    total_work = total_work.saturating_add(1);
                    break; // Reached genesis
                }
                let prev_work = total_work;
                total_work = total_work
                    .saturating_add(calculate_difficulty_from_target(&parent.header.target));
                // SECURITY (H-7): Detect u128 saturation during deep reorgs.
                // saturating_add silently caps at u128::MAX, which could cause
                // incorrect chain selection if both forks saturate.
                if total_work == u128::MAX && prev_work != u128::MAX {
                    tracing::warn!(
                        "Cumulative work saturated at u128::MAX during fork calculation at height {}",
                        parent.header.height
                    );
                }
                current_hash = parent.header.prev_hash;
            } else {
                break; // Parent not found
            }
        }

        total_work
    }

    /// Deterministically recompute cumulative chain work for the active chain
    /// `[0, height]` as `1 + Σ dft(block_h.target)` for `h in 1..=height`.
    ///
    /// This is the SINGLE canonical definition of `total_difficulty`, and it
    /// agrees by construction with:
    ///   - the extend path (`total_difficulty += dft(block)` from a genesis
    ///     base of `1`), and
    ///   - the reorg path (`calculate_fork_cumulative_work`, which now also
    ///     uses the genesis base `1`).
    ///
    /// Called once on load (`load_from_database`) so that a node whose stored
    /// value drifted — via the pre-fix reorg path that used a `dft(genesis)`
    /// base, or a partial fork walk — SELF-HEALS to the deterministic value on
    /// restart. Because `total_difficulty` is advertised to peers in
    /// `ChainWorkMessage` (feeding the `work_behind` heavier-chain veto),
    /// converging every node's value is what stops the veto from
    /// false-positiving followers whose only "sin" was computing the same
    /// tip's work correctly.
    ///
    /// Returns `None` if any block in `[1, height]` is missing from storage
    /// (caller keeps the existing value rather than storing a wrong partial).
    ///
    /// Cost: O(height) DB reads, once per process start. Fine at testnet
    /// scale (~12k blocks, sub-second). A mainnet-scale chain would want a
    /// periodically-checkpointed cumulative value instead of a full walk.
    fn recompute_total_difficulty(&self, height: u64) -> Option<u128> {
        let mut total: u128 = 1; // genesis base (matches genesis init + fork walk)
        for h in 1..=height {
            let block = self.get_block_by_height(h)?;
            total = total.saturating_add(calculate_difficulty_from_target(&block.header.target));
        }
        Some(total)
    }

    /// Find the common ancestor (fork point) between the current main chain
    /// and a fork block.
    ///
    /// Returns `Some(height)` for a real common ancestor (including the
    /// legitimate "fork point is genesis" case → `Some(0)`).
    ///
    /// Returns `None` when DB corruption is detected:
    /// - Cycle in `prev_hash` chain (the walk would loop forever
    ///   without the visited-set guard).
    /// - A `prev_hash` references a block that isn't in storage.
    ///
    /// The caller (chain reorganization in [`Self::add_block`]) MUST
    /// treat `None` as a corruption-class rejection — not as "fork
    /// point is genesis". Previously this function returned `0` for
    /// both genesis and corruption, which masked corruption as a
    /// legitimate deep-reorg attempt: `evaluate_reorg_acceptability`
    /// then rejected it as "ReorgTooDeep" with a misleading
    /// diagnostic. Audit-prep fix 2026-05-23.
    fn find_fork_point(&self, fork_block: &Block) -> Option<u64> {
        let mut current_hash = fork_block.header.prev_hash;
        let mut visited = std::collections::HashSet::new();

        loop {
            if !visited.insert(current_hash) {
                tracing::error!(
                    "DB corruption: cycle detected during fork-point search; \
                     starting from fork_block height={} hash={}",
                    fork_block.header.height,
                    fork_block.hash().to_hex(),
                );
                return None;
            }
            if let Some(parent) = self.get_block(&current_hash) {
                let height = parent.header.height;
                if let Some(main_hash) = self.get_block_hash(height) {
                    if main_hash == current_hash {
                        return Some(height);
                    }
                }
                if height == 0 {
                    return Some(0);
                }
                current_hash = parent.header.prev_hash;
            } else {
                tracing::error!(
                    "DB corruption: prev_hash {} not in storage during fork-point search; \
                     fork_block height={}",
                    current_hash.to_hex(),
                    fork_block.header.height,
                );
                return None;
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
                tracing::error!(
                    "Cycle detected in fork chain at hash {}",
                    current_hash.to_hex()
                );
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
    fn begin_state_update(&self) -> StateUpdate<'_> {
        self.state_updates_in_progress
            .fetch_add(1, std::sync::atomic::Ordering::AcqRel);
        StateUpdate { chain: self }
    }

    /// Return the current generation only while canonical chain state is stable.
    pub fn stable_generation(&self) -> Option<u64> {
        use std::sync::atomic::Ordering;

        if self.state_updates_in_progress.load(Ordering::Acquire) != 0 {
            return None;
        }
        let generation = self.state_generation.load(Ordering::Acquire);
        (self.state_updates_in_progress.load(Ordering::Acquire) == 0).then_some(generation)
    }

    /// Async wrapper around [`Blockchain::add_block`]. Runs full block
    /// validation + DB write on `tokio::task::spawn_blocking`.
    pub async fn add_block_async(self: Arc<Self>, block: Block) -> Result<BlockStatus> {
        tokio::task::spawn_blocking(move || self.add_block(block))
            .await
            .map_err(|e| {
                Error::Internal(format!("spawn_blocking join error in add_block: {}", e))
            })?
    }

    /// Async wrapper around [`Blockchain::process_block`]. Equivalent to
    /// `add_block_async` (process_block is a thin alias today).
    pub async fn process_block_async(self: Arc<Self>, block: Block) -> Result<BlockStatus> {
        tokio::task::spawn_blocking(move || self.process_block(block))
            .await
            .map_err(|e| {
                Error::Internal(format!("spawn_blocking join error in process_block: {}", e))
            })?
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
            .map_err(|e| {
                Error::Internal(format!(
                    "spawn_blocking join error in validate_transaction: {}",
                    e
                ))
            })?
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

#[cfg(test)]
mod generation_tests {
    use super::Blockchain;

    #[test]
    fn generation_is_unavailable_until_all_updates_finish() {
        let chain = Blockchain::new();
        let initial = chain.stable_generation().expect("new chain is stable");
        let first = chain.begin_state_update();
        let second = chain.begin_state_update();

        assert_eq!(chain.stable_generation(), None);
        drop(first);
        assert_eq!(chain.stable_generation(), None);
        drop(second);
        assert_eq!(chain.stable_generation(), Some(initial + 2));
    }

    #[test]
    fn database_load_path_advances_generation() {
        let chain = Blockchain::new();
        let initial = chain.stable_generation().expect("new chain is stable");

        chain
            .load_from_database_with_outcome()
            .expect("fresh in-memory chain loads");

        assert_eq!(chain.stable_generation(), Some(initial + 1));
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

    fn state_for_genesis(block: &Block) -> ChainStateData {
        ChainStateData {
            tip_hash: block.hash(),
            height: block.header.height,
            total_difficulty: 1,
            total_supply: u128::from(calculate_block_reward(block.header.height).as_atomic()),
            total_burned: 0,
            last_checkpoint: 0,
        }
    }

    #[test]
    fn total_supply_accumulator_is_u128_and_survives_the_old_u64_ceiling() {
        // Regression for the aggregate-supply overflow (junbyjun's finding):
        // the running supply total crossed u64::MAX (~1.84e19 atomic ≈ 18.4M
        // CYNC) at height ~407,828 and panicked the `checked_add` on block
        // connect. The accumulator is now u128, so the same addition is well
        // within range. Individual Amounts stay u64 — only this total widened.
        let mut stats = ChainStats::default();
        // Park it just below the old u64 ceiling…
        stats.total_supply = u64::MAX as u128 - 5;
        // …then apply the exact block reward junbyjun observed at height 407,838
        // (~40.77 CYNC). On a u64 accumulator this addition overflowed.
        let emission: u128 = 40_774_342_596_145;
        stats.total_supply = stats
            .total_supply
            .checked_add(emission)
            .expect("u128 accumulator must not overflow crossing the u64 ceiling");
        assert!(
            stats.total_supply > u64::MAX as u128,
            "crossed the u64 ceiling"
        );
        // Proof the pre-fix u64 path would have overflowed at exactly this point:
        assert!(
            (u64::MAX - 5).checked_add(emission as u64).is_none(),
            "the old u64 accumulator overflowed here — this is the bug"
        );
        assert_eq!(
            stats.total_supply.to_string(),
            "18446784848052147755",
            "the exact post-ceiling aggregate remains available to API layers"
        );
    }

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
    fn load_from_database_distinguishes_fresh_and_loaded_state() {
        let dir = tempfile::tempdir().unwrap();
        let db = Arc::new(Database::open(dir.path()).unwrap());
        let chain = Blockchain::with_database(Arc::clone(&db), NetworkType::Testnet);

        assert_eq!(
            chain.load_from_database_with_outcome().unwrap(),
            ChainLoadOutcome::Fresh
        );
        chain.init_genesis().unwrap();

        let reloaded = Blockchain::with_database(db, NetworkType::Testnet);
        assert_eq!(
            reloaded.load_from_database_with_outcome().unwrap(),
            ChainLoadOutcome::Loaded
        );
    }

    #[test]
    fn load_from_database_rejects_blocks_without_chain_state() {
        let dir = tempfile::tempdir().unwrap();
        let db = Arc::new(Database::open(dir.path()).unwrap());
        let genesis = crate::testnet::testnet_genesis();
        let genesis_hash = genesis.hash();
        db.blocks.insert(&genesis).unwrap();
        db.blocks.set_height_hash(0, &genesis_hash).unwrap();

        let chain = Blockchain::with_database(db, NetworkType::Testnet);
        let error = chain.load_from_database().unwrap_err().to_string();
        assert!(
            error.contains("without chain state"),
            "unexpected error: {}",
            error
        );
    }

    #[test]
    fn load_from_database_rejects_missing_tip_block() {
        let dir = tempfile::tempdir().unwrap();
        let db = Arc::new(Database::open(dir.path()).unwrap());
        let genesis = crate::testnet::testnet_genesis();
        let genesis_hash = genesis.hash();
        db.blocks.insert(&genesis).unwrap();
        db.blocks.set_height_hash(0, &genesis_hash).unwrap();

        let state = ChainStateData {
            tip_hash: Hash::from_bytes([0x42; 32]),
            height: 10,
            ..state_for_genesis(&genesis)
        };
        db.state.save_state(&state).unwrap();

        let chain = Blockchain::with_database(db, NetworkType::Testnet);
        let error = chain.load_from_database().unwrap_err().to_string();
        assert!(
            error.contains("missing tip block"),
            "unexpected error: {}",
            error
        );
    }

    #[test]
    fn load_from_database_rejects_wrong_network_genesis() {
        let dir = tempfile::tempdir().unwrap();
        let db = Arc::new(Database::open(dir.path()).unwrap());
        let genesis = crate::mainnet::mainnet_genesis();
        let genesis_hash = genesis.hash();
        db.blocks.insert(&genesis).unwrap();
        db.blocks.set_height_hash(0, &genesis_hash).unwrap();
        db.state.save_state(&state_for_genesis(&genesis)).unwrap();

        let chain = Blockchain::with_database(db, NetworkType::Testnet);
        let error = chain.load_from_database().unwrap_err().to_string();
        assert!(
            error.contains("does not match"),
            "unexpected error: {}",
            error
        );
    }

    #[test]
    fn total_difficulty_recompute_and_fork_walk_agree_on_genesis_base() {
        // Regression lock for the fleet-wide total_difficulty divergence bug.
        //
        // The extend path accumulates `total_difficulty` from a genesis base
        // of `1` (`+= dft(block)` per block). The reorg path recomputes via
        // `calculate_fork_cumulative_work`, which USED to add `dft(genesis)`
        // for the genesis block instead of the base `1` — so the two
        // definitions disagreed by `dft(genesis) - 1`. That made an EQUAL-work
        // fork look heavier (spurious reorgs) and, once latched into the
        // stored value, produced nodes on the identical tip disagreeing on
        // cumulative work — which false-positived the peer `work_behind` veto
        // and locked follower miners out. This test pins the two paths (and
        // the on-load recompute) to the SAME genesis base.
        let chain = Blockchain::new();
        chain.init_genesis().unwrap();
        let genesis = chain.get_block_by_height(0).expect("genesis present");
        let d = calculate_difficulty_from_target(&genesis.header.target);
        assert!(d > 0, "genesis target must yield positive work");

        // Append 3 child blocks, each reusing the genesis target so each
        // contributes exactly `d` to cumulative work.
        let mut prev = genesis.hash();
        let mut tip_block = genesis.clone();
        for h in 1..=3u64 {
            let mut b = genesis.clone();
            b.header.height = h;
            b.header.prev_hash = prev;
            b.header.nonce = 1000 + h; // distinct hashes
            let hash = b.hash();
            {
                let mut inner = chain.inner.write();
                inner.blocks.insert(hash, b.clone());
                inner.height_to_hash.insert(h, hash);
            }
            prev = hash;
            tip_block = b;
        }

        // Canonical definition: genesis base 1 + Σ dft(1..=3) = 1 + 3d.
        let recomputed = chain
            .recompute_total_difficulty(3)
            .expect("all blocks present");
        assert_eq!(
            recomputed,
            1 + 3 * d,
            "recompute must be 1 + Σ dft(1..=height)"
        );

        // The from-scratch fork walk MUST agree with the recompute. Before the
        // fix this differed by exactly `d - 1` (dft(genesis) vs base 1).
        let fork_cumulative = chain.calculate_fork_cumulative_work(&tip_block);
        assert_eq!(
            fork_cumulative, recomputed,
            "fork walk and recompute must share the genesis base 1"
        );

        // Genesis-only chain is the bare base.
        assert_eq!(chain.recompute_total_difficulty(0), Some(1));

        // A missing block yields None (caller keeps stored value, never a
        // wrong partial sum).
        assert_eq!(chain.recompute_total_difficulty(99), None);
    }

    #[test]
    fn test_reorg_acceptability_shallow_requires_more_work() {
        // Shallow reorgs still require strict cumulative-work superiority.
        let h = BOOTSTRAP_MESS_HEIGHT + 1; // post-bootstrap, full rules apply
        let max = max_reorg_depth_for(NetworkType::Testnet);
        assert!(evaluate_reorg_acceptability(3, 101, 100, h, max).is_ok());
        assert!(evaluate_reorg_acceptability(3, 100, 100, h, max).is_err());
    }

    #[test]
    fn test_reorg_acceptability_mess_multiplier() {
        // At depth 50, exponent = (50-10)/20 = 2 => required multiplier 4x.
        let h = BOOTSTRAP_MESS_HEIGHT + 1; // post-bootstrap
        let max = max_reorg_depth_for(NetworkType::Testnet);
        let err = evaluate_reorg_acceptability(50, 399, 100, h, max).unwrap_err();
        assert!(err.contains("requires 4x work"));
        assert!(evaluate_reorg_acceptability(50, 401, 100, h, max).is_ok());
    }

    #[test]
    fn test_reorg_acceptability_hard_depth_cap() {
        // F31: use the network-taking form so this test doesn't rely on the
        // deprecated compile-time free function. Verify both networks so the
        // caps are pinned by tests to their intended values.
        let testnet_max = max_reorg_depth_for(NetworkType::Testnet);
        let mainnet_max = max_reorg_depth_for(NetworkType::Mainnet);
        assert_eq!(testnet_max, 1000, "testnet hard-finality cap must be 1000");
        assert_eq!(mainnet_max, 100, "mainnet hard-finality cap must be 100");

        let err_testnet = evaluate_reorg_acceptability(
            testnet_max + 1,
            u128::MAX,
            1,
            BOOTSTRAP_MESS_HEIGHT + 1,
            testnet_max,
        )
        .unwrap_err();
        assert!(err_testnet.contains("exceeds absolute maximum"));
        assert!(
            err_testnet.contains("1000"),
            "testnet error must cite testnet cap"
        );

        let err_mainnet = evaluate_reorg_acceptability(
            mainnet_max + 1,
            u128::MAX,
            1,
            BOOTSTRAP_MESS_HEIGHT + 1,
            mainnet_max,
        )
        .unwrap_err();
        assert!(err_mainnet.contains("exceeds absolute maximum"));
        assert!(
            err_mainnet.contains("100"),
            "mainnet error must cite mainnet cap"
        );
    }

    #[test]
    fn test_reorg_acceptability_bootstrap_bypass() {
        // Below BOOTSTRAP_MESS_HEIGHT, Tier-2 MESS is skipped and only the
        // longest-chain rule applies even at deep reorg depths. This is the
        // launch convergence fix: a young fleet whose nodes diverge at low
        // heights must be able to converge once one chain pulls ahead.
        let bootstrap_h = BOOTSTRAP_MESS_HEIGHT / 2;
        let max = max_reorg_depth_for(NetworkType::Testnet);
        // Depth 50 with only slightly-more work: rejected post-bootstrap,
        // accepted during bootstrap.
        assert!(evaluate_reorg_acceptability(50, 101, 100, bootstrap_h, max).is_ok());
        // Equal work still loses (longest chain must strictly exceed).
        let err = evaluate_reorg_acceptability(50, 100, 100, bootstrap_h, max).unwrap_err();
        assert!(err.contains("bootstrap phase"));
        // Tier-3 hard cap still enforced during bootstrap.
        assert!(evaluate_reorg_acceptability(max + 1, u128::MAX, 1, bootstrap_h, max).is_err());
    }

    #[test]
    fn f31_blockchain_max_reorg_depth_uses_runtime_network() {
        // REGRESSION LOCK for F31 SEV-A. Pre-audit `max_reorg_depth()` was
        // a free function using `#[cfg(feature = "testnet")]` — compile-time.
        // A binary built without `--features testnet` would use max=100
        // (mainnet) EVEN WHEN CONFIGURED TO RUN ON TESTNET at runtime via
        // `--network testnet`. That misconfiguration exacerbated the
        // 2026-07-04 partition trap (628-block reorg needed the testnet
        // 1000-cap, hit the compile-time-mainnet 100-cap instead).
        //
        // Post-fix, `Blockchain::max_reorg_depth()` reads from the runtime
        // `self.network` field. Verify both network selections yield the
        // correct cap regardless of which feature flags were passed to the
        // build.
        let testnet_chain = Blockchain::new_with_network(NetworkType::Testnet);
        assert_eq!(
            testnet_chain.max_reorg_depth(),
            1000,
            "Blockchain configured for testnet at runtime MUST use the \
             1000-block hard-finality cap. Pre-F31 fix, a binary built \
             without --features testnet would return 100 here despite \
             the runtime network selection — that was the 2026-07-04 \
             partition-trap surface.",
        );
        let mainnet_chain = Blockchain::new_with_network(NetworkType::Mainnet);
        assert_eq!(
            mainnet_chain.max_reorg_depth(),
            100,
            "Blockchain configured for mainnet at runtime MUST use the \
             100-block hard-finality cap. Pre-F31, a binary built WITH \
             --features testnet would return 1000 here even when the \
             operator configured mainnet at runtime — the inverse bug.",
        );
    }

    /// Reorg-with-stores integration test for the Phase-2 privacy
    /// store wiring (CIP-009.D / post-launch campaign item #2).
    ///
    /// Exercises `checkpoint_phase2_stores` / `rewind_phase2_stores` —
    /// the uniform wiring primitive every one of the 8 connect /
    /// disconnect sites in `add_block` / `rollback_to_height` calls —
    /// with all three Phase-2 stores instantiated. Drives them through
    /// the exact checkpoint-then-append / rewind sequence the chain
    /// applies on a reorg, and asserts the three stores stay in
    /// lock-step: a rewind of N blocks restores all three to their
    /// shared state from N blocks earlier, byte-identical roots.
    ///
    /// Scope note: the 8 chain.rs call sites place these helpers
    /// correctly by construction — each is a single documented call,
    /// `cargo check` confirms they compile, and the connect/disconnect
    /// pairing is argued inline at each site. A full reorg-path test
    /// driving real `add_block` calls would need valid-PoW
    /// two-fork block-construction machinery the chain test module
    /// does not yet have; this test covers the helper contract and the
    /// cross-store lock-step property, and the site placement is
    /// review-verified.
    #[test]
    fn phase2_stores_rewind_together_through_helpers() {
        use crate::crypto::mw_cutthrough::MwKernel;
        use crate::storage::{
            KernelStore, NoteCommitmentEntry, ShieldedStore, SparkCoinEntry, SparkStore,
        };

        let mut chain = Blockchain::new();
        chain.shielded_store = Some(Arc::new(ShieldedStore::new()));
        chain.spark_store = Some(Arc::new(SparkStore::new()));
        chain.kernel_store = Some(Arc::new(KernelStore::new()));

        // Genesis (empty) roots — the state a full rewind must restore.
        let genesis_roots = (
            chain.shielded_root(),
            chain.spark_root(),
            chain.mw_kernel_root(),
        );

        // Apply one block's worth of Phase-2 state the way the chain
        // will once activation wires the appends: site-1 checkpoint
        // FIRST (Interp-B contract), THEN the block's appends.
        let apply_block = |chain: &Blockchain, height: u64, byte: u8| {
            chain.checkpoint_phase2_stores(height);
            chain
                .shielded_store
                .as_ref()
                .unwrap()
                .append_commitment(NoteCommitmentEntry {
                    commitment: [byte; 32],
                    height,
                    tx_index: 0,
                    position: 0,
                });
            chain
                .spark_store
                .as_ref()
                .unwrap()
                .add_coin(SparkCoinEntry {
                    coin_id: height,
                    commitment: [byte; 32],
                    height,
                });
            chain.kernel_store.as_ref().unwrap().append(MwKernel {
                excess: [byte; 32],
                signature: vec![0u8; 64],
                fee: 0,
                height,
            });
        };

        let roots = |chain: &Blockchain| {
            (
                chain.shielded_root(),
                chain.spark_root(),
                chain.mw_kernel_root(),
            )
        };

        apply_block(&chain, 1, 0xA1);
        let roots_after_1 = roots(&chain);
        assert_ne!(
            roots_after_1, genesis_roots,
            "block 1 must move all three store roots"
        );

        apply_block(&chain, 2, 0xB1);
        apply_block(&chain, 3, 0xC1);
        let roots_after_3 = roots(&chain);
        assert_ne!(roots_after_3, roots_after_1);

        // Reorg disconnects block 3, then block 2 — one
        // `rewind_phase2_stores` per disconnected block, reverse order,
        // exactly as the chain's reorg disconnect loop does.
        chain.rewind_phase2_stores(3);
        chain.rewind_phase2_stores(2);
        assert_eq!(
            roots(&chain),
            roots_after_1,
            "after rewinding blocks 3 and 2 all three stores must be \
             byte-identical to their shared state after block 1"
        );

        // Disconnect block 1 — back to genesis, all three together.
        chain.rewind_phase2_stores(1);
        assert_eq!(
            roots(&chain),
            genesis_roots,
            "full rewind restores all three stores to genesis roots"
        );

        // Re-applying an identical block 2 after the rewind reproduces
        // the post-block-1 → post-block-2 transition with no residue:
        // proves rewind left none of the disconnected state behind in
        // any of the three stores.
        apply_block(&chain, 1, 0xA1);
        assert_eq!(roots(&chain), roots_after_1, "re-apply of block 1 is clean");
        apply_block(&chain, 2, 0xB1);
        apply_block(&chain, 3, 0xC1);
        assert_eq!(
            roots(&chain),
            roots_after_3,
            "re-applied chain reproduces the original roots — rewind left no residue"
        );

        // `rewind_phase2_stores` past an empty checkpoint stack is a
        // safe no-op (it logs a per-store warning); it must not panic.
        chain.rewind_phase2_stores(3);
        chain.rewind_phase2_stores(2);
        chain.rewind_phase2_stores(1);
        chain.rewind_phase2_stores(0); // stacks already empty — no panic
        assert_eq!(roots(&chain), genesis_roots);
    }

    // ─── count_signaling_blocks_in_window — BIP-9 helper ───────────────────

    /// Empty range returns 0. Cheap smoke test ensuring the early-out path
    /// works and doesn't allocate a 0-capacity vector or otherwise misbehave
    /// on a degenerate window. Also asserts the `signal_count_fn` contract
    /// (matches ForkSignaler's `signal_count_fn: Fn(u64,u64,u32) -> u64`):
    /// the half-open `[start, start)` interval contains zero blocks.
    #[test]
    fn count_signaling_blocks_empty_window_returns_zero() {
        let chain = Blockchain::new();
        chain.init_genesis().unwrap();
        let count = chain.count_signaling_blocks_in_window(
            10,
            10,
            crate::consensus::fork_signal::bits::V1_0_12_BUNDLE,
        );
        assert_eq!(count, 0);
    }

    /// Range that extends beyond the tip returns 0 for every heights gap
    /// without panicking. Defensive — the BIP-9 state machine queries
    /// arbitrary windows including ones that haven't been mined yet, and
    /// must not crash the validator if asked about height ranges that
    /// don't exist yet on this chain.
    #[test]
    fn count_signaling_blocks_past_tip_returns_zero() {
        let chain = Blockchain::new();
        chain.init_genesis().unwrap();
        // Chain is at height 0 (genesis only). Query window 1000..2000 —
        // none of those blocks exist; method must return 0, not panic.
        let count = chain.count_signaling_blocks_in_window(
            1000,
            2000,
            crate::consensus::fork_signal::bits::V1_0_12_BUNDLE,
        );
        assert_eq!(count, 0);
    }

    /// Inverted range (end < start) saturates to 0 without iterating
    /// backwards or overflowing. The `saturating_sub` early-out at the
    /// top of the method handles this; this test pins that behavior so
    /// a future refactor that drops the guard fails fast.
    #[test]
    fn count_signaling_blocks_inverted_range_returns_zero() {
        let chain = Blockchain::new();
        chain.init_genesis().unwrap();
        let count = chain.count_signaling_blocks_in_window(
            2000,
            1000,
            crate::consensus::fork_signal::bits::V1_0_12_BUNDLE,
        );
        assert_eq!(count, 0);
    }

    /// Firework Phase 2 (I6): the work-behind veto overrides height-based
    /// synced. A node that is flagged synced (at/above peer height) must
    /// still report NOT synced while a heavier chain is known, and must
    /// recover once the veto is cleared (the anti-wedge machinery clears it
    /// when an unsubstantiated claim is dropped).
    #[test]
    fn work_behind_veto_overrides_height_synced() {
        let chain = Blockchain::new();
        chain.init_genesis().unwrap();
        chain.set_sync_info(true, 0); // height-synced
        assert!(chain.is_synced(), "baseline: height-synced reports synced");
        chain.set_work_behind(true); // a heavier chain is discovered
        assert!(
            !chain.is_synced(),
            "work-behind must veto synced even though the height flag is true"
        );
        chain.set_work_behind(false); // anti-wedge clears the claim
        assert!(chain.is_synced(), "clearing the veto restores synced");
    }

    /// Genesis block coinbase has 8-byte extra (height only); it must
    /// NOT signal any CIP bit. Asserts the "legacy coinbase = no signal"
    /// invariant through the chain method (rather than only at the
    /// `decode_signal_bits` unit-test level).
    #[test]
    fn count_signaling_blocks_genesis_signals_nothing() {
        let chain = Blockchain::new();
        chain.init_genesis().unwrap();
        // Window covers exactly genesis (height 0..1). Genesis coinbase
        // has 8-byte extra → no CIP bits set.
        for bit in [
            crate::consensus::fork_signal::bits::V1_0_12_BUNDLE,
            crate::consensus::fork_signal::bits::VIEW_TAGS,
            crate::consensus::fork_signal::bits::RING_SIZE_16,
            crate::consensus::fork_signal::bits::FEE_MARKET_V2,
        ] {
            let count = chain.count_signaling_blocks_in_window(0, 1, bit);
            assert_eq!(
                count, 0,
                "genesis coinbase unexpectedly signaled bit 0x{:08x}",
                bit
            );
        }
    }
}
