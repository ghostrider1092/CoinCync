//! # Blockchain State Machine
//!
//! Core blockchain state management.
//!
//! ## Audit map
//! This file is the audit-critical (non-consensus) state machine: block connect,
//! fork choice, reorg execution, rollback, load/rebuild, genesis. Each `§` below
//! names the code element(s), the INVARIANT it guarantees, the THREAT/incident it
//! defends, and the real TESTS that prove it (or the KNOWN gap). `§N` tags on the
//! banner comments below point back here. (Renders in `cargo doc`.)
//!
//! - **§1 `add_block` extend path** (`commit_block_atomic` call, supply/burn
//!   `checked_add`) — INVARIANT: on the extend branch the four consensus trees
//!   (output_index, height_index, state, tx_index) move together via
//!   `Database::commit_block_atomic`; in-memory tip never lands ahead of a failed
//!   disk commit (commit failure PANICS rather than diverging). Supply/burn use
//!   `checked_add` + panic (symmetry with the reorg-rollback `checked_sub`).
//!   THREAT: torn write leaving height index ahead of state → post-crash
//!   double-spend / inflation. TESTS: `total_supply_is_conserved_per_block`,
//!   `total_supply_accumulator_is_u128_and_survives_the_old_u64_ceiling`,
//!   `add_block_duplicate_in_memory_cache_returns_already_known`,
//!   `add_block_duplicate_in_db_not_cache_returns_already_known`,
//!   `commit_block_atomic_writes_all_four_trees_together` (DB-unit).
//! - **§2 RACE-R7 tip-moved recheck** (`inner.tip.hash != tip_hash` on the extend
//!   path) — INVARIANT: if the tip advanced between the read and the apply, the
//!   extend is abandoned and the block falls through to the fork path, never
//!   double-applied to a stale tip. THREAT: concurrent-writer TOCTOU that applies
//!   the same block twice / onto the wrong parent. TESTS: (gap — no test drives a
//!   concurrent tip move through the RACE-R7 branch).
//! - **§3 Fork choice** (`calculate_fork_cumulative_work`, hash-lex tiebreak) —
//!   INVARIANT: genesis contributes a fixed base of 1 (not `dft(genesis)`) so an
//!   equal-work fork is never spuriously heavier; strictly-greater work switches,
//!   exactly-equal work breaks deterministically by lexicographic tip hash
//!   (`fork_tip < current_tip` wins) — network-deterministic, no timestamp
//!   tiebreak. THREAT: selfish-miner / equivocation split from a nondeterministic
//!   or timestamp-gameable tiebreak. TESTS:
//!   `total_difficulty_recompute_and_fork_walk_agree_on_genesis_base`,
//!   `calculate_fork_cumulative_work_parent_not_found_returns_partial`,
//!   `calculate_fork_cumulative_work_cycle_breaks_at_max_steps`,
//!   `two_node_partition_heals_to_heavier_chain`,
//!   `equivocating_miner_does_not_split_honest_nodes` (direct add_block tiebreak
//!   assertion is a gap).
//! - **§4 Fork walk helpers** (`find_fork_point`, `collect_fork_chain`,
//!   `recompute_total_difficulty`) — INVARIANT: fork walks bound their steps and
//!   return `None`/partial on a cycle or missing parent (never loop forever);
//!   `recompute_total_difficulty` = `1 + Σ dft(1..=h)` and agrees with the fork
//!   walk. THREAT: crafted prev_hash cycle → hang / corruption-driven acceptance.
//!   TESTS: `find_fork_point_returns_common_ancestor_and_genesis`,
//!   `find_fork_point_detects_cycle_returns_none`,
//!   `find_fork_point_missing_parent_returns_none`,
//!   `collect_fork_chain_returns_ascending_and_stops_at_fork_point`,
//!   `recompute_total_difficulty_missing_mid_range_returns_none`.
//! - **§5 Reorg execution + `apply_reorg_atomic`** (disconnect loop, re-apply
//!   loop, `Database::apply_reorg_atomic`) — INVARIANT: the whole switch (output
//!   removals/adds, height sets/removals, state, tx add/remove) commits atomically
//!   or not at all; losing-fork work never leaks into `total_difficulty`;
//!   orphaned non-coinbase txs are returned for mempool restore. THREAT: partial
//!   reorg commit → hybrid tip / inflation. TESTS:
//!   `total_difficulty_is_reorg_history_independent`,
//!   `reorg_does_not_drop_a_re_mined_output_index_entry` (DB-unit),
//!   `reorg_preserves_oldest_wins_for_non_removed_shared_address` (DB-unit).
//!   GAP (P0): an ACCEPTED reorg re-applying REAL non-coinbase txs is untested —
//!   only the *rejected* double-spend reorg is covered (§6).
//! - **§6 C1 fork-vs-active-UTXO validation + double-spend defense** (contextual
//!   validation flag; REORG-TIP-VALIDATE recheck) — INVARIANT: a fork sharing a
//!   real non-coinbase tx / double-spent key image with the active branch is
//!   rejected; tip unchanged, key image stays unspent, supply unchanged. THREAT:
//!   reorg-driven double-spend / inflation. TESTS:
//!   `reorg_tip_double_spend_is_rejected`,
//!   `ring_size_availability_is_reorg_history_invariant` (storage-level).
//! - **§7 H3 failed-reorg rollback (path A / path B)** (`reorg_error`,
//!   `rolled_back` gate) — INVARIANT: when a fork block fails mid-reorg, rollback
//!   restores pre-reorg tip/stats/UTXO/output_index exactly. H3 FIX: path-A
//!   removal is now bounded by the highest fork height so a failed reorg no longer
//!   leaves stale `height_to_hash` entries above the restored tip; path A and
//!   path B are mutually exclusive (`!rolled_back` fires path B only when path A
//!   did not, e.g. a triggering-block difficulty recheck failure). THREAT: stale
//!   height→hash mapping after a rejected reorg → later reads resolve a ghost
//!   block. TESTS: (gap — the path-A/path-B rollback and the H3 stale-height fix
//!   have no chain-level regression test).
//! - **§8 `rollback_to_height`** (finality floor, cache→DB disconnect fallback,
//!   orphaned-tx return) — INVARIANT: refuses to roll back below the persisted
//!   `last_checkpoint` (FINALITY VIOLATION → `Err`, no mutation); disconnects
//!   DB-only blocks past the ~200-block cache window via DB fallback; unwinds
//!   supply/burn through the same disconnect site as connect (symmetric);
//!   `target >= height` is a no-op. THREAT: deep rollback past finality; silent
//!   under-disconnect when the body is only on disk. TESTS:
//!   `rollback_to_height_rejects_target_below_last_checkpoint`,
//!   `rollback_to_height_disconnects_db_only_blocks_past_the_cache`,
//!   `rollback_to_height_unwinds_total_burned_through_the_real_disconnect_site`,
//!   `rollback_to_height_returns_non_coinbase_txs_as_orphaned`,
//!   `tier5_rollback_to_current_height_is_noop`,
//!   `tier5_rollback_beyond_genesis_handled`,
//!   `total_burned_apply_disconnect_is_symmetric_and_reorg_correct`.
//! - **§9 Reorg disconnect loop is CACHE-ONLY** (no DB fallback, unlike §8) —
//!   INVARIANT (intended): every orphaned block on the losing branch is
//!   disconnected. KNOWN RISK: the reorg disconnect loop reads bodies from the
//!   in-memory cache only; a reorg whose `fork_point` sits just inside the
//!   ~200-block cache edge could silently under-disconnect (supply / UTXO /
//!   phase-2 stores under-counted) where `rollback_to_height` would not. THREAT:
//!   latent inflation / stuck-spent key image near the cache boundary. TESTS:
//!   (gap — latent under-disconnect at the cache edge is untested; flagged risk).
//! - **§10 Supply/burn `checked_sub`/`checked_add` underflow panics + STATS
//!   INVARIANT floor** — INVARIANT: every supply/burn move uses checked
//!   arithmetic and PANICS (halts) on under/overflow rather than silently
//!   clamping — a clamp would mask corruption/inflation; `total_supply` is `u128`
//!   (survives the old `u64` ~18.4M-CYNC ceiling). L2: `total_burned` and the
//!   block/tx counters move in lockstep with `total_supply` (`checked_sub`
//!   None → logs `STATS INVARIANT VIOLATION` and floors, not panic, for the
//!   telemetry counters). THREAT: silent underflow → phantom supply / inflation
//!   (ring-size determinism, 1d27d3c8). TESTS:
//!   `total_supply_accumulator_is_u128_and_survives_the_old_u64_ceiling`,
//!   `total_burned_apply_disconnect_is_symmetric_and_reorg_correct`,
//!   `block_fee_burn_matches_validator_burn_split` (the four disconnect-side
//!   underflow-panic sites themselves are an untested gap).
//! - **§11 `load_from_database` / `rebuild_utxo_set`** — INVARIANT: a load either
//!   yields a fully-consistent chain or errors — never a half-state mistaken for
//!   fresh; genesis/tip/height/network are cross-checked and the UTXO set +
//!   block/tx counters are reconstructed (not reset to 0) on reopen. THREAT: a
//!   drifted/partial DB booted as canonical → fork from the network. TESTS:
//!   `load_from_database_distinguishes_fresh_and_loaded_state`,
//!   `load_from_database_rejects_blocks_without_chain_state`,
//!   `load_from_database_rejects_missing_tip_block`,
//!   `load_from_database_rejects_wrong_network_genesis`,
//!   `load_from_database_rejects_missing_genesis_height_entry`,
//!   `load_from_database_rejects_state_height_mismatch_with_tip_block`,
//!   `db_reopen_reconstructs_identical_state` (rebuild L8 counter reconstruction
//!   is a gap).
//! - **§12 `init_genesis` / `verify_tip_integrity`** — INVARIANT: genesis hash
//!   must equal the expected network genesis (mismatch → `Err`); on init supply =
//!   `reward(0)`, burned = 0, and genesis+height+state are persisted;
//!   `verify_tip_integrity` reloads from DB when the in-memory tip disagrees with
//!   `state.tip_hash`. THREAT: wrong-network / forged genesis silently adopted.
//!   TESTS: `test_genesis_block`, `tier5_genesis_supply_matches_emission`
//!   (verify_tip_integrity mismatch-reload branch is a gap).
//! - **§13 `is_spent` (fail-closed) + `max_reorg_depth`** — INVARIANT: `is_spent`
//!   returns the in-memory hit, then the DB fallback, and on a DB *error* returns
//!   `true` (fail-CLOSED) — a lookup failure must never let a key image be treated
//!   as spendable; `max_reorg_depth` uses the runtime network, not the compile
//!   feature. THREAT: DB error opening a double-spend window; feature/runtime
//!   network mismatch loosening the reorg cap. TESTS:
//!   `is_spent_no_db_false_and_in_memory_hit_true`, `is_spent_db_fallback_true`,
//!   `f31_blockchain_max_reorg_depth_uses_runtime_network` (the DB-error
//!   fail-closed→true branch is an untested gap).
//! - **§14 Phase-2 checkpoint/rewind** (`checkpoint_phase2_stores`,
//!   `rewind_phase2_stores`; shielded / spark / MW-kernel roots) — INVARIANT: the
//!   three phase-2 stores checkpoint and rewind together in lockstep with block
//!   connect/disconnect; a rewind past an empty checkpoint stack hits the loud
//!   error branch rather than silently desyncing. THREAT: phase-2 root divergence
//!   across a reorg → shielded/MW state inconsistent with the transparent chain.
//!   TESTS: `phase2_stores_rewind_together_through_helpers` (rewind-past-restart
//!   loud-error branch is a gap).

use parking_lot::RwLock;
use std::collections::HashMap;
use std::sync::Arc;

use crate::config::NetworkType;
use crate::consensus::{calculate_difficulty, max_target, Block, DifficultyBlock};
use crate::db::{ChainStateData, Database, OutputIndexEntry};
use crate::decoy::{
    DecoyDistributionSnapshot, OutputLocator, ResolvedDecoySnapshot, DECOY_LOCATOR_POLICY_VERSION,
};
use crate::emission::calculate_block_reward;
use crate::error::{Error, Result};
use crate::primitives::{Hash, KeyImage};
use crate::storage::UtxoSet;
use crate::transaction::Transaction;

// Auto-checkpoint cadence is the global `constants::CHECKPOINT_INTERVAL`
// (144 blocks, ~5h). The local shadow was removed (C-5 fix) to prevent drift
// and the permanent chain splits the old 5-block/~10-minute interval caused on
// longer partitions. See that constant.

// -- Reorg / finality POLICY -------------------------------------------------
// The pure reorg-acceptance policy -- the depth caps and the MESS
// work-multiplier decision -- now lives in `crate::consensus::finality`, its
// natural module home. It is re-exported here so `crate::chain::{...}` remains
// a valid import path for existing callers and tests; behavior and the public
// API are unchanged. Chain MUTATION (block connect/disconnect, UTXO/state
// application, reorg execution) stays in this file.
pub use crate::consensus::finality::{
    evaluate_reorg_acceptability, max_reorg_depth_for, BOOTSTRAP_MESS_HEIGHT,
    MESS_EXPONENT_DIVISOR, REORG_UNCONDITIONAL_DEPTH,
};
#[allow(deprecated)]
pub use crate::consensus::finality::max_reorg_depth;

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
    /// Cumulative burned fees, in atomic units.
    ///
    /// Telemetry counter (not a consensus value) maintained IN LOCKSTEP with
    /// `total_supply`: it moves by `block_fee_burn(block)` at exactly the sites
    /// where `total_supply` moves by the block's emission — `+=` on
    /// apply/extend, `-=` on disconnect/rollback — so it is reorg-symmetric and
    /// path-independent. `u128`, not `Amount` (`u64`), for headroom parity with
    /// `total_supply`. `circulating = total_supply - total_burned`.
    pub total_burned: u128,
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

/// Read-only query getters live in a child module (issue #108). As a descendant
/// of `chain`, it can read `Blockchain`'s private fields; nothing there takes
/// `apply_lock` or mutates, so lock scope is unchanged.
mod queries;

/// Fork-choice + difficulty-window calculation helpers (issue #108). Read-only
/// `&self` helpers, `pub(super)` so `add_block`/`load` (in this module) and the
/// tests can call them; none take `apply_lock`, so lock scope is unchanged.
mod fork_calc;

/// Database load / genesis init / recovery (issue #108). Construction-time only,
/// never on the live apply path; each takes its own `inner.write()` guard
/// verbatim and none takes `apply_lock`, so lock scope is unchanged.
mod recovery;

/// Chain-event ring-buffer methods (issue #108). record_event/get_events; no
/// apply_lock, so lock scope is unchanged.
mod events;

/// Blockchain state machine with interior mutability
pub struct Blockchain {
    /// Coarse serialization lock for the ENTIRE block-application operation
    /// (`add_block` / `rollback_to_height` / `restore_state`).
    ///
    /// This is NOT the data lock — `inner` still guards the structures. Its sole
    /// job is to make the whole read→decide→mutate→persist sequence atomic
    /// against OTHER writers: `add_block` is a series of separate `inner.write()`
    /// critical sections with reads, DB I/O, validation, and (on reorg) a
    /// lock-released `collect_fork_chain` in between; without this, two ingest
    /// paths (P2P `BlockReceived`, RPC `submit_block`, the internal miner) can
    /// interleave across those gaps (reorg-vs-extend, reorg-vs-reorg), corrupting
    /// the UTXO set / `total_supply` / `height_to_hash`. The `state_updates`
    /// counter below does NOT serialize — it only signals the mempool.
    ///
    /// LOCK ORDER: always acquire `apply_lock` BEFORE `inner`, never the reverse.
    /// REENTRANCY: `parking_lot::Mutex` is NOT reentrant. ONLY the public write
    /// entry points take it (`add_block`, `rollback_to_height`, `restore_state`).
    /// `process_block` delegates to `add_block` and MUST NOT take it; no internal
    /// helper may take it. Violating either invariant self-deadlocks.
    apply_lock: parking_lot::Mutex<()>,
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
            apply_lock: parking_lot::Mutex::new(()),
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
            apply_lock: parking_lot::Mutex::new(()),
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
        // `rewind()` returns false ONLY when the in-memory checkpoint stack is
        // empty (see the store impls). That has two very different meanings we
        // must NOT conflate:
        //   * the store is EMPTY (no Phase-2 data) — nothing to roll back. This
        //     is the normal case today: shielded/spark/MW are dormant, so every
        //     reorg used to spam a scary "state may be inconsistent" warning
        //     (once per store per disconnected block) for a completely benign
        //     no-op. Demote to debug.
        //   * the store is NON-EMPTY but the checkpoint stack is gone (e.g. a
        //     reorg reaching past a node restart — the stack is in-memory and
        //     not yet restart-durable). Then a disconnected block's Phase-2
        //     state is stranded above the new tip: a genuine inconsistency.
        //     Make it a loud, unmistakable error that names the blocker.
        //
        // The full fix (restart-durable rewind checkpoints for the three
        // Phase-2 stores) is a prerequisite for activating shielded/spark/MW —
        // tracked as the phase-2-reorg-rewind mainnet blocker. Until then the
        // stores stay dormant and this only ever hits the benign branch.
        let stores: [(&str, Option<bool>, usize); 3] = [
            (
                "shielded",
                self.shielded_store.as_ref().map(|s| s.rewind()),
                self.shielded_store.as_ref().map(|s| s.tree_size()).unwrap_or(0),
            ),
            (
                "spark",
                self.spark_store.as_ref().map(|s| s.rewind()),
                self.spark_store.as_ref().map(|s| s.size()).unwrap_or(0),
            ),
            (
                "kernel",
                self.kernel_store.as_ref().map(|s| s.rewind()),
                self.kernel_store.as_ref().map(|s| s.len()).unwrap_or(0),
            ),
        ];
        for (name, outcome, remaining) in stores {
            if outcome != Some(false) {
                continue;
            }
            if remaining == 0 {
                tracing::debug!(
                    "{}_store.rewind() at h={}: empty store, nothing to roll back",
                    name,
                    height
                );
            } else {
                tracing::error!(
                    "{}_store.rewind() FAILED at h={} with {} element(s) still \
                     held — a disconnected block's Phase-2 state cannot be rolled \
                     back and is now inconsistent with the reorged chain. \
                     shielded/spark/MW MUST NOT be activated until rewind \
                     checkpoints are restart-durable (phase-2-reorg-rewind).",
                    name,
                    height,
                    remaining
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

    // init_genesis / expected_genesis_hash / verify_tip_integrity /
    // load_from_database(_with_outcome) / rebuild_utxo_set moved to
    // chain::recovery (issue #108).

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

    // height / tip / utxo_count / get_tx_location / tip_hash /
    // available_output_count moved to `chain::queries` (issue #108).

    pub fn decoy_distribution_snapshot(&self) -> DecoyDistributionSnapshot {
        let inner = self.inner.read();
        DecoyDistributionSnapshot {
            snapshot_height: inner.tip.height,
            snapshot_hash: inner.tip.hash,
            policy_version: DECOY_LOCATOR_POLICY_VERSION,
            heights: inner.utxos.output_distribution(inner.tip.height),
        }
    }

    pub fn resolve_decoy_snapshot(
        &self,
        snapshot_height: u64,
        snapshot_hash: Hash,
        policy_version: u16,
        locators: &[OutputLocator],
    ) -> Result<ResolvedDecoySnapshot> {
        if policy_version != DECOY_LOCATOR_POLICY_VERSION {
            return Err(Error::InvalidParams(format!(
                "unsupported decoy locator policy version {policy_version}"
            )));
        }
        if locators.len() > 256 {
            return Err(Error::InvalidParams(
                "decoy locator request exceeds 256 outputs".into(),
            ));
        }

        let inner = self.inner.read();
        if snapshot_height > inner.tip.height {
            return Err(Error::InvalidState(format!(
                "decoy snapshot height {snapshot_height} is above canonical tip {}",
                inner.tip.height
            )));
        }
        let canonical_hash = inner
            .height_to_hash
            .get(&snapshot_height)
            .copied()
            .or_else(|| {
                self.db
                    .as_ref()
                    .and_then(|db| db.blocks.get_hash_by_height(snapshot_height).ok().flatten())
            })
            .ok_or_else(|| {
                Error::InvalidState(format!(
                    "canonical block hash unavailable at height {snapshot_height}"
                ))
            })?;
        if canonical_hash != snapshot_hash {
            return Err(Error::InvalidState(format!(
                "decoy snapshot hash mismatch at height {snapshot_height}"
            )));
        }

        Ok(ResolvedDecoySnapshot {
            snapshot_height,
            snapshot_hash,
            policy_version,
            outputs: inner.utxos.resolve_output_locators(locators)?,
        })
    }

    // validate_transaction / difficulty / next_difficulty / expected_next_target /
    // next_target / is_synced / stats / median_time_past_of_lineage / get_block /
    // get_block_hash / get_block_by_height / count_signaling_blocks_in_window moved
    // to chain::queries (issue #108).

    /// Restore state from database
    pub fn restore_state(&self, height: u64, tip_hash: Hash, total_difficulty: u128) -> Result<()> {
        // Coarse writer lock — serialize against add_block / rollback_to_height
        // (see `apply_lock` doc). No reentrancy: does not call an apply_lock taker.
        let _apply = self.apply_lock.lock();
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
        // Coarse writer lock — serialize this multi-section mutation against
        // add_block / restore_state (see `apply_lock` doc). Does not call back
        // into any apply_lock taker, so no reentrancy.
        let _apply = self.apply_lock.lock();
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
                let orphan_hash = inner.height_to_hash.get(&h).copied().or_else(|| {
                    self.db
                        .as_ref()
                        .and_then(|db| db.blocks.get_hash_by_height(h).ok().flatten())
                });
                if let Some(oh) = orphan_hash {
                    // Resolve the block body from the in-memory cache, falling back
                    // to the DB. Deep rollbacks (this function's whole purpose)
                    // routinely target heights below the ~200-block cache window; if
                    // the body is DB-only, the original cache-only lookup returned
                    // None and skipped ALL of the disconnect below (UTXO / supply /
                    // burn / total_difficulty / phase-2) while the tip still moved
                    // down — over-counting persisted state. Mirror the tip cascade.
                    let orphan_block = inner.blocks.get(&oh).cloned().or_else(|| {
                        self.db
                            .as_ref()
                            .and_then(|db| db.blocks.get(&oh).ok().flatten())
                    });
                    let orphan_block = match orphan_block {
                        Some(b) => b,
                        None => {
                            // Body missing from cache AND DB: cannot revert this
                            // block's state safely. Fail loudly instead of silently
                            // under-disconnecting (which corrupts supply/work) —
                            // consistent with the halt-on-corruption arms below.
                            return Err(Error::InvalidState(format!(
                                "rollback_to_height: block {} at height {} missing from \
                                 cache AND DB; cannot revert its state — resync required",
                                oh.to_hex(),
                                h
                            )));
                        }
                    };
                    let txs = orphan_block.transactions.clone();
                    {
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
                        // Burn accumulator moves in lockstep with supply: the
                        // block being disconnected is the one in the cache under
                        // `oh` (its txs were just read above), so its fee-burn is
                        // well-defined. Computed before the stat mutations so the
                        // immutable borrow of `inner.blocks` is released first.
                        let fee_burn = block_fee_burn(self.network, &orphan_block);
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
                        // Mirror the supply subtract for the burn accumulator.
                        inner.stats.total_burned = inner
                            .stats
                            .total_burned
                            .checked_sub(fee_burn)
                            .unwrap_or_else(|| {
                                panic!(
                                    "CONSENSUS CORRUPTION: total_burned underflow on reorg \
                                     rollback — tried to subtract fee_burn={} from \
                                     total_burned={} at height being disconnected. Burn \
                                     telemetry is unrecoverable; halting to preserve on-disk \
                                     state. Restart re-derives it from the persisted chain.",
                                    fee_burn, inner.stats.total_burned
                                )
                            });
                        // F3 (audit fix): decrement cumulative work per disconnected
                        // block, mirroring the connect path's `total_difficulty +=
                        // difficulty`. Without this, rollback_to_height persists the
                        // pre-rollback (inflated) total_difficulty against a lower tip,
                        // so this node would advertise more work than one that reached
                        // the same tip linearly — a false `work_behind` veto / wrong
                        // fork choice. saturating_sub: work never drops below the base.
                        let disc_difficulty =
                            calculate_difficulty_from_target(&orphan_block.header.target);
                        inner.stats.total_difficulty =
                            inner.stats.total_difficulty.saturating_sub(disc_difficulty);
                        // Telemetry parity with the connect path (which does
                        // `total_blocks += 1` and `total_transactions += txs.len()`):
                        // a reorg/rollback MUST unwind these too, or a node that
                        // reorged reports inflated block/tx totals versus a node that
                        // built the identical tip linearly — breaking apply/disconnect
                        // symmetry (caught by the real-PoW e2e
                        // `apply_disconnect_symmetry_and_supply_conservation`). Not
                        // consensus-critical (fork choice uses total_difficulty, above,
                        // which IS unwound), but a correctness bug in reported stats.
                        // saturating_sub: telemetry never underflows below zero.
                        inner.stats.total_blocks = inner.stats.total_blocks.saturating_sub(1);
                        inner.stats.total_transactions = inner
                            .stats
                            .total_transactions
                            .saturating_sub(txs.len() as u64);
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
                total_burned: inner.stats.total_burned as u64,
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

    // record_event / get_events moved to chain::events (issue #108).

    /// Process/add block to chain
    pub fn process_block(&self, block: Block) -> Result<BlockStatus> {
        self.add_block(block)
    }

    /// Add block to chain
    pub fn add_block(&self, block: Block) -> Result<BlockStatus> {
        // Serialize the ENTIRE block-application operation against other writers
        // (see `apply_lock` doc). Held for the whole read→decide→mutate→persist
        // sequence — no other add_block/rollback/restore can interleave across
        // the fine-grained `inner` sections or the lock-released fork walk.
        // `process_block` delegates here and must NOT take this lock.
        let _apply = self.apply_lock.lock();
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

        // SECURITY: Enforce hardcoded checkpoints (below).
        //
        // DETERMINISM (2026-08-16): the DB-recorded per-height checkpoint HASH
        // gate that used to live here was REMOVED. `db.state.get_checkpoint(h)`
        // records whichever block this node FIRST saw at height h, is written
        // only on the linear extend path (chain.rs add_checkpoint) and is NEVER
        // updated on reorg — so it is PATH-DEPENDENT: two honest nodes on the
        // same canonical tip reached via different reorg histories recorded
        // different hashes, and the stale orphaned hash would reject the
        // network's true-canonical block on re-offer, partitioning the node.
        // This is the mechanism that broke the 2026-05-10 launch (the
        // RECENT_REORG_DEPTH=10 band-aid only narrowed the window). It is also
        // REDUNDANT: deep-reorg finality is already enforced deterministically
        // by the `fork_point < finality_floor` reorg reject, where the floor is
        // computed as a pure function of tip height (`tip - tip % INTERVAL`, see
        // ~L2505 — NOT the stored last_checkpoint) plus the rollback floor, and by the
        // hardcoded cross-node checkpoints below. Same divergence class as the
        // fixed total_difficulty / total_outputs_ever bugs — removed at the root
        // rather than band-aided. The get_checkpoint hashes are still recorded
        // (harmless; available to RPC/telemetry) but no longer gate consensus.
        //
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
            // C1 FIX: a COMPETING FORK block (parent != active tip) is validated
            // against `inner.utxos`, which is the ACTIVE chain's UTXO set -- the
            // wrong snapshot for that block. The active-UTXO-relative checks
            // (key-image double-spend, duplicate-stealth-vs-chain, ring-member
            // existence, available-count ring size) would false-reject an
            // ordinary natural fork that shares a mempool tx with the active
            // branch, the block would never be stored, and the honest peer
            // serving it banned -- leaving the node unable to ever reorg onto a
            // heavier branch (permanent partition). For fork blocks we therefore
            // defer those checks (`contextual = false`); the reorg loop re-runs
            // FULL validation against the rewound fork-point UTXO set before the
            // fork can win. PoW and all context-free/crypto checks still run here.
            let validation = crate::consensus::validate_block_ctx(
                &block,
                parent.as_ref(),
                &inner.utxos,
                cp,
                self.network,
                is_main_chain,
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
        // Block timestamp must be greater than the median of the 11 blocks
        // that PRECEDE it ON ITS OWN CHAIN. This prevents miners from
        // backdating blocks to manipulate difficulty.
        //
        // REORG-CORRECTNESS: we walk the block's ACTUAL parent lineage via
        // `prev_hash`, not the active chain by height. Reading by height was
        // wrong for a competing-fork block — it computed the median from
        // unrelated main-chain timestamps at those heights, so a valid
        // heavier fork whose near-fork blocks predated the active chain's MTP
        // was rejected AND the honest peer serving it was banned
        // (InvalidBlockPoW), blocking legitimate reorgs and risking permanent
        // self-isolation of a drifted node. For a main-chain block the parent
        // lineage IS the by-height ancestry, so this is behaviour-identical
        // on the common path. Mirrors the fork-aware difficulty window below.
        if block.header.height >= 11 {
            if let Some(mtp) = self.median_time_past_of_lineage(block.header.prev_hash) {
                if block.header.timestamp <= mtp {
                    return Ok(BlockStatus::Invalid(format!(
                        "Block timestamp {} is not greater than median-time-past {} (median of last 11 blocks on its own chain)",
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
                // DB-sourced fork window — deterministic across all nodes
                // (fix for chain.rs:2056; replaces the volatile in-memory-cache
                // walk that made two nodes compute different windows/targets for
                // the same fork block → consensus split).
                self.fork_difficulty_window(block.header.prev_hash, block.header.height)
            };

            // `test-fast-pow` (INSECURE test feature) skips the ASERT target
            // match so the instant-mining harness can use a trivial target.
            if difficulty_blocks.len() >= 2 && !cfg!(feature = "test-fast-pow") {
                let expected_target =
                    self.expected_next_target(&difficulty_blocks, block.header.height);
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

                    // Track supply: total_supply is GROSS emission — the full
                    // per-block reward is added; fee burns are NOT subtracted
                    // here (total_burned is tracked separately). So total_supply
                    // == sum of the deterministic emission schedule, which is
                    // exactly what get_supply_info exposes as verifiable.
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
                    // Burn accumulator, in lockstep with the supply add above.
                    inner.stats.total_burned = inner
                        .stats
                        .total_burned
                        .checked_add(block_fee_burn(self.network, &block))
                        .unwrap_or_else(|| {
                            panic!(
                                "CONSENSUS CORRUPTION: total_burned overflow on block \
                                 connect — total_burned={} + this block's fee-burn \
                                 exceeded u128. Halting for RocksDB flush + operator triage.",
                                inner.stats.total_burned
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
                // Post-lock work: build the atomic-commit batch, then commit it
                // ONCE below (crash-consistent). Replaces the former separate,
                // non-transactional persist_output_index + per-tx index_tx +
                // set_height_hash + save_state writes — a crash between any two
                // of those left disk internally inconsistent (db/blocks.rs:227,
                // output_index.rs:130). See Database::commit_block_atomic.
                let mut output_additions: Vec<([u8; 32], Vec<u8>)> = Vec::new();
                let mut tx_index_adds: Vec<([u8; 32], u64, u32)> = Vec::new();
                for (tx_idx, tx) in block.transactions.iter().enumerate() {
                    let is_coinbase = tx.is_coinbase();
                    for output in &tx.outputs {
                        let entry = OutputIndexEntry {
                            commitment: output.commitment,
                            height: block.header.height,
                            is_coinbase,
                            lock_height: output.lock_height,
                        };
                        let bytes = crate::db::serialize(&entry).map_err(|e| {
                            Error::Internal(format!(
                                "serialize OutputIndexEntry failed at height {}: {}",
                                block.header.height, e
                            ))
                        })?;
                        output_additions.push((*output.stealth_address.as_bytes(), bytes));
                    }
                    tx_index_adds.push((*tx.hash().as_bytes(), block.header.height, tx_idx as u32));
                }

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
                // (tx-index is now written inside commit_block_atomic below,
                // as part of the single crash-consistent transaction.)

                // Update database height index (only after race check passes).
                //
                // ATOMICITY (2026-08-18): the in-memory tip/stats/UTXO were already
                // committed under the write lock above. A persistence failure here
                // therefore cannot be a recoverable `?`-return — that would leave
                // the in-memory chain one block ahead of durable state (the node
                // would keep building on, and serve, a tip it never persisted). We
                // halt instead, consistent with the supply-accumulator corruption
                // handling above: the SIGTERM/SIGINT handler flushes RocksDB
                // cleanly, and on restart the node re-syncs this single block from
                // peers rather than running with in-memory ahead of disk.
                if let Some(ref db) = self.db {
                    // (height→hash is now written inside commit_block_atomic
                    // below, atomically with output-index, state, and tx-index.)

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
                        total_burned: stats.total_burned as u64,
                        last_checkpoint: last_checkpoint_height,
                    };
                    let state_bytes = crate::db::serialize(&state).unwrap_or_else(|e| {
                        panic!(
                            "CONSENSUS PERSISTENCE FAILURE: could not serialize chain state at \
                             height {} (tip {}): {}. In-memory tip already advanced; halting.",
                            block.header.height,
                            hash.to_hex(),
                            e
                        )
                    });
                    // ── ONE crash-consistent transaction ──
                    // Commits output-index + height→hash + chain-state + tx-index
                    // together (Database::commit_block_atomic), replacing the four
                    // former separate writes so a crash can never leave the height
                    // index / output index / tx index / state disagreeing.
                    // Same halt-on-error model as the previous save_state: a
                    // returned Err would mean in-memory is ahead of disk, so we
                    // panic to let the SIGTERM flush + restart re-sync this one
                    // block from peers. (Rollback-instead-of-halt is a separable,
                    // reviewer-gated enhancement.)
                    db.commit_block_atomic(
                        &output_additions,
                        (block.header.height, *hash.as_bytes()),
                        &tx_index_adds,
                        &state_bytes,
                    )
                    .unwrap_or_else(|e| {
                        panic!(
                            "CONSENSUS PERSISTENCE FAILURE: commit_block_atomic failed at height \
                             {} (tip {}): {}. In-memory supply/difficulty/tip have already \
                             advanced; halting to preserve on-disk state (SIGTERM handler flushes \
                             RocksDB cleanly) so restart re-derives consistently rather than \
                             running with in-memory ahead of disk.",
                            block.header.height,
                            hash.to_hex(),
                            e
                        )
                    });
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
                    if block.header.height >= self.network.rolling_finality_enable_height() {
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

                // Approaching a RandomX key-epoch boundary? Prewarm the next
                // epoch's dataset in the background so the boundary crossing
                // (during IBD or steady-state validation) promotes it instantly
                // instead of stalling the pipeline for the build. No-op away
                // from a boundary; idempotent.
                #[cfg(feature = "randomx")]
                crate::consensus::prewarm_next_epoch_if_near(block.header.height);

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
                    if block.header.height >= self.network.rolling_finality_enforce_height()
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

                // SECURITY + DETERMINISM (2026-08-18): Reject reorgs that would
                // revert past the finality floor — the highest CHECKPOINT_INTERVAL
                // boundary at or below the current canonical tip height. This
                // prevents long-range reorganization from far in the past.
                //
                // The floor is computed as a PURE FUNCTION of tip height, NOT read
                // from the persisted `last_checkpoint`. That stored value is
                // advanced ONLY on the linear tip-extend path (at 144-multiple
                // heights) and merely re-persisted unchanged on the reorg-commit
                // path — so it was PATH-DEPENDENT: two honest nodes on the same
                // canonical tip reached via different reorg histories held
                // different `last_checkpoint` values, and could therefore split on
                // a deep-reorg accept/reject (one rejects `fork_point < 288` while
                // the other, whose stored value was stale at 144, accepts it).
                // Same divergence class as the already-fixed total_difficulty /
                // total_outputs_ever / self-checkpoint-hash bugs. This finally
                // implements the property the hash-gate-removal comment (~L1896)
                // already asserted — "checkpoint HEIGHT is a pure function of tip
                // height" — which the stored accumulator never actually provided.
                //
                // On the linear path the stored value already equals this floor,
                // so honest-majority behavior is unchanged; only stale-low
                // reorg-path nodes are tightened up to the majority (the safe
                // direction — it can only reject reorgs the majority also rejects,
                // never accept ones they reject). `last_checkpoint` is still
                // recorded for assume-valid IBD and telemetry; it just no longer
                // gates consensus.
                {
                    // audit H-3: a rolling finality floor that ALWAYS leaves a
                    // full CHECKPOINT_INTERVAL window reorg-able. The previous
                    // `tip - (tip % interval)` made the floor the last boundary,
                    // so the max reorg depth was `tip % interval` — as low as
                    // ZERO when the tip sat exactly on a boundary — permanently
                    // rejecting a routine shallow reorg that happened to cross a
                    // boundary and stranding the node on the minority branch.
                    // Base the floor a full interval below the tip instead; the
                    // 3-tier MESS gate above remains the primary depth policy.
                    let tip_height = self.inner.read().tip.height;
                    let interval = crate::constants::CHECKPOINT_INTERVAL;
                    let finality_floor = tip_height.saturating_sub(interval);
                    if finality_floor > 0 && fork_point < finality_floor {
                        let depth = block.header.height.saturating_sub(fork_point);
                        tracing::error!(
                            "Rejecting reorg: fork point {} is before finality floor {} (depth {})",
                            fork_point,
                            finality_floor,
                            depth
                        );
                        // Return ReorgTooDeep (NOT BlockStatus::Invalid) so the
                        // honest peer serving the heavier chain is not banned —
                        // this is a "too deep for our finality rule" outcome,
                        // identical in spirit to the MESS hard cap above, which
                        // also returns this (audit H-3 / P2P Finding 4).
                        return Err(Error::ReorgTooDeep {
                            depth,
                            max: interval,
                        });
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
                                // Burn accumulator, in lockstep with the supply
                                // subtract below. The disconnected block is still
                                // in the cache under `oh`; compute its fee-burn
                                // before mutating stats to release the borrow.
                                let fee_burn = block_fee_burn(
                                    self.network,
                                    inner.blocks.get(&oh).expect(
                                        "disconnected block is in cache; its txs were just read",
                                    ),
                                );
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
                                // Mirror the supply subtract for the burn accumulator.
                                inner.stats.total_burned = inner
                                    .stats
                                    .total_burned
                                    .checked_sub(fee_burn)
                                    .unwrap_or_else(|| {
                                        panic!(
        "CONSENSUS CORRUPTION: total_burned underflow on reorg rollback — \
         tried to subtract fee_burn={} from total_burned={} at height being disconnected. \
         Burn telemetry is unrecoverable; halting to preserve on-disk state. \
         Restart re-derives it from the persisted chain.",
        fee_burn, inner.stats.total_burned
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
                                    if let Some(ref db) = self.db {
                                        // DB-sourced (deterministic across nodes). Heights
                                        // <= fork_point are stable during a reorg (it only
                                        // mutates heights above fork_point). Falls back to the
                                        // held in-memory guard only in no-DB test mode.
                                        if let Ok(Some(b)) = db.blocks.get_by_height(h) {
                                            diff_blocks.push(DifficultyBlock {
                                                height: h,
                                                timestamp: b.header.timestamp,
                                                target: b.header.target,
                                            });
                                        }
                                    } else if let Some(hash) = inner.height_to_hash.get(&h) {
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

                            if diff_blocks.len() >= 2 && !cfg!(feature = "test-fast-pow") {
                                let expected_target = self
                                    .expected_next_target(&diff_blocks, fork_block.header.height);
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
                        // Placement is load-bearing: keep the height mapping
                        // and checkpoint adjacent, before the UTXO mutation.
                        // The site-5a rollback guard keys on height_to_hash,
                        // so a mapped block must always own one checkpoint.
                        // Inert while stores are None.
                        self.checkpoint_phase2_stores(fork_block.header.height);

                        // Defer canonical DB mappings until the final atomic
                        // reorg commit, after every fork block has validated.
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
                        // Burn accumulator, in lockstep with this fork block's
                        // supply add above.
                        inner.stats.total_burned = inner
                            .stats
                            .total_burned
                            .checked_add(block_fee_burn(self.network, fork_block))
                            .unwrap_or_else(|| {
                                panic!(
                                    "CONSENSUS CORRUPTION: total_burned overflow on reorg \
                                     fork-block connect — total_burned={} + this block's \
                                     fee-burn exceeded u128. Halting for RocksDB flush + \
                                     operator triage.",
                                    inner.stats.total_burned
                                )
                            });
                    }

                    // SECURITY (REORG-TIP-VALIDATE, 2026-08-13): re-validate the
                    // triggering (fork-tip) block against the REORGED UTXO state,
                    // exactly as each fork block was validated in the loop above.
                    // The tip's only prior consensus validation (in `add_block`,
                    // ~L1814) ran against the PRE-rewind MAIN-chain UTXO set, which
                    // does not reflect the fork's spends. Without this re-check, a
                    // tip that re-spends a key image already consumed by a fork
                    // block is applied unchecked: `UtxoSet::apply_batch` silently
                    // no-ops the duplicate key image (mark_key_image_spent returns
                    // false, not an error) while STILL adding the tip's outputs —
                    // minting coins from a single input (post-reorg double-spend /
                    // inflation). We validate here, BEFORE the unconditional
                    // rollback below, so a failure routes through the same
                    // proven `reorg_error` cleanup that fork-block failures use.
                    if reorg_error.is_none() {
                        let tip_parent = inner.blocks.get(&block.header.prev_hash).cloned();
                        match crate::consensus::validate_block_with_checkpoint_for_network(
                            &block,
                            tip_parent.as_ref(),
                            &inner.utxos,
                            None,
                            self.network,
                        ) {
                            Ok(v) if v.valid => {}
                            Ok(v) => {
                                let errors = v.errors.join("; ");
                                tracing::warn!(
                                    "Reorg tip block {} rejected against reorged state: {}",
                                    hash.to_hex(),
                                    errors
                                );
                                reorg_error =
                                    Some(format!("Invalid reorg tip block: {}", errors));
                            }
                            Err(e) => {
                                reorg_error =
                                    Some(format!("Reorg tip validation error: {}", e));
                            }
                        }
                    }

                    // Tracks whether the path-A rollback below actually ran, so the
                    // triggering-block difficulty rollback (path B) can be gated on
                    // it instead of on `inner.tip.hash != pre_reorg_tip.hash` — see
                    // the fix note at path B.
                    let mut rolled_back = false;

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
                                // Burn accumulator, in lockstep with the supply
                                // subtract below (undoing this fork block's add).
                                let fee_burn = block_fee_burn(self.network, fork_block);
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
                                // Mirror the supply subtract for the burn accumulator.
                                inner.stats.total_burned = inner
                                    .stats
                                    .total_burned
                                    .checked_sub(fee_burn)
                                    .unwrap_or_else(|| {
                                        panic!(
        "CONSENSUS CORRUPTION: total_burned underflow on failed-reorg rollback — \
         tried to subtract fee_burn={} from total_burned={} for a fork block being undone. \
         Burn telemetry is unrecoverable; halting to preserve on-disk state. \
         Restart re-derives it from the persisted chain.",
        fee_burn, inner.stats.total_burned
    )
                                    });
                            }
                        }

                        // Remove fork block height mappings above fork point.
                        //
                        // H3: `inner.tip` has NOT been advanced yet (that happens
                        // after a successful reorg), so `inner.tip.height ==
                        // pre_reorg_tip.height` here — bounding the removal by it
                        // leaves the mappings of any fork block applied at a
                        // height ABOVE the old tip in place. RPC/sync would then
                        // report an unapplied fork block as canonical, and a
                        // follow-up block parented on it could commit a chain
                        // with an unapplied gap. Bound the removal by the highest
                        // fork height instead (removing a height that was never
                        // inserted is a harmless no-op), so every partially
                        // applied fork mapping is cleaned up.
                        let highest_fork_height = fork_blocks
                            .iter()
                            .map(|b| b.header.height)
                            .max()
                            .unwrap_or(pre_reorg_tip.height);
                        let removal_top = pre_reorg_tip.height.max(highest_fork_height);
                        for h in (fork_point + 1..=removal_top).rev() {
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
                                let txs = orphan_block.transactions.clone();
                                let batch = UtxoSet::batch_from_block(*h, &txs);
                                inner.utxos.apply_batch(batch);
                                // F1 (audit fix): the disconnect above removed these
                                // outputs from the ON-DISK output_index too (R-68,
                                // immediate write in remove_output). Re-applying only
                                // in memory leaves disk permanently missing them, so
                                // after they age out of the ~1000-block cache, ring-
                                // member validation using one as a decoy fails on this
                                // node but succeeds on nodes that never did this failed
                                // reorg -> mempool/consensus partition. Restore the disk
                                // rows so the rollback is symmetric on disk as well.
                                self.persist_output_index(&txs, *h);
                            }
                        }

                        // Restore tip and stats
                        inner.tip = pre_reorg_tip.clone();
                        inner.stats = pre_reorg_stats.clone();
                        rolled_back = true;
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
                                    if let Some(ref db) = self.db {
                                        // DB-sourced (deterministic across nodes). Heights
                                        // <= fork_point are stable during a reorg (it only
                                        // mutates heights above fork_point). Falls back to the
                                        // held in-memory guard only in no-DB test mode.
                                        if let Ok(Some(b)) = db.blocks.get_by_height(h) {
                                            diff_blocks.push(DifficultyBlock {
                                                height: h,
                                                timestamp: b.header.timestamp,
                                                target: b.header.target,
                                            });
                                        }
                                    } else if let Some(hash) = inner.height_to_hash.get(&h) {
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

                            if diff_blocks.len() >= 2 && !cfg!(feature = "test-fast-pow") {
                                let expected_target =
                                    self.expected_next_target(&diff_blocks, block.header.height);
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

                    // If the triggering block's difficulty re-check failed, roll
                    // back. BUG (2026-08-18): this was previously gated on
                    // `inner.tip.hash != pre_reorg_tip.hash`, which is ALWAYS false
                    // here — `inner.tip` is never advanced to the fork head before
                    // this point (it is only set on success, or restored by path
                    // A), so path B could never fire and a difficulty-recheck
                    // failure left the reorg half-applied (main-chain blocks
                    // disconnected, fork blocks connected, supply/burn/UTXO mutated
                    // but never rolled back). Path A and path B are mutually
                    // exclusive (the difficulty check just above runs only when
                    // reorg_error was None at path A), so `!rolled_back` fires path
                    // B exactly when path A did not.
                    if reorg_error.is_some() && !rolled_back {
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
                            // Burn accumulator, in lockstep with the supply
                            // subtract below (undoing this fork block's add).
                            let fee_burn = block_fee_burn(self.network, fork_block);
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
                            // Mirror the supply subtract for the burn accumulator.
                            inner.stats.total_burned = inner
                                .stats
                                .total_burned
                                .checked_sub(fee_burn)
                                .unwrap_or_else(|| {
                                    panic!(
        "CONSENSUS CORRUPTION: total_burned underflow on failed-reorg rollback — \
         tried to subtract fee_burn={} from total_burned={} at fork block being disconnected. \
         Burn telemetry is unrecoverable; halting to preserve on-disk state. \
         Restart re-derives it from the persisted chain.",
        fee_burn, inner.stats.total_burned
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
                                let txs = orphan_block.transactions.clone();
                                let batch = UtxoSet::batch_from_block(*h, &txs);
                                inner.utxos.apply_batch(batch);
                                // F1 (audit fix): restore the ON-DISK output_index the
                                // disconnect removed (R-68), so a failed reorg is
                                // symmetric on disk — see the path-A note above.
                                self.persist_output_index(&txs, *h);
                            }
                        }

                        inner.tip = pre_reorg_tip.clone();
                        inner.stats = pre_reorg_stats.clone();
                    }

                    if reorg_error.is_none() {
                        // F2 (audit fix): checkpoint the Phase-2 stores BEFORE the tip
                        // block's UTXO mutations, matching every other apply site
                        // (clean-extend, fork-block loop, both rollback paths). The
                        // triggering tip is excluded from collect_fork_chain and only
                        // applied here, so without this the Phase-2 checkpoint stack
                        // ends one short per reorg and a later disconnect through this
                        // tip rewinds the wrong boundary (mainnet blocker once the
                        // shielded/spark/kernel stores activate; inert while None).
                        self.checkpoint_phase2_stores(block.header.height);
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
                        // Burn accumulator, in lockstep with the tip supply add.
                        inner.stats.total_burned = inner
                            .stats
                            .total_burned
                            .checked_add(block_fee_burn(self.network, &block))
                            .unwrap_or_else(|| {
                                panic!(
                                    "CONSENSUS CORRUPTION: total_burned overflow on reorg tip \
                                     apply — total_burned={} + the tip block's fee-burn \
                                     exceeded u128. Halting for RocksDB flush + operator triage.",
                                    inner.stats.total_burned
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
                let persist_result = (|| -> Result<()> {
                    // Bound (not `_`-prefixed) because we READ through it below:
                    // any `self.<method>()` that re-locks `self.inner` while this
                    // write guard is held self-deadlocks under parking_lot's
                    // non-re-entrant RwLock. Read shared state via the guard.
                    let reorg_commit_guard = self.inner.write();
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
                             ti: &mut Vec<([u8; 32], u64, u32)>| -> Result<()> {
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
                                        let data = crate::db::serialize(&entry).map_err(|e| {
                                            Error::Internal(format!(
                                                "serialize OutputIndexEntry failed at height {}: {}",
                                                h, e
                                            ))
                                        })?;
                                        oi.push((*output.stealth_address.as_bytes(), data));
                                    }
                                    ti.push((*tx.hash().as_bytes(), h, idx as u32));
                                }
                                Ok(())
                            };

                        for fork_block in &fork_blocks {
                            collect_block_outputs(
                                fork_block,
                                &mut oi_additions,
                                &mut height_sets,
                                &mut ti_adds,
                            )?;
                        }
                        collect_block_outputs(
                            &block,
                            &mut oi_additions,
                            &mut height_sets,
                            &mut ti_adds,
                        )?;

                        // 3. Compute stale heights to remove (above new tip)
                        let new_tip_height = block.header.height;
                        let height_removals: Vec<u64> = if new_tip_height < pre_reorg_tip.height {
                            (new_tip_height + 1..=pre_reorg_tip.height).collect()
                        } else {
                            Vec::new()
                        };

                        // 4. Serialize new chain state
                        let last_checkpoint = db
                            .state
                            .get_state()?
                            .map(|s| s.last_checkpoint)
                            .unwrap_or(0);
                        let new_state = ChainStateData {
                            tip_hash: hash,
                            height: new_tip_height,
                            total_difficulty: fork_cumulative,
                            // Read supply through the held write guard, NOT
                            // self.stats() — the latter takes self.inner.read()
                            // and would self-deadlock against this write guard
                            // (parking_lot RwLock is not re-entrant), freezing
                            // the node on EVERY successful reorg. The value is
                            // identical: stats() clones inner.stats.
                            // Read burn through the held write guard for the
                            // same reason as total_supply above (self.stats()
                            // would self-deadlock the parking_lot RwLock).
                            total_supply: reorg_commit_guard.stats.total_supply,
                            total_burned: reorg_commit_guard.stats.total_burned as u64,
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
                    Ok(())
                })(); // R-34: close the write-guard scope before handling errors
                      // or taking the read lock used by the commit log below.

                if let Err(error) = persist_result {
                    panic!(
                        "CONSENSUS PERSISTENCE FAILURE: reorg to block {} at height {} could not \
                         be committed atomically: {}. The in-memory chain has already advanced, \
                         while the atomic DB batch left the previous canonical state intact. \
                         Halting so restart reloads that durable state instead of serving a \
                         divergent tip.",
                        hash.to_hex(),
                        block.header.height,
                        error
                    );
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

                // Enterprise metrics: count the reorg and record its depth.
                crate::metrics::record_reorg(reorg_depth as u64);

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
    /// A main-chain block's `DifficultyBlock`, sourced from DURABLE storage so
    /// the difficulty window is identical on every node. Reading the volatile,
    /// height-evicted in-memory cache (MAX_BLOCK_CACHE) is what made difficulty
    /// validation nondeterministic (chain.rs:2056/2810 — a cold-cache node built
    /// a truncated window and computed a different expected target than a
    /// hot-cache node, a consensus split). The DB path takes no `inner` lock;
    /// the cache fallback is reached ONLY in no-DB in-memory test mode (where
    /// callers do not hold the lock).
    // main_chain_diff_block / fork_difficulty_window moved to chain::fork_calc
    // (issue #108).

    // get_difficulty_blocks / is_spent / target_height / peer_advertised_height
    // moved to chain::queries (issue #108).

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

    // secs_since_last_block / is_phantom_stall moved to chain::queries (issue #108).

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

    // export_checkpoints moved to chain::queries (issue #108).

    // calculate_fork_cumulative_work / recompute_total_difficulty /
    // find_fork_point / collect_fork_chain moved to chain::fork_calc (issue #108).
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

    // stable_generation moved to chain::queries (issue #108).

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

/// Total fees BURNED by `block`, in atomic units.
///
/// Computed EXACTLY as the consensus validator computes the coinbase burn (see
/// `src/consensus/validation.rs` `max_coinbase` / `distribute_fee`, ~L269-294),
/// so the `total_burned` telemetry accumulator equals the coins consensus
/// required this block to burn. This is the value `total_burned` moves by
/// whenever the block is connected (`+=`) or disconnected (`-=`), maintained in
/// lockstep with the block's emission in `total_supply`.
///
/// Mirror of validation.rs:
///   * `total_fees` = Σ `fee` over NON-coinbase txs. `Amount`'s `Sum` impl is
///     `saturating_add`, identical to the validator's
///     `.skip(1).map(|tx| tx.fee).sum()` (first tx is the coinbase).
///   * below `FEE_DISTRIBUTION_HEIGHT`, or zero fees → `0` (miner claims all
///     fees), matching `block.height() >= FEE_DISTRIBUTION_HEIGHT
///     && total_fees.as_atomic() > 0`.
///   * `congestion_pct = (block.size() * 100) / MAX_BLOCK_SIZE` (integer),
///     `congested = congestion_pct >= CONGESTION_THRESHOLD` — the same
///     `size = block.size()` the validator uses.
///   * burn = `distribute_fee(total_fees, congested).burned`.
fn block_fee_burn(network: crate::config::NetworkType, block: &Block) -> u128 {
    let total_fees: crate::primitives::Amount = block
        .transactions
        .iter()
        .filter(|tx| !tx.is_coinbase())
        .map(|tx| tx.fee)
        .sum();

    // Below activation, or no fees: nothing burned — miner claims all fees.
    // Runtime-network hardening: resolve the activation height from the runtime
    // network so burn accounting matches the validator (which does the same).
    if block.height() < network.fee_distribution_height() || total_fees.as_atomic() == 0 {
        return 0;
    }

    // Integer congestion, mirroring validation.rs `max_coinbase` exactly.
    let size = block.size();
    let congestion_pct =
        ((size as u128 * 100) / crate::constants::MAX_BLOCK_SIZE as u128) as u64;
    let congested = congestion_pct >= crate::constants::CONGESTION_THRESHOLD;

    crate::consensus::fee_market::distribute_fee(total_fees, congested)
        .burned
        .as_atomic() as u128
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
// §12  Genesis Block
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

    // Runtime-network hardening: `block_fee_burn` now resolves the activation
    // height from the network. These tests use `crate::constants::FEE_DISTRIBUTION_HEIGHT`
    // (the compiled const) as their boundary, so pass the compiled network —
    // pinned equal to that const by the drift guard in constants.rs.
    #[cfg(feature = "testnet")]
    const TEST_NET: crate::config::NetworkType = crate::config::NetworkType::Testnet;
    #[cfg(not(feature = "testnet"))]
    const TEST_NET: crate::config::NetworkType = crate::config::NetworkType::Mainnet;

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

    /// #108 (failure boundary): a failed block application must leave chain state
    /// byte-for-behavior unchanged. A block whose parent is unknown is rejected
    /// (Orphan) before any state mutation, so tip, height, cumulative work, block
    /// count and the UTXO set must all be exactly as they were.
    #[test]
    fn failed_block_application_leaves_chain_state_unchanged_108() {
        let dir = tempfile::tempdir().unwrap();
        let db = Arc::new(Database::open(dir.path()).unwrap());
        let chain = Blockchain::with_database(db, NetworkType::Testnet);
        chain.init_genesis().unwrap();

        let tip_before = chain.tip().hash;
        let height_before = chain.height();
        let stats_before = chain.stats();
        let utxo_before = chain.utxo_count();

        // Unknown parent → rejected without touching state.
        let orphan = walk_block(5, Hash::from_bytes([0xAB; 32]), 99);
        let status = chain.add_block(orphan).unwrap();
        assert!(
            matches!(status, BlockStatus::Orphan | BlockStatus::Invalid(_)),
            "a bad-parent block must be rejected (Orphan/Invalid), got {status:?}"
        );

        assert_eq!(chain.tip().hash, tip_before, "tip moved after a failed apply");
        assert_eq!(chain.height(), height_before, "height moved after a failed apply");
        assert_eq!(
            chain.stats().total_difficulty,
            stats_before.total_difficulty,
            "total_difficulty moved after a failed apply"
        );
        assert_eq!(
            chain.stats().total_blocks,
            stats_before.total_blocks,
            "total_blocks moved after a failed apply"
        );
        assert_eq!(chain.utxo_count(), utxo_before, "utxo set changed after a failed apply");
    }

    /// #108 (reopen): reopening the database restores the expected chain. After
    /// genesis init, a fresh `Blockchain` over the SAME db must load (not fresh)
    /// and report the identical tip, height, cumulative work, supply and UTXO
    /// count via its public getters — i.e. the recovery path (load_from_database
    /// + rebuild_utxo_set + recompute_total_difficulty + tip restore, now in
    /// chain::recovery) reconstructs state faithfully.
    #[test]
    fn reopening_database_restores_expected_chain_108() {
        let dir = tempfile::tempdir().unwrap();
        let db = Arc::new(Database::open(dir.path()).unwrap());

        let chain = Blockchain::with_database(Arc::clone(&db), NetworkType::Testnet);
        assert_eq!(
            chain.load_from_database_with_outcome().unwrap(),
            ChainLoadOutcome::Fresh
        );
        chain.init_genesis().unwrap();
        let tip = chain.tip().hash;
        let height = chain.height();
        let supply = chain.stats().total_supply;
        let total_blocks = chain.stats().total_blocks;
        let utxos = chain.utxo_count();

        // A freshly initialised node must already carry the canonical genesis
        // cumulative-work base — identical to what a restart reports below (this
        // pins the init_genesis total_difficulty fix).
        assert_eq!(
            chain.stats().total_difficulty,
            1,
            "fresh genesis chain must carry the canonical total_difficulty base"
        );

        // Reopen over the same DB — must Load and restore the expected chain.
        let reloaded = Blockchain::with_database(db, NetworkType::Testnet);
        assert_eq!(
            reloaded.load_from_database_with_outcome().unwrap(),
            ChainLoadOutcome::Loaded
        );
        assert_eq!(reloaded.tip().hash, tip, "tip not restored on reopen");
        assert_eq!(reloaded.height(), height, "height not restored on reopen");
        assert_eq!(reloaded.stats().total_supply, supply, "supply not restored on reopen");
        assert_eq!(
            reloaded.stats().total_blocks,
            total_blocks,
            "block count not restored on reopen"
        );
        assert_eq!(reloaded.utxo_count(), utxos, "utxo set not restored on reopen");
        // Fresh-init and reloaded now agree on the canonical genesis base.
        assert_eq!(
            reloaded.stats().total_difficulty,
            1,
            "reopened genesis chain must carry the canonical total_difficulty base"
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
    fn mtp_uses_fork_lineage_not_active_chain_by_height() {
        // R-1 regression: Median-Time-Past for a competing-fork block must be
        // computed from the FORK's own ancestors (walk prev_hash), not the
        // active chain's blocks at those heights. Before the fix, a valid
        // heavier fork whose near-fork blocks predated the active chain's MTP
        // was rejected as InvalidBlockPoW and the honest peer serving it was
        // banned — blocking legitimate reorgs (observed live 2026-08-16).
        let chain = Blockchain::new();
        chain.init_genesis().unwrap();
        let genesis = chain.get_block_by_height(0).expect("genesis present");

        let mk = |prev: Hash, height: u64, ts: u64, nonce: u64| -> Block {
            let mut b = genesis.clone();
            b.header.height = height;
            b.header.prev_hash = prev;
            b.header.timestamp = ts;
            b.header.nonce = nonce;
            b
        };

        // ACTIVE main chain h1..=14 with LATE timestamps (100_000 + h*100).
        let mut prev = genesis.hash();
        for h in 1..=14u64 {
            let b = mk(prev, h, 100_000 + h * 100, 5000 + h);
            let hash = b.hash();
            {
                let mut inner = chain.inner.write();
                inner.blocks.insert(hash, b.clone());
                inner.height_to_hash.insert(h, hash);
            }
            prev = hash;
        }

        // Competing FORK from genesis, h1..=13, with EARLY timestamps
        // (1_000 + h*10) and distinct nonces so the hashes don't collide with
        // the active chain. Stored as a side chain (no height_to_hash).
        let mut fprev = genesis.hash();
        let mut fork_h13 = genesis.hash();
        for h in 1..=13u64 {
            let b = mk(fprev, h, 1_000 + h * 10, 9000 + h);
            let hash = b.hash();
            {
                let mut inner = chain.inner.write();
                inner.blocks.insert(hash, b.clone());
            }
            fprev = hash;
            fork_h13 = hash;
        }

        // MTP for a hypothetical fork block at h14 (parent = fork h13). The 11
        // ancestors are fork h3..=13 (early); the median is fork h8 = 1_080.
        let mtp = chain
            .median_time_past_of_lineage(fork_h13)
            .expect(">=11 fork ancestors present");
        assert_eq!(mtp, 1_000 + 8 * 10, "MTP must be the fork lineage median");
        assert!(
            mtp < 100_000,
            "MTP must come from the fork lineage, not the active chain's late timestamps"
        );

        // Control: MTP off the ACTIVE tip (h14's parent = active h13) uses the
        // late active timestamps — median of active h3..=13 = active h8.
        let active_h13 = chain.get_block_by_height(13).unwrap().hash();
        let mtp_active = chain
            .median_time_past_of_lineage(active_h13)
            .expect(">=11 active ancestors present");
        assert_eq!(mtp_active, 100_000 + 8 * 100, "active-chain MTP median");
        assert!(
            mtp_active > mtp,
            "the two lineages must yield different MTPs — proving lineage-awareness"
        );
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

    // ── total_burned accumulator ──────────────────────────────────────
    //
    // `block_fee_burn` must equal the coins the consensus validator required
    // to be burned (src/consensus/validation.rs `max_coinbase`), and the
    // accumulator must be reorg-symmetric: `+=` on apply, `-=` on disconnect,
    // landing at Σ over the NEW canonical chain independent of the reorg path.

    /// A non-coinbase Transfer tx carrying `fee` atomic units. Only `fee`,
    /// `tx_type` and serialized size are read by `block_fee_burn`.
    fn burn_test_tx(fee: u64) -> Transaction {
        Transaction {
            version: 1,
            tx_type: crate::transaction::TxType::Transfer,
            inputs: Vec::new(),
            outputs: Vec::new(),
            fee: crate::primitives::Amount::from_atomic(fee),
            range_proof: Vec::new(),
            extra: Vec::new(),
        }
    }

    /// A small (non-congested) block at `height`, cloned from genesis, whose
    /// non-coinbase txs carry `fees`. `nonce` keeps block hashes distinct.
    fn burn_test_block(height: u64, nonce: u64, fees: &[u64]) -> Block {
        let mut b = create_genesis_block();
        assert!(
            b.transactions[0].is_coinbase(),
            "genesis first tx must be the coinbase"
        );
        b.header.height = height;
        b.header.nonce = nonce;
        let mut txs = vec![b.transactions[0].clone()];
        for &f in fees {
            txs.push(burn_test_tx(f));
        }
        b.transactions = txs;
        b
    }

    #[test]
    fn block_fee_burn_matches_validator_burn_split() {
        let act = crate::constants::FEE_DISTRIBUTION_HEIGHT;

        // Above activation, non-congested: burn == distribute_fee(Σfee,false).burned,
        // exactly the value validation.rs `max_coinbase` withholds from the miner.
        let fees = [1_000_000u64, 2_000_000u64];
        let b = burn_test_block(act + 10, 1, &fees);
        let total: u64 = fees.iter().sum();
        let expected = crate::consensus::fee_market::distribute_fee(
            crate::primitives::Amount::from_atomic(total),
            false,
        )
        .burned
        .as_atomic() as u128;
        assert_eq!(block_fee_burn(TEST_NET, &b), expected);
        // Concrete: 3_000_000 fees × 30% normal burn = 900_000.
        assert_eq!(block_fee_burn(TEST_NET, &b), 900_000);

        // Zero fees → nothing burned.
        assert_eq!(block_fee_burn(TEST_NET, &burn_test_block(act + 10, 2, &[])), 0);
        assert_eq!(block_fee_burn(TEST_NET, &burn_test_block(act + 10, 3, &[0])), 0);

        // Below the activation height miners claim all fees, nothing burned
        // (only reachable when activation > 0 — the testnet feature).
        if act > 0 {
            assert_eq!(block_fee_burn(TEST_NET, &burn_test_block(act - 1, 4, &fees)), 0);
        }
    }

    #[test]
    fn total_burned_apply_disconnect_is_symmetric_and_reorg_correct() {
        let act = crate::constants::FEE_DISTRIBUTION_HEIGHT;
        // Canonical chain A (2 blocks) vs a competing chain B (3 blocks), with
        // DIFFERENT per-block fees so the two totals differ.
        let a1 = burn_test_block(act + 1, 11, &[1_000_000]);
        let a2 = burn_test_block(act + 2, 12, &[2_000_000]);
        let b1 = burn_test_block(act + 1, 21, &[500_000]);
        let b2 = burn_test_block(act + 2, 22, &[1_000_000]);
        let b3 = burn_test_block(act + 3, 23, &[4_000_000]);

        let sum = |bs: &[&Block]| -> u128 { bs.iter().map(|b| block_fee_burn(TEST_NET, b)).sum() };

        // Apply A the way every connect site does: += block_fee_burn.
        let mut stats = ChainStats::default();
        for blk in [&a1, &a2] {
            stats.total_burned = stats.total_burned.checked_add(block_fee_burn(TEST_NET, blk)).unwrap();
        }
        assert_eq!(stats.total_burned, sum(&[&a1, &a2]));
        assert!(stats.total_burned > 0, "chain A must burn something");

        // Reorg: disconnect A in reverse order, then apply B — the exact
        // -=/+= pattern wired at the reorg disconnect/apply sites.
        for blk in [&a2, &a1] {
            stats.total_burned = stats.total_burned.checked_sub(block_fee_burn(TEST_NET, blk)).unwrap();
        }
        assert_eq!(
            stats.total_burned, 0,
            "apply-then-disconnect must return to the pre-apply value (+=/-= symmetry)"
        );
        for blk in [&b1, &b2, &b3] {
            stats.total_burned = stats.total_burned.checked_add(block_fee_burn(TEST_NET, blk)).unwrap();
        }
        // Reorg-correct: total_burned == Σ burn over the NEW canonical chain,
        // NOT path-dependent on the disconnected A branch.
        let expected_b = sum(&[&b1, &b2, &b3]);
        assert_eq!(stats.total_burned, expected_b);
        assert_ne!(expected_b, sum(&[&a1, &a2]), "the two chains must differ");
    }

    #[test]
    fn rollback_to_height_unwinds_total_burned_through_the_real_disconnect_site() {
        // Authentic exercise of the real disconnect wiring (rollback_to_height):
        // stage two fee-carrying blocks in the in-memory chain with the
        // accumulator advanced exactly as the connect sites do, then roll back
        // to genesis and assert total_burned returns to 0.
        let chain = Blockchain::new();
        chain.init_genesis().unwrap();
        // Use the CHAIN's runtime network for both the activation height and the
        // burn computation: block_fee_burn now follows the chain's network, so
        // the test must too (else it diverges under a feature set where the
        // compiled network differs from the chain's runtime network).
        let net = chain.network();
        let act = net.fee_distribution_height();
        let h1 = act.max(1);
        let h2 = h1 + 1;
        let genesis_hash = chain.tip_hash();

        let b1 = burn_test_block(h1, 31, &[3_000_000]);
        let b2 = burn_test_block(h2, 32, &[5_000_000]);
        let burn1 = block_fee_burn(net, &b1);
        let burn2 = block_fee_burn(net, &b2);
        assert!(burn1 > 0 && burn2 > 0, "staged blocks must burn fees");

        {
            let mut inner = chain.inner.write();
            let h1h = b1.hash();
            let h2h = b2.hash();
            inner.blocks.insert(h1h, b1.clone());
            inner.blocks.insert(h2h, b2.clone());
            inner.height_to_hash.insert(h1, h1h);
            inner.height_to_hash.insert(h2, h2h);
            inner.tip.hash = h2h;
            inner.tip.height = h2;
            inner.stats.height = h2;
            inner.stats.tip_hash = h2h;
            // Advance the accumulators as the connect path would have. Ample
            // supply headroom so the emission subtracts never underflow.
            inner.stats.total_supply = u64::MAX as u128;
            inner.stats.total_burned = burn1 + burn2;
        }

        assert_eq!(chain.stats().total_burned, burn1 + burn2);

        // The real disconnect path runs block_fee_burn(-=) for h2 then h1.
        chain.rollback_to_height(0).expect("rollback to genesis");

        assert_eq!(chain.tip_hash(), genesis_hash, "tip back at genesis");
        assert_eq!(
            chain.stats().total_burned, 0,
            "disconnecting every fee-carrying block returns total_burned to 0"
        );
    }

    /// Regression for the apply/disconnect-symmetry bug the real-PoW e2e
    /// `apply_disconnect_symmetry_and_supply_conservation` caught:
    /// `rollback_to_height` unwound supply/burn/total_difficulty but NOT the
    /// `total_blocks` / `total_transactions` telemetry counters, so a reorged
    /// node reported inflated totals versus a linearly-built node on the same
    /// tip. Fast staged version of that invariant.
    #[test]
    fn rollback_to_height_unwinds_total_blocks_and_transactions() {
        let chain = Blockchain::new();
        chain.init_genesis().unwrap();
        let net = chain.network();
        let act = net.fee_distribution_height();
        let h1 = act.max(1);
        let h2 = h1 + 1;
        let genesis_hash = chain.tip_hash();
        let base_blocks = chain.stats().total_blocks;
        let base_txs = chain.stats().total_transactions;

        let b1 = burn_test_block(h1, 41, &[1_000_000]);
        let b2 = burn_test_block(h2, 42, &[2_000_000, 3_000_000]);
        let added_txs = (b1.transactions.len() + b2.transactions.len()) as u64;
        let burn1 = block_fee_burn(net, &b1);
        let burn2 = block_fee_burn(net, &b2);

        {
            let mut inner = chain.inner.write();
            let h1h = b1.hash();
            let h2h = b2.hash();
            inner.blocks.insert(h1h, b1.clone());
            inner.blocks.insert(h2h, b2.clone());
            inner.height_to_hash.insert(h1, h1h);
            inner.height_to_hash.insert(h2, h2h);
            inner.tip.hash = h2h;
            inner.tip.height = h2;
            inner.stats.height = h2;
            inner.stats.tip_hash = h2h;
            inner.stats.total_supply = u64::MAX as u128; // headroom for emission subtract
            inner.stats.total_burned = burn1 + burn2; // headroom for burn subtract
            // Advance the block/tx counters exactly as the connect path would.
            inner.stats.total_blocks = base_blocks + 2;
            inner.stats.total_transactions = base_txs + added_txs;
        }

        chain.rollback_to_height(0).expect("rollback to genesis");
        assert_eq!(chain.tip_hash(), genesis_hash, "tip back at genesis");
        assert_eq!(
            chain.stats().total_blocks,
            base_blocks,
            "total_blocks must unwind to the pre-staging base after a full rollback"
        );
        assert_eq!(
            chain.stats().total_transactions,
            base_txs,
            "total_transactions must unwind to the pre-staging base after a full rollback"
        );
    }

    #[test]
    fn rollback_to_height_disconnects_db_only_blocks_past_the_cache() {
        // Regression (junbyjun1238, PR #48): deep rollbacks target heights below
        // the ~200-block in-memory cache window, so the blocks being disconnected
        // live only in the DB. Their UTXO / supply / burn / total_difficulty must
        // still be reverted. Stage two fee-carrying blocks in the DB ONLY (never
        // the in-memory cache — the cache-evicted condition), advance the
        // accumulators as the connect path would, then roll back to genesis.
        // Before the fix the cache-only lookup skipped these blocks entirely,
        // leaving state over-counted while the tip still moved down; now the
        // disconnect loop falls back to the DB.
        let dir = tempfile::tempdir().unwrap();
        let db = Arc::new(Database::open(dir.path()).unwrap());
        let chain = Blockchain::with_database(Arc::clone(&db), NetworkType::Testnet);
        let genesis_hash = chain.init_genesis().unwrap();

        // Resolve activation + burn from the chain's runtime network (Testnet
        // here), matching what the chain's disconnect path uses.
        let net = chain.network();
        let act = net.fee_distribution_height();
        let h1 = act.max(1);
        let h2 = h1 + 1;
        let b1 = burn_test_block(h1, 31, &[3_000_000]);
        let b2 = burn_test_block(h2, 32, &[5_000_000]);
        let burn1 = block_fee_burn(net, &b1);
        let burn2 = block_fee_burn(net, &b2);
        let diff1 = calculate_difficulty_from_target(&b1.header.target);
        let diff2 = calculate_difficulty_from_target(&b2.header.target);
        assert!(burn1 > 0 && burn2 > 0, "staged blocks must burn fees");

        // DB-ONLY: bodies + height index into the DB; deliberately NOT into
        // inner.blocks / inner.height_to_hash (simulating cache eviction).
        db.blocks.insert(&b1).unwrap();
        db.blocks.insert(&b2).unwrap();
        db.blocks.set_height_hash(h1, &b1.hash()).unwrap();
        db.blocks.set_height_hash(h2, &b2.hash()).unwrap();

        let base_supply;
        let base_diff;
        {
            let mut inner = chain.inner.write();
            base_supply = inner.stats.total_supply;
            base_diff = inner.stats.total_difficulty;
            inner.tip.hash = b2.hash();
            inner.tip.height = h2;
            inner.stats.height = h2;
            inner.stats.tip_hash = b2.hash();
            inner.stats.total_supply = base_supply
                + calculate_block_reward(h1).as_atomic() as u128
                + calculate_block_reward(h2).as_atomic() as u128;
            inner.stats.total_burned += burn1 + burn2;
            inner.stats.total_difficulty = base_diff + diff1 + diff2;
        }
        let burned_before = chain.stats().total_burned;

        chain
            .rollback_to_height(0)
            .expect("deep rollback to genesis (DB-only blocks)");

        assert_eq!(chain.tip_hash(), genesis_hash, "tip back at genesis");
        assert_eq!(
            chain.stats().total_supply,
            base_supply,
            "supply reverted through the DB-fallback disconnect"
        );
        assert_eq!(
            chain.stats().total_burned,
            burned_before - burn1 - burn2,
            "burn reverted through the DB-fallback disconnect"
        );
        assert_eq!(
            chain.stats().total_difficulty,
            base_diff,
            "total_difficulty reverted through the DB-fallback disconnect"
        );
    }

    // ═══════════════════════════════════════════════════════════════════════
    // State-machine gap tests (audit test-plan docs/audit/test-plan/
    // chain-storage.md). These cover the add_block / fork-choice / rollback /
    // load / helper branches that are exercisable WITHOUT real PoW mining:
    // graph-walk helpers (find_fork_point, collect_fork_chain,
    // calculate_fork_cumulative_work, recompute_total_difficulty), the
    // AlreadyKnown cache/DB branches, load_from_database error branches, the
    // rollback finality floor + orphaned-tx return, and is_spent branches.
    //
    // The PoW-gated items (accepted reorg re-applying real txs, chain-level
    // ReorgTooDeep / AcceptedFork / tiebreak) live in
    // tests/chain_statemachine.rs, marked #[ignore] like the reorg e2e harness.
    // ═══════════════════════════════════════════════════════════════════════

    /// Clone the genesis block and rewrite only the header identity fields
    /// (height / prev_hash / nonce) to fabricate a distinct block for the pure
    /// prev_hash-walk helpers. The body is the real genesis coinbase, which is
    /// irrelevant to find_fork_point / collect_fork_chain /
    /// calculate_fork_cumulative_work (they only read header + storage links).
    fn walk_block(height: u64, prev_hash: Hash, nonce: u64) -> Block {
        let mut b = create_genesis_block();
        b.header.height = height;
        b.header.prev_hash = prev_hash;
        b.header.nonce = nonce;
        b
    }

    #[test]
    fn add_block_duplicate_in_memory_cache_returns_already_known() {
        // add_block's first check is the in-memory cache: a hash already present
        // short-circuits to AlreadyKnown before any parent/validation work.
        let chain = Blockchain::new();
        let b = walk_block(5, Hash::from_bytes([0x07; 32]), 42);
        let h = b.hash();
        {
            let mut inner = chain.inner.write();
            inner.blocks.insert(h, b.clone());
        }
        assert!(matches!(
            chain.add_block(b).unwrap(),
            BlockStatus::AlreadyKnown
        ));
    }

    #[test]
    fn add_block_duplicate_in_db_not_cache_returns_already_known() {
        // Second AlreadyKnown branch: block absent from the in-memory cache but
        // present in the DB (db.blocks.contains) — the post-restart replay case.
        let dir = tempfile::tempdir().unwrap();
        let db = Arc::new(Database::open(dir.path()).unwrap());
        let chain = Blockchain::with_database(Arc::clone(&db), NetworkType::Testnet);
        let b = walk_block(5, Hash::from_bytes([0x07; 32]), 43);
        db.blocks.insert(&b).unwrap();
        // Deliberately NOT inserted into the in-memory cache.
        assert!(matches!(
            chain.add_block(b).unwrap(),
            BlockStatus::AlreadyKnown
        ));
    }

    #[test]
    fn find_fork_point_returns_common_ancestor_and_genesis() {
        let chain = Blockchain::new();
        let genesis_hash = chain.init_genesis().unwrap();

        // Main chain m1(h1), m2(h2).
        let m1 = walk_block(1, genesis_hash, 101);
        let m2 = walk_block(2, m1.hash(), 102);
        {
            let mut inner = chain.inner.write();
            inner.blocks.insert(m1.hash(), m1.clone());
            inner.height_to_hash.insert(1, m1.hash());
            inner.blocks.insert(m2.hash(), m2.clone());
            inner.height_to_hash.insert(2, m2.hash());
        }

        // A competing fork block at height 2 off m1 → common ancestor is m1 (1).
        let f2 = walk_block(2, m1.hash(), 202);
        {
            let mut inner = chain.inner.write();
            inner.blocks.insert(f2.hash(), f2.clone());
        }
        assert_eq!(chain.find_fork_point(&f2), Some(1));

        // A fork block at height 1 off genesis → fork point is genesis (0).
        let f1 = walk_block(1, genesis_hash, 201);
        {
            let mut inner = chain.inner.write();
            inner.blocks.insert(f1.hash(), f1.clone());
        }
        assert_eq!(chain.find_fork_point(&f1), Some(0));
    }

    #[test]
    fn find_fork_point_detects_cycle_returns_none() {
        // A prev_hash cycle (corruption) must be reported as None, not masked as
        // a genesis fork point. Blocks are stored under arbitrary map keys so the
        // links form a genuine cycle the visited-set guard must catch.
        let chain = Blockchain::new();
        let key_a = Hash::from_bytes([0xA1; 32]);
        let key_b = Hash::from_bytes([0xB2; 32]);
        let block_a = walk_block(5, key_b, 1); // prev → key_b
        let block_b = walk_block(4, key_a, 2); // prev → key_a  (cycle)
        {
            let mut inner = chain.inner.write();
            inner.blocks.insert(key_a, block_a);
            inner.blocks.insert(key_b, block_b);
        }
        let fork = walk_block(6, key_a, 3); // enters the cycle at key_a
        assert_eq!(chain.find_fork_point(&fork), None);
    }

    #[test]
    fn find_fork_point_missing_parent_returns_none() {
        // prev_hash references a block that is not in storage → None (corruption),
        // not a silent genesis fork point.
        let chain = Blockchain::new();
        let fork = walk_block(3, Hash::from_bytes([0xCC; 32]), 9);
        assert_eq!(chain.find_fork_point(&fork), None);
    }

    #[test]
    fn collect_fork_chain_returns_ascending_and_stops_at_fork_point() {
        let chain = Blockchain::new();
        let genesis_hash = chain.init_genesis().unwrap();
        let m1 = walk_block(1, genesis_hash, 11);
        {
            let mut inner = chain.inner.write();
            inner.blocks.insert(m1.hash(), m1.clone());
            inner.height_to_hash.insert(1, m1.hash());
        }
        let f2 = walk_block(2, m1.hash(), 22);
        let f3 = walk_block(3, f2.hash(), 33);
        let f4 = walk_block(4, f3.hash(), 44);
        {
            let mut inner = chain.inner.write();
            inner.blocks.insert(f2.hash(), f2.clone());
            inner.blocks.insert(f3.hash(), f3.clone());
            inner.blocks.insert(f4.hash(), f4.clone());
        }
        // Collect from fork tip f4 down to fork_point=1. Returns ascending order,
        // excluding both the tip (f4) and the fork point.
        let collected = chain.collect_fork_chain(&f4, 1);
        let heights: Vec<u64> = collected.iter().map(|b| b.header.height).collect();
        assert_eq!(heights, vec![2, 3]);

        // Missing parent link → the walk breaks immediately, returning empty.
        let orphan_tip = walk_block(9, Hash::from_bytes([0xEE; 32]), 99);
        assert!(chain.collect_fork_chain(&orphan_tip, 1).is_empty());
    }

    #[test]
    fn calculate_fork_cumulative_work_parent_not_found_returns_partial() {
        // The walk breaks when a parent is absent, returning only the starting
        // block's own work (the genesis base +1 is never added).
        let chain = Blockchain::new();
        let b = walk_block(3, Hash::from_bytes([0xAB; 32]), 7);
        let expected = calculate_difficulty_from_target(&b.header.target);
        assert_eq!(chain.calculate_fork_cumulative_work(&b), expected);
    }

    #[test]
    fn calculate_fork_cumulative_work_cycle_breaks_at_max_steps() {
        // A prev_hash cycle must terminate via the max_steps guard rather than
        // hang, returning accumulated partial work.
        let chain = Blockchain::new();
        let key_a = Hash::from_bytes([0x5A; 32]);
        let key_b = Hash::from_bytes([0x5B; 32]);
        let a = walk_block(1, key_b, 1); // height 1 → never treated as genesis
        let b = walk_block(1, key_a, 2);
        {
            let mut inner = chain.inner.write();
            inner.blocks.insert(key_a, a);
            inner.blocks.insert(key_b, b);
        }
        let start = walk_block(1, key_a, 3);
        let work = chain.calculate_fork_cumulative_work(&start);
        assert!(
            work >= calculate_difficulty_from_target(&start.header.target),
            "cycle walk terminates and returns accumulated partial work"
        );
    }

    #[test]
    fn recompute_total_difficulty_missing_mid_range_returns_none() {
        // A gap anywhere in [1, height] yields None so the caller keeps the
        // stored value instead of persisting a wrong partial sum.
        let chain = Blockchain::new();
        let genesis_hash = chain.init_genesis().unwrap();
        let m1 = walk_block(1, genesis_hash, 71);
        {
            let mut inner = chain.inner.write();
            inner.blocks.insert(m1.hash(), m1.clone());
            inner.height_to_hash.insert(1, m1.hash());
        }
        assert_eq!(
            chain.recompute_total_difficulty(1),
            Some(1 + calculate_difficulty_from_target(&m1.header.target)),
        );
        // Height 2 absent → None.
        assert_eq!(chain.recompute_total_difficulty(2), None);
    }

    #[test]
    fn is_spent_no_db_false_and_in_memory_hit_true() {
        let chain = Blockchain::new(); // db = None
        let ki = KeyImage::from_bytes([0x11; 32]);
        assert!(!chain.is_spent(&ki), "empty set, no DB → not spent");
        {
            let mut inner = chain.inner.write();
            inner.utxos.mark_key_image_spent(ki);
        }
        assert!(chain.is_spent(&ki), "in-memory marked key image → spent");
    }

    #[test]
    fn is_spent_db_fallback_true() {
        // Empty in-memory set (output_count 0, key image absent) falls through to
        // the persistent DB lookup — the fresh-startup-before-rebuild path.
        let dir = tempfile::tempdir().unwrap();
        let db = Arc::new(Database::open(dir.path()).unwrap());
        let chain = Blockchain::with_database(Arc::clone(&db), NetworkType::Testnet);
        let ki = KeyImage::from_bytes([0x22; 32]);
        db.utxos.mark_key_image(&ki).unwrap();
        assert!(chain.is_spent(&ki), "DB-marked key image found via fallback");
    }

    #[test]
    fn load_from_database_rejects_missing_genesis_height_entry() {
        // Chain state present but the height index has no genesis (height-0)
        // entry → Err("no genesis entry"), never a spurious Fresh.
        let dir = tempfile::tempdir().unwrap();
        let db = Arc::new(Database::open(dir.path()).unwrap());
        let genesis = crate::testnet::testnet_genesis();
        db.blocks.insert(&genesis).unwrap();
        db.state.save_state(&state_for_genesis(&genesis)).unwrap();
        // Deliberately NO set_height_hash(0, ..).
        let chain = Blockchain::with_database(db, NetworkType::Testnet);
        let error = chain.load_from_database().unwrap_err().to_string();
        assert!(
            error.contains("no genesis entry"),
            "unexpected error: {error}"
        );
    }

    #[test]
    fn load_from_database_rejects_state_height_mismatch_with_tip_block() {
        // state.tip_hash resolves to a real block, but state.height disagrees
        // with that block's header height → Err (guards against a truncated /
        // corrupt state record silently loading at the wrong height).
        let dir = tempfile::tempdir().unwrap();
        let db = Arc::new(Database::open(dir.path()).unwrap());
        let genesis = crate::testnet::testnet_genesis();
        let genesis_hash = genesis.hash();
        db.blocks.insert(&genesis).unwrap();
        db.blocks.set_height_hash(0, &genesis_hash).unwrap();
        let state = ChainStateData {
            tip_hash: genesis_hash, // resolves to the genesis block (height 0)
            height: 5,              // …but state claims height 5
            ..state_for_genesis(&genesis)
        };
        db.state.save_state(&state).unwrap();
        let chain = Blockchain::with_database(db, NetworkType::Testnet);
        let error = chain.load_from_database().unwrap_err().to_string();
        assert!(
            error.contains("does not match tip block height"),
            "unexpected error: {error}"
        );
    }

    #[test]
    fn rollback_to_height_rejects_target_below_last_checkpoint() {
        // FINALITY: rollback below the persisted last_checkpoint is refused with
        // Err(InvalidState) and mutates nothing.
        let dir = tempfile::tempdir().unwrap();
        let db = Arc::new(Database::open(dir.path()).unwrap());
        let chain = Blockchain::with_database(Arc::clone(&db), NetworkType::Testnet);
        let genesis = crate::testnet::testnet_genesis();
        let state = ChainStateData {
            last_checkpoint: 5,
            ..state_for_genesis(&genesis)
        };
        db.state.save_state(&state).unwrap();
        // Pretend the live tip sits at height 10.
        {
            let mut inner = chain.inner.write();
            inner.tip.height = 10;
            inner.stats.height = 10;
        }
        let err = chain.rollback_to_height(3).unwrap_err();
        assert!(matches!(err, Error::InvalidState(_)), "got {err:?}");
        assert!(err.to_string().contains("finality"), "{err}");
        assert_eq!(chain.height(), 10, "finality rejection must not mutate the tip");
    }

    #[test]
    fn rollback_to_height_returns_non_coinbase_txs_as_orphaned() {
        // Disconnecting blocks with real non-coinbase txs must return exactly
        // those txs (for mempool restoration) and never the coinbases.
        let chain = Blockchain::new();
        chain.init_genesis().unwrap();
        let genesis_hash = chain.tip_hash();

        let b1 = burn_test_block(1, 51, &[1_000_000]);
        let b2 = burn_test_block(2, 52, &[2_000_000]);
        let want: Vec<Hash> = [&b1, &b2]
            .iter()
            .flat_map(|b| {
                b.transactions
                    .iter()
                    .filter(|t| !t.is_coinbase())
                    .map(|t| t.hash())
            })
            .collect();
        assert_eq!(want.len(), 2, "each staged block carries one non-coinbase tx");

        {
            let mut inner = chain.inner.write();
            for (h, b) in [(1u64, &b1), (2u64, &b2)] {
                inner.blocks.insert(b.hash(), b.clone());
                inner.height_to_hash.insert(h, b.hash());
            }
            inner.tip.hash = b2.hash();
            inner.tip.height = 2;
            inner.stats.height = 2;
            inner.stats.tip_hash = b2.hash();
            // Ample headroom so the emission/burn checked_subs never underflow
            // regardless of the compiled fee-distribution activation height.
            inner.stats.total_supply = u64::MAX as u128;
            inner.stats.total_burned = u64::MAX as u128;
        }

        let orphaned = chain.rollback_to_height(0).unwrap();
        assert_eq!(orphaned.len(), 2);
        assert!(orphaned.iter().all(|t| !t.is_coinbase()), "no coinbase returned");
        let got: Vec<Hash> = orphaned.iter().map(|t| t.hash()).collect();
        for w in &want {
            assert!(got.contains(w), "missing an orphaned non-coinbase tx");
        }
        assert_eq!(chain.tip_hash(), genesis_hash, "tip reset to genesis");
    }
}
