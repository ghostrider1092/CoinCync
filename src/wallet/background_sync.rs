//! Background wallet synchronization with progress tracking
//!
//! Provides non-blocking wallet sync with real-time progress updates.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use tokio::sync::{mpsc, watch};
#[allow(unused_imports)]
use crate::primitives::Hash;
use crate::consensus::Block;
use crate::error::Result;


/// Sync progress information
#[derive(Clone, Debug)]
pub struct SyncProgress {
    /// Current height being scanned
    pub current_height: u64,
    /// Target height (chain tip)
    pub target_height: u64,
    /// Blocks scanned in this session
    pub blocks_scanned: u64,
    /// Outputs found in this session
    pub outputs_found: u64,
    /// Scan rate (blocks per second)
    pub blocks_per_second: f64,
    /// Estimated time remaining in seconds
    pub eta_seconds: Option<u64>,
    /// Whether sync is complete
    pub is_complete: bool,
    /// Whether sync is paused
    pub is_paused: bool,
    /// Last error message
    pub last_error: Option<String>,
    /// Height at which the most recent reorg was detected, if any.
    /// Set by the orchestrator (Task #5) after a successful reorg
    /// recovery. Surfaced to the UI for the reorg-notification banner.
    pub last_reorg_at_height: Option<u64>,
    /// Number of blocks rewound in the most recent reorg recovery.
    /// `last_reorg_at_height - new_height` post-recovery.
    pub last_reorg_depth: Option<u64>,
}

impl Default for SyncProgress {
    fn default() -> Self {
        SyncProgress {
            current_height: 0,
            target_height: 0,
            blocks_scanned: 0,
            outputs_found: 0,
            blocks_per_second: 0.0,
            eta_seconds: None,
            is_complete: false,
            is_paused: false,
            last_error: None,
            last_reorg_at_height: None,
            last_reorg_depth: None,
        }
    }
}

impl SyncProgress {
    /// Get percentage complete (0.0 to 100.0)
    pub fn percent_complete(&self) -> f64 {
        if self.target_height == 0 {
            return 0.0;
        }
        (self.current_height as f64 / self.target_height as f64 * 100.0).min(100.0)
    }

    /// Get remaining blocks
    pub fn remaining_blocks(&self) -> u64 {
        self.target_height.saturating_sub(self.current_height)
    }
}

/// Background sync configuration
#[derive(Clone, Debug)]
pub struct BackgroundSyncConfig {
    /// Batch size for block scanning
    pub batch_size: usize,
    /// How often to persist state (in blocks)
    pub persist_interval: u64,
    /// How often to send progress updates (in blocks)
    pub progress_interval: u64,
    /// Maximum blocks to process per second (0 = unlimited)
    pub rate_limit: u64,
    /// Whether to use parallel scanning
    pub parallel: bool,
    /// Number of parallel workers
    pub workers: usize,
    /// Task #6: how often to poll the node for the block hash at the
    /// scanner's current tip. Mismatch triggers reorg recovery — this
    /// is the only signal the wallet has for a reorg that happened
    /// while it was offline (scan_block_v2 only fires when a new block
    /// arrives). 30s is a balance between recovery latency and RPC
    /// load. Set to 0 to disable the poll entirely.
    pub tip_check_interval_secs: u64,
}

impl Default for BackgroundSyncConfig {
    fn default() -> Self {
        BackgroundSyncConfig {
            batch_size: 100,
            persist_interval: 100,
            progress_interval: 10,
            rate_limit: 0,
            parallel: true,
            workers: num_cpus::get().max(1),
            tip_check_interval_secs: 30,
        }
    }
}

/// Commands for controlling background sync
#[derive(Clone, Debug)]
pub enum SyncCommand {
    /// Start/resume sync
    Start,
    /// Pause sync
    Pause,
    /// Stop sync completely
    Stop,
    /// Update target height
    UpdateTarget(u64),
    /// Force rescan from height
    RescanFrom(u64),
}

/// Background sync controller
pub struct BackgroundSyncController {
    /// Command channel
    command_tx: mpsc::Sender<SyncCommand>,
    /// Progress receiver
    progress_rx: watch::Receiver<SyncProgress>,
    /// Whether sync is running
    is_running: Arc<AtomicBool>,
}

impl BackgroundSyncController {
    /// Start sync
    pub async fn start(&self) -> Result<()> {
        self.command_tx.send(SyncCommand::Start).await
            .map_err(|_| crate::error::Error::InvalidState("Sync task not running".into()))
    }

    /// Pause sync
    pub async fn pause(&self) -> Result<()> {
        self.command_tx.send(SyncCommand::Pause).await
            .map_err(|_| crate::error::Error::InvalidState("Sync task not running".into()))
    }

    /// Stop sync
    pub async fn stop(&self) -> Result<()> {
        self.command_tx.send(SyncCommand::Stop).await
            .map_err(|_| crate::error::Error::InvalidState("Sync task not running".into()))
    }

    /// Get current progress
    pub fn progress(&self) -> SyncProgress {
        self.progress_rx.borrow().clone()
    }

    /// Check if sync is running
    pub fn is_running(&self) -> bool {
        self.is_running.load(Ordering::Relaxed)
    }

    /// Wait for progress update
    pub async fn wait_for_update(&mut self) -> SyncProgress {
        let _ = self.progress_rx.changed().await;
        self.progress_rx.borrow().clone()
    }
}

/// Block batch for efficient scanning
pub struct BlockBatch {
    /// Blocks in this batch
    pub blocks: Vec<Block>,
    /// Starting height
    pub start_height: u64,
    /// Ending height
    pub end_height: u64,
}

impl BlockBatch {
    /// Create new batch
    pub fn new(blocks: Vec<Block>, start_height: u64) -> Self {
        let end_height = start_height + blocks.len() as u64;
        BlockBatch {
            blocks,
            start_height,
            end_height,
        }
    }

    /// Get batch size
    pub fn len(&self) -> usize {
        self.blocks.len()
    }

    /// Check if empty
    pub fn is_empty(&self) -> bool {
        self.blocks.is_empty()
    }
}

/// Background sync state machine
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SyncState {
    /// Not started
    Idle,
    /// Syncing blocks
    Syncing,
    /// Paused
    Paused,
    /// Completed
    Complete,
    /// Error state
    Error,
}

/// Background sync manager
pub struct BackgroundSyncManager {
    /// Current state
    state: SyncState,
    /// Current height
    current_height: u64,
    /// Target height
    target_height: u64,
    /// Configuration
    config: BackgroundSyncConfig,
    /// Statistics
    stats: SyncStats,
    /// Is running flag
    is_running: Arc<AtomicBool>,
    /// Last error message — surfaced via [`Self::progress`] in
    /// `SyncProgress::last_error` so the UI can show *why* sync entered
    /// `SyncState::Error`. Previously [`Self::record_error`] dropped its
    /// `msg` argument on the floor and the operator saw only "Error"
    /// with no explanation.
    last_error: Option<String>,
    /// Most-recent reorg-recovery stats. Surfaced via `SyncProgress`
    /// so the UI can display the reorg-notification banner. Cleared
    /// when the user dismisses the banner (`clear_reorg_stats`).
    last_reorg: Option<ReorgRecoveryStats>,
}

/// Sync statistics
#[derive(Clone, Debug, Default)]
pub struct SyncStats {
    /// Total blocks scanned
    pub blocks_scanned: u64,
    /// Total outputs found
    pub outputs_found: u64,
    /// Total transactions scanned
    pub transactions_scanned: u64,
    /// Start time (unix timestamp)
    pub start_time: u64,
    /// Total scan time in milliseconds
    pub scan_time_ms: u64,
}

impl SyncStats {
    /// Calculate blocks per second
    pub fn blocks_per_second(&self) -> f64 {
        if self.scan_time_ms == 0 {
            return 0.0;
        }
        (self.blocks_scanned as f64) / (self.scan_time_ms as f64 / 1000.0)
    }

    /// Calculate transactions per second
    pub fn txs_per_second(&self) -> f64 {
        if self.scan_time_ms == 0 {
            return 0.0;
        }
        (self.transactions_scanned as f64) / (self.scan_time_ms as f64 / 1000.0)
    }
}

impl BackgroundSyncManager {
    /// Create new sync manager
    pub fn new(config: BackgroundSyncConfig) -> Self {
        BackgroundSyncManager {
            state: SyncState::Idle,
            current_height: 0,
            target_height: 0,
            config,
            stats: SyncStats::default(),
            is_running: Arc::new(AtomicBool::new(false)),
            last_error: None,
            last_reorg: None,
        }
    }

    /// Start syncing from given height
    pub fn start(&mut self, from_height: u64, target_height: u64) {
        self.current_height = from_height;
        self.target_height = target_height;
        self.state = SyncState::Syncing;
        self.is_running.store(true, Ordering::Relaxed);
        self.stats.start_time = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
    }

    /// Pause syncing
    pub fn pause(&mut self) {
        if self.state == SyncState::Syncing {
            self.state = SyncState::Paused;
        }
    }

    /// Resume syncing
    pub fn resume(&mut self) {
        if self.state == SyncState::Paused {
            self.state = SyncState::Syncing;
        }
    }

    /// Stop syncing
    pub fn stop(&mut self) {
        self.state = SyncState::Idle;
        self.is_running.store(false, Ordering::Relaxed);
    }

    /// Update after processing blocks
    pub fn update_progress(&mut self, blocks_processed: u64, outputs_found: u64, txs_scanned: u64) {
        self.current_height += blocks_processed;
        self.stats.blocks_scanned += blocks_processed;
        self.stats.outputs_found += outputs_found;
        self.stats.transactions_scanned += txs_scanned;

        if self.current_height >= self.target_height {
            self.state = SyncState::Complete;
            self.is_running.store(false, Ordering::Relaxed);
        }
    }

    /// Update target height
    pub fn update_target(&mut self, target: u64) {
        self.target_height = target;
        if self.state == SyncState::Complete && target > self.current_height {
            self.state = SyncState::Syncing;
            self.is_running.store(true, Ordering::Relaxed);
        }
    }

    /// Get current progress
    pub fn progress(&self) -> SyncProgress {
        let remaining = self.target_height.saturating_sub(self.current_height);
        let bps = self.stats.blocks_per_second();
        let eta = if bps > 0.0 {
            Some((remaining as f64 / bps) as u64)
        } else {
            None
        };

        SyncProgress {
            current_height: self.current_height,
            target_height: self.target_height,
            blocks_scanned: self.stats.blocks_scanned,
            outputs_found: self.stats.outputs_found,
            blocks_per_second: bps,
            eta_seconds: eta,
            is_complete: self.state == SyncState::Complete,
            is_paused: self.state == SyncState::Paused,
            last_error: self.last_error.clone(),
            last_reorg_at_height: self.last_reorg.as_ref().map(|r| r.reorg_at_height),
            last_reorg_depth: self.last_reorg.as_ref().map(|r| r.depth),
        }
    }

    /// Get current state
    pub fn state(&self) -> SyncState {
        self.state
    }

    /// Should continue syncing?
    pub fn should_continue(&self) -> bool {
        self.state == SyncState::Syncing
    }

    /// Get next batch height range
    pub fn next_batch_range(&self) -> Option<(u64, u64)> {
        if !self.should_continue() {
            return None;
        }

        let start = self.current_height;
        let end = (start + self.config.batch_size as u64).min(self.target_height);

        if start >= end {
            return None;
        }

        Some((start, end))
    }

    /// Record an error and stash the message for the next [`Self::progress`]
    /// call. The UI's sync indicator reads `progress.last_error` to show
    /// the operator why sync stopped; without this stash the operator
    /// sees a generic "Error" state with no diagnostic.
    pub fn record_error(&mut self, msg: String) {
        self.state = SyncState::Error;
        self.last_error = Some(msg);
    }

    /// Clear the recorded error (call when sync resumes).
    pub fn clear_error(&mut self) {
        self.last_error = None;
    }

    /// Rewind the manager's view of `current_height` to `new_height`
    /// after a successful reorg recovery. Resets state to `Syncing` so
    /// the loop continues from `new_height + 1` toward the existing
    /// target. Used by the orchestrator (Task #5) after
    /// `BlockScanner::handle_reorg_recovery` resolves.
    pub fn rewind_to(&mut self, new_height: u64) {
        if new_height < self.current_height {
            self.current_height = new_height;
        }
        // A reorg recovery should resume sync regardless of prior state
        // (could have been Complete if reorg arrived after we caught up).
        self.state = SyncState::Syncing;
        self.is_running.store(true, Ordering::Relaxed);
    }

    /// Stash reorg-recovery stats so the next `progress()` call surfaces
    /// them through `SyncProgress::last_reorg_*`. The UI uses these to
    /// render the reorg-notification banner.
    pub fn record_reorg_stats(&mut self, stats: ReorgRecoveryStats) {
        self.last_reorg = Some(stats);
    }

    /// Clear the stashed reorg stats (call after the UI banner has
    /// been dismissed by the user or after a configurable display
    /// window has elapsed).
    pub fn clear_reorg_stats(&mut self) {
        self.last_reorg = None;
    }
}

/// Outcome of a single block scan. Task #5 (reorg-aware orchestrator)
/// adds `ReorgDetected` so the sync loop can branch into the recovery
/// path: query `find_fork_point`, rewind the wallet state, restart sync.
#[derive(Clone, Debug)]
pub enum ScanBlockOutcome {
    /// Normal scan path. Same counts the legacy `scan_block` returned.
    Scanned {
        outputs: u64,
        txs: u64,
    },
    /// The wallet scanner detected a chain reorg while applying this
    /// block. Carries the wallet's most-recent canonical `(height, hash)`
    /// — the orchestrator passes this pair to `BlockFetcher::find_fork_point`
    /// to learn the height at which the wallet's view diverged from the
    /// chain's current view.
    ReorgDetected {
        /// Height the incoming block claimed (one past the wallet's
        /// last-known canonical block — that's why the prev-hash check
        /// failed).
        at_height: u64,
        /// Wallet's most-recent canonical height.
        known_height: u64,
        /// Wallet's most-recent canonical block hash.
        known_hash: Hash,
    },
}

/// Statistics from a successful reorg-recovery pass. Surfaced through
/// `SyncProgress` (Task #7) so the wallet UI can render the
/// reorg-notification banner with the right depth + height.
#[derive(Clone, Debug, Default)]
pub struct ReorgRecoveryStats {
    /// Height at which the reorg was detected (= `ScanBlockOutcome::ReorgDetected.at_height`).
    pub reorg_at_height: u64,
    /// New canonical height after rewind. The next block to scan is `new_height + 1`.
    pub new_height: u64,
    /// Depth of the reorg = `reorg_at_height - new_height`. The UI's
    /// banner reads this for "Chain reorg detected at depth N — balance
    /// updated". Stored explicitly to avoid arithmetic in callers.
    pub depth: u64,
    /// Number of UTXOs the wallet dropped during rewind.
    pub utxos_removed: u64,
    /// Number of UTXOs the wallet unspent (from orphaned outgoing txs).
    pub utxos_unspent: u64,
}

/// Trait for fetching blocks during sync (implemented by RPC clients, direct DB access, etc.)
#[async_trait::async_trait]
pub trait BlockFetcher: Send + Sync {
    /// Fetch a block by height. Returns None if not available.
    async fn fetch_block(&self, height: u64) -> std::result::Result<Option<Block>, String>;
    /// Get the current chain tip height.
    async fn get_chain_height(&self) -> std::result::Result<u64, String>;
    /// Get the block hash at `height` (used by the periodic tip-hash
    /// poll in Task #6 to catch reorgs the wallet missed while offline).
    /// Default impl returns Err — implementors that opt into reorg
    /// recovery override this.
    async fn get_block_hash_at(&self, _height: u64) -> std::result::Result<Option<Hash>, String> {
        Err("get_block_hash_at not implemented".into())
    }
    /// Ask the node whether the wallet's `(known_hash, known_height)`
    /// pair is still on the canonical chain. Returns:
    ///   - `Ok(Some(fork_height))` — last common-ancestor height (the
    ///     wallet should rewind down to this height and resume scanning
    ///     from `fork_height + 1`)
    ///   - `Ok(None)` — no fork point found in the searchable window;
    ///     wallet must fall back to a full rescan from the most recent
    ///     hardcoded checkpoint
    ///   - `Err(_)` — RPC transport / node error
    ///
    /// Default impl returns Err — RPC-backed implementors override.
    async fn find_fork_point(
        &self,
        _known_hash: Hash,
        _known_height: u64,
    ) -> std::result::Result<Option<u64>, String> {
        Err("find_fork_point not implemented for this BlockFetcher".into())
    }
}

/// Trait for processing scanned blocks (wallet-specific scanning logic)
pub trait BlockScanner: Send {
    /// Scan a block for wallet-relevant outputs. Returns (outputs_found, txs_scanned).
    fn scan_block(&mut self, block: &Block, height: u64) -> (u64, u64);
    /// Persist current wallet state (called periodically).
    fn persist_state(&mut self, height: u64) -> Result<()>;
    /// Reorg-aware extension to `scan_block`. Default delegates and
    /// always returns `Scanned`. Implementors that route through a
    /// reorg-aware scanner (one with `BlockApplyDiff` journal +
    /// `scan_block_with_result`) override this to surface
    /// `ReorgDetected` so the sync loop can trigger recovery.
    fn scan_block_v2(&mut self, block: &Block, height: u64) -> ScanBlockOutcome {
        let (outputs, txs) = self.scan_block(block, height);
        ScanBlockOutcome::Scanned { outputs, txs }
    }
    /// Apply a reorg rewind to all wallet state layers (scanner journal +
    /// balance UTXOs + history records). Called by the sync loop after
    /// `find_fork_point` resolves the rewind target. Returns the stats
    /// used to populate `SyncProgress::last_reorg_*` for the UI.
    ///
    /// Default impl returns Err — only implementors that have wired
    /// the full Task #3b + #1b machinery should override.
    fn handle_reorg_recovery(
        &mut self,
        fork_height: u64,
    ) -> std::result::Result<ReorgRecoveryStats, String> {
        Err(format!(
            "handle_reorg_recovery not implemented; cannot rewind to fork_height={}",
            fork_height
        ))
    }

    /// The scanner's most-recent canonical `(height, hash)` pair. Used
    /// by the periodic tip-hash poll (Task #6) to ask the node "is the
    /// block at MY current tip height still your block at that height?"
    /// — catches the offline-during-reorg case that scan_block_v2 alone
    /// would miss (since scan_block_v2 only fires on incoming blocks,
    /// and an offline wallet doesn't receive any).
    ///
    /// Default returns `(0, Hash::zero())` so legacy scanners that
    /// don't track per-block state simply opt out of the periodic
    /// check (the wallet will fall back to `scan_block_v2` detection
    /// when sync resumes).
    fn current_position(&self) -> (u64, Hash) {
        (0, Hash::zero())
    }
}

/// Shared reorg-recovery dispatch used by both Task #5 (scan-detected)
/// and Task #6 (periodic tip-hash poll). Asks the node for the fork
/// point, then asks the scanner to rewind to it. Returns:
///   - `Ok(Some(stats))` — recovery succeeded; caller applies
///     `manager.rewind_to(stats.new_height)` + `record_reorg_stats(stats)`
///   - `Ok(None)` — fork point is below the searchable window; caller
///     must surface as error and prompt full rescan
///   - `Err(_)` — RPC transport / scanner-side error
async fn try_reorg_recovery(
    fetcher: &dyn BlockFetcher,
    scanner: &mut Box<dyn BlockScanner>,
    known_hash: Hash,
    known_height: u64,
    at_height: u64,
) -> std::result::Result<Option<ReorgRecoveryStats>, String> {
    match fetcher.find_fork_point(known_hash, known_height).await {
        Ok(Some(fork_height)) => match scanner.handle_reorg_recovery(fork_height) {
            Ok(mut stats) => {
                // Backfill the detection-height from the caller, since
                // the scanner can't know it (the journal entry it just
                // rewound from didn't capture the "incoming block that
                // tripped detection" height — only the wallet's own
                // last-canonical height).
                stats.reorg_at_height = at_height;
                Ok(Some(stats))
            }
            Err(e) => Err(format!(
                "handle_reorg_recovery failed at fork_height {}: {}",
                fork_height, e
            )),
        },
        Ok(None) => Ok(None),
        Err(e) => Err(format!("find_fork_point failed: {}", e)),
    }
}

/// Spawn background sync and return a controller for managing it.
///
/// This creates the actual sync loop that:
/// 1. Fetches blocks in batches from the block source
/// 2. Scans each block for wallet-relevant outputs
/// 3. Reports progress via the watch channel
/// 4. Persists state at configured intervals
/// 5. Responds to start/pause/stop commands
pub fn spawn_background_sync(
    config: BackgroundSyncConfig,
    fetcher: Arc<dyn BlockFetcher>,
    mut scanner: Box<dyn BlockScanner>,
    start_height: u64,
    target_height: u64,
) -> BackgroundSyncController {
    let (cmd_tx, mut cmd_rx) = mpsc::channel::<SyncCommand>(16);
    let (progress_tx, progress_rx) = watch::channel(SyncProgress::default());

    let mut manager = BackgroundSyncManager::new(config.clone());
    manager.start(start_height, target_height);

    let is_running = manager.is_running.clone();

    tokio::spawn(async move {
        let mut persist_counter: u64 = 0;
        let scan_start = std::time::Instant::now();
        // Task #6: track last tip-hash poll. Initial value is "now" so
        // the first poll fires after the configured interval, not
        // immediately on startup (the scanner has nothing useful at
        // height 0 to compare anyway).
        let mut last_tip_check = std::time::Instant::now();
        let tip_check_interval = if config.tip_check_interval_secs > 0 {
            Some(std::time::Duration::from_secs(config.tip_check_interval_secs))
        } else {
            None
        };

        loop {
            // Task #6: periodic tip-hash poll. Fires regardless of sync
            // state (Syncing / Complete / Paused) — the offline-during-
            // reorg case is precisely when the wallet sat at Complete
            // with no new blocks arriving. Disabled when interval == 0.
            if let Some(interval) = tip_check_interval {
                if last_tip_check.elapsed() >= interval {
                    last_tip_check = std::time::Instant::now();
                    let (known_h, known_hash) = scanner.current_position();
                    if known_h > 0 {
                        match fetcher.get_block_hash_at(known_h).await {
                            Ok(Some(chain_hash)) if chain_hash != known_hash => {
                                tracing::warn!(
                                    target: "wallet::reorg",
                                    "Periodic tip-hash check: wallet hash mismatch at height {} (wallet={}, chain={})",
                                    known_h, known_hash, chain_hash,
                                );
                                match try_reorg_recovery(
                                    fetcher.as_ref(),
                                    &mut scanner,
                                    known_hash,
                                    known_h,
                                    known_h,
                                ).await {
                                    Ok(Some(stats)) => {
                                        tracing::info!(
                                            target: "wallet::reorg",
                                            "Reorg recovered via periodic poll: rewound to {} (depth {})",
                                            stats.new_height, stats.depth,
                                        );
                                        manager.rewind_to(stats.new_height);
                                        manager.record_reorg_stats(stats);
                                        let _ = progress_tx.send(manager.progress());
                                        continue;
                                    }
                                    Ok(None) => {
                                        manager.record_error(format!(
                                            "Periodic poll detected reorg at height {}; deeper than journal window (full rescan required)",
                                            known_h,
                                        ));
                                        let _ = progress_tx.send(manager.progress());
                                        continue;
                                    }
                                    Err(e) => {
                                        // Transient RPC failure — log + carry on,
                                        // we'll retry on next tick.
                                        tracing::warn!(
                                            target: "wallet::reorg",
                                            "Periodic reorg recovery RPC failed (will retry): {}",
                                            e,
                                        );
                                    }
                                }
                            }
                            Ok(Some(_)) => {
                                // Match — wallet's view is canonical.
                            }
                            Ok(None) => {
                                tracing::debug!(
                                    target: "wallet::reorg",
                                    "Periodic tip-hash check: node has no block at height {}",
                                    known_h,
                                );
                            }
                            Err(e) => {
                                tracing::debug!(
                                    target: "wallet::reorg",
                                    "Periodic tip-hash check RPC failed: {}",
                                    e,
                                );
                            }
                        }
                    }
                }
            }

            // Check for commands (non-blocking)
            while let Ok(cmd) = cmd_rx.try_recv() {
                match cmd {
                    SyncCommand::Start => manager.resume(),
                    SyncCommand::Pause => manager.pause(),
                    SyncCommand::Stop => {
                        manager.stop();
                        let _ = scanner.persist_state(manager.current_height);
                        let _ = progress_tx.send(manager.progress());
                        return;
                    }
                    SyncCommand::UpdateTarget(h) => manager.update_target(h),
                    SyncCommand::RescanFrom(h) => {
                        manager.stop();
                        manager.start(h, manager.target_height);
                    }
                }
            }

            if !manager.should_continue() {
                if manager.state() == SyncState::Complete {
                    let _ = progress_tx.send(manager.progress());
                    // Wait for new commands (target update, stop)
                    match cmd_rx.recv().await {
                        Some(SyncCommand::Stop) => return,
                        Some(SyncCommand::UpdateTarget(h)) => {
                            manager.update_target(h);
                            continue;
                        }
                        Some(SyncCommand::RescanFrom(h)) => {
                            manager.stop();
                            manager.start(h, manager.target_height);
                            continue;
                        }
                        Some(_) => continue,
                        None => return, // Channel closed
                    }
                }
                // Paused or error — wait for resume
                tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                continue;
            }

            // Get next batch
            let (batch_start, batch_end) = match manager.next_batch_range() {
                Some(range) => range,
                None => {
                    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                    continue;
                }
            };

            // Fetch and scan blocks in batch
            let mut batch_outputs = 0u64;
            let mut batch_txs = 0u64;
            let mut batch_count = 0u64;
            let mut had_error = false;
            // Task #5: when scan_block_v2 returns ReorgDetected, we break
            // out of the inner block loop AND skip the
            // update_progress(batch_count) call below so current_height
            // isn't advanced past the orphaned block. The recovery path
            // then rewinds current_height down to the fork point.
            let mut reorg_recovery_done = false;
            // Fetch returned Ok(None) — block not yet available at the
            // node. Signals the post-batch handler to back off before
            // retrying so we don't hot-loop against the fetcher.
            let mut fetch_stalled = false;

            for height in batch_start..batch_end {
                match fetcher.fetch_block(height).await {
                    Ok(Some(block)) => {
                        match scanner.scan_block_v2(&block, height) {
                            ScanBlockOutcome::Scanned { outputs, txs } => {
                                batch_outputs += outputs;
                                batch_txs += txs;
                                batch_count += 1;
                            }
                            ScanBlockOutcome::ReorgDetected {
                                at_height,
                                known_height,
                                known_hash,
                            } => {
                                tracing::warn!(
                                    target: "wallet::reorg",
                                    "Reorg detected at height {} (wallet at known_height={}); recovery path A",
                                    at_height,
                                    known_height,
                                );
                                // Path A (Task #5): same dispatch helper
                                // that Task #6's periodic poll uses, so
                                // both paths produce identical state
                                // transitions on success.
                                match try_reorg_recovery(
                                    fetcher.as_ref(),
                                    &mut scanner,
                                    known_hash,
                                    known_height,
                                    at_height,
                                ).await {
                                    Ok(Some(stats)) => {
                                        tracing::info!(
                                            target: "wallet::reorg",
                                            "Reorg recovered: rewound to {} (depth {}, {} UTXOs removed, {} UTXOs unspent)",
                                            stats.new_height,
                                            stats.depth,
                                            stats.utxos_removed,
                                            stats.utxos_unspent,
                                        );
                                        manager.rewind_to(stats.new_height);
                                        manager.record_reorg_stats(stats);
                                        reorg_recovery_done = true;
                                    }
                                    Ok(None) => {
                                        tracing::error!(
                                            target: "wallet::reorg",
                                            "Reorg at height {} deeper than searchable window; full rescan required",
                                            at_height,
                                        );
                                        manager.record_error(format!(
                                            "Reorg at height {} deeper than journal window — full rescan required (not yet automated)",
                                            at_height,
                                        ));
                                        had_error = true;
                                    }
                                    Err(e) => {
                                        tracing::warn!(
                                            target: "wallet::reorg",
                                            "Reorg recovery failed: {}", e,
                                        );
                                        manager.record_error(format!(
                                            "Reorg recovery failed: {}", e,
                                        ));
                                        had_error = true;
                                    }
                                }
                                // Whatever the outcome, the rest of this
                                // batch is on the orphaned chain — drop it.
                                break;
                            }
                        }
                    }
                    Ok(None) => {
                        // Block not available yet at the node. Do NOT
                        // shrink `target_height` here: it represents the
                        // chain tip we're still syncing toward, and
                        // lowering it to `height` pins target==current
                        // (state stays Syncing, next_batch_range then
                        // returns None indefinitely) until an explicit
                        // UpdateTarget command arrives. Instead, break
                        // the batch and let the post-batch handler back
                        // off before we retry from the same position.
                        fetch_stalled = true;
                        break;
                    }
                    Err(e) => {
                        tracing::warn!("Block fetch error at height {}: {}", height, e);
                        manager.record_error(e);
                        had_error = true;
                        break;
                    }
                }
            }

            if reorg_recovery_done {
                // current_height has been rewound; next iteration will
                // pick up the next batch from the new position. Push the
                // updated progress (with last_reorg_* fields) to the UI
                // before looping.
                let _ = progress_tx.send(manager.progress());
                continue;
            }

            if batch_count > 0 {
                // Update elapsed time
                manager.stats.scan_time_ms = scan_start.elapsed().as_millis() as u64;
                manager.update_progress(batch_count, batch_outputs, batch_txs);
                persist_counter += batch_count;

                // Persist state periodically
                if persist_counter >= config.persist_interval {
                    if let Err(e) = scanner.persist_state(manager.current_height) {
                        tracing::warn!("Failed to persist sync state: {}", e);
                    }
                    persist_counter = 0;
                }

                // Send progress update
                let _ = progress_tx.send(manager.progress());
            }

            if had_error {
                // Back off on errors
                tokio::time::sleep(std::time::Duration::from_secs(5)).await;
                manager.resume(); // Try to continue
            }

            // Fetcher returned Ok(None) — the block we asked for isn't
            // available at the node yet. Back off before retrying so we
            // don't hot-loop the RPC. Independent of `had_error` (which
            // only fires on transport failures).
            if fetch_stalled && !had_error {
                tokio::time::sleep(std::time::Duration::from_millis(500)).await;
            }

            // Rate limiting
            if config.rate_limit > 0 && batch_count > 0 {
                let delay = std::time::Duration::from_millis(
                    (batch_count * 1000 / config.rate_limit.max(1)) as u64
                );
                tokio::time::sleep(delay).await;
            }
        }
    });

    BackgroundSyncController {
        command_tx: cmd_tx,
        progress_rx,
        is_running,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sync_progress() {
        let mut progress = SyncProgress::default();
        progress.current_height = 500;
        progress.target_height = 1000;

        assert_eq!(progress.percent_complete(), 50.0);
        assert_eq!(progress.remaining_blocks(), 500);
    }

    #[test]
    fn test_sync_manager() {
        let config = BackgroundSyncConfig::default();
        let mut manager = BackgroundSyncManager::new(config);

        manager.start(0, 1000);
        assert_eq!(manager.state(), SyncState::Syncing);

        manager.update_progress(100, 5, 200);
        let progress = manager.progress();
        assert_eq!(progress.current_height, 100);
        assert_eq!(progress.outputs_found, 5);

        manager.pause();
        assert_eq!(manager.state(), SyncState::Paused);

        manager.resume();
        assert_eq!(manager.state(), SyncState::Syncing);

        manager.update_progress(900, 45, 1800);
        assert_eq!(manager.state(), SyncState::Complete);
    }

    #[test]
    fn test_cancellation() {
        let config = BackgroundSyncConfig::default();
        let mut manager = BackgroundSyncManager::new(config);

        manager.start(0, 1000);
        assert_eq!(manager.state(), SyncState::Syncing);

        manager.update_progress(100, 2, 50);
        // Stop mid-scan
        manager.stop();
        assert_eq!(manager.state(), SyncState::Idle);

        // Progress should retain what was scanned
        let progress = manager.progress();
        assert_eq!(progress.current_height, 100);
    }

    // === Reorg-handling tests (Task #5) =================================

    /// Minimal Block used only as a placeholder reference in tests
    /// whose stub scanners ignore the block content. The real chain
    /// constructs Block via Block::new(header, txs); we go through
    /// the struct literal because there's no Default impl and the
    /// header has many fields we don't care about for these tests.
    fn empty_block() -> Block {
        use crate::consensus::BlockHeader;
        use crate::primitives::PublicKey;
        Block::new(
            BlockHeader {
                network_magic: [0u8; 4],
                version: 0,
                height: 0,
                timestamp: 0,
                prev_hash: Hash::zero(),
                tx_root: Hash::zero(),
                anchor: Hash::zero(),
                algorithm: 0,
                nonce: 0,
                target: Hash::zero(),
                miner_pubkey: PublicKey::from_bytes([0u8; 32]),
                supply_commitment: [0u8; 32],
                checkpoint_vote: None,
                spark_set_root: [0u8; 32],
                mw_kernel_root: [0u8; 32],
            },
            Vec::new(),
        )
    }


    /// `rewind_to` pulls current_height back to the recovery target and
    /// re-arms the state machine to Syncing. The next batch_range will
    /// then start at the new position.
    #[test]
    fn test_rewind_to_moves_current_height_and_resumes() {
        let config = BackgroundSyncConfig::default();
        let mut manager = BackgroundSyncManager::new(config);
        manager.start(0, 1000);
        manager.update_progress(500, 10, 250);
        assert_eq!(manager.progress().current_height, 500);

        manager.rewind_to(450);
        assert_eq!(manager.progress().current_height, 450);
        assert_eq!(manager.state(), SyncState::Syncing);
    }

    /// `rewind_to` from a Complete state re-arms back to Syncing (a
    /// reorg arriving after the wallet caught up is the realistic
    /// trigger — we must not stay Complete).
    #[test]
    fn test_rewind_to_unsticks_complete_state() {
        let config = BackgroundSyncConfig::default();
        let mut manager = BackgroundSyncManager::new(config);
        manager.start(0, 100);
        manager.update_progress(100, 1, 10);
        assert_eq!(manager.state(), SyncState::Complete);

        manager.rewind_to(95);
        assert_eq!(manager.state(), SyncState::Syncing);
        assert_eq!(manager.progress().current_height, 95);
    }

    /// `rewind_to` with a target greater than current_height is a no-op
    /// on the height field (you can't rewind forward) but still resumes
    /// the state machine. Defensive — shouldn't happen in practice, but
    /// silently corrupting current_height would be worse.
    #[test]
    fn test_rewind_to_forward_is_height_noop() {
        let config = BackgroundSyncConfig::default();
        let mut manager = BackgroundSyncManager::new(config);
        manager.start(0, 1000);
        manager.update_progress(100, 1, 10);

        manager.rewind_to(500);
        assert_eq!(manager.progress().current_height, 100);
    }

    /// `record_reorg_stats` populates the `SyncProgress` fields the UI
    /// reads for the reorg-notification banner (Tasks #7 + #8).
    #[test]
    fn test_record_reorg_stats_surfaces_via_progress() {
        let config = BackgroundSyncConfig::default();
        let mut manager = BackgroundSyncManager::new(config);
        manager.start(0, 1000);

        let stats = ReorgRecoveryStats {
            reorg_at_height: 105,
            new_height: 100,
            depth: 5,
            utxos_removed: 2,
            utxos_unspent: 1,
        };
        manager.record_reorg_stats(stats);
        let progress = manager.progress();
        assert_eq!(progress.last_reorg_at_height, Some(105));
        assert_eq!(progress.last_reorg_depth, Some(5));

        manager.clear_reorg_stats();
        let progress = manager.progress();
        assert_eq!(progress.last_reorg_at_height, None);
        assert_eq!(progress.last_reorg_depth, None);
    }

    /// Stub BlockScanner that emits ReorgDetected on a configurable
    /// height, then on the next call simulates successful recovery.
    /// Used to exercise the orchestrator's reorg branch without needing
    /// a real chain.
    struct StubReorgScanner {
        emit_reorg_at: u64,
        scanned_calls: u64,
        recovery_calls: u64,
    }

    impl BlockScanner for StubReorgScanner {
        fn scan_block(&mut self, _block: &Block, _height: u64) -> (u64, u64) {
            self.scanned_calls += 1;
            (1, 1)
        }
        fn scan_block_v2(&mut self, _block: &Block, height: u64) -> ScanBlockOutcome {
            if height == self.emit_reorg_at && self.recovery_calls == 0 {
                ScanBlockOutcome::ReorgDetected {
                    at_height: height,
                    known_height: height - 1,
                    known_hash: Hash::from_bytes([0xAB; 32]),
                }
            } else {
                self.scanned_calls += 1;
                ScanBlockOutcome::Scanned { outputs: 1, txs: 1 }
            }
        }
        fn handle_reorg_recovery(
            &mut self,
            fork_height: u64,
        ) -> std::result::Result<ReorgRecoveryStats, String> {
            self.recovery_calls += 1;
            Ok(ReorgRecoveryStats {
                reorg_at_height: fork_height + 1,
                new_height: fork_height,
                depth: 1,
                utxos_removed: 0,
                utxos_unspent: 0,
            })
        }
        fn persist_state(&mut self, _height: u64) -> Result<()> {
            Ok(())
        }
    }

    /// `scan_block_v2` default impl wraps `scan_block` in `Scanned`,
    /// so existing legacy scanners stay compatible without modification.
    #[test]
    fn test_scan_block_v2_default_wraps_legacy_scan() {
        struct LegacyOnly;
        impl BlockScanner for LegacyOnly {
            fn scan_block(&mut self, _b: &Block, _h: u64) -> (u64, u64) { (3, 7) }
            fn persist_state(&mut self, _h: u64) -> Result<()> { Ok(()) }
        }
        let mut s = LegacyOnly;
        let dummy_block = empty_block();
        match s.scan_block_v2(&dummy_block, 0) {
            ScanBlockOutcome::Scanned { outputs, txs } => {
                assert_eq!(outputs, 3);
                assert_eq!(txs, 7);
            }
            ScanBlockOutcome::ReorgDetected { .. } => {
                panic!("legacy default should never emit ReorgDetected");
            }
        }
    }

    /// `handle_reorg_recovery` default impl returns Err with a message
    /// containing the fork_height — so legacy scanners can't silently
    /// "succeed" a recovery they aren't actually performing.
    #[test]
    fn test_handle_reorg_recovery_default_is_err() {
        struct LegacyOnly;
        impl BlockScanner for LegacyOnly {
            fn scan_block(&mut self, _b: &Block, _h: u64) -> (u64, u64) { (0, 0) }
            fn persist_state(&mut self, _h: u64) -> Result<()> { Ok(()) }
        }
        let mut s = LegacyOnly;
        let res = s.handle_reorg_recovery(42);
        assert!(res.is_err());
        assert!(res.unwrap_err().contains("42"));
    }

    /// `find_fork_point` default impl returns Err — legacy fetchers
    /// can't claim a fork point exists. Symmetric guard to the scanner
    /// side: both defaults must surface absence-of-impl loudly.
    #[tokio::test]
    async fn test_find_fork_point_default_is_err() {
        struct LegacyFetcher;
        #[async_trait::async_trait]
        impl BlockFetcher for LegacyFetcher {
            async fn fetch_block(&self, _h: u64)
                -> std::result::Result<Option<Block>, String> {
                Ok(None)
            }
            async fn get_chain_height(&self)
                -> std::result::Result<u64, String> {
                Ok(0)
            }
        }
        let f = LegacyFetcher;
        let res = f.find_fork_point(Hash::zero(), 0).await;
        assert!(res.is_err());
    }

    /// `current_position` default returns (0, Hash::zero()) so legacy
    /// scanners opt out of the periodic tip-hash poll cleanly. The
    /// periodic check (Task #6) skips the RPC call when known_h == 0,
    /// so this default is effectively a no-op gate.
    #[test]
    fn test_current_position_default_is_zero() {
        struct LegacyOnly;
        impl BlockScanner for LegacyOnly {
            fn scan_block(&mut self, _b: &Block, _h: u64) -> (u64, u64) { (0, 0) }
            fn persist_state(&mut self, _h: u64) -> Result<()> { Ok(()) }
        }
        let s = LegacyOnly;
        assert_eq!(s.current_position(), (0, Hash::zero()));
    }

    /// `try_reorg_recovery` round-trip: a fetcher that resolves a fork
    /// point + a scanner that succeeds recovery produces stats with
    /// `reorg_at_height` backfilled from the caller's `at_height` arg.
    /// This is the path both Task #5 and Task #6 share.
    #[tokio::test]
    async fn test_try_reorg_recovery_round_trip() {
        struct StubFetcher;
        #[async_trait::async_trait]
        impl BlockFetcher for StubFetcher {
            async fn fetch_block(&self, _h: u64) -> std::result::Result<Option<Block>, String> {
                Ok(None)
            }
            async fn get_chain_height(&self) -> std::result::Result<u64, String> {
                Ok(10)
            }
            async fn find_fork_point(
                &self, _kh: Hash, _kheight: u64,
            ) -> std::result::Result<Option<u64>, String> {
                Ok(Some(4))
            }
        }
        let fetcher = StubFetcher;
        let mut scanner: Box<dyn BlockScanner> = Box::new(StubReorgScanner {
            emit_reorg_at: 5,
            scanned_calls: 0,
            recovery_calls: 0,
        });
        let result = try_reorg_recovery(
            &fetcher, &mut scanner,
            Hash::from_bytes([0xAB; 32]),
            5, // known_height
            5, // at_height — the height the reorg was detected at
        ).await;
        let stats = result.expect("recovery should not error")
            .expect("fork point should resolve to Some");
        // Stub returns depth=1 + new_height=fork_height=4; helper
        // backfills reorg_at_height=at_height=5.
        assert_eq!(stats.new_height, 4);
        assert_eq!(stats.depth, 1);
        assert_eq!(stats.reorg_at_height, 5);
    }

    /// `try_reorg_recovery` returns Ok(None) when find_fork_point
    /// resolves to None (reorg deeper than searchable window).
    /// The orchestrator surfaces this as an error to the operator
    /// (full rescan needed).
    #[tokio::test]
    async fn test_try_reorg_recovery_no_fork_point() {
        struct NoForkFetcher;
        #[async_trait::async_trait]
        impl BlockFetcher for NoForkFetcher {
            async fn fetch_block(&self, _h: u64) -> std::result::Result<Option<Block>, String> {
                Ok(None)
            }
            async fn get_chain_height(&self) -> std::result::Result<u64, String> { Ok(0) }
            async fn find_fork_point(
                &self, _kh: Hash, _kheight: u64,
            ) -> std::result::Result<Option<u64>, String> {
                Ok(None)
            }
        }
        let fetcher = NoForkFetcher;
        let mut scanner: Box<dyn BlockScanner> = Box::new(StubReorgScanner {
            emit_reorg_at: 99,
            scanned_calls: 0,
            recovery_calls: 0,
        });
        let result = try_reorg_recovery(&fetcher, &mut scanner, Hash::zero(), 10, 10).await;
        assert!(matches!(result, Ok(None)));
    }

    /// Smoke test for the StubReorgScanner: confirms it switches from
    /// emitting ReorgDetected to emitting Scanned after a recovery call.
    /// This is what the orchestrator loop relies on for restart.
    #[test]
    fn test_stub_reorg_scanner_switches_after_recovery() {
        let mut s = StubReorgScanner {
            emit_reorg_at: 5,
            scanned_calls: 0,
            recovery_calls: 0,
        };
        let block = empty_block();
        // Before recovery: emits ReorgDetected at the target height.
        assert!(matches!(
            s.scan_block_v2(&block, 5),
            ScanBlockOutcome::ReorgDetected { .. }
        ));
        // Simulate orchestrator calling recovery.
        s.handle_reorg_recovery(4).expect("recovery");
        // After recovery: same height now emits Scanned.
        assert!(matches!(
            s.scan_block_v2(&block, 5),
            ScanBlockOutcome::Scanned { .. }
        ));
    }
}
