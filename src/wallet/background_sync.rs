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
            last_error: None,
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

    /// Record an error
    pub fn record_error(&mut self, _msg: String) {
        self.state = SyncState::Error;
    }
}

/// Trait for fetching blocks during sync (implemented by RPC clients, direct DB access, etc.)
#[async_trait::async_trait]
pub trait BlockFetcher: Send + Sync {
    /// Fetch a block by height. Returns None if not available.
    async fn fetch_block(&self, height: u64) -> std::result::Result<Option<Block>, String>;
    /// Get the current chain tip height.
    async fn get_chain_height(&self) -> std::result::Result<u64, String>;
}

/// Trait for processing scanned blocks (wallet-specific scanning logic)
pub trait BlockScanner: Send {
    /// Scan a block for wallet-relevant outputs. Returns (outputs_found, txs_scanned).
    fn scan_block(&mut self, block: &Block, height: u64) -> (u64, u64);
    /// Persist current wallet state (called periodically).
    fn persist_state(&mut self, height: u64) -> Result<()>;
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

        loop {
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

            for height in batch_start..batch_end {
                match fetcher.fetch_block(height).await {
                    Ok(Some(block)) => {
                        let (outputs, txs) = scanner.scan_block(&block, height);
                        batch_outputs += outputs;
                        batch_txs += txs;
                        batch_count += 1;
                    }
                    Ok(None) => {
                        // Block not available yet — update target and pause
                        manager.update_target(height);
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
}
