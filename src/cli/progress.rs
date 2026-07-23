//! Progress bars and spinners for CLI

use console::style;
use indicatif::{MultiProgress, ProgressBar, ProgressDrawTarget, ProgressStyle};
use std::time::Duration;

/// Create a spinner for indeterminate operations
pub fn create_spinner(message: &str) -> ProgressBar {
    let spinner = ProgressBar::new_spinner();
    spinner.set_style(
        ProgressStyle::default_spinner()
            .tick_chars("⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏")
            .template("{spinner:.cyan} {msg}")
            .expect("invalid spinner template"),
    );
    spinner.set_message(message.to_string());
    spinner.enable_steady_tick(Duration::from_millis(80));
    spinner
}

/// Create a progress bar for known-length operations
pub fn create_progress_bar(total: u64, message: &str) -> ProgressBar {
    let bar = ProgressBar::new(total);
    bar.set_style(
        ProgressStyle::default_bar()
            .template("{msg}\n{spinner:.cyan} [{bar:40.cyan/blue}] {pos}/{len} ({percent}%) {eta}")
            .expect("invalid progress bar template")
            .progress_chars("█▓▒░  "),
    );
    bar.set_message(message.to_string());
    bar
}

/// Create a download-style progress bar with bytes
pub fn create_download_bar(total: u64) -> ProgressBar {
    let bar = ProgressBar::new(total);
    bar.set_style(
        ProgressStyle::default_bar()
            .template("{spinner:.cyan} [{bar:40.cyan/blue}] {bytes}/{total_bytes} ({bytes_per_sec}) {eta}")
            .expect("invalid download bar template")
            .progress_chars("█▓▒░  ")
    );
    bar
}

/// Create a sync progress bar for blockchain sync
pub fn create_sync_bar(total_blocks: u64) -> ProgressBar {
    let bar = ProgressBar::new(total_blocks);
    bar.set_style(
        ProgressStyle::default_bar()
            .template("{msg}\n{spinner:.cyan} [{bar:40.cyan/blue}] {pos}/{len} blocks ({percent}%)\n  ⏱  ETA: {eta} | Speed: {per_sec} blocks/s")
            .expect("invalid sync bar template")
            .progress_chars("█▓▒░  ")
    );
    bar.set_message("Syncing blockchain...");
    bar
}

/// Create a multi-progress display for concurrent operations
pub fn create_multi_progress() -> MultiProgress {
    MultiProgress::new()
}

/// Create a hidden progress bar (for background operations)
pub fn create_hidden_bar(total: u64) -> ProgressBar {
    let bar = ProgressBar::new(total);
    bar.set_draw_target(ProgressDrawTarget::hidden());
    bar
}

/// Progress context for wallet operations
pub struct WalletProgress {
    multi: MultiProgress,
    main_bar: ProgressBar,
}

impl WalletProgress {
    /// Create new wallet progress display
    pub fn new(operation: &str) -> Self {
        let multi = MultiProgress::new();
        let main_bar = multi.add(create_spinner(operation));
        Self { multi, main_bar }
    }

    /// Update main message
    pub fn set_message(&self, message: &str) {
        self.main_bar.set_message(message.to_string());
    }

    /// Add a sub-progress bar
    pub fn add_bar(&self, total: u64, message: &str) -> ProgressBar {
        let bar = self.multi.add(create_progress_bar(total, message));
        bar
    }

    /// Finish with success message
    pub fn finish_success(&self, message: &str) {
        self.main_bar
            .finish_with_message(format!("{} {}", style("✓").green(), message));
    }

    /// Finish with error message
    pub fn finish_error(&self, message: &str) {
        self.main_bar
            .finish_with_message(format!("{} {}", style("✗").red(), message));
    }
}

/// Progress context for node operations
pub struct NodeProgress {
    sync_bar: Option<ProgressBar>,
    peer_count: u64,
    block_height: u64,
}

impl NodeProgress {
    /// Create new node progress
    pub fn new() -> Self {
        Self {
            sync_bar: None,
            peer_count: 0,
            block_height: 0,
        }
    }

    /// Start sync progress
    pub fn start_sync(&mut self, target_height: u64) {
        let bar = create_sync_bar(target_height);
        self.sync_bar = Some(bar);
    }

    /// Update sync progress
    pub fn update_sync(&mut self, current_height: u64) {
        if let Some(bar) = &self.sync_bar {
            bar.set_position(current_height);
            self.block_height = current_height;
        }
    }

    /// Update peer count
    pub fn update_peers(&mut self, count: u64) {
        self.peer_count = count;
        if let Some(bar) = &self.sync_bar {
            bar.set_message(format!("Syncing blockchain... ({} peers)", count));
        }
    }

    /// Finish sync
    pub fn finish_sync(&mut self) {
        if let Some(bar) = self.sync_bar.take() {
            bar.finish_with_message(format!(
                "{} Sync complete! Height: {}",
                style("✓").green(),
                self.block_height
            ));
        }
    }

    /// Check if syncing
    pub fn is_syncing(&self) -> bool {
        self.sync_bar.is_some()
    }
}

impl Default for NodeProgress {
    fn default() -> Self {
        Self::new()
    }
}

/// Mining progress display
#[allow(dead_code)]
pub struct MiningProgress {
    bar: ProgressBar,
    hashes: u64,
    blocks_found: u64,
}

impl MiningProgress {
    /// Create new mining progress
    pub fn new() -> Self {
        let bar = ProgressBar::new_spinner();
        bar.set_style(
            ProgressStyle::default_spinner()
                .tick_chars("⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏")
                .template("{spinner:.cyan} Mining... {msg}")
                .expect("invalid mining progress template"),
        );
        bar.enable_steady_tick(Duration::from_millis(100));
        Self {
            bar,
            hashes: 0,
            blocks_found: 0,
        }
    }

    /// Update hashrate
    pub fn update(&mut self, hashrate: f64, height: u64) {
        self.bar.set_message(format!(
            "Block {} | {:.2} H/s | {} blocks found",
            height, hashrate, self.blocks_found
        ));
    }

    /// Block found
    pub fn block_found(&mut self, height: u64, reward: &str) {
        self.blocks_found += 1;
        self.bar.println(format!(
            "{} Block {} mined! Reward: {}",
            style("⛏").yellow(),
            height,
            style(reward).green()
        ));
    }

    /// Stop mining
    pub fn stop(&self) {
        self.bar.finish_with_message(format!(
            "Mining stopped. {} blocks found.",
            self.blocks_found
        ));
    }
}

impl Default for MiningProgress {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_spinner() {
        let spinner = create_spinner("Testing...");
        spinner.finish();
    }

    #[test]
    fn test_create_progress_bar() {
        let bar = create_progress_bar(100, "Processing");
        bar.set_position(50);
        bar.finish();
    }
}
