//! # Mining Progress Display
//!
//! Progress bars, notifications, and real-time mining status.
//!
//! ## Components
//!
//! - **MinerDisplay**: Startup banner and status display
//! - **MiningProgress**: Live progress tracking
//! - **MiningProgressHandle**: Thread-safe progress updates
//! - **TerminalUI**: Box drawing and beautiful formatting

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use std::io::Write;
use std::collections::VecDeque;

use crate::primitives::Amount;

// ============================================================================
// Terminal UI Components - Box Drawing and Styling
// ============================================================================

/// Box drawing characters for terminal UI
pub mod box_chars {
    // Single line box
    pub const TOP_LEFT: &str = "┌";
    pub const TOP_RIGHT: &str = "┐";
    pub const BOTTOM_LEFT: &str = "└";
    pub const BOTTOM_RIGHT: &str = "┘";
    pub const HORIZONTAL: &str = "─";
    pub const VERTICAL: &str = "│";
    pub const T_DOWN: &str = "┬";
    pub const T_UP: &str = "┴";
    pub const T_RIGHT: &str = "├";
    pub const T_LEFT: &str = "┤";
    pub const CROSS: &str = "┼";

    // Double line box
    pub const D_TOP_LEFT: &str = "╔";
    pub const D_TOP_RIGHT: &str = "╗";
    pub const D_BOTTOM_LEFT: &str = "╚";
    pub const D_BOTTOM_RIGHT: &str = "╝";
    pub const D_HORIZONTAL: &str = "═";
    pub const D_VERTICAL: &str = "║";
    pub const D_T_DOWN: &str = "╦";
    pub const D_T_UP: &str = "╩";
    pub const D_T_RIGHT: &str = "╠";
    pub const D_T_LEFT: &str = "╣";

    // Status indicators
    pub const DOT_FILLED: &str = "●";
    pub const DOT_EMPTY: &str = "○";
    pub const DOT_HALF: &str = "◐";
    pub const DIAMOND: &str = "◆";
    pub const ARROW_RIGHT: &str = "▶";
    pub const CHECK: &str = "✓";
    pub const CROSS_MARK: &str = "✗";
    pub const WARNING: &str = "⚠";
    pub const PICKAXE: &str = "⛏";
    pub const LIGHTNING: &str = "⚡";
    pub const CLOCK: &str = "⏱";
    pub const COIN: &str = "🪙";
    pub const FIRE: &str = "🔥";
}

/// Sparkline characters for mini graphs
pub mod sparkline {
    pub const BLOCKS: [&str; 8] = ["▁", "▂", "▃", "▄", "▅", "▆", "▇", "█"];

    /// Generate sparkline from values
    pub fn generate(values: &[f64], width: usize) -> String {
        if values.is_empty() {
            return " ".repeat(width);
        }

        let max = values.iter().cloned().fold(f64::MIN, f64::max);
        let min = values.iter().cloned().fold(f64::MAX, f64::min);
        let range = if (max - min).abs() < f64::EPSILON { 1.0 } else { max - min };

        values.iter()
            .take(width)
            .map(|&v| {
                let normalized = ((v - min) / range * 7.0).round() as usize;
                BLOCKS[normalized.min(7)]
            })
            .collect()
    }
}

/// ANSI color codes
pub mod colors {
    pub const RESET: &str = "\x1b[0m";
    pub const BOLD: &str = "\x1b[1m";
    pub const DIM: &str = "\x1b[2m";

    // Foreground colors
    pub const BLACK: &str = "\x1b[30m";
    pub const RED: &str = "\x1b[31m";
    pub const GREEN: &str = "\x1b[32m";
    pub const YELLOW: &str = "\x1b[33m";
    pub const BLUE: &str = "\x1b[34m";
    pub const MAGENTA: &str = "\x1b[35m";
    pub const CYAN: &str = "\x1b[36m";
    pub const WHITE: &str = "\x1b[37m";
    pub const GRAY: &str = "\x1b[90m";

    // Bright foreground
    pub const BRIGHT_GREEN: &str = "\x1b[92m";
    pub const BRIGHT_YELLOW: &str = "\x1b[93m";
    pub const BRIGHT_CYAN: &str = "\x1b[96m";
    pub const BRIGHT_WHITE: &str = "\x1b[97m";
}

/// Spinner animation frames
pub const SPINNER_FRAMES: [&str; 10] = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"];

/// Mining animation frames
pub const MINING_FRAMES: [&str; 4] = ["⛏ ", " ⛏", "  ⛏", " ⛏"];

/// ASCII art logo for CoinCync (bold block style)
pub const LOGO: &str = r#"
╔═══════════════════════════════════════════════════════════╗
║   ██████╗ ██████╗ ██╗███╗   ██╗ ██████╗██╗   ██╗███╗   ██╗║
║  ██╔════╝██╔═══██╗██║████╗  ██║██╔════╝╚██╗ ██╔╝████╗  ██║║
║  ██║     ██║   ██║██║██╔██╗ ██║██║      ╚████╔╝ ██╔██╗ ██║║
║  ██║     ██║   ██║██║██║╚██╗██║██║       ╚██╔╝  ██║╚██╗██║║
║  ╚██████╗╚██████╔╝██║██║ ╚████║╚██████╗   ██║   ██║ ╚████║║
║   ╚═════╝ ╚═════╝ ╚═╝╚═╝  ╚═══╝ ╚═════╝   ╚═╝   ╚═╝  ╚═══╝║
║                  ⛏  Privacy-First Crypto  ⛏              ║
╚═══════════════════════════════════════════════════════════╝
"#;

/// Compact logo
pub const LOGO_SMALL: &str = "◆ CoinCync";

/// Hashrate history for sparkline
#[derive(Clone, Debug, Default)]
pub struct HashrateHistory {
    values: VecDeque<f64>,
    max_size: usize,
}

impl HashrateHistory {
    pub fn new(max_size: usize) -> Self {
        HashrateHistory {
            values: VecDeque::with_capacity(max_size),
            max_size,
        }
    }

    pub fn push(&mut self, value: f64) {
        if self.values.len() >= self.max_size {
            self.values.pop_front();
        }
        self.values.push_back(value);
    }

    pub fn sparkline(&self, width: usize) -> String {
        let vals: Vec<f64> = self.values.iter().cloned().collect();
        sparkline::generate(&vals, width)
    }

    pub fn average(&self) -> f64 {
        if self.values.is_empty() {
            0.0
        } else {
            self.values.iter().sum::<f64>() / self.values.len() as f64
        }
    }
}

// ============================================================================
// Miner Display - Startup Banner and Status
// ============================================================================

/// Mining mode
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MiningMode {
    /// Mining directly to your own node
    Solo,
    /// Mining to a pool
    Pool,
}

impl std::fmt::Display for MiningMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            MiningMode::Solo => write!(f, "Solo Mining"),
            MiningMode::Pool => write!(f, "Pool Mining"),
        }
    }
}

/// Warning types for miner display
#[derive(Clone, Debug)]
pub enum MinerWarning {
    /// Low hashrate detected
    LowHashrate { current: f64, expected: f64 },
    /// Lost connection to node
    NodeDisconnected,
    /// Block became stale before submission
    StaleBlock { height: u64 },
    /// Node has no peers
    NoPeers,
    /// High reject rate
    HighRejectRate { percent: f64 },
    /// CPU temperature warning (if available)
    HighTemperature { celsius: f32 },
}

impl MinerWarning {
    /// Format warning message with color
    pub fn format(&self, use_colors: bool) -> String {
        let prefix = if use_colors { "\x1b[33m!\x1b[0m" } else { "!" };

        match self {
            MinerWarning::LowHashrate { current, expected } => {
                format!("{} Low hashrate: {}/s (expected ~{}/s)",
                    prefix, format_hashrate(*current), format_hashrate(*expected))
            }
            MinerWarning::NodeDisconnected => {
                format!("{} Lost connection to node", prefix)
            }
            MinerWarning::StaleBlock { height } => {
                format!("{} Block {} became stale", prefix, height)
            }
            MinerWarning::NoPeers => {
                format!("{} Node has no peers - blocks won't propagate", prefix)
            }
            MinerWarning::HighRejectRate { percent } => {
                format!("{} High reject rate: {:.1}%", prefix, percent)
            }
            MinerWarning::HighTemperature { celsius } => {
                format!("{} High CPU temperature: {:.0}C", prefix, celsius)
            }
        }
    }
}

/// Miner display configuration
#[derive(Clone, Debug)]
pub struct MinerDisplayConfig {
    /// Mining reward address
    pub mining_address: String,
    /// Network name
    pub network: String,
    /// Node RPC endpoint
    pub node_endpoint: String,
    /// Mining mode (solo/pool)
    pub mode: MiningMode,
    /// Number of mining threads
    pub threads: usize,
    /// PoW algorithm name
    pub algorithm: String,
    /// Pool URL (if pool mining)
    pub pool_url: Option<String>,
    /// Use colored output
    pub use_colors: bool,
}

impl Default for MinerDisplayConfig {
    fn default() -> Self {
        MinerDisplayConfig {
            mining_address: String::new(),
            network: "mainnet".to_string(),
            node_endpoint: "127.0.0.1:19081".to_string(),
            mode: MiningMode::Solo,
            threads: 1,
            algorithm: "RandomX (CPU-optimized)".to_string(),
            pool_url: None,
            use_colors: true,
        }
    }
}

/// Network state for display
#[derive(Clone, Debug, Default)]
pub struct NetworkState {
    /// Current block height
    pub block_height: u64,
    /// Network difficulty
    pub difficulty: u128,
    /// Estimated network hashrate
    pub network_hashrate: f64,
    /// Target block time in seconds
    pub block_time: u64,
    /// Number of connected peers
    pub peer_count: usize,
    /// Is node synced
    pub is_synced: bool,
}

/// Live mining metrics
#[derive(Clone, Debug, Default)]
pub struct LiveMetrics {
    /// Current hashrate
    pub hashrate: f64,
    /// Valid shares found (pool mining)
    pub shares: u64,
    /// Blocks found
    pub blocks_found: u64,
    /// Mining uptime
    pub uptime: Duration,
    /// Total hashes computed
    pub total_hashes: u64,
    /// Rejected shares (pool mining)
    pub rejected_shares: u64,
    /// Last block found time
    pub last_block_time: Option<Instant>,
    /// Hashrate history for sparkline
    pub hashrate_history: Vec<f64>,
}

impl LiveMetrics {
    /// Estimate daily earnings based on current hashrate and network state
    pub fn estimate_daily_earnings(&self, network: &NetworkState, block_reward: Amount) -> Amount {
        if network.network_hashrate <= 0.0 || self.hashrate <= 0.0 {
            return Amount::from_atomic(0);
        }

        // Your share of the network hashrate
        let hash_share = self.hashrate / network.network_hashrate;

        // Blocks per day
        let blocks_per_day = if network.block_time > 0 {
            86400.0 / network.block_time as f64
        } else {
            86400.0 / 30.0 // Default 30 second blocks
        };

        // Expected blocks you'll find per day
        let expected_blocks = blocks_per_day * hash_share;

        // Expected earnings
        let earnings_atomic = block_reward.as_atomic() as f64 * expected_blocks;
        Amount::from_atomic(earnings_atomic as u64)
    }
}

/// Complete miner display manager
pub struct MinerDisplay {
    config: MinerDisplayConfig,
    network: NetworkState,
    metrics: LiveMetrics,
    start_time: Instant,
    warnings: Vec<MinerWarning>,
    is_connected: bool,
    hashrate_history: HashrateHistory,
    animation_frame: usize,
}

impl MinerDisplay {
    /// Create new miner display
    pub fn new(config: MinerDisplayConfig) -> Self {
        MinerDisplay {
            config,
            network: NetworkState::default(),
            metrics: LiveMetrics::default(),
            start_time: Instant::now(),
            warnings: Vec::new(),
            is_connected: false,
            hashrate_history: HashrateHistory::new(60), // 1 minute of history
            animation_frame: 0,
        }
    }

    /// Print startup banner with all essential information (beautiful box version)
    pub fn print_startup_banner(&self) {
        let c = self.config.use_colors;
        let width = 64;

        // Logo
        if c {
            println!("{}{}{}", colors::CYAN, LOGO, colors::RESET);
        } else {
            println!("{}", LOGO);
        }

        // Main title box
        self.print_box_top(width, c);
        self.print_box_title("MINER v2.0", width, c);
        self.print_box_separator(width, c);

        // Configuration section
        self.print_box_section_header("Configuration", width, c);

        // Mining address (truncated for display)
        let addr_display = if self.config.mining_address.len() > 20 {
            format!("{}...{}",
                &self.config.mining_address[..10],
                &self.config.mining_address[self.config.mining_address.len()-8..])
        } else if self.config.mining_address.is_empty() {
            "(not set)".to_string()
        } else {
            self.config.mining_address.clone()
        };

        self.print_box_field("Mining Address", &addr_display, width, c);
        self.print_box_field("Network", &self.config.network.to_uppercase(), width, c);

        // Connection status with indicator
        let (conn_indicator, conn_status) = if self.is_connected {
            (box_chars::DOT_FILLED, format!("Connected to {}", self.config.node_endpoint))
        } else {
            (box_chars::DOT_EMPTY, format!("Connecting to {}...", self.config.node_endpoint))
        };
        self.print_box_field_with_indicator("Node", &conn_status, conn_indicator, self.is_connected, width, c);

        // Mining mode with icon
        let mode_str = match self.config.mode {
            MiningMode::Solo => format!("{} Solo Mining", box_chars::PICKAXE),
            MiningMode::Pool => {
                if let Some(ref url) = self.config.pool_url {
                    format!("{} Pool: {}", box_chars::PICKAXE, url)
                } else {
                    format!("{} Pool Mining", box_chars::PICKAXE)
                }
            }
        };
        self.print_box_row(&mode_str, width, c);
        self.print_box_field("Threads", &format!("{} CPU threads", self.config.threads), width, c);
        self.print_box_field("Algorithm", &self.config.algorithm, width, c);

        self.print_box_separator(width, c);

        // Network State section
        self.print_box_section_header("Network State", width, c);

        // Sync indicator
        let sync_indicator = if self.network.is_synced { box_chars::CHECK } else { box_chars::DOT_HALF };
        self.print_box_field_with_indicator("Block Height", &format_large_number(self.network.block_height), sync_indicator, self.network.is_synced, width, c);
        self.print_box_field("Difficulty", &format_difficulty(self.network.difficulty), width, c);
        self.print_box_field("Network Hash", &format!("~{}/s", format_hashrate(self.network.network_hashrate)), width, c);
        self.print_box_field("Block Time", &format!("{} seconds", self.network.block_time), width, c);

        // Peers with warning color if 0
        let peer_color = if self.network.peer_count == 0 && c {
            colors::YELLOW
        } else if c {
            colors::GREEN
        } else {
            ""
        };
        if c {
            println!("{} {:>16}: {}{}{} peers{}                             {}",
                box_chars::VERTICAL, "Peers",
                peer_color, self.network.peer_count, colors::RESET,
                " ".repeat(width - 35),
                box_chars::VERTICAL);
        } else {
            self.print_box_field("Peers", &format!("{} peers", self.network.peer_count), width, c);
        }

        // Warnings section (if any)
        if !self.warnings.is_empty() {
            self.print_box_separator(width, c);
            self.print_box_section_header(&format!("{} Warnings", box_chars::WARNING), width, c);
            for warning in &self.warnings {
                self.print_box_row(&warning.format(c), width, c);
            }
        }

        self.print_box_bottom(width, c);

        // Started message
        println!();
        if c {
            println!("  {}{}[STARTED]{} Mining started. Press {}Ctrl+C{} to stop.",
                colors::BOLD, colors::GREEN, colors::RESET,
                colors::BOLD, colors::RESET);
        } else {
            println!("  [STARTED] Mining started. Press Ctrl+C to stop.");
        }
        println!();
    }

    // Box drawing helpers

    fn print_box_top(&self, width: usize, use_colors: bool) {
        if use_colors {
            println!("  {}{}{}{}", colors::CYAN, box_chars::D_TOP_LEFT,
                box_chars::D_HORIZONTAL.repeat(width), box_chars::D_TOP_RIGHT);
            print!("{}", colors::RESET);
        } else {
            println!("  {}{}{}", box_chars::D_TOP_LEFT,
                box_chars::D_HORIZONTAL.repeat(width), box_chars::D_TOP_RIGHT);
        }
    }

    fn print_box_bottom(&self, width: usize, use_colors: bool) {
        if use_colors {
            println!("  {}{}{}{}", colors::CYAN, box_chars::D_BOTTOM_LEFT,
                box_chars::D_HORIZONTAL.repeat(width), box_chars::D_BOTTOM_RIGHT);
            print!("{}", colors::RESET);
        } else {
            println!("  {}{}{}", box_chars::D_BOTTOM_LEFT,
                box_chars::D_HORIZONTAL.repeat(width), box_chars::D_BOTTOM_RIGHT);
        }
    }

    fn print_box_separator(&self, width: usize, use_colors: bool) {
        if use_colors {
            println!("  {}{}{}{}", colors::CYAN, box_chars::D_T_RIGHT,
                box_chars::D_HORIZONTAL.repeat(width), box_chars::D_T_LEFT);
            print!("{}", colors::RESET);
        } else {
            println!("  {}{}{}", box_chars::D_T_RIGHT,
                box_chars::D_HORIZONTAL.repeat(width), box_chars::D_T_LEFT);
        }
    }

    fn print_box_title(&self, title: &str, width: usize, use_colors: bool) {
        let padding = (width - title.len()) / 2;
        let extra = (width - title.len()) % 2;
        if use_colors {
            println!("  {}{}{}{}{}{}{}", colors::CYAN, box_chars::D_VERTICAL,
                " ".repeat(padding), colors::BOLD, title, colors::RESET,
                colors::CYAN);
            print!("{}{}{}", " ".repeat(padding + extra), box_chars::D_VERTICAL, colors::RESET);
            println!();
        } else {
            println!("  {}{}{}{}",
                box_chars::D_VERTICAL, " ".repeat(padding), title,
                " ".repeat(padding + extra));
            println!("{}", box_chars::D_VERTICAL);
        }
    }

    fn print_box_section_header(&self, title: &str, width: usize, use_colors: bool) {
        if use_colors {
            println!("  {}{}  {}{}{}{}", colors::CYAN, box_chars::D_VERTICAL,
                colors::BOLD, colors::BRIGHT_WHITE, title, colors::RESET);
            print!("{}", " ".repeat(width - title.len() - 2));
            println!("{}{}{}", colors::CYAN, box_chars::D_VERTICAL, colors::RESET);
        } else {
            let content = format!("  {}", title);
            let padding = width - content.len();
            println!("  {}{}{}{}", box_chars::D_VERTICAL, content,
                " ".repeat(padding), box_chars::D_VERTICAL);
        }
    }

    fn print_box_field(&self, label: &str, value: &str, width: usize, use_colors: bool) {
        let content = format!("{:>16}: {}", label, value);
        let padding = width.saturating_sub(content.len() + 2);
        if use_colors {
            println!("  {}{}  {}{}: {}{}{}{}", colors::CYAN, box_chars::D_VERTICAL,
                colors::GRAY, label, colors::RESET, value,
                " ".repeat(padding),
                colors::CYAN);
            print!("{}{}", box_chars::D_VERTICAL, colors::RESET);
            println!();
        } else {
            println!("  {}  {}{}{}", box_chars::D_VERTICAL, content,
                " ".repeat(padding), box_chars::D_VERTICAL);
        }
    }

    fn print_box_field_with_indicator(&self, label: &str, value: &str, indicator: &str, is_good: bool, width: usize, use_colors: bool) {
        let content = format!("{:>16}: {} {}", label, indicator, value);
        let padding = width.saturating_sub(content.len() + 2);
        if use_colors {
            let indicator_color = if is_good { colors::GREEN } else { colors::YELLOW };
            println!("  {}{}  {}{}: {}{}{} {}{}{}", colors::CYAN, box_chars::D_VERTICAL,
                colors::GRAY, label, indicator_color, indicator, colors::RESET, value,
                " ".repeat(padding.saturating_sub(2)),
                colors::CYAN);
            print!("{}{}", box_chars::D_VERTICAL, colors::RESET);
            println!();
        } else {
            println!("  {}  {}{}{}", box_chars::D_VERTICAL, content,
                " ".repeat(padding), box_chars::D_VERTICAL);
        }
    }

    fn print_box_row(&self, content: &str, width: usize, use_colors: bool) {
        let padding = width.saturating_sub(content.len() + 2);
        if use_colors {
            println!("  {}{}  {}{}{}{}", colors::CYAN, box_chars::D_VERTICAL,
                content, " ".repeat(padding),
                colors::CYAN, box_chars::D_VERTICAL);
            print!("{}", colors::RESET);
        } else {
            println!("  {}  {}{}{}", box_chars::D_VERTICAL, content,
                " ".repeat(padding), box_chars::D_VERTICAL);
        }
    }

    /// Print live metrics update (single line, overwrites previous)
    pub fn print_live_update(&self) {
        let c = self.config.use_colors;

        let uptime_str = format_duration(self.metrics.uptime);
        let hashrate_str = format_hashrate(self.metrics.hashrate);

        // Animation frame
        let spinner = SPINNER_FRAMES[self.animation_frame % SPINNER_FRAMES.len()];

        // Sparkline from hashrate history
        let spark = self.hashrate_history.sparkline(12);

        // Estimate daily earnings
        let block_reward = Amount::from_atomic(1_000_000_000_000); // 1 CYNC placeholder
        let daily_est = self.metrics.estimate_daily_earnings(&self.network, block_reward);
        let daily_str = format!("{:.4}", daily_est.as_atomic() as f64 / 1_000_000_000_000.0);

        let status = if c {
            format!(
                "\r{}{}{} {}{}/s{} {}[{}]{} B:{} S:{} {}{}{} {}~{} CYNC/day{}    ",
                colors::CYAN, spinner, colors::RESET,
                colors::GREEN, hashrate_str, colors::RESET,
                colors::DIM, spark, colors::RESET,
                self.metrics.blocks_found,
                self.metrics.shares,
                colors::GRAY, uptime_str, colors::RESET,
                colors::YELLOW, daily_str, colors::RESET
            )
        } else {
            format!(
                "\r{} {}/s [{}] B:{} S:{} {} ~{} CYNC/day    ",
                spinner,
                hashrate_str,
                spark,
                self.metrics.blocks_found,
                self.metrics.shares,
                uptime_str,
                daily_str
            )
        };

        print!("{}", status);
        let _ = std::io::stdout().flush();
    }

    /// Print compact single-line status with sparkline
    pub fn print_compact_status(&self) {
        let c = self.config.use_colors;
        let spinner = MINING_FRAMES[self.animation_frame % MINING_FRAMES.len()];
        let spark = self.hashrate_history.sparkline(20);
        let hashrate_str = format_hashrate(self.metrics.hashrate);

        if c {
            print!("\r  {}{}{}  {}{}/s{}  [{}]  {}{}H:{} {}  ",
                colors::CYAN, spinner, colors::RESET,
                colors::GREEN, hashrate_str, colors::RESET,
                spark,
                colors::YELLOW, box_chars::LIGHTNING, colors::RESET,
                format_large_number(self.metrics.total_hashes)
            );
        } else {
            print!("\r  {}  {}/s  [{}]  H:{}  ",
                spinner, hashrate_str, spark,
                format_large_number(self.metrics.total_hashes)
            );
        }
        let _ = std::io::stdout().flush();
    }

    /// Advance animation frame
    pub fn tick_animation(&mut self) {
        self.animation_frame = self.animation_frame.wrapping_add(1);
    }

    /// Record hashrate sample for sparkline history
    pub fn record_hashrate(&mut self, hashrate: f64) {
        self.hashrate_history.push(hashrate);
    }

    /// Print detailed stats (multi-line) with box drawing
    pub fn print_detailed_stats(&self) {
        let c = self.config.use_colors;
        let width = 50;

        println!();

        // Box header
        self.print_box_top(width, c);
        self.print_box_title("Mining Statistics", width, c);
        self.print_box_separator(width, c);

        // Hashrate with sparkline
        let spark = self.hashrate_history.sparkline(16);
        let hashrate_line = format!("{}/s  [{}]", format_hashrate(self.metrics.hashrate), spark);
        self.print_box_field_with_indicator("Hashrate", &hashrate_line, box_chars::LIGHTNING, true, width, c);

        // Shares
        self.print_box_field("Shares", &self.metrics.shares.to_string(), width, c);

        // Blocks found with icon
        let blocks_str = if self.metrics.blocks_found > 0 {
            format!("{} {}", box_chars::DOT_FILLED, self.metrics.blocks_found)
        } else {
            "0".to_string()
        };
        self.print_box_field("Blocks Found", &blocks_str, width, c);

        // Uptime
        self.print_box_field_with_indicator("Uptime", &format_duration(self.metrics.uptime), box_chars::CLOCK, true, width, c);

        // Total hashes
        self.print_box_field("Total Hashes", &format_large_number(self.metrics.total_hashes), width, c);

        // Rejected shares (if any)
        if self.metrics.rejected_shares > 0 {
            let reject_rate = if self.metrics.shares > 0 {
                (self.metrics.rejected_shares as f64 / (self.metrics.shares + self.metrics.rejected_shares) as f64) * 100.0
            } else {
                0.0
            };
            let reject_str = format!("{} ({:.1}%)", self.metrics.rejected_shares, reject_rate);
            self.print_box_field_with_indicator("Rejected", &reject_str, box_chars::CROSS_MARK, false, width, c);
        }

        self.print_box_separator(width, c);

        // Earnings estimate
        let block_reward = Amount::from_atomic(1_000_000_000_000);
        let daily_est = self.metrics.estimate_daily_earnings(&self.network, block_reward);
        let earnings_str = format!("~{:.4} CYNC", daily_est.as_atomic() as f64 / 1_000_000_000_000.0);
        self.print_box_field("Est. Daily", &earnings_str, width, c);

        self.print_box_bottom(width, c);
        println!();
    }

    /// Print warning message
    pub fn print_warning(&self, warning: &MinerWarning) {
        println!();
        println!("  {}", warning.format(self.config.use_colors));
    }

    /// Print block found notification with celebration box
    pub fn print_block_found(&self, height: u64, hash: &str, reward: Amount) {
        let c = self.config.use_colors;
        let width = 58;

        println!();
        println!();

        // Celebration header with double box
        if c {
            println!("  {}{}{}{}",
                colors::BRIGHT_GREEN,
                box_chars::D_TOP_LEFT,
                box_chars::D_HORIZONTAL.repeat(width),
                box_chars::D_TOP_RIGHT);
            println!("  {}{}  {} {} {} BLOCK FOUND! {} {} {}{}{}",
                colors::BOLD,
                box_chars::D_VERTICAL,
                box_chars::FIRE, box_chars::DIAMOND,
                colors::BRIGHT_GREEN,
                colors::RESET, colors::BRIGHT_GREEN,
                box_chars::DIAMOND, box_chars::FIRE,
                " ".repeat(width - 30));
            println!("{}{}", box_chars::D_VERTICAL, colors::RESET);
        } else {
            println!("  {}{}{}", box_chars::D_TOP_LEFT,
                box_chars::D_HORIZONTAL.repeat(width), box_chars::D_TOP_RIGHT);
            println!("  {}  *** BLOCK FOUND! ***{}{}",
                box_chars::D_VERTICAL, " ".repeat(width - 22), box_chars::D_VERTICAL);
        }

        // Separator
        if c {
            println!("  {}{}{}{}{}",
                colors::BRIGHT_GREEN, box_chars::D_T_RIGHT,
                box_chars::D_HORIZONTAL.repeat(width),
                box_chars::D_T_LEFT, colors::RESET);
        } else {
            println!("  {}{}{}", box_chars::D_T_RIGHT,
                box_chars::D_HORIZONTAL.repeat(width), box_chars::D_T_LEFT);
        }

        // Block details
        let reward_str = format!("{:.4} CYNC", reward.as_atomic() as f64 / 1_000_000_000_000.0);

        self.print_box_field_with_indicator("Height", &format_large_number(height), box_chars::DOT_FILLED, true, width, c);

        // Truncate hash if too long
        let hash_display = if hash.len() > 40 {
            format!("{}...", &hash[..37])
        } else {
            hash.to_string()
        };
        self.print_box_field("Hash", &hash_display, width, c);
        self.print_box_field_with_indicator("Reward", &reward_str, box_chars::COIN, true, width, c);
        self.print_box_field("Hashrate", &format!("{}/s", format_hashrate(self.metrics.hashrate)), width, c);
        self.print_box_field_with_indicator("Time", &format_duration(self.metrics.uptime), box_chars::CLOCK, true, width, c);

        // Bottom
        if c {
            println!("  {}{}{}{}{}",
                colors::BRIGHT_GREEN, box_chars::D_BOTTOM_LEFT,
                box_chars::D_HORIZONTAL.repeat(width),
                box_chars::D_BOTTOM_RIGHT, colors::RESET);
        } else {
            println!("  {}{}{}", box_chars::D_BOTTOM_LEFT,
                box_chars::D_HORIZONTAL.repeat(width), box_chars::D_BOTTOM_RIGHT);
        }

        println!();
    }

    /// Update network state
    pub fn update_network(&mut self, network: NetworkState) {
        // Check for warnings
        if network.peer_count == 0 && self.is_connected {
            self.add_warning(MinerWarning::NoPeers);
        }

        self.network = network;
    }

    /// Update live metrics
    pub fn update_metrics(&mut self, metrics: LiveMetrics) {
        self.metrics = metrics;
        self.metrics.uptime = self.start_time.elapsed();
    }

    /// Set connection status
    pub fn set_connected(&mut self, connected: bool) {
        if self.is_connected && !connected {
            self.add_warning(MinerWarning::NodeDisconnected);
        }
        self.is_connected = connected;
    }

    /// Add a warning
    pub fn add_warning(&mut self, warning: MinerWarning) {
        // Don't add duplicate warnings
        let dominated = self.warnings.iter().any(|w| {
            std::mem::discriminant(w) == std::mem::discriminant(&warning)
        });

        if !dominated {
            self.warnings.push(warning);
        }
    }

    /// Clear a warning type
    pub fn clear_warning_type<F>(&mut self, predicate: F)
    where
        F: Fn(&MinerWarning) -> bool,
    {
        self.warnings.retain(|w| !predicate(w));
    }

    // Helper methods for formatted output (used by display rendering)

    #[allow(dead_code)]
    fn print_header(&self, title: &str, use_colors: bool) {
        if use_colors {
            println!("\x1b[36;1m=== {} ===\x1b[0m", title);
        } else {
            println!("=== {} ===", title);
        }
    }

    #[allow(dead_code)]
    fn print_section_header(&self, title: &str, use_colors: bool) {
        if use_colors {
            println!("  \x1b[1m{}\x1b[0m", title);
        } else {
            println!("  {}", title);
        }
    }

    #[allow(dead_code)]
    fn print_field(&self, label: &str, value: &str, use_colors: bool) {
        if use_colors {
            println!("    \x1b[90m{:>18}:\x1b[0m {}", label, value);
        } else {
            println!("    {:>18}: {}", label, value);
        }
    }
}

// ============================================================================
// Mining Events and Progress Tracking
// ============================================================================

/// Mining event types for notifications
#[derive(Clone, Debug)]
pub enum MiningEvent {
    /// Started mining on a new block
    Started { height: u64, target_difficulty: u128 },
    /// Found a valid block
    BlockFound { height: u64, nonce: u64, hash: String },
    /// Another miner found the block first
    BlockLost { height: u64, winner: Option<String> },
    /// Mining stopped
    Stopped,
    /// Progress update
    Progress { percent: f64, hashrate: f64, elapsed: Duration },
    /// Difficulty adjustment occurred
    DifficultyAdjusted { old: u128, new: u128, change_percent: f64 },
}

/// Progress bar configuration
#[derive(Clone, Debug)]
pub struct ProgressConfig {
    /// Width of progress bar in characters
    pub bar_width: usize,
    /// Update interval for progress display
    pub update_interval: Duration,
    /// Show detailed stats
    pub show_details: bool,
    /// Use colors (ANSI escape codes)
    pub use_colors: bool,
}

impl Default for ProgressConfig {
    fn default() -> Self {
        ProgressConfig {
            bar_width: 40,
            update_interval: Duration::from_millis(500),
            show_details: true,
            use_colors: true,
        }
    }
}

/// Mining progress tracker
#[allow(dead_code)]
pub struct MiningProgress {
    config: ProgressConfig,
    start_time: Instant,
    hashes: Arc<AtomicU64>,
    is_active: Arc<AtomicBool>,
    current_height: AtomicU64,
    target_difficulty: AtomicU64,
    estimated_time_secs: AtomicU64,
}

impl MiningProgress {
    /// Create new progress tracker
    pub fn new(config: ProgressConfig) -> Self {
        MiningProgress {
            config,
            start_time: Instant::now(),
            hashes: Arc::new(AtomicU64::new(0)),
            is_active: Arc::new(AtomicBool::new(false)),
            current_height: AtomicU64::new(0),
            target_difficulty: AtomicU64::new(0),
            estimated_time_secs: AtomicU64::new(0),
        }
    }

    /// Start tracking a new mining session
    pub fn start(&mut self, height: u64, difficulty: u128) {
        self.start_time = Instant::now();
        self.hashes.store(0, Ordering::SeqCst);
        self.is_active.store(true, Ordering::SeqCst);
        self.current_height.store(height, Ordering::SeqCst);
        self.target_difficulty.store(difficulty as u64, Ordering::SeqCst);

        if self.config.use_colors {
            println!("\x1b[32m[MINING]\x1b[0m Starting to mine block {}", height);
        } else {
            println!("[MINING] Starting to mine block {}", height);
        }
        println!("  Target difficulty: {}", format_difficulty(difficulty));
    }

    /// Update hash count
    pub fn add_hashes(&self, count: u64) {
        self.hashes.fetch_add(count, Ordering::Relaxed);
    }

    /// Get current hashrate
    pub fn hashrate(&self) -> f64 {
        let elapsed = self.start_time.elapsed().as_secs_f64();
        if elapsed > 0.0 {
            self.hashes.load(Ordering::Relaxed) as f64 / elapsed
        } else {
            0.0
        }
    }

    /// Estimate time to find block based on current hashrate and difficulty
    pub fn estimate_time_to_block(&self, difficulty: u128) -> Duration {
        let hashrate = self.hashrate();
        if hashrate > 0.0 {
            let expected_hashes = difficulty as f64;
            let seconds = expected_hashes / hashrate;
            Duration::from_secs_f64(seconds.min(86400.0 * 365.0)) // Cap at 1 year
        } else {
            Duration::from_secs(u64::MAX)
        }
    }

    /// Render progress bar to string
    pub fn render_progress_bar(&self) -> String {
        let elapsed = self.start_time.elapsed();
        let hashrate = self.hashrate();
        let difficulty = self.target_difficulty.load(Ordering::Relaxed) as u128;
        let hashes = self.hashes.load(Ordering::Relaxed);

        // Estimate progress (probabilistic - not exact)
        let progress = if difficulty > 0 {
            let expected = difficulty as f64;
            let done = hashes as f64;
            (done / expected).min(0.99) // Never show 100% until actually found
        } else {
            0.0
        };

        let filled = (progress * self.config.bar_width as f64) as usize;
        let empty = self.config.bar_width - filled;

        let bar = if self.config.use_colors {
            format!(
                "\x1b[32m{}\x1b[0m{}",
                "=".repeat(filled),
                " ".repeat(empty)
            )
        } else {
            format!("{}{}", "=".repeat(filled), " ".repeat(empty))
        };

        let eta = self.estimate_time_to_block(difficulty);

        format!(
            "[{}] {:.1}% | {}/s | ETA: {} | Elapsed: {}",
            bar,
            progress * 100.0,
            format_hashrate(hashrate),
            format_duration(eta),
            format_duration(elapsed),
        )
    }

    /// Print progress update to console
    pub fn print_progress(&self) {
        let bar = self.render_progress_bar();
        // Use carriage return to overwrite previous line
        print!("\r{}", bar);
        use std::io::Write;
        let _ = std::io::stdout().flush();
    }

    /// Notify block found
    pub fn block_found(&self, height: u64, nonce: u64, hash: &str) {
        println!(); // New line after progress bar
        if self.config.use_colors {
            println!("\x1b[32;1m[SUCCESS]\x1b[0m Block {} found!", height);
        } else {
            println!("[SUCCESS] Block {} found!", height);
        }
        println!("  Nonce:    {}", nonce);
        println!("  Hash:     {}", hash);
        println!("  Hashrate: {}/s", format_hashrate(self.hashrate()));
        println!("  Time:     {}", format_duration(self.start_time.elapsed()));

        self.is_active.store(false, Ordering::SeqCst);
    }

    /// Notify block lost to another miner
    pub fn block_lost(&self, height: u64, winner: Option<&str>) {
        println!(); // New line after progress bar
        if self.config.use_colors {
            println!("\x1b[31m[LOST]\x1b[0m Block {} found by another miner", height);
        } else {
            println!("[LOST] Block {} found by another miner", height);
        }
        if let Some(w) = winner {
            println!("  Winner: {}", w);
        }
        println!("  Your hashrate was: {}/s", format_hashrate(self.hashrate()));

        self.is_active.store(false, Ordering::SeqCst);
    }

    /// Stop tracking
    pub fn stop(&self) {
        println!(); // New line after progress bar
        if self.config.use_colors {
            println!("\x1b[33m[STOPPED]\x1b[0m Mining stopped");
        } else {
            println!("[STOPPED] Mining stopped");
        }
        println!(
            "  Total hashes: {}",
            format_large_number(self.hashes.load(Ordering::Relaxed))
        );
        println!("  Duration: {}", format_duration(self.start_time.elapsed()));

        self.is_active.store(false, Ordering::SeqCst);
    }

    /// Check if mining is active
    pub fn is_active(&self) -> bool {
        self.is_active.load(Ordering::SeqCst)
    }

    /// Get handle for updating from mining thread
    pub fn handle(&self) -> MiningProgressHandle {
        MiningProgressHandle {
            hashes: Arc::clone(&self.hashes),
            is_active: Arc::clone(&self.is_active),
        }
    }
}

/// Handle for updating progress from mining thread
#[derive(Clone)]
pub struct MiningProgressHandle {
    hashes: Arc<AtomicU64>,
    is_active: Arc<AtomicBool>,
}

impl MiningProgressHandle {
    /// Add hashes to counter
    pub fn add_hashes(&self, count: u64) {
        self.hashes.fetch_add(count, Ordering::Relaxed);
    }

    /// Check if should continue mining
    pub fn should_continue(&self) -> bool {
        self.is_active.load(Ordering::Relaxed)
    }
}

/// Format hashrate for display
pub fn format_hashrate(hashrate: f64) -> String {
    if hashrate >= 1_000_000_000_000.0 {
        format!("{:.2} TH", hashrate / 1_000_000_000_000.0)
    } else if hashrate >= 1_000_000_000.0 {
        format!("{:.2} GH", hashrate / 1_000_000_000.0)
    } else if hashrate >= 1_000_000.0 {
        format!("{:.2} MH", hashrate / 1_000_000.0)
    } else if hashrate >= 1_000.0 {
        format!("{:.2} KH", hashrate / 1_000.0)
    } else {
        format!("{:.0} H", hashrate)
    }
}

/// Format duration for display
pub fn format_duration(duration: Duration) -> String {
    let secs = duration.as_secs();
    if secs >= 86400 {
        let days = secs / 86400;
        let hours = (secs % 86400) / 3600;
        format!("{}d {}h", days, hours)
    } else if secs >= 3600 {
        let hours = secs / 3600;
        let mins = (secs % 3600) / 60;
        format!("{}h {}m", hours, mins)
    } else if secs >= 60 {
        let mins = secs / 60;
        let secs_rem = secs % 60;
        format!("{}m {}s", mins, secs_rem)
    } else {
        format!("{}s", secs)
    }
}

/// Format difficulty for display
pub fn format_difficulty(difficulty: u128) -> String {
    if difficulty >= 1_000_000_000_000 {
        format!("{:.2}T", difficulty as f64 / 1_000_000_000_000.0)
    } else if difficulty >= 1_000_000_000 {
        format!("{:.2}G", difficulty as f64 / 1_000_000_000.0)
    } else if difficulty >= 1_000_000 {
        format!("{:.2}M", difficulty as f64 / 1_000_000.0)
    } else if difficulty >= 1_000 {
        format!("{:.2}K", difficulty as f64 / 1_000.0)
    } else {
        format!("{}", difficulty)
    }
}

/// Format large numbers with separators
pub fn format_large_number(n: u64) -> String {
    let s = n.to_string();
    let mut result = String::new();
    let chars: Vec<char> = s.chars().rev().collect();

    for (i, c) in chars.iter().enumerate() {
        if i > 0 && i % 3 == 0 {
            result.push(',');
        }
        result.push(*c);
    }

    result.chars().rev().collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_format_hashrate() {
        assert_eq!(format_hashrate(500.0), "500 H");
        assert_eq!(format_hashrate(1500.0), "1.50 KH");
        assert_eq!(format_hashrate(1_500_000.0), "1.50 MH");
        assert_eq!(format_hashrate(1_500_000_000.0), "1.50 GH");
    }

    #[test]
    fn test_format_duration() {
        assert_eq!(format_duration(Duration::from_secs(30)), "30s");
        assert_eq!(format_duration(Duration::from_secs(90)), "1m 30s");
        assert_eq!(format_duration(Duration::from_secs(3700)), "1h 1m");
        assert_eq!(format_duration(Duration::from_secs(90000)), "1d 1h");
    }

    #[test]
    fn test_format_difficulty() {
        assert_eq!(format_difficulty(500), "500");
        assert_eq!(format_difficulty(1500), "1.50K");
        assert_eq!(format_difficulty(1_500_000), "1.50M");
    }

    #[test]
    fn test_format_large_number() {
        assert_eq!(format_large_number(1000), "1,000");
        assert_eq!(format_large_number(1000000), "1,000,000");
        assert_eq!(format_large_number(123456789), "123,456,789");
    }

    #[test]
    fn test_mining_progress() {
        let config = ProgressConfig::default();
        let progress = MiningProgress::new(config);

        assert!(!progress.is_active());
        assert_eq!(progress.hashrate(), 0.0);
    }

    #[test]
    fn test_miner_display_config() {
        let config = MinerDisplayConfig::default();
        assert_eq!(config.mode, MiningMode::Solo);
        assert_eq!(config.threads, 1);
        assert!(config.use_colors);
    }

    #[test]
    fn test_miner_display_new() {
        let config = MinerDisplayConfig {
            mining_address: "CYNC1abc123def456".to_string(),
            network: "testnet".to_string(),
            threads: 4,
            ..Default::default()
        };

        let display = MinerDisplay::new(config);
        assert!(!display.is_connected);
    }

    #[test]
    fn test_network_state_default() {
        let state = NetworkState::default();
        assert_eq!(state.block_height, 0);
        assert_eq!(state.difficulty, 0);
        assert_eq!(state.peer_count, 0);
    }

    #[test]
    fn test_live_metrics_estimate_earnings() {
        let metrics = LiveMetrics {
            hashrate: 1000.0, // 1 KH/s
            ..Default::default()
        };

        let network = NetworkState {
            network_hashrate: 100000.0, // 100 KH/s total
            block_time: 30,
            ..Default::default()
        };

        let block_reward = Amount::from_atomic(1_000_000_000_000); // 1 CYNC
        let daily = metrics.estimate_daily_earnings(&network, block_reward);

        // With 1% of network hashrate, ~1% of daily blocks = ~28.8 blocks/day * 0.01 = ~0.288 CYNC/day
        assert!(daily.as_atomic() > 0);
    }

    #[test]
    fn test_miner_warning_format() {
        let warning = MinerWarning::NoPeers;
        let formatted = warning.format(false);
        assert!(formatted.contains("no peers"));
    }

    #[test]
    fn test_mining_mode_display() {
        assert_eq!(MiningMode::Solo.to_string(), "Solo Mining");
        assert_eq!(MiningMode::Pool.to_string(), "Pool Mining");
    }

    #[test]
    fn test_miner_display_warnings() {
        let config = MinerDisplayConfig::default();
        let mut display = MinerDisplay::new(config);

        display.add_warning(MinerWarning::NoPeers);
        assert_eq!(display.warnings.len(), 1);

        // Adding same warning type again should not duplicate
        display.add_warning(MinerWarning::NoPeers);
        assert_eq!(display.warnings.len(), 1);

        // Different warning type should be added
        display.add_warning(MinerWarning::NodeDisconnected);
        assert_eq!(display.warnings.len(), 2);
    }

    #[test]
    fn test_zero_hashrate_display() {
        // 0 H/s should format without panic
        let formatted = format_hashrate(0.0);
        assert_eq!(formatted, "0 H");
    }
}