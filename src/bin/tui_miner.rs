//! CoinCync Mining TUI — polished terminal dashboard + miner launcher.
//!
//! Spawns `coincync-miner` as a child process, parses its output for
//! live metrics, and polls the local node RPC for chain state.
//!
//! Usage:
//!   coincync-tui-miner --address tCYNC1... [--threads 4] [--rpc http://127.0.0.1:28081] [--testnet]
//!
//! Monitor-only (no mining):
//!   coincync-tui-miner [--rpc http://127.0.0.1:28081]

use std::collections::VecDeque;
use std::io::{self, Read};
use std::process::{Child, Command, Stdio};
use std::sync::mpsc;
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use chrono::{DateTime, Local};
use clap::Parser;
use crossterm::{
    event::{self, Event, KeyCode},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::{
    backend::CrosstermBackend,
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, List, ListItem, Paragraph, Sparkline},
    Frame, Terminal,
};
use serde_json::Value;

// ═══════════════════════════════════════════════════════════════════════
// CLI
// ═══════════════════════════════════════════════════════════════════════

#[derive(Parser)]
#[command(name = "coincync-tui-miner")]
#[command(about = "CoinCync Mining TUI Dashboard")]
#[command(version = coincync::VERSION)]
struct Args {
    /// Mining reward address (tCYNC.../CYNC...)
    #[arg(long)]
    address: Option<String>,

    /// Number of mining threads (0 = auto-detect CPU cores)
    #[arg(long, default_value = "0")]
    threads: u32,

    /// Node RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:28081")]
    rpc: String,

    /// Use testnet
    #[arg(long)]
    testnet: bool,
}

// ═══════════════════════════════════════════════════════════════════════
// Palette — gold-on-dark, CoinCync brand
// ═══════════════════════════════════════════════════════════════════════

const GOLD:  Color = Color::Rgb(212, 168, 67);
const DGOLD: Color = Color::Rgb(107, 84, 34);
const DIM:   Color = Color::Rgb(64, 52, 28);
const GREEN: Color = Color::Rgb(51, 255, 87);
const RED:   Color = Color::Rgb(255, 68, 68);
const CYAN:  Color = Color::Rgb(0, 229, 255);
const AMBER: Color = Color::Rgb(255, 179, 0);
const WHITE: Color = Color::Rgb(230, 225, 215);
const BG:    Color = Color::Rgb(10, 10, 15);

fn gold()      -> Style { Style::default().fg(GOLD) }
fn dgold()     -> Style { Style::default().fg(DGOLD) }
fn dim()       -> Style { Style::default().fg(DIM) }
fn green()     -> Style { Style::default().fg(GREEN) }
fn red()       -> Style { Style::default().fg(RED) }
fn cyan()      -> Style { Style::default().fg(CYAN) }
fn amber()     -> Style { Style::default().fg(AMBER) }
fn white()     -> Style { Style::default().fg(WHITE) }
fn bold_gold() -> Style { Style::default().fg(GOLD).add_modifier(Modifier::BOLD) }

fn panel(title: &str) -> Block<'_> {
    Block::default()
        .title(Span::styled(format!(" {} ", title), dgold()))
        .borders(Borders::ALL)
        .border_style(dgold())
        .style(Style::default().bg(BG))
}

// ═══════════════════════════════════════════════════════════════════════
// Events — channel-driven architecture (no shared mutexes)
// ═══════════════════════════════════════════════════════════════════════

enum AppEvent {
    MinerLine(String),
    MinerExited,
    ChainUpdate(ChainInfo),
    RpcDown,
}

struct ChainInfo {
    height: u64,
    difficulty: String,
    tip_age_secs: u64,
    synced: bool,
    peer_count: u64,
    network: String,
    block_reward: u64,
    ping_ms: u64,
    tx_pool_size: u64,
}

// ═══════════════════════════════════════════════════════════════════════
// Data models
// ═══════════════════════════════════════════════════════════════════════

#[derive(Clone)]
struct FoundBlock {
    height: u64,
    time: DateTime<Local>,
    reward_estimate: u64,
}

impl FoundBlock {
    fn ago(&self) -> String {
        let secs = Local::now()
            .signed_duration_since(self.time)
            .num_seconds()
            .max(0);
        if secs < 60 {
            format!("{}s ago", secs)
        } else if secs < 3600 {
            format!("{}m ago", secs / 60)
        } else if secs < 86400 {
            format!("{}h {}m", secs / 3600, (secs % 3600) / 60)
        } else {
            format!("{}d {}h", secs / 86400, (secs % 86400) / 3600)
        }
    }
}

#[derive(Clone, Copy, PartialEq)]
enum LogLevel {
    Info,
    Warn,
    Error,
    Block,
}

impl LogLevel {
    fn color(self) -> Color {
        match self {
            LogLevel::Info  => CYAN,
            LogLevel::Warn  => AMBER,
            LogLevel::Error => RED,
            LogLevel::Block => GREEN,
        }
    }

    fn label(self) -> &'static str {
        match self {
            LogLevel::Info  => "INFO",
            LogLevel::Warn  => "WARN",
            LogLevel::Error => "ERR ",
            LogLevel::Block => "BLK ",
        }
    }
}

#[derive(Clone)]
struct LogEntry {
    time: DateTime<Local>,
    level: LogLevel,
    message: String,
}

// ═══════════════════════════════════════════════════════════════════════
// App state — sole owner, updated via event channel
// ═══════════════════════════════════════════════════════════════════════

struct App {
    // Config
    address: Option<String>,
    threads: u32,
    rpc_url: String,
    testnet: bool,

    // Miner process
    miner_pid: Option<u32>,
    miner_alive: bool,

    // Mining stats (parsed from miner output)
    hashrate: f64,
    hashrate_peak: f64,
    hashrate_history: VecDeque<u64>,
    blocks_found: u64,

    // Chain state (from RPC)
    chain_height: u64,
    difficulty: String,
    tip_age_secs: u64,
    synced: bool,
    peer_count: u64,
    network: String,
    block_reward: u64,
    rpc_connected: bool,
    rpc_ping_ms: u64,
    tx_pool_size: u64,

    // Found blocks
    found_blocks: Vec<FoundBlock>,

    // Log
    log: VecDeque<LogEntry>,

    // Session
    start_time: Instant,
    should_quit: bool,
    last_hr_record: Instant,
}

impl App {
    fn new(args: &Args) -> Self {
        Self {
            address: args.address.clone(),
            threads: args.threads,
            rpc_url: args.rpc.clone(),
            testnet: args.testnet,

            miner_pid: None,
            miner_alive: false,

            hashrate: 0.0,
            hashrate_peak: 0.0,
            hashrate_history: VecDeque::new(),
            blocks_found: 0,

            chain_height: 0,
            difficulty: "0".into(),
            tip_age_secs: 0,
            synced: false,
            peer_count: 0,
            network: if args.testnet { "testnet" } else { "mainnet" }.into(),
            block_reward: 0,
            rpc_connected: false,
            rpc_ping_ms: 0,
            tx_pool_size: 0,

            found_blocks: Vec::new(),
            log: VecDeque::new(),
            start_time: Instant::now(),
            should_quit: false,
            last_hr_record: Instant::now(),
        }
    }

    fn push_log(&mut self, level: LogLevel, message: String) {
        self.log.push_front(LogEntry {
            time: Local::now(),
            level,
            message,
        });
        if self.log.len() > 500 {
            self.log.truncate(500);
        }
    }

    fn uptime(&self) -> String {
        let s = self.start_time.elapsed().as_secs();
        format!("{:02}:{:02}:{:02}", s / 3600, (s % 3600) / 60, s % 60)
    }

    /// Parse a line from the miner subprocess stdout/stderr.
    fn process_miner_line(&mut self, raw: &str) {
        let line = strip_ansi(raw);
        let trimmed = line.trim();
        if trimmed.is_empty() {
            return;
        }

        // ── Block found ─────────────────────────────────────
        if trimmed.contains("BLOCK FOUND") {
            self.blocks_found += 1;
            if let Some(h) = extract_number_after(trimmed, "height ") {
                self.found_blocks.insert(
                    0,
                    FoundBlock {
                        height: h,
                        time: Local::now(),
                        reward_estimate: self.block_reward,
                    },
                );
                if self.found_blocks.len() > 50 {
                    self.found_blocks.truncate(50);
                }
            }
            self.push_log(LogLevel::Block, trimmed.to_string());
            return;
        }

        // ── Hashrate from live update line ───────────────────
        if let Some(hr) = extract_hashrate(trimmed) {
            self.hashrate = hr;
            if hr > self.hashrate_peak {
                self.hashrate_peak = hr;
            }
        }

        // ── Blocks count from live line (B:N) ───────────────
        if let Some(b) = extract_number_after(trimmed, "B:") {
            if b > self.blocks_found {
                self.blocks_found = b;
            }
        }

        // ── Classify log level ──────────────────────────────
        let level = if trimmed.contains("error")
            || trimmed.contains("Error")
            || trimmed.contains("failed")
        {
            LogLevel::Error
        } else if trimmed.contains("warn") || trimmed.contains("Warn") {
            LogLevel::Warn
        } else {
            LogLevel::Info
        };

        // Skip the rapid-fire live update lines (500ms cadence) from
        // flooding the log. They contain "H/s" AND "B:" AND "CYNC/day".
        let is_live_ticker = trimmed.contains("H/s")
            && trimmed.contains("B:")
            && trimmed.contains("CYNC/day");
        if !is_live_ticker {
            self.push_log(level, trimmed.to_string());
        }
    }

    fn update_chain(&mut self, info: ChainInfo) {
        self.chain_height = info.height;
        self.difficulty = info.difficulty;
        self.tip_age_secs = info.tip_age_secs;
        self.synced = info.synced;
        self.peer_count = info.peer_count;
        self.network = info.network;
        self.block_reward = info.block_reward;
        self.rpc_connected = true;
        self.rpc_ping_ms = info.ping_ms;
        self.tx_pool_size = info.tx_pool_size;
    }

    /// Record current hashrate for sparkline (called every second).
    fn record_hashrate_tick(&mut self) {
        if self.last_hr_record.elapsed() >= Duration::from_secs(1) {
            self.hashrate_history
                .push_back(self.hashrate.round() as u64);
            if self.hashrate_history.len() > 120 {
                self.hashrate_history.pop_front();
            }
            self.last_hr_record = Instant::now();
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════
// Formatting helpers
// ═══════════════════════════════════════════════════════════════════════

fn fmt_hashrate(h: f64) -> String {
    if h >= 1_000_000_000.0 {
        format!("{:.2} GH/s", h / 1_000_000_000.0)
    } else if h >= 1_000_000.0 {
        format!("{:.2} MH/s", h / 1_000_000.0)
    } else if h >= 1_000.0 {
        format!("{:.2} KH/s", h / 1_000.0)
    } else {
        format!("{:.1} H/s", h)
    }
}

fn fmt_cync(atomic: u64) -> String {
    let whole = atomic / 1_000_000_000_000;
    let frac = (atomic % 1_000_000_000_000) / 100_000_000;
    if frac == 0 {
        format!("{} CYNC", whole)
    } else {
        format!("{}.{:04} CYNC", whole, frac)
    }
}

fn fmt_number(n: u64) -> String {
    let s = n.to_string();
    let mut r = String::new();
    for (i, c) in s.chars().rev().enumerate() {
        if i > 0 && i % 3 == 0 {
            r.push(',');
        }
        r.push(c);
    }
    r.chars().rev().collect()
}

fn fmt_duration_short(secs: u64) -> String {
    if secs < 60 {
        format!("{}s", secs)
    } else if secs < 3600 {
        format!("{}m {:02}s", secs / 60, secs % 60)
    } else {
        format!("{}h {:02}m", secs / 3600, (secs % 3600) / 60)
    }
}

fn truncate_addr(addr: &str, max: usize) -> String {
    if addr.len() <= max {
        addr.to_string()
    } else {
        let half = max / 2;
        format!("{}…{}", &addr[..half], &addr[addr.len() - half..])
    }
}

// ═══════════════════════════════════════════════════════════════════════
// ANSI stripping + output parsing
// ═══════════════════════════════════════════════════════════════════════

fn strip_ansi(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut chars = s.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '\x1b' {
            // Skip ESC[...m and similar CSI sequences
            if chars.peek() == Some(&'[') {
                chars.next();
                while let Some(&n) = chars.peek() {
                    chars.next();
                    if n.is_ascii_alphabetic() {
                        break;
                    }
                }
            }
        } else {
            out.push(c);
        }
    }
    out
}

fn extract_hashrate(line: &str) -> Option<f64> {
    let lower = line.to_lowercase();
    for (suffix, mult) in [
        ("gh/s", 1e9),
        ("mh/s", 1e6),
        ("kh/s", 1e3),
        ("h/s", 1.0),
        ("gh", 1e9),
        ("mh", 1e6),
        ("kh", 1e3),
    ] {
        if let Some(pos) = lower.find(suffix) {
            let before = lower[..pos].trim();
            let token = before.split_whitespace().last()?;
            let clean = token.replace(',', "");
            if let Ok(val) = clean.parse::<f64>() {
                return Some(val * mult);
            }
        }
    }
    None
}

fn extract_number_after(line: &str, keyword: &str) -> Option<u64> {
    let pos = line.find(keyword)?;
    let after = &line[pos + keyword.len()..];
    let num: String = after
        .chars()
        .take_while(|c| c.is_ascii_digit() || *c == ',')
        .collect();
    num.replace(',', "").parse().ok()
}

// ═══════════════════════════════════════════════════════════════════════
// RPC polling (tokio task)
// ═══════════════════════════════════════════════════════════════════════

async fn rpc_call_async(
    client: &reqwest::Client,
    url: &str,
    method: &str,
) -> Result<Value> {
    let body = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": method,
        "params": [],
    });
    let mut req = client.post(url).json(&body);
    if let Ok(key) = std::env::var("COINCYNC_RPC_API_KEY") {
        let key = key.trim();
        if !key.is_empty() {
            req = req.header("Authorization", format!("Bearer {}", key));
        }
    }
    let resp = req
        .send()
        .await
        .context("RPC request failed")?;
    if resp.status() == reqwest::StatusCode::UNAUTHORIZED {
        anyhow::bail!(
            "RPC unauthorized (401). Set COINCYNC_RPC_API_KEY when node enforces Bearer auth."
        );
    }
    let json: Value = resp.json().await.context("RPC parse failed")?;
    if let Some(err) = json.get("error") {
        anyhow::bail!("RPC error: {}", err);
    }
    Ok(json["result"].clone())
}

fn spawn_rpc_poller(rpc_url: String, tx: mpsc::Sender<AppEvent>) {
    tokio::spawn(async move {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(5))
            .danger_accept_invalid_certs(true)
            .build()
            .unwrap();

        loop {
            let start = Instant::now();

            match rpc_call_async(&client, &rpc_url, "get_info").await {
                Ok(v) => {
                    let ping = start.elapsed().as_millis() as u64;
                    let height = v["height"].as_u64().unwrap_or(0);

                    // Also fetch block reward estimate from supply info
                    let reward =
                        match rpc_call_async(&client, &rpc_url, "get_supply_info").await {
                            Ok(s) => {
                                let emitted = s["total_emitted"].as_u64().unwrap_or(0);
                                let h = s["height"].as_u64().unwrap_or(1).max(1);
                                emitted / h
                            }
                            Err(_) => 0,
                        };

                    let _ = tx.send(AppEvent::ChainUpdate(ChainInfo {
                        height,
                        difficulty: v["difficulty"]
                            .as_str()
                            .unwrap_or("0")
                            .to_string(),
                        tip_age_secs: v["tip_age_secs"].as_u64().unwrap_or(0),
                        synced: v["synced"].as_bool().unwrap_or(false),
                        peer_count: v["peer_count"].as_u64().unwrap_or(0),
                        network: v["network"]
                            .as_str()
                            .unwrap_or("unknown")
                            .to_string(),
                        block_reward: reward,
                        ping_ms: ping,
                        tx_pool_size: v["tx_pool_size"].as_u64().unwrap_or(0),
                    }));
                }
                Err(_) => {
                    let _ = tx.send(AppEvent::RpcDown);
                }
            }

            tokio::time::sleep(Duration::from_secs(2)).await;
        }
    });
}

// ═══════════════════════════════════════════════════════════════════════
// Miner process management
// ═══════════════════════════════════════════════════════════════════════

/// RAII guard — kills the child miner when the TUI exits.
struct MinerGuard {
    child: Child,
}

impl Drop for MinerGuard {
    fn drop(&mut self) {
        // On Windows, also kill the child's subtree so the actual
        // mining threads don't outlive the TUI.
        #[cfg(windows)]
        {
            let pid = self.child.id();
            let _ = Command::new("taskkill")
                .args(["/F", "/T", "/PID", &pid.to_string()])
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status();
        }
        #[cfg(not(windows))]
        {
            let _ = self.child.kill();
        }
        let _ = self.child.wait();
    }
}

fn resolve_miner_binary() -> String {
    let self_dir = std::env::current_exe()
        .ok()
        .and_then(|e| e.parent().map(|p| p.to_path_buf()));

    if let Some(ref dir) = self_dir {
        for name in &["coincync-miner.exe", "coincync-miner"] {
            let p = dir.join(name);
            if p.exists() {
                return p.to_string_lossy().to_string();
            }
        }
        // Dev builds: check parent target dirs
        for sub in &[
            "../release",
            "../debug",
            "../../target/release",
            "../../target/debug",
        ] {
            for name in &["coincync-miner.exe", "coincync-miner"] {
                let p = dir.join(sub).join(name);
                if let Ok(canonical) = p.canonicalize() {
                    return canonical.to_string_lossy().to_string();
                }
            }
        }
    }
    "coincync-miner".to_string() // fall back to PATH
}

fn spawn_miner(args: &Args, tx: mpsc::Sender<AppEvent>) -> Result<MinerGuard> {
    let miner_bin = resolve_miner_binary();
    let address = args.address.as_ref().context("No mining address")?;
    let node_addr = args
        .rpc
        .trim_start_matches("http://")
        .trim_start_matches("https://");

    let mut cmd = Command::new(&miner_bin);
    cmd.args(["--address", address]);
    if args.threads > 0 {
        cmd.args(["--threads", &args.threads.to_string()]);
    }
    cmd.args(["--node", node_addr]);
    if args.testnet {
        cmd.arg("--testnet");
    }
    cmd.stdout(Stdio::piped()).stderr(Stdio::piped());

    let mut child = cmd
        .spawn()
        .context(format!("Failed to spawn miner: {}", miner_bin))?;
    let pid = child.id();

    // Background reader for stdout (handles \r live-update lines)
    let stdout = child.stdout.take().unwrap();
    let tx_out = tx.clone();
    std::thread::spawn(move || read_miner_output(stdout, tx_out));

    // Background reader for stderr
    let stderr = child.stderr.take().unwrap();
    let tx_err = tx.clone();
    std::thread::spawn(move || read_miner_output(stderr, tx_err));

    let _ = tx.send(AppEvent::MinerLine(format!(
        "Miner started (PID: {}, binary: {})",
        pid, miner_bin
    )));

    Ok(MinerGuard { child })
}

/// Read from a pipe, splitting on both \r and \n.
/// The miner uses \r for live status overwrites and \n for events.
fn read_miner_output(mut reader: impl Read + Send + 'static, tx: mpsc::Sender<AppEvent>) {
    let mut buf = [0u8; 4096];
    let mut partial = String::new();
    loop {
        match reader.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => {
                let chunk = String::from_utf8_lossy(&buf[..n]);
                partial.push_str(&chunk);
                while let Some(pos) = partial.find(|c: char| c == '\r' || c == '\n') {
                    let line: String = partial.drain(..=pos).collect();
                    let trimmed = line.trim();
                    if !trimmed.is_empty() {
                        let _ = tx.send(AppEvent::MinerLine(trimmed.to_string()));
                    }
                }
                // Safety valve: discard partial buffer if it grows too large
                if partial.len() > 8192 {
                    partial.clear();
                }
            }
            Err(_) => break,
        }
    }
    let _ = tx.send(AppEvent::MinerExited);
}

// ═══════════════════════════════════════════════════════════════════════
// UI rendering
// ═══════════════════════════════════════════════════════════════════════

fn draw(frame: &mut Frame, app: &App) {
    let area = frame.area();

    // Fill background
    frame.render_widget(Block::default().style(Style::default().bg(BG)), area);

    // Outer: header / body / footer
    let outer = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(1), // header
            Constraint::Min(0),    // body
            Constraint::Length(1), // footer
        ])
        .split(area);

    draw_header(frame, app, outer[0]);
    draw_body(frame, app, outer[1]);
    draw_footer(frame, app, outer[2]);
}

// ── Header ──────────────────────────────────────────────────────────

fn draw_header(frame: &mut Frame, app: &App, area: Rect) {
    let now = Local::now().format("%H:%M:%S").to_string();
    let net = if app.testnet { "testnet" } else { "mainnet" };
    let (conn_label, conn_style) = if app.rpc_connected {
        ("● NODE CONNECTED", green())
    } else {
        ("○ DISCONNECTED", red())
    };

    let line = Line::from(vec![
        Span::styled("◆ COINCYNC MINER", bold_gold()),
        Span::styled(
            format!("  v{} · {} · ", coincync::VERSION, net),
            dim(),
        ),
        Span::styled(now, cyan()),
        Span::styled("    threads: ", dim()),
        Span::styled(format!("{}", app.threads), white()),
        Span::styled("    ", dim()),
        Span::styled(conn_label, conn_style),
    ]);
    frame.render_widget(
        Paragraph::new(line).style(Style::default().bg(BG)),
        area,
    );
}

// ── Body ────────────────────────────────────────────────────────────

fn draw_body(frame: &mut Frame, app: &App, area: Rect) {
    let rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(7),  // row 1: stats panels
            Constraint::Min(6),     // row 2: miner + blocks
            Constraint::Length(13), // row 3: mining log
        ])
        .split(area);

    draw_stats_row(frame, app, rows[0]);
    draw_detail_row(frame, app, rows[1]);
    draw_log(frame, app, rows[2]);
}

// ── Row 1: Hashrate | Mining | Network ──────────────────────────────

fn draw_stats_row(frame: &mut Frame, app: &App, area: Rect) {
    let cols = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage(38),
            Constraint::Percentage(28),
            Constraint::Percentage(34),
        ])
        .split(area);

    draw_hashrate(frame, app, cols[0]);
    draw_mining(frame, app, cols[1]);
    draw_network(frame, app, cols[2]);
}

fn draw_hashrate(frame: &mut Frame, app: &App, area: Rect) {
    let blk = panel("hashrate");
    let inner_area = blk.inner(area);
    frame.render_widget(blk, area);

    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Min(1), Constraint::Length(1)])
        .split(inner_area);

    let hr_str = fmt_hashrate(app.hashrate);
    let mut parts = hr_str.splitn(2, ' ');
    let hr_num = parts.next().unwrap_or("0.0");
    let hr_unit = parts.next().unwrap_or("H/s");

    let avg = if app.hashrate_history.is_empty() {
        0.0
    } else {
        app.hashrate_history.iter().sum::<u64>() as f64
            / app.hashrate_history.len() as f64
    };

    let text = vec![
        Line::from(vec![
            Span::styled(
                hr_num.to_string(),
                bold_gold().add_modifier(Modifier::BOLD),
            ),
            Span::styled(format!(" {}", hr_unit), dgold()),
        ]),
        Line::from(vec![
            Span::styled("avg: ", dim()),
            Span::styled(fmt_hashrate(avg), white()),
            Span::styled("  peak: ", dim()),
            Span::styled(fmt_hashrate(app.hashrate_peak), amber()),
        ]),
    ];
    frame.render_widget(
        Paragraph::new(text).style(Style::default().bg(BG)),
        chunks[0],
    );

    // Hashrate sparkline
    let data: Vec<u64> = app.hashrate_history.iter().copied().collect();
    if !data.is_empty() {
        let spark = Sparkline::default()
            .data(&data)
            .max(app.hashrate_peak.max(1.0) as u64)
            .style(gold());
        frame.render_widget(spark, chunks[1]);
    }
}

fn draw_mining(frame: &mut Frame, app: &App, area: Rect) {
    let session_secs = app.start_time.elapsed().as_secs().max(1);
    let est_hashes = (app.hashrate * session_secs as f64) as u64;

    let text = vec![
        Line::from(vec![
            Span::styled("Blocks    ", dim()),
            Span::styled(
                format!("{}", app.blocks_found),
                if app.blocks_found > 0 {
                    bold_gold()
                } else {
                    white()
                },
            ),
        ]),
        Line::from(vec![
            Span::styled("Hashes    ", dim()),
            Span::styled(fmt_number(est_hashes), white()),
        ]),
        Line::from(vec![
            Span::styled("Reward    ", dim()),
            Span::styled(
                if app.block_reward > 0 {
                    format!("~{}", fmt_cync(app.block_reward))
                } else {
                    "—".into()
                },
                amber(),
            ),
        ]),
        Line::from(vec![
            Span::styled("Mempool   ", dim()),
            Span::styled(format!("{} txs", app.tx_pool_size), white()),
        ]),
        Line::from(vec![
            Span::styled("Algorithm ", dim()),
            Span::styled("RandomX", cyan()),
        ]),
    ];
    frame.render_widget(
        Paragraph::new(text)
            .block(panel("mining"))
            .style(Style::default().bg(BG)),
        area,
    );
}

fn draw_network(frame: &mut Frame, app: &App, area: Rect) {
    let text = vec![
        Line::from(vec![
            Span::styled("Difficulty    ", dim()),
            Span::styled(&app.difficulty, white()),
        ]),
        Line::from(vec![
            Span::styled("Block Height  ", dim()),
            Span::styled(fmt_number(app.chain_height), cyan()),
        ]),
        Line::from(vec![
            Span::styled("Tip Age       ", dim()),
            Span::styled(
                fmt_duration_short(app.tip_age_secs),
                if app.tip_age_secs > 300 {
                    amber()
                } else {
                    white()
                },
            ),
        ]),
        Line::from(vec![
            Span::styled("Peers         ", dim()),
            Span::styled(format!("{}", app.peer_count), white()),
        ]),
        Line::from(vec![
            Span::styled("Status        ", dim()),
            Span::styled(
                if app.synced { "SYNCED" } else { "SYNCING..." },
                if app.synced { green() } else { amber() },
            ),
        ]),
    ];
    frame.render_widget(
        Paragraph::new(text)
            .block(panel("network"))
            .style(Style::default().bg(BG)),
        area,
    );
}

// ── Row 2: Miner Status | Blocks Found ──────────────────────────────

fn draw_detail_row(frame: &mut Frame, app: &App, area: Rect) {
    let cols = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
        .split(area);

    draw_miner_status(frame, app, cols[0]);
    draw_blocks_found(frame, app, cols[1]);
}

fn draw_miner_status(frame: &mut Frame, app: &App, area: Rect) {
    let (status_text, status_style) = if app.address.is_none() {
        ("MONITOR ONLY", dim())
    } else if app.miner_alive {
        ("● MINING", green())
    } else {
        ("○ STOPPED", red())
    };

    let addr_display = app
        .address
        .as_deref()
        .map(|a| truncate_addr(a, 28))
        .unwrap_or_else(|| "—".into());
    let node_display = app.rpc_url.trim_start_matches("http://").to_string();

    let text = vec![
        Line::from(vec![
            Span::styled("Status    ", dim()),
            Span::styled(status_text, status_style),
        ]),
        Line::from(vec![
            Span::styled("PID       ", dim()),
            Span::styled(
                app.miner_pid
                    .map(|p| p.to_string())
                    .unwrap_or_else(|| "—".into()),
                white(),
            ),
        ]),
        Line::from(vec![
            Span::styled("Threads   ", dim()),
            Span::styled(
                if app.threads == 0 {
                    "auto".into()
                } else {
                    app.threads.to_string()
                },
                white(),
            ),
        ]),
        Line::from(vec![
            Span::styled("Address   ", dim()),
            Span::styled(addr_display, cyan()),
        ]),
        Line::from(vec![
            Span::styled("Node      ", dim()),
            Span::styled(node_display, dgold()),
        ]),
        Line::from(vec![
            Span::styled("Uptime    ", dim()),
            Span::styled(app.uptime(), white()),
        ]),
    ];
    frame.render_widget(
        Paragraph::new(text)
            .block(panel("miner"))
            .style(Style::default().bg(BG)),
        area,
    );
}

fn draw_blocks_found(frame: &mut Frame, app: &App, area: Rect) {
    if app.found_blocks.is_empty() {
        let empty = Paragraph::new(Line::from(vec![Span::styled(
            "  No blocks found yet",
            dim(),
        )]))
        .block(panel("blocks found"))
        .style(Style::default().bg(BG));
        frame.render_widget(empty, area);
    } else {
        let items: Vec<ListItem> = app
            .found_blocks
            .iter()
            .take(20)
            .map(|b| {
                ListItem::new(Line::from(vec![
                    Span::styled(format!("#{:<12}", fmt_number(b.height)), cyan()),
                    Span::styled(format!("+{}", fmt_cync(b.reward_estimate)), amber()),
                    Span::styled(format!("  {}", b.ago()), dim()),
                ]))
            })
            .collect();

        frame.render_widget(
            List::new(items)
                .block(panel("blocks found"))
                .style(Style::default().bg(BG)),
            area,
        );
    }
}

// ── Row 3: Mining Log ───────────────────────────────────────────────

fn draw_log(frame: &mut Frame, app: &App, area: Rect) {
    let items: Vec<ListItem> = app
        .log
        .iter()
        .take(50)
        .map(|e| {
            let tag_style = Style::default().fg(e.level.color());
            let msg_style = match e.level {
                LogLevel::Error => red(),
                LogLevel::Warn => amber(),
                LogLevel::Block => green(),
                LogLevel::Info => white(),
            };
            ListItem::new(Line::from(vec![
                Span::styled(e.time.format("%H:%M:%S ").to_string(), dim()),
                Span::styled(format!("[{}]", e.level.label()), tag_style),
                Span::styled(format!("  {}", e.message), msg_style),
            ]))
        })
        .collect();

    frame.render_widget(
        List::new(items)
            .block(panel("mining log"))
            .style(Style::default().bg(BG)),
        area,
    );
}

// ── Footer ──────────────────────────────────────────────────────────

fn draw_footer(frame: &mut Frame, app: &App, area: Rect) {
    let addr_short = app
        .address
        .as_deref()
        .map(|a| truncate_addr(a, 16))
        .unwrap_or_else(|| "—".into());

    let line = Line::from(vec![
        Span::styled("node: ", dim()),
        Span::styled(app.rpc_url.trim_start_matches("http://"), dgold()),
        Span::styled("    ping: ", dim()),
        Span::styled(format!("{}ms", app.rpc_ping_ms), cyan()),
        Span::styled("    session: ", dim()),
        Span::styled(app.uptime(), white()),
        Span::styled("    addr: ", dim()),
        Span::styled(addr_short, dgold()),
        Span::styled("    press ", dim()),
        Span::styled("Q", bold_gold()),
        Span::styled(" to quit", dim()),
    ]);
    frame.render_widget(
        Paragraph::new(line).style(Style::default().bg(BG)),
        area,
    );
}

// ═══════════════════════════════════════════════════════════════════════
// Main
// ═══════════════════════════════════════════════════════════════════════

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();
    let (tx, rx) = mpsc::channel::<AppEvent>();

    // ── Spawn miner subprocess (if address provided) ────────────
    let _miner_guard = if args.address.is_some() {
        match spawn_miner(&args, tx.clone()) {
            Ok(guard) => Some(guard),
            Err(e) => {
                eprintln!(
                    "Failed to start miner: {}. Running in monitor-only mode.",
                    e
                );
                None
            }
        }
    } else {
        None
    };

    // ── Start RPC polling ───────────────────────────────────────
    spawn_rpc_poller(args.rpc.clone(), tx.clone());

    // ── Terminal setup ──────────────────────────────────────────
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;
    terminal.clear()?;

    // ── App state ───────────────────────────────────────────────
    let mut app = App::new(&args);
    if let Some(ref guard) = _miner_guard {
        app.miner_pid = Some(guard.child.id());
        app.miner_alive = true;
    }
    app.push_log(
        LogLevel::Info,
        format!("CoinCync Miner TUI v{} started", coincync::VERSION),
    );
    let rpc_key_present = std::env::var("COINCYNC_RPC_API_KEY")
        .ok()
        .map(|v| !v.trim().is_empty())
        .unwrap_or(false);
    if rpc_key_present {
        app.push_log(
            LogLevel::Info,
            "RPC auth key detected (COINCYNC_RPC_API_KEY set)".into(),
        );
    } else {
        app.push_log(
            LogLevel::Warn,
            "RPC auth key not set. If node enforces Bearer auth, set COINCYNC_RPC_API_KEY."
                .into(),
        );
    }
    if app.address.is_none() {
        app.push_log(
            LogLevel::Warn,
            "No --address provided — running in monitor-only mode".into(),
        );
    }

    // ── Event loop ──────────────────────────────────────────────
    let tick_rate = Duration::from_millis(100);

    loop {
        terminal.draw(|f| draw(f, &app))?;

        // Keyboard
        if event::poll(tick_rate)? {
            if let Event::Key(key) = event::read()? {
                match key.code {
                    KeyCode::Char('q') | KeyCode::Char('Q') | KeyCode::Esc => {
                        app.should_quit = true;
                    }
                    _ => {}
                }
            }
        }

        // Drain channel
        while let Ok(evt) = rx.try_recv() {
            match evt {
                AppEvent::MinerLine(line) => app.process_miner_line(&line),
                AppEvent::MinerExited => {
                    app.miner_alive = false;
                    app.push_log(LogLevel::Warn, "Miner process exited".into());
                }
                AppEvent::ChainUpdate(info) => app.update_chain(info),
                AppEvent::RpcDown => {
                    app.rpc_connected = false;
                }
            }
        }

        // Record hashrate for sparkline (1 sample/sec)
        app.record_hashrate_tick();

        if app.should_quit {
            break;
        }
    }

    // ── Teardown ────────────────────────────────────────────────
    disable_raw_mode()?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen)?;
    terminal.show_cursor()?;
    println!("CoinCync Miner TUI stopped.");

    Ok(())
}
