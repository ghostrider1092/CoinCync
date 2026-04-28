//! CoinCync Operator TUI — developer-only terminal dashboard.
//!
//! Polls the local JSON-RPC endpoint and renders chain state, mining,
//! peers, zombie detector, and a live event log using ratatui.
//!
//! Usage:
//!   coincync-tui [--rpc http://127.0.0.1:28081] [--interval 2]

use std::io;
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use chrono::{DateTime, Local};
use crossterm::{
    event::{self, DisableMouseCapture, EnableMouseCapture, Event, KeyCode, KeyModifiers},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::{
    backend::CrosstermBackend,
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Cell, Gauge, List, ListItem, Paragraph, Row, Table, Tabs},
    Frame, Terminal,
};
use serde::Deserialize;
use serde_json::Value;

// ── RPC helper ───────────────────────────────────────────────────────

async fn rpc_call(url: &str, method: &str, params: Value) -> Result<Value> {
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(5))
        .danger_accept_invalid_certs(true)
        .build()?;
    let body = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": method,
        "params": params,
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
    let json: Value = resp.json().await.context("RPC response parse failed")?;
    if let Some(err) = json.get("error") {
        anyhow::bail!("RPC error: {}", err);
    }
    Ok(json["result"].clone())
}

// ── Data models ──────────────────────────────────────────────────────

#[derive(Debug, Clone, Default)]
pub struct ChainInfo {
    pub version: String,
    pub network: String,
    pub height: u64,
    pub target_height: u64,
    pub top_hash: String,
    pub difficulty: String,
    pub tx_pool_size: u64,
    pub synced: bool,
    pub tip_age_secs: u64,
    pub tip_timestamp: u64,
    pub peer_count: u64,
    pub anonymity_set: u64,
    pub effective_ring_size: u64,
    pub has_zombies: bool,
    pub process_count: u64,
    pub health_score: f64,
    pub status: String,
}

#[derive(Debug, Clone, Default)]
pub struct MiningInfo {
    pub is_mining: bool,
    pub hashrate: f64,
    pub hashes_total: u64,
    pub blocks_found: u64,
    pub algorithm: u64,
    pub mining_height: u64,
    pub target_hex: String,
    pub best_hash_hex: String,
    pub best_leading_zeros: u64,
    pub target_leading_zeros: u64,
    pub current_nonce: u64,
    pub block_just_found: bool,
    pub winning_nonce: u64,
    pub winning_hash_hex: String,
    pub sample_hashes: Vec<SampleHash>,
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct SampleHash {
    pub nonce: u64,
    pub hash_hex: String,
    pub leading_zeros: u64,
}

#[derive(Debug, Clone, Default)]
pub struct SupplyInfo {
    pub height: u64,
    pub total_emitted: u64,
    pub total_burned: u64,
    pub circulating: u64,
    pub tip_hash: String,
}

#[derive(Debug, Clone)]
pub struct LogEntry {
    pub time: DateTime<Local>,
    pub level: LogLevel,
    pub message: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LogLevel {
    Info,
    Warn,
    Error,
    Mining,
}

impl LogLevel {
    fn color(&self) -> Color {
        match self {
            LogLevel::Info => Color::Cyan,
            LogLevel::Warn => Color::Yellow,
            LogLevel::Error => Color::Red,
            LogLevel::Mining => Color::Green,
        }
    }

    fn label(&self) -> &'static str {
        match self {
            LogLevel::Info => "INFO",
            LogLevel::Warn => "WARN",
            LogLevel::Error => "ERR ",
            LogLevel::Mining => "MINE",
        }
    }
}

// ── Application state ────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tab {
    Overview,
    Mining,
    Network,
    Log,
}

impl Tab {
    const ALL: [Tab; 4] = [Tab::Overview, Tab::Mining, Tab::Network, Tab::Log];

    fn title(&self) -> &'static str {
        match self {
            Tab::Overview => "Overview",
            Tab::Mining => "Mining",
            Tab::Network => "Network",
            Tab::Log => "Log",
        }
    }

    fn index(&self) -> usize {
        match self {
            Tab::Overview => 0,
            Tab::Mining => 1,
            Tab::Network => 2,
            Tab::Log => 3,
        }
    }
}

pub struct OperatorApp {
    pub rpc_url: String,
    pub chain: ChainInfo,
    pub mining: MiningInfo,
    pub supply: SupplyInfo,
    pub log: Vec<LogEntry>,
    pub tab: Tab,
    pub last_poll: Option<Instant>,
    pub poll_interval: Duration,
    pub rpc_ok: bool,
    pub prev_height: u64,
    pub prev_blocks_found: u64,
}

impl OperatorApp {
    fn new(rpc_url: String, poll_secs: u64) -> Self {
        Self {
            rpc_url,
            chain: ChainInfo::default(),
            mining: MiningInfo::default(),
            supply: SupplyInfo::default(),
            log: Vec::new(),
            tab: Tab::Overview,
            last_poll: None,
            poll_interval: Duration::from_secs(poll_secs),
            rpc_ok: false,
            prev_height: 0,
            prev_blocks_found: 0,
        }
    }

    fn push_log(&mut self, level: LogLevel, message: String) {
        self.log.push(LogEntry {
            time: Local::now(),
            level,
            message,
        });
        // Keep log bounded
        if self.log.len() > 2000 {
            self.log.drain(..500);
        }
    }

    fn next_tab(&mut self) {
        let idx = (self.tab.index() + 1) % Tab::ALL.len();
        self.tab = Tab::ALL[idx];
    }

    fn prev_tab(&mut self) {
        let idx = if self.tab.index() == 0 {
            Tab::ALL.len() - 1
        } else {
            self.tab.index() - 1
        };
        self.tab = Tab::ALL[idx];
    }

    async fn poll(&mut self) {
        // get_info
        match rpc_call(&self.rpc_url, "get_info", Value::Array(vec![])).await {
            Ok(v) => {
                self.rpc_ok = true;
                self.chain = ChainInfo {
                    version: v["version"].as_str().unwrap_or("?").to_string(),
                    network: v["network"].as_str().unwrap_or("?").to_string(),
                    height: v["height"].as_u64().unwrap_or(0),
                    target_height: v["target_height"].as_u64().unwrap_or(0),
                    top_hash: v["top_hash"].as_str().unwrap_or("").to_string(),
                    difficulty: v["difficulty"].as_str().unwrap_or("0").to_string(),
                    tx_pool_size: v["tx_pool_size"].as_u64().unwrap_or(0),
                    synced: v["synced"].as_bool().unwrap_or(false),
                    tip_age_secs: v["tip_age_secs"].as_u64().unwrap_or(0),
                    tip_timestamp: v["tip_timestamp"].as_u64().unwrap_or(0),
                    peer_count: v["peer_count"].as_u64().unwrap_or(0),
                    anonymity_set: v["anonymity_set"].as_u64().unwrap_or(0),
                    effective_ring_size: v["effective_ring_size"].as_u64().unwrap_or(0),
                    has_zombies: v["has_zombies"].as_bool().unwrap_or(false),
                    process_count: v["process_count"].as_u64().unwrap_or(1),
                    health_score: v["health_score"].as_f64().unwrap_or(0.0),
                    status: v["status"].as_str().unwrap_or("unknown").to_string(),
                };

                // Detect new block
                if self.chain.height > self.prev_height && self.prev_height > 0 {
                    self.push_log(
                        LogLevel::Info,
                        format!(
                            "New block #{} — hash {}",
                            self.chain.height,
                            &self.chain.top_hash[..16.min(self.chain.top_hash.len())]
                        ),
                    );
                }
                self.prev_height = self.chain.height;

                // Zombie warning
                if self.chain.has_zombies {
                    self.push_log(
                        LogLevel::Warn,
                        format!(
                            "Zombie detected! {} cyncd processes running",
                            self.chain.process_count
                        ),
                    );
                }
            }
            Err(e) => {
                self.rpc_ok = false;
                self.push_log(LogLevel::Error, format!("RPC get_info failed: {e}"));
            }
        }

        // get_mining_live
        match rpc_call(&self.rpc_url, "get_mining_live", Value::Array(vec![])).await {
            Ok(v) => {
                let samples: Vec<SampleHash> = v["sample_hashes"]
                    .as_array()
                    .map(|arr| {
                        arr.iter()
                            .filter_map(|s| serde_json::from_value(s.clone()).ok())
                            .collect()
                    })
                    .unwrap_or_default();

                let new_mining = MiningInfo {
                    is_mining: v["is_mining"].as_bool().unwrap_or(false),
                    hashrate: v["hashrate"].as_f64().unwrap_or(0.0),
                    hashes_total: v["hashes_total"].as_u64().unwrap_or(0),
                    blocks_found: v["blocks_found"].as_u64().unwrap_or(0),
                    algorithm: v["algorithm"].as_u64().unwrap_or(0),
                    mining_height: v["mining_height"].as_u64().unwrap_or(0),
                    target_hex: v["target_hex"].as_str().unwrap_or("").to_string(),
                    best_hash_hex: v["best_hash_hex"].as_str().unwrap_or("").to_string(),
                    best_leading_zeros: v["best_leading_zeros"].as_u64().unwrap_or(0),
                    target_leading_zeros: v["target_leading_zeros"].as_u64().unwrap_or(0),
                    current_nonce: v["current_nonce"].as_u64().unwrap_or(0),
                    block_just_found: v["block_just_found"].as_bool().unwrap_or(false),
                    winning_nonce: v["winning_nonce"].as_u64().unwrap_or(0),
                    winning_hash_hex: v["winning_hash_hex"].as_str().unwrap_or("").to_string(),
                    sample_hashes: samples,
                };

                // Detect block found
                if new_mining.blocks_found > self.prev_blocks_found && self.prev_blocks_found > 0
                {
                    self.push_log(
                        LogLevel::Mining,
                        format!(
                            "BLOCK FOUND! nonce={} hash={}",
                            new_mining.winning_nonce,
                            &new_mining.winning_hash_hex
                                [..16.min(new_mining.winning_hash_hex.len())]
                        ),
                    );
                }
                self.prev_blocks_found = new_mining.blocks_found;
                self.mining = new_mining;
            }
            Err(_) => {
                // Mining RPC may require auth — not critical
            }
        }

        // get_supply_info
        match rpc_call(&self.rpc_url, "get_supply_info", Value::Array(vec![])).await {
            Ok(v) => {
                self.supply = SupplyInfo {
                    height: v["height"].as_u64().unwrap_or(0),
                    total_emitted: v["total_emitted"].as_u64().unwrap_or(0),
                    total_burned: v["total_burned"].as_u64().unwrap_or(0),
                    circulating: v["circulating"].as_u64().unwrap_or(0),
                    tip_hash: v["tip_hash"].as_str().unwrap_or("").to_string(),
                };
            }
            Err(_) => {}
        }

        self.last_poll = Some(Instant::now());
    }
}

// ── Formatting helpers ───────────────────────────────────────────────

fn fmt_cync(atomic: u64) -> String {
    let whole = atomic / 1_000_000_000_000;
    let frac = (atomic % 1_000_000_000_000) / 1_000_000_000;
    if frac == 0 {
        format!("{whole} CYNC")
    } else {
        format!("{whole}.{frac:03} CYNC")
    }
}

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

fn fmt_age(secs: u64) -> String {
    if secs < 60 {
        format!("{secs}s")
    } else if secs < 3600 {
        format!("{}m {}s", secs / 60, secs % 60)
    } else {
        format!("{}h {}m", secs / 3600, (secs % 3600) / 60)
    }
}

fn tip_age_color(secs: u64) -> Color {
    if secs <= 90 {
        Color::Green
    } else if secs <= 180 {
        Color::Yellow
    } else {
        Color::Red
    }
}

fn algo_name(id: u64) -> &'static str {
    // CoinCync 1.0 is RandomX-only. Any non-zero algorithm id here is
    // either a future-version block we can't describe, or a bug in the
    // miner surface feeding the TUI — we render "unknown" rather than
    // silently falling back to RandomX.
    match id {
        0 => "RandomX",
        _ => "unknown",
    }
}

// ── Rendering ────────────────────────────────────────────────────────

fn render_status_bar(f: &mut Frame, area: Rect, app: &OperatorApp) {
    let status_color = if !app.rpc_ok {
        Color::Red
    } else if app.chain.has_zombies {
        Color::Yellow
    } else if app.chain.synced {
        Color::Green
    } else {
        Color::Cyan
    };

    let status_text = if !app.rpc_ok {
        "DISCONNECTED".to_string()
    } else if app.chain.has_zombies {
        format!("ZOMBIE ({} procs)", app.chain.process_count)
    } else {
        app.chain.status.to_uppercase()
    };

    let now = Local::now().format("%H:%M:%S").to_string();
    let bar = Line::from(vec![
        Span::styled(
            " COINCYNC OPERATOR ",
            Style::default()
                .fg(Color::Black)
                .bg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        ),
        Span::raw(" "),
        Span::styled(
            format!(" {status_text} "),
            Style::default()
                .fg(Color::Black)
                .bg(status_color)
                .add_modifier(Modifier::BOLD),
        ),
        Span::raw("  "),
        Span::styled(
            format!("v{}", app.chain.version),
            Style::default().fg(Color::DarkGray),
        ),
        Span::raw("  "),
        Span::styled(
            format!("net:{}", app.chain.network),
            Style::default().fg(Color::DarkGray),
        ),
        Span::raw("  "),
        Span::styled(now, Style::default().fg(Color::DarkGray)),
    ]);

    f.render_widget(Paragraph::new(bar), area);
}

fn render_tabs(f: &mut Frame, area: Rect, app: &OperatorApp) {
    let titles: Vec<Line> = Tab::ALL
        .iter()
        .map(|t| Line::from(format!(" {} ", t.title())))
        .collect();
    let tabs = Tabs::new(titles)
        .select(app.tab.index())
        .style(Style::default().fg(Color::DarkGray))
        .highlight_style(
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD)
                .add_modifier(Modifier::UNDERLINED),
        )
        .divider(Span::raw("|"));
    f.render_widget(tabs, area);
}

fn render_overview(f: &mut Frame, area: Rect, app: &OperatorApp) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(8),  // top panels
            Constraint::Length(8),  // supply + mining summary
            Constraint::Min(5),    // recent log
        ])
        .split(area);

    render_top_panels(f, chunks[0], app);
    render_mid_panels(f, chunks[1], app);
    render_recent_log(f, chunks[2], app);
}

fn render_top_panels(f: &mut Frame, area: Rect, app: &OperatorApp) {
    let cols = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage(40),
            Constraint::Percentage(30),
            Constraint::Percentage(30),
        ])
        .split(area);

    // Chain panel
    let sync_status = if app.chain.synced {
        Span::styled("SYNCED", Style::default().fg(Color::Green))
    } else {
        Span::styled(
            format!("SYNCING {}/{}", app.chain.height, app.chain.target_height),
            Style::default().fg(Color::Yellow),
        )
    };

    let chain_lines = vec![
        Line::from(vec![
            Span::raw("Height:    "),
            Span::styled(
                format!("{}", app.chain.height),
                Style::default()
                    .fg(Color::White)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::raw("  "),
            sync_status,
        ]),
        Line::from(vec![
            Span::raw("Tip age:   "),
            Span::styled(
                fmt_age(app.chain.tip_age_secs),
                Style::default().fg(tip_age_color(app.chain.tip_age_secs)),
            ),
        ]),
        Line::from(vec![
            Span::raw("Difficulty:"),
            Span::styled(
                format!(" {}", app.chain.difficulty),
                Style::default().fg(Color::White),
            ),
        ]),
        Line::from(vec![
            Span::raw("Mempool:   "),
            Span::styled(
                format!("{} txs", app.chain.tx_pool_size),
                Style::default().fg(Color::White),
            ),
        ]),
        Line::from(vec![
            Span::raw("Top hash:  "),
            Span::styled(
                if app.chain.top_hash.len() > 16 {
                    format!("{}...", &app.chain.top_hash[..16])
                } else {
                    app.chain.top_hash.clone()
                },
                Style::default().fg(Color::DarkGray),
            ),
        ]),
    ];

    let chain_block = Block::default()
        .title(Span::styled(
            " Chain ",
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        ))
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::DarkGray));

    f.render_widget(Paragraph::new(chain_lines).block(chain_block), cols[0]);

    // Privacy panel
    let privacy_lines = vec![
        Line::from(vec![
            Span::raw("Anon set:  "),
            Span::styled(
                format!("{}", app.chain.anonymity_set),
                Style::default()
                    .fg(Color::Green)
                    .add_modifier(Modifier::BOLD),
            ),
        ]),
        Line::from(vec![
            Span::raw("Ring size: "),
            Span::styled(
                format!("{}", app.chain.effective_ring_size),
                Style::default().fg(Color::Green),
            ),
        ]),
        Line::from(Span::raw("")),
        Line::from(vec![
            Span::styled("Peers: ", Style::default().fg(Color::White)),
            Span::styled(
                format!("{}", app.chain.peer_count),
                Style::default().fg(if app.chain.peer_count > 0 {
                    Color::Green
                } else {
                    Color::Red
                }),
            ),
        ]),
    ];

    let privacy_block = Block::default()
        .title(Span::styled(
            " Privacy ",
            Style::default()
                .fg(Color::Green)
                .add_modifier(Modifier::BOLD),
        ))
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::DarkGray));

    f.render_widget(
        Paragraph::new(privacy_lines).block(privacy_block),
        cols[1],
    );

    // Zombie panel
    let zombie_color = if app.chain.has_zombies {
        Color::Red
    } else {
        Color::Green
    };
    let zombie_status = if app.chain.has_zombies {
        "ZOMBIES DETECTED"
    } else {
        "Clean"
    };

    let zombie_lines = vec![
        Line::from(vec![
            Span::raw("Status:    "),
            Span::styled(
                zombie_status,
                Style::default()
                    .fg(zombie_color)
                    .add_modifier(Modifier::BOLD),
            ),
        ]),
        Line::from(vec![
            Span::raw("Processes: "),
            Span::styled(
                format!("{}", app.chain.process_count),
                Style::default().fg(zombie_color),
            ),
        ]),
        Line::from(vec![
            Span::raw("Health:    "),
            Span::styled(
                format!("{:.0}%", app.chain.health_score * 100.0),
                Style::default().fg(if app.chain.health_score >= 0.7 {
                    Color::Green
                } else if app.chain.health_score >= 0.3 {
                    Color::Yellow
                } else {
                    Color::Red
                }),
            ),
        ]),
    ];

    let zombie_block = Block::default()
        .title(Span::styled(
            " Zombie Detector ",
            Style::default()
                .fg(zombie_color)
                .add_modifier(Modifier::BOLD),
        ))
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::DarkGray));

    f.render_widget(
        Paragraph::new(zombie_lines).block(zombie_block),
        cols[2],
    );
}

fn render_mid_panels(f: &mut Frame, area: Rect, app: &OperatorApp) {
    let cols = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
        .split(area);

    // Supply panel
    let supply_lines = vec![
        Line::from(vec![
            Span::raw("Circulating: "),
            Span::styled(
                fmt_cync(app.supply.circulating),
                Style::default()
                    .fg(Color::White)
                    .add_modifier(Modifier::BOLD),
            ),
        ]),
        Line::from(vec![
            Span::raw("Emitted:     "),
            Span::styled(
                fmt_cync(app.supply.total_emitted),
                Style::default().fg(Color::White),
            ),
        ]),
        Line::from(vec![
            Span::raw("Burned:      "),
            Span::styled(
                fmt_cync(app.supply.total_burned),
                Style::default().fg(Color::Yellow),
            ),
        ]),
        Line::from(vec![
            Span::raw("Max supply:  "),
            Span::styled(
                "250,000,000 CYNC",
                Style::default().fg(Color::DarkGray),
            ),
        ]),
    ];

    let supply_block = Block::default()
        .title(Span::styled(
            " Supply Audit ",
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        ))
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::DarkGray));

    f.render_widget(
        Paragraph::new(supply_lines).block(supply_block),
        cols[0],
    );

    // Mining summary
    let mining_status = if app.mining.is_mining {
        Span::styled(
            "ACTIVE",
            Style::default()
                .fg(Color::Green)
                .add_modifier(Modifier::BOLD),
        )
    } else {
        Span::styled("IDLE", Style::default().fg(Color::DarkGray))
    };

    let mining_lines = vec![
        Line::from(vec![Span::raw("Status:   "), mining_status]),
        Line::from(vec![
            Span::raw("Hashrate: "),
            Span::styled(
                fmt_hashrate(app.mining.hashrate),
                Style::default().fg(Color::Green),
            ),
        ]),
        Line::from(vec![
            Span::raw("Algo:     "),
            Span::styled(
                algo_name(app.mining.algorithm),
                Style::default().fg(Color::Cyan),
            ),
        ]),
        Line::from(vec![
            Span::raw("Found:    "),
            Span::styled(
                format!("{} blocks", app.mining.blocks_found),
                Style::default().fg(Color::Yellow),
            ),
        ]),
    ];

    let mining_block = Block::default()
        .title(Span::styled(
            " Mining ",
            Style::default()
                .fg(Color::Green)
                .add_modifier(Modifier::BOLD),
        ))
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::DarkGray));

    f.render_widget(
        Paragraph::new(mining_lines).block(mining_block),
        cols[1],
    );
}

fn render_recent_log(f: &mut Frame, area: Rect, app: &OperatorApp) {
    let max_lines = area.height.saturating_sub(2) as usize;
    let start = if app.log.len() > max_lines {
        app.log.len() - max_lines
    } else {
        0
    };

    let items: Vec<ListItem> = app.log[start..]
        .iter()
        .map(|entry| {
            let time_str = entry.time.format("%H:%M:%S").to_string();
            ListItem::new(Line::from(vec![
                Span::styled(
                    format!("[{time_str}]"),
                    Style::default().fg(Color::DarkGray),
                ),
                Span::raw(" "),
                Span::styled(
                    entry.level.label(),
                    Style::default()
                        .fg(entry.level.color())
                        .add_modifier(Modifier::BOLD),
                ),
                Span::raw(" "),
                Span::raw(&entry.message),
            ]))
        })
        .collect();

    let log_block = Block::default()
        .title(Span::styled(
            " Event Log ",
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        ))
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::DarkGray));

    f.render_widget(List::new(items).block(log_block), area);
}

fn render_mining_tab(f: &mut Frame, area: Rect, app: &OperatorApp) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(10), // mining detail
            Constraint::Length(5),  // progress
            Constraint::Min(5),    // sample hashes
        ])
        .split(area);

    // Mining detail
    let detail_lines = vec![
        Line::from(vec![
            Span::raw("Status:          "),
            if app.mining.is_mining {
                Span::styled(
                    "MINING",
                    Style::default()
                        .fg(Color::Green)
                        .add_modifier(Modifier::BOLD),
                )
            } else {
                Span::styled("IDLE", Style::default().fg(Color::DarkGray))
            },
        ]),
        Line::from(vec![
            Span::raw("Hashrate:        "),
            Span::styled(
                fmt_hashrate(app.mining.hashrate),
                Style::default().fg(Color::Green),
            ),
        ]),
        Line::from(vec![
            Span::raw("Algorithm:       "),
            Span::styled(
                algo_name(app.mining.algorithm),
                Style::default().fg(Color::Cyan),
            ),
        ]),
        Line::from(vec![
            Span::raw("Mining height:   "),
            Span::styled(
                format!("{}", app.mining.mining_height),
                Style::default().fg(Color::White),
            ),
        ]),
        Line::from(vec![
            Span::raw("Blocks found:    "),
            Span::styled(
                format!("{}", app.mining.blocks_found),
                Style::default()
                    .fg(Color::Yellow)
                    .add_modifier(Modifier::BOLD),
            ),
        ]),
        Line::from(vec![
            Span::raw("Total hashes:    "),
            Span::styled(
                format!("{}", app.mining.hashes_total),
                Style::default().fg(Color::White),
            ),
        ]),
        Line::from(vec![
            Span::raw("Current nonce:   "),
            Span::styled(
                format!("{}", app.mining.current_nonce),
                Style::default().fg(Color::DarkGray),
            ),
        ]),
    ];

    let detail_block = Block::default()
        .title(Span::styled(
            " Mining Detail ",
            Style::default()
                .fg(Color::Green)
                .add_modifier(Modifier::BOLD),
        ))
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::DarkGray));

    f.render_widget(
        Paragraph::new(detail_lines).block(detail_block),
        chunks[0],
    );

    // Progress gauge (leading zeros vs target)
    let ratio = if app.mining.target_leading_zeros > 0 {
        (app.mining.best_leading_zeros as f64 / app.mining.target_leading_zeros as f64)
            .clamp(0.0, 1.0)
    } else {
        0.0
    };

    let gauge_label = format!(
        "Best: {} zeros / Target: {} zeros",
        app.mining.best_leading_zeros, app.mining.target_leading_zeros
    );

    let gauge = Gauge::default()
        .block(
            Block::default()
                .title(Span::styled(
                    " Progress ",
                    Style::default()
                        .fg(Color::Cyan)
                        .add_modifier(Modifier::BOLD),
                ))
                .borders(Borders::ALL)
                .border_style(Style::default().fg(Color::DarkGray)),
        )
        .gauge_style(Style::default().fg(Color::Green).bg(Color::DarkGray))
        .ratio(ratio)
        .label(Span::styled(gauge_label, Style::default().fg(Color::White)));

    f.render_widget(gauge, chunks[1]);

    // Sample hashes table
    let header = Row::new(vec![
        Cell::from("Nonce").style(Style::default().fg(Color::Cyan)),
        Cell::from("Hash").style(Style::default().fg(Color::Cyan)),
        Cell::from("Zeros").style(Style::default().fg(Color::Cyan)),
    ]);

    let rows: Vec<Row> = app
        .mining
        .sample_hashes
        .iter()
        .rev()
        .take(20)
        .map(|s| {
            let hash_display = if s.hash_hex.len() > 32 {
                format!("{}...", &s.hash_hex[..32])
            } else {
                s.hash_hex.clone()
            };
            Row::new(vec![
                Cell::from(format!("{}", s.nonce)),
                Cell::from(hash_display).style(Style::default().fg(Color::DarkGray)),
                Cell::from(format!("{}", s.leading_zeros)).style(Style::default().fg(
                    if s.leading_zeros >= app.mining.target_leading_zeros {
                        Color::Green
                    } else {
                        Color::White
                    },
                )),
            ])
        })
        .collect();

    let table = Table::new(
        rows,
        [
            Constraint::Length(16),
            Constraint::Min(32),
            Constraint::Length(8),
        ],
    )
    .header(header)
    .block(
        Block::default()
            .title(Span::styled(
                " Sample Hashes ",
                Style::default()
                    .fg(Color::Cyan)
                    .add_modifier(Modifier::BOLD),
            ))
            .borders(Borders::ALL)
            .border_style(Style::default().fg(Color::DarkGray)),
    );

    f.render_widget(table, chunks[2]);
}

fn render_network_tab(f: &mut Frame, area: Rect, app: &OperatorApp) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(8), Constraint::Min(5)])
        .split(area);

    // Network summary
    let net_lines = vec![
        Line::from(vec![
            Span::raw("Peers:     "),
            Span::styled(
                format!("{}", app.chain.peer_count),
                Style::default()
                    .fg(if app.chain.peer_count > 0 {
                        Color::Green
                    } else {
                        Color::Red
                    })
                    .add_modifier(Modifier::BOLD),
            ),
        ]),
        Line::from(vec![
            Span::raw("Synced:    "),
            Span::styled(
                if app.chain.synced { "Yes" } else { "No" },
                Style::default().fg(if app.chain.synced {
                    Color::Green
                } else {
                    Color::Yellow
                }),
            ),
        ]),
        Line::from(vec![
            Span::raw("Network:   "),
            Span::styled(&app.chain.network, Style::default().fg(Color::Cyan)),
        ]),
        Line::from(vec![
            Span::raw("Tip age:   "),
            Span::styled(
                fmt_age(app.chain.tip_age_secs),
                Style::default().fg(tip_age_color(app.chain.tip_age_secs)),
            ),
        ]),
    ];

    let net_block = Block::default()
        .title(Span::styled(
            " Network ",
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        ))
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::DarkGray));

    f.render_widget(Paragraph::new(net_lines).block(net_block), chunks[0]);

    // Placeholder for peer list (would need additional RPC data)
    let peer_info = Paragraph::new(vec![
        Line::from(Span::styled(
            "Detailed peer list requires authenticated RPC access.",
            Style::default().fg(Color::DarkGray),
        )),
        Line::from(Span::styled(
            "Connect with --rpc-api-key to see full peer table.",
            Style::default().fg(Color::DarkGray),
        )),
    ])
    .block(
        Block::default()
            .title(Span::styled(
                " Peers ",
                Style::default()
                    .fg(Color::Cyan)
                    .add_modifier(Modifier::BOLD),
            ))
            .borders(Borders::ALL)
            .border_style(Style::default().fg(Color::DarkGray)),
    );

    f.render_widget(peer_info, chunks[1]);
}

fn render_log_tab(f: &mut Frame, area: Rect, app: &OperatorApp) {
    let max_lines = area.height.saturating_sub(2) as usize;
    let start = if app.log.len() > max_lines {
        app.log.len() - max_lines
    } else {
        0
    };

    let items: Vec<ListItem> = app.log[start..]
        .iter()
        .map(|entry| {
            let time_str = entry.time.format("%H:%M:%S").to_string();
            ListItem::new(Line::from(vec![
                Span::styled(
                    format!("[{time_str}]"),
                    Style::default().fg(Color::DarkGray),
                ),
                Span::raw(" "),
                Span::styled(
                    entry.level.label(),
                    Style::default()
                        .fg(entry.level.color())
                        .add_modifier(Modifier::BOLD),
                ),
                Span::raw(" "),
                Span::raw(&entry.message),
            ]))
        })
        .collect();

    let log_block = Block::default()
        .title(Span::styled(
            format!(" Event Log ({} entries) ", app.log.len()),
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        ))
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::DarkGray));

    f.render_widget(List::new(items).block(log_block), area);
}

fn render_help_bar(f: &mut Frame, area: Rect) {
    let help = Line::from(vec![
        Span::styled(" Tab/Shift+Tab ", Style::default().fg(Color::Black).bg(Color::DarkGray)),
        Span::raw(" switch tabs  "),
        Span::styled(" q/Esc ", Style::default().fg(Color::Black).bg(Color::DarkGray)),
        Span::raw(" quit  "),
        Span::styled(" 1-4 ", Style::default().fg(Color::Black).bg(Color::DarkGray)),
        Span::raw(" jump to tab"),
    ]);
    f.render_widget(Paragraph::new(help), area);
}

fn ui(f: &mut Frame, app: &OperatorApp) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(1), // status bar
            Constraint::Length(1), // tabs
            Constraint::Min(10),  // main content
            Constraint::Length(1), // help bar
        ])
        .split(f.area());

    render_status_bar(f, chunks[0], app);
    render_tabs(f, chunks[1], app);

    match app.tab {
        Tab::Overview => render_overview(f, chunks[2], app),
        Tab::Mining => render_mining_tab(f, chunks[2], app),
        Tab::Network => render_network_tab(f, chunks[2], app),
        Tab::Log => render_log_tab(f, chunks[2], app),
    }

    render_help_bar(f, chunks[3]);
}

// ── Main ─────────────────────────────────────────────────────────────

#[tokio::main]
async fn main() -> Result<()> {
    let mut rpc_url = "http://127.0.0.1:28081".to_string();
    let mut poll_secs: u64 = 2;

    // Simple arg parsing (no clap dependency needed for the TUI binary)
    let args: Vec<String> = std::env::args().collect();
    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--rpc" | "--rpc-url" => {
                i += 1;
                if i < args.len() {
                    rpc_url = args[i].clone();
                }
            }
            "--interval" => {
                i += 1;
                if i < args.len() {
                    poll_secs = args[i].parse().unwrap_or(2);
                }
            }
            "--help" | "-h" => {
                println!("CoinCync Operator TUI");
                println!();
                println!("Usage: coincync-tui [OPTIONS]");
                println!();
                println!("Options:");
                println!("  --rpc <URL>        RPC endpoint (default: http://127.0.0.1:28081)");
                println!("  --interval <SECS>  Poll interval in seconds (default: 2)");
                println!("  -h, --help         Show this help");
                return Ok(());
            }
            _ => {}
        }
        i += 1;
    }

    // Setup terminal
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen, EnableMouseCapture)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    let mut app = OperatorApp::new(rpc_url, poll_secs);
    app.push_log(LogLevel::Info, "Operator TUI started".to_string());
    let rpc_key_present = std::env::var("COINCYNC_RPC_API_KEY")
        .ok()
        .map(|v| !v.trim().is_empty())
        .unwrap_or(false);
    if rpc_key_present {
        app.push_log(
            LogLevel::Info,
            "RPC auth key detected (COINCYNC_RPC_API_KEY set)".to_string(),
        );
    } else {
        app.push_log(
            LogLevel::Warn,
            "RPC auth key not set. If node enforces Bearer auth, set COINCYNC_RPC_API_KEY."
                .to_string(),
        );
    }

    let result = run_app(&mut terminal, &mut app).await;

    // Restore terminal
    disable_raw_mode()?;
    execute!(
        terminal.backend_mut(),
        LeaveAlternateScreen,
        DisableMouseCapture
    )?;
    terminal.show_cursor()?;

    if let Err(e) = result {
        eprintln!("Error: {e}");
    }

    Ok(())
}

async fn run_app(
    terminal: &mut Terminal<CrosstermBackend<io::Stdout>>,
    app: &mut OperatorApp,
) -> Result<()> {
    let tick_rate = Duration::from_millis(100);

    loop {
        // Poll RPC if interval elapsed
        let should_poll = app
            .last_poll
            .map(|t| t.elapsed() >= app.poll_interval)
            .unwrap_or(true);

        if should_poll {
            app.poll().await;
        }

        // Draw
        terminal.draw(|f| ui(f, app))?;

        // Handle input
        if crossterm::event::poll(tick_rate)? {
            if let Event::Key(key) = event::read()? {
                match key.code {
                    KeyCode::Char('q') | KeyCode::Esc => return Ok(()),
                    KeyCode::Char('c') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                        return Ok(())
                    }
                    KeyCode::Tab => app.next_tab(),
                    KeyCode::BackTab => app.prev_tab(),
                    KeyCode::Char('1') => app.tab = Tab::Overview,
                    KeyCode::Char('2') => app.tab = Tab::Mining,
                    KeyCode::Char('3') => app.tab = Tab::Network,
                    KeyCode::Char('4') => app.tab = Tab::Log,
                    _ => {}
                }
            }
        }
    }
}
