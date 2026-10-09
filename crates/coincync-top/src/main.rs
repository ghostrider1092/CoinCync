//! coincync-top — a native-Rust system + CoinCync-node monitor (btop-style).
//!
//! Phase 1: live boxed panels for the host (CPU per-core, memory, network,
//! top processes — via `sysinfo`) AND the node (chain / mining / peers —
//! polled read-only from the node RPC). `q`/`Esc`/`Ctrl-C` to quit. Not a
//! replacement for the node's log — a separate monitor you run when you want it.

use std::collections::VecDeque;
use std::time::{Duration, Instant};

use clap::Parser;
use crossterm::event::{self, Event, KeyCode, KeyModifiers};
use ratatui::{
    layout::{Constraint, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, BorderType, Borders, Gauge, List, ListItem, Paragraph},
    Frame,
};
use sysinfo::{Networks, System};

const HIST: usize = 120; // sparkline history depth

/// Brand cyan (the ◈ glyph colour used across CoinCync).
const CYAN: Color = Color::Rgb(0x3a, 0xd1, 0xd1);
const DIM: Color = Color::Rgb(0x6c, 0x7a, 0x7a);

#[derive(Parser)]
#[command(name = "coincync-top", about = "System + CoinCync node monitor (btop-style)")]
struct Cli {
    /// Node RPC URL to poll (chain/mining/peers). Omit to monitor the host only.
    #[arg(long, default_value = "http://127.0.0.1:28121")]
    rpc: String,
    /// Refresh interval, milliseconds.
    #[arg(long, default_value_t = 1000)]
    refresh_ms: u64,
}

/// Node metrics parsed from the RPC (best-effort; None when the node is down).
#[derive(Default, Clone)]
struct NodeInfo {
    online: bool,
    network: String,
    height: u64,
    target_height: u64,
    top_hash: String,
    synced: bool,
    fork_stuck: bool,
    sync_stall_secs: u64,
    mesh_degraded: bool,
    peers: u64,
    difficulty: String,
    mempool: u64,
    is_mining: bool,
    hashrate: f64,
    hashes_total: u64,
    blocks_found: u64,
}

/// A single line in the chain-activity feed (the "processes" panel shows these:
/// the node's work, reconstructed from RPC state deltas — we're a pure client, so
/// this is honest derived telemetry, not a tail of the node's own log file).
#[derive(Clone)]
struct ChainEvent {
    ts: String,
    tag: &'static str,
    msg: String,
    color: Color,
}

const EVENTS_CAP: usize = 300;

struct App {
    sys: System,
    nets: Networks,
    client: reqwest::blocking::Client,
    rpc: String,
    // host history
    cpu_hist: VecDeque<u64>,
    down_hist: VecDeque<u64>,
    up_hist: VecDeque<u64>,
    // node history
    hash_hist: VecDeque<u64>,
    mempool_hist: VecDeque<u64>,
    node: NodeInfo,
    events: VecDeque<ChainEvent>, // chain-activity feed (newest at back)
    last_poll: Instant,
    paused: bool,
    frame: u64,                   // animation frame (advances ~5x/sec)
    prev_blocks: Option<u64>,     // last blocks_found seen (block-found edge)
    block_flash: Option<Instant>, // when a block was just found (flash window)
}

impl App {
    fn new(cli: &Cli) -> Self {
        let mut sys = System::new_all();
        sys.refresh_all();
        App {
            sys,
            nets: Networks::new_with_refreshed_list(),
            client: reqwest::blocking::Client::builder()
                .timeout(Duration::from_millis(800))
                .build()
                .expect("http client"),
            rpc: cli.rpc.clone(),
            cpu_hist: VecDeque::from(vec![0; HIST]),
            down_hist: VecDeque::from(vec![0; HIST]),
            up_hist: VecDeque::from(vec![0; HIST]),
            hash_hist: VecDeque::from(vec![0; HIST]),
            mempool_hist: VecDeque::from(vec![0; HIST]),
            node: NodeInfo::default(),
            events: VecDeque::new(),
            last_poll: Instant::now(),
            paused: false,
            frame: 0,
            prev_blocks: None,
            block_flash: None,
        }
    }

    fn tick(&mut self) {
        self.sys.refresh_all();
        self.nets.refresh();

        // CPU (average across cores)
        let cpus = self.sys.cpus();
        let cpu = if cpus.is_empty() {
            0.0
        } else {
            cpus.iter().map(|c| c.cpu_usage()).sum::<f32>() / cpus.len() as f32
        };
        push(&mut self.cpu_hist, cpu.round() as u64);

        // Network (bytes since last refresh → per-interval)
        let (mut down, mut up) = (0u64, 0u64);
        for (_name, data) in self.nets.iter() {
            down += data.received();
            up += data.transmitted();
        }
        push(&mut self.down_hist, down / 1024); // KiB/interval
        push(&mut self.up_hist, up / 1024);

        // Node RPC (best-effort)
        let fresh = self.poll_node();
        let prev = std::mem::replace(&mut self.node, fresh);
        self.derive_events(&prev);
        // Block-found edge → trigger the celebratory flash.
        if self.node.online {
            let bf = self.node.blocks_found;
            if matches!(self.prev_blocks, Some(p) if bf > p) {
                self.block_flash = Some(Instant::now());
            }
            self.prev_blocks = Some(bf);
        }
        push(&mut self.hash_hist, self.node.hashrate.round().max(0.0) as u64);
        push(&mut self.mempool_hist, self.node.mempool);
    }

    /// Turn the delta between the previous and current RPC snapshot into
    /// human-readable activity lines, btop/node-log style.
    fn derive_events(&mut self, prev: &NodeInfo) {
        let now = self.node.clone();

        // Online / offline transitions.
        if now.online && !prev.online {
            self.push_event("node", Color::Green,
                format!("rpc up — {} height={}", now.network, now.height));
        } else if !now.online && prev.online {
            self.push_event("node", Color::Red, "rpc unreachable — node down?".into());
        }
        if !now.online {
            return;
        }

        // Chain growth. One commit line per new tip; a big jump is an IBD catch-up.
        if prev.online && now.height > prev.height {
            let delta = now.height - prev.height;
            let short = short_hash(&now.top_hash);
            if delta == 1 {
                self.push_event("chain::commit", CYAN,
                    format!("BLOCK height={} diff={} tip={}", now.height, now.difficulty, short));
            } else {
                self.push_event("sync_driver", Color::Yellow,
                    format!("IBD +{} blocks → height={} tip={}", delta, now.height, short));
            }
        }

        // Our miner landed a block.
        if prev.online && now.blocks_found > prev.blocks_found {
            self.push_event("miner", Color::Rgb(0x6c, 0xff, 0x6c),
                format!("⛏ block at height {} — Accepted", now.height));
        }

        // Peer count moves.
        if prev.online && now.peers != prev.peers {
            let (arrow, col) = if now.peers > prev.peers {
                ("▲", Color::Green)
            } else {
                ("▼", Color::Rgb(0xff, 0xb0, 0x5a))
            };
            self.push_event("net", col, format!("{} peers {}→{}", arrow, prev.peers, now.peers));
        }

        // Mempool deltas (only when it actually changes).
        if prev.online && now.mempool != prev.mempool {
            if now.mempool > prev.mempool {
                self.push_event("mempool", DIM,
                    format!("+{} tx → {} pending", now.mempool - prev.mempool, now.mempool));
            } else {
                self.push_event("mempool", DIM,
                    format!("-{} tx → {} pending", prev.mempool - now.mempool, now.mempool));
            }
        }

        // Health edges.
        if now.fork_stuck && !prev.fork_stuck {
            self.push_event("sync", Color::Red,
                format!("FORK-STUCK — behind & stalled {}s", now.sync_stall_secs));
        } else if !now.fork_stuck && prev.fork_stuck {
            self.push_event("sync", Color::Green, "fork recovered — progressing".into());
        }
        if now.mesh_degraded && !prev.mesh_degraded {
            self.push_event("net", Color::Red, "mesh degraded — thin peer set".into());
        } else if !now.mesh_degraded && prev.mesh_degraded {
            self.push_event("net", Color::Green, "mesh healthy".into());
        }
        if now.synced && !prev.synced {
            self.push_event("sync", Color::Green,
                format!("fully synced at height {}", now.height));
        }
    }

    fn push_event(&mut self, tag: &'static str, color: Color, msg: String) {
        if self.events.len() >= EVENTS_CAP {
            self.events.pop_front();
        }
        self.events.push_back(ChainEvent { ts: clock_hms(), tag, msg, color });
    }

    fn poll_node(&self) -> NodeInfo {
        let info = self.rpc_call("get_info");
        let mining = self.rpc_call("get_mining_live");
        let Some(info) = info else {
            return NodeInfo::default();
        };
        let r = info.get("result").unwrap_or(&info);
        let m = mining.as_ref().and_then(|v| v.get("result").cloned());
        let m = m.unwrap_or(serde_json::Value::Null);
        NodeInfo {
            online: true,
            network: r.get("network").and_then(|v| v.as_str()).unwrap_or("?").to_string(),
            height: r.get("height").and_then(|v| v.as_u64()).unwrap_or(0),
            target_height: r.get("target_height").and_then(|v| v.as_u64()).unwrap_or(0),
            top_hash: r.get("top_hash").and_then(|v| v.as_str()).unwrap_or("").to_string(),
            synced: r.get("synced").and_then(|v| v.as_bool()).unwrap_or(false),
            fork_stuck: r.get("fork_stuck").and_then(|v| v.as_bool()).unwrap_or(false),
            sync_stall_secs: r.get("sync_stall_secs").and_then(|v| v.as_u64()).unwrap_or(0),
            mesh_degraded: r.get("mesh_degraded").and_then(|v| v.as_bool()).unwrap_or(false),
            peers: r.get("peer_count").and_then(|v| v.as_u64()).unwrap_or(0),
            difficulty: r.get("difficulty").and_then(|v| v.as_str()).unwrap_or("?").to_string(),
            mempool: r.get("mempool_size").and_then(|v| v.as_u64()).unwrap_or(0),
            is_mining: m.get("is_mining").and_then(|v| v.as_bool()).unwrap_or(false),
            hashrate: m.get("hashrate").and_then(|v| v.as_f64()).unwrap_or(0.0),
            hashes_total: m.get("hashes_total").and_then(|v| v.as_u64()).unwrap_or(0),
            blocks_found: m.get("blocks_found").and_then(|v| v.as_u64()).unwrap_or(0),
        }
    }

    fn rpc_call(&self, method: &str) -> Option<serde_json::Value> {
        let body = serde_json::json!({"jsonrpc":"2.0","id":1,"method":method,"params":[]});
        self.client.post(&self.rpc).json(&body).send().ok()?.json().ok()
    }
}

fn push(q: &mut VecDeque<u64>, v: u64) {
    if q.len() >= HIST {
        q.pop_front();
    }
    q.push_back(v);
}

fn as_slice(q: &VecDeque<u64>) -> Vec<u64> {
    q.iter().copied().collect()
}

/// Local wall-clock HH:MM:SS with no extra crates (derived from the system clock).
fn clock_hms() -> String {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let d = secs % 86_400;
    format!("{:02}:{:02}:{:02}", d / 3600, (d % 3600) / 60, d % 60)
}

/// First 8 + last 4 hex of a block hash, or "…" when unknown.
fn short_hash(h: &str) -> String {
    if h.len() <= 14 {
        if h.is_empty() { "…".into() } else { h.to_string() }
    } else {
        format!("{}…{}", &h[..8], &h[h.len() - 4..])
    }
}

fn human_bytes(b: u64) -> String {
    const U: [&str; 5] = ["B", "KiB", "MiB", "GiB", "TiB"];
    let mut v = b as f64;
    let mut i = 0;
    while v >= 1024.0 && i < U.len() - 1 {
        v /= 1024.0;
        i += 1;
    }
    format!("{v:.1} {}", U[i])
}

fn human_hashrate(h: f64) -> String {
    if h >= 1_000_000.0 {
        format!("{:.2} MH/s", h / 1e6)
    } else if h >= 1_000.0 {
        format!("{:.2} kH/s", h / 1e3)
    } else {
        format!("{h:.0} H/s")
    }
}

/// Load-based colour: green < 60%, yellow < 85%, red above.
fn load_color(pct: f64) -> Color {
    if pct < 60.0 {
        Color::Rgb(0x58, 0xd6, 0x8a)
    } else if pct < 85.0 {
        Color::Rgb(0xe3, 0xc4, 0x4f)
    } else {
        Color::Rgb(0xe3, 0x5c, 0x5c)
    }
}

/// Vertical bar glyph for a 0..=100 percentage (8 levels).
fn bar_char(pct: f64) -> char {
    const B: [char; 8] = ['▁', '▂', '▃', '▄', '▅', '▆', '▇', '█'];
    let i = ((pct / 100.0) * 7.0).round().clamp(0.0, 7.0) as usize;
    B[i]
}

/// Animated miner swinging a pickaxe. Returns (line, is_strike-frame).
fn mining_art(frame: u64) -> (&'static str, bool) {
    match (frame / 2) % 4 {
        0 => ("(•_•)  ⛏      ", false),
        1 => ("(•_•)    ⛏    ", false),
        2 => ("(•_•)      ⛏ ✦", true), // strike + spark
        _ => ("(•_•)    ⛏    ", false),
    }
}

/// Braille dot bitmasks: `[column 0|1][row top→bottom]`.
const BRAILLE_DOTS: [[u8; 4]; 2] = [
    [0x01, 0x02, 0x04, 0x40],
    [0x08, 0x10, 0x20, 0x80],
];

/// Filled braille area graph, right-aligned over the most recent samples:
/// `rows` text lines × `cols` chars, each char a 2×4 dot cell (btop-style).
fn braille_graph(data: &[u64], max: u64, cols: usize, rows: usize) -> Vec<String> {
    if cols == 0 || rows == 0 {
        return vec![];
    }
    let dot_w = cols * 2;
    let dot_h = rows * 4;
    let maxv = max.max(1) as f64;
    let n = data.len();
    let mut heights = vec![0usize; dot_w];
    for i in 0..dot_w.min(n) {
        let v = data[n - 1 - i] as f64; // newest sample on the right edge
        let h = ((v / maxv) * dot_h as f64).round() as usize;
        heights[dot_w - 1 - i] = h.min(dot_h);
    }
    let mut cells = vec![vec![0u8; cols]; rows];
    for (dx, &h) in heights.iter().enumerate() {
        for dy in 0..h {
            let row_from_top = dot_h - 1 - dy;
            cells[row_from_top / 4][dx / 2] |= BRAILLE_DOTS[dx % 2][row_from_top % 4];
        }
    }
    cells
        .iter()
        .map(|row| {
            row.iter()
                .map(|&b| char::from_u32(0x2800 + b as u32).unwrap_or(' '))
                .collect()
        })
        .collect()
}

/// A bordered braille-graph panel sized to `area`.
fn graph(title: &str, data: &VecDeque<u64>, max: u64, color: Color, area: Rect) -> Paragraph<'static> {
    let cols = area.width.saturating_sub(2) as usize;
    let rows = area.height.saturating_sub(2) as usize;
    let d = as_slice(data);
    let lines: Vec<Line> = braille_graph(&d, max, cols, rows)
        .into_iter()
        .map(|s| Line::from(Span::styled(s, Style::default().fg(color))))
        .collect();
    Paragraph::new(lines).block(panel(title))
}


/// Human-readable duration from seconds.
fn human_dur(secs: f64) -> String {
    if !secs.is_finite() || secs <= 0.0 {
        return "—".into();
    }
    let s = secs as u64;
    if s < 60 {
        format!("{s}s")
    } else if s < 3600 {
        format!("{}m{:02}s", s / 60, s % 60)
    } else if s < 86400 {
        format!("{}h{:02}m", s / 3600, (s % 3600) / 60)
    } else {
        format!("{}d{}h", s / 86400, (s % 86400) / 3600)
    }
}

/// A node alert banner (message, colour), if any condition is active.
fn node_alert(n: &NodeInfo) -> Option<(String, Color)> {
    if !n.online {
        Some(("⚠  node RPC offline".into(), Color::Red))
    } else if n.fork_stuck {
        Some((
            "⚠  FORK-STUCK — wedged on a minority fork; an operator reset may be needed".into(),
            Color::Red,
        ))
    } else if n.mesh_degraded {
        Some(("⚠  mesh degraded — too few peers".into(), Color::Yellow))
    } else {
        None
    }
}

fn panel(title: &str) -> Block<'static> {
    Block::default()
        .borders(Borders::ALL)
        .border_type(BorderType::Rounded)
        .border_style(Style::default().fg(DIM))
        .title(Span::styled(
            format!(" {title} "),
            Style::default().fg(CYAN).add_modifier(Modifier::BOLD),
        ))
}

fn draw(f: &mut Frame, app: &App) {
    let area = f.area();
    // header | alert | body | footer
    let rows = Layout::vertical([
        Constraint::Length(1),
        Constraint::Length(1),
        Constraint::Min(0),
        Constraint::Length(1),
    ])
    .split(area);

    draw_header(f, rows[0], app);

    if let Some((msg, col)) = node_alert(&app.node) {
        f.render_widget(
            Paragraph::new(Line::from(Span::styled(
                format!(" {msg} "),
                Style::default().fg(Color::Black).bg(col).add_modifier(Modifier::BOLD),
            ))),
            rows[1],
        );
    }

    // body: left (system) | right (node)
    let cols = Layout::horizontal([Constraint::Percentage(58), Constraint::Percentage(42)])
        .split(rows[2]);
    draw_system(f, cols[0], app);
    draw_node(f, cols[1], app);

    let mut hint = vec![
        Span::styled(" q ", Style::default().fg(Color::Black).bg(CYAN)),
        Span::styled(" quit  ", Style::default().fg(DIM)),
        Span::styled("space", Style::default().fg(CYAN)),
        Span::styled(" pause  ", Style::default().fg(DIM)),
    ];
    if app.paused {
        hint.push(Span::styled(
            "PAUSED  ",
            Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD),
        ));
    }
    hint.push(Span::styled("◈ coincync-top", Style::default().fg(CYAN)));
    f.render_widget(Paragraph::new(Line::from(hint)), rows[3]);
}

fn draw_header(f: &mut Frame, area: Rect, app: &App) {
    let host = System::host_name().unwrap_or_else(|| "host".into());
    let os = System::long_os_version().unwrap_or_default();
    let up = System::uptime();
    let line = Line::from(vec![
        Span::styled("◈ coincync-top", Style::default().fg(CYAN).add_modifier(Modifier::BOLD)),
        Span::styled(format!("  {host}  "), Style::default().fg(Color::White)),
        Span::styled(format!("{os}  "), Style::default().fg(DIM)),
        Span::styled(
            format!("up {}h{:02}m", up / 3600, (up % 3600) / 60),
            Style::default().fg(DIM),
        ),
        Span::styled(
            format!("   rpc {}", if app.node.online { "●" } else { "○" }),
            Style::default().fg(if app.node.online { Color::Green } else { Color::Red }),
        ),
        Span::styled(format!("   {}", clock_hms()), Style::default().fg(DIM)),
    ]);
    f.render_widget(Paragraph::new(line), area);
}

fn draw_system(f: &mut Frame, area: Rect, app: &App) {
    let rows = Layout::vertical([
        Constraint::Length(6), // cpu graph
        Constraint::Length(3), // per-core bars
        Constraint::Length(3), // mem
        Constraint::Length(6), // net
        Constraint::Min(0),    // processes
    ])
    .split(area);

    // CPU — braille area graph, coloured by load
    let cpu_now = *app.cpu_hist.back().unwrap_or(&0);
    f.render_widget(
        graph(&format!("cpu  {cpu_now}%"), &app.cpu_hist, 100, load_color(cpu_now as f64), rows[0]),
        rows[0],
    );

    // Per-core — one vertical bar per core, coloured by load
    let cores: Vec<Span> = app
        .sys
        .cpus()
        .iter()
        .map(|c| {
            let u = c.cpu_usage() as f64;
            Span::styled(bar_char(u).to_string(), Style::default().fg(load_color(u)))
        })
        .collect();
    f.render_widget(
        Paragraph::new(Line::from(cores))
            .block(panel(&format!("cores  ({})", app.sys.cpus().len()))),
        rows[1],
    );

    // Mem — gauge coloured by load
    let total = app.sys.total_memory();
    let used = app.sys.used_memory();
    let ratio = if total > 0 { used as f64 / total as f64 } else { 0.0 };
    f.render_widget(
        Gauge::default()
            .block(panel("memory"))
            .ratio(ratio.clamp(0.0, 1.0))
            .label(format!("{} / {}", human_bytes(used), human_bytes(total)))
            .gauge_style(Style::default().fg(load_color(ratio * 100.0))),
        rows[2],
    );

    // Net — braille area graph of download (auto-scaled)
    let down = *app.down_hist.back().unwrap_or(&0);
    let up = *app.up_hist.back().unwrap_or(&0);
    let nmax = app.down_hist.iter().copied().max().unwrap_or(1).max(1);
    f.render_widget(
        graph(
            &format!("net  ↓{down} ↑{up} KiB/s"),
            &app.down_hist,
            nmax,
            Color::Rgb(0x58, 0xd6, 0x8a),
            rows[3],
        ),
        rows[3],
    );

    // Chain activity — the "processes" panel now shows the blockchain working:
    // a rolling feed of commits, mined blocks, IBD, peer/mempool/health deltas,
    // reconstructed live from RPC state changes. Newest at the bottom, log-style.
    let rows_n = rows[4].height.saturating_sub(2) as usize;
    let items: Vec<ListItem> = if app.events.is_empty() {
        vec![ListItem::new(Line::from(Span::styled(
            "waiting for chain activity…",
            Style::default().fg(DIM),
        )))]
    } else {
        app.events
            .iter()
            .rev()
            .take(rows_n)
            .collect::<Vec<_>>()
            .into_iter()
            .rev()
            .map(|e| {
                ListItem::new(Line::from(vec![
                    Span::styled(format!("{} ", e.ts), Style::default().fg(DIM)),
                    Span::styled(format!("{:<13} ", e.tag), Style::default().fg(CYAN)),
                    Span::styled(e.msg.clone(), Style::default().fg(e.color)),
                ]))
            })
            .collect()
    };
    f.render_widget(
        List::new(items).block(panel(&format!("chain activity  ({} events)", app.events.len()))),
        rows[4],
    );
}

fn draw_node(f: &mut Frame, area: Rect, app: &App) {
    let n = &app.node;
    let rows = Layout::vertical([
        Constraint::Length(8), // chain
        Constraint::Length(7), // mining
        Constraint::Length(4), // peers/privacy
        Constraint::Min(0),    // mempool graph
    ])
    .split(area);

    if !n.online {
        f.render_widget(
            Paragraph::new(Line::from(Span::styled(
                "node RPC offline — start a node or pass --rpc",
                Style::default().fg(Color::Red),
            )))
            .block(panel("node")),
            rows[0],
        );
        return;
    }

    // Chain
    let sync = if n.synced {
        Span::styled("synced", Style::default().fg(Color::Green))
    } else if n.fork_stuck {
        Span::styled("FORK-STUCK", Style::default().fg(Color::Red).add_modifier(Modifier::BOLD))
    } else {
        Span::styled(format!("syncing (stall {}s)", n.sync_stall_secs), Style::default().fg(Color::Yellow))
    };
    let mut chain = vec![
        Line::from(vec![Span::styled("height  ", Style::default().fg(DIM)), Span::styled(n.height.to_string(), Style::default().fg(Color::White).add_modifier(Modifier::BOLD))]),
        Line::from(vec![Span::styled("state   ", Style::default().fg(DIM)), sync]),
        Line::from(vec![Span::styled("network ", Style::default().fg(DIM)), Span::raw(n.network.clone())]),
        Line::from(vec![Span::styled("diff    ", Style::default().fg(DIM)), Span::raw(n.difficulty.clone())]),
        Line::from(vec![Span::styled("mempool ", Style::default().fg(DIM)), Span::raw(format!("{} tx", n.mempool))]),
    ];
    if !n.synced && n.target_height > n.height {
        let pct = (n.height as f64 / n.target_height.max(1) as f64) * 100.0;
        chain.insert(
            2,
            Line::from(vec![
                Span::styled("sync    ", Style::default().fg(DIM)),
                Span::styled(
                    format!("{pct:.1}%  ({}/{})", n.height, n.target_height),
                    Style::default().fg(Color::Yellow),
                ),
            ]),
        );
    }
    f.render_widget(Paragraph::new(chain).block(panel("chain")), rows[0]);

    // Mining
    let mining_title = if n.is_mining {
        format!("mining  {}", human_hashrate(n.hashrate))
    } else {
        "mining  (off)".to_string()
    };
    let mrows = Layout::vertical([Constraint::Length(4), Constraint::Min(0)]).split(rows[1]);
    let hmax = app.hash_hist.iter().copied().max().unwrap_or(1).max(1);
    f.render_widget(
        graph(
            &mining_title,
            &app.hash_hist,
            hmax,
            if n.is_mining { CYAN } else { DIM },
            mrows[0],
        ),
        mrows[0],
    );

    // Animated miner + celebratory block-found flash (3s).
    let gold = Color::Rgb(0xf5, 0xc8, 0x42);
    let flashing = app
        .block_flash
        .map(|t| t.elapsed() < Duration::from_secs(3))
        .unwrap_or(false);
    let face = if flashing {
        Line::from(Span::styled(
            "  ✦ ⛏  BLOCK FOUND!  ⛏ ✦",
            Style::default().fg(gold).add_modifier(Modifier::BOLD),
        ))
    } else if n.is_mining {
        let (art, strike) = mining_art(app.frame);
        Line::from(Span::styled(art, Style::default().fg(if strike { gold } else { CYAN })))
    } else {
        Line::from(Span::styled("  (-_-) zzz   idle", Style::default().fg(DIM)))
    };
    let diff_val: f64 = n.difficulty.parse().unwrap_or(0.0);
    let eta_line = if n.is_mining && n.hashrate > 0.0 && diff_val > 0.0 {
        Line::from(vec![
            Span::styled("~block ", Style::default().fg(DIM)),
            Span::styled(human_dur(diff_val / n.hashrate), Style::default().fg(CYAN)),
            Span::styled(" (solo est.)", Style::default().fg(DIM)),
        ])
    } else {
        Line::from("")
    };
    f.render_widget(
        Paragraph::new(vec![
            face,
            Line::from(vec![
                Span::styled("blocks ", Style::default().fg(DIM)),
                Span::styled(n.blocks_found.to_string(), Style::default().fg(Color::White)),
                Span::styled("   hashes ", Style::default().fg(DIM)),
                Span::raw(n.hashes_total.to_string()),
            ]),
            eta_line,
        ]),
        mrows[1],
    );

    // Peers / privacy
    let privacy = if n.peers >= 3 {
        Span::styled("Baffle · adequate", Style::default().fg(Color::Green))
    } else {
        Span::styled("Baffle · size-limited", Style::default().fg(Color::Yellow))
    };
    let peers = vec![
        Line::from(vec![Span::styled("peers   ", Style::default().fg(DIM)), Span::styled(n.peers.to_string(), Style::default().fg(Color::White))]),
        Line::from(vec![Span::styled("privacy ", Style::default().fg(DIM)), privacy]),
    ];
    f.render_widget(Paragraph::new(peers).block(panel("peers")), rows[2]);

    // Mempool — braille area graph of pending-tx count over time.
    let mmax = app.mempool_hist.iter().copied().max().unwrap_or(1).max(1);
    f.render_widget(
        graph(
            &format!("mempool  ({} tx)", n.mempool),
            &app.mempool_hist,
            mmax,
            Color::Rgb(0xc8, 0x8a, 0xf0),
            rows[3],
        ),
        rows[3],
    );
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    let mut app = App::new(&cli);
    let mut terminal = ratatui::init();
    let refresh = Duration::from_millis(cli.refresh_ms.max(200));

    app.tick();
    let res = run(&mut terminal, &mut app, refresh);
    ratatui::restore();
    res
}

fn run(
    terminal: &mut ratatui::DefaultTerminal,
    app: &mut App,
    refresh: Duration,
) -> anyhow::Result<()> {
    loop {
        terminal.draw(|f| draw(f, app))?;

        // Redraw at ~5 fps (for animation); refresh DATA at the slower `refresh`.
        if event::poll(Duration::from_millis(200))? {
            if let Event::Key(k) = event::read()? {
                match k.code {
                    KeyCode::Char('q') | KeyCode::Char('Q') | KeyCode::Esc => return Ok(()),
                    KeyCode::Char('c') if k.modifiers.contains(KeyModifiers::CONTROL) => {
                        return Ok(())
                    }
                    KeyCode::Char(' ') => app.paused = !app.paused,
                    _ => {}
                }
            }
        }
        app.frame = app.frame.wrapping_add(1);
        if !app.paused && app.last_poll.elapsed() >= refresh {
            app.tick();
            app.last_poll = Instant::now();
        }
    }
}
