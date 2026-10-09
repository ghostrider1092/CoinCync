//! coincync-top — a native-Rust system + CoinCync-node monitor (btop-style).
//!
//! Phase 1: live boxed panels for the host (CPU per-core, memory, network,
//! top processes — via `sysinfo`) AND the node (chain / mining / peers —
//! polled read-only from the node RPC). `q`/`Esc`/`Ctrl-C` to quit. Not a
//! replacement for the node's log — a separate monitor you run when you want it.

use std::collections::VecDeque;
use std::fs::File;
use std::io::{BufRead, BufReader, Seek, SeekFrom};
use std::sync::mpsc::{self, Receiver};
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
    /// Tail this node log file into the chain-activity feed (the node's own
    /// lines: heartbeat ticks, GetBlocks/Received, BLOCK_COMMIT, miner Accepted).
    /// Point it at the file the node writes/tees to. Without it, the feed falls
    /// back to events synthesised from RPC state deltas.
    #[arg(long)]
    log: Option<String>,
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

/// A single line in the chain-activity feed. Either the node's own log line
/// (when `--log` tails the node output) or an event synthesised from RPC state
/// deltas (the fallback). Stored as pre-coloured spans so both sources render
/// identically.
#[derive(Clone)]
struct FeedLine {
    spans: Vec<(String, Color)>,
}

const EVENTS_CAP: usize = 500;

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
    events: VecDeque<FeedLine>,   // chain-activity feed (newest at back)
    log_rx: Option<Receiver<String>>, // node-log tailer channel (when --log set)
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
            log_rx: cli.log.clone().map(spawn_log_tailer),
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
        // RPC-derived events are the fallback feed; when we're tailing the node
        // log, the real log lines are the feed instead (drained in drain_log()).
        if self.log_rx.is_none() {
            self.derive_events(&prev);
        }
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
        let (icon, icon_color) = icon_for("INFO", tag, &msg);
        self.push_feed(FeedLine {
            spans: vec![
                (format!("{icon} "), icon_color),
                (format!("{} ", clock_hms()), DIM),
                (format!("{:<13} ", tag), CYAN),
                (msg, color),
            ],
        });
    }

    fn push_feed(&mut self, line: FeedLine) {
        if self.events.len() >= EVENTS_CAP {
            self.events.pop_front();
        }
        self.events.push_back(line);
    }

    /// Drain any node-log lines the tailer thread has queued into the feed.
    fn drain_log(&mut self) {
        // Pull the receiver out so we can borrow self mutably inside the loop.
        if let Some(rx) = self.log_rx.take() {
            while let Ok(line) = rx.try_recv() {
                if !line.trim().is_empty() {
                    self.push_feed(parse_log_line(&line));
                }
            }
            self.log_rx = Some(rx);
        }
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

/// Parse one tracing-fmt node log line into coloured feed spans. Format seen
/// live: `YYYY-MM-DD HH:MM:SS.mmm  LEVEL  ◈ module::path  message…`. We colour
/// the time dim, the level by severity, the module cyan and highlight the
/// interesting messages (commits / miner accepts). Anything that doesn't match
/// the shape is shown verbatim so nothing is ever dropped.
fn parse_log_line(line: &str) -> FeedLine {
    let t: Vec<&str> = line.split_whitespace().collect();
    // Need at least date, time, level.
    if t.len() < 3 || !looks_like_level(t[2]) {
        return FeedLine {
            spans: vec![("▸ ".to_string(), DIM), (line.trim_end().to_string(), Color::White)],
        };
    }
    let time = t[1];
    let level = t[2];
    // Skip an optional decoration glyph (◈, or its mojibake under a mangled
    // console codepage): any short token with no ASCII-alphanumeric character.
    let mut i = 3;
    if t.get(i)
        .map(|s| !s.chars().any(|c| c.is_ascii_alphanumeric()))
        .unwrap_or(false)
    {
        i += 1;
    }
    let module = t.get(i).copied().unwrap_or("");
    let msg = t.get(i + 1..).map(|r| r.join(" ")).unwrap_or_default();

    let level_color = match level {
        "ERROR" | "ERRO" => Color::Red,
        "WARN" | "WARNING" => Color::Yellow,
        "INFO" => Color::Green,
        "DEBUG" => Color::Rgb(0x7a, 0x9c, 0xd6),
        _ => DIM,
    };
    let msg_color = if msg.contains("BLOCK_COMMIT") || msg.contains("Accepted") {
        Color::Rgb(0x6c, 0xff, 0x6c)
    } else if level == "WARN" || level == "WARNING" {
        Color::Yellow
    } else if level == "ERROR" || level == "ERRO" {
        Color::Red
    } else if msg.contains("[IBD]") {
        Color::Rgb(0xf5, 0xc8, 0x42)
    } else {
        Color::White
    };

    let (icon, icon_color) = icon_for(level, module, &msg);
    FeedLine {
        spans: vec![
            (format!("{icon} "), icon_color),
            (format!("{time} "), DIM),
            (format!("{level:<5} "), level_color),
            (format!("{module}  "), CYAN),
            (msg, msg_color),
        ],
    }
}

fn looks_like_level(s: &str) -> bool {
    matches!(s, "ERROR" | "ERRO" | "WARN" | "WARNING" | "INFO" | "DEBUG" | "TRACE")
}

/// Pick a single-width category icon (+ its colour) for a feed line, from the
/// severity, module and message. All glyphs are BMP width-1 so the columns stay
/// aligned line-to-line.
fn icon_for(level: &str, module: &str, msg: &str) -> (&'static str, Color) {
    let gold = Color::Rgb(0xf5, 0xc8, 0x42);
    let green = Color::Rgb(0x6c, 0xff, 0x6c);
    match level {
        "ERROR" | "ERRO" => return ("✖", Color::Red),
        "WARN" | "WARNING" => return ("⚑", Color::Yellow),
        _ => {}
    }
    if msg.contains("BLOCK_COMMIT") {
        ("⬢", green) // a block landed on our chain
    } else if module.contains("miner") || msg.contains("Accepted") {
        ("✦", gold) // our miner found/accepted a block
    } else if module.contains("heartbeat") {
        ("♥", DIM) // maintenance tick
    } else if module.contains("dispatch") {
        ("⇣", CYAN) // blocks/data received
    } else if module.contains("sync_driver") || msg.contains("[IBD]") {
        ("⇅", gold) // sync traffic
    } else if module.contains("peer_manager")
        || module.contains("connection")
        || msg.contains("handshake")
        || msg.contains("peer")
    {
        ("●", CYAN) // peer/mesh
    } else if module.contains("randomx") || module.contains("pow") {
        ("◆", Color::Rgb(0xc8, 0x8a, 0xf0)) // RandomX / PoW
    } else if module.contains("rpc") || module.contains("rest") || module.contains("metrics") {
        ("⚙", DIM) // service endpoints
    } else if module.contains("dandelion") {
        ("⟐", Color::Rgb(0xc8, 0x8a, 0xf0)) // privacy / Baffle
    } else {
        ("▸", DIM)
    }
}

/// Follow a node log file (`tail -f`): seed with the recent tail, then stream
/// new lines. Survives the file not existing yet and truncation/rotation.
/// Runs on its own thread; returns the receiving end of the line channel.
fn spawn_log_tailer(path: String) -> Receiver<String> {
    let (tx, rx) = mpsc::channel::<String>();
    std::thread::spawn(move || {
        // Wait for the file to appear.
        let mut file = loop {
            match File::open(&path) {
                Ok(f) => break f,
                Err(_) => {
                    if tx.send(String::new()).is_err() {
                        return;
                    }
                    std::thread::sleep(Duration::from_millis(500));
                }
            }
        };
        // Seed from roughly the last 48 KiB so the feed isn't empty on open.
        let mut pos: u64 = 0;
        if let Ok(meta) = file.metadata() {
            pos = meta.len().saturating_sub(48 * 1024);
        }
        let _ = file.seek(SeekFrom::Start(pos));
        let mut reader = BufReader::new(file);
        // Drop a partial first line when we seeked into the middle of one.
        if pos > 0 {
            let mut skip = String::new();
            let _ = reader.read_line(&mut skip);
        }
        loop {
            let mut buf = String::new();
            match reader.read_line(&mut buf) {
                Ok(0) => {
                    // EOF: check for truncation/rotation, else wait for growth.
                    let cur = reader.stream_position().unwrap_or(0);
                    if let Ok(f) = File::open(&path) {
                        if let Ok(meta) = f.metadata() {
                            if meta.len() < cur {
                                // File shrank → reopen from the start.
                                let mut nf = f;
                                let _ = nf.seek(SeekFrom::Start(0));
                                reader = BufReader::new(nf);
                                continue;
                            }
                        }
                    }
                    std::thread::sleep(Duration::from_millis(150));
                }
                Ok(_) => {
                    if tx.send(buf.trim_end().to_string()).is_err() {
                        return;
                    }
                }
                Err(_) => std::thread::sleep(Duration::from_millis(250)),
            }
        }
    });
    rx
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
        let wait = if app.log_rx.is_some() {
            "waiting for node log… (is --log pointing at the node output?)"
        } else {
            "waiting for chain activity…"
        };
        vec![ListItem::new(Line::from(Span::styled(wait, Style::default().fg(DIM))))]
    } else {
        app.events
            .iter()
            .rev()
            .take(rows_n)
            .collect::<Vec<_>>()
            .into_iter()
            .rev()
            .map(|e| {
                ListItem::new(Line::from(
                    e.spans
                        .iter()
                        .map(|(t, c)| Span::styled(t.clone(), Style::default().fg(*c)))
                        .collect::<Vec<_>>(),
                ))
            })
            .collect()
    };
    let title = if app.log_rx.is_some() {
        format!("chain activity · node log  ({} lines)", app.events.len())
    } else {
        format!("chain activity · rpc  ({} events)", app.events.len())
    };
    f.render_widget(List::new(items).block(panel(&title)), rows[4]);
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
        // Stream node-log lines every frame so the feed stays live between polls.
        if !app.paused {
            app.drain_log();
        }
        if !app.paused && app.last_poll.elapsed() >= refresh {
            app.tick();
            app.last_poll = Instant::now();
        }
    }
}
