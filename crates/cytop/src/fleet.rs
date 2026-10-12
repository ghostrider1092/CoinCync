//! Fleet overview — poll N CoinCync nodes concurrently and render a single
//! screen of testnet health: per-node tip/sync/peers/health plus a derived
//! *network* summary (height agreement, consensus-fingerprint agreement, and
//! fork/lag detection). This is the "is the whole testnet working?" view, which
//! a single-node monitor (nview-style) can't answer.
//!
//! Pure read-only JSON-RPC client, exactly like `collect::NodeClient` — it only
//! ever calls `get_info`. Reach remote nodes whose RPC is loopback-bound via SSH
//! local forwards (see `scripts/fleet-tunnels.sh`), then point `--fleet` at the
//! forwarded `127.0.0.1:<port>` URLs.

use std::collections::VecDeque;
use std::time::{Duration, Instant};

use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Cell, Padding, Paragraph, Row, Sparkline, Table};
use ratatui::Frame;

use crate::theme::Theme;

/// Heights within this many blocks of each other count as "in agreement" — one
/// node a block or two ahead mid-propagation is normal, not a split.
pub const AGREE_TOLERANCE: u64 = 2;

/// Per-node rolling height history length (for the sparkline).
const HIST: usize = 60;

/// One node to watch: a short display label + its JSON-RPC URL.
#[derive(Clone)]
pub struct FleetTarget {
    pub label: String,
    pub url: String,
}

impl FleetTarget {
    /// Parse a `--fleet` spec: comma-separated `label=url` entries, or bare
    /// `url` entries (auto-labelled `n1`, `n2`, …). A bare host:port or host is
    /// upgraded to `http://host:port` (default port 28081).
    pub fn parse_list(spec: &str) -> Vec<FleetTarget> {
        let mut out = Vec::new();
        for (i, raw) in spec.split(',').map(str::trim).filter(|s| !s.is_empty()).enumerate() {
            let (label, url) = match raw.split_once('=') {
                Some((l, u)) => (l.trim().to_string(), u.trim().to_string()),
                None => (format!("n{}", i + 1), raw.to_string()),
            };
            out.push(FleetTarget { label, url: normalize_url(&url) });
        }
        out
    }
}

fn normalize_url(u: &str) -> String {
    let u = u.trim();
    if u.starts_with("http://") || u.starts_with("https://") {
        return u.to_string();
    }
    if u.contains(':') {
        format!("http://{u}")
    } else {
        format!("http://{u}:28081")
    }
}

/// A rich snapshot of one node from `get_info` (best-effort; `online=false`
/// when the RPC is unreachable or returns no result).
#[derive(Clone, Default)]
pub struct FleetNode {
    pub online: bool,
    pub network: String,
    pub version: String,
    pub status: String,
    pub height: u64,
    pub target_height: u64,
    pub tip_hash: String,
    pub tip_age_secs: u64,
    pub synced: bool,
    pub mesh_degraded: bool,
    pub peer_count: u64,
    pub inbound_peers: u64,
    pub difficulty: String,
    pub total_difficulty: String,
    pub health_score: f64,
    pub anonymity_set: u64,
    pub mempool: u64,
    /// Short (8-char) consensus fingerprint — mismatch across the fleet means a
    /// node is running incompatible consensus params (a bad/partial deploy).
    pub fingerprint: String,
    /// Poll round-trip, milliseconds (connectivity/latency signal).
    pub rtt_ms: u64,
}

/// Read-only JSON-RPC client; one `get_info` call per poll, short timeout.
pub struct FleetClient {
    client: reqwest::blocking::Client,
}

impl FleetClient {
    pub fn new(timeout: Duration) -> Self {
        FleetClient {
            client: reqwest::blocking::Client::builder()
                .timeout(timeout)
                .build()
                .expect("http client"),
        }
    }

    fn poll_one(&self, url: &str) -> FleetNode {
        let t0 = Instant::now();
        let body = serde_json::json!({"jsonrpc":"2.0","id":1,"method":"get_info","params":[]});
        let resp: Option<serde_json::Value> = self
            .client
            .post(url)
            .json(&body)
            .send()
            .ok()
            .and_then(|r| r.json().ok());
        let rtt_ms = t0.elapsed().as_millis() as u64;
        let Some(v) = resp else {
            return FleetNode { rtt_ms, ..Default::default() };
        };
        let r = v.get("result").unwrap_or(&v);
        let s = |k: &str| r.get(k).and_then(|x| x.as_str()).unwrap_or("").to_string();
        let u = |k: &str| r.get(k).and_then(|x| x.as_u64()).unwrap_or(0);
        let b = |k: &str| r.get(k).and_then(|x| x.as_bool()).unwrap_or(false);
        let f = |k: &str| r.get(k).and_then(|x| x.as_f64()).unwrap_or(0.0);
        FleetNode {
            online: true,
            network: s("network"),
            version: s("version"),
            status: s("status"),
            height: u("height"),
            target_height: {
                let t = u("peer_target_height");
                if t == 0 { u("target_height") } else { t }
            },
            tip_hash: s("tip_hash"),
            tip_age_secs: u("tip_age_secs"),
            synced: b("synced") || b("is_synced"),
            mesh_degraded: b("mesh_degraded"),
            peer_count: u("peer_count"),
            inbound_peers: u("inbound_peers"),
            difficulty: s("difficulty"),
            total_difficulty: s("total_difficulty"),
            health_score: f("health_score"),
            anonymity_set: u("anonymity_set"),
            mempool: u("mempool_size"),
            fingerprint: s("consensus_fingerprint").chars().take(8).collect(),
            rtt_ms,
        }
    }
}

/// Poll every target concurrently (one scoped thread each) so the whole fleet
/// is sampled in ~one slow-node round-trip, not the sum. Order is preserved.
pub fn poll_fleet(targets: &[FleetTarget], timeout: Duration) -> Vec<FleetNode> {
    std::thread::scope(|scope| {
        let handles: Vec<_> = targets
            .iter()
            .map(|t| scope.spawn(move || FleetClient::new(timeout).poll_one(&t.url)))
            .collect();
        handles
            .into_iter()
            .map(|h| h.join().unwrap_or_default())
            .collect()
    })
}

/// Network-level summary derived from the per-node snapshots.
#[derive(Default)]
pub struct FleetSummary {
    pub online: usize,
    pub total: usize,
    pub min_height: u64,
    pub max_height: u64,
    pub height_spread: u64,
    pub in_agreement: bool,
    pub fingerprints_match: bool,
    pub fingerprint: String,
    pub fork_suspected: bool,
    pub worst_tip_age: u64,
    pub worst_health: f64,
    pub network: String,
    /// Network anonymity-set size (max across online nodes — they converge).
    pub anonymity_set: u64,
    /// Total mempool backlog across the fleet (txs in flight right now).
    pub mempool_total: u64,
}

impl FleetSummary {
    pub fn derive(nodes: &[FleetNode]) -> FleetSummary {
        let online: Vec<&FleetNode> = nodes.iter().filter(|n| n.online).collect();
        let mut sum = FleetSummary {
            total: nodes.len(),
            online: online.len(),
            worst_health: 1.0,
            fingerprints_match: true,
            ..Default::default()
        };
        if online.is_empty() {
            sum.worst_health = 0.0;
            return sum;
        }
        sum.min_height = online.iter().map(|n| n.height).min().unwrap_or(0);
        sum.max_height = online.iter().map(|n| n.height).max().unwrap_or(0);
        sum.height_spread = sum.max_height.saturating_sub(sum.min_height);
        sum.in_agreement = sum.height_spread <= AGREE_TOLERANCE;
        sum.worst_tip_age = online.iter().map(|n| n.tip_age_secs).max().unwrap_or(0);
        sum.worst_health = online.iter().map(|n| n.health_score).fold(1.0, f64::min);
        sum.anonymity_set = online.iter().map(|n| n.anonymity_set).max().unwrap_or(0);
        sum.mempool_total = online.iter().map(|n| n.mempool).sum();
        sum.network = online
            .iter()
            .map(|n| n.network.clone())
            .find(|n| !n.is_empty())
            .unwrap_or_default();

        // Fingerprint agreement: all online nodes that report one must share it.
        let fps: Vec<&str> = online
            .iter()
            .map(|n| n.fingerprint.as_str())
            .filter(|f| !f.is_empty())
            .collect();
        if let Some(first) = fps.first().copied() {
            sum.fingerprint = first.to_string();
            sum.fingerprints_match = fps.iter().all(|f| *f == first);
        }

        // Fork suspicion: two online nodes at the SAME height reporting DIFFERENT
        // tip hashes is a genuine split (not just lag).
        'outer: for (i, a) in online.iter().enumerate() {
            if a.tip_hash.is_empty() {
                continue;
            }
            for b in online.iter().skip(i + 1) {
                if a.height != b.height {
                    continue;
                }
                // Same height but a different tip hash is a genuine split; a
                // different cumulative work at the same height is the same thing
                // seen from the work side (one node is on a heavier/lighter fork).
                let diff_tip = !b.tip_hash.is_empty() && a.tip_hash != b.tip_hash;
                let diff_work = !a.total_difficulty.is_empty()
                    && !b.total_difficulty.is_empty()
                    && a.total_difficulty != b.total_difficulty;
                if diff_tip || diff_work {
                    sum.fork_suspected = true;
                    break 'outer;
                }
            }
        }
        sum
    }
}

/// Fleet view state: targets, latest snapshots, derived summary, per-node height
/// history, and the usual loop bookkeeping.
pub struct FleetApp {
    pub targets: Vec<FleetTarget>,
    pub nodes: Vec<FleetNode>,
    pub summary: FleetSummary,
    pub hist: Vec<VecDeque<u64>>,
    pub theme: Theme,
    pub timeout: Duration,
    pub last_poll: Instant,
    pub paused: bool,
    pub frame: u64,
}

impl FleetApp {
    pub fn new(targets: Vec<FleetTarget>, theme: Theme, timeout: Duration) -> Self {
        let n = targets.len();
        FleetApp {
            targets,
            nodes: vec![FleetNode::default(); n],
            summary: FleetSummary::default(),
            hist: vec![VecDeque::from(vec![0u64; HIST]); n],
            theme,
            timeout,
            last_poll: Instant::now(),
            paused: false,
            frame: 0,
        }
    }

    pub fn tick(&mut self) {
        self.nodes = poll_fleet(&self.targets, self.timeout);
        for (h, node) in self.hist.iter_mut().zip(self.nodes.iter()) {
            if h.len() >= HIST {
                h.pop_front();
            }
            h.push_back(node.height);
        }
        self.summary = FleetSummary::derive(&self.nodes);
    }
}

// ─────────────────────── one-shot (non-TUI) mode ──────────────────────────

/// Poll the fleet once, print a plain-text (or JSON) report, and return a
/// process exit code: 0 when the network is healthy (all targets online, in
/// height agreement, fingerprints match, no fork), else 1. Handy as a cron /
/// CI health gate, and a quick "is the testnet up?" without the full TUI.
pub fn run_once(targets: &[FleetTarget], timeout: Duration, json: bool) -> i32 {
    let nodes = poll_fleet(targets, timeout);
    let s = FleetSummary::derive(&nodes);
    let healthy = s.online == s.total
        && s.online > 0
        && s.in_agreement
        && s.fingerprints_match
        && !s.fork_suspected;

    if json {
        let arr: Vec<serde_json::Value> = targets
            .iter()
            .zip(nodes.iter())
            .map(|(t, n)| {
                serde_json::json!({
                    "label": t.label, "url": t.url, "online": n.online,
                    "height": n.height, "tip_hash": n.tip_hash,
                    "tip_age_secs": n.tip_age_secs, "synced": n.synced,
                    "peers": n.peer_count, "inbound_peers": n.inbound_peers,
                    "mempool": n.mempool, "difficulty": n.difficulty,
                    "total_difficulty": n.total_difficulty, "health": n.health_score,
                    "mesh_degraded": n.mesh_degraded, "fingerprint": n.fingerprint,
                    "version": n.version, "status": n.status, "rtt_ms": n.rtt_ms,
                })
            })
            .collect();
        let out = serde_json::json!({
            "healthy": healthy,
            "network": s.network,
            "online": s.online, "total": s.total,
            "min_height": s.min_height, "max_height": s.max_height,
            "height_spread": s.height_spread, "in_agreement": s.in_agreement,
            "fingerprints_match": s.fingerprints_match, "fingerprint": s.fingerprint,
            "fork_suspected": s.fork_suspected, "worst_tip_age_secs": s.worst_tip_age,
            "anonymity_set": s.anonymity_set, "mempool_total": s.mempool_total,
            "nodes": arr,
        });
        println!("{}", serde_json::to_string_pretty(&out).unwrap_or_default());
    } else {
        let net = if s.network.is_empty() { "fleet".into() } else { s.network.to_uppercase() };
        println!(
            "CoinCync {net}: {}/{} online · tip {} · Δ{} · {} · {} · worst tip-age {} · anon {} · mempool {}",
            s.online, s.total,
            if s.online > 0 { s.max_height.to_string() } else { "—".into() },
            s.height_spread,
            if s.in_agreement { "in agreement" } else { "HEIGHTS SPLIT" },
            if s.fork_suspected {
                "FORK SUSPECTED"
            } else if !s.fingerprints_match {
                "FP MISMATCH"
            } else {
                "fp ok, no fork"
            },
            fmt_age(s.worst_tip_age),
            s.anonymity_set, s.mempool_total,
        );
        for (t, n) in targets.iter().zip(nodes.iter()) {
            if n.online {
                println!(
                    "  {:<14} h={:<8} age={:<5} peers={}({}) mem={} health={:.2} sync={} mesh={} fp={} {} {}ms",
                    t.label, n.height, fmt_age(n.tip_age_secs), n.peer_count, n.inbound_peers,
                    n.mempool, n.health_score,
                    if n.synced { "y" } else { "n" },
                    if n.mesh_degraded { "DEGR" } else { "ok" },
                    if n.fingerprint.is_empty() { "—" } else { &n.fingerprint },
                    n.version,
                    n.rtt_ms,
                );
            } else {
                println!("  {:<14} OFFLINE (unreachable, {}ms)", t.label, n.rtt_ms);
            }
        }
        println!("verdict: {}", if healthy { "HEALTHY" } else { "ATTENTION NEEDED" });
    }
    if healthy { 0 } else { 1 }
}

// ───────────────────────────── rendering ──────────────────────────────────

fn fmt_age(secs: u64) -> String {
    if secs == 0 {
        "—".into()
    } else if secs < 90 {
        format!("{secs}s")
    } else if secs < 5400 {
        format!("{}m", secs / 60)
    } else {
        format!("{}h", secs / 3600)
    }
}

/// Group a decimal difficulty string with thousands separators (best-effort;
/// non-numeric strings pass through).
fn group_num(s: &str) -> String {
    if s.is_empty() || !s.bytes().all(|b| b.is_ascii_digit()) {
        return if s.is_empty() { "?".into() } else { s.to_string() };
    }
    let bytes = s.as_bytes();
    let mut out = String::with_capacity(s.len() + s.len() / 3);
    let first = bytes.len() % 3;
    for (i, &b) in bytes.iter().enumerate() {
        if i != 0 && (i - first) % 3 == 0 && !(i == 0) {
            out.push(',');
        }
        out.push(b as char);
    }
    out
}

/// Draw the whole fleet view into `f`.
pub fn draw_fleet(f: &mut Frame, app: &FleetApp) {
    let th = &app.theme;
    let area = f.area();
    let rows = Layout::vertical([
        Constraint::Length(4), // summary band
        Constraint::Min(5),    // node table
        Constraint::Length(1), // footer
    ])
    .split(area);

    draw_summary(f, rows[0], app);
    draw_table(f, rows[1], app);

    let footer = Line::from(vec![
        Span::styled(" q", bold(th.c("main_fg"))),
        Span::styled(" quit  ", dim(th)),
        Span::styled("space", bold(th.c("main_fg"))),
        Span::styled(
            if app.paused { " resume  " } else { " pause  " },
            dim(th),
        ),
        Span::styled("r", bold(th.c("main_fg"))),
        Span::styled(" refresh now", dim(th)),
    ]);
    f.render_widget(Paragraph::new(footer), rows[2]);
}

fn draw_summary(f: &mut Frame, area: Rect, app: &FleetApp) {
    let th = &app.theme;
    let s = &app.summary;
    let net = if s.network.is_empty() {
        "fleet".to_string()
    } else {
        s.network.to_uppercase()
    };

    let ok = th.g("free", 80.0);
    let warn = th.g("available", 55.0);
    let bad = th.g("used", 100.0);

    let online_c = if s.online == s.total {
        ok
    } else if s.online == 0 {
        bad
    } else {
        warn
    };

    // Line 1: network + online count + the headline height.
    let l1 = Line::from(vec![
        Span::styled(format!("CoinCync {net} fleet"), bold(th.c("main_fg"))),
        Span::styled("   nodes ", dim(th)),
        Span::styled(format!("{}/{}", s.online, s.total), bold(online_c)),
        Span::styled("   tip ", dim(th)),
        Span::styled(
            if s.online > 0 { s.max_height.to_string() } else { "—".into() },
            bold(th.c("main_fg")),
        ),
        Span::styled("   paused: ", dim(th)),
        Span::styled(
            if app.paused { "yes" } else { "no" },
            if app.paused { bold(warn) } else { dim(th) },
        ),
    ]);

    // Line 2: the three network verdicts — agreement, fork, fingerprint.
    let (agree_txt, agree_c) = if s.online == 0 {
        ("no nodes online".to_string(), bad)
    } else if s.in_agreement {
        (format!("✓ in agreement (Δ{})", s.height_spread), ok)
    } else {
        (format!("⚠ heights split Δ{}", s.height_spread), warn)
    };
    let (fork_txt, fork_c) = if s.fork_suspected {
        ("⛔ FORK suspected", bad)
    } else {
        ("✓ no fork", ok)
    };
    let (fp_txt, fp_c) = if s.fingerprint.is_empty() {
        ("fp —".to_string(), dim_color(th))
    } else if s.fingerprints_match {
        (format!("✓ fp {}", s.fingerprint), ok)
    } else {
        (format!("⛔ fp MISMATCH ({}…)", s.fingerprint), bad)
    };
    let l2 = Line::from(vec![
        Span::styled(agree_txt, bold(agree_c)),
        Span::raw("   "),
        Span::styled(fork_txt, bold(fork_c)),
        Span::raw("   "),
        Span::styled(fp_txt, bold(fp_c)),
        Span::styled("   worst tip-age ", dim(th)),
        Span::styled(fmt_age(s.worst_tip_age), {
            let c = if s.worst_tip_age > 600 { warn } else { th.c("main_fg") };
            Style::default().fg(c)
        }),
        Span::styled("   anon-set ", dim(th)),
        Span::styled(group_num(&s.anonymity_set.to_string()), Style::default().fg(th.c("main_fg"))),
        Span::styled("   mempool ", dim(th)),
        Span::styled(
            s.mempool_total.to_string(),
            Style::default().fg(if s.mempool_total > 0 { warn } else { dim_color(th) }),
        ),
    ]);

    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(th.c("inactive_fg")))
        .padding(Padding::horizontal(1))
        .title(Span::styled(" testnet overview ", bold(th.c("main_fg"))));
    f.render_widget(
        Paragraph::new(vec![l1, l2]).block(block),
        area,
    );
}

fn draw_table(f: &mut Frame, area: Rect, app: &FleetApp) {
    let th = &app.theme;
    let ok = th.g("free", 80.0);
    let warn = th.g("available", 55.0);
    let bad = th.g("used", 100.0);

    let header = Row::new(
        [
            "", "NODE", "HEIGHT", "Δ", "TIP-AGE", "PEERS", "MEM", "DIFF", "HEALTH", "SYNC",
            "MESH", "FP", "VER", "RTT", "HEIGHT TREND",
        ]
        .into_iter()
        .map(|h| Cell::from(h).style(bold(th.c("main_fg")))),
    )
    .height(1);

    let max_h = app.summary.max_height;
    let mut rows: Vec<Row> = Vec::with_capacity(app.nodes.len());
    for (i, n) in app.nodes.iter().enumerate() {
        let label = app
            .targets
            .get(i)
            .map(|t| t.label.clone())
            .unwrap_or_else(|| format!("n{}", i + 1));

        if !n.online {
            rows.push(Row::new(vec![
                Cell::from("●").style(Style::default().fg(bad)),
                Cell::from(label),
                Cell::from("offline").style(Style::default().fg(bad)), // HEIGHT
                Cell::from("—"),                                       // Δ
                Cell::from("—"),                                       // TIP-AGE
                Cell::from("—"),                                       // PEERS
                Cell::from("—"),                                       // MEM
                Cell::from("—"),                                       // DIFF
                Cell::from("—"),                                       // HEALTH
                Cell::from("—"),                                       // SYNC
                Cell::from("—"),                                       // MESH
                Cell::from("—"),                                       // FP
                Cell::from("—"),                                       // VER
                Cell::from(format!("{}ms", n.rtt_ms)).style(dim(th)),  // RTT
                Cell::from("unreachable").style(dim(th)),              // TREND
            ]));
            continue;
        }

        let lag = max_h.saturating_sub(n.height);
        // "behind its own view": the node itself believes the network is higher
        // than its tip (still catching up), independent of the fleet max.
        let behind_own = n.target_height > n.height;
        // status strings other than healthy/empty (e.g. "degraded", "syncing").
        let status_bad = !n.status.is_empty() && n.status != "healthy";
        // Status dot: green = synced & caught up & healthy; red = fp mismatch or
        // fork; yellow = lagging / unsynced / mesh degraded / unhealthy status.
        let fp_bad = !app.summary.fingerprints_match
            && !n.fingerprint.is_empty()
            && n.fingerprint != app.summary.fingerprint;
        let dot_c = if fp_bad || app.summary.fork_suspected {
            bad
        } else if !n.synced
            || behind_own
            || lag > AGREE_TOLERANCE
            || n.mesh_degraded
            || status_bad
        {
            warn
        } else {
            ok
        };

        let lag_cell = if lag == 0 {
            Cell::from("0").style(dim(th))
        } else {
            Cell::from(format!("-{lag}")).style(Style::default().fg(if lag > AGREE_TOLERANCE {
                warn
            } else {
                th.c("main_fg")
            }))
        };

        let age_c = if n.tip_age_secs > 600 { warn } else { th.c("main_fg") };
        let health_c = if n.health_score >= 0.99 {
            ok
        } else if n.health_score >= 0.5 {
            warn
        } else {
            bad
        };
        let sync_cell = if n.synced {
            Cell::from("✓").style(Style::default().fg(ok))
        } else {
            Cell::from("sync").style(Style::default().fg(warn))
        };
        let mesh_cell = if n.mesh_degraded {
            Cell::from("degr").style(Style::default().fg(bad))
        } else {
            Cell::from("ok").style(Style::default().fg(ok))
        };
        let fp_cell = {
            let c = if fp_bad { bad } else { dim_color(th) };
            Cell::from(if n.fingerprint.is_empty() {
                "—".into()
            } else {
                n.fingerprint.clone()
            })
            .style(Style::default().fg(c))
        };

        rows.push(Row::new(vec![
            Cell::from("●").style(Style::default().fg(dot_c)),
            Cell::from(label).style(bold(th.c("main_fg"))),
            Cell::from(n.height.to_string()).style(bold(th.c("main_fg"))),
            lag_cell,
            Cell::from(fmt_age(n.tip_age_secs)).style(Style::default().fg(age_c)),
            Cell::from(format!("{}({})", n.peer_count, n.inbound_peers)),
            Cell::from(n.mempool.to_string())
                .style(Style::default().fg(if n.mempool > 0 { warn } else { dim_color(th) })),
            Cell::from(group_num(&n.difficulty)),
            Cell::from(format!("{:.2}", n.health_score)).style(Style::default().fg(health_c)),
            sync_cell,
            mesh_cell,
            fp_cell,
            Cell::from(if n.version.is_empty() { "—".into() } else { n.version.clone() })
                .style(dim(th)),
            Cell::from(format!("{}ms", n.rtt_ms)).style(dim(th)),
            // placeholder; the sparkline is drawn as an overlay below.
            Cell::from(""),
        ]));
    }

    let widths = [
        Constraint::Length(1),  // dot
        Constraint::Length(10), // node
        Constraint::Length(8),  // height
        Constraint::Length(5),  // Δ
        Constraint::Length(7),  // tip-age
        Constraint::Length(8),  // peers(in)
        Constraint::Length(5),  // mem
        Constraint::Length(11), // diff
        Constraint::Length(6),  // health
        Constraint::Length(5),  // sync
        Constraint::Length(5),  // mesh
        Constraint::Length(9),  // fp
        Constraint::Length(7),  // ver
        Constraint::Length(7),  // rtt
        Constraint::Min(12),    // height trend sparkline
    ];

    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(th.c("inactive_fg")))
        .title(Span::styled(" nodes ", bold(th.c("main_fg"))));
    let inner = block.inner(area);
    f.render_widget(block, area);

    let table = Table::new(rows, widths)
        .header(header)
        .column_spacing(1)
        .row_highlight_style(Style::default().add_modifier(Modifier::REVERSED));
    f.render_widget(table, inner);

    // Overlay a per-node height sparkline in the last column. The table reserves
    // the space; we compute each data row's rect and draw into the trend column.
    let trend_x = inner.x
        + widths
            .iter()
            .take(widths.len() - 1)
            .map(|c| match c {
                Constraint::Length(l) => *l,
                _ => 0,
            })
            .sum::<u16>()
        + widths.len() as u16; // column_spacing(1) between 14 columns
    if trend_x < inner.x + inner.width {
        let trend_w = inner.x + inner.width - trend_x;
        // header occupies inner.y; data rows start at inner.y + 1.
        for (i, h) in app.hist.iter().enumerate() {
            let ry = inner.y + 1 + i as u16;
            if ry >= inner.y + inner.height {
                break;
            }
            if !app.nodes.get(i).map(|n| n.online).unwrap_or(false) {
                continue;
            }
            let data: Vec<u64> = h.iter().copied().collect();
            // Normalize against this node's own range so a flat-but-advancing
            // chain still shows motion.
            let spark = Sparkline::default()
                .data(&data)
                .style(Style::default().fg(th.g("available", 60.0)));
            let rect = Rect {
                x: trend_x,
                y: ry,
                width: trend_w,
                height: 1,
            };
            f.render_widget(spark, rect);
        }
    }
}

fn bold(c: Color) -> Style {
    Style::default().fg(c).add_modifier(Modifier::BOLD)
}
fn dim(th: &Theme) -> Style {
    Style::default().fg(th.c("inactive_fg"))
}
fn dim_color(th: &Theme) -> Color {
    th.c("inactive_fg")
}
