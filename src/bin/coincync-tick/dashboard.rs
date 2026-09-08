//! glances-style TUI for coincync-tick (`--dashboard`). The CALM view is driven
//! by REAL adapter + colony Act data each round (see `apply_real`); the 1/2/3
//! keys layer clearly-badged SIMULATED scenarios on top (illustrative designed
//! responses, never a peer's real-time defensive posture — colony README §web
//! console). Advisory, non-consensus, dry-run: nothing here is sent anywhere.
//!
//! Ported from the standalone `colony-dashboard` demo crate; the render layer is
//! unchanged (ratatui 0.30, same API the coincync-rig TUI uses).

use std::collections::VecDeque;

use coincync::colony::act::ActReport;
use ratatui::{
    layout::{Alignment, Constraint, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Gauge, List, ListItem, Paragraph, Sparkline},
    Frame,
};

// ─── model ─────────────────────────────────────────────────────────────────

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Grp {
    Sense,
    Defend,
    Relay,
    Hide,
}

impl Grp {
    fn label(self) -> &'static str {
        match self {
            Grp::Sense => "SENSING",
            Grp::Defend => "DEFENSE",
            Grp::Relay => "RELAY",
            Grp::Hide => "CAMOUFLAGE",
        }
    }
    const ALL: [Grp; 4] = [Grp::Sense, Grp::Defend, Grp::Relay, Grp::Hide];
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Status {
    Live,
    Core,
    Infra,
}

impl Status {
    fn tag(self) -> &'static str {
        match self {
            Status::Live => "observe·live",
            Status::Core => "pure core",
            Status::Infra => "infra",
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    Calm,
    Partition,
    Flood,
    Eclipse,
}

impl Mode {
    fn is_sim(self) -> bool {
        self != Mode::Calm
    }
    fn label(self) -> &'static str {
        match self {
            Mode::Calm => "calm · this node",
            Mode::Partition => "partition",
            Mode::Flood => "flood",
            Mode::Eclipse => "eclipse",
        }
    }
}

pub struct Caste {
    id: &'static str,
    grp: Grp,
    status: Status,
    micro: String,
    responding: bool,
}

pub struct LedgerRow {
    ts: String,
    action: String,
    denied: bool,
}

pub struct Snapshot {
    node: String,
    armed: bool,
    tick: u64,
    uptime_s: u64,
    ram_pct: u16,
    swap_pct: u16,
    mempool: u32,
    peers: u32,
    relay_mode: &'static str,
    next_housekeeping_s: u32,
    envelope_b: u32,
    allowed: u64,
    denied: u64,
    mode: Mode,
    castes: Vec<Caste>,
    ledger: VecDeque<LedgerRow>,
    allowed_hist: VecDeque<u64>,
    ci: usize,
}

// Prime-varied housekeeping intervals (only used to animate the sim modes).
const CICADA: [u32; 8] = [169, 221, 247, 300, 378, 404, 482, 534];

fn caste(id: &'static str, grp: Grp, status: Status) -> Caste {
    Caste {
        id,
        grp,
        status,
        micro: String::new(),
        responding: false,
    }
}

impl Snapshot {
    pub fn new(node: &str, armed: bool) -> Self {
        let castes = vec![
            caste("forager", Grp::Sense, Status::Live),
            caste("sensor", Grp::Sense, Status::Live),
            caste("pheromone", Grp::Sense, Status::Infra),
            caste("spider", Grp::Sense, Status::Core),
            caste("mantis", Grp::Defend, Status::Core),
            caste("army_ant", Grp::Defend, Status::Core),
            caste("centipede", Grp::Relay, Status::Core),
            caste("locust", Grp::Relay, Status::Core),
            caste("cicada", Grp::Hide, Status::Core),
            caste("firefly", Grp::Hide, Status::Core),
            caste("stick_insect", Grp::Hide, Status::Core),
        ];
        let mut s = Snapshot {
            node: node.to_string(),
            armed,
            tick: 0,
            uptime_s: 0,
            ram_pct: 0,
            swap_pct: 0,
            mempool: 0,
            peers: 0,
            relay_mode: "Solitary",
            next_housekeeping_s: CICADA[0],
            envelope_b: 2048,
            allowed: 0,
            denied: 0,
            mode: Mode::Calm,
            castes,
            ledger: VecDeque::new(),
            allowed_hist: VecDeque::new(),
            ci: 0,
        };
        s.refresh_micro();
        s
    }

    pub fn set_mode(&mut self, m: Mode) {
        self.mode = m;
    }
    pub fn mode_is_sim(&self) -> bool {
        self.mode.is_sim()
    }

    fn responders(&self) -> &'static [&'static str] {
        match self.mode {
            Mode::Calm => &["cicada", "stick_insect"],
            Mode::Partition => &["spider", "army_ant", "locust", "centipede"],
            Mode::Flood => &["spider", "mantis", "locust", "firefly"],
            Mode::Eclipse => &["spider", "forager", "army_ant", "pheromone"],
        }
    }

    fn caption(&self) -> &'static str {
        match self.mode {
            Mode::Calm => "observe · dry-run — castes log what they WOULD do; nothing sent to node or network",
            Mode::Partition => "SIM: spider flags the split; army_ant re-spans it with netgroup-diverse peers; locust swarm-relays",
            Mode::Flood => "SIM: spider reads the surge; mantis tarpits sources on an escalating hold; locust rides it out (hysteresis)",
            Mode::Eclipse => "SIM: spider spots netgroup concentration; forager re-scores; army_ant restores diversity",
        }
    }

    fn refresh_micro(&mut self) {
        let mode = self.mode;
        let peers = self.peers;
        let relay = self.relay_mode;
        let hk = self.next_housekeeping_s;
        let tick = self.tick;
        let resp = self.responders();
        for c in &mut self.castes {
            c.responding = resp.contains(&c.id);
            c.micro = match c.id {
                "cicada" => format!("next housekeeping {}s", hk),
                "stick_insect" => "envelope 2048B  UA /coincync/".into(),
                "locust" => {
                    let density = if mode == Mode::Calm { 0 } else { (20 + tick % 70) as u32 };
                    format!("{}  density {}%", relay, density)
                }
                "forager" => match mode {
                    Mode::Calm if peers == 0 => "0 peers scored".into(),
                    Mode::Calm => format!("scored {} peer(s)", peers),
                    _ => format!("re-scoring {} peers", peers),
                },
                "sensor" => match mode {
                    Mode::Calm => "personal · no fleet aggregate".into(),
                    Mode::Partition => "state DIVERGENT".into(),
                    Mode::Flood => "state STRESSED".into(),
                    Mode::Eclipse => "state CONCENTRATED".into(),
                },
                "spider" => if mode == Mode::Calm { "standing by".into() }
                            else { format!("signature {}", mode.label().to_uppercase()) },
                "mantis" => if mode == Mode::Flood { "tarpit hold x5 (escalating)".into() }
                            else { "armed · no malice feed".into() },
                "army_ant" => if matches!(mode, Mode::Partition | Mode::Eclipse) { "bridging 3 diverse legs".into() }
                              else { "armed".into() },
                "centipede" => if mode == Mode::Partition { "relay 3 diverse legs".into() }
                               else { "legs standby".into() },
                "firefly" => "cover cap armed · needs pulse feed".into(),
                "pheromone" => "trail evaporating each round".into(),
                _ => String::new(),
            };
        }
    }

    /// CALM view fed by REAL adapter + Act data. `report` supplies the ledger
    /// rows (WOULD/DENIED) exactly as the log path emits them.
    pub fn apply_real(
        &mut self,
        v: &crate::RoundVitals,
        report: &ActReport,
        uptime_s: u64,
        hms: &str,
    ) {
        self.mode = Mode::Calm;
        self.tick += 1;
        self.uptime_s = uptime_s;
        self.ram_pct = v.ram_pct;
        self.swap_pct = v.swap_pct;
        self.mempool = v.mempool;
        self.peers = v.peers_scored;
        self.relay_mode = v.relay_mode;
        self.next_housekeeping_s = v.next_housekeeping_s;

        let mut allowed_this = 0u64;
        for a in &report.allowed {
            self.allowed += 1;
            allowed_this += 1;
            self.ledger.push_front(LedgerRow { ts: hms.into(), action: a.clone(), denied: false });
        }
        for (a, _reason) in &report.denied {
            self.denied += 1;
            self.ledger.push_front(LedgerRow { ts: hms.into(), action: a.clone(), denied: true });
        }
        while self.ledger.len() > 200 {
            self.ledger.pop_back();
        }
        self.allowed_hist.push_back(allowed_this);
        while self.allowed_hist.len() > 60 {
            self.allowed_hist.pop_front();
        }
        self.refresh_micro();
    }

    /// Animate a SIMULATED scenario (1/2/3). Illustrative only.
    pub fn simulate(&mut self, clock_hms: String) {
        self.tick += 1;
        self.uptime_s += 5;
        self.ci = (self.ci + 1) % CICADA.len();
        self.next_housekeeping_s = CICADA[self.ci];

        self.ram_pct = if self.mode == Mode::Calm { 0 } else { (8 + (self.tick * 7) % 60) as u16 };
        self.mempool = match self.mode {
            Mode::Flood => ((40 + self.tick * 13) % 400) as u32,
            Mode::Calm => 0,
            _ => ((self.tick * 3) % 30) as u32,
        };
        self.peers = match self.mode {
            Mode::Calm => 0,
            Mode::Partition => 14,
            Mode::Flood => 16,
            Mode::Eclipse => 12,
        };
        self.relay_mode = if matches!(self.mode, Mode::Flood | Mode::Partition) { "Gregarious" } else { "Solitary" };

        let mut rows: Vec<(String, bool)> =
            vec![(format!("housekeep in {}s", self.next_housekeeping_s), false)];
        if self.tick % 3 == 0 {
            rows.push((format!("relay mode {}", self.relay_mode), false));
        } else {
            rows.push(("relay mode Solitary".into(), true));
        }
        if self.tick % 5 == 0 {
            rows.push(("cover-traffic pulse".into(), false));
        }
        rows.push(("assert canonical wire profile".into(), false));
        if self.mode == Mode::Flood {
            rows.push(("tarpit hold -> 3 peers".into(), false));
        }
        if self.mode == Mode::Partition {
            rows.push(("bridge 3 netgroup-diverse peers".into(), false));
        }

        let mut allowed_this = 0u64;
        for (a, d) in rows {
            if d {
                self.denied += 1;
            } else {
                self.allowed += 1;
                allowed_this += 1;
            }
            self.ledger.push_front(LedgerRow { ts: clock_hms.clone(), action: a, denied: d });
        }
        while self.ledger.len() > 200 {
            self.ledger.pop_back();
        }
        self.allowed_hist.push_back(allowed_this);
        while self.allowed_hist.len() > 60 {
            self.allowed_hist.pop_front();
        }
        self.refresh_micro();
    }
}

// ─── render ────────────────────────────────────────────────────────────────

const AMBER: Color = Color::Rgb(224, 172, 71);
const AMBER_DIM: Color = Color::Rgb(150, 118, 54);
const SAGE: Color = Color::Rgb(130, 177, 138);
const TEAL: Color = Color::Rgb(116, 167, 174);
const RUST: Color = Color::Rgb(205, 109, 73);
const INK_LINE: Color = Color::Rgb(40, 76, 69);
const PARCH: Color = Color::Rgb(236, 227, 207);
const MUTED: Color = Color::Rgb(139, 160, 149);
const DIM2: Color = Color::Rgb(90, 105, 98);

fn status_color(s: Status) -> Color {
    match s {
        Status::Live => SAGE,
        Status::Core => TEAL,
        Status::Infra => MUTED,
    }
}

pub fn draw(f: &mut Frame, s: &Snapshot) {
    let root = Layout::vertical([
        Constraint::Length(3),
        Constraint::Min(0),
        Constraint::Length(1),
    ])
    .split(f.area());

    header(f, root[0], s);

    let cols = Layout::horizontal([
        Constraint::Length(32),
        Constraint::Min(30),
        Constraint::Length(46),
    ])
    .split(root[1]);

    vitals(f, cols[0], s);
    roster(f, cols[1], s);
    ledger(f, cols[2], s);
    footer(f, root[2], s);
}

fn pill<'a>(label: &'a str, val: &'a str, val_col: Color) -> Vec<Span<'a>> {
    vec![
        Span::styled(format!(" {label} "), Style::default().fg(MUTED)),
        Span::styled(format!("{val} "), Style::default().fg(val_col).add_modifier(Modifier::BOLD)),
        Span::styled("· ", Style::default().fg(INK_LINE)),
    ]
}

fn header(f: &mut Frame, area: Rect, s: &Snapshot) {
    let sim = s.mode.is_sim();
    let mut spans = vec![
        Span::styled(" ▲ ", Style::default().fg(AMBER).add_modifier(Modifier::BOLD)),
        Span::styled("The Colony", Style::default().fg(PARCH).add_modifier(Modifier::BOLD)),
        Span::styled("  coincync-tick   ", Style::default().fg(MUTED)),
    ];
    if sim {
        spans.extend(pill("view", "SIMULATED", RUST));
    } else {
        spans.extend(pill("node", &s.node, SAGE));
    }
    spans.extend(pill("castes", "observe", SAGE));
    spans.extend(pill("act", "dry-run", TEAL));
    if s.armed {
        spans.extend(pill("kill switch", "armed", AMBER));
    } else {
        spans.extend(pill("kill switch", "disarmed", MUTED));
    }

    let right = format!("tick {}   up {}m{:02}s ", s.tick, s.uptime_s / 60, s.uptime_s % 60);

    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(if sim { RUST } else { INK_LINE }));
    let inner = block.inner(area);
    f.render_widget(block, area);

    let cut = Layout::horizontal([Constraint::Min(0), Constraint::Length(right.len() as u16 + 1)]).split(inner);
    f.render_widget(Paragraph::new(Line::from(spans)), cut[0]);
    f.render_widget(
        Paragraph::new(Line::from(Span::styled(right, Style::default().fg(MUTED)))).alignment(Alignment::Right),
        cut[1],
    );
}

fn vitals(f: &mut Frame, area: Rect, s: &Snapshot) {
    let block = Block::default()
        .title(Span::styled(" THIS NODE ", Style::default().fg(AMBER_DIM)))
        .borders(Borders::ALL)
        .border_style(Style::default().fg(INK_LINE));
    let inner = block.inner(area);
    f.render_widget(block, area);

    let rows = Layout::vertical([
        Constraint::Length(1),
        Constraint::Length(1),
        Constraint::Length(1),
        Constraint::Min(0),
        Constraint::Length(4),
    ])
    .split(inner);

    let gstyle = |v: u16| Style::default().fg(if v > 75 { RUST } else if v > 45 { AMBER } else { SAGE });
    f.render_widget(
        Gauge::default().gauge_style(gstyle(s.ram_pct)).percent(s.ram_pct.min(100))
            .label(format!("RAM {:>3}%", s.ram_pct)).use_unicode(true),
        rows[0],
    );
    let mem_pct = ((s.mempool as f64 / 400.0) * 100.0).min(100.0) as u16;
    f.render_widget(
        Gauge::default().gauge_style(gstyle(mem_pct)).percent(mem_pct)
            .label(format!("mempool {} txs", s.mempool)).use_unicode(true),
        rows[1],
    );

    let kv = |k: &str, v: String, c: Color| {
        Line::from(vec![
            Span::styled(format!("{:<16}", k), Style::default().fg(MUTED)),
            Span::styled(v, Style::default().fg(c).add_modifier(Modifier::BOLD)),
        ])
    };
    let peers_c = if s.peers == 0 { MUTED } else { AMBER };
    let mode_c = if s.relay_mode == "Solitary" { SAGE } else { AMBER };
    let text = vec![
        kv("swap", format!("{}%", s.swap_pct), SAGE),
        kv("peers scored", s.peers.to_string(), peers_c),
        kv("relay mode", s.relay_mode.to_string(), mode_c),
        kv("next housekeep", format!("{}s", s.next_housekeeping_s), AMBER),
        kv("wire envelope", format!("{} B", s.envelope_b), PARCH),
        Line::from(""),
        Line::from(vec![
            Span::styled("allowed ", Style::default().fg(MUTED)),
            Span::styled(s.allowed.to_string(), Style::default().fg(SAGE).add_modifier(Modifier::BOLD)),
            Span::styled("  denied ", Style::default().fg(MUTED)),
            Span::styled(s.denied.to_string(), Style::default().fg(RUST).add_modifier(Modifier::BOLD)),
        ]),
    ];
    f.render_widget(Paragraph::new(text), rows[3]);

    let hist: Vec<u64> = s.allowed_hist.iter().copied().collect();
    let spark = Sparkline::default()
        .block(Block::default().title(Span::styled("actions/round", Style::default().fg(MUTED))))
        .data(&hist)
        .style(Style::default().fg(TEAL));
    f.render_widget(spark, rows[4]);
}

fn roster(f: &mut Frame, area: Rect, s: &Snapshot) {
    let block = Block::default()
        .title(Span::styled(" CASTES · 11 shipped ", Style::default().fg(AMBER_DIM)))
        .borders(Borders::ALL)
        .border_style(Style::default().fg(INK_LINE));
    let inner = block.inner(area);
    f.render_widget(block, area);

    let mut items: Vec<ListItem> = Vec::new();
    for g in Grp::ALL {
        items.push(ListItem::new(Line::from(Span::styled(
            format!("── {} ", g.label()),
            Style::default().fg(AMBER_DIM).add_modifier(Modifier::BOLD),
        ))));
        for c in s.castes.iter().filter(|c| c.grp == g) {
            let dim = s.mode.is_sim() && !c.responding;
            let name_style = if dim {
                Style::default().fg(MUTED)
            } else if c.responding && s.mode.is_sim() {
                Style::default().fg(AMBER).add_modifier(Modifier::BOLD)
            } else {
                Style::default().fg(PARCH).add_modifier(Modifier::BOLD)
            };
            let marker = if c.responding && s.mode.is_sim() { "▸ " } else { "  " };
            let line = Line::from(vec![
                Span::styled(marker, Style::default().fg(AMBER)),
                Span::styled(format!("{:<13}", c.id), name_style),
                Span::styled(format!("{:<13} ", c.status.tag()),
                    Style::default().fg(if dim { MUTED } else { status_color(c.status) })),
                Span::styled(c.micro.clone(), Style::default().fg(if dim { DIM2 } else { MUTED })),
            ]);
            items.push(ListItem::new(line));
        }
    }
    f.render_widget(List::new(items), inner);
}

fn ledger(f: &mut Frame, area: Rect, s: &Snapshot) {
    let block = Block::default()
        .title(Span::styled(" WOULD-DO LEDGER · authorized, logged only ", Style::default().fg(AMBER_DIM)))
        .borders(Borders::ALL)
        .border_style(Style::default().fg(INK_LINE));
    let inner = block.inner(area);
    f.render_widget(block, area);

    let rows: Vec<ListItem> = s.ledger.iter().take(inner.height as usize).map(|r| {
        let (tag, tag_col) = if r.denied { ("DENIED", RUST) } else { ("WOULD ", TEAL) };
        ListItem::new(Line::from(vec![
            Span::styled(format!("{} ", r.ts), Style::default().fg(DIM2)),
            Span::styled(format!("{} ", tag), Style::default().fg(tag_col).add_modifier(Modifier::BOLD)),
            Span::styled(r.action.clone(), Style::default().fg(if r.denied { MUTED } else { PARCH })),
        ]))
    }).collect();
    f.render_widget(List::new(rows), inner);
}

fn footer(f: &mut Frame, area: Rect, s: &Snapshot) {
    let sim = s.mode.is_sim();
    let msg = if sim {
        Span::styled(format!("  {}", s.caption()), Style::default().fg(RUST))
    } else {
        Span::styled("  advisory only · consensus unaffected · a colony bug degrades margin, never validity",
            Style::default().fg(SAGE))
    };
    let keys = Span::styled("0 calm  1 partition  2 flood  3 eclipse  ·  q quit ",
        Style::default().fg(MUTED));
    let cut = Layout::horizontal([Constraint::Min(0), Constraint::Length(48)]).split(area);
    f.render_widget(Paragraph::new(Line::from(msg)), cut[0]);
    f.render_widget(Paragraph::new(Line::from(keys)).alignment(Alignment::Right), cut[1]);
}
