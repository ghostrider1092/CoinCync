//! Presentation toolkit — reusable, theme-driven primitives shared by every
//! panel: boxes with btop-style notch tabs, `■` gradient meters, braille area
//! graphs, value formatters, and the node-log line parser.

use std::collections::VecDeque;

use ratatui::{
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, BorderType, Borders},
};

use crate::collect::FeedLine;
use crate::theme::Theme;

/// Brand cyan — the ◈ glyph colour used across CoinCync (not themed).
pub const BRAND: Color = Color::Rgb(0x3a, 0xd1, 0xd1);

// ─── boxes ──────────────────────────────────────────────────────────────────

pub fn superscript(n: u32) -> String {
    const S: [char; 10] = ['⁰', '¹', '²', '³', '⁴', '⁵', '⁶', '⁷', '⁸', '⁹'];
    n.to_string().chars().filter_map(|c| c.to_digit(10)).map(|d| S[d as usize]).collect()
}

/// A btop-style panel: rounded corners in the panel's box colour, a red
/// (hi_fg) superscript index + white (title) name tab, and optional right tab.
pub fn bpanel(theme: &Theme, idx: u32, title: &str, tabs: &str, box_role: &str) -> Block<'static> {
    let box_color = theme.c(box_role);
    // Wrap a title in btop's notch glyphs: ─┐ … ┌ (box colour), the ┐/┌ notching
    // the label down into the top border line.
    let notch = |inner: Vec<Span<'static>>| {
        let mut v = vec![
            Span::styled("─┐", Style::default().fg(box_color)),
        ];
        v.extend(inner);
        v.push(Span::styled("┌", Style::default().fg(box_color)));
        v
    };
    let mut b = Block::default()
        .borders(Borders::ALL)
        .border_type(BorderType::Rounded)
        .border_style(Style::default().fg(box_color))
        .title(Line::from(notch(vec![
            Span::styled(superscript(idx), Style::default().fg(theme.c("hi_fg")).add_modifier(Modifier::BOLD)),
            Span::styled(title.to_string(), Style::default().fg(theme.c("title")).add_modifier(Modifier::BOLD)),
        ])));
    if !tabs.is_empty() {
        b = b.title(
            Line::from(notch(vec![Span::styled(tabs.to_string(), Style::default().fg(theme.c("title")))]))
                .right_aligned(),
        );
    }
    b
}

// ─── meters ─────────────────────────────────────────────────────────────────

/// `width` cells of `■`: filled cells follow gradient `grad` (start→value),
/// empty cells are grey (meter_bg).
pub fn meter_spans(theme: &Theme, grad: &str, pct: f64, width: usize) -> Vec<Span<'static>> {
    let pct = pct.clamp(0.0, 100.0);
    let filled = ((pct / 100.0) * width as f64).round() as usize;
    (0..width)
        .map(|i| {
            if i < filled {
                let frac = if width > 1 { i as f64 / (width - 1) as f64 } else { 0.0 };
                Span::styled("■", Style::default().fg(theme.g(grad, frac * 100.0)))
            } else {
                Span::styled("■", Style::default().fg(theme.c("meter_bg")))
            }
        })
        .collect()
}

/// `label  NN% ■■■■■■  value`.
pub fn meter_line(theme: &Theme, label: &str, grad: &str, pct: f64, value: &str, bar_w: usize) -> Line<'static> {
    let mut spans = vec![
        Span::styled(format!("{label:<8}"), Style::default().fg(theme.c("inactive_fg"))),
        Span::styled(format!("{pct:>3.0}% "), Style::default().fg(theme.c("main_fg"))),
    ];
    spans.extend(meter_spans(theme, grad, pct, bar_w));
    spans.push(Span::styled(format!("  {value}"), Style::default().fg(theme.c("main_fg"))));
    Line::from(spans)
}

// ─── braille area graph ───────────────────────────────────────────────────────

const BRAILLE_DOTS: [[u8; 4]; 2] = [[0x01, 0x02, 0x04, 0x40], [0x08, 0x10, 0x20, 0x80]];

/// Filled braille area graph: `rows` lines × `cols` chars, newest on the right.
pub fn braille_graph(data: &[u64], max: u64, cols: usize, rows: usize) -> Vec<String> {
    if cols == 0 || rows == 0 {
        return vec![];
    }
    let dot_w = cols * 2;
    let dot_h = rows * 4;
    let maxv = max.max(1) as f64;
    let n = data.len();
    let mut heights = vec![0usize; dot_w];
    for i in 0..dot_w.min(n) {
        let v = data[n - 1 - i] as f64;
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
        .map(|row| row.iter().map(|&b| char::from_u32(0x2800 + b as u32).unwrap_or(' ')).collect())
        .collect()
}

pub fn slice(q: &VecDeque<u64>) -> Vec<u64> {
    q.iter().copied().collect()
}

// ─── formatters ───────────────────────────────────────────────────────────────

pub fn human_bytes(b: u64) -> String {
    const U: [&str; 5] = ["B", "KiB", "MiB", "GiB", "TiB"];
    let mut v = b as f64;
    let mut i = 0;
    while v >= 1024.0 && i < U.len() - 1 {
        v /= 1024.0;
        i += 1;
    }
    format!("{v:.1} {}", U[i])
}

pub fn human_hashrate(h: f64) -> String {
    if h >= 1_000_000.0 {
        format!("{:.2} MH/s", h / 1e6)
    } else if h >= 1_000.0 {
        format!("{:.2} kH/s", h / 1e3)
    } else {
        format!("{h:.0} H/s")
    }
}

pub fn human_dur(secs: f64) -> String {
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

pub fn clock_hms() -> String {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let d = secs % 86_400;
    format!("{:02}:{:02}:{:02}", d / 3600, (d % 3600) / 60, d % 60)
}

pub fn short_hash(h: &str) -> String {
    if h.len() <= 14 {
        if h.is_empty() { "…".into() } else { h.to_string() }
    } else {
        format!("{}…{}", &h[..8], &h[h.len() - 4..])
    }
}

pub fn truncate(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        s.to_string()
    } else {
        s.chars().take(max.saturating_sub(1)).collect::<String>() + "…"
    }
}

// ─── node-log parsing + icons ────────────────────────────────────────────────

fn looks_like_level(s: &str) -> bool {
    matches!(s, "ERROR" | "ERRO" | "WARN" | "WARNING" | "INFO" | "DEBUG" | "TRACE")
}

/// A single-width category icon (+ colour) for a feed line.
pub fn icon_for(theme: &Theme, level: &str, module: &str, msg: &str) -> (&'static str, Color) {
    match level {
        "ERROR" | "ERRO" => return ("✖", theme.g("used", 100.0)),
        "WARN" | "WARNING" => return ("⚑", theme.g("available", 70.0)),
        _ => {}
    }
    let green = theme.g("free", 80.0);
    let gold = theme.g("available", 70.0);
    let purple = theme.c("net_box");
    if msg.contains("BLOCK_COMMIT") {
        ("⬢", green)
    } else if module.contains("miner") || msg.contains("Accepted") {
        ("✦", gold)
    } else if module.contains("heartbeat") {
        ("♥", theme.c("inactive_fg"))
    } else if module.contains("dispatch") {
        ("⇣", BRAND)
    } else if module.contains("sync_driver") || msg.contains("[IBD]") {
        ("⇅", gold)
    } else if module.contains("peer_manager") || module.contains("connection") || msg.contains("handshake") || msg.contains("peer") {
        ("●", BRAND)
    } else if module.contains("randomx") || module.contains("pow") {
        ("◆", purple)
    } else if module.contains("rpc") || module.contains("rest") || module.contains("metrics") {
        ("⚙", theme.c("inactive_fg"))
    } else if module.contains("dandelion") {
        ("⟐", purple)
    } else {
        ("▸", theme.c("inactive_fg"))
    }
}

/// Parse one tracing-fmt node log line into coloured feed spans.
pub fn parse_log_line(theme: &Theme, line: &str) -> FeedLine {
    let t: Vec<&str> = line.split_whitespace().collect();
    if t.len() < 3 || !looks_like_level(t[2]) {
        return FeedLine {
            spans: vec![("▸ ".to_string(), theme.c("inactive_fg")), (line.trim_end().to_string(), theme.c("main_fg"))],
        };
    }
    let time = t[1];
    let level = t[2];
    let mut i = 3;
    if t.get(i).map(|s| !s.chars().any(|c| c.is_ascii_alphanumeric())).unwrap_or(false) {
        i += 1;
    }
    let module = t.get(i).copied().unwrap_or("");
    let msg = t.get(i + 1..).map(|r| r.join(" ")).unwrap_or_default();

    let level_color = match level {
        "ERROR" | "ERRO" => theme.g("used", 100.0),
        "WARN" | "WARNING" => theme.g("available", 70.0),
        "INFO" => theme.c("proc_misc"),
        "DEBUG" => theme.c("net_box"),
        _ => theme.c("inactive_fg"),
    };
    let msg_color = if msg.contains("BLOCK_COMMIT") || msg.contains("Accepted") {
        theme.g("free", 80.0)
    } else if level == "WARN" || level == "WARNING" {
        theme.g("available", 70.0)
    } else if level == "ERROR" || level == "ERRO" {
        theme.g("used", 100.0)
    } else if msg.contains("[IBD]") {
        theme.g("available", 60.0)
    } else {
        theme.c("main_fg")
    };

    let (icon, icon_color) = icon_for(theme, level, module, &msg);
    FeedLine {
        spans: vec![
            (format!("{icon} "), icon_color),
            (format!("{time} "), theme.c("inactive_fg")),
            (format!("{level:<5} "), level_color),
            (format!("{module}  "), BRAND),
            (msg, msg_color),
        ],
    }
}
