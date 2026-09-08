//! btop-style render for the RandomX miner. `draw(frame, &Miner)` paints one frame.

use crate::miner::{Miner, ShareKind};
use ratatui::{
    layout::{Alignment, Constraint, Layout, Rect},
    style::{Color, Modifier, Style},
    symbols::Marker,
    text::{Line, Span},
    widgets::{Axis, Block, Borders, Chart, Dataset, GraphType, List, ListItem, Paragraph},
    Frame,
};

pub const AMBER: Color = Color::Rgb(224, 172, 71);
pub const AMBER_DIM: Color = Color::Rgb(150, 118, 54);
pub const SAGE: Color = Color::Rgb(130, 177, 138);
pub const TEAL: Color = Color::Rgb(116, 167, 174);
pub const RUST: Color = Color::Rgb(205, 109, 73);
pub const INK_LINE: Color = Color::Rgb(40, 76, 69);
pub const PARCH: Color = Color::Rgb(236, 227, 207);
pub const MUTED: Color = Color::Rgb(139, 160, 149);
const DIM2: Color = Color::Rgb(90, 105, 98);

fn hr_fmt(h: f64) -> String {
    if h >= 1_000_000.0 { format!("{:.2} MH/s", h / 1e6) }
    else if h >= 1000.0 { format!("{:.2} kH/s", h / 1e3) }
    else { format!("{:.0} H/s", h) }
}
fn diff_fmt(d: f64) -> String {
    if d >= 1e9 { format!("{:.2}G", d / 1e9) }
    else if d >= 1e6 { format!("{:.2}M", d / 1e6) }
    else if d >= 1e3 { format!("{:.1}k", d / 1e3) }
    else { format!("{:.0}", d) }
}
fn heat(t: u16) -> Color { if t >= 80 { RUST } else if t >= 66 { AMBER } else { SAGE } }
fn dur_fmt(s: u64) -> String {
    if s == 0 { "—".into() }
    else if s >= 86_400 { format!("{}d{:02}h", s / 86_400, (s % 86_400) / 3600) }
    else if s >= 3600 { format!("{}h{:02}m", s / 3600, (s % 3600) / 60) }
    else if s >= 60 { format!("{}m{:02}s", s / 60, s % 60) }
    else { format!("{}s", s) }
}
fn short_addr(a: &str) -> String {
    if a.len() <= 20 { a.to_string() } else { format!("{}…{}", &a[..9], &a[a.len() - 8..]) }
}
fn titled(t: &str) -> Block<'_> {
    Block::default().title(Span::styled(format!(" {t} "), Style::default().fg(AMBER_DIM)))
        .borders(Borders::ALL).border_style(Style::default().fg(INK_LINE))
}
fn bar(ratio: f64, width: usize, col: Color) -> Vec<Span<'static>> {
    let n = ((ratio.clamp(0.0, 1.0)) * width as f64).round() as usize;
    vec![
        Span::styled("█".repeat(n), Style::default().fg(col)),
        Span::styled("░".repeat(width - n), Style::default().fg(DIM2)),
    ]
}

pub fn draw(f: &mut Frame, m: &Miner) {
    let root = Layout::vertical([
        Constraint::Length(13), // hero: hashrate graph + cpu box
        Constraint::Length(9),  // stats row
        Constraint::Min(6),     // ledger
        Constraint::Length(1),  // footer
    ]).split(f.area());

    let top = Layout::horizontal([Constraint::Min(40), Constraint::Length(42)]).split(root[0]);
    hero_chart(f, top[0], m);
    cpu_box(f, top[1], m);

    let mid = Layout::horizontal([
        Constraint::Length(38), Constraint::Length(38), Constraint::Min(20),
    ]).split(root[1]);
    mining_box(f, mid[0], m);
    shares_box(f, mid[1], m);
    chain_box(f, mid[2], m);

    ledger(f, root[2], m);
    footer(f, root[3], m);
}

fn hero_chart(f: &mut Frame, area: Rect, m: &Miner) {
    let stalled = m.paused || (m.solo && !m.online);
    let status = if m.solo && !m.online { "waiting for rig" }
                 else if m.paused { "PAUSED" }
                 else { "mining" };
    let title = format!("HASHRATE · {} · {}", m.algo, status);
    let block = Block::default()
        .title(Span::styled(format!(" {title} "),
            Style::default().fg(if stalled { RUST } else { AMBER_DIM })))
        .title(ratatui::widgets::block::Title::from(
            Span::styled(format!(" {} ", hr_fmt(m.hashrate)),
                Style::default().fg(if stalled { RUST } else { SAGE }).add_modifier(Modifier::BOLD)))
            .alignment(Alignment::Right))
        .borders(Borders::ALL).border_style(Style::default().fg(INK_LINE));
    let inner = block.inner(area);
    f.render_widget(block, area);

    let pts: Vec<(f64, f64)> = m.hr_hist.iter().enumerate()
        .map(|(i, v)| (i as f64, *v)).collect();
    if pts.len() < 2 { return; }
    let xmax = (pts.len() - 1) as f64;
    let hi = m.hr_hist.iter().cloned().fold(0.0f64, f64::max).max(1.0);
    let lo = m.hr_hist.iter().cloned().fold(hi, f64::min);
    let (ylo, yhi) = (lo * 0.97, hi * 1.03);
    let ds = Dataset::default()
        .marker(Marker::Braille)
        .graph_type(GraphType::Line)
        .style(Style::default().fg(if stalled { DIM2 } else { TEAL }))
        .data(&pts);
    let chart = Chart::new(vec![ds])
        .x_axis(Axis::default().bounds([0.0, xmax]))
        .y_axis(Axis::default().bounds([ylo, yhi]));
    f.render_widget(chart, inner);
}

fn cpu_box(f: &mut Frame, area: Rect, m: &Miner) {
    let block = titled("RANDOMX");
    let inner = block.inner(area);
    f.render_widget(block, area);

    let rows = Layout::vertical([
        Constraint::Length(1), // model + freq
        Constraint::Length(1), // total bar + temp
        Constraint::Min(0),    // per-core
        Constraint::Length(1), // load
    ]).split(inner);

    f.render_widget(Paragraph::new(Line::from(vec![
        Span::styled(m.cpu_model.clone(), Style::default().fg(PARCH).add_modifier(Modifier::BOLD)),
    ])), rows[0]);
    let colw = rows[0].width.saturating_sub(9) as usize;
    f.render_widget(Paragraph::new(Line::from(Span::styled(
        format!("{:.1} GHz", m.freq_ghz), Style::default().fg(MUTED))))
        .alignment(Alignment::Right), rows[0]);

    // total utilisation bar + temp
    let total_ratio = if m.hr_max > 0.0 { m.hashrate / m.hr_max } else { 0.0 };
    let mut spans = vec![Span::styled("HASH ", Style::default().fg(MUTED))];
    spans.extend(bar(total_ratio, colw.saturating_sub(2).min(16), if m.paused { DIM2 } else { SAGE }));
    spans.push(Span::styled(format!("  {}°C", m.cpu_temp_c),
        Style::default().fg(heat(m.cpu_temp_c)).add_modifier(Modifier::BOLD)));
    f.render_widget(Paragraph::new(Line::from(spans)), rows[1]);

    // per-core rows (cap to fit)
    let maxrows = rows[2].height as usize;
    let show = m.per_core.len().min(maxrows);
    let mut items: Vec<Line> = Vec::new();
    let core_max = m.per_core.iter().cloned().fold(1.0f64, f64::max);
    for i in 0..show {
        let v = m.per_core[i];
        let mut sp = vec![Span::styled(format!("T{:02} ", i), Style::default().fg(MUTED))];
        sp.extend(bar(v / core_max, 10, if m.paused { DIM2 } else { TEAL }));
        sp.push(Span::styled(format!(" {:>4.0} H/s", v), Style::default().fg(PARCH)));
        items.push(Line::from(sp));
    }
    f.render_widget(Paragraph::new(items), rows[2]);

    f.render_widget(Paragraph::new(Line::from(vec![
        Span::styled("Load ", Style::default().fg(MUTED)),
        Span::styled(format!("{:.2}  {:.2}  {:.2}", m.load[0], m.load[1], m.load[2]),
            Style::default().fg(PARCH)),
    ])), rows[3]);
}

fn kv<'a>(k: &'a str, v: String, c: Color) -> Line<'a> {
    Line::from(vec![
        Span::styled(format!("{:<15}", k), Style::default().fg(MUTED)),
        Span::styled(v, Style::default().fg(c).add_modifier(Modifier::BOLD)),
    ])
}

fn mining_box(f: &mut Frame, area: Rect, m: &Miner) {
    let block = titled("MINING");
    let inner = block.inner(area);
    f.render_widget(block, area);
    // Solo mining has no pool share difficulty; show the payout address there
    // instead. Pool mode keeps `share diff`.
    let fifth = if m.solo {
        kv("payout", short_addr(&m.address), TEAL)
    } else {
        kv("share diff", diff_fmt(m.share_diff), AMBER)
    };
    let text = vec![
        kv("hashrate", hr_fmt(m.hashrate), SAGE),
        kv("10m avg", hr_fmt(m.hr_avg), PARCH),
        kv("peak", hr_fmt(m.hr_max), TEAL),
        kv("threads", m.threads.to_string(), PARCH),
        fifth,
        kv("uptime", format!("{}h{:02}m", m.uptime_s / 3600, (m.uptime_s % 3600) / 60), MUTED),
    ];
    f.render_widget(Paragraph::new(text), inner);
}

fn shares_box(f: &mut Frame, area: Rect, m: &Miner) {
    if m.solo {
        return blocks_box(f, area, m);
    }
    let block = titled("SHARES");
    let inner = block.inner(area);
    f.render_widget(block, area);
    let total = (m.accepted + m.rejected + m.stale).max(1) as f64;
    let acc_ratio = m.accepted as f64 / total;
    let mut accbar = vec![Span::styled("accept  ", Style::default().fg(MUTED))];
    accbar.extend(bar(acc_ratio, 12, SAGE));
    accbar.push(Span::styled(format!(" {:.1}%", acc_ratio * 100.0),
        Style::default().fg(SAGE).add_modifier(Modifier::BOLD)));
    let text = vec![
        Line::from(accbar),
        Line::from(""),
        kv("accepted", m.accepted.to_string(), SAGE),
        kv("rejected", m.rejected.to_string(), RUST),
        kv("stale", m.stale.to_string(), AMBER),
        kv("effort/luck", format!("{:.0}%", m.effort_pct), if m.effort_pct <= 100.0 { SAGE } else { AMBER }),
    ];
    f.render_widget(Paragraph::new(text), inner);
}

/// Solo mining has no pool shares — it submits blocks. Show real block counts,
/// estimated earnings, and expected time-to-block.
fn blocks_box(f: &mut Frame, area: Rect, m: &Miner) {
    let block = titled("BLOCKS · EARN");
    let inner = block.inner(area);
    f.render_widget(block, area);
    let earned = if m.reward > 0.0 {
        format!("{:.2} CYNC", m.coins_earned)
    } else {
        "— (set --reward)".into()
    };
    let text = vec![
        kv("found", m.blocks_found.to_string(), if m.blocks_found > 0 { AMBER } else { MUTED }),
        kv("accepted", m.blocks_accepted.to_string(), if m.blocks_accepted > 0 { SAGE } else { MUTED }),
        kv("rejected", m.blocks_rejected.to_string(), if m.blocks_rejected > 0 { RUST } else { MUTED }),
        kv("est earned", earned, SAGE),
        kv("est time/blk", dur_fmt(m.est_ttb_s), TEAL),
    ];
    f.render_widget(Paragraph::new(text), inner);
}

fn chain_box(f: &mut Frame, area: Rect, m: &Miner) {
    let block = titled("CHAIN");
    let inner = block.inner(area);
    f.render_widget(block, area);
    let tip_c = if m.tip_age_s > 180 { RUST } else if m.tip_age_s > 90 { AMBER } else { SAGE };
    // In solo mode the block counts live in the BLOCKS panel, so show node
    // health here instead; pool mode keeps the local blocks-found line.
    let fourth = if m.solo {
        kv(
            "sync / peers",
            format!("{} · {}", if m.synced { "synced" } else { "syncing" }, m.peers),
            if m.synced { SAGE } else { AMBER },
        )
    } else {
        kv("blocks found", m.blocks_found.to_string(), if m.blocks_found > 0 { AMBER } else { MUTED })
    };
    let text = vec![
        kv("height", m.net_height.to_string(), PARCH),
        kv("net diff", diff_fmt(m.net_diff), AMBER),
        kv("tip age", format!("{}s", m.tip_age_s), tip_c),
        fourth,
        Line::from(vec![Span::styled("via ", Style::default().fg(MUTED)),
            Span::styled(m.connection.clone(), Style::default().fg(TEAL))]),
    ];
    f.render_widget(Paragraph::new(text), inner);
}

fn ledger(f: &mut Frame, area: Rect, m: &Miner) {
    let block = titled("RECENT SHARES & BLOCKS");
    let inner = block.inner(area);
    f.render_widget(block, area);
    let rows: Vec<ListItem> = m.ledger.iter().take(inner.height as usize).map(|r| {
        let col = match r.kind {
            ShareKind::Accepted => SAGE, ShareKind::Rejected => RUST,
            ShareKind::Stale => AMBER, ShareKind::Block => AMBER,
        };
        let bold = matches!(r.kind, ShareKind::Block);
        let mut tag_style = Style::default().fg(col).add_modifier(Modifier::BOLD);
        if bold { tag_style = tag_style.add_modifier(Modifier::REVERSED); }
        ListItem::new(Line::from(vec![
            Span::styled(format!("{} ", r.ts), Style::default().fg(DIM2)),
            Span::styled(format!(" {} ", r.kind.tag()), tag_style),
            Span::styled(format!("  {}", r.detail), Style::default().fg(if bold { AMBER } else { PARCH })),
        ]))
    }).collect();
    f.render_widget(List::new(rows), inner);
}

fn footer(f: &mut Frame, area: Rect, m: &Miner) {
    // Shortened so it never clips mid-word into the key hints. The honest
    // "keys live elsewhere" note stays (the rig holds no signing keys).
    let tag = if m.solo { "solo · keys live elsewhere" } else { "fair launch · 0% dev tax" };
    let left = Span::styled(
        format!("  {} · RandomX · CPU-only · {}", m.rig, tag),
        Style::default().fg(SAGE));
    // Real mode has no demo keys; only `q` quits.
    let (keys_text, keys_w) = if m.solo {
        ("q quit ", 10u16)
    } else {
        ("space pause  b block  ·  q quit ", 32u16)
    };
    let keys = Span::styled(keys_text, Style::default().fg(MUTED));
    let cut = Layout::horizontal([Constraint::Min(0), Constraint::Length(keys_w)]).split(area);
    f.render_widget(Paragraph::new(Line::from(left)), cut[0]);
    f.render_widget(Paragraph::new(Line::from(keys)).alignment(Alignment::Right), cut[1]);
}
