//! The draw layer: the btop silhouette (cpu full-width, then mem|node|net, then
//! a full-width chain-activity feed) rendered from `App`, all colours from the
//! active `Theme`.

use ratatui::{
    layout::{Constraint, Layout, Rect},
    style::{Modifier, Style},
    text::{Line, Span},
    widgets::{
        Block, BorderType, Borders, List, ListItem, Paragraph, Scrollbar, ScrollbarOrientation,
        ScrollbarState,
    },
    Frame,
};
use sysinfo::System;

use crate::app::App;
use crate::draw::{
    bpanel, braille_graph, human_bytes, human_cync, human_dur, human_hashrate, meter_line,
    meter_spans, slice, truncate, BRAND,
};

pub fn draw(f: &mut Frame, app: &mut App) {
    let area = f.area();
    let rows = Layout::vertical([
        Constraint::Length(1), // header
        Constraint::Length(1), // alert
        Constraint::Min(0),    // body
        Constraint::Length(1), // footer
    ])
    .split(area);

    draw_header(f, rows[0], app);
    draw_alert(f, rows[1], app);

    let body = Layout::vertical([
        Constraint::Percentage(32),
        Constraint::Percentage(30),
        Constraint::Percentage(38),
    ])
    .split(rows[2]);
    draw_cpu(f, body[0], app);
    let mid = Layout::horizontal([
        Constraint::Percentage(34),
        Constraint::Percentage(33),
        Constraint::Percentage(33),
    ])
    .split(body[1]);
    // Left column stacks mem over disks (btop-style).
    let left = Layout::vertical([Constraint::Percentage(50), Constraint::Percentage(50)]).split(mid[0]);
    draw_mem(f, left[0], app);
    draw_disks(f, left[1], app);
    draw_node(f, mid[1], app);
    // Right third stacks net over gpu.
    let right = Layout::vertical([Constraint::Percentage(55), Constraint::Percentage(45)]).split(mid[2]);
    draw_net(f, right[0], app);
    draw_gpu(f, right[1], app);
    draw_activity(f, body[2], app);

    draw_footer(f, rows[3], app);
}

fn draw_header(f: &mut Frame, area: Rect, app: &App) {
    let t = &app.theme;
    let host = System::host_name().unwrap_or_else(|| "host".into());
    let os = System::long_os_version().unwrap_or_default();
    let up = System::uptime();
    let line = Line::from(vec![
        Span::styled("◈ cytop", Style::default().fg(BRAND).add_modifier(Modifier::BOLD)),
        Span::styled(format!("  {host}  "), Style::default().fg(t.c("title"))),
        Span::styled(format!("{os}  "), Style::default().fg(t.c("inactive_fg"))),
        Span::styled(format!("up {}h{:02}m", up / 3600, (up % 3600) / 60), Style::default().fg(t.c("inactive_fg"))),
        Span::styled(
            format!("   rpc {}", if app.node.online { "●" } else { "○" }),
            Style::default().fg(if app.node.online { t.g("free", 80.0) } else { t.g("used", 100.0) }),
        ),
        Span::styled(format!("   {}", crate::draw::clock_hms()), Style::default().fg(t.c("inactive_fg"))),
    ]);
    f.render_widget(Paragraph::new(line), area);
}

fn draw_alert(f: &mut Frame, area: Rect, app: &App) {
    let t = &app.theme;
    let n = &app.node;
    let alert = if !n.online {
        Some(("⚠  node RPC offline", t.g("used", 100.0)))
    } else if n.fork_stuck {
        Some(("⚠  FORK-STUCK — wedged on a minority fork; an operator reset may be needed", t.g("used", 100.0)))
    } else if n.mesh_degraded {
        Some(("⚠  mesh degraded — too few peers", t.g("available", 70.0)))
    } else {
        None
    };
    if let Some((msg, col)) = alert {
        f.render_widget(
            Paragraph::new(Line::from(Span::styled(
                format!(" {msg} "),
                Style::default().fg(t.c("main_bg")).bg(col).add_modifier(Modifier::BOLD),
            ))),
            area,
        );
    }
}

fn draw_cpu(f: &mut Frame, area: Rect, app: &App) {
    let t = &app.theme;
    let cpu_now = *app.cpu_hist.back().unwrap_or(&0);
    let up = System::uptime();
    let block = bpanel(
        t,
        1,
        "cpu",
        &format!(" up {}d {:02}h{:02}m ", up / 86400, (up % 86400) / 3600, (up % 3600) / 60),
        "cpu_box",
    );
    let inner = block.inner(area);
    f.render_widget(block, area);

    let core_w = 30u16.min(inner.width.saturating_sub(20));
    let parts = Layout::horizontal([Constraint::Min(0), Constraint::Length(core_w)]).split(inner);

    let glines: Vec<Line> = braille_graph(&slice(&app.cpu_hist), 100, parts[0].width as usize, parts[0].height as usize)
        .into_iter()
        .map(|s| Line::from(Span::styled(s, Style::default().fg(t.g("cpu", cpu_now as f64)))))
        .collect();
    f.render_widget(Paragraph::new(glines), parts[0]);

    let cpus = app.sys.cpus();
    let brand = cpus.first().map(|c| c.brand().trim().to_string()).unwrap_or_default();
    let brand = if brand.is_empty() { format!("{} cores", cpus.len()) } else { brand };
    let cbox = Block::default()
        .borders(Borders::ALL)
        .border_type(BorderType::Rounded)
        .border_style(Style::default().fg(t.c("cpu_box")))
        .title(Span::styled(truncate(&brand, core_w.saturating_sub(2) as usize), Style::default().fg(t.c("title"))));
    let cinner = cbox.inner(parts[1]);
    f.render_widget(cbox, parts[1]);

    let bar_w = (cinner.width as usize).saturating_sub(10);
    let mut lines = vec![core_row(app, "CPU", cpu_now as f64, bar_w)];
    let avail = cinner.height.saturating_sub(1) as usize;
    for (i, c) in cpus.iter().enumerate().take(avail.saturating_sub(1)) {
        lines.push(core_row(app, &format!("C{i}"), c.cpu_usage() as f64, bar_w));
    }
    f.render_widget(Paragraph::new(lines), cinner);
}

fn core_row(app: &App, label: &str, pct: f64, bar_w: usize) -> Line<'static> {
    let t = &app.theme;
    let mut spans = vec![
        Span::styled(format!("{label:<4}"), Style::default().fg(t.c("inactive_fg"))),
        Span::styled(format!("{pct:>3.0}% "), Style::default().fg(t.c("main_fg"))),
    ];
    if bar_w > 0 {
        spans.extend(meter_spans(t, "cpu", pct, bar_w));
    }
    Line::from(spans)
}

fn draw_mem(f: &mut Frame, area: Rect, app: &App) {
    let t = &app.theme;
    let block = bpanel(t, 2, "mem", "", "mem_box");
    let inner = block.inner(area);
    f.render_widget(block, area);
    let bar_w = (inner.width as usize).saturating_sub(22).clamp(4, 40);

    let total = app.sys.total_memory().max(1);
    let used = app.sys.used_memory();
    let avail = app.sys.available_memory();
    let free = app.sys.free_memory();
    let stotal = app.sys.total_swap();
    let sused = app.sys.used_swap();
    let pct = |v: u64| v as f64 / total as f64 * 100.0;

    let mut lines = vec![
        Line::from(vec![
            Span::styled("Total   ", Style::default().fg(t.c("inactive_fg"))),
            Span::styled(human_bytes(total), Style::default().fg(t.c("title")).add_modifier(Modifier::BOLD)),
        ]),
        meter_line(t, "Used", "used", pct(used), &human_bytes(used), bar_w),
        meter_line(t, "Avail", "available", pct(avail), &human_bytes(avail), bar_w),
        meter_line(t, "Free", "free", pct(free), &human_bytes(free), bar_w),
    ];
    if stotal > 0 {
        lines.push(meter_line(t, "Swap", "used", sused as f64 / stotal as f64 * 100.0, &human_bytes(sused), bar_w));
    }
    f.render_widget(Paragraph::new(lines), inner);
}

fn draw_disks(f: &mut Frame, area: Rect, app: &App) {
    let t = &app.theme;
    let block = bpanel(t, 6, "disks", "", "mem_box");
    let inner = block.inner(area);
    f.render_widget(block, area);
    let bar_w = (inner.width as usize).saturating_sub(24).clamp(4, 40);

    let avail_rows = inner.height as usize;
    let mut lines: Vec<Line> = Vec::new();
    for disk in app.disks.iter() {
        if lines.len() >= avail_rows {
            break;
        }
        let total = disk.total_space();
        if total == 0 {
            continue;
        }
        let used = total.saturating_sub(disk.available_space());
        let pct = used as f64 / total as f64 * 100.0;
        let mount = disk.mount_point().to_string_lossy();
        let label = truncate(mount.trim_end_matches('\\'), 7);
        let value = format!("{}/{}", human_bytes(used), human_bytes(total));
        lines.push(meter_line(t, &label, "used", pct, &value, bar_w));
    }
    if lines.is_empty() {
        lines.push(Line::from(Span::styled("no disks", Style::default().fg(t.c("inactive_fg")))));
    }
    f.render_widget(Paragraph::new(lines), inner);
}

fn draw_net(f: &mut Frame, area: Rect, app: &App) {
    let t = &app.theme;
    let down = *app.down_hist.back().unwrap_or(&0);
    let up = *app.up_hist.back().unwrap_or(&0);
    let block = bpanel(t, 4, "net", &format!(" ↓{down} ↑{up} KiB/s "), "net_box");
    let inner = block.inner(area);
    f.render_widget(block, area);
    let nmax = app.down_hist.iter().copied().max().unwrap_or(1).max(1);
    let glines: Vec<Line> = braille_graph(&slice(&app.down_hist), nmax, inner.width as usize, inner.height as usize)
        .into_iter()
        .map(|s| Line::from(Span::styled(s, Style::default().fg(t.g("download", 100.0)))))
        .collect();
    f.render_widget(Paragraph::new(glines), inner);
}

fn draw_gpu(f: &mut Frame, area: Rect, app: &App) {
    let t = &app.theme;
    let g = &app.gpu;
    let title = if g.present && !g.name.is_empty() {
        truncate(&g.name, 24)
    } else {
        "gpu".into()
    };
    let tab = if g.present { format!(" {} ", g.backend) } else { String::new() };
    let block = bpanel(t, 7, &title, &tab, "net_box");
    let inner = block.inner(area);
    f.render_widget(block, area);
    let dim = t.c("inactive_fg");

    if !g.present {
        f.render_widget(
            Paragraph::new(vec![
                Line::from(Span::styled("gpu  n/a", Style::default().fg(dim))),
                Line::from(Span::styled("(no nvidia-smi / GPU counters)", Style::default().fg(dim))),
            ]),
            inner,
        );
        return;
    }

    let bar_w = (inner.width as usize).saturating_sub(22).clamp(4, 36);
    let mut lines = vec![meter_line(t, "util", "cpu", g.util, "", bar_w)];
    if g.mem_total > 0 {
        let pct = g.mem_used as f64 / g.mem_total as f64 * 100.0;
        lines.push(meter_line(t, "vram", "used", pct, &format!("{}/{}", human_bytes(g.mem_used), human_bytes(g.mem_total)), bar_w));
    }
    let mut tp: Vec<Span> = Vec::new();
    if let Some(temp) = g.temp {
        tp.push(Span::styled("temp ", Style::default().fg(dim)));
        tp.push(Span::styled(format!("{temp:.0}°C  "), Style::default().fg(t.g("cpu", (temp / 100.0 * 100.0).min(100.0)))));
    }
    if let Some(pw) = g.power {
        tp.push(Span::styled("power ", Style::default().fg(dim)));
        tp.push(Span::styled(format!("{pw:.0} W"), Style::default().fg(t.c("main_fg"))));
    }
    if !tp.is_empty() {
        lines.push(Line::from(tp));
    }
    f.render_widget(Paragraph::new(lines), inner);
}

fn draw_node(f: &mut Frame, area: Rect, app: &App) {
    let t = &app.theme;
    let n = &app.node;
    let block = bpanel(t, 3, "node", &format!(" {} ", n.network), "proc_box");
    let inner = block.inner(area);
    f.render_widget(block, area);

    if !n.online {
        f.render_widget(
            Paragraph::new(Line::from(Span::styled("RPC offline — start a node or pass --rpc", Style::default().fg(t.g("used", 100.0))))),
            inner,
        );
        return;
    }

    let bar_w = (inner.width as usize).saturating_sub(22).clamp(4, 36);
    let dim = t.c("inactive_fg");
    let mut lines: Vec<Line> = vec![Line::from(vec![
        Span::styled("height  ", Style::default().fg(dim)),
        Span::styled(n.height.to_string(), Style::default().fg(t.c("title")).add_modifier(Modifier::BOLD)),
        Span::styled("   diff ", Style::default().fg(dim)),
        Span::styled(n.difficulty.clone(), Style::default().fg(t.c("main_fg"))),
    ])];
    if n.synced {
        lines.push(Line::from(vec![
            Span::styled("state   ", Style::default().fg(dim)),
            Span::styled("● synced", Style::default().fg(t.g("free", 80.0))),
        ]));
    } else if n.fork_stuck {
        lines.push(Line::from(vec![
            Span::styled("state   ", Style::default().fg(dim)),
            Span::styled("● FORK-STUCK", Style::default().fg(t.g("used", 100.0)).add_modifier(Modifier::BOLD)),
        ]));
    } else {
        let pct = n.height as f64 / n.target_height.max(n.height).max(1) as f64 * 100.0;
        lines.push(meter_line(t, "sync", "cpu", pct, &format!("{}/{}", n.height, n.target_height), bar_w));
    }
    lines.push(meter_line(t, "peers", "process", (n.peers as f64 / 16.0 * 100.0).min(100.0), &format!("{}/16", n.peers), bar_w));
    let privacy = if n.peers >= 3 {
        Span::styled("● Baffle adequate", Style::default().fg(t.g("free", 80.0)))
    } else {
        Span::styled("● Baffle size-limited", Style::default().fg(t.g("available", 70.0)))
    };
    lines.push(Line::from(vec![Span::styled("privacy ", Style::default().fg(dim)), privacy]));

    let hmax = app.hash_hist.iter().copied().max().unwrap_or(1).max(1) as f64;
    if n.is_mining {
        lines.push(meter_line(t, "hashR", "cpu", n.hashrate / hmax * 100.0, &human_hashrate(n.hashrate), bar_w));
    } else {
        lines.push(Line::from(vec![
            Span::styled("hashR   ", Style::default().fg(dim)),
            Span::styled("mining off", Style::default().fg(dim)),
        ]));
    }
    lines.push(Line::from(vec![
        Span::styled("blocks  ", Style::default().fg(dim)),
        Span::styled(n.blocks_found.to_string(), Style::default().fg(t.c("main_fg"))),
        Span::styled("   mempool ", Style::default().fg(dim)),
        Span::styled(format!("{} tx", n.mempool), Style::default().fg(t.c("main_fg"))),
    ]));

    // Shielded (Spark) pool: coin count + short anchor root. Empty while
    // shielded is activation-gated off, so show a muted placeholder then.
    if n.shielded_coins > 0 {
        lines.push(Line::from(vec![
            Span::styled("shield  ", Style::default().fg(dim)),
            Span::styled(
                format!("{} coins", n.shielded_coins),
                Style::default().fg(t.g("available", 80.0)),
            ),
            Span::styled("   anchor ", Style::default().fg(dim)),
            Span::styled(n.shielded_anchor.clone(), Style::default().fg(t.c("main_fg"))),
        ]));
    } else {
        lines.push(Line::from(vec![
            Span::styled("shield  ", Style::default().fg(dim)),
            Span::styled("pool empty (gated off)", Style::default().fg(dim)),
        ]));
    }

    // Estimated mining earnings = blocks_found × last block reward (reward is
    // derived from supply_atomic deltas in the log feed). ESTIMATE ONLY — ignores
    // reward drift across blocks, coinbase maturity, and anything spent.
    let earned = match app.block_reward {
        Some(r) if n.blocks_found > 0 => format!("≈ {}", human_cync(r.saturating_mul(n.blocks_found))),
        _ => "—".to_string(),
    };
    lines.push(Line::from(vec![
        Span::styled("earned  ", Style::default().fg(dim)),
        Span::styled(earned, Style::default().fg(t.g("free", 80.0))),
        Span::styled("  estimate", Style::default().fg(t.g("available", 70.0))),
    ]));

    let gold = t.g("available", 80.0);
    let flashing = app.block_flash.map(|x| x.elapsed() < std::time::Duration::from_secs(3)).unwrap_or(false);
    let diff_val: f64 = n.difficulty.parse().unwrap_or(0.0);
    if flashing {
        lines.push(Line::from(Span::styled("✦ ⛏ BLOCK FOUND! ⛏ ✦", Style::default().fg(gold).add_modifier(Modifier::BOLD))));
    } else if n.is_mining {
        let (art, strike) = mining_art(app.frame);
        let eta = if n.hashrate > 0.0 && diff_val > 0.0 {
            format!("  ~block {} (solo)", human_dur(diff_val / n.hashrate))
        } else {
            String::new()
        };
        lines.push(Line::from(vec![
            Span::styled(art, Style::default().fg(if strike { gold } else { BRAND })),
            Span::styled(eta, Style::default().fg(dim)),
        ]));
    } else {
        lines.push(Line::from(Span::styled("(-_-) zzz  idle", Style::default().fg(dim))));
    }

    f.render_widget(Paragraph::new(lines), inner);
}

fn mining_art(frame: u64) -> (&'static str, bool) {
    match (frame / 2) % 4 {
        0 => ("(•_•)  ⛏      ", false),
        1 => ("(•_•)    ⛏    ", false),
        2 => ("(•_•)      ⛏ ✦", true),
        _ => ("(•_•)    ⛏    ", false),
    }
}

fn draw_activity(f: &mut Frame, area: Rect, app: &mut App) {
    let src = if app.log_mode() { "node log" } else { "rpc" };
    if app.events.is_empty() {
        let wait = if app.log_mode() {
            "waiting for node log… (is --log pointing at the node output?)"
        } else {
            "waiting for chain activity…"
        };
        let block = bpanel(&app.theme, 5, "chain-activity", &format!(" {src} "), "proc_box");
        f.render_widget(Paragraph::new(Line::from(Span::styled(wait, Style::default().fg(app.theme.c("inactive_fg"))))).block(block), area);
        return;
    }

    let len = app.events.len();
    if app.feed_follow {
        app.feed_state.select(Some(len - 1));
    }
    let items: Vec<ListItem> = app
        .events
        .iter()
        .map(|e| {
            ListItem::new(Line::from(
                e.spans.iter().map(|(txt, c)| Span::styled(txt.clone(), Style::default().fg(*c))).collect::<Vec<_>>(),
            ))
        })
        .collect();

    let mode = if app.feed_follow { "live" } else { "scroll" };
    let sel = app.feed_state.selected().map(|i| i + 1).unwrap_or(len);
    let tabs = format!(" {src} · {sel}/{len} · {mode} ");
    let block = bpanel(&app.theme, 5, "chain-activity", &tabs, "proc_box");
    let inner = block.inner(area);
    app.feed_area = inner; // for mouse hit-testing
    let hl = if app.feed_follow {
        Style::default()
    } else {
        Style::default().bg(app.theme.c("selected_bg")).add_modifier(Modifier::BOLD)
    };
    let list = List::new(items).block(block).highlight_style(hl);
    f.render_stateful_widget(list, area, &mut app.feed_state);

    let mut sb = ScrollbarState::new(len).position(app.feed_state.selected().unwrap_or(len - 1));
    f.render_stateful_widget(
        Scrollbar::new(ScrollbarOrientation::VerticalRight)
            .begin_symbol(None)
            .end_symbol(None)
            .thumb_style(Style::default().fg(app.theme.c("proc_box")))
            .track_style(Style::default().fg(app.theme.c("div_line"))),
        inner,
        &mut sb,
    );
}

fn draw_footer(f: &mut Frame, area: Rect, app: &App) {
    let t = &app.theme;
    let key = |s: &'static str| Span::styled(s, Style::default().fg(t.c("hi_fg")).add_modifier(Modifier::BOLD));
    let lbl = |s: &'static str| Span::styled(s, Style::default().fg(t.c("inactive_fg")));
    let mut hint = vec![
        key("q"), lbl(" quit  "),
        key("j/k"), lbl(" scroll  "),
        key("G"), lbl(" live  "),
        key("space"), lbl(" pause  "),
        key("t"), lbl(" theme:"),
        Span::styled(format!("{}  ", app.theme_name), Style::default().fg(t.c("title"))),
    ];
    if app.paused {
        hint.push(Span::styled("PAUSED  ", Style::default().fg(t.g("available", 70.0)).add_modifier(Modifier::BOLD)));
    }
    hint.push(Span::styled("◈ cytop", Style::default().fg(BRAND)));
    f.render_widget(Paragraph::new(Line::from(hint)), area);
}
