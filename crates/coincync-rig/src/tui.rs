//! Premium ratatui dashboard for `run-solo` (`--tui`).
//!
//! Layered visual design:
//!   1. Branded header bar — `COINCYNC` in bold,
//!      mining-status pill, network/height context, RPC quality dot.
//!   2. Optional stale-chain warning (>5 min tip age).
//!   3. Hero hashrate — 5-row block-letter digits dominating upper third,
//!      auto-scaling unit (H/s → KH/s → MH/s → GH/s).
//!   4. 60-sample hashrate sparkline directly under the hero.
//!   5. Five stat cards (HEIGHT / FOUND / ACCEPT% / EARNED / UPTIME).
//!   6. Next-block ETA gauge with Braille spinner.
//!   7. Log scrollback with level-glyph bullets.
//!   8. Found-blocks 24h timeline strip + ticker.
//!   9. Keybinding footer.
//!
//! Three themes (Brass / Moon / Mono) toggled with `t`. `?` pops a help
//! modal; `p` pauses mining; `c` snapshots the dashboard to a tmpfile;
//! `l` toggles the log pane. Quit with `q` / `Esc` — exit prints a
//! session summary before the terminal restores.
//!
//! See [`crate::tui_theme`] for the palette types and [`crate::tui_blockfont`]
//! for the hero-letter font.

use std::collections::VecDeque;
use std::io;
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::sync::mpsc::{Receiver, Sender, channel};
use std::time::{Duration, Instant, SystemTime};

use crossterm::{
    event::{self, Event, KeyCode},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::{
    backend::CrosstermBackend,
    layout::{Alignment, Constraint, Direction, Layout, Rect},
    style::{Modifier, Style},
    symbols,
    text::{Line, Span},
    widgets::{Block, BorderType, Borders, Clear, Gauge, List, ListItem, Paragraph, Sparkline, Wrap},
    Frame, Terminal,
};
use tracing::field::Field;
use tracing_subscriber::Layer;

use crate::metrics::MetricsState;
use crate::tui_blockfont as bf;
use crate::tui_theme::{self, Theme, THEMES};

/// Most recent log lines we keep around for the scrolling pane. Anything
/// older falls off the front. Tuned for ~1 KB per line × 1000 lines = 1 MB
/// max footprint, comfortably under any modern terminal's scrollback.
const MAX_LOG_LINES: usize = 1000;

// ─── Tracing → channel layer ─────────────────────────────────────────

/// `tracing_subscriber::Layer` that forwards each event into an mpsc
/// channel as a single formatted line. Cheap; the render loop is the
/// only consumer and `try_recv`s every frame.
pub struct TuiLogLayer {
    sender: Sender<String>,
}

impl TuiLogLayer {
    pub fn new() -> (Self, Receiver<String>) {
        let (tx, rx) = channel();
        (Self { sender: tx }, rx)
    }
}

impl<S> Layer<S> for TuiLogLayer
where
    S: tracing::Subscriber,
{
    fn on_event(&self, event: &tracing::Event<'_>, _ctx: tracing_subscriber::layer::Context<'_, S>) {
        let mut visitor = StringVisitor::default();
        event.record(&mut visitor);
        let level = *event.metadata().level();
        let target = event.metadata().target();
        // Compact target: drop the `coincync_rig::` prefix the tracing
        // default would otherwise repeat on every line.
        let target = target.strip_prefix("coincync_rig::").unwrap_or(target);
        let line = format!("{:<5} {} {}", level, target, visitor.message.trim_start());
        // try_send equivalent: if the channel is full / closed we don't
        // care — the TUI may have exited and we're just on our way out.
        let _ = self.sender.send(line);
    }
}

#[derive(Default)]
struct StringVisitor {
    message: String,
}

impl tracing::field::Visit for StringVisitor {
    fn record_str(&mut self, field: &Field, value: &str) {
        self.append(field.name(), value);
    }
    fn record_bool(&mut self, field: &Field, value: bool) {
        self.append(field.name(), &value.to_string());
    }
    fn record_i64(&mut self, field: &Field, value: i64) {
        self.append(field.name(), &value.to_string());
    }
    fn record_u64(&mut self, field: &Field, value: u64) {
        self.append(field.name(), &value.to_string());
    }
    fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
        self.append(field.name(), &format!("{:?}", value));
    }
}

impl StringVisitor {
    fn append(&mut self, name: &str, value: &str) {
        if name == "message" {
            // Primary message slot — strip surrounding quotes that
            // record_debug adds for &str fields.
            self.message
                .push_str(value.trim_matches('"'));
        } else {
            if !self.message.is_empty() {
                self.message.push(' ');
            }
            self.message.push_str(name);
            self.message.push('=');
            self.message.push_str(value);
        }
    }
}

// ─── UI state ────────────────────────────────────────────────────────

/// All non-metrics UI state lives here so the render loop is just
/// "drain logs, update spinner phase, draw, poll input".
struct UiState {
    /// Index into [`THEMES`].
    theme_idx: usize,
    /// Wall instant the dashboard was first painted, used for splash
    /// timing and the spinner phase.
    started: Instant,
    /// When the most recent block-found celebration kicked off. `None`
    /// means no active celebration. Border + toast render based on
    /// `(now - this).as_secs_f32() < CELEBRATION_SECS`.
    celebrate_until: Option<Instant>,
    /// Tracks blocks_accepted_total to detect new blocks vs the last
    /// frame and trigger celebration.
    last_blocks_accepted: u64,
    /// `false` after the user toggles `l`.
    show_log: bool,
    /// `true` while the help modal overlay is up.
    show_help: bool,
    /// `true` for the first ~2.5s of the session (splash screen).
    show_splash: bool,
}

impl UiState {
    fn new() -> Self {
        Self {
            theme_idx: 0,
            started: Instant::now(),
            celebrate_until: None,
            last_blocks_accepted: 0,
            show_log: true,
            show_help: false,
            show_splash: true,
        }
    }

    fn theme(&self) -> &'static Theme {
        &THEMES[self.theme_idx]
    }
}

/// How long the gold-border block-found flash stays up after a block
/// lands. Long enough to be obvious, short enough not to compete with
/// the next iteration of mining.
const CELEBRATION_SECS: f32 = 1.5;

/// Splash duration. Ratatui+crossterm initialize fast enough that
/// 2.5s feels like an intentional reveal rather than a stutter.
const SPLASH_SECS: f32 = 2.5;

/// Braille spinner frames for the ETA gauge "searching..." indicator.
const SPINNER: &[char] = &['⠋', '⠙', '⠹', '⠸', '⠼', '⠴', '⠦', '⠧', '⠇', '⠏'];

/// Mark-rolodex glyphs in the header — four geometrically-related
/// diamond variants that read as a slow rotation rather than random.
/// One frame per ~6 seconds (see `mark_rolodex_glyph`); ambient brand
/// presence without competing with the rest of the dashboard for the
/// user's attention.
const MARK_ROLODEX: &[char] = &['◆', '◈', '❖', '◇'];

/// Pick the current mark-rolodex glyph based on elapsed session time.
/// Each glyph is shown for `MARK_ROLODEX_PERIOD_MS`; cycles forever.
fn mark_rolodex_glyph(elapsed: Duration) -> char {
    const PERIOD_MS: u128 = 6_000;
    let idx = (elapsed.as_millis() / PERIOD_MS) as usize % MARK_ROLODEX.len();
    MARK_ROLODEX[idx]
}

// ─── Render loop ─────────────────────────────────────────────────────

/// Block on the dashboard render loop. Returns when the user presses q
/// / Q / Esc; on return, the caller should exit the process — the
/// orchestrator does not have a cancel hook.
pub fn run_dashboard(
    metrics: Arc<MetricsState>,
    log_rx: Receiver<String>,
) -> io::Result<()> {
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    let restore = || {
        let _ = disable_raw_mode();
        let mut stdout = io::stdout();
        let _ = execute!(stdout, LeaveAlternateScreen);
    };
    let _guard = scopeguard_call_on_drop(restore);

    let mut log_buffer: VecDeque<String> = VecDeque::with_capacity(MAX_LOG_LINES);
    let mut ui = UiState::new();

    loop {
        // Drain incoming log events into the scrollback.
        while let Ok(line) = log_rx.try_recv() {
            if log_buffer.len() >= MAX_LOG_LINES {
                log_buffer.pop_front();
            }
            log_buffer.push_back(line);
        }

        // Detect newly-accepted block → kick off celebration.
        let blocks_now = metrics.blocks_accepted_total.load(Ordering::Relaxed);
        if blocks_now > ui.last_blocks_accepted && ui.last_blocks_accepted != 0 {
            ui.celebrate_until = Some(Instant::now() + Duration::from_millis(
                (CELEBRATION_SECS * 1000.0) as u64,
            ));
        }
        ui.last_blocks_accepted = blocks_now;

        // Splash auto-clears.
        if ui.show_splash && ui.started.elapsed().as_secs_f32() > SPLASH_SECS {
            ui.show_splash = false;
        }

        terminal.draw(|f| draw(f, &metrics, &log_buffer, &ui))?;

        // Poll input with a short timeout so animations advance even
        // when no keys are pressed (sparkline, spinner, splash, flash).
        if event::poll(Duration::from_millis(120))? {
            if let Event::Key(key) = event::read()? {
                match key.code {
                    KeyCode::Char('q') | KeyCode::Char('Q') | KeyCode::Esc => {
                        if ui.show_help {
                            ui.show_help = false;
                        } else {
                            // Print session summary before terminal restores.
                            print_session_summary(&metrics);
                            break;
                        }
                    }
                    KeyCode::Char('t') | KeyCode::Char('T') => {
                        ui.theme_idx = tui_theme::next_theme(ui.theme_idx);
                    }
                    KeyCode::Char('l') | KeyCode::Char('L') => {
                        ui.show_log = !ui.show_log;
                    }
                    KeyCode::Char('?') | KeyCode::Char('h') | KeyCode::Char('H') => {
                        ui.show_help = !ui.show_help;
                    }
                    KeyCode::Char('p') | KeyCode::Char('P') => {
                        // Toggle pause flag — orchestrator polls this and
                        // sleeps instead of fetching a template when set.
                        let was = metrics.paused.load(Ordering::Relaxed);
                        metrics.paused.store(!was, Ordering::Relaxed);
                    }
                    KeyCode::Char('c') | KeyCode::Char('C') => {
                        snapshot_to_tmpfile(&metrics);
                    }
                    _ => {}
                }
            }
        }
    }

    Ok(())
}

fn draw(f: &mut Frame, metrics: &MetricsState, logs: &VecDeque<String>, ui: &UiState) {
    if ui.show_splash {
        draw_splash(f, ui);
        return;
    }

    let theme = ui.theme();
    let stale = metrics.tip_age_secs.load(Ordering::Relaxed) > 300;

    // Layout planning. Heights sum to a "comfortable minimum" of ~36
    // rows; on shorter terminals ratatui will compress the log pane.
    let mut constraints: Vec<Constraint> = vec![
        Constraint::Length(3), // header
    ];
    if stale {
        constraints.push(Constraint::Length(3)); // stale-chain banner
    }
    constraints.push(Constraint::Length(9));    // hero hashrate (5 rows + label + sparkline)
    // Worker heatmap row — only renders if we actually have per-thread
    // samples (the metric is empty until the first iteration completes).
    let has_worker_samples = !metrics.per_thread_hashrate_samples().is_empty();
    if has_worker_samples {
        constraints.push(Constraint::Length(1));
    }
    constraints.push(Constraint::Length(4));    // stat cards
    constraints.push(Constraint::Length(3));    // ETA gauge
    if ui.show_log {
        constraints.push(Constraint::Min(5));   // log
    } else {
        constraints.push(Constraint::Min(0));   // collapsed
    }
    constraints.push(Constraint::Length(2));    // ticker / blocks-timeline
    constraints.push(Constraint::Length(1));    // footer

    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints(constraints)
        .split(f.area());

    let mut idx = 0;
    draw_header(f, chunks[idx], metrics, ui); idx += 1;
    if stale {
        draw_stale_banner(f, chunks[idx], metrics, theme); idx += 1;
    }
    draw_hero(f, chunks[idx], metrics, theme, ui); idx += 1;
    if has_worker_samples {
        draw_worker_heatmap(f, chunks[idx], metrics, theme); idx += 1;
    }
    draw_stat_cards(f, chunks[idx], metrics, theme); idx += 1;
    draw_eta_gauge(f, chunks[idx], metrics, theme, ui); idx += 1;
    if ui.show_log {
        draw_logs(f, chunks[idx], logs, theme);
    }
    idx += 1;
    draw_blocks_timeline_and_ticker(f, chunks[idx], metrics, theme, ui); idx += 1;
    draw_footer(f, chunks[idx], theme, metrics);

    if ui.show_help {
        draw_help_modal(f, theme);
    }
}

// ─── Header ──────────────────────────────────────────────────────────

fn draw_header(f: &mut Frame, area: Rect, metrics: &MetricsState, ui: &UiState) {
    let theme = ui.theme();

    let paused = metrics.paused.load(Ordering::Relaxed);
    let blocks_accepted = metrics.blocks_accepted_total.load(Ordering::Relaxed);
    let height = metrics.current_template_height.load(Ordering::Relaxed);
    let threads = metrics.threads.load(Ordering::Relaxed);
    let rpc_ms = metrics.rpc_latency_ms.load(Ordering::Relaxed);

    // Status pill: gold "MINING" / muted "PAUSED" / gold "BLOCK FOUND"
    // during celebration window.
    let in_celebration = ui
        .celebrate_until
        .map(|t| Instant::now() < t)
        .unwrap_or(false);
    let (pill_glyph, pill_text, pill_style) = if in_celebration {
        ("◉", "BLOCK FOUND", Style::default().fg(theme.accent).add_modifier(Modifier::BOLD))
    } else if paused {
        ("○", "PAUSED", Style::default().fg(theme.muted))
    } else {
        ("◉", "MINING", Style::default().fg(theme.accent).add_modifier(Modifier::BOLD))
    };

    // Connection-quality dot — green/yellow/red based on RPC latency.
    let (rpc_dot, rpc_style) = if rpc_ms == 0 {
        ('○', Style::default().fg(theme.muted))
    } else if rpc_ms < 100 {
        ('●', Style::default().fg(theme.success))
    } else if rpc_ms < 500 {
        ('●', Style::default().fg(theme.warn))
    } else {
        ('●', Style::default().fg(theme.danger))
    };

    let rolodex = mark_rolodex_glyph(ui.started.elapsed());

    let line = Line::from(vec![
        Span::raw(" "),
        Span::styled(
            rolodex.to_string(),
            Style::default().fg(theme.accent_dim).add_modifier(Modifier::BOLD),
        ),
        Span::raw(" "),
        Span::styled("COINCYNC", Style::default().fg(theme.accent).add_modifier(Modifier::BOLD)),
        Span::styled(" rig", Style::default().fg(theme.muted)),
        Span::raw("    "),
        Span::styled(pill_glyph, pill_style),
        Span::raw(" "),
        Span::styled(pill_text, pill_style),
        Span::raw("      "),
        Span::styled("testnet", Style::default().fg(theme.muted)),
        Span::raw(" · "),
        Span::styled(format!("h{}", height), Style::default().fg(theme.body)),
        Span::raw(" · "),
        Span::styled(format!("{} found", blocks_accepted), Style::default().fg(theme.body)),
        Span::raw(" · "),
        Span::styled(format!("{} threads", threads), Style::default().fg(theme.body)),
        Span::raw("      "),
        Span::styled(rpc_dot.to_string(), rpc_style),
        Span::raw(" "),
        Span::styled(
            if rpc_ms == 0 { "RPC —".to_string() } else { format!("RPC {}ms", rpc_ms) },
            Style::default().fg(theme.muted),
        ),
    ]);

    let in_celebration = ui
        .celebrate_until
        .map(|t| Instant::now() < t)
        .unwrap_or(false);
    let border_style = if in_celebration {
        Style::default().fg(theme.accent).add_modifier(Modifier::BOLD)
    } else {
        Style::default().fg(theme.border)
    };

    let block = Block::default()
        .borders(Borders::ALL)
        .border_type(BorderType::Rounded)
        .border_style(border_style);
    let widget = Paragraph::new(line).block(block);
    f.render_widget(widget, area);
}

// ─── Stale-chain warning banner ──────────────────────────────────────

fn draw_stale_banner(f: &mut Frame, area: Rect, metrics: &MetricsState, theme: &Theme) {
    let age = metrics.tip_age_secs.load(Ordering::Relaxed);
    let mins = age / 60;
    let line = Line::from(vec![
        Span::styled("  ⚠  ", Style::default().fg(theme.warn).add_modifier(Modifier::BOLD)),
        Span::styled("STALE TIP", Style::default().fg(theme.warn).add_modifier(Modifier::BOLD)),
        Span::raw("  "),
        Span::styled(
            format!("connected node hasn't seen a block in {}m {}s — your work may be wasted", mins, age % 60),
            Style::default().fg(theme.body),
        ),
    ]);
    let block = Block::default()
        .borders(Borders::ALL)
        .border_type(BorderType::Rounded)
        .border_style(Style::default().fg(theme.warn));
    let p = Paragraph::new(line).block(block);
    f.render_widget(p, area);
}

// ─── Hero hashrate ───────────────────────────────────────────────────

fn draw_hero(f: &mut Frame, area: Rect, metrics: &MetricsState, theme: &Theme, ui: &UiState) {
    let hps = metrics.current_hashrate_hps.load(Ordering::Relaxed);
    let (digits, unit) = bf::format_hashrate(hps);

    let big = bf::render(&digits);

    // Vertical centering inside the panel: 5 digit rows + 1 unit row +
    // 1 sparkline = 7 lines, panel is 9 (with borders), so render with
    // a 1-line top pad.
    let mut lines: Vec<Line> = Vec::with_capacity(7);
    lines.push(Line::from(""));
    let digit_style = Style::default().fg(theme.accent).add_modifier(Modifier::BOLD);
    for r in &big {
        lines.push(Line::from(Span::styled(format!("  {}", r), digit_style)));
    }
    // Unit + secondary stats line: unit suffix, then network share %
    // if known, then 1m-trend.
    let net_hps = metrics.network_hashrate_hps.load(Ordering::Relaxed);
    let mut secondary: Vec<Span> = vec![
        Span::raw("  "),
        Span::styled(unit, Style::default().fg(theme.body).add_modifier(Modifier::BOLD)),
    ];
    if net_hps > 0 && hps > 0 {
        let pct = (hps as f64 / net_hps as f64) * 100.0;
        secondary.push(Span::raw("    "));
        secondary.push(Span::styled("network share ", Style::default().fg(theme.muted)));
        secondary.push(Span::styled(
            format!("{:.1}%", pct),
            Style::default().fg(theme.body).add_modifier(Modifier::BOLD),
        ));
    }
    secondary.push(Span::raw("    "));
    secondary.push(Span::styled("trend ", Style::default().fg(theme.muted)));
    let arrow = trend_arrow(metrics);
    secondary.push(Span::styled(
        arrow.0.to_string(),
        Style::default().fg(arrow.1.unwrap_or(theme.muted)),
    ));
    lines.push(Line::from(secondary));

    // Auto-tuning hint on a separate line if applicable.
    if let Some(hint) = auto_tune_hint(metrics) {
        lines.push(Line::from(vec![
            Span::raw("  "),
            Span::styled("hint ", Style::default().fg(theme.muted)),
            Span::styled(hint, Style::default().fg(theme.warn)),
        ]));
    }

    let in_celebration = ui
        .celebrate_until
        .map(|t| Instant::now() < t)
        .unwrap_or(false);
    let border_style = if in_celebration {
        Style::default().fg(theme.accent).add_modifier(Modifier::BOLD)
    } else {
        Style::default().fg(theme.border)
    };

    let block = Block::default()
        .borders(Borders::ALL)
        .border_type(BorderType::Rounded)
        .border_style(border_style)
        .title(Span::styled(
            " HASHRATE ",
            Style::default().fg(theme.muted).add_modifier(Modifier::BOLD),
        ));

    let inner = block.inner(area);
    f.render_widget(block, area);

    // Split the inner: left ~= text lines, right ~= sparkline.
    let split = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Min(20), Constraint::Length(28)])
        .split(inner);

    let p = Paragraph::new(lines).style(Style::default().fg(theme.body));
    f.render_widget(p, split[0]);

    // Sparkline on the right, full panel height.
    let samples: Vec<u64> = metrics.hashrate_samples();
    if !samples.is_empty() {
        let spark = Sparkline::default()
            .data(&samples)
            .style(Style::default().fg(theme.accent_dim))
            .bar_set(symbols::bar::NINE_LEVELS);
        f.render_widget(spark, split[1]);
    }
}

fn trend_arrow(metrics: &MetricsState) -> (char, Option<ratatui::style::Color>) {
    let samples = metrics.hashrate_samples();
    if samples.len() < 4 {
        return ('—', None);
    }
    let half = samples.len() / 2;
    let early: u64 = samples[..half].iter().sum::<u64>() / (half as u64).max(1);
    let late: u64 = samples[half..].iter().sum::<u64>() / ((samples.len() - half) as u64).max(1);
    if late > early + (early / 20) {
        ('▲', None)
    } else if early > late + (early / 20) {
        ('▼', None)
    } else {
        ('—', None)
    }
}

fn auto_tune_hint(metrics: &MetricsState) -> Option<String> {
    let threads = metrics.threads.load(Ordering::Relaxed);
    let cores = std::thread::available_parallelism()
        .map(|n| n.get() as u64)
        .unwrap_or(1);
    if threads == 0 || cores <= threads {
        return None;
    }
    // Suggest only if we're using less than half the available cores.
    if threads * 2 <= cores {
        Some(format!("try `--threads {}` ({} cores idle)", cores, cores - threads))
    } else {
        None
    }
}

// ─── Stat cards ──────────────────────────────────────────────────────

fn draw_stat_cards(f: &mut Frame, area: Rect, metrics: &MetricsState, theme: &Theme) {
    let height = metrics.current_template_height.load(Ordering::Relaxed);
    let found = metrics.blocks_accepted_total.load(Ordering::Relaxed);
    let rejected = metrics.blocks_rejected_total.load(Ordering::Relaxed);
    let accept_pct = if found + rejected == 0 {
        100.0
    } else {
        (found as f64 / (found + rejected) as f64) * 100.0
    };
    // Earned = blocks × testnet block reward (placeholder 1.0 CYNC/block;
    // the real number comes from the daemon's emission curve. Showing
    // approximate is fine for a dashboard celebration counter — it's
    // never authoritative state.)
    let earned_cync = found as f64 * 1.0;
    let uptime = uptime_seconds(metrics);

    let cells = [
        ("HEIGHT", format!("{}", height)),
        ("FOUND", format!("{}", found)),
        ("ACCEPT", format!("{:.1}%", accept_pct)),
        ("EARNED", format!("{:.0} CYNC", earned_cync)),
        ("UPTIME", format_duration(uptime)),
    ];

    let cols = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Ratio(1, 5),
            Constraint::Ratio(1, 5),
            Constraint::Ratio(1, 5),
            Constraint::Ratio(1, 5),
            Constraint::Ratio(1, 5),
        ])
        .split(area);

    for (i, (label, value)) in cells.iter().enumerate() {
        let block = Block::default()
            .borders(Borders::ALL)
            .border_type(BorderType::Rounded)
            .border_style(Style::default().fg(theme.border))
            .title(Span::styled(
                format!(" {} ", label),
                Style::default().fg(theme.muted),
            ));
        let inner = block.inner(cols[i]);
        f.render_widget(block, cols[i]);
        let p = Paragraph::new(Line::from(Span::styled(
            value.clone(),
            Style::default().fg(theme.accent).add_modifier(Modifier::BOLD),
        )))
        .alignment(Alignment::Center);
        // Vertical center hack: render with an empty top line.
        let centered = Layout::default()
            .direction(Direction::Vertical)
            .constraints([Constraint::Length(0), Constraint::Min(1)])
            .split(inner);
        f.render_widget(p, centered[1]);
    }
}

// ─── Worker-thread heatmap ───────────────────────────────────────────

/// Render a one-line heatmap strip showing each worker thread's current
/// hashrate as a colored block. Cool blue cells = thread is throttled
/// (lower H/s than its peers); hot accent cells = thread is running at
/// full speed. Surfaces single-core thermal throttling at a glance —
/// without this, an 8-thread miner whose core 3 is downclocking looks
/// the same as a healthy miner from the aggregate hashrate alone.
fn draw_worker_heatmap(f: &mut Frame, area: Rect, metrics: &MetricsState, theme: &Theme) {
    let samples = metrics.per_thread_hashrate_samples();
    if samples.is_empty() {
        return;
    }
    let max_hps = *samples.iter().max().unwrap_or(&1).max(&1);

    // Each thread takes one cell. Cell width scales to fit the row.
    // We use the unicode "full block" character to draw the cell,
    // colored by relative hashrate. The label "WORKERS" sits left of
    // the strip for visual anchoring.
    let n_threads = samples.len();
    let label_text = format!(" WORKERS×{} ", n_threads);

    // Approximate cell width: divide the remaining row width by the
    // thread count, floored at 2 chars and capped at 4.
    let avail = (area.width as usize).saturating_sub(label_text.chars().count() + 2);
    let per_cell = (avail / n_threads).clamp(2, 4);

    let mut spans: Vec<Span> = Vec::with_capacity(n_threads + 2);
    spans.push(Span::styled(label_text, Style::default().fg(theme.muted)));
    for &hps in &samples {
        // Map hashrate to a discrete intensity 0..=4. Bottom 20% =
        // throttled (cool), top 20% = full-speed (hot accent), middle
        // graded between.
        let ratio = hps as f64 / max_hps as f64;
        let intensity = (ratio * 4.0).round() as u8;
        let color = match intensity {
            0 => theme.danger,    // throttled or stuck
            1 => theme.warn,      // below average
            2 => theme.muted,     // average
            3 => theme.accent_dim,// above average
            _ => theme.accent,    // full speed
        };
        let cell: String = std::iter::repeat('▆').take(per_cell).collect();
        spans.push(Span::styled(cell, Style::default().fg(color).add_modifier(Modifier::BOLD)));
        spans.push(Span::raw(" "));
    }
    let p = Paragraph::new(Line::from(spans));
    f.render_widget(p, area);
}

// ─── Next-block ETA gauge ────────────────────────────────────────────

fn draw_eta_gauge(f: &mut Frame, area: Rect, metrics: &MetricsState, theme: &Theme, ui: &UiState) {
    // Anchor the elapsed-since-last-find at the most recent block-find
    // timestamp; if no blocks yet, anchor at session start. Compared to
    // testnet target block time (120 s) as the expected window.
    const EXPECTED_SECS: u64 = 120;
    let now = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let last_find = metrics
        .recent_block_finds(now)
        .last()
        .copied()
        .unwrap_or(metrics.started_unix_seconds);
    let elapsed = now.saturating_sub(last_find).min(EXPECTED_SECS * 4);
    let pct = (elapsed as u16 * 100 / EXPECTED_SECS as u16).min(100);
    let phase = (ui.started.elapsed().as_millis() / 100) as usize % SPINNER.len();
    let spinner = SPINNER[phase];

    let label = if pct >= 100 {
        format!("{} looking… overdue", spinner)
    } else {
        format!("{} searching · ~{}s expected", spinner, EXPECTED_SECS - elapsed)
    };

    let gauge = Gauge::default()
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_type(BorderType::Rounded)
                .border_style(Style::default().fg(theme.border))
                .title(Span::styled(
                    " NEXT BLOCK ETA ",
                    Style::default().fg(theme.muted).add_modifier(Modifier::BOLD),
                )),
        )
        .gauge_style(Style::default().fg(theme.accent).bg(theme.accent_dim))
        .percent(pct)
        .label(Span::styled(
            label,
            Style::default().fg(theme.body).add_modifier(Modifier::BOLD),
        ));
    f.render_widget(gauge, area);
}

// ─── Log scrollback ──────────────────────────────────────────────────

fn draw_logs(f: &mut Frame, area: Rect, logs: &VecDeque<String>, theme: &Theme) {
    let visible = (area.height as usize).saturating_sub(2);
    let start = logs.len().saturating_sub(visible);
    let items: Vec<ListItem> = logs
        .iter()
        .skip(start)
        .map(|l| {
            let level = l.split_whitespace().next().unwrap_or("");
            let (glyph, color) = match level {
                "ERROR" => ('✗', theme.danger),
                "WARN" => ('▲', theme.warn),
                "INFO" => ('◉', theme.accent),
                "DEBUG" => ('◌', theme.muted),
                "TRACE" => ('·', theme.muted),
                _ => (' ', theme.body),
            };
            let rest = l.get(level.len()..).unwrap_or("").trim_start();
            ListItem::new(Line::from(vec![
                Span::styled(format!(" {} ", glyph), Style::default().fg(color).add_modifier(Modifier::BOLD)),
                Span::styled(level.to_string(), Style::default().fg(color)),
                Span::raw("  "),
                Span::styled(rest.to_string(), Style::default().fg(theme.body)),
            ]))
        })
        .collect();

    let list = List::new(items).block(
        Block::default()
            .borders(Borders::ALL)
            .border_type(BorderType::Rounded)
            .border_style(Style::default().fg(theme.border))
            .title(Span::styled(
                " LOG ",
                Style::default().fg(theme.muted).add_modifier(Modifier::BOLD),
            )),
    );
    f.render_widget(list, area);
}

// ─── Found-blocks 24h timeline + scrolling CYNC ticker ───────────────

fn draw_blocks_timeline_and_ticker(
    f: &mut Frame,
    area: Rect,
    metrics: &MetricsState,
    theme: &Theme,
    ui: &UiState,
) {
    let split = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(1), Constraint::Length(1)])
        .split(area);

    // Timeline — last 24h as gold pips on a horizontal ruler. Each
    // column = 1 hour; bucket count of finds drives the glyph.
    let now = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let finds = metrics.recent_block_finds(now);
    let mut buckets = [0u32; 24];
    for &t in &finds {
        let hours_ago = (now.saturating_sub(t) / 3600) as usize;
        if hours_ago < 24 {
            buckets[23 - hours_ago] += 1;
        }
    }
    let bucket_glyphs: Vec<Span> = buckets
        .iter()
        .map(|&n| {
            let g = match n {
                0 => '·',
                1 => '▁',
                2 => '▃',
                3 => '▅',
                _ => '▇',
            };
            let color = if n == 0 { theme.muted } else { theme.accent };
            Span::styled(format!("{}", g), Style::default().fg(color))
        })
        .collect();
    let mut row1 = vec![Span::styled(
        " 24h ",
        Style::default().fg(theme.muted),
    )];
    row1.extend(bucket_glyphs);
    row1.push(Span::raw(" "));
    row1.push(Span::styled(
        format!("({} blocks today)", finds.len()),
        Style::default().fg(theme.muted),
    ));
    f.render_widget(Paragraph::new(Line::from(row1)), split[0]);

    // Ticker — slowly scrolling stat line. Compose from current state.
    let height = metrics.current_template_height.load(Ordering::Relaxed);
    let net = metrics.network_hashrate_hps.load(Ordering::Relaxed);
    let mine = metrics.current_hashrate_hps.load(Ordering::Relaxed);
    let share = if net > 0 {
        format!("{:.1}%", (mine as f64 / net as f64) * 100.0)
    } else {
        "—".into()
    };
    let mining_status = if metrics.paused.load(Ordering::Relaxed) {
        "PAUSED"
    } else {
        "MINING"
    };
    let raw = format!(
        "  ◉ {} · tip h{} · net {} · share {} · 0% dev fee · no telemetry · home miner · cyncthub.xyz   ",
        mining_status, height, fmt_hps(net), share,
    );
    // Scroll by area.width per frame; cycle the string.
    let scroll = (ui.started.elapsed().as_millis() / 200) as usize % raw.chars().count().max(1);
    let visible_w = split[1].width as usize;
    let chars: Vec<char> = raw.chars().chain(raw.chars()).chain(raw.chars()).collect();
    let view: String = chars
        .into_iter()
        .skip(scroll)
        .take(visible_w)
        .collect();
    let p = Paragraph::new(Line::from(Span::styled(
        view,
        Style::default().fg(theme.muted),
    )));
    f.render_widget(p, split[1]);
}

fn fmt_hps(h: u64) -> String {
    let (n, u) = bf::format_hashrate(h);
    format!("{} {}", n, u)
}

// ─── Footer ──────────────────────────────────────────────────────────

fn draw_footer(f: &mut Frame, area: Rect, theme: &Theme, metrics: &MetricsState) {
    let key = |k: &str| Span::styled(k.to_string(), Style::default().fg(theme.accent).add_modifier(Modifier::BOLD));
    let txt = |t: &str| Span::styled(t.to_string(), Style::default().fg(theme.muted));
    let theme_name = THEMES.iter().enumerate()
        .find(|(_, t)| std::ptr::eq(*t as *const _, theme as *const _))
        .map(|(_, t)| t.name)
        .unwrap_or("Brass");
    let pause_label = if metrics.paused.load(Ordering::Relaxed) { "resume" } else { "pause" };
    let line = Line::from(vec![
        Span::raw(" "),
        key("q"), txt(" quit  "),
        key("t"), txt(&format!(" theme · {}  ", theme_name)),
        key("p"), txt(&format!(" {}  ", pause_label)),
        key("l"), txt(" log  "),
        key("?"), txt(" help  "),
        key("c"), txt(" snapshot"),
    ]);
    f.render_widget(Paragraph::new(line), area);
}

// ─── Splash screen ───────────────────────────────────────────────────

fn draw_splash(f: &mut Frame, ui: &UiState) {
    let theme = ui.theme();
    let elapsed = ui.started.elapsed().as_secs_f32();
    let total = SPLASH_SECS;
    let progress = (elapsed / total).clamp(0.0, 1.0);

    // Typewriter the brand mark. 9 chars of `COINCYNC `; reveal one
    // char per ~250ms.
    let chars: Vec<char> = "COINCYNC".chars().collect();
    let visible = ((progress * chars.len() as f32) as usize).min(chars.len());
    let revealed: String = chars.iter().take(visible).collect();
    let pending: String = chars.iter().skip(visible).map(|_| ' ').collect();

    let area = f.area();
    let v_pad = (area.height.saturating_sub(7)) / 2;
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(v_pad),
            Constraint::Length(3),
            Constraint::Length(1),
            Constraint::Length(1),
            Constraint::Length(1),
            Constraint::Min(0),
        ])
        .split(area);

    let mark = Paragraph::new(Line::from(Span::styled(
        format!("{}{}", revealed, pending),
        Style::default().fg(theme.accent).add_modifier(Modifier::BOLD),
    )))
    .alignment(Alignment::Center);
    f.render_widget(mark, chunks[1]);

    let tagline = Paragraph::new(Line::from(Span::styled(
        "rig",
        Style::default().fg(theme.muted),
    )))
    .alignment(Alignment::Center);
    f.render_widget(tagline, chunks[2]);

    let sub = Paragraph::new(Line::from(Span::styled(
        "no donation · no telemetry · no surprises",
        Style::default().fg(theme.muted),
    )))
    .alignment(Alignment::Center);
    f.render_widget(sub, chunks[4]);
}

// ─── Help modal ──────────────────────────────────────────────────────

fn draw_help_modal(f: &mut Frame, theme: &Theme) {
    let area = f.area();
    let w = 56.min(area.width.saturating_sub(4));
    let h = 14.min(area.height.saturating_sub(4));
    let x = (area.width.saturating_sub(w)) / 2;
    let y = (area.height.saturating_sub(h)) / 2;
    let modal = Rect { x, y, width: w, height: h };

    f.render_widget(Clear, modal);

    let block = Block::default()
        .borders(Borders::ALL)
        .border_type(BorderType::Rounded)
        .border_style(Style::default().fg(theme.accent))
        .title(Span::styled(
            " HELP ",
            Style::default().fg(theme.accent).add_modifier(Modifier::BOLD),
        ));
    let inner = block.inner(modal);
    f.render_widget(block, modal);

    let row = |k: &'static str, v: &'static str| {
        Line::from(vec![
            Span::raw("  "),
            Span::styled(k, Style::default().fg(theme.accent).add_modifier(Modifier::BOLD)),
            Span::raw(format!("  {}", v)),
        ])
    };
    let lines = vec![
        Line::from(""),
        row("q / Esc", "quit (prints session summary)"),
        row("t      ", "cycle theme · Brass / Moon / Mono"),
        row("p      ", "pause / resume mining"),
        row("l      ", "toggle log pane"),
        row("c      ", "snapshot dashboard to /tmp"),
        row("?      ", "this help"),
        Line::from(""),
        Line::from(vec![
            Span::raw("  "),
            Span::styled("0% dev fee · no telemetry · home miner", Style::default().fg(theme.muted)),
        ]),
    ];
    f.render_widget(
        Paragraph::new(lines)
            .style(Style::default().fg(theme.body))
            .wrap(Wrap { trim: false }),
        inner,
    );
}

// ─── Snapshot to tmpfile ─────────────────────────────────────────────

fn snapshot_to_tmpfile(metrics: &MetricsState) {
    let now = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let uptime = uptime_seconds(metrics);
    let hps = metrics.current_hashrate_hps.load(Ordering::Relaxed);
    let height = metrics.current_template_height.load(Ordering::Relaxed);
    let found = metrics.blocks_accepted_total.load(Ordering::Relaxed);
    let threads = metrics.threads.load(Ordering::Relaxed);
    let body = format!(
        "coincync-rig snapshot @ {}\n\
         uptime    {}\n\
         hashrate  {} ({} threads)\n\
         tip       h{}\n\
         blocks    {}\n\
         no telemetry · 0% dev fee\n",
        now,
        format_duration(uptime),
        fmt_hps(hps),
        threads,
        height,
        found,
    );
    let dir = std::env::temp_dir();
    let path = dir.join(format!("coincync-rig-{}.txt", now));
    let _ = std::fs::write(&path, body);
    tracing::info!(path = %path.display(), "snapshot saved");
}

// ─── Session summary ─────────────────────────────────────────────────

fn print_session_summary(metrics: &MetricsState) {
    let uptime = uptime_seconds(metrics);
    let found = metrics.blocks_accepted_total.load(Ordering::Relaxed);
    let samples = metrics.hashrate_samples();
    let avg_hps: u64 = if samples.is_empty() {
        metrics.current_hashrate_hps.load(Ordering::Relaxed)
    } else {
        samples.iter().sum::<u64>() / samples.len() as u64
    };
    let earned = found as f64 * 1.0;
    eprintln!();
    eprintln!("─── coincync-rig session summary ─────────────────────");
    eprintln!("  mined for     {}", format_duration(uptime));
    eprintln!("  avg hashrate  {}", fmt_hps(avg_hps));
    eprintln!("  blocks found  {}", found);
    eprintln!("  earned        ~{:.0} CYNC", earned);
    eprintln!("  status        no telemetry · 0% dev fee · come back soon");
    eprintln!();
}

fn uptime_seconds(metrics: &MetricsState) -> u64 {
    let now = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(metrics.started_unix_seconds);
    now.saturating_sub(metrics.started_unix_seconds)
}

fn format_duration(secs: u64) -> String {
    let h = secs / 3600;
    let m = (secs % 3600) / 60;
    let s = secs % 60;
    if h > 0 {
        format!("{:02}:{:02}:{:02}", h, m, s)
    } else {
        format!("{:02}:{:02}", m, s)
    }
}

// ─── Tiny scope-guard ────────────────────────────────────────────────
// Avoids pulling in the `scopeguard` crate just for this; same idea, ten
// lines.

fn scopeguard_call_on_drop<F: FnOnce()>(f: F) -> impl Drop {
    struct Guard<F: FnOnce()>(Option<F>);
    impl<F: FnOnce()> Drop for Guard<F> {
        fn drop(&mut self) {
            if let Some(f) = self.0.take() {
                f();
            }
        }
    }
    Guard(Some(f))
}
