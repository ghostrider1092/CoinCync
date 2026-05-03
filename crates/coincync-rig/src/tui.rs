//! Optional ratatui dashboard for `run-solo` (`--tui`).
//!
//! Layout:
//!   ┌─ coincync-rig ─────────────────────────────────────────┐
//!   │ height 1867   hashrate 54 H/s   blocks 236   threads 1 │
//!   │ uptime 02:14:08                                        │
//!   ├────────────────────────────────────────────────────────┤
//!   │ 22:44:42  INFO orchestrator: solo mining loop starting │
//!   │ 22:44:42  INFO RandomX VM created in 0.41s             │
//!   │ ...                                                    │
//!   └─ q / esc to quit ──────────────────────────────────────┘
//!
//! The TUI shares the metrics module's `MetricsState` for the stats bar
//! (so headless `--metrics-port` and interactive `--tui` always agree on
//! what's happening) and captures tracing events via a custom layer that
//! forwards each event as a formatted string into a channel the render
//! loop drains every frame.
//!
//! Quit via `q`, `Q`, or `Esc`. The render loop calls `process::exit(0)`
//! after restoring the terminal — the orchestrator has no cancel hook
//! and we don't need a graceful one for an interactive miner.

use std::collections::VecDeque;
use std::io;
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::sync::mpsc::{Receiver, Sender, channel};
use std::time::{Duration, SystemTime};

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
    widgets::{Block, Borders, List, ListItem, Paragraph},
    Frame, Terminal,
};
use tracing::field::Field;
use tracing_subscriber::Layer;

use crate::metrics::MetricsState;

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

    // Make sure we always restore the terminal on panic — leaving raw
    // mode + alt-screen on means the user's shell becomes unusable.
    let restore = || {
        let _ = disable_raw_mode();
        let mut stdout = io::stdout();
        let _ = execute!(stdout, LeaveAlternateScreen);
    };
    let _guard = scopeguard_call_on_drop(restore);

    let mut log_buffer: VecDeque<String> = VecDeque::with_capacity(MAX_LOG_LINES);

    loop {
        // Drain incoming log events into the scrollback.
        while let Ok(line) = log_rx.try_recv() {
            if log_buffer.len() >= MAX_LOG_LINES {
                log_buffer.pop_front();
            }
            log_buffer.push_back(line);
        }

        terminal.draw(|f| draw(f, &metrics, &log_buffer))?;

        // Poll input with a short timeout so the stats bar refreshes
        // even when no keys are pressed.
        if event::poll(Duration::from_millis(250))? {
            if let Event::Key(key) = event::read()? {
                let quit = matches!(key.code, KeyCode::Char('q') | KeyCode::Char('Q') | KeyCode::Esc);
                if quit {
                    break;
                }
            }
        }
    }

    Ok(())
}

fn draw(f: &mut Frame, metrics: &MetricsState, logs: &VecDeque<String>) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(4), // stats panel (border + 2 lines + border)
            Constraint::Min(0),    // log scrollback
            Constraint::Length(1), // footer
        ])
        .split(f.area());

    draw_stats(f, chunks[0], metrics);
    draw_logs(f, chunks[1], logs);
    draw_footer(f, chunks[2]);
}

fn draw_stats(f: &mut Frame, area: Rect, metrics: &MetricsState) {
    let height = metrics.current_template_height.load(Ordering::Relaxed);
    let hps = metrics.current_hashrate_hps.load(Ordering::Relaxed);
    let blocks_accepted = metrics.blocks_accepted_total.load(Ordering::Relaxed);
    let blocks_rejected = metrics.blocks_rejected_total.load(Ordering::Relaxed);
    let threads = metrics.threads.load(Ordering::Relaxed);
    let uptime = uptime_seconds(metrics);

    let label = Style::default().fg(Color::Gray);
    let value = Style::default()
        .fg(Color::Yellow)
        .add_modifier(Modifier::BOLD);

    let row1 = Line::from(vec![
        Span::styled("height ", label),
        Span::styled(format!("{:>5}", height), value),
        Span::raw("    "),
        Span::styled("hashrate ", label),
        Span::styled(format!("{:>5} H/s", hps), value),
        Span::raw("    "),
        Span::styled("blocks ", label),
        Span::styled(format!("{}", blocks_accepted), value),
        if blocks_rejected > 0 {
            Span::styled(
                format!(" ({} rejected)", blocks_rejected),
                Style::default().fg(Color::Red),
            )
        } else {
            Span::raw("")
        },
    ]);
    let row2 = Line::from(vec![
        Span::styled("uptime ", label),
        Span::styled(format_duration(uptime), value),
        Span::raw("    "),
        Span::styled("threads ", label),
        Span::styled(format!("{}", threads), value),
    ]);

    let stats = Paragraph::new(vec![row1, row2]).block(
        Block::default()
            .borders(Borders::ALL)
            .title(Span::styled(" coincync-rig ", Style::default().fg(Color::Cyan))),
    );
    f.render_widget(stats, area);
}

fn draw_logs(f: &mut Frame, area: Rect, logs: &VecDeque<String>) {
    let visible = (area.height as usize).saturating_sub(2); // borders
    let start = logs.len().saturating_sub(visible);
    let items: Vec<ListItem> = logs
        .iter()
        .skip(start)
        .map(|l| {
            // Color the level token at the start of the line.
            let level = l.split_whitespace().next().unwrap_or("");
            let style = match level {
                "ERROR" => Style::default().fg(Color::Red),
                "WARN" => Style::default().fg(Color::Yellow),
                "INFO" => Style::default().fg(Color::Green),
                "DEBUG" => Style::default().fg(Color::Gray),
                "TRACE" => Style::default().fg(Color::DarkGray),
                _ => Style::default(),
            };
            let rest = l.get(level.len()..).unwrap_or("");
            ListItem::new(Line::from(vec![
                Span::styled(level.to_string(), style),
                Span::raw(rest.to_string()),
            ]))
        })
        .collect();

    let list = List::new(items).block(
        Block::default()
            .borders(Borders::ALL)
            .title(Span::styled(" log ", Style::default().fg(Color::Cyan))),
    );
    f.render_widget(list, area);
}

fn draw_footer(f: &mut Frame, area: Rect) {
    let footer = Paragraph::new(Line::from(vec![
        Span::styled("q", Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)),
        Span::raw(" / "),
        Span::styled("esc", Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)),
        Span::raw(" to quit"),
    ]));
    f.render_widget(footer, area);
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
