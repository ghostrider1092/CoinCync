//! cytop — a from-scratch, btop-architecture system + CoinCync node monitor.
//!
//! Modules: `theme` (btop `.theme` parser + 101-step gradients), `collect`
//! (node RPC + log tailer), `draw` (themed primitives), `app` (state/tick),
//! `ui` (panels/layout). This file is just the CLI and the event loop.

mod app;
mod collect;
mod draw;
mod theme;
mod ui;

use std::time::{Duration, Instant};

use clap::Parser;
use crossterm::event::{self, Event, KeyCode, KeyModifiers};

use crate::app::App;
use crate::theme::Theme;

#[derive(Parser)]
#[command(name = "cytop", about = "btop-architecture system + CoinCync node monitor")]
struct Cli {
    /// Node RPC URL to poll (chain/mining/peers).
    #[arg(long, default_value = "http://127.0.0.1:28121")]
    rpc: String,
    /// Refresh interval, milliseconds.
    #[arg(long, default_value_t = 1000)]
    refresh_ms: u64,
    /// Tail this node log file into the chain-activity feed.
    #[arg(long)]
    log: Option<String>,
    /// Load a btop `.theme` file (falls back to the built-in Default theme).
    #[arg(long)]
    theme: Option<String>,
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    let theme = match &cli.theme {
        Some(path) => match std::fs::read_to_string(path) {
            Ok(text) => Theme::from_str(&text),
            Err(e) => {
                eprintln!("warning: could not read theme '{path}': {e}; using Default");
                Theme::default_theme()
            }
        },
        None => Theme::default_theme(),
    };

    let mut app = App::new(cli.rpc.clone(), cli.log.clone(), theme);
    let refresh = Duration::from_millis(cli.refresh_ms.max(200));

    let mut terminal = ratatui::init();
    app.tick();
    let res = run(&mut terminal, &mut app, refresh);
    ratatui::restore();
    res
}

fn run(terminal: &mut ratatui::DefaultTerminal, app: &mut App, refresh: Duration) -> anyhow::Result<()> {
    loop {
        terminal.draw(|f| ui::draw(f, app))?;

        if event::poll(Duration::from_millis(200))? {
            if let Event::Key(k) = event::read()? {
                match k.code {
                    KeyCode::Char('q') | KeyCode::Char('Q') | KeyCode::Esc => return Ok(()),
                    KeyCode::Char('c') if k.modifiers.contains(KeyModifiers::CONTROL) => return Ok(()),
                    KeyCode::Char(' ') => app.paused = !app.paused,
                    KeyCode::Down | KeyCode::Char('j') => app.feed_scroll(1),
                    KeyCode::Up | KeyCode::Char('k') => app.feed_scroll(-1),
                    KeyCode::PageDown => app.feed_scroll(15),
                    KeyCode::PageUp => app.feed_scroll(-15),
                    KeyCode::End | KeyCode::Char('G') => app.feed_follow = true,
                    KeyCode::Home | KeyCode::Char('g') => {
                        app.feed_follow = false;
                        app.feed_state.select(Some(0));
                    }
                    _ => {}
                }
            }
        }
        app.frame = app.frame.wrapping_add(1);
        if !app.paused {
            app.drain_log();
        }
        if !app.paused && app.last_poll.elapsed() >= refresh {
            app.tick();
            app.last_poll = Instant::now();
        }
    }
}
