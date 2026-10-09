//! cytop — a from-scratch, btop-architecture system + CoinCync node monitor.
//!
//! Modules: `theme` (btop `.theme` parser + 101-step gradients), `collect`
//! (node RPC + log tailer + GPU poller), `draw` (themed primitives), `config`
//! (persistent settings), `app` (state/tick), `ui` (panels/layout).

mod app;
mod collect;
mod config;
mod draw;
mod theme;
mod ui;

use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use clap::Parser;
use crossterm::event::{self, Event, KeyCode, KeyModifiers};

use crate::app::App;
use crate::config::{Config, DEFAULT_REFRESH_MS, DEFAULT_RPC};
use crate::theme::Theme;

#[derive(Parser)]
#[command(name = "cytop", about = "btop-architecture system + CoinCync node monitor")]
struct Cli {
    /// Node RPC URL to poll (overrides config; default http://127.0.0.1:28121).
    #[arg(long)]
    rpc: Option<String>,
    /// Refresh interval, milliseconds (overrides config; default 1000).
    #[arg(long)]
    refresh_ms: Option<u64>,
    /// Tail this node log file into the chain-activity feed.
    #[arg(long)]
    log: Option<String>,
    /// A btop `.theme` file path, or a built-in name (default/coincync/matrix/amber/mono).
    #[arg(long)]
    theme: Option<String>,
    /// Config file path (default: %APPDATA%/cytop/cytop.conf or ~/.config/cytop/cytop.conf).
    #[arg(long)]
    config: Option<String>,
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    // Config: CLI > file > built-in default.
    let config_path: PathBuf = cli.config.clone().map(PathBuf::from).unwrap_or_else(config::default_path);
    let cfg = Config::load(&config_path);
    let rpc = cli.rpc.clone().or(cfg.rpc.clone()).unwrap_or_else(|| DEFAULT_RPC.to_string());
    let log = cli.log.clone().or(cfg.log.clone());
    let refresh_ms = cli.refresh_ms.or(cfg.refresh_ms).unwrap_or(DEFAULT_REFRESH_MS);
    let theme_arg = cli.theme.clone().or(cfg.theme.clone());

    // Themes: built-ins, plus a file theme (path) inserted first, or select a
    // built-in by name.
    let mut themes = theme::builtins();
    let mut start_idx = 0;
    let mut file_theme = None;
    if let Some(s) = &theme_arg {
        if Path::new(s).is_file() {
            match std::fs::read_to_string(s) {
                Ok(text) => {
                    let name = Path::new(s)
                        .file_stem()
                        .map(|x| x.to_string_lossy().into_owned())
                        .unwrap_or_else(|| "custom".into());
                    themes.insert(0, (name, Theme::from_str(&text)));
                    start_idx = 0;
                    file_theme = Some((0usize, s.clone()));
                }
                Err(e) => eprintln!("warning: could not read theme '{s}': {e}; using Default"),
            }
        } else if let Some(i) = themes.iter().position(|(n, _)| n == s) {
            start_idx = i;
        } else {
            eprintln!("warning: unknown theme '{s}'; using Default");
        }
    }

    let mut app = App::new(rpc.clone(), log.clone(), themes, start_idx, file_theme);
    let refresh = Duration::from_millis(refresh_ms.max(200));

    let mut terminal = ratatui::init();
    app.tick();
    let res = run(&mut terminal, &mut app, refresh);
    ratatui::restore();

    // Persist the resolved settings (incl. the theme the user ended on).
    Config::save(&config_path, &rpc, log.as_deref(), &app.config_theme(), refresh_ms);
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
                    KeyCode::Char('t') | KeyCode::Char('T') => app.next_theme(),
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
