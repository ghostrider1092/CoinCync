//! cytop — a from-scratch, btop-architecture system + CoinCync node monitor.
//!
//! Modules: `theme` (btop `.theme` parser + 101-step gradients), `collect`
//! (node RPC + log tailer + GPU poller), `draw` (themed primitives), `config`
//! (persistent settings), `app` (state/tick), `ui` (panels/layout).

mod app;
mod collect;
mod config;
mod draw;
mod fleet;
mod theme;
mod ui;

use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use clap::Parser;
use crossterm::event::{
    self, DisableMouseCapture, EnableMouseCapture, Event, KeyCode, KeyModifiers, MouseButton,
    MouseEventKind,
};
use crossterm::execute;

use crate::app::App;
use crate::config::{Config, DEFAULT_REFRESH_MS, DEFAULT_RPC};
use crate::theme::Theme;

#[derive(Parser)]
#[command(
    name = "cytop",
    about = "btop-architecture system + CoinCync node monitor"
)]
struct Cli {
    /// Node RPC URL to poll (overrides config; default http://127.0.0.1:28081).
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
    /// Fleet overview: watch many nodes at once. A comma list of `label=url`
    /// (or bare urls, auto-labelled n1,n2…). Bare `host` → http://host:28081.
    /// Remote nodes with loopback-bound RPC: forward them first (see
    /// scripts/fleet-tunnels.sh), then pass the 127.0.0.1:<port> urls.
    #[arg(long)]
    fleet: Option<String>,
    /// Per-node poll timeout in the fleet view, milliseconds (default 1500).
    #[arg(long)]
    fleet_timeout_ms: Option<u64>,
    /// With --fleet: poll once, print a text report, and exit 0 (healthy) / 1.
    /// A scriptable health gate; no TUI.
    #[arg(long)]
    once: bool,
    /// With --fleet --once: emit JSON instead of text.
    #[arg(long)]
    json: bool,
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    // Config: CLI > file > built-in default.
    let config_path: PathBuf = cli
        .config
        .clone()
        .map(PathBuf::from)
        .unwrap_or_else(config::default_path);
    let cfg = Config::load(&config_path);
    let rpc = cli
        .rpc
        .clone()
        .or(cfg.rpc.clone())
        .unwrap_or_else(|| DEFAULT_RPC.to_string());
    let log = cli.log.clone().or(cfg.log.clone());
    let refresh_ms = cli
        .refresh_ms
        .or(cfg.refresh_ms)
        .unwrap_or(DEFAULT_REFRESH_MS);
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

    let refresh = Duration::from_millis(refresh_ms.max(200));

    // Fleet overview mode: watch many nodes at once, no host/log panels.
    if let Some(spec) = cli.fleet.clone() {
        let targets = fleet::FleetTarget::parse_list(&spec);
        if targets.is_empty() {
            eprintln!("error: --fleet had no usable targets (expected label=url,…)");
            std::process::exit(2);
        }
        let timeout = Duration::from_millis(cli.fleet_timeout_ms.unwrap_or(1500).max(200));
        if cli.once {
            std::process::exit(fleet::run_once(&targets, timeout, cli.json));
        }
        let theme = themes[start_idx.min(themes.len().saturating_sub(1))].1.clone();
        let mut fapp = fleet::FleetApp::new(targets, theme, timeout);
        let mut terminal = ratatui::init();
        fapp.tick();
        let res = run_fleet(&mut terminal, &mut fapp, refresh);
        ratatui::restore();
        return res;
    }

    let mut app = App::new(rpc.clone(), log.clone(), themes, start_idx, file_theme);

    let mut terminal = ratatui::init();
    let _ = execute!(std::io::stdout(), EnableMouseCapture);
    app.tick();
    let res = run(&mut terminal, &mut app, refresh);
    let _ = execute!(std::io::stdout(), DisableMouseCapture);
    ratatui::restore();

    // Persist the resolved settings (incl. the theme the user ended on).
    Config::save(
        &config_path,
        &rpc,
        log.as_deref(),
        &app.config_theme(),
        refresh_ms,
    );
    res
}

fn run(
    terminal: &mut ratatui::DefaultTerminal,
    app: &mut App,
    refresh: Duration,
) -> anyhow::Result<()> {
    loop {
        terminal.draw(|f| ui::draw(f, app))?;

        if event::poll(Duration::from_millis(200))? {
            match event::read()? {
                Event::Key(k) => match k.code {
                    KeyCode::Char('q') | KeyCode::Char('Q') | KeyCode::Esc => return Ok(()),
                    KeyCode::Char('c') if k.modifiers.contains(KeyModifiers::CONTROL) => {
                        return Ok(())
                    }
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
                },
                Event::Mouse(m) => match m.kind {
                    MouseEventKind::ScrollDown => app.feed_scroll(3),
                    MouseEventKind::ScrollUp => app.feed_scroll(-3),
                    MouseEventKind::Down(MouseButton::Left) => app.click_feed(m.column, m.row),
                    _ => {}
                },
                _ => {}
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

fn run_fleet(
    terminal: &mut ratatui::DefaultTerminal,
    app: &mut fleet::FleetApp,
    refresh: Duration,
) -> anyhow::Result<()> {
    // A fleet poll fans out to every node and can take up to the per-node
    // timeout; never poll more often than once per `refresh`, but also give the
    // network a breath so a slow fleet doesn't hammer.
    let refresh = refresh.max(Duration::from_millis(750));
    loop {
        terminal.draw(|f| fleet::draw_fleet(f, app))?;

        if event::poll(Duration::from_millis(200))? {
            if let Event::Key(k) = event::read()? {
                match k.code {
                    KeyCode::Char('q') | KeyCode::Char('Q') | KeyCode::Esc => return Ok(()),
                    KeyCode::Char('c') if k.modifiers.contains(KeyModifiers::CONTROL) => {
                        return Ok(())
                    }
                    KeyCode::Char(' ') => app.paused = !app.paused,
                    KeyCode::Char('r') | KeyCode::Char('R') => {
                        app.tick();
                        app.last_poll = Instant::now();
                    }
                    _ => {}
                }
            }
        }
        app.frame = app.frame.wrapping_add(1);
        if !app.paused && app.last_poll.elapsed() >= refresh {
            app.tick();
            app.last_poll = Instant::now();
        }
    }
}
