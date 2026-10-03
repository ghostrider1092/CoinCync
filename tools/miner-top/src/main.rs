//! coincync miner-top — a btop-style RandomX miner dashboard.
//!
//! DEMO (no flags):   cargo run --release
//!   built-in simulator; keys: space pause · b block · q/Esc quit
//!
//! REAL (solo mining):
//!   miner-top --rig http://127.0.0.1:9109/metrics --node http://127.0.0.1:28081 \
//!             --address <payout> [--reward <CYNC-per-block>] [--threads 8]
//!   fills the dashboard from the rig's /metrics + the node's get_info each
//!   round; keys: q/Esc quit. Read-only.

use std::io;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use coincync_miner_top::feed;
use coincync_miner_top::miner::Miner;
use coincync_miner_top::ui::draw;
use ratatui::crossterm::event::{self, Event, KeyCode, KeyEventKind};

fn hms() -> String {
    let secs = SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0);
    let d = secs % 86_400;
    format!("{:02}:{:02}:{:02}", d / 3600, (d % 3600) / 60, d % 60)
}

struct Args {
    rig: Option<String>,
    node: Option<String>,
    address: String,
    reward: f64,
    threads: usize,
    port: u16,
    interval: u64,
    tick: Option<String>,
    tick_token: String,
}

fn parse_args() -> Args {
    let mut a = Args {
        rig: None,
        node: None,
        address: String::new(),
        reward: 0.0,
        threads: 8,
        port: 9110,
        interval: 3,
        tick: None,
        tick_token: std::env::var("COINCYNC_TICK_MAINTAINER_TOKEN").unwrap_or_default(),
    };
    let mut it = std::env::args().skip(1);
    while let Some(flag) = it.next() {
        match flag.as_str() {
            "--rig" => a.rig = it.next(),
            "--node" => a.node = it.next(),
            "--address" => a.address = it.next().unwrap_or_default(),
            "--reward" => a.reward = it.next().and_then(|v| v.parse().ok()).unwrap_or(0.0),
            "--threads" => a.threads = it.next().and_then(|v| v.parse().ok()).unwrap_or(8),
            "--port" => a.port = it.next().and_then(|v| v.parse().ok()).unwrap_or(9110),
            "--interval" => a.interval = it.next().and_then(|v| v.parse().ok()).unwrap_or(3),
            // Maintainer colony view: --tick <sidecar-origin> + --tick-token <token>
            // (token also read from COINCYNC_TICK_MAINTAINER_TOKEN).
            "--tick" => a.tick = it.next(),
            "--tick-token" => a.tick_token = it.next().unwrap_or_default(),
            _ => {}
        }
    }
    a
}

/// `http://host:port/path` → `host:port` for the "via solo @ …" line.
fn host_of(url: &str) -> String {
    url.trim_start_matches("http://")
        .trim_start_matches("https://")
        .split('/')
        .next()
        .unwrap_or(url)
        .to_string()
}

fn main() -> io::Result<()> {
    let args = parse_args();

    // `miner-top serve` → run the local web bridge (serves the dashboard + a live
    // /data endpoint from the real rig/node) instead of the terminal UI.
    if std::env::args().nth(1).as_deref() == Some("serve") {
        let (rig, node) = match (args.rig.clone(), args.node.clone()) {
            (Some(r), Some(n)) => (r, n),
            _ => {
                eprintln!(
                    "usage: miner-top serve --rig <metrics-url> --node <rpc-url> \
                     [--address <payout>] [--reward <cync>] [--port 9110] [--interval 3]"
                );
                std::process::exit(2);
            }
        };
        return coincync_miner_top::serve::serve(
            args.port,
            rig,
            node,
            args.address,
            args.reward,
            args.interval,
            args.tick,
            args.tick_token,
        );
    }

    let real = match (&args.rig, &args.node) {
        (Some(rig), Some(node)) => Some((rig.clone(), node.clone())),
        _ => None,
    };

    let mut terminal = ratatui::init();
    let mut miner = Miner::new("rig-01", args.threads);

    if let Some((ref rig, ref node)) = real {
        miner.address = args.address.clone();
        miner.connection = format!("solo @ {}", host_of(node));
        let d = feed::poll(rig, node);
        miner.apply_real(&d, args.reward, hms());
    } else {
        miner.simulate(hms());
    }

    // Real mode polls two endpoints per round, so a gentler cadence.
    let tick_every = Duration::from_millis(if real.is_some() { 2000 } else { 1000 });
    let mut last = Instant::now();

    let res = loop {
        if let Err(e) = terminal.draw(|f| draw(f, &miner)) { break Err(e); }
        let timeout = tick_every.saturating_sub(last.elapsed());
        match event::poll(timeout) {
            Ok(true) => match event::read() {
                Ok(Event::Key(k)) if k.kind == KeyEventKind::Press => match k.code {
                    KeyCode::Char('q') | KeyCode::Esc => break Ok(()),
                    // Demo-only keys — disabled in real mode (they'd desync
                    // from live data).
                    KeyCode::Char(' ') if real.is_none() => miner.toggle_pause(),
                    KeyCode::Char('b') if real.is_none() => miner.force_block(hms()),
                    _ => {}
                },
                Ok(_) => {}
                Err(e) => break Err(e),
            },
            Ok(false) => {}
            Err(e) => break Err(e),
        }
        if last.elapsed() >= tick_every {
            match &real {
                Some((rig, node)) => {
                    let d = feed::poll(rig, node);
                    miner.apply_real(&d, args.reward, hms());
                }
                None => miner.simulate(hms()),
            }
            last = Instant::now();
        }
    };

    ratatui::restore();
    res
}
