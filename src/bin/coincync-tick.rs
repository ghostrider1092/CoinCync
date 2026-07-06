//! `coincync-tick` — read-only health-monitoring sidecar for a coincync-node.
//!
//! ## What this is
//!
//! A standalone process that watches a local `coincync-node` over RPC and
//! reports host + node health on an interval. This is the **HealthTick**
//! role of the tick framework: passive observation, never intervention.
//!
//! It runs as a **separate process** on purpose (see the tick design):
//! a bug, panic, or hang here **cannot crash or wedge the node**. It only
//! reads — the local node's `get_info` RPC plus this host's `/proc` — and
//! never writes chain state, never feeds peers, never touches consensus.
//!
//! ## What is deliberately NOT here
//!
//! `RescueTick` (active recovery — its `feed` phase pushes blocks to peers
//! via `submit_block`) is **intentionally not wired**. Activating it is
//! consensus/network-consequential and requires its safety gate plus
//! staged two-node testing. This sidecar is the safe first step; the
//! `RescueTick` wiring is a separate, later change.
//!
//! ## Usage
//!
//! ```text
//! coincync-tick --config /etc/coincync-tick/config.toml --interval 30
//! coincync-tick --once        # single snapshot then exit (systemd/CI check)
//! ```
//!
//! With no `--config`, the built-in `CoincyncAdapterConfig` defaults apply
//! (loopback RPC, personal deployment mode).

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use clap::Parser;
use tracing::{info, warn};

use coincync::colony::forager::{advise, observe_round};
use coincync::colony::pheromone::PheromoneMap;
use coincync::colony::sensor::{classify, NetSignal};
use coincync::tick_adapter::{CoincyncAdapter, CoincyncAdapterConfig};
use tick::{ChainAdapter, DeploymentMode};

#[derive(Parser)]
#[command(
    name = "coincync-tick",
    about = "Read-only health-monitoring sidecar for a coincync-node (HealthTick)"
)]
struct Cli {
    /// Path to a TOML `CoincyncAdapterConfig`. Omit to use built-in defaults.
    #[arg(long)]
    config: Option<PathBuf>,

    /// Poll interval in seconds (minimum 1).
    #[arg(long, default_value_t = 30)]
    interval: u64,

    /// Take a single snapshot, print it, and exit. For testing / systemd checks.
    #[arg(long)]
    once: bool,

    /// Run the colony forager in OBSERVE mode: score peers by public
    /// block/tip signals and log the ranking each round. Sends nothing,
    /// changes no node behavior, observes no transaction. Off by default.
    #[arg(long)]
    colony_observe: bool,

    /// Run the colony forager in ADVISE mode: additionally log the bounded
    /// peer-preference recommendation the colony *would* advise the node to
    /// prefer. Still sends NOTHING to the node — pushing advice to the node's
    /// peer manager is a separate, reviewed step. Implies --colony-observe.
    #[arg(long)]
    colony_advise: bool,
}

/// Max peers the colony recommends preferring — small (diversity over
/// volume; also bounds any eventual advisory RPC).
const COLONY_MAX_PREFER: usize = 3;

fn init_tracing() {
    let env_filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"));
    tracing_subscriber::fmt().with_env_filter(env_filter).init();
}

/// Load the adapter config from a TOML file, or fall back to defaults.
fn load_config(path: Option<&Path>) -> anyhow::Result<CoincyncAdapterConfig> {
    match path {
        Some(p) => {
            let text = std::fs::read_to_string(p)
                .map_err(|e| anyhow::anyhow!("reading config {}: {}", p.display(), e))?;
            toml::from_str(&text)
                .map_err(|e| anyhow::anyhow!("parsing config {}: {}", p.display(), e))
        }
        None => Ok(CoincyncAdapterConfig::default()),
    }
}

/// Read the RPC bearer token from `path`. Returns `None` (with a warning)
/// when the file is missing/empty/unreadable — the sidecar still runs and
/// reports local `/proc` stats; it just can't reach an auth-required RPC.
///
/// The token is treated as a secret: it is never logged.
fn read_bearer(path: &Path) -> Option<String> {
    match std::fs::read_to_string(path) {
        Ok(s) => {
            let t = s.trim().to_string();
            if t.is_empty() {
                warn!("RPC token file {} is empty — running without auth", path.display());
                None
            } else {
                Some(t)
            }
        }
        Err(e) => {
            warn!(
                "RPC token file {} unreadable ({}) — running without auth",
                path.display(),
                e
            );
            None
        }
    }
}

/// Emit one health report. Read-only: on any adapter error it logs and
/// returns — a monitoring sidecar must never abort the loop over a
/// transient RPC hiccup.
fn report_once(adapter: &CoincyncAdapter, fleet: bool) {
    match adapter.health_snapshot() {
        Ok(h) => info!(
            ram_pct = h.ram_used_pct,
            swap_pct = h.swap_used_pct,
            uptime_secs = h.uptime_secs,
            mempool_txs = h.mempool_txs,
            "health"
        ),
        Err(e) => warn!("health_snapshot failed: {}", e),
    }

    if fleet {
        match adapter.aggregate_fleet_health() {
            Ok(a) => info!(
                hosts = a.total_hosts,
                stalled = a.stalled_count,
                low_peer = a.low_peer_count,
                divergent = a.divergent_count,
                median_difficulty = a.median_difficulty,
                "fleet"
            ),
            Err(e) => warn!("aggregate_fleet_health failed: {}", e),
        }
    }
}

/// One colony forager observe round: score peers on public block/tip
/// signals and log the top-ranked block-relay recommendation. Read-only —
/// sends nothing to the node, observes no transaction.
fn colony_observe_report(
    adapter: &CoincyncAdapter,
    map: &mut PheromoneMap,
    fleet: bool,
    advise_mode: bool,
) {
    // Forager: block-relay peer scoring.
    let ranked = observe_round(adapter, map);
    if ranked.is_empty() {
        info!("colony/forager (observe): no peers scored yet");
    } else {
        for (peer, score) in ranked.iter().take(3) {
            info!(
                peer = %peer.0,
                score,
                "colony/forager (observe): would prefer for block relay"
            );
        }
    }

    // Advise mode: log the bounded recommendation the colony WOULD advise.
    // Still sends nothing — the node-side advisory application is a separate,
    // reviewed step.
    if advise_mode {
        let advice = advise(map, COLONY_MAX_PREFER);
        if advice.prefer.is_empty() {
            info!("colony/forager (advise): no peer clears the advice threshold yet");
        } else {
            let peers: Vec<&str> = advice.prefer.iter().map(|p| p.0.as_str()).collect();
            info!(?peers, "colony/forager (advise): WOULD advise node to prefer (not sent)");
        }
    }

    // Sensor: partition/eclipse detection from aggregate fleet health.
    // Only meaningful with fleet peers to aggregate over.
    if fleet {
        match adapter.aggregate_fleet_health() {
            Ok(agg) => match classify(&agg) {
                NetSignal::Healthy => {
                    info!(hosts = agg.total_hosts, "colony/sensor (observe): network healthy")
                }
                NetSignal::Degraded(reasons) => {
                    warn!(hosts = agg.total_hosts, ?reasons, "colony/sensor (observe): degraded")
                }
                NetSignal::PartitionSuspected(reasons) => warn!(
                    hosts = agg.total_hosts,
                    ?reasons,
                    "colony/sensor (observe): PARTITION suspected"
                ),
            },
            Err(e) => warn!("colony/sensor: aggregate_fleet_health failed: {}", e),
        }
    }
}

fn main() -> anyhow::Result<()> {
    init_tracing();
    let cli = Cli::parse();

    let config = load_config(cli.config.as_deref())?;
    let bearer = read_bearer(&config.local_rpc_token_path);
    info!(
        rpc = %config.local_rpc_url,
        mode = ?config.deployment_mode,
        "coincync-tick starting (read-only HealthTick)"
    );

    let adapter = CoincyncAdapter::new(config, bearer)
        .map_err(|e| anyhow::anyhow!("building adapter: {}", e))?;
    let fleet = matches!(adapter.deployment_mode(), DeploymentMode::Fleet);

    // Local pheromone map for the forager. Persists across rounds so
    // evaporation/reinforcement can track current conditions. --colony-advise
    // implies observe (advise reads the map the observe round builds).
    let mut pheromone = PheromoneMap::new();
    let colony_active = cli.colony_observe || cli.colony_advise;
    if colony_active {
        let m = if cli.colony_advise { "OBSERVE+ADVISE" } else { "OBSERVE" };
        info!("colony forager: {m} mode (read-only; recommendations logged, nothing sent)");
    }

    if cli.once {
        report_once(&adapter, fleet);
        if colony_active {
            colony_observe_report(&adapter, &mut pheromone, fleet, cli.colony_advise);
        }
        return Ok(());
    }

    // Graceful shutdown: SIGTERM (systemd stop) / SIGINT (Ctrl-C) flip the
    // flag and the loop exits cleanly. Unix-only — on other platforms the
    // process is simply terminated (fine for a stateless read-only monitor).
    let shutdown = Arc::new(AtomicBool::new(false));
    #[cfg(unix)]
    {
        signal_hook::flag::register(signal_hook::consts::SIGTERM, shutdown.clone())?;
        signal_hook::flag::register(signal_hook::consts::SIGINT, shutdown.clone())?;
    }

    let interval = Duration::from_secs(cli.interval.max(1));
    let tick = Duration::from_millis(200);
    info!(interval_secs = interval.as_secs(), "entering monitor loop");

    while !shutdown.load(Ordering::Relaxed) {
        report_once(&adapter, fleet);
        if colony_active {
            colony_observe_report(&adapter, &mut pheromone, fleet, cli.colony_advise);
        }
        // Sleep the interval in small slices so shutdown stays responsive.
        let mut slept = Duration::ZERO;
        while slept < interval && !shutdown.load(Ordering::Relaxed) {
            std::thread::sleep(tick);
            slept += tick;
        }
    }

    info!("coincync-tick shutting down");
    Ok(())
}
