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
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

// Explicit path: a file-based bin resolves `mod` siblings in `src/bin/` (which
// cargo would auto-discover as separate binaries), so the dashboard module
// lives in a subdirectory and is pointed at directly.
#[path = "coincync-tick/dashboard.rs"]
mod dashboard;

use clap::Parser;
use tracing::{debug, info, warn};

use std::collections::BTreeMap;

use coincync::colony::act::{ActReport, ColonyActor, ColonySignals, LoggingActuator};
use coincync::colony::army_ant::{self, BridgeCandidate};
use coincync::colony::centipede::{self, Leg};
use coincync::colony::cicada::CicadaSchedule;
use coincync::colony::forager::{advise, observe_round, probe_deposits};
use coincync::colony::guard::{ColonyGuards, NetgroupCensus};
use coincync::colony::locust::Locust;
use coincync::colony::pheromone::PheromoneMap;
use coincync::colony::sensor::{classify, NetSignal};
use coincync::colony::spider::{self, SentinelReading, ThreatSignature};
use coincync::colony::stick_insect;
use coincync::tick_adapter::{CoincyncAdapter, CoincyncAdapterConfig};
use tick::{AggregateFleetHealth, ChainAdapter, DeploymentMode, FleetPeer};

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

    /// Run the biomimetic caste suite in OBSERVE mode: drive each caste
    /// (cicada, stick-insect, spider, locust, centipede, army-ant) with
    /// real adapter signals and log what each WOULD do. mantis/firefly are
    /// "armed" only — the read-only HealthTick has no malice/pulse feed to
    /// drive them (that arrives in the node-adapter phase). Sends nothing,
    /// changes no node behavior, observes no transaction. Off by default.
    #[arg(long)]
    castes_observe: bool,

    /// Run the unified colony **Act** pipeline (Phase 2) in dry-run: every
    /// caste routes decision → guard → actuator through one path, and the
    /// inert `LoggingActuator` logs what each authorized action WOULD do.
    /// The kill switch is **DISARMED by default**, so every action is gated
    /// (denied) and nothing runs. Set `COINCYNC_COLONY_ACT_ENABLED=1` to arm
    /// the kill switch and see the dry-run "would" actions. Even armed, the
    /// actuator only logs — NOTHING is ever sent to the node or the network
    /// (a real network-mutating actuator is a separate, reviewed step).
    /// Off by default.
    #[arg(long)]
    colony_act: bool,

    /// Render a live `glances`-style TUI dashboard instead of the scrolling log.
    /// The CALM view is driven by REAL adapter + colony Act data each round;
    /// keys 1/2/3 layer clearly-badged SIMULATED scenarios (illustrative
    /// designed responses, never live peer data). The kill switch follows
    /// COINCYNC_COLONY_ACT_ENABLED exactly as `--colony-act`. Read-only,
    /// dry-run: nothing is sent. Needs an interactive terminal; `q` quits.
    #[arg(long)]
    dashboard: bool,

    /// Serve a Prometheus/OpenMetrics `/metrics` endpoint on this address
    /// (e.g. `127.0.0.1:9109`) exposing the health data this sidecar already
    /// collects. Strictly observational — scraping it changes no node state,
    /// peer selection, or recovery behavior. Requires the `metrics` build
    /// feature; without it the flag is accepted but a warning is logged.
    #[arg(long)]
    metrics_listen: Option<String>,

    /// Path to a file containing the **maintainer** Bearer token that gates the
    /// authenticated `/colony` endpoint (advisory colony + guard/security status
    /// — maintainers only). The token is read once, hashed (SHA-256), and only
    /// the hash is kept in memory; the plaintext is never logged. Alternatively
    /// set `COINCYNC_TICK_MAINTAINER_TOKEN`. When neither is provided, `/colony`
    /// stays DISABLED (fails closed) even while `--metrics-listen` is on, so the
    /// colony view is never served without maintainer authentication.
    #[arg(long)]
    maintainer_token_file: Option<String>,
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

/// Resolve the maintainer token that gates `/colony` and return only its
/// SHA-256 hash — the plaintext is read, hashed, and dropped here, never
/// retained or logged. Source precedence: `--maintainer-token-file` (trimmed
/// file contents), then `COINCYNC_TICK_MAINTAINER_TOKEN`. Returns `None` when
/// neither is set or the value is empty, so `/colony` fails closed (disabled).
#[cfg(feature = "metrics")]
fn load_maintainer_token_hash(token_file: Option<&str>) -> Option<[u8; 32]> {
    use sha2::Digest;
    let raw = match token_file {
        Some(path) => match std::fs::read_to_string(path) {
            Ok(s) => s,
            Err(e) => {
                warn!(
                    "maintainer: could not read --maintainer-token-file {}: {} \
                     (/colony disabled)",
                    path, e
                );
                return None;
            }
        },
        None => std::env::var("COINCYNC_TICK_MAINTAINER_TOKEN").unwrap_or_default(),
    };
    let token = raw.trim();
    if token.is_empty() {
        info!("maintainer: no token configured — /colony endpoint disabled (fails closed)");
        return None;
    }
    let hash = sha2::Sha256::digest(token.as_bytes());
    info!("maintainer: /colony authentication ENABLED (token hashed; plaintext never stored)");
    let mut out = [0u8; 32];
    out.copy_from_slice(&hash);
    Some(out)
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
                warn!(
                    "RPC token file {} is empty — running without auth",
                    path.display()
                );
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

/// Shared metrics state. With the `metrics` feature it is an
/// `Arc<Mutex<Snapshot>>` published to on every tick and read by the
/// `/metrics` HTTP handler; without the feature it is a zero-sized no-op so
/// the rest of the loop compiles and runs unchanged.
#[cfg(feature = "metrics")]
type MetricsState = std::sync::Arc<std::sync::Mutex<metrics_endpoint::Snapshot>>;
#[cfg(not(feature = "metrics"))]
type MetricsState = ();

/// Prometheus/OpenMetrics `/metrics` endpoint for the sidecar. Strictly
/// observational: it mirrors the health values the tick already computes and
/// serves them over HTTP. It never touches the adapter, the node, peer
/// selection, or any recovery path — a scrape only reads a snapshot of numbers.
#[cfg(feature = "metrics")]
mod metrics_endpoint {
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::sync::{Arc, Mutex};

    /// Last-observed values, published for `/metrics` scrapes. The `*_present`
    /// flags stay false until a value is successfully read, so the exposition
    /// omits metrics we have never obtained (e.g. mempool/fleet numbers while
    /// the local RPC is unavailable) while host-level metrics keep flowing.
    #[derive(Default)]
    pub struct Snapshot {
        pub host_present: bool,
        pub ram_used_pct: u8,
        pub swap_used_pct: u8,
        pub uptime_secs: u64,
        pub mempool_present: bool,
        pub mempool_txs: u64,
        pub fleet_present: bool,
        pub fleet_stalled: u16,
        pub fleet_low_peer: u16,
        pub fleet_divergent: u16,
        pub fleet_median_difficulty: u128,
    }

    /// Publish the host + local-node portion of a tick (after a successful
    /// `health_snapshot()`).
    pub fn publish_health(state: &Arc<Mutex<Snapshot>>, ram: u8, swap: u8, uptime: u64, mempool: u64) {
        if let Ok(mut s) = state.lock() {
            s.host_present = true;
            s.ram_used_pct = ram;
            s.swap_used_pct = swap;
            s.uptime_secs = uptime;
            s.mempool_present = true;
            s.mempool_txs = mempool;
        }
    }

    /// Publish the fleet-aggregate portion of a tick.
    pub fn publish_fleet(state: &Arc<Mutex<Snapshot>>, stalled: u16, low_peer: u16, divergent: u16, median: u128) {
        if let Ok(mut s) = state.lock() {
            s.fleet_present = true;
            s.fleet_stalled = stalled;
            s.fleet_low_peer = low_peer;
            s.fleet_divergent = divergent;
            s.fleet_median_difficulty = median;
        }
    }

    /// Mark the host + local-node series ABSENT after a failed `health_snapshot()`
    /// so `/metrics` omits them rather than exposing the last-successful (now
    /// stale) values. Without this, once `*_present` was set true it was never
    /// cleared, so a later refresh failure left stale gauges published.
    /// (audit #38, junbyjun1238)
    pub fn publish_health_absent(state: &Arc<Mutex<Snapshot>>) {
        if let Ok(mut s) = state.lock() {
            s.host_present = false;
            s.mempool_present = false;
        }
    }

    /// Mark the fleet-aggregate series ABSENT after a failed
    /// `aggregate_fleet_health()`, for the same reason as `publish_health_absent`.
    pub fn publish_fleet_absent(state: &Arc<Mutex<Snapshot>>) {
        if let Ok(mut s) = state.lock() {
            s.fleet_present = false;
        }
    }

    /// Render the snapshot in Prometheus text-exposition format (v0.0.4).
    fn render(s: &Snapshot) -> String {
        let mut out = String::with_capacity(1024);
        let mut gauge = |name: &str, help: &str, val: String| {
            out.push_str("# HELP ");
            out.push_str(name);
            out.push(' ');
            out.push_str(help);
            out.push_str("\n# TYPE ");
            out.push_str(name);
            out.push_str(" gauge\n");
            out.push_str(name);
            out.push(' ');
            out.push_str(&val);
            out.push('\n');
        };
        if s.host_present {
            gauge("coincync_node_ram_usage_percent", "Host RAM in use (percent).", s.ram_used_pct.to_string());
            gauge("coincync_node_swap_usage_percent", "Host swap in use (percent).", s.swap_used_pct.to_string());
            gauge("coincync_node_uptime_seconds", "Host uptime (seconds).", s.uptime_secs.to_string());
        }
        if s.mempool_present {
            gauge("coincync_node_mempool_transactions", "Local node mempool transaction count.", s.mempool_txs.to_string());
        }
        if s.fleet_present {
            gauge("coincync_fleet_stalled_nodes", "Fleet nodes whose tip is stalled.", s.fleet_stalled.to_string());
            gauge("coincync_fleet_low_peer_nodes", "Fleet nodes below the low-peer threshold.", s.fleet_low_peer.to_string());
            gauge("coincync_fleet_divergent_nodes", "Fleet nodes diverging from the median difficulty.", s.fleet_divergent.to_string());
            gauge("coincync_fleet_median_difficulty", "Median difficulty across the fleet.", s.fleet_median_difficulty.to_string());
        }
        out
    }

    /// Public for testing: render an arbitrary snapshot.
    #[cfg(test)]
    pub fn render_for_test(s: &Snapshot) -> String {
        render(s)
    }

    // ─── Colony status (maintainers-only `/colony`) ──────────────────────────
    //
    // The advisory, non-consensus colony/guard state, published each Act round.
    // Everything here is already the guard-gated, display-safe view the TUI
    // shows (allow/deny labels + reasons, kill-switch state, health vitals) —
    // no peer identities, no raw telemetry. Served ONLY over the authenticated
    // `/colony` route so it stays maintainers-only.

    /// Latest colony round, published for authenticated `/colony` reads.
    #[derive(Default)]
    pub struct ColonyStatus {
        pub present: bool,
        pub armed: bool,
        pub tick: u64,
        pub uptime_secs: u64,
        pub ram_pct: u16,
        pub swap_pct: u16,
        pub mempool: u32,
        pub peers_scored: u32,
        pub relay_mode: String,
        pub next_housekeeping_secs: u32,
        /// Actions the guards ALLOWED this round (caste action labels).
        pub allowed: Vec<String>,
        /// Actions the guards GATED this round: (label, reason).
        pub denied: Vec<(String, String)>,
        pub total_allowed: u64,
        pub total_denied: u64,
    }

    /// Publish one colony Act round. Called from the monitor loop; a no-op
    /// consumer without the `metrics` feature never reaches here.
    #[allow(clippy::too_many_arguments)]
    pub fn publish_colony(
        state: &Arc<Mutex<ColonyStatus>>,
        armed: bool,
        tick: u64,
        uptime_secs: u64,
        ram_pct: u16,
        swap_pct: u16,
        mempool: u32,
        peers_scored: u32,
        relay_mode: &str,
        next_housekeeping_secs: u32,
        allowed: &[String],
        denied: &[(String, String)],
    ) {
        if let Ok(mut s) = state.lock() {
            s.present = true;
            s.armed = armed;
            s.tick = tick;
            s.uptime_secs = uptime_secs;
            s.ram_pct = ram_pct;
            s.swap_pct = swap_pct;
            s.mempool = mempool;
            s.peers_scored = peers_scored;
            s.relay_mode = relay_mode.to_string();
            s.next_housekeeping_secs = next_housekeeping_secs;
            s.total_allowed = s.total_allowed.saturating_add(allowed.len() as u64);
            s.total_denied = s.total_denied.saturating_add(denied.len() as u64);
            s.allowed = allowed.to_vec();
            s.denied = denied.to_vec();
        }
    }

    /// Serialize the colony status as JSON for an authenticated maintainer read.
    fn colony_json(s: &ColonyStatus) -> String {
        let denied: Vec<serde_json::Value> = s
            .denied
            .iter()
            .map(|(action, reason)| serde_json::json!({ "action": action, "reason": reason }))
            .collect();
        serde_json::json!({
            "present": s.present,
            "armed": s.armed,
            "tick": s.tick,
            "uptime_secs": s.uptime_secs,
            "ram_pct": s.ram_pct,
            "swap_pct": s.swap_pct,
            "mempool": s.mempool,
            "peers_scored": s.peers_scored,
            "relay_mode": s.relay_mode,
            "next_housekeeping_secs": s.next_housekeeping_secs,
            "allowed": s.allowed,
            "denied": denied,
            "total_allowed": s.total_allowed,
            "total_denied": s.total_denied,
        })
        .to_string()
    }

    /// Constant-time maintainer Bearer check against a raw HTTP request head.
    /// Mirrors the RPC server's hardened pattern: SHA-256 the supplied token,
    /// `ct_eq` against the expected hash — never compares plaintext, and the
    /// empty/missing-header case hashes to a non-matching digest (fails closed).
    fn colony_authorized(head: &str, expected_hash: &[u8; 32]) -> bool {
        use sha2::Digest;
        let mut supplied = "";
        for line in head.lines() {
            let (name, val) = match line.split_once(':') {
                Some(kv) => kv,
                None => continue,
            };
            if name.trim().eq_ignore_ascii_case("authorization") {
                let v = val.trim();
                if let Some(tok) = v
                    .strip_prefix("Bearer ")
                    .or_else(|| v.strip_prefix("bearer "))
                {
                    supplied = tok.trim();
                }
            }
        }
        let supplied_hash = sha2::Sha256::digest(supplied.as_bytes());
        coincync::crypto::ct_eq(&supplied_hash[..], &expected_hash[..])
    }

    /// Spawn a tiny blocking HTTP/1.1 server answering `GET /metrics` (open,
    /// health) and `GET /colony` (maintainer-authenticated colony status) from
    /// the shared snapshots. One dedicated thread; connections are handled
    /// synchronously. Read-only. A bind failure is logged, not fatal — the
    /// monitor loop keeps running. `maintainer_token_hash == None` ⇒ `/colony`
    /// is disabled (503), never served without authentication.
    pub fn spawn_server(
        addr: String,
        state: Arc<Mutex<Snapshot>>,
        colony: Arc<Mutex<ColonyStatus>>,
        maintainer_token_hash: Option<[u8; 32]>,
    ) {
        std::thread::spawn(move || {
            let listener = match TcpListener::bind(&addr) {
                Ok(l) => l,
                Err(e) => {
                    tracing::warn!("metrics: failed to bind {}: {} (endpoint disabled)", addr, e);
                    return;
                }
            };
            tracing::info!("metrics: Prometheus endpoint on http://{}/metrics", addr);
            for stream in listener.incoming() {
                let mut stream = match stream {
                    Ok(s) => s,
                    Err(_) => continue,
                };
                // Bound how long one (mis)behaving client can hold this handler
                // thread. Connections are served serially, so without a read
                // timeout a client that connects and sends nothing blocks read()
                // forever and stalls every later scrape. (audit #38, junbyjun1238)
                let _ = stream.set_read_timeout(Some(std::time::Duration::from_secs(5)));
                let _ = stream.set_write_timeout(Some(std::time::Duration::from_secs(5)));
                // Only the request line matters; cap the read so a slow or
                // oversized client can't tie the thread up unboundedly.
                let mut buf = [0u8; 1024];
                let n = stream.read(&mut buf).unwrap_or(0);
                let head = String::from_utf8_lossy(&buf[..n]);
                let first = head.lines().next().unwrap_or("");
                // (status, content-type, body, needs_auth_challenge)
                let (status, ctype, body, challenge) = if first.starts_with("GET /metrics") {
                    let body = state.lock().map(|s| render(&s)).unwrap_or_default();
                    ("200 OK", "text/plain; version=0.0.4", body, false)
                } else if first.starts_with("GET /colony") {
                    match &maintainer_token_hash {
                        // Fail closed: no maintainer token ⇒ never serve colony.
                        None => (
                            "503 Service Unavailable",
                            "application/json",
                            r#"{"error":"colony endpoint disabled: no maintainer token configured"}"#.to_string(),
                            false,
                        ),
                        Some(expected) if colony_authorized(&head, expected) => {
                            let body = colony.lock().map(|c| colony_json(&c)).unwrap_or_default();
                            ("200 OK", "application/json", body, false)
                        }
                        Some(_) => (
                            "401 Unauthorized",
                            "application/json",
                            r#"{"error":"maintainer authentication required"}"#.to_string(),
                            true,
                        ),
                    }
                } else {
                    ("404 Not Found", "text/plain", String::new(), false)
                };
                let auth_hdr = if challenge {
                    "WWW-Authenticate: Bearer realm=\"coincync-colony\"\r\n"
                } else {
                    ""
                };
                let resp = format!(
                    "HTTP/1.1 {status}\r\nContent-Type: {ctype}\r\n{auth_hdr}Content-Length: {}\r\nCache-Control: no-store\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                let _ = stream.write_all(resp.as_bytes());
            }
        });
    }
}

/// Emit one health report. Read-only: on any adapter error it logs and
/// returns — a monitoring sidecar must never abort the loop over a
/// transient RPC hiccup. Also publishes the values to the metrics snapshot
/// (a no-op without the `metrics` feature).
fn report_once(adapter: &CoincyncAdapter, fleet: bool, metrics: &MetricsState) {
    #[cfg(not(feature = "metrics"))]
    let _ = metrics;
    match adapter.health_snapshot() {
        Ok(h) => {
            info!(
                ram_pct = h.ram_used_pct,
                swap_pct = h.swap_used_pct,
                uptime_secs = h.uptime_secs,
                mempool_txs = h.mempool_txs,
                "health"
            );
            #[cfg(feature = "metrics")]
            metrics_endpoint::publish_health(
                metrics,
                h.ram_used_pct,
                h.swap_used_pct,
                h.uptime_secs,
                h.mempool_txs as u64,
            );
        }
        Err(e) => {
            warn!("health_snapshot failed: {}", e);
            // Clear the host/local series so /metrics omits them instead of
            // serving the last-successful (now stale) values. (audit #38)
            #[cfg(feature = "metrics")]
            metrics_endpoint::publish_health_absent(metrics);
        }
    }

    if fleet {
        match adapter.aggregate_fleet_health() {
            Ok(a) => {
                info!(
                    hosts = a.total_hosts,
                    stalled = a.stalled_count,
                    low_peer = a.low_peer_count,
                    divergent = a.divergent_count,
                    median_difficulty = a.median_difficulty,
                    "fleet"
                );
                #[cfg(feature = "metrics")]
                metrics_endpoint::publish_fleet(
                    metrics,
                    a.stalled_count,
                    a.low_peer_count,
                    a.divergent_count,
                    a.median_difficulty,
                );
            }
            Err(e) => {
                warn!("aggregate_fleet_health failed: {}", e);
                // Clear the fleet series so /metrics omits it rather than serving
                // stale aggregates. (audit #38)
                #[cfg(feature = "metrics")]
                metrics_endpoint::publish_fleet_absent(metrics);
            }
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
            info!(
                ?peers,
                "colony/forager (advise): WOULD advise node to prefer (not sent)"
            );
        }
    }

    // Sensor: partition/eclipse detection from aggregate fleet health.
    // Only meaningful with fleet peers to aggregate over.
    if fleet {
        match adapter.aggregate_fleet_health() {
            Ok(agg) => match classify(&agg) {
                NetSignal::Healthy => {
                    info!(
                        hosts = agg.total_hosts,
                        "colony/sensor (observe): network healthy"
                    )
                }
                NetSignal::Degraded(reasons) => {
                    warn!(
                        hosts = agg.total_hosts,
                        ?reasons,
                        "colony/sensor (observe): degraded"
                    )
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

// ─── biomimetic caste observe harness ─────────────────────────────────────

/// Housekeeping cadence (seconds) that the cicada schedule varies around.
/// Advisory only — cicada logs the *next* prime-varied interval; it does
/// not (yet) pace any real action.
const CICADA_HOUSEKEEPING_BASE_SECS: u64 = 300;

/// Max relay legs / bridges a caste recommends — small (diversity over
/// volume), matching `COLONY_MAX_PREFER`.
const CASTE_MAX_LEGS: usize = 3;

/// Extract the bare host from a peer's RPC URL, stripping scheme, path,
/// userinfo, and port. Handles bracketed IPv6 (`[2001:db8::1]:8332` -> the
/// address without brackets) — which naive `split(':')` mangles because IPv6
/// addresses contain `:` themselves. IPv4, bare hostnames, and unbracketed
/// IPv6 are handled too.
fn extract_host(rpc_url: &str) -> &str {
    let after_scheme = rpc_url.rsplit("://").next().unwrap_or(rpc_url);
    let authority = after_scheme.split('/').next().unwrap_or(after_scheme);
    // Strip any userinfo ("user:pass@" or "user@").
    let host_port = authority.rsplit('@').next().unwrap_or(authority);

    // Bracketed IPv6: `[addr]` or `[addr]:port`.
    if let Some(rest) = host_port.strip_prefix('[') {
        return match rest.find(']') {
            Some(end) => &rest[..end],
            None => rest, // malformed; best effort
        };
    }

    // Unbracketed. Exactly one ':' => host:port (IPv4 or hostname) -> take the
    // host. Zero colons => a bare host. Two or more => a bare (unbracketed)
    // IPv6 literal, which we must NOT split on ':' -> keep the whole string.
    match host_port.matches(':').count() {
        1 => host_port.split(':').next().unwrap_or(host_port),
        _ => host_port,
    }
}

/// Derive a `/16`-style netgroup bucket from a peer's RPC URL host, used as the
/// diversity/concentration input for the eclipse-observation logic. IPv4 hosts
/// bucket by their first two octets (a `/16`, matching the eviction module).
/// IPv6 hosts bucket by their `/32` routing prefix (Bitcoin's IPv6 netgroup
/// granularity), so distinct IPv6 networks separate deterministically instead
/// of all collapsing on the pre-colon text. IPv4-mapped IPv6 (`::ffff:a.b.c.d`)
/// folds onto the IPv4 bucket. Hostnames and unparseable hosts fall back to a
/// stable byte hash. Deterministic for every input.
fn netgroup_of(rpc_url: &str) -> u16 {
    let host = extract_host(rpc_url);

    // IPv4 (incl. an IPv4-mapped IPv6 that resolves to a v4): first two octets.
    let v4 = host.parse::<std::net::Ipv4Addr>().ok().or_else(|| {
        host.parse::<std::net::Ipv6Addr>()
            .ok()
            .and_then(|v6| v6.to_ipv4_mapped())
    });
    if let Some(v4) = v4 {
        let o = v4.octets();
        return (u16::from(o[0]) << 8) | u16::from(o[1]);
    }

    // IPv6: hash the first four bytes (the /32 network prefix) into the bucket.
    if let Ok(v6) = host.parse::<std::net::Ipv6Addr>() {
        let o = v6.octets();
        let mut h: u16 = 0;
        for byte in &o[..4] {
            h = h.wrapping_mul(31).wrapping_add(u16::from(*byte));
        }
        return h;
    }

    // Hostname / unparseable: stable byte hash of the extracted host.
    let mut h: u16 = 0;
    for byte in host.bytes() {
        h = h.wrapping_mul(31).wrapping_add(u16::from(byte));
    }
    h
}

/// Integer percentage `n/total` clamped to `0..=100`, zero-total safe.
/// `try_from` (not `as`) keeps this clear of `cast_possible_truncation`.
fn pct_u8(n: u16, total: u16) -> u8 {
    if total == 0 {
        return 0;
    }
    let p = u32::from(n) * 100 / u32::from(total);
    u8::try_from(p.min(100)).unwrap_or(100)
}

/// Share of `peers` concentrated in the single largest netgroup (percent).
/// High concentration is spider's eclipse-pressure input.
fn largest_netgroup_pct(peers: &[FleetPeer]) -> u8 {
    if peers.is_empty() {
        return 0;
    }
    let mut counts: BTreeMap<u16, u16> = BTreeMap::new();
    for p in peers {
        *counts.entry(netgroup_of(&p.rpc_url)).or_insert(0) += 1;
    }
    let max = counts.values().copied().max().unwrap_or(0);
    let total = u16::try_from(peers.len()).unwrap_or(u16::MAX);
    pct_u8(max, total)
}

/// Build a spider [`SentinelReading`] from the real signals the read-only
/// HealthTick has. Fields it cannot see (per-message duplicate rate, raw
/// inbound-connection rate) are left at 0 — honest absence, so they never
/// false-trip a signature.
fn sentinel_reading(agg: &AggregateFleetHealth, peers: &[FleetPeer]) -> SentinelReading {
    SentinelReading {
        inbound_new_per_min: 0,
        largest_netgroup_pct: largest_netgroup_pct(peers),
        duplicate_msg_pct: 0,
        unreachable_sentinel_pct: pct_u8(agg.stalled_count, agg.total_hosts),
    }
}

/// One observe round of the biomimetic caste suite. Read-only: drives each
/// caste with real adapter data and logs what it WOULD do; sends nothing,
/// observes no transaction. `cicada`/`locust` carry state across rounds.
fn castes_observe_report(
    adapter: &CoincyncAdapter,
    fleet: bool,
    cicada: &mut CicadaSchedule,
    locust: &mut Locust,
) {
    // cicada — prime-varied housekeeping cadence (no external input).
    let next = cicada.advance();
    info!(
        next_secs = next,
        "caste/cicada (observe): next prime-varied housekeeping interval"
    );

    // stick-insect — the canonical wire fingerprint every node presents.
    info!(
        user_agent = stick_insect::CANONICAL_USER_AGENT,
        example_pad_1300 = stick_insect::padded_len(1300),
        "caste/stick-insect (observe): canonical fingerprint (uniformity is anonymity)"
    );

    // Gather real signals once per round.
    let health = adapter.health_snapshot().ok();
    let peers = adapter.fleet_peers();
    let agg = if fleet {
        adapter.aggregate_fleet_health().ok()
    } else {
        None
    };

    // spider — attack-signature detection (needs fleet aggregate + peers).
    let mut under_attack = false;
    if let Some(a) = &agg {
        let reading = sentinel_reading(a, &peers);
        let sigs = spider::assess(&reading);
        under_attack = !sigs.is_empty();
        if sigs.is_empty() {
            info!(
                hosts = a.total_hosts,
                "caste/spider (observe): web calm, no attack signature"
            );
        } else {
            warn!(
                ?sigs,
                largest_netgroup_pct = reading.largest_netgroup_pct,
                unreachable_pct = reading.unreachable_sentinel_pct,
                "caste/spider (observe): attack signature(s) detected"
            );
        }

        // army-ant — activate ONLY when a partition is signalled; probe
        // peers for freshness, then log the diverse bridge set it WOULD
        // reconnect toward. Nothing is sent.
        if sigs.contains(&ThreatSignature::PartitionOnset) {
            let cands: Vec<BridgeCandidate> = peers
                .iter()
                .map(|p| {
                    let age = if adapter.probe_peer(p).is_ok() {
                        0
                    } else {
                        3_600
                    };
                    BridgeCandidate::new(p.name.clone(), netgroup_of(&p.rpc_url), age)
                })
                .collect();
            let bridges = army_ant::select_bridges(&cands, CASTE_MAX_LEGS);
            let names: Vec<&str> = bridges.iter().map(|b| b.id.as_str()).collect();
            warn!(
                ?names,
                "caste/army-ant (observe): WOULD bridge toward these to heal partition (not sent)"
            );
        }
    } else {
        info!("caste/spider (observe): personal mode / no fleet aggregate — standing by");
    }

    // locust — density-adaptive relay mode (real host load + attack flag).
    if let Some(h) = &health {
        let density = h.ram_used_pct.max(h.cpu_used_pct);
        let mode = locust.update(density, under_attack);
        info!(
            density_pct = density,
            under_attack,
            ?mode,
            "caste/locust (observe): relay-aggressiveness mode"
        );
    }

    // centipede — netgroup-diverse block-relay legs over the real peer set.
    if peers.is_empty() {
        info!("caste/centipede (observe): no fleet peers to select relay legs from");
    } else {
        let legs: Vec<Leg> = peers
            .iter()
            .map(|p| Leg::new(p.name.clone(), netgroup_of(&p.rpc_url)))
            .collect();
        let chosen = centipede::select_legs(&legs, CASTE_MAX_LEGS);
        let names: Vec<&str> = chosen.iter().map(|l| l.id.as_str()).collect();
        info!(
            ?names,
            distinct_netgroups = centipede::distinct_netgroups(&chosen),
            "caste/centipede (observe): WOULD relay new blocks over these diverse legs (not sent)"
        );
    }

    // mantis / firefly — armed, but the read-only HealthTick has no
    // per-peer misbehavior feed (mantis) or neighbour-pulse feed (firefly).
    // Feeding unreachable-but-honest peers to mantis would violate the
    // ban-consistency rule (D.5), so we deliberately do NOT; these activate
    // with node-adapter signals in a later, reviewed phase.
    info!("caste/mantis (observe): armed; no malice feed in read-only HealthTick (node-adapter phase)");
    info!("caste/firefly (observe): armed; needs live peer-pulse feed (node integration phase)");
}

// ─── unified colony Act host (Phase 2, dry-run) ────────────────────────────

/// Firefly free-running phase increment. Fires roughly every
/// `ceil(PHASE_MAX / increment)` = 10 rounds — a periodic cover-pulse cadence
/// for the dry-run, well clear of any per-round rhythm.
const FIREFLY_PHASE_INCREMENT: u32 = coincync::colony::firefly::PHASE_MAX / 10;

/// Is the colony Act kill switch armed? Arming is a **deliberate, explicit**
/// operator action via `COINCYNC_COLONY_ACT_ENABLED=1` (or `true`), never a
/// default. Disarmed → the actor authorizes nothing and the round is a no-op.
fn colony_act_armed() -> bool {
    std::env::var("COINCYNC_COLONY_ACT_ENABLED")
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false)
}

/// The node's current outbound diversity, from the fleet peer set: distinct
/// `/16`-style netgroups and total peers. Feeds the guard diversity floor —
/// below it, topology-narrowing acts (bridge/leg/tarpit) are refused.
fn netgroup_census(peers: &[FleetPeer]) -> NetgroupCensus {
    let distinct: std::collections::BTreeSet<u16> =
        peers.iter().map(|p| netgroup_of(&p.rpc_url)).collect();
    NetgroupCensus {
        distinct_netgroups: distinct.len(),
        total_outbound: peers.len(),
    }
}

/// One round of the unified Act pipeline. Gathers the public signals every
/// caste reads, runs `ColonyActor::tick` through the guard layer against the
/// inert `LoggingActuator`, and logs the allow/deny report. Read-only: sends
/// nothing, observes no transaction. With the kill switch disarmed (default)
/// every action is gated and the actuator is never touched.
/// Real per-round vitals distilled from the adapter + Act report, for the
/// dashboard's live "calm" view. Everything here is a public, read-only signal.
pub struct RoundVitals {
    pub ram_pct: u16,
    pub swap_pct: u16,
    pub mempool: u32,
    pub peers_scored: u32,
    pub relay_mode: &'static str,
    pub next_housekeeping_s: u32,
}

/// Run one Act round against real adapter data and return the vitals plus the
/// guard-gated report. Shared by the log path (`colony_act_report`) and the
/// dashboard, so both see identical numbers. Read-only; nothing is sent.
fn colony_act_round(
    adapter: &CoincyncAdapter,
    actor: &mut ColonyActor,
    fleet: bool,
) -> (RoundVitals, ActReport) {
    // Fuel the forager's internal pheromone map with this round's public probe
    // deposits (probe → Untrusted → sanitize → deposit). Read-only.
    let deposits = probe_deposits(adapter);
    let peers_scored = deposits.len() as u32;
    actor.observe_peers(&deposits);

    let peers = adapter.fleet_peers();
    let health = adapter.health_snapshot().ok();
    let agg = if fleet {
        adapter.aggregate_fleet_health().ok()
    } else {
        None
    };

    // spider input: real fleet concentration/stall signals, else calm.
    let sentinel = match &agg {
        Some(a) => sentinel_reading(a, &peers),
        None => SentinelReading::default(),
    };
    // locust input: host load as relay-density proxy (as in observe mode).
    let density_pct = health
        .as_ref()
        .map(|h| h.ram_used_pct.max(h.cpu_used_pct))
        .unwrap_or(0);
    // army_ant / centipede candidate sets, netgroup-tagged for the diversity
    // floor. Per-peer freshness probing is skipped here (age 0) to keep each
    // round cheap; selection still maximizes netgroup diversity.
    let bridge_candidates: Vec<BridgeCandidate> = peers
        .iter()
        .map(|p| BridgeCandidate::new(p.name.clone(), netgroup_of(&p.rpc_url), 0))
        .collect();
    let leg_candidates: Vec<Leg> = peers
        .iter()
        .map(|p| Leg::new(p.name.clone(), netgroup_of(&p.rpc_url)))
        .collect();

    let signals = ColonySignals {
        sentinel,
        density_pct,
        bridge_candidates,
        leg_candidates,
        // mantis: the read-only HealthTick has no per-peer malice feed, and
        // tarpitting merely-unreachable honest peers would violate the ban-
        // consistency rule (D.5). No offenders until the node-adapter phase.
        offenders: Vec::new(),
        census: netgroup_census(&peers),
        max_prefer: COLONY_MAX_PREFER,
        max_legs: CASTE_MAX_LEGS,
        max_bridges: CASTE_MAX_LEGS,
    };

    let report = actor.tick(&signals, &LoggingActuator);

    // Derive display vitals from the report's action details (present whether
    // the action was allowed or gated), so the dashboard shows the real cicada
    // interval and relay mode even while disarmed.
    let mut relay_mode = "Solitary";
    let mut next_housekeeping_s = 0u32;
    for detail in report
        .allowed
        .iter()
        .chain(report.denied.iter().map(|(a, _)| a))
    {
        if detail.contains("relay mode Gregarious") {
            relay_mode = "Gregarious";
        } else if detail.contains("relay mode Solitary") {
            relay_mode = "Solitary";
        }
        if let Some(rest) = detail.strip_prefix("housekeep in ") {
            next_housekeeping_s = rest.trim_end_matches('s').parse().unwrap_or(0);
        }
    }

    let vitals = RoundVitals {
        ram_pct: health.as_ref().map(|h| h.ram_used_pct as u16).unwrap_or(0),
        swap_pct: health.as_ref().map(|h| h.swap_used_pct as u16).unwrap_or(0),
        mempool: health.as_ref().map(|h| h.mempool_txs as u32).unwrap_or(0),
        peers_scored,
        relay_mode,
        next_housekeeping_s,
    };
    (vitals, report)
}

/// One Act round, logged. Read-only: sends nothing, observes no transaction.
/// Returns the round's vitals + guard-gated report so the caller can publish
/// them to the maintainer `/colony` endpoint.
fn colony_act_report(
    adapter: &CoincyncAdapter,
    actor: &mut ColonyActor,
    fleet: bool,
) -> (RoundVitals, ActReport) {
    let (vitals, report) = colony_act_round(adapter, actor, fleet);
    if report.allowed.is_empty() && report.denied.is_empty() {
        info!("colony/act: no recommendations this round");
        return (vitals, report);
    }
    info!(
        allowed = report.allowed.len(),
        denied = report.denied.len(),
        "colony/act: round complete (dry-run — nothing sent)"
    );
    for action in &report.allowed {
        info!(action = %action, "colony/act: WOULD (authorized; LoggingActuator only)");
    }
    for (action, reason) in &report.denied {
        debug!(action = %action, reason, "colony/act: gated by guard");
    }
    (vitals, report)
}

/// Wall-clock `HH:MM:SS` for ledger timestamps.
fn hms() -> String {
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let d = secs % 86_400;
    format!("{:02}:{:02}:{:02}", d / 3600, (d % 3600) / 60, d % 60)
}

/// Live TUI loop. CALM view = real adapter + Act data (`colony_act_round`);
/// 1/2/3 = badged simulations. Read-only; `q`/Esc quits. Restores the terminal
/// on every exit path.
fn run_dashboard(
    adapter: &CoincyncAdapter,
    actor: &mut ColonyActor,
    fleet: bool,
    armed: bool,
    node: &str,
    interval: Duration,
) -> anyhow::Result<()> {
    use ratatui::crossterm::event::{self, Event, KeyCode, KeyEventKind};

    let mut terminal = ratatui::init();
    let mut snap = dashboard::Snapshot::new(node, armed);
    let start = Instant::now();

    // Seed the first frame from real data so the dashboard opens populated.
    let (v, r) = colony_act_round(adapter, actor, fleet);
    snap.apply_real(&v, &r, start.elapsed().as_secs(), &hms());

    let mut last = Instant::now();
    let res = loop {
        if let Err(e) = terminal.draw(|f| dashboard::draw(f, &snap)) {
            break Err(anyhow::Error::from(e));
        }
        let timeout = interval.saturating_sub(last.elapsed());
        match event::poll(timeout) {
            Ok(true) => {
                if let Ok(Event::Key(k)) = event::read() {
                    if k.kind == KeyEventKind::Press {
                        match k.code {
                            KeyCode::Char('q') | KeyCode::Esc => break Ok(()),
                            KeyCode::Char('0') => snap.set_mode(dashboard::Mode::Calm),
                            KeyCode::Char('1') => snap.set_mode(dashboard::Mode::Partition),
                            KeyCode::Char('2') => snap.set_mode(dashboard::Mode::Flood),
                            KeyCode::Char('3') => snap.set_mode(dashboard::Mode::Eclipse),
                            _ => {}
                        }
                    }
                }
            }
            Ok(false) => {}
            Err(e) => break Err(anyhow::Error::from(e)),
        }
        if last.elapsed() >= interval {
            if snap.mode_is_sim() {
                snap.simulate(hms());
            } else {
                let (v, r) = colony_act_round(adapter, actor, fleet);
                snap.apply_real(&v, &r, start.elapsed().as_secs(), &hms());
            }
            last = Instant::now();
        }
    };

    ratatui::restore();
    res
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    // The dashboard owns the terminal (alternate screen); a tracing subscriber
    // writing to stdout would corrupt it. Skipping init leaves tracing without
    // a global subscriber, so the LoggingActuator's WOULD/DENIED events become
    // no-ops — the dashboard surfaces them in its ledger instead.
    if !cli.dashboard {
        init_tracing();
    }

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

    // Live TUI dashboard: owns the terminal for its whole run. CALM view driven
    // by real adapter + Act data; kill switch follows COINCYNC_COLONY_ACT_ENABLED.
    if cli.dashboard {
        let guards = Arc::new(ColonyGuards::with_defaults());
        let armed = colony_act_armed();
        if armed {
            guards.arm();
        }
        let mut actor = ColonyActor::new(
            guards,
            CICADA_HOUSEKEEPING_BASE_SECS,
            FIREFLY_PHASE_INCREMENT,
        );
        // Header label = the real RPC target (host:port), scheme and any path
        // stripped, e.g. "http://127.0.0.1:28081" → "127.0.0.1:28081".
        let url = adapter.config().local_rpc_url.clone();
        let node_label = url
            .rsplit("://")
            .next()
            .unwrap_or(&url)
            .split('/')
            .next()
            .unwrap_or(&url);
        return run_dashboard(
            &adapter,
            &mut actor,
            fleet,
            armed,
            node_label,
            Duration::from_secs(cli.interval.max(1)),
        );
    }

    // Local pheromone map for the forager. Persists across rounds so
    // evaporation/reinforcement can track current conditions. --colony-advise
    // implies observe (advise reads the map the observe round builds).
    let mut pheromone = PheromoneMap::new();
    let colony_active = cli.colony_observe || cli.colony_advise;
    if colony_active {
        let m = if cli.colony_advise {
            "OBSERVE+ADVISE"
        } else {
            "OBSERVE"
        };
        info!("colony forager: {m} mode (read-only; recommendations logged, nothing sent)");
    }

    // Biomimetic caste suite (observe). cicada + locust carry state across
    // rounds; --castes-observe gates the whole thing, off by default.
    let mut cicada_sched = CicadaSchedule::new(CICADA_HOUSEKEEPING_BASE_SECS);
    let mut locust = Locust::new();
    let castes_active = cli.castes_observe;
    if castes_active {
        info!("biomimetic castes: OBSERVE mode (read-only; each caste logs what it WOULD do, nothing sent)");
    }

    // Unified colony Act pipeline (Phase 2), dry-run. The actor owns caste
    // state (pheromone/cicada/locust/firefly/tarpit) across rounds. The kill
    // switch is DISARMED unless the operator explicitly sets
    // COINCYNC_COLONY_ACT_ENABLED=1 — and even armed, the LoggingActuator only
    // logs; nothing is ever sent to the node or the network.
    let mut colony_actor = if cli.colony_act {
        let guards = Arc::new(ColonyGuards::with_defaults());
        if colony_act_armed() {
            guards.arm();
            info!(
                "colony/act: ENABLED — kill switch ARMED (dry-run: LoggingActuator logs \
                 authorized actions; NOTHING sent to node or network)"
            );
        } else {
            info!(
                "colony/act: ENABLED — kill switch DISARMED (every action gated; set \
                 COINCYNC_COLONY_ACT_ENABLED=1 to arm the dry-run)"
            );
        }
        Some(ColonyActor::new(
            guards,
            CICADA_HOUSEKEEPING_BASE_SECS,
            FIREFLY_PHASE_INCREMENT,
        ))
    } else {
        None
    };

    // Metrics snapshot shared with the /metrics endpoint. Created regardless
    // of the feature (it is `()` without it) so report_once has one to receive.
    #[cfg(feature = "metrics")]
    let metrics_state: MetricsState =
        std::sync::Arc::new(std::sync::Mutex::new(metrics_endpoint::Snapshot::default()));
    #[cfg(not(feature = "metrics"))]
    let metrics_state: MetricsState = ();

    // Colony status shared with the authenticated `/colony` endpoint (maintainers
    // only), plus the maintainer token hash that gates it. Both exist only with
    // the `metrics` feature; `maintainer_hash == None` keeps `/colony` disabled.
    #[cfg(feature = "metrics")]
    let colony_state: std::sync::Arc<std::sync::Mutex<metrics_endpoint::ColonyStatus>> =
        std::sync::Arc::new(std::sync::Mutex::new(metrics_endpoint::ColonyStatus::default()));
    #[cfg(feature = "metrics")]
    let maintainer_hash: Option<[u8; 32]> =
        load_maintainer_token_hash(cli.maintainer_token_file.as_deref());
    #[cfg(feature = "metrics")]
    let colony_armed = colony_act_armed();

    if cli.once {
        report_once(&adapter, fleet, &metrics_state);
        if colony_active {
            colony_observe_report(&adapter, &mut pheromone, fleet, cli.colony_advise);
        }
        if castes_active {
            castes_observe_report(&adapter, fleet, &mut cicada_sched, &mut locust);
        }
        if let Some(actor) = colony_actor.as_mut() {
            colony_act_report(&adapter, actor, fleet);
        }
        return Ok(());
    }

    // Start the Prometheus endpoint for the long-running loop (not for --once).
    #[cfg(feature = "metrics")]
    if let Some(addr) = cli.metrics_listen.clone() {
        metrics_endpoint::spawn_server(
            addr,
            metrics_state.clone(),
            colony_state.clone(),
            maintainer_hash,
        );
    }
    #[cfg(not(feature = "metrics"))]
    if cli.metrics_listen.is_some() {
        warn!(
            "--metrics-listen was given but this build lacks the `metrics` feature; \
             endpoint disabled (rebuild with --features metrics)"
        );
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
    #[cfg(feature = "metrics")]
    let loop_start = std::time::Instant::now();
    #[cfg(feature = "metrics")]
    let mut colony_tick: u64 = 0;

    while !shutdown.load(Ordering::Relaxed) {
        report_once(&adapter, fleet, &metrics_state);
        if colony_active {
            colony_observe_report(&adapter, &mut pheromone, fleet, cli.colony_advise);
        }
        if castes_active {
            castes_observe_report(&adapter, fleet, &mut cicada_sched, &mut locust);
        }
        if let Some(actor) = colony_actor.as_mut() {
            let round = colony_act_report(&adapter, actor, fleet);
            // Publish the guard-gated round to the maintainer `/colony` view.
            #[cfg(feature = "metrics")]
            {
                let (v, r) = round;
                colony_tick += 1;
                let denied: Vec<(String, String)> = r
                    .denied
                    .iter()
                    .map(|(a, b)| (a.clone(), b.to_string()))
                    .collect();
                metrics_endpoint::publish_colony(
                    &colony_state,
                    colony_armed,
                    colony_tick,
                    loop_start.elapsed().as_secs(),
                    v.ram_pct,
                    v.swap_pct,
                    v.mempool,
                    v.peers_scored,
                    v.relay_mode,
                    v.next_housekeeping_s,
                    &r.allowed,
                    &denied,
                );
            }
            #[cfg(not(feature = "metrics"))]
            let _ = round;
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

#[cfg(test)]
mod tests {
    use super::*;

    fn peer(name: &str, url: &str) -> FleetPeer {
        FleetPeer {
            name: name.into(),
            rpc_url: url.into(),
            role: "seed".into(),
        }
    }

    #[test]
    fn netgroup_ipv4_uses_first_two_octets() {
        assert_eq!(netgroup_of("http://66.135.23.193:8332"), (66u16 << 8) | 135);
        // Same /16 -> same bucket regardless of the last two octets/port.
        assert_eq!(
            netgroup_of("http://66.135.99.1:1"),
            netgroup_of("http://66.135.23.193:8332")
        );
        // Different /16 -> different bucket.
        assert_ne!(
            netgroup_of("http://66.135.23.1:1"),
            netgroup_of("http://140.82.57.1:1")
        );
    }

    #[test]
    fn netgroup_nonip_is_stable_and_deterministic() {
        let a = netgroup_of("http://seed.example.com:8332");
        assert_eq!(a, netgroup_of("http://seed.example.com:8332"));
    }

    #[test]
    fn netgroup_ipv6_bracketed_and_bucketed_by_network() {
        // Bracketed IPv6 with a port parses to the address itself, not the
        // mangled pre-colon text the old `split(':')` produced.
        let a = netgroup_of("http://[2001:db8::1]:8332");
        // Deterministic.
        assert_eq!(a, netgroup_of("http://[2001:db8::1]:8332"));
        // Bracket-with-port == bracket-without-port == unbracketed literal.
        assert_eq!(a, netgroup_of("http://[2001:db8::1]"));
        assert_eq!(a, netgroup_of("http://2001:db8::1"));
        // Same /32 network, different host suffix -> same bucket.
        assert_eq!(a, netgroup_of("http://[2001:db8:ffff::9]:1"));
        // THE FIX: two IPv6 addresses sharing only the leading hextet but in
        // different /32 networks must NOT collapse into one bucket — the old
        // code mangled both to "[2001" and hashed them identically.
        assert_ne!(a, netgroup_of("http://[2001:dead::1]:8332"));
        // Entirely different network -> different bucket.
        assert_ne!(a, netgroup_of("http://[2a01:4f8::1]:8332"));
    }

    #[test]
    fn netgroup_ipv4_mapped_ipv6_folds_onto_ipv4_bucket() {
        assert_eq!(
            netgroup_of("http://[::ffff:66.135.23.193]:8332"),
            netgroup_of("http://66.135.23.193:8332")
        );
    }

    #[cfg(feature = "metrics")]
    #[test]
    fn metrics_render_exposes_series_and_gates_absent_data() {
        use super::metrics_endpoint::{render_for_test, Snapshot};

        // Everything present: all eight series, each a typed gauge.
        let full = Snapshot {
            host_present: true,
            ram_used_pct: 42,
            swap_used_pct: 7,
            uptime_secs: 12345,
            mempool_present: true,
            mempool_txs: 9,
            fleet_present: true,
            fleet_stalled: 2,
            fleet_low_peer: 1,
            fleet_divergent: 0,
            fleet_median_difficulty: 100_000,
        };
        let out = render_for_test(&full);
        for name in [
            "coincync_node_ram_usage_percent",
            "coincync_node_swap_usage_percent",
            "coincync_node_uptime_seconds",
            "coincync_node_mempool_transactions",
            "coincync_fleet_stalled_nodes",
            "coincync_fleet_low_peer_nodes",
            "coincync_fleet_divergent_nodes",
            "coincync_fleet_median_difficulty",
        ] {
            assert!(out.contains(&format!("# TYPE {name} gauge")), "missing TYPE for {name}");
        }
        assert!(out.contains("coincync_node_ram_usage_percent 42\n"));
        assert!(out.contains("coincync_fleet_median_difficulty 100000\n"));

        // RPC unavailable: host metrics still flow; mempool + fleet are omitted.
        let host_only = Snapshot {
            host_present: true,
            ram_used_pct: 5,
            ..Default::default()
        };
        let out2 = render_for_test(&host_only);
        assert!(out2.contains("coincync_node_ram_usage_percent 5\n"));
        assert!(
            !out2.contains("coincync_node_mempool_transactions"),
            "mempool must be omitted when absent"
        );
        assert!(
            !out2.contains("coincync_fleet_stalled_nodes"),
            "fleet metrics must be omitted when absent"
        );
    }

    #[cfg(feature = "metrics")]
    #[test]
    fn absent_publishers_clear_present_flags_so_stale_series_are_omitted() {
        // audit #38: a failed refresh must clear the *_present flags so /metrics
        // omits those series instead of serving the last-successful (stale)
        // values. Populate as a good tick would, then simulate a failed refresh.
        use super::metrics_endpoint::{
            publish_fleet, publish_fleet_absent, publish_health, publish_health_absent,
            render_for_test, Snapshot,
        };
        use std::sync::{Arc, Mutex};

        let state = Arc::new(Mutex::new(Snapshot::default()));
        publish_health(&state, 50, 10, 1000, 7);
        publish_fleet(&state, 1, 0, 0, 42);
        {
            let out = render_for_test(&state.lock().unwrap());
            assert!(out.contains("coincync_node_mempool_transactions 7\n"));
            assert!(out.contains("coincync_fleet_stalled_nodes 1\n"));
        }

        // Failed refreshes → clear the series.
        publish_health_absent(&state);
        publish_fleet_absent(&state);
        let out = render_for_test(&state.lock().unwrap());
        assert!(
            !out.contains("coincync_node_mempool_transactions"),
            "mempool omitted after a failed refresh, not served stale"
        );
        assert!(
            !out.contains("coincync_node_ram_usage_percent"),
            "host omitted after a failed refresh, not served stale"
        );
        assert!(
            !out.contains("coincync_fleet_stalled_nodes"),
            "fleet omitted after a failed refresh, not served stale"
        );
    }

    #[test]
    fn pct_is_bounded_and_zero_total_safe() {
        assert_eq!(pct_u8(0, 0), 0);
        assert_eq!(pct_u8(1, 4), 25);
        assert_eq!(pct_u8(4, 4), 100);
        assert!(pct_u8(10, 3) <= 100, "must clamp to 100");
    }

    #[test]
    fn largest_netgroup_detects_concentration() {
        // 3 of 4 peers share one /16 -> 75% concentration (eclipse input).
        let peers = vec![
            peer("a", "http://66.135.1.1:1"),
            peer("b", "http://66.135.2.2:1"),
            peer("c", "http://66.135.3.3:1"),
            peer("d", "http://10.0.0.1:1"),
        ];
        assert_eq!(largest_netgroup_pct(&peers), 75);
        assert_eq!(
            largest_netgroup_pct(&[]),
            0,
            "empty peer set is not concentrated"
        );
    }

    #[test]
    fn sentinel_reading_maps_real_fields_and_zeroes_the_rest() {
        let agg = AggregateFleetHealth {
            total_hosts: 4,
            stalled_count: 2,
            low_peer_count: 0,
            divergent_count: 0,
            median_difficulty: 0,
            high_ram_count: 0,
            high_disk_count: 0,
        };
        let peers = vec![
            peer("a", "http://66.135.1.1:1"),
            peer("b", "http://66.135.2.2:1"),
        ];
        let r = sentinel_reading(&agg, &peers);
        assert_eq!(
            r.unreachable_sentinel_pct, 50,
            "2 of 4 hosts stalled -> 50%"
        );
        assert_eq!(r.largest_netgroup_pct, 100, "both peers share a /16");
        // Fields the read-only HealthTick can't see stay 0 (never false-trip).
        assert_eq!(r.inbound_new_per_min, 0);
        assert_eq!(r.duplicate_msg_pct, 0);
    }

    #[test]
    fn sentinel_reading_drives_spider_signatures_end_to_end() {
        // A concentrated + stalled fleet must trip both eclipse and partition
        // through the real derivation path.
        let agg = AggregateFleetHealth {
            total_hosts: 4,
            stalled_count: 3, // 75% unreachable -> partition
            low_peer_count: 0,
            divergent_count: 0,
            median_difficulty: 0,
            high_ram_count: 0,
            high_disk_count: 0,
        };
        let peers = vec![
            peer("a", "http://66.135.1.1:1"),
            peer("b", "http://66.135.2.2:1"), // same /16 -> 100% concentration
        ];
        let sigs = spider::assess(&sentinel_reading(&agg, &peers));
        assert!(sigs.contains(&ThreatSignature::EclipsePressure));
        assert!(sigs.contains(&ThreatSignature::PartitionOnset));
    }
}
