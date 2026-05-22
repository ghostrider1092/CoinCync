//! coincync-rig — CoinCync canonical CPU miner.
//!
//! Phase 1 shipped: hasher correctness foundation.
//! Phase 2 shipped: Stratum client (compiles, parse-tested, no live pool yet).
//! Phase 3 shipped: worker pool scaffold (compiles, nonce/blob tested).
//! Phase 4a (this commit): operator-grade subcommands that exercise the
//! foundation immediately — hash verifier, benchmark, daemon info.
//! Phase 4b: full solo mining loop (orchestrator + coinbase construction).
//! Phase 5: failover, auto-reconnect, TLS, Prometheus, ratatui dashboard.
//!
//! ## What you can do with the binary today
//!
//!   coincync-rig --version
//!   coincync-rig selftest                          # one fixed-input hash
//!   coincync-rig verify --anchor HEX --tx-root HEX --height N --nonce HEX [--target HEX]
//!   coincync-rig bench [--threads N] [--duration SECS]
//!   coincync-rig info --node URL [--api-key KEY]   # check daemon connectivity

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use coincync::primitives::Hash;
use tracing::info;

mod daemon;
mod hasher;
mod metrics;
mod orchestrator;
mod stratum;
mod tui;
mod tui_blockfont;
mod tui_theme;
mod worker;

use daemon::DaemonClient;
use hasher::{HashInput, Hasher};

#[derive(Parser)]
#[command(name = "coincync-rig")]
#[command(about = "CoinCync canonical CPU miner.")]
#[command(version)]
struct Cli {
    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Subcommand)]
enum Command {
    /// One-shot hash of a fixed test input. Smallest possible end-to-end
    /// check that the binary + RandomX FFI are wired correctly.
    Selftest,

    /// Hash a specific (anchor, tx_root, height, nonce) tuple and print
    /// the result. Optionally check it against a target. The most
    /// useful debugging tool we ship — use it when a pool reports a
    /// share rejected and you want to know why locally.
    Verify {
        /// 32-byte anchor as hex.
        #[arg(long)]
        anchor: String,
        /// 32-byte tx_root as hex.
        #[arg(long)]
        tx_root: String,
        /// Block height (used to derive the RandomX epoch seed).
        #[arg(long)]
        height: u64,
        /// 8-byte (u64) nonce as hex (with or without 0x prefix).
        #[arg(long)]
        nonce: String,
        /// Optional 32-byte target as hex; if set, prints whether the
        /// hash meets the difficulty.
        #[arg(long)]
        target: Option<String>,
    },

    /// Benchmark mode — hash as fast as possible for `--duration` seconds
    /// using `--threads` worker threads, then print total hashes and H/s.
    /// No share submission, no pool. Just raw RandomX throughput on this
    /// machine. Output is the number to compare against xmrig on the
    /// same hardware (typical gap: 5-15%).
    Bench {
        /// Number of worker threads. 0 = auto-detect (cpu count).
        #[arg(long, default_value = "0")]
        threads: usize,
        /// Benchmark duration in seconds.
        #[arg(long, default_value = "30")]
        duration: u64,
    },

    /// Connect to a daemon, run `get_info`, print height + tip + peers.
    /// The "is the network even reachable" smoke test — does NOT mine.
    Info {
        /// Daemon JSON-RPC URL. Examples:
        ///   http://127.0.0.1:28081                    (local)
        ///   https://api.coincync.network/rpc/testnet  (public Cloudflare-fronted)
        #[arg(long)]
        node: String,
        /// Bearer API key (env: COINCYNC_RPC_API_KEY). Required when
        /// the daemon enforces auth; optional when behind nginx that
        /// injects the bearer server-side (the public api.* path).
        #[arg(long, env = "COINCYNC_RPC_API_KEY")]
        api_key: Option<String>,
    },

    /// Solo mining loop: poll a daemon for templates, build the
    /// candidate block (coinbase paying `--address`), search for a
    /// valid nonce, submit on found, repeat. Multi-thread, auto-
    /// reconnect, optional Prometheus /metrics endpoint, optional
    /// ratatui dashboard.
    RunSolo {
        /// Daemon JSON-RPC URL.
        #[arg(long)]
        node: String,
        /// Bearer API key (env: COINCYNC_RPC_API_KEY).
        #[arg(long, env = "COINCYNC_RPC_API_KEY")]
        api_key: Option<String>,
        /// Mining payout address (full tCYNC.../CYNC... wallet address).
        #[arg(long)]
        address: String,
        /// Network. Defaults to testnet.
        #[arg(long, default_value = "testnet")]
        network: NetworkArg,
        /// Refresh template every N seconds. If no nonce is found in
        /// this window, the loop pulls a fresh template (in case the
        /// chain advanced under us).
        #[arg(long, default_value = "60")]
        poll_interval_secs: u64,
        /// Number of mining threads. 0 = auto-detect (cpu count).
        /// On a 1-vCPU box (e.g. the Vultr api host) keep at 1 so the
        /// node + nginx still get cycles.
        #[arg(long, default_value = "0")]
        threads: usize,
        /// If set, expose a Prometheus /metrics endpoint on this TCP
        /// port. 0 = disabled. Defaults to binding `127.0.0.1` only —
        /// override with --metrics-bind to publish more widely. /metrics
        /// is unauthenticated, so non-loopback binds should be firewalled.
        #[arg(long, default_value = "0")]
        metrics_port: u16,
        /// Bind address for the /metrics endpoint. Default `127.0.0.1`
        /// (loopback only — safe by default). Set to `0.0.0.0` to expose
        /// to all interfaces, or to a specific internal IP for split-
        /// horizon scraping. Operators upgrading from earlier versions
        /// previously got 0.0.0.0 implicitly; set this explicitly to
        /// restore that behavior.
        #[arg(long, default_value = "127.0.0.1")]
        metrics_bind: String,
        /// Render an interactive ratatui dashboard (stats bar + scrolling
        /// log pane). Tracing logs are routed into the pane instead of
        /// stdout while the TUI is up. Press q / Esc to quit. Don't use
        /// inside systemd units — the TUI needs a real TTY.
        #[arg(long, default_value_t = false)]
        tui: bool,
    },

    /// Same as `run-solo`, but takes a TOML config file. CLI flags
    /// override config values when both are present. Useful for
    /// systemd units that don't want long ExecStart lines.
    RunConfig {
        /// Path to a TOML config file. See docs/CONFIG.md.
        #[arg(long, default_value = "/etc/coincync-rig/coincync-rig.toml")]
        config: String,
    },
}

/// Network selector that maps cleanly to coincync::config::NetworkType.
///
/// Regtest is accepted so local end-to-end mine + send rehearsals
/// (the kind that exercise spawn_blocking + cover-packet flows
/// against a real chain without polluting the live testnet) can run
/// against an isolated `coincync-node --network regtest` instance.
#[derive(Clone, Copy, Debug, clap::ValueEnum)]
enum NetworkArg {
    Mainnet,
    Testnet,
    Regtest,
}

impl NetworkArg {
    fn into_network_type(self) -> coincync::config::NetworkType {
        match self {
            NetworkArg::Mainnet => coincync::config::NetworkType::Mainnet,
            NetworkArg::Testnet => coincync::config::NetworkType::Testnet,
            NetworkArg::Regtest => coincync::config::NetworkType::Regtest,
        }
    }
}

fn main() -> Result<()> {
    // Parse CLI BEFORE installing the tracing subscriber so we can pick
    // a fmt-to-stdout subscriber (default) vs a TuiLogLayer (--tui) on
    // the basis of which command was selected. Once a global subscriber
    // is set, swapping it is not supported, so we have to commit early.
    let cli = Cli::parse();

    let tui_log_rx: Option<std::sync::mpsc::Receiver<String>> =
        if matches!(&cli.command, Some(Command::RunSolo { tui: true, .. })) {
            use tracing_subscriber::layer::SubscriberExt;
            let (layer, rx) = tui::TuiLogLayer::new();
            let env_filter = tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"));
            let subscriber = tracing_subscriber::registry()
                .with(env_filter)
                .with(layer);
            tracing::subscriber::set_global_default(subscriber)
                .expect("setting tracing subscriber failed");
            Some(rx)
        } else {
            tracing_subscriber::fmt()
                .with_env_filter(
                    tracing_subscriber::EnvFilter::try_from_default_env()
                        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
                )
                .init();
            None
        };

    print_banner();

    match cli.command.unwrap_or(Command::Selftest) {
        Command::Selftest => run_selftest(),
        Command::Verify { anchor, tx_root, height, nonce, target } => {
            run_verify(&anchor, &tx_root, height, &nonce, target.as_deref())
        }
        Command::Bench { threads, duration } => run_bench(threads, duration),
        Command::Info { node, api_key } => run_info(&node, api_key),
        Command::RunSolo { node, api_key, address, network, poll_interval_secs, threads, metrics_port, metrics_bind, tui } => {
            run_solo_cli(&node, api_key, &address, network, poll_interval_secs, threads, metrics_port, &metrics_bind, tui, tui_log_rx)
        }
        Command::RunConfig { config } => run_config_cli(&config),
    }
}

fn print_banner() {
    println!("CoinCync Rig v{}", env!("CARGO_PKG_VERSION"));
    println!("No donation. No telemetry. No surprises.");
    println!();
}

fn run_selftest() -> Result<()> {
    info!("running hasher selftest with fixed input");
    let input = HashInput {
        anchor: Hash::from_bytes([0x11; 32]),
        tx_root: Hash::from_bytes([0x22; 32]),
        height: 1,
    };
    let nonce = 0xC01D_C7AC_u64;
    let h = Hasher::new().hash(&input, nonce)?;
    println!("input.anchor   = {}", hex::encode(input.anchor.as_bytes()));
    println!("input.tx_root  = {}", hex::encode(input.tx_root.as_bytes()));
    println!("input.height   = {}", input.height);
    println!("nonce          = {:#018x}", nonce);
    println!("pow_hash       = {}", hex::encode(h.as_bytes()));
    println!();
    println!("OK — hasher returned a value. `cargo test -p coincync-rig`");
    println!("verifies byte-for-byte agreement with the validator.");
    Ok(())
}

// ─── verify ──────────────────────────────────────────────────────────

fn run_verify(
    anchor_hex: &str,
    tx_root_hex: &str,
    height: u64,
    nonce_hex: &str,
    target_hex: Option<&str>,
) -> Result<()> {
    let anchor = decode_hash(anchor_hex).context("bad --anchor")?;
    let tx_root = decode_hash(tx_root_hex).context("bad --tx_root")?;
    let nonce = decode_nonce(nonce_hex).context("bad --nonce")?;
    let input = HashInput { anchor, tx_root, height };

    let h = Hasher::new().hash(&input, nonce)?;
    println!("anchor        = {}", hex::encode(input.anchor.as_bytes()));
    println!("tx_root       = {}", hex::encode(input.tx_root.as_bytes()));
    println!("height        = {}", input.height);
    println!("nonce         = {:#018x}", nonce);
    println!("pow_hash      = {}", hex::encode(h.as_bytes()));

    if let Some(t) = target_hex {
        let target = decode_hash(t).context("bad --target")?;
        let meets = Hasher::new().meets_target(&h, &target);
        println!("target        = {}", hex::encode(target.as_bytes()));
        println!("meets target  = {}", if meets { "YES ✓" } else { "no" });
        if !meets {
            std::process::exit(1);
        }
    }
    Ok(())
}

fn decode_hash(s: &str) -> Result<Hash> {
    let bytes = hex::decode(s.trim_start_matches("0x")).context("not valid hex")?;
    let arr: [u8; 32] = bytes
        .try_into()
        .map_err(|v: Vec<u8>| anyhow::anyhow!("expected 32 bytes, got {}", v.len()))?;
    Ok(Hash::from_bytes(arr))
}

fn decode_nonce(s: &str) -> Result<u64> {
    let cleaned = s.trim_start_matches("0x");
    u64::from_str_radix(cleaned, 16).context("not valid u64 hex")
}

// ─── bench ───────────────────────────────────────────────────────────

fn run_bench(threads: usize, duration_secs: u64) -> Result<()> {
    let n_threads = if threads == 0 {
        match std::thread::available_parallelism() {
            Ok(n) => n.get(),
            Err(e) => {
                tracing::warn!(
                    error = %e,
                    "available_parallelism() failed; falling back to 1 mining thread — \
                     pass --threads N explicitly to override",
                );
                1
            }
        }
    } else {
        threads
    };
    println!(
        "Benchmarking with {} thread(s) for {} seconds...",
        n_threads, duration_secs
    );
    println!("(RandomX VM warmup is included in the duration — first 1-2s is 0 H/s)");
    println!();

    // Single shared input — every thread hashes (input, nonce_n) for
    // increasing n. We don't care about share validity here; only raw
    // throughput of the hash function.
    let input = Arc::new(HashInput {
        anchor: Hash::from_bytes([0xA1; 32]),
        tx_root: Hash::from_bytes([0xB2; 32]),
        height: 1,
    });
    let total_hashes = Arc::new(AtomicU64::new(0));
    let stop_flag = Arc::new(std::sync::atomic::AtomicBool::new(false));

    let started = Instant::now();
    let mut handles = Vec::with_capacity(n_threads);
    for tid in 0..n_threads {
        let input = input.clone();
        let counter = total_hashes.clone();
        let stop = stop_flag.clone();
        handles.push(std::thread::spawn(move || {
            let hasher = Hasher::new();
            // Each thread starts from a different nonce slice so we
            // never have two threads hashing the same (input, nonce).
            let mut nonce: u64 = (tid as u64) << 32;
            let mut local: u64 = 0;
            while !stop.load(Ordering::Relaxed) {
                let _ = hasher.hash(&input, nonce);
                nonce = nonce.wrapping_add(1);
                local += 1;
                if local % 1024 == 0 {
                    counter.fetch_add(1024, Ordering::Relaxed);
                    local = 0;
                }
            }
            counter.fetch_add(local, Ordering::Relaxed);
        }));
    }

    std::thread::sleep(Duration::from_secs(duration_secs));
    stop_flag.store(true, Ordering::Relaxed);
    for h in handles {
        let _ = h.join();
    }
    let elapsed = started.elapsed();
    let total = total_hashes.load(Ordering::Relaxed);
    let hps = total as f64 / elapsed.as_secs_f64();

    println!("Results:");
    println!("  Total hashes:  {}", total);
    println!("  Elapsed:       {:.2}s", elapsed.as_secs_f64());
    println!("  Hashrate:      {:.0} H/s", hps);
    println!("  Per thread:    {:.0} H/s avg", hps / n_threads as f64);
    Ok(())
}

// ─── info ────────────────────────────────────────────────────────────

fn run_info(node: &str, api_key: Option<String>) -> Result<()> {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .context("creating tokio runtime")?;
    rt.block_on(async {
        let client = DaemonClient::new(node, api_key)?;
        let info = client.get_info().await?;
        println!("daemon: {node}");
        if let Some(h) = info.get("height").and_then(|v| v.as_u64()) {
            println!("  height       = {h}");
        }
        if let Some(t) = info.get("target_height").and_then(|v| v.as_u64()) {
            println!("  target       = {t}");
        }
        if let Some(p) = info.get("peer_count").and_then(|v| v.as_u64()) {
            println!("  peers        = {p}");
        }
        if let Some(s) = info.get("synced").and_then(|v| v.as_bool()) {
            println!("  synced       = {s}");
        }
        if let Some(a) = info.get("tip_age_secs").and_then(|v| v.as_u64()) {
            println!("  tip_age_s    = {a}");
        }
        Ok::<_, anyhow::Error>(())
    })
}

// ─── run-solo ────────────────────────────────────────────────────────

fn run_solo_cli(
    node: &str,
    api_key: Option<String>,
    address: &str,
    network: NetworkArg,
    poll_interval_secs: u64,
    threads: usize,
    metrics_port: u16,
    metrics_bind: &str,
    tui_enabled: bool,
    tui_log_rx: Option<std::sync::mpsc::Receiver<String>>,
) -> Result<()> {
    let n_threads = if threads == 0 {
        match std::thread::available_parallelism() {
            Ok(n) => n.get(),
            Err(e) => {
                tracing::warn!(
                    error = %e,
                    "available_parallelism() failed; falling back to 1 mining thread — \
                     pass --threads N explicitly to override",
                );
                1
            }
        }
    } else {
        threads
    };
    // Multi-thread runtime here (vs current_thread for `info`) because
    // the orchestrator spawns helper tasks (auto-reconnect + the
    // Prometheus /metrics accept loop).
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .context("creating tokio runtime")?;

    // If --tui is set, the TUI dashboard always wants a MetricsState so
    // its stats bar has something to read — promote it from "optional
    // observability surface" to "required when TUI is up".
    let need_metrics_state = metrics_port != 0 || tui_enabled;

    rt.block_on(async {
        let client = DaemonClient::new(node, api_key)?;
        match client.get_info().await {
            Ok(info) => {
                let height = info.get("height").and_then(|v| v.as_u64()).unwrap_or(0);
                let synced = info.get("synced").and_then(|v| v.as_bool()).unwrap_or(false);
                println!("daemon ok: height={height} synced={synced}");
            }
            Err(e) => {
                println!("daemon get_info failed: {e}");
                println!("(continuing — orchestrator retries per-template)");
            }
        }
        println!("mining threads: {n_threads}");

        let metrics_state = if need_metrics_state {
            Some(metrics::MetricsState::new(n_threads))
        } else {
            None
        };
        if metrics_port != 0 {
            if let Some(state) = metrics_state.as_ref() {
                if let Err(e) = metrics::serve(metrics_bind, metrics_port, state.clone()).await {
                    tracing::warn!(error = %e, bind = metrics_bind, port = metrics_port,
                        "metrics: failed to bind /metrics endpoint, continuing without metrics");
                }
            }
        }

        // If --tui, hand the dashboard the same MetricsState the
        // orchestrator updates. The dashboard runs on a blocking thread
        // (raw-mode terminal I/O is sync); when it returns we exit the
        // process. The orchestrator has no cancel hook — interactive
        // miners terminate by quitting the TUI.
        if tui_enabled {
            let metrics_for_tui = metrics_state.clone()
                .expect("metrics_state must exist when tui_enabled");
            let log_rx = tui_log_rx.expect("tui mode set but no log channel");
            tokio::task::spawn_blocking(move || {
                if let Err(e) = tui::run_dashboard(metrics_for_tui, log_rx) {
                    eprintln!("tui error: {e}");
                }
                std::process::exit(0);
            });
        }

        orchestrator::run_solo(
            &client,
            address,
            network.into_network_type(),
            poll_interval_secs,
            n_threads,
            metrics_state,
        )
        .await
    })
}

// ─── run-config ──────────────────────────────────────────────────────

#[derive(serde::Deserialize, Debug)]
struct FileConfig {
    daemon: DaemonSection,
    mining: MiningSection,
}

#[derive(serde::Deserialize, Debug)]
struct DaemonSection {
    node: String,
    api_key: Option<String>,
}

#[derive(serde::Deserialize, Debug)]
struct MiningSection {
    address: String,
    #[serde(default = "default_network")]
    network: String,
    #[serde(default = "default_poll_interval")]
    poll_interval_secs: u64,
    #[serde(default)]
    threads: usize,
    /// Prometheus /metrics endpoint port. 0 (or unset) = disabled.
    #[serde(default)]
    metrics_port: u16,
    /// Bind address for /metrics. Default `127.0.0.1` (loopback only).
    /// Set to `0.0.0.0` or a specific internal IP to expose more widely;
    /// /metrics is unauthenticated, so non-loopback binds should be
    /// firewalled.
    #[serde(default = "default_metrics_bind")]
    metrics_bind: String,
}

fn default_metrics_bind() -> String {
    "127.0.0.1".to_string()
}

fn default_network() -> String {
    "testnet".to_string()
}
fn default_poll_interval() -> u64 {
    60
}

fn run_config_cli(config_path: &str) -> Result<()> {
    let raw = std::fs::read_to_string(config_path)
        .with_context(|| format!("reading config file {config_path}"))?;
    let cfg: FileConfig =
        toml::from_str(&raw).with_context(|| format!("parsing TOML at {config_path}"))?;

    let network = match cfg.mining.network.to_lowercase().as_str() {
        "mainnet" => NetworkArg::Mainnet,
        "testnet" => NetworkArg::Testnet,
        "regtest" => NetworkArg::Regtest,
        other => return Err(anyhow::anyhow!("unknown network in config: {other:?}")),
    };

    println!("config: {config_path}");
    println!("  daemon  = {}", cfg.daemon.node);
    println!(
        "  network = {:?}  poll_interval = {}s  threads = {}",
        network, cfg.mining.poll_interval_secs, cfg.mining.threads
    );

    // run-config never opens a TUI (it's the systemd entry point —
    // there's no TTY). If you want a TUI, use `run-solo --tui`.
    run_solo_cli(
        &cfg.daemon.node,
        cfg.daemon.api_key,
        &cfg.mining.address,
        network,
        cfg.mining.poll_interval_secs,
        cfg.mining.threads,
        cfg.mining.metrics_port,
        &cfg.mining.metrics_bind,
        false,
        None,
    )
}
