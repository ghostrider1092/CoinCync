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
        /// Signal miner readiness for the v1.0.12 hard-fork bundle
        /// (CIP-012 — encrypted_amount=8, dup-stealth rejection,
        /// per-output size caps, ring-size monotonic).
        ///
        /// When set, the rig appends a 4-byte SignalBits suffix to
        /// the coinbase `extra` field with the V1_0_12_BUNDLE bit set.
        /// Validators currently DON'T consult this signal (the v1.0.12
        /// rules on PR #68 are still height-gated by
        /// HARD_FORK_V1_0_12_HEIGHT) — so passing this flag today is
        /// informational only. Once BIP-9 wiring lands in a follow-up
        /// PR, the fork will activate when ≥SIGNAL_THRESHOLD blocks
        /// in a SIGNAL_WINDOW have this bit set AND the height gate
        /// is met. Operators upgrading to a v1.0.12-aware rig should
        /// enable this flag so the signal count accumulates as they
        /// mine — once the wiring activates, that history retroactively
        /// counts toward lock-in.
        #[arg(long, default_value_t = false)]
        signal_v1012: bool,
        /// Show full hashes/addresses instead of truncated (full
        /// consensus_fingerprint + full payout address in the startup banner).
        #[arg(long, default_value_t = false)]
        verbose: bool,
    },

    /// Mine against a CoinCync stratum POOL (the node's built-in `--stratum`
    /// pool, or any pool speaking CoinCync's login/job/submit protocol). The
    /// pool builds the coinbase to ITS payout address and assembles/submits
    /// blocks server-side; this client only searches nonces and submits.
    RunPool {
        /// Pool address, e.g. `127.0.0.1:3333`.
        #[arg(long)]
        pool: String,
        /// Worker login label sent to the pool (payout is decided by the pool).
        #[arg(long, default_value = "coincync-rig")]
        login: String,
        /// Optional pool password.
        #[arg(long, default_value = "")]
        password: String,
        /// Network. Defaults to testnet.
        #[arg(long, default_value = "testnet")]
        network: NetworkArg,
        /// Number of mining threads. 0 = auto-detect (cpu count).
        #[arg(long, default_value = "0")]
        threads: usize,
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
            let subscriber = tracing_subscriber::registry().with(env_filter).with(layer);
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
        Command::Verify {
            anchor,
            tx_root,
            height,
            nonce,
            target,
        } => run_verify(&anchor, &tx_root, height, &nonce, target.as_deref()),
        Command::Bench { threads, duration } => run_bench(threads, duration),
        Command::Info { node, api_key } => run_info(&node, api_key),
        Command::RunSolo {
            node,
            api_key,
            address,
            network,
            poll_interval_secs,
            threads,
            metrics_port,
            metrics_bind,
            tui,
            signal_v1012,
            verbose,
        } => run_solo_cli(
            &node,
            api_key,
            &address,
            network,
            poll_interval_secs,
            threads,
            metrics_port,
            &metrics_bind,
            tui,
            signal_v1012,
            verbose,
            tui_log_rx,
        ),
        Command::RunPool {
            pool,
            login,
            password,
            network,
            threads,
        } => run_pool_cli(&pool, &login, &password, network, threads),
        Command::RunConfig { config } => run_config_cli(&config),
    }
}

// ─── run-pool ────────────────────────────────────────────────────────

/// #145: the rig hashes through the shared
/// `coincync::consensus::pow::randomx_cache`, whose mode default became LIGHT
/// unless `NODE_MINING_ACTIVE` is set (#135). Only `coincync-node` set it (from
/// `--mine`), so the rig silently ran in light mode — ~7x slower. Every rig
/// MINING entry point (run-solo, run-pool, run-config → run-solo, bench) calls
/// this ONCE before the first `Hasher` is constructed, so the shared cache
/// builds a full-mem dataset. Verify/selftest/info stay light (a one-off check
/// doesn't need the 2 GB dataset). `COINCYNC_RANDOMX_LIGHT_MODE=1` remains the
/// explicit low-RAM opt-out.
fn activate_full_mem_hashing() {
    coincync::consensus::pow::set_node_mining_active(true);
}

fn run_pool_cli(
    pool: &str,
    login: &str,
    password: &str,
    network: NetworkArg,
    threads: usize,
) -> Result<()> {
    activate_full_mem_hashing(); // #145
    let net = network.into_network_type();
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .context("creating tokio runtime")?;
    println!("connecting to CoinCync pool {pool} …");
    rt.block_on(async move { orchestrator::run_pool(pool, login, password, net, threads).await })
}

/// Detect the CPU crypto features RandomX cares about (x86 only; `false`
/// elsewhere). Pure std — no extra dependency.
fn cpu_flags() -> (bool, bool) {
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    {
        (
            std::is_x86_feature_detected!("aes"),
            std::is_x86_feature_detected!("avx2"),
        )
    }
    #[cfg(not(any(target_arch = "x86", target_arch = "x86_64")))]
    {
        (false, false)
    }
}

/// XMRig-style system-info banner, CoinCync-branded (teal/green, "the mole goes
/// underground" ethos — no gold). Shows what the rig is and what it will run on:
/// version, PoW, CPU + the crypto features that gate RandomX speed. Degrades to a
/// plain, un-colored banner when stdout is not a terminal (piped / logged), so a
/// captured log never carries escape codes.
fn print_banner() {
    use crossterm::style::{Color, Stylize};
    use std::io::IsTerminal;

    let ver = env!("CARGO_PKG_VERSION");
    let cores = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(0);
    let arch = std::env::consts::ARCH;
    let os = std::env::consts::OS;
    let (aes, avx2) = cpu_flags();
    let yn = |b: bool| if b { "yes" } else { "no" };

    // CPU model + memory via sysinfo (one-time read for the banner).
    let sys = sysinfo::System::new_all();
    let cpu_desc = sys
        .cpus()
        .first()
        .map(|c| c.brand().trim().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| format!("{arch} CPU"));
    let total_gb = sys.total_memory() as f64 / 1_000_000_000.0;
    let used_gb = sys.used_memory() as f64 / 1_000_000_000.0;
    let mem_pct = if total_gb > 0.0 {
        (used_gb / total_gb * 100.0).round() as u32
    } else {
        0
    };

    // Plain fallback for non-terminals (pipes, log files).
    if !std::io::stdout().is_terminal() {
        println!("CoinCync Rig v{ver}  (RandomX, CPU-only)");
        println!("the mole goes underground - no donation, no telemetry, no surprises");
        println!("POW RandomX (rx/cync)");
        println!("CPU {cpu_desc} ({cores} cores, {arch}, AES {}, AVX2 {})", yn(aes), yn(avx2));
        println!("MEMORY {used_gb:.1} / {total_gb:.1} GB ({mem_pct}% used)");
        println!("SYSTEM {os}");
        println!();
        return;
    }

    // Palette (no gold): teal accent for the frame + labels, green for "on",
    // soft off-white body, muted gray for secondary text.
    let teal = Color::Rgb { r: 86, g: 194, b: 180 };
    let teal_dim = Color::Rgb { r: 58, g: 130, b: 122 };
    let green = Color::Rgb { r: 127, g: 184, b: 121 };
    let body = Color::Rgb { r: 224, g: 230, b: 228 };
    let muted = Color::Rgb { r: 138, g: 148, b: 146 };

    // Framed title. Width derives from the longest content line so the box always
    // closes flush. ANSI codes are zero-width, so padding is computed on the plain
    // text and the colors applied after.
    let title = "CoinCync Rig  -  RandomX CPU miner".to_string();
    let sub = format!("v{ver} - the mole goes underground");
    let inner = title.chars().count().max(sub.chars().count()) + 2; // 1-space gutter each side
    let bar = "─".repeat(inner);

    let framed = |text: &str| {
        let pad = inner - 2 - text.chars().count(); // "│ " + text + pad + " │" = inner, so box closes flush
        format!(
            "  {} {}{} {}",
            "│".with(teal),
            text.with(body),
            " ".repeat(pad),
            "│".with(teal)
        )
    };

    println!();
    println!("  {}{}{}", "┌".with(teal), bar.clone().with(teal), "┐".with(teal));
    println!("{}", framed(&title));
    println!("{}", framed(&sub));
    println!("  {}{}{}", "└".with(teal), bar.with(teal), "┘".with(teal));
    println!();

    // XMRig-style `* LABEL  value` rows.
    let row = |label: &str, value: String| {
        println!(
            "   {} {}  {}",
            "*".with(teal),
            format!("{label:<9}").with(teal_dim).bold(),
            value
        );
    };
    let on = |b: bool| {
        if b {
            "yes".to_string().with(green).to_string()
        } else {
            "no".to_string().with(muted).to_string()
        }
    };
    // Continuation line, aligned under a row's value column (3 + "* " + 9 + 2).
    let cont = |value: String| println!("{}{}", " ".repeat(16), value);

    row("ABOUT", format!("{} {}", format!("CoinCync Rig v{ver}").with(body), "(RandomX, CPU-only)".with(muted)));
    row("POW", format!("{}  {}  {}", "RandomX".with(body), "·".with(muted), "rx/cync".with(muted)));
    row("CPU", cpu_desc.clone().with(body).to_string());
    cont(format!(
        "{} cores {} {} {} AES {} {} AVX2 {}",
        cores.to_string().with(body),
        "·".with(muted),
        arch.with(body),
        "·".with(muted),
        on(aes),
        "·".with(muted),
        on(avx2),
    ));
    row(
        "MEMORY",
        format!(
            "{} {} {} GB {} {}",
            format!("{used_gb:.1}").with(body),
            "/".with(muted),
            format!("{total_gb:.1}").with(body),
            "·".with(muted),
            format!("{mem_pct}% used").with(muted),
        ),
    );
    row("SYSTEM", os.with(body).to_string());
    row(
        "DONATE",
        format!(
            "{}  {}",
            "0%".with(green).bold(),
            "no donation · no telemetry · no surprises".with(muted)
        ),
    );
    println!();
}

/// HONEST run-solo startup metadata banner. Logged once, right after the
/// (reachable or not) startup `get_info`, before the mining loop starts.
///
/// Design rule: print ONLY what this rig can actually know.
///   * Rig-local facts (version, git commit, build profile, chosen network,
///     node URL, miner address, thread count, RandomX dataset mode, metrics
///     endpoint) come from the build / CLI / process.
///   * Chain + consensus facts (consensus_fingerprint, the node's own
///     `network` string, height/target, sync, tip age, difficulty, and — if
///     the daemon exposes it — network hashrate) come from the startup
///     `get_info` result and are omitted when a field is absent.
///   * Node-internal privacy machinery (Spark/shielded proving, SRS /
///     trusted-setup, nullifier DB, encrypted mempool, commitment tree) is
///     NEVER fabricated here. This is a transparent RandomX PoW miner; the
///     ZK posture line says exactly that and points at the node.
///
/// Best-effort: when `info` is `None` the node was unreachable at startup —
/// the CHAIN section says so and the loop's sync gate retries per-template.
/// Matches `print_banner`'s palette + `* LABEL value` row style, and degrades
/// to a plain, un-colored block when stdout is not a terminal.
#[allow(clippy::too_many_arguments)]
fn print_runsolo_metadata(
    node: &str,
    network: NetworkArg,
    address: &str,
    n_threads: usize,
    metrics_port: u16,
    metrics_bind: &str,
    info: Option<&serde_json::Value>,
    verbose: bool,
) {
    use crossterm::style::{Color, Stylize};
    use std::io::IsTerminal;

    let term = std::io::stdout().is_terminal();
    // Palette matches print_banner, extended with amber (warning), red (error)
    // and cyan (numeric / accent) so values are colored by MEANING — the
    // XMRig convention: green = healthy, amber = attention, red = fault.
    let teal = Color::Rgb { r: 86, g: 194, b: 180 };
    let teal_dim = Color::Rgb { r: 58, g: 130, b: 122 };
    let green = Color::Rgb { r: 127, g: 184, b: 121 };
    let amber = Color::Rgb { r: 218, g: 183, b: 94 };
    let red = Color::Rgb { r: 209, g: 108, b: 108 };
    let cyan = Color::Rgb { r: 122, g: 200, b: 214 };
    let body = Color::Rgb { r: 224, g: 230, b: 228 };
    let muted = Color::Rgb { r: 138, g: 148, b: 146 };

    // Conditional color: real ANSI in a TTY, clean plain text when piped to a
    // file / log (crossterm would otherwise emit escape codes either way).
    let p = |s: &str, col: Color| -> String {
        if term {
            s.with(col).to_string()
        } else {
            s.to_string()
        }
    };
    let pb = |s: &str, col: Color| -> String {
        if term {
            s.with(col).bold().to_string()
        } else {
            s.to_string()
        }
    };
    let sep = format!(" {} ", p("·", muted));
    // Trailing state badge: a geometric glyph in a TTY, an ASCII tag when piped.
    let badge = |glyph: &str, plain: &str, col: Color| -> String {
        if term {
            glyph.with(col).bold().to_string()
        } else {
            plain.to_string()
        }
    };

    // `* LABEL value` primary row + indented continuation, aligned under the
    // value column exactly like print_banner (3 + "* " + 9 + 2 = 16).
    let row = |label: &str, value: String| {
        if term {
            println!(
                "   {} {}  {}",
                "*".with(teal),
                format!("{label:<9}").with(teal_dim).bold(),
                value
            );
        } else {
            println!("   * {label:<9}  {value}");
        }
    };
    let cont = |value: String| println!("{}{}", " ".repeat(16), value);

    // ── NODE / SOFTWARE ─────────────────────────────────────────────
    let ver = env!("CARGO_PKG_VERSION");
    let commit = coincync::build_info::git_commit();
    let commit_short = if commit != "unknown" && commit.len() > 10 {
        &commit[..10]
    } else {
        commit
    };
    let profile = if cfg!(debug_assertions) {
        "debug"
    } else {
        "release"
    };
    row(
        "NODE",
        [
            pb(&format!("CoinCync Rig v{ver}"), cyan),
            p(&format!("commit {commit_short}"), muted),
            p(profile, if profile == "release" { green } else { amber }),
        ]
        .join(&sep),
    );

    // ── NETWORK ─────────────────────────────────────────────────────
    let net_id = format!("{network:?}").to_lowercase();
    row(
        "NETWORK",
        [p(&net_id, body), p(&format!("node {node}"), muted)].join(&sep),
    );
    if let Some(info) = info {
        // --verbose shows the full fingerprint; default truncates to 12 hex +
        // ellipsis (enough to spot a divergent peer at a glance).
        let fp = info
            .get("consensus_fingerprint")
            .and_then(|v| v.as_str())
            .map(|s| {
                if verbose || s.len() <= 12 {
                    s.to_string()
                } else {
                    format!("{}…", &s[..12])
                }
            });
        let net_field = info.get("network").and_then(|v| v.as_str());
        match (fp.as_deref(), net_field) {
            (Some(fp), Some(nf)) => cont(
                [
                    format!("{} {}", p("fingerprint", muted), pb(fp, cyan)),
                    p(&format!("node reports \"{nf}\""), body),
                ]
                .join(&sep),
            ),
            (Some(fp), None) => {
                cont(format!("{} {}", p("fingerprint", muted), pb(fp, cyan)))
            }
            (None, Some(nf)) => cont(p(&format!("node reports \"{nf}\""), body)),
            (None, None) => {}
        }
    }

    // ── CHAIN STATE ─────────────────────────────────────────────────
    // Purely from get_info. (get_info exposes no genesis hash and no
    // network_hashrate today — genesis omitted; hashrate shown only if a
    // future daemon reports it > 0.)
    if let Some(info) = info {
        let height = info.get("height").and_then(|v| v.as_u64());
        let target = info.get("target_height").and_then(|v| v.as_u64());
        let peer_target = info.get("peer_target_height").and_then(|v| v.as_u64());
        let synced = info
            .get("synced")
            .or_else(|| info.get("is_synced"))
            .and_then(|v| v.as_bool());
        let tip_age = info.get("tip_age_secs").and_then(|v| v.as_u64());
        // difficulty is emitted as a decimal string by get_info.
        let difficulty = info.get("difficulty").and_then(|v| {
            v.as_str()
                .map(|s| s.to_string())
                .or_else(|| v.as_u64().map(|n| n.to_string()))
        });

        let mut parts: Vec<String> = Vec::new();
        match (height, target) {
            (Some(h), Some(t)) => parts.push(format!(
                "{} {} {} {}",
                p("height", muted),
                pb(&h.to_string(), cyan),
                p("/ target", muted),
                pb(&t.to_string(), cyan)
            )),
            (Some(h), None) => parts.push(format!("{} {}", p("height", muted), pb(&h.to_string(), cyan))),
            _ => {}
        }
        if let Some(pt) = peer_target {
            if pt > 0 {
                parts.push(format!("{} {}", p("peer", muted), pb(&pt.to_string(), cyan)));
            }
        }
        if let Some(s) = synced {
            parts.push(if s {
                p("synced", green)
            } else {
                p("NOT synced", amber)
            });
        }
        if let Some(a) = tip_age {
            parts.push(p(&format!("tip {a}s"), muted));
        }
        if let Some(d) = difficulty {
            parts.push(format!("{} {}", p("diff", muted), pb(&d, cyan)));
        }
        // Trailing badge reflecting sync state: synced → ✔, syncing / NOT-synced
        // / unknown → ▲.
        let chain_badge = match synced {
            Some(true) => badge("✔", "[ok]", green),
            _ => badge("▲", "[!]", amber),
        };
        let chain_value = if parts.is_empty() {
            p("get_info returned no recognizable chain fields", muted)
        } else {
            parts.join(&sep)
        };
        row("CHAIN", format!("{chain_value}{sep}{chain_badge}"));
        let net_hr = info
            .get("network_hashrate")
            .and_then(|v| v.as_u64())
            .or_else(|| info.get("hashrate_hps").and_then(|v| v.as_u64()));
        if let Some(hr) = net_hr {
            if hr > 0 {
                cont(format!("{} {}", p("network", muted), pb(&format!("{hr} H/s"), cyan)));
            }
        }
    } else {
        row(
            "CHAIN",
            format!(
                "{}{sep}{}",
                p("node unreachable at startup — will retry per-template", red),
                badge("✖", "[x]", red)
            ),
        );
    }

    // ── MINING ──────────────────────────────────────────────────────
    // Short payout address, thread count, and RandomX dataset mode (full-mem
    // vs light — the SAME node_mining_active() signal the orchestrator's
    // hashrate-health guard uses, so the banner can't disagree with runtime).
    // --verbose shows the full payout address; default truncates it.
    let addr_disp = if verbose || address.len() <= 18 {
        address.to_string()
    } else {
        format!("{}…{}", &address[..10], &address[address.len() - 6..])
    };
    let light_forced = std::env::var("COINCYNC_RANDOMX_LIGHT_MODE")
        .map(|v| matches!(v.trim(), "1" | "true" | "TRUE" | "yes" | "on"))
        .unwrap_or(false);
    let full_mem = coincync::consensus::pow::node_mining_active() && !light_forced;
    let (rx_mode, rx_col) = if full_mem { ("full-mem", green) } else { ("light", amber) };
    // Trailing badge: full-mem → ✔, light → ▲.
    let mining_badge = if full_mem {
        badge("✔", "[ok]", green)
    } else {
        badge("▲", "[!]", amber)
    };
    row(
        "MINING",
        [
            p(&format!("addr {addr_disp}"), body),
            format!("{} {}", pb(&n_threads.to_string(), cyan), p("threads", muted)),
            format!("{} {}", p("RandomX", muted), p(rx_mode, rx_col)),
            mining_badge,
        ]
        .join(&sep),
    );
    if metrics_port != 0 {
        cont(format!(
            "{} {}",
            p("metrics", muted),
            p(&format!("{metrics_bind}:{metrics_port}"), body)
        ));
    }

    // ── PRIVACY / ZK POSTURE (honest) ───────────────────────────────
    // No SRS/circuit/nullifier/commitment values invented — this is a
    // transparent PoW miner; shielded machinery is node-side and inactive.
    row(
        "PRIVACY",
        [
            p("transparent RandomX PoW", body),
            p("shielded/Spark node-side", muted),
            p("INACTIVE", amber),
        ]
        .join(&sep),
    );
    cont(p("activation height not yet reached — see node logs", muted));
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
    println!("nonce          = {nonce:#018x}");
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
    let input = HashInput {
        anchor,
        tx_root,
        height,
    };

    let h = Hasher::new().hash(&input, nonce)?;
    println!("anchor        = {}", hex::encode(input.anchor.as_bytes()));
    println!("tx_root       = {}", hex::encode(input.tx_root.as_bytes()));
    println!("height        = {}", input.height);
    println!("nonce         = {nonce:#018x}");
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
    activate_full_mem_hashing(); // #145 — bench must measure full-mem hashrate
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
    println!("Benchmarking with {n_threads} thread(s) for {duration_secs} seconds...");
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

    // Use the same auto-scaling formatter the TUI uses so bench output
    // matches what an operator sees mid-mining. Without this, a Phase-2
    // box hitting 163000 H/s renders as "163000 H/s" which a tired
    // operator misreads as 163 H/s -- the exact "explorer says 163 hs"
    // confusion the community has been hitting.
    let (hps_digits, hps_unit) = tui_blockfont::format_hashrate(hps.round() as u64);
    let per_thread = hps / n_threads as f64;
    let (pt_digits, pt_unit) = tui_blockfont::format_hashrate(per_thread.round() as u64);

    println!("Results:");
    println!("  Total hashes:  {total}");
    println!("  Elapsed:       {:.2}s", elapsed.as_secs_f64());
    println!("  Hashrate:      {hps_digits} {hps_unit}");
    println!("  Per thread:    {pt_digits} {pt_unit} avg");
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

#[allow(clippy::too_many_arguments)] // CLI dispatch: mirrors the run-solo flag set
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
    signal_v1012: bool,
    verbose: bool,
    tui_log_rx: Option<std::sync::mpsc::Receiver<String>>,
) -> Result<()> {
    activate_full_mem_hashing(); // #145 (also covers run-config, which calls this)
    // Build SignalBits from miner opt-in flags. Today there's only
    // V1_0_12_BUNDLE (CIP-012); future CIPs add their own flag here
    // and OR their bit into `signal_raw`. Passing SignalBits(0)
    // produces a legacy 8-byte coinbase.extra (byte-identical to
    // pre-CIP-012 miners); passing any non-zero set produces the
    // 12-byte form. See fork_signal::encode_coinbase_extra.
    let signal_bits = {
        let mut raw = 0u32;
        if signal_v1012 {
            raw |= coincync::consensus::fork_signal::bits::V1_0_12_BUNDLE;
        }
        if raw == 0 {
            coincync::consensus::fork_signal::SignalBits(0)
        } else {
            coincync::consensus::fork_signal::SignalBits::new(raw)
        }
    };
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

    // The solo miner always keeps a MetricsState now: it is the live hashrate /
    // health source the loop's colored heartbeat reads from (as do the --tui
    // dashboard and the optional /metrics endpoint). It is a cheap Arc of
    // atomics updated inline by the mining loop — no extra threads, no cost when
    // nothing reads it — so it is unconditional rather than gated on
    // --tui / --metrics-port, which means a plain miner also gets the heartbeat.

    rt.block_on(async {
        let client = DaemonClient::new(node, api_key)?;
        // Best-effort startup get_info — feeds the HONEST metadata banner.
        // On failure we don't bail: the banner prints "node: unreachable at
        // startup" and the orchestrator's sync gate retries per-template.
        let startup_info = match client.get_info().await {
            Ok(info) => Some(info),
            Err(e) => {
                tracing::warn!(
                    error = %e,
                    "run-solo: get_info failed at startup — continuing, \
                     orchestrator retries per-template"
                );
                None
            }
        };
        print_runsolo_metadata(
            node,
            network,
            address,
            n_threads,
            metrics_port,
            metrics_bind,
            startup_info.as_ref(),
            verbose,
        );

        let metrics_state = Some(metrics::MetricsState::new(n_threads));
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
            let metrics_for_tui = metrics_state
                .clone()
                .expect("metrics_state must exist when tui_enabled");
            let log_rx = tui_log_rx.expect("tui mode set but no log channel");
            tokio::task::spawn_blocking(move || {
                if let Err(e) = tui::run_dashboard(metrics_for_tui, log_rx) {
                    eprintln!("tui error: {e}");
                }
                std::process::exit(0);
            });
        }

        // Graceful shutdown: race the mining loop against SIGINT (ctrl-c). On a
        // plain CLI we print a framed session summary and exit cleanly; under
        // --tui the dashboard owns the terminal and already exits on q/Esc, so
        // we just exit without scribbling over it. Clone the metrics handle
        // first — run_solo takes ownership of the original.
        let started = std::time::Instant::now();
        let metrics_shutdown = metrics_state.clone();
        tokio::select! {
            res = orchestrator::run_solo(
                &client,
                address,
                network.into_network_type(),
                poll_interval_secs,
                n_threads,
                metrics_state,
                signal_bits,
                // Colored live heartbeat on the plain CLI; suppressed under --tui,
                // which owns the terminal with its own dashboard.
                !tui_enabled,
            ) => {
                res
            }
            _ = tokio::signal::ctrl_c() => {
                if !tui_enabled {
                    if let Some(m) = metrics_shutdown.as_ref() {
                        print_shutdown_summary(m, started.elapsed());
                    }
                }
                std::process::exit(0);
            }
        }
    })
}

/// Framed session summary printed on ctrl-c (plain-CLI only). Reuses the
/// startup banner's teal framed-box style. All figures come straight from the
/// live MetricsState atomics — nothing fabricated.
fn print_shutdown_summary(m: &metrics::MetricsState, uptime: std::time::Duration) {
    use crossterm::style::{Color, Stylize};
    use std::io::IsTerminal;
    use std::sync::atomic::Ordering::Relaxed;

    let term = std::io::stdout().is_terminal();
    let teal = Color::Rgb { r: 86, g: 194, b: 180 };
    let body = Color::Rgb { r: 224, g: 230, b: 228 };

    let secs = uptime.as_secs();
    let uptime_str = format!("{:02}:{:02}:{:02}", secs / 3600, (secs % 3600) / 60, secs % 60);

    let hashes = m.hashes_total.load(Relaxed);
    let found = m.blocks_found_total.load(Relaxed);
    let accepted = m.blocks_accepted_total.load(Relaxed);
    let threads = m.threads.load(Relaxed);
    // Average over the whole session (not the instantaneous rate), via the same
    // auto-scaling formatter the heartbeat uses.
    let avg_hps = if secs > 0 { hashes / secs } else { 0 };
    let (ad, au) = tui_blockfont::format_hashrate(avg_hps);

    let title = "CoinCync Rig  -  session summary".to_string();
    let lines = [
        format!("uptime    {uptime_str}"),
        format!("hashes    {}", group_thousands(hashes)),
        format!("blocks    {found} found · {accepted} accepted"),
        format!("avg rate  {ad} {au}"),
        format!("threads   {threads}"),
    ];

    // Box width derives from the longest plain line (ANSI codes are zero-width,
    // so padding is computed on plain text then colored — same as print_banner).
    let inner = lines
        .iter()
        .map(|l| l.chars().count())
        .chain(std::iter::once(title.chars().count()))
        .max()
        .unwrap_or(0)
        + 2;
    let bar = "─".repeat(inner);
    let framed = |text: &str, col: Color| {
        // 1-space gutter each side: "│ " + text + pad + " │" fills exactly `inner`.
        let pad = inner - 2 - text.chars().count();
        if term {
            format!(
                "  {} {}{} {}",
                "│".with(teal),
                text.with(col),
                " ".repeat(pad),
                "│".with(teal)
            )
        } else {
            format!("  | {}{} |", text, " ".repeat(pad))
        }
    };

    println!();
    if term {
        println!("  {}{}{}", "┌".with(teal), bar.clone().with(teal), "┐".with(teal));
    } else {
        println!("  +{}+", "-".repeat(inner));
    }
    println!("{}", framed(&title, teal));
    for l in &lines {
        println!("{}", framed(l, body));
    }
    if term {
        println!("  {}{}{}", "└".with(teal), bar.with(teal), "┘".with(teal));
    } else {
        println!("  +{}+", "-".repeat(inner));
    }
    println!();
}

/// Group a count into thousands with `,` separators (e.g. 1234567 → 1,234,567).
fn group_thousands(n: u64) -> String {
    let s = n.to_string();
    let bytes = s.as_bytes();
    let len = bytes.len();
    let mut out = String::with_capacity(len + len / 3);
    for (i, b) in bytes.iter().enumerate() {
        if i > 0 && (len - i) % 3 == 0 {
            out.push(',');
        }
        out.push(*b as char);
    }
    out
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
    /// Signal v1.0.12 hard-fork readiness (CIP-012). See `--signal-v1012`
    /// in `RunSolo` for full details. Defaults to false (no signaling)
    /// for backward-compat with operators on pre-CIP-012 rig configs.
    #[serde(default)]
    signal_v1012: bool,
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
        cfg.mining.signal_v1012,
        false, // verbose: run-config is the systemd entry point; keep logs terse
        None,
    )
}

#[cfg(test)]
mod mode_tests {
    #[test]
    fn rig_mining_activates_full_mem() {
        // #145 regression: the rig's mining entry points must declare mining
        // active so the shared randomx_cache selects full-mem, not the ~7x-slow
        // light mode it silently fell into after #135. If the call is dropped
        // from activate_full_mem_hashing (or an entry point stops calling it),
        // this fails.
        super::activate_full_mem_hashing();
        assert!(
            coincync::consensus::pow::node_mining_active(),
            "activate_full_mem_hashing must set NODE_MINING_ACTIVE so rig miners \
             use full-mem RandomX (#145)"
        );
    }
}
