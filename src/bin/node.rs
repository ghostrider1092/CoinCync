// src/bin/node.rs — coincync-node daemon
//
// Real daemon for the P0 running-node milestone. Opens the database,
// loads / initializes chain state, starts the P2P listener and the
// JSON-RPC server, then blocks until ctrl-C.

use std::path::PathBuf;
use std::sync::Arc;

use clap::{Parser, Subcommand};
use tracing::{error, info, warn};

use coincync::chain::Blockchain;
use coincync::config::Network;
use coincync::db::Database;
use coincync::mempool::SharedMempool;
use coincync::network::P2PNode;
use coincync::network::node::NodeConfig as P2PNodeConfig;
use coincync::rpc::{start_rpc_server, RpcConfig};

#[derive(Parser)]
#[command(name = "coincync-node")]
#[command(about = "CoinCync 1.0 full node daemon")]
#[command(version)]
struct Cli {
    /// Data directory.
    #[arg(long, default_value = "~/.coincync")]
    data_dir: PathBuf,

    /// Network.
    #[arg(long, default_value = "testnet", value_parser = ["mainnet", "testnet", "regtest"])]
    network: String,

    /// Path to config file (TOML). Currently unused — defaults are used
    /// with CLI overrides applied on top.
    #[arg(long)]
    config: Option<PathBuf>,

    /// Log level.
    #[arg(long, default_value = "info")]
    log_level: String,

    /// P2P listen address (overrides the network default).
    #[arg(long)]
    p2p_bind: Option<String>,

    /// RPC listen address (overrides the network default).
    #[arg(long)]
    rpc_bind: Option<String>,

    /// Extra peer address(es) to try on startup.
    #[arg(long = "addnode")]
    addnode: Vec<String>,

    /// Disable all automatic peer discovery (for isolated tests).
    #[arg(long)]
    no_peers: bool,

    /// SOCKS5 proxy address (e.g. `127.0.0.1:9050` for a local Tor
    /// daemon). When set, P2P connections AND DNS-seed queries route
    /// through the proxy. DNS uses DNS-over-TCP via the proxy (default
    /// resolver `1.1.1.1:53`; override with `COINCYNC_SOCKS_DNS_RESOLVER`)
    /// so the OS resolver never sees the seed hostnames.
    #[arg(long, value_name = "HOST:PORT")]
    proxy: Option<String>,

    /// Convenience shortcut for `--proxy 127.0.0.1:9050` — the default
    /// Tor SOCKS5 listener. Ignored if `--proxy` is also set.
    #[arg(long)]
    tor: bool,

    /// Refuse to connect to clearnet peers — only `.onion` addresses
    /// accepted. Implies a proxy (`--tor` is added automatically if
    /// neither `--proxy` nor `--tor` is set). Use this when you require
    /// strict Tor-only operation; the node will reject any peer whose
    /// address isn't a `.onion` host.
    #[arg(long)]
    onion_only: bool,

    /// Mount the embedded block explorer at GET / on the REST port.
    ///
    /// LOCAL DEVELOPMENT ONLY. For public deployment, run the
    /// standalone Caddy stack in `deploy/explorer/` instead — it
    /// isolates the explorer's public-facing HTTP from the consensus
    /// binary. See `deploy/explorer/README.md` for the full
    /// architectural rationale.
    #[arg(long)]
    explorer: bool,

    /// Bind address for the REST + explorer server. Defaults to
    /// `127.0.0.1:<rpc_port + 2>`. Only relevant when `--explorer`
    /// is set OR when an external client wants the rest.rs surface.
    /// Binding to a non-localhost address with `--explorer` set
    /// triggers a security warning at startup but is permitted.
    #[arg(long)]
    rest_bind: Option<String>,

    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Subcommand)]
enum Command {
    /// Start the node (default if no command is given).
    Start,
    /// Print the genesis block hash and exit.
    PrintGenesisHash,
    /// Show node status.
    Status,
    /// Check the GitHub releases page for a newer version and exit.
    ///
    /// User-invoked only. The node does *not* poll for updates on
    /// startup — for a privacy coin, an automatic phone-home would
    /// leak "a CoinCync node is starting" from every user's IP to
    /// GitHub and intermediaries on every restart. Running this
    /// subcommand explicitly is informed-consent update checking.
    CheckUpdate,
}

// SECURITY (runtime resilience): force at least 4 worker threads regardless of
// host CPU count. The default `#[tokio::main]` derives worker_threads from
// num_cpus, which gives ONE worker on the single-vCPU Vultr boxes that run
// our fleet. A single blocked worker — whether from a RocksDB compaction
// stall, a parking_lot mutex contention spike, or any other synchronous
// block — freezes the entire async runtime: RPC stops responding, P2P stops
// processing, the broadcast channel saturates, and the node sits zombie
// until manual restart.
//
// Observed live 2026-05-12 16:18 UTC on the api box: process alive per
// systemd, zero log output for 13+ minutes, RPC TCP timing out. Workaround
// was a manual restart; root cause was the single-worker fragility.
//
// 4 workers means a single blocked worker leaves 3 others scheduling, so
// the runtime stays responsive even when one task is wedged. On the actual
// 1-vCPU hardware this is just kernel time-slicing (no real parallelism
// added), but it converts a permanent freeze into a transient slowdown.
//
// 2026-06-03 BUMP 4 → 8: production observation on coincync-lon hit the
// "all workers blocked on chain.inner.read()" pathology — 4 workers all
// queued behind a sync-side inner.write() during sustained IBD-cascade
// activity, RPC silently hung for 37+ minutes. 8 workers buys real
// breathing room for the case where 2-4 are blocked on chain reads
// while others handle RPC. Also see Layer 2 below — every RPC handler
// that touches chain state should be using `register_blocking_method`
// (the hot ones — get_info, get_peer_info, get_blockchain_info — were
// converted in the same patch).
//
// Layer 2 fix in progress: hot-path RPC handlers converted to
// register_blocking_method so they run on the blocking thread pool,
// not on tokio workers. Larger sweep of all 41 handlers is queued
// for v1.0.11 — for now we covered the highest-traffic three.
#[tokio::main(flavor = "multi_thread", worker_threads = 8)]
async fn main() {
    let cli = Cli::parse();

    // Initialize tracing. Prefer RUST_LOG, then --log-level, then "info"
    // as a guaranteed-valid last resort. A malformed RUST_LOG or
    // --log-level must NOT panic before tracing is up — that's a node
    // failure with zero diagnostic output. We warn to stderr instead.
    let env_filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .or_else(|_| cli.log_level.parse())
        .unwrap_or_else(|_| {
            eprintln!(
                "warning: log filter '{}' is invalid (and RUST_LOG was unset or also invalid); \
                 falling back to 'info'",
                cli.log_level
            );
            "info".parse().expect("'info' is a valid log filter")
        });
    tracing_subscriber::fmt()
        .with_env_filter(env_filter)
        .with_target(false)
        .init();

    let network = match cli.network.as_str() {
        "mainnet" => Network::Mainnet,
        "testnet" => Network::Testnet,
        "regtest" => Network::Regtest,
        _ => Network::Testnet,
    };

    // RandomX VM keys must use the same genesis binding as the rest of the network.
    coincync::consensus::bind_randomx_genesis_for_network(network);

    // Resolve ~
    let data_dir = if let Some(stripped) = cli
        .data_dir
        .to_string_lossy()
        .strip_prefix("~/")
    {
        dirs_next::home_dir()
            .unwrap_or_else(|| PathBuf::from("."))
            .join(stripped)
    } else {
        cli.data_dir.clone()
    };

    match cli.command.unwrap_or(Command::Start) {
        Command::PrintGenesisHash => print_genesis_hash(network),
        Command::Status => show_status(network, &data_dir).await,
        Command::CheckUpdate => check_update().await,
        Command::Start => {
            if let Err(e) = start_node(
                network,
                data_dir,
                cli.p2p_bind,
                cli.rpc_bind,
                cli.rest_bind,
                cli.addnode,
                cli.no_peers,
                cli.explorer,
                cli.proxy,
                cli.tor,
                cli.onion_only,
            ).await {
                error!("node start failed: {}", e);
                std::process::exit(1);
            }
        }
    }
}

fn print_genesis_hash(network: Network) {
    let genesis = match network {
        Network::Mainnet => coincync::mainnet::mainnet_genesis(),
        _ => coincync::testnet::testnet_genesis(),
    };
    let hash = genesis.hash();
    println!("Genesis hash: {}", hex::encode(hash.as_bytes()));
    println!(
        "Paste this into src/{}.rs as the GENESIS_HASH constant.",
        match network {
            Network::Mainnet => "mainnet",
            Network::Testnet => "testnet",
            Network::Regtest => "testnet",
        }
    );
}

/// Print the current binary's version and, if it differs from the
/// latest published GitHub release, the new version's tag and download
/// URL. Single outbound HTTPS request to `api.github.com`; exits 0 on
/// success, 1 on network failure or unparseable response.
///
/// Privacy: this subcommand is user-invoked only — there is no
/// automatic update poll. For a privacy coin, a startup phone-home to
/// `api.github.com` from every user's IP would leak "a CoinCync node
/// is starting up here" to GitHub and any on-path observer on every
/// restart. Running `coincync-node check-update` explicitly is the
/// informed-consent alternative.
async fn check_update() {
    const REPO: &str = "ghostrider1092/Coincync-Testnet-";
    let current = env!("CARGO_PKG_VERSION");
    println!("Current version: {}", current);
    println!("Contacting api.github.com to check for releases...");

    let client = match reqwest::Client::builder()
        .user_agent(format!("coincync-node/{}", current))
        .timeout(std::time::Duration::from_secs(8))
        .build()
    {
        Ok(c) => c,
        Err(e) => {
            eprintln!("Failed to build HTTP client: {}", e);
            std::process::exit(1);
        }
    };

    // Try the GitHub-blessed `/releases/latest` first (respects the
    // "Latest" badge — returns the most recent NON-prerelease). If
    // 404, fall back to the most recently published release including
    // prereleases — every CoinCync release is currently flagged
    // prerelease, so the badged endpoint returns 404 today.
    let latest_url = format!("https://api.github.com/repos/{}/releases/latest", REPO);
    let recent_url = format!("https://api.github.com/repos/{}/releases?per_page=1", REPO);

    let release = match client
        .get(&latest_url)
        .header("Accept", "application/vnd.github+json")
        .send()
        .await
    {
        Ok(resp) if resp.status().is_success() => match resp.json::<serde_json::Value>().await {
            Ok(v) => extract_release(&v),
            Err(e) => {
                eprintln!("Failed to parse GitHub response: {}", e);
                None
            }
        },
        Ok(resp) if resp.status() == reqwest::StatusCode::NOT_FOUND => {
            // No "Latest"-badged release — fall back.
            match client
                .get(&recent_url)
                .header("Accept", "application/vnd.github+json")
                .send()
                .await
            {
                Ok(resp) if resp.status().is_success() => {
                    match resp.json::<serde_json::Value>().await {
                        Ok(serde_json::Value::Array(arr)) => arr.first().and_then(extract_release),
                        Ok(_) => None,
                        Err(e) => {
                            eprintln!("Failed to parse GitHub response: {}", e);
                            None
                        }
                    }
                }
                Ok(resp) => {
                    eprintln!("GitHub returned status {}", resp.status());
                    None
                }
                Err(e) => {
                    eprintln!("Couldn't reach api.github.com: {}", e);
                    None
                }
            }
        }
        Ok(resp) => {
            eprintln!("GitHub returned status {}", resp.status());
            None
        }
        Err(e) => {
            eprintln!("Couldn't reach api.github.com: {}", e);
            None
        }
    };

    match release {
        Some((tag, name, url, is_pre)) => {
            // Normalise the tag for comparison: strip the leading `v`
            // and anything after the first `-` (e.g. `v1.0.7-testnet`
            // → `1.0.7`). Compare via plain string equality — sufficient
            // for "is the release a different version", which is the
            // user-facing question. Semver-aware comparison can land
            // later if there's a use case for distinguishing
            // ahead-of-stable from behind-stable.
            let latest_clean: String = tag
                .trim_start_matches('v')
                .split('-')
                .next()
                .unwrap_or(&tag)
                .to_string();
            let pre_note = if is_pre { " (prerelease)" } else { "" };
            if current == latest_clean {
                println!("✓ You have the latest release{}: {} ({})", pre_note, tag, name);
            } else {
                println!("⚠ A different release is available{}: {} ({})", pre_note, tag, name);
                println!("    Current: {}", current);
                println!("    Latest:  {}", latest_clean);
                println!("    Download: {}", url);
            }
        }
        None => {
            eprintln!(
                "Could not determine the latest release. \
                 Check manually at https://github.com/{}/releases",
                REPO
            );
            std::process::exit(1);
        }
    }
}

/// Pull `(tag_name, name, html_url, prerelease)` out of a release JSON
/// object. Returns `None` if any of the load-bearing fields is missing
/// or the wrong type — better to fail closed than to print garbage.
fn extract_release(v: &serde_json::Value) -> Option<(String, String, String, bool)> {
    let tag = v.get("tag_name")?.as_str()?.to_string();
    let name = v
        .get("name")
        .and_then(|x| x.as_str())
        .unwrap_or(&tag)
        .to_string();
    let url = v
        .get("html_url")
        .and_then(|x| x.as_str())
        .unwrap_or("")
        .to_string();
    let is_pre = v.get("prerelease").and_then(|x| x.as_bool()).unwrap_or(false);
    Some((tag, name, url, is_pre))
}

async fn show_status(network: Network, data_dir: &PathBuf) {
    let db_path = data_dir.join(match network {
        Network::Mainnet => "mainnet",
        Network::Testnet => "testnet",
        Network::Regtest => "regtest",
    });

    match Database::open(&db_path) {
        Ok(db) => {
            let chain = Blockchain::with_database(Arc::new(db), network);
            let _ = chain.load_from_database();
            let tip = chain.tip();
            println!("Network:   {:?}", network);
            println!("Data dir:  {:?}", db_path);
            println!("Height:    {}", tip.height);
            println!("Tip hash:  {}", hex::encode(tip.hash.as_bytes()));
        }
        Err(e) => {
            eprintln!("Failed to open database at {:?}: {}", db_path, e);
            std::process::exit(1);
        }
    }
}

async fn start_node(
    network: Network,
    data_dir: PathBuf,
    p2p_bind: Option<String>,
    rpc_bind: Option<String>,
    rest_bind: Option<String>,
    addnodes: Vec<String>,
    no_peers: bool,
    serve_explorer: bool,
    proxy_arg: Option<String>,
    tor_shortcut: bool,
    onion_only: bool,
) -> coincync::Result<()> {
    info!("CoinCync 1.0 node starting");
    info!("Network:  {:?}", network);
    info!("Data dir: {:?}", data_dir);

    // Ensure data dir exists
    std::fs::create_dir_all(&data_dir).ok();

    // Build P2P node config from CLI overrides
    let mut p2p_config = P2PNodeConfig::default();
    p2p_config.magic = network.magic_bytes();
    p2p_config.data_dir = data_dir.clone();
    if let Some(bind) = &p2p_bind {
        if let Ok(addr) = bind.parse() {
            p2p_config.listen_addr = addr;
        } else {
            warn!("Ignoring bad --p2p-bind {:?}", bind);
        }
    } else {
        p2p_config.listen_addr = ([0, 0, 0, 0], network.default_p2p_port()).into();
    }
    // Parse --addnode entries up-front so any syntax errors fail before
    // we open the database. Accept either "ip:port" or "[ipv6]:port"; the
    // std `SocketAddr::from_str` handles both.
    let mut extra_peers: Vec<std::net::SocketAddr> = Vec::new();
    for raw in &addnodes {
        match raw.parse::<std::net::SocketAddr>() {
            Ok(addr) => extra_peers.push(addr),
            Err(e) => {
                warn!("Ignoring bad --addnode {:?}: {}", raw, e);
            }
        }
    }

    if no_peers {
        info!("--no-peers: automatic peer discovery disabled (manual --addnode peers still allowed)");
        // Enforce true isolation: disable bootstrap seeds and outbound slots.
        // Without this, the node can still dial built-in seeds.
        p2p_config.bootstrap.dns_seeds.clear();
        p2p_config.bootstrap.seed_nodes.clear();
        p2p_config.max_outbound = 0;
    }

    // --proxy / --tor / --onion-only wire-up.
    //
    // Resolution order (CLI flags only — config-file path lands separately):
    //
    //   1. `--proxy HOST:PORT`  — explicit address; takes priority
    //   2. `--tor`               — shortcut for 127.0.0.1:9050
    //   3. `--onion-only` alone  — implies --tor (no clear-net DNS path
    //                              exists otherwise; without a proxy the
    //                              bootstrapper would just skip DNS)
    //
    // The resulting `ProxyConfig` is plumbed through `p2p_config.proxy`;
    // bootstrap.rs's `get_peers_with_proxy()` / `initial_peers()` route
    // DNS-seed queries via DNS-over-TCP through the proxy automatically
    // when this is set (landed in commit 86eee87).
    let proxy_cfg = if let Some(addr) = proxy_arg.as_deref() {
        // Parse "host:port" — accepts ipv4, ipv6 in [brackets], or
        // hostname. The bootstrap layer pipes the string straight to
        // tokio_socks::Socks5Stream::connect(), which does its own
        // resolution.
        match addr.rsplit_once(':') {
            Some((host, port_str)) => match port_str.parse::<u16>() {
                Ok(port) => Some(coincync::config::ProxyConfig {
                    enabled: true,
                    address: host.trim_matches(|c| c == '[' || c == ']').to_string(),
                    port,
                    onion_only,
                    ..Default::default()
                }),
                Err(_) => {
                    error!("--proxy port is not a valid u16: {:?}", port_str);
                    std::process::exit(1);
                }
            },
            None => {
                error!("--proxy must be HOST:PORT, got {:?}", addr);
                std::process::exit(1);
            }
        }
    } else if tor_shortcut || onion_only {
        // Both shortcuts converge on the local Tor SOCKS5 default.
        let mut tor = coincync::config::ProxyConfig::tor();
        tor.onion_only = onion_only;
        Some(tor)
    } else {
        None
    };

    if let Some(cfg) = proxy_cfg {
        info!(
            "Proxy enabled: {}:{} ({}{})",
            cfg.address,
            cfg.port,
            if cfg.onion_only { "onion-only" } else { "clearnet+onion" },
            if cfg.username.is_some() { ", authenticated" } else { "" },
        );
        p2p_config.proxy = Some(cfg);
    }

    // Open database
    let db_path = data_dir.join(match network {
        Network::Mainnet => "mainnet",
        Network::Testnet => "testnet",
        Network::Regtest => "regtest",
    });
    info!("Opening database at {:?}", db_path);
    let db = Database::open(&db_path).map_err(|e| {
        error!("Database open failed: {}", e);
        e
    })?;
    let db = Arc::new(db);

    // Initialize blockchain
    let mut chain = Blockchain::with_database(db.clone(), network);

    // Light Spark wire-up (CIP-005 sketch, read-only observability for v1.0).
    // `chain.spark_store` defaults to `None` ("Phase 2 stores: None until
    // Phase 2 activation" per chain.rs comment). Without initializing it
    // here the `get_privacy_stats` RPC returns spark_root=zeros and
    // spark_accumulator_size=0 even though the storage layer is fully
    // functional. We initialize the persistent SparkStore so users
    // running the node can SEE the accumulator state via
    // `coincync-wallet privacy-stats`. This is observation-only — full
    // Spark transaction validation in consensus is CIP-005's complete
    // implementation, queued post-mainnet (see project_staged_mainnet
    // memory + the "wire up sparks" decision recorded 2026-05-24:
    // light wire-up only, no consensus integration).
    match coincync::storage::SparkStore::open_with_db(&db) {
        Ok(store) => {
            info!("Spark accumulator loaded ({} coins)", store.size());
            chain.spark_store = Some(Arc::new(store));
        }
        Err(e) => {
            warn!(
                "Spark store init failed: {} — get_privacy_stats will show \
                 zeros for spark_root/spark_accumulator_size",
                e
            );
        }
    }

    // Mirror init for the other two Phase 2 stores — same light wire-up
    // posture: observation-only, no consensus integration in v1.0. The
    // /privacy-pools explorer page reads all three through get_privacy_stats.
    match coincync::storage::ShieldedStore::open_with_db(&db) {
        Ok(store) => {
            info!("Shielded tree loaded ({} notes)", store.tree_size());
            chain.shielded_store = Some(Arc::new(store));
        }
        Err(e) => {
            warn!(
                "Shielded store init failed: {} — get_privacy_stats will show \
                 zeros for shielded_root/shielded_tree_size",
                e
            );
        }
    }
    match coincync::storage::KernelStore::open_with_db(&db) {
        Ok(store) => {
            info!("Kernel store loaded");
            chain.kernel_store = Some(Arc::new(store));
        }
        Err(e) => {
            warn!(
                "Kernel store init failed: {} — get_privacy_stats will show \
                 zeros for mw_kernel_root",
                e
            );
        }
    }
    // CutThroughEngine is in-memory only (no disk-backed state); init
    // unconditionally so MW cut-through stats are non-zero from the moment
    // the node starts accepting blocks.
    chain.cut_through = Some(Arc::new(parking_lot::Mutex::new(
        coincync::crypto::mw_cutthrough::CutThroughEngine::new(),
    )));

    if let Err(e) = chain.load_from_database() {
        warn!("load_from_database: {} (will init genesis)", e);
        let _ = chain.init_genesis();
    } else if chain.tip().hash.is_zero() && chain.height() == 0 {
        // Fresh DB: load_from_database returned Ok(()) with nothing
        // to load (no saved tip state), so genesis was never inserted.
        // Without this, every submitted block becomes an orphan because
        // its parent (genesis) doesn't exist in the chain.
        info!("Fresh database: initializing genesis block");
        let _ = chain.init_genesis();
    }

    let tip = chain.tip();
    info!("Chain tip: height={}, hash={}", tip.height, hex::encode(&tip.hash.as_bytes()[..8]));

    let chain_arc: Arc<Blockchain> = Arc::new(chain);

    // Create mempool
    let mempool = SharedMempool::new();
    mempool.set_height(tip.height);

    // Start P2P node
    let listen_addr = p2p_config.listen_addr;
    let p2p = Arc::new(P2PNode::new(p2p_config, chain_arc.clone(), mempool.clone()));
    info!("Starting P2P listener on {}", listen_addr);
    if let Err(e) = p2p.start().await {
        error!("P2P start failed: {}", e);
        return Err(e);
    }

    // Seed the handshake-side chain_height / chain_tip with the on-disk
    // tip so the very first peer Version we send advertises the real
    // height. Without this, the initial handshake advertises 0 until a
    // new block is processed, which can take minutes on a quiet chain
    // and breaks block relay in the meantime.
    p2p.set_chain_state(tip.height, tip.hash).await;

    // Feed any --addnode peers into the address book so the peer-
    // discovery loop dials them on the next tick. This runs AFTER
    // P2PNode::start() so the address book is initialized, and before
    // the RPC server comes up so a caller can rely on the node having
    // tried every manual peer by the time its first RPC succeeds.
    for addr in &extra_peers {
        info!("--addnode: adding manual peer {}", addr);
        p2p.add_seed_address(*addr).await;
    }

    // Consume P2P NodeEvents and feed BlockReceived into the chain.
    // Without this subscriber, the broadcast channel has zero
    // receivers, so blocks arriving over the wire are silently
    // dropped — peers stay at height 0 even when one of them is
    // mining and propagating. The 1.0 codebase shipped with the
    // network->chain wiring missing.
    let event_chain = chain_arc.clone();
    let event_mempool = mempool.clone();
    let event_p2p = p2p.clone();
    let mut node_events = p2p.subscribe();
    tokio::spawn(async move {
        use coincync::network::node::NodeEvent;
        use coincync::chain::BlockStatus;
        use tokio::sync::broadcast::error::RecvError;
        info!("NodeEvent consumer started");
        loop {
            match node_events.recv().await {
                Ok(NodeEvent::BlockReceived(block, peer_id)) => {
                    // Phase 1 #6: time the full block-receive-to-tip path.
                    // Captures spawn_blocking dispatch + chain.process_block +
                    // mempool sync + chain_state refresh. The stopwatch lives
                    // for the entire match arm; observe() fires before the
                    // continue/loop-back.
                    let _block_timer = coincync::metrics::BLOCK_RECEIVE_TO_TIP.start_timer();
                    let hash = block.hash();
                    let block_height = block.header.height;
                    let prev_hash = block.header.prev_hash;
                    let block_txs = block.transactions.clone();
                    let block_for_relay = block.clone();
                    // Runtime resilience: route block processing through the
                    // `process_block_async` wrapper (chain.rs Phase 2 #9), which
                    // moves the CPU-bound + DB-write path onto tokio's blocking
                    // thread pool. Layer 1 (commit 5c98bae, 4 worker threads)
                    // remains as defense in depth. The async wrapper converts
                    // spawn_blocking JoinError into `Error::Internal(...)` —
                    // caught by the `Err(e)` arm below alongside any other
                    // process_block failure, no special-case panic handling
                    // needed at this call site.
                    let block_status = event_chain.clone().process_block_async(block).await;
                    match block_status {
                        Ok(status @ (BlockStatus::Accepted
                                    | BlockStatus::AcceptedFork
                                    | BlockStatus::AcceptedReorg { .. })) => {
                            // Keep mempool aligned with chain state: remove mined txs and
                            // advance mempool height so activation-gated checks stay correct.
                            event_mempool.remove_confirmed(&block_txs);
                            // On reorg, re-admit txs that were mined in disconnected
                            // blocks but are still spendable on the new chain. Without
                            // this, user transactions silently vanish across a reorg.
                            if let BlockStatus::AcceptedReorg { orphaned_txs } = status {
                                event_mempool.restore_orphaned(orphaned_txs, &event_chain);
                            }
                            event_mempool.set_height(event_chain.height());
                            // Shadow-evict mempool txs that no longer
                            // validate. Catches hard-fork rule
                            // transitions + reorg-induced maturity
                            // changes. Belt-and-suspenders for the
                            // miner-side filter in mining/template.rs.
                            event_mempool.shadow_evict_invalid(event_chain.as_ref());

                            // Notify IBD sync manager so it advances its
                            // local_height cursor and releases the next
                            // batch window; without this the sync engine
                            // keeps re-requesting blocks we've already
                            // applied. Then gossip onward.
                            //
                            // Also refresh the handshake-side chain_height /
                            // chain_tip so subsequent peer Version messages
                            // advertise our actual tip instead of the stale
                            // initial value (was a real bug: peers saw us as
                            // start_height=0 forever, broke block relay).
                            let p2p2 = event_p2p.clone();
                            let new_height = event_chain.height();
                            let new_tip = event_chain.tip_hash();
                            tokio::spawn(async move {
                                p2p2.notify_block_received(&hash).await;
                                p2p2.notify_block_processed(hash, block_height).await;
                                p2p2.set_chain_state(new_height, new_tip).await;
                                let _ = p2p2.broadcast_block(&block_for_relay).await;
                            });
                        }
                        Ok(BlockStatus::AlreadyKnown) => {
                            // Ensure mempool activation height catches up during normal sync.
                            event_mempool.set_height(event_chain.height());
                            let p2p2 = event_p2p.clone();
                            tokio::spawn(async move {
                                p2p2.notify_block_received(&hash).await;
                            });
                        }
                        Ok(BlockStatus::Orphan) => {
                            // Don't re-request the orphan itself — peers will keep handing
                            // back the same block and we never advance. Instead, ask sync
                            // to fetch the orphan's parent so the gap fills. When the
                            // parent connects, gossip re-delivers the orphan and the
                            // second pass succeeds. See sync::mark_block_orphan for the
                            // long version of why; root-caused 2026-05-02.
                            warn!(
                                "Block {} from peer {:?} orphan; fetching parent {}",
                                hex::encode(&hash.as_bytes()[..8]),
                                &peer_id[..4],
                                hex::encode(&prev_hash.as_bytes()[..8]),
                            );
                            let p2p2 = event_p2p.clone();
                            tokio::spawn(async move {
                                p2p2.notify_block_received(&hash).await;
                                p2p2.notify_block_orphan(&peer_id, &hash, &prev_hash).await;
                            });
                        }
                        Ok(BlockStatus::Invalid(reason)) => {
                            warn!(
                                "Block {} from peer {:?} invalid: {}",
                                hex::encode(&hash.as_bytes()[..8]),
                                &peer_id[..4],
                                reason
                            );
                            // Score the peer for the invalid block. Without this,
                            // a peer on a divergent chain spams the same rejected
                            // block forever (165k/24h pattern observed 2026-05-11).
                            let p2p2 = event_p2p.clone();
                            tokio::spawn(async move {
                                p2p2.notify_block_received(&hash).await;
                                p2p2.notify_block_failed(&hash).await;
                                p2p2.notify_block_invalid(&peer_id, &reason).await;
                            });
                        }
                        Err(e) => {
                            warn!(
                                "Block {} from peer {:?} processing error: {}",
                                hex::encode(&hash.as_bytes()[..8]),
                                &peer_id[..4],
                                e
                            );
                            let p2p2 = event_p2p.clone();
                            tokio::spawn(async move {
                                p2p2.notify_block_received(&hash).await;
                                p2p2.notify_block_failed(&hash).await;
                            });
                        }
                    }
                }
                Ok(NodeEvent::TransactionReceived(tx, source)) => {
                    // Phase 1 #6: time the full tx-admit path including
                    // spawn_blocking dispatch + full crypto verify + mempool
                    // insert + Dandelion stempool update.
                    let _tx_timer = coincync::metrics::TX_ADMIT_TO_MEMPOOL.start_timer();
                    // Admit fluffed network txs into local mempool so they become mineable.
                    // Routes through `add_with_chain_async` (mempool.rs Phase 2 #9)
                    // which moves the full crypto verify + key-image dedup off
                    // the worker thread. JoinError on spawn_blocking comes back
                    // as `Error::Internal(...)` — handled by the same Err arm
                    // below as any other admit failure.
                    let admit = event_mempool
                        .clone()
                        .add_with_chain_async(tx, event_chain.clone())
                        .await;
                    if let Err(e) = admit {
                        let reason = e.to_string();
                        warn!("P2P transaction rejected by mempool: {}", reason);
                        // Score the originating peer if known. Mempool admit
                        // runs full crypto (ring sig, range proof, key image,
                        // double-spend) which an honest peer should have caught
                        // before relay. Locally-generated txs (source=None)
                        // are skipped — that's our own broken tx, not abuse.
                        if let Some(peer_id) = source {
                            let p2p2 = event_p2p.clone();
                            tokio::spawn(async move {
                                p2p2.notify_tx_invalid_full(&peer_id, &reason).await;
                            });
                        }
                    }
                }
                Ok(_other) => {
                    // PeerConnected/Disconnected: no chain action required.
                }
                Err(RecvError::Lagged(n)) => {
                    warn!("NodeEvent consumer lagged by {} messages", n);
                }
                Err(RecvError::Closed) => {
                    warn!("NodeEvent channel closed; consumer exiting");
                    break;
                }
            }
        }
    });

    // Start RPC server
    let rpc_listen: std::net::SocketAddr = rpc_bind
        .as_deref()
        .and_then(|s| s.parse().ok())
        .unwrap_or_else(|| {
            ([127, 0, 0, 1], network.default_rpc_port()).into()
        });
    let mut rpc_config = RpcConfig {
        listen_addr: rpc_listen,
        network_name: format!("{:?}", network).to_lowercase(),
        ..RpcConfig::default()
    };
    if let Ok(key) = std::env::var("COINCYNC_RPC_API_KEY") {
        let key = key.trim().to_string();
        if !key.is_empty() {
            rpc_config.api_key = Some(key);
            rpc_config.auth_enabled = true;
        }
    }
    info!("Starting RPC server on {}", rpc_listen);
    let _rpc = start_rpc_server(
        chain_arc.clone(),
        mempool.clone(),
        Some(p2p.clone()),
        rpc_config,
    )
    .await?;

    // ── Prometheus /metrics scrape endpoint ─────────────────────
    //
    // Bound to RPC port + 1 (e.g. 28081 → 28082). Phase 1 #6 of
    // the post-launch campaign: real production observability
    // backing the noop stubs that lived in src/metrics.rs in the
    // 1.0 trim. Spawned as a background task so node shutdown
    // still flows through the ctrl-c handler below.
    let metrics_listen: std::net::SocketAddr =
        ([127, 0, 0, 1], rpc_listen.port().wrapping_add(1)).into();
    info!("Starting Prometheus /metrics endpoint on {}", metrics_listen);
    tokio::spawn(async move {
        if let Err(e) = coincync::metrics::serve_metrics(metrics_listen).await {
            warn!("Metrics endpoint exited: {}", e);
        }
    });

    // ── REST + (optional) embedded explorer ────────────────────
    //
    // The REST surface lives in `coincync::rpc::rest::run_rest_api`
    // and is conditionally spawned here. It runs on its own port
    // (default = jsonrpsee port + 2) and proxies allowlisted
    // read-only RPC methods to the jsonrpsee endpoint above.
    //
    // When `--explorer` is set, the same REST app additionally
    // serves the embedded block explorer at `GET /`. This is
    // local-development only — production public deployment uses
    // the standalone Caddy stack in `deploy/explorer/`.
    //
    // We always start the REST app when --explorer is set, and
    // skip it otherwise (the REST surface is otherwise opt-in via
    // --rest-bind). Spawned as a background task so the node's
    // ctrl-c shutdown loop below still runs.
    let rest_listen: Option<std::net::SocketAddr> = rest_bind
        .as_deref()
        .and_then(|s| s.parse().ok())
        .or_else(|| {
            if serve_explorer {
                // Default to rpc_port + 2 so it doesn't collide with
                // either the jsonrpsee server (rpc_port) or the
                // conventional "explorer HTTP" slot at rpc_port + 1
                // (which deploy/explorer/Caddyfile uses externally).
                Some(([127, 0, 0, 1], rpc_listen.port().wrapping_add(2)).into())
            } else {
                None
            }
        });

    if let Some(addr) = rest_listen {
        info!("Starting REST API on {}{}",
            addr,
            if serve_explorer { " (with embedded explorer at GET /)" } else { "" }
        );
        let jsonrpc_addr = rpc_listen;
        tokio::spawn(async move {
            if let Err(e) = coincync::rpc::rest::run_rest_api(addr, jsonrpc_addr, serve_explorer).await {
                error!("REST API exited: {}", e);
            }
        });
    }

    info!("Node is running. Ctrl-C to stop.");

    // Wait for shutdown signal
    tokio::signal::ctrl_c()
        .await
        .expect("failed to install ctrl-c handler");

    info!("Shutdown signal received, stopping node...");
    Ok(())
}
