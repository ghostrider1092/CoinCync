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

    /// Our own externally-reachable address. Accepts a bare IP
    /// (`45.32.79.234`, our listen port is attached) or `IP:PORT`.
    /// Registered as a self-address so peer gossip that echoes our own IP
    /// back to us never makes us dial ourselves. Strongly recommended for
    /// fixed-IP fleet nodes.
    #[arg(long = "external-ip", value_name = "IP[:PORT]")]
    external_ip: Option<String>,

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
    /// `127.0.0.1:<rpc_port + 2>`. Binding to a non-localhost address
    /// with `--explorer` set triggers a security warning at startup
    /// but is permitted.
    #[arg(long)]
    rest_bind: Option<String>,

    /// Opt out of the REST layer entirely. By default the REST server
    /// is spawned on 127.0.0.1:<rpc_port + 2> on every node so that a
    /// load balancer (Cloudflare LB, nginx, HAProxy) fronting
    /// api.coincync.network can health-check every fleet host and
    /// route around a wedged one — closing the single-api-host SPOF
    /// that caused the 41-hour public-RPC outage on 2026-07-02.
    ///
    /// Set this flag on resource-constrained hosts that don't need
    /// the REST surface (e.g., miners running rig on the same box).
    #[arg(long)]
    rest_disable: bool,

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
    /// One-shot: stamp a pre-v1 chaindata as `schema_version = 1`,
    /// after validating the genesis block in the DB matches the
    /// expected genesis hash for `--network`. Operator-only escape
    /// hatch for upgrading from v1.0.11.x (no stamp) to v1.0.12+
    /// (requires stamp).
    ///
    /// Idempotent: re-running on an already-stamped DB is a no-op.
    /// Aborts if the DB belongs to a different chain (genesis hash
    /// mismatch). See `docs/operations/v1.0.12-hard-fork-rollout.md`
    /// for the full upgrade runbook.
    MigrateLegacyDb,

    /// Export a consistent chain snapshot for trusted fast-sync bootstrap.
    ///
    /// The node MUST be stopped (the sled DB is single-process). Produces
    /// `<out>/db/` + `<out>/manifest.json`; copy that directory to a lagging
    /// node and run `snapshot-import` there instead of grinding IBD from
    /// genesis. See `src/snapshot.rs` for the format + trust model.
    SnapshotExport {
        /// Output directory for the snapshot (must not already contain `db/`).
        #[arg(long)]
        out: PathBuf,
    },

    /// Install a chain snapshot produced by `snapshot-export`.
    ///
    /// The node MUST be stopped. Verifies the snapshot's network + genesis
    /// hash (refuses a wrong-chain snapshot) and a blake3 integrity hash,
    /// backs up any existing chaindata to a `.pre-snapshot-<ts>` sibling
    /// (reversible), then installs the snapshot.
    SnapshotImport {
        /// Snapshot directory (containing `db/` + `manifest.json`).
        #[arg(long)]
        input: PathBuf,
    },
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
        Command::MigrateLegacyDb => {
            // Resolve the chaindata path the same way start_node does
            // (data_dir / <network>) so this subcommand operates on the
            // exact directory the daemon would open. Mismatched paths
            // are the #1 way operators end up "migrating" a different
            // DB than the one their service is using.
            let network_subdir = match network {
                Network::Mainnet => "mainnet",
                Network::Testnet => "testnet",
                Network::Regtest => "regtest",
            };
            let chaindata_path = data_dir.join(network_subdir);
            let expected_genesis = match network {
                Network::Mainnet => coincync::mainnet::mainnet_genesis().hash(),
                _ => coincync::testnet::expected_genesis_hash(),
            };
            info!(
                "Migrating legacy DB at {} (network={}, expected_genesis={})",
                chaindata_path.display(),
                network_subdir,
                expected_genesis,
            );
            match coincync::db::migrate_legacy_db_to_v1(
                &chaindata_path,
                coincync::db::DbConfig::default(),
                &expected_genesis,
            ) {
                Ok(coincync::db::MigrationOutcome::AlreadyStamped) => {
                    info!("DB was already stamped at the expected schema version. No changes made.");
                }
                Ok(coincync::db::MigrationOutcome::Stamped { genesis_hash }) => {
                    info!(
                        "✓ Legacy DB migrated successfully. schema_version stamped. (genesis verified: {})",
                        genesis_hash,
                    );
                    info!("You can now start the node normally: `systemctl start coincync-node` (or just `coincync-node`).");
                }
                Err(e) => {
                    error!("Migration failed: {}", e);
                    error!("The DB has NOT been modified. Read the error above carefully — most migration failures are 'wrong --network flag' or 'wrong --data-dir path'.");
                    std::process::exit(1);
                }
            }
        }
        Command::SnapshotExport { out } => {
            let network_subdir = match network {
                Network::Mainnet => "mainnet",
                Network::Testnet => "testnet",
                Network::Regtest => "regtest",
            };
            let chaindata_path = data_dir.join(network_subdir);

            // Open the (stopped) node's DB just long enough to capture the tip
            // for the manifest, then DROP the handle inside this block so sled
            // flushes and releases its lock BEFORE snapshot::export copies the
            // directory. If the daemon is still running it holds the lock and
            // Database::open fails here — exactly the guard we want (never
            // snapshot a live, mid-write DB).
            let (height, tip_hex, genesis_hex) = {
                let db = match Database::open(&chaindata_path) {
                    Ok(db) => db,
                    Err(e) => {
                        error!(
                            "Cannot open chaindata at {} for export: {}. Is the node still running? Stop it first.",
                            chaindata_path.display(),
                            e
                        );
                        std::process::exit(1);
                    }
                };
                let chain = Blockchain::with_database(Arc::new(db), network);
                let _ = chain.load_from_database();
                let tip = chain.tip();
                let genesis = match network {
                    Network::Mainnet => coincync::mainnet::expected_genesis_hash(),
                    _ => coincync::testnet::expected_genesis_hash(),
                };
                (
                    tip.height,
                    hex::encode(tip.hash.as_bytes()),
                    hex::encode(genesis.as_bytes()),
                )
                // `chain` (and its Arc<Database>) dropped here → sled flush + unlock.
            };

            let created_at = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0);
            let version = env!("CARGO_PKG_VERSION");

            info!(
                "Exporting snapshot: network={} height={} tip={} → {}",
                network_subdir,
                height,
                tip_hex,
                out.display()
            );
            match coincync::snapshot::export(
                &chaindata_path,
                &out,
                network_subdir,
                &genesis_hex,
                height,
                &tip_hex,
                version,
                created_at,
            ) {
                Ok(m) => {
                    info!(
                        "✓ Snapshot exported to {} (height={}, db_blake3={})",
                        out.display(),
                        m.height,
                        m.db_blake3
                    );

                    // Optional: sign the manifest if COINCYNC_SNAPSHOT_SIGN_SEED_HEX
                    // (32-byte hex Ed25519 seed) is set. Produces `manifest.sig`,
                    // which importers with a matching trusted-signer allowlist
                    // require. Unset = an unsigned snapshot (fine for a private
                    // trusted fleet).
                    match std::env::var("COINCYNC_SNAPSHOT_SIGN_SEED_HEX") {
                        Ok(seed_hex) => {
                            let seed_hex = seed_hex.trim();
                            match hex::decode(seed_hex) {
                                Ok(bytes) if bytes.len() == 32 => {
                                    let mut seed = [0u8; 32];
                                    seed.copy_from_slice(&bytes);
                                    match coincync::snapshot::sign_snapshot_dir(&out, &seed) {
                                        Ok(sig) => info!(
                                            "✓ Snapshot manifest signed by {} → {}/manifest.sig",
                                            sig.signer_pubkey,
                                            out.display()
                                        ),
                                        Err(e) => {
                                            error!("Snapshot signing failed: {}", e);
                                            std::process::exit(1);
                                        }
                                    }
                                }
                                _ => {
                                    error!("COINCYNC_SNAPSHOT_SIGN_SEED_HEX must be 32-byte (64-char) hex; snapshot exported UNSIGNED");
                                    std::process::exit(1);
                                }
                            }
                        }
                        Err(_) => {
                            info!("(unsigned — set COINCYNC_SNAPSHOT_SIGN_SEED_HEX to sign the manifest)");
                        }
                    }

                    info!("Copy that directory to the target node and run: `coincync-node snapshot-import --input <dir>`");
                }
                Err(e) => {
                    error!("Snapshot export failed: {}", e);
                    std::process::exit(1);
                }
            }
        }
        Command::SnapshotImport { input } => {
            let network_subdir = match network {
                Network::Mainnet => "mainnet",
                Network::Testnet => "testnet",
                Network::Regtest => "regtest",
            };
            let chaindata_path = data_dir.join(network_subdir);
            let genesis = match network {
                Network::Mainnet => coincync::mainnet::expected_genesis_hash(),
                _ => coincync::testnet::expected_genesis_hash(),
            };
            let backup_stamp = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0);

            // Consensus checkpoints baked into this binary. The snapshot's DB
            // must match them at every checkpoint height or the import is
            // refused — this defeats a fabricated / wrong-fork snapshot from an
            // untrusted source. Always includes genesis, so it's never empty.
            let checkpoints: Vec<(u64, coincync::primitives::Hash)> = match network {
                Network::Mainnet => coincync::mainnet::mainnet_checkpoints()
                    .into_iter()
                    .map(|c| (c.height, c.hash))
                    .collect(),
                _ => coincync::testnet::testnet_checkpoints()
                    .into_iter()
                    .map(|c| (c.height, c.hash))
                    .collect(),
            };
            // Optional trusted-source gate. If COINCYNC_SNAPSHOT_TRUSTED_PUBKEYS
            // is set (comma-separated hex Ed25519 keys), the snapshot must carry
            // a `manifest.sig` signed by one of them. Unset (the private-fleet
            // default) means signatures are not required.
            let trusted_signers: Vec<String> = std::env::var("COINCYNC_SNAPSHOT_TRUSTED_PUBKEYS")
                .ok()
                .map(|v| {
                    v.split(',')
                        .map(|s| s.trim().to_string())
                        .filter(|s| !s.is_empty())
                        .collect()
                })
                .unwrap_or_default();
            if !trusted_signers.is_empty() {
                info!(
                    "Snapshot signature required: {} trusted signer(s) configured",
                    trusted_signers.len()
                );
            }
            let policy = coincync::snapshot::ImportPolicy {
                network,
                expected_genesis: &genesis,
                checkpoints: &checkpoints,
                trusted_signers: &trusted_signers,
                backup_stamp,
            };

            info!(
                "Importing snapshot from {} into {} (network={}, verifying against {} checkpoints)",
                input.display(),
                chaindata_path.display(),
                network_subdir,
                checkpoints.len(),
            );
            match coincync::snapshot::import(&input, &chaindata_path, &policy) {
                Ok(m) => {
                    info!(
                        "✓ Snapshot imported: height={} tip={} (produced by {} at unix {}).",
                        m.height, m.tip_hash, m.node_version, m.created_at
                    );
                    info!("Start the node normally to resume from height {}.", m.height);
                }
                Err(e) => {
                    error!("Snapshot import failed: {}", e);
                    error!("Your previous chaindata (if any) was moved to a `.pre-snapshot-*` sibling and NOT deleted — see the error above.");
                    std::process::exit(1);
                }
            }
        }
        Command::Start => {
            if let Err(e) = start_node(
                network,
                data_dir,
                cli.p2p_bind,
                cli.rpc_bind,
                cli.rest_bind,
                cli.rest_disable,
                cli.addnode,
                cli.external_ip,
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
    const REPO: &str = "Coincync/Coincync-Testnet-";
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
    rest_disable: bool,
    addnodes: Vec<String>,
    external_ip: Option<String>,
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

    // Runtime deadlock watchdog. Arm BEFORE any tokio work so the
    // startup phase (RandomX dataset build, DB open, etc.) is
    // observable too — the watchdog's own 90s grace window covers
    // the legitimate startup lock-park pattern. Diagnostic snapshots
    // land under `data_dir` on confirmed hang; systemd's Restart=
    // then brings us back. See src/runtime_watchdog.rs for the
    // full design (motivated by the 2026-07-02 api.coincync.network
    // 41-hour futex-park deadlock — every tokio worker on
    // futex_wait_queue for hours with no observable output).
    let watchdog_heartbeat = coincync::runtime_watchdog::arm(&data_dir);
    coincync::runtime_watchdog::spawn_heartbeat_task(watchdog_heartbeat);

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

    // --external-ip: register our own reachable address as a self-address
    // so peer gossip echoing our IP back to us can't make us self-dial.
    // Accept "IP:PORT" directly, or a bare "IP" (attach our listen port).
    if let Some(raw) = &external_ip {
        let parsed = raw.parse::<std::net::SocketAddr>().ok().or_else(|| {
            raw.parse::<std::net::IpAddr>()
                .ok()
                .map(|ip| std::net::SocketAddr::new(ip, p2p_config.listen_addr.port()))
        });
        match parsed {
            Some(addr) => {
                info!("--external-ip: registering {} as our self-address", addr);
                p2p_config.external_addr = Some(addr);
            }
            None => warn!("Ignoring bad --external-ip {:?}", raw),
        }
    }

    if no_peers {
        info!("--no-peers: automatic peer discovery disabled (manual --addnode peers still allowed)");
        // Enforce true isolation: disable bootstrap seeds.
        p2p_config.bootstrap.dns_seeds.clear();
        p2p_config.bootstrap.seed_nodes.clear();
        // 2026-06-09: cap outbound at the manual --addnode count, not 0.
        // The previous `= 0` was silently fatal to --addnode: the node
        // would log the peer was registered ("--addnode: adding manual
        // peer X") + show "1 known addresses" in peer maintenance, yet
        // never dial because the outbound slot budget was zero. The
        // info-line above advertised "--addnode peers still allowed",
        // which was a lie. Found via Crucible Cycle 01 — operator
        // tried to peer with the only other v1.0.11 node (cross-CGNAT
        // workaround), watched 0 outbound for 5+ minutes despite the
        // manual peer being in the list.
        // Min of 1 keeps the slot available even if the operator
        // passed --no-peers without --addnode (degenerate but legal).
        p2p_config.max_outbound = extra_peers.len().max(1);
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
    p2p.set_chain_state(p2p.next_chain_seq(), tip.height, tip.hash).await;

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
                            //
                            // Wrapped in spawn_blocking to move the
                            // synchronous parking_lot::RwLock contention
                            // off the tokio worker thread. Previously
                            // `shadow_evict_invalid` ran inline on the
                            // worker; under sustained block flow it would
                            // hold the chain RwLock for the duration of
                            // the mempool walk, blocking other tokio
                            // tasks (RPC, network reads) on the same
                            // worker. Bitcoin Core's
                            // `MaybeUpdateMempoolForReorg` (VERIFIED as
                            // declared at validation.h:883 in the
                            // master read this session) fills an
                            // analogous role at the equivalent hook;
                            // the prior comment's specific "runs on a
                            // separate background thread" claim about
                            // upstream's execution model was not
                            // verified this session and is dropped.
                            //
                            // We .await the join so the post-block
                            // notifications below see the updated
                            // mempool state, but the worker is freed
                            // during the blocking work.
                            let evict_mempool = event_mempool.clone();
                            let evict_chain = event_chain.clone();
                            let _ = tokio::task::spawn_blocking(move || {
                                evict_mempool.shadow_evict_invalid(evict_chain.as_ref());
                            }).await;

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
                            // Capture the accept-order sequence BEFORE the
                            // detached spawn. These tasks are not serialized,
                            // so an older one can complete after a newer one;
                            // the seq lets set_chain_state drop the stale
                            // write instead of regressing the P2P shadow
                            // (issue #249).
                            let chain_seq = event_p2p.next_chain_seq();
                            tokio::spawn(async move {
                                p2p2.notify_block_received(&hash).await;
                                p2p2.notify_block_processed(hash, block_height).await;
                                p2p2.set_chain_state(chain_seq, new_height, new_tip).await;
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
                            // to fetch the orphan's parent so the gap fills, AND pass the
                            // orphan body so the sync manager can stash it in
                            // `orphan_blocks`. When the parent connects, the drain loop in
                            // `on_block_received_from` replays the pooled orphan directly —
                            // no second gossip required.
                            //
                            // See sync::mark_block_orphan for the long version, including
                            // the 2026-06-17 root-cause notes on why the hashes-only
                            // version stuck the chain at h=167 with 200 blocks of
                            // orphan-fetch loops.
                            warn!(
                                "Block {} from peer {:?} orphan; fetching parent {}",
                                hex::encode(&hash.as_bytes()[..8]),
                                &peer_id[..4],
                                hex::encode(&prev_hash.as_bytes()[..8]),
                            );
                            let p2p2 = event_p2p.clone();
                            let block_for_pool = block_for_relay.clone();
                            tokio::spawn(async move {
                                p2p2.notify_block_received(&hash).await;
                                p2p2.notify_block_orphan(&peer_id, block_for_pool, &prev_hash).await;
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
    // Multi-host REST: default REST to bind on 127.0.0.1:<rpc+2> on
    // EVERY node, not just those with --explorer or --rest-bind.
    // Rationale: the REST surface exposes /api/v1/health, /health/live,
    // /health/ready, /rpc allowlist and /api/v1/status. A load balancer
    // (Cloudflare LB, nginx, HAProxy) fronting api.coincync.network can
    // now health-check every fleet host and route around a wedged one
    // — closing the SPOF where one broken api-role box takes down the
    // entire public RPC surface (the 41-hour outage on 2026-07-02
    // that motivated this change).
    //
    // Precedence:
    //   1. --rest-disable wins (opt out — e.g. resource-constrained
    //      miner boxes). Returns None → REST is not spawned.
    //   2. Explicit --rest-bind wins over the default.
    //   3. Otherwise default to 127.0.0.1:<rpc+2>.
    //
    // Loopback default means no exposure without an explicit nginx/LB
    // wiring; ufw stays untouched by this change.
    let rest_listen: Option<std::net::SocketAddr> = if rest_disable {
        None
    } else {
        rest_bind
            .as_deref()
            .and_then(|s| s.parse().ok())
            .or_else(|| {
                // Default to rpc_port + 2 so it doesn't collide with
                // either the jsonrpsee server (rpc_port) or the
                // conventional "explorer HTTP" slot at rpc_port + 1
                // (which deploy/explorer/Caddyfile uses externally).
                Some(([127, 0, 0, 1], rpc_listen.port().wrapping_add(2)).into())
            })
    };

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

    info!("Node is running. Ctrl-C or systemctl stop to shut down.");

    // AUDIT 2026-06-30 (C2 root cause): catch SIGTERM as well as SIGINT
    // on Unix. The previous `tokio::signal::ctrl_c()` only catches SIGINT
    // — which means `systemctl stop coincync-node` (SIGTERM) bypassed
    // the entire graceful shutdown path, hard-killing the process without
    // flushing RocksDB. That was the actual mechanism behind the
    // 2026-06-30 zombie state: WAL entries never made it to SST, next
    // startup hung on WAL replay.
    //
    // Prior art (VERIFIED against upstream master this session):
    // Bitcoin Core installs `SIGTERM` and `SIGINT` handlers in
    // `AppInitBasicSetup` (init.cpp:908; registration at :928-:929),
    // both routed to `HandleSIGTERM` (init.cpp:451), plus a `SIGHUP`
    // handler `HandleSIGHUP` (init.cpp:458, registered :932). The
    // prior comment placed the registration in `AppInit()` and
    // claimed all three "route to the same `StartShutdown()` path";
    // the enclosing function name has changed and the internal
    // path from HandleSIGTERM to StartShutdown was not traced this
    // session, so the specific `StartShutdown()` chain claim is
    // dropped in favour of the verified handler-registration
    // receipts.
    #[cfg(unix)]
    {
        let mut sigterm = tokio::signal::unix::signal(
            tokio::signal::unix::SignalKind::terminate()
        ).expect("failed to install SIGTERM handler");

        tokio::select! {
            _ = tokio::signal::ctrl_c() => {
                info!("SIGINT received (Ctrl+C), stopping node...");
            }
            _ = sigterm.recv() => {
                info!("SIGTERM received (systemctl stop / kill), stopping node...");
            }
        }
    }
    #[cfg(not(unix))]
    {
        tokio::signal::ctrl_c()
            .await
            .expect("failed to install ctrl-c handler");
        info!("Ctrl+C received, stopping node...");
    }

    // AUDIT 2026-06-05 #14 — persist mempool before exit so unconfirmed
    // txs survive the restart. Failure is logged but not fatal — the
    // node still needs to release the chain DB lock and exit.
    //
    // 2026-06-10 (Crucible Cycle 01 Finding #4): wrap the save in a
    // `tokio::select!` against a second Ctrl+C, so a user who hits
    // Ctrl+C twice can skip the save and force-exit immediately. The
    // save normally takes <1s but can stall if the data directory is
    // on a misbehaving disk; without the escape hatch, the user had
    // no way to abort the shutdown.
    let shutdown_seq = async {
        match mempool.save_to_disk(&data_dir) {
            Ok(0) => {}
            Ok(n) => info!("Mempool: saved {} txs to disk", n),
            Err(e) => error!("Mempool: save_to_disk failed: {}", e),
        }
    };

    tokio::select! {
        _ = shutdown_seq => {
            info!("Shutdown complete.");
        }
        _ = tokio::signal::ctrl_c() => {
            warn!("Second Ctrl+C received — skipping mempool save, exiting immediately.");
        }
    }

    // AUDIT 2026-06-30 (C2): explicit RocksDB flush before force-exit —
    // root cause of the 2026-06-30 zombie state where stop-tar-start
    // cycles left coincync-node running with an unresponsive RPC.
    //
    // The previous claim "RocksDB has its own atomic-write guarantees"
    // is true for individual writes, but NOT for the WAL between memtable
    // flushes. On a hard `process::exit(0)`, Rust does not run `Drop` for
    // the `Arc<Database>` — the OS reaps the process and RocksDB never
    // gets to flush pending WAL entries to SST files. On next startup,
    // RocksDB attempts WAL replay, which can hang (WAL truncated by tar
    // capturing mid-write) or produce an inconsistent state that leaves
    // the RPC unresponsive while the DB is stuck in recovery.
    //
    // The fix is a two-step graceful drain BEFORE the hard exit:
    //   1. `db.flush()` — force memtable → SST + WAL truncation
    //   2. `cancel_all_background_work(wait=true)` — let compactions
    //      complete instead of leaving them mid-run
    //
    // Both are best-effort with a short deadline; if either hangs we
    // still force-exit to preserve the "restart works even if disk is
    // broken" property. But under normal conditions this eliminates the
    // WAL-replay-hang failure mode entirely.
    //
    // Prior art (UNVERIFIED this session): the prior comment cited
    // Bitcoin Core `Shutdown()` explicitly calling `pcoinsdbview->Flush()`
    // and `pblocktree->Sync()` before returning to main, and Zebrad's
    // `RpcServer::stop_service` explicitly awaiting DB drain. Neither
    // specific identifier chain was re-verified against upstream this
    // session, so both citations are dropped. The flush-before-exit
    // design here stands on its own reasoning above (the 2026-06-30
    // WAL-replay-hang incident).
    info!("Draining RocksDB before exit...");
    let flush_deadline = std::time::Duration::from_secs(10);
    let flush_start = std::time::Instant::now();
    match tokio::time::timeout(flush_deadline, tokio::task::spawn_blocking({
        let db = db.clone();
        move || db.flush_best_effort()
    })).await {
        Ok(Ok(())) => {
            info!(
                flush_ms = flush_start.elapsed().as_millis(),
                "RocksDB flushed cleanly, exiting"
            );
        }
        Ok(Err(join_err)) => {
            error!("RocksDB flush task panicked: {} — exiting anyway", join_err);
        }
        Err(_) => {
            warn!(
                "RocksDB flush did not complete within {}s — force-exiting. \
                 Next startup may need to replay WAL.",
                flush_deadline.as_secs()
            );
        }
    }

    // 2026-06-10 (Crucible Cycle 01 Finding #4): force the process to
    // exit. The previous code returned `Ok(())` and relied on the
    // `#[tokio::main]` runtime to drop, which in turn would abort all
    // spawned tasks. In practice that never completed — 13+ orphaned
    // tasks (REST API, JSON-RPC, P2P listeners, REST explorer,
    // spawn_blocking workers for block processing) kept the runtime
    // alive indefinitely after main's future resolved. Operator-
    // visible symptom: "Shutdown signal received, stopping node..."
    // logged, then no exit. SIGINT had to be repeated or the terminal
    // killed to actually stop the process.
    //
    // Process exits with code 0 (clean shutdown). Don't change to
    // non-zero — operators (and systemd) treat that as a crash and
    // may attempt restart.
    std::process::exit(0);
}
