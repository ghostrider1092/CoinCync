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
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();

    // Initialize tracing
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| cli.log_level.parse().unwrap()),
        )
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
    let chain = Blockchain::with_database(db.clone(), network);
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
                    let hash = block.hash();
                    let block_height = block.header.height;
                    let block_txs = block.transactions.clone();
                    let block_for_relay = block.clone();
                    match event_chain.process_block(block) {
                        Ok(BlockStatus::Accepted)
                        | Ok(BlockStatus::AcceptedFork)
                        | Ok(BlockStatus::AcceptedReorg { .. }) => {
                            // Keep mempool aligned with chain state: remove mined txs and
                            // advance mempool height so activation-gated checks stay correct.
                            event_mempool.remove_confirmed(&block_txs);
                            event_mempool.set_height(event_chain.height());

                            // Notify IBD sync manager so it advances its
                            // local_height cursor and releases the next
                            // batch window; without this the sync engine
                            // keeps re-requesting blocks we've already
                            // applied. Then gossip onward.
                            let p2p2 = event_p2p.clone();
                            tokio::spawn(async move {
                                p2p2.notify_block_received(&hash).await;
                                p2p2.notify_block_processed(hash, block_height).await;
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
                            warn!(
                                "Block {} from peer {:?} orphan",
                                hex::encode(&hash.as_bytes()[..8]),
                                &peer_id[..4]
                            );
                            let p2p2 = event_p2p.clone();
                            tokio::spawn(async move {
                                p2p2.notify_block_received(&hash).await;
                                p2p2.notify_block_failed(&hash).await;
                            });
                        }
                        Ok(BlockStatus::Invalid(reason)) => {
                            warn!(
                                "Block {} from peer {:?} invalid: {}",
                                hex::encode(&hash.as_bytes()[..8]),
                                &peer_id[..4],
                                reason
                            );
                            let p2p2 = event_p2p.clone();
                            tokio::spawn(async move {
                                p2p2.notify_block_received(&hash).await;
                                p2p2.notify_block_failed(&hash).await;
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
                Ok(NodeEvent::TransactionReceived(tx)) => {
                    // Admit fluffed network txs into local mempool so they become mineable.
                    if let Err(e) = event_mempool.add_with_chain(tx, &event_chain) {
                        warn!("P2P transaction rejected by mempool: {}", e);
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
