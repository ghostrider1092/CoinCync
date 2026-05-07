//! # Configuration Management
//!
//! Runtime configuration for CoinCync nodes and wallets.
//!
//! Supports:
//! - TOML configuration files
//! - Environment variable overrides
//! - Schema validation with helpful errors
//!
//! ## Configuration File Location
//!
//! Default: `~/.coincync/config.toml`
//!
//! ## Environment Variables
//!
//! All config options can be overridden with `CYNC_` prefix:
//! - `CYNC_NETWORK=testnet`
//! - `CYNC_P2P_PORT=28080`
//! - `CYNC_RPC_PORT=28081`
//! - `CYNC_DATA_DIR=/custom/path`

use std::path::{Path, PathBuf};
use std::env;
use serde::{Serialize, Deserialize};
use crate::constants::{
    DEFAULT_P2P_PORT, DEFAULT_RPC_PORT, TESTNET_P2P_PORT, TESTNET_RPC_PORT,
    REGTEST_P2P_PORT, REGTEST_RPC_PORT,
    MAINNET_ADDRESS_PREFIX, TESTNET_ADDRESS_PREFIX,
    ADDRESS_HRP, T_ADDRESS_HRP, R_ADDRESS_HRP,
    MAX_PEERS, DB_CACHE_SIZE_MB,
};

/// Node tier in the hybrid network model.
///
/// CoinCync uses a 3-tier hybrid node architecture:
/// - **Personal**: Light node storing only YOUR chain/UTXOs/keys. Phone/RPi capable.
/// - **Network**: Incentivized node relaying fraud proofs, serving block filters,
///   and maintaining a DHT shard of key images.
/// - **Archive**: Full history node for explorers and audit. Not required for consensus.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum NodeTier {
    /// Tier 1: Personal node — header-only chain + own wallet scanning.
    /// ~50 MB RAM, ~500 MB storage. Runs on phone, RPi, browser.
    Personal,
    /// Tier 2: Network node — serves block filters, relays fraud proofs,
    /// maintains a DHT shard of key images. ~500 MB RAM, ~10 GB storage.
    Network,
    /// Tier 3: Archive node — full block history, explorer support.
    /// Standard full node. ~2 GB RAM, ~100+ GB storage.
    Archive,
}

impl Default for NodeTier {
    fn default() -> Self {
        NodeTier::Archive // Backward-compatible: default is full node behavior
    }
}

/// Configuration for personal (Tier 1) lightweight nodes.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PersonalConfig {
    /// Trusted network nodes to connect to for block filters and digests.
    /// These serve as the personal node's view of the network.
    pub trusted_peers: Vec<String>,
    /// Maximum number of block headers to cache in memory.
    pub max_cached_headers: usize,
    /// How often to poll for new blocks (seconds).
    pub poll_interval_secs: u64,
    /// Enable background wallet scanning.
    pub background_scan: bool,
    /// Path to wallet file (encrypted).
    pub wallet_path: Option<PathBuf>,
}

impl Default for PersonalConfig {
    fn default() -> Self {
        PersonalConfig {
            trusted_peers: Vec::new(),
            max_cached_headers: 10_000,
            poll_interval_secs: 6, // Match block time
            background_scan: true,
            wallet_path: None,
        }
    }
}

/// Configuration for network (Tier 2) nodes — DHT and filter serving.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NetworkTierConfig {
    /// Number of DHT stripes for key image sharding (e.g., 8 = each node stores 1/8).
    pub dht_stripe_count: u32,
    /// This node's DHT stripe (auto-assigned from node pubkey if None).
    pub dht_stripe: Option<u32>,
    /// Enable serving block filters to personal nodes.
    pub serve_block_filters: bool,
    /// Enable serving output digests to personal nodes.
    pub serve_output_digests: bool,
    /// Fee share percentage for relay incentives (basis points).
    pub relay_fee_share_bps: u64,
}

impl Default for NetworkTierConfig {
    fn default() -> Self {
        NetworkTierConfig {
            dht_stripe_count: 8,
            dht_stripe: None,
            serve_block_filters: true,
            serve_output_digests: true,
            relay_fee_share_bps: 50, // 0.5% of tx fees
        }
    }
}

/// Network type
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum NetworkType {
    Mainnet,
    Testnet,
    Regtest,
}

/// Canonical per-network runtime parameters.
///
/// Mature chains keep network identity in one immutable table to avoid
/// split-brain behavior caused by scattered constants.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ChainParams {
    pub network: NetworkType,
    pub magic: [u8; 4],
    pub p2p_port: u16,
    pub rpc_port: u16,
    pub data_dir_name: &'static str,
    pub name: &'static str,
    pub address_hrp: &'static str,
    pub address_prefix: &'static str,
}

/// Compatibility alias for `NetworkType`. Some ported 1.0-skeleton code
/// refers to the network enum as `Network`. Kept here so both names work
/// without either import path needing surgery.
pub type Network = NetworkType;

impl Default for NetworkType {
    fn default() -> Self {
        NetworkType::Mainnet
    }
}

impl NetworkType {
    pub fn params(&self) -> ChainParams {
        match self {
            NetworkType::Mainnet => ChainParams {
                network: NetworkType::Mainnet,
                magic: crate::constants::MAINNET_MAGIC,
                p2p_port: DEFAULT_P2P_PORT,
                rpc_port: DEFAULT_RPC_PORT,
                data_dir_name: "mainnet",
                name: "mainnet",
                address_hrp: ADDRESS_HRP,
                address_prefix: MAINNET_ADDRESS_PREFIX,
            },
            NetworkType::Testnet => ChainParams {
                network: NetworkType::Testnet,
                magic: crate::constants::TESTNET_MAGIC,
                p2p_port: TESTNET_P2P_PORT,
                rpc_port: TESTNET_RPC_PORT,
                data_dir_name: "testnet",
                name: "testnet",
                address_hrp: T_ADDRESS_HRP,
                address_prefix: TESTNET_ADDRESS_PREFIX,
            },
            NetworkType::Regtest => ChainParams {
                network: NetworkType::Regtest,
                magic: crate::constants::REGTEST_MAGIC,
                p2p_port: REGTEST_P2P_PORT,
                rpc_port: REGTEST_RPC_PORT,
                data_dir_name: "regtest",
                name: "regtest",
                address_hrp: R_ADDRESS_HRP,
                address_prefix: TESTNET_ADDRESS_PREFIX,
            },
        }
    }

    pub fn default_p2p_port(&self) -> u16 {
        self.params().p2p_port
    }

    /// Alias for `default_p2p_port` — some ported code calls `.p2p_port()`.
    #[inline]
    pub fn p2p_port(&self) -> u16 { self.default_p2p_port() }

    pub fn default_rpc_port(&self) -> u16 {
        self.params().rpc_port
    }

    pub fn data_dir_name(&self) -> &str {
        self.params().data_dir_name
    }

    /// 4-byte magic identifier stamped into every P2P message and block header.
    /// Different per network so testnet blocks/messages are rejected instantly
    /// on mainnet (and vice versa) before any expensive validation.
    pub fn magic_bytes(&self) -> [u8; 4] {
        self.params().magic
    }

    /// Network name for display and logging.
    pub fn name(&self) -> &'static str {
        self.params().name
    }

    /// Returns true if this is any non-production network.
    pub fn is_test_network(&self) -> bool {
        !matches!(self, NetworkType::Mainnet)
    }

    /// Parse from magic bytes. Returns None if unknown.
    pub fn from_magic_bytes(bytes: [u8; 4]) -> Option<Self> {
        if bytes == crate::constants::MAINNET_MAGIC { return Some(NetworkType::Mainnet); }
        if bytes == crate::constants::TESTNET_MAGIC { return Some(NetworkType::Testnet); }
        if bytes == crate::constants::REGTEST_MAGIC { return Some(NetworkType::Regtest); }
        None
    }
}

impl std::fmt::Display for NetworkType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.name())
    }
}

/// Node configuration
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NodeConfig {
    /// Network type
    pub network: NetworkType,

    /// Node tier (Personal / Network / Archive)
    #[serde(default)]
    pub node_tier: NodeTier,

    /// Data directory
    pub data_dir: PathBuf,

    /// P2P configuration
    pub p2p: P2PConfig,

    /// RPC configuration
    pub rpc: RpcConfig,

    /// Database configuration
    pub database: DatabaseConfig,

    /// Mining configuration
    pub mining: MiningConfig,

    /// Pruning configuration
    #[serde(default)]
    pub pruning: PruningConfig,

    /// Personal node configuration (Tier 1)
    #[serde(default)]
    pub personal: PersonalConfig,

    /// Network tier configuration (Tier 2 — DHT, filter serving)
    #[serde(default)]
    pub network_tier: NetworkTierConfig,

    /// Logging level
    pub log_level: String,

    /// Extra peer addresses to always try connecting to (from CLI `--addnode`).
    #[serde(default)]
    pub addnodes: Vec<String>,

    /// When `true`, skip all automatic peer discovery (from CLI `--no-peers`).
    #[serde(default)]
    pub no_peers: bool,
}

impl Default for NodeConfig {
    fn default() -> Self {
        let network = NetworkType::Mainnet;
        NodeConfig {
            network,
            node_tier: NodeTier::default(),
            data_dir: default_data_dir(network),
            p2p: P2PConfig::default(),
            rpc: RpcConfig::default(),
            database: DatabaseConfig::default(),
            mining: MiningConfig::default(),
            pruning: PruningConfig::default(),
            personal: PersonalConfig::default(),
            network_tier: NetworkTierConfig::default(),
            log_level: "info".to_string(),
            addnodes: Vec::new(),
            no_peers: false,
        }
    }
}

impl NodeConfig {
    /// Create config for a specific network
    pub fn for_network(network: NetworkType) -> Self {
        let mut config = Self::default();
        config.network = network;
        config.data_dir = default_data_dir(network);
        config.p2p.port = network.default_p2p_port();
        config.rpc.port = network.default_rpc_port();
        config
    }

    /// Get the blocks database path
    pub fn blocks_db_path(&self) -> PathBuf {
        self.data_dir.join("blocks")
    }

    /// Get the chain state database path
    pub fn state_db_path(&self) -> PathBuf {
        self.data_dir.join("state")
    }

    /// Get the wallet directory path
    pub fn wallet_dir(&self) -> PathBuf {
        self.data_dir.join("wallets")
    }

    /// Load config from file
    pub fn load(path: &PathBuf) -> crate::error::Result<Self> {
        let content = std::fs::read_to_string(path)?;
        serde_json::from_str(&content)
            .map_err(|e| crate::error::Error::SerializationError(e.to_string()))
    }

    /// Save config to file
    pub fn save(&self, path: &PathBuf) -> crate::error::Result<()> {
        let content = serde_json::to_string_pretty(self)
            .map_err(|e| crate::error::Error::SerializationError(e.to_string()))?;
        std::fs::write(path, content)?;
        Ok(())
    }
}

/// P2P network configuration
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct P2PConfig {
    /// Listen address
    pub listen_addr: String,

    /// Listen port
    pub port: u16,

    /// Maximum number of peers
    pub max_peers: usize,

    /// Bootstrap nodes
    pub bootstrap_nodes: Vec<String>,

    /// Enable UPnP
    pub upnp: bool,

    /// External IP (if known)
    pub external_ip: Option<String>,

    /// Offline mode (no P2P connections)
    #[serde(default)]
    pub offline: bool,

    /// SOCKS5 proxy configuration (for Tor, I2P, etc.)
    /// Users install and run their own proxy - CoinCync just connects to it
    #[serde(default)]
    pub proxy: Option<ProxyConfig>,

    /// Noise Protocol encryption configuration
    #[serde(default)]
    pub encryption: P2PEncryptionConfig,
}

/// Noise Protocol encryption configuration for P2P connections
///
/// Controls whether node-to-node traffic is encrypted using the Noise_XX
/// protocol with X25519 key exchange, ChaCha20-Poly1305 AEAD, and BLAKE3.
///
/// By default, encryption is both preferred and required to prevent plaintext
/// downgrade paths. Operators can explicitly disable `required` only for
/// transitional compatibility on isolated networks.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct P2PEncryptionConfig {
    /// Require encryption — reject peers that don't support Noise
    /// Default: false (allow plaintext fallback during transition)
    #[serde(default)]
    pub required: bool,

    /// Prefer encryption — attempt Noise handshake before falling back
    /// Default: true
    #[serde(default = "default_true")]
    pub preferred: bool,

    /// Trusted peer static public keys (hex-encoded X25519 pubkeys)
    /// When non-empty, only peers with these static keys are allowed
    #[serde(default)]
    pub trusted_peers: Vec<String>,
}

fn default_true() -> bool {
    true
}

impl Default for P2PEncryptionConfig {
    fn default() -> Self {
        P2PEncryptionConfig {
            required: true,
            preferred: true,
            trusted_peers: vec![],
        }
    }
}

/// SOCKS5 proxy configuration
///
/// CoinCync supports routing traffic through a SOCKS5 proxy.
/// This allows users to use Tor, I2P, or other privacy networks.
///
/// **Important**: CoinCync does NOT bundle or manage Tor.
/// Users must install and run their own proxy software.
///
/// ## Example: Using with Tor
///
/// 1. Install Tor: https://www.torproject.org/
/// 2. Start Tor (default SOCKS5 port: 9050)
/// 3. Configure CoinCync:
///    ```toml
///    [p2p.proxy]
///    enabled = true
///    address = "127.0.0.1"
///    port = 9050
///    ```
#[derive(Clone, Serialize, Deserialize)]
pub struct ProxyConfig {
    /// Enable proxy
    #[serde(default)]
    pub enabled: bool,

    /// Proxy address (e.g., "127.0.0.1")
    pub address: String,

    /// Proxy port (Tor default: 9050)
    pub port: u16,

    /// Proxy username (optional)
    #[serde(default)]
    pub username: Option<String>,

    /// Proxy password (optional)
    #[serde(default)]
    pub password: Option<String>,

    /// Only connect to .onion addresses (Tor-only mode)
    #[serde(default)]
    pub onion_only: bool,

    /// Proxy type (default: socks5)
    #[serde(default = "default_proxy_type")]
    pub proxy_type: ProxyType,
}

// SECURITY (M-10): Manual Debug impl to redact password field from logs.
impl std::fmt::Debug for ProxyConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ProxyConfig")
            .field("enabled", &self.enabled)
            .field("address", &self.address)
            .field("port", &self.port)
            .field("username", &self.username)
            .field("password", &self.password.as_ref().map(|_| "[REDACTED]"))
            .field("onion_only", &self.onion_only)
            .field("proxy_type", &self.proxy_type)
            .finish()
    }
}

fn default_proxy_type() -> ProxyType {
    ProxyType::Socks5
}

/// Supported proxy types
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum ProxyType {
    #[default]
    Socks5,
    Socks4,
    Http,
}

impl Default for ProxyConfig {
    fn default() -> Self {
        ProxyConfig {
            enabled: false,
            address: "127.0.0.1".to_string(),
            port: 9050, // Tor default
            username: None,
            password: None,
            onion_only: false,
            proxy_type: ProxyType::Socks5,
        }
    }
}

impl ProxyConfig {
    /// Create a Tor proxy configuration
    pub fn tor() -> Self {
        ProxyConfig {
            enabled: true,
            address: "127.0.0.1".to_string(),
            port: 9050,
            username: None,
            password: None,
            onion_only: false,
            proxy_type: ProxyType::Socks5,
        }
    }

    /// Create a Tor Browser proxy configuration (different port)
    pub fn tor_browser() -> Self {
        ProxyConfig {
            enabled: true,
            address: "127.0.0.1".to_string(),
            port: 9150, // Tor Browser uses 9150
            username: None,
            password: None,
            onion_only: false,
            proxy_type: ProxyType::Socks5,
        }
    }

    /// Get the proxy URL (without credentials for safe logging/display)
    ///
    /// SECURITY: Credentials are intentionally excluded from the URL string
    /// to prevent password leakage through logging, error messages, or debugging.
    /// Use `credentials()` separately when connecting to the proxy.
    pub fn url(&self) -> String {
        let scheme = match self.proxy_type {
            ProxyType::Socks5 => "socks5",
            ProxyType::Socks4 => "socks4",
            ProxyType::Http => "http",
        };
        format!("{}://{}:{}", scheme, self.address, self.port)
    }

    /// Get proxy credentials separately (not included in URL for security)
    pub fn credentials(&self) -> Option<(&str, &str)> {
        match (&self.username, &self.password) {
            (Some(u), Some(p)) => Some((u.as_str(), p.as_str())),
            _ => None,
        }
    }

    /// Check if proxy is configured and enabled
    pub fn is_active(&self) -> bool {
        self.enabled && !self.address.is_empty() && self.port > 0
    }
}

impl Default for P2PConfig {
    fn default() -> Self {
        P2PConfig {
            listen_addr: "0.0.0.0".to_string(),
            port: DEFAULT_P2P_PORT,
            max_peers: MAX_PEERS,
            bootstrap_nodes: vec![],
            // SECURITY (M-12): UPnP disabled by default. UPnP opens a port on
            // the user's router without explicit consent, which is a security risk.
            // Users who want incoming connections should enable this explicitly.
            upnp: false,
            external_ip: None,
            offline: false,
            proxy: None,
            encryption: P2PEncryptionConfig::default(),
        }
    }
}

impl P2PConfig {
    pub fn listen_socket(&self) -> String {
        format!("{}:{}", self.listen_addr, self.port)
    }
}

/// RPC configuration
#[derive(Clone, Serialize, Deserialize)]
pub struct RpcConfig {
    /// Enable RPC server
    pub enabled: bool,

    /// Listen address
    pub listen_addr: String,

    /// Listen port
    pub port: u16,

    /// Require authentication
    pub auth_required: bool,

    /// Username (if auth required)
    pub username: Option<String>,

    /// Password (if auth required)
    pub password: Option<String>,

    /// Allowed origins for CORS
    pub cors_origins: Vec<String>,

    /// Enable TLS for RPC connections
    /// Default: true (auto-generates self-signed cert on first run)
    #[serde(default = "default_true")]
    pub tls_enabled: bool,

    /// Path to TLS certificate PEM file (auto-generated if not set)
    #[serde(default)]
    pub tls_cert_path: Option<String>,

    /// Path to TLS private key PEM file (auto-generated if not set)
    #[serde(default)]
    pub tls_key_path: Option<String>,

    /// Enable mutual TLS (client certificate required)
    #[serde(default)]
    pub tls_mutual: bool,

    /// Path to client CA certificate PEM for mutual TLS
    #[serde(default)]
    pub tls_client_ca: Option<String>,
}

// SECURITY (M-10): Manual Debug impl to redact password field from logs.
impl std::fmt::Debug for RpcConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RpcConfig")
            .field("enabled", &self.enabled)
            .field("listen_addr", &self.listen_addr)
            .field("port", &self.port)
            .field("auth_required", &self.auth_required)
            .field("username", &self.username)
            .field("password", &self.password.as_ref().map(|_| "[REDACTED]"))
            .field("cors_origins", &self.cors_origins)
            .field("tls_enabled", &self.tls_enabled)
            .field("tls_cert_path", &self.tls_cert_path)
            .field("tls_key_path", &"[REDACTED]")
            .field("tls_mutual", &self.tls_mutual)
            .field("tls_client_ca", &self.tls_client_ca)
            .finish()
    }
}

impl Default for RpcConfig {
    fn default() -> Self {
        RpcConfig {
            enabled: true,
            listen_addr: "127.0.0.1".to_string(),
            port: DEFAULT_RPC_PORT,
            // SECURITY (M8): Default auth_required to false when no credentials are set.
            // Previously defaulted to true with no credentials, which silently rejected
            // ALL RPC requests — confusing for users. Now defaults to open on localhost
            // (127.0.0.1 only). Users should set credentials + auth_required=true for
            // any non-localhost or production deployment.
            auth_required: false,
            username: None,
            password: None,
            cors_origins: vec![],
            tls_enabled: true,
            tls_cert_path: None,
            tls_key_path: None,
            tls_mutual: false,
            tls_client_ca: None,
        }
    }
}

impl RpcConfig {
    pub fn listen_socket(&self) -> String {
        format!("{}:{}", self.listen_addr, self.port)
    }
}

/// Database configuration
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DatabaseConfig {
    /// Cache size in MB
    pub cache_size_mb: usize,

    /// Enable compression
    pub compression: bool,

    /// Sync writes to disk
    pub sync_writes: bool,
}

impl Default for DatabaseConfig {
    fn default() -> Self {
        DatabaseConfig {
            cache_size_mb: DB_CACHE_SIZE_MB,
            compression: true,
            sync_writes: true,
        }
    }
}

/// Mining configuration
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MiningConfig {
    /// Enable mining
    pub enabled: bool,

    /// Number of mining threads
    pub threads: usize,

    /// Miner address (for rewards)
    pub miner_address: Option<String>,

    /// Pool URL (if pool mining)
    pub pool_url: Option<String>,
}

impl Default for MiningConfig {
    fn default() -> Self {
        MiningConfig {
            enabled: false,
            threads: 1,
            miner_address: None,
            pool_url: None,
        }
    }
}

/// Pruning configuration
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PruningConfig {
    /// Pruning mode: "archive", "recent", "unspent"
    #[serde(default = "default_prune_mode")]
    pub mode: String,

    /// Number of recent blocks to keep (for "recent" mode)
    #[serde(default = "default_keep_blocks")]
    pub keep_blocks: u64,

    /// How often to run the pruner (every N accepted blocks)
    #[serde(default = "default_prune_interval")]
    pub prune_interval: u64,

    /// Keep checkpoint blocks when pruning
    #[serde(default = "default_true")]
    pub keep_checkpoints: bool,

    /// Checkpoint interval (keep every Nth block as checkpoint)
    #[serde(default = "default_checkpoint_interval")]
    pub checkpoint_interval: u64,
}

fn default_prune_mode() -> String { "archive".to_string() }
fn default_keep_blocks() -> u64 { 5000 }
fn default_prune_interval() -> u64 { 1000 }
fn default_checkpoint_interval() -> u64 { 10000 }

impl Default for PruningConfig {
    fn default() -> Self {
        PruningConfig {
            mode: default_prune_mode(),
            keep_blocks: default_keep_blocks(),
            prune_interval: default_prune_interval(),
            keep_checkpoints: true,
            checkpoint_interval: default_checkpoint_interval(),
        }
    }
}

/// Wallet configuration
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WalletConfig {
    /// Network type
    pub network: NetworkType,

    /// Wallet file path
    pub wallet_path: PathBuf,

    /// Node RPC URL
    pub node_url: String,

    /// Auto-sync on startup
    pub auto_sync: bool,
}

impl Default for WalletConfig {
    fn default() -> Self {
        WalletConfig {
            network: NetworkType::Mainnet,
            wallet_path: default_wallet_path(),
            node_url: format!("http://127.0.0.1:{}", DEFAULT_RPC_PORT),
            auto_sync: true,
        }
    }
}

/// Get default data directory
fn default_data_dir(network: NetworkType) -> PathBuf {
    let base = dirs_next::data_dir()
        .unwrap_or_else(|| PathBuf::from("."));
    base.join("coincync").join(network.data_dir_name())
}

/// Get default wallet path
fn default_wallet_path() -> PathBuf {
    let base = dirs_next::data_dir()
        .unwrap_or_else(|| PathBuf::from("."));
    base.join("coincync").join("wallet.dat")
}

/// Ensure data directories exist
pub fn ensure_dirs(config: &NodeConfig) -> std::io::Result<()> {
    std::fs::create_dir_all(&config.data_dir)?;
    std::fs::create_dir_all(config.blocks_db_path())?;
    std::fs::create_dir_all(config.state_db_path())?;
    std::fs::create_dir_all(config.wallet_dir())?;
    Ok(())
}

/// Builder for NodeConfig
#[derive(Default)]
pub struct NodeConfigBuilder {
    network: Option<NetworkType>,
    data_dir: Option<PathBuf>,
    p2p_port: Option<u16>,
    rpc_port: Option<u16>,
    rpc_enabled: Option<bool>,
    max_peers: Option<usize>,
    mining_enabled: Option<bool>,
    mining_threads: Option<usize>,
    miner_address: Option<String>,
    log_level: Option<String>,
    bootstrap_nodes: Option<Vec<String>>,
}

impl NodeConfigBuilder {
    /// Create a new builder
    pub fn new() -> Self {
        Self::default()
    }

    /// Set network type
    pub fn network(mut self, network: NetworkType) -> Self {
        self.network = Some(network);
        self
    }

    /// Set testnet mode
    pub fn testnet(self) -> Self {
        self.network(NetworkType::Testnet)
    }

    /// Set data directory
    pub fn data_dir(mut self, path: impl Into<PathBuf>) -> Self {
        self.data_dir = Some(path.into());
        self
    }

    /// Set P2P port
    pub fn p2p_port(mut self, port: u16) -> Self {
        self.p2p_port = Some(port);
        self
    }

    /// Set RPC port
    pub fn rpc_port(mut self, port: u16) -> Self {
        self.rpc_port = Some(port);
        self
    }

    /// Enable/disable RPC
    pub fn rpc_enabled(mut self, enabled: bool) -> Self {
        self.rpc_enabled = Some(enabled);
        self
    }

    /// Set maximum peers
    pub fn max_peers(mut self, max: usize) -> Self {
        self.max_peers = Some(max);
        self
    }

    /// Enable mining
    pub fn mining(mut self, enabled: bool) -> Self {
        self.mining_enabled = Some(enabled);
        self
    }

    /// Set mining threads
    pub fn mining_threads(mut self, threads: usize) -> Self {
        self.mining_threads = Some(threads);
        self
    }

    /// Set miner address
    pub fn miner_address(mut self, address: impl Into<String>) -> Self {
        self.miner_address = Some(address.into());
        self
    }

    /// Set log level
    pub fn log_level(mut self, level: impl Into<String>) -> Self {
        self.log_level = Some(level.into());
        self
    }

    /// Add bootstrap nodes
    pub fn bootstrap_nodes(mut self, nodes: Vec<String>) -> Self {
        self.bootstrap_nodes = Some(nodes);
        self
    }

    /// Build the configuration
    pub fn build(self) -> NodeConfig {
        let network = self.network.unwrap_or(NetworkType::Mainnet);
        let mut config = NodeConfig::for_network(network);

        if let Some(dir) = self.data_dir {
            config.data_dir = dir;
        }
        if let Some(port) = self.p2p_port {
            config.p2p.port = port;
        }
        if let Some(port) = self.rpc_port {
            config.rpc.port = port;
        }
        if let Some(enabled) = self.rpc_enabled {
            config.rpc.enabled = enabled;
        }
        if let Some(max) = self.max_peers {
            config.p2p.max_peers = max;
        }
        if let Some(enabled) = self.mining_enabled {
            config.mining.enabled = enabled;
        }
        if let Some(threads) = self.mining_threads {
            config.mining.threads = threads;
        }
        if let Some(addr) = self.miner_address {
            config.mining.miner_address = Some(addr);
        }
        if let Some(level) = self.log_level {
            config.log_level = level;
        }
        if let Some(nodes) = self.bootstrap_nodes {
            config.p2p.bootstrap_nodes = nodes;
        }

        config
    }
}

impl NodeConfig {
    /// Create a builder for fluent configuration
    pub fn builder() -> NodeConfigBuilder {
        NodeConfigBuilder::new()
    }

    /// Load configuration from TOML file
    pub fn load_toml(path: &Path) -> crate::error::Result<Self> {
        let content = std::fs::read_to_string(path)?;
        let config: Self = toml::from_str(&content)
            .map_err(|e| crate::error::Error::ConfigError(format_toml_error(&e, &content)))?;
        config.validate()?;
        Ok(config)
    }

    /// Save configuration to TOML file
    pub fn save_toml(&self, path: &Path) -> crate::error::Result<()> {
        let content = toml::to_string_pretty(self)
            .map_err(|e| crate::error::Error::SerializationError(e.to_string()))?;

        // Ensure parent directory exists
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }

        std::fs::write(path, content)?;
        Ok(())
    }

    /// Load configuration with environment variable overrides
    pub fn load_with_env(path: Option<&Path>) -> crate::error::Result<Self> {
        // Start with default or file config
        let mut config = if let Some(p) = path {
            if p.exists() {
                Self::load_toml(p)?
            } else {
                Self::default()
            }
        } else {
            // Try default config path
            let default_path = default_config_path();
            if default_path.exists() {
                Self::load_toml(&default_path)?
            } else {
                Self::default()
            }
        };

        // Apply environment variable overrides
        config.apply_env_overrides();

        // Validate final config
        config.validate()?;

        Ok(config)
    }

    /// Apply environment variable overrides
    fn apply_env_overrides(&mut self) {
        // Network
        if let Ok(network) = env::var("CYNC_NETWORK") {
            self.network = match network.to_lowercase().as_str() {
                "mainnet" | "main" => NetworkType::Mainnet,
                "testnet" | "test" => NetworkType::Testnet,
                "regtest" | "reg" => NetworkType::Regtest,
                _ => self.network,
            };
        }

        // Data directory
        if let Ok(dir) = env::var("CYNC_DATA_DIR") {
            self.data_dir = PathBuf::from(dir);
        }

        // P2P settings
        if let Ok(port) = env::var("CYNC_P2P_PORT") {
            if let Ok(p) = port.parse() {
                self.p2p.port = p;
            }
        }
        if let Ok(max) = env::var("CYNC_MAX_PEERS") {
            if let Ok(m) = max.parse() {
                self.p2p.max_peers = m;
            }
        }
        if let Ok(addr) = env::var("CYNC_P2P_LISTEN") {
            self.p2p.listen_addr = addr;
        }

        // RPC settings
        if let Ok(port) = env::var("CYNC_RPC_PORT") {
            if let Ok(p) = port.parse() {
                self.rpc.port = p;
            }
        }
        if let Ok(enabled) = env::var("CYNC_RPC_ENABLED") {
            self.rpc.enabled = enabled.parse().unwrap_or(true);
        }
        if let Ok(addr) = env::var("CYNC_RPC_LISTEN") {
            self.rpc.listen_addr = addr;
        }

        // Mining settings
        if let Ok(enabled) = env::var("CYNC_MINING_ENABLED") {
            self.mining.enabled = enabled.parse().unwrap_or(false);
        }
        if let Ok(threads) = env::var("CYNC_MINING_THREADS") {
            if let Ok(t) = threads.parse() {
                self.mining.threads = t;
            }
        }
        if let Ok(addr) = env::var("CYNC_MINER_ADDRESS") {
            self.mining.miner_address = Some(addr);
        }

        // Logging
        if let Ok(level) = env::var("CYNC_LOG_LEVEL") {
            self.log_level = level;
        }

        // Proxy settings (for Tor/I2P - user-installed)
        if let Ok(enabled) = env::var("CYNC_PROXY_ENABLED") {
            if enabled.parse().unwrap_or(false) {
                let proxy = self.p2p.proxy.get_or_insert(ProxyConfig::default());
                proxy.enabled = true;
            }
        }
        if let Ok(addr) = env::var("CYNC_PROXY_ADDRESS") {
            let proxy = self.p2p.proxy.get_or_insert(ProxyConfig::default());
            proxy.address = addr;
        }
        if let Ok(port) = env::var("CYNC_PROXY_PORT") {
            if let Ok(p) = port.parse() {
                let proxy = self.p2p.proxy.get_or_insert(ProxyConfig::default());
                proxy.port = p;
            }
        }
        if let Ok(onion) = env::var("CYNC_PROXY_ONION_ONLY") {
            if onion.parse().unwrap_or(false) {
                let proxy = self.p2p.proxy.get_or_insert(ProxyConfig::default());
                proxy.onion_only = true;
            }
        }

        // P2P encryption settings
        if let Ok(required) = env::var("CYNC_P2P_ENCRYPTION_REQUIRED") {
            self.p2p.encryption.required = required.parse().unwrap_or(false);
        }
        if let Ok(preferred) = env::var("CYNC_P2P_ENCRYPTION_PREFERRED") {
            self.p2p.encryption.preferred = preferred.parse().unwrap_or(true);
        }

        // RPC TLS settings
        if let Ok(enabled) = env::var("CYNC_RPC_TLS_ENABLED") {
            self.rpc.tls_enabled = enabled.parse().unwrap_or(true);
        }
        if let Ok(cert) = env::var("CYNC_RPC_TLS_CERT") {
            self.rpc.tls_cert_path = Some(cert);
        }
        if let Ok(key) = env::var("CYNC_RPC_TLS_KEY") {
            self.rpc.tls_key_path = Some(key);
        }
    }

    /// Validate configuration
    pub fn validate(&self) -> crate::error::Result<()> {
        let mut errors = Vec::new();

        // Port validation
        if self.p2p.port == 0 {
            errors.push("P2P port cannot be 0".to_string());
        }
        if self.rpc.port == 0 {
            errors.push("RPC port cannot be 0".to_string());
        }
        if self.p2p.port == self.rpc.port {
            errors.push(format!(
                "P2P port ({}) and RPC port ({}) cannot be the same",
                self.p2p.port, self.rpc.port
            ));
        }

        // Peer count validation
        if self.p2p.max_peers == 0 {
            errors.push("max_peers must be at least 1".to_string());
        }
        if self.p2p.max_peers > 1000 {
            errors.push("max_peers cannot exceed 1000".to_string());
        }

        // Mining validation
        if self.mining.enabled {
            if self.mining.threads == 0 {
                errors.push("mining threads must be at least 1 when mining is enabled".to_string());
            }
            if self.mining.miner_address.is_none() && self.mining.pool_url.is_none() {
                errors.push("miner_address or pool_url required when mining is enabled".to_string());
            }
        }

        // Database validation
        if self.database.cache_size_mb == 0 {
            errors.push("database cache_size_mb must be at least 1".to_string());
        }

        // SECURITY (H-22): Warn about plaintext RPC credentials and non-localhost exposure
        if self.rpc.enabled {
            if self.rpc.password.is_some() {
                tracing::warn!(
                    "RPC password is stored in plaintext in config file. \
                     Consider using environment-based credential injection for production."
                );
            }
            if self.rpc.listen_addr != "127.0.0.1" && self.rpc.listen_addr != "::1" {
                if !self.rpc.auth_required {
                    tracing::warn!(
                        "RPC is listening on {} without authentication! \
                         Set auth_required=true and configure credentials for non-localhost RPC.",
                        self.rpc.listen_addr
                    );
                }
            }
        }

        if errors.is_empty() {
            Ok(())
        } else {
            Err(crate::error::Error::ConfigError(
                format!("Configuration validation failed:\n  - {}", errors.join("\n  - "))
            ))
        }
    }

    /// Create example config file with comments
    pub fn example_toml() -> String {
        r#"# CoinCync 2.0 Configuration
# https://git.coincync.network/coincync/cync-protocol

# Network: mainnet, testnet, or regtest
network = "mainnet"

# Data directory (default: ~/.coincync/<network>)
# data_dir = "/path/to/data"

# Logging level: error, warn, info, debug, trace
log_level = "info"

[p2p]
# P2P listen address
listen_addr = "0.0.0.0"
# P2P port (mainnet: 18080, testnet: 28080)
port = 18080
# Maximum peer connections
max_peers = 50
# Enable UPnP port forwarding
upnp = true
# Bootstrap nodes (optional, uses defaults if empty)
# bootstrap_nodes = ["seed1.coincync.network:19080", "seed2.coincync.network:19080"]

# SOCKS5 Proxy Configuration (for Tor, I2P, etc.)
# ================================================
# CoinCync does NOT bundle Tor. You must install and run it yourself.
#
# To use Tor:
#   1. Install Tor: https://www.torproject.org/
#   2. Start Tor service (SOCKS5 on port 9050 by default)
#   3. Uncomment and configure proxy settings below
#
# [p2p.proxy]
# enabled = true
# address = "127.0.0.1"
# port = 9050              # Tor default: 9050, Tor Browser: 9150
# proxy_type = "socks5"    # Options: socks5, socks4, http
# onion_only = false       # Set true to ONLY connect to .onion peers
# username = ""            # Optional SOCKS5 auth
# password = ""            # Optional SOCKS5 auth

[rpc]
# Enable JSON-RPC server
enabled = true
# RPC listen address (127.0.0.1 = local only, 0.0.0.0 = public)
listen_addr = "127.0.0.1"
# RPC port (mainnet: 18081, testnet: 28081)
port = 18081
# Require authentication
auth_required = false
# username = "user"
# password = "YOUR_STRONG_PASSWORD"
# CORS allowed origins
cors_origins = []

[database]
# Cache size in MB
cache_size_mb = 256
# Enable compression
compression = true
# Sync writes to disk immediately
sync_writes = true

[mining]
# Enable mining
enabled = false
# Number of mining threads (0 = auto-detect)
threads = 1
# Wallet address for mining rewards
# miner_address = "CYNC..."
# Pool URL for pool mining (optional)
# pool_url = "stratum+tcp://pool.example.com:3333"
"#.to_string()
    }
}

/// Get default config file path
pub fn default_config_path() -> PathBuf {
    dirs_next::config_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join("coincync")
        .join("config.toml")
}

/// Format TOML parsing error with line context
fn format_toml_error(err: &toml::de::Error, content: &str) -> String {
    let mut msg = format!("TOML parse error: {}", err);

    // Try to extract line number and show context
    if let Some(span) = err.span() {
        let lines: Vec<&str> = content.lines().collect();
        let mut char_count = 0;
        for (i, line) in lines.iter().enumerate() {
            if char_count + line.len() >= span.start {
                msg.push_str(&format!("\n  Line {}: {}", i + 1, line));
                msg.push_str(&format!("\n  {}", "^".repeat(line.len().min(20))));
                break;
            }
            char_count += line.len() + 1; // +1 for newline
        }
    }

    msg
}

/// Configuration validation error with context
#[derive(Debug)]
pub struct ConfigValidationError {
    pub field: String,
    pub message: String,
    pub suggestion: Option<String>,
}

impl std::fmt::Display for ConfigValidationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "'{}': {}", self.field, self.message)?;
        if let Some(ref suggestion) = self.suggestion {
            write!(f, " (hint: {})", suggestion)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = NodeConfig::default();
        assert_eq!(config.network, NetworkType::Mainnet);
        assert_eq!(config.p2p.port, DEFAULT_P2P_PORT);
        assert_eq!(config.rpc.port, DEFAULT_RPC_PORT);
    }

    #[test]
    fn test_testnet_config() {
        let config = NodeConfig::for_network(NetworkType::Testnet);
        assert_eq!(config.p2p.port, TESTNET_P2P_PORT);
        assert_eq!(config.rpc.port, TESTNET_RPC_PORT);
    }

    #[test]
    fn test_chain_params_are_network_specific() {
        let main = NetworkType::Mainnet.params();
        let test = NetworkType::Testnet.params();
        let reg = NetworkType::Regtest.params();

        assert_ne!(main.magic, test.magic);
        assert_ne!(main.magic, reg.magic);
        assert_ne!(test.magic, reg.magic);

        assert_eq!(main.p2p_port, DEFAULT_P2P_PORT);
        assert_eq!(test.p2p_port, TESTNET_P2P_PORT);
        assert_eq!(reg.p2p_port, REGTEST_P2P_PORT);
    }
}
