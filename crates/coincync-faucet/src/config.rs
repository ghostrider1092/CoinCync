//! Faucet configuration. Pulled from environment via clap; typically
//! loaded by the systemd unit from `/etc/coincync/faucet.env`.

use std::path::PathBuf;

use clap::Parser;

#[derive(Parser, Debug)]
#[command(version, about = "CoinCync testnet faucet HTTP service")]
pub struct Config {
    /// `host:port` to bind. Behind nginx, use `127.0.0.1:8082`.
    /// Public-facing direct binds should use `0.0.0.0:<port>`.
    #[arg(long, env = "FAUCET_LISTEN_ADDR", default_value = "127.0.0.1:8082")]
    pub listen_addr: String,

    /// SQLite database file for the drip log.
    #[arg(long, env = "FAUCET_DB_PATH", default_value = "/var/lib/coincync/faucet/drips.db")]
    pub db_path: PathBuf,

    /// Path to the hot-wallet file the faucet drips from.
    #[arg(long, env = "FAUCET_WALLET_PATH", default_value = "/var/lib/coincync/faucet/hot.wallet")]
    pub wallet_path: PathBuf,

    /// Hot-wallet password. Required. Loaded from systemd
    /// `EnvironmentFile=` (mode 600). Never logged.
    #[arg(long, env = "FAUCET_WALLET_PASSWORD")]
    pub wallet_password: String,

    /// Path to the `coincync-wallet` binary.
    #[arg(long, env = "FAUCET_WALLET_BIN", default_value = "/usr/local/bin/coincync-wallet")]
    pub wallet_bin: PathBuf,

    /// Node RPC URL the wallet hits to broadcast.
    #[arg(long, env = "FAUCET_NODE_RPC", default_value = "http://127.0.0.1:28081")]
    pub node_rpc: String,

    /// Network name passed to the wallet binary.
    #[arg(long, env = "FAUCET_NETWORK", default_value = "testnet")]
    pub network: String,

    /// Drip amount, in atomic units. Default: 10 tCYNC = 10 * 10^12 atomic.
    #[arg(long, env = "FAUCET_DRIP_AMOUNT_ATOMIC", default_value_t = 10_000_000_000_000u64)]
    pub drip_amount_atomic: u64,

    /// Per-address rate-limit window, in seconds.
    #[arg(long, env = "FAUCET_RATE_LIMIT_ADDRESS_SECS", default_value_t = 3600)]
    pub rate_limit_address_secs: i64,

    /// Per-IP rate-limit window, in seconds.
    #[arg(long, env = "FAUCET_RATE_LIMIT_IP_SECS", default_value_t = 1800)]
    pub rate_limit_ip_secs: i64,

    /// Comma-separated list of CORS origins to allow.
    #[arg(
        long,
        env = "FAUCET_CORS_ORIGINS",
        default_value = "https://coincync.network,https://www.coincync.network,https://coincync.org,https://www.coincync.org"
    )]
    pub cors_origins_csv: String,

    /// Wallet `send` subprocess timeout, in seconds.
    #[arg(long, env = "FAUCET_SEND_TIMEOUT_SECS", default_value_t = 60)]
    pub send_timeout_secs: u64,
}

impl Config {
    /// Verify the configured paths point at things that exist before
    /// the server starts taking requests. Better to fail loud at
    /// startup than to drop the first user's drip.
    pub fn validate_paths(&self) -> anyhow::Result<()> {
        // DB parent directory must be writable
        if let Some(parent) = self.db_path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        // Wallet file must exist (we don't auto-create — provisioning is
        // a deliberate operator step that includes funding)
        if !self.wallet_path.exists() {
            anyhow::bail!(
                "wallet file not found at {} — provision the hot wallet first",
                self.wallet_path.display()
            );
        }
        if !self.wallet_bin.exists() {
            anyhow::bail!(
                "coincync-wallet binary not found at {}",
                self.wallet_bin.display()
            );
        }
        Ok(())
    }

    /// Parse CORS origins into the form Axum's CorsLayer wants.
    pub fn cors_origins(&self) -> Vec<axum::http::HeaderValue> {
        self.cors_origins_csv
            .split(',')
            .map(|s| s.trim())
            .filter(|s| !s.is_empty())
            .filter_map(|s| s.parse().ok())
            .collect()
    }
}
