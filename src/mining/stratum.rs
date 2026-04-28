//! # Stratum Mining Protocol
//!
//! Implementation of the Stratum protocol for pool mining.
//! Allows miners to connect and submit shares.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader};
use tokio::net::TcpListener;
use tokio::sync::{broadcast, mpsc, RwLock};
use tokio_rustls::TlsAcceptor;
use tracing::{debug, error, info, warn};

use crate::chain::SharedBlockchain;
use crate::mempool::SharedMempool;
use crate::primitives::{Hash, PublicKey};
use crate::error::{Error, Result};

const MIN_SUBMIT_INTERVAL_MS: u64 = 200;
const MAX_INVALID_STREAK: u32 = 20;
const STRATUM_BAN_THRESHOLD: u32 = 20;
const STRATUM_BAN_DURATION_SECS: u64 = 3600;

fn env_bool(name: &str) -> bool {
    std::env::var(name)
        .ok()
        .map(|v| {
            let t = v.trim();
            t == "1" || t.eq_ignore_ascii_case("true") || t.eq_ignore_ascii_case("yes")
        })
        .unwrap_or(false)
}

#[derive(Clone, Debug, Default, serde::Serialize, serde::Deserialize)]
struct PersistedBanEntry {
    score: u32,
    banned_until: u64,
    last_seen: u64,
}

/// Default Stratum port
pub const DEFAULT_STRATUM_PORT: u16 = 3333;

/// Stratum server configuration
#[derive(Clone, Debug)]
pub struct StratumConfig {
    /// Bind address
    pub bind_addr: SocketAddr,
    /// Pool fee percentage (0-100)
    pub pool_fee: f64,
    /// Share difficulty
    pub share_difficulty: u64,
    /// Job timeout in seconds
    pub job_timeout: u64,
    /// Maximum connections
    pub max_connections: usize,
    /// Optional shared password checked in `mining.authorize` params[1].
    pub auth_password: Option<String>,
    /// Enable native TLS transport for miner connections.
    pub tls_enabled: bool,
    /// PEM certificate path for native TLS mode.
    pub tls_cert_path: Option<PathBuf>,
    /// PEM private key path for native TLS mode.
    pub tls_key_path: Option<PathBuf>,
}

impl Default for StratumConfig {
    fn default() -> Self {
        let public_bind = std::env::var("COINCYNC_STRATUM_PUBLIC_BIND")
            .ok()
            .map(|v| {
                let t = v.trim();
                t == "1" || t.eq_ignore_ascii_case("true") || t.eq_ignore_ascii_case("yes")
            })
            .unwrap_or(false);
        let bind_literal = if public_bind {
            "0.0.0.0:3333"
        } else {
            "127.0.0.1:3333"
        };
        StratumConfig {
            // Default loopback-only for safety; opt into public bind explicitly.
            // safe: literal address is always valid
            bind_addr: bind_literal.parse().expect("valid literal socket address"),
            pool_fee: 1.0,
            share_difficulty: 1000,
            job_timeout: 60,
            max_connections: 1000,
            auth_password: std::env::var("COINCYNC_STRATUM_PASSWORD")
                .ok()
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty()),
            tls_enabled: env_bool("COINCYNC_STRATUM_TLS_ENABLED"),
            tls_cert_path: std::env::var("COINCYNC_STRATUM_TLS_CERT_PATH")
                .ok()
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .map(PathBuf::from),
            tls_key_path: std::env::var("COINCYNC_STRATUM_TLS_KEY_PATH")
                .ok()
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .map(PathBuf::from),
        }
    }
}

fn validate_stratum_exposure_policy(config: &StratumConfig) -> Result<()> {
    let public_bind = !config.bind_addr.ip().is_loopback();
    if !public_bind {
        return Ok(());
    }
    if !env_bool("COINCYNC_STRATUM_PUBLIC_BIND_ACK") {
        return Err(Error::InvalidState(
            "Refusing public Stratum bind without explicit acknowledgement. \
             Set COINCYNC_STRATUM_PUBLIC_BIND_ACK=1 only behind TLS/reverse-proxy."
                .into(),
        ));
    }
    if config.auth_password.as_deref().map(str::is_empty).unwrap_or(true) {
        return Err(Error::InvalidState(
            "Refusing public Stratum bind without COINCYNC_STRATUM_PASSWORD. \
             Public Stratum must require worker authorization."
                .into(),
        ));
    }
    if !config.tls_enabled && !env_bool("COINCYNC_STRATUM_TLS_PROXY_ACK") {
        return Err(Error::InvalidState(
            "Refusing public Stratum bind without encrypted transport acknowledgement. \
             Either enable native TLS (COINCYNC_STRATUM_TLS_ENABLED=1) or set \
             COINCYNC_STRATUM_TLS_PROXY_ACK=1 when using a trusted TLS terminator."
                .into(),
        ));
    }
    Ok(())
}

fn build_stratum_tls_acceptor(config: &StratumConfig) -> Result<Option<TlsAcceptor>> {
    if !config.tls_enabled {
        return Ok(None);
    }

    let (cert_path, key_path) = match (&config.tls_cert_path, &config.tls_key_path) {
        (Some(c), Some(k)) => (c.clone(), k.clone()),
        _ => {
            // Native TLS convenience: auto-generate a self-signed cert when explicit files are not set.
            let data_dir = std::env::var("COINCYNC_STRATUM_TLS_DATA_DIR")
                .ok()
                .map(PathBuf::from)
                .unwrap_or_else(|| PathBuf::from(".coincync/stratum-tls"));
            crate::rpc::tls::generate_self_signed_cert(&data_dir, "coincync-stratum")?
        }
    };

    let tls_cfg = crate::rpc::tls::load_server_tls_config(&cert_path, &key_path, None)?;
    Ok(Some(TlsAcceptor::from(Arc::new(tls_cfg))))
}

/// Mining job sent to workers
#[derive(Clone, Debug)]
pub struct MiningJob {
    /// Unique job ID
    pub job_id: String,
    /// Previous block hash
    pub prev_hash: Hash,
    /// Coinbase transaction (part 1)
    pub coinbase1: Vec<u8>,
    /// Coinbase transaction (part 2)
    pub coinbase2: Vec<u8>,
    /// Merkle branches for coinbase
    pub merkle_branches: Vec<Hash>,
    /// Block version
    pub version: u32,
    /// Difficulty target (nbits)
    pub nbits: u32,
    /// Block timestamp
    pub ntime: u32,
    /// Whether to clean previous jobs
    pub clean_jobs: bool,
    /// Block height
    pub height: u64,
}

/// Share submitted by a worker
#[derive(Debug, Clone)]
pub struct Share {
    /// Worker name
    pub worker: String,
    /// Job ID
    pub job_id: String,
    /// Extranonce2
    pub extranonce2: Vec<u8>,
    /// Ntime
    pub ntime: u32,
    /// Nonce
    pub nonce: u32,
}

/// Result of share verification
#[derive(Debug)]
pub enum ShareResult {
    /// Share is valid (meets share difficulty)
    Valid,
    /// Share is valid and also meets block difficulty
    Block(Hash),
    /// Share is stale (job not found)
    Stale,
    /// Share is invalid (doesn't meet difficulty)
    Invalid,
    /// Duplicate share
    Duplicate,
}

impl Share {
    /// Verify a share meets the target difficulty
    ///
    /// Returns ShareResult indicating if the share is valid and potentially a block.
    pub fn verify(&self, job: &MiningJob, share_difficulty: u64, extranonce1: &[u8]) -> ShareResult {
        use crate::consensus::{compute_pow_hash, PowAlgorithm};
        use sha3::{Sha3_256, Digest};

        // Build the coinbase transaction
        let mut coinbase = Vec::new();
        coinbase.extend_from_slice(&job.coinbase1);
        coinbase.extend_from_slice(extranonce1);
        coinbase.extend_from_slice(&self.extranonce2);
        coinbase.extend_from_slice(&job.coinbase2);

        // Hash the coinbase to get coinbase hash
        let coinbase_hash = Sha3_256::digest(&coinbase);

        // Build merkle root from coinbase + branches
        let mut merkle = Hash::from_bytes({
            let mut bytes = [0u8; 32];
            bytes.copy_from_slice(&coinbase_hash);
            bytes
        });

        for branch in &job.merkle_branches {
            let mut hasher = Sha3_256::new();
            hasher.update(merkle.as_bytes());
            hasher.update(branch.as_bytes());
            let result = hasher.finalize();
            let mut bytes = [0u8; 32];
            bytes.copy_from_slice(&result);
            merkle = Hash::from_bytes(bytes);
        }

        // Compute PoW hash using the standard algorithm
        // anchor = prev_hash, nonce from share, tx_root = merkle
        let pow_hash = match compute_pow_hash(
            PowAlgorithm::RandomX,
            &job.prev_hash,
            self.nonce as u64,
            &merkle,
            job.height,
        ) {
            Ok(h) => h,
            Err(_) => return ShareResult::Invalid,
        };

        // Compare against full share target hash (not leading-zero approximation).
        let share_target = Hash::from_difficulty(share_difficulty);
        if !pow_hash.meets_difficulty(&share_target) {
            return ShareResult::Invalid;
        }

        // Check if hash also meets block target encoded in compact nbits.
        let block_target = nbits_to_target(job.nbits);
        if pow_hash.meets_difficulty(&block_target) {
            return ShareResult::Block(pow_hash);
        }

        ShareResult::Valid
    }
}

/// Convert compact `nbits` into a full 256-bit target (big-endian).
fn nbits_to_target(nbits: u32) -> Hash {
    let exponent = ((nbits >> 24) & 0xff) as usize;
    let mantissa = nbits & 0x007f_ffff;
    let mut bytes = [0u8; 32];

    // Negative/zero compact encodings are invalid => impossible-hard target.
    if exponent == 0 || (nbits & 0x0080_0000) != 0 {
        return Hash::from_bytes(bytes);
    }

    if exponent <= 3 {
        let value = mantissa >> (8 * (3 - exponent));
        let be = value.to_be_bytes();
        bytes[29] = be[1];
        bytes[30] = be[2];
        bytes[31] = be[3];
    } else {
        let offset = exponent - 3;
        if offset > 29 {
            // Over-wide compact target: clamp to easiest target.
            return Hash::from_bytes([0xff; 32]);
        }
        let i = 32 - (offset + 3);
        bytes[i] = ((mantissa >> 16) & 0xff) as u8;
        bytes[i + 1] = ((mantissa >> 8) & 0xff) as u8;
        bytes[i + 2] = (mantissa & 0xff) as u8;
    }

    Hash::from_bytes(bytes)
}

/// Worker connection state
#[allow(dead_code)]
struct Worker {
    /// Worker name
    name: String,
    /// Worker address (for payout)
    address: Option<PublicKey>,
    /// Extranonce1 assigned to this worker
    extranonce1: Vec<u8>,
    /// Shares submitted
    shares: u64,
    /// Valid shares
    valid_shares: u64,
    /// Stale shares
    stale_shares: u64,
    /// Invalid shares
    invalid_shares: u64,
    /// Difficulty
    difficulty: u64,
    /// Set true after successful `mining.authorize`.
    authorized: bool,
    /// Timestamp (ms) of last submit attempt.
    last_submit_ms: u64,
    /// Consecutive invalid/stale/duplicate submits.
    invalid_streak: u32,
    /// Last activity timestamp
    last_activity: u64,
    /// Message sender
    tx: mpsc::Sender<String>,
}

/// Stratum server statistics
#[derive(Clone, Debug, Default)]
pub struct StratumStats {
    pub connected_workers: usize,
    pub total_shares: u64,
    pub valid_shares: u64,
    pub stale_shares: u64,
    pub invalid_shares: u64,
    pub blocks_found: u64,
    pub hashrate: f64,
}

/// Stratum server
pub struct StratumServer {
    config: StratumConfig,
    chain: SharedBlockchain,
    mempool: SharedMempool,
    workers: Arc<RwLock<HashMap<u64, Worker>>>,
    next_worker_id: Arc<AtomicU64>,
    next_job_id: Arc<AtomicU64>,
    extranonce_counter: Arc<AtomicU64>,
    current_job: Arc<RwLock<Option<MiningJob>>>,
    job_broadcast: broadcast::Sender<MiningJob>,
    stats: Arc<RwLock<StratumStats>>,
    running: Arc<std::sync::atomic::AtomicBool>,
    bans: Arc<RwLock<HashMap<String, PersistedBanEntry>>>,
    banlist_path: Option<PathBuf>,
}

impl StratumServer {
    /// Create a new Stratum server
    pub fn new(
        config: StratumConfig,
        chain: SharedBlockchain,
        mempool: SharedMempool,
    ) -> Self {
        let (job_broadcast, _) = broadcast::channel(16);
        let banlist_path = std::env::var("COINCYNC_STRATUM_BANLIST_PATH")
            .ok()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .map(PathBuf::from)
            .or_else(|| Some(PathBuf::from("stratum_bans.json")));
        let bans = banlist_path
            .as_ref()
            .map(load_banlist)
            .unwrap_or_default();

        StratumServer {
            config,
            chain,
            mempool,
            workers: Arc::new(RwLock::new(HashMap::new())),
            next_worker_id: Arc::new(AtomicU64::new(1)),
            next_job_id: Arc::new(AtomicU64::new(1)),
            extranonce_counter: Arc::new(AtomicU64::new(1)),
            current_job: Arc::new(RwLock::new(None)),
            job_broadcast,
            stats: Arc::new(RwLock::new(StratumStats::default())),
            running: Arc::new(std::sync::atomic::AtomicBool::new(false)),
            bans: Arc::new(RwLock::new(bans)),
            banlist_path,
        }
    }

    /// Start the Stratum server
    pub async fn start(&self) -> Result<()> {
        if self.running.load(Ordering::SeqCst) {
            return Ok(());
        }
        validate_stratum_exposure_policy(&self.config)?;
        let tls_acceptor = build_stratum_tls_acceptor(&self.config)?;

        let listener = TcpListener::bind(&self.config.bind_addr)
            .await
            .map_err(|e| Error::ConnectionFailed(e.to_string()))?;

        self.running.store(true, Ordering::SeqCst);
        info!(
            "Stratum server listening on {} (native_tls={})",
            self.config.bind_addr,
            tls_acceptor.is_some()
        );

        // Spawn job update task
        self.spawn_job_updater();

        // Accept connections
        while self.running.load(Ordering::SeqCst) {
            match listener.accept().await {
                Ok((stream, addr)) => {
                    let ip = addr.ip().to_string();
                    {
                        let bans = self.bans.read().await;
                        if let Some(entry) = bans.get(&ip) {
                            let now = timestamp_now();
                            if entry.banned_until > now {
                                warn!(
                                    "Rejecting banned Stratum client {} (until {})",
                                    ip, entry.banned_until
                                );
                                continue;
                            }
                        }
                    }
                    let worker_count = self.workers.read().await.len();
                    if worker_count >= self.config.max_connections {
                        warn!("Max connections reached, rejecting {}", addr);
                        continue;
                    }

                    debug!("New miner connection from {}", addr);
                    if let Some(acceptor) = tls_acceptor.clone() {
                        match acceptor.accept(stream).await {
                            Ok(tls_stream) => self.spawn_worker_handler(tls_stream, addr),
                            Err(e) => warn!("TLS handshake failed from {}: {}", addr, e),
                        }
                    } else {
                        self.spawn_worker_handler(stream, addr);
                    }
                }
                Err(e) => {
                    error!("Accept error: {}", e);
                }
            }
        }

        Ok(())
    }

    /// Stop the Stratum server
    pub fn stop(&self) {
        self.running.store(false, Ordering::SeqCst);
        info!("Stratum server stopped");
    }

    /// Get server statistics
    pub async fn stats(&self) -> StratumStats {
        let mut stats = self.stats.read().await.clone();
        stats.connected_workers = self.workers.read().await.len();
        stats
    }

    /// Spawn job update task
    fn spawn_job_updater(&self) {
        let chain = self.chain.clone();
        let mempool = self.mempool.clone();
        let current_job = self.current_job.clone();
        let job_broadcast = self.job_broadcast.clone();
        let next_job_id = self.next_job_id.clone();
        let running = self.running.clone();
        let share_difficulty = self.config.share_difficulty;

        tokio::spawn(async move {
            let mut last_tip = Hash::zero();

            while running.load(Ordering::SeqCst) {
                let tip = chain.tip_hash();

                // Check if we need a new job
                if tip != last_tip {
                    last_tip = tip;

                    // Create new job
                    let job_id = next_job_id.fetch_add(1, Ordering::SeqCst);
                    let height = chain.height() + 1;
                    let timestamp = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .map(|d| d.as_secs() as u32)
                        .unwrap_or(0);

                    let job = MiningJob {
                        job_id: format!("{:08x}", job_id),
                        prev_hash: tip,
                        coinbase1: create_coinbase_prefix(height),
                        coinbase2: create_coinbase_suffix(),
                        merkle_branches: compute_merkle_branches(&mempool),
                        version: 1,
                        nbits: difficulty_to_nbits(share_difficulty),
                        ntime: timestamp,
                        clean_jobs: true,
                        height,
                    };

                    // Update current job
                    *current_job.write().await = Some(job.clone());

                    // Broadcast to all workers
                    let _ = job_broadcast.send(job);

                    info!("New mining job: height={}", height);
                }

                tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
            }
        });
    }

    /// Spawn worker handler task
    fn spawn_worker_handler<S>(&self, stream: S, addr: SocketAddr)
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        let worker_id = self.next_worker_id.fetch_add(1, Ordering::SeqCst);
        let extranonce1 = self.extranonce_counter.fetch_add(1, Ordering::SeqCst);
        let workers = self.workers.clone();
        let current_job = self.current_job.clone();
        let mut job_rx = self.job_broadcast.subscribe();
        let stats = self.stats.clone();
        let chain = self.chain.clone();
        let share_difficulty = self.config.share_difficulty;
        let required_password = self.config.auth_password.clone();
        let bans = self.bans.clone();
        let banlist_path = self.banlist_path.clone();
        let running = self.running.clone();

        tokio::spawn(async move {
            let (reader, mut writer) = tokio::io::split(stream);
            let mut reader = BufReader::new(reader);
            let (tx, mut rx) = mpsc::channel::<String>(32);

            // Create worker entry
            let worker = Worker {
                name: format!("worker_{}", worker_id),
                address: None,
                extranonce1: extranonce1.to_le_bytes()[..4].to_vec(),
                shares: 0,
                valid_shares: 0,
                stale_shares: 0,
                invalid_shares: 0,
                difficulty: share_difficulty,
                authorized: false,
                last_submit_ms: 0,
                invalid_streak: 0,
                last_activity: timestamp_now(),
                tx: tx.clone(),
            };

            workers.write().await.insert(worker_id, worker);
            info!("Worker {} connected from {}", worker_id, addr);

            // Spawn writer task
            let write_running = running.clone();
            tokio::spawn(async move {
                while write_running.load(Ordering::SeqCst) {
                    tokio::select! {
                        Some(msg) = rx.recv() => {
                            if writer.write_all(msg.as_bytes()).await.is_err() {
                                break;
                            }
                            if writer.write_all(b"\n").await.is_err() {
                                break;
                            }
                            let _ = writer.flush().await;
                        }
                        job = job_rx.recv() => {
                            if let Ok(job) = job {
                                let notify = format_mining_notify(&job);
                                if writer.write_all(notify.as_bytes()).await.is_err() {
                                    break;
                                }
                                if writer.write_all(b"\n").await.is_err() {
                                    break;
                                }
                                let _ = writer.flush().await;
                            }
                        }
                    }
                }
            });

            // SECURITY: Maximum line length to prevent memory exhaustion.
            // BufReader::read_line reads into a String until \n, so a malicious
            // client sending GB of data without \n would exhaust memory. We cap
            // the BufReader's internal buffer to MAX_LINE_LENGTH so it cannot
            // buffer more than that before returning an error or partial read.
            const MAX_LINE_LENGTH: usize = 16 * 1024;

            // Read and handle messages
            let mut line = String::with_capacity(256);
            loop {
                line.clear();
                // Read up to MAX_LINE_LENGTH bytes to find a newline
                let mut limited = (&mut reader).take(MAX_LINE_LENGTH as u64);
                match limited.read_line(&mut line).await {
                    Ok(0) => break, // Connection closed
                    Ok(_) if !line.ends_with('\n') => {
                        // Line exceeded MAX_LINE_LENGTH without a newline
                        warn!("Worker {} sent oversized message (>{} bytes), disconnecting", worker_id, MAX_LINE_LENGTH);
                        break;
                    }
                    Ok(_) => {
                        if let Some(response) = handle_stratum_message(
                            &line,
                            worker_id,
                            &workers,
                            &current_job,
                            &stats,
                            &chain,
                            share_difficulty,
                            required_password.as_deref(),
                            &addr.ip().to_string(),
                            &bans,
                            banlist_path.as_ref(),
                        ).await {
                            let _ = tx.send(response).await;
                        }
                    }
                    Err(_) => break,
                }
            }

            // Cleanup
            workers.write().await.remove(&worker_id);
            info!("Worker {} disconnected", worker_id);
        });
    }
}

/// Handle a Stratum JSON-RPC message
async fn handle_stratum_message(
    message: &str,
    worker_id: u64,
    workers: &Arc<RwLock<HashMap<u64, Worker>>>,
    current_job: &Arc<RwLock<Option<MiningJob>>>,
    stats: &Arc<RwLock<StratumStats>>,
    _chain: &SharedBlockchain,
    share_difficulty: u64,
    required_password: Option<&str>,
    client_ip: &str,
    bans: &Arc<RwLock<HashMap<String, PersistedBanEntry>>>,
    banlist_path: Option<&PathBuf>,
) -> Option<String> {
    let json: serde_json::Value = serde_json::from_str(message.trim()).ok()?;

    let id = json.get("id")?;
    let method = json.get("method")?.as_str()?;
    let params = json.get("params")?;

    match method {
        "mining.subscribe" => {
            let workers = workers.read().await;
            let worker = workers.get(&worker_id)?;
            let extranonce1 = hex::encode(&worker.extranonce1);

            // Send subscription response
            Some(format!(
                r#"{{"id":{},"result":[[["mining.notify","{}"],["mining.set_difficulty","{}"]],"{}",4],"error":null}}"#,
                id,
                format!("{:08x}", worker_id),
                format!("{:08x}", worker_id),
                extranonce1
            ))
        }

        "mining.authorize" => {
            let worker_name = params.get(0)?.as_str()?;
            let supplied_password = params.get(1).and_then(|v| v.as_str()).unwrap_or("");

            if let Some(expected_password) = required_password {
                if supplied_password.len() != expected_password.len()
                    || !crate::crypto::ct_eq(
                        supplied_password.as_bytes(),
                        expected_password.as_bytes(),
                    )
                {
                    warn!("Worker {} failed authorization", worker_id);
                    register_stratum_strike(bans, banlist_path, client_ip, 5).await;
                    return Some(format!(
                        r#"{{"id":{},"result":false,"error":[24,"Unauthorized",null]}}"#,
                        id
                    ));
                }
            }

            // Update worker name
            {
                let mut workers = workers.write().await;
                if let Some(worker) = workers.get_mut(&worker_id) {
                    worker.name = worker_name.to_string();
                    worker.authorized = true;
                    worker.last_activity = timestamp_now();
                }
            }

            info!("Worker {} authorized as {}", worker_id, worker_name);

            // Send auth success and current job
            let job = current_job.read().await;
            let mut response = format!(r#"{{"id":{},"result":true,"error":null}}"#, id);

            // Send set_difficulty
            response.push('\n');
            response.push_str(&format!(
                r#"{{"id":null,"method":"mining.set_difficulty","params":[{}]}}"#,
                share_difficulty
            ));

            // Send current job if available
            if let Some(job) = job.as_ref() {
                response.push('\n');
                response.push_str(&format_mining_notify(job));
            }

            Some(response)
        }

        "mining.submit" => {
            // params: [worker_name, job_id, extranonce2, ntime, nonce]
            let worker_name = params.get(0)?.as_str()?;
            let job_id = params.get(1)?.as_str()?;
            let extranonce2_hex = params.get(2)?.as_str()?;
            let ntime_hex = params.get(3)?.as_str()?;
            let nonce_hex = params.get(4)?.as_str()?;

            // Enforce authorization before accepting shares.
            {
                let workers_read = workers.read().await;
                if !workers_read.get(&worker_id).map(|w| w.authorized).unwrap_or(false) {
                    return Some(format!(
                        r#"{{"id":{},"result":false,"error":[24,"Not authorized",null]}}"#,
                        id
                    ));
                }
            }

            // Basic anti-spam throttle on submit cadence.
            let mut throttled = false;
            {
                let now_ms = timestamp_now_ms();
                let mut workers_write = workers.write().await;
                if let Some(worker) = workers_write.get_mut(&worker_id) {
                    if worker.last_submit_ms > 0
                        && now_ms.saturating_sub(worker.last_submit_ms) < MIN_SUBMIT_INTERVAL_MS
                    {
                        worker.invalid_streak = worker.invalid_streak.saturating_add(1);
                        if worker.invalid_streak >= MAX_INVALID_STREAK {
                            worker.authorized = false;
                            warn!("Worker {} hit submit-rate abuse threshold; deauthorizing", worker_id);
                        }
                        throttled = true;
                    } else {
                        worker.last_submit_ms = now_ms;
                    }
                }
            }
            if throttled {
                register_stratum_strike(bans, banlist_path, client_ip, 3).await;
                return Some(format!(
                    r#"{{"id":{},"result":false,"error":[20,"Throttled submit rate",null]}}"#,
                    id
                ));
            }

            // Parse share data
            let extranonce2 = match hex::decode(extranonce2_hex) {
                Ok(v) => v,
                Err(_) => {
                    return Some(format!(
                        r#"{{"id":{},"result":false,"error":[20,"Invalid extranonce2",null]}}"#,
                        id
                    ));
                }
            };
            let ntime = match u32::from_str_radix(ntime_hex, 16) {
                Ok(v) => v,
                Err(_) => {
                    return Some(format!(
                        r#"{{"id":{},"result":false,"error":[20,"Invalid ntime",null]}}"#,
                        id
                    ));
                }
            };
            let nonce = match u32::from_str_radix(nonce_hex, 16) {
                Ok(v) => v,
                Err(_) => {
                    return Some(format!(
                        r#"{{"id":{},"result":false,"error":[20,"Invalid nonce",null]}}"#,
                        id
                    ));
                }
            };

            // Get worker's extranonce1
            let extranonce1 = {
                let workers_read = workers.read().await;
                workers_read.get(&worker_id)
                    .map(|w| w.extranonce1.clone())
                    .unwrap_or_default()
            };

            // Build share struct
            let share = Share {
                worker: worker_name.to_string(),
                job_id: job_id.to_string(),
                extranonce2,
                ntime,
                nonce,
            };

            // Verify share against current job
            let current = current_job.read().await;
            let share_result = if let Some(job) = current.as_ref() {
                if job.job_id != job_id {
                    ShareResult::Stale
                } else {
                    share.verify(job, share_difficulty, &extranonce1)
                }
            } else {
                ShareResult::Stale
            };

            // Update stats based on result
            let mut should_strike_for_invalid_streak = false;
            {
                let mut workers = workers.write().await;
                if let Some(worker) = workers.get_mut(&worker_id) {
                    worker.shares += 1;
                    worker.last_activity = timestamp_now();
                    match &share_result {
                        ShareResult::Valid | ShareResult::Block(_) => {
                            worker.valid_shares += 1;
                            worker.invalid_streak = 0;
                        }
                        ShareResult::Stale => {
                            worker.stale_shares += 1;
                            worker.invalid_streak = worker.invalid_streak.saturating_add(1);
                        }
                        ShareResult::Invalid | ShareResult::Duplicate => {
                            worker.invalid_shares += 1;
                            worker.invalid_streak = worker.invalid_streak.saturating_add(1);
                        }
                    }
                    if worker.invalid_streak >= MAX_INVALID_STREAK {
                        worker.authorized = false;
                        warn!(
                            "Worker {} exceeded invalid share streak {}; deauthorizing",
                            worker_id, worker.invalid_streak
                        );
                        should_strike_for_invalid_streak = true;
                    }
                }
            }
            if should_strike_for_invalid_streak {
                register_stratum_strike(bans, banlist_path, client_ip, 10).await;
            }

            {
                let mut s = stats.write().await;
                s.total_shares += 1;
                match &share_result {
                    ShareResult::Valid => s.valid_shares += 1,
                    ShareResult::Block(hash) => {
                        s.valid_shares += 1;
                        s.blocks_found += 1;
                        info!("BLOCK FOUND by worker {}! Hash: {}", worker_id, hex::encode(hash.as_bytes()));
                    }
                    ShareResult::Stale => s.stale_shares += 1,
                    ShareResult::Invalid | ShareResult::Duplicate => s.invalid_shares += 1,
                }
            }

            debug!(
                "Share from worker {}: job={} nonce={:08x} result={:?}",
                worker_id, job_id, nonce, share_result
            );

            match share_result {
                ShareResult::Valid | ShareResult::Block(_) => {
                    Some(format!(r#"{{"id":{},"result":true,"error":null}}"#, id))
                }
                ShareResult::Stale => {
                    Some(format!(
                        r#"{{"id":{},"result":false,"error":[21,"Stale share",null]}}"#,
                        id
                    ))
                }
                ShareResult::Invalid => {
                    Some(format!(
                        r#"{{"id":{},"result":false,"error":[23,"Low difficulty share",null]}}"#,
                        id
                    ))
                }
                ShareResult::Duplicate => {
                    Some(format!(
                        r#"{{"id":{},"result":false,"error":[22,"Duplicate share",null]}}"#,
                        id
                    ))
                }
            }
        }

        "mining.extranonce.subscribe" => {
            Some(format!(r#"{{"id":{},"result":true,"error":null}}"#, id))
        }

        _ => {
            warn!("Unknown stratum method: {}", method);
            Some(format!(
                r#"{{"id":{},"result":null,"error":[20,"Unknown method",null]}}"#,
                id
            ))
        }
    }
}

/// Format mining.notify message
fn format_mining_notify(job: &MiningJob) -> String {
    let merkle: Vec<String> = job.merkle_branches.iter()
        .map(|h| hex::encode(h.as_bytes()))
        .collect();

    format!(
        r#"{{"id":null,"method":"mining.notify","params":["{}","{}","{}","{}",{},"{:08x}","{:08x}","{:08x}",{}]}}"#,
        job.job_id,
        hex::encode(job.prev_hash.as_bytes()),
        hex::encode(&job.coinbase1),
        hex::encode(&job.coinbase2),
        serde_json::to_string(&merkle).unwrap_or_else(|_| "[]".to_string()),
        job.version,
        job.nbits,
        job.ntime,
        job.clean_jobs
    )
}

/// Create coinbase transaction prefix
fn create_coinbase_prefix(height: u64) -> Vec<u8> {
    let mut prefix = Vec::new();
    // Version
    prefix.extend_from_slice(&1u32.to_le_bytes());
    // Input count
    prefix.push(1);
    // Previous output (null for coinbase)
    prefix.extend_from_slice(&[0u8; 32]);
    prefix.extend_from_slice(&0xFFFFFFFFu32.to_le_bytes());
    // Script length placeholder (will include height + extranonce)
    prefix.push(8 + 4); // height (8) + extranonce1 (4)
    // Height in script (BIP34)
    prefix.push(8);
    prefix.extend_from_slice(&height.to_le_bytes());
    prefix
}

/// Create coinbase transaction suffix
fn create_coinbase_suffix() -> Vec<u8> {
    let mut suffix = Vec::new();
    // Sequence
    suffix.extend_from_slice(&0xFFFFFFFFu32.to_le_bytes());
    // Output count
    suffix.push(1);
    // Output value (placeholder - actual reward calculated by pool)
    suffix.extend_from_slice(&0u64.to_le_bytes());
    // Output script length
    suffix.push(0);
    // Lock time
    suffix.extend_from_slice(&0u32.to_le_bytes());
    suffix
}

/// Compute merkle branches from mempool transactions
fn compute_merkle_branches(mempool: &SharedMempool) -> Vec<Hash> {
    let txs = mempool.get_all();
    if txs.is_empty() {
        return Vec::new();
    }

    // Get transaction hashes
    let hashes: Vec<Hash> = txs.iter().map(|tx| tx.hash()).collect();

    // Compute merkle branches (path from coinbase to root)
    let mut branches = Vec::new();
    let mut level = hashes;

    while level.len() > 1 {
        // First hash is coinbase, take second
        if level.len() >= 2 {
            branches.push(level[1]);
        }

        // Compute next level
        let mut next_level = Vec::new();
        for chunk in level.chunks(2) {
            let combined = if chunk.len() == 2 {
                crate::primitives::hash_concat(&[
                    chunk[0].as_bytes(),
                    chunk[1].as_bytes(),
                ])
            } else {
                crate::primitives::hash_concat(&[
                    chunk[0].as_bytes(),
                    chunk[0].as_bytes(),
                ])
            };
            next_level.push(combined);
        }
        level = next_level;
    }

    branches
}

/// Convert difficulty to compact nbits format
fn difficulty_to_nbits(difficulty: u64) -> u32 {
    if difficulty == 0 {
        return 0x1d00ffff; // Bitcoin's initial difficulty
    }

    // Calculate target from difficulty
    // target = max_target / difficulty
    let leading_zeros = (64 - difficulty.leading_zeros()) / 8;
    let exponent = (32 - leading_zeros) as u8;
    // SECURITY (A6-SHIFT): Guard against shift >= 24 on the mantissa mask,
    // which causes UB/panic for difficulty >= 2^32.
    let shift_amount = leading_zeros * 8;
    let mantissa = if shift_amount >= 24 { 0u32 } else { 0xFFFFFF >> shift_amount };

    ((exponent as u32) << 24) | mantissa
}

/// Get current timestamp
fn timestamp_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn timestamp_now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

fn load_banlist(path: &PathBuf) -> HashMap<String, PersistedBanEntry> {
    match std::fs::read_to_string(path) {
        Ok(raw) => serde_json::from_str::<HashMap<String, PersistedBanEntry>>(&raw)
            .unwrap_or_else(|e| {
                warn!("Failed to parse Stratum banlist {}: {}", path.display(), e);
                HashMap::new()
            }),
        Err(_) => HashMap::new(),
    }
}

fn persist_banlist(path: &PathBuf, bans: &HashMap<String, PersistedBanEntry>) {
    if let Ok(raw) = serde_json::to_string_pretty(bans) {
        if let Err(e) = std::fs::write(path, raw) {
            warn!("Failed to persist Stratum banlist {}: {}", path.display(), e);
        }
    }
}

async fn register_stratum_strike(
    bans: &Arc<RwLock<HashMap<String, PersistedBanEntry>>>,
    banlist_path: Option<&PathBuf>,
    client_ip: &str,
    severity: u32,
) {
    let now = timestamp_now();
    let mut guard = bans.write().await;
    let entry = guard.entry(client_ip.to_string()).or_default();
    entry.last_seen = now;
    entry.score = entry.score.saturating_add(severity);
    if entry.score >= STRATUM_BAN_THRESHOLD {
        entry.banned_until = now.saturating_add(STRATUM_BAN_DURATION_SECS);
        entry.score = STRATUM_BAN_THRESHOLD;
        warn!(
            "Stratum client {} banned until {} (score={})",
            client_ip, entry.banned_until, entry.score
        );
    }
    if let Some(path) = banlist_path {
        persist_banlist(path, &guard);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use std::sync::{Mutex, OnceLock};

    fn env_lock() -> &'static Mutex<()> {
        static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        LOCK.get_or_init(|| Mutex::new(()))
    }

    #[test]
    fn test_stratum_config_default() {
        let config = StratumConfig::default();
        assert_eq!(config.bind_addr.port(), 3333);
        assert_eq!(config.pool_fee, 1.0);
    }

    #[test]
    fn test_public_bind_policy_requires_encrypted_transport_ack_or_native_tls() {
        let _guard = env_lock().lock().expect("env lock");
        std::env::set_var("COINCYNC_STRATUM_PUBLIC_BIND_ACK", "1");
        std::env::remove_var("COINCYNC_STRATUM_TLS_PROXY_ACK");
        let mut cfg = StratumConfig::default();
        cfg.bind_addr = "0.0.0.0:3333".parse().expect("socket");
        cfg.auth_password = Some("pw".to_string());
        cfg.tls_enabled = false;
        assert!(validate_stratum_exposure_policy(&cfg).is_err());

        cfg.tls_enabled = true;
        assert!(validate_stratum_exposure_policy(&cfg).is_ok());
        std::env::remove_var("COINCYNC_STRATUM_PUBLIC_BIND_ACK");
    }

    #[test]
    fn test_public_bind_policy_accepts_tls_proxy_ack() {
        let _guard = env_lock().lock().expect("env lock");
        std::env::set_var("COINCYNC_STRATUM_PUBLIC_BIND_ACK", "1");
        std::env::set_var("COINCYNC_STRATUM_TLS_PROXY_ACK", "1");
        let mut cfg = StratumConfig::default();
        cfg.bind_addr = "0.0.0.0:3333".parse().expect("socket");
        cfg.auth_password = Some("pw".to_string());
        cfg.tls_enabled = false;
        assert!(validate_stratum_exposure_policy(&cfg).is_ok());
        std::env::remove_var("COINCYNC_STRATUM_PUBLIC_BIND_ACK");
        std::env::remove_var("COINCYNC_STRATUM_TLS_PROXY_ACK");
    }

    #[test]
    fn test_coinbase_prefix() {
        let prefix = create_coinbase_prefix(100);
        assert!(!prefix.is_empty());
        // Check version
        assert_eq!(&prefix[0..4], &1u32.to_le_bytes());
    }

    #[test]
    fn test_difficulty_to_nbits() {
        let nbits = difficulty_to_nbits(1);
        assert!(nbits > 0);

        let nbits2 = difficulty_to_nbits(1000);
        assert!(nbits2 > 0);
    }

    #[test]
    fn test_mining_notify_format() {
        let job = MiningJob {
            job_id: "00000001".to_string(),
            prev_hash: Hash::zero(),
            coinbase1: vec![0, 1, 2, 3],
            coinbase2: vec![4, 5, 6, 7],
            merkle_branches: vec![],
            version: 1,
            nbits: 0x1d00ffff,
            ntime: 1234567890,
            clean_jobs: true,
            height: 100,
        };

        let notify = format_mining_notify(&job);
        assert!(notify.contains("mining.notify"));
        assert!(notify.contains("00000001"));
    }

    #[test]
    fn test_nbits_to_target_rejects_negative_compact() {
        // Compact targets with sign bit set are invalid and should map to impossible target.
        let t = nbits_to_target(0x1d80ffff);
        assert_eq!(t, Hash::zero());
    }

    #[test]
    fn test_nbits_to_target_overwide_clamps_to_easiest() {
        // Exponent too large should clamp to easiest target instead of panicking.
        let t = nbits_to_target(0xff00ffff);
        assert_eq!(t, Hash::from_bytes([0xff; 32]));
    }

    #[test]
    fn test_load_banlist_corrupt_json_is_safe_empty() {
        let uniq = format!(
            "coincync-stratum-bans-{}-{}.json",
            std::process::id(),
            timestamp_now_ms()
        );
        let path = std::env::temp_dir().join(uniq);
        let mut f = std::fs::File::create(&path).expect("create");
        f.write_all(b"{not-json").expect("write");
        let bans = load_banlist(&path);
        assert!(bans.is_empty());
        let _ = std::fs::remove_file(path);
    }

    #[tokio::test]
    async fn test_stratum_strike_progression_reaches_ban() {
        let bans = Arc::new(RwLock::new(HashMap::<String, PersistedBanEntry>::new()));
        let client_ip = "203.0.113.7";

        register_stratum_strike(&bans, None, client_ip, 5).await;
        {
            let guard = bans.read().await;
            let entry = guard.get(client_ip).expect("entry after first strike");
            assert_eq!(entry.score, 5);
            assert_eq!(entry.banned_until, 0);
        }

        register_stratum_strike(&bans, None, client_ip, 20).await;
        {
            let guard = bans.read().await;
            let entry = guard.get(client_ip).expect("entry after second strike");
            assert_eq!(entry.score, STRATUM_BAN_THRESHOLD);
            assert!(entry.banned_until > timestamp_now());
        }
    }

    #[tokio::test]
    async fn test_submit_throttle_increments_streak_and_can_deauthorize() {
        let worker_id = 7u64;
        let (tx, _rx) = mpsc::channel::<String>(4);
        let worker = Worker {
            name: "w".to_string(),
            address: None,
            extranonce1: vec![1, 2, 3, 4],
            shares: 0,
            valid_shares: 0,
            stale_shares: 0,
            invalid_shares: 0,
            difficulty: 1000,
            authorized: true,
            // Force immediate throttle path.
            last_submit_ms: timestamp_now_ms(),
            invalid_streak: MAX_INVALID_STREAK - 1,
            last_activity: timestamp_now(),
            tx,
        };

        let workers = Arc::new(RwLock::new(HashMap::<u64, Worker>::new()));
        workers.write().await.insert(worker_id, worker);
        let current_job = Arc::new(RwLock::new(Some(MiningJob {
            job_id: "job-1".to_string(),
            prev_hash: Hash::zero(),
            coinbase1: vec![],
            coinbase2: vec![],
            merkle_branches: vec![],
            version: 1,
            nbits: 0x1d00ffff,
            ntime: 1,
            clean_jobs: true,
            height: 1,
        })));
        let stats = Arc::new(RwLock::new(StratumStats::default()));
        let bans = Arc::new(RwLock::new(HashMap::<String, PersistedBanEntry>::new()));
        let chain = Arc::new(crate::chain::Blockchain::new());

        let submit = r#"{"id":1,"method":"mining.submit","params":["w","job-1","00","00000001","00000001"]}"#;
        let resp = handle_stratum_message(
            submit,
            worker_id,
            &workers,
            &current_job,
            &stats,
            &chain,
            1000,
            None,
            "198.51.100.77",
            &bans,
            None,
        ).await.expect("response");
        assert!(resp.contains("Throttled submit rate"));

        let guard = workers.read().await;
        let updated = guard.get(&worker_id).expect("worker still present");
        assert!(!updated.authorized, "worker should be deauthorized at streak threshold");
        drop(guard);

        let bans_guard = bans.read().await;
        assert!(bans_guard.get("198.51.100.77").is_some(), "throttled submit should register strike");
    }
}
