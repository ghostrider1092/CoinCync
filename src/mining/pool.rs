//! # Mining Pool Reference Implementation
//!
//! A reference implementation for CoinCync mining pools using the Stratum protocol.
//! This provides a foundation for pool operators to build upon.
//!
//! ## Features
//! - Stratum V1 protocol support
//! - Share accounting with PPLNS payout scheme
//! - Vardiff (variable difficulty) for miners
//! - Job management and work distribution
//!
//! ## Usage
//!
//! ```ignore
//! let config = PoolConfig::default();
//! let pool = MiningPool::new(config).await?;
//! pool.start().await?;
//! ```

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, RwLock};

use crate::primitives::{Hash, Amount, hash_concat};
use crate::consensus::{compute_pow_hash, compute_full_anchor, PowAlgorithm};
use crate::error::{Error, Result};

/// Mining pool configuration
#[derive(Clone, Debug)]
pub struct PoolConfig {
    /// Address to bind the Stratum server
    pub bind_address: SocketAddr,
    /// Pool fee percentage (e.g., 1.0 = 1%)
    pub pool_fee: f64,
    /// Minimum payout amount
    pub min_payout: Amount,
    /// Target shares per minute per miner (for vardiff)
    pub target_shares_per_minute: u32,
    /// PPLNS window size (number of shares to consider)
    pub pplns_window: u64,
    /// Initial share difficulty
    pub initial_difficulty: u64,
    /// Minimum share difficulty
    pub min_difficulty: u64,
    /// Maximum share difficulty
    pub max_difficulty: u64,
    /// Pool wallet address for receiving block rewards
    pub pool_address: String,
}

impl Default for PoolConfig {
    fn default() -> Self {
        PoolConfig {
            // safe: literal address is always valid
            bind_address: "127.0.0.1:3333".parse().expect("valid literal socket address"),
            pool_fee: 1.0,
            min_payout: Amount::from_cync(1).expect("1 CYNC is valid"),
            target_shares_per_minute: 10,
            pplns_window: 10000,
            initial_difficulty: 10000,
            min_difficulty: 1000,
            max_difficulty: 1000000000,
            pool_address: String::new(),
        }
    }
}

/// Stratum protocol message types
#[allow(dead_code)]
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum StratumMessage {
    Request(StratumRequest),
    Response(StratumResponse),
    Notification(StratumNotification),
}

/// Stratum request from miner
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StratumRequest {
    pub id: u64,
    pub method: String,
    pub params: serde_json::Value,
}

/// Stratum response from pool
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StratumResponse {
    pub id: u64,
    pub result: serde_json::Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<StratumError>,
}

/// Stratum notification (pool to miner, no response expected)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StratumNotification {
    pub id: Option<()>, // null id for notifications
    pub method: String,
    pub params: serde_json::Value,
}

/// Stratum error
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StratumError {
    pub code: i32,
    pub message: String,
}

/// Mining job sent to miners
#[derive(Debug, Clone)]
pub struct MiningJob {
    /// Job ID
    pub job_id: String,
    /// Block template
    pub block_template: BlockTemplate,
    /// Target difficulty for this job
    pub target: Hash,
    /// When the job was created
    pub created_at: Instant,
}

/// Block template for miners
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockTemplate {
    /// Previous block hash
    pub prev_hash: String,
    /// Coinbase transaction (hex)
    pub coinbase: String,
    /// Merkle branches (hex strings)
    pub merkle_branch: Vec<String>,
    /// Block version
    pub version: u32,
    /// Difficulty target (compact)
    pub nbits: u32,
    /// Block timestamp
    pub timestamp: u64,
    /// Block height
    pub height: u64,
    /// Algorithm index for this block
    pub algorithm: u8,
}

/// Miner connection state
#[derive(Debug)]
pub struct MinerConnection {
    /// Unique miner ID
    pub miner_id: u64,
    /// Worker name
    pub worker_name: String,
    /// Wallet address for payouts
    pub address: String,
    /// Current difficulty
    pub difficulty: u64,
    /// Shares submitted
    pub shares_submitted: u64,
    /// Valid shares
    pub valid_shares: u64,
    /// Invalid shares
    pub invalid_shares: u64,
    /// Last share time
    pub last_share: Instant,
    /// Shares in current vardiff window
    pub vardiff_shares: u32,
    /// Vardiff window start
    pub vardiff_window_start: Instant,
    /// Connection time
    pub connected_at: Instant,
    /// Is subscribed
    pub subscribed: bool,
    /// Is authorized
    pub authorized: bool,
    /// Current extra nonce
    pub extra_nonce1: String,

    /// 2026-06-03 anti-replay: per-job dedup set of submitted
    /// `(extra_nonce2, nonce)` tuples. A repeated tuple under the same
    /// job_id is rejected as a duplicate share — see the long-form
    /// rationale on the mining.submit handler. Cleared each time the
    /// miner's `current_job_id` rotates.
    pub current_job_id: String,
    pub submitted_shares: std::collections::HashSet<(String, String)>,
}

impl MinerConnection {
    fn new(miner_id: u64) -> Self {
        let now = Instant::now();
        MinerConnection {
            miner_id,
            worker_name: String::new(),
            address: String::new(),
            difficulty: 10000,
            shares_submitted: 0,
            valid_shares: 0,
            invalid_shares: 0,
            last_share: now,
            vardiff_shares: 0,
            vardiff_window_start: now,
            connected_at: now,
            subscribed: false,
            authorized: false,
            extra_nonce1: format!("{:08x}", miner_id),
            current_job_id: String::new(),
            submitted_shares: std::collections::HashSet::new(),
        }
    }
}

/// Share submission from a miner
#[allow(dead_code)]
#[derive(Debug, Clone)]
pub struct Share {
    /// Miner who submitted
    pub miner_id: u64,
    /// Job ID
    pub job_id: String,
    /// Extra nonce 2
    pub extra_nonce2: String,
    /// Nonce
    pub nonce: String,
    /// Time submitted
    pub timestamp: u64,
    /// Difficulty of this share
    pub difficulty: u64,
    /// Whether this share found a block
    pub is_block: bool,
    /// Block hash if is_block
    pub block_hash: Option<Hash>,
}

/// PPLNS share for payout calculation
#[derive(Debug, Clone)]
pub struct PplnsShare {
    /// Miner address
    pub address: String,
    /// Share difficulty
    pub difficulty: u64,
    /// Block height when share was submitted
    pub height: u64,
    /// Timestamp
    pub timestamp: u64,
}

/// Pool statistics
#[derive(Debug, Clone, Default)]
pub struct PoolStats {
    /// Total hashrate (H/s)
    pub hashrate: f64,
    /// Connected miners
    pub miners: u32,
    /// Workers (multiple per miner possible)
    pub workers: u32,
    /// Blocks found
    pub blocks_found: u64,
    /// Total shares
    pub total_shares: u64,
    /// Pool uptime
    pub uptime_seconds: u64,
    /// Last block time
    pub last_block_time: Option<u64>,
    /// Pending payouts
    pub pending_payouts: Amount,
    /// Total paid out
    pub total_paid: Amount,
}

/// Mining pool server
pub struct MiningPool {
    /// Configuration
    config: PoolConfig,
    /// Connected miners
    miners: Arc<RwLock<HashMap<u64, MinerConnection>>>,
    /// Current jobs
    jobs: Arc<RwLock<HashMap<String, MiningJob>>>,
    /// PPLNS shares
    pplns_shares: Arc<RwLock<Vec<PplnsShare>>>,
    /// Pending balances per address
    balances: Arc<RwLock<HashMap<String, Amount>>>,
    /// Pool statistics
    stats: Arc<RwLock<PoolStats>>,
    /// Next miner ID
    next_miner_id: Arc<RwLock<u64>>,
    /// Current block height (updated by job notifications)
    _current_height: Arc<RwLock<u64>>,
    /// Shutdown signal
    shutdown_tx: Option<mpsc::Sender<()>>,
}

impl MiningPool {
    /// Create a new mining pool
    pub fn new(config: PoolConfig) -> Self {
        MiningPool {
            config,
            miners: Arc::new(RwLock::new(HashMap::new())),
            jobs: Arc::new(RwLock::new(HashMap::new())),
            pplns_shares: Arc::new(RwLock::new(Vec::new())),
            balances: Arc::new(RwLock::new(HashMap::new())),
            stats: Arc::new(RwLock::new(PoolStats::default())),
            next_miner_id: Arc::new(RwLock::new(1)),
            _current_height: Arc::new(RwLock::new(0)),
            shutdown_tx: None,
        }
    }

    /// Start the mining pool server
    pub async fn start(&mut self) -> Result<()> {
        let public_bind = !self.config.bind_address.ip().is_loopback();
        if public_bind {
            let public_ack = std::env::var("COINCYNC_POOL_PUBLIC_BIND_ACK")
                .ok()
                .map(|v| {
                    let t = v.trim();
                    t == "1" || t.eq_ignore_ascii_case("true") || t.eq_ignore_ascii_case("yes")
                })
                .unwrap_or(false);
            if !public_ack {
                return Err(Error::InvalidState(
                    "Refusing public pool bind without COINCYNC_POOL_PUBLIC_BIND_ACK=1.".into(),
                ));
            }
            let tls_ack = std::env::var("COINCYNC_POOL_TLS_PROXY_ACK")
                .ok()
                .map(|v| {
                    let t = v.trim();
                    t == "1" || t.eq_ignore_ascii_case("true") || t.eq_ignore_ascii_case("yes")
                })
                .unwrap_or(false);
            if !tls_ack {
                return Err(Error::InvalidState(
                    "Refusing public pool bind without COINCYNC_POOL_TLS_PROXY_ACK=1. \
                     Public pool traffic must be protected by TLS termination."
                        .into(),
                ));
            }
        }

        let listener = TcpListener::bind(&self.config.bind_address).await
            .map_err(|e| Error::ConnectionFailed(format!("Failed to bind: {}", e)))?;

        tracing::info!("Mining pool listening on {}", self.config.bind_address);

        let (shutdown_tx, mut shutdown_rx) = mpsc::channel::<()>(1);
        self.shutdown_tx = Some(shutdown_tx);

        let miners = Arc::clone(&self.miners);
        let jobs = Arc::clone(&self.jobs);
        let pplns_shares = Arc::clone(&self.pplns_shares);
        let balances = Arc::clone(&self.balances);
        let stats = Arc::clone(&self.stats);
        let next_miner_id = Arc::clone(&self.next_miner_id);
        let config = self.config.clone();

        tokio::spawn(async move {
            loop {
                tokio::select! {
                    result = listener.accept() => {
                        match result {
                            Ok((socket, addr)) => {
                                let miners = Arc::clone(&miners);
                                let jobs = Arc::clone(&jobs);
                                let pplns_shares = Arc::clone(&pplns_shares);
                                let balances = Arc::clone(&balances);
                                let stats = Arc::clone(&stats);
                                let next_miner_id = Arc::clone(&next_miner_id);
                                let config = config.clone();

                                tokio::spawn(async move {
                                    if let Err(e) = handle_miner(
                                        socket, addr, miners, jobs, pplns_shares,
                                        balances, stats, next_miner_id, config
                                    ).await {
                                        tracing::debug!("Miner {} disconnected: {}", addr, e);
                                    }
                                });
                            }
                            Err(e) => {
                                tracing::error!("Accept error: {}", e);
                            }
                        }
                    }
                    _ = shutdown_rx.recv() => {
                        tracing::info!("Mining pool shutting down");
                        break;
                    }
                }
            }
        });

        Ok(())
    }

    /// Stop the mining pool
    pub async fn stop(&mut self) {
        if let Some(tx) = self.shutdown_tx.take() {
            let _ = tx.send(()).await;
        }
    }

    /// Get pool statistics
    pub async fn stats(&self) -> PoolStats {
        self.stats.read().await.clone()
    }

    /// Get connected miners count
    pub async fn miner_count(&self) -> usize {
        self.miners.read().await.len()
    }

    /// Create a new block template/job
    pub async fn create_job(&self, template: BlockTemplate) -> MiningJob {
        let job_id = format!("{:08x}", rand::random::<u32>());
        let target = difficulty_to_target(self.config.initial_difficulty);

        let job = MiningJob {
            job_id: job_id.clone(),
            block_template: template,
            target,
            created_at: Instant::now(),
        };

        self.jobs.write().await.insert(job_id, job.clone());
        job
    }

    /// Process a block found by the pool
    pub async fn on_block_found(&self, block_hash: Hash, height: u64, reward: Amount) {
        tracing::info!("Block found! Hash: {:?}, Height: {}", block_hash, height);

        // Update stats
        {
            let mut stats = self.stats.write().await;
            stats.blocks_found += 1;
            // SECURITY (A6-CLOCK): Use unwrap_or(0) to handle pre-epoch clocks
            // consistently with the rest of the codebase (stratum.rs, persistence.rs)
            stats.last_block_time = Some(
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_secs())
                    .unwrap_or(0)
            );
        }

        // Calculate payouts using PPLNS, then prune old shares
        let mut shares = self.pplns_shares.write().await;
        let window_shares: Vec<_> = shares.iter()
            .rev()
            .take(self.config.pplns_window as usize)
            .collect();

        if window_shares.is_empty() {
            return;
        }

        // Calculate total difficulty in window
        let total_diff: u64 = window_shares.iter().map(|s| s.difficulty).sum();
        if total_diff == 0 {
            return;
        }

        // Calculate net reward after pool fee (safe float-to-u64 cast)
        let fee_f64 = reward.as_atomic() as f64 * self.config.pool_fee / 100.0;
        let fee_u64 = if fee_f64.is_finite() && fee_f64 >= 0.0 {
            (fee_f64.min(u64::MAX as f64)) as u64
        } else {
            0u64
        };
        let fee_amount = Amount::from_atomic(fee_u64);
        let net_reward = reward.saturating_sub(fee_amount);

        // Distribute to miners
        let mut address_diff: HashMap<String, u64> = HashMap::new();
        for share in window_shares {
            *address_diff.entry(share.address.clone()).or_insert(0) += share.difficulty;
        }

        let mut balances = self.balances.write().await;
        for (address, diff) in address_diff {
            let share_ratio = diff as f64 / total_diff as f64;
            let payout_f64 = net_reward.as_atomic() as f64 * share_ratio;
            let payout = Amount::from_atomic(
                if payout_f64.is_finite() && payout_f64 >= 0.0 {
                    (payout_f64.min(u64::MAX as f64)) as u64
                } else {
                    0u64
                }
            );
            let balance = balances.entry(address).or_insert(Amount::from_atomic(0));
            *balance = balance.saturating_add(payout);
        }

        // Prune old shares to prevent unbounded memory growth.
        // Keep 2x PPLNS window to allow for minor timing variations.
        let max_shares = self.config.pplns_window as usize * 2;
        if shares.len() > max_shares {
            let drain_count = shares.len() - max_shares;
            shares.drain(..drain_count);
        }
    }

    /// Get pending balance for an address
    pub async fn get_balance(&self, address: &str) -> Amount {
        self.balances.read().await
            .get(address)
            .copied()
            .unwrap_or(Amount::from_atomic(0))
    }

    /// Process payout for an address
    pub async fn process_payout(&self, address: &str) -> Option<Amount> {
        let mut balances = self.balances.write().await;
        let balance = balances.get(address).copied()?;

        if balance < self.config.min_payout {
            return None;
        }

        // Mark as paid (actual transaction would be created here)
        balances.remove(address);

        // Update stats
        {
            let mut stats = self.stats.write().await;
            stats.total_paid = stats.total_paid.saturating_add(balance);
        }

        Some(balance)
    }
}

/// Handle a single miner connection
async fn handle_miner(
    socket: TcpStream,
    addr: SocketAddr,
    miners: Arc<RwLock<HashMap<u64, MinerConnection>>>,
    jobs: Arc<RwLock<HashMap<String, MiningJob>>>,
    pplns_shares: Arc<RwLock<Vec<PplnsShare>>>,
    _balances: Arc<RwLock<HashMap<String, Amount>>>,
    stats: Arc<RwLock<PoolStats>>,
    next_miner_id: Arc<RwLock<u64>>,
    config: PoolConfig,
) -> Result<()> {
    // Assign miner ID
    let miner_id = {
        let mut id = next_miner_id.write().await;
        let current = *id;
        *id += 1;
        current
    };

    // Create miner state
    let mut miner = MinerConnection::new(miner_id);
    miner.difficulty = config.initial_difficulty;

    tracing::info!("Miner {} connected from {}", miner_id, addr);

    // Update stats
    {
        let mut s = stats.write().await;
        s.miners += 1;
    }

    // SECURITY: Max line length to prevent memory exhaustion DoS.
    // read_line reads until \n, so without a cap a malicious client can
    // send GB of data without a newline to exhaust memory.
    const MAX_LINE_LENGTH: usize = 16 * 1024; // 16 KB

    let (reader, mut writer) = socket.into_split();
    let mut reader = BufReader::new(reader);
    let mut line = String::with_capacity(256);

    loop {
        line.clear();
        let mut limited = (&mut reader).take(MAX_LINE_LENGTH as u64);
        match limited.read_line(&mut line).await {
            Ok(0) => break, // EOF
            Ok(_) => {
                if !line.ends_with('\n') {
                    tracing::warn!("Oversized message from {} (>{} bytes), disconnecting", addr, MAX_LINE_LENGTH);
                    break;
                }
                let trimmed = line.trim();
                if trimmed.is_empty() {
                    continue;
                }

                match serde_json::from_str::<StratumRequest>(trimmed) {
                    Ok(request) => {
                        let response = process_stratum_request(
                            &request, &mut miner, &jobs, &pplns_shares, &config
                        ).await;

                        // SECURITY: Handle serialization errors gracefully instead of panicking
                        let response_json = match serde_json::to_string(&response) {
                            Ok(json) => json,
                            Err(e) => {
                                tracing::error!("Failed to serialize response: {}", e);
                                continue;
                            }
                        };
                        if writer.write_all(format!("{}\n", response_json).as_bytes()).await.is_err() {
                            break;
                        }

                        // If miner just authorized, send them work
                        if request.method == "mining.authorize" && miner.authorized {
                            let jobs = jobs.read().await;
                            if let Some(job) = jobs.values().next() {
                                let notify = create_job_notification(job, true);
                                if let Ok(notify_json) = serde_json::to_string(&notify) {
                                    let _ = writer.write_all(format!("{}\n", notify_json).as_bytes()).await;
                                }
                            }
                        }
                    }
                    Err(e) => {
                        tracing::debug!("Failed to parse message from {}: {}", addr, e);
                    }
                }
            }
            Err(e) => {
                tracing::debug!("Read error from {}: {}", addr, e);
                break;
            }
        }
    }

    // Cleanup
    miners.write().await.remove(&miner_id);
    {
        let mut s = stats.write().await;
        s.miners = s.miners.saturating_sub(1);
    }

    tracing::info!("Miner {} disconnected", miner_id);
    Ok(())
}

/// Process a Stratum request
async fn process_stratum_request(
    request: &StratumRequest,
    miner: &mut MinerConnection,
    jobs: &Arc<RwLock<HashMap<String, MiningJob>>>,
    pplns_shares: &Arc<RwLock<Vec<PplnsShare>>>,
    config: &PoolConfig,
) -> StratumResponse {
    match request.method.as_str() {
        "mining.subscribe" => {
            miner.subscribed = true;

            // Return subscription details
            // [session_id, extra_nonce1, extra_nonce2_size]
            StratumResponse {
                id: request.id,
                result: serde_json::json!([
                    [["mining.notify", format!("{:08x}", miner.miner_id)]],
                    miner.extra_nonce1.clone(),
                    4  // extra_nonce2 size
                ]),
                error: None,
            }
        }

        "mining.authorize" => {
            // Params: [username, password]
            // Username format: address.worker_name
            if let Some(params) = request.params.as_array() {
                if let Some(username) = params.get(0).and_then(|v| v.as_str()) {
                    let parts: Vec<&str> = username.split('.').collect();
                    miner.address = parts.get(0).unwrap_or(&"").to_string();
                    miner.worker_name = parts.get(1).unwrap_or(&"default").to_string();
                    miner.authorized = true;

                    tracing::info!(
                        "Miner {} authorized: {} (worker: {})",
                        miner.miner_id, miner.address, miner.worker_name
                    );

                    return StratumResponse {
                        id: request.id,
                        result: serde_json::json!(true),
                        error: None,
                    };
                }
            }

            StratumResponse {
                id: request.id,
                result: serde_json::json!(false),
                error: Some(StratumError {
                    code: 24,
                    message: "Invalid authorization".into(),
                }),
            }
        }

        "mining.submit" => {
            // Params: [worker_name, job_id, extra_nonce2, ntime, nonce]
            if !miner.authorized {
                return StratumResponse {
                    id: request.id,
                    result: serde_json::json!(false),
                    error: Some(StratumError {
                        code: 24,
                        message: "Not authorized".into(),
                    }),
                };
            }

            if let Some(params) = request.params.as_array() {
                let job_id = params.get(1).and_then(|v| v.as_str()).unwrap_or("");
                let extra_nonce2 = params.get(2).and_then(|v| v.as_str()).unwrap_or("");
                let _ntime = params.get(3).and_then(|v| v.as_str()).unwrap_or("");
                let nonce = params.get(4).and_then(|v| v.as_str()).unwrap_or("");

                // Verify job exists
                let jobs = jobs.read().await;
                let job = match jobs.get(job_id) {
                    Some(j) => j,
                    None => {
                        miner.invalid_shares += 1;
                        return StratumResponse {
                            id: request.id,
                            result: serde_json::json!(false),
                            error: Some(StratumError {
                                code: 21,
                                message: "Job not found".into(),
                            }),
                        };
                    }
                };

                // 2026-06-03 anti-replay duplicate-share defense.
                //
                // Previously this reference pool had NO per-job dedup of
                // submitted `(extra_nonce2, nonce)` tuples — a malicious
                // miner could submit the same valid share repeatedly to
                // inflate `valid_shares`, which directly drives PPLNS
                // payout share. The chain ignores duplicates (a block
                // can only be mined once) but the pool's reward
                // accounting was being defrauded.
                //
                // The active production Stratum server (stratum.rs:836-855)
                // already had this defense; this reference template was
                // missing it, so any pool operator who built on the
                // template inherited the replay vulnerability. Closes
                // the footgun at the template level.
                //
                // Dedup is per-job: when the miner's `current_job_id`
                // rotates, the set is wiped (old shares are stale anyway,
                // and the set would grow unbounded otherwise).
                if miner.current_job_id != job_id {
                    miner.submitted_shares.clear();
                    miner.current_job_id = job_id.to_string();
                }
                let dedup_key = (extra_nonce2.to_string(), nonce.to_string());
                if !miner.submitted_shares.insert(dedup_key) {
                    miner.invalid_shares += 1;
                    return StratumResponse {
                        id: request.id,
                        result: serde_json::json!(false),
                        error: Some(StratumError {
                            code: 22,
                            message: "Duplicate share".into(),
                        }),
                    };
                }

                // Verify the share by computing PoW hash and checking difficulty
                miner.shares_submitted += 1;

                // Parse prev_hash from job template
                let prev_hash = match hex::decode(&job.block_template.prev_hash) {
                    Ok(bytes) if bytes.len() == 32 => {
                        let mut arr = [0u8; 32];
                        arr.copy_from_slice(&bytes);
                        Hash::from_bytes(arr)
                    }
                    _ => {
                        miner.invalid_shares += 1;
                        return StratumResponse {
                            id: request.id,
                            result: serde_json::json!(false),
                            error: Some(StratumError {
                                code: 20,
                                message: "Invalid job prev_hash".into(),
                            }),
                        };
                    }
                };

                // Parse nonce (extra_nonce1 + extra_nonce2 + submitted nonce)
                let full_nonce_hex = format!("{}{}{}", miner.extra_nonce1, extra_nonce2, nonce);

                // SECURITY: Validate nonce length is exactly 16 hex chars (8 bytes = u64)
                // to prevent silent truncation that could cause nonce collisions
                if full_nonce_hex.len() != 16 {
                    miner.invalid_shares += 1;
                    tracing::warn!(
                        "Nonce length mismatch: expected 16 hex chars, got {} (extra_nonce1={}, extra_nonce2={}, nonce={})",
                        full_nonce_hex.len(), miner.extra_nonce1, extra_nonce2, nonce
                    );
                    return StratumResponse {
                        id: request.id,
                        result: serde_json::json!(false),
                        error: Some(StratumError {
                            code: 20,
                            message: format!(
                                "Invalid nonce length: expected 16 hex chars, got {}",
                                full_nonce_hex.len()
                            ),
                        }),
                    };
                }

                let nonce_value = match u64::from_str_radix(&full_nonce_hex, 16) {
                    Ok(n) => n,
                    Err(_) => {
                        miner.invalid_shares += 1;
                        return StratumResponse {
                            id: request.id,
                            result: serde_json::json!(false),
                            error: Some(StratumError {
                                code: 20,
                                message: "Invalid nonce format".into(),
                            }),
                        };
                    }
                };

                // Compute anchor for this block
                let anchor = match compute_full_anchor(
                    &prev_hash,
                    job.block_template.height,
                    job.block_template.timestamp,
                ) {
                    Ok(a) => a,
                    Err(e) => {
                        tracing::error!("Failed to compute anchor: {}", e);
                        miner.invalid_shares += 1;
                        return StratumResponse {
                            id: request.id,
                            result: serde_json::json!(false),
                            error: Some(StratumError {
                                code: 20,
                                message: "Anchor computation failed".into(),
                            }),
                        };
                    }
                };

                // Compute tx_root from coinbase (simplified - real impl would merkle hash)
                let tx_root_bytes = match hex::decode(&job.block_template.coinbase) {
                    Ok(bytes) => {
                        let hash = hash_concat(&[&bytes, b"TX_ROOT"]);
                        hash
                    }
                    Err(_) => {
                        miner.invalid_shares += 1;
                        return StratumResponse {
                            id: request.id,
                            result: serde_json::json!(false),
                            error: Some(StratumError {
                                code: 20,
                                message: "Invalid coinbase".into(),
                            }),
                        };
                    }
                };

                // Compute the PoW hash
                let algo = PowAlgorithm::from_index(job.block_template.algorithm);
                let pow_hash = match compute_pow_hash(algo, &anchor.mixed_hash, nonce_value, &tx_root_bytes, job.block_template.height) {
                    Ok(h) => h,
                    Err(_) => {
                        return StratumResponse {
                            id: request.id,
                            result: serde_json::json!(false),
                            error: Some(StratumError {
                                code: 20,
                                message: "PoW hash computation failed".into(),
                            }),
                        };
                    }
                };

                // Check if hash meets share difficulty target
                let share_target = difficulty_to_target(miner.difficulty);
                if !pow_hash.meets_difficulty(&share_target) {
                    miner.invalid_shares += 1;
                    tracing::debug!(
                        "Share rejected from {} (job: {}, nonce: {}) - doesn't meet share target",
                        miner.address, job_id, nonce
                    );
                    return StratumResponse {
                        id: request.id,
                        result: serde_json::json!(false),
                        error: Some(StratumError {
                            code: 23,
                            message: "Low difficulty share".into(),
                        }),
                    };
                }

                // Valid share!
                miner.valid_shares += 1;
                miner.last_share = Instant::now();
                miner.vardiff_shares += 1;

                // Check if it also meets block target (found a block!)
                if pow_hash.meets_difficulty(&job.target) {
                    tracing::info!(
                        "BLOCK FOUND by miner {} (job: {})! Hash: {}",
                        miner.address, job_id, hex::encode(pow_hash.as_bytes())
                    );
                    // Block submission would be handled by pool operator
                    // This is a reference implementation - actual block submission
                    // requires integration with the node
                }

                // Record share for PPLNS
                {
                    let mut shares = pplns_shares.write().await;
                    shares.push(PplnsShare {
                        address: miner.address.clone(),
                        difficulty: miner.difficulty,
                        height: job.block_template.height,
                        timestamp: std::time::SystemTime::now()
                            .duration_since(std::time::UNIX_EPOCH)
                            .unwrap_or_default()
                            .as_secs(),
                    });

                    // Prune old shares beyond PPLNS window
                    if shares.len() > config.pplns_window as usize * 2 {
                        shares.drain(0..config.pplns_window as usize);
                    }
                }

                // Check for vardiff adjustment
                let elapsed = miner.vardiff_window_start.elapsed();
                if elapsed >= Duration::from_secs(60) {
                    let shares_per_minute = miner.vardiff_shares as f64 / elapsed.as_secs_f64() * 60.0;

                    if shares_per_minute > config.target_shares_per_minute as f64 * 1.5 {
                        // Too many shares, increase difficulty
                        miner.difficulty = miner.difficulty.saturating_mul(3) / 2; // *1.5 without float
                        miner.difficulty = miner.difficulty.min(config.max_difficulty);
                    } else if shares_per_minute < config.target_shares_per_minute as f64 * 0.5 {
                        // Too few shares, decrease difficulty.
                        // SAFETY: saturating_mul protects against u64 overflow when difficulty
                        // > u64::MAX/7 (~2.6e18). Plain `* 7` would panic in debug / wrap in
                        // release; the subsequent .max(min_difficulty) catches wrap-to-near-zero
                        // but NOT wrap-to-medium, so the saturate-then-divide form is required.
                        miner.difficulty = miner.difficulty.saturating_mul(7) / 10; // *0.7 without float
                        miner.difficulty = miner.difficulty.max(config.min_difficulty);
                    }

                    miner.vardiff_shares = 0;
                    miner.vardiff_window_start = Instant::now();
                }

                tracing::debug!(
                    "Share accepted from {} (job: {}, nonce: {})",
                    miner.address, job_id, nonce
                );

                return StratumResponse {
                    id: request.id,
                    result: serde_json::json!(true),
                    error: None,
                };
            }

            StratumResponse {
                id: request.id,
                result: serde_json::json!(false),
                error: Some(StratumError {
                    code: 20,
                    message: "Invalid params".into(),
                }),
            }
        }

        "mining.extranonce.subscribe" => {
            // Optional extension for extranonce notifications
            StratumResponse {
                id: request.id,
                result: serde_json::json!(true),
                error: None,
            }
        }

        _ => {
            tracing::debug!("Unknown method: {}", request.method);
            StratumResponse {
                id: request.id,
                result: serde_json::Value::Null,
                error: Some(StratumError {
                    code: -1,
                    message: format!("Unknown method: {}", request.method),
                }),
            }
        }
    }
}

/// Create a job notification message
fn create_job_notification(job: &MiningJob, clean_jobs: bool) -> StratumNotification {
    StratumNotification {
        id: None,
        method: "mining.notify".into(),
        params: serde_json::json!([
            job.job_id,
            job.block_template.prev_hash,
            job.block_template.coinbase,
            job.block_template.merkle_branch,
            format!("{:08x}", job.block_template.version),
            format!("{:08x}", job.block_template.nbits),
            format!("{:08x}", job.block_template.timestamp),
            clean_jobs
        ]),
    }
}

/// Convert difficulty to target hash
fn difficulty_to_target(difficulty: u64) -> Hash {
    // Max target (difficulty 1) has leading zeros
    // Higher difficulty = more leading zeros = smaller target
    let mut bytes = [0xFFu8; 32];

    if difficulty > 0 {
        let shift = (difficulty as f64).log2() as usize;
        if shift < 256 {
            for i in 0..(shift / 8).min(32) {
                bytes[i] = 0;
            }
            if shift / 8 < 32 {
                bytes[shift / 8] = (0xFF >> (shift % 8)) as u8;
            }
        }
    }

    Hash::from_bytes(bytes)
}

/// Pool payout schemes
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PayoutScheme {
    /// Pay-Per-Last-N-Shares
    PPLNS,
    /// Pay-Per-Share (pool takes variance risk)
    PPS,
    /// Proportional
    Proportional,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pool_config_default() {
        let config = PoolConfig::default();
        assert_eq!(config.pool_fee, 1.0);
        assert_eq!(config.target_shares_per_minute, 10);
    }

    #[test]
    fn test_miner_connection_new() {
        let miner = MinerConnection::new(1);
        assert_eq!(miner.miner_id, 1);
        assert!(!miner.subscribed);
        assert!(!miner.authorized);
        assert_eq!(miner.valid_shares, 0);
    }

    #[test]
    fn test_difficulty_to_target() {
        let target1 = difficulty_to_target(1);
        let target1000 = difficulty_to_target(1000);

        // Higher difficulty should result in smaller target
        assert!(target1000.as_bytes() < target1.as_bytes());
    }

    #[tokio::test]
    async fn test_pool_creation() {
        let config = PoolConfig::default();
        let pool = MiningPool::new(config);
        assert_eq!(pool.miner_count().await, 0);
    }

    #[tokio::test]
    async fn test_pool_balance() {
        let config = PoolConfig::default();
        let pool = MiningPool::new(config);

        let balance = pool.get_balance("test_address").await;
        assert_eq!(balance, Amount::from_atomic(0));
    }
}
