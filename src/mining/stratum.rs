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
use crate::error::{Error, Result};
use crate::mempool::SharedMempool;
use crate::mining::block_builder::{self, CandidateBlock};
use crate::primitives::{Hash, PublicKey};

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
    /// Payout keys. The coinbase of any block this pool finds is paid to a
    /// stealth address derived from `(payout_spend_public, payout_view_public)`
    /// via [`block_builder::build_candidate_block`](crate::mining::block_builder).
    /// REQUIRED to actually produce blocks: when `None`, the server can still
    /// validate shares but cannot build/submit a real block (it logs a found
    /// share without submitting). Wired into block production in Stage 3
    /// (the CoinCync/RandomX job model).
    pub payout_spend_public: Option<PublicKey>,
    /// See [`payout_spend_public`](Self::payout_spend_public).
    pub payout_view_public: Option<PublicKey>,
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
            // No default payout keys — a pool operator must set these before
            // the server can produce blocks. Absent = shares only.
            payout_spend_public: None,
            payout_view_public: None,
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
    if config
        .auth_password
        .as_deref()
        .map(str::is_empty)
        .unwrap_or(true)
    {
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

/// Mining job sent to workers.
///
/// CoinCync/RandomX model: a miner hashes
/// `compute_pow_hash(RandomX, anchor, nonce, tx_root, height)` and wins when it
/// meets `target`. `seed_hash` is the RandomX VM key for this height. The full
/// candidate block backing this job is held server-side in
/// `StratumServer::candidates[job_id]` so a winning nonce can be assembled and
/// submitted. (The Bitcoin-style `prev_hash`/`coinbase1`/`coinbase2`/
/// `merkle_branches`/`nbits`/`version` fields are retained for the legacy wire
/// format until the Monero-style wire protocol lands in Step 7; block
/// production no longer uses them.)
#[derive(Clone, Debug)]
pub struct MiningJob {
    /// Unique job ID
    pub job_id: String,
    // --- CoinCync/RandomX PoW fields (authoritative for verification) ---
    /// PoW anchor for this height (from the candidate block).
    pub anchor: Hash,
    /// Merkle root over the candidate's transactions.
    pub tx_root: Hash,
    /// RandomX VM seed (key) for this height.
    pub seed_hash: [u8; 32],
    /// Full 256-bit block target.
    pub target: Hash,
    /// Block height
    pub height: u64,
    // --- legacy Bitcoin-style fields (wire compatibility only) ---
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
    pub fn verify(
        &self,
        job: &MiningJob,
        share_difficulty: u64,
        _extranonce1: &[u8],
    ) -> ShareResult {
        use crate::consensus::{compute_pow_hash, PowAlgorithm};

        // CoinCync/RandomX PoW — identical to what the validator computes:
        // hash the job's anchor + tx_root (both taken from the server-side
        // candidate block) with the submitted nonce. A hash that meets the
        // block target therefore corresponds to a real, submittable block; the
        // submit handler assembles the stored candidate with `self.nonce`.
        let pow_hash = match compute_pow_hash(
            PowAlgorithm::RandomX,
            &job.anchor,
            self.nonce as u64,
            &job.tx_root,
            job.height,
        ) {
            Ok(h) => h,
            Err(_) => return ShareResult::Invalid,
        };

        // Must meet the per-worker share target — clamped so it is never harder
        // than the block target (issue #44), otherwise a hash that IS a valid
        // block could be rejected here as a low-difficulty share.
        let share_target =
            Hash::from_difficulty(effective_share_difficulty(share_difficulty, &job.target));
        if !pow_hash.meets_difficulty(&share_target) {
            return ShareResult::Invalid;
        }

        // Also meets the full block target? => a real block was found.
        if pow_hash.meets_difficulty(&job.target) {
            return ShareResult::Block(pow_hash);
        }

        ShareResult::Valid
    }
}

/// Convert compact `nbits` into a full 256-bit target (big-endian).
// Retained for the legacy Bitcoin-style wire (format_mining_notify sends nbits)
// and its unit tests; the CoinCync PoW path uses the job's full `target`.
#[allow(dead_code)]
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
    /// The miner's payout login (the `login` string, conventionally
    /// `<miner_address>.<worker>`). A public pool credits this miner's shares
    /// here; the operator distributes rewards off the share tally.
    payout_login: String,
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
    /// Blocks accepted by the chain (issue #42: distinct from PoW solutions —
    /// a solution that meets the block target but is not accepted, e.g. lost a
    /// race or failed validation, is counted in `block_pow_hits` only).
    pub blocks_found: u64,
    /// PoW solutions that met the block target and were submitted, regardless of
    /// whether the chain accepted them.
    pub block_pow_hits: u64,
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
    /// Server-owned per-canonical-job accepted-nonce ledger (share-replay
    /// defense). Shared across all worker connections; see [`JobNonceLedger`].
    nonce_dedup: Arc<RwLock<JobNonceLedger>>,
    /// Full candidate block backing each live job, keyed by job_id. A winning
    /// nonce is assembled from the candidate here and submitted to the chain.
    /// Only populated when payout keys are configured.
    candidates: Arc<RwLock<HashMap<String, CandidateBlock>>>,
    job_broadcast: broadcast::Sender<MiningJob>,
    stats: Arc<RwLock<StratumStats>>,
    running: Arc<std::sync::atomic::AtomicBool>,
    bans: Arc<RwLock<HashMap<String, PersistedBanEntry>>>,
    banlist_path: Option<PathBuf>,
    /// Optional P2P handle so a pool-found block is broadcast to peers. Without
    /// it, an accepted block stays local — fine for an isolated regtest node,
    /// but on a real network the pool would fork away from its peers.
    p2p: Option<Arc<crate::network::P2PNode>>,
}

impl StratumServer {
    /// Create a new Stratum server
    pub fn new(config: StratumConfig, chain: SharedBlockchain, mempool: SharedMempool) -> Self {
        let (job_broadcast, _) = broadcast::channel(16);
        let banlist_path = std::env::var("COINCYNC_STRATUM_BANLIST_PATH")
            .ok()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .map(PathBuf::from)
            .or_else(|| Some(PathBuf::from("stratum_bans.json")));
        let bans = banlist_path.as_ref().map(load_banlist).unwrap_or_default();

        StratumServer {
            config,
            chain,
            mempool,
            workers: Arc::new(RwLock::new(HashMap::new())),
            next_worker_id: Arc::new(AtomicU64::new(1)),
            next_job_id: Arc::new(AtomicU64::new(1)),
            extranonce_counter: Arc::new(AtomicU64::new(1)),
            current_job: Arc::new(RwLock::new(None)),
            nonce_dedup: Arc::new(RwLock::new(JobNonceLedger::default())),
            candidates: Arc::new(RwLock::new(HashMap::new())),
            job_broadcast,
            stats: Arc::new(RwLock::new(StratumStats::default())),
            running: Arc::new(std::sync::atomic::AtomicBool::new(false)),
            p2p: None,
            bans: Arc::new(RwLock::new(bans)),
            banlist_path,
        }
    }

    /// Attach a P2P handle so pool-found blocks are broadcast to peers. Call
    /// this when wiring the server into a node that has a live P2P layer.
    pub fn with_p2p(mut self, p2p: Arc<crate::network::P2PNode>) -> Self {
        self.p2p = Some(p2p);
        self
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

    /// Per-login share tally for a PUBLIC-pool operator: each miner's valid
    /// shares weighted by their share difficulty, keyed by their `login`
    /// (conventionally `<miner_address>.<worker>`). This is the input to a
    /// payout scheme — the operator distributes the coinbase (which pays the
    /// pool's own `--stratum-address`) to miners in proportion to these
    /// weighted shares. Solo/self-hosted operators can ignore it.
    pub async fn share_tally(&self) -> HashMap<String, u128> {
        let mut out: HashMap<String, u128> = HashMap::new();
        for w in self.workers.read().await.values() {
            if w.payout_login.is_empty() {
                continue;
            }
            *out.entry(w.payout_login.clone()).or_insert(0) +=
                (w.valid_shares as u128).saturating_mul(w.difficulty.max(1) as u128);
        }
        out
    }

    /// Spawn job update task
    fn spawn_job_updater(&self) {
        let chain = self.chain.clone();
        let mempool = self.mempool.clone();
        let current_job = self.current_job.clone();
        let candidates = self.candidates.clone();
        let job_broadcast = self.job_broadcast.clone();
        let next_job_id = self.next_job_id.clone();
        let running = self.running.clone();
        let share_difficulty = self.config.share_difficulty;
        let payout_spend = self.config.payout_spend_public;
        let payout_view = self.config.payout_view_public;

        tokio::spawn(async move {
            let mut last_tip = Hash::zero();

            while running.load(Ordering::SeqCst) {
                let tip = chain.tip_hash();

                // Check if we need a new job
                if tip != last_tip {
                    last_tip = tip;

                    // Create new job
                    let job_id_num = next_job_id.fetch_add(1, Ordering::SeqCst);
                    let job_id = format!("{:08x}", job_id_num);
                    let height = chain.height() + 1;
                    let timestamp = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .map(|d| d.as_secs() as u32)
                        .unwrap_or(0);

                    // Build the real candidate block if payout keys are set. The
                    // candidate carries the authoritative anchor/tx_root/target
                    // and is stashed so a winning nonce can be assembled into a
                    // submittable block. Without payout keys the pool can only
                    // hand out (legacy) shares-only jobs.
                    let (anchor, tx_root, target, job_height) = match (payout_spend, payout_view) {
                        (Some(spend), Some(view)) => {
                            match block_builder::build_candidate_block(
                                &chain,
                                &mempool,
                                &spend,
                                &view,
                                chain.network(),
                                crate::consensus::fork_signal::SignalBits(0),
                            ) {
                                Ok(cand) => {
                                    let (a, t, h) = cand.pow_inputs();
                                    let tgt = cand.header.target;
                                    // Keep only the current job's candidate — a new
                                    // job only fires on a tip change, so older
                                    // candidates are for a superseded tip and can
                                    // never produce a canonical block.
                                    let mut c = candidates.write().await;
                                    c.clear();
                                    c.insert(job_id.clone(), cand);
                                    (a, t, tgt, h)
                                }
                                Err(e) => {
                                    warn!("stratum: build_candidate_block failed: {e}; retrying");
                                    tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
                                    continue;
                                }
                            }
                        }
                        _ => (
                            Hash::zero(),
                            Hash::zero(),
                            Hash::from_difficulty(share_difficulty),
                            height,
                        ),
                    };
                    let seed_hash = crate::consensus::randomx_seed_for_height(job_height);

                    let job = MiningJob {
                        job_id: job_id.clone(),
                        anchor,
                        tx_root,
                        seed_hash,
                        target,
                        height: job_height,
                        prev_hash: tip,
                        coinbase1: create_coinbase_prefix(height),
                        coinbase2: create_coinbase_suffix(),
                        merkle_branches: compute_merkle_branches(&mempool),
                        version: 1,
                        nbits: difficulty_to_nbits(share_difficulty),
                        ntime: timestamp,
                        clean_jobs: true,
                    };

                    // Update current job
                    *current_job.write().await = Some(job.clone());

                    // Broadcast to all workers
                    let _ = job_broadcast.send(job);

                    info!(
                        "New mining job: height={} block_production={}",
                        job_height,
                        payout_spend.is_some()
                    );
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
        let nonce_dedup = self.nonce_dedup.clone();
        let mut job_rx = self.job_broadcast.subscribe();
        let stats = self.stats.clone();
        let chain = self.chain.clone();
        let mempool = self.mempool.clone();
        let candidates = self.candidates.clone();
        let p2p = self.p2p.clone();
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
                payout_login: String::new(),
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
                                let notify = format_cync_job_notify(&job, share_difficulty);
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
                        warn!(
                            "Worker {} sent oversized message (>{} bytes), disconnecting",
                            worker_id, MAX_LINE_LENGTH
                        );
                        break;
                    }
                    Ok(_) => {
                        if let Some(response) = handle_stratum_message(
                            &line,
                            worker_id,
                            &workers,
                            &current_job,
                            &nonce_dedup,
                            &candidates,
                            &stats,
                            &chain,
                            &mempool,
                            p2p.as_ref(),
                            share_difficulty,
                            required_password.as_deref(),
                            &addr.ip().to_string(),
                            &bans,
                            banlist_path.as_ref(),
                        )
                        .await
                        {
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
/// Assemble the stored candidate for `job_id` with the winning `nonce`, submit
/// it through the validated chain path, and broadcast on acceptance. Shared by
/// the legacy and CoinCync-native submit paths.
/// Submit a mined candidate and broadcast it if the chain accepts it. Returns
/// `true` iff the block was accepted by the chain — the caller uses this to count
/// chain-accepted blocks separately from PoW solutions (issue #42).
async fn submit_and_broadcast(
    candidates: &Arc<RwLock<HashMap<String, CandidateBlock>>>,
    chain: &SharedBlockchain,
    mempool: &SharedMempool,
    p2p: Option<&Arc<crate::network::P2PNode>>,
    job_id: &str,
    nonce: u64,
    worker_id: u64,
) -> bool {
    let cand = candidates.read().await.get(job_id).cloned();
    match cand {
        Some(cand) => {
            let block = cand.into_block(nonce);
            // Clone for broadcast before submit consumes the block.
            let block_for_broadcast = p2p.map(|_| block.clone());
            match block_builder::submit_mined_block(chain, mempool, block) {
                Ok(status) => {
                    info!("stratum: block from worker {} submitted — {:?}", worker_id, status);
                    let accepted = matches!(
                        status,
                        crate::chain::BlockStatus::Accepted
                            | crate::chain::BlockStatus::AcceptedFork
                            | crate::chain::BlockStatus::AcceptedReorg { .. }
                    );
                    if accepted {
                        if let (Some(p2p), Some(b)) = (p2p, block_for_broadcast) {
                            let update = p2p.next_chain_update();
                            p2p.set_chain_state(update).await;
                            if let Err(e) = p2p.broadcast_block(&b).await {
                                warn!("stratum: block broadcast failed: {}", e);
                            }
                        }
                    }
                    accepted
                }
                Err(e) => {
                    warn!("stratum: block submit failed: {}", e);
                    false
                }
            }
        }
        None => {
            warn!(
                "stratum: block found for job {} but no candidate stored \
                 (shares-only pool, or the job was superseded)",
                job_id
            );
            false
        }
    }
}

/// The CoinCync mining job as a JSON object. A miner varies a u64 `nonce` and
/// wins when `compute_pow_hash(RandomX, anchor, nonce, tx_root, height)` —
/// i.e. `RandomX(seed_hash, blake3(anchor ‖ nonce_le ‖ tx_root))` — meets
/// `target`. This is CoinCync's OWN protocol; it is not Monero/xmrig blob
/// mining (our PoW folds the nonce through blake3, which xmrig does not do).
///
/// The effective share difficulty for a job: the requested share difficulty,
/// clamped so the share target is **never harder than the block target** (issue
/// #44). Without the clamp a rig would skip nonces that meet the block target but
/// not an over-hard share target — throwing away valid blocks.
fn effective_share_difficulty(requested: u64, block_target: &Hash) -> u64 {
    let block_difficulty = block_target.to_difficulty().max(1);
    requested.min(block_difficulty).max(1)
}

/// The job as sent on the wire. Emits **distinct** `share_target` and
/// `block_target` (issue #44) so the two meanings are never conflated; `target`
/// is kept as an alias of `share_target` for older clients. The share target is
/// the (clamped) threshold the miner aims for at a steady rate; the server still
/// checks every share against `block_target` and submits a block when one is met.
fn cync_job_json(job: &MiningJob, share_difficulty: u64) -> serde_json::Value {
    let block_target = job.target;
    let share_target =
        Hash::from_difficulty(effective_share_difficulty(share_difficulty, &block_target));
    serde_json::json!({
        "job_id": job.job_id,
        "algo": "cync/rx",
        "anchor": hex::encode(job.anchor.as_bytes()),
        "tx_root": hex::encode(job.tx_root.as_bytes()),
        "seed_hash": hex::encode(job.seed_hash),
        "share_target": hex::encode(share_target.as_bytes()),
        "block_target": hex::encode(block_target.as_bytes()),
        "target": hex::encode(share_target.as_bytes()),
        "height": job.height,
    })
}

/// A pushed `job` notification (sent to a logged-in miner on a tip change).
fn format_cync_job_notify(job: &MiningJob, share_difficulty: u64) -> String {
    serde_json::json!({
        "jsonrpc": "2.0",
        "method": "job",
        "params": cync_job_json(job, share_difficulty),
    })
    .to_string()
}

/// Server-owned, per-canonical-job accepted-nonce ledger.
///
/// SECURITY (share-replay): deduplication MUST be owned by the server and keyed
/// by the *current canonical* job — never by per-worker state or a client-supplied
/// `job_id`. Per-worker sets let the same PoW nonce be re-credited from a second
/// connection (the extranonce fields are not part of the CoinCync PoW, which is
/// `H(anchor, nonce, tx_root, height)`), and clearing the set on a client-supplied
/// id lets a miner toggle a stale id to wipe the set and replay. This ledger holds
/// the accepted nonces for exactly one canonical job and resets when the canonical
/// job rotates.
#[derive(Default)]
struct JobNonceLedger {
    /// The canonical job_id these nonces belong to (server-chosen).
    job_id: String,
    /// Nonces already credited under `job_id`. Keyed by `u64` to cover the
    /// native path's 64-bit nonce; the legacy path widens its `u32` nonce.
    nonces: std::collections::HashSet<u64>,
}

/// Outcome of trying to claim a `(job, nonce)` against the canonical ledger.
#[derive(Debug, PartialEq, Eq)]
enum NonceClaim {
    /// First time this nonce is seen for the current canonical job.
    Accepted,
    /// The submitted job_id is not the current canonical job (checked before the
    /// ledger is touched, so a stale id can never wipe the accepted set).
    StaleJob,
    /// This nonce was already credited under the current canonical job.
    Duplicate,
}

/// Claim `(submitted_job_id, nonce)` against the server-owned canonical ledger.
///
/// Rejects a stale/non-current job id *before* modifying the ledger, resets the
/// ledger when the canonical job rotates, and returns a clone of the canonical
/// [`MiningJob`] so the caller hashes against the exact job it claimed. Dedup is
/// on `nonce` alone — that is the only client-supplied input to the PoW.
async fn claim_canonical_nonce(
    current_job: &Arc<RwLock<Option<MiningJob>>>,
    ledger: &Arc<RwLock<JobNonceLedger>>,
    submitted_job_id: &str,
    nonce: u64,
) -> (NonceClaim, Option<MiningJob>) {
    let job = match current_job.read().await.as_ref() {
        Some(j) => j.clone(),
        None => return (NonceClaim::StaleJob, None),
    };
    // Reject stale/non-current ids BEFORE touching the ledger — a stale id must
    // never be able to clear the accepted-nonce set for the real job.
    if job.job_id != submitted_job_id {
        return (NonceClaim::StaleJob, Some(job));
    }
    let mut led = ledger.write().await;
    if led.job_id != job.job_id {
        // Canonical job rotated: this is the first submit for the new job.
        led.job_id = job.job_id.clone();
        led.nonces.clear();
    }
    if !led.nonces.insert(nonce) {
        return (NonceClaim::Duplicate, Some(job));
    }
    (NonceClaim::Accepted, Some(job))
}

/// Re-read the canonical job and confirm it is still `expected_job_id`.
///
/// Called after RandomX hashing and before any share accounting or block
/// submission: if the canonical job rotated during the hash, the result is stale
/// and must not be credited or broadcast.
async fn canonical_job_unchanged(
    current_job: &Arc<RwLock<Option<MiningJob>>>,
    expected_job_id: &str,
) -> bool {
    matches!(current_job.read().await.as_ref(), Some(j) if j.job_id == expected_job_id)
}

#[allow(clippy::too_many_arguments)]
async fn handle_stratum_message(
    message: &str,
    worker_id: u64,
    workers: &Arc<RwLock<HashMap<u64, Worker>>>,
    current_job: &Arc<RwLock<Option<MiningJob>>>,
    nonce_dedup: &Arc<RwLock<JobNonceLedger>>,
    candidates: &Arc<RwLock<HashMap<String, CandidateBlock>>>,
    stats: &Arc<RwLock<StratumStats>>,
    chain: &SharedBlockchain,
    mempool: &SharedMempool,
    p2p: Option<&Arc<crate::network::P2PNode>>,
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
        // ===== CoinCync-native protocol: login / job / submit / keepalived =====
        "login" => {
            let login_name = params.get("login").and_then(|v| v.as_str()).unwrap_or("cync");
            let pass = params.get("pass").and_then(|v| v.as_str()).unwrap_or("");
            if let Some(expected) = required_password {
                if pass.len() != expected.len()
                    || !crate::crypto::ct_eq(pass.as_bytes(), expected.as_bytes())
                {
                    warn!("login: worker {} failed password", worker_id);
                    register_stratum_strike(bans, banlist_path, client_ip, 5).await;
                    return Some(
                        serde_json::json!({"id": id.clone(), "jsonrpc": "2.0",
                            "result": serde_json::Value::Null,
                            "error": {"code": -1, "message": "unauthorized"}})
                        .to_string(),
                    );
                }
            }
            {
                let mut w = workers.write().await;
                if let Some(worker) = w.get_mut(&worker_id) {
                    worker.name = login_name.to_string();
                    // Credit this miner's shares to their login (conventionally
                    // <miner_address>.<worker>). The operator pays out on this.
                    worker.payout_login = login_name.to_string();
                    worker.authorized = true;
                    worker.last_activity = timestamp_now();
                }
            }
            info!("login: worker {} authorized as {}", worker_id, login_name);
            let job_val = current_job
                .read()
                .await
                .as_ref()
                .map(|j| cync_job_json(j, share_difficulty))
                .unwrap_or(serde_json::Value::Null);
            Some(
                serde_json::json!({
                    "id": id.clone(), "jsonrpc": "2.0",
                    "result": {"id": format!("{:08x}", worker_id), "job": job_val, "status": "OK"},
                    "error": serde_json::Value::Null
                })
                .to_string(),
            )
        }

        "submit" => {
            // Params: {id: <session>, job_id, nonce (hex u64)}.
            {
                let wr = workers.read().await;
                if !wr.get(&worker_id).map(|w| w.authorized).unwrap_or(false) {
                    return Some(
                        serde_json::json!({"id": id.clone(), "jsonrpc": "2.0",
                            "result": serde_json::Value::Null,
                            "error": {"code": -1, "message": "unauthenticated"}})
                        .to_string(),
                    );
                }
            }
            let sub_job_id = params.get("job_id").and_then(|v| v.as_str()).unwrap_or("");
            let nonce_hex = params.get("nonce").and_then(|v| v.as_str()).unwrap_or("");
            let nonce = match u64::from_str_radix(nonce_hex.trim_start_matches("0x"), 16) {
                Ok(n) => n,
                Err(_) => {
                    return Some(
                        serde_json::json!({"id": id.clone(), "jsonrpc": "2.0",
                            "result": serde_json::Value::Null,
                            "error": {"code": -1, "message": "bad nonce"}})
                        .to_string(),
                    )
                }
            };
            // Cadence throttle.
            {
                let now_ms = timestamp_now_ms();
                let mut ww = workers.write().await;
                if let Some(w) = ww.get_mut(&worker_id) {
                    if w.last_submit_ms > 0
                        && now_ms.saturating_sub(w.last_submit_ms) < MIN_SUBMIT_INTERVAL_MS
                    {
                        return Some(
                            serde_json::json!({"id": id.clone(), "jsonrpc": "2.0",
                                "result": serde_json::Value::Null,
                                "error": {"code": -1, "message": "throttled"}})
                            .to_string(),
                        );
                    }
                    w.last_submit_ms = now_ms;
                    w.last_activity = timestamp_now();
                }
            }
            // Server-owned per-canonical-job dedup. Rejects a stale/non-current
            // job id BEFORE touching the ledger (so it can't wipe the accepted
            // set) and rejects a replayed nonce before any PoW is recomputed.
            // Returns the canonical job so we hash against exactly what we claimed.
            let job = match claim_canonical_nonce(current_job, nonce_dedup, sub_job_id, nonce).await
            {
                (NonceClaim::Accepted, Some(j)) => j,
                (NonceClaim::Duplicate, _) => {
                    let mut wr = workers.write().await;
                    if let Some(w) = wr.get_mut(&worker_id) {
                        w.invalid_shares += 1;
                        w.invalid_streak = w.invalid_streak.saturating_add(1);
                    }
                    return Some(
                        serde_json::json!({"id": id.clone(), "jsonrpc": "2.0",
                            "result": serde_json::Value::Null,
                            "error": {"code": -1, "message": "duplicate share"}})
                        .to_string(),
                    );
                }
                _ => {
                    return Some(
                        serde_json::json!({"id": id.clone(), "jsonrpc": "2.0",
                            "result": serde_json::Value::Null,
                            "error": {"code": -1, "message": "stale job"}})
                        .to_string(),
                    )
                }
            };
            let pow = match crate::consensus::compute_pow_hash(
                crate::consensus::PowAlgorithm::RandomX,
                &job.anchor,
                nonce,
                &job.tx_root,
                job.height,
            ) {
                Ok(h) => h,
                Err(_) => {
                    return Some(
                        serde_json::json!({"id": id.clone(), "jsonrpc": "2.0",
                            "result": serde_json::Value::Null,
                            "error": {"code": -1, "message": "hash error"}})
                        .to_string(),
                    )
                }
            };
            if !pow
                .meets_difficulty(&Hash::from_difficulty(effective_share_difficulty(
                    share_difficulty,
                    &job.target,
                ))) {
                let mut wr = workers.write().await;
                if let Some(w) = wr.get_mut(&worker_id) {
                    w.invalid_shares += 1;
                }
                return Some(
                    serde_json::json!({"id": id.clone(), "jsonrpc": "2.0",
                        "result": serde_json::Value::Null,
                        "error": {"code": -1, "message": "low difficulty share"}})
                    .to_string(),
                );
            }
            // Revalidate: if the canonical job rotated during RandomX hashing, this
            // share is for a stale template — do not credit it or submit a block.
            if !canonical_job_unchanged(current_job, &job.job_id).await {
                let mut wr = workers.write().await;
                if let Some(w) = wr.get_mut(&worker_id) {
                    w.stale_shares += 1;
                }
                stats.write().await.stale_shares += 1;
                return Some(
                    serde_json::json!({"id": id.clone(), "jsonrpc": "2.0",
                        "result": serde_json::Value::Null,
                        "error": {"code": -1, "message": "stale job"}})
                    .to_string(),
                );
            }
            {
                let mut wr = workers.write().await;
                if let Some(w) = wr.get_mut(&worker_id) {
                    w.valid_shares += 1;
                    w.invalid_streak = 0;
                }
                let mut s = stats.write().await;
                s.total_shares += 1;
                s.valid_shares += 1;
            }
            if pow.meets_difficulty(&job.target) {
                // A PoW solution is a "hit"; whether it becomes a chain-accepted
                // block is reported separately (issue #42).
                stats.write().await.block_pow_hits += 1;
                info!("submit: PoW block solution by worker {} (job {})", worker_id, sub_job_id);
                let accepted =
                    submit_and_broadcast(candidates, chain, mempool, p2p, &job.job_id, nonce, worker_id)
                        .await;
                if accepted {
                    stats.write().await.blocks_found += 1;
                }
                return Some(
                    serde_json::json!({"id": id.clone(), "jsonrpc": "2.0",
                        "result": {"status": "OK",
                            "block": if accepted { "accepted" } else { "rejected" }},
                        "error": serde_json::Value::Null})
                    .to_string(),
                );
            }
            Some(
                serde_json::json!({"id": id.clone(), "jsonrpc": "2.0",
                    "result": {"status": "OK"}, "error": serde_json::Value::Null})
                .to_string(),
            )
        }

        "keepalived" => Some(
            serde_json::json!({"id": id.clone(), "jsonrpc": "2.0",
                "result": {"status": "KEEPALIVED"}, "error": serde_json::Value::Null})
            .to_string(),
        ),

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
                if !workers_read
                    .get(&worker_id)
                    .map(|w| w.authorized)
                    .unwrap_or(false)
                {
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
                            warn!(
                                "Worker {} hit submit-rate abuse threshold; deauthorizing",
                                worker_id
                            );
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

            // Worker's extranonce1 (for share verification only).
            let extranonce1 = {
                let wr = workers.read().await;
                wr.get(&worker_id).map(|w| w.extranonce1.clone()).unwrap_or_default()
            };

            // Server-owned per-canonical-job dedup. Rejects a stale/non-current
            // job id BEFORE touching the ledger (so a stale id cannot wipe the
            // accepted set) and rejects a replayed nonce across ALL worker
            // connections before verify() recomputes the PoW. Dedup is on the
            // PoW nonce — the extranonce fields are not part of the CoinCync PoW.
            let (claim, canonical_job) =
                claim_canonical_nonce(current_job, nonce_dedup, job_id, nonce as u64).await;

            // Build share struct
            let share = Share {
                worker: worker_name.to_string(),
                job_id: job_id.to_string(),
                extranonce2,
                ntime,
                nonce,
            };

            // A duplicate/stale claim short-circuits before paying for PoW.
            let share_result = match claim {
                NonceClaim::StaleJob => ShareResult::Stale,
                NonceClaim::Duplicate => ShareResult::Duplicate,
                NonceClaim::Accepted => match canonical_job.as_ref() {
                    Some(job) => share.verify(job, share_difficulty, &extranonce1),
                    None => ShareResult::Stale,
                },
            };

            // Revalidate the canonical job AFTER verify()'s (RandomX) hashing and
            // BEFORE any accounting: if the server's canonical job rotated during
            // the hash, a Valid/Block result was computed against a stale template
            // and must not be credited to worker/pool stats (nor submitted). The
            // native path already revalidates before crediting; the legacy path
            // previously only revalidated before block submission, so a rotation
            // during verify() still credited a stale share to stats. Downgrade to
            // Stale here so both the stats blocks below and the submission guard
            // see the corrected result. (audit #35, junbyjun1238)
            let share_result = match share_result {
                ShareResult::Valid | ShareResult::Block(_)
                    if !canonical_job_unchanged(current_job, job_id).await =>
                {
                    ShareResult::Stale
                }
                other => other,
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
                        // PoW solution; chain acceptance is counted after submit
                        // (issue #42).
                        s.block_pow_hits += 1;
                        info!(
                            "PoW block solution by worker {}! Hash: {}",
                            worker_id,
                            hex::encode(hash.as_bytes())
                        );
                    }
                    ShareResult::Stale => s.stale_shares += 1,
                    ShareResult::Invalid | ShareResult::Duplicate => s.invalid_shares += 1,
                }
            }

            // A real block was found — assemble the stored candidate with the
            // winning nonce and submit + broadcast it. Revalidate first: if the
            // canonical job rotated during verify()'s hashing, the candidate is
            // stale and must not be submitted or broadcast.
            if matches!(share_result, ShareResult::Block(_)) {
                if canonical_job_unchanged(current_job, job_id).await {
                    let accepted = submit_and_broadcast(
                        candidates,
                        chain,
                        mempool,
                        p2p,
                        job_id,
                        share.nonce as u64,
                        worker_id,
                    )
                    .await;
                    if accepted {
                        stats.write().await.blocks_found += 1;
                    }
                } else {
                    warn!(
                        "submit: worker {} found a block for a rotated job {}; not broadcasting stale candidate",
                        worker_id, job_id
                    );
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
                ShareResult::Stale => Some(format!(
                    r#"{{"id":{},"result":false,"error":[21,"Stale share",null]}}"#,
                    id
                )),
                ShareResult::Invalid => Some(format!(
                    r#"{{"id":{},"result":false,"error":[23,"Low difficulty share",null]}}"#,
                    id
                )),
                ShareResult::Duplicate => Some(format!(
                    r#"{{"id":{},"result":false,"error":[22,"Duplicate share",null]}}"#,
                    id
                )),
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
    let merkle: Vec<String> = job
        .merkle_branches
        .iter()
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
                crate::primitives::hash_concat(&[chunk[0].as_bytes(), chunk[1].as_bytes()])
            } else {
                crate::primitives::hash_concat(&[chunk[0].as_bytes(), chunk[0].as_bytes()])
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
    let mantissa = if shift_amount >= 24 {
        0u32
    } else {
        0xFFFFFF >> shift_amount
    };

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
        Ok(raw) => {
            serde_json::from_str::<HashMap<String, PersistedBanEntry>>(&raw).unwrap_or_else(|e| {
                warn!("Failed to parse Stratum banlist {}: {}", path.display(), e);
                HashMap::new()
            })
        }
        Err(_) => HashMap::new(),
    }
}

fn persist_banlist(path: &PathBuf, bans: &HashMap<String, PersistedBanEntry>) {
    if let Ok(raw) = serde_json::to_string_pretty(bans) {
        if let Err(e) = std::fs::write(path, raw) {
            warn!(
                "Failed to persist Stratum banlist {}: {}",
                path.display(),
                e
            );
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
            anchor: Hash::zero(),
            tx_root: Hash::zero(),
            seed_hash: [0u8; 32],
            target: Hash::from_difficulty(1000),
            height: 100,
            prev_hash: Hash::zero(),
            coinbase1: vec![0, 1, 2, 3],
            coinbase2: vec![4, 5, 6, 7],
            merkle_branches: vec![],
            version: 1,
            nbits: 0x1d00ffff,
            ntime: 1234567890,
            clean_jobs: true,
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
            payout_login: "w".to_string(),
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
            anchor: Hash::zero(),
            tx_root: Hash::zero(),
            seed_hash: [0u8; 32],
            target: Hash::from_difficulty(1000),
            height: 1,
            prev_hash: Hash::zero(),
            coinbase1: vec![],
            coinbase2: vec![],
            merkle_branches: vec![],
            version: 1,
            nbits: 0x1d00ffff,
            ntime: 1,
            clean_jobs: true,
        })));
        let stats = Arc::new(RwLock::new(StratumStats::default()));
        let nonce_dedup = Arc::new(RwLock::new(JobNonceLedger::default()));
        let bans = Arc::new(RwLock::new(HashMap::<String, PersistedBanEntry>::new()));
        let chain = Arc::new(crate::chain::Blockchain::new());
        let mempool = crate::mempool::SharedMempool::new();
        let candidates = Arc::new(RwLock::new(HashMap::<String, CandidateBlock>::new()));

        let submit = r#"{"id":1,"method":"mining.submit","params":["w","job-1","00","00000001","00000001"]}"#;
        let resp = handle_stratum_message(
            submit,
            worker_id,
            &workers,
            &current_job,
            &nonce_dedup,
            &candidates,
            &stats,
            &chain,
            &mempool,
            None,
            1000,
            None,
            "198.51.100.77",
            &bans,
            None,
        )
        .await
        .expect("response");
        assert!(resp.contains("Throttled submit rate"));

        let guard = workers.read().await;
        let updated = guard.get(&worker_id).expect("worker still present");
        assert!(
            !updated.authorized,
            "worker should be deauthorized at streak threshold"
        );
        drop(guard);

        let bans_guard = bans.read().await;
        assert!(
            bans_guard.get("198.51.100.77").is_some(),
            "throttled submit should register strike"
        );
    }

    /// Stage-3 milestone: an authorized worker submits a REAL winning nonce and
    /// the in-node pool assembles the stored candidate + submits it, advancing
    /// the chain. This is the end-to-end "the pool produces blocks" proof.
    /// `#[ignore]` — builds a RandomX cache and mines a block (~seconds). Run:
    ///   cargo test -p coincync --features "randomx testnet" --lib -- --ignored stratum_submit_produces_block
    #[tokio::test]
    #[ignore]
    async fn stratum_submit_produces_block() {
        std::env::set_var("COINCYNC_RANDOMX_LIGHT_MODE", "1");
        use crate::consensus::{compute_pow_hash, PowAlgorithm};
        let net = crate::config::NetworkType::Testnet;
        crate::consensus::bind_randomx_genesis_for_network(net);

        // Fresh chain + mempool + payout keys.
        let chain: SharedBlockchain = Arc::new(crate::chain::Blockchain::new());
        chain.init_genesis().expect("genesis");
        let mempool = crate::mempool::SharedMempool::new();
        let spend = crate::primitives::SecretKey::from_bytes([7u8; 32]).public_key();
        let view = crate::primitives::SecretKey::from_bytes([9u8; 32]).public_key();

        // Build the candidate the job updater would, and a matching job.
        let cand = block_builder::build_candidate_block(
            &chain,
            &mempool,
            &spend,
            &view,
            net,
            crate::consensus::fork_signal::SignalBits(0),
        )
        .expect("candidate");
        let (anchor, tx_root, height) = cand.pow_inputs();
        let target = cand.header.target;
        let job_id = "job-1".to_string();

        // Mine a u32 nonce meeting the block target (floor difficulty on a fresh chain).
        let mut nonce: u32 = 0;
        let winning = loop {
            let h = compute_pow_hash(PowAlgorithm::RandomX, &anchor, nonce as u64, &tx_root, height)
                .expect("hash");
            if h.meets_difficulty(&target) {
                break nonce;
            }
            nonce = nonce.checked_add(1).expect("nonce found within u32 at floor difficulty");
        };

        // Stash candidate + job.
        let candidates = Arc::new(RwLock::new(HashMap::<String, CandidateBlock>::new()));
        candidates.write().await.insert(job_id.clone(), cand);
        let current_job = Arc::new(RwLock::new(Some(MiningJob {
            job_id: job_id.clone(),
            anchor,
            tx_root,
            seed_hash: crate::consensus::randomx_seed_for_height(height),
            target,
            height,
            prev_hash: chain.tip_hash(),
            coinbase1: vec![],
            coinbase2: vec![],
            merkle_branches: vec![],
            version: 1,
            nbits: 0,
            ntime: 0,
            clean_jobs: true,
        })));

        // Authorized worker, no prior submit (so not throttled).
        let worker_id = 1u64;
        let (tx, _rx) = mpsc::channel::<String>(4);
        let worker = Worker {
            name: "w".to_string(),
            payout_login: "w".to_string(),
            address: None,
            extranonce1: vec![0, 0, 0, 0],
            shares: 0,
            valid_shares: 0,
            stale_shares: 0,
            invalid_shares: 0,
            difficulty: 1000,
            authorized: true,
            last_submit_ms: 0,
            invalid_streak: 0,
            last_activity: timestamp_now(),
            tx,
        };
        let workers = Arc::new(RwLock::new(HashMap::<u64, Worker>::new()));
        workers.write().await.insert(worker_id, worker);
        let stats = Arc::new(RwLock::new(StratumStats::default()));
        let nonce_dedup = Arc::new(RwLock::new(JobNonceLedger::default()));
        let bans = Arc::new(RwLock::new(HashMap::<String, PersistedBanEntry>::new()));

        // Submit the winning nonce through the real handler.
        let submit = format!(
            r#"{{"id":1,"method":"mining.submit","params":["w","{}","00","00000000","{:08x}"]}}"#,
            job_id, winning
        );
        let resp = handle_stratum_message(
            &submit,
            worker_id,
            &workers,
            &current_job,
            &nonce_dedup,
            &candidates,
            &stats,
            &chain,
            &mempool,
            None,
            1000,
            None,
            "127.0.0.1",
            &bans,
            None,
        )
        .await
        .expect("response");

        assert!(resp.contains("\"result\":true"), "share accepted: {resp}");
        assert_eq!(chain.height(), 1, "pool submitted the block; tip advanced");
        assert_eq!(stats.read().await.blocks_found, 1, "one block found");
    }

    /// Stage-7 milestone: the CoinCync-native protocol end-to-end — `login`
    /// authenticates + returns a job, then `submit` of a real winning u64 nonce
    /// produces + submits the block. This is "our own version" of stratum.
    /// `#[ignore]` — builds a RandomX cache + mines a block.
    #[tokio::test]
    #[ignore]
    async fn cync_login_and_submit_produces_block() {
        std::env::set_var("COINCYNC_RANDOMX_LIGHT_MODE", "1");
        use crate::consensus::{compute_pow_hash, PowAlgorithm};
        let net = crate::config::NetworkType::Testnet;
        crate::consensus::bind_randomx_genesis_for_network(net);

        let chain: SharedBlockchain = Arc::new(crate::chain::Blockchain::new());
        chain.init_genesis().expect("genesis");
        let mempool = crate::mempool::SharedMempool::new();
        let spend = crate::primitives::SecretKey::from_bytes([7u8; 32]).public_key();
        let view = crate::primitives::SecretKey::from_bytes([9u8; 32]).public_key();
        let cand = block_builder::build_candidate_block(
            &chain,
            &mempool,
            &spend,
            &view,
            net,
            crate::consensus::fork_signal::SignalBits(0),
        )
        .expect("candidate");
        let (anchor, tx_root, height) = cand.pow_inputs();
        let target = cand.header.target;
        let job_id = "job-1".to_string();

        // Mine a full u64 nonce (the native protocol uses u64 nonces).
        let mut nonce: u64 = 0;
        let winning = loop {
            let h = compute_pow_hash(PowAlgorithm::RandomX, &anchor, nonce, &tx_root, height)
                .expect("hash");
            if h.meets_difficulty(&target) {
                break nonce;
            }
            nonce += 1;
        };

        let candidates = Arc::new(RwLock::new(HashMap::<String, CandidateBlock>::new()));
        candidates.write().await.insert(job_id.clone(), cand);
        let current_job = Arc::new(RwLock::new(Some(MiningJob {
            job_id: job_id.clone(),
            anchor,
            tx_root,
            seed_hash: crate::consensus::randomx_seed_for_height(height),
            target,
            height,
            prev_hash: chain.tip_hash(),
            coinbase1: vec![],
            coinbase2: vec![],
            merkle_branches: vec![],
            version: 1,
            nbits: 0,
            ntime: 0,
            clean_jobs: true,
        })));

        // Worker starts UNauthorized — login authorizes it.
        let worker_id = 1u64;
        let (tx, _rx) = mpsc::channel::<String>(4);
        let worker = Worker {
            name: String::new(),
            payout_login: "pool.w".to_string(),
            address: None,
            extranonce1: vec![0, 0, 0, 0],
            shares: 0,
            valid_shares: 0,
            stale_shares: 0,
            invalid_shares: 0,
            difficulty: 1000,
            authorized: false,
            last_submit_ms: 0,
            invalid_streak: 0,
            last_activity: timestamp_now(),
            tx,
        };
        let workers = Arc::new(RwLock::new(HashMap::<u64, Worker>::new()));
        workers.write().await.insert(worker_id, worker);
        let stats = Arc::new(RwLock::new(StratumStats::default()));
        let nonce_dedup = Arc::new(RwLock::new(JobNonceLedger::default()));
        let bans = Arc::new(RwLock::new(HashMap::<String, PersistedBanEntry>::new()));

        // login
        let login = r#"{"id":1,"method":"login","params":{"login":"pool.w","pass":"","algo":["cync/rx"]}}"#;
        let resp = handle_stratum_message(
            login, worker_id, &workers, &current_job, &nonce_dedup, &candidates, &stats, &chain, &mempool, None,
            1000, None, "127.0.0.1", &bans, None,
        )
        .await
        .expect("login response");
        assert!(resp.contains("\"status\":\"OK\""), "login OK: {resp}");
        assert!(resp.contains(&job_id), "login returns the current job");

        // submit the winning nonce
        let submit = format!(
            r#"{{"id":2,"method":"submit","params":{{"id":"sess","job_id":"{}","nonce":"{:x}"}}}}"#,
            job_id, winning
        );
        let resp2 = handle_stratum_message(
            &submit, worker_id, &workers, &current_job, &nonce_dedup, &candidates, &stats, &chain, &mempool, None,
            1000, None, "127.0.0.1", &bans, None,
        )
        .await
        .expect("submit response");
        assert!(resp2.contains("\"status\":\"OK\""), "submit OK: {resp2}");
        assert_eq!(chain.height(), 1, "native submit produced a block; tip advanced");
        assert_eq!(stats.read().await.blocks_found, 1, "one block found");
    }

    // ── Share-replay defense: server-owned per-canonical-job nonce ledger ──

    fn mk_job(job_id: &str) -> MiningJob {
        MiningJob {
            job_id: job_id.to_string(),
            anchor: Hash::zero(),
            tx_root: Hash::zero(),
            seed_hash: [0u8; 32],
            target: Hash::from_difficulty(1000),
            height: 1,
            prev_hash: Hash::zero(),
            coinbase1: vec![],
            coinbase2: vec![],
            merkle_branches: vec![],
            version: 1,
            nbits: 0x1d00ffff,
            ntime: 1,
            clean_jobs: true,
        }
    }

    /// A stale/non-current job id must be rejected BEFORE the ledger is touched,
    /// so it cannot be used to wipe the accepted-nonce set for the real job.
    #[tokio::test]
    async fn claim_rejects_stale_job_id_without_clearing_ledger() {
        let cur = Arc::new(RwLock::new(Some(mk_job("aaaa"))));
        let led = Arc::new(RwLock::new(JobNonceLedger::default()));

        assert_eq!(
            claim_canonical_nonce(&cur, &led, "aaaa", 7).await.0,
            NonceClaim::Accepted
        );
        // Attacker toggles a stale id to try to clear the set.
        assert_eq!(
            claim_canonical_nonce(&cur, &led, "deadbeef", 7).await.0,
            NonceClaim::StaleJob
        );
        // The ledger was untouched: the real (aaaa, 7) is still a duplicate.
        assert_eq!(
            claim_canonical_nonce(&cur, &led, "aaaa", 7).await.0,
            NonceClaim::Duplicate
        );
    }

    /// The ledger is server-owned (no worker identity), so the same nonce
    /// replayed from a second connection for the same canonical job is a
    /// duplicate — the extranonce fields are not part of the PoW.
    #[tokio::test]
    async fn claim_dedups_same_nonce_across_workers() {
        let cur = Arc::new(RwLock::new(Some(mk_job("job1"))));
        let led = Arc::new(RwLock::new(JobNonceLedger::default()));

        // Worker A submits nonce 42.
        assert_eq!(
            claim_canonical_nonce(&cur, &led, "job1", 42).await.0,
            NonceClaim::Accepted
        );
        // Worker B replays the SAME nonce for the same job → duplicate.
        assert_eq!(
            claim_canonical_nonce(&cur, &led, "job1", 42).await.0,
            NonceClaim::Duplicate
        );
        // A different nonce is still creditable.
        assert_eq!(
            claim_canonical_nonce(&cur, &led, "job1", 43).await.0,
            NonceClaim::Accepted
        );
    }

    /// When the canonical job rotates the ledger resets, and a stale id for the
    /// previous job is rejected.
    #[tokio::test]
    async fn claim_resets_on_canonical_job_rotation() {
        let cur = Arc::new(RwLock::new(Some(mk_job("j1"))));
        let led = Arc::new(RwLock::new(JobNonceLedger::default()));

        assert_eq!(claim_canonical_nonce(&cur, &led, "j1", 1).await.0, NonceClaim::Accepted);
        assert_eq!(claim_canonical_nonce(&cur, &led, "j1", 1).await.0, NonceClaim::Duplicate);

        *cur.write().await = Some(mk_job("j2"));
        // Same nonce, new canonical job → accepted again.
        assert_eq!(claim_canonical_nonce(&cur, &led, "j2", 1).await.0, NonceClaim::Accepted);
        // Stale id for the old job is rejected.
        assert_eq!(claim_canonical_nonce(&cur, &led, "j1", 2).await.0, NonceClaim::StaleJob);
    }

    /// Post-hash revalidation catches a job that rotated during hashing.
    #[tokio::test]
    async fn canonical_job_unchanged_detects_rotation() {
        let cur = Arc::new(RwLock::new(Some(mk_job("x"))));
        assert!(canonical_job_unchanged(&cur, "x").await);
        *cur.write().await = Some(mk_job("y"));
        assert!(!canonical_job_unchanged(&cur, "x").await);
        *cur.write().await = None;
        assert!(!canonical_job_unchanged(&cur, "x").await);
    }
}
