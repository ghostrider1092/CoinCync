//! # Auto-Churn — Transaction Graph Poisoning
//!
//! Automatically sends coins to self at random intervals, creating fake
//! transaction graph edges that poison chain analysis. Each churn tx is
//! indistinguishable from a real transfer to another person:
//!
//! - Fresh stealth address each time (standard CoinCync behavior)
//! - CLSAG ring signature with full decoy set
//! - Bulletproofs+ range proof on the amount
//! - Minimal fee (same as real txs — zero-fee would be a fingerprint)
//! - Poisson-distributed timing (not fixed interval)
//! - Variable amounts (not always the same percentage)
//!
//! ## How it works
//!
//! 1. Sleep for a Poisson-distributed random interval
//! 2. Pick a random amount between min_pct and max_pct of spendable balance
//! 3. Generate a fresh stealth address for self
//! 4. Build a standard privacy transaction (CLSAG + BP+)
//! 5. Submit via `send_raw_transaction` RPC
//! 6. Loop
//!
//! ## Constitutional basis
//!
//! Article III (Privacy): transactions are mandatory-private. Auto-churn
//! strengthens the anonymity set by adding indistinguishable noise to
//! the transaction graph.
//!
//! Bill of Rights, Amendment IV: protection against surveillance.
//! Churn makes graph analysis futile even for a state-level adversary.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use tokio::time::{sleep, Duration};
use rand::Rng;
use rand_distr::{Exp, Distribution};
use tracing::{info, warn, debug};
use serde::{Serialize, Deserialize};
use zeroize::Zeroizing;

// ═══════════════════════════════════════════════════════════════════════
// Configuration
// ═══════════════════════════════════════════════════════════════════════

/// Auto-churn configuration.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ChurnConfig {
    /// Whether auto-churn is enabled.
    pub enabled: bool,
    /// Minimum time between churns in seconds.
    pub min_interval_secs: u64,
    /// Maximum time between churns in seconds.
    pub max_interval_secs: u64,
    /// Minimum percentage of spendable balance to churn (1-100).
    pub min_amount_pct: u8,
    /// Maximum percentage of spendable balance to churn (1-100).
    pub max_amount_pct: u8,
    /// Node RPC URL for submitting transactions.
    pub node_url: String,
}

impl Default for ChurnConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            min_interval_secs: 1800,  // 30 minutes
            max_interval_secs: 7200,  // 2 hours
            min_amount_pct: 10,
            max_amount_pct: 50,
            node_url: "http://127.0.0.1:28081".to_string(),
        }
    }
}

impl ChurnConfig {
    /// Validate configuration parameters.
    pub fn validate(&self) -> Result<(), String> {
        if self.min_interval_secs == 0 {
            return Err("min_interval_secs must be > 0".into());
        }
        if self.max_interval_secs < self.min_interval_secs {
            return Err("max_interval_secs must be >= min_interval_secs".into());
        }
        if self.min_amount_pct == 0 || self.min_amount_pct > 100 {
            return Err("min_amount_pct must be 1-100".into());
        }
        if self.max_amount_pct < self.min_amount_pct || self.max_amount_pct > 100 {
            return Err("max_amount_pct must be >= min_amount_pct and <= 100".into());
        }
        Ok(())
    }
}

// ═══════════════════════════════════════════════════════════════════════
// Churn statistics
// ═══════════════════════════════════════════════════════════════════════

/// Runtime statistics for the churn engine.
#[derive(Clone, Debug, Default, Serialize)]
pub struct ChurnStats {
    /// Total churn transactions submitted.
    pub churns_completed: u64,
    /// Total churn attempts that failed.
    pub churns_failed: u64,
    /// Total atomic CYNC churned.
    pub total_churned: u64,
    /// Timestamp of last successful churn (Unix seconds).
    pub last_churn_time: u64,
    /// Whether the churn loop is currently running.
    pub is_running: bool,
}

// ═══════════════════════════════════════════════════════════════════════
// Churn Engine
// ═══════════════════════════════════════════════════════════════════════

/// The auto-churn engine. Runs as a background tokio task alongside
/// the wallet's background_sync task.
pub struct ChurnEngine {
    config: ChurnConfig,
    /// Wallet file path.
    wallet_path: std::path::PathBuf,
    /// Wallet password (held in memory while churn is active).
    ///
    /// SECURITY (R-87 fix, 2026-07-02 + v1.0.13 #5 propagation
    /// 2026-06-14): wrapped in `Zeroizing<String>` so the password
    /// bytes are wiped from the heap allocation when the
    /// `ChurnEngine` is dropped. Prior code held a plain `String`,
    /// meaning shutdown left the plaintext password sitting in the
    /// allocator's freed pool where a subsequent memory dump (core
    /// file, hibernation image, swap) could recover it. `Zeroizing`
    /// runs a `Zeroize` on Drop before the allocation is freed, so
    /// the freed memory contains all-zeros instead of the password.
    ///
    /// The `new()` constructor also takes `Zeroizing<String>` (not
    /// `String`) so the wrapper travels the whole call chain from
    /// the CLI prompt in `bin/wallet.rs` — this closes the pre-v1.0.13
    /// window where the caller's owned `String` sat un-zeroized on
    /// the heap until it was dropped independently of the engine.
    /// ChurnEngine instances live the duration of the auto-churn
    /// session (hours/days) — the largest in-process exposure window
    /// outside WalletData itself.
    wallet_password: Zeroizing<String>,
    /// Shutdown signal.
    shutdown: Arc<AtomicBool>,
    /// Runtime stats.
    stats: Arc<parking_lot::Mutex<ChurnStats>>,
}

impl ChurnEngine {
    /// Create a new churn engine.
    ///
    /// The caller passes an already-`Zeroizing<String>` wrapper for
    /// `wallet_password` (see the struct field docstring for why the
    /// wrapper travels the whole call chain rather than being applied
    /// at the boundary). Engine takes ownership; the memory is wiped
    /// when the engine drops.
    pub fn new(
        config: ChurnConfig,
        wallet_path: std::path::PathBuf,
        wallet_password: Zeroizing<String>,
        shutdown: Arc<AtomicBool>,
    ) -> Result<Self, String> {
        config.validate()?;
        Ok(Self {
            config,
            wallet_path,
            wallet_password,
            shutdown,
            stats: Arc::new(parking_lot::Mutex::new(ChurnStats::default())),
        })
    }

    /// Get current churn statistics.
    pub fn stats(&self) -> ChurnStats {
        self.stats.lock().clone()
    }

    /// Compute the next sleep interval using a Poisson process.
    ///
    /// The Poisson process produces exponentially-distributed inter-arrival
    /// times. We use the mean of min and max as the lambda parameter, then
    /// clamp the result to [min, max]. This makes the timing pattern
    /// unpredictable to an observer — unlike fixed intervals, Poisson
    /// arrivals have no periodic signature.
    fn next_interval_secs(&self) -> u64 {
        let mean = (self.config.min_interval_secs + self.config.max_interval_secs) as f64 / 2.0;
        let lambda = 1.0 / mean;
        let exp = Exp::new(lambda).unwrap_or_else(|_| Exp::new(1.0 / 3600.0).expect("hardcoded 1/3600 is always valid"));

        let mut rng = rand::thread_rng();
        let sample = exp.sample(&mut rng) as u64;

        // Clamp to [min, max]
        sample.clamp(self.config.min_interval_secs, self.config.max_interval_secs)
    }

    /// Pick a random churn amount based on the current spendable balance.
    ///
    /// SECURITY (R-88 fix, 2026-07-02): all arithmetic switched to
    /// saturating operations. Prior code did `spendable_balance * pct`
    /// and `amount + min_fee_reserve` with unchecked ops — for very
    /// large balances (e.g. an exchange hot-wallet holding
    /// > 1.84e17 atomic ≈ 184k CYNC at max_amount_pct=50), the
    /// multiply overflowed u64 in debug (panic) or wrapped in release
    /// (silent nonsense), yielding a churn amount uncorrelated with
    /// the intended percentage. `saturating_mul` clamps at u64::MAX
    /// before the divide, and `saturating_add` on the fee-reserve
    /// comparison keeps the branch selection sane at the top of the
    /// u64 range.
    fn pick_churn_amount(&self, spendable_balance: u64) -> u64 {
        if spendable_balance == 0 {
            return 0;
        }
        let mut rng = rand::thread_rng();
        let pct = rng.gen_range(self.config.min_amount_pct..=self.config.max_amount_pct) as u64;
        // R-88: `spendable_balance * pct` overflows u64 when
        // spendable_balance is near u64::MAX (e.g. an exchange
        // hot-wallet or an adversarial upstream value). Naive
        // saturating_mul clamps at u64::MAX and destroys the
        // percentage intent (50% of u64::MAX ends up being 1% after
        // the /100 because the multiply already saturated). Compute
        // the percentage in u128 to keep every u64×u64 product
        // representable, then narrow back — `pct` is bounded to
        // [1, 100] by ChurnConfig::validate, so the u128 result is
        // <= spendable_balance and always fits back in u64.
        let amount = ((spendable_balance as u128) * (pct as u128) / 100) as u64;
        // Reserve enough for the fee. A typical privacy CLSAG transaction
        // is ~2.5 KB with bulletproof + ring signatures; multiply by
        // MIN_FEE_PER_BYTE and add 50% headroom for congestion multiplier
        // ×1.5 (the punchlist's prior hardcoded 10_000 was ~250× too low
        // and would silently let pick_churn_amount return a value that
        // can't actually pay the on-chain fee, causing the tx-builder to
        // reject the churn attempt).
        const TYPICAL_PRIV_TX_BYTES: u64 = 2_500;
        let min_fee_reserve = TYPICAL_PRIV_TX_BYTES
            .saturating_mul(crate::constants::MIN_FEE_PER_BYTE)
            .saturating_mul(3) / 2; // ×1.5 congestion headroom
        if amount.saturating_add(min_fee_reserve) > spendable_balance {
            spendable_balance.saturating_sub(min_fee_reserve)
        } else {
            amount
        }
    }

    /// Run the churn loop. This is the entry point for the background task.
    ///
    /// Spawns as `tokio::spawn(engine.run())` from the wallet daemon.
    pub async fn run(self) {
        info!(
            min_interval = self.config.min_interval_secs,
            max_interval = self.config.max_interval_secs,
            min_pct = self.config.min_amount_pct,
            max_pct = self.config.max_amount_pct,
            "auto-churn engine started"
        );

        {
            let mut stats = self.stats.lock();
            stats.is_running = true;
        }

        while !self.shutdown.load(Ordering::Relaxed) {
            // Sleep for a Poisson-distributed interval
            let interval_secs = self.next_interval_secs();
            debug!(interval_secs, "churn: sleeping before next churn");

            // Check shutdown every 10 seconds during the sleep
            let mut remaining = interval_secs;
            while remaining > 0 && !self.shutdown.load(Ordering::Relaxed) {
                let chunk = remaining.min(10);
                sleep(Duration::from_secs(chunk)).await;
                remaining -= chunk;
            }

            if self.shutdown.load(Ordering::Relaxed) {
                break;
            }

            // Execute one churn
            match self.execute_churn().await {
                Ok(amount) => {
                    let mut stats = self.stats.lock();
                    stats.churns_completed += 1;
                    stats.total_churned += amount;
                    stats.last_churn_time = unix_now();
                    info!(
                        amount,
                        total_churns = stats.churns_completed,
                        "churn transaction submitted"
                    );
                }
                Err(e) => {
                    let mut stats = self.stats.lock();
                    stats.churns_failed += 1;
                    warn!(error = %e, "churn transaction failed");
                }
            }
        }

        {
            let mut stats = self.stats.lock();
            stats.is_running = false;
        }
        info!("auto-churn engine stopped");
    }

    /// Execute a single churn transaction.
    ///
    /// Opens the wallet, picks a random amount, builds a self-send
    /// transaction, and submits it to the node.
    async fn execute_churn(&self) -> Result<u64, String> {
        use crate::wallet::{Wallet, KeyEpoch};
        use crate::primitives::Amount;
        use crate::transaction::DecoyOutput;

        // Open and unlock wallet
        let mut wallet = Wallet::open(self.wallet_path.clone())
            .map_err(|e| format!("open wallet: {}", e))?;
        wallet.unlock(&self.wallet_password)
            .map_err(|e| format!("unlock wallet: {}", e))?;

        let keys: KeyEpoch = wallet
            .current_keys()
            .cloned()
            .ok_or_else(|| "wallet has no current key epoch".to_string())?;

        // Check balance
        let balance = wallet.balance();
        let spendable = wallet.total_balance();
        let spendable_atomic = spendable.as_atomic();
        if spendable_atomic == 0 {
            return Err("no spendable balance for churn".into());
        }

        let churn_amount = self.pick_churn_amount(spendable_atomic);
        if churn_amount == 0 {
            return Err("churn amount is zero (balance too low)".into());
        }

        debug!(spendable = spendable_atomic, churn_amount, "churn: building self-send");

        // Query chain state from node
        let info = rpc_call_simple(&self.config.node_url, "get_info").await?;
        let current_height = info
            .get("height")
            .and_then(|v| v.as_u64())
            .unwrap_or(0);

        // Fetch decoys
        let ring_size = 16usize;
        let decoys_json = rpc_call(
            &self.config.node_url,
            "get_decoys",
            serde_json::json!([ring_size * 8, 0]),
        )
        .await?;
        let decoys_arr = decoys_json
            .get("decoys")
            .and_then(|v| v.as_array())
            .cloned()
            .unwrap_or_default();

        let mut decoy_pool: Vec<DecoyOutput> = Vec::with_capacity(decoys_arr.len());
        for d in &decoys_arr {
            let pk_hex = d.get("public_key").and_then(|v| v.as_str()).unwrap_or("");
            let commit_hex = d.get("commitment").and_then(|v| v.as_str()).unwrap_or("");
            let height = d.get("height").and_then(|v| v.as_u64()).unwrap_or(0);
            if let (Ok(pk_b), Ok(c_b)) = (hex::decode(pk_hex), hex::decode(commit_hex)) {
                if pk_b.len() == 32 && c_b.len() == 32 {
                    let mut pk_arr = [0u8; 32];
                    let mut c_arr = [0u8; 32];
                    pk_arr.copy_from_slice(&pk_b);
                    c_arr.copy_from_slice(&c_b);
                    decoy_pool.push(DecoyOutput {
                        public_key: crate::primitives::PublicKey::from_bytes(pk_arr),
                        commitment: c_arr,
                        height,
                    });
                }
            }
        }

        if decoy_pool.is_empty() {
            return Err("no decoys available for churn ring".into());
        }

        // Build self-send: recipient is our OWN public keys
        let recipients = vec![(
            keys.spend_public,
            keys.view_public,
            Amount::from_atomic(churn_amount),
        )];

        let mut rng = rand::rngs::OsRng;
        let tx = crate::wallet::send::create_privacy_transaction_with_fee(
            &balance,
            &recipients,
            &keys,
            &decoy_pool,
            current_height,
            1.0, // standard fee — using zero would be a fingerprint
            &mut rng,
        )
        .map_err(|e| format!("build churn tx: {}", e))?;

        let tx_hash = tx.hash();
        let tx_bytes = borsh::to_vec(&tx).map_err(|e| format!("serialize: {}", e))?;
        let tx_hex = hex::encode(&tx_bytes);

        debug!(
            hash = hex::encode(tx_hash.as_bytes()),
            inputs = tx.inputs.len(),
            outputs = tx.outputs.len(),
            amount = churn_amount,
            "churn: submitting self-send"
        );

        // Submit
        let result = rpc_call(
            &self.config.node_url,
            "send_raw_transaction",
            serde_json::json!([tx_hex]),
        )
        .await?;

        let accepted = result
            .get("accepted")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);

        if !accepted {
            return Err(format!("node rejected churn tx: {}", result));
        }

        // Mark UTXOs as spent.
        //
        // AUDIT (R-89 fix, 2026-07-03): pre-fix code marked UTXOs
        // spent in-memory (mark_spent_by_key_image) and then called
        // wallet.save(...). The pre-existing wallet.save persists
        // the state to disk BUT relies on the persistence layer's
        // durability guarantees, which pre-R-37 could delay the
        // fsync arbitrarily. Under a crash between the RPC "accepted"
        // return and the wallet.save's fsync, the wallet came up
        // NOT knowing these UTXOs were spent — the node's mempool
        // + chain already accepted the churn tx, but the wallet
        // would try to spend the same UTXOs again in the next
        // send, producing a rejected double-spend.
        //
        // Fix: after save() returns, explicitly emit a tracing::info
        // marking that the durability boundary has been crossed.
        // The R-37/R-97 fixes at the persistence layer now
        // guarantee that save() implies fsync; this log is the
        // observability contract for that guarantee at the churn
        // level, so an operator sees the crash-safe boundary.
        for ki in tx.key_images() {
            wallet.mark_spent_by_key_image(&ki);
        }
        wallet.save(Some(&self.wallet_password))
            .map_err(|e| format!("save wallet: {}", e))?;
        tracing::info!(
            target: "wallet::churn::R89",
            tx_hash = hex::encode(tx_hash.as_bytes()),
            input_key_images = tx.key_images().len(),
            "R-89: churn spend-marking durable on disk"
        );

        Ok(churn_amount)
    }
}

// ═══════════════════════════════════════════════════════════════════════
// RPC helpers (minimal, self-contained)
// ═══════════════════════════════════════════════════════════════════════

async fn rpc_call(
    node: &str,
    method: &str,
    params: serde_json::Value,
) -> Result<serde_json::Value, String> {
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(15))
        .build()
        .map_err(|e| e.to_string())?;
    let body = serde_json::json!({
        "jsonrpc": "2.0",
        "method": method,
        "params": params,
        "id": 1,
    });
    let resp = client
        .post(node)
        .json(&body)
        .send()
        .await
        .map_err(|e| e.to_string())?;
    let json: serde_json::Value = resp.json().await.map_err(|e| e.to_string())?;
    if let Some(err) = json.get("error") {
        return Err(format!("rpc error: {}", err));
    }
    json.get("result")
        .cloned()
        .ok_or_else(|| "rpc response missing result".into())
}

async fn rpc_call_simple(node: &str, method: &str) -> Result<serde_json::Value, String> {
    rpc_call(node, method, serde_json::json!([])).await
}

fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

// ═══════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_config_is_valid() {
        let config = ChurnConfig::default();
        assert!(config.validate().is_ok());
    }

    #[test]
    fn invalid_config_rejected() {
        let mut config = ChurnConfig::default();
        config.min_interval_secs = 0;
        assert!(config.validate().is_err());

        let mut config = ChurnConfig::default();
        config.max_interval_secs = 100; // less than min (1800)
        assert!(config.validate().is_err());

        let mut config = ChurnConfig::default();
        config.min_amount_pct = 0;
        assert!(config.validate().is_err());

        let mut config = ChurnConfig::default();
        config.max_amount_pct = 101;
        assert!(config.validate().is_err());
    }

    #[test]
    fn churn_amount_respects_bounds() {
        let shutdown = Arc::new(AtomicBool::new(false));
        let engine = ChurnEngine::new(
            ChurnConfig {
                enabled: true,
                min_amount_pct: 10,
                max_amount_pct: 50,
                ..Default::default()
            },
            std::path::PathBuf::from("/tmp/test.wallet"),
            zeroize::Zeroizing::new("test".to_string()),
            shutdown,
        )
        .unwrap();

        // Use a realistic spendable balance — 1 CYNC = 1e12 atomic.
        // The 1_000_000 (= 1 µCYNC) the old test used was smaller
        // than the realistic privacy-tx fee reserve (~3.75M atomic
        // for a 2.5KB CLSAG+bulletproof tx at MIN_FEE_PER_BYTE=1000
        // with ×1.5 congestion headroom), so every pick clamped to
        // 0 after the fee-reserve fix landed. Scaling the balance
        // up keeps the bounds-check intent (10-50% of spendable)
        // testable.
        const BALANCE: u64 = 1_000_000_000_000; // 1 CYNC
        for _ in 0..100 {
            let amount = engine.pick_churn_amount(BALANCE);
            // 10% of 1e12 = 1e11. Fee reserve (~3.75e6) is rounding
            // error at this scale, so the lower bound is essentially
            // the pct calc.
            assert!(amount >= BALANCE / 10, "amount {} too low", amount);
            assert!(amount <= BALANCE / 2, "amount {} too high", amount); // 50%
        }
    }

    #[test]
    fn churn_amount_zero_balance() {
        let shutdown = Arc::new(AtomicBool::new(false));
        let engine = ChurnEngine::new(
            ChurnConfig::default(),
            std::path::PathBuf::from("/tmp/test.wallet"),
            zeroize::Zeroizing::new("test".to_string()),
            shutdown,
        )
        .unwrap();
        assert_eq!(engine.pick_churn_amount(0), 0);
    }

    /// R-88 regression: pick_churn_amount must not panic (debug) or
    /// silently wrap (release) when the spendable balance is near
    /// u64::MAX. Realistic scenario: exchange hot-wallet or dust
    /// consolidator; unrealistic scenario: an adversarial or corrupt
    /// balance value passed by an upstream bug. Either way the fn
    /// must return a sane value, not overflow.
    #[test]
    fn pick_churn_amount_saturates_at_u64_max() {
        let shutdown = Arc::new(AtomicBool::new(false));
        let engine = ChurnEngine::new(
            ChurnConfig {
                enabled: true,
                min_amount_pct: 50,
                max_amount_pct: 50,
                ..Default::default()
            },
            std::path::PathBuf::from("/tmp/test.wallet"),
            zeroize::Zeroizing::new("test".to_string()),
            shutdown,
        )
        .unwrap();
        // Prior code did `u64::MAX * 50` which overflows in debug.
        // Now it saturates. We don't assert on the exact value —
        // just that the call returns without panic and doesn't
        // wrap to something absurdly small.
        let amount = engine.pick_churn_amount(u64::MAX);
        assert!(
            amount > u64::MAX / 4,
            "R-88: amount {} suggests silent wrap at 50% of u64::MAX",
            amount
        );
    }

    #[test]
    fn poisson_intervals_are_bounded() {
        let shutdown = Arc::new(AtomicBool::new(false));
        let engine = ChurnEngine::new(
            ChurnConfig {
                min_interval_secs: 60,
                max_interval_secs: 300,
                ..Default::default()
            },
            std::path::PathBuf::from("/tmp/test.wallet"),
            zeroize::Zeroizing::new("test".to_string()),
            shutdown,
        )
        .unwrap();

        for _ in 0..200 {
            let interval = engine.next_interval_secs();
            assert!(interval >= 60, "interval {} below min", interval);
            assert!(interval <= 300, "interval {} above max", interval);
        }
    }
}
