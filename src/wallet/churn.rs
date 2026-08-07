//! Auto-churn transaction scheduling.
//!
//! Churn timing and amount selection live here.  Transaction construction,
//! RPC policy and reservation lifecycle are delegated to `SpendCoordinator`
//! so a churn self-send follows the same safety rules as an interactive send.

use super::send::Payment;
use super::spend::{SpendCoordinator, SpendIntent, SpendSubmission};
use super::{KeyEpoch, Wallet};
use crate::primitives::Amount;
use rand::Rng;
use rand_distr::{Distribution, Exp};
use serde::{Deserialize, Serialize};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use tokio::time::{sleep, Duration};
use tracing::{debug, info, warn};
use zeroize::Zeroizing;

/// Auto-churn configuration.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ChurnConfig {
    /// Whether the feature is enabled by the embedding application.
    pub enabled: bool,
    /// Minimum delay between attempts.
    pub min_interval_secs: u64,
    /// Maximum delay between attempts.
    pub max_interval_secs: u64,
    /// Minimum percentage of currently spendable value to self-send.
    pub min_amount_pct: u8,
    /// Maximum percentage of currently spendable value to self-send.
    pub max_amount_pct: u8,
    /// JSON-RPC endpoint used by the shared wallet client.
    pub node_url: String,
}

impl Default for ChurnConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            min_interval_secs: 1_800,
            max_interval_secs: 7_200,
            min_amount_pct: 10,
            max_amount_pct: 50,
            node_url: "http://127.0.0.1:28081".to_string(),
        }
    }
}

impl ChurnConfig {
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
        if self.node_url.trim().is_empty() {
            return Err("node_url must not be empty".into());
        }
        Ok(())
    }
}

/// Runtime statistics for the churn engine.
#[derive(Clone, Debug, Default, Serialize)]
pub struct ChurnStats {
    /// Transactions accepted by the node.
    pub churns_completed: u64,
    /// Attempts that did not reach an accepted state.
    pub churns_failed: u64,
    /// Total atomic CYNC submitted in accepted churn transactions.
    pub total_churned: u64,
    /// Unix timestamp of the latest accepted churn.
    pub last_churn_time: u64,
    /// Whether the scheduling loop is active.
    pub is_running: bool,
}

/// Background auto-churn engine.
pub struct ChurnEngine {
    config: ChurnConfig,
    wallet_path: std::path::PathBuf,
    wallet_password: Zeroizing<String>,
    shutdown: Arc<AtomicBool>,
    stats: Arc<parking_lot::Mutex<ChurnStats>>,
    coordinator: SpendCoordinator,
}

impl ChurnEngine {
    pub fn new(
        config: ChurnConfig,
        wallet_path: std::path::PathBuf,
        wallet_password: Zeroizing<String>,
        shutdown: Arc<AtomicBool>,
    ) -> Result<Self, String> {
        config.validate()?;
        let coordinator = SpendCoordinator::for_node(config.node_url.clone())
            .map_err(|error| format!("create spend coordinator: {error}"))?;

        Ok(Self {
            config,
            wallet_path,
            wallet_password,
            shutdown,
            stats: Arc::new(parking_lot::Mutex::new(ChurnStats::default())),
            coordinator,
        })
    }

    pub fn stats(&self) -> ChurnStats {
        self.stats.lock().clone()
    }

    /// Draw an exponentially distributed interval and clamp it to the
    /// configured operating window.
    fn next_interval_secs(&self) -> u64 {
        let mean = self.config.min_interval_secs as f64 / 2.0
            + self.config.max_interval_secs as f64 / 2.0;
        let lambda = 1.0 / mean;
        let distribution = Exp::new(lambda)
            .unwrap_or_else(|_| Exp::new(1.0 / 3_600.0).expect("positive fallback rate"));
        let sample = distribution.sample(&mut rand::thread_rng()) as u64;

        sample.clamp(
            self.config.min_interval_secs,
            self.config.max_interval_secs,
        )
    }

    /// Choose a percentage using u128 arithmetic so a large u64 wallet value
    /// cannot overflow before division.
    fn pick_churn_amount(&self, spendable_balance: u64) -> u64 {
        if spendable_balance == 0 {
            return 0;
        }

        let percentage = rand::thread_rng()
            .gen_range(self.config.min_amount_pct..=self.config.max_amount_pct)
            as u64;
        let amount =
            ((spendable_balance as u128) * (percentage as u128) / 100) as u64;

        const TYPICAL_PRIVACY_TX_BYTES: u64 = 2_500;
        let fee_reserve = TYPICAL_PRIVACY_TX_BYTES
            .saturating_mul(crate::constants::MIN_FEE_PER_BYTE)
            .saturating_mul(3)
            / 2;

        if amount.saturating_add(fee_reserve) > spendable_balance {
            spendable_balance.saturating_sub(fee_reserve)
        } else {
            amount
        }
    }

    pub async fn run(self) {
        info!(
            min_interval = self.config.min_interval_secs,
            max_interval = self.config.max_interval_secs,
            min_pct = self.config.min_amount_pct,
            max_pct = self.config.max_amount_pct,
            "auto-churn engine started"
        );
        self.stats.lock().is_running = true;

        while !self.shutdown.load(Ordering::Relaxed) {
            self.sleep_until_next_attempt().await;
            if self.shutdown.load(Ordering::Relaxed) {
                break;
            }

            match self.execute_churn().await {
                Ok(amount) => {
                    let mut stats = self.stats.lock();
                    stats.churns_completed = stats.churns_completed.saturating_add(1);
                    stats.total_churned = stats.total_churned.saturating_add(amount);
                    stats.last_churn_time = unix_now();
                    info!(
                        amount,
                        total_churns = stats.churns_completed,
                        "churn transaction submitted"
                    );
                }
                Err(error) => {
                    let mut stats = self.stats.lock();
                    stats.churns_failed = stats.churns_failed.saturating_add(1);
                    warn!(error = %error, "churn transaction failed");
                }
            }
        }

        self.stats.lock().is_running = false;
        info!("auto-churn engine stopped");
    }

    async fn sleep_until_next_attempt(&self) {
        let interval_secs = self.next_interval_secs();
        debug!(interval_secs, "churn: sleeping before next attempt");

        let mut remaining = interval_secs;
        while remaining > 0 && !self.shutdown.load(Ordering::Relaxed) {
            let chunk = remaining.min(10);
            sleep(Duration::from_secs(chunk)).await;
            remaining -= chunk;
        }
    }

    async fn execute_churn(&self) -> Result<u64, String> {
        let mut wallet =
            Wallet::open(self.wallet_path.clone()).map_err(|error| format!("open wallet: {error}"))?;
        wallet
            .unlock(self.wallet_password.as_str())
            .map_err(|error| format!("unlock wallet: {error}"))?;

        let keys: KeyEpoch = wallet
            .current_keys()
            .cloned()
            .ok_or_else(|| "wallet has no current key epoch".to_string())?;
        let session = self
            .coordinator
            .begin()
            .await
            .map_err(|error| format!("start spend session: {error}"))?;
        let context = session.context();

        let balance = wallet.balance_ref();
        let mut mature_values = balance
            .available_utxos(context.target_height(), context.min_output_age())
            .iter()
            .map(|utxo| utxo.amount.as_atomic())
            .collect::<Vec<_>>();
        if mature_values.len() < 2 {
            return Err(format!(
                "churn needs at least 2 mature UTXOs; have {}",
                mature_values.len()
            ));
        }

        mature_values.sort_unstable_by(|left, right| right.cmp(left));
        let two_input_cap = mature_values[0].saturating_add(mature_values[1]);
        let mature_spendable = balance
            .spendable(context.target_height(), context.min_output_age())
            .as_atomic();
        let churn_amount = self.pick_churn_amount(mature_spendable.min(two_input_cap));
        if churn_amount == 0 {
            return Err("churn amount is zero (mature balance too low)".into());
        }

        debug!(
            mature_spendable,
            two_input_cap,
            churn_amount,
            "churn: building self-send"
        );

        let intent = SpendIntent::new(vec![Payment::new(
            keys.spend_public,
            keys.view_public,
            Amount::from_atomic(churn_amount),
        )]);
        let mut rng = rand::rngs::OsRng;
        let built = self
            .coordinator
            .build_privacy_transaction(&session, balance, &keys, intent, &mut rng)
            .await
            .map_err(|error| format!("build churn transaction: {error}"))?;

        debug!(
            hash = %hex::encode(built.transaction().hash().as_bytes()),
            inputs = built.transaction().inputs.len(),
            outputs = built.transaction().outputs.len(),
            amount = churn_amount,
            "churn: submitting self-send"
        );

        match self
            .coordinator
            .submit_reserved(&mut wallet, self.wallet_password.as_str(), built)
            .await
            .map_err(|error| format!("submit churn transaction: {error}"))?
        {
            SpendSubmission::Accepted {
                tx_hash,
                wallet_save_error,
            } => {
                if let Some(error) = wallet_save_error {
                    warn!(
                        tx_hash = %hex::encode(tx_hash.as_bytes()),
                        error = %error,
                        "churn accepted, but wallet state was not persisted"
                    );
                } else {
                    info!(
                        target: "wallet::churn::R89",
                        tx_hash = %hex::encode(tx_hash.as_bytes()),
                        "R-89: churn spend-marking durable on disk"
                    );
                }
                Ok(churn_amount)
            }
            SpendSubmission::Rejected {
                tx_hash,
                reason,
                released_reservations,
                wallet_save_error,
            } => {
                let persistence_note = wallet_save_error
                    .map(|error| format!("; reservation release was not persisted: {error}"))
                    .unwrap_or_default();
                Err(format!(
                    "node rejected churn transaction {}: {} (released {} reservation(s){})",
                    hex::encode(tx_hash.as_bytes()),
                    reason,
                    released_reservations,
                    persistence_note
                ))
            }
            SpendSubmission::Unknown { tx_hash, reason } => Err(format!(
                "churn submission status for {} is unknown: {}; input reservation retained",
                hex::encode(tx_hash.as_bytes()),
                reason
            )),
        }
    }
}

fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_engine(config: ChurnConfig) -> ChurnEngine {
        ChurnEngine::new(
            config,
            std::path::PathBuf::from("/tmp/test.wallet"),
            Zeroizing::new("test".to_string()),
            Arc::new(AtomicBool::new(false)),
        )
        .unwrap()
    }

    #[test]
    fn default_config_is_valid() {
        assert!(ChurnConfig::default().validate().is_ok());
    }

    #[test]
    fn invalid_config_rejected() {
        let mut config = ChurnConfig::default();
        config.min_interval_secs = 0;
        assert!(config.validate().is_err());

        let mut config = ChurnConfig::default();
        config.max_interval_secs = 100;
        assert!(config.validate().is_err());

        let mut config = ChurnConfig::default();
        config.min_amount_pct = 0;
        assert!(config.validate().is_err());

        let mut config = ChurnConfig::default();
        config.max_amount_pct = 101;
        assert!(config.validate().is_err());

        let mut config = ChurnConfig::default();
        config.node_url.clear();
        assert!(config.validate().is_err());
    }

    #[test]
    fn churn_amount_respects_bounds() {
        let engine = test_engine(ChurnConfig {
            enabled: true,
            min_amount_pct: 10,
            max_amount_pct: 50,
            ..Default::default()
        });
        const BALANCE: u64 = 1_000_000_000_000;

        for _ in 0..100 {
            let amount = engine.pick_churn_amount(BALANCE);
            assert!(amount >= BALANCE / 10, "amount {amount} too low");
            assert!(amount <= BALANCE / 2, "amount {amount} too high");
        }
    }

    #[test]
    fn churn_amount_handles_zero_and_u64_max() {
        let engine = test_engine(ChurnConfig {
            enabled: true,
            min_amount_pct: 50,
            max_amount_pct: 50,
            ..Default::default()
        });

        assert_eq!(engine.pick_churn_amount(0), 0);
        assert!(engine.pick_churn_amount(u64::MAX) > u64::MAX / 4);
    }

    #[test]
    fn poisson_intervals_are_bounded() {
        let engine = test_engine(ChurnConfig {
            min_interval_secs: 60,
            max_interval_secs: 300,
            ..Default::default()
        });

        for _ in 0..200 {
            let interval = engine.next_interval_secs();
            assert!((60..=300).contains(&interval));
        }
    }
}
