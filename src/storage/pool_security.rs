//! # Pool Security Service — "Secret Service" for the shielded pool
//!
//! A **read-only** protection detail over the [`SparkPoolStore`]. It never
//! mutates consensus state; it *observes* the pool and reports integrity
//! violations and anomalies so an operator — or a fail-closed caller — can act.
//! Think of it as the security detail guarding the vault: it watches, scans,
//! and investigates, but it does not move the money.
//!
//! Three details, matching how the operator asked for it:
//!
//! - **Secret Service (guards)** — [`SecretService::guard`]: fail-closed
//!   invariant sentries. These are properties that MUST always hold for an
//!   honest pool (nothing dated in the future, checkpoint stack within bounds,
//!   spent-tag/coin heights sane). A non-empty result is a red alert: the pool
//!   is in a state an honest node should never produce.
//! - **CIA (scan)** — [`SecretService::cia_scan`]: a surveillance snapshot of
//!   the pool (counts, tips) plus soft anomaly flags (mint velocity, spend
//!   ratio) that warrant a closer look but are not, alone, proof of a fault.
//! - **FBI (investigation)** — [`SecretService::fbi_investigate`]: a forensic
//!   trace of one subject (a linking tag or a coin outpoint) — is it known to
//!   the pool, and with what history.
//!
//! Gated `sketch-gk-proof` (it observes the gated pool) and inert: reporting
//! only. Wiring `guard` into a block-apply assertion (halt on violation) is an
//! operator choice left to the caller.

use spark_connector::Nullifier;

use crate::storage::spark_pool::SparkPoolStore;

/// A pool-integrity invariant that an honest node must never break. A guard
/// sweep returning any of these is a red alert.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum GuardViolation {
    /// A coin is minted at a height above the chain tip (impossible honestly).
    CoinFromTheFuture { tip: u64, max_coin_height: u64 },
    /// A tag was spent at a height above the chain tip.
    TagSpentInTheFuture { tip: u64, max_tag_height: u64 },
    /// The reorg checkpoint stack exceeded its bound (desync / leak).
    CheckpointStackOverflow { count: usize, max: usize },
    /// The shielded pool value went NEGATIVE — more was unshielded than was ever
    /// shielded in (inflation across the veil). Must never happen honestly.
    PoolValueNegative { pool_value: i128 },
}

/// Soft anomaly flags from a surveillance scan — worth a look, not proof.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Anomaly {
    /// An unusually large number of coins minted in the recent window.
    HighMintVelocity { window_blocks: u64, minted: usize, threshold: usize },
    /// A large fraction of the pool's coins have been spent (pool draining).
    HighSpendRatio { spent: usize, coins: usize },
}

/// The surveillance snapshot the CIA scan returns.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ScanReport {
    pub coin_count: usize,
    pub spent_tag_count: usize,
    pub checkpoint_count: usize,
    pub max_coin_height: Option<u64>,
    pub max_spent_tag_height: Option<u64>,
    pub anomalies: Vec<Anomaly>,
}

/// A subject to investigate: a linking tag or a coin outpoint.
#[derive(Clone, Debug)]
pub enum Subject {
    /// A VRF linking tag — is it in the spent set, and at what height.
    Tag(Nullifier),
    /// A coin outpoint (`tx_hash ‖ vout`, the pool key) — is the coin present.
    Outpoint(Vec<u8>),
}

/// The forensic finding for one subject.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Finding {
    /// The tag is spent, recorded at this height.
    TagSpent { height: u64 },
    /// The tag is not in the spent set (the coin behind it is unspent, or
    /// unknown to this pool).
    TagUnspent,
    /// The coin is in the pool at this cover index + mint height.
    CoinPresent { cover_index: u64, height: u64 },
    /// No coin at this outpoint (never seen, or rewound out).
    CoinAbsent,
}

/// Reporting thresholds for the scan. Defaults are conservative; an operator
/// tunes them to their chain's cadence.
#[derive(Clone, Copy, Debug)]
pub struct Thresholds {
    /// Window (in blocks, counted back from tip) for the mint-velocity check.
    pub velocity_window: u64,
    /// Mints within the window above this count flag high velocity.
    pub velocity_max: usize,
    /// Spent/coins ratio (percent) above this flags pool draining.
    pub spend_ratio_pct: u64,
}

impl Default for Thresholds {
    fn default() -> Self {
        Self { velocity_window: 100, velocity_max: 10_000, spend_ratio_pct: 90 }
    }
}

/// The security detail. Stateless — construct one per sweep over a store.
pub struct SecretService {
    thresholds: Thresholds,
}

impl SecretService {
    pub fn new() -> Self {
        Self { thresholds: Thresholds::default() }
    }

    pub fn with_thresholds(thresholds: Thresholds) -> Self {
        Self { thresholds }
    }

    /// **Secret Service.** Fail-closed invariant sweep. Returns every violated
    /// invariant (empty = clean). A caller that wants a hard guarantee treats a
    /// non-empty result as a halt condition. `tip` is the current chain height.
    pub fn guard(&self, store: &SparkPoolStore, tip: u64) -> Vec<GuardViolation> {
        let mut v = Vec::new();
        if let Some(h) = store.max_coin_height() {
            if h > tip {
                v.push(GuardViolation::CoinFromTheFuture { tip, max_coin_height: h });
            }
        }
        if let Some(h) = store.max_spent_tag_height() {
            if h > tip {
                v.push(GuardViolation::TagSpentInTheFuture { tip, max_tag_height: h });
            }
        }
        // The store caps its reorg stack at MAX_CHECKPOINTS; exceeding it means
        // a desync/leak. Mirror the store's bound here as the sentry threshold.
        const MAX: usize = 1000;
        let cps = store.checkpoint_count();
        if cps > MAX {
            v.push(GuardViolation::CheckpointStackOverflow { count: cps, max: MAX });
        }
        // No inflation across the veil: the pool value can never be negative.
        let pv = store.pool_value();
        if pv < 0 {
            v.push(GuardViolation::PoolValueNegative { pool_value: pv });
        }
        v
    }

    /// True iff the pool passes every hard invariant (a convenience over
    /// [`guard`](Self::guard)).
    pub fn is_secure(&self, store: &SparkPoolStore, tip: u64) -> bool {
        self.guard(store, tip).is_empty()
    }

    /// **CIA.** A surveillance snapshot + soft anomaly flags. `tip` is the
    /// current chain height (used for the velocity window).
    pub fn cia_scan(&self, store: &SparkPoolStore, tip: u64) -> ScanReport {
        let coin_count = store.coin_count();
        let spent_tag_count = store.spent_tag_count();
        let mut anomalies = Vec::new();

        let window_start = tip.saturating_sub(self.thresholds.velocity_window);
        let minted = store.coins_at_or_after(window_start);
        if minted > self.thresholds.velocity_max {
            anomalies.push(Anomaly::HighMintVelocity {
                window_blocks: self.thresholds.velocity_window,
                minted,
                threshold: self.thresholds.velocity_max,
            });
        }
        if coin_count > 0 {
            let ratio_pct = (spent_tag_count as u128 * 100 / coin_count as u128) as u64;
            if ratio_pct >= self.thresholds.spend_ratio_pct {
                anomalies.push(Anomaly::HighSpendRatio { spent: spent_tag_count, coins: coin_count });
            }
        }

        ScanReport {
            coin_count,
            spent_tag_count,
            checkpoint_count: store.checkpoint_count(),
            max_coin_height: store.max_coin_height(),
            max_spent_tag_height: store.max_spent_tag_height(),
            anomalies,
        }
    }

    /// **FBI.** Investigate one subject — trace a tag's spend status or a coin's
    /// presence in the pool.
    pub fn fbi_investigate(&self, store: &SparkPoolStore, subject: &Subject) -> Finding {
        match subject {
            Subject::Tag(tag) => match store.spent_tag_height(tag) {
                Some(height) => Finding::TagSpent { height },
                None => Finding::TagUnspent,
            },
            Subject::Outpoint(op) => match store.index_of(op) {
                Some(cover_index) => {
                    let height = store.coin_at(cover_index).map(|c| c.height).unwrap_or(0);
                    Finding::CoinPresent { cover_index, height }
                }
                None => Finding::CoinAbsent,
            },
        }
    }
}

impl Default for SecretService {
    fn default() -> Self {
        Self::new()
    }
}

/// Adapts the shielded pool's [`SecretService`] into the chain-wide
/// [`SecurityDetail`](crate::security::SecurityDetail) framework, so the pool
/// takes its place alongside other subsystems' details under one
/// [`SecurityCommand`](crate::security::SecurityCommand). Guard violations
/// become `Critical` alerts; scan anomalies become `Warning`s.
pub struct PoolSecurityDetail<'a> {
    store: &'a SparkPoolStore,
    tip: u64,
    svc: SecretService,
}

impl<'a> PoolSecurityDetail<'a> {
    pub fn new(store: &'a SparkPoolStore, tip: u64) -> Self {
        Self { store, tip, svc: SecretService::new() }
    }
}

impl crate::security::SecurityDetail for PoolSecurityDetail<'_> {
    fn label(&self) -> &'static str {
        "shielded-pool"
    }

    fn sweep(&self) -> crate::security::SecurityReport {
        use crate::security::{SecurityReport, Severity};
        let mut r = SecurityReport::clean();

        for v in self.svc.guard(self.store, self.tip) {
            let (code, msg) = match v {
                GuardViolation::CoinFromTheFuture { tip, max_coin_height } => (
                    "coin-from-future",
                    format!("a coin is minted at height {max_coin_height} above tip {tip}"),
                ),
                GuardViolation::TagSpentInTheFuture { tip, max_tag_height } => (
                    "tag-from-future",
                    format!("a tag was spent at height {max_tag_height} above tip {tip}"),
                ),
                GuardViolation::CheckpointStackOverflow { count, max } => (
                    "checkpoint-overflow",
                    format!("reorg checkpoint stack {count} exceeds bound {max}"),
                ),
                GuardViolation::PoolValueNegative { pool_value } => (
                    "pool-underflow",
                    format!("shielded pool value {pool_value} < 0 — inflation across the veil"),
                ),
            };
            // Guards are deterministic + O(1) → consensus-critical (safe to halt).
            r.raise_consensus("shielded-pool", Severity::Critical, code, msg);
        }

        for a in self.svc.cia_scan(self.store, self.tip).anomalies {
            let (code, msg) = match a {
                Anomaly::HighMintVelocity { window_blocks, minted, threshold } => (
                    "high-mint-velocity",
                    format!("{minted} coins minted in the last {window_blocks} blocks (> {threshold})"),
                ),
                Anomaly::HighSpendRatio { spent, coins } => (
                    "high-spend-ratio",
                    format!("{spent}/{coins} coins spent — pool draining"),
                ),
            };
            // Anomalies are heuristic → operational (page, never halt).
            r.raise_operational("shielded-pool", Severity::Warning, code, msg);
        }
        r
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use spark_connector::CoinBytes;

    fn coin(tag: u8) -> CoinBytes {
        CoinBytes(vec![tag; 40])
    }
    fn nf(tag: u8) -> Nullifier {
        Nullifier(vec![tag; 34])
    }

    #[test]
    fn secret_service_guard_flags_future_dated_entries() {
        let store = SparkPoolStore::new();
        store.add_coin(b"op:0".to_vec(), coin(1), b"c".to_vec(), 50);
        store.mark_tag_spent(&nf(1), 40);
        let ss = SecretService::new();

        // Tip 100: everything is in the past → clean.
        assert!(ss.is_secure(&store, 100));
        assert!(ss.guard(&store, 100).is_empty());

        // Tip 30: a coin at height 50 and a tag at 40 are "from the future" →
        // two violations (an honest node can never produce this).
        let v = ss.guard(&store, 30);
        assert!(v.contains(&GuardViolation::CoinFromTheFuture { tip: 30, max_coin_height: 50 }));
        assert!(v.contains(&GuardViolation::TagSpentInTheFuture { tip: 30, max_tag_height: 40 }));
    }

    #[test]
    fn cia_scan_snapshots_and_flags_spend_ratio() {
        let store = SparkPoolStore::new();
        for i in 0..10u8 {
            store.add_coin(vec![i], coin(i), b"c".to_vec(), 5);
        }
        // Spend 9 of 10 → 90% spent → HighSpendRatio.
        for i in 0..9u8 {
            store.mark_tag_spent(&nf(i), 6);
        }
        let report = SecretService::new().cia_scan(&store, 100);
        assert_eq!(report.coin_count, 10);
        assert_eq!(report.spent_tag_count, 9);
        assert_eq!(report.max_coin_height, Some(5));
        assert!(report
            .anomalies
            .iter()
            .any(|a| matches!(a, Anomaly::HighSpendRatio { spent: 9, coins: 10 })));
    }

    #[test]
    fn cia_scan_flags_high_mint_velocity() {
        let store = SparkPoolStore::new();
        let th = Thresholds { velocity_window: 100, velocity_max: 3, spend_ratio_pct: 90 };
        for i in 0..5u8 {
            store.add_coin(vec![i], coin(i), b"c".to_vec(), 95); // all within the window
        }
        let report = SecretService::with_thresholds(th).cia_scan(&store, 100);
        assert!(report
            .anomalies
            .iter()
            .any(|a| matches!(a, Anomaly::HighMintVelocity { minted: 5, .. })));
    }

    #[test]
    fn redteam_guard_boundaries_and_scan_degenerates_dont_slip_or_crash() {
        let ss = SecretService::new();

        // Guard boundary: a coin at EXACTLY tip is legal; tip+1 is not; u64::MAX
        // is caught when tip is below it. No off-by-one slip.
        let store = SparkPoolStore::new();
        store.add_coin(b"op:0".to_vec(), coin(1), b"c".to_vec(), 100);
        assert!(ss.guard(&store, 100).is_empty(), "coin at exactly tip is legal");
        assert!(!ss.guard(&store, 99).is_empty(), "coin one above tip is caught");

        let store_max = SparkPoolStore::new();
        store_max.add_coin(b"op:m".to_vec(), coin(2), b"c".to_vec(), u64::MAX);
        assert!(!ss.guard(&store_max, 1000).is_empty(), "u64::MAX height is caught");

        // Scan degenerates: empty pool must not divide-by-zero or panic.
        let empty = SparkPoolStore::new();
        let r = ss.cia_scan(&empty, 0);
        assert_eq!(r.coin_count, 0);
        assert!(r.anomalies.is_empty());

        // Pathological: more spent tags than coins (can't happen honestly) must
        // still not panic and just flags the ratio.
        let weird = SparkPoolStore::new();
        weird.add_coin(b"op:x".to_vec(), coin(3), b"c".to_vec(), 1);
        for t in 0u8..5 {
            weird.mark_tag_spent(&nf(t), 1);
        }
        let _ = ss.cia_scan(&weird, 1); // must not panic

        // FBI on garbage subjects → benign findings, never a panic.
        assert_eq!(ss.fbi_investigate(&empty, &Subject::Tag(nf(0xEE))), Finding::TagUnspent);
        assert_eq!(ss.fbi_investigate(&empty, &Subject::Outpoint(vec![])), Finding::CoinAbsent);
        assert_eq!(
            ss.fbi_investigate(&empty, &Subject::Outpoint(vec![0xFF; 1024])),
            Finding::CoinAbsent
        );
    }

    #[test]
    fn pool_plugs_into_the_chain_wide_security_command() {
        use crate::security::{SecurityCommand, SecurityDetail};
        let store = SparkPoolStore::new();
        store.add_coin(b"op:0".to_vec(), coin(1), b"c".to_vec(), 50);

        // Clean at a sane tip: no consensus halt.
        let detail = PoolSecurityDetail::new(&store, 100);
        let details: [&dyn SecurityDetail; 1] = [&detail];
        assert!(SecurityCommand::assert_consensus_safe(&details).is_ok());

        // At an impossibly-low tip the coin is "from the future" → a
        // consensus-critical alert halts through the coordinator.
        let detail_bad = PoolSecurityDetail::new(&store, 10);
        let bad: [&dyn SecurityDetail; 1] = [&detail_bad];
        let report = SecurityCommand::assert_consensus_safe(&bad).unwrap_err();
        assert!(report.has_consensus_halt());
        assert_eq!(detail_bad.label(), "shielded-pool");
        assert!(report.criticals().any(|a| a.code == "coin-from-future"));
    }

    #[test]
    fn fbi_investigate_traces_tags_and_coins() {
        let store = SparkPoolStore::new();
        store.add_coin(b"op:known".to_vec(), coin(7), b"c".to_vec(), 12);
        store.mark_tag_spent(&nf(7), 20);
        let ss = SecretService::new();

        // A spent tag → recorded height.
        assert_eq!(
            ss.fbi_investigate(&store, &Subject::Tag(nf(7))),
            Finding::TagSpent { height: 20 }
        );
        // An unknown tag → unspent.
        assert_eq!(ss.fbi_investigate(&store, &Subject::Tag(nf(99))), Finding::TagUnspent);
        // A known coin → present with its index + height.
        assert_eq!(
            ss.fbi_investigate(&store, &Subject::Outpoint(b"op:known".to_vec())),
            Finding::CoinPresent { cover_index: 0, height: 12 }
        );
        // An unknown coin → absent.
        assert_eq!(
            ss.fbi_investigate(&store, &Subject::Outpoint(b"op:nope".to_vec())),
            Finding::CoinAbsent
        );
    }
}
