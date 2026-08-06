//! # Transaction Mempool
//!
//! Manages pending transactions waiting to be included in blocks.

use crate::consensus::{
    validate_transaction_basic, verify_balance_proof, verify_output_range_proofs,
    verify_ring_signature,
};
use crate::constants::{MAX_TX_SIZE, MIN_FEE_PER_BYTE};
use crate::error::{Error, Result};
use crate::primitives::{Amount, Hash, KeyImage};
use crate::transaction::Transaction;
use parking_lot::RwLock;
use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};
use std::path::Path;
use std::sync::Arc;

/// Minimal chain interface for `shadow_evict_invalid`. Defined as a
/// trait so the mempool doesn't take a hard `&Blockchain` dependency
/// (avoids tying the mempool's API to the concrete chain type and
/// keeps unit tests easy — a test fake can implement this in a few
/// lines without standing up a full Blockchain). Blanket-impl'd for
/// `Blockchain` below.
pub trait ShadowEvictChain {
    fn validate_transaction(&self, tx: &Transaction) -> Result<()>;
}

impl ShadowEvictChain for crate::chain::Blockchain {
    fn validate_transaction(&self, tx: &Transaction) -> Result<()> {
        crate::chain::Blockchain::validate_transaction(self, tx)
    }
}

const MAX_CHAIN_GENERATION_ATTEMPTS: usize = 4;

trait GenerationSource {
    fn stable_generation(&self) -> Option<u64>;
}

impl GenerationSource for crate::chain::Blockchain {
    fn stable_generation(&self) -> Option<u64> {
        crate::chain::Blockchain::stable_generation(self)
    }
}

enum AdmissionAttempt<T> {
    Retry,
    Complete(Result<T>),
}

fn retry_stable_admission<C, F, T>(chain: &C, mut attempt: F) -> Result<T>
where
    C: GenerationSource,
    F: FnMut(u64) -> AdmissionAttempt<T>,
{
    for _ in 0..MAX_CHAIN_GENERATION_ATTEMPTS {
        let Some(generation) = chain.stable_generation() else {
            std::thread::yield_now();
            continue;
        };

        match attempt(generation) {
            AdmissionAttempt::Retry => std::thread::yield_now(),
            AdmissionAttempt::Complete(result) => return result,
        }
    }

    Err(Error::InvalidState(format!(
        "chain state changed during mempool admission after {} attempts; retry submission",
        MAX_CHAIN_GENERATION_ATTEMPTS
    )))
}

// ── Fee estimation ──────────────────────────────────────────────────────────

/// Mempool fee percentile snapshot for fee estimation.
///
/// Wallets query this to determine competitive fee rates based on current
/// mempool conditions rather than relying on the static `MIN_FEE_PER_BYTE`.
#[derive(Clone, Debug, serde::Serialize)]
pub struct FeePercentiles {
    /// 25th percentile fee-per-byte (low priority)
    pub p25: u64,
    /// 50th percentile fee-per-byte (normal priority)
    pub p50: u64,
    /// 75th percentile fee-per-byte (high priority)
    pub p75: u64,
    /// 90th percentile fee-per-byte (urgent)
    pub p90: u64,
    /// Number of transactions in the sample
    pub count: usize,
}

// ── Mempool audit log ────────────────────────────────────────────────────────

/// Maximum number of audit events retained in memory.
const AUDIT_LOG_CAPACITY: usize = 4096;

/// The reason a transaction was removed from the mempool.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum EvictReason {
    /// Included in a confirmed block.
    Confirmed,
    /// Spends a UTXO that was just claimed by a confirmed block tx.
    /// The mempool tx is now permanently invalid; eviction prevents
    /// it from poisoning future block templates ("duplicate key image"
    /// rejection at consensus time would otherwise stall block
    /// production until expiry).
    DoubleSpend,
    /// Replaced by a higher-fee transaction (RBF).
    ReplacedByFee,
    /// Evicted to free space for a higher-fee transaction.
    LowFee,
    /// Sat in the mempool longer than the maximum age.
    Expired,
}

/// A single auditable mempool event.
#[derive(Clone, Debug)]
pub enum AuditEvent {
    /// Transaction was accepted into the mempool.
    TxAdded {
        hash: Hash,
        fee: Amount,
        size: usize,
        timestamp: u64,
    },
    /// Transaction was rejected before entering the mempool.
    TxRejected {
        hash: Hash,
        reason: String,
        timestamp: u64,
    },
    /// Transaction was removed from the mempool.
    TxRemoved {
        hash: Hash,
        reason: EvictReason,
        timestamp: u64,
    },
}

impl AuditEvent {
    pub fn timestamp(&self) -> u64 {
        match self {
            AuditEvent::TxAdded { timestamp, .. } => *timestamp,
            AuditEvent::TxRejected { timestamp, .. } => *timestamp,
            AuditEvent::TxRemoved { timestamp, .. } => *timestamp,
        }
    }

    pub fn hash(&self) -> &Hash {
        match self {
            AuditEvent::TxAdded { hash, .. } => hash,
            AuditEvent::TxRejected { hash, .. } => hash,
            AuditEvent::TxRemoved { hash, .. } => hash,
        }
    }
}

fn unix_now() -> u64 {
    // Monotonic-max fallback: SystemTime::duration_since(UNIX_EPOCH) can
    // theoretically fail (system clock set before 1970, which doesn't
    // happen on a running system) or step backwards (NTP correction).
    // The original `unwrap_or(0)` would mark fresh mempool entries as
    // 56 years old, triggering immediate eviction by the TTL sweep.
    // Track the last good value and return max(now, last) so a clock
    // hiccup never produces an artificially-ancient timestamp. Costs
    // one relaxed atomic CAS per call — negligible vs the syscall.
    static LAST: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let last = LAST.load(std::sync::atomic::Ordering::Relaxed);
    let out = now.max(last);
    if out > last {
        LAST.store(out, std::sync::atomic::Ordering::Relaxed);
    }
    out
}

/// A transaction in the mempool with metadata
#[derive(Clone, Debug)]
pub struct MempoolEntry {
    pub tx: Transaction,
    pub tx_hash: Hash,
    pub fee: Amount,
    pub fee_per_byte: u64,
    pub size: usize,
    pub added_time: u64,
    pub height_added: u64,
}

impl MempoolEntry {
    pub fn new(tx: Transaction, height: u64, time: u64) -> Self {
        let tx_hash = tx.hash();
        let size = tx.size();
        // SECURITY (L4): Ensure size is at least 1 to prevent zero-size entries
        // from stalling the mempool eviction loop.
        let size = size.max(1);
        let fee = tx.fee;

        // SECURITY: Use scaled fee calculation to prevent precision loss
        // Multiply fee by 1_000_000 before division to maintain precision for small fees
        // This gives us micro-sync per byte precision instead of sync per byte
        //
        // Example: 50 syncs / 100 bytes = 0 (lost precision)
        // With scaling: (50 * 1_000_000) / 100 = 500_000 micro-syncs per byte
        let fee_per_byte = if size > 0 {
            // Use u128 intermediate to prevent overflow for large fees
            let scaled_fee = fee.as_atomic() as u128 * 1_000_000;
            let result = scaled_fee / size as u128;
            // SECURITY (A5-MEM-01): Clamp to u64::MAX instead of silent truncation.
            // Without this, extreme fee values wrap around to near-zero, causing
            // the transaction to be evicted first despite paying a high fee.
            result.min(u64::MAX as u128) as u64
        } else {
            0
        };

        MempoolEntry {
            tx,
            tx_hash,
            fee,
            fee_per_byte,
            size,
            added_time: time,
            height_added: height,
        }
    }
}

/// Minimum fee bump percentage for replace-by-fee (25% = 125/100)
const RBF_FEE_BUMP_NUMERATOR: u64 = 125;
const RBF_FEE_BUMP_DENOMINATOR: u64 = 100;

/// Compute scaled fee-per-byte (matches MempoolEntry calculation)
fn scaled_fee_per_byte(fee_atomic: u64, size: usize) -> u64 {
    let size = size.max(1);
    let scaled = fee_atomic as u128 * 1_000_000;
    (scaled / size as u128).min(u64::MAX as u128) as u64
}

/// Transaction mempool
///
/// # Thread Safety
///
/// The Mempool struct is NOT thread-safe by itself. It uses internal HashMap,
/// BTreeMap, and HashSet which are not synchronized. Callers MUST wrap it in
/// appropriate synchronization primitives (typically `Arc<RwLock<Mempool>>`).
///
/// All operations that modify state require exclusive (write) access:
/// - `add()`, `remove()`, `remove_conflicts()`, `evict_lowest_fee()`
///
/// Read-only operations require shared (read) access:
/// - `contains()`, `get()`, `size()`, `count()`, `select_transactions()`
///
/// # Size Tracking Invariant
///
/// The `current_size` field must always equal the sum of all `entry.size` values
/// in `transactions`. This invariant is maintained atomically within each method:
/// - `add()`: adds `entry.size` when inserting
/// - `remove()`: subtracts `entry.size` when removing
/// - `evict_lowest_fee()`: subtracts size when evicting
///
/// The size is captured once in `MempoolEntry::new` to ensure consistency
/// between add and remove operations. This guarantees the invariant holds
/// as long as the external lock is held during the entire operation.
pub struct Mempool {
    /// Transactions by hash
    transactions: HashMap<Hash, MempoolEntry>,
    /// Transactions ordered by fee (fee_per_byte -> tx_hash)
    by_fee: BTreeMap<(u64, Hash), Hash>,
    /// Key images in mempool (for double-spend detection)
    key_images: HashSet<KeyImage>,
    /// Maximum mempool size in bytes
    max_size: usize,
    /// Current size in bytes (invariant: sum of all entry.size)
    current_size: usize,
    /// Current chain height
    chain_height: u64,
    /// Circular audit log of recent mempool events (capped at AUDIT_LOG_CAPACITY)
    audit_log: VecDeque<AuditEvent>,
}

impl Mempool {
    /// Create a new mempool with default max size.
    ///
    /// Default sourced from `constants::MAX_MEMPOOL_BYTES` (300 MB) for
    /// Bitcoin Core parity (`DEFAULT_MAX_MEMPOOL_SIZE_MB = 300` at
    /// src/kernel/mempool_options.h:19 in the master read this session;
    /// the prior comment placed the constant in `src/policy/policy.h`,
    /// which is the wrong header). Prior to this fix, `Mempool::new`
    /// hardcoded 100 MB which silently diverged from
    /// `constants::MAX_MEMPOOL_BYTES` — the constant was authoritative
    /// in name only.
    pub fn new() -> Self {
        Self::with_max_size(crate::constants::MAX_MEMPOOL_BYTES)
    }

    /// Create a new mempool with specified max size
    pub fn with_max_size(max_size: usize) -> Self {
        Mempool {
            transactions: HashMap::new(),
            by_fee: BTreeMap::new(),
            key_images: HashSet::new(),
            max_size,
            current_size: 0,
            chain_height: 0,
            audit_log: VecDeque::with_capacity(AUDIT_LOG_CAPACITY),
        }
    }

    /// Update chain height and expire old transactions.
    pub fn set_height(&mut self, height: u64) {
        self.chain_height = height;
        self.expire_old_transactions(height);
    }

    /// HARDENING (Layer 5): Transaction expiry.
    /// Evict transactions that have been in the mempool for more than
    /// TX_EXPIRY_BLOCKS blocks (~9.6 hours at 120s blocks). This prevents
    /// the mempool from accumulating stale transactions that will never
    /// be mined (e.g., fee too low for current conditions).
    ///
    /// AUDIT (2026-07-02): switched from a local `const TX_EXPIRY_BLOCKS
    /// = 288` shadow to `crate::constants::TX_EXPIRY_BLOCKS`. The public
    /// constant had been declared as 500 (in constants.rs L182) while
    /// this local shadow used 288, so the wider codebase (see
    /// wallet/balance.rs L51 and L64) had learned to reference "the
    /// mempool's TX_EXPIRY_BLOCKS (288)" from *this* file's local
    /// value — the public constant was orphaned and its value was a
    /// lie. Public constant is now aligned to 288 and imported here.
    fn expire_old_transactions(&mut self, current_height: u64) {
        use crate::constants::TX_EXPIRY_BLOCKS;

        let expired: Vec<Hash> = self
            .transactions
            .iter()
            .filter(|(_, entry)| {
                current_height.saturating_sub(entry.height_added) > TX_EXPIRY_BLOCKS
            })
            .map(|(hash, _)| *hash)
            .collect();

        for hash in &expired {
            self.audit(AuditEvent::TxRemoved {
                hash: *hash,
                reason: EvictReason::Expired,
                timestamp: unix_now(),
            });
            self.remove(hash);
        }

        if !expired.is_empty() {
            tracing::info!(
                "Expired {} stale transactions (>{} blocks old)",
                expired.len(),
                TX_EXPIRY_BLOCKS
            );
        }
    }

    /// Push an event onto the audit log, dropping the oldest if at capacity.
    fn audit(&mut self, event: AuditEvent) {
        if self.audit_log.len() >= AUDIT_LOG_CAPACITY {
            self.audit_log.pop_front();
        }
        self.audit_log.push_back(event);
    }

    /// Emit a rejection event and return the error unchanged.
    fn reject(&mut self, hash: Hash, err: Error) -> Error {
        self.audit(AuditEvent::TxRejected {
            hash,
            reason: err.to_string(),
            timestamp: unix_now(),
        });
        err
    }

    /// Alias for [`add`](Self::add) — kept because `rpc/server.rs` and
    /// `rpc/node_api.rs` (ported from 2.0) call `mempool.accept(tx)`.
    #[inline]
    pub fn accept(&mut self, tx: Transaction) -> Result<Hash> {
        self.add(tx)
    }

    /// Add a transaction to the mempool with FULL crypto verification.
    /// This is the only public admission path; production code must use this
    /// (or the `accept` alias above).
    ///
    /// Phase A8 (audit fix): Crypto verification was extracted into a
    /// private helper `verify_crypto_for_admission` so a
    /// `#[cfg(any(test, feature = "test-utilities"))] add_skip_signatures`
    /// variant can exercise the same admission / RBF / key-image-conflict
    /// path with garbage range proofs. That is a deliberate, narrow test
    /// escape hatch — not a production code path. It is gated by
    /// `#[cfg(any(test, feature = "test-utilities"))]` so it cannot be
    /// called from any non-test compilation.
    ///
    /// AUDIT (2026-07-01): rewrote the docblock. Previously the doc
    /// comment for `add` had been split across the `accept` alias
    /// declaration — the "Alias for add" sentence had been pasted mid-
    /// paragraph, orphaning the "escape hatch — not a production code
    /// path" clause on top of `add`'s signature (starting with the word
    /// "hatch"). No behavior change; the two functions and their
    /// contracts are unchanged. Only the prose was untangled.
    pub fn add(&mut self, tx: Transaction) -> Result<Hash> {
        let tx_hash = tx.hash();

        if let Err(e) = self.preflight_check(&tx) {
            return Err(self.reject(tx_hash, e));
        }
        // Already-in-mempool short-circuit lives inside preflight_check.
        if self.transactions.contains_key(&tx_hash) {
            return Ok(tx_hash);
        }

        // Full crypto verification — required for production. Skipped only
        // in the test escape hatch below.
        // C-2 FIX: Use chain_tip_height for BP+ activation gate.
        // Mempool uses its tracked height (set via update_chain_height).
        let chain_h = self.chain_height;
        if let Err(e) = Self::verify_crypto_for_admission(&tx, chain_h) {
            return Err(self.reject(tx_hash, e));
        }

        self.admit_after_checks(tx, tx_hash)
    }

    /// Test-only: skip Bulletproof / balance / ring-sig verification.
    ///
    /// **NEVER** call this from production code. It's gated behind both
    /// `#[cfg(test)]` (for unit tests in this file) and the
    /// `test-utilities` Cargo feature (for integration tests in `tests/`).
    /// Without one of those compile contexts, the function does not exist
    /// and any caller fails to compile.
    ///
    /// Used by mempool RBF property tests in `tests/consensus_properties.rs`
    /// that build minimal Transfer txs with garbage range proofs to exercise
    /// the conflict resolution / fee ordering / size accounting paths
    /// without the (very expensive) crypto setup. Production callers must
    /// always go through `add()` which runs full Bulletproof + balance +
    /// ring sig verification (the C21-FIX hardening).
    #[cfg(any(test, feature = "test-utilities"))]
    /// Admit a transaction to the mempool, skipping ONLY cryptographic
    /// verification (ring signatures, range proofs). ALL other validation
    /// — structural, privacy policy, keyimage uniqueness, fee checks —
    /// still runs unconditionally.
    ///
    /// Use this ONLY for:
    /// - Test harnesses with pre-verified transactions
    /// - Replay from a local trusted database
    /// - Never for untrusted network input
    ///
    /// SECURITY (C-8 FIX): This was previously named add_skip_crypto and
    /// was interpreted too broadly. Category B (structural) and Category C
    /// (state) checks now always run.
    pub fn add_skip_signatures(&mut self, tx: Transaction) -> Result<Hash> {
        let tx_hash = tx.hash();
        if let Err(e) = self.preflight_check(&tx) {
            return Err(self.reject(tx_hash, e));
        }
        if self.transactions.contains_key(&tx_hash) {
            return Ok(tx_hash);
        }
        self.admit_after_checks(tx, tx_hash)
    }

    /// Legacy alias for [`add_skip_signatures`]. Same test-only contract,
    /// same test-only cfg gate.
    ///
    /// SECURITY (2026-06-03 critical-file review): previously this alias
    /// was a `pub fn` with NO cfg attribute — it leaked the signature-skip
    /// admission path into production builds. No production caller used
    /// it (confirmed via repo-wide grep), but the absence of the gate
    /// meant any future caller — including a malicious extension or an
    /// accidental refactor — could bypass ring-sig + range-proof +
    /// balance-proof verification by name alone. The Cargo.toml comment
    /// at the `test-utilities` feature explicitly stated the intent
    /// ("cfg-gated test-only helpers"); the gate was just omitted on the
    /// alias when add_skip_signatures was renamed in for C-8. Defense
    /// in depth: gate it, delegate to the cfg-gated implementation, and
    /// the surface disappears in release builds.
    #[cfg(any(test, feature = "test-utilities"))]
    #[doc(hidden)]
    pub fn add_skip_crypto(&mut self, tx: Transaction) -> Result<Hash> {
        self.add_skip_signatures(tx)
    }

    /// Pre-flight checks shared by both `add` and `add_skip_crypto`:
    /// reject coinbase, run structural + privacy policy validation.
    ///
    /// SECURITY (C-8 FIX): This function runs ALL Category B (structural)
    /// and Category C (state) checks. Only Category A (cryptographic
    /// verification — signatures, range proofs) may be skipped.
    /// Privacy policy checks (zero stealth address, zero commitment)
    /// are Category B and must NEVER be skipped.
    fn preflight_check(&self, tx: &Transaction) -> Result<()> {
        // SECURITY: Reject coinbase transactions from the mempool.
        if tx.is_coinbase() {
            return Err(Error::InvalidMessage(
                "coinbase transactions cannot enter mempool".into(),
            ));
        }

        // SECURITY (A6-MEMPOOL): Run structural validation.
        validate_transaction_basic(tx)?;

        // SECURITY (C-8 FIX): Run privacy policy checks unconditionally.
        // These are Category B (structural) — a zero stealth address or
        // zero commitment is malformed data, not a crypto question.
        // Previously these only ran in the full validate_transaction path,
        // meaning skip_crypto bypassed them.
        if !tx.is_coinbase() {
            crate::consensus::privacy_policy::check_tx_privacy(tx)?;
        }

        Ok(())
    }

    /// Full cryptographic verification of a tx before mempool admission.
    /// Range proofs (Bulletproofs), balance proof, and CLSAG ring signatures.
    /// SECURITY (C21-FIX): the entire reason this function exists.
    /// C-2 FIX: Accept chain_height to enforce BP+ activation gate at mempool level.
    fn verify_crypto_for_admission(tx: &Transaction, chain_height: u64) -> Result<()> {
        if tx.is_coinbase() {
            return Ok(());
        }
        if !verify_output_range_proofs(tx, chain_height) {
            return Err(Error::InvalidTransaction(
                "Range proof verification failed — rejected at mempool".into(),
            ));
        }
        if !verify_balance_proof(tx) {
            return Err(Error::InvalidTransaction(
                "Balance proof verification failed — rejected at mempool".into(),
            ));
        }
        for (idx, input) in tx.inputs.iter().enumerate() {
            if !verify_ring_signature(tx, input, idx) {
                return Err(Error::InvalidTransaction(format!(
                    "Ring signature verification failed on input {} — rejected at mempool",
                    idx
                )));
            }
        }
        Ok(())
    }

    /// Final admission path: size/fee/RBF checks + actual insertion.
    /// Called by both `add` (after crypto verify) and `add_skip_crypto`
    /// (skipping crypto). Owns the consensus rules below the crypto layer.
    fn admit_after_checks(&mut self, tx: Transaction, tx_hash: Hash) -> Result<Hash> {
        // Check transaction size
        let size = tx.size();
        if size > MAX_TX_SIZE {
            let err = Error::TransactionTooLarge {
                size,
                max: MAX_TX_SIZE,
            };
            return Err(self.reject(tx_hash, err));
        }

        // HARDENING (Layer 5): Dynamic minimum fee.
        // As mempool fills, required fee increases exponentially.
        // This makes spam attacks progressively more expensive.
        //   fullness < 25%: base fee (MIN_FEE_PER_BYTE)
        //   fullness 25-50%: 2x base
        //   fullness 50-75%: 4x base
        //   fullness 75-100%: 8x base
        let fullness_pct = if self.max_size > 0 {
            (self.current_size * 100) / self.max_size
        } else {
            0
        };
        let fee_multiplier: u64 = match fullness_pct {
            0..=24 => 1,
            25..=49 => 2,
            50..=74 => 4,
            _ => 8,
        };
        let min_fee = (size as u64) * MIN_FEE_PER_BYTE * fee_multiplier;
        if tx.fee.as_atomic() < min_fee {
            let err = Error::FeeTooLow {
                fee: tx.fee.as_atomic(),
                min: min_fee,
            };
            return Err(self.reject(tx_hash, err));
        }

        // SECURITY (BUG-12): Check for double-spend in mempool — allow RBF if fee is higher.
        // Collect ALL conflicting transactions (not just the first one) to maintain
        // the invariant that no two mempool txs share a key image.
        let new_fee_rate = scaled_fee_per_byte(tx.fee.as_atomic(), size);
        let mut to_replace: Vec<Hash> = Vec::new();
        for ki in tx.key_images() {
            if self.key_images.contains(&ki) {
                // Find the conflicting transaction for this key image
                let conflicting = self
                    .transactions
                    .iter()
                    .find(|(_, entry)| entry.tx.key_images().iter().any(|k| k == &ki))
                    .map(|(hash, entry)| (*hash, entry.fee_per_byte));

                if let Some((old_hash, old_fee_rate)) = conflicting {
                    // Require 25% fee bump minimum to prevent spam.
                    // Phase D (audit fix): cross-multiply to avoid integer-division
                    // rounding (the previous `old*125/100` then `>` form rejected exact
                    // 125% bumps and silently allowed no-bump replacements at fee_rate=1).
                    //
                    // Accept iff: new_rate * DEN >= old_rate * NUM AND new_rate > old_rate
                    let lhs =
                        (new_fee_rate as u128).saturating_mul(RBF_FEE_BUMP_DENOMINATOR as u128);
                    let rhs = (old_fee_rate as u128).saturating_mul(RBF_FEE_BUMP_NUMERATOR as u128);
                    if lhs >= rhs && new_fee_rate > old_fee_rate {
                        if !to_replace.contains(&old_hash) {
                            to_replace.push(old_hash);
                        }
                        continue; // Check remaining key images for other conflicts
                    }
                }
                let err =
                    Error::DuplicateKeyImage("duplicate key image; fee too low to replace".into());
                return Err(self.reject(tx_hash, err));
            }
        }
        // Perform ALL replacements outside the borrow
        for old_hash in &to_replace {
            self.audit(AuditEvent::TxRemoved {
                hash: *old_hash,
                reason: EvictReason::ReplacedByFee,
                timestamp: unix_now(),
            });
            self.remove(&old_hash);
        }

        // Evict if needed to make room
        // SECURITY: Limit eviction attempts to prevent infinite loop if eviction fails
        let mut eviction_attempts = 0;
        const MAX_EVICTION_ATTEMPTS: usize = 100;
        while self.current_size + size > self.max_size && !self.transactions.is_empty() {
            let prev_size = self.current_size;
            self.evict_lowest_fee();
            eviction_attempts += 1;

            // If eviction didn't reduce size or we hit the limit, stop.
            // Log loudly so operators see why admission stalled — silent
            // rejection masked the cause in prior incidents. Throttled
            // to once per 5 seconds to avoid disk-fill during sustained
            // low-fee floods (audit-fix: previously could emit 10k+
            // WARN/s). Reference: Bitcoin Core `CTxMemPool::TrimToSize`
            // is at src/txmempool.cpp:861 in the master read this
            // session. The prior comment additionally asserted that
            // Bitcoin Core's `LogPrintf` facility does per-attempt
            // deduplication so throttling is unnecessary there — that
            // specific claim about LogPrintf's dedup behaviour was not
            // re-verified this session and is dropped.
            if self.current_size >= prev_size || eviction_attempts >= MAX_EVICTION_ATTEMPTS {
                use std::sync::atomic::{AtomicU64, Ordering};
                static LAST_WARN_UNIX: AtomicU64 = AtomicU64::new(0);
                const WARN_THROTTLE_SECS: u64 = 5;
                let now_secs = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_secs())
                    .unwrap_or(0);
                let last = LAST_WARN_UNIX.load(Ordering::Relaxed);
                if now_secs.saturating_sub(last) >= WARN_THROTTLE_SECS {
                    LAST_WARN_UNIX.store(now_secs, Ordering::Relaxed);
                    tracing::warn!(
                        target: "mempool",
                        "Admission rejected: eviction exhausted after {} attempts. \
                         current_size={} max_size={} incoming_tx_size={}. \
                         Either incoming tx fee-rate is below the floor or all \
                         resident entries are equal-or-higher fee. \
                         (Log throttled to once per {}s.)",
                        eviction_attempts, self.current_size, self.max_size, size,
                        WARN_THROTTLE_SECS,
                    );
                }
                let err = Error::MempoolFull;
                return Err(self.reject(tx_hash, err));
            }
        }

        // Add transaction
        let timestamp = unix_now();
        let entry = MempoolEntry::new(tx, self.chain_height, timestamp);

        self.audit(AuditEvent::TxAdded {
            hash: tx_hash,
            fee: entry.fee,
            size: entry.size,
            timestamp,
        });

        // Track key images
        for ki in entry.tx.key_images() {
            self.key_images.insert(ki);
        }

        // Add to indices
        self.by_fee.insert((entry.fee_per_byte, tx_hash), tx_hash);
        self.current_size += entry.size;
        self.transactions.insert(tx_hash, entry);

        Ok(tx_hash)
    }

    /// Remove a transaction from the mempool
    pub fn remove(&mut self, tx_hash: &Hash) -> Option<Transaction> {
        if let Some(entry) = self.transactions.remove(tx_hash) {
            // Remove key images
            for ki in entry.tx.key_images() {
                self.key_images.remove(&ki);
            }

            // Remove from fee index
            self.by_fee.remove(&(entry.fee_per_byte, *tx_hash));
            self.current_size = self.current_size.saturating_sub(entry.size);

            Some(entry.tx)
        } else {
            None
        }
    }

    /// Remove transactions that are now in a block, AND evict any mempool
    /// transactions that conflict with them on key images (double-spend
    /// shadows of confirmed txs).
    ///
    /// # Why both removals matter
    ///
    /// 1. **Confirmed txs**: a tx that mined was already in our mempool;
    ///    we drop it because it's no longer pending.
    /// 2. **Shadow conflicts**: another mempool tx can spend the same UTXO
    ///    as a confirmed tx (different tx, same key image). The mempool
    ///    invariant `no two mempool txs share a key image` prevents this
    ///    *internally*, but it can still happen when:
    ///      - A peer had tx_A in their mempool, mined it, propagated the
    ///        block to us; we never saw tx_A but our mempool has tx_B
    ///        that re-spends the same UTXO. After block_accepted, tx_B
    ///        is permanently invalid (UTXO is now spent on chain) — every
    ///        subsequent block template that includes tx_B will be
    ///        rejected for "duplicate key image", stalling block
    ///        production until tx_B is manually evicted or expires.
    ///
    /// Without this eviction, a single shadow-conflict tx would stall the
    /// chain indefinitely (until the 288-block expiry timer fires, ~9.6
    /// hours). This caused two chain stalls during 2026-05-07 testing.
    /// Bitcoin Core does the same shadow-eviction from
    /// `CTxMemPool::removeForBlock` (VERIFIED at src/txmempool.cpp:405
    /// in the master read this session). The prior comment additionally
    /// cited Monero `tx_pool::on_blockchain_inc`; that specific Monero
    /// identifier was not re-confirmed against Monero source this
    /// session and is dropped. CoinCync missed the shadow-eviction step
    /// on the initial port.
    pub fn remove_confirmed(&mut self, txs: &[Transaction]) {
        let now = unix_now();

        // Pass 1: drop the txs that just confirmed.
        for tx in txs {
            let hash = tx.hash();
            self.audit(AuditEvent::TxRemoved {
                hash,
                reason: EvictReason::Confirmed,
                timestamp: now,
            });
            self.remove(&hash);
        }

        // Pass 2: evict shadow conflicts. For each key image used by the
        // confirmed block, find any mempool tx that ALSO uses it and drop
        // it — that mempool tx is now permanently invalid, and keeping it
        // would poison every subsequent block template.
        //
        // Two-pass collect-then-remove pattern: we cannot mutate
        // `self.transactions` while iterating it, so we first collect the
        // hashes to evict, then call `self.remove(&hash)` on each. The
        // self.remove() call cleans up by_fee, key_images, and
        // current_size atomically (its existing contract).
        let mut conflicting_hashes: Vec<Hash> = Vec::new();
        for confirmed_tx in txs {
            for ki in confirmed_tx.key_images() {
                // Find any MEMPOOL tx (other than ones we just removed in
                // pass 1, which are no longer present) using this key
                // image. Multiple mempool txs cannot share a key image
                // (mempool invariant enforced in add()), so this find()
                // returns at most one match per key image.
                let conflicting = self
                    .transactions
                    .iter()
                    .find(|(_, entry)| entry.tx.key_images().iter().any(|k| k == &ki))
                    .map(|(hash, _)| *hash);
                if let Some(h) = conflicting {
                    if !conflicting_hashes.contains(&h) {
                        conflicting_hashes.push(h);
                    }
                }
            }
        }
        for hash in &conflicting_hashes {
            self.audit(AuditEvent::TxRemoved {
                hash: *hash,
                reason: EvictReason::DoubleSpend,
                timestamp: now,
            });
            self.remove(hash);
        }
        if !conflicting_hashes.is_empty() {
            tracing::info!(
                "Evicted {} shadow-conflict mempool tx(s) after block apply",
                conflicting_hashes.len()
            );
        }
    }

    /// Re-validate every remaining mempool tx against the current chain
    /// state and evict any that no longer pass. Called by the chain
    /// orchestrator after `remove_confirmed` + `set_height` on every
    /// successful block apply.
    ///
    /// **What this catches that `remove_confirmed` doesn't:**
    /// `remove_confirmed` drops mined txs and shadow-conflicts (same
    /// key image as a confirmed tx). It does NOT catch txs whose
    /// CONSENSUS VALIDITY changed without a mined-tx collision.
    /// Two scenarios make this matter:
    ///
    /// 1. **Hard-fork rule transition** — at the activation height of
    ///    the `MIN_OUTPUT_AGE` 10 → 100 fork (v1.0.10), every mempool
    ///    tx whose input coinbase was age 10-99 just became invalid.
    ///    `remove_confirmed` wouldn't catch these because no confirmed
    ///    tx shares their key images.
    ///
    /// 2. **Reorg** — `AcceptedReorg` changes which UTXOs exist and
    ///    at what heights. A mempool tx whose input coinbase landed
    ///    in an orphaned block may now reference a non-existent
    ///    output, OR may reference a coinbase that's now at a
    ///    different (younger) height under the reorg branch. The
    ///    `restore_orphaned` path re-admits txs that orphaned-block
    ///    miners had, but doesn't revalidate already-mempool txs.
    ///
    /// **Belt-and-suspenders.** `src/mining/template.rs:70-95` does
    /// the same filter at template-build time, so a tx that escaped
    /// this evict path wouldn't poison a mined block — but it'd sit
    /// in the mempool burning memory + propagating to peers who'd
    /// also waste cycles validating it. Evicting at admission time
    /// is the cheaper place to do this work.
    ///
    /// **Cost.** O(N_mempool_txs) × cost-of-validate_transaction
    /// (~5ms per CLSAG tx). For a healthy mempool ≤1000 txs, ~5s
    /// per block worst case — well under the 120s block budget.
    /// For larger mempools this could matter; revisit with a
    /// dirty-set / changed-context optimization if it shows up in
    /// profiles.
    pub fn shadow_evict_invalid<C>(&mut self, chain: &C)
    where
        C: ShadowEvictChain,
    {
        let now = unix_now();
        let mut invalid_hashes: Vec<(Hash, String)> = Vec::new();

        for (hash, entry) in &self.transactions {
            if let Err(e) = chain.validate_transaction(&entry.tx) {
                invalid_hashes.push((*hash, format!("{}", e)));
            }
        }

        if invalid_hashes.is_empty() {
            return;
        }

        tracing::info!(
            "shadow-evict: dropping {} mempool tx(s) that no longer validate against chain state",
            invalid_hashes.len()
        );
        for (hash, reason) in invalid_hashes {
            tracing::debug!("  shadow-evict {}: {}", hash, reason);
            self.audit(AuditEvent::TxRemoved {
                hash,
                reason: EvictReason::DoubleSpend, // closest existing variant
                timestamp: now,
            });
            self.remove(&hash);
        }
    }

    /// Check if a key image is in the mempool
    pub fn contains_key_image(&self, ki: &KeyImage) -> bool {
        self.key_images.contains(ki)
    }

    /// Check if a transaction is in the mempool
    pub fn contains(&self, tx_hash: &Hash) -> bool {
        self.transactions.contains_key(tx_hash)
    }

    /// Get a transaction by hash
    pub fn get(&self, tx_hash: &Hash) -> Option<&Transaction> {
        self.transactions.get(tx_hash).map(|e| &e.tx)
    }

    /// Get transactions for block template, ordered by fee (highest first)
    ///
    /// Uses a HashSet for O(1) key image conflict detection between selected
    /// transactions, avoiding the previous O(n*m) nested iteration.
    pub fn get_block_transactions(&self, max_size: usize, max_count: usize) -> Vec<Transaction> {
        let mut result = Vec::new();
        let mut total_size = 0;
        let mut selected_key_images: HashSet<KeyImage> = HashSet::new();

        // Iterate in reverse order (highest fee first)
        for (_, tx_hash) in self.by_fee.iter().rev() {
            if result.len() >= max_count {
                break;
            }

            if let Some(entry) = self.transactions.get(tx_hash) {
                if total_size + entry.size <= max_size {
                    // Check for key image conflicts with already-selected txs (O(1) per key image)
                    let tx_key_images = entry.tx.key_images();
                    let has_conflict = tx_key_images
                        .iter()
                        .any(|ki| selected_key_images.contains(ki));
                    if has_conflict {
                        continue;
                    }

                    // Track key images from this transaction
                    for ki in &tx_key_images {
                        selected_key_images.insert(*ki);
                    }

                    result.push(entry.tx.clone());
                    total_size += entry.size;
                }
            }
        }

        result
    }

    /// Get all transaction hashes
    pub fn get_hashes(&self) -> Vec<Hash> {
        self.transactions.keys().copied().collect()
    }

    /// Get mempool size in bytes
    pub fn size(&self) -> usize {
        self.current_size
    }

    /// Get transaction count
    pub fn len(&self) -> usize {
        self.transactions.len()
    }

    /// Compute fee-per-byte percentiles from current mempool contents.
    ///
    /// Returns a map of percentile → fee_per_byte (e.g., p25, p50, p75, p90).
    /// When the mempool is empty, returns `MIN_FEE_PER_BYTE` for all percentiles.
    /// This enables wallets to estimate competitive fees based on actual demand.
    pub fn fee_percentiles(&self) -> FeePercentiles {
        let min_fee = crate::constants::MIN_FEE_PER_BYTE;

        if self.transactions.is_empty() {
            return FeePercentiles {
                p25: min_fee,
                p50: min_fee,
                p75: min_fee,
                p90: min_fee,
                count: 0,
            };
        }

        // Collect all fee_per_byte values, ALREADY sorted ascending.
        // `by_fee` is BTreeMap<(fee_per_byte, Hash), _>; key iteration
        // visits in tuple-ascending order, which is (fee_per_byte asc,
        // tied by hash asc). Extracting just fee_per_byte preserves the
        // ascending order. No `sort_unstable()` needed — that was an
        // O(N) no-op the audit caught. Reference: std::collections
        // BTreeMap docs guarantee sorted iteration.
        let fees: Vec<u64> = self.by_fee.keys().map(|(fpb, _)| *fpb).collect();

        let n = fees.len();
        let percentile = |pct: usize| -> u64 {
            let idx = (n * pct / 100).min(n.saturating_sub(1));
            fees[idx].max(min_fee)
        };

        FeePercentiles {
            p25: percentile(25),
            p50: percentile(50),
            p75: percentile(75),
            p90: percentile(90),
            count: n,
        }
    }

    /// Check if mempool is empty
    pub fn is_empty(&self) -> bool {
        self.transactions.is_empty()
    }

    /// Clear the mempool
    pub fn clear(&mut self) {
        self.transactions.clear();
        self.by_fee.clear();
        self.key_images.clear();
        self.current_size = 0;
    }

    /// SECURITY (M-8): Remove transactions older than `max_age_secs`.
    ///
    /// Transactions that sit in the mempool indefinitely waste memory and may
    /// reference outputs that have since been spent in other blocks. This
    /// should be called periodically (e.g. every 60s from the maintenance task).
    pub fn expire_old(&mut self, max_age_secs: u64) -> usize {
        let now = unix_now();

        let expired: Vec<Hash> = self
            .transactions
            .iter()
            .filter(|(_, entry)| now.saturating_sub(entry.added_time) > max_age_secs)
            .map(|(hash, _)| *hash)
            .collect();

        let count = expired.len();
        for hash in expired {
            self.audit(AuditEvent::TxRemoved {
                hash,
                reason: EvictReason::Expired,
                timestamp: now,
            });
            self.remove(&hash);
        }
        count
    }

    /// Verify size tracking invariant (for testing/debugging)
    ///
    /// Returns true if current_size matches the sum of all entry sizes.
    /// This should always return true in correctly functioning code.
    pub fn verify_size_invariant(&self) -> bool {
        let actual_size: usize = self.transactions.values().map(|e| e.size).sum();
        if actual_size != self.current_size {
            tracing::error!(
                "Mempool size invariant violated: tracked={}, actual={}",
                self.current_size,
                actual_size
            );
            return false;
        }
        true
    }

    /// Evict the transaction with lowest fee
    fn evict_lowest_fee(&mut self) {
        if let Some(((_, tx_hash), _)) = self.by_fee.iter().next().map(|(k, v)| (*k, *v)) {
            self.audit(AuditEvent::TxRemoved {
                hash: tx_hash,
                reason: EvictReason::LowFee,
                timestamp: unix_now(),
            });
            self.remove(&tx_hash);
        }
    }

    /// Remove transactions that conflict with confirmed key images
    pub fn remove_conflicts(&mut self, key_images: &[KeyImage]) {
        let to_remove: Vec<Hash> = self
            .transactions
            .iter()
            .filter(|(_, entry)| {
                entry
                    .tx
                    .key_images()
                    .iter()
                    .any(|ki| key_images.contains(ki))
            })
            .map(|(hash, _)| *hash)
            .collect();

        for hash in to_remove {
            self.remove(&hash);
        }
    }

    /// Return all audit events currently in the log, oldest first.
    pub fn audit_log(&self) -> Vec<AuditEvent> {
        self.audit_log.iter().cloned().collect()
    }

    /// Number of events currently in the audit log.
    pub fn audit_log_len(&self) -> usize {
        self.audit_log.len()
    }

    /// Clear the audit log without touching the mempool contents.
    pub fn clear_audit_log(&mut self) {
        self.audit_log.clear();
    }

    /// Save all mempool transactions to disk for persistence across restarts.
    ///
    /// Serializes transactions using borsh and writes to `<data_dir>/mempool.dat`.
    /// Called on graceful shutdown to avoid losing unconfirmed transactions.
    pub fn save_to_disk(&self, data_dir: &Path) -> Result<usize> {
        let txs: Vec<Transaction> = self.transactions.values().map(|e| e.tx.clone()).collect();
        let count = txs.len();
        if count == 0 {
            // Remove stale file if mempool is empty
            let path = data_dir.join("mempool.dat");
            let _ = std::fs::remove_file(&path);
            return Ok(0);
        }
        let data = borsh::to_vec(&txs).map_err(|e| Error::SerializationError(e.to_string()))?;
        let path = data_dir.join("mempool.dat");

        // Atomic write: write to .tmp first, then rename onto the target
        // path. A crash mid-write would leave a partial .tmp file (which
        // we ignore on next startup because we only read .dat), preserving
        // the previous good mempool.dat. Reference: Bitcoin Core's
        // `DumpMempool` (VERIFIED at src/node/mempool_persist.cpp:153
        // in the master read this session) uses a similar temp-file +
        // rename dump pattern. The prior comment named a `RenameOver`
        // helper as the rename primitive; that specific helper name
        // was not re-confirmed against upstream this session, so the
        // specific helper reference is dropped. Direct `fs::write`
        // (the pre-fix behavior here) would
        // corrupt mempool.dat on power loss, then line 1042 (silent file
        // removal on parse failure) would drop ALL pending txs on
        // restart — confirmed transaction loss for users.
        let tmp_path = path.with_extension("dat.tmp");
        std::fs::write(&tmp_path, &data)
            .map_err(|e| Error::DatabaseError(format!("Failed to write mempool.dat.tmp: {}", e)))?;
        std::fs::rename(&tmp_path, &path).map_err(|e| {
            // Best-effort cleanup of the stranded temp file. We do
            // NOT propagate this error — the original rename error
            // is the meaningful one for the caller.
            let _ = std::fs::remove_file(&tmp_path);
            Error::DatabaseError(format!(
                "Failed to atomically rename mempool.dat.tmp \u{2192} mempool.dat: {}",
                e
            ))
        })?;
        Ok(count)
    }

    /// Load transactions from disk and re-add them to the mempool.
    ///
    /// Reads `<data_dir>/mempool.dat`, deserializes, and calls `add()` for each
    /// transaction. Invalid or conflicting transactions are silently skipped.
    /// The file is deleted after loading regardless of success.
    pub fn load_from_disk(&mut self, data_dir: &Path) -> Result<usize> {
        let path = data_dir.join("mempool.dat");
        if !path.exists() {
            return Ok(0);
        }

        // DoS-on-startup defense: bound the read at MAX_MEMPOOL_BYTES
        // before allocating, then bound the parsed Vec length at
        // MAX_MEMPOOL_TXS as defense in depth.
        //
        // Trust model: mempool.dat is normally written by THIS node, but
        // ANY actor with filesystem access (other local user, container
        // neighbor, exfiltrator, leftover file from a crashed peer
        // process) can substitute a crafted file. An untrusted file with
        // a 4 GB Vec length prefix would (a) be fully read into memory by
        // std::fs::read, then (b) push borsh into a long allocation loop
        // before failing. Even bounded allocation strategies in borsh 1.x
        // can still amortize tens of GB of work before erroring.
        //
        // Prior art: Bitcoin Core's `LoadMempool` is VERIFIED at
        // src/node/mempool_persist.cpp:43 in the master read this
        // session. The prior comment additionally asserted specific
        // per-project limits (`MAX_BLOCK_SERIALIZED_SIZE = 4 MB`
        // file-size cap + tx-count sanity check for Bitcoin Core,
        // Monero `Blockchain::load_pool` with a 100k-tx cap); those
        // specific numeric values and the Monero identifier were not
        // re-verified against upstream this session and are dropped.
        // The bound-first pattern below stands on its own reasoning
        // above.
        let metadata = std::fs::metadata(&path)
            .map_err(|e| Error::DatabaseError(format!("stat mempool.dat: {}", e)))?;
        if metadata.len() > crate::constants::MAX_MEMPOOL_BYTES as u64 {
            // Remove the oversized file so we don't refuse forever.
            let _ = std::fs::remove_file(&path);
            return Err(Error::SerializationError(format!(
                "mempool.dat too large: {} bytes (max {})",
                metadata.len(),
                crate::constants::MAX_MEMPOOL_BYTES
            )));
        }

        let data = std::fs::read(&path)
            .map_err(|e| Error::DatabaseError(format!("Failed to read mempool.dat: {}", e)))?;
        // Always remove the file after reading to avoid replaying stale txs
        let _ = std::fs::remove_file(&path);

        let txs: Vec<Transaction> = borsh::from_slice(&data)
            .map_err(|e| Error::SerializationError(format!("mempool.dat corrupt: {}", e)))?;

        if txs.len() > crate::constants::MAX_MEMPOOL_TXS {
            return Err(Error::SerializationError(format!(
                "mempool.dat contains {} txs (max {})",
                txs.len(),
                crate::constants::MAX_MEMPOOL_TXS
            )));
        }

        let mut loaded = 0;
        for tx in txs {
            if self.add(tx).is_ok() {
                loaded += 1;
            }
        }
        Ok(loaded)
    }

    /// Get mempool statistics
    pub fn stats(&self) -> MempoolStats {
        let total_fee: Amount = self.transactions.values().map(|e| e.fee).sum();

        MempoolStats {
            tx_count: self.transactions.len(),
            size_bytes: self.current_size,
            total_fee,
            max_size: self.max_size,
        }
    }
}

impl Default for Mempool {
    fn default() -> Self {
        Self::new()
    }
}

/// Mempool statistics
#[derive(Clone, Debug)]
pub struct MempoolStats {
    pub tx_count: usize,
    pub size_bytes: usize,
    pub total_fee: Amount,
    pub max_size: usize,
}

/// Thread-safe mempool wrapper
pub struct SharedMempool {
    inner: Arc<RwLock<Mempool>>,
}

impl SharedMempool {
    pub fn new() -> Self {
        SharedMempool {
            inner: Arc::new(RwLock::new(Mempool::new())),
        }
    }

    // Helper to acquire write lock, recovering from poison if needed
    fn write_lock(&self) -> parking_lot::RwLockWriteGuard<'_, Mempool> {
        self.inner.write()
    }

    // Helper to acquire read lock, recovering from poison if needed
    fn read_lock(&self) -> parking_lot::RwLockReadGuard<'_, Mempool> {
        self.inner.read()
    }

    /// Public read lock — used by RPC handlers that need direct mempool access.
    pub fn read(&self) -> parking_lot::RwLockReadGuard<'_, Mempool> {
        self.inner.read()
    }

    /// Public write lock — used by RPC handlers that need direct mempool access.
    pub fn write(&self) -> parking_lot::RwLockWriteGuard<'_, Mempool> {
        self.inner.write()
    }

    pub fn add(&self, tx: Transaction) -> Result<Hash> {
        self.write_lock().add(tx)
    }

    /// Add a transaction with cheap chain-state prechecks before mempool admission.
    /// This rejects obviously unmineable transactions early to reduce DoS pressure.
    pub fn add_with_chain(
        &self,
        tx: Transaction,
        chain: &crate::chain::SharedBlockchain,
    ) -> Result<Hash> {
        // Audit MEDIUM #26: cheap precheck FIRST, expensive chain
        // validator second. Trivially-invalid txs (coinbase-shaped from
        // network, oversized, missing privacy fields, zero stealth
        // address) used to walk the full UTXO set + height-gated rules
        // before being rejected — wasteful CPU on attacker-controlled
        // garbage. The precheck is the same structural+privacy gate
        // that runs in Mempool::preflight_check but inlined here so we
        // don't need to acquire the mempool write lock first. Reference:
        // Bitcoin Core's `AcceptToMemoryPool` (VERIFIED at
        // src/validation.cpp:1781 in the master read this session) runs
        // an analogous cheap-first, expensive-second sequence. The prior
        // comment specifically ordered `CheckTransaction` (structural)
        // before `Consensus::CheckTxInputs` (UTXO walk) inside that
        // function; the exact internal call sequence was not re-read
        // this session and is not asserted. The qualitative cheap-
        // before-expensive principle stands.
        if tx.is_coinbase() {
            return Err(Error::InvalidMessage(
                "coinbase transactions cannot enter mempool".into(),
            ));
        }
        crate::consensus::validate_transaction_basic(&tx)?;
        crate::consensus::privacy_policy::check_tx_privacy(&tx)?;

        // 2026-06-07: run the FULL chain validator at submission time.
        // The previous code only checked key-image-spent — it missed
        // every height-gated rule (coinbase maturity, ring member
        // existence, lock heights, V2 activation, uniform-shape).
        // Those rules ARE enforced by shadow_evict_invalid after the
        // next block lands, so any tx tripping them was accepted to
        // mempool, sat briefly, then silently evicted — confusing
        // failure mode for users. Running the full validator here
        // makes the two paths (accept + revalidate) symmetric: if a
        // tx passes accept, it cannot evict for a chain-state reason
        // (only for true state churn AFTER acceptance, e.g. its real
        // input getting spent in a competing tx that landed first).
        let mut pending = Some(tx);
        retry_stable_admission(chain.as_ref(), |generation| {
            let Some(tx) = pending.as_ref() else {
                return AdmissionAttempt::Complete(Err(Error::Internal(
                    "transaction consumed before mempool admission completed".into(),
                )));
            };
            let validation = chain.validate_transaction(tx);

            // Do not acquire the chain lock while holding the mempool lock.
            // The final generation check is atomic and remains under this write
            // lock, so any later canonical update must run cleanup after insert.
            let mut mempool = self.write_lock();
            if chain.stable_generation() != Some(generation) {
                return AdmissionAttempt::Retry;
            }
            if let Err(error) = validation {
                return AdmissionAttempt::Complete(Err(error));
            }

            let Some(tx) = pending.take() else {
                return AdmissionAttempt::Complete(Err(Error::Internal(
                    "transaction consumed before mempool admission completed".into(),
                )));
            };
            AdmissionAttempt::Complete(mempool.add(tx))
        })
    }

    /// Re-admit transactions that were mined in blocks that just got
    /// disconnected during a chain reorganization. Each tx is re-checked
    /// against the new chain state — txs whose key images are spent in
    /// the new fork are silently dropped (the new chain superseded them),
    /// the rest go back into the mempool to be mined into the new chain.
    /// Returns the number of txs successfully restored.
    ///
    /// Without this, user transactions that were mined in orphaned blocks
    /// vanish on reorg — losing fee income for senders and breaking
    /// expectations for any wallet that observed the (now-orphaned)
    /// confirmation.
    pub fn restore_orphaned(
        &self,
        orphaned_txs: Vec<Transaction>,
        chain: &crate::chain::SharedBlockchain,
    ) -> usize {
        let total = orphaned_txs.len();
        let mut restored = 0;
        for tx in orphaned_txs {
            match self.add_with_chain(tx, chain) {
                Ok(_) => restored += 1,
                Err(e) => {
                    tracing::debug!(
                        "Reorg-orphaned tx not restored to mempool (likely superseded): {}",
                        e
                    );
                }
            }
        }
        if total > 0 {
            tracing::info!(
                "Reorg: restored {}/{} orphaned tx(s) to mempool",
                restored,
                total
            );
        }
        restored
    }

    pub fn remove(&self, tx_hash: &Hash) -> Option<Transaction> {
        self.write_lock().remove(tx_hash)
    }

    pub fn contains(&self, tx_hash: &Hash) -> bool {
        self.read_lock().contains(tx_hash)
    }

    pub fn get(&self, tx_hash: &Hash) -> Option<Transaction> {
        self.read_lock().get(tx_hash).cloned()
    }

    pub fn get_block_transactions(&self, max_size: usize, max_count: usize) -> Vec<Transaction> {
        self.read_lock().get_block_transactions(max_size, max_count)
    }

    pub fn stats(&self) -> MempoolStats {
        self.read_lock().stats()
    }

    pub fn fee_percentiles(&self) -> FeePercentiles {
        self.read_lock().fee_percentiles()
    }

    pub fn remove_confirmed(&self, txs: &[Transaction]) {
        self.write_lock().remove_confirmed(txs)
    }

    /// Re-validate remaining mempool txs against the chain and evict
    /// any that no longer pass. See `Mempool::shadow_evict_invalid`
    /// for the full rationale + cost analysis. Call after
    /// `remove_confirmed` + `set_height` on every block apply.
    pub fn shadow_evict_invalid<C>(&self, chain: &C)
    where
        C: ShadowEvictChain,
    {
        self.write_lock().shadow_evict_invalid(chain)
    }

    pub fn set_height(&self, height: u64) {
        self.write_lock().set_height(height)
    }

    pub fn len(&self) -> usize {
        self.read_lock().len()
    }

    pub fn size(&self) -> usize {
        self.read_lock().size()
    }

    pub fn get_all(&self) -> Vec<Transaction> {
        self.read_lock()
            .get_block_transactions(usize::MAX, usize::MAX)
    }

    pub fn total_fees(&self) -> Amount {
        self.read_lock().stats().total_fee
    }

    pub fn oldest_timestamp(&self) -> u64 {
        self.read_lock()
            .transactions
            .values()
            .map(|e| e.added_time)
            .min()
            .unwrap_or(0)
    }

    #[tracing::instrument(skip(self, tx), fields(tx_hash = %tx.hash().to_hex(), fee = tx.fee.as_atomic()))]
    pub fn add_transaction(&self, tx: Transaction) -> Result<Hash> {
        self.write_lock().add(tx)
    }

    /// Remove expired transactions (default: 24 hours)
    pub fn expire_old(&self, max_age_secs: u64) -> usize {
        self.write_lock().expire_old(max_age_secs)
    }

    /// Return all audit events currently in the log, oldest first.
    pub fn audit_log(&self) -> Vec<AuditEvent> {
        self.read_lock().audit_log()
    }

    /// Number of events currently in the audit log.
    pub fn audit_log_len(&self) -> usize {
        self.read_lock().audit_log_len()
    }

    /// Clear the audit log.
    pub fn clear_audit_log(&mut self) {
        self.write_lock().clear_audit_log();
    }

    /// Save mempool to disk for persistence across restarts.
    pub fn save_to_disk(&self, data_dir: &Path) -> Result<usize> {
        self.read_lock().save_to_disk(data_dir)
    }

    /// Load mempool from disk (call once at startup).
    pub fn load_from_disk(&self, data_dir: &Path) -> Result<usize> {
        self.write_lock().load_from_disk(data_dir)
    }

    // ------------------------------------------------------------------
    // Removed 2026-06-03: `revalidate_on_reorg`.
    //
    // Was dead code (zero callers via repo-wide grep) AND weaker than the
    // active reorg path. The real flow is restore_orphaned + shadow_evict
    // _invalid (wired in node.rs:695-703 and rpc/server.rs:890-899):
    //   * re-admits orphaned-block txs with full crypto verification, and
    //   * re-validates every remaining mempool tx via
    //     chain.validate_transaction — catching V2 activation flips, ring-
    //     member integrity, and lock-height changes, not just spends.
    //
    // The removed function only checked `chain.is_spent(ki)` per tx, so a
    // future engineer reaching for it by name would silently get the
    // inferior revalidation. Deleting eliminates the footgun without
    // changing any caller. If a chain.is_spent-only fast path is ever
    // wanted, add a narrower-named replacement (e.g. evict_double_spends
    // _only) so the contract is unambiguous.
    // ------------------------------------------------------------------
}

impl Default for SharedMempool {
    fn default() -> Self {
        Self::new()
    }
}

impl Clone for SharedMempool {
    fn clone(&self) -> Self {
        SharedMempool {
            inner: Arc::clone(&self.inner),
        }
    }
}

// ════════════════════════════════════════════════════════════════════
// Async wrappers (Phase 2 of the post-launch runtime-resilience refactor)
// ════════════════════════════════════════════════════════════════════
//
// Mirror of the `Blockchain::*_async` wrappers in `chain.rs`. The
// SharedMempool sync methods take parking_lot write locks and run full
// crypto verification on tx admit. Routing those through
// `tokio::task::spawn_blocking` from async contexts prevents the
// single-vCPU runtime-freeze pattern observed 2026-05-12 16:18 UTC.
//
// `SharedMempool` is `Clone` (just an Arc bump), so callers pass an
// owned clone instead of `&self`; the `spawn_blocking` closure needs
// `'static + Send` and an owned value satisfies that trivially.

impl SharedMempool {
    /// Async wrapper around [`SharedMempool::add_with_chain`]. Runs the
    /// cheap chain-state pre-check + full mempool admit (which includes
    /// CLSAG and Bulletproof+ verify) on `tokio::task::spawn_blocking`.
    pub async fn add_with_chain_async(
        self,
        tx: Transaction,
        chain: crate::chain::SharedBlockchain,
    ) -> Result<Hash> {
        tokio::task::spawn_blocking(move || self.add_with_chain(tx, &chain))
            .await
            .map_err(|e| {
                Error::Internal(format!(
                    "spawn_blocking join error in add_with_chain: {}",
                    e
                ))
            })?
    }

    /// Async wrapper around [`SharedMempool::get_block_transactions`].
    /// Mempool iteration up to `max_count` txs / `max_size` bytes.
    pub async fn get_block_transactions_async(
        self,
        max_size: usize,
        max_count: usize,
    ) -> Vec<Transaction> {
        tokio::task::spawn_blocking(move || self.get_block_transactions(max_size, max_count))
            .await
            .unwrap_or_default()
    }
}

#[cfg(test)]
mod generation_tests {
    use super::{
        retry_stable_admission, AdmissionAttempt, GenerationSource, MAX_CHAIN_GENERATION_ATTEMPTS,
    };
    use crate::error::Result;
    use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
    use std::sync::{Arc, Barrier};

    #[derive(Default)]
    struct FakeChain {
        generation: AtomicU64,
        updating: AtomicBool,
    }

    impl GenerationSource for FakeChain {
        fn stable_generation(&self) -> Option<u64> {
            if self.updating.load(Ordering::Acquire) {
                return None;
            }
            let generation = self.generation.load(Ordering::Acquire);
            (!self.updating.load(Ordering::Acquire)).then_some(generation)
        }
    }

    #[test]
    fn retries_when_generation_changes_before_commit() {
        let chain = Arc::new(FakeChain::default());
        let validation_ready = Arc::new(Barrier::new(2));
        let update_done = Arc::new(Barrier::new(2));

        let update_chain = Arc::clone(&chain);
        let update_ready = Arc::clone(&validation_ready);
        let update_complete = Arc::clone(&update_done);
        let updater = std::thread::spawn(move || {
            update_ready.wait();
            update_chain.updating.store(true, Ordering::Release);
            update_chain.generation.fetch_add(1, Ordering::AcqRel);
            update_chain.updating.store(false, Ordering::Release);
            update_complete.wait();
        });

        let attempts = AtomicUsize::new(0);
        let committed_generation = AtomicU64::new(u64::MAX);
        let result: Result<()> = retry_stable_admission(chain.as_ref(), |generation| {
            if attempts.fetch_add(1, Ordering::SeqCst) == 0 {
                validation_ready.wait();
                update_done.wait();
            }
            if chain.stable_generation() != Some(generation) {
                return AdmissionAttempt::Retry;
            }
            committed_generation.store(generation, Ordering::SeqCst);
            AdmissionAttempt::Complete(Ok(()))
        });

        updater.join().expect("updater thread panicked");
        result.expect("admission should succeed after retry");
        assert_eq!(attempts.load(Ordering::SeqCst), 2);
        assert_eq!(committed_generation.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn generation_retries_are_bounded() {
        let chain = FakeChain::default();
        let attempts = AtomicUsize::new(0);
        let result: Result<()> = retry_stable_admission(&chain, |_generation| {
            attempts.fetch_add(1, Ordering::SeqCst);
            chain.generation.fetch_add(1, Ordering::AcqRel);
            AdmissionAttempt::Retry
        });

        assert_eq!(
            attempts.load(Ordering::SeqCst),
            MAX_CHAIN_GENERATION_ATTEMPTS
        );
        assert!(matches!(result, Err(crate::error::Error::InvalidState(_))));
    }
}

// NOTE: the mempool test module previously used `TxType::AssetIssuance`
// to build cheap test transactions that bypassed crypto verification.
// The asset layer has been removed in the 1.0 cleanup, so the tests are
// gated out until a replacement builder (real Transfer txs with valid
// CLSAG + Bulletproofs) is authored.
#[cfg(any())]
mod tests {
    use super::*;
    use crate::primitives::SecretKey;
    use crate::transaction::TxType;

    /// Phase A7-4 (audit fix): Build a real cryptographically-valid AssetIssuance
    /// transaction.
    ///
    /// The previous version of this helper built a `TxType::Transfer` with garbage
    /// CLSAG signatures and a 100-byte zeroed range proof. That worked when the
    /// mempool deferred crypto verification to block validation, but the C21-FIX
    /// hardening (added later) now runs full Bulletproof + balance + ring sig
    /// verification on `add()`. The garbage tx legitimately fails — exactly
    /// what we want from the mempool, but it broke these tests.
    ///
    /// AssetIssuance bypasses range proof / balance / ring sig verification but
    /// still requires a valid issuer Schnorr signature, which we generate here
    /// with the real `sign_issuer_signature` helper. This gives us a tx that
    /// passes mempool admission *and* exercises the real add/remove/order
    /// codepaths — no test-only escape hatch needed.
    ///
    /// `tag` is mixed into the asset_id so each call produces a tx with a
    /// unique hash (otherwise the second `add()` would silently no-op).
    fn make_real_test_tx(fee: u64, tag: u8) -> Transaction {
        use rand::rngs::OsRng;
        let issuer_sk = SecretKey::generate(&mut OsRng);
        let issuer_pk = issuer_sk.public_key();

        let mut asset_bytes = [0u8; 32];
        asset_bytes[0] = tag;
        asset_bytes[1..9].copy_from_slice(&fee.to_le_bytes());
        let asset_id = AssetId::from_bytes(asset_bytes);

        let policy = AssetPolicy {
            asset_id,
            issuer_pubkey: issuer_pk,
            precision: 6,
            name: AssetPolicy::set_name("MEMPOOL_TEST"),
            can_mint_more: false,
            audit_pubkey: None,
        };

        let policy_bytes = borsh::to_vec(&policy).expect("policy borsh");
        let issuer_signature =
            crate::crypto::asset::sign_issuer_signature(&issuer_sk, &policy_bytes, &mut OsRng);

        Transaction {
            version: 1,
            tx_type: TxType::AssetIssuance,
            inputs: vec![],
            outputs: vec![],
            fee: Amount::from_atomic(fee),
            range_proof: vec![],
            extra: vec![],
            issuance: Some(AssetIssuanceData {
                policy,
                initial_mint: 1_000_000,
                issuer_signature,
            }),
        }
    }

    #[test]
    fn test_mempool_add_remove() {
        let mut mempool = Mempool::new();
        let tx = make_real_test_tx(100_000_000, 0xAA);
        let hash = mempool.add(tx.clone()).unwrap();

        assert!(mempool.contains(&hash));
        assert_eq!(mempool.len(), 1);

        mempool.remove(&hash);
        assert!(!mempool.contains(&hash));
        assert_eq!(mempool.len(), 0);
    }

    #[test]
    fn test_mempool_fee_ordering() {
        // Phase A7-4 (audit fix): the previous version of this test asserted
        // strict fee-descending ordering, which is only meaningful for
        // Transfer/Churn txs (which sort by `fee_per_byte`). AssetIssuance
        // txs all use a synthetic fee_per_byte=0 (see L307 in `add()`) and
        // sort by hash, not declared fee. Asserting `txs[0].fee >= txs[1].fee`
        // on two AssetIssuance txs is therefore meaningless.
        //
        // What we CAN assert with AssetIssuance test fixtures:
        //   1. Both txs are present in the block selection.
        //   2. Total fee atomic equals the sum of both individual fees.
        //   3. The selection is bounded by max_count.
        //
        // For real fee-priority ordering, see consensus_properties.rs which
        // exercises the full Transfer path with real ring sigs + range proofs.
        let mut mempool = Mempool::new();

        let tx_low = make_real_test_tx(100_000_000, 0x01);
        let tx_high = make_real_test_tx(500_000_000, 0x02);

        mempool.add(tx_low).unwrap();
        mempool.add(tx_high).unwrap();

        let txs = mempool.get_block_transactions(1_000_000, 10);
        assert_eq!(txs.len(), 2, "both AssetIssuance txs must be selected");
        let total: u64 = txs.iter().map(|t| t.fee.as_atomic()).sum();
        assert_eq!(
            total, 600_000_000,
            "sum of selected fees must equal both inputs"
        );
    }

    // (placeholder removed — load_from_disk tests now live in
    //  `mod load_from_disk_tests` below, outside the gated-out asset
    //  test module, so they actually compile.)
}

// Standalone test module for `load_from_disk` DoS defenses. Lives
// outside the `mod tests` block above which is intentionally gated
// out (`#[cfg(any())]`) pending a Transfer-tx test builder. These
// tests only need `Mempool::new()` + tempfile, no asset machinery.
#[cfg(test)]
mod load_from_disk_tests {
    use super::*;

    /// Startup DoS defense: a mempool.dat larger than MAX_MEMPOOL_BYTES
    /// must be rejected at the stat() stage before any read or
    /// borsh-decode work happens. The oversized file is removed so the
    /// node doesn't fail-loop on every startup.
    #[test]
    fn load_from_disk_rejects_oversized_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("mempool.dat");

        // Write exactly MAX_MEMPOOL_BYTES + 1 zero bytes — just past the cap.
        // Cheap: no allocation of the full payload, just a sparse-write
        // friendly seek + 1-byte tail. (On NTFS the underlying file may
        // physically allocate; that's fine for a unit test.)
        let oversize = crate::constants::MAX_MEMPOOL_BYTES as u64 + 1;
        let f = std::fs::File::create(&path).unwrap();
        f.set_len(oversize).unwrap();
        // Make sure the size reads back correctly.
        assert_eq!(std::fs::metadata(&path).unwrap().len(), oversize);

        let mut mempool = Mempool::new();
        let result = mempool.load_from_disk(dir.path());

        assert!(result.is_err(), "oversized mempool.dat must be rejected");
        let err_msg = format!("{}", result.unwrap_err());
        assert!(
            err_msg.contains("too large") || err_msg.contains("max"),
            "error must surface the size-cap reason, got: {}",
            err_msg
        );
        // And the oversized file MUST have been removed so we don't fail-loop.
        assert!(
            !path.exists(),
            "oversized mempool.dat must be removed after rejection"
        );
    }

    /// Companion to the above: a mempool.dat whose borsh-decoded
    /// `Vec<Transaction>` length prefix lies above MAX_MEMPOOL_TXS must
    /// also be rejected. We construct a forged file with a borsh
    /// little-endian u32 length prefix of MAX_MEMPOOL_TXS + 1 followed
    /// by zero payload — borsh will try to deserialize that many
    /// elements, which fails on the first read (truncated), so we
    /// actually verify the count check by writing a valid empty Vec
    /// representation and crafting the count check via a separate
    /// scaffold. Simplest: build an actual oversized Vec and serialize
    /// it. But 100,001 real Transactions would dominate test time, so
    /// we skip the exact-count test and rely on the constant + the
    /// straightforward `> MAX_MEMPOOL_TXS` check in the code being
    /// self-evident.
    ///
    /// What we DO test: the boundary case where len == 0 succeeds
    /// (zero-tx file loads to zero loaded, no error).
    #[test]
    fn load_from_disk_accepts_empty_vec() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("mempool.dat");

        // borsh encoding of an empty Vec<Transaction>: 4-byte u32(0) length prefix.
        let empty: Vec<Transaction> = Vec::new();
        let bytes = borsh::to_vec(&empty).unwrap();
        std::fs::write(&path, &bytes).unwrap();

        let mut mempool = Mempool::new();
        let loaded = mempool.load_from_disk(dir.path()).unwrap();
        assert_eq!(
            loaded, 0,
            "empty mempool.dat must load zero txs without error"
        );
        assert!(!path.exists(), "file is removed after successful read");
    }
}
