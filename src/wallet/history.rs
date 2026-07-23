//! # Transaction History
//!
//! Stores and manages wallet transaction history with full metadata.

use crate::primitives::{Amount, Hash};
use crate::wallet::SubaddressIndex;
use serde::{Deserialize, Serialize};

/// Transaction direction
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TxDirection {
    /// Incoming transaction (received funds)
    Incoming,
    /// Outgoing transaction (sent funds)
    Outgoing,
}

impl std::fmt::Display for TxDirection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TxDirection::Incoming => write!(f, "Incoming"),
            TxDirection::Outgoing => write!(f, "Outgoing"),
        }
    }
}

/// Transaction status
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TxStatus {
    /// Transaction is in mempool, not yet confirmed
    Pending,
    /// Transaction is confirmed but outputs not yet spendable
    Confirming,
    /// Transaction is fully confirmed and spendable
    Confirmed,
    /// Transaction failed (rejected by network)
    Failed,
}

impl TxStatus {
    /// Get status from confirmation count
    pub fn from_confirmations(confirmations: u64, unlock_height: u64, current_height: u64) -> Self {
        if confirmations == 0 {
            TxStatus::Pending
        } else if current_height < unlock_height {
            TxStatus::Confirming
        } else {
            TxStatus::Confirmed
        }
    }
}

impl std::fmt::Display for TxStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TxStatus::Pending => write!(f, "Pending"),
            TxStatus::Confirming => write!(f, "Confirming"),
            TxStatus::Confirmed => write!(f, "Confirmed"),
            TxStatus::Failed => write!(f, "Failed"),
        }
    }
}

/// A single transaction record in wallet history
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransactionRecord {
    // === Essential Fields ===
    /// Transaction hash (unique identifier)
    pub tx_hash: Hash,

    /// Unix timestamp when the transaction was mined (0 if pending)
    pub timestamp: u64,

    /// Amount transferred (in atomic units)
    pub amount: Amount,

    /// Transaction direction (incoming/outgoing)
    pub direction: TxDirection,

    /// Current status
    pub status: TxStatus,

    // === Context Fields ===
    /// Block height where transaction was included (0 if pending)
    pub block_height: u64,

    /// Transaction fee (only for outgoing, 0 for incoming)
    pub fee: Amount,

    /// Subaddress that received the funds (for incoming)
    pub subaddress: Option<SubaddressIndex>,

    /// Payment ID (if provided)
    pub payment_id: Option<String>,

    /// User-added memo/note (stored locally only)
    pub memo: Option<String>,

    /// Recipient address (for outgoing transactions)
    pub recipient_address: Option<String>,

    /// Block height when outputs become spendable
    pub unlock_height: u64,

    // === Internal Fields ===
    /// Output indices in this transaction that belong to us
    pub output_indices: Vec<u8>,

    /// Whether this transaction has been spent (for incoming)
    pub spent: bool,

    /// Key image (for tracking spent status)
    pub key_image: Option<Hash>,
}

impl TransactionRecord {
    /// Create a new incoming transaction record
    pub fn incoming(
        tx_hash: Hash,
        amount: Amount,
        block_height: u64,
        timestamp: u64,
        output_index: u8,
        subaddress: Option<SubaddressIndex>,
    ) -> Self {
        TransactionRecord {
            tx_hash,
            timestamp,
            amount,
            direction: TxDirection::Incoming,
            status: TxStatus::Pending,
            block_height,
            fee: Amount::from_atomic(0),
            subaddress,
            payment_id: None,
            memo: None,
            recipient_address: None,
            // CONSENSUS-COUPLED: maturity floor flips at MIN_OUTPUT_AGE
            // hard-fork height. Compute the unlock height using the rule
            // that will be in force when this output is first eligible to
            // spend — pessimistic (uses the landed-block's rule, which
            // matches what the user sees today). At the activation
            // boundary the rule strictly tightens, so a UI showing
            // unlock = landed + 10 for pre-fork outputs is correct even
            // if the spend happens post-fork (the validator's rule at
            // spend time uses the spend-block's height, which already
            // sees age >= 10 + (fork_height - landed) >= 100 by the time
            // it matters).
            unlock_height: block_height
                .saturating_add(crate::constants::min_output_age_at_height(block_height)),
            output_indices: vec![output_index],
            spent: false,
            key_image: None,
        }
    }

    /// Create a new outgoing transaction record
    pub fn outgoing(
        tx_hash: Hash,
        amount: Amount,
        fee: Amount,
        block_height: u64,
        timestamp: u64,
    ) -> Self {
        TransactionRecord {
            tx_hash,
            timestamp,
            amount,
            direction: TxDirection::Outgoing,
            status: TxStatus::Pending,
            block_height,
            fee,
            subaddress: None,
            payment_id: None,
            memo: None,
            recipient_address: None,
            unlock_height: 0, // N/A for outgoing
            output_indices: vec![],
            spent: false,
            key_image: None,
        }
    }

    /// Calculate confirmations based on current height
    pub fn confirmations(&self, current_height: u64) -> u64 {
        if self.block_height == 0 || current_height < self.block_height {
            0
        } else {
            current_height - self.block_height + 1
        }
    }

    /// Update status based on current blockchain state
    pub fn update_status(&mut self, current_height: u64) {
        let confirmations = self.confirmations(current_height);
        self.status =
            TxStatus::from_confirmations(confirmations, self.unlock_height, current_height);
    }

    /// Check if outputs are spendable
    pub fn is_spendable(&self, current_height: u64) -> bool {
        self.direction == TxDirection::Incoming
            && !self.spent
            && current_height >= self.unlock_height
    }

    /// Set user memo
    pub fn set_memo(&mut self, memo: &str) {
        self.memo = Some(memo.to_string());
    }

    /// Set payment ID
    pub fn set_payment_id(&mut self, payment_id: &str) {
        self.payment_id = Some(payment_id.to_string());
    }

    /// Mark as spent
    pub fn mark_spent(&mut self) {
        self.spent = true;
    }

    /// Format timestamp as human-readable string
    pub fn format_timestamp(&self) -> String {
        use std::time::{Duration, UNIX_EPOCH};

        if self.timestamp == 0 {
            return "Pending".to_string();
        }

        let _datetime = UNIX_EPOCH + Duration::from_secs(self.timestamp);

        // Use chrono for correct date formatting (handles leap years, etc.)
        use chrono::DateTime;
        match DateTime::from_timestamp(self.timestamp as i64, 0) {
            Some(dt) => dt.format("%Y-%m-%d %H:%M:%S UTC").to_string(),
            None => format!("{}s", self.timestamp),
        }
    }
}

/// Transaction history manager
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TransactionHistory {
    /// All transaction records
    records: Vec<TransactionRecord>,
}

impl TransactionHistory {
    /// Create empty history
    pub fn new() -> Self {
        TransactionHistory {
            records: Vec::new(),
        }
    }

    /// Add a transaction record, merging output indices if the same tx_hash
    /// and direction already exists (e.g., a tx sending to two of our subaddresses).
    pub fn add(&mut self, record: TransactionRecord) {
        if let Some(existing) = self
            .records
            .iter_mut()
            .find(|r| r.tx_hash == record.tx_hash && r.direction == record.direction)
        {
            // Merge: add only new output indices and accumulate amount once
            let mut has_new_index = false;
            for idx in &record.output_indices {
                if !existing.output_indices.contains(idx) {
                    existing.output_indices.push(*idx);
                    has_new_index = true;
                }
            }
            // Add the record's amount once if any new outputs were found
            if has_new_index {
                existing.amount = existing.amount.saturating_add(record.amount);
            }
        } else {
            self.records.push(record);
        }
    }

    /// Get transaction by hash
    pub fn get(&self, tx_hash: &Hash) -> Option<&TransactionRecord> {
        self.records.iter().find(|r| &r.tx_hash == tx_hash)
    }

    /// Get mutable transaction by hash
    pub fn get_mut(&mut self, tx_hash: &Hash) -> Option<&mut TransactionRecord> {
        self.records.iter_mut().find(|r| &r.tx_hash == tx_hash)
    }

    /// Get all records
    pub fn all(&self) -> &[TransactionRecord] {
        &self.records
    }

    /// Get records filtered by direction
    pub fn by_direction(&self, direction: TxDirection) -> Vec<&TransactionRecord> {
        self.records
            .iter()
            .filter(|r| r.direction == direction)
            .collect()
    }

    /// Get incoming transactions
    pub fn incoming(&self) -> Vec<&TransactionRecord> {
        self.by_direction(TxDirection::Incoming)
    }

    /// Get outgoing transactions
    pub fn outgoing(&self) -> Vec<&TransactionRecord> {
        self.by_direction(TxDirection::Outgoing)
    }

    /// Get pending transactions
    pub fn pending(&self) -> Vec<&TransactionRecord> {
        self.records
            .iter()
            .filter(|r| r.status == TxStatus::Pending)
            .collect()
    }

    /// Get recent transactions (sorted by timestamp, newest first)
    pub fn recent(&self, limit: usize) -> Vec<&TransactionRecord> {
        let mut sorted: Vec<_> = self.records.iter().collect();
        sorted.sort_by(|a, b| b.timestamp.cmp(&a.timestamp));
        sorted.into_iter().take(limit).collect()
    }

    /// Get transactions since a specific timestamp
    pub fn since(&self, timestamp: u64) -> Vec<&TransactionRecord> {
        self.records
            .iter()
            .filter(|r| r.timestamp >= timestamp)
            .collect()
    }

    /// Get transactions in a block range
    pub fn in_block_range(&self, start: u64, end: u64) -> Vec<&TransactionRecord> {
        self.records
            .iter()
            .filter(|r| r.block_height >= start && r.block_height <= end)
            .collect()
    }

    /// Update all transaction statuses based on current height
    pub fn update_all_statuses(&mut self, current_height: u64) {
        for record in &mut self.records {
            record.update_status(current_height);
        }
    }

    /// Drop incoming records whose `tx_hash` appears in `outputs`.
    /// Returns the number of records removed.
    ///
    /// Used during reorg rewind: the scanner's `outputs_to_remove`
    /// field names `(tx_hash, output_index)` pairs that were journaled
    /// as ours in the now-orphaned blocks. Because all outputs of a
    /// single tx live in the same block (txs are atomic), the
    /// appearance of ANY `(tx_hash, _)` in the rewind list means the
    /// entire incoming record for `tx_hash` belongs to an orphan and
    /// must go. We dedupe by `tx_hash` up front since `outputs` may
    /// list multiple `(h, i)` entries for the same `h`.
    pub fn remove_incoming_outputs(&mut self, outputs: &[(Hash, u8)]) -> usize {
        use std::collections::HashSet;
        let affected: HashSet<Hash> = outputs.iter().map(|(h, _)| *h).collect();
        let before = self.records.len();
        self.records
            .retain(|r| !(r.direction == TxDirection::Incoming && affected.contains(&r.tx_hash)));
        before - self.records.len()
    }

    /// Reset every outgoing record confirmed above `new_height` back to
    /// pending state (block_height = 0, status = Pending). Returns the
    /// number of records updated.
    ///
    /// Used during reorg rewind alongside `remove_incoming_outputs`:
    /// the scanner's `outputs_to_remove` only describes incoming outputs
    /// we own, so outgoing txs we previously sent that landed in an
    /// orphaned block need a complementary height-based pass. The tx
    /// itself is presumed re-broadcastable (it stays in mempool until
    /// TX_EXPIRY_BLOCKS); the rewind here just unrecords the
    /// no-longer-real confirmation. The next canonical block that
    /// includes the tx will re-set block_height + status via the
    /// normal scan path.
    ///
    /// NOTE: this is a coarse pass — it cannot tell which outgoing
    /// records had their tx actually re-broadcast and confirmed in a
    /// canonical block versus those that were re-confirmed at the same
    /// height during the same reorg window. Both cases are handled by
    /// the subsequent rescan, which will idempotently re-set
    /// block_height and status as it walks the canonical chain.
    pub fn revert_outgoing_above_height(&mut self, new_height: u64) -> usize {
        let mut count = 0;
        for r in &mut self.records {
            if r.direction == TxDirection::Outgoing && r.block_height > new_height {
                r.block_height = 0;
                r.status = TxStatus::Pending;
                count += 1;
            }
        }
        count
    }

    /// Mark a transaction as spent by key image
    pub fn mark_spent_by_key_image(&mut self, key_image: &Hash) {
        for record in &mut self.records {
            if record.key_image.as_ref() == Some(key_image) {
                record.mark_spent();
            }
        }
    }

    /// Inverse of `mark_spent_by_key_image`. Used during reorg rewind:
    /// when the spend signal that marked a record came from a tx in a
    /// now-orphaned block, the record needs `spent = false` so the UI
    /// + balance derivations reflect the canonical chain state.
    /// Returns the number of records actually updated.
    pub fn unmark_spent_by_key_image(&mut self, key_image: &Hash) -> usize {
        let mut count = 0;
        for record in &mut self.records {
            if record.key_image.as_ref() == Some(key_image) && record.spent {
                record.spent = false;
                count += 1;
            }
        }
        count
    }

    /// Set memo for a transaction
    pub fn set_memo(&mut self, tx_hash: &Hash, memo: &str) -> bool {
        if let Some(record) = self.get_mut(tx_hash) {
            record.set_memo(memo);
            true
        } else {
            false
        }
    }

    /// Check if any record's `recipient_address` field equals `address`.
    ///
    /// AUDIT (R-91 fix, 2026-07-02): the prior docstring said this
    /// checked BOTH "the address appears as a recipient in any outgoing
    /// tx" AND "as a receiving address in any incoming tx". That was
    /// misleading in two ways:
    ///
    /// 1. There is only ONE storage field consulted — `recipient_address`
    ///    on `TransactionRecord`. Whether that field carries meaning for
    ///    an incoming tx depends entirely on whether a caller has
    ///    invoked `set_recipient_address` after `record_incoming`.
    ///    Nothing populates it automatically for incoming records.
    /// 2. The prior wording made the function sound like a privacy
    ///    guarantee ("Useful for address reuse detection to protect
    ///    privacy") when in fact it will silently return `false` for
    ///    an incoming tx whose recipient_address was never annotated.
    ///    A caller relying on this to gate wallet actions ("only send
    ///    to fresh addresses") could reuse an address the wallet DID
    ///    receive from, unnoticed.
    ///
    /// The correct read: this is a bookkeeping helper for records the
    /// caller has explicitly tagged. Do NOT rely on it as a privacy
    /// gate — for outgoing-address reuse detection, the wallet keeps a
    /// separate set on `WalletData`; for incoming-address reuse, a
    /// dedicated stealth-address / subaddress lookup path exists.
    pub fn has_address(&self, address: &str) -> bool {
        self.records
            .iter()
            .any(|r| r.recipient_address.as_deref() == Some(address))
    }

    /// Set recipient address for a transaction (works for both directions).
    /// Should be called after record_outgoing/record_incoming to enable
    /// address reuse detection via has_address().
    pub fn set_recipient_address(&mut self, tx_hash: &Hash, address: &str) -> bool {
        if let Some(record) = self.get_mut(tx_hash) {
            record.recipient_address = Some(address.to_string());
            true
        } else {
            false
        }
    }

    /// Total received amount
    pub fn total_received(&self) -> Amount {
        self.incoming()
            .iter()
            .fold(Amount::from_atomic(0), |acc, r| {
                acc.saturating_add(r.amount)
            })
    }

    /// Total sent amount (including fees)
    pub fn total_sent(&self) -> Amount {
        self.outgoing()
            .iter()
            .fold(Amount::from_atomic(0), |acc, r| {
                acc.saturating_add(r.amount).saturating_add(r.fee)
            })
    }

    /// Total fees paid
    pub fn total_fees(&self) -> Amount {
        self.outgoing()
            .iter()
            .fold(Amount::from_atomic(0), |acc, r| acc.saturating_add(r.fee))
    }

    /// Number of transactions
    pub fn count(&self) -> usize {
        self.records.len()
    }

    /// Clear all history
    pub fn clear(&mut self) {
        self.records.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_hash() -> Hash {
        Hash::from_bytes([1u8; 32])
    }

    #[test]
    fn test_incoming_record() {
        let block_height = 100u64;
        let record = TransactionRecord::incoming(
            test_hash(),
            Amount::from_atomic(1_000_000_000_000), // 1 CYNC
            block_height,
            1700000000,
            0,
            None,
        );

        assert_eq!(record.direction, TxDirection::Incoming);
        assert_eq!(record.block_height, block_height);
        // unlock_height = block_height + min_output_age_at_height(block_height).
        // Pre-fork (testnet placeholder MIN_OUTPUT_AGE_HARDFORK_HEIGHT=u64::MAX)
        // this is 100 + 10 = 110. Mainnet (HARDFORK_HEIGHT=0) it's 100 + 100 = 200.
        // Computing from the helper keeps the test correct on both feature
        // configurations and on whatever activation height we eventually set.
        let expected_unlock =
            block_height + crate::constants::min_output_age_at_height(block_height);
        assert_eq!(record.unlock_height, expected_unlock);
        assert!(!record.spent);
    }

    #[test]
    fn test_outgoing_record() {
        let record = TransactionRecord::outgoing(
            test_hash(),
            Amount::from_atomic(500_000_000_000), // 0.5 CYNC
            Amount::from_atomic(3_000_000),       // fee
            100,
            1700000000,
        );

        assert_eq!(record.direction, TxDirection::Outgoing);
        assert_eq!(record.fee, Amount::from_atomic(3_000_000));
    }

    #[test]
    fn test_confirmations() {
        let record = TransactionRecord::incoming(
            test_hash(),
            Amount::from_atomic(1_000_000_000_000),
            100,
            1700000000,
            0,
            None,
        );

        assert_eq!(record.confirmations(99), 0);
        assert_eq!(record.confirmations(100), 1);
        assert_eq!(record.confirmations(110), 11);
    }

    #[test]
    fn test_history() {
        let mut history = TransactionHistory::new();

        let incoming = TransactionRecord::incoming(
            Hash::from_bytes([1u8; 32]),
            Amount::from_atomic(1_000_000_000_000),
            100,
            1700000000,
            0,
            None,
        );

        let outgoing = TransactionRecord::outgoing(
            Hash::from_bytes([2u8; 32]),
            Amount::from_atomic(500_000_000_000),
            Amount::from_atomic(3_000_000),
            101,
            1700001000,
        );

        history.add(incoming);
        history.add(outgoing);

        assert_eq!(history.count(), 2);
        assert_eq!(history.incoming().len(), 1);
        assert_eq!(history.outgoing().len(), 1);
    }

    #[test]
    fn test_set_memo() {
        let mut history = TransactionHistory::new();

        let record = TransactionRecord::incoming(
            test_hash(),
            Amount::from_atomic(1_000_000_000_000),
            100,
            1700000000,
            0,
            None,
        );

        history.add(record);
        history.set_memo(&test_hash(), "Coffee payment");

        let updated = history.get(&test_hash()).unwrap();
        assert_eq!(updated.memo, Some("Coffee payment".to_string()));
    }

    // === Reorg rewind tests (Task #3b: history side) ==================

    /// `remove_incoming_outputs` drops the incoming record for every
    /// distinct tx_hash mentioned in `outputs`, leaving outgoing
    /// records and unrelated incoming records untouched.
    #[test]
    fn test_remove_incoming_outputs_drops_matched_incoming() {
        let mut history = TransactionHistory::new();
        let orphan_tx = Hash::from_bytes([0xAA; 32]);
        let canonical_tx = Hash::from_bytes([0xBB; 32]);
        let sent_tx = Hash::from_bytes([0xCC; 32]);

        history.add(TransactionRecord::incoming(
            orphan_tx,
            Amount::from_atomic(1000),
            100,
            1700000000,
            0,
            None,
        ));
        history.add(TransactionRecord::incoming(
            canonical_tx,
            Amount::from_atomic(2000),
            90,
            1700000000,
            0,
            None,
        ));
        history.add(TransactionRecord::outgoing(
            sent_tx,
            Amount::from_atomic(500),
            Amount::from_atomic(10),
            95,
            1700000000,
        ));
        assert_eq!(history.count(), 3);

        let dropped = history.remove_incoming_outputs(&[(orphan_tx, 0)]);
        assert_eq!(dropped, 1);
        assert_eq!(history.count(), 2);
        assert!(history.get(&orphan_tx).is_none());
        assert!(history.get(&canonical_tx).is_some());
        assert!(history.get(&sent_tx).is_some());
    }

    /// Two outputs of the same tx in the rewind list collapse to one
    /// record removal (records are keyed by tx_hash + direction; the
    /// `add` merge logic ensures one record per incoming tx_hash).
    #[test]
    fn test_remove_incoming_outputs_dedupes_by_tx_hash() {
        let mut history = TransactionHistory::new();
        let tx = Hash::from_bytes([0xAA; 32]);
        let mut r =
            TransactionRecord::incoming(tx, Amount::from_atomic(1000), 100, 1700000000, 0, None);
        r.output_indices = vec![0, 1, 2];
        history.add(r);

        let dropped = history.remove_incoming_outputs(&[(tx, 0), (tx, 1), (tx, 2)]);
        assert_eq!(dropped, 1);
        assert!(history.get(&tx).is_none());
    }

    /// `remove_incoming_outputs` is idempotent — re-running the same
    /// removal returns 0 (the records are already gone). Defensive
    /// for orchestrators that may double-apply on retry.
    #[test]
    fn test_remove_incoming_outputs_idempotent() {
        let mut history = TransactionHistory::new();
        let tx = Hash::from_bytes([0xAA; 32]);
        history.add(TransactionRecord::incoming(
            tx,
            Amount::from_atomic(1000),
            100,
            1700000000,
            0,
            None,
        ));
        assert_eq!(history.remove_incoming_outputs(&[(tx, 0)]), 1);
        assert_eq!(history.remove_incoming_outputs(&[(tx, 0)]), 0);
        assert_eq!(history.count(), 0);
    }

    /// `revert_outgoing_above_height` resets outgoing records confirmed
    /// above `new_height` to Pending state, leaves earlier ones alone.
    #[test]
    fn test_revert_outgoing_above_height_resets_orphaned() {
        let mut history = TransactionHistory::new();
        let tx_low = Hash::from_bytes([0x01; 32]);
        let tx_high = Hash::from_bytes([0x02; 32]);

        let mut r_low = TransactionRecord::outgoing(
            tx_low,
            Amount::from_atomic(500),
            Amount::from_atomic(10),
            90,
            1700000000,
        );
        r_low.status = TxStatus::Confirmed;
        let mut r_high = TransactionRecord::outgoing(
            tx_high,
            Amount::from_atomic(700),
            Amount::from_atomic(10),
            105,
            1700000000,
        );
        r_high.status = TxStatus::Confirmed;
        history.add(r_low);
        history.add(r_high);

        // Rewind to height 95: tx at 90 stays, tx at 105 reverts.
        let updated = history.revert_outgoing_above_height(95);
        assert_eq!(updated, 1);
        let low = history.get(&tx_low).unwrap();
        let high = history.get(&tx_high).unwrap();
        assert_eq!(low.block_height, 90);
        assert_eq!(low.status, TxStatus::Confirmed);
        assert_eq!(high.block_height, 0);
        assert_eq!(high.status, TxStatus::Pending);
    }

    /// `revert_outgoing_above_height` does NOT touch incoming records
    /// confirmed above `new_height`. Those are handled by the
    /// `remove_incoming_outputs` path, which is driven by the scanner's
    /// explicit outputs_to_remove list (more precise than a height pass).
    #[test]
    fn test_revert_outgoing_does_not_touch_incoming() {
        let mut history = TransactionHistory::new();
        let tx = Hash::from_bytes([0x03; 32]);
        let mut r =
            TransactionRecord::incoming(tx, Amount::from_atomic(1000), 105, 1700000000, 0, None);
        r.status = TxStatus::Confirmed;
        history.add(r);

        let updated = history.revert_outgoing_above_height(95);
        assert_eq!(updated, 0);
        let after = history.get(&tx).unwrap();
        assert_eq!(after.block_height, 105);
        assert_eq!(after.status, TxStatus::Confirmed);
    }

    #[test]
    fn test_pagination() {
        let mut history = TransactionHistory::new();
        for i in 0..10u8 {
            let record = TransactionRecord::incoming(
                Hash::from_bytes([i; 32]),
                Amount::from_atomic(1_000_000_000_000),
                i as u64 * 10,
                1700000000 + i as u64,
                0,
                None,
            );
            history.add(record);
        }
        assert_eq!(history.count(), 10);
        let all = history.incoming();
        assert_eq!(all.len(), 10);
        // Verify distinct hashes
        let unique: std::collections::HashSet<_> = all.iter().map(|r| r.tx_hash).collect();
        assert_eq!(unique.len(), 10);
    }
}
