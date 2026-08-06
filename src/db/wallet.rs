//! # Wallet Database
//!
//! Persistent storage for wallet state, scanned outputs, and transactions.

use super::{deserialize, serialize};
use crate::db::shim::{Db, Tree};
use crate::error::{Error, Result};
use crate::primitives::{Amount, Hash, PublicKey};
use crate::transaction::{Transaction, TxOutput};
use borsh::{BorshDeserialize, BorshSerialize};
use serde::{Deserialize, Serialize};

/// Owned output (detected as ours during scanning)
#[derive(Clone, Debug, Serialize, Deserialize, BorshSerialize, BorshDeserialize)]
pub struct OwnedOutput {
    /// Transaction hash
    pub tx_hash: Hash,
    /// Output index in transaction
    pub output_index: u8,
    /// The output data
    pub output: TxOutput,
    /// Decrypted amount (if available)
    pub amount: Option<u64>,
    /// Block height where this was confirmed
    pub height: u64,
    /// Block hash
    pub block_hash: Hash,
    /// Timestamp of block
    pub timestamp: u64,
    /// Whether this output has been spent
    pub spent: bool,
    /// If spent, the spending transaction hash
    pub spent_by: Option<Hash>,
    /// If spent, the block height
    pub spent_at_height: Option<u64>,
    /// Subaddress index within the account (if using subaddresses)
    pub subaddress_index: Option<u32>,
    /// Account the subaddress belongs to (#26 follow-up). `None` for the main
    /// account / main address. Together with `subaddress_index` this is the
    /// full `(account, index)` the output was received on — needed to spend
    /// from the correct subaddress in a multi-account wallet. Old records
    /// persisted before this field decode via the legacy path with `None`.
    pub subaddress_account: Option<u32>,
}

impl OwnedOutput {
    /// Get the amount as Amount type
    pub fn amount_value(&self) -> Amount {
        Amount::from_atomic(self.amount.unwrap_or(0))
    }

    /// Check if output is spendable (confirmed and not spent)
    pub fn is_spendable(&self, current_height: u64, confirmations: u64) -> bool {
        !self.spent && current_height >= self.height + confirmations
    }
}

/// Legacy on-disk layout of [`OwnedOutput`], as written before the
/// `subaddress_account` field (#26 follow-up) was added. Field order and types
/// are identical to `OwnedOutput` minus that trailing field. Used only by
/// [`deserialize_owned_output`] to read records from older builds (and to
/// synthesize a legacy record in the migration test).
#[derive(BorshSerialize, BorshDeserialize)]
struct OwnedOutputLegacy {
    tx_hash: Hash,
    output_index: u8,
    output: TxOutput,
    amount: Option<u64>,
    height: u64,
    block_hash: Hash,
    timestamp: u64,
    spent: bool,
    spent_by: Option<Hash>,
    spent_at_height: Option<u64>,
    subaddress_index: Option<u32>,
}

/// Deserialize an [`OwnedOutput`], tolerating records written before the
/// `subaddress_account` field existed.
///
/// The current layout is tried first. borsh requires full byte consumption, so
/// a legacy record (which ends after `subaddress_index`) fails the new decode
/// when it reaches the trailing `subaddress_account` — we then fall back to the
/// legacy layout and default `subaddress_account = None`. The record is upgraded
/// to the new layout the next time it is written (`add_output` / `mark_spent`).
fn deserialize_owned_output(bytes: &[u8]) -> Result<OwnedOutput> {
    match deserialize::<OwnedOutput>(bytes) {
        Ok(o) => Ok(o),
        Err(_) => {
            let legacy: OwnedOutputLegacy = deserialize(bytes)?;
            Ok(OwnedOutput {
                tx_hash: legacy.tx_hash,
                output_index: legacy.output_index,
                output: legacy.output,
                amount: legacy.amount,
                height: legacy.height,
                block_hash: legacy.block_hash,
                timestamp: legacy.timestamp,
                spent: legacy.spent,
                spent_by: legacy.spent_by,
                spent_at_height: legacy.spent_at_height,
                subaddress_index: legacy.subaddress_index,
                subaddress_account: None,
            })
        }
    }
}

/// Wallet transaction record
#[derive(Clone, Debug, Serialize, Deserialize, BorshSerialize, BorshDeserialize)]
pub struct WalletTx {
    /// Transaction hash
    pub tx_hash: Hash,
    /// Full transaction (if stored)
    pub tx: Option<Transaction>,
    /// Block height (None if unconfirmed)
    pub height: Option<u64>,
    /// Block hash
    pub block_hash: Option<Hash>,
    /// Timestamp
    pub timestamp: u64,
    /// Amount received
    pub amount_received: u64,
    /// Amount sent
    pub amount_sent: u64,
    /// Fee paid (if we sent this tx)
    pub fee: u64,
    /// Whether this is an outgoing transaction
    pub outgoing: bool,
    /// Memo/note
    pub memo: Option<String>,
}

impl WalletTx {
    /// Net change to wallet balance
    ///
    /// SECURITY (A6-OVERFLOW): Use i128 intermediate to prevent wrapping overflow.
    /// With 10^12 atomic units per CYNC, values above ~9,223 CYNC would produce
    /// incorrect signs when cast directly to i64, showing wrong balance changes.
    pub fn net_change(&self) -> i64 {
        let received = self.amount_received as i128;
        let spent = (self.amount_sent as i128) + (self.fee as i128);
        (received - spent).clamp(i64::MIN as i128, i64::MAX as i128) as i64
    }

    /// Is this transaction confirmed?
    pub fn is_confirmed(&self) -> bool {
        self.height.is_some()
    }
}

/// Wallet scan state
#[derive(Clone, Debug, Default, Serialize, Deserialize, BorshSerialize, BorshDeserialize)]
pub struct ScanState {
    /// Last scanned block height
    pub scanned_height: u64,
    /// Last scanned block hash
    pub scanned_hash: Hash,
    /// Total outputs found
    pub outputs_found: u64,
    /// Total outputs spent
    pub outputs_spent: u64,
    /// Scan start time
    pub scan_started: u64,
    /// Last scan time
    pub last_scan_time: u64,
}

/// Wallet database
pub struct WalletDb {
    /// Owned outputs: output_key -> OwnedOutput
    outputs: Tree,
    /// Transactions: tx_hash -> WalletTx
    transactions: Tree,
    /// Scan state
    scan_state: Tree,
    /// Pending (unconfirmed) transactions
    pending: Tree,
    /// Address labels
    labels: Tree,
    /// H23: Secondary index tracking only unspent output keys
    unspent_outputs: Tree,
    /// H24: Secondary index for transactions ordered by timestamp
    tx_by_time: Tree,
}

impl WalletDb {
    const KEY_SCAN_STATE: &'static [u8] = b"scan_state";
    #[allow(dead_code)]
    const KEY_BALANCE: &'static [u8] = b"balance";

    /// Create new wallet database
    pub fn new(db: &Db) -> Result<Self> {
        let outputs = db
            .open_tree("wallet_outputs")
            .map_err(|e| Error::DatabaseError(e.to_string()))?;
        let transactions = db
            .open_tree("wallet_transactions")
            .map_err(|e| Error::DatabaseError(e.to_string()))?;
        let scan_state = db
            .open_tree("wallet_scan_state")
            .map_err(|e| Error::DatabaseError(e.to_string()))?;
        let pending = db
            .open_tree("wallet_pending")
            .map_err(|e| Error::DatabaseError(e.to_string()))?;
        let labels = db
            .open_tree("wallet_labels")
            .map_err(|e| Error::DatabaseError(e.to_string()))?;
        let unspent_outputs = db
            .open_tree("unspent_outputs")
            .map_err(|e| Error::DatabaseError(e.to_string()))?;
        let tx_by_time = db
            .open_tree("tx_by_time")
            .map_err(|e| Error::DatabaseError(e.to_string()))?;

        Ok(WalletDb {
            outputs,
            transactions,
            scan_state,
            pending,
            labels,
            unspent_outputs,
            tx_by_time,
        })
    }

    /// Make key for output lookup
    fn make_output_key(tx_hash: &Hash, index: u8) -> Vec<u8> {
        let mut key = Vec::with_capacity(33);
        key.extend_from_slice(tx_hash.as_bytes());
        key.push(index);
        key
    }

    /// Add owned output.
    ///
    /// AUDIT (2026-07-01): the two writes (primary `outputs` + secondary
    /// `unspent_outputs`) are now atomic — a crash between them was
    /// leaving the primary row without an index entry, which
    /// `get_unspent_outputs()` (line ~238) iterates via the secondary
    /// index. Result was that the wallet PERMANENTLY LOST VISIBILITY of
    /// UTXOs added in the crash window: `calculate_balance()` still saw
    /// them via `get_all_outputs()` (reads primary), but
    /// `get_spendable_outputs()` — the send path — went through
    /// `get_unspent_outputs()` and returned an empty result for the lost
    /// row, so the user could see the balance but not spend it. A rescan
    /// recovered it, but that's a manual step. Same shape as the
    /// utxos.rs "storage #1 + #7" atomicity fix; this brings the wallet
    /// db in line.
    pub fn add_output(&self, output: &OwnedOutput) -> Result<()> {
        let key = Self::make_output_key(&output.tx_hash, output.output_index);
        let data = serialize(output)?;
        let is_unspent = !output.spent;

        use crate::db::shim::transaction::Transactional;
        [&self.outputs, &self.unspent_outputs]
            .as_slice()
            .transaction(|trees| {
                let outputs_tx = &trees[0];
                let unspent_tx = &trees[1];
                outputs_tx.insert(key.clone(), data.clone())?;
                if is_unspent {
                    unspent_tx.insert(key.clone(), &[1u8][..])?;
                }
                Ok(())
            })
            .map_err(|e| Error::DatabaseError(e.to_string()))?;
        Ok(())
    }

    /// Get owned output
    pub fn get_output(&self, tx_hash: &Hash, index: u8) -> Result<Option<OwnedOutput>> {
        let key = Self::make_output_key(tx_hash, index);
        match self.outputs.get(&key) {
            Ok(Some(data)) => {
                let output: OwnedOutput = deserialize_owned_output(&data)?;
                Ok(Some(output))
            }
            Ok(None) => Ok(None),
            Err(e) => Err(Error::DatabaseError(e.to_string())),
        }
    }

    /// Mark output as spent.
    ///
    /// AUDIT (2026-07-01): the "set spent flag on primary" and "remove
    /// from unspent secondary index" writes are now atomic. Before this
    /// fix, a crash between the two left the row marked spent in the
    /// primary tree while still present in the `unspent_outputs` index.
    /// `get_unspent_outputs` (line ~238) has a defensive filter
    /// (`if !output.spent`) that dropped stale index entries, so the
    /// observable-badness in mark_spent's crash window was smaller than
    /// add_output's (no wrong balance / send). But (a) other iterations
    /// of `unspent_outputs` may not carry the defensive filter, and (b)
    /// the state divergence itself is a footgun for future readers.
    /// Fixing here matches the pattern the utxos.rs "storage #1 + #7"
    /// audit already established.
    /// AUDIT (R-46 fix, 2026-07-03): the pre-fix code did the
    /// `self.outputs.get()` read OUTSIDE the transaction, checked
    /// `output.spent`, then opened a transaction to commit. That
    /// creates a TOCTOU window: two concurrent mark_spent calls
    /// for the same (tx_hash, index) — e.g. two nodes reprocessing
    /// the same received tx after a reorg — could BOTH observe
    /// `output.spent == false`, both stage their spent_by
    /// attribution, and both transactions commit. The LATER commit
    /// wins, silently overwriting the first spent_by/spent_at_height.
    /// This corrupts wallet accounting (the visible spender in
    /// history now points at the wrong tx) and can mask a real
    /// double-spend from the wallet's perspective.
    ///
    /// Fix: the pre-read stays where it is (we need to know if the
    /// row exists to skip early). But we also do a CAS on the
    /// primary key's serialized form — if another writer already
    /// updated the row between our pre-read and our CAS, the CAS
    /// fails and we return `Ok(false)` (already-spent semantics).
    /// The transaction's `remove(unspent_outputs)` still runs but
    /// is idempotent — removing an already-absent key is a no-op.
    pub fn mark_spent(
        &self,
        tx_hash: &Hash,
        index: u8,
        spent_by: Hash,
        spent_at_height: u64,
    ) -> Result<bool> {
        let key = Self::make_output_key(tx_hash, index);

        if let Some(data) = self
            .outputs
            .get(&key)
            .map_err(|e| Error::DatabaseError(e.to_string()))?
        {
            let mut output: OwnedOutput = deserialize_owned_output(&data)?;

            if output.spent {
                return Ok(false); // Already spent
            }

            output.spent = true;
            output.spent_by = Some(spent_by);
            output.spent_at_height = Some(spent_at_height);

            let new_data = serialize(&output)?;

            // R-46: CAS on the primary tree — replace ONLY IF the
            // stored bytes still equal the pre-read snapshot. If a
            // concurrent mark_spent already mutated the row, CAS
            // returns Ok(Err(...)) and we bail with `Ok(false)`.
            match self.outputs.compare_and_swap(
                key.as_slice(),
                Some(data.as_ref()),
                Some(new_data.as_slice()),
            ) {
                Ok(Ok(())) => {
                    // Our update won. Drop the unspent_outputs index
                    // entry to keep it in sync. Non-atomic vs the CAS
                    // above; a crash between CAS and this remove
                    // leaves a stale index entry that the defensive
                    // `if !output.spent` filter in get_unspent_outputs
                    // already tolerates (see the pre-existing
                    // docstring above L227-229).
                    self.unspent_outputs
                        .remove(key.as_slice())
                        .map_err(|e| Error::DatabaseError(e.to_string()))?;
                    return Ok(true);
                }
                Ok(Err(_)) => {
                    // Concurrent writer beat us — treat as already
                    // spent. This is the correct semantics: our
                    // attempt to attribute this spend lost the race,
                    // whoever won is now the source of truth.
                    return Ok(false);
                }
                Err(e) => {
                    return Err(Error::DatabaseError(format!(
                        "R-46: mark_spent CAS failed for tx {} idx {}: {}",
                        hex::encode(tx_hash.as_bytes()),
                        index,
                        e
                    )));
                }
            }
        }

        Ok(false)
    }

    /// Get all unspent outputs.
    ///
    /// H23: Reads from the `unspent_outputs` secondary index tree instead
    /// of scanning the entire outputs tree and filtering.
    pub fn get_unspent_outputs(&self) -> Result<Vec<OwnedOutput>> {
        let mut outputs = Vec::new();

        for result in self.unspent_outputs.iter() {
            let (key, _) = result.map_err(|e| Error::DatabaseError(e.to_string()))?;
            if let Some(data) = self
                .outputs
                .get(&key)
                .map_err(|e| Error::DatabaseError(e.to_string()))?
            {
                let output: OwnedOutput = deserialize_owned_output(&data)?;
                if !output.spent {
                    outputs.push(output);
                }
            }
        }

        // Sort by height (oldest first for spending)
        outputs.sort_by_key(|o| o.height);
        Ok(outputs)
    }

    /// Get all outputs (spent and unspent)
    pub fn get_all_outputs(&self) -> Result<Vec<OwnedOutput>> {
        let mut outputs = Vec::new();

        for result in self.outputs.iter() {
            let (_, data) = result.map_err(|e| Error::DatabaseError(e.to_string()))?;
            let output: OwnedOutput = deserialize_owned_output(&data)?;
            outputs.push(output);
        }

        outputs.sort_by_key(|o| std::cmp::Reverse(o.height));
        Ok(outputs)
    }

    /// Get spendable outputs (confirmed and not spent)
    pub fn get_spendable_outputs(
        &self,
        current_height: u64,
        min_confirmations: u64,
    ) -> Result<Vec<OwnedOutput>> {
        let outputs = self.get_unspent_outputs()?;
        Ok(outputs
            .into_iter()
            .filter(|o| o.is_spendable(current_height, min_confirmations))
            .collect())
    }

    /// Calculate total balance
    pub fn calculate_balance(&self) -> Result<(u64, u64)> {
        let outputs = self.get_all_outputs()?;

        let total: u64 = outputs
            .iter()
            .filter(|o| !o.spent)
            .filter_map(|o| o.amount)
            .sum();

        let pending: u64 = outputs
            .iter()
            .filter(|o| !o.spent && o.height == 0)
            .filter_map(|o| o.amount)
            .sum();

        Ok((total, pending))
    }

    /// Add wallet transaction.
    ///
    /// AUDIT (2026-07-02): the two writes (primary `transactions` +
    /// secondary `tx_by_time` H24 index) are now atomic. This is the same
    /// class of multi-tree-without-transaction shape that the 2026-07-01
    /// audit found and fixed in `add_output`, `mark_spent`, and
    /// pruning — but this callsite was missed at that time. A systematic
    /// re-verification of `db/wallet.rs` on 2026-07-02 grepped every
    /// `self.<tree>.insert`/`.remove` pair and caught it. Same failure
    /// shape as add_output: crash between L341 and L349 (pre-fix) left
    /// the tx in the primary tree without a `tx_by_time` index entry;
    /// callers reading via `transactions.get` still see it (that path
    /// is used by `get_transaction`), but any iterator via `tx_by_time`
    /// misses it — the recent-transactions view, wallet UI history,
    /// and any downstream analytics all silently drop the row. On
    /// reorg-rewind or clear+rescan the drift widens.
    pub fn add_transaction(&self, tx: &WalletTx) -> Result<()> {
        let data = serialize(tx)?;

        // H24: Insert into timestamp-prefixed index for efficient recent-tx queries.
        // Key = BE timestamp (8 bytes) + tx_hash (32 bytes) for correct ordering.
        let mut time_key = Vec::with_capacity(40);
        time_key.extend_from_slice(&tx.timestamp.to_be_bytes());
        time_key.extend_from_slice(tx.tx_hash.as_bytes());

        use crate::db::shim::transaction::Transactional;
        [&self.transactions, &self.tx_by_time]
            .as_slice()
            .transaction(|trees| {
                let transactions_tx = &trees[0];
                let tx_by_time_tx = &trees[1];
                transactions_tx.insert(tx.tx_hash.as_bytes(), data.clone())?;
                tx_by_time_tx.insert(time_key.clone(), tx.tx_hash.as_bytes())?;
                Ok(())
            })
            .map_err(|e| Error::DatabaseError(e.to_string()))?;
        Ok(())
    }

    /// Get wallet transaction
    pub fn get_transaction(&self, tx_hash: &Hash) -> Result<Option<WalletTx>> {
        match self.transactions.get(tx_hash.as_bytes()) {
            Ok(Some(data)) => {
                let tx: WalletTx = deserialize(&data)?;
                Ok(Some(tx))
            }
            Ok(None) => Ok(None),
            Err(e) => Err(Error::DatabaseError(e.to_string())),
        }
    }

    /// Get recent transactions.
    ///
    /// H24: Uses the `tx_by_time` index tree with reverse iteration instead
    /// of scanning all transactions, sorting, and truncating.
    pub fn get_recent_transactions(&self, limit: usize) -> Result<Vec<WalletTx>> {
        let mut txs = Vec::new();

        for result in self.tx_by_time.iter().rev().take(limit) {
            let (_, tx_hash_bytes) = result.map_err(|e| Error::DatabaseError(e.to_string()))?;
            if let Some(data) = self
                .transactions
                .get(&tx_hash_bytes)
                .map_err(|e| Error::DatabaseError(e.to_string()))?
            {
                let tx: WalletTx = deserialize(&data)?;
                txs.push(tx);
            }
        }

        Ok(txs)
    }

    /// Get transactions in height range
    pub fn get_transactions_in_range(
        &self,
        start_height: u64,
        end_height: u64,
    ) -> Result<Vec<WalletTx>> {
        let mut txs = Vec::new();

        for result in self.transactions.iter() {
            let (_, data) = result.map_err(|e| Error::DatabaseError(e.to_string()))?;
            let tx: WalletTx = deserialize(&data)?;
            if let Some(height) = tx.height {
                if height >= start_height && height <= end_height {
                    txs.push(tx);
                }
            }
        }

        txs.sort_by_key(|t| t.height);
        Ok(txs)
    }

    /// Get scan state
    pub fn get_scan_state(&self) -> Result<ScanState> {
        match self.scan_state.get(Self::KEY_SCAN_STATE) {
            Ok(Some(data)) => {
                let state: ScanState = deserialize(&data)?;
                Ok(state)
            }
            Ok(None) => Ok(ScanState::default()),
            Err(e) => Err(Error::DatabaseError(e.to_string())),
        }
    }

    /// Update scan state
    pub fn update_scan_state(&self, state: &ScanState) -> Result<()> {
        let data = serialize(state)?;
        self.scan_state
            .insert(Self::KEY_SCAN_STATE, data)
            .map_err(|e| Error::DatabaseError(e.to_string()))?;
        Ok(())
    }

    /// Add pending transaction
    pub fn add_pending(&self, tx: &Transaction) -> Result<()> {
        let hash = tx.hash();
        let data = serialize(tx)?;
        self.pending
            .insert(hash.as_bytes(), data)
            .map_err(|e| Error::DatabaseError(e.to_string()))?;
        Ok(())
    }

    /// Get pending transaction
    pub fn get_pending(&self, tx_hash: &Hash) -> Result<Option<Transaction>> {
        match self.pending.get(tx_hash.as_bytes()) {
            Ok(Some(data)) => {
                let tx: Transaction = deserialize(&data)?;
                Ok(Some(tx))
            }
            Ok(None) => Ok(None),
            Err(e) => Err(Error::DatabaseError(e.to_string())),
        }
    }

    /// Remove pending transaction (confirmed or expired)
    pub fn remove_pending(&self, tx_hash: &Hash) -> Result<()> {
        self.pending
            .remove(tx_hash.as_bytes())
            .map_err(|e| Error::DatabaseError(e.to_string()))?;
        Ok(())
    }

    /// Get all pending transactions
    pub fn get_all_pending(&self) -> Result<Vec<Transaction>> {
        let mut txs = Vec::new();

        for result in self.pending.iter() {
            let (_, data) = result.map_err(|e| Error::DatabaseError(e.to_string()))?;
            let tx: Transaction = deserialize(&data)?;
            txs.push(tx);
        }

        Ok(txs)
    }

    /// Set label for address
    pub fn set_label(&self, address: &PublicKey, label: &str) -> Result<()> {
        self.labels
            .insert(address.as_bytes(), label.as_bytes())
            .map_err(|e| Error::DatabaseError(e.to_string()))?;
        Ok(())
    }

    /// Get label for address
    pub fn get_label(&self, address: &PublicKey) -> Result<Option<String>> {
        match self.labels.get(address.as_bytes()) {
            Ok(Some(data)) => {
                let label = String::from_utf8(data.to_vec())
                    .map_err(|e| Error::DatabaseError(e.to_string()))?;
                Ok(Some(label))
            }
            Ok(None) => Ok(None),
            Err(e) => Err(Error::DatabaseError(e.to_string())),
        }
    }

    /// Count outputs
    pub fn output_count(&self) -> usize {
        self.outputs.len()
    }

    /// Count transactions
    pub fn transaction_count(&self) -> usize {
        self.transactions.len()
    }

    /// Clear all wallet data (dangerous!).
    ///
    /// AUDIT (2026-07-01): added `unspent_outputs` (H23 secondary index)
    /// and `tx_by_time` (H24 secondary index) to the clear set. Before
    /// this fix, `clear()` reset the 5 primary trees but left both
    /// secondary indexes populated. On a subsequent `add_output()` /
    /// `add_transaction()` the stale indexes would still point at the
    /// pre-clear primary rows — but those rows had been deleted, so
    /// `get_unspent_outputs()` (which reads `outputs.get(&key)` after
    /// the index lookup at line ~243) got `None` and skipped them, so no
    /// user-observable ghost balance. The indexes still drifted from
    /// the primaries indefinitely, wasting disk and confusing every
    /// future audit of these tables. The two missing tree clears are
    /// added below. Atomicity across all 7 clears is not required —
    /// `clear()` is a full-wallet reset explicitly gated as
    /// "dangerous!"; recovery from an interrupted clear is a rescan.
    pub fn clear(&self) -> Result<()> {
        self.outputs
            .clear()
            .map_err(|e| Error::DatabaseError(e.to_string()))?;
        self.transactions
            .clear()
            .map_err(|e| Error::DatabaseError(e.to_string()))?;
        self.scan_state
            .clear()
            .map_err(|e| Error::DatabaseError(e.to_string()))?;
        self.pending
            .clear()
            .map_err(|e| Error::DatabaseError(e.to_string()))?;
        self.labels
            .clear()
            .map_err(|e| Error::DatabaseError(e.to_string()))?;
        // 2026-07-01: secondary indexes missing from the original clear.
        self.unspent_outputs
            .clear()
            .map_err(|e| Error::DatabaseError(e.to_string()))?;
        self.tx_by_time
            .clear()
            .map_err(|e| Error::DatabaseError(e.to_string()))?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn test_wallet_output() {
        let dir = tempdir().unwrap();
        let db = crate::db::shim::open(dir.path()).unwrap();
        let wallet_db = WalletDb::new(&db).unwrap();

        let tx_hash = Hash::from_bytes([1u8; 32]);
        let output = OwnedOutput {
            tx_hash,
            output_index: 0,
            output: TxOutput {
                stealth_address: PublicKey::from_bytes([2u8; 32]),
                tx_public_key: PublicKey::from_bytes([3u8; 32]),
                commitment: [4u8; 32],
                encrypted_amount: vec![0u8; 8],
                view_tag: 0,
                lock_height: None,
                encrypted_memo: vec![],
            },
            amount: Some(1_000_000_000),
            height: 100,
            block_hash: Hash::from_bytes([5u8; 32]),
            timestamp: 1234567890,
            spent: false,
            spent_by: None,
            spent_at_height: None,
            subaddress_index: None,
            subaddress_account: None,
        };

        wallet_db.add_output(&output).unwrap();

        let loaded = wallet_db.get_output(&tx_hash, 0).unwrap().unwrap();
        assert_eq!(loaded.amount, Some(1_000_000_000));
        assert!(!loaded.spent);

        let unspent = wallet_db.get_unspent_outputs().unwrap();
        assert_eq!(unspent.len(), 1);

        // Mark as spent
        let spent_by = Hash::from_bytes([6u8; 32]);
        assert!(wallet_db.mark_spent(&tx_hash, 0, spent_by, 150).unwrap());

        let unspent = wallet_db.get_unspent_outputs().unwrap();
        assert_eq!(unspent.len(), 0);
    }

    #[test]
    fn legacy_owned_output_migrates_with_none_account() {
        // #26 follow-up: a record written before `subaddress_account` existed
        // must still load, defaulting the account to None; new records round-trip.
        let legacy = OwnedOutputLegacy {
            tx_hash: Hash::from_bytes([1u8; 32]),
            output_index: 0,
            output: TxOutput {
                stealth_address: PublicKey::from_bytes([2u8; 32]),
                tx_public_key: PublicKey::from_bytes([3u8; 32]),
                commitment: [4u8; 32],
                encrypted_amount: vec![0u8; 8],
                view_tag: 0,
                lock_height: None,
                encrypted_memo: vec![],
            },
            amount: Some(42),
            height: 100,
            block_hash: Hash::from_bytes([5u8; 32]),
            timestamp: 123,
            spent: false,
            spent_by: None,
            spent_at_height: None,
            subaddress_index: Some(3),
        };
        // Old on-disk bytes decode via the legacy fallback → account None.
        let old_bytes = serialize(&legacy).unwrap();
        let migrated = deserialize_owned_output(&old_bytes).unwrap();
        assert_eq!(migrated.subaddress_index, Some(3));
        assert_eq!(
            migrated.subaddress_account, None,
            "legacy record must default account to None"
        );
        assert_eq!(migrated.amount, Some(42));

        // A new-format record (account set) round-trips through the same reader.
        let mut modern = migrated;
        modern.subaddress_account = Some(2);
        let new_bytes = serialize(&modern).unwrap();
        let rt = deserialize_owned_output(&new_bytes).unwrap();
        assert_eq!(rt.subaddress_account, Some(2));
        assert_eq!(rt.subaddress_index, Some(3));
    }

    #[test]
    fn test_scan_state() {
        let dir = tempdir().unwrap();
        let db = crate::db::shim::open(dir.path()).unwrap();
        let wallet_db = WalletDb::new(&db).unwrap();

        let state = ScanState {
            scanned_height: 1000,
            scanned_hash: Hash::from_bytes([1u8; 32]),
            outputs_found: 50,
            outputs_spent: 10,
            scan_started: 1234567890,
            last_scan_time: 1234567900,
        };

        wallet_db.update_scan_state(&state).unwrap();

        let loaded = wallet_db.get_scan_state().unwrap();
        assert_eq!(loaded.scanned_height, 1000);
        assert_eq!(loaded.outputs_found, 50);
    }
}
