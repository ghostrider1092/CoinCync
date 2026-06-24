//! # Wallet Implementation
//!
//! Main wallet struct that combines keys, balance, and operations.

use std::path::PathBuf;
use std::sync::Arc;
use parking_lot::RwLock;

use rand::RngCore;
use zeroize::Zeroize;
use crate::primitives::{Hash, Amount, KeyImage};
use crate::error::{Error, Result};

use super::wallet_keys::WalletKeys;
use super::key_epoch::KeyEpoch;
use super::balance::{Balance, UTXO};
use super::persistence::{WalletData, save_wallet, load_wallet, generate_mnemonic, mnemonic_to_seed};
use super::history::{TransactionHistory, TransactionRecord};

/// Wallet state
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WalletState {
    /// Wallet is locked (encrypted, needs password)
    Locked,
    /// Wallet is unlocked and ready
    Unlocked,
    /// Wallet is syncing with blockchain
    Syncing,
}

/// Wallet information
#[derive(Clone, Debug)]
pub struct WalletInfo {
    pub state: WalletState,
    pub address: String,
    pub balance: Amount,
    pub spendable: Amount,
    pub pending: Amount,
    pub scanned_height: u64,
    pub utxo_count: usize,
    pub key_epoch: u64,
}

/// Main wallet struct
pub struct Wallet {
    /// Wallet file path
    path: PathBuf,
    /// Keys (None if locked)
    keys: Option<WalletKeys>,
    /// Balance tracker
    balance: Balance,
    /// Transaction history
    history: TransactionHistory,
    /// Current state
    state: WalletState,
    /// Scanned blockchain height
    scanned_height: u64,
    /// Network type
    network: String,
    /// Wallet label
    label: String,
    /// Watch-only mode (view key only, cannot spend)
    watch_only: bool,
    /// Subaddress data for persistence
    subaddress_data: Option<super::SubaddressData>,
    /// Original creation timestamp (preserved across saves)
    created_at: u64,
}

impl Wallet {
    /// Create a new wallet
    pub fn create(
        path: PathBuf,
        password: Option<&str>,
        network: &str,
    ) -> Result<(Self, String)> {
        if path.exists() {
            return Err(Error::WalletExists(path.display().to_string()));
        }

        // Generate seed
        let (mnemonic, seed) = generate_mnemonic();

        // Create keys
        let keys = WalletKeys::from_seed(seed);

        // Create wallet data
        let data = WalletData::new(seed, network);

        // Save to file
        save_wallet(&path, &data, password)?;

        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let wallet = Wallet {
            path,
            keys: Some(keys),
            balance: Balance::new(),
            history: TransactionHistory::new(),
            state: WalletState::Unlocked,
            scanned_height: 0,
            network: network.to_string(),
            label: String::new(),
            watch_only: false,
            subaddress_data: None,
            created_at: timestamp,
        };

        Ok((wallet, mnemonic))
    }

    /// Create a watch-only wallet from view key and spend public key
    ///
    /// Watch-only wallets can:
    /// - Monitor incoming transactions
    /// - Calculate and display balance
    /// - Export transaction history for accounting
    ///
    /// Watch-only wallets CANNOT:
    /// - Spend any funds
    /// - Sign transactions
    /// - Export the seed phrase
    pub fn create_watch_only(
        path: PathBuf,
        view_key_hex: &str,
        spend_public_hex: &str,
        password: Option<&str>,
        network: &str,
    ) -> Result<Self> {
        use crate::primitives::PublicKey;

        if path.exists() {
            return Err(Error::WalletExists(path.display().to_string()));
        }

        // Parse view key
        let view_bytes = hex::decode(view_key_hex)
            .map_err(|e| Error::InvalidParams(format!("invalid view key hex: {}", e)))?;
        if view_bytes.len() != 32 {
            return Err(Error::InvalidParams("view key must be 32 bytes".into()));
        }
        let mut view_arr = [0u8; 32];
        view_arr.copy_from_slice(&view_bytes);
        let view_secret = crate::primitives::SecretKey::from_bytes(view_arr);

        // Parse spend public key
        let spend_bytes = hex::decode(spend_public_hex)
            .map_err(|e| Error::InvalidParams(format!("invalid spend public key hex: {}", e)))?;
        if spend_bytes.len() != 32 {
            return Err(Error::InvalidParams("spend public key must be 32 bytes".into()));
        }
        let mut spend_arr = [0u8; 32];
        spend_arr.copy_from_slice(&spend_bytes);
        let spend_public = PublicKey::from_bytes(spend_arr);

        // Create watch-only keys
        let keys = WalletKeys::watch_only(view_secret, spend_public);

        // SECURITY (CRIT-9): Store view_secret as the seed so it persists across
        // lock/unlock cycles. The spend_public key is encoded in the label field
        // with a "watch-only:" prefix. This avoids changing the wallet file format
        // (which would break backwards compatibility with borsh serialization).
        let mut data = WalletData::new(view_arr, network);
        data.label = format!("watch-only:{}", hex::encode(spend_arr));

        // Save to file
        save_wallet(&path, &data, password)?;

        Ok(Wallet {
            path,
            keys: Some(keys),
            balance: Balance::new(),
            history: TransactionHistory::new(),
            state: WalletState::Unlocked,
            scanned_height: 0,
            network: network.to_string(),
            label: data.label.clone(),
            watch_only: true,
            subaddress_data: None,
            created_at: data.created_at,
        })
    }

    /// Check if this is a watch-only wallet
    pub fn is_watch_only(&self) -> bool {
        self.watch_only || self.keys.as_ref().map(|k| k.is_watch_only()).unwrap_or(false)
    }

    /// Restore wallet from mnemonic
    pub fn restore(
        path: PathBuf,
        mnemonic: &str,
        password: Option<&str>,
        network: &str,
    ) -> Result<Self> {
        if path.exists() {
            return Err(Error::WalletExists(path.display().to_string()));
        }

        // Convert mnemonic to seed
        let seed = mnemonic_to_seed(mnemonic)?;

        // Create keys
        let keys = WalletKeys::from_seed(seed);

        // Create wallet data
        let data = WalletData::new(seed, network);

        // Save to file
        save_wallet(&path, &data, password)?;

        Ok(Wallet {
            path,
            keys: Some(keys),
            balance: Balance::new(),
            history: TransactionHistory::new(),
            state: WalletState::Unlocked,
            scanned_height: 0,
            network: network.to_string(),
            label: String::new(),
            watch_only: false,
            subaddress_data: None,
            created_at: data.created_at,
        })
    }

    /// Open existing wallet (locked)
    pub fn open(path: PathBuf) -> Result<Self> {
        if !path.exists() {
            return Err(Error::WalletNotFound(path.display().to_string()));
        }

        // Load without password to get metadata
        // Will fail if encrypted - that's expected
        let (network, label, watch_only) = match load_wallet(&path, None) {
            Ok(data) => {
                let is_wo = data.label.starts_with("watch-only:");
                (data.network.clone(), data.label.clone(), is_wo)
            }
            Err(_) => ("unknown".to_string(), String::new(), false),
        };

        Ok(Wallet {
            path,
            keys: None,
            balance: Balance::new(),
            history: TransactionHistory::new(),
            state: WalletState::Locked,
            scanned_height: 0,
            network,
            label,
            watch_only, // Detected from label prefix if wallet is unencrypted
            subaddress_data: None,
            created_at: 0, // Will be populated from wallet data on unlock
        })
    }

    /// Unlock wallet with password
    ///
    /// SECURITY (CRIT-9): Detects watch-only wallets by checking the label prefix.
    /// Watch-only wallets store the view_secret in the seed field and the spend
    /// public key hex-encoded in the label. Using `from_seed()` on a zero seed
    /// (old format) or view secret would derive completely wrong keys.
    pub fn unlock(&mut self, password: &str) -> Result<()> {
        let data = load_wallet(&self.path, Some(password))?;

        // Detect watch-only wallet: label starts with "watch-only:" and contains
        // the hex-encoded spend public key, OR seed is all zeros (legacy format)
        let keys = if data.label.starts_with("watch-only:") {
            let spend_hex = &data.label["watch-only:".len()..];
            let spend_bytes = hex::decode(spend_hex)
                .map_err(|e| Error::InvalidState(format!(
                    "corrupt watch-only wallet: invalid spend key hex: {}", e
                )))?;
            if spend_bytes.len() != 32 {
                return Err(Error::InvalidState(
                    "corrupt watch-only wallet: spend key must be 32 bytes".into()
                ));
            }
            let mut spend_arr = [0u8; 32];
            spend_arr.copy_from_slice(&spend_bytes);

            let view_secret = crate::primitives::SecretKey::from_bytes(data.seed);
            let spend_public = crate::primitives::PublicKey::from_bytes(spend_arr);

            self.watch_only = true;
            WalletKeys::watch_only(view_secret, spend_public)
        } else if data.seed == [0u8; 32] {
            // Legacy watch-only format with zero seed - cannot restore keys
            return Err(Error::InvalidState(
                "legacy watch-only wallet with zero seed cannot be unlocked; \
                 re-import using view key and spend public key".into()
            ));
        } else {
            self.watch_only = false;
            WalletKeys::from_seed(data.seed)
        };

        self.keys = Some(keys);
        self.scanned_height = data.scanned_height;
        self.network = data.network.clone();
        self.label = data.label.clone();
        self.state = WalletState::Unlocked;
        self.subaddress_data = data.subaddresses.clone();
        self.created_at = data.created_at;

        // Restore persisted UTXOs from sidecar file (decrypt if encrypted)
        let utxo_path = self.path.with_extension("utxos");
        if utxo_path.exists() {
            if let Ok(bytes) = std::fs::read(&utxo_path) {
                let json_bytes = Self::decrypt_sidecar(&bytes, password);
                if let Ok(utxos) = serde_json::from_slice::<Vec<UTXO>>(&json_bytes) {
                    for utxo in utxos {
                        self.balance.add_utxo(utxo);
                    }
                }
            }
        }

        // Restore persisted transaction history from sidecar file (decrypt if encrypted)
        let history_path = self.path.with_extension("history");
        if history_path.exists() {
            if let Ok(bytes) = std::fs::read(&history_path) {
                let json_bytes = Self::decrypt_sidecar(&bytes, password);
                if let Ok(records) = serde_json::from_slice::<Vec<TransactionRecord>>(&json_bytes) {
                    for record in records {
                        self.history.add(record);
                    }
                }
            }
        }

        // Restore in-flight UTXO reservations from sidecar (Item 1).
        // `restore_reservations` skips entries already past expiry, so a
        // wallet that's been closed for hours/days won't resurrect stale
        // claims. `scanned_height` is the best available "current height"
        // proxy at unlock time — wallets that refresh more aggressively
        // can call `release_expired_reservations(true_current_height)` on
        // open with a fresh chain query.
        let reservations_path = self.path.with_extension("reservations");
        if reservations_path.exists() {
            if let Ok(bytes) = std::fs::read(&reservations_path) {
                let json_bytes = Self::decrypt_sidecar(&bytes, password);
                if let Ok(entries) = serde_json::from_slice::<Vec<((Hash, u8), super::balance::Reservation)>>(&json_bytes) {
                    self.balance.restore_reservations(entries, self.scanned_height);
                }
            }
        }

        Ok(())
    }

    /// Lock wallet
    ///
    /// SECURITY: Explicitly drops keys to trigger zeroize-on-drop behavior
    /// from WalletKeys. We take() the Option to ensure Drop runs immediately.
    pub fn lock(&mut self) {
        if let Some(keys) = self.keys.take() {
            drop(keys); // Explicitly trigger Drop (which runs ZeroizeOnDrop)
        }
        self.state = WalletState::Locked;
    }

    /// Check if wallet is unlocked
    pub fn is_unlocked(&self) -> bool {
        self.keys.is_some()
    }

    /// Get wallet state
    pub fn state(&self) -> WalletState {
        self.state
    }

    /// Get primary address
    pub fn address(&self) -> Result<String> {
        use crate::primitives::{Address, Network};

        let keys = self.keys.as_ref()
            .ok_or(Error::InvalidState("wallet locked".into()))?;

        let epoch = keys.current()
            .ok_or(Error::InvalidState("no key epoch".into()))?;

        // Determine network from wallet config
        let network = if self.network == "testnet" {
            Network::Testnet
        } else {
            Network::Mainnet
        };

        // Create proper address with network prefix and checksum
        let addr = Address::new(network, epoch.spend_public, epoch.view_public);
        Ok(addr.to_string())
    }

    /// Export view key as hex string
    ///
    /// This allows creating a view-only wallet for auditing purposes.
    /// The view key can decrypt incoming transactions but cannot spend.
    ///
    /// # Security Warning
    ///
    /// **SENSITIVE**: The view key can decrypt ALL incoming transaction amounts
    /// and identify which outputs belong to this wallet. Exposure of this key
    /// compromises transaction privacy but NOT spending ability.
    ///
    /// ## Permitted Uses
    /// - Creating view-only wallets for accounting/auditing
    /// - Third-party portfolio tracking services
    /// - Tax compliance reporting
    ///
    /// ## Required Precautions
    /// - Never share the view key with untrusted parties
    /// - The recipient can see ALL your transaction history
    /// - Consider using per-transaction view keys for limited disclosure
    /// - Ensure secure transmission (encrypted channel)
    pub fn export_view_key(&self, epoch: Option<u64>) -> Result<String> {
        // SECURITY: Log that sensitive key material is being exported
        tracing::warn!(
            target: "wallet::security",
            "View key export requested - this reveals transaction history"
        );

        let keys = self.keys.as_ref()
            .ok_or(Error::InvalidState("wallet locked".into()))?;

        // Get the requested epoch or current
        let key_epoch = match epoch {
            Some(e) => keys.get_epoch(e)
                .ok_or(Error::InvalidState(format!("epoch {} not found", e)))?,
            None => keys.current()
                .ok_or(Error::InvalidState("no key epoch".into()))?,
        };

        Ok(hex::encode(key_epoch.view_secret.as_bytes()))
    }

    /// Get current key epoch number
    pub fn current_epoch(&self) -> Result<u64> {
        let keys = self.keys.as_ref()
            .ok_or(Error::InvalidState("wallet locked".into()))?;

        let epoch = keys.current()
            .ok_or(Error::InvalidState("no key epoch".into()))?;

        Ok(epoch.epoch)
    }

    /// Get total balance
    pub fn total_balance(&self) -> Amount {
        self.balance.total()
    }

    /// Get the full Balance tracker
    pub fn balance(&self) -> Balance {
        self.balance.clone()
    }

    /// Borrow the Balance tracker (cheap, no clone). Use this when the
    /// caller only needs to query (e.g. `lookup_by_key_image`) and
    /// would otherwise clone the entire UTXO set per scan iteration.
    pub fn balance_ref(&self) -> &Balance {
        &self.balance
    }

    /// Get spendable balance
    pub fn spendable_balance(&self, current_height: u64) -> Amount {
        // CONSENSUS-COUPLED: maturity floor flips at the
        // MIN_OUTPUT_AGE hard-fork height. Read via the height-keyed
        // helper so the wallet shows the SAME spendable set the
        // validator would accept at this height.
        let min_age = crate::constants::min_output_age_at_height(current_height);
        self.balance.spendable(current_height, min_age)
    }

    /// Get available UTXOs for spending
    pub fn available_utxos(&self, current_height: u64) -> Vec<&UTXO> {
        let min_age = crate::constants::min_output_age_at_height(current_height);
        self.balance.available_utxos(current_height, min_age)
    }

    /// Add a UTXO to balance
    pub fn add_utxo(&mut self, utxo: UTXO) {
        self.balance.add_utxo(utxo);
    }

    /// Mark UTXO as spent
    pub fn mark_spent(&mut self, tx_hash: Hash, output_index: u8) {
        self.balance.mark_spent(tx_hash, output_index);
    }

    /// Get all UTXOs (including spent) for key image export
    pub fn all_utxos(&self) -> Vec<UTXO> {
        self.balance.all_utxos()
    }

    /// Mark a UTXO as spent by its key image. O(1) via the
    /// `Balance::key_image_index` reverse-lookup added in Item 8;
    /// previously this iterated `all_utxos()` per call.
    pub fn mark_spent_by_key_image(&mut self, key_image: &KeyImage) {
        if let Some((tx_hash, output_index)) = self.balance.lookup_by_key_image(key_image) {
            self.balance.mark_spent(tx_hash, output_index);
        }
    }

    /// Inverse of `mark_spent_by_key_image`: restore a previously-spent
    /// UTXO to spendable. Used during reorg rewind (Task #1b) when the
    /// only spend signal was a tx in a now-orphaned block.
    ///
    /// Updates both Balance (flips `UTXO.spent`) and TransactionHistory
    /// (flips record.spent on any outgoing record holding this
    /// key_image). The two layers track related-but-distinct state:
    /// Balance's flag drives spendable() / available_utxos(); history's
    /// flag drives the UI's spent-marker display.
    pub fn unmark_spent_by_key_image(&mut self, key_image: &KeyImage) {
        self.balance.unmark_spent_by_key_image(key_image);
        // History uses Hash not KeyImage for its key_image field (legacy
        // shape); reinterpret the bytes — the field is opaque to history.
        let key_image_hash = Hash::from_bytes(*key_image.as_bytes());
        self.history.unmark_spent_by_key_image(&key_image_hash);
    }

    // === Reservation API (Item 1: in-flight UTXO tracking) =============
    //
    // Wrappers over Balance::reserve_utxos / release_*. Callers (cmd_send,
    // cmd_scan) talk to the Wallet, not Balance directly; these wrappers
    // keep the surface uniform.

    /// Reserve UTXOs for a tx that's about to be submitted. See
    /// `Balance::reserve_utxos` for atomicity guarantees.
    pub fn reserve_utxos(
        &mut self,
        keys: &[(Hash, u8)],
        by_tx: Hash,
        current_height: u64,
    ) -> std::result::Result<(), super::balance::ReservationConflict> {
        self.balance.reserve_utxos(keys, by_tx, current_height)
    }

    /// Release every reservation held by `by_tx`. Returns the count
    /// released. Use this when a submission is rejected by mempool.
    pub fn release_reservations_by_tx(&mut self, by_tx: Hash) -> usize {
        self.balance.release_reservations_by_tx(by_tx)
    }

    /// Sweep expired reservations. Cheap to call periodically (during
    /// scan, every wallet open, etc.).
    pub fn release_expired_reservations(&mut self, current_height: u64) -> usize {
        self.balance.release_expired_reservations(current_height)
    }

    // === Transaction History Methods ===

    /// Add an incoming transaction to history
    pub fn record_incoming(
        &mut self,
        tx_hash: Hash,
        amount: Amount,
        block_height: u64,
        timestamp: u64,
        output_index: u8,
        subaddress: Option<super::SubaddressIndex>,
    ) {
        let record = TransactionRecord::incoming(
            tx_hash, amount, block_height, timestamp, output_index, subaddress,
        );
        self.history.add(record);
    }

    /// Add an outgoing transaction to history
    pub fn record_outgoing(
        &mut self,
        tx_hash: Hash,
        amount: Amount,
        fee: Amount,
        block_height: u64,
        timestamp: u64,
    ) {
        let record = TransactionRecord::outgoing(
            tx_hash, amount, fee, block_height, timestamp,
        );
        self.history.add(record);
    }

    /// Add an outgoing transaction to history with recipient address for reuse detection
    pub fn record_outgoing_with_address(
        &mut self,
        tx_hash: Hash,
        amount: Amount,
        fee: Amount,
        block_height: u64,
        timestamp: u64,
        recipient_address: &str,
    ) {
        let mut record = TransactionRecord::outgoing(
            tx_hash, amount, fee, block_height, timestamp,
        );
        record.recipient_address = Some(recipient_address.to_string());
        self.history.add(record);
    }

    /// Get all transaction history
    pub fn history(&self) -> &TransactionHistory {
        &self.history
    }

    /// Get mutable access to transaction history
    pub fn history_mut(&mut self) -> &mut TransactionHistory {
        &mut self.history
    }

    /// Set memo for a transaction
    pub fn set_tx_memo(&mut self, tx_hash: &Hash, memo: &str) -> bool {
        self.history.set_memo(tx_hash, memo)
    }

    /// Update all transaction statuses based on current height
    pub fn update_tx_statuses(&mut self, current_height: u64) {
        self.history.update_all_statuses(current_height);
    }

    /// Get current key epoch
    pub fn current_keys(&self) -> Option<&KeyEpoch> {
        self.keys.as_ref()?.current()
    }

    /// Get keys for specific epoch
    pub fn keys_for_epoch(&self, epoch: u64) -> Option<&KeyEpoch> {
        self.keys.as_ref()?.get_epoch(epoch)
    }

    /// Derive next key epoch
    pub fn derive_next_epoch(&mut self) -> Result<u64> {
        let keys = self.keys.as_mut()
            .ok_or(Error::InvalidState("wallet locked".into()))?;

        let next_epoch = keys.current()
            .map(|e| e.epoch + 1)
            .unwrap_or(0);

        keys.derive_epoch(next_epoch);
        Ok(next_epoch)
    }

    /// Update scanned height
    pub fn set_scanned_height(&mut self, height: u64) {
        self.scanned_height = height;
    }

    /// Get scanned height
    pub fn scanned_height(&self) -> u64 {
        self.scanned_height
    }

    /// Get subaddress data
    pub fn subaddress_data(&self) -> Option<&super::SubaddressData> {
        self.subaddress_data.as_ref()
    }

    /// Set subaddress data for persistence
    pub fn set_subaddress_data(&mut self, data: super::SubaddressData) {
        self.subaddress_data = Some(data);
    }

    /// Save wallet state.
    ///
    /// # Persistence ordering (Bug #5 fix)
    ///
    /// Three files are involved:
    ///   - `<wallet>` (the encrypted seed + scanned_height + metadata)
    ///   - `<wallet>.utxos` (UTXO sidecar)
    ///   - `<wallet>.history` (transaction history sidecar)
    ///
    /// Each file write is atomic (temp + rename), but the writes are NOT
    /// transactional across files. If the process dies between file writes
    /// we want the failure mode to be "we re-scan some blocks" rather than
    /// "we lost owned outputs".
    ///
    /// The previous order was wallet -> utxos -> history. That meant a
    /// crash between steps 1 and 2 left `scanned_height` advanced on disk
    /// while the UTXOs from those scanned blocks were still in volatile
    /// memory. The next scan started from the new `scanned_height`,
    /// skipped the just-found-but-not-persisted blocks, and the wallet
    /// looked like it had 0 balance forever -- exactly the symptom we
    /// observed during 2026-05-07 testnet bring-up.
    ///
    /// New order: utxos first, then history, then wallet+scanned_height
    /// last. If a crash happens before the wallet file is written:
    ///   - sidecars contain the new UTXOs (preserved)
    ///   - scanned_height is still the OLD value
    ///   - next scan re-processes the same range, re-detects the outputs,
    ///     replaces the sidecar entries (idempotent: keyed by (tx_hash,
    ///     output_index)). No data loss; some redundant work.
    pub fn save(&self, password: Option<&str>) -> Result<()> {
        let keys = self.keys.as_ref()
            .ok_or(Error::InvalidState("wallet locked".into()))?;

        // === Step 1: UTXO sidecar ===
        // (was step 2 before; now first so a crash leaves no stale state.)
        let utxo_path = self.path.with_extension("utxos");
        let utxos = self.balance.all_utxos();
        if !utxos.is_empty() {
            let mut json = serde_json::to_vec(&utxos)
                .map_err(|e| Error::InvalidState(format!("failed to serialize UTXOs: {}", e)))?;
            let bytes_to_write = if let Some(pw) = password {
                let mut salt = [0u8; 32];
                rand::rngs::OsRng.fill_bytes(&mut salt);
                let mut key = super::derive_key_default(pw, &salt);
                let mut nonce = [0u8; 24];
                rand::rngs::OsRng.fill_bytes(&mut nonce);
                let encrypted = super::encrypt(&json, &key, &nonce)?;
                key.zeroize();
                json.zeroize();
                [salt.as_slice(), nonce.as_slice(), encrypted.as_slice()].concat()
            } else {
                json
            };
            let utxo_tmp_path = self.path.with_extension("utxos.tmp");
            std::fs::write(&utxo_tmp_path, &bytes_to_write)
                .map_err(|e| Error::InvalidState(format!("failed to write UTXO temp file: {}", e)))?;
            std::fs::rename(&utxo_tmp_path, &utxo_path)
                .map_err(|e| Error::InvalidState(format!("failed to rename UTXO file: {}", e)))?;
        } else if utxo_path.exists() {
            let _ = std::fs::remove_file(&utxo_path);
        }

        // === Step 1.5: reservations sidecar (Item 1) ===
        // Persisted alongside UTXOs because a reservation is meaningless
        // without the UTXO it claims. Same atomic-rename pattern.
        // Empty reservations -> remove the sidecar to avoid stale residue
        // (matches utxos behavior on the empty path).
        let reservations_path = self.path.with_extension("reservations");
        let reservations = self.balance.all_reservations();
        if !reservations.is_empty() {
            let mut json = serde_json::to_vec(&reservations)
                .map_err(|e| Error::InvalidState(format!("failed to serialize reservations: {}", e)))?;
            let bytes_to_write = if let Some(pw) = password {
                let mut salt = [0u8; 32];
                rand::rngs::OsRng.fill_bytes(&mut salt);
                let mut key = super::derive_key_default(pw, &salt);
                let mut nonce = [0u8; 24];
                rand::rngs::OsRng.fill_bytes(&mut nonce);
                let encrypted = super::encrypt(&json, &key, &nonce)?;
                key.zeroize();
                json.zeroize();
                [salt.as_slice(), nonce.as_slice(), encrypted.as_slice()].concat()
            } else {
                json
            };
            let reservations_tmp_path = self.path.with_extension("reservations.tmp");
            std::fs::write(&reservations_tmp_path, &bytes_to_write)
                .map_err(|e| Error::InvalidState(format!("failed to write reservations temp file: {}", e)))?;
            std::fs::rename(&reservations_tmp_path, &reservations_path)
                .map_err(|e| Error::InvalidState(format!("failed to rename reservations file: {}", e)))?;
        } else if reservations_path.exists() {
            let _ = std::fs::remove_file(&reservations_path);
        }

        // === Step 2: history sidecar ===
        let history_path = self.path.with_extension("history");
        let history_records = self.history.all();
        if !history_records.is_empty() {
            let records: Vec<&TransactionRecord> = history_records.iter().collect();
            let mut json = serde_json::to_vec(&records)
                .map_err(|e| Error::InvalidState(format!("failed to serialize history: {}", e)))?;
            let bytes_to_write = if let Some(pw) = password {
                let mut salt = [0u8; 32];
                rand::rngs::OsRng.fill_bytes(&mut salt);
                let mut key = super::derive_key_default(pw, &salt);
                let mut nonce = [0u8; 24];
                rand::rngs::OsRng.fill_bytes(&mut nonce);
                let encrypted = super::encrypt(&json, &key, &nonce)?;
                key.zeroize();
                json.zeroize();
                [salt.as_slice(), nonce.as_slice(), encrypted.as_slice()].concat()
            } else {
                json
            };
            let history_tmp_path = self.path.with_extension("history.tmp");
            std::fs::write(&history_tmp_path, &bytes_to_write)
                .map_err(|e| Error::InvalidState(format!("failed to write history temp file: {}", e)))?;
            std::fs::rename(&history_tmp_path, &history_path)
                .map_err(|e| Error::InvalidState(format!("failed to rename history file: {}", e)))?;
        } else if history_path.exists() {
            let _ = std::fs::remove_file(&history_path);
        }

        // === Step 3: wallet file (with scanned_height) -- LAST ===
        // CRITICAL FIX (commit f8daaea): Use master_seed, NOT derived
        // spend_secret. Using spend_secret would cause restore to produce
        // wrong keys since the derived key would be treated as a master
        // seed. Using master_seed_for_backup() which is the secure API.
        let seed = *keys.master_seed_for_backup();
        let data = WalletData {
            seed,
            current_epoch: keys.current().map(|e| e.epoch).unwrap_or(0),
            scanned_height: self.scanned_height,
            label: self.label.clone(),
            created_at: self.created_at,
            network: self.network.clone(),
            subaddresses: self.subaddress_data.clone(),
            mnemonic_phrase: None,
        };
        save_wallet(&self.path, &data, password)?;

        Ok(())
    }

    /// Try to decrypt a sidecar file. If the data starts with a 32-byte
    /// salt + 24-byte nonce and the password can decrypt it, returns the
    /// plaintext. Falls back to treating the bytes as unencrypted JSON
    /// for backward compat with very early plaintext sidecars.
    ///
    /// (Item 22) Decryption tries the binary's current default Argon2id
    /// params first, then falls back to the v2 legacy params for
    /// sidecars saved by pre-2026-05-08 binaries — handled inside
    /// `persistence::decrypt_sidecar_with_fallback`.
    fn decrypt_sidecar(bytes: &[u8], password: &str) -> Vec<u8> {
        // Encrypted format: salt(32) || nonce(24) || ciphertext(...)
        if bytes.len() > 56 {
            let mut salt = [0u8; 32];
            salt.copy_from_slice(&bytes[..32]);
            let mut nonce = [0u8; 24];
            nonce.copy_from_slice(&bytes[32..56]);
            let ciphertext = &bytes[56..];
            if let Ok(plaintext) = super::decrypt_sidecar_with_fallback(
                &salt, &nonce, ciphertext, password,
            ) {
                return plaintext;
            }
        }
        // Fallback: assume unencrypted (backward compatibility for the
        // very early wallet format that stored sidecars in plaintext).
        bytes.to_vec()
    }

    /// Get wallet info
    pub fn info(&self, current_height: u64) -> WalletInfo {
        WalletInfo {
            state: self.state,
            address: self.address().unwrap_or_default(),
            balance: self.total_balance(),
            spendable: self.spendable_balance(current_height),
            pending: self.total_balance().saturating_sub(self.spendable_balance(current_height)),
            scanned_height: self.scanned_height,
            utxo_count: self.available_utxos(current_height).len(),
            key_epoch: self.keys.as_ref()
                .and_then(|k| k.current())
                .map(|e| e.epoch)
                .unwrap_or(0),
        }
    }
}

/// Thread-safe wallet wrapper
pub struct SharedWallet {
    inner: Arc<RwLock<Wallet>>,
}

impl SharedWallet {
    pub fn new(wallet: Wallet) -> Self {
        SharedWallet {
            inner: Arc::new(RwLock::new(wallet)),
        }
    }

    /// Acquire read lock.
    /// SECURITY: Recovers from poisoned locks instead of panicking. A poisoned lock
    /// means a thread panicked during a wallet mutation. We recover the inner data
    /// because wallet operations are individually atomic (each UTXO add/spend is
    /// self-contained) and crashing would prevent the user from saving or recovering
    /// their wallet entirely. This matches the chain.rs recovery strategy.
    fn read_lock(&self) -> parking_lot::RwLockReadGuard<'_, Wallet> {
        self.inner.read()
    }

    fn write_lock(&self) -> parking_lot::RwLockWriteGuard<'_, Wallet> {
        self.inner.write()
    }

    pub fn unlock(&self, password: &str) -> Result<()> {
        self.write_lock().unlock(password)
    }

    pub fn lock(&self) {
        self.write_lock().lock()
    }

    pub fn is_unlocked(&self) -> bool {
        self.read_lock().is_unlocked()
    }

    pub fn is_watch_only(&self) -> bool {
        self.read_lock().is_watch_only()
    }

    /// Get current key epoch (cloned, since we can't hold a reference through RwLock)
    pub fn current_keys(&self) -> Option<KeyEpoch> {
        self.read_lock().current_keys().cloned()
    }

    /// Get the wallet's network name
    pub fn network_name(&self) -> String {
        self.read_lock().network.clone()
    }

    pub fn address(&self) -> Result<String> {
        self.read_lock().address()
    }

    pub fn total_balance(&self) -> Amount {
        self.read_lock().total_balance()
    }

    pub fn spendable_balance(&self, current_height: u64) -> Amount {
        self.read_lock().spendable_balance(current_height)
    }

    pub fn info(&self, current_height: u64) -> WalletInfo {
        self.read_lock().info(current_height)
    }

    pub fn add_utxo(&self, utxo: UTXO) {
        self.write_lock().add_utxo(utxo)
    }

    pub fn set_scanned_height(&self, height: u64) {
        self.write_lock().set_scanned_height(height)
    }

    pub fn scanned_height(&self) -> u64 {
        self.read_lock().scanned_height()
    }

    /// Get subaddress data
    pub fn subaddress_data(&self) -> Option<super::SubaddressData> {
        self.read_lock().subaddress_data().cloned()
    }

    /// Set subaddress data for persistence
    pub fn set_subaddress_data(&self, data: super::SubaddressData) {
        self.write_lock().set_subaddress_data(data)
    }

    /// Get a reference to the balance for creating transactions
    /// This returns a clone of the balance since we can't return a reference
    /// through the RwLock
    pub fn balance(&self) -> Balance {
        self.read_lock().balance.clone()
    }

    /// Get all UTXOs (for export_key_images)
    pub fn get_all_utxos(&self) -> Vec<UTXO> {
        self.read_lock().balance.all_utxos()
    }

    /// Trigger rescan from a given height
    pub fn trigger_rescan(&self, from_height: u64) {
        let mut wallet = self.write_lock();
        wallet.scanned_height = from_height;
        wallet.state = WalletState::Syncing;
    }

    // === Transaction History Methods ===

    /// Record an incoming transaction
    pub fn record_incoming(
        &self,
        tx_hash: Hash,
        amount: Amount,
        block_height: u64,
        timestamp: u64,
        output_index: u8,
        subaddress: Option<super::SubaddressIndex>,
    ) {
        self.write_lock().record_incoming(
            tx_hash, amount, block_height, timestamp, output_index, subaddress,
        );
    }

    /// Record an outgoing transaction
    pub fn record_outgoing(
        &self,
        tx_hash: Hash,
        amount: Amount,
        fee: Amount,
        block_height: u64,
        timestamp: u64,
    ) {
        self.write_lock().record_outgoing(
            tx_hash, amount, fee, block_height, timestamp,
        );
    }

    /// Record an outgoing transaction with recipient address for reuse detection
    pub fn record_outgoing_with_address(
        &self,
        tx_hash: Hash,
        amount: Amount,
        fee: Amount,
        block_height: u64,
        timestamp: u64,
        recipient_address: &str,
    ) {
        self.write_lock().record_outgoing_with_address(
            tx_hash, amount, fee, block_height, timestamp, recipient_address,
        );
    }

    /// Get recent transactions (newest first)
    pub fn recent_transactions(&self, limit: usize) -> Vec<TransactionRecord> {
        self.read_lock().history().recent(limit).into_iter().cloned().collect()
    }

    /// Get all incoming transactions
    pub fn incoming_transactions(&self) -> Vec<TransactionRecord> {
        self.read_lock().history().incoming().into_iter().cloned().collect()
    }

    /// Get all outgoing transactions
    pub fn outgoing_transactions(&self) -> Vec<TransactionRecord> {
        self.read_lock().history().outgoing().into_iter().cloned().collect()
    }

    /// Get pending transactions
    pub fn pending_transactions(&self) -> Vec<TransactionRecord> {
        self.read_lock().history().pending().into_iter().cloned().collect()
    }

    /// Get transaction count
    pub fn transaction_count(&self) -> usize {
        self.read_lock().history().count()
    }

    /// Set memo for a transaction
    pub fn set_tx_memo(&self, tx_hash: &Hash, memo: &str) -> bool {
        self.write_lock().set_tx_memo(tx_hash, memo)
    }

    /// Update transaction statuses based on current height
    pub fn update_tx_statuses(&self, current_height: u64) {
        self.write_lock().update_tx_statuses(current_height);
    }

    /// Get total received amount
    pub fn total_received(&self) -> Amount {
        self.read_lock().history().total_received()
    }

    /// Get total sent amount (including fees)
    pub fn total_sent(&self) -> Amount {
        self.read_lock().history().total_sent()
    }

    /// Get total fees paid
    pub fn total_fees(&self) -> Amount {
        self.read_lock().history().total_fees()
    }

    /// Get view key for read-only wallet functionality
    ///
    /// # Security Warning
    /// See `Wallet::export_view_key` for security implications.
    /// The view key reveals ALL transaction history to anyone who possesses it.
    pub fn view_key_hex(&self) -> Option<String> {
        // SECURITY: Log sensitive key access
        tracing::warn!(
            target: "wallet::security",
            "View key accessed via SharedWallet - this reveals transaction history"
        );
        let wallet = self.read_lock();
        wallet.keys.as_ref()?.current().map(|epoch| hex::encode(epoch.view_secret.as_bytes()))
    }

    /// Create a transfer transaction
    ///
    /// This is the primary method for creating transactions. It:
    /// 1. Validates the wallet is unlocked
    /// 2. Selects UTXOs for the transfer
    /// 3. Gets decoy outputs from the blockchain
    /// 4. Constructs a fully signed transaction
    ///
    /// # Arguments
    /// * `recipients` - List of (address, amount) pairs
    /// * `chain` - Reference to the blockchain for decoy selection
    ///
    /// # Returns
    /// * The signed transaction ready for broadcast
    pub fn create_transfer(
        &self,
        recipients: &[(crate::primitives::Address, Amount)],
        chain: &crate::chain::SharedBlockchain,
    ) -> Result<crate::transaction::Transaction> {
        // SECURITY: Use write lock to serialize transaction creation.
        // A read lock would allow concurrent calls to select the same UTXOs,
        // causing the second transaction to be rejected by the mempool.
        let wallet = self.write_lock();

        // SECURITY: Prevent watch-only wallets from attempting transactions.
        // Without this guard, the zero spend_secret would cause cryptographic
        // failures deep in ring signature code with confusing error messages.
        if wallet.is_watch_only() {
            return Err(Error::InvalidState(
                "Cannot create transactions from a watch-only wallet".into()
            ));
        }

        // Check wallet is unlocked
        if !wallet.is_unlocked() {
            return Err(Error::WalletLocked);
        }

        // Get keys
        let keys = wallet.keys.as_ref()
            .ok_or(Error::WalletLocked)?
            .current()
            .ok_or(Error::WalletLocked)?;

        // C1: height-coupled consensus values must be computed for the
        // height the tx will be MINED at — that's chain tip + 1, not the
        // wallet's last-scanned height. Two failure modes the old
        // `wallet.scanned_height` triggered:
        //
        //   (a) Wallet is behind the chain tip (mid-IBD, post-disconnect,
        //       just-opened). scanned_height is stale; the validator runs at
        //       the live tip+1. ring_size_at_height, min_output_age_at_height,
        //       and V2_TX_ACTIVATION_HEIGHT gates can all disagree, and the
        //       validator rejects with InvalidRingSize / InvalidLockHeight /
        //       version errors.
        //
        //   (b) Wallet is at the chain tip but the tip straddles an
        //       activation boundary. Wallet at tip=4999 picks ring=11
        //       (BOOTSTRAP_MIN_RING_SIZE); tx will be mined at h=5000 where
        //       validator requires ring=13 (MID_RING_SIZE) → silent rejection.
        //       Same shape at 9,999→10,000 and for MIN_OUTPUT_AGE_HARDFORK
        //       and V2_TX_ACTIVATION_HEIGHT.
        //
        // The correct height is `chain.height() + 1` — what `bin/wallet.rs`
        // already does via `info.height`. The library path mirrors that now.
        let current_height = chain.height().saturating_add(1);

        // Convert recipients to the format needed by create_privacy_transaction
        let privacy_recipients: Vec<(crate::primitives::PublicKey, crate::primitives::PublicKey, Amount)> =
            recipients.iter()
                .map(|(addr, amount)| (addr.spend_public_key, addr.view_public_key, *amount))
                .collect();

        // Get ring size for the height the tx will be mined at.
        let ring_size = crate::constants::ring_size_at_height(current_height);

        // Get decoy outputs from the chain
        // We need (ring_size - 1) decoys per input, estimate we need up to 5 inputs max
        let decoy_count = (ring_size - 1) * 5;
        // CONSENSUS-COUPLED: maturity floor flips at the hard-fork
        // height. Decoy selection must match the validator's rule or
        // the wallet will pick decoys the validator rejects.
        let min_age = crate::constants::min_output_age_at_height(current_height);
        let decoys = chain.get_decoy_outputs(decoy_count, min_age);

        // SECURITY (A6-RING): Check for sufficient decoys. Without enough ring members,
        // the real spend becomes trivially identifiable, destroying privacy.
        if decoys.len() < ring_size - 1 {
            #[cfg(not(feature = "testnet"))]
            {
                return Err(Error::InsufficientDecoys {
                    available: decoys.len(),
                    needed: ring_size - 1,
                });
            }
            #[cfg(feature = "testnet")]
            tracing::warn!(
                "Testnet: insufficient decoys ({}/{}) - proceeding with reduced privacy",
                decoys.len(),
                ring_size - 1
            );
        }

        // Create the transaction
        let mut rng = rand::rngs::OsRng;
        super::send::create_privacy_transaction(
            &wallet.balance,
            &privacy_recipients,
            keys,
            &decoys,
            current_height,
            &mut rng,
        )
    }

    /// Create a vesting transaction that locks funds until a target height.
    pub fn create_vesting(
        &self,
        amount: Amount,
        recipient: &crate::primitives::Address,
        unlock_height: u64,
        chain: &crate::chain::SharedBlockchain,
    ) -> Result<crate::transaction::Transaction> {
        // SECURITY: Write lock serializes tx creation (see create_transfer)
        let wallet = self.write_lock();

        if wallet.is_watch_only() {
            return Err(Error::InvalidState(
                "Cannot create transactions from a watch-only wallet".into(),
            ));
        }

        if !wallet.is_unlocked() {
            return Err(Error::WalletLocked);
        }

        let keys = wallet.keys.as_ref()
            .ok_or(Error::WalletLocked)?
            .current()
            .ok_or(Error::WalletLocked)?;

        // C1: use chain.height()+1 (where the tx will be mined) instead
        // of wallet.scanned_height (a potentially stale past height). Same
        // reasoning as the matching site in create_transfer above — see
        // that comment for full rationale.
        let current_height = chain.height().saturating_add(1);
        let ring_size = crate::constants::ring_size_at_height(current_height);
        let decoy_count = (ring_size - 1) * 5;
        // CONSENSUS-COUPLED: see comment at the matching site in
        // create_transfer above (decoy maturity must match validator).
        let min_age = crate::constants::min_output_age_at_height(current_height);
        let decoys = chain.get_decoy_outputs(decoy_count, min_age);

        let mut rng = rand::rngs::OsRng;
        super::send::create_vesting_transaction(
            &wallet.balance,
            recipient.spend_public_key,
            recipient.view_public_key,
            amount,
            unlock_height,
            keys,
            &decoys,
            current_height,
            &mut rng,
        )
    }
}

impl Clone for SharedWallet {
    fn clone(&self) -> Self {
        SharedWallet {
            inner: Arc::clone(&self.inner),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn test_wallet_create() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("test.wallet");

        let (wallet, mnemonic) = Wallet::create(path.clone(), Some("test123"), "testnet").unwrap();

        assert!(wallet.is_unlocked());
        assert!(!mnemonic.is_empty());
        assert!(path.exists());
    }

    #[test]
    fn test_wallet_lock_unlock() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("test.wallet");

        let (mut wallet, _) = Wallet::create(path.clone(), Some("test123"), "testnet").unwrap();

        wallet.lock();
        assert!(!wallet.is_unlocked());

        wallet.unlock("test123").unwrap();
        assert!(wallet.is_unlocked());
    }
}
