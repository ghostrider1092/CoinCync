//! # Wallet Implementation
//!
//! Main wallet struct that combines keys, balance, and operations.

use parking_lot::RwLock;
use std::path::PathBuf;
use std::sync::Arc;

use crate::error::{Error, Result};
use crate::primitives::{Amount, Hash, KeyImage};
use rand::RngCore;
use zeroize::Zeroize;

use super::balance::{Balance, UTXO};
use super::history::{TransactionHistory, TransactionRecord};
use super::key_epoch::KeyEpoch;
use super::persistence::{
    generate_mnemonic, load_wallet, mnemonic_to_seed, save_wallet, WalletData,
};
use super::wallet_keys::WalletKeys;

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
    pub fn create(path: PathBuf, password: Option<&str>, network: &str) -> Result<(Self, String)> {
        if path.exists() {
            return Err(Error::WalletExists(path.display().to_string()));
        }

        // Generate seed
        let (mnemonic, mut seed) = generate_mnemonic();

        // Create keys.
        //
        // AUDIT (R-110 fix, 2026-07-03): pre-fix code did
        //   let (mnemonic, seed) = generate_mnemonic();
        //   let keys = WalletKeys::from_seed(seed);
        //   let data = WalletData::new(seed, network);
        // The `seed: [u8; 32]` local was Copy-moved into
        // WalletKeys::from_seed AND WalletData::new. Both structs
        // implement zero-on-drop on their INTERNAL fields, but the
        // Copy-source `seed` on THIS stack frame is untouched and
        // never zeroized. Wallet::create is only called at wallet
        // creation, so the window is one-shot per wallet — but the
        // stack frame COULD be reused by a subsequent scan / send
        // that dumps stack via a bug or panic. Explicit zeroize
        // closes the window.
        let mut keys = WalletKeys::from_seed(seed);
        // R-115: annotate with the mnemonic so future save() cycles
        // preserve it. Also passes the phrase through to the initial
        // save via WalletData.mnemonic_phrase (which save_wallet
        // will encrypt+persist).
        keys.set_mnemonic_phrase(mnemonic.clone());

        // Create wallet data
        let mut data = WalletData::new(seed, network);
        data.mnemonic_phrase = Some(mnemonic.clone());

        // Save to file
        save_wallet(&path, &data, password)?;

        // R-110: wipe local `seed` after both consumers have taken
        // their Copy. `keys` and `data` internally hold their own
        // seed copies, protected by their own drop chains.
        {
            use zeroize::Zeroize;
            seed.zeroize();
        }

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
            return Err(Error::InvalidParams(
                "spend public key must be 32 bytes".into(),
            ));
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
        self.watch_only
            || self
                .keys
                .as_ref()
                .map(|k| k.is_watch_only())
                .unwrap_or(false)
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
        let mut keys = WalletKeys::from_seed(seed);
        // R-115: annotate with the caller-supplied mnemonic so
        // future save() calls preserve it.
        keys.set_mnemonic_phrase(mnemonic.to_string());

        // Create wallet data
        let mut data = WalletData::new(seed, network);
        data.mnemonic_phrase = Some(mnemonic.to_string());

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
            let spend_bytes = hex::decode(spend_hex).map_err(|e| {
                Error::InvalidState(format!(
                    "corrupt watch-only wallet: invalid spend key hex: {}",
                    e
                ))
            })?;
            if spend_bytes.len() != 32 {
                return Err(Error::InvalidState(
                    "corrupt watch-only wallet: spend key must be 32 bytes".into(),
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
                 re-import using view key and spend public key"
                    .into(),
            ));
        } else {
            self.watch_only = false;
            WalletKeys::from_seed(data.seed)
        };

        // R-115 SURGICAL FIX (2026-07-03): restore the mnemonic
        // phrase into WalletKeys if the save file persisted one.
        // Pre-fix code did WalletKeys::from_seed(data.seed) and
        // discarded data.mnemonic_phrase.
        let mut keys = keys;
        if let Some(phrase) = data.mnemonic_phrase.as_ref() {
            keys.set_mnemonic_phrase(phrase.clone());
        }

        self.keys = Some(keys);
        self.scanned_height = data.scanned_height;
        self.network = data.network.clone();
        self.label = data.label.clone();
        self.state = WalletState::Unlocked;
        self.subaddress_data = data.subaddresses.clone();
        self.created_at = data.created_at;

        // Restore persisted UTXOs from sidecar file (decrypt if encrypted).
        //
        // R-111 fix (2026-07-02): `decrypt_sidecar` returns a `Vec<u8>`
        // containing decrypted plaintext (UTXO structs with the
        // amount_blinding_bytes secret material). Prior code let the
        // Vec drop unzeroized, leaving the plaintext on the heap
        // until re-allocation. Now: `mut json_bytes` + explicit
        // `.zeroize()` after deserialization at each sidecar path.
        let utxo_path = self.path.with_extension("utxos");
        if utxo_path.exists() {
            if let Ok(bytes) = std::fs::read(&utxo_path) {
                let mut json_bytes = Self::decrypt_sidecar(&bytes, password);
                if let Ok(utxos) = serde_json::from_slice::<Vec<UTXO>>(&json_bytes) {
                    for utxo in utxos {
                        self.balance.add_utxo(utxo);
                    }
                }
                json_bytes.zeroize();
            }
        }

        // Restore persisted transaction history from sidecar file (decrypt if encrypted).
        // See R-111 note above; same pattern.
        let history_path = self.path.with_extension("history");
        if history_path.exists() {
            if let Ok(bytes) = std::fs::read(&history_path) {
                let mut json_bytes = Self::decrypt_sidecar(&bytes, password);
                if let Ok(records) = serde_json::from_slice::<Vec<TransactionRecord>>(&json_bytes) {
                    for record in records {
                        self.history.add(record);
                    }
                }
                json_bytes.zeroize();
            }
        }

        // Restore in-flight UTXO reservations from sidecar (Item 1).
        // `restore_reservations` skips entries already past expiry, so a
        // wallet that's been closed for hours/days won't resurrect stale
        // claims. `scanned_height` is the best available "current height"
        // proxy at unlock time — wallets that refresh more aggressively
        // can call `release_expired_reservations(true_current_height)` on
        // open with a fresh chain query.
        //
        // R-111 fix: zeroize decrypted plaintext after use.
        let reservations_path = self.path.with_extension("reservations");
        if reservations_path.exists() {
            if let Ok(bytes) = std::fs::read(&reservations_path) {
                let mut json_bytes = Self::decrypt_sidecar(&bytes, password);
                if let Ok(entries) = serde_json::from_slice::<
                    Vec<((Hash, u8), super::balance::Reservation)>,
                >(&json_bytes)
                {
                    self.balance
                        .restore_reservations(entries, self.scanned_height);
                }
                json_bytes.zeroize();
            }
        }

        Ok(())
    }

    /// Lock wallet.
    ///
    /// SECURITY (R-112 fix, 2026-07-02): Prior implementation only dropped
    /// `WalletKeys`. Balance, history and subaddress caches survived,
    /// which leaked spend-side privacy: an attacker with a memory dump
    /// after `lock()` still saw UTXOs, ring positions, transaction
    /// history and subaddress indices. Now we:
    ///   1. Explicitly drop `WalletKeys` (triggers ZeroizeOnDrop).
    ///   2. Replace `balance` with an empty `Balance` (drops the old
    ///      UTXO + key-image tables).
    ///   3. Clear `history.records` in place.
    ///   4. Drop `subaddress_data` (subaddress derivation indices are
    ///      a privacy leak — they reveal receive-address patterns).
    /// `scanned_height`, `network`, `label`, `path` and `created_at` are
    /// non-secret bookkeeping and are kept so unlock() can restore scan
    /// state without a full re-scan.
    pub fn lock(&mut self) {
        if let Some(keys) = self.keys.take() {
            drop(keys); // Explicitly trigger Drop (which runs ZeroizeOnDrop)
        }
        self.balance = Balance::new();
        self.history.clear();
        self.subaddress_data = None;
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

        let keys = self
            .keys
            .as_ref()
            .ok_or(Error::InvalidState("wallet locked".into()))?;

        let epoch = keys
            .current()
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
        // Audit MEDIUM #32 closure: this entry point now refuses export.
        // The view key reveals ALL transaction history — exporting it
        // from an already-unlocked wallet without password re-confirm is
        // an unattended-session footgun (an attacker who walks up to an
        // unlocked desktop wallet can dump the view key in one RPC call).
        // Use `export_view_key_confirmed(password, epoch)` instead. The
        // bool-toggle variant proposed by the audit was rejected as too
        // easy to call with the wrong default; making the safe API the
        // only API forces every caller to be explicit.
        //
        // The unlock-gated pattern this fix mirrors is present in
        // zcashd's `z_exportviewingkey` at src/wallet/rpcdump.cpp:976,
        // which calls `EnsureWalletIsUnlocked()` at line 1002 before
        // returning any viewing key. CoinCync's design goes one step
        // further by also requiring an explicit password re-confirm
        // parameter on the successor API, not just an unlock check.
        let _ = epoch;
        Err(Error::InvalidState(
            "export_view_key requires password re-confirmation; \
             call export_view_key_confirmed(password, epoch) instead"
                .into(),
        ))
    }

    /// Export the view key after re-verifying the wallet password.
    ///
    /// Closes audit MEDIUM #32 (view-key export not gated behind password
    /// re-entry). Password verification is implicit: we re-run `load_wallet`
    /// with the supplied password and reject on cipher-tag mismatch. The
    /// password is held in memory only for the verify call; it is dropped
    /// before the view key is returned.
    pub fn export_view_key_confirmed(&self, password: &str, epoch: Option<u64>) -> Result<String> {
        // Re-verify password by attempting wallet load. A wrong password
        // surfaces as a decrypt error (Argon2id KDF + AEAD tag check).
        // We discard the loaded data — we only need confirmation that
        // the operator currently holds the password, not the data itself.
        let _ = load_wallet(&self.path, Some(password))?;

        tracing::warn!(
            target: "wallet::security",
            "View key export confirmed by password re-entry; \
             this reveals transaction history to the recipient"
        );

        let keys = self
            .keys
            .as_ref()
            .ok_or(Error::InvalidState("wallet locked".into()))?;

        let key_epoch = match epoch {
            Some(e) => keys
                .get_epoch(e)
                .ok_or(Error::InvalidState(format!("epoch {} not found", e)))?,
            None => keys
                .current()
                .ok_or(Error::InvalidState("no key epoch".into()))?,
        };

        Ok(hex::encode(key_epoch.view_secret.as_bytes()))
    }

    /// Get current key epoch number
    pub fn current_epoch(&self) -> Result<u64> {
        let keys = self
            .keys
            .as_ref()
            .ok_or(Error::InvalidState("wallet locked".into()))?;

        let epoch = keys
            .current()
            .ok_or(Error::InvalidState("no key epoch".into()))?;

        Ok(epoch.epoch)
    }

    /// Get total balance
    pub fn total_balance(&self) -> Amount {
        self.balance.total()
    }

    /// Get the full Balance tracker.
    ///
    /// AUDIT (R-113 note, 2026-07-03): `Balance` contains a
    /// `HashMap<OutputKey, UTXO>` where each `UTXO` holds an
    /// `amount_blinding_bytes: [u8; 32]` — the Pedersen blinding
    /// factor, which is SECRET material. `.clone()` DUPLICATES
    /// every blinding factor into a fresh HashMap on the caller's
    /// heap, doubling the memory footprint of secret material and
    /// widening the attack surface for a memory dump.
    ///
    /// Callers who only need to QUERY the balance should use
    /// `balance_ref()` (already public, see just below) — it
    /// returns `&Balance` with zero clone cost. This fn stays
    /// public for the small number of callers who genuinely need
    /// an owned Balance (RPC serialization, snapshot testing);
    /// they accept the secret-duplication cost. New callers must
    /// justify the clone.
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

    /// Reorg rewind (Task #1b): drop UTXOs the wallet received in
    /// now-orphaned blocks, from BOTH balance and history, keeping the two
    /// layers consistent. Fed by `RewindOutcome.outputs_to_remove` from
    /// [`WalletScanner::rewind_to_height`]. Returns the number of balance
    /// UTXOs removed.
    pub fn remove_outputs(&mut self, outputs: &[(Hash, u8)]) -> usize {
        self.history.remove_incoming_outputs(outputs);
        self.balance.remove_outputs(outputs)
    }

    /// Reorg rewind: revert outgoing history records for transactions that
    /// were confirmed only in now-orphaned blocks (height > `new_height`),
    /// so the UI stops showing a spend that no longer happened on the
    /// canonical chain. Returns the number of records reverted.
    pub fn revert_outgoing_above_height(&mut self, new_height: u64) -> usize {
        self.history.revert_outgoing_above_height(new_height)
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
            tx_hash,
            amount,
            block_height,
            timestamp,
            output_index,
            subaddress,
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
        let record = TransactionRecord::outgoing(tx_hash, amount, fee, block_height, timestamp);
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
        let mut record = TransactionRecord::outgoing(tx_hash, amount, fee, block_height, timestamp);
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
        let keys = self
            .keys
            .as_mut()
            .ok_or(Error::InvalidState("wallet locked".into()))?;

        let next_epoch = keys.current().map(|e| e.epoch + 1).unwrap_or(0);

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
        let keys = self
            .keys
            .as_ref()
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
                let mut key = super::derive_key_default(pw, &salt)?;
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
            std::fs::write(&utxo_tmp_path, &bytes_to_write).map_err(|e| {
                Error::InvalidState(format!("failed to write UTXO temp file: {}", e))
            })?;
            // R-100 fix: harden BEFORE the atomic rename so the
            // as-visible-to-others file always has restrictive perms.
            super::persistence::harden_secret_file_permissions(&utxo_tmp_path);
            std::fs::rename(&utxo_tmp_path, &utxo_path)
                .map_err(|e| Error::InvalidState(format!("failed to rename UTXO file: {}", e)))?;
            // Also harden the final path in case the rename doesn't
            // preserve ACLs on this platform (Windows preserves them
            // via move within same volume, but this is defense-in-depth).
            super::persistence::harden_secret_file_permissions(&utxo_path);
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
            let mut json = serde_json::to_vec(&reservations).map_err(|e| {
                Error::InvalidState(format!("failed to serialize reservations: {}", e))
            })?;
            let bytes_to_write = if let Some(pw) = password {
                let mut salt = [0u8; 32];
                rand::rngs::OsRng.fill_bytes(&mut salt);
                let mut key = super::derive_key_default(pw, &salt)?;
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
            std::fs::write(&reservations_tmp_path, &bytes_to_write).map_err(|e| {
                Error::InvalidState(format!("failed to write reservations temp file: {}", e))
            })?;
            // R-100 fix: harden reservations sidecar (same defense as .utxos).
            super::persistence::harden_secret_file_permissions(&reservations_tmp_path);
            std::fs::rename(&reservations_tmp_path, &reservations_path).map_err(|e| {
                Error::InvalidState(format!("failed to rename reservations file: {}", e))
            })?;
            super::persistence::harden_secret_file_permissions(&reservations_path);
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
                let mut key = super::derive_key_default(pw, &salt)?;
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
            std::fs::write(&history_tmp_path, &bytes_to_write).map_err(|e| {
                Error::InvalidState(format!("failed to write history temp file: {}", e))
            })?;
            // R-100 fix: harden history sidecar (same defense as .utxos).
            super::persistence::harden_secret_file_permissions(&history_tmp_path);
            std::fs::rename(&history_tmp_path, &history_path).map_err(|e| {
                Error::InvalidState(format!("failed to rename history file: {}", e))
            })?;
            super::persistence::harden_secret_file_permissions(&history_path);
        } else if history_path.exists() {
            let _ = std::fs::remove_file(&history_path);
        }

        // === Step 3: wallet file (with scanned_height) -- LAST ===
        // CRITICAL FIX (commit f8daaea): Use master_seed, NOT derived
        // spend_secret. Using spend_secret would cause restore to produce
        // wrong keys since the derived key would be treated as a master
        // seed. Using master_seed_for_backup() which is the secure API.
        //
        // R-114 fix (2026-07-02): the prior `let seed = *keys.master_seed_for_backup();`
        // Copy'd the [u8; 32] master seed onto the stack of save(). The
        // stack copy was never zeroized; it persisted until save()
        // returned. Since save() is called after every scan cycle (i.e.
        // frequently in a running wallet), the stack window was reopened
        // constantly. Now we scope the seed inside a mutable local +
        // build the WalletData from a clone-then-zeroize pattern:
        // WalletData's Drop already zeros its own seed, so once we move
        // the seed into WalletData we can clear the local immediately.
        // R-75: master_seed_for_backup now returns Option — None on
        // watch-only. Save persists the raw sentinel via the internal
        // accessor because save preserves round-trip fidelity (a
        // watch-only wallet re-loaded must round-trip to the same
        // watch-only state). External backup callers must use
        // master_seed_for_backup and handle the None branch.
        let mut seed = *keys.raw_master_seed_or_sentinel();
        // AUDIT (R-115 note, 2026-07-03): `mnemonic_phrase` is
        // hardcoded to `None` in every save cycle. That means:
        //   - Wallets CREATED with a mnemonic (Wallet::create)
        //     persist without the phrase.
        //   - On subsequent load, the phrase is not recoverable
        //     even though the seed is — the user can't ever run
        //     "show my seed phrase" after the first save cycle.
        //   - Wallets restored FROM a mnemonic via Wallet::restore
        //     ALSO lose the phrase on their first save.
        // This is a UX bug rather than a security bug — the seed
        // IS still on disk, so the wallet still functions and the
        // BIP39 phrase can be regenerated at import via a fresh
        // Wallet::from_seed roundtrip. But an operator invoking
        // "show mnemonic phrase" on an already-saved wallet gets
        // an error, and support tickets for "I lost my seed
        // phrase" go up. Not fixing structurally here because
        // preserving the phrase requires threading it through
        // Wallet's fields (WalletKeys doesn't currently retain
        // the phrase — it only retains the derived seed). Follow-
        // up to add `WalletKeys::mnemonic: Option<Zeroizing<String>>`
        // is queued separately.
        let data = WalletData {
            seed, // Copy'd into WalletData.seed; original local zeroed below.
            current_epoch: keys.current().map(|e| e.epoch).unwrap_or(0),
            scanned_height: self.scanned_height,
            label: self.label.clone(),
            created_at: self.created_at,
            network: self.network.clone(),
            subaddresses: self.subaddress_data.clone(),
            // R-115 SURGICAL FIX (2026-07-03): preserve the mnemonic
            // phrase from WalletKeys through save. Prior code
            // hardcoded `None` here.
            mnemonic_phrase: keys.mnemonic_phrase().map(|s| s.to_string()),
        };
        // R-114 fix: wipe the stack copy immediately. WalletData::Drop
        // wipes its own `.seed` field on drop; this closes the parallel
        // stack-copy window.
        seed.zeroize();
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
            if let Ok(plaintext) =
                super::decrypt_sidecar_with_fallback(&salt, &nonce, ciphertext, password)
            {
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
            pending: self
                .total_balance()
                .saturating_sub(self.spendable_balance(current_height)),
            scanned_height: self.scanned_height,
            utxo_count: self.available_utxos(current_height).len(),
            key_epoch: self
                .keys
                .as_ref()
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
    ///
    /// AUDIT (R-116 fix, 2026-07-02): the prior comment here claimed
    /// "SECURITY: Recovers from poisoned locks instead of panicking."
    /// That's a stale doc from a `std::sync::RwLock` era. This uses
    /// `parking_lot::RwLock`, which does NOT poison — a panic-in-guard
    /// leaves the mutex intact and the next acquirer gets a normal
    /// lock. There is nothing to recover from because there is no
    /// poison state; the false-security comment misled readers into
    /// thinking a safety net existed. If a real poisoning strategy is
    /// needed (e.g. because a mutation panicked while wallet state was
    /// half-updated), that would be a domain-level invariant reset —
    /// not a lock-poison recovery — and the design belongs on the
    /// mutation methods, not here.
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
    /// through the RwLock.
    ///
    /// AUDIT (R-113 note): the clone DUPLICATES `amount_blinding_bytes`
    /// (secret material) for every UTXO. See [`with_balance`] for a
    /// zero-clone alternative that runs a closure under the read
    /// lock and returns the closure's output.
    pub fn balance(&self) -> Balance {
        self.read_lock().balance.clone()
    }

    /// R-113 SURGICAL FIX (2026-07-03): run `f` with a shared
    /// reference to the underlying Balance, holding the read lock
    /// only for the closure's duration. Returns `f`'s output.
    /// Zero secret-material clones. Callers that only need to
    /// COMPUTE something from Balance (fee estimate, iterator,
    /// summed amount) should use this instead of `balance()`.
    pub fn with_balance<T>(&self, f: impl FnOnce(&Balance) -> T) -> T {
        let guard = self.read_lock();
        f(&guard.balance)
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
            tx_hash,
            amount,
            block_height,
            timestamp,
            output_index,
            subaddress,
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
        self.write_lock()
            .record_outgoing(tx_hash, amount, fee, block_height, timestamp);
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
            tx_hash,
            amount,
            fee,
            block_height,
            timestamp,
            recipient_address,
        );
    }

    /// Get recent transactions (newest first)
    pub fn recent_transactions(&self, limit: usize) -> Vec<TransactionRecord> {
        self.read_lock()
            .history()
            .recent(limit)
            .into_iter()
            .cloned()
            .collect()
    }

    /// Get all incoming transactions
    pub fn incoming_transactions(&self) -> Vec<TransactionRecord> {
        self.read_lock()
            .history()
            .incoming()
            .into_iter()
            .cloned()
            .collect()
    }

    /// Get all outgoing transactions
    pub fn outgoing_transactions(&self) -> Vec<TransactionRecord> {
        self.read_lock()
            .history()
            .outgoing()
            .into_iter()
            .cloned()
            .collect()
    }

    /// Get pending transactions
    pub fn pending_transactions(&self) -> Vec<TransactionRecord> {
        self.read_lock()
            .history()
            .pending()
            .into_iter()
            .cloned()
            .collect()
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
        wallet
            .keys
            .as_ref()?
            .current()
            .map(|epoch| hex::encode(epoch.view_secret.as_bytes()))
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
                "Cannot create transactions from a watch-only wallet".into(),
            ));
        }

        // Check wallet is unlocked
        if !wallet.is_unlocked() {
            return Err(Error::WalletLocked);
        }

        // Get keys
        let keys = wallet
            .keys
            .as_ref()
            .ok_or(Error::WalletLocked)?
            .current()
            .ok_or(Error::WalletLocked)?;

        let snapshot = chain.decoy_distribution_snapshot();
        let current_height = snapshot.snapshot_height.saturating_add(1);

        // Convert recipients to the format needed by create_privacy_transaction
        let privacy_recipients: Vec<(
            crate::primitives::PublicKey,
            crate::primitives::PublicKey,
            Amount,
        )> = recipients
            .iter()
            .map(|(addr, amount)| (addr.spend_public_key, addr.view_public_key, *amount))
            .collect();

        let ring_size = crate::constants::ring_size_at_height(current_height);
        let min_age = crate::constants::min_output_age_at_height(current_height);
        let mut rng = rand::rngs::OsRng;
        let prepared = super::send::prepare_privacy_transaction_with_options(
            &wallet.balance,
            &privacy_recipients,
            keys,
            current_height,
            ring_size,
            1.0,
            None,
            Vec::new(),
            &mut rng,
        )?;
        let real_outputs = prepared.real_outputs();
        let real_locators: Vec<_> = real_outputs.iter().map(|output| output.locator).collect();
        let requested = super::decoy_selection::build_covered_request(
            &snapshot,
            &real_locators,
            prepared.ring_size(),
            min_age,
            &mut rng,
        )?;
        let resolved = chain.resolve_decoy_snapshot(
            snapshot.snapshot_height,
            snapshot.snapshot_hash,
            snapshot.policy_version,
            &requested,
        )?;
        let rings = super::decoy_selection::allocate_unique_rings(
            &snapshot,
            &requested,
            &resolved,
            &real_outputs,
            prepared.ring_size(),
            min_age,
            &mut rng,
        )?;
        super::send::build_prepared_privacy_transaction(prepared, rings, &mut rng)
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

        let keys = wallet
            .keys
            .as_ref()
            .ok_or(Error::WalletLocked)?
            .current()
            .ok_or(Error::WalletLocked)?;

        let snapshot = chain.decoy_distribution_snapshot();
        let current_height = snapshot.snapshot_height.saturating_add(1);
        let ring_size = crate::constants::ring_size_at_height(current_height);
        let min_age = crate::constants::min_output_age_at_height(current_height);
        let mut rng = rand::rngs::OsRng;
        let prepared = super::send::prepare_vesting_transaction(
            &wallet.balance,
            recipient.spend_public_key,
            recipient.view_public_key,
            amount,
            unlock_height,
            keys,
            current_height,
            ring_size,
            &mut rng,
        )?;
        let real_outputs = prepared.real_outputs();
        let real_locators: Vec<_> = real_outputs.iter().map(|output| output.locator).collect();
        let requested = super::decoy_selection::build_covered_request(
            &snapshot,
            &real_locators,
            prepared.ring_size(),
            min_age,
            &mut rng,
        )?;
        let resolved = chain.resolve_decoy_snapshot(
            snapshot.snapshot_height,
            snapshot.snapshot_hash,
            snapshot.policy_version,
            &requested,
        )?;
        let rings = super::decoy_selection::allocate_unique_rings(
            &snapshot,
            &requested,
            &resolved,
            &real_outputs,
            prepared.ring_size(),
            min_age,
            &mut rng,
        )?;
        super::send::build_prepared_vesting_transaction(prepared, rings, &mut rng)
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

    /// R-112 regression: lock() must clear cached balance, history, and
    /// subaddress data — not just wallet keys — so a post-lock memory
    /// dump does not leak UTXOs, ring metadata, or subaddress indices.
    #[test]
    fn lock_clears_balance_history_and_subaddress_caches() {
        use crate::primitives::{Amount, Hash, KeyImage, PublicKey};
        use crate::wallet::balance::UTXO;
        use crate::wallet::history::TransactionRecord;

        let dir = tempdir().unwrap();
        let path = dir.path().join("test.wallet");
        let (mut wallet, _) = Wallet::create(path.clone(), Some("test123"), "testnet").unwrap();

        wallet.balance.add_utxo(UTXO {
            tx_hash: Hash::from_bytes([1u8; 32]),
            output_index: 0,
            output_locator: None,
            amount: Amount::from_atomic(1_000_000),
            height: 42,
            key_image: KeyImage::from_bytes([3u8; 32]),
            spent: false,
            amount_blinding_bytes: [7u8; 32],
            tx_public_key: PublicKey::from_bytes([2u8; 32]),
            lock_height: None,
        });
        wallet.history.add(TransactionRecord::incoming(
            Hash::from_bytes([5u8; 32]),
            Amount::from_atomic(1_000_000),
            42,
            0,
            0,
            None,
        ));
        wallet.subaddress_data = Some(super::super::SubaddressData::default());

        assert!(
            wallet.balance.total().as_atomic() > 0,
            "precondition: balance seeded"
        );
        assert!(
            wallet.subaddress_data.is_some(),
            "precondition: subaddr seeded"
        );

        wallet.lock();

        assert!(!wallet.is_unlocked(), "wallet should be locked");
        assert_eq!(
            wallet.balance.total().as_atomic(),
            0,
            "R-112: balance must be cleared on lock"
        );
        assert!(
            wallet.subaddress_data.is_none(),
            "R-112: subaddress_data must be cleared on lock"
        );
    }
}
