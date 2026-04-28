//! # Wallet Output Scanner for CoinCync 2.0
//!
//! Scans blockchain outputs to detect which belong to our wallet.
//! Uses view tags for fast filtering and proper amount decryption.

use std::sync::Arc;

use crate::primitives::{PublicKey, SecretKey, Hash, hash_domain};
use crate::transaction::{Transaction, TxOutput, TxType};
use crate::consensus::Block;
use crate::crypto::{StealthAddress, is_output_ours, BlindingFactor, SecretScalar, PublicPoint};
use crate::db::{WalletDb, OwnedOutput, ScanState};
use crate::error::Result;

use rayon::prelude::*;
use tracing::{info, debug};

/// Decrypted output information
///
/// SECURITY (WAL-002): Implements Drop to zeroize secret material
/// (shared_secret, amount) when no longer needed.
#[derive(Clone)]
pub struct DecryptedOutput {
    /// Transaction hash
    pub tx_hash: Hash,
    /// Output index
    pub output_index: u8,
    /// The raw output
    pub output: TxOutput,
    /// Decrypted amount
    pub amount: u64,
    /// Blinding factor for spending
    pub blinding_factor: BlindingFactor,
    /// The shared secret (for other derivations)
    pub shared_secret: [u8; 32],
    /// Which epoch/key found this
    pub key_epoch: u64,
    /// SECURITY (C9-FIX / H19-FIX): Subaddress index (account, index) if output
    /// was detected via a subaddress key. None means primary address.
    /// Previously this was always dropped, causing BackgroundScanner to persist
    /// `subaddress_index: None` for all outputs, losing subaddress association.
    pub subaddress_index: Option<(u32, u32)>,
}

impl std::fmt::Debug for DecryptedOutput {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DecryptedOutput")
            .field("tx_hash", &self.tx_hash)
            .field("output_index", &self.output_index)
            .field("amount", &"[REDACTED]")
            .field("shared_secret", &"[REDACTED]")
            .field("key_epoch", &self.key_epoch)
            .finish()
    }
}

impl Drop for DecryptedOutput {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.shared_secret.zeroize();
        self.amount = 0;
    }
}

/// Key set for scanning
///
/// SECURITY: Implements Drop to zeroize the view_secret when no longer needed.
/// Clone is required for parallel scanning but each clone is also zeroized on drop.
#[derive(Clone)]
pub struct ScanKeys {
    /// View secret key
    pub view_secret: SecretKey,
    /// Spend public key (primary address)
    pub spend_public: PublicKey,
    /// Key epoch
    pub epoch: u64,
    /// Subaddress spend public keys: (account, index) -> spend_public
    pub subaddress_keys: Vec<(u32, u32, PublicKey)>,
}

impl ScanKeys {
    pub fn new(view_secret: SecretKey, spend_public: PublicKey, epoch: u64) -> Self {
        ScanKeys {
            view_secret,
            spend_public,
            epoch,
            subaddress_keys: Vec::new(),
        }
    }
}

impl Drop for ScanKeys {
    fn drop(&mut self) {
        // SecretKey already zeroizes on drop, but we explicitly mark the epoch
        // to prevent information leakage about which key epoch was used.
        self.epoch = 0;
    }
}

/// Wallet output scanner
pub struct WalletScanner {
    /// Scan keys by epoch
    keys: Vec<ScanKeys>,
    /// Last scanned height
    last_height: u64,
    /// Last scanned hash
    last_hash: Hash,
    /// Statistics
    stats: ScanStats,
}

/// Scanning statistics
#[derive(Clone, Debug, Default)]
pub struct ScanStats {
    /// Blocks scanned
    pub blocks_scanned: u64,
    /// Transactions scanned
    pub transactions_scanned: u64,
    /// Outputs scanned
    pub outputs_scanned: u64,
    /// View tag matches (fast filter passed)
    pub view_tag_matches: u64,
    /// Full matches (ours)
    pub outputs_found: u64,
    /// Total amount found (u128 to prevent overflow from large asset supplies)
    pub total_amount: u128,
    /// Scan time in milliseconds
    pub scan_time_ms: u64,
}

impl WalletScanner {
    /// Create a new scanner
    pub fn new() -> Self {
        WalletScanner {
            keys: Vec::new(),
            last_height: 0,
            last_hash: Hash::zero(),
            stats: ScanStats::default(),
        }
    }

    /// Add keys for scanning
    pub fn add_keys(&mut self, view_secret: SecretKey, spend_public: PublicKey, epoch: u64) {
        self.keys.push(ScanKeys::new(view_secret, spend_public, epoch));
    }

    /// Register subaddress spend keys so the scanner can detect outputs
    /// sent to subaddresses. Call this after `add_keys()`.
    pub fn add_subaddress_keys(&mut self, subkeys: Vec<(u32, u32, PublicKey)>) {
        if let Some(keys) = self.keys.last_mut() {
            keys.subaddress_keys = subkeys;
        }
    }

    /// Clear all keys
    pub fn clear_keys(&mut self) {
        self.keys.clear();
    }

    /// Get current scan position
    pub fn position(&self) -> (u64, Hash) {
        (self.last_height, self.last_hash)
    }

    /// Set scan position (for resuming)
    pub fn set_position(&mut self, height: u64, hash: Hash) {
        self.last_height = height;
        self.last_hash = hash;
    }

    /// Get statistics
    pub fn stats(&self) -> &ScanStats {
        &self.stats
    }

    /// Reset statistics
    pub fn reset_stats(&mut self) {
        self.stats = ScanStats::default();
    }

    /// Scan a single output
    pub fn scan_output(
        &self,
        output: &TxOutput,
        output_index: u8,
        tx_hash: Hash,
        is_coinbase: bool,
    ) -> Option<DecryptedOutput> {
        // Try each key set
        for keys in &self.keys {
            if is_coinbase {
                // Coinbase outputs always store the amount as a plaintext LE u64.
                // New coinbases (post-fix) use proper ECDH stealth addresses — detect via
                // view_tag + is_output_ours, then read the plaintext amount.
                // Old coinbases use raw spend_public as stealth_address — detect by direct match.

                // Old-format coinbase: stealth_address == spend_public
                if output.stealth_address == keys.spend_public {
                    let amount = if output.encrypted_amount.len() >= 8 {
                        let mut bytes = [0u8; 8];
                        bytes.copy_from_slice(&output.encrypted_amount[..8]);
                        u64::from_le_bytes(bytes)
                    } else {
                        0
                    };
                    return Some(DecryptedOutput {
                        tx_hash,
                        output_index,
                        output: output.clone(),
                        amount,
                        blinding_factor: BlindingFactor::zero(),
                        shared_secret: [0u8; 32],
                        key_epoch: keys.epoch,
                        subaddress_index: None, // Coinbase always to primary address
                    });
                }

                // New-format coinbase: ECDH-derived unique stealth address
                let stealth_check = StealthAddress {
                    public_key: output.stealth_address,
                    tx_public_key: output.tx_public_key,
                };
                if is_output_ours(&stealth_check, &keys.view_secret, &keys.spend_public, output_index) {
                    let amount = if output.encrypted_amount.len() >= 8 {
                        let mut bytes = [0u8; 8];
                        bytes.copy_from_slice(&output.encrypted_amount[..8]);
                        u64::from_le_bytes(bytes)
                    } else {
                        0
                    };
                    return Some(DecryptedOutput {
                        tx_hash,
                        output_index,
                        output: output.clone(),
                        amount,
                        blinding_factor: BlindingFactor::zero(),
                        shared_secret: [0u8; 32],
                        key_epoch: keys.epoch,
                        subaddress_index: None, // Coinbase always to primary address
                    });
                }

                // This coinbase is not ours under this key_set; try the next one
                continue;
            }

            // Full ownership check on every non-coinbase output.
            // Previously the view_tag was used as a hard filter (skipping outputs on mismatch),
            // but any corruption in tx_public_key through serialization would permanently
            // lose the output. Now we always check ownership directly.
            let stealth = StealthAddress {
                public_key: output.stealth_address,
                tx_public_key: output.tx_public_key,
            };

            // Check primary address first
            let mut matched_spend_pub = None;
            let mut matched_subaddr: Option<(u32, u32)> = None;
            if is_output_ours(&stealth, &keys.view_secret, &keys.spend_public, output_index) {
                matched_spend_pub = Some(keys.spend_public);
                // Primary address: subaddress_index stays None
            }

            // If not primary, check all subaddress spend keys
            if matched_spend_pub.is_none() {
                for &(account, index, ref sub_spend) in &keys.subaddress_keys {
                    if is_output_ours(&stealth, &keys.view_secret, sub_spend, output_index) {
                        matched_spend_pub = Some(*sub_spend);
                        // SECURITY (C9-FIX): Preserve subaddress index for persistence
                        matched_subaddr = Some((account, index));
                        break;
                    }
                }
            }

            if matched_spend_pub.is_some() {
                // This output is ours! Decrypt the amount
                let shared_secret = compute_shared_secret(
                    &keys.view_secret,
                    &output.tx_public_key,
                    output_index,
                );

                let (amount, blinding_factor) = decrypt_amount(
                    &output.encrypted_amount,
                    &shared_secret,
                );

                return Some(DecryptedOutput {
                    tx_hash,
                    output_index,
                    output: output.clone(),
                    amount,
                    blinding_factor,
                    shared_secret,
                    key_epoch: keys.epoch,
                    subaddress_index: matched_subaddr,
                });
            }
        }

        None
    }

    /// Scan a transaction
    pub fn scan_transaction(&mut self, tx: &Transaction) -> Vec<DecryptedOutput> {
        let tx_hash = tx.hash();
        let mut found = Vec::new();
        let is_coinbase = tx.tx_type == TxType::Coinbase;

        self.stats.transactions_scanned += 1;

        for (idx, output) in tx.outputs.iter().enumerate() {
            // SECURITY (A6-IDX-TRUNC): Skip outputs past index 255 to prevent
            // idx as u8 truncation, which would cause incorrect one-time key
            // derivation and potentially miss real outputs or create phantom ones.
            if idx > 255 {
                tracing::warn!("Transaction {} has >255 outputs, skipping index {}", tx_hash.to_hex(), idx);
                break;
            }
            self.stats.outputs_scanned += 1;

            if let Some(decrypted) = self.scan_output(output, idx as u8, tx_hash, is_coinbase) {
                self.stats.outputs_found += 1;
                self.stats.total_amount += decrypted.amount as u128;
                found.push(decrypted);
            }
        }

        found
    }

    /// Scan a block
    #[tracing::instrument(skip(self, block), fields(height = block.height(), txs = block.transactions.len()))]
    pub fn scan_block(&mut self, block: &Block) -> Vec<DecryptedOutput> {
        let block_hash = block.hash();
        let height = block.height();

        debug!("Scanning block {} at height {}", &block_hash.to_hex()[..8], height);

        self.stats.blocks_scanned += 1;

        let mut all_found = Vec::new();

        // Scan all transactions (coinbase is first tx)
        for tx in &block.transactions {
            let found = self.scan_transaction(tx);
            all_found.extend(found);
        }

        // Update position
        self.last_height = height;
        self.last_hash = block_hash;

        if !all_found.is_empty() {
            info!(
                "Found {} outputs in block {} (height {})",
                all_found.len(),
                &block_hash.to_hex()[..8],
                height
            );
        }

        all_found
    }

    /// Scan multiple blocks (with parallel output scanning)
    pub fn scan_blocks(&mut self, blocks: &[Block]) -> Vec<DecryptedOutput> {
        let start = std::time::Instant::now();
        let mut all_found = Vec::new();

        for block in blocks {
            let found = self.scan_block(block);
            all_found.extend(found);
        }

        self.stats.scan_time_ms = start.elapsed().as_millis() as u64;

        all_found
    }

    /// Scan blocks in parallel (for catch-up sync)
    pub fn scan_blocks_parallel(&mut self, blocks: &[Block]) -> Vec<DecryptedOutput> {
        let start = std::time::Instant::now();

        // Clone keys for parallel access
        let keys = self.keys.clone();

        // Parallel scan
        let results: Vec<Vec<DecryptedOutput>> = blocks
            .par_iter()
            .map(|block| {
                let mut block_results = Vec::new();
                let _block_hash = block.hash();

                // Scan all transactions (coinbase is first tx)
                for tx in &block.transactions {
                    let tx_hash = tx.hash();
                    let is_coinbase = tx.tx_type == TxType::Coinbase;
                    for (idx, output) in tx.outputs.iter().enumerate() {
                        // SECURITY (A6-IDX-TRUNC): Skip outputs past index 255
                        if idx > 255 { break; }
                        if let Some(decrypted) = scan_output_with_keys(
                            output,
                            idx as u8,
                            tx_hash,
                            &keys,
                            is_coinbase,
                        ) {
                            block_results.push(decrypted);
                        }
                    }
                }

                block_results
            })
            .collect();

        // Flatten results and deduplicate by (tx_hash, output_index) to prevent
        // inflated balances when the same block range is processed concurrently.
        let mut seen = std::collections::HashSet::new();
        let all_found: Vec<DecryptedOutput> = results.into_iter().flatten()
            .filter(|o| seen.insert((o.tx_hash, o.output_index)))
            .collect();

        // Update stats (FIX: include transactions_scanned and outputs_scanned
        // which were previously missing from parallel path, causing stats divergence
        // between serial and parallel scanning)
        self.stats.blocks_scanned += blocks.len() as u64;
        self.stats.transactions_scanned += blocks.iter()
            .map(|b| b.transactions.len() as u64)
            .sum::<u64>();
        self.stats.outputs_scanned += blocks.iter()
            .flat_map(|b| b.transactions.iter())
            .map(|tx| tx.outputs.len().min(256) as u64)
            .sum::<u64>();
        self.stats.outputs_found += all_found.len() as u64;
        self.stats.total_amount += all_found.iter().map(|o| o.amount as u128).sum::<u128>();
        self.stats.scan_time_ms = start.elapsed().as_millis() as u64;

        // Update position to last block
        if let Some(last) = blocks.last() {
            self.last_height = last.height();
            self.last_hash = last.hash();
        }

        all_found
    }
}

impl Default for WalletScanner {
    fn default() -> Self {
        Self::new()
    }
}

/// Scan output with given keys (for parallel scanning)
fn scan_output_with_keys(
    output: &TxOutput,
    output_index: u8,
    tx_hash: Hash,
    keys: &[ScanKeys],
    is_coinbase: bool,
) -> Option<DecryptedOutput> {
    for key_set in keys {
        if is_coinbase {
            // Old-format coinbase: stealth_address == spend_public (direct match)
            if output.stealth_address == key_set.spend_public {
                let amount = if output.encrypted_amount.len() >= 8 {
                    let mut bytes = [0u8; 8];
                    bytes.copy_from_slice(&output.encrypted_amount[..8]);
                    u64::from_le_bytes(bytes)
                } else {
                    0
                };
                return Some(DecryptedOutput {
                    tx_hash,
                    output_index,
                    output: output.clone(),
                    amount,
                    blinding_factor: BlindingFactor::zero(),
                    shared_secret: [0u8; 32],
                    key_epoch: key_set.epoch,
                    subaddress_index: None, // Coinbase always to primary address
                });
            }

            // New-format coinbase: ECDH-derived unique stealth address, plaintext amount
            // No view_tag gate — matches serial scan_output path to avoid missing
            // coinbase outputs if view_tag is corrupted during serialization.
            let stealth = StealthAddress {
                public_key: output.stealth_address,
                tx_public_key: output.tx_public_key,
            };
            if is_output_ours(&stealth, &key_set.view_secret, &key_set.spend_public, output_index) {
                let amount = if output.encrypted_amount.len() >= 8 {
                    let mut bytes = [0u8; 8];
                    bytes.copy_from_slice(&output.encrypted_amount[..8]);
                    u64::from_le_bytes(bytes)
                } else {
                    0
                };
                return Some(DecryptedOutput {
                    tx_hash,
                    output_index,
                    output: output.clone(),
                    amount,
                    blinding_factor: BlindingFactor::zero(),
                    shared_secret: [0u8; 32],
                    key_epoch: key_set.epoch,
                    subaddress_index: None, // Coinbase always to primary address
                });
            }
            continue; // Not ours under this key_set
        }

        // View tag check (diagnostic only — never skip the full ownership check)
        let _expected_tag = compute_view_tag(
            &key_set.view_secret,
            &output.tx_public_key,
            output_index,
        );

        // Full ownership check on every output (view_tag is not a gate)
        let stealth = StealthAddress {
            public_key: output.stealth_address,
            tx_public_key: output.tx_public_key,
        };

        // Check primary address first
        let mut matched = is_output_ours(&stealth, &key_set.view_secret, &key_set.spend_public, output_index);
        let mut matched_subaddr: Option<(u32, u32)> = None;

        // SECURITY (BUG-6): If not primary, check all subaddress spend keys.
        // Previously the parallel scanner only checked spend_public, permanently
        // missing all outputs sent to subaddresses.
        if !matched {
            for &(account, index, ref sub_spend) in &key_set.subaddress_keys {
                if is_output_ours(&stealth, &key_set.view_secret, sub_spend, output_index) {
                    matched = true;
                    // SECURITY (C9-FIX): Preserve subaddress index for persistence
                    matched_subaddr = Some((account, index));
                    break;
                }
            }
        }

        if matched {
            let shared_secret = compute_shared_secret(
                &key_set.view_secret,
                &output.tx_public_key,
                output_index,
            );

            let (amount, blinding_factor) = decrypt_amount(
                &output.encrypted_amount,
                &shared_secret,
            );

            return Some(DecryptedOutput {
                tx_hash,
                output_index,
                output: output.clone(),
                amount,
                blinding_factor,
                shared_secret,
                key_epoch: key_set.epoch,
                subaddress_index: matched_subaddr,
            });
        }
    }

    None
}

/// Compute view tag for fast filtering
///
/// SECURITY: Uses proper ECDH (view_secret * tx_public_POINT) so that
/// sender (tx_secret * view_public) and receiver produce the same shared point.
fn compute_view_tag(view_secret: &SecretKey, tx_public: &PublicKey, output_index: u8) -> u8 {
    let view_scalar = SecretScalar::from_bytes(*view_secret.as_bytes());
    let tx_point = match PublicPoint::from_bytes(*tx_public.as_bytes()) {
        Some(p) => p,
        // SECURITY (A6-VIEWTAG): Return 0xFF as sentinel for invalid points.
        // Previously returned 0, which falsely matches 1/256 of legitimate outputs
        // with view_tag=0, triggering expensive full ownership checks.
        None => return 0xFF,
    };
    // ECDH: shared_point = view_secret * tx_public (same as sender's tx_secret * view_public)
    let shared_point = tx_point.mul(&view_scalar);

    let tag_input = [shared_point.to_bytes().as_slice(), &[output_index]].concat();
    let tag_hash = hash_domain(b"COINCYNC_VIEWTAG_v2", &tag_input);
    tag_hash.as_bytes()[0]
}

/// Compute shared secret for decryption
///
/// SECURITY: Uses proper ECDH so sender and receiver derive the same shared secret.
fn compute_shared_secret(view_secret: &SecretKey, tx_public: &PublicKey, output_index: u8) -> [u8; 32] {
    let view_scalar = SecretScalar::from_bytes(*view_secret.as_bytes());
    let tx_point = match PublicPoint::from_bytes(*tx_public.as_bytes()) {
        Some(p) => p,
        None => {
            tracing::warn!("compute_shared_secret: invalid tx_public_key, returning zeroed secret");
            return [0u8; 32];
        }
    };
    let shared_point = tx_point.mul(&view_scalar);

    let shared = hash_domain(
        b"COINCYNC_SHARED_v2",
        &[shared_point.to_bytes().as_slice(), &[output_index]].concat(),
    );
    *shared.as_bytes()
}

/// Decrypt amount and derive blinding factor
fn decrypt_amount(encrypted: &[u8], shared_secret: &[u8; 32]) -> (u64, BlindingFactor) {
    // Derive decryption key
    let decrypt_key = hash_domain(b"COINCYNC_AMOUNT_KEY", shared_secret);

    // Decrypt amount (XOR with first 8 bytes of decrypt_key)
    let mut amount_bytes = [0u8; 8];
    if encrypted.len() >= 8 {
        for i in 0..8 {
            amount_bytes[i] = encrypted[i] ^ decrypt_key.as_bytes()[i];
        }
    }
    let amount = u64::from_le_bytes(amount_bytes);

    // Derive blinding factor
    let blinding_hash = hash_domain(b"COINCYNC_BLINDING", shared_secret);
    let blinding_factor = BlindingFactor::from_bytes(*blinding_hash.as_bytes());

    (amount, blinding_factor)
}

/// Encrypt amount for sending (inverse of decrypt_amount)
pub fn encrypt_amount(amount: u64, shared_secret: &[u8; 32]) -> Vec<u8> {
    let decrypt_key = hash_domain(b"COINCYNC_AMOUNT_KEY", shared_secret);

    let amount_bytes = amount.to_le_bytes();
    let mut encrypted = Vec::with_capacity(8);

    for i in 0..8 {
        encrypted.push(amount_bytes[i] ^ decrypt_key.as_bytes()[i]);
    }

    encrypted
}

/// Generate view tag for output (sender side)
///
/// SECURITY: Uses proper ECDH (tx_secret * view_public_POINT).
pub fn generate_view_tag(
    view_public: &PublicKey,
    tx_secret: &SecretKey,
    output_index: u8,
) -> u8 {
    let tx_scalar = SecretScalar::from_bytes(*tx_secret.as_bytes());
    let view_point = match PublicPoint::from_bytes(*view_public.as_bytes()) {
        Some(p) => p,
        None => return 0xFF, // Sentinel: matches receiver side (compute_view_tag)
    };
    // ECDH: shared_point = tx_secret * view_public (same as receiver's view_secret * tx_public)
    let shared_point = view_point.mul(&tx_scalar);

    let tag_input = [shared_point.to_bytes().as_slice(), &[output_index]].concat();
    let tag_hash = hash_domain(b"COINCYNC_VIEWTAG_v2", &tag_input);
    tag_hash.as_bytes()[0]
}

/// Background scanner that persists to database
pub struct BackgroundScanner {
    scanner: WalletScanner,
    db: Arc<WalletDb>,
}

impl BackgroundScanner {
    /// Create new background scanner
    pub fn new(db: Arc<WalletDb>) -> Self {
        BackgroundScanner {
            scanner: WalletScanner::new(),
            db,
        }
    }

    /// Add keys
    pub fn add_keys(&mut self, view_secret: SecretKey, spend_public: PublicKey, epoch: u64) {
        self.scanner.add_keys(view_secret, spend_public, epoch);
    }

    /// SECURITY (C9-FIX / H19-FIX): Add subaddress keys to the scanner.
    /// Previously BackgroundScanner had no way to load subaddress keys,
    /// causing all subaddress outputs to be missed during background sync.
    pub fn add_subaddress_keys(&mut self, keys: Vec<(u32, u32, PublicKey)>) {
        self.scanner.add_subaddress_keys(keys);
    }

    /// Load state from database
    pub fn load_state(&mut self) -> Result<()> {
        let state = self.db.get_scan_state()?;
        self.scanner.set_position(state.scanned_height, state.scanned_hash);
        Ok(())
    }

    /// Save state to database
    pub fn save_state(&self) -> Result<()> {
        let (height, hash) = self.scanner.position();
        let stats = self.scanner.stats();

        let state = ScanState {
            scanned_height: height,
            scanned_hash: hash,
            outputs_found: stats.outputs_found,
            outputs_spent: 0, // Updated separately
            scan_started: 0,  // Set when scan starts
            last_scan_time: chrono::Utc::now().timestamp() as u64,
        };

        self.db.update_scan_state(&state)?;
        Ok(())
    }

    /// Scan block and persist results
    pub fn scan_and_persist(&mut self, block: &Block) -> Result<usize> {
        let height = block.height();
        let block_hash = block.hash();
        let timestamp = block.header.timestamp;

        let found = self.scanner.scan_block(block);
        let count = found.len();

        // Persist each found output
        for decrypted in found {
            let owned = OwnedOutput {
                tx_hash: decrypted.tx_hash,
                output_index: decrypted.output_index,
                output: decrypted.output.clone(),
                amount: Some(decrypted.amount),
                height,
                block_hash,
                timestamp,
                spent: false,
                spent_by: None,
                spent_at_height: None,
                // SECURITY (H19-FIX): Propagate subaddress index from scanner.
                // Previously always set to None, losing subaddress association
                // and making it impossible to track per-subaddress balances.
                // OwnedOutput stores minor index only; account is implicit.
                subaddress_index: decrypted.subaddress_index.map(|(_account, index)| index),
            };

            self.db.add_output(&owned)?;
        }

        // Update state
        self.save_state()?;

        Ok(count)
    }

    /// Get scanner position
    pub fn position(&self) -> (u64, Hash) {
        self.scanner.position()
    }

    /// Get statistics
    pub fn stats(&self) -> &ScanStats {
        self.scanner.stats()
    }
}

/// Async wallet sync service
/// Runs continuously in the background, scanning new blocks as they arrive
pub struct WalletSyncService {
    /// Background scanner
    scanner: BackgroundScanner,
    /// Channel to receive new blocks
    block_rx: tokio::sync::mpsc::Receiver<Block>,
    /// Channel to receive shutdown signal
    shutdown_rx: tokio::sync::oneshot::Receiver<()>,
    /// Last known chain tip
    chain_tip: u64,
}

impl WalletSyncService {
    /// Create a new sync service
    pub fn new(
        scanner: BackgroundScanner,
        block_rx: tokio::sync::mpsc::Receiver<Block>,
        shutdown_rx: tokio::sync::oneshot::Receiver<()>,
    ) -> Self {
        WalletSyncService {
            scanner,
            block_rx,
            shutdown_rx,
            chain_tip: 0,
        }
    }

    /// Run the sync service
    pub async fn run(mut self) -> Result<ScanStats> {
        info!("Wallet sync service starting");

        // Load saved scan position
        if let Err(e) = self.scanner.load_state() {
            tracing::warn!("Failed to load scan state: {}", e);
        }

        let (start_height, _) = self.scanner.position();
        info!("Resuming wallet scan from height {}", start_height);

        loop {
            tokio::select! {
                // Check for shutdown
                _ = &mut self.shutdown_rx => {
                    info!("Wallet sync service shutting down");
                    break;
                }

                // Process new blocks
                Some(block) = self.block_rx.recv() => {
                    let height = block.height();
                    let (scan_height, _) = self.scanner.position();

                    // Only scan if this is the next block we need
                    if height == scan_height + 1 || height == scan_height {
                        match self.scanner.scan_and_persist(&block) {
                            Ok(found) => {
                                if found > 0 {
                                    info!("Found {} outputs at height {}", found, height);
                                }
                                self.chain_tip = height;
                            }
                            Err(e) => {
                                tracing::error!("Failed to scan block {}: {}", height, e);
                            }
                        }
                    } else if height > scan_height + 1 {
                        // Gap detected - we're behind
                        debug!("Wallet scan behind: at {} but chain at {}", scan_height, height);
                    }
                }
            }
        }

        // Save final state
        if let Err(e) = self.scanner.save_state() {
            tracing::error!("Failed to save final scan state: {}", e);
        }

        Ok(self.scanner.stats().clone())
    }
}

/// Wallet sync handle for controlling the sync service
pub struct WalletSyncHandle {
    /// Channel to send blocks for scanning
    pub block_tx: tokio::sync::mpsc::Sender<Block>,
    /// Channel to trigger shutdown
    pub shutdown_tx: Option<tokio::sync::oneshot::Sender<()>>,
}

impl WalletSyncHandle {
    /// Create a new sync handle and service
    pub fn new(scanner: BackgroundScanner, buffer_size: usize) -> (Self, WalletSyncService) {
        let (block_tx, block_rx) = tokio::sync::mpsc::channel(buffer_size);
        let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel();

        let service = WalletSyncService::new(scanner, block_rx, shutdown_rx);
        let handle = WalletSyncHandle {
            block_tx,
            shutdown_tx: Some(shutdown_tx),
        };

        (handle, service)
    }

    /// Send a block for scanning
    pub async fn scan_block(&self, block: Block) -> std::result::Result<(), tokio::sync::mpsc::error::SendError<Block>> {
        self.block_tx.send(block).await
    }

    /// Shutdown the sync service
    pub fn shutdown(&mut self) {
        if let Some(tx) = self.shutdown_tx.take() {
            let _ = tx.send(());
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════
// DecryptedOutput → UTXO conversion
// ═══════════════════════════════════════════════════════════════════════

/// Build a spendable `UTXO` from a `DecryptedOutput` the scanner
/// produced for this wallet, plus the owner's spend secret.
///
/// Key image is derived the CLSAG way: `I = x * Hp(x*G)` where `x` is
/// the one-time spend secret for this output. That one-time secret is
/// the Monero-style stealth derivation:
///
/// ```text
///   one_time = H(shared_secret || output_index) + spend_secret
/// ```
///
/// Returns an error if the stealth address in the decrypted output
/// does not decompress to a valid Ristretto point (shouldn't happen
/// for outputs we scanned ourselves).
pub fn decrypted_to_utxo(
    decrypted: &DecryptedOutput,
    view_secret: &SecretKey,
    spend_secret: &SecretKey,
    height: u64,
) -> Result<crate::wallet::balance::UTXO> {
    use crate::crypto::KeyImage as CurveKeyImage;
    use crate::primitives::{Amount, KeyImage};

    // Compute the one-time spend secret for this output.
    let stealth = StealthAddress {
        public_key: decrypted.output.stealth_address,
        tx_public_key: decrypted.output.tx_public_key,
    };
    let one_time_secret = crate::crypto::compute_one_time_secret(
        &stealth,
        view_secret,
        spend_secret,
        decrypted.output_index,
    )?;

    // Derive the key image via the CLSAG formula.
    let one_time_scalar = SecretScalar::from_bytes(*one_time_secret.as_bytes());
    let key_image_curve = CurveKeyImage::from_secret(&one_time_scalar);
    let key_image_bytes: [u8; 32] = key_image_curve.to_bytes();
    let key_image = KeyImage::from_bytes(key_image_bytes);

    Ok(crate::wallet::balance::UTXO {
        tx_hash: decrypted.tx_hash,
        output_index: decrypted.output_index,
        amount: Amount::from_atomic(decrypted.amount),
        height,
        key_image,
        spent: false,
        amount_blinding_bytes: decrypted.blinding_factor.to_bytes(),
        tx_public_key: decrypted.output.tx_public_key,
        lock_height: decrypted.output.lock_height,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::NetworkType;
    // Phase A1 (audit fix): test below at line 1083 builds a Transaction
    // literal with Amount::from_atomic(0) for the fee. The bare module
    // imports were missing Amount, breaking `cargo test --lib`.
    use crate::primitives::Amount;

    #[test]
    fn test_view_tag() {
        use rand::rngs::OsRng;

        // Use proper key pairs so ECDH works with valid curve points
        let view_secret = SecretKey::generate(&mut OsRng);
        let tx_secret = SecretKey::generate(&mut OsRng);
        let tx_public = tx_secret.public_key();
        let view_public = view_secret.public_key();

        let tag1 = compute_view_tag(&view_secret, &tx_public, 0);
        let tag2 = compute_view_tag(&view_secret, &tx_public, 1);

        // Different output indices should give different tags (with high probability)
        // Not guaranteed for all key pairs, but extremely likely
        assert_ne!(tag1, tag2);

        // Same inputs should give same tag
        let tag3 = compute_view_tag(&view_secret, &tx_public, 0);
        assert_eq!(tag1, tag3);

        // Sender and receiver tags must match (ECDH correctness)
        let sender_tag = generate_view_tag(&view_public, &tx_secret, 0);
        assert_eq!(tag1, sender_tag, "ECDH mismatch: sender and receiver view tags differ");
    }

    #[test]
    fn test_amount_encryption() {
        let shared_secret = [42u8; 32];
        let amount = 1_000_000_000u64;

        let encrypted = encrypt_amount(amount, &shared_secret);
        let (decrypted, _) = decrypt_amount(&encrypted, &shared_secret);

        assert_eq!(amount, decrypted);
    }

    #[test]
    fn test_scanner_creation() {
        let mut scanner = WalletScanner::new();
        let view_secret = SecretKey::from_bytes([1u8; 32]);
        let spend_public = PublicKey::from_bytes([2u8; 32]);

        scanner.add_keys(view_secret, spend_public, 0);

        assert_eq!(scanner.keys.len(), 1);
        assert_eq!(scanner.position(), (0, Hash::zero()));
    }

    /// Full roundtrip test: generate stealth address (sender side), build a TxOutput,
    /// then verify the scanner detects and decrypts it (receiver side).
    #[test]
    fn test_scanner_stealth_roundtrip() {
        use rand::rngs::OsRng;
        use crate::crypto::generate_stealth_address_checked;
        use crate::primitives::Amount;

        // Generate recipient keypair (Bob)
        let bob_view_secret = SecretKey::generate(&mut OsRng);
        let _bob_spend_secret = SecretKey::generate(&mut OsRng);
        let bob_view_public = bob_view_secret.public_key();
        let bob_spend_public = _bob_spend_secret.public_key();

        let output_index: u8 = 0;
        let send_amount: u64 = 25_000_000_000; // 25 CYNC

        // Sender generates stealth address for Bob
        let (stealth, tx_secret) = generate_stealth_address_checked(
            &bob_spend_public,
            &bob_view_public,
            output_index,
            &mut OsRng,
        ).expect("stealth address generation");

        // Sender computes shared secret for amount encryption
        let tx_scalar = SecretScalar::from_bytes(*tx_secret.as_bytes());
        let view_point = PublicPoint::from_bytes(*bob_view_public.as_bytes()).unwrap();
        let shared_point = view_point.mul(&tx_scalar);
        let shared_secret_hash = hash_domain(
            b"COINCYNC_SHARED_v2",
            &[shared_point.to_bytes().as_slice(), &[output_index]].concat(),
        );
        let sender_shared_secret: [u8; 32] = *shared_secret_hash.as_bytes();

        // Sender encrypts amount
        let encrypted_amount = encrypt_amount(send_amount, &sender_shared_secret);

        // Sender computes view tag
        let view_tag = generate_view_tag(&bob_view_public, &tx_secret, output_index);

        // Build a TxOutput as the sender would
        let tx_output = TxOutput {
            stealth_address: stealth.public_key,
            tx_public_key: stealth.tx_public_key,
            commitment: [0u8; 32], // simplified for test
            encrypted_amount,
            view_tag,
            lock_height: None,
            encrypted_memo: vec![],
        };

        // Build a non-coinbase transaction containing this output
        let tx = Transaction {
            version: 1,
            tx_type: TxType::Transfer,
            inputs: vec![],  // Simplified for scanner test
            outputs: vec![tx_output],
            fee: Amount::from_atomic(0),
            range_proof: vec![],
            extra: vec![],
        };
        let tx_hash = tx.hash();

        // Bob's scanner should detect this output
        let mut scanner = WalletScanner::new();
        scanner.add_keys(bob_view_secret.clone(), bob_spend_public, 0);

        let found = scanner.scan_transaction(&tx);
        assert_eq!(found.len(), 1, "Scanner should detect exactly 1 output for Bob");

        let decrypted = &found[0];
        assert_eq!(decrypted.tx_hash, tx_hash);
        assert_eq!(decrypted.output_index, 0);
        assert_eq!(decrypted.amount, send_amount, "Decrypted amount should match sent amount");

        // An unrelated wallet should NOT detect this output
        let other_view_secret = SecretKey::generate(&mut OsRng);
        let other_spend_public = SecretKey::generate(&mut OsRng).public_key();
        let mut other_scanner = WalletScanner::new();
        other_scanner.add_keys(other_view_secret, other_spend_public, 0);
        let other_found = other_scanner.scan_transaction(&tx);
        assert_eq!(other_found.len(), 0, "Unrelated wallet should not detect this output");
    }

    #[test]
    fn test_subaddress_detection_coverage() {
        use rand::rngs::OsRng;
        use crate::crypto::generate_stealth_address_checked;
        use crate::wallet::subaddress::{SubaddressManager, SubaddressIndex};

        // Generate wallet keys
        let view_secret = SecretKey::generate(&mut OsRng);
        let spend_secret = SecretKey::generate(&mut OsRng);
        let view_public = view_secret.public_key();
        let spend_public = spend_secret.public_key();

        // Create subaddress manager and generate subaddresses
        let view_sk = crate::primitives::SecretKey::from_bytes(*view_secret.as_bytes());
        let spend_pk = PublicKey::from_bytes(*spend_public.as_bytes());
        let view_pk = PublicKey::from_bytes(*view_public.as_bytes());
        let mut mgr = SubaddressManager::new(view_sk, spend_pk, view_pk);
        // Phase A6 (audit fix): generate_at returns Option<&Subaddress>, a borrow
        // of `&mut self`. Two consecutive calls would overlap mutable borrows,
        // so each result is converted to owned bytes before the next call.
        // Same pattern as the drive-by fix in src/wallet/subaddress.rs.
        let sub1_spend_bytes: [u8; 32] = *mgr
            .generate_at(SubaddressIndex::new(0, 1))
            .unwrap()
            .spend_public
            .as_bytes();
        let sub2_spend_bytes: [u8; 32] = *mgr
            .generate_at(SubaddressIndex::new(0, 2))
            .unwrap()
            .spend_public
            .as_bytes();
        let sub1_spend_public = PublicKey::from_bytes(sub1_spend_bytes);
        let sub2_spend_public = PublicKey::from_bytes(sub2_spend_bytes);

        // Build tx to subaddress index (0,2)
        let sub2_spend = PublicKey::from_bytes(*sub2_spend_public.as_bytes());
        let (stealth, tx_secret) = generate_stealth_address_checked(
            &sub2_spend, &view_public, 0, &mut OsRng,
        ).unwrap();

        let tx_scalar = SecretScalar::from_bytes(*tx_secret.as_bytes());
        let view_point = PublicPoint::from_bytes(*view_public.as_bytes()).unwrap();
        let shared_point = view_point.mul(&tx_scalar);
        let shared_hash = hash_domain(
            b"COINCYNC_SHARED_v2",
            &[shared_point.to_bytes().as_slice(), &[0u8]].concat(),
        );
        let sender_shared: [u8; 32] = *shared_hash.as_bytes();
        let encrypted_amount = encrypt_amount(5_000_000_000, &sender_shared);
        let view_tag = generate_view_tag(&view_public, &tx_secret, 0);

        let tx = Transaction {
            version: 1, tx_type: TxType::Transfer, inputs: vec![],
            outputs: vec![TxOutput {
                stealth_address: stealth.public_key,
                tx_public_key: stealth.tx_public_key,
                commitment: [0u8; 32], encrypted_amount, view_tag,
                                                lock_height: None, encrypted_memo: vec![],
            }],
            fee: Amount::from_atomic(0), range_proof: vec![], extra: vec![],
        };

        // Scanner with subaddress keys should detect the output
        let mut scanner = WalletScanner::new();
        scanner.add_keys(view_secret, spend_public, 0);
        scanner.add_subaddress_keys(vec![
            (0, 1, sub1_spend_public),
            (0, 2, sub2_spend_public),
        ]);
        let found = scanner.scan_transaction(&tx);
        assert_eq!(found.len(), 1, "Scanner should detect output sent to subaddress (0,2)");
    }

    /// Test scanning a block with both coinbase and regular transactions
    #[test]
    fn test_scanner_block_with_transfer() {
        use rand::rngs::OsRng;
        use crate::crypto::generate_stealth_address_checked;
        use crate::primitives::Amount;

        // Miner keys (Alice)
        let alice_spend_secret = SecretKey::generate(&mut OsRng);
        let alice_spend_public = alice_spend_secret.public_key();

        // Recipient keys (Bob)
        let bob_view_secret = SecretKey::generate(&mut OsRng);
        let _bob_spend_secret = SecretKey::generate(&mut OsRng);
        let bob_view_public = bob_view_secret.public_key();
        let bob_spend_public = _bob_spend_secret.public_key();

        // Create a non-coinbase transfer to Bob (output index 0)
        let output_index: u8 = 0;
        let send_amount: u64 = 10_000_000_000;

        let (stealth, tx_secret) = generate_stealth_address_checked(
            &bob_spend_public,
            &bob_view_public,
            output_index,
            &mut OsRng,
        ).unwrap();

        let tx_scalar = SecretScalar::from_bytes(*tx_secret.as_bytes());
        let view_point = PublicPoint::from_bytes(*bob_view_public.as_bytes()).unwrap();
        let shared_point = view_point.mul(&tx_scalar);
        let shared_secret_hash = hash_domain(
            b"COINCYNC_SHARED_v2",
            &[shared_point.to_bytes().as_slice(), &[output_index]].concat(),
        );
        let sender_shared_secret: [u8; 32] = *shared_secret_hash.as_bytes();
        let encrypted_amount = encrypt_amount(send_amount, &sender_shared_secret);
        let view_tag = generate_view_tag(&bob_view_public, &tx_secret, output_index);

        let transfer_tx = Transaction {
            version: 1,
            tx_type: TxType::Transfer,
            inputs: vec![],
            outputs: vec![TxOutput {
                stealth_address: stealth.public_key,
                tx_public_key: stealth.tx_public_key,
                commitment: [0u8; 32],
                encrypted_amount,
                view_tag,
                lock_height: None,
                encrypted_memo: vec![],
            }],
            fee: Amount::from_atomic(0),
            range_proof: vec![],
            extra: vec![],
        };

        // Create a coinbase tx for Alice (old-format: stealth_address = spend_public)
        let coinbase_tx = Transaction {
            version: 1,
            tx_type: TxType::Coinbase,
            inputs: vec![],
            outputs: vec![TxOutput {
                stealth_address: alice_spend_public,
                tx_public_key: PublicKey::from_bytes([0u8; 32]),
                commitment: [0u8; 32],
                encrypted_amount: 50_000_000_000u64.to_le_bytes().to_vec(),
                view_tag: 0,
                lock_height: None,
                encrypted_memo: vec![],
            }],
            fee: Amount::from_atomic(0),
            range_proof: vec![],
            extra: vec![],
        };

        // Build block with both transactions
        let block = Block {
            header: crate::consensus::BlockHeader {
                network_magic: NetworkType::Testnet.magic_bytes(),
                version: 1,
                height: 10,
                timestamp: 1000,
                prev_hash: Hash::zero(),
                tx_root: Hash::zero(),
                anchor: Hash::zero(),
                algorithm: 0,
                nonce: 0,
                target: Hash::from_bytes([0xFFu8; 32]),
                miner_pubkey: alice_spend_public,
                supply_commitment: [0u8; 32],
                checkpoint_vote: None,
                spark_set_root: [0u8; 32],
                mw_kernel_root: [0u8; 32],
            },
            transactions: vec![coinbase_tx, transfer_tx],
        };

        // Bob's scanner should find the transfer output
        let mut bob_scanner = WalletScanner::new();
        bob_scanner.add_keys(bob_view_secret, bob_spend_public, 0);
        let bob_found = bob_scanner.scan_block(&block);
        assert_eq!(bob_found.len(), 1, "Bob should find 1 output (the transfer)");
        assert_eq!(bob_found[0].amount, send_amount);
    }
}
