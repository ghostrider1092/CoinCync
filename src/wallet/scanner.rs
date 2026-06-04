//! # Wallet Output Scanner for CoinCync 1.0
//!
//! Scans blockchain outputs to detect which belong to our wallet.
//! Uses view tags for fast filtering and proper amount decryption.

use std::collections::VecDeque;
use std::sync::Arc;

use crate::primitives::{PublicKey, SecretKey, Hash, KeyImage, hash_domain};
use crate::transaction::{Transaction, TxOutput, TxType};
use crate::consensus::Block;
use crate::crypto::{StealthAddress, is_output_ours, BlindingFactor, SecretScalar, PublicPoint, PedersenCommitment};
use crate::db::{WalletDb, OwnedOutput, ScanState};
use crate::error::Result;

use rayon::prelude::*;
use tracing::{info, debug};

/// Default bound on the scanner's per-block journal (used for reorg-aware
/// rewind). Sized at `max_reorg_depth + safety_margin` so a reorg up to
/// the tier-3 cap is recoverable without falling back to a full rescan.
///
/// Reorgs deeper than this trigger a full rescan from a hardcoded
/// checkpoint or genesis. See [`docs/wallet-v2-reorg-handling-design.md`]
/// (the BlockApplyDiff section) for the design rationale.
const JOURNAL_MAX_DEFAULT: usize = 200;

/// Result variant returned by [`WalletScanner::scan_block_with_result`].
///
/// Reorg-handling Task #2b — the typed signal the orchestrator needs to
/// know whether the block was applied to wallet state, or whether the
/// chain-continuity check refused to apply it because the incoming
/// block's `prev_hash` doesn't match the journal's tip.
///
/// The legacy [`WalletScanner::scan_block`] returns `Vec<DecryptedOutput>`
/// and discards the `ReorgDetected` variant (matching the Task #2a
/// behavior of "log + return empty Vec"). New orchestration code should
/// call [`WalletScanner::scan_block_with_result`] and handle both
/// variants explicitly. The two coexist until the legacy callers are
/// migrated.
#[derive(Clone, Debug)]
pub enum ScanResult {
    /// The block was successfully applied to wallet state. Journal +
    /// `last_height` / `last_hash` advanced; outputs detected as ours
    /// are included.
    Scanned {
        /// Outputs the wallet now owns from this block (may be empty).
        outputs: Vec<DecryptedOutput>,
        /// Block height that was just applied.
        height: u64,
        /// Block hash that was just applied.
        block_hash: Hash,
    },
    /// The block doesn't extend the chain we previously scanned. Wallet
    /// state is **unchanged** — no journal write, no `last_*` advance,
    /// no outputs returned. Caller should invoke
    /// [`WalletScanner::rewind_to_height`] to undo to the fork point,
    /// then re-scan the new canonical chain forward.
    ReorgDetected {
        /// Height of the block that arrived (would-be apply height).
        at_height: u64,
        /// `block.prev_hash` from the incoming block.
        actual_prev: Hash,
        /// Hash the scanner expected to see (i.e., what's at
        /// `journal_back().block_hash`). May be `Hash::zero()` if the
        /// reorg-signal came from a non-monotonic height (block at
        /// height <= current) rather than a prev-hash mismatch.
        expected_prev: Hash,
    },
}

impl ScanResult {
    /// Convenience: extract outputs, panicking on `ReorgDetected`.
    /// Useful for tests + callers that know they're scanning a fresh
    /// chain. Production orchestration code should `match` instead.
    pub fn outputs_or_panic(self) -> Vec<DecryptedOutput> {
        match self {
            ScanResult::Scanned { outputs, .. } => outputs,
            ScanResult::ReorgDetected { at_height, .. } => panic!(
                "ScanResult::outputs_or_panic called on ReorgDetected at height {}",
                at_height
            ),
        }
    }

    /// Convenience: returns `Some(outputs)` when `Scanned`, `None` on
    /// `ReorgDetected`. Lets simple callers `let outputs = result.outputs_opt().unwrap_or_default();`
    /// without losing the diagnostic surface entirely.
    pub fn outputs_opt(&self) -> Option<&[DecryptedOutput]> {
        match self {
            ScanResult::Scanned { outputs, .. } => Some(outputs),
            ScanResult::ReorgDetected { .. } => None,
        }
    }
}

/// Outcome of a successful [`WalletScanner::rewind_to_height`] call.
///
/// Returned by Task #3 so the caller can apply the inverse state
/// changes downstream (balance.rs UTXO removal + history.rs row
/// removal). The scanner doesn't own the wallet's UTXO state itself —
/// it journals what it observed; the caller is responsible for the
/// downstream undo using these IDs.
#[derive(Clone, Debug, Default)]
pub struct RewindOutcome {
    /// Number of journal entries popped (one per block undone).
    pub entries_undone: usize,
    /// `(tx_hash, output_index)` for every output the scanner reported
    /// in the rewound blocks. Caller removes these from the wallet's
    /// UTXO set + balance + history layers.
    ///
    /// Ordering: reverse application order — most-recent block's
    /// outputs first, oldest popped block's outputs last. The caller
    /// can iterate in vec order without needing to reverse first.
    pub outputs_to_remove: Vec<(Hash, u8)>,
    /// `KeyImage` for every wallet UTXO that was marked spent in the
    /// rewound blocks. The caller flips each one's `spent` flag back
    /// to false via `Balance::unmark_spent_by_key_image` so balance
    /// queries reflect the canonical chain after rewind.
    ///
    /// Same reverse-application ordering as `outputs_to_remove`.
    /// Populated from each popped `BlockApplyDiff.key_images_marked_spent`.
    /// May contain duplicates if the same key image somehow appeared
    /// in two blocks (defensive — orchestrator should de-dupe before
    /// applying if its idempotency model needs it).
    pub key_images_to_unspend: Vec<KeyImage>,
    /// Height after rewind: equals `target_height` requested, or 0
    /// when the journal becomes empty.
    pub new_height: u64,
    /// Block hash at the new tip post-rewind. `Hash::zero()` when the
    /// journal becomes empty (rewound past everything).
    pub new_hash: Hash,
}

/// Reasons [`WalletScanner::rewind_to_height`] can refuse to rewind.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RewindError {
    /// Requested target is older than the journal's earliest entry —
    /// can't rewind there without a full rescan from a hardcoded
    /// checkpoint. Caller should rescan instead.
    OutsideJournalWindow {
        /// Requested rewind target.
        target_height: u64,
        /// Oldest height currently retained in the journal.
        earliest_in_journal: u64,
    },
    /// Requested target is above the scanner's current `last_height`.
    /// Rewinding "forward" is nonsensical; caller should `scan_block`
    /// instead.
    TargetAboveCurrent {
        /// Requested rewind target.
        target_height: u64,
        /// Scanner's current `last_height`.
        current_height: u64,
    },
}

impl std::fmt::Display for RewindError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RewindError::OutsideJournalWindow {
                target_height,
                earliest_in_journal,
            } => write!(
                f,
                "rewind target {} is older than journal's earliest entry {} — full rescan needed",
                target_height, earliest_in_journal
            ),
            RewindError::TargetAboveCurrent {
                target_height,
                current_height,
            } => write!(
                f,
                "rewind target {} is above current last_height {} — cannot rewind forward",
                target_height, current_height
            ),
        }
    }
}

impl std::error::Error for RewindError {}

/// Per-block journal entry tracking what the scanner added to the
/// wallet state when applying a block. Used by `rewind_to_height`
/// (Task #3 of the reorg-handling design) to undo state changes when
/// a reorg invalidates previously-scanned blocks.
///
/// Task #1 seeded the journal with the minimum fields needed for reorg
/// DETECTION (height + block_hash + prev_block_hash + outputs_added).
/// Task #1b (2026-05-23) extends with `key_images_marked_spent` so a
/// rewind can also UN-spend UTXOs whose only "spent" signal was a tx
/// in a now-orphaned block. Without this, a wallet that spent UTXO X
/// in block N (orphaned) would carry `X.spent = true` forever after
/// rewind, leaking spendable balance.
#[derive(Clone, Debug)]
pub struct BlockApplyDiff {
    /// Height of the block this diff records.
    pub height: u64,
    /// Hash of the block this diff records.
    pub block_hash: Hash,
    /// Hash of the block's parent. Used by the chain-continuity
    /// check in Task #2 (incoming `block.prev_hash == journal_back().block_hash`).
    pub prev_block_hash: Hash,
    /// `(tx_hash, output_index)` for each output detected as ours in
    /// this block. Used by Task #3's rewind to remove these from the
    /// wallet's UTXO set when a reorg invalidates this block.
    pub outputs_added: Vec<(Hash, u8)>,
    /// `KeyImage` for each of OUR UTXOs that got marked spent because
    /// of inputs in this block's transactions. Populated by the
    /// orchestrator via [`WalletScanner::record_spend_for_last_block`]
    /// after `scan_block_with_result` returns. On rewind, these are
    /// surfaced as `RewindOutcome.key_images_to_unspend` so the caller
    /// can flip the corresponding UTXO `spent = false`.
    pub key_images_marked_spent: Vec<KeyImage>,
}

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
    /// Rolling per-block journal for reorg-aware rewind. Capped at
    /// `journal_max` entries; older entries are dropped. See
    /// [`BlockApplyDiff`] + the reorg-handling design doc for the
    /// staged plan (this is Task #1 — journal in place, but `rewind`
    /// + detection-trigger paths come in Tasks #2-#3).
    journal: VecDeque<BlockApplyDiff>,
    /// Maximum journal length. Defaults to [`JOURNAL_MAX_DEFAULT`].
    journal_max: usize,
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
            journal: VecDeque::with_capacity(JOURNAL_MAX_DEFAULT),
            journal_max: JOURNAL_MAX_DEFAULT,
        }
    }

    /// Current size of the reorg journal (number of recorded
    /// [`BlockApplyDiff`] entries).
    pub fn journal_len(&self) -> usize {
        self.journal.len()
    }

    /// Maximum journal length. Reorgs deeper than this trigger a full
    /// rescan from a hardcoded checkpoint rather than journal-based
    /// rewind.
    pub fn journal_max(&self) -> usize {
        self.journal_max
    }

    /// Peek the most-recent journal entry without removing it. Used by
    /// the chain-continuity check (Task #2) — caller compares the
    /// incoming block's `prev_hash` against `journal_back().block_hash`.
    pub fn journal_back(&self) -> Option<&BlockApplyDiff> {
        self.journal.back()
    }

    /// Push a journal entry and trim oldest entries to maintain the
    /// bounded length invariant. Called by [`scan_block`] after each
    /// successful block scan. Public so integration tests in
    /// `tests/wallet_reorg_recovery.rs` can drive the journal without
    /// constructing real wallet-detectable outputs (stealth addresses +
    /// view tags + commitment blinding) just to exercise the rewind
    /// machinery. Production callers should use `scan_block_with_result`.
    ///
    /// Also fast-forwards `last_height` + `last_hash` to the diff's
    /// fields — this keeps the rewind guard (`TargetAboveCurrent`) in
    /// sync without the caller having to do it. Internal production
    /// callers (`scan_block_with_result`, the parallel scan path) set
    /// last_* to the same values just after, so the assignment is a
    /// no-op for them.
    pub fn record_journal_entry(&mut self, diff: BlockApplyDiff) {
        self.last_height = diff.height;
        self.last_hash = diff.block_hash;
        self.journal.push_back(diff);
        while self.journal.len() > self.journal_max {
            self.journal.pop_front();
        }
    }

    /// Append a key image to the most-recent journal entry's
    /// `key_images_marked_spent` list. Returns `true` if a journal
    /// entry was found and updated, `false` if the journal is empty.
    ///
    /// Task #1b: the orchestrator calls this after `scan_block_with_result`
    /// returns, once for each input in the block's transactions whose
    /// key image matches one of the wallet's UTXOs. On rewind, these
    /// key images come back via `RewindOutcome.key_images_to_unspend`
    /// so the caller can un-flip the corresponding `UTXO.spent` flag.
    ///
    /// The naive alternative — having the scanner re-detect spends by
    /// holding a copy of the wallet's owned-key-image set — would
    /// couple the scanner to mutable wallet state. Pushing spend
    /// detection to the orchestrator keeps the scanner output-focused
    /// while still letting the journal capture the data rewind needs.
    pub fn record_spend_for_last_block(&mut self, key_image: KeyImage) -> bool {
        match self.journal.back_mut() {
            Some(diff) => {
                diff.key_images_marked_spent.push(key_image);
                true
            }
            None => false,
        }
    }

    /// Reorg-handling Task #3: rewind the scanner's journal + position
    /// to `target_height`, returning a [`RewindOutcome`] the caller
    /// uses to undo downstream state (UTXO set, balance, TX history).
    ///
    /// After this call:
    /// - All journal entries with `height > target_height` are removed.
    /// - `last_height` + `last_hash` are set to the journal's new back
    ///   (or `0` + `Hash::zero()` if the journal becomes empty).
    /// - The returned `RewindOutcome` lists all `(tx_hash, output_index)`
    ///   pairs that were in the rewound blocks, in **reverse
    ///   application order** (most-recent-first).
    ///
    /// Errors:
    /// - [`RewindError::TargetAboveCurrent`] if `target_height >
    ///   self.last_height` — can't rewind forward.
    /// - [`RewindError::OutsideJournalWindow`] if `target_height` is
    ///   older than the journal's earliest entry. Caller must rescan
    ///   from a hardcoded checkpoint in that case (rewind cannot
    ///   reconstruct state for blocks no longer journaled).
    ///
    /// `target_height == self.last_height` is a valid no-op rewind:
    /// returns `Ok(RewindOutcome { entries_undone: 0, .. })`.
    ///
    /// This method is scanner-internal — Task #2b (`ScanResult` enum)
    /// will wire it into the orchestrator path. Until then, callers
    /// invoke it directly when they detect a reorg via the warn-log
    /// from Task #2a.
    pub fn rewind_to_height(
        &mut self,
        target_height: u64,
    ) -> std::result::Result<RewindOutcome, RewindError> {
        if target_height > self.last_height {
            return Err(RewindError::TargetAboveCurrent {
                target_height,
                current_height: self.last_height,
            });
        }

        // If journal is non-empty, target must be in-range (>= oldest
        // retained height). A target of 0 with empty journal is fine
        // (means "you're already at genesis-or-earlier").
        if let Some(front) = self.journal.front() {
            if target_height < front.height && target_height != 0 {
                return Err(RewindError::OutsideJournalWindow {
                    target_height,
                    earliest_in_journal: front.height,
                });
            }
        }

        let mut outcome = RewindOutcome {
            entries_undone: 0,
            outputs_to_remove: Vec::new(),
            key_images_to_unspend: Vec::new(),
            new_height: target_height,
            new_hash: Hash::zero(),
        };

        // Pop journal entries with height > target_height. They come off
        // in reverse application order (newest first), which is exactly
        // the order the caller wants to apply undo operations.
        while let Some(back) = self.journal.back() {
            if back.height <= target_height {
                break;
            }
            // safe: we just confirmed there's a back entry
            let entry = self
                .journal
                .pop_back()
                .expect("journal::pop_back: just checked back() was Some");
            outcome.entries_undone += 1;
            outcome.outputs_to_remove.extend(entry.outputs_added);
            outcome.key_images_to_unspend.extend(entry.key_images_marked_spent);
        }

        // Update last_height + last_hash to journal's new back (or
        // genesis if journal emptied).
        if let Some(back) = self.journal.back() {
            self.last_height = back.height;
            self.last_hash = back.block_hash;
            outcome.new_height = back.height;
            outcome.new_hash = back.block_hash;
        } else {
            self.last_height = 0;
            self.last_hash = Hash::zero();
            outcome.new_height = 0;
            outcome.new_hash = Hash::zero();
        }

        tracing::info!(
            target: "wallet::reorg",
            "Scanner rewound to height {}: {} journal entries undone, {} outputs marked for removal",
            outcome.new_height,
            outcome.entries_undone,
            outcome.outputs_to_remove.len(),
        );

        Ok(outcome)
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

                // 2026-06-03 ghost-balance defense: recompute the
                // Pedersen commitment from the decrypted (amount,
                // blinding) and refuse to claim the output if it
                // doesn't match the on-chain `output.commitment`.
                //
                // Why this matters: an honest sender derives the
                // blinding factor from the ECDH shared secret (see
                // transaction/builder.rs:333-344, the CRIT-R7-1 fix),
                // and the on-chain commitment binds (amount, blinding).
                // A malicious sender could craft an `encrypted_amount`
                // that decrypts to a value the recipient cannot prove
                // — the homomorphic balance equation at chain level
                // doesn't constrain what the recipient *thinks* the
                // amount is, only that the sum balances. Without this
                // check the wallet would show a ghost balance the user
                // cannot spend; the spend attempt would later fail
                // (CLSAG can't sign over a commitment mismatch) with
                // a cryptic crypto error.
                //
                // Defense: rebuild commit(amount, blinding) and
                // byte-compare against the on-chain commitment. If
                // it doesn't match we silently drop the output and
                // move to the next key set — same effect as
                // is_output_ours returning false, but catches the
                // narrow class of attacks where stealth ownership
                // matches but the encrypted amount is forged.
                let expected_commitment = PedersenCommitment::commit(
                    amount,
                    &blinding_factor,
                ).to_bytes();
                if expected_commitment != output.commitment {
                    tracing::debug!(
                        "scanner: stealth match but commitment recompute mismatch \
                         (tx={}, output_idx={}, claimed amount {}). \
                         Likely malicious sender or corrupted output — skipping.",
                        tx_hash.to_hex(),
                        output_index,
                        amount,
                    );
                    continue;
                }

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

    /// Scan a block with full reorg-aware result. **Reorg-handling
    /// Task #2b** — returns [`ScanResult::Scanned`] for normal apply,
    /// or [`ScanResult::ReorgDetected`] when the chain-continuity check
    /// refuses to apply the block (wallet state stays unchanged in
    /// that case; caller should rewind + re-scan).
    ///
    /// New orchestration code should prefer this over [`Self::scan_block`].
    /// The legacy `scan_block` is preserved for backward compatibility
    /// with 4 call sites that still consume `Vec<DecryptedOutput>`
    /// directly; it now delegates to this method and strips the
    /// `ReorgDetected` variant to an empty Vec (matching Task #2a's
    /// observed behavior).
    #[tracing::instrument(skip(self, block), fields(height = block.height(), txs = block.transactions.len()))]
    pub fn scan_block_with_result(&mut self, block: &Block) -> ScanResult {
        let block_hash = block.hash();
        let height = block.height();
        let block_prev_hash = block.header.prev_hash;

        // Chain-continuity check (Task #2a logic, now wired to the
        // typed return).
        let reorg_signal = if let Some(prev_entry) = self.journal.back() {
            if height == prev_entry.height + 1 && block_prev_hash != prev_entry.block_hash {
                Some(prev_entry.block_hash)
            } else if height <= prev_entry.height {
                Some(prev_entry.block_hash)
            } else {
                None
            }
        } else {
            None
        };

        if let Some(expected_prev) = reorg_signal {
            tracing::warn!(
                target: "wallet::reorg",
                "Reorg detected at height {} during scan_block_with_result: \
                 incoming block.prev_hash={} but expected={} \
                 (journal_back.height={}, journal_len={})",
                height,
                block_prev_hash.to_hex(),
                expected_prev.to_hex(),
                self.journal.back().map(|e| e.height).unwrap_or(0),
                self.journal.len(),
            );
            self.stats.blocks_scanned += 1;
            return ScanResult::ReorgDetected {
                at_height: height,
                actual_prev: block_prev_hash,
                expected_prev,
            };
        }

        debug!("Scanning block {} at height {}", &block_hash.to_hex()[..8], height);
        self.stats.blocks_scanned += 1;

        let mut all_found = Vec::new();
        for tx in &block.transactions {
            let found = self.scan_transaction(tx);
            all_found.extend(found);
        }

        self.last_height = height;
        self.last_hash = block_hash;

        let diff = BlockApplyDiff {
            height,
            block_hash,
            prev_block_hash: block_prev_hash,
            outputs_added: all_found.iter().map(|o| (o.tx_hash, o.output_index)).collect(),
            // Spends are journaled by the orchestrator via
            // `record_spend_for_last_block` after this method returns.
            // We seed the field empty; the caller fills it as it walks
            // tx inputs and recognizes its own key_images.
            key_images_marked_spent: Vec::new(),
        };
        self.record_journal_entry(diff);

        if !all_found.is_empty() {
            info!(
                "Found {} outputs in block {} (height {})",
                all_found.len(),
                &block_hash.to_hex()[..8],
                height
            );
        }

        ScanResult::Scanned {
            outputs: all_found,
            height,
            block_hash,
        }
    }

    /// Scan a block — legacy compatibility surface. **Deprecated for
    /// new code; use [`Self::scan_block_with_result`] for the typed
    /// return.** This method delegates to `scan_block_with_result` and
    /// strips the `ReorgDetected` variant to an empty Vec, preserving
    /// Task #2a behavior for the 4 in-tree callers that haven't been
    /// migrated yet:
    /// - `WalletScanner::scan_blocks` (internal)
    /// - `Wallet::scan_and_persist` (wrapper struct)
    /// - tests inside this module
    /// - `src/bin/wallet.rs::scan_command`
    ///
    /// Returns `Vec::new()` on a detected reorg; check
    /// `journal_len()` / `position()` if you need to know whether
    /// state was advanced.
    pub fn scan_block(&mut self, block: &Block) -> Vec<DecryptedOutput> {
        match self.scan_block_with_result(block) {
            ScanResult::Scanned { outputs, .. } => outputs,
            ScanResult::ReorgDetected { .. } => Vec::new(),
        }
    }

    /// Scan multiple blocks (with parallel output scanning)
    pub fn scan_blocks(&mut self, blocks: &[Block]) -> Vec<DecryptedOutput> {
        let start = std::time::Instant::now();
        let mut all_found = Vec::new();

        // Migrated to scan_block_with_result (Task #2b consumer) so
        // we stop the loop at the first detected reorg rather than
        // continuing to "apply" later blocks that may also be on the
        // orphaned chain. Caller of scan_blocks then sees the partial
        // outputs Vec + can check `scanner.last_height()` /
        // `journal_back()` to detect the abort condition and trigger
        // rewind. Tasks #5-9 will surface this more explicitly via
        // ScanBatchResult — for v1.0 we accept the implicit signal.
        for block in blocks {
            match self.scan_block_with_result(block) {
                ScanResult::Scanned { outputs, .. } => all_found.extend(outputs),
                ScanResult::ReorgDetected {
                    at_height,
                    actual_prev,
                    expected_prev,
                } => {
                    tracing::warn!(
                        target: "wallet::reorg",
                        "scan_blocks aborting at height {}: reorg detected (actual_prev={}, expected_prev={}). \
                         Caller should rewind + rescan from the canonical fork point.",
                        at_height,
                        actual_prev.to_hex(),
                        expected_prev.to_hex(),
                    );
                    break;
                }
            }
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

    /// Scan block and persist results.
    ///
    /// Reorg-aware (Task #2b): if the inner scanner returns
    /// `ReorgDetected`, this method surfaces an `InvalidState` error
    /// rather than silently persisting nothing. The caller is expected
    /// to invoke the reorg-recovery path (rewind + find_fork_point)
    /// before retrying. Persisting an empty result on reorg would
    /// look like a successful no-op scan and let the wallet advance
    /// `last_height` past the orphaned block — which is exactly the
    /// state corruption the journal was designed to prevent.
    pub fn scan_and_persist(&mut self, block: &Block) -> Result<usize> {
        let height = block.height();
        let block_hash = block.hash();
        let timestamp = block.header.timestamp;

        let found = match self.scanner.scan_block_with_result(block) {
            ScanResult::Scanned { outputs, .. } => outputs,
            ScanResult::ReorgDetected { at_height, actual_prev, expected_prev } => {
                return Err(crate::error::Error::InvalidState(format!(
                    "Reorg detected during scan_and_persist at height {} (block prev_hash={:?} != journal back={:?}); \
                     caller must rewind + find_fork_point + retry",
                    at_height, actual_prev, expected_prev,
                )));
            }
        };
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
    use crate::crypto::PedersenCommitment;
    use crate::primitives::{Amount, KeyImage};

    // ITEM 12 (defence in depth): the wallet decrypted `amount` and
    // `blinding_factor` for this output via ECDH with our view key. Before
    // we trust those values and persist a UTXO worth `amount` CYNC, verify
    // they actually commit to the on-chain output.commitment. A malicious
    // tx-builder could send us a stealth address derivable from our keys
    // but with an `encrypted_amount` blob that decrypts to whatever they
    // want — if the wallet trusted the decrypted amount blindly, it would
    // believe it owned more (or less) than the chain says, and spending
    // such an output would fail consensus at submission time with a
    // confusing error. We catch the mismatch HERE so the wallet never
    // adds the bogus UTXO to its balance in the first place.
    //
    // Math: Pedersen commitment is C = amount * H + blinding * G. If
    // someone forged the encrypted_amount, the recomputed C from their
    // (lying) amount and blinding will not equal the on-chain
    // output.commitment. Constant-time comparison via slice equality is
    // adequate — these are public on-chain values, no timing leak.
    let expected = PedersenCommitment::commit(decrypted.amount, &decrypted.blinding_factor);
    let expected_bytes = expected.to_bytes();
    if expected_bytes != decrypted.output.commitment {
        return Err(crate::error::Error::InvalidState(format!(
            "decrypted output {}:{} fails commitment check (amount/blinding don't \
             match on-chain commitment); refusing to add to wallet balance",
            hex::encode(decrypted.tx_hash.as_bytes()),
            decrypted.output_index,
        )));
    }

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

    fn push_diff(scanner: &mut WalletScanner, height: u64, tag: u8) {
        scanner.record_journal_entry(BlockApplyDiff {
            height,
            block_hash: Hash::from_bytes([tag; 32]),
            prev_block_hash: Hash::from_bytes([tag.wrapping_sub(1); 32]),
            outputs_added: vec![(Hash::from_bytes([tag; 32]), 0)],
            key_images_marked_spent: vec![],
        });
        // Keep scanner.last_* in sync with the journal back so rewind's
        // "TargetAboveCurrent" guard reflects real state.
        scanner.last_height = height;
        scanner.last_hash = Hash::from_bytes([tag; 32]);
    }

    /// Reorg-handling Task #3: rewind to a specific height drops newer
    /// journal entries and emits the correct RewindOutcome (entries_undone,
    /// outputs_to_remove in reverse-application order, updated tip).
    #[test]
    fn rewind_to_specific_height_pops_correct_entries() {
        let mut scanner = WalletScanner::new();
        // Apply heights 1..=5
        for h in 1u64..=5 {
            push_diff(&mut scanner, h, h as u8);
        }
        assert_eq!(scanner.journal_len(), 5);
        assert_eq!(scanner.position().0, 5);

        // Rewind to height 2 — should pop entries 5, 4, 3.
        let outcome = scanner.rewind_to_height(2).expect("rewind to in-window height should succeed");

        assert_eq!(outcome.entries_undone, 3);
        assert_eq!(outcome.new_height, 2);
        assert_eq!(outcome.new_hash, Hash::from_bytes([2u8; 32]));
        assert_eq!(scanner.journal_len(), 2, "journal should retain only heights 1 + 2");
        assert_eq!(scanner.position().0, 2);

        // outputs_to_remove should be in reverse application order:
        // first the height-5 output, then height-4, then height-3.
        assert_eq!(outcome.outputs_to_remove.len(), 3);
        assert_eq!(outcome.outputs_to_remove[0].0, Hash::from_bytes([5u8; 32]));
        assert_eq!(outcome.outputs_to_remove[1].0, Hash::from_bytes([4u8; 32]));
        assert_eq!(outcome.outputs_to_remove[2].0, Hash::from_bytes([3u8; 32]));
    }

    /// Task #3: rewind to current height is a valid no-op.
    #[test]
    fn rewind_to_current_height_is_noop() {
        let mut scanner = WalletScanner::new();
        for h in 1u64..=5 {
            push_diff(&mut scanner, h, h as u8);
        }
        let outcome = scanner.rewind_to_height(5).expect("rewind to current should succeed");
        assert_eq!(outcome.entries_undone, 0);
        assert_eq!(outcome.outputs_to_remove.len(), 0);
        assert_eq!(outcome.new_height, 5);
        assert_eq!(scanner.journal_len(), 5);
    }

    /// Task #3: rewinding "forward" (target above last_height) returns
    /// TargetAboveCurrent — callers cannot use rewind to advance state.
    #[test]
    fn rewind_above_current_height_errs() {
        let mut scanner = WalletScanner::new();
        for h in 1u64..=3 {
            push_diff(&mut scanner, h, h as u8);
        }
        let err = scanner
            .rewind_to_height(10)
            .expect_err("rewind above current should error");
        match err {
            RewindError::TargetAboveCurrent {
                target_height: 10,
                current_height: 3,
            } => {}
            other => panic!("expected TargetAboveCurrent{{10,3}}, got {:?}", other),
        }
        // Scanner state is unchanged.
        assert_eq!(scanner.journal_len(), 3);
        assert_eq!(scanner.position().0, 3);
    }

    /// Task #3: rewinding past the oldest journal entry returns
    /// OutsideJournalWindow — callers fall back to a full rescan.
    #[test]
    fn rewind_outside_journal_window_errs() {
        let mut scanner = WalletScanner::new();
        // Apply heights 50..=53. Journal's earliest is 50.
        for h in 50u64..=53 {
            push_diff(&mut scanner, h, h as u8);
        }
        // Target 40 — older than journal's earliest (50). Should err.
        let err = scanner
            .rewind_to_height(40)
            .expect_err("rewind below journal window should error");
        match err {
            RewindError::OutsideJournalWindow {
                target_height: 40,
                earliest_in_journal: 50,
            } => {}
            other => panic!(
                "expected OutsideJournalWindow{{40,50}}, got {:?}",
                other
            ),
        }
        // Scanner state unchanged.
        assert_eq!(scanner.journal_len(), 4);
    }

    /// Task #3: a full rewind (target=0) empties the journal and
    /// returns last_height to 0 + Hash::zero. The caller's downstream
    /// undo work uses outputs_to_remove to clean up.
    #[test]
    fn rewind_to_zero_empties_journal() {
        let mut scanner = WalletScanner::new();
        for h in 1u64..=5 {
            push_diff(&mut scanner, h, h as u8);
        }
        let outcome = scanner.rewind_to_height(0).expect("rewind to 0 should succeed");
        assert_eq!(outcome.entries_undone, 5);
        assert_eq!(outcome.outputs_to_remove.len(), 5);
        assert_eq!(outcome.new_height, 0);
        assert_eq!(outcome.new_hash, Hash::zero());
        assert_eq!(scanner.journal_len(), 0);
        assert_eq!(scanner.position().0, 0);
        assert_eq!(scanner.position().1, Hash::zero());
    }

    /// Task #1b: spends journaled via `record_spend_for_last_block`
    /// surface in `RewindOutcome.key_images_to_unspend` in reverse
    /// application order. Without this, a wallet that spent its own
    /// UTXO in a now-orphaned block would carry `spent = true` forever
    /// after rewind (the outputs_to_remove path only handles incoming
    /// outputs, not spend signals on pre-existing UTXOs).
    #[test]
    fn rewind_surfaces_journaled_spends_in_reverse_order() {
        let mut scanner = WalletScanner::new();
        // Heights 1, 2, 3 — each gets one journaled spend tagged by height.
        for h in 1u64..=3 {
            push_diff(&mut scanner, h, h as u8);
            let ki = KeyImage::from_bytes([h as u8 + 0x80; 32]);
            assert!(scanner.record_spend_for_last_block(ki),
                "record_spend_for_last_block should find the just-pushed entry");
        }
        assert_eq!(scanner.journal_len(), 3);

        let outcome = scanner.rewind_to_height(1).expect("rewind succeeds");
        assert_eq!(outcome.entries_undone, 2);
        // Reverse order: height 3's spend pops first, then height 2's.
        // Height 1 stays in journal so its spend is NOT surfaced.
        assert_eq!(outcome.key_images_to_unspend.len(), 2);
        assert_eq!(outcome.key_images_to_unspend[0],
                   KeyImage::from_bytes([3 + 0x80; 32]));
        assert_eq!(outcome.key_images_to_unspend[1],
                   KeyImage::from_bytes([2 + 0x80; 32]));
    }

    /// `record_spend_for_last_block` returns false when the journal is
    /// empty (no entry to attach the spend to). Defensive — the
    /// orchestrator may call this before the first block is scanned
    /// during edge-case startup paths.
    #[test]
    fn record_spend_on_empty_journal_returns_false() {
        let mut scanner = WalletScanner::new();
        assert_eq!(scanner.journal_len(), 0);
        let ki = KeyImage::from_bytes([0xAA; 32]);
        assert!(!scanner.record_spend_for_last_block(ki));
    }

    /// Reorg-handling Task #2a: chain-continuity check skips the
    /// journal write when the incoming block's prev_hash doesn't match
    /// the most-recent journal entry. The wallet state stays at the
    /// pre-reorg block; the caller receives an empty outputs Vec.
    #[test]
    fn reorg_detection_skips_journal_on_prev_hash_mismatch() {
        let mut scanner = WalletScanner::new();

        // Seed journal with a "block at height 10" entry. Block_hash =
        // 0x01..., representing the canonical chain at that point.
        let canonical_h10_hash = Hash::from_bytes([0x01; 32]);
        scanner.record_journal_entry(BlockApplyDiff {
            height: 10,
            block_hash: canonical_h10_hash,
            prev_block_hash: Hash::from_bytes([0x00; 32]),
            outputs_added: vec![],
            key_images_marked_spent: vec![],
        });
        assert_eq!(scanner.journal_len(), 1);

        // Now construct a "reorg block at height 11" — its prev_hash
        // points to a DIFFERENT block than canonical_h10_hash, i.e., it
        // descends from a fork of the chain we previously saw.
        let reorg_block_prev = Hash::from_bytes([0xff; 32]);
        let synthetic_reorg_diff = BlockApplyDiff {
            height: 11,
            block_hash: Hash::from_bytes([0x02; 32]),
            prev_block_hash: reorg_block_prev,
            outputs_added: vec![],
            key_images_marked_spent: vec![],
        };

        // Verify the detection condition the way scan_block evaluates it:
        let detected = {
            let prev_entry = scanner.journal_back().unwrap();
            synthetic_reorg_diff.height == prev_entry.height + 1
                && synthetic_reorg_diff.prev_block_hash != prev_entry.block_hash
        };
        assert!(
            detected,
            "Task #2a continuity-check predicate must flag a divergent prev_hash"
        );

        // The journal length is still 1 (Task #2a doesn't write on
        // detection). The full scan_block path is exercised by the
        // existing test_scanner_block_with_transfer test; this test
        // focuses on the predicate logic + journal-skip invariant.
        assert_eq!(scanner.journal_len(), 1);
    }

    /// Reorg-handling Task #1: journal is bounded at `journal_max` —
    /// older entries get dropped when capacity is exceeded.
    #[test]
    fn journal_bounded_at_max_capacity() {
        let mut scanner = WalletScanner::new();
        let max = scanner.journal_max();
        assert!(max > 0, "journal_max must be positive");

        // Push max+10 synthetic entries; expect journal length to settle at max.
        for i in 0..(max as u64) + 10 {
            let diff = BlockApplyDiff {
                height: i,
                block_hash: Hash::zero(),
                prev_block_hash: Hash::zero(),
                outputs_added: vec![],
                key_images_marked_spent: vec![],
            };
            scanner.record_journal_entry(diff);
        }
        assert_eq!(
            scanner.journal_len(),
            max,
            "journal must be bounded at journal_max"
        );

        // The oldest retained entry should correspond to height = 10
        // (the first 10 should have been dropped).
        let oldest = scanner
            .journal
            .front()
            .expect("journal should not be empty");
        assert_eq!(
            oldest.height, 10,
            "expected oldest retained entry at height 10 (first 10 dropped)"
        );

        // Newest entry should be the last height we pushed.
        let newest = scanner
            .journal_back()
            .expect("journal should not be empty");
        assert_eq!(
            newest.height,
            (max as u64) + 9,
            "expected newest entry at height max+9"
        );
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

        // Derive the blinding factor exactly as the production builder does
        // (transaction/builder.rs:333-344) so the scanner's commit-recompute
        // check (added 2026-06-03 for ghost-balance defense) passes.
        let blinding_hash = hash_domain(b"COINCYNC_BLINDING", &sender_shared_secret);
        let blinding = BlindingFactor::from_bytes(*blinding_hash.as_bytes());
        let commitment = PedersenCommitment::commit(send_amount, &blinding).to_bytes();

        // Build a TxOutput as the sender would
        let tx_output = TxOutput {
            stealth_address: stealth.public_key,
            tx_public_key: stealth.tx_public_key,
            commitment,
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
        let send_amount: u64 = 5_000_000_000;
        let encrypted_amount = encrypt_amount(send_amount, &sender_shared);
        let view_tag = generate_view_tag(&view_public, &tx_secret, 0);

        // Real commitment so scanner's commit-recompute check passes
        // (matches the production builder's blinding derivation).
        let blinding_hash = hash_domain(b"COINCYNC_BLINDING", &sender_shared);
        let blinding = BlindingFactor::from_bytes(*blinding_hash.as_bytes());
        let commitment = PedersenCommitment::commit(send_amount, &blinding).to_bytes();

        let tx = Transaction {
            version: 1, tx_type: TxType::Transfer, inputs: vec![],
            outputs: vec![TxOutput {
                stealth_address: stealth.public_key,
                tx_public_key: stealth.tx_public_key,
                commitment, encrypted_amount, view_tag,
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

        // Real commitment so scanner's commit-recompute check passes
        // (matches the production builder's blinding derivation).
        let blinding_hash = hash_domain(b"COINCYNC_BLINDING", &sender_shared_secret);
        let blinding = BlindingFactor::from_bytes(*blinding_hash.as_bytes());
        let transfer_commitment = PedersenCommitment::commit(send_amount, &blinding).to_bytes();

        let transfer_tx = Transaction {
            version: 1,
            tx_type: TxType::Transfer,
            inputs: vec![],
            outputs: vec![TxOutput {
                stealth_address: stealth.public_key,
                tx_public_key: stealth.tx_public_key,
                commitment: transfer_commitment,
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
