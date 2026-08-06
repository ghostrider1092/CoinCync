//! # Lightweight Wallet Sync (SPV).
//!
//! Privacy posture: this protocol downloads ALL output digests in a height
//! range and scans them locally. The server learns only the range, never
//! which outputs the wallet cares about — strictly stronger than BIP-157,
//! where the wallet's address set leaks to whoever serves the filters. See
//! `docs/security/LIGHTSYNC_AUDIT.md` for the full comparison.
//!
//! ## Wire surface
//!
//! - `GetOutputDigests = 62` / `OutputDigests = 63` (network layer, served
//!   by `crate::network::node`).
//! - JSON-RPC: `get_output_digests` in `crate::rpc::lightwallet`.
//! - Per-request cap: 100 blocks (digests are larger than filters; see the
//!   handler for the byte budget calculation).
//!
//! ## What's here
//!
//! - **Block digests**: compact output-only summaries (~138 B / output vs
//!   full blocks)
//! - **View tag pre-filtering**: reject 255/256 outputs without ECDH
//! - **Parallel scanning**: process multiple digests concurrently via rayon
//! - **Sync checkpoints**: periodic trust anchors for fast initial sync.
//!   Audit **Gap 2** (checkpoint *authentication*): a consumer must call
//!   [`SyncCheckpoint::authenticate`] and only fast-skip on
//!   [`CheckpointAuth::Authenticated`] — this validates a server-provided
//!   checkpoint against the binary's hardcoded `CONSENSUS_CHECKPOINTS` set.
//!   Full miner-signed checkpoints remain the v1.0.1 solution; until then an
//!   unhardcoded height is `Unverifiable` and must fall back to a full scan.
//!
//! Bandwidth savings: ~50-100x reduction vs downloading full blocks.

use borsh::{BorshDeserialize, BorshSerialize};
use rayon::prelude::*;
use serde::{Deserialize, Serialize};

use crate::consensus::Block;
use crate::crypto::{is_output_ours, BlindingFactor, PublicPoint, SecretScalar, StealthAddress};
use crate::decoy::canonical_output_locators;
use crate::primitives::{hash_domain, Hash, PublicKey, SecretKey};
use crate::transaction::TxOutput;
use crate::wallet::scanner::{DecryptedOutput, ScanKeys};

// =============================================================================
// OUTPUT DIGEST - minimal per-output data for scanning
// =============================================================================

/// Compact representation of a transaction output for wallet scanning.
///
/// Contains only the fields needed to detect ownership and decrypt amounts.
/// Strips ring signatures, range proofs, and all input data.
///
/// Size: ~105 bytes per output (vs ~1-5KB for a full transaction)
#[derive(Clone, Debug, Serialize, Deserialize, BorshSerialize, BorshDeserialize)]
pub struct OutputDigest {
    /// Transaction public key for ECDH (32 bytes)
    pub tx_public_key: PublicKey,
    /// View tag for fast pre-filtering (1 byte)
    pub view_tag: u8,
    /// One-time stealth address (32 bytes)
    pub stealth_address: PublicKey,
    /// Pedersen commitment to the amount (32 bytes)
    pub commitment: [u8; 32],
    /// Encrypted amount for recipient (~8 bytes)
    pub encrypted_amount: Vec<u8>,
    /// Reference: transaction hash (32 bytes)
    pub tx_hash: Hash,
    /// Reference: output index within the transaction (1 byte)
    pub output_index: u8,
}

impl OutputDigest {
    /// Create an OutputDigest from a TxOutput and its transaction context
    pub fn from_output(output: &TxOutput, tx_hash: Hash, output_index: u8) -> Self {
        OutputDigest {
            tx_public_key: output.tx_public_key,
            view_tag: output.view_tag,
            stealth_address: output.stealth_address,
            commitment: output.commitment,
            encrypted_amount: output.encrypted_amount.clone(),
            tx_hash,
            output_index,
        }
    }

    /// Estimated serialized size in bytes
    pub fn estimated_size() -> usize {
        // 32 + 1 + 32 + 32 + 8 + 32 + 1 = ~138 with overhead
        138
    }
}

// =============================================================================
// BLOCK DIGEST - compact block summary for wallet scanning
// =============================================================================

/// Compact block summary containing only output data needed for wallet scanning.
///
/// Strips all inputs, signatures, range proofs, and transaction structure.
/// Only includes output-level data needed to detect incoming payments.
#[derive(Clone, Debug, Serialize, Deserialize, BorshSerialize, BorshDeserialize)]
pub struct BlockDigest {
    /// Block height
    pub height: u64,
    /// Block hash (for chain verification)
    pub hash: Hash,
    /// Previous block hash (for chain continuity)
    pub prev_hash: Hash,
    /// Block timestamp
    pub timestamp: u64,
    /// Total number of outputs in this block
    pub output_count: u16,
    /// All outputs from all transactions
    pub outputs: Vec<OutputDigest>,
}

impl BlockDigest {
    /// Create a BlockDigest from a full Block (server-side operation)
    pub fn from_block(block: &Block) -> Self {
        let hash = block.hash();
        let mut outputs = Vec::new();

        for tx in &block.transactions {
            let tx_hash = tx.hash();
            for (idx, output) in tx.outputs.iter().enumerate() {
                if idx > 255 {
                    break;
                } // Same safety as WalletScanner
                outputs.push(OutputDigest::from_output(output, tx_hash, idx as u8));
            }
        }

        BlockDigest {
            height: block.height(),
            hash,
            prev_hash: block.header.prev_hash,
            timestamp: block.header.timestamp,
            output_count: outputs.len() as u16,
            outputs,
        }
    }

    /// Estimated serialized size in bytes
    pub fn estimated_size(&self) -> usize {
        // Header: 8 + 32 + 32 + 8 + 2 = 82 bytes
        // Outputs: ~138 bytes each
        82 + self.outputs.len() * OutputDigest::estimated_size()
    }
}

// =============================================================================
// SYNC CHECKPOINT - periodic trust anchors
// =============================================================================

/// Periodic checkpoint for fast initial sync.
///
/// Allows light wallets to skip scanning blocks before the checkpoint height,
/// trusting the UTXO commitment hash for verification.
#[derive(Clone, Debug, Serialize, Deserialize, BorshSerialize, BorshDeserialize)]
pub struct SyncCheckpoint {
    /// Block height of the checkpoint
    pub height: u64,
    /// Block hash at this height
    pub block_hash: Hash,
    /// Total outputs created up to this height
    pub total_outputs: u64,
    /// Hash of the UTXO set state (for verification)
    pub utxo_hash: Hash,
}

impl SyncCheckpoint {
    /// Create a checkpoint from chain state
    pub fn new(height: u64, block_hash: Hash, total_outputs: u64, utxo_hash: Hash) -> Self {
        SyncCheckpoint {
            height,
            block_hash,
            total_outputs,
            utxo_hash,
        }
    }

    /// Verify checkpoint integrity (hash includes all fields).
    ///
    /// NOTE: this only computes a *self*-consistency hash — it proves the
    /// fields haven't been mangled in transit, NOT that the checkpoint is
    /// legitimate. A malicious server can craft a perfectly self-consistent
    /// but forged checkpoint. To establish *authenticity*, call
    /// [`authenticate`](Self::authenticate).
    pub fn verify_hash(&self) -> Hash {
        hash_domain(
            b"COINCYNC_CHECKPOINT_v1",
            &[
                &self.height.to_le_bytes()[..],
                self.block_hash.as_bytes(),
                &self.total_outputs.to_le_bytes(),
                self.utxo_hash.as_bytes(),
            ]
            .concat(),
        )
    }

    /// Authenticate this (server-provided) checkpoint against the binary's
    /// hardcoded `CONSENSUS_CHECKPOINTS` set — the interim mitigation for
    /// **audit Gap 2** (checkpoint authentication) until miner-signed
    /// checkpoints are wired (v1.0.1).
    ///
    /// SECURITY: a light wallet that "trusts a checkpoint to skip scanning
    /// blocks before its height" is trusting the server not to lie. A forged
    /// checkpoint could make the wallet skip real blocks and miss the
    /// owner's own incoming transactions, or accept a false chain state. A
    /// consumer MUST call this and **only fast-skip when the result is
    /// [`CheckpointAuth::Authenticated`]**; [`Unverifiable`](CheckpointAuth::Unverifiable)
    /// and [`Forged`](CheckpointAuth::Forged) must both fall back to a normal
    /// scan (and `Forged` should additionally distrust the peer).
    pub fn authenticate(&self) -> CheckpointAuth {
        self.authenticate_against(crate::constants::expected_checkpoint_hash(self.height))
    }

    /// Core of [`authenticate`](Self::authenticate), split out so the
    /// decision logic is unit-testable without depending on the (currently
    /// sparse/empty pre-launch) hardcoded checkpoint table.
    fn authenticate_against(&self, expected: Option<&[u8; 32]>) -> CheckpointAuth {
        match expected {
            Some(h) if self.block_hash.as_bytes()[..] == h[..] => CheckpointAuth::Authenticated,
            Some(_) => CheckpointAuth::Forged,
            None => CheckpointAuth::Unverifiable,
        }
    }
}

/// Result of authenticating a server-provided [`SyncCheckpoint`] against the
/// binary's hardcoded consensus-checkpoint set (audit Gap 2 mitigation).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CheckpointAuth {
    /// A hardcoded checkpoint exists at this height AND its block hash
    /// matches. Safe to trust as a fast-sync anchor.
    Authenticated,
    /// A hardcoded checkpoint exists at this height but the block hash
    /// DIFFERS — the checkpoint is forged. Reject it and distrust the peer.
    Forged,
    /// No hardcoded checkpoint at this height, so authenticity can't be
    /// established. Do NOT fast-skip — scan normally. Until miner-signed
    /// checkpoints land (v1.0.1) and the hardcoded table is populated, this
    /// is the expected common case.
    Unverifiable,
}

// =============================================================================
// RPC REQUEST/RESPONSE TYPES
// =============================================================================

/// Request for output digests from the RPC server
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DigestRequest {
    /// Start height (inclusive)
    pub start_height: u64,
    /// End height (inclusive)
    pub end_height: u64,
    /// Maximum digests to return (capped at 1000)
    pub max_digests: Option<u16>,
}

/// Response containing output digests
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DigestResponse {
    /// Block digests in the requested range
    pub digests: Vec<BlockDigest>,
    /// Current chain height (so client knows how far behind it is)
    pub chain_height: u64,
    /// Total serialized size in bytes (approximate)
    pub bandwidth_bytes: usize,
}

// =============================================================================
// LIGHT WALLET SYNC ENGINE
// =============================================================================

/// Lightweight wallet sync engine.
///
/// Scans BlockDigests instead of full blocks, using the same view tag +
/// ECDH pattern as WalletScanner but with ~50-100x less bandwidth.
pub struct LightWalletSync {
    /// Scan keys (same as full scanner)
    scan_keys: Vec<ScanKeys>,
    /// Last successfully scanned height
    last_scanned: u64,
    /// Scanning statistics
    stats: LightSyncStats,
}

/// Statistics for lightweight scanning
#[derive(Clone, Debug, Default)]
pub struct LightSyncStats {
    /// Digests scanned
    pub digests_scanned: u64,
    /// Outputs scanned
    pub outputs_scanned: u64,
    /// View tag matches (passed fast filter)
    pub view_tag_matches: u64,
    /// Outputs confirmed as ours
    pub outputs_found: u64,
    /// Total amount found (u128 to prevent overflow from large asset supplies)
    pub total_amount: u128,
    /// Bytes processed (estimated)
    pub bytes_processed: u64,
    /// Scan time in milliseconds
    pub scan_time_ms: u64,
}

impl LightWalletSync {
    /// Create a new lightweight sync engine
    pub fn new(keys: Vec<ScanKeys>) -> Self {
        LightWalletSync {
            scan_keys: keys,
            last_scanned: 0,
            stats: LightSyncStats::default(),
        }
    }

    /// Get last scanned height
    pub fn last_scanned(&self) -> u64 {
        self.last_scanned
    }

    /// Get scanning statistics
    pub fn stats(&self) -> &LightSyncStats {
        &self.stats
    }

    /// Reset statistics
    pub fn reset_stats(&mut self) {
        self.stats = LightSyncStats::default();
    }

    /// Scan a single output digest for ownership
    ///
    /// SECURITY (C9-FIX): Now checks subaddress keys in addition to primary address.
    /// Previously only checked `keys.spend_public`, missing all outputs sent to
    /// subaddresses via light sync — causing permanent fund loss for subaddress users.
    fn scan_output_digest(&self, output: &OutputDigest) -> Option<DecryptedOutput> {
        for keys in &self.scan_keys {
            // Step 1: View tag fast filter (eliminates ~255/256 outputs)
            let expected_tag = compute_view_tag_light(
                &keys.view_secret,
                &output.tx_public_key,
                output.output_index,
            );

            if output.view_tag != expected_tag {
                continue;
            }

            // Step 2: Full ECDH ownership check — primary address first
            let stealth = StealthAddress {
                public_key: output.stealth_address,
                tx_public_key: output.tx_public_key,
            };

            let mut matched = is_output_ours(
                &stealth,
                &keys.view_secret,
                &keys.spend_public,
                output.output_index,
            );
            let mut matched_subaddr: Option<(u32, u32)> = None;

            // SECURITY (C9-FIX): Check subaddress keys if primary didn't match
            if !matched {
                for &(account, index, ref sub_spend) in &keys.subaddress_keys {
                    if is_output_ours(&stealth, &keys.view_secret, sub_spend, output.output_index) {
                        matched = true;
                        matched_subaddr = Some((account, index));
                        break;
                    }
                }
            }

            if matched {
                // Step 3: Decrypt amount
                let shared_secret = compute_shared_secret_light(
                    &keys.view_secret,
                    &output.tx_public_key,
                    output.output_index,
                );

                let (amount, blinding_factor) =
                    decrypt_amount_light(&output.encrypted_amount, &shared_secret);

                // 2026-06-03 ghost-balance defense (parity with
                // wallet/scanner.rs::scan_output): verify the decrypted
                // (amount, blinding) reconstructs to output.commitment.
                // See the long-form rationale in scanner.rs commit
                // 0894835. Light-sync path needs the same check —
                // otherwise a malicious sender's forged encrypted_amount
                // shows up as ghost balance in light wallets too.
                let expected_commitment =
                    crate::crypto::PedersenCommitment::commit(amount, &blinding_factor).to_bytes();
                if expected_commitment != output.commitment {
                    tracing::debug!(
                        "lightsync: stealth match but commitment recompute mismatch \
                         (tx={}, output_idx={}, claimed amount {}). \
                         Likely malicious sender or corrupted digest — skipping.",
                        output.tx_hash.to_hex(),
                        output.output_index,
                        amount,
                    );
                    continue;
                }

                // Reconstruct TxOutput for DecryptedOutput compatibility
                let tx_output = TxOutput {
                    stealth_address: output.stealth_address,
                    tx_public_key: output.tx_public_key,
                    commitment: output.commitment,
                    encrypted_amount: output.encrypted_amount.clone(),
                    view_tag: output.view_tag,
                    lock_height: None,
                    encrypted_memo: vec![],
                };

                return Some(DecryptedOutput {
                    tx_hash: output.tx_hash,
                    output_index: output.output_index,
                    output_locator: None,
                    output: tx_output,
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

    /// Scan a single block digest for owned outputs
    pub fn scan_digest(&mut self, digest: &BlockDigest) -> Vec<DecryptedOutput> {
        let mut found = Vec::new();
        let locators = canonical_output_locators(
            digest.height,
            digest
                .outputs
                .iter()
                .map(|output| (output.tx_hash, output.output_index)),
        );

        self.stats.digests_scanned += 1;
        self.stats.bytes_processed += digest.estimated_size() as u64;

        for output in &digest.outputs {
            self.stats.outputs_scanned += 1;

            // View tag stats: check against all key sets to avoid hardcoding index 0
            // (which would panic if scan_keys is empty or miss matches for later epochs)
            if self.scan_keys.iter().any(|ks| {
                let expected = compute_view_tag_light(
                    &ks.view_secret,
                    &output.tx_public_key,
                    output.output_index,
                );
                output.view_tag == expected
            }) {
                self.stats.view_tag_matches += 1;
            }

            if let Some(mut decrypted) = self.scan_output_digest(output) {
                decrypted.output_locator = locators
                    .get(&(output.tx_hash, output.output_index))
                    .copied();
                self.stats.outputs_found += 1;
                self.stats.total_amount += decrypted.amount as u128;
                found.push(decrypted);
            }
        }

        self.last_scanned = digest.height;
        found
    }

    /// Scan multiple block digests in parallel using rayon
    pub fn scan_digests_parallel(&mut self, digests: &[BlockDigest]) -> Vec<DecryptedOutput> {
        let start = std::time::Instant::now();

        let keys = self.scan_keys.clone();

        let results: Vec<Vec<DecryptedOutput>> = digests
            .par_iter()
            .map(|digest| {
                let mut found = Vec::new();
                let locators = canonical_output_locators(
                    digest.height,
                    digest
                        .outputs
                        .iter()
                        .map(|output| (output.tx_hash, output.output_index)),
                );
                for output in &digest.outputs {
                    if let Some(mut decrypted) = scan_output_digest_with_keys(output, &keys) {
                        decrypted.output_locator = locators
                            .get(&(output.tx_hash, output.output_index))
                            .copied();
                        found.push(decrypted);
                    }
                }
                found
            })
            .collect();

        let all_found: Vec<DecryptedOutput> = results.into_iter().flatten().collect();

        // Update stats
        self.stats.digests_scanned += digests.len() as u64;
        self.stats.outputs_scanned += digests.iter().map(|d| d.outputs.len() as u64).sum::<u64>();
        self.stats.outputs_found += all_found.len() as u64;
        self.stats.total_amount += all_found.iter().map(|o| o.amount as u128).sum::<u128>();
        self.stats.bytes_processed += digests
            .iter()
            .map(|d| d.estimated_size() as u64)
            .sum::<u64>();
        self.stats.scan_time_ms += start.elapsed().as_millis() as u64;

        // Update position to last digest
        if let Some(last) = digests.last() {
            self.last_scanned = last.height;
        }

        all_found
    }

    /// Estimate bandwidth needed for a height range
    ///
    /// # Arguments
    /// * `block_count` - Number of blocks in range
    /// * `avg_outputs_per_block` - Average outputs per block
    pub fn estimate_bandwidth(block_count: u64, avg_outputs_per_block: u16) -> usize {
        let header_bytes = 82; // BlockDigest header
        let output_bytes = OutputDigest::estimated_size();
        (block_count as usize) * (header_bytes + (avg_outputs_per_block as usize) * output_bytes)
    }
}

// =============================================================================
// STANDALONE SCANNING FUNCTIONS (for parallel use)
// =============================================================================

/// Scan a single output digest with provided keys (thread-safe, no mutation)
///
/// SECURITY (C9-FIX): Now checks subaddress keys in addition to primary address.
fn scan_output_digest_with_keys(
    output: &OutputDigest,
    keys: &[ScanKeys],
) -> Option<DecryptedOutput> {
    for key_set in keys {
        // View tag fast filter
        let expected_tag = compute_view_tag_light(
            &key_set.view_secret,
            &output.tx_public_key,
            output.output_index,
        );

        if output.view_tag != expected_tag {
            continue;
        }

        // Full ECDH check — primary address first
        let stealth = StealthAddress {
            public_key: output.stealth_address,
            tx_public_key: output.tx_public_key,
        };

        let mut matched = is_output_ours(
            &stealth,
            &key_set.view_secret,
            &key_set.spend_public,
            output.output_index,
        );
        let mut matched_subaddr: Option<(u32, u32)> = None;

        // SECURITY (C9-FIX): Check subaddress keys if primary didn't match
        if !matched {
            for &(account, index, ref sub_spend) in &key_set.subaddress_keys {
                if is_output_ours(
                    &stealth,
                    &key_set.view_secret,
                    sub_spend,
                    output.output_index,
                ) {
                    matched = true;
                    matched_subaddr = Some((account, index));
                    break;
                }
            }
        }

        if matched {
            let shared_secret = compute_shared_secret_light(
                &key_set.view_secret,
                &output.tx_public_key,
                output.output_index,
            );

            let (amount, blinding_factor) =
                decrypt_amount_light(&output.encrypted_amount, &shared_secret);

            // 2026-06-03 ghost-balance defense (parity with
            // wallet/scanner.rs::scan_output). See commit 0894835.
            let expected_commitment =
                crate::crypto::PedersenCommitment::commit(amount, &blinding_factor).to_bytes();
            if expected_commitment != output.commitment {
                tracing::debug!(
                    "lightsync (free fn): stealth match but commitment recompute mismatch \
                     (tx={}, output_idx={}, claimed amount {}). Skipping.",
                    output.tx_hash.to_hex(),
                    output.output_index,
                    amount,
                );
                continue;
            }

            let tx_output = TxOutput {
                stealth_address: output.stealth_address,
                tx_public_key: output.tx_public_key,
                commitment: output.commitment,
                encrypted_amount: output.encrypted_amount.clone(),
                view_tag: output.view_tag,
                lock_height: None,
                encrypted_memo: vec![],
            };

            return Some(DecryptedOutput {
                tx_hash: output.tx_hash,
                output_index: output.output_index,
                output_locator: None,
                output: tx_output,
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

// =============================================================================
// CRYPTO HELPERS (same algorithms as scanner.rs, kept here for modularity)
// =============================================================================

/// Compute view tag using ECDH (same as scanner.rs compute_view_tag)
fn compute_view_tag_light(view_secret: &SecretKey, tx_public: &PublicKey, output_index: u8) -> u8 {
    let view_scalar = SecretScalar::from_bytes(*view_secret.as_bytes());
    let tx_point = match PublicPoint::from_bytes(*tx_public.as_bytes()) {
        Some(p) => p,
        None => return 0xFF,
    };
    // R-7 CLASS (2026-07-03): ECDH shared point + heap-derived buffer
    // both hold secret material. Mirror wallet/scanner.rs::compute_view_tag:
    // build the input buffer explicitly, then zeroize shared_bytes,
    // tag_input, and the RistrettoPoint before scope exit.
    let mut shared_point = tx_point.mul(&view_scalar);
    let mut shared_bytes = shared_point.to_bytes();
    let mut tag_input = Vec::with_capacity(32 + 1);
    tag_input.extend_from_slice(&shared_bytes);
    tag_input.push(output_index);
    let tag_hash = hash_domain(b"COINCYNC_VIEWTAG_v2", &tag_input);
    {
        use zeroize::Zeroize;
        tag_input.zeroize();
        shared_bytes.zeroize();
        shared_point.zeroize();
    }
    tag_hash.as_bytes()[0]
}

/// Compute shared secret for amount decryption (same as scanner.rs)
fn compute_shared_secret_light(
    view_secret: &SecretKey,
    tx_public: &PublicKey,
    output_index: u8,
) -> [u8; 32] {
    let view_scalar = SecretScalar::from_bytes(*view_secret.as_bytes());
    let tx_point = match PublicPoint::from_bytes(*tx_public.as_bytes()) {
        Some(p) => p,
        None => return [0u8; 32],
    };
    // R-7 CLASS (2026-07-03): same treatment as compute_view_tag_light —
    // the shared_point is the ECDH shared secret; zeroize both the
    // point and the heap buffer we serialize it into.
    let mut shared_point = tx_point.mul(&view_scalar);
    let mut shared_bytes = shared_point.to_bytes();
    let mut buf = Vec::with_capacity(32 + 1);
    buf.extend_from_slice(&shared_bytes);
    buf.push(output_index);
    let shared = hash_domain(b"COINCYNC_SHARED_v2", &buf);
    {
        use zeroize::Zeroize;
        buf.zeroize();
        shared_bytes.zeroize();
        shared_point.zeroize();
    }
    *shared.as_bytes()
}

/// Decrypt amount and derive blinding factor (same as scanner.rs)
fn decrypt_amount_light(encrypted: &[u8], shared_secret: &[u8; 32]) -> (u64, BlindingFactor) {
    let decrypt_key = hash_domain(b"COINCYNC_AMOUNT_KEY", shared_secret);

    let mut amount_bytes = [0u8; 8];
    if encrypted.len() >= 8 {
        for i in 0..8 {
            amount_bytes[i] = encrypted[i] ^ decrypt_key.as_bytes()[i];
        }
    }
    let amount = u64::from_le_bytes(amount_bytes);

    let blinding_hash = hash_domain(b"COINCYNC_BLINDING", shared_secret);
    let blinding_factor = BlindingFactor::from_bytes(*blinding_hash.as_bytes());

    (amount, blinding_factor)
}

// =============================================================================
// TESTS
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::NetworkType;
    use crate::consensus::{Block, BlockHeader};
    use crate::crypto::{PublicPoint as CurvePublicPoint, SecretScalar as CurveSecretScalar};
    use crate::primitives::{Amount, PublicKey, SecretKey};
    use crate::transaction::{Transaction, TxOutput, TxType};
    use crate::wallet::scanner::{encrypt_amount, generate_view_tag};
    use rand::rngs::OsRng;

    /// Create a test stealth output that a specific key pair can detect
    fn create_test_output(
        view_secret: &SecretKey,
        spend_public: &PublicKey,
        amount: u64,
        output_index: u8,
    ) -> (TxOutput, SecretKey) {
        // Generate tx_secret (sender side)
        let tx_secret_scalar = CurveSecretScalar::random(&mut OsRng);
        let tx_public_point = tx_secret_scalar.to_public();
        let tx_secret = SecretKey::from_bytes(tx_secret_scalar.to_bytes());
        let tx_public = PublicKey::from_bytes(tx_public_point.to_bytes());

        // View tag
        let view_public = {
            let vs = CurveSecretScalar::from_bytes(*view_secret.as_bytes());
            let vp = vs.to_public();
            PublicKey::from_bytes(vp.to_bytes())
        };
        let view_tag = generate_view_tag(&view_public, &tx_secret, output_index);

        // Shared secret for encryption
        let view_scalar = CurveSecretScalar::from_bytes(*view_secret.as_bytes());
        let shared_point = tx_public_point.mul(&view_scalar);
        let shared = hash_domain(
            b"COINCYNC_SHARED_v2",
            &[shared_point.to_bytes().as_slice(), &[output_index]].concat(),
        );
        let shared_secret: [u8; 32] = *shared.as_bytes();

        // Encrypted amount
        let encrypted_amount = encrypt_amount(amount, &shared_secret);

        // Derive stealth address: P = H(shared || idx)*G + spend_public
        let stealth_scalar = crate::crypto::hash_to_scalar(
            &[shared_point.to_bytes().as_slice(), &[output_index]].concat(),
        );
        let spend_point = CurvePublicPoint::from_bytes(*spend_public.as_bytes())
            .expect("test spend_public is always a valid curve point");
        let stealth_point = CurvePublicPoint::from_point(
            stealth_scalar * crate::crypto::generator() + *spend_point.as_point(),
        );
        let stealth_address = PublicKey::from_bytes(stealth_point.to_bytes());

        // Blinding factor for commitment
        let blinding_hash = hash_domain(b"COINCYNC_BLINDING", &shared_secret);
        let blinding = BlindingFactor::from_bytes(*blinding_hash.as_bytes());
        let commitment = crate::crypto::PedersenCommitment::commit(amount, &blinding);

        let output = TxOutput {
            stealth_address,
            tx_public_key: tx_public,
            commitment: commitment.to_bytes(),
            encrypted_amount,
            view_tag,
            lock_height: None,
            encrypted_memo: vec![],
        };

        (output, tx_secret)
    }

    fn make_test_keys() -> (SecretKey, PublicKey) {
        let secret = CurveSecretScalar::random(&mut OsRng);
        let public = secret.to_public();
        (
            SecretKey::from_bytes(secret.to_bytes()),
            PublicKey::from_bytes(public.to_bytes()),
        )
    }

    fn test_magic() -> [u8; 4] {
        NetworkType::Testnet.magic_bytes()
    }

    #[test]
    fn test_create_digest_from_block() {
        let (view_secret, spend_public) = make_test_keys();
        let (output, _) = create_test_output(&view_secret, &spend_public, 1_000_000, 0);

        // Create a minimal block with one transaction
        let tx = Transaction {
            version: 1,
            tx_type: TxType::Coinbase,
            inputs: vec![],
            outputs: vec![output.clone()],
            fee: Amount::from_atomic(0),
            range_proof: vec![],
            extra: vec![],
        };
        let tx_hash = tx.hash();

        let header = BlockHeader {
            network_magic: test_magic(),
            version: 1,
            height: 1,
            timestamp: 1000,
            prev_hash: Hash::from_bytes([0u8; 32]),
            tx_root: tx_hash,
            anchor: Hash::from_bytes([0u8; 32]),
            algorithm: 0,
            nonce: 0,
            target: Hash::from_bytes([0xFF; 32]),
            miner_pubkey: spend_public,
            supply_commitment: [0u8; 32],
            checkpoint_vote: None,
            spark_set_root: [0u8; 32],
            mw_kernel_root: [0u8; 32],
        };

        let block = Block::new(header, vec![tx]);
        let digest = BlockDigest::from_block(&block);

        assert_eq!(digest.height, 1);
        assert_eq!(digest.output_count, 1);
        assert_eq!(digest.outputs.len(), 1);
        assert_eq!(digest.outputs[0].view_tag, output.view_tag);
        assert_eq!(digest.outputs[0].stealth_address, output.stealth_address);
        assert_eq!(digest.outputs[0].tx_public_key, output.tx_public_key);
    }

    #[test]
    fn test_scan_digest_finds_output() {
        let (view_secret, spend_public) = make_test_keys();
        let amount = 5_000_000u64;
        let (output, _) = create_test_output(&view_secret, &spend_public, amount, 0);

        let tx = Transaction {
            version: 1,
            tx_type: TxType::Coinbase,
            inputs: vec![],
            outputs: vec![output],
            fee: Amount::from_atomic(0),
            range_proof: vec![],
            extra: vec![],
        };

        let header = BlockHeader {
            network_magic: test_magic(),
            version: 1,
            height: 1,
            timestamp: 1000,
            prev_hash: Hash::from_bytes([0u8; 32]),
            tx_root: tx.hash(),
            anchor: Hash::from_bytes([0u8; 32]),
            algorithm: 0,
            nonce: 0,
            target: Hash::from_bytes([0xFF; 32]),
            miner_pubkey: spend_public,
            supply_commitment: [0u8; 32],
            checkpoint_vote: None,
            spark_set_root: [0u8; 32],
            mw_kernel_root: [0u8; 32],
        };

        let block = Block::new(header, vec![tx]);
        let digest = BlockDigest::from_block(&block);

        let keys = ScanKeys::new(view_secret, spend_public, 0);
        let mut sync = LightWalletSync::new(vec![keys]);

        let found = sync.scan_digest(&digest);
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].amount, amount);
        assert_eq!(
            found[0].output_locator,
            Some(crate::decoy::OutputLocator {
                height: 1,
                ordinal: 0,
            })
        );
    }

    #[test]
    fn test_scan_digest_rejects_others() {
        // Create output for one key pair
        let (view_secret1, spend_public1) = make_test_keys();
        let (output, _) = create_test_output(&view_secret1, &spend_public1, 1_000_000, 0);

        let tx = Transaction {
            version: 1,
            tx_type: TxType::Coinbase,
            inputs: vec![],
            outputs: vec![output],
            fee: Amount::from_atomic(0),
            range_proof: vec![],
            extra: vec![],
        };

        let header = BlockHeader {
            network_magic: test_magic(),
            version: 1,
            height: 1,
            timestamp: 1000,
            prev_hash: Hash::from_bytes([0u8; 32]),
            tx_root: tx.hash(),
            anchor: Hash::from_bytes([0u8; 32]),
            algorithm: 0,
            nonce: 0,
            target: Hash::from_bytes([0xFF; 32]),
            miner_pubkey: spend_public1,
            supply_commitment: [0u8; 32],
            checkpoint_vote: None,
            spark_set_root: [0u8; 32],
            mw_kernel_root: [0u8; 32],
        };

        let block = Block::new(header, vec![tx]);
        let digest = BlockDigest::from_block(&block);

        // Try scanning with a DIFFERENT key pair
        let (view_secret2, spend_public2) = make_test_keys();
        let keys = ScanKeys::new(view_secret2, spend_public2, 0);
        let mut sync = LightWalletSync::new(vec![keys]);

        let found = sync.scan_digest(&digest);
        assert_eq!(found.len(), 0);
    }

    #[test]
    fn test_parallel_scan() {
        let (view_secret, spend_public) = make_test_keys();

        // Create multiple digests
        let mut digests = Vec::new();
        let mut expected_total = 0u64;

        for h in 1..=5 {
            let amount = h * 100_000;
            let (output, _) = create_test_output(&view_secret, &spend_public, amount, 0);

            let tx = Transaction {
                version: 1,
                tx_type: TxType::Coinbase,
                inputs: vec![],
                outputs: vec![output],
                fee: Amount::from_atomic(0),
                range_proof: vec![],
                extra: vec![],
            };

            let header = BlockHeader {
                network_magic: test_magic(),
                version: 1,
                height: h,
                timestamp: 1000 + h * 30,
                prev_hash: Hash::from_bytes([0u8; 32]),
                tx_root: tx.hash(),
                anchor: Hash::from_bytes([0u8; 32]),
                algorithm: 0,
                nonce: 0,
                target: Hash::from_bytes([0xFF; 32]),
                miner_pubkey: spend_public,
                supply_commitment: [0u8; 32],
                checkpoint_vote: None,
                spark_set_root: [0u8; 32],
                mw_kernel_root: [0u8; 32],
            };

            let block = Block::new(header, vec![tx]);
            digests.push(BlockDigest::from_block(&block));
            expected_total += amount;
        }

        let keys = ScanKeys::new(view_secret, spend_public, 0);
        let mut sync = LightWalletSync::new(vec![keys]);

        let found = sync.scan_digests_parallel(&digests);
        assert_eq!(found.len(), 5);

        let total: u64 = found.iter().map(|o| o.amount).sum();
        assert_eq!(total, expected_total);
        assert!(found.iter().all(|output| output.output_locator.is_some()));
    }

    #[test]
    fn test_bandwidth_estimate() {
        let estimate = LightWalletSync::estimate_bandwidth(1000, 20);
        // 1000 blocks * (82 header + 20 * 138 output) = 1000 * 2842 = ~2.8MB
        assert!(estimate > 2_000_000);
        assert!(estimate < 5_000_000);
    }

    #[test]
    fn test_checkpoint_creation() {
        let cp = SyncCheckpoint::new(
            1000,
            Hash::from_bytes([1u8; 32]),
            50_000,
            Hash::from_bytes([2u8; 32]),
        );

        assert_eq!(cp.height, 1000);
        assert_eq!(cp.total_outputs, 50_000);

        // Hash should be deterministic
        let h1 = cp.verify_hash();
        let h2 = cp.verify_hash();
        assert_eq!(h1, h2);
    }

    #[test]
    fn checkpoint_authenticate_accepts_matching_hardcoded() {
        let cp = SyncCheckpoint::new(
            1000,
            Hash::from_bytes([7u8; 32]),
            50_000,
            Hash::from_bytes([2u8; 32]),
        );
        // A hardcoded checkpoint at this height with the SAME block hash.
        assert_eq!(
            cp.authenticate_against(Some(&[7u8; 32])),
            CheckpointAuth::Authenticated
        );
    }

    #[test]
    fn checkpoint_authenticate_rejects_forged() {
        let cp = SyncCheckpoint::new(
            1000,
            Hash::from_bytes([7u8; 32]),
            50_000,
            Hash::from_bytes([2u8; 32]),
        );
        // A hardcoded checkpoint exists at this height but the hash DIFFERS.
        assert_eq!(
            cp.authenticate_against(Some(&[9u8; 32])),
            CheckpointAuth::Forged
        );
    }

    #[test]
    fn checkpoint_authenticate_unverifiable_without_hardcoded() {
        let cp = SyncCheckpoint::new(
            1000,
            Hash::from_bytes([7u8; 32]),
            50_000,
            Hash::from_bytes([2u8; 32]),
        );
        // No hardcoded checkpoint at this height -> cannot authenticate; caller must not fast-skip.
        assert_eq!(cp.authenticate_against(None), CheckpointAuth::Unverifiable);
    }

    #[test]
    fn checkpoint_authenticate_never_false_accepts_against_real_table() {
        // Safety property that holds whether the hardcoded table is empty
        // (pre-launch) or populated: a made-up checkpoint at an arbitrary
        // height must NEVER authenticate.
        let cp = SyncCheckpoint::new(
            123_456,
            Hash::from_bytes([3u8; 32]),
            1,
            Hash::from_bytes([4u8; 32]),
        );
        assert_ne!(cp.authenticate(), CheckpointAuth::Authenticated);
    }

    #[test]
    fn test_digest_serialization() {
        let digest = BlockDigest {
            height: 42,
            hash: Hash::from_bytes([1u8; 32]),
            prev_hash: Hash::from_bytes([2u8; 32]),
            timestamp: 1700000000,
            output_count: 0,
            outputs: vec![],
        };

        // Borsh roundtrip
        let bytes = borsh::to_vec(&digest).unwrap();
        let recovered: BlockDigest = borsh::from_slice(&bytes).unwrap();
        assert_eq!(recovered.height, 42);
        assert_eq!(recovered.timestamp, 1700000000);

        // JSON roundtrip
        let json = serde_json::to_string(&digest).unwrap();
        let recovered2: BlockDigest = serde_json::from_str(&json).unwrap();
        assert_eq!(recovered2.height, 42);
    }
}
