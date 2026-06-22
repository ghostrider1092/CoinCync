//! # Block Validation
//!
//! Comprehensive block and transaction validation with parallel verification.
//!
//! Uses rayon for parallel cryptographic verification to maximize throughput
//! on multi-core systems. Transaction signatures and range proofs are verified
//! concurrently when validating blocks.

use super::{Block, BlockHeader};
use super::pow::verify_pow;
use super::difficulty::max_target;
use crate::primitives::{Hash, merkle_root, Amount};
use crate::storage::UtxoSet;
use crate::transaction::{Transaction, TxType};
use crate::emission::calculate_block_reward;
use crate::error::{Error, Result};
use crate::constants::{
    MAX_BLOCK_SIZE, MAX_TXS_PER_BLOCK,
    block_version_at_height, MAX_TIMESTAMP_DRIFT,
    MIN_FEE_PER_BYTE,
};
use super::fee_market::{congestion_multiplier, distribute_fee};

use rayon::prelude::*;
use std::sync::atomic::{AtomicBool, Ordering};

fn allow_checkpoint_crypto_skip() -> bool {
    std::env::var("COINCYNC_ALLOW_CHECKPOINT_CRYPTO_SKIP")
        .ok()
        .map(|v| {
            let t = v.trim();
            t == "1" || t.eq_ignore_ascii_case("true") || t.eq_ignore_ascii_case("yes")
        })
        .unwrap_or(false)
}

/// Block validation result
#[derive(Clone, Debug)]
pub struct BlockValidation {
    pub valid: bool,
    pub errors: Vec<String>,
    pub warnings: Vec<String>,
}

impl BlockValidation {
    pub fn ok() -> Self {
        BlockValidation {
            valid: true,
            errors: vec![],
            warnings: vec![],
        }
    }

    pub fn error(msg: impl Into<String>) -> Self {
        BlockValidation {
            valid: false,
            errors: vec![msg.into()],
            warnings: vec![],
        }
    }

    pub fn add_error(&mut self, msg: impl Into<String>) {
        self.errors.push(msg.into());
        self.valid = false;
    }

    pub fn add_warning(&mut self, msg: impl Into<String>) {
        self.warnings.push(msg.into());
    }
}

/// Validate a block.
///
/// If `checkpoint_height` is Some and the block height is at or below it,
/// the expensive VDF anchor recomputation is skipped (Bitcoin-style "assume-valid").
/// The block hash was already verified against the checkpoint chain, so PoW is
/// implicitly trusted. This makes IBD 10-100x faster.
pub fn validate_block(
    block: &Block,
    prev_block: Option<&Block>,
    utxos: &UtxoSet,
) -> Result<BlockValidation> {
    validate_block_with_checkpoint(block, prev_block, utxos, None)
}

/// Validate a block with optional checkpoint-based PoW skip.
///
/// **Monero-style fast sync**: When `checkpoint_height` is Some and the block
/// height is at or below it, ALL expensive cryptographic verification is
/// skipped — not just PoW/VDF, but also CLSAG ring signatures, Bulletproofs
/// range proofs, balance proofs, and asset surjection proofs. Only structural
/// checks are performed (header chain, height, coinbase amount, merkle root,
/// timestamps). This is safe because:
/// 1. The block hash was already verified against the checkpoint chain
/// 2. If any transaction were invalid, the block hash would differ
/// 3. Monero uses this exact pattern for blocks below hardcoded checkpoints
#[tracing::instrument(
    skip(block, prev_block, utxos),
    fields(
        height = block.header.height,
        tx_count = block.transactions.len(),
    )
)]
pub fn validate_block_with_checkpoint(
    block: &Block,
    prev_block: Option<&Block>,
    utxos: &UtxoSet,
    checkpoint_height: Option<u64>,
) -> Result<BlockValidation> {
    // Backward-compatible entry point for legacy callers that don't pass a
    // runtime network. Core chain validation should call
    // `validate_block_with_checkpoint_for_network`.
    #[cfg(feature = "testnet")]
    let expected_network = crate::config::NetworkType::Testnet;
    #[cfg(not(feature = "testnet"))]
    let expected_network = crate::config::NetworkType::Mainnet;

    validate_block_with_checkpoint_for_network(
        block,
        prev_block,
        utxos,
        checkpoint_height,
        expected_network,
    )
}

pub fn validate_block_with_checkpoint_for_network(
    block: &Block,
    prev_block: Option<&Block>,
    utxos: &UtxoSet,
    checkpoint_height: Option<u64>,
    expected_network: crate::config::NetworkType,
) -> Result<BlockValidation> {
    let mut result = BlockValidation::ok();

    // SECURITY (NetworkTag): FIRST CHECK — reject wrong-network blocks before
    // any expensive crypto. A 4-byte comparison that catches misconfigured peers,
    // cross-network attacks, and testnet/mainnet contamination instantly.
    //
    // FIX #43: check against THIS node's specific network magic, not just
    // "any known network". Previously a testnet node would accept a mainnet
    // block as having "valid magic" (because mainnet is also a known
    // network) — providing no defense against cross-network contamination.
    // Now we compare against the compile-time-selected expected magic.
    // Genesis blocks (height 0) with zero magic are accepted for backwards compat.
    if block.header.network_magic != [0u8; 4] || block.height() > 0 {
        let expected_magic = expected_network.magic_bytes();

        if block.header.network_magic != expected_magic {
            result.add_error(format!(
                "Wrong network magic {:?} — expected {:?} (this is a {} node)",
                block.header.network_magic,
                expected_magic,
                expected_network.name()
            ));
            return Ok(result);
        }
    }

    // CONSENSUS CHECKPOINT (CIP-009 Path B) — hard reorg defense.
    //
    // The `CONSENSUS_CHECKPOINTS` table in `constants.rs` carries
    // hardcoded (height, block_hash) pairs that ALL honest nodes
    // refuse to contradict. If a block at one of those heights
    // proposes a different hash, reject the whole block here, before
    // any expensive cryptographic verification — the attacker has
    // already failed.
    //
    // Distinct from the "fast-sync" `checkpoint_height` parameter
    // below, which controls whether to SKIP crypto for blocks under
    // a known-good ancestor. Consensus checkpoints REJECT chains
    // that rewrite past them; fast-sync checkpoints just speed up
    // verification of blocks below them. Both can be active
    // simultaneously and they don't interfere.
    //
    // Genesis (height 0) is exempt by construction: the table can
    // include height 0 if desired, but a chain whose genesis differs
    // from a recorded checkpoint would never have produced a block
    // we'd be validating in the first place.
    if let Some(expected_hash) = crate::constants::expected_checkpoint_hash(block.height()) {
        let actual_hash = block.hash();
        if actual_hash.as_bytes() != expected_hash {
            result.add_error(format!(
                "consensus checkpoint mismatch at height {}: \
                 expected {} but got {} — refusing to accept reorg \
                 chain that contradicts a hardcoded checkpoint",
                block.height(),
                hex::encode(expected_hash),
                hex::encode(actual_hash.as_bytes()),
            ));
            return Ok(result);
        }
    }

    // Determine if we're in fast-sync mode (below checkpoint)
    let fast_sync_requested = checkpoint_height
        .map(|cp| block.height() <= cp)
        .unwrap_or(false);
    let fast_sync = fast_sync_requested && allow_checkpoint_crypto_skip();

    // Validate header
    validate_header(&block.header, prev_block.map(|b| &b.header), &mut result);

    // CRITICAL SECURITY: Validate Proof of Work
    // Skip PoW verification for genesis block (height 0)
    if block.height() > 0 {
        if let Some(prev) = prev_block {
            // Bitcoin-style "assume-valid": skip expensive VDF recomputation
            // for blocks below the last verified checkpoint. The block hash
            // was already validated against the checkpoint chain.
            if fast_sync {
                tracing::trace!("Block {} PoW skipped (below checkpoint {})",
                    block.height(), checkpoint_height.unwrap_or(0));
            } else if fast_sync_requested {
                tracing::warn!(
                    "Checkpoint crypto skip requested but disabled by policy at height {}. \
                     Set COINCYNC_ALLOW_CHECKPOINT_CRYPTO_SKIP=1 only for explicitly trusted bootstrap flows.",
                    block.height()
                );
            } else {
                // Full PoW verification including VDF anchor recomputation
                match verify_pow(
                    &prev.header.hash(),
                    block.height(),
                    block.header.timestamp,
                    block.header.nonce,
                    &block.header.tx_root,
                    &block.header.target,
                    &block.header.anchor,
                    block.header.algorithm,
                ) {
                    Ok(()) => {
                        tracing::debug!("Block {} PoW verified successfully", block.height());
                    }
                    Err(e) => {
                        result.add_error(format!("Proof of work validation error: {}", e));
                    }
                }
            }

            // CRITICAL: Verify difficulty target is correct for this height
            // This prevents miners from using artificially easy targets
            validate_difficulty_target(block, prev_block, &mut result);
        } else {
            // Non-genesis block without parent - already caught in header validation
            // but we add explicit PoW error too
            result.add_error("Cannot verify PoW without previous block");
        }
    }

    // Validate size
    let size = block.size();
    if size > MAX_BLOCK_SIZE {
        result.add_error(format!("Block too large: {} > {}", size, MAX_BLOCK_SIZE));
    }

    // SECURITY: Block weight validation that accounts for ring signature verification cost.
    // Ring signatures are O(ring_size) to verify, so a block with many high-ring-size txs
    // takes disproportionately long to validate relative to its byte size.
    // Weight = sum of (ring_members_count * RING_SIG_WEIGHT + byte_size) per tx.
    // Maximum weight is 4x the max block size (prevents CPU-exhaustion attacks).
    //
    // FIX #46: run the weight check UNCONDITIONALLY, not only outside
    // fast-sync. The weight check is a pure structural check — it has no
    // cryptographic cost; it's just arithmetic over sizes and ring
    // counts. Fast-sync is exactly the path where DoS risk is HIGHEST
    // (block throughput is maximised) and where a cheap pre-flight
    // check is most valuable. Only the CRYPTOGRAPHIC verification
    // (CLSAG, range proofs, signatures) should skip below the
    // checkpoint via the separate `fast_sync` branches below.
    {
        const RING_SIG_WEIGHT: usize = 256; // ~cost of verifying one ring member
        const MAX_BLOCK_WEIGHT: usize = MAX_BLOCK_SIZE * 4;

        let block_weight: usize = block.transactions.iter().map(|tx| {
            let ring_members: usize = tx.inputs.iter()
                .map(|input| input.ring_members.len())
                .sum();
            tx.size() + ring_members * RING_SIG_WEIGHT
        }).sum();

        if block_weight > MAX_BLOCK_WEIGHT {
            result.add_error(format!(
                "Block weight too high: {} > {} (ring sig verification cost exceeds limit)",
                block_weight, MAX_BLOCK_WEIGHT
            ));
        }
    }

    // Validate transaction count
    if block.transactions.len() > MAX_TXS_PER_BLOCK {
        result.add_error(format!(
            "Too many transactions: {} > {}",
            block.transactions.len(),
            MAX_TXS_PER_BLOCK
        ));
    }

    // Validate has coinbase
    if block.transactions.is_empty() {
        result.add_error("Missing coinbase transaction");
        return Ok(result);
    }

    // First transaction must be coinbase (using safe access)
    match block.transactions.first() {
        Some(first_tx) if !first_tx.is_coinbase() => {
            result.add_error("First transaction must be coinbase");
        }
        None => {
            // Should not reach here due to earlier empty check, but be safe
            result.add_error("Block has no transactions");
        }
        _ => {} // First tx is valid coinbase
    }

    // Validate merkle root
    let tx_hashes: Vec<Hash> = block.transactions.iter().map(|tx| tx.hash()).collect();
    let computed_root = merkle_root(&tx_hashes);
    if computed_root != block.header.tx_root {
        result.add_error("Invalid merkle root");
    }

    // Stage 6 (Constitution Article III — Mandatory Privacy): every
    // non-coinbase tx must have Pedersen-committed amounts, a stealth
    // address, and at least one privacy-preserving input. Rejection is
    // structural and fast — no ring-sig / range-proof verification is
    // performed here, only field-shape checks that catch transparent or
    // naked transactions before the expensive crypto runs.
    if let Err(e) = crate::consensus::privacy_policy::enforce_privacy_policy(block) {
        result.add_error(format!("Privacy policy violation: {}", e));
    }

    // Validate coinbase reward
    let expected_reward = calculate_block_reward(block.height());
    let total_fees: Amount = block.transactions.iter()
        .skip(1) // Skip coinbase
        .map(|tx| tx.fee)
        .sum();

    // SECURITY: After FEE_DISTRIBUTION_HEIGHT, enforce miner/burn/protocol split.
    // Before activation, miners claim all fees (backward compatible).
    // SECURITY (BUG-8): Pure integer congestion check for max_coinbase.
    //
    // M4 (audit fix): use `checked_add` instead of `saturating_add`. Saturating
    // arithmetic silently clamps overflow to `Amount::MAX` — an attacker
    // crafting a block with `total_fees` near u64::MAX could exploit the silent
    // clamp to claim a coinbase much larger than the legal maximum without
    // tripping any validation. With `checked_add`, the overflow is rejected
    // outright via `Error::AmountOverflow`, classified by the IronConsensus
    // classifier as `IronVerdict::Bad`, and the peer is struck.
    let max_coinbase = if block.height() >= crate::constants::FEE_DISTRIBUTION_HEIGHT && total_fees.as_atomic() > 0 {
        let congestion_pct = ((size as u128 * 100) / MAX_BLOCK_SIZE as u128) as u64;
        let congested = congestion_pct >= crate::constants::CONGESTION_THRESHOLD;
        let dist = distribute_fee(total_fees, congested);
        match expected_reward.checked_add(dist.to_miner) {
            Ok(v) => v,
            Err(_) => {
                result.add_error(format!(
                    "Coinbase max overflow: reward={} + miner_share={} > u64::MAX",
                    expected_reward.as_atomic(), dist.to_miner.as_atomic()
                ));
                return Ok(result);
            }
        }
    } else {
        match expected_reward.checked_add(total_fees) {
            Ok(v) => v,
            Err(_) => {
                result.add_error(format!(
                    "Coinbase max overflow: reward={} + total_fees={} > u64::MAX",
                    expected_reward.as_atomic(), total_fees.as_atomic()
                ));
                return Ok(result);
            }
        }
    };

    // H6: Defense-in-depth tail supply check.
    // After year 12 (tail phase), the reward must not exceed TAIL_EMISSION.
    if block.height() > crate::constants::BLOCKS_PER_YEAR * 12 {
        if expected_reward.as_atomic() > crate::constants::TAIL_EMISSION {
            result.add_error(format!(
                "Tail phase reward {} exceeds TAIL_EMISSION {} at height {}",
                expected_reward.as_atomic(),
                crate::constants::TAIL_EMISSION,
                block.height()
            ));
        }
    }

    if let Some(coinbase) = block.coinbase() {
        // Coinbase output validation
        if coinbase.outputs.is_empty() {
            result.add_error("Coinbase has no outputs");
        }

        // Coinbase must not have inputs (except the null coinbase input marker)
        if !coinbase.inputs.is_empty() && !coinbase.is_coinbase() {
            result.add_error("Coinbase transaction has invalid inputs");
        }

        // Verify output count is reasonable
        let max_outputs = 16;
        if coinbase.outputs.len() > max_outputs {
            result.add_error(format!(
                "Coinbase has too many outputs: {} (max {})",
                coinbase.outputs.len(),
                max_outputs
            ));
        }

        // SECURITY: Reject coinbase dust outputs that bloat the UTXO set.
        // With N coinbase outputs, each must receive at least MIN_OUTPUT_AMOUNT
        // to prevent miners from creating unspendable micro-outputs.
        if coinbase.outputs.len() > 1 {
            let min_per_output = crate::constants::MIN_OUTPUT_AMOUNT;
            let min_total = min_per_output.saturating_mul(coinbase.outputs.len() as u64);
            if max_coinbase.as_atomic() < min_total {
                result.add_error(format!(
                    "Coinbase splits into {} outputs but reward {} is too small \
                     (need at least {} per output = {} total)",
                    coinbase.outputs.len(),
                    max_coinbase,
                    min_per_output,
                    min_total
                ));
            }
        }

        // CRITICAL: Verify coinbase reward doesn't exceed allowed amount
        // For privacy coins, coinbase outputs use zero blinding factor since
        // the reward is publicly known. We verify each output commitment.
        //
        // Sum of coinbase output commitments must equal commitment to max_coinbase
        // with zero blinding factor.
        //
        // MONERO-STYLE FAST SYNC: Skip Pedersen commitment verification below
        // checkpoint — the block hash already guarantees integrity.
        use crate::crypto::{PedersenCommitment, BlindingFactor};
        use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
        use curve25519_dalek::traits::Identity;

        // Skip genesis block (height 0) which has placeholder commitments
        // Also skip below checkpoint (fast sync mode)
        if block.height() > 0 && !fast_sync {
            // SECURITY (C19-FIX): Verify EACH coinbase output individually, not just the sum.
            // Previously only the sum of commitments was checked against commit(max_coinbase, 0).
            // A miner could use non-zero blinding factors that cancel in sum (b1 + b2 = 0),
            // hiding arbitrary per-output amounts while the sum appeared correct.
            // Like Monero's RCTTypeNull enforcement, coinbase outputs must be transparent:
            // each commitment must equal commit(declared_amount, zero_blinding).
            let mut total_declared: u64 = 0;
            let mut all_valid = true;

            // v1.0.12 audit-follow-up #5 (backport of v1.0.12-release
            // 3507a1cd): coinbase encrypted_amount must be exactly 8
            // bytes post-fork. Honest coinbase construction always
            // emits exactly 8 (LE u64). The pre-fork `>= 8` silently
            // accepted longer payloads and used only the first 8
            // bytes — bounded chain bloat that compounds across every
            // block forever. Tightened at HARD_FORK_V1_0_12_HEIGHT.
            let v1_0_12_active = block.header.height >= crate::constants::HARD_FORK_V1_0_12_HEIGHT;
            for (idx, output) in coinbase.outputs.iter().enumerate() {
                // Extract declared amount from encrypted_amount field
                // (coinbase uses plaintext amount since reward is public)
                let length_ok = if v1_0_12_active {
                    output.encrypted_amount.len() == 8
                } else {
                    output.encrypted_amount.len() >= 8
                };
                let declared_amount = if length_ok {
                    let mut bytes = [0u8; 8];
                    bytes.copy_from_slice(&output.encrypted_amount[..8]);
                    u64::from_le_bytes(bytes)
                } else {
                    let expected_msg = if v1_0_12_active { "exactly 8 bytes" } else { "8 bytes" };
                    result.add_error(format!(
                        "Coinbase output {} has invalid amount encoding (expected {}, got {})",
                        idx, expected_msg, output.encrypted_amount.len()
                    ));
                    all_valid = false;
                    continue;
                };

                // SECURITY (C19-FIX): Verify this output's commitment equals
                // commit(declared_amount, zero_blinding). This prevents the blinding
                // trick where non-zero blindings cancel in sum.
                let expected_commitment = PedersenCommitment::commit(
                    declared_amount,
                    &BlindingFactor::zero(),
                );

                let expected_bytes = expected_commitment.as_point().as_bytes();
                if output.commitment != *expected_bytes {
                    result.add_error(format!(
                        "Coinbase output {} commitment mismatch: declared {} atomic units \
                         but commitment doesn't match commit(amount, zero_blinding). \
                         Possible inflation attack via non-zero blinding factor.",
                        idx, declared_amount
                    ));
                    all_valid = false;
                }

                // Verify commitment is a valid curve point and not identity
                match CompressedRistretto(output.commitment).decompress() {
                    Some(point) if point == RistrettoPoint::identity() => {
                        result.add_error(format!(
                            "Coinbase output {} has zero commitment (identity point)", idx
                        ));
                        all_valid = false;
                    }
                    None => {
                        result.add_error(format!(
                            "Coinbase output {} has invalid commitment (not on curve)", idx
                        ));
                        all_valid = false;
                    }
                    _ => {}
                }

                // FIX #41: use checked_add. Previously a coinbase with
                // outputs that summed past u64::MAX silently clamped to
                // u64::MAX via saturating_add. Combined with an upstream
                // overflow in max_coinbase (also fixed with checked_add
                // above), the comparison `total_declared != max_coinbase`
                // could be bypassed with both sides saturating to the
                // same u64::MAX value — allowing arbitrary inflation.
                // Treat an overflow as an explicit validation error with
                // an AmountOverflow signal for peer classification.
                match total_declared.checked_add(declared_amount) {
                    Some(next) => total_declared = next,
                    None => {
                        result.add_error(format!(
                            "Coinbase output sum overflow at output {} — possible inflation attack",
                            idx
                        ));
                        all_valid = false;
                        break;
                    }
                }
            }

            // Verify total declared amount matches expected coinbase exactly
            if all_valid {
                if total_declared != max_coinbase.as_atomic() {
                    result.add_error(format!(
                        "Coinbase total {} doesn't match expected {} (reward {} + fees {}). \
                         Miners must claim exactly the allowed amount.",
                        total_declared, max_coinbase.as_atomic(),
                        expected_reward, total_fees
                    ));
                }
            }
        }

        tracing::debug!(
            "Block {} coinbase verified: max {} (reward: {} + fees: {})",
            block.height(),
            max_coinbase,
            expected_reward,
            total_fees
        );
    }

    // SECURITY: Check for duplicate transaction hashes within this block.
    // A malicious miner could attempt to include the same transaction twice
    // to double-count fees or cause state inconsistencies.
    //
    // FIX #48: reuse `tx_hashes` computed earlier for the merkle-root
    // check rather than calling `tx.hash()` a second time per transaction.
    // For a large block (~5000 txs) this halves the hashing work in the
    // dedup path — hashing is cheap per tx but the savings compound
    // during IBD. Note: `tx_hashes` is computed above (~line 259) and
    // is still in scope here.
    let mut seen_tx_hashes = std::collections::HashSet::new();
    for hash in &tx_hashes {
        if !seen_tx_hashes.insert(*hash) {
            result.add_error("Duplicate transaction hash in block".to_string());
        }
    }

    // SECURITY: Two-phase key image validation:
    //
    // Phase 1 (here): Check for duplicate key images WITHIN this block
    // - Fast O(n) check using HashSet
    // - Rejects blocks with internal double-spends early
    // - Avoids expensive cryptographic verification on obviously invalid blocks
    //
    // Phase 2 (in validate_transaction): Check against GLOBAL UTXO set
    // - Verifies each key image isn't already spent in the chain
    // - Done via utxos.contains_key_image() in validate_transaction
    // - Catches attempts to spend already-spent outputs
    //
    // Both phases are required for full security.
    let mut seen_key_images = std::collections::HashSet::new();
    for tx in &block.transactions {
        for ki in tx.key_images() {
            if !seen_key_images.insert(ki) {
                result.add_error(format!("Duplicate key image in block: {}", ki));
            }
        }
    }

    // v1.0.12 protocol upgrade (gated by HARD_FORK_V1_0_12_HEIGHT):
    // reject blocks where two distinct txs create the same stealth
    // address as an output.
    //
    // The dup-stealth check inside `validate_transaction` catches:
    // (a) duplicates within a single tx via an in-tx HashSet,
    // (b) clash with any already-on-chain output via
    // `utxos.get_output_index_entry`. It does NOT catch CROSS-TX-
    // WITHIN-BLOCK clashes — tx1 and tx2 each create an output with
    // stealth X, neither X is in the UTXO yet at validation time,
    // and `validate_transaction` runs in parallel across txs so
    // they cannot see each other's new outputs.
    //
    // Without this check, block-apply would `or_insert` index tx1's
    // output X and silently drop tx2's output X from
    // stealth_index/output_index — silent-output-loss + CLSAG
    // forgery-path via wrong-commitment ring lookup against tx2's
    // "shadowed" output. Backport of v1.0.12-release commit cfc680b7.
    //
    // Strictly tightening: any block accepted under this check is
    // also acceptable under the pre-fork rules. Honest wallets
    // generate Diffie-Hellman-derived per-output stealth addresses
    // (effectively random); no honest block was ever produced with a
    // clash. Activation deferred until HARD_FORK_V1_0_12_HEIGHT is
    // set away from u64::MAX in a coordinated deploy.
    if block.header.height >= crate::constants::HARD_FORK_V1_0_12_HEIGHT {
        let mut seen_block_outputs = std::collections::HashSet::new();
        for (tx_idx, tx) in block.transactions.iter().enumerate() {
            for (out_idx, output) in tx.outputs.iter().enumerate() {
                let addr_bytes = *output.stealth_address.as_bytes();
                if !seen_block_outputs.insert(addr_bytes) {
                    result.add_error(format!(
                        "Cross-tx duplicate stealth address in block at tx {} output {}",
                        tx_idx, out_idx
                    ));
                }
            }
        }
    }

    // If there are duplicate key images (or cross-tx dup stealth
    // addresses, post v1.0.12 activation), fail fast before expensive
    // validation
    if !result.valid {
        return Ok(result);
    }

    // SECURITY: Validate dynamic fees based on block congestion.
    // Static minimum (size * MIN_FEE_PER_BYTE) is always required, but when the
    // block is heavily utilized, transactions must pay the congestion premium.
    // This prevents miners from filling blocks with below-market-rate transactions.
    //
    // MONERO-STYLE FAST SYNC: Skip fee validation below checkpoint.
    if block.height() > 0 && !fast_sync {
        // SECURITY (BUG-8): Pure integer arithmetic for consensus-critical fee
        // validation. Previously used f64 which is non-deterministic across CPU
        // architectures, risking consensus forks at boundary values.
        // Congestion thresholds: <50% → 1x, <75% → 1.5x, <90% → 2x, >=90% → 3x
        // Expressed as size * 100 / MAX_BLOCK_SIZE (percent, integer).
        //
        // CONSENSUS-DEDUP (2026-05-24): the multiplier is now sourced from
        // `fee_market::congestion_multiplier` rather than an inlined
        // duplicate table. Both the validator and the wallet/RPC fee
        // estimators MUST agree on the bucket boundaries — any divergent
        // edit would manifest as the validator rejecting every transaction
        // in blocks near a congestion boundary while wallets thought their
        // fees were sufficient (a consensus-fork-flavored failure mode).
        // The returned value is multiplier × 100 (100/150/200/300); the
        // prior inlined table used × 10 (10/15/20/30). The arithmetic is
        // bit-identical because `q * (mul*10) / 10` and `q * (mul*100) / 100`
        // produce the same floor-divided integer for any q where the
        // multiplication doesn't approach u64::MAX (the `checked_mul`
        // chain catches that case identically).
        let congestion_pct: u64 = ((size as u128 * 100) / MAX_BLOCK_SIZE as u128) as u64;
        let multiplier_x100: u64 = congestion_multiplier(congestion_pct);

        for (idx, tx) in block.transactions.iter().enumerate().skip(1) {
            let tx_size = tx.size() as u64;
            // FIX #42: use checked_mul. Previously saturating_mul silently
            // clamped to u64::MAX on overflow, producing a `dynamic_min`
            // of ~1.8e18 — well above any realistic fee. The fee-low
            // check then rejected every transaction in the block with a
            // misleading error message. Treating overflow as an explicit
            // oversized-transaction error surfaces the real problem.
            let dynamic_min = match tx_size
                .checked_mul(MIN_FEE_PER_BYTE)
                .and_then(|v| v.checked_mul(multiplier_x100))
                .map(|v| v / 100)
            {
                Some(v) => v,
                None => {
                    result.add_error(format!(
                        "Transaction {} fee calculation overflow (tx size {} too large for fee computation)",
                        idx, tx_size
                    ));
                    continue;
                }
            };
            if tx.fee.as_atomic() < dynamic_min {
                result.add_error(format!(
                    "Transaction {} fee too low for congestion: {} < {} (congestion {}%, multiplier {}x/100)",
                    idx, tx.fee.as_atomic(), dynamic_min,
                    congestion_pct, multiplier_x100
                ));
            }
        }

        // Validate coinbase fee distribution (miner/burn/protocol split).
        // The coinbase must claim fees according to the distribution rules,
        // preventing miners from keeping 100% of fees and bypassing the burn.
        // SECURITY (BUG-8): Use integer congestion_pct instead of f64
        let congested = congestion_pct >= crate::constants::CONGESTION_THRESHOLD;
        let dist = distribute_fee(total_fees, congested);

        // Log fee distribution for monitoring. Enforcement is now handled at the
        // coinbase validation level (max_coinbase uses dist.to_miner after activation).
        let _max_miner_coinbase = expected_reward.saturating_add(dist.to_miner);
        if total_fees.as_atomic() > 0 {
            tracing::debug!(
                "Block {} fee distribution: total={}, miner={}, burn={}, protocol={}, congested={}",
                block.height(), total_fees, dist.to_miner, dist.burned, dist.to_protocol, congested
            );
        }
    }

    // Validate non-coinbase transactions in parallel
    // Cryptographic verification (ring signatures, range proofs) is CPU-intensive
    // and can be parallelized since each transaction is independent.
    // NOTE: This also performs Phase 2 key image validation (global check).
    //
    // MONERO-STYLE FAST SYNC: Below checkpoint height, skip ALL expensive
    // cryptographic verification (CLSAG, Bulletproofs, balance proofs, ASP).
    // The block hash was already verified against the checkpoint, so if any
    // transaction were tampered with, the merkle root (and thus block hash)
    // would differ. Only structural checks (duplicate coinbase, key image
    // uniqueness within block) are still performed above.
    if fast_sync {
        tracing::trace!(
            "Block {} tx crypto skipped (below checkpoint {}): {} txs",
            block.height(),
            checkpoint_height.unwrap_or(0),
            block.transactions.len().saturating_sub(1),
        );
        // Still check for multiple coinbase transactions
        for (idx, tx) in block.transactions.iter().enumerate().skip(1) {
            if tx.is_coinbase() {
                result.add_error(format!("Invalid transaction {}: Multiple coinbase transactions", idx));
            }
        }
    } else {
        let tx_errors: Vec<(usize, String)> = block.transactions
            .par_iter()
            .enumerate()
            .skip(1) // Skip coinbase
            .filter_map(|(idx, tx)| {
                if tx.is_coinbase() {
                    return Some((idx, "Multiple coinbase transactions".to_string()));
                }

                match validate_transaction(tx, utxos, block.height()) {
                    Ok(_) => None,
                    Err(e) => Some((idx, e.to_string())),
                }
            })
            .collect();

        // Add all transaction errors to result
        for (idx, error) in tx_errors {
            result.add_error(format!("Invalid transaction {}: {}", idx, error));
        }
    }

    Ok(result)
}

/// Validate block header
fn validate_header(
    header: &BlockHeader,
    prev_header: Option<&BlockHeader>,
    result: &mut BlockValidation,
) {
    // FIX #47: treat block_version_at_height as a MINIMUM, not a strict
    // equality. Previously the check `header.version != expected_version`
    // rejected any version-bump block mined the block before the fork
    // activation: a miner producing a V2 block at (activation_height - 1)
    // would be rejected by this gate even though the block is otherwise
    // valid for the upgrade. Accepting any version >= min allows smooth
    // activation; downgrades (version < min) are still rejected.
    let min_version = block_version_at_height(header.height);
    if header.version < min_version {
        result.add_error(format!(
            "Block version {} below minimum {} for height {}",
            header.version, min_version, header.height
        ));
    }

    // Check against previous header
    if let Some(prev) = prev_header {
        // SECURITY: Block version cannot decrease (prevent downgrade attacks)
        if header.version < prev.version {
            result.add_error(format!(
                "Block version cannot decrease: v{} -> v{}",
                prev.version, header.version
            ));
        }
        // Height must be exactly one more
        if header.height != prev.height + 1 {
            result.add_error(format!(
                "Invalid height: expected {}, got {}",
                prev.height + 1,
                header.height
            ));
        }

        // Previous hash must match
        if header.prev_hash != prev.hash() {
            result.add_error("Previous hash mismatch");
        }

        // Timestamp must be greater than previous
        // SECURITY: This check, combined with the height-by-height validation during
        // block processing, ensures chain-wide timestamp monotonicity by induction:
        // - Each new block must have timestamp > previous block
        // - Therefore: block[n].timestamp > block[n-1].timestamp > ... > block[0].timestamp
        //
        // During reorganizations, the new chain is validated block-by-block from the
        // fork point, ensuring monotonicity is maintained on the new chain as well.
        if header.timestamp <= prev.timestamp {
            result.add_error("Timestamp not greater than previous block");
        }
    } else {
        // Genesis block checks
        if header.height != 0 {
            result.add_error("Non-genesis block without parent");
        }
    }

    // SECURITY (CC-L1): Validate checkpoint_vote if present.
    // Checkpoint vote must reference a height that already exists (not future).
    if let Some((cp_height, _cp_hash)) = &header.checkpoint_vote {
        if *cp_height >= header.height {
            result.add_error(format!(
                "checkpoint_vote references future height {} (block height {})",
                cp_height, header.height
            ));
        }
    }

    // Check timestamp is not too far in future
    // SECURITY: System time failure must not allow timestamp bypass
    let current_time = match std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH) {
        Ok(d) => d.as_secs(),
        Err(e) => {
            // System clock is before UNIX epoch - this is a critical error
            result.add_error(format!("System clock error: {}. Cannot validate block timestamps.", e));
            return; // Cannot proceed with timestamp validation
        }
    };

    // Sanity check: current time should be reasonably recent (after 2020)
    const MIN_REASONABLE_TIME: u64 = 1577836800; // 2020-01-01 00:00:00 UTC
    if current_time < MIN_REASONABLE_TIME {
        result.add_warning("System clock appears to be set incorrectly (before 2020)");
    }

    // SECURITY: exempt the genesis block (height = 0) from the
    // future-timestamp check. The genesis timestamp is a protocol constant
    // that ships hardcoded in the binary (see `testnet_genesis()` and
    // `mainnet_genesis()`), and trust in that constant is established by
    // the hardcoded `{TESTNET,MAINNET}_GENESIS_HASH` bytes + the hash-match
    // check in `Blockchain::init_genesis`. Mainnet genesis in particular
    // intentionally carries a future-dated activation timestamp (the launch
    // date) and must not be rejected on pre-launch clock comparisons.
    // Non-genesis blocks are still bounded by `MAX_TIMESTAMP_DRIFT`.
    //
    // SPEC: the bound is INCLUSIVE — `timestamp == current_time +
    // MAX_TIMESTAMP_DRIFT` is accepted, only strictly-greater is
    // rejected. Matches Bitcoin Core's `nMaxFutureBlockTime` semantics
    // (pow.cpp) and the NTP/RFC 5905 convention where the drift bound
    // IS the tolerable window, not one tick less. Switching to `>=`
    // would reject legitimate blocks whose timestamp exactly hits the
    // boundary, with no security gain.
    if header.height > 0 && header.timestamp > current_time + MAX_TIMESTAMP_DRIFT {
        result.add_error("Block timestamp too far in future");
    }
}

/// Validate that block's difficulty target is correct — INTENTIONALLY LOOSE
/// sanity gate, paired with the strict ASERT check at the chain level.
///
/// ## Two-layer difficulty-validation design
///
/// CoinCync validates a block's difficulty target in two independent passes:
///
/// 1. **Sanity gate (this function)** — runs inside
///    `validate_block_with_checkpoint_for_network` with access to only
///    `block` and `prev_block`. Catches gross manipulation (~32x swing
///    normal, ~256x emergency) that no legitimate ASERT step could
///    produce. Bounds are intentionally LOOSE because ASERT's own 2x
///    per-block clamp can produce apparent inter-block ratios up to
///    ~16x when consecutive blocks both sit at clamp boundaries — a
///    tighter sanity check here would false-reject those legitimate
///    edge cases.
///
/// 2. **Strict ASERT enforcement (chain.rs, `Blockchain::add_block`)** —
///    runs WITH access to the full difficulty window (8 short, 144 long
///    blocks of history). Computes the exact canonical target and
///    requires bit-for-bit equality. This is the authoritative
///    enforcement.
///
/// Removing this function — or weakening it — leaves only the chain-
/// level check. That's structurally fine for security (chain-level
/// enforces exact ASERT) but loses defense-in-depth: a bug in the
/// chain-level path would have nothing catching it. Keep both layers.
///
/// A previous "TODO: Delete" comment on this function was misleading;
/// the function isn't dead code, it's a defense-in-depth sanity check
/// by design. (2026-06-03 critical-file-review clarification.)
///
/// ## Checks performed
///
/// 1. Target must not be easier than `max_target` (effectively dead
///    code today because `max_target = [0xFF; 32]`, but kept as a
///    forward-compat assertion in case the constant tightens).
/// 2. Target must be non-zero (would mean impossibly hard, which is
///    not a legitimate ASERT output).
/// 3. Target-to-prev-target ratio is within sanity bounds: ~32x normal,
///    ~256x emergency (when block time > 5x expected).
///
/// Compared to the strict ASERT check this is approximately 16x looser
/// — that gap is intentional, sized to never false-reject a legitimate
/// boundary-clamped sequence.
fn validate_difficulty_target(
    block: &Block,
    prev_block: Option<&Block>,
    result: &mut BlockValidation,
) {
    let target = &block.header.target;

    // Check 1: Target must not be easier than max_target.
    //
    // Use the same u128 path as the adjustment-ratio check below
    // (line ~862) so the two comparisons can't drift. The previous
    // bytewise `target.as_bytes() > max.as_bytes()` was mathematically
    // equivalent only while max_target = [0xFF; 32] (in which case the
    // check is dead code — no 32-byte value can be lexicographically
    // greater than all-0xFF). If max_target is ever lowered, bytewise
    // comparison would consider bytes [16..32] which target_to_u128
    // ignores, and the two checks would disagree.
    let max = max_target();
    let target_value = target_to_u128(target.as_bytes());
    let max_value = target_to_u128(max.as_bytes());
    if target_value > max_value {
        result.add_error("Target easier than max_target (minimum difficulty)");
        return;
    }

    // Check 2: Target must be non-zero (would be impossibly hard)
    if target.as_bytes().iter().all(|&b| b == 0) {
        result.add_error("Target is zero (impossible difficulty)");
        return;
    }

    // Check 3: If we have previous block, verify adjustment ratio is within bounds.
    // Uses u128 target values for precision instead of the previous leading-zero
    // heuristic which was too coarse (2-bit tolerance allowed ~4x manipulation).
    if let Some(prev) = prev_block {
        let target_value = target_to_u128(target.as_bytes());
        let prev_value = target_to_u128(prev.header.target.as_bytes());

        if prev_value > 0 && target_value > 0 {
            // Compute ratio as (target * 1000) / prev without overflow.
            // When target_value is large (near u128::MAX), target_value * 1000 overflows.
            // The old approach of `(target / prev) * 1000` truncates to zero for any
            // ratio < 1.0 (e.g. 0.5x → 0 instead of 500), causing valid ASERT-clamped
            // blocks to be falsely rejected. Fix: shift both down by 10 bits first
            // (dividing by 1024), which preserves the ratio while keeping a * 1000 in range.
            let ratio_scaled = if target_value > u128::MAX / 1000 {
                // Scale both down proportionally to fit target * 1000 in u128.
                let a = target_value >> 10;
                let b = (prev_value >> 10).max(1);
                (a * 1000) / b
            } else {
                (target_value * 1000) / prev_value
            };

            // Normal bounds: target can change by at most 4x in either direction
            // 4x = ratio_scaled 4000, 0.25x = ratio_scaled 250
            let time_diff = block.header.timestamp.saturating_sub(prev.header.timestamp);
            let expected_time = crate::constants::TARGET_BLOCK_TIME;

            // NOTE: The sanity check here is intentionally loose because the exact
            // ASERT-computed target is enforced precisely in Blockchain::add_block().
            // This check only exists to catch wildly invalid targets (e.g. >32x swing).
            // The ASERT internal clamp (2x per block) combined with possible clamping
            // interactions can produce apparent ratios up to ~16x across two consecutive
            // blocks when the previous block itself was at a clamping boundary.
            let (min_ratio, max_ratio) = if time_diff >= expected_time * 5 {
                // Emergency: allow wide bounds for hashrate crash recovery
                (4, 256_000) // 0.004x to 256x
            } else {
                // Normal: sanity check allows up to 32x swing
                (31, 32_000) // 0.031x to 32x
            };

            if ratio_scaled < min_ratio || ratio_scaled > max_ratio {
                result.add_error(format!(
                    "Difficulty adjustment out of bounds: ratio {:.3}x (allowed {:.3}x to {:.1}x)",
                    ratio_scaled as f64 / 1000.0,
                    min_ratio as f64 / 1000.0,
                    max_ratio as f64 / 1000.0,
                ));
            }
        }
    }
}

/// Convert first 16 bytes of a 32-byte target hash to u128 for comparison
fn target_to_u128(bytes: &[u8; 32]) -> u128 {
    let mut buf = [0u8; 16];
    buf.copy_from_slice(&bytes[..16]);
    u128::from_be_bytes(buf)
}


/// Validate a transaction
#[tracing::instrument(
    skip(tx, utxos),
    fields(
        tx_hash = %tx.hash().to_hex(),
        inputs = tx.inputs.len(),
        outputs = tx.outputs.len(),
    )
)]
pub fn validate_transaction(
    tx: &Transaction,
    utxos: &UtxoSet,
    current_height: u64,
) -> Result<()> {
    // ── Version range enforcement ──────────────────────────────────────
    // Reject tx.version == 0 and tx.version > MAX_TX_VERSION.
    //
    // 2026-06-03 bug found during critical-file review: previously this
    // function only checked the V2 *activation* gate (below). The upper
    // bound and the version==0 reject lived ONLY in
    // `validate_transaction_basic`, which runs on mempool admission — not
    // on block validation. A miner could therefore include a tx with
    // version=0 or version=255 directly in a mined block; block
    // validation calls `validate_transaction` (see validate_block at
    // line ~698), which would let any future / unknown version through
    // as long as the crypto held.
    //
    // Why this matters for future hard forks: a v1.0 node receiving a
    // version=3 tx in a v1.1 block must NOT accept it (the on-wire shape
    // could differ across versions, and silent acceptance would split
    // consensus at the fork). With this gate, a future hard fork that
    // introduces version=3 must explicitly bump MAX_TX_VERSION in the
    // upgraded code — a flag-day rejection on stale nodes is the correct
    // behaviour. Coinbase included: a coinbase with version=99 was
    // previously waved through by the `is_coinbase()` early-return.
    if tx.version == 0 || tx.version > MAX_TX_VERSION {
        return Err(Error::InvalidTxVersion(tx.version));
    }

    // Coinbase has no inputs to validate
    if tx.is_coinbase() {
        return Ok(());
    }

    // ── Version enforcement ─────────────────────────────────────────────
    // V2 transactions are only valid at/above the activation height.
    // V1 transactions remain valid at all heights (backward compat).
    // Rejecting V2 below activation prevents pre-fork asset tx injection.
    if tx.version >= 2 && current_height < crate::constants::V2_TX_ACTIVATION_HEIGHT {
        return Err(Error::InvalidState(format!(
            "V2 transactions not allowed below activation height {} (current: {})",
            crate::constants::V2_TX_ACTIVATION_HEIGHT, current_height
        )));
    }
    // Must have inputs
    if tx.inputs.is_empty() {
        return Err(Error::InvalidInputCount { count: 0, max: crate::constants::MAX_TX_INPUTS });
    }

    // Must have outputs
    if tx.outputs.is_empty() {
        return Err(Error::InvalidOutputCount { count: 0, max: crate::constants::MAX_TX_OUTPUTS });
    }

    // v1.0.12 audit-follow-up #4 (backport of v1.0.12-release commit
    // 3507a1cd): non-coinbase output encrypted_amount must be exactly
    // 8 bytes post-fork. The XOR-masked u64 design (see
    // src/crypto/memo.rs) implies exactly 8 bytes; honest wallets
    // construct it as `vec![0u8; 8]` everywhere (grep
    // "encrypted_amount: vec" in src/ — 9 sites, all 8 bytes).
    //
    // Pre-fork, the `len() > 64` upper bound in
    // validate_transaction_basic accepted 0..=64, silently letting
    // malicious miners pad up to 56 surplus bytes per output —
    // bounded chain bloat that compounds across every UTXO outliving
    // the tx. Tightened to exact length at activation.
    //
    // Strictly tightening: any tx valid under this check is also
    // valid under the pre-fork rule. Honest wallets unaffected.
    if current_height >= crate::constants::HARD_FORK_V1_0_12_HEIGHT {
        for (out_idx, output) in tx.outputs.iter().enumerate() {
            // v1.0.12 #3/8 (cf. commit 9c8633e7): encrypted_amount must be
            // exactly 8 bytes post-fork.
            if output.encrypted_amount.len() != 8 {
                return Err(Error::InvalidTransaction(format!(
                    "output {} encrypted_amount must be exactly 8 bytes, got {}",
                    out_idx, output.encrypted_amount.len()
                )));
            }
            // v1.0.12 #4/8 (backport of v1.0.12-release 161fd74f):
            // per-output size caps at block-level validation.
            //
            // Pre-fix, the encrypted_memo size cap lived ONLY in
            // `validate_transaction_basic` (mempool admission). The main
            // `validate_transaction` — called by block validation — never
            // checked it. A miner could include a tx with
            // encrypted_memo.len() = many KiB in a self-mined block;
            // block validation let it through.
            //
            // Same bug class as the version=0 / MAX_TX_VERSION gap found
            // 2026-06-03: a check duplicated by accident between the
            // mempool and block paths drifts at the block path. The
            // single-source-of-truth refactor for this class lives in
            // `check_context_free_invariants` on v1.0.13-refactor
            // (commit 4bd0bca1) and is the longer-term fix; v1.0.12 just
            // ports the missing cap into validate_transaction here.
            //
            // MAX_TX_SIZE caps the overall tx so per-block damage is
            // bounded, but every honest node pays disk + bandwidth for
            // the inflated bytes forever, AND the bloated UTXO persists
            // until the output is spent.
            //
            // The matching encrypted_amount > 64 cap from the upstream
            // 161fd74f commit is INTENTIONALLY OMITTED here: the v1.0.12
            // tightening to `!= 8` above is strictly stricter than `> 64`,
            // so the > 64 check is dead code after activation.
            if output.encrypted_memo.len() > crate::constants::MAX_OUTPUT_MEMO_SIZE {
                return Err(Error::InvalidTransaction(format!(
                    "output {} encrypted_memo too large: {} bytes (max {})",
                    out_idx,
                    output.encrypted_memo.len(),
                    crate::constants::MAX_OUTPUT_MEMO_SIZE,
                )));
            }
        }
    }

    // Check input count
    if tx.inputs.len() > crate::constants::MAX_TX_INPUTS {
        return Err(Error::InvalidInputCount {
            count: tx.inputs.len(),
            max: crate::constants::MAX_TX_INPUTS,
        });
    }

    // Check output count
    if tx.outputs.len() > crate::constants::MAX_TX_OUTPUTS {
        return Err(Error::InvalidOutputCount {
            count: tx.outputs.len(),
            max: crate::constants::MAX_TX_OUTPUTS,
        });
    }

    // SECURITY: Reject extreme input/output ratios that could indicate
    // dust attacks or chain analysis attempts. Normal transactions rarely
    // exceed 16:1 ratio in either direction.
    let ratio_limit = 32usize;
    if tx.inputs.len() > tx.outputs.len().saturating_mul(ratio_limit) {
        return Err(Error::InvalidTransaction(format!(
            "Input/output ratio too high: {} inputs to {} outputs (max {}:1)",
            tx.inputs.len(), tx.outputs.len(), ratio_limit
        )));
    }
    if tx.outputs.len() > tx.inputs.len().saturating_mul(ratio_limit) {
        return Err(Error::InvalidTransaction(format!(
            "Output/input ratio too high: {} outputs to {} inputs (max {}:1)",
            tx.outputs.len(), tx.inputs.len(), ratio_limit
        )));
    }

    // M6 (audit fix + forward-looking bug): Uniform shape enforcement.
    //
    // CoinCync has TWO standard transaction shapes that BOTH form their own
    // anonymity set:
    //
    //   - CYNC Transfer/Churn: 2 inputs, 2 outputs
    //   - Asset Transfer:      2 inputs, 3 outputs  (CYNC fee in,
    //                                                asset out + CYNC change + asset change)
    //
    // Both are TxType::Transfer at the borsh level (no separate AssetTransfer
    // variant exists, and adding one would be a hard-fork-only consensus change).
    // The wallet builds asset txs as 2-in/3-out — see `create_asset_transaction`
    // in src/wallet/send.rs which calls `estimate_tx_size(2, 3, ring_size)`.
    //
    // Without this dual-shape allowance, all asset transfers would start failing
    // validation at UNIFORM_TX_SHAPE_HEIGHT — the previous code only accepted
    // 2-in/2-out, which would brick the asset subsystem at block 50,000.
    //
    // Privacy: each shape has its own anonymity set. A 2-in/2-out tx is one of
    // many CYNC transfers; a 2-in/3-out tx is one of many asset transfers.
    // An observer cannot distinguish individual asset txs from each other,
    // and cannot tell which specific asset is being transferred (the asset
    // commitments hide that). The privacy story remains intact.
    if current_height >= crate::constants::UNIFORM_TX_SHAPE_HEIGHT {
        let requires_uniform = matches!(tx.tx_type, TxType::Transfer | TxType::Churn);
        if requires_uniform {
            // Inputs must always be exactly STANDARD_INPUT_COUNT (== 2).
            if tx.inputs.len() != crate::constants::STANDARD_INPUT_COUNT {
                return Err(Error::InvalidTransaction(format!(
                    "Post-activation Transfer/Churn must have exactly {} inputs, got {}",
                    crate::constants::STANDARD_INPUT_COUNT, tx.inputs.len()
                )));
            }
            // Outputs must be EITHER STANDARD_OUTPUT_COUNT (CYNC, == 2) OR
            // STANDARD_OUTPUT_COUNT + 1 (asset transfer == 3). Anything else
            // is non-uniform and reduces privacy.
            let cync_shape  = crate::constants::STANDARD_OUTPUT_COUNT;
            let asset_shape = crate::constants::STANDARD_OUTPUT_COUNT + 1;
            if tx.outputs.len() != cync_shape && tx.outputs.len() != asset_shape {
                return Err(Error::InvalidTransaction(format!(
                    "Post-activation Transfer/Churn must have exactly {} outputs (CYNC) \
                     or {} outputs (asset), got {}",
                    cync_shape, asset_shape, tx.outputs.len()
                )));
            }
            // Churn is always pure CYNC — if a churn tx tries to use the asset
            // shape (3 outputs), reject it. Churns by definition spend and
            // re-receive the SAME CYNC, never assets.
            if matches!(tx.tx_type, TxType::Churn) && tx.outputs.len() != cync_shape {
                return Err(Error::InvalidTransaction(format!(
                    "Churn must have exactly {} outputs (CYNC shape), got {}",
                    cync_shape, tx.outputs.len()
                )));
            }
        }
    }

    // Check for double-spend (key image already used in the chain)
    // AND for in-tx duplicate key_images (two inputs of the SAME tx sharing a
    // key_image). 2026-06-03 bug found during code review: the previous code
    // only checked against `utxos.contains_key_image()` — which is empty for
    // the current tx's own inputs since they're not committed yet. So a tx
    // with inputs [K, K, X] would pass mempool admission (waste capacity)
    // and only fail at block-validation time (validate_block has its own
    // cross-tx duplicate check at validation.rs:582). DoS vector, not a
    // theft vector (the block-level check still catches it), but worth
    // closing at admission to stop wasting mempool space + miner cycles.
    let mut seen_in_tx = std::collections::HashSet::with_capacity(tx.inputs.len());
    for input in &tx.inputs {
        // In-tx duplicate check (NEW, 2026-06-03)
        if !seen_in_tx.insert(input.key_image) {
            // SECURITY (M-18 echo): Generic error to avoid revealing the
            // duplicated key_image to the submitter. The attacker either
            // already knows (they made the tx) or shouldn't learn from us.
            return Err(Error::DuplicateKeyImage("duplicate key image detected".into()));
        }
        // Chain-level double-spend check (existing)
        if utxos.contains_key_image(&input.key_image) {
            return Err(Error::DuplicateKeyImage("duplicate key image detected".into()));
        }
    }

    // v1.0.12 #5/8 (backport of v1.0.12-release 5aeb27dd): reject
    // duplicate stealth addresses across this tx's outputs AND
    // collisions with any existing on-chain output's stealth address.
    //
    // Why: `UtxoSet::add_output_ext` indexes outputs by stealth address
    // via `HashMap::entry().or_insert()` — first-wins semantics chosen
    // for coinbase-output sharing across heights. For regular Transfer
    // outputs that becomes a footgun:
    //
    //   In-tx case: tx.outputs[0].stealth_address ==
    //   tx.outputs[1].stealth_address — both OutputRefs land in the
    //   primary (tx_hash, index) map, but only outputs[0] gets indexed
    //   in stealth_index / output_index. Every spend-side lookup
    //   (`get_output_by_stealth`, ring-member commitment-match check at
    //   line ~1167) returns outputs[0]'s OutputRef + commitment. CLSAG
    //   verification consults the wrong commitment → silently accepts a
    //   fabricated ring signature OR silently rejects a valid one,
    //   depending on the attacker's framing.
    //
    //   Cross-tx case: a new output's stealth address matches an
    //   existing on-chain output's — the new entry is silently dropped
    //   in stealth_index / output_index. Same lookup poisoning.
    //
    // Honest stealth addresses are random (Diffie-Hellman derived
    // per-output); duplicates only happen via deliberate construction
    // or broken RNG. Rejecting is safe.
    //
    // We check via the permanent `output_index` (retains historical
    // outputs including spent ones) so a cross-tx clash with any
    // ever-existed output is caught.
    //
    // Strictly tightening: any tx valid post-fork is also valid
    // pre-fork (under the current loose "first-wins" rule the tx would
    // have been silently accepted with broken indexing). Honest
    // wallets unaffected.
    //
    // The cross-tx-WITHIN-BLOCK variant (two distinct txs in the same
    // block each creating an output with the same stealth address) is
    // covered by item #2/8 (commit 1cc2f1f4) at block-validation level.
    if current_height >= crate::constants::HARD_FORK_V1_0_12_HEIGHT {
        let mut seen_outputs_in_tx = std::collections::HashSet::with_capacity(tx.outputs.len());
        for (out_idx, output) in tx.outputs.iter().enumerate() {
            let addr_bytes = *output.stealth_address.as_bytes();
            if !seen_outputs_in_tx.insert(addr_bytes) {
                return Err(Error::InvalidTransaction(format!(
                    "duplicate stealth address at output {}",
                    out_idx,
                )));
            }
            if utxos.get_output_index_entry(&addr_bytes).is_some() {
                return Err(Error::InvalidTransaction(format!(
                    "output {} stealth address collides with existing on-chain output",
                    out_idx,
                )));
            }
        }
    }

    // SECURITY (CRIT-5 + HIGH-4): Validate ring members exist in UTXO set and
    // enforce coinbase maturity. Ring members referencing non-existent outputs
    // could be used to forge ring signatures. Immature coinbase outputs must
    // not appear in rings to prevent miners from spending rewards immediately.
    for (input_idx, input) in tx.inputs.iter().enumerate() {
        for (member_idx, member) in input.ring_members.iter().enumerate() {
            let stealth_bytes = member.public_key.as_bytes();
            match utxos.get_output_by_stealth(stealth_bytes) {
                Some(output_ref) => {
                    // SECURITY (CRIT-R4-1): Verify ring member commitment matches on-chain
                    // commitment. Without this check, an attacker can substitute a forged
                    // commitment with an inflated amount, and the CLSAG + balance proof
                    // would still verify (they're internally consistent). This enables
                    // unlimited supply inflation.
                    if member.commitment != output_ref.output.commitment {
                        return Err(Error::InvalidTransaction(format!(
                            "Input {} ring member {} commitment mismatch \
                             (transaction commitment does not match on-chain UTXO)",
                            input_idx, member_idx
                        )));
                    }
                    // Check coinbase maturity.
                    //
                    // CONSENSUS HARD FORK (MIN_OUTPUT_AGE 10 → 100,
                    // activates at `MIN_OUTPUT_AGE_HARDFORK_HEIGHT`):
                    // read the required age via the height-keyed
                    // helper so blocks BEFORE activation still validate
                    // against the old 10-block floor, and blocks AT OR
                    // AFTER activation enforce the new 100-block floor.
                    // The validator's `current_height` here is the
                    // height of the block being validated — that's the
                    // right input because activation is "applies to
                    // blocks at this height and later".
                    if output_ref.is_coinbase {
                        let age = current_height.saturating_sub(output_ref.height);
                        let required = crate::constants::min_output_age_at_height(current_height);
                        if age < required {
                            return Err(Error::InvalidTransaction(format!(
                                "Input {} ring member {} references immature coinbase output \
                                 (height {}, age {} < required {})",
                                input_idx, member_idx, output_ref.height,
                                age, required
                            )));
                        }
                    }
                    // Check time lock: locked outputs cannot appear in rings
                    // (prevents privacy leak — using a locked output as a decoy
                    // reveals it is not the real spend)
                    if let Some(lh) = output_ref.output.lock_height {
                        if current_height < lh {
                            return Err(Error::InvalidTransaction(format!(
                                "Input {} ring member {} references time-locked output \
                                 (unlocks at height {}, current {})",
                                input_idx, member_idx, lh, current_height
                            )));
                        }
                    }
                }
                None => {
                    // Ring member not found in UTXO set — check the permanent
                    // output index which retains ALL historical outputs (spent
                    // outputs are kept so ring members can still be validated).
                    match utxos.get_output_index_entry(stealth_bytes) {
                        Some(idx_entry) => {
                            // Output existed on-chain. Validate commitment match.
                            if member.commitment != idx_entry.commitment {
                                return Err(Error::InvalidTransaction(format!(
                                    "Input {} ring member {} commitment mismatch \
                                     (spent output commitment does not match on-chain record)",
                                    input_idx, member_idx
                                )));
                            }
                            // Check coinbase maturity
                            //
                            // BUG FIX 2026-06-03: previously used the raw
                            // `MIN_OUTPUT_AGE` constant (always 10) instead
                            // of the height-keyed helper. That meant for
                            // SPENT coinbase outputs referenced as decoys,
                            // the post-fork 100-block floor was never
                            // enforced — only the live-UTXO branch above
                            // got the helper. Now both branches use the
                            // same height-keyed read, so the
                            // MIN_OUTPUT_AGE 10 → 100 hard fork actually
                            // applies uniformly at the activation height.
                            // Verified the live-UTXO branch at line 1133
                            // uses the same call.
                            if idx_entry.is_coinbase {
                                let age = current_height.saturating_sub(idx_entry.height);
                                let required = crate::constants::min_output_age_at_height(current_height);
                                if age < required {
                                    return Err(Error::InvalidTransaction(format!(
                                        "Input {} ring member {} references immature coinbase \
                                         output (height {}, age {} < required {})",
                                        input_idx, member_idx, idx_entry.height,
                                        age, required
                                    )));
                                }
                            }
                            // Check time lock
                            if let Some(lh) = idx_entry.lock_height {
                                if current_height < lh {
                                    return Err(Error::InvalidTransaction(format!(
                                        "Input {} ring member {} references time-locked output \
                                         (unlocks at height {}, current {})",
                                        input_idx, member_idx, lh, current_height
                                    )));
                                }
                            }
                        }
                        None => {
                            // Output never existed on this chain.
                            if current_height >= crate::constants::STRICT_RING_MEMBER_HEIGHT {
                                return Err(Error::InvalidTransaction(format!(
                                    "Input {} ring member {} references non-existent output \
                                     (stealth address not found in output index)",
                                    input_idx, member_idx
                                )));
                            } else {
                                // H3: Pre-activation — warn and allow for backward compat.
                                // SECURITY TRADEOFF: Before STRICT_RING_MEMBER_HEIGHT, ring
                                // members referencing non-existent outputs are permitted so
                                // that the young chain can bootstrap. This is a known gap
                                // that closes automatically at STRICT_RING_MEMBER_HEIGHT.
                                // Transactions accepted under this relaxed rule should be
                                // considered for future revalidation once the chain matures.
                                tracing::warn!(
                                    "Ring member {}.{} not found in output index \
                                     (pre-activation height {}, allowing — \
                                     known gap, closes at STRICT_RING_MEMBER_HEIGHT)",
                                    input_idx, member_idx, current_height
                                );
                            }
                        }
                    }
                }
            }
        }
    }

    // Check ring size and duplicate ring members
    for (input_idx, input) in tx.inputs.iter().enumerate() {
        // v1.0.12 #6/8 (backport of v1.0.12-release 1d27d3c8): use
        // monotonic `total_outputs_ever()` instead of the live
        // `output_count()` for the ring-size enforcement input.
        //
        // ## The bug this fixes
        //
        // `output_count()` returns the count of CURRENTLY UNSPENT outputs.
        // That value (a) decreases as outputs are spent, (b) differs
        // transiently between nodes mid-reorg as they disconnect chains
        // at different rates, and (c) differs between archival nodes and
        // any node running pruning. Below `RING_SIZE_RAMP_TO_FULL_HEIGHT`
        // (10,000), `effective_ring_size` keys off `available` to compute
        // the bootstrap-adapt ring size — so two nodes with different
        // `available` for the same block can REQUIRE DIFFERENT RING SIZES,
        // accept on one node and reject on the other, and produce a
        // consensus split.
        //
        // ## The fix
        //
        // `total_outputs_ever()` is monotonically incremented in
        // `add_output_ext` and NEVER decremented (the disconnect counter
        // is separate at `reorg_disconnects_total`). Every node that
        // processed the same chain prefix has identical values.
        // Determinism preserved across all node configurations.
        //
        // ## Cast safety
        //
        // u64 → usize via `as`: on all supported 64-bit targets this is
        // identity. On hypothetical 32-bit hosts it saturates at
        // u32::MAX, which is still vastly larger than any target ring
        // size (≤ 16), so the consensus decision is unaffected.
        //
        // ## Why gated despite being a determinism fix
        //
        // The flip from `output_count()` to `total_outputs_ever()` is
        // a hardening, but it IS a consensus rule change: a block that
        // happened to pass under the buggy formula on node A and fail
        // on node B might now fail on both. Gating the change at
        // HARD_FORK_V1_0_12_HEIGHT means every node flips the rule at
        // the same height; binaries with this code shipped before the
        // activation height still apply the old (nondeterministic)
        // logic, exactly matching v1.0.11.x nodes that don't have this
        // commit at all. No split at deploy time; clean cutover at the
        // height.
        //
        // ## Why this is the v1.0.12 release blocker
        //
        // Pre-fork, the buggy formula is non-deterministic — different
        // node configurations can disagree on ring-size requirements
        // for the SAME block in the bootstrap window (h < 10,000). The
        // testnet has been lucky so far (no archival/pruned-node mix
        // observed live), but mainnet at launch would absolutely have
        // both. This must activate by mainnet GA (2026-10-01).
        let available = if current_height >= crate::constants::HARD_FORK_V1_0_12_HEIGHT {
            utxos.total_outputs_ever() as usize
        } else {
            utxos.output_count()
        };
        let ring_size = crate::constants::effective_ring_size(current_height, available);
        if input.ring_members.len() != ring_size {
            return Err(Error::InvalidRingSize {
                expected: ring_size,
                got: input.ring_members.len(),
            });
        }

        // SECURITY: Reject duplicate ring members within the same input.
        // Duplicate public keys would reduce the effective ring size,
        // degrading privacy and potentially enabling signature forgery.
        let mut seen_keys = std::collections::HashSet::new();
        for member in &input.ring_members {
            if !seen_keys.insert(*member.public_key.as_bytes()) {
                return Err(Error::InvalidSignature(format!(
                    "Duplicate ring member in input {}", input_idx
                )));
            }
        }
    }

    // Verify ring signatures for each input in parallel
    // Ring signature verification is cryptographically expensive
    // and each input can be verified independently.
    //
    // SECURITY: Use SeqCst ordering to ensure visibility across threads.
    // Relaxed ordering could allow threads to miss the failure flag being set,
    // potentially allowing invalid signatures to pass validation in edge cases.
    let all_sigs_valid = AtomicBool::new(true);
    let failed_idx = std::sync::atomic::AtomicUsize::new(usize::MAX);

    tx.inputs.par_iter().enumerate().for_each(|(idx, input)| {
        if all_sigs_valid.load(Ordering::SeqCst) {
            if !verify_ring_signature(tx, input, idx) {
                all_sigs_valid.store(false, Ordering::SeqCst);
                // Store the first failed index
                failed_idx.fetch_min(idx, Ordering::SeqCst);
            }
        }
    });

    if !all_sigs_valid.load(Ordering::SeqCst) {
        let idx = failed_idx.load(Ordering::SeqCst);
        return Err(Error::InvalidSignature(format!(
            "Ring signature verification failed for input {}", idx
        )));
    }

    // Verify range proofs for all outputs (proves amounts are non-negative)
    // C-2 FIX: pass current_height to enforce BP+ activation gate
    if !verify_output_range_proofs(tx, current_height) {
        return Err(Error::RangeProofInvalid);
    }

    // Verify balance proof: sum(input commitments) == sum(output commitments) + fee_commitment
    // This is the core privacy-preserving balance check using Pedersen commitment arithmetic
    if !verify_balance_proof(tx) {
        return Err(Error::CommitmentMismatch);
    }

    Ok(())
}

/// Verify CLSAG ring signature for a transaction input with caching
///
/// Uses verification cache for speedup during sync.
/// Cache key is hash of (message, signature_data).
/// SECURITY (C21-FIX): Made pub(crate) so mempool can verify ring signatures
/// before admission, preventing invalid transactions from propagating.
pub(crate) fn verify_ring_signature(tx: &Transaction, input: &crate::transaction::TxInput, _idx: usize) -> bool {
    use crate::crypto::{
        ClsagRingMember, clsag_verify, EcCommitment, PublicPoint,
        global_cache, ring_sig_cache_key,
    };

    // Message is the transaction hash (excluding signatures)
    let message = tx.signing_hash();

    // Serialize signature for cache key
    let sig_bytes = input.signature.to_bytes();

    // Check cache first
    let cache_key = ring_sig_cache_key(message.as_bytes(), &sig_bytes);
    let cache = global_cache();

    if let Some(cached_result) = cache.check_ring_sig(&cache_key) {
        return cached_result;
    }

    // Build CLSAG ring from transaction ring member references
    let ring: Vec<ClsagRingMember> = match input.ring_members.iter()
        .map(|rm| {
            let pk = PublicPoint::from_bytes(*rm.public_key.as_bytes())?;
            let commit = EcCommitment::from_point(PublicPoint::from_bytes(rm.commitment)?);
            Some(ClsagRingMember::new(pk, commit))
        })
        .collect::<Option<Vec<_>>>()
    {
        Some(ring) => ring,
        None => {
            tracing::warn!("CLSAG verification failed: invalid ring member curve points");
            cache.cache_ring_sig(cache_key, false);
            return false;
        }
    };

    // Reconstruct pseudo-output commitment for CLSAG verification
    let pseudo_output = match PublicPoint::from_bytes(input.pseudo_output_commitment) {
        Some(p) => EcCommitment::from_point(p),
        None => {
            tracing::warn!("CLSAG verification failed: invalid pseudo-output commitment");
            cache.cache_ring_sig(cache_key, false);
            return false;
        }
    };

    // Verify the CLSAG ring signature
    let valid = clsag_verify(message.as_bytes(), &ring, &pseudo_output, &input.signature);

    // Cache the result
    cache.cache_ring_sig(cache_key, valid);

    valid
}

/// Verify range proofs for all outputs with caching
///
/// Uses verification cache for 10-50x speedup during sync.
/// Cache key is hash of (proof_data, commitment_data).
/// SECURITY (C21-FIX): Made pub(crate) so mempool can verify range proofs
/// before admission, preventing inflation attacks from propagating.
/// SECURITY (C-2 FIX): Accept current_height to enforce BP+ activation gate.
pub(crate) fn verify_output_range_proofs(tx: &Transaction, current_height: u64) -> bool {
    use crate::crypto::{
        PedersenCommitment, verify_range_proofs_dispatch, RangeProof,
        global_cache, proof_cache_key,
    };

    // Coinbase transactions don't need range proofs (amounts are public)
    if tx.is_coinbase() {
        return true;
    }

    // Empty range proof is invalid for non-coinbase
    if tx.range_proof.is_empty() {
        tracing::warn!("Transaction has empty range proof");
        return false;
    }

    // Parse the aggregated range proof
    let proof = match RangeProof::from_bytes(&tx.range_proof) {
        Ok(p) => p,
        Err(_) => {
            tracing::warn!("Failed to parse range proof");
            return false;
        }
    };

    // Collect all output commitments
    // SECURITY (A6-COMMITMENT): Use checked deserialization to reject invalid curve
    // points from network data. Unchecked from_bytes could accept non-Ristretto bytes,
    // breaking the homomorphic balance equation and potentially enabling inflation.
    let commitments: Vec<PedersenCommitment> = match tx.outputs.iter()
        .map(|o| PedersenCommitment::from_bytes_checked(o.commitment))
        .collect::<Option<Vec<_>>>() {
        Some(c) => c,
        None => {
            tracing::warn!("Transaction contains invalid commitment point (not on Ristretto curve)");
            return false;
        }
    };

    // Build commitment data for cache key
    let commitment_bytes: Vec<u8> = commitments.iter()
        .flat_map(|c| c.to_bytes())
        .collect();

    // Check cache first (10-50x speedup during sync)
    let cache_key = proof_cache_key(&tx.range_proof, &commitment_bytes);
    let cache = global_cache();

    if let Some(cached_result) = cache.check_bulletproof(&cache_key) {
        return cached_result;
    }

    // Cache miss - perform expensive verification (version-dispatched: v2=standard, v3=BP+)
    // Always use aggregated verifier — the builder always uses prove_multiple,
    // so even single-output txs need verify_multiple (with matching transcript label).
    let valid = verify_range_proofs_dispatch(&commitments, &proof, current_height);

    // Cache the result (only caches positive results)
    cache.cache_bulletproof(cache_key, valid);

    valid
}

/// Verify balance proof using Pedersen commitment arithmetic
///
/// For a valid transaction: sum(pseudo_output_commitments) = sum(output_commitments) + fee_commitment
///
/// In CLSAG-based privacy coins:
/// - Each input has a "pseudo-output" commitment that the ring signature proves is valid
/// - The pseudo-output commits to the same value as the real input, but with a different blinding factor
/// - The balance equation becomes: sum(pseudo_outputs) = sum(outputs) + fee_commitment
/// - The blinding factors cancel because the signer computed them to balance
///
/// ## Security Model
///
/// The balance proof relies on two independent verifications:
///
/// 1. **Ring signature verification** (done in validate_transaction):
///    - Proves the signer knows the secret key for one ring member
///    - Proves knowledge of the blinding factor difference: (pseudo_bf - real_bf)
///    - This links the pseudo-output to the real input cryptographically
///
/// 2. **Balance equation** (done here):
///    - Verifies: sum(pseudo_outputs) = sum(outputs) + fee_commitment
///    - If balance holds AND ring signatures are valid, no money was created
///
/// SECURITY: Both checks are required. An attacker cannot:
/// - Create fake pseudo-outputs (ring sig would fail)
/// - Use valid pseudo-outputs with wrong balance (this check would fail)
/// - Inflate supply (would require breaking either CLSAG or discrete log)
/// SECURITY (C21-FIX): Made pub(crate) so mempool can verify balance proofs
/// before admission, preventing supply inflation from propagating.
pub(crate) fn verify_balance_proof(tx: &Transaction) -> bool {
    use crate::crypto::{PedersenCommitment, BlindingFactor};
    use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
    use curve25519_dalek::traits::Identity;

    // Coinbase transactions don't have inputs to balance
    if tx.is_coinbase() {
        return true;
    }

    // Must have inputs for a non-coinbase transaction
    if tx.inputs.is_empty() {
        tracing::warn!("Transaction has no inputs");
        return false;
    }

    // Must have outputs
    if tx.outputs.is_empty() {
        tracing::warn!("Transaction has no outputs");
        return false;
    }

    // Sum of pseudo-output commitments (from each input's ring signature)
    // The pseudo-output is the commitment the signer claims the input has
    // CLSAG verification proves the signer knows the blinding factor difference
    let mut input_sum = RistrettoPoint::identity();
    for input in &tx.inputs {
        // Each input must have a pseudo-output commitment
        // This is embedded in the ring signature data
        let pseudo_output_bytes = input.pseudo_output_commitment;

        // Validate the pseudo-output is a valid curve point
        match CompressedRistretto(pseudo_output_bytes).decompress() {
            Some(point) if point == RistrettoPoint::identity() => {
                // FIX #44: reject identity pseudo-outputs. An identity
                // point contributes zero to the input sum — the balance
                // equation collapses to `output_sum + fee == 0` for that
                // input, letting an attacker craft a transaction that
                // passes balance without actually spending anything.
                // Monero explicitly rejects identity pseudo-outputs for
                // exactly this reason.
                tracing::warn!("Pseudo-output is identity point — rejecting");
                return false;
            }
            Some(point) => {
                input_sum += point;
            }
            None => {
                tracing::warn!("Invalid pseudo-output commitment point");
                return false;
            }
        }
    }

    // Sum of output commitments
    let mut output_sum = RistrettoPoint::identity();
    for output in &tx.outputs {
        let commitment_bytes = output.commitment;

        // Validate each output commitment is a valid curve point
        match CompressedRistretto(commitment_bytes).decompress() {
            Some(point) => {
                output_sum += point;
            }
            None => {
                tracing::warn!("Invalid output commitment point");
                return false;
            }
        }
    }

    // Fee commitment: commit(fee, 0) = fee * H
    // Since blinding factor is zero, this is just fee * H (value generator)
    let fee_commitment = PedersenCommitment::commit(tx.fee.as_atomic(), &BlindingFactor::zero());
    let fee_point = match fee_commitment.as_point().decompress() {
        Some(point) => point,
        None => {
            tracing::warn!("Invalid fee commitment point");
            return false;
        }
    };

    // Verify balance: input_sum == output_sum + fee_commitment
    // This equation proves:
    // - sum(input_values) == sum(output_values) + fee (value balance)
    // - sum(input_blindings) == sum(output_blindings) (blinding factor balance)
    //
    // Both must hold for the equation to be satisfied on the curve
    let expected_output_sum = output_sum + fee_point;

    if input_sum != expected_output_sum {
        tracing::warn!(
            "Balance proof failed: input_sum != output_sum + fee. \
             Possible money creation or inflation attack detected."
        );
        return false;
    }

    true
}

/// Batch validate multiple transactions in parallel
///
/// Useful for mempool admission when receiving many transactions at once.
/// Returns a vector of (index, result) for each transaction.
#[allow(dead_code)]
pub fn validate_transactions_parallel(
    transactions: &[Transaction],
    utxos: &UtxoSet,
    current_height: u64,
) -> Vec<(usize, Result<()>)> {
    transactions
        .par_iter()
        .enumerate()
        .map(|(idx, tx)| (idx, validate_transaction(tx, utxos, current_height)))
        .collect()
}

/// Batch validate transactions with early termination on first error
///
/// More efficient than validate_transactions_parallel when you want to
/// reject a batch on any error (e.g., block validation).
#[allow(dead_code)]
pub fn validate_all_transactions(
    transactions: &[Transaction],
    utxos: &UtxoSet,
    current_height: u64,
) -> Result<()> {
    let error_found = AtomicBool::new(false);
    let first_error = parking_lot::Mutex::new(None);

    transactions.par_iter().enumerate().for_each(|(idx, tx)| {
        // Skip if error already found (early termination)
        if error_found.load(Ordering::Relaxed) {
            return;
        }

        if let Err(e) = validate_transaction(tx, utxos, current_height) {
            error_found.store(true, Ordering::Relaxed);
            {
                let mut guard = first_error.lock();
                if guard.is_none() {
                    *guard = Some((idx, e));
                }
            }
        }
    });

    {
        let guard = first_error.lock();
        if let Some((idx, ref e)) = *guard {
            return Err(Error::InvalidTransaction(format!(
                "Transaction {} failed: {}", idx, e
            )));
        }
    }

    Ok(())
}

/// Maximum transaction version accepted anywhere in the pipeline.
/// Bump this on each hard fork that introduces a new version.
const MAX_TX_VERSION: u8 = 2;

/// Quick contextless validation (for mempool)
pub fn validate_transaction_basic(tx: &Transaction) -> Result<()> {
    // FIX #39: accept any version in 1..=MAX_TX_VERSION.
    // Previously this was a hard `tx.version != 1` reject which made V2
    // transactions impossible to submit via mempool even after
    // V2_TX_ACTIVATION_HEIGHT, completely breaking the V2 feature for
    // external users. The activation-height gate lives in the full
    // `validate_transaction()` (see the `tx.version >= 2 && current_height
    // < V2_TX_ACTIVATION_HEIGHT` check at line ~811), so pre-activation
    // V2 txs are still rejected — just not by this contextless path.
    if tx.version == 0 || tx.version > MAX_TX_VERSION {
        return Err(Error::InvalidTxVersion(tx.version));
    }

    // SECURITY (BUG-17): Reject transactions with empty inputs or outputs.
    // This prevents mempool pollution with malformed transactions that can
    // never be mined (full validate_transaction checks this, but basic didn't).
    if tx.inputs.is_empty() {
        return Err(Error::InvalidTransaction("transaction has no inputs".into()));
    }
    if tx.outputs.is_empty() {
        return Err(Error::InvalidTransaction("transaction has no outputs".into()));
    }

    // Check size
    let size = tx.size();
    if size > crate::constants::MAX_TX_SIZE {
        return Err(Error::TransactionTooLarge {
            size,
            max: crate::constants::MAX_TX_SIZE,
        });
    }

    if size < crate::constants::MIN_TX_SIZE {
        return Err(Error::TransactionTooSmall {
            size,
            min: crate::constants::MIN_TX_SIZE,
        });
    }

    // Check minimum fee
    let min_fee = (size as u64) * crate::constants::MIN_FEE_PER_BYTE;
    if tx.fee.as_atomic() < min_fee && !tx.is_coinbase() {
        return Err(Error::FeeTooLow {
            fee: tx.fee.as_atomic(),
            min: min_fee,
        });
    }

    // ═══ CONSTITUTIONAL ENFORCEMENT ═══
    // Constitution Article III / Bill of Rights I: Mandatory Privacy
    // Every transaction MUST have ring signatures (inputs with ring members)
    // and range proofs (Bulletproofs). No transparent transactions allowed.
    if !tx.is_coinbase() {
        // Ring size must meet minimum (Constitution Article III)
        for input in &tx.inputs {
            if input.ring_members.len() < crate::constants::BOOTSTRAP_MIN_RING_SIZE {
                return Err(Error::InvalidTransaction(format!(
                    "UNCONSTITUTIONAL: ring size {} < minimum {} (Article III — Mandatory Privacy)",
                    input.ring_members.len(), crate::constants::BOOTSTRAP_MIN_RING_SIZE
                )));
            }
        }
        // Range proof must exist (Bill of Rights I — Bulletproofs required)
        if tx.range_proof.is_empty() {
            return Err(Error::InvalidTransaction(
                "UNCONSTITUTIONAL: missing range proof (Bill of Rights I — Bulletproofs required)".into()
            ));
        }
    }

    // Constitution Article IX / Bill of Rights X: No censorship
    // This validation function processes ALL valid transactions equally.
    // There is no blacklist check, no address filter, no censorship hook.
    // The absence of such code IS the enforcement.

    // SECURITY: Reject transactions with duplicate key images within a single tx.
    // Without this, attackers can relay double-spend txs that pass mempool admission
    // but can never be mined, wasting mempool space and network bandwidth.
    {
        let mut seen_key_images = std::collections::HashSet::new();
        for input in &tx.inputs {
            if !seen_key_images.insert(input.key_image) {
                return Err(Error::InvalidTransaction(
                    "duplicate key image within transaction".into()
                ));
            }
        }
    }

    // Check input/output count bounds
    if tx.inputs.len() > crate::constants::MAX_TX_INPUTS {
        return Err(Error::InvalidInputCount {
            count: tx.inputs.len(),
            max: crate::constants::MAX_TX_INPUTS,
        });
    }
    if tx.outputs.len() > crate::constants::MAX_TX_OUTPUTS {
        return Err(Error::InvalidOutputCount {
            count: tx.outputs.len(),
            max: crate::constants::MAX_TX_OUTPUTS,
        });
    }

    // Check output amounts and field size limits
    // SECURITY (DESER-R7): Reject outputs with oversized Vec<u8> fields to prevent
    // memory exhaustion from malicious blocks/transactions during deserialization.
    for output in &tx.outputs {
        // Output must have valid structure
        if output.encrypted_amount.is_empty() {
            return Err(Error::OutputTooSmall {
                amount: 0,
                min: crate::constants::MIN_OUTPUT_AMOUNT,
            });
        }
        // encrypted_amount: exactly 8 bytes (XOR'd u64)
        if output.encrypted_amount.len() > 64 {
            return Err(Error::InvalidTransaction(
                format!("encrypted_amount too large: {} bytes (max 64)", output.encrypted_amount.len()),
            ));
        }
        // encrypted_memo: optional, max 256 bytes to prevent blockchain bloat
        if output.encrypted_memo.len() > 256 {
            return Err(Error::InvalidTransaction(
                format!("encrypted_memo too large: {} bytes (max 256)", output.encrypted_memo.len()),
            ));
        }

        // SECURITY (H-19): Reject outputs with invalid curve points as stealth address.
        // An invalid Ristretto point (e.g., all-0xFF, random non-curve bytes) creates
        // an unspendable output — enabling burning attacks where an attacker destroys
        // another user's funds by sending to addresses nobody can spend from.
        // Historical precedent: Monero burning bug (September 2018).
        if output.stealth_address.as_bytes() == &[0u8; 32] {
            return Err(Error::InvalidTransaction(
                "output stealth address is zero (unspendable — potential burning attack)".into()
            ));
        }
        if crate::crypto::PublicPoint::from_bytes(*output.stealth_address.as_bytes()).is_none() {
            return Err(Error::InvalidTransaction(
                "output stealth address is not a valid Ristretto point (unspendable)".into()
            ));
        }

        // SECURITY (H-19): Reject zero or invalid commitments.
        // A zero commitment (identity point) breaks the balance equation.
        if output.commitment == [0u8; 32] {
            return Err(Error::InvalidTransaction(
                "output commitment is zero (identity point — balance equation breakable)".into()
            ));
        }
        if crate::crypto::PublicPoint::from_bytes(output.commitment).is_none() {
            return Err(Error::InvalidTransaction(
                "output commitment is not a valid Ristretto point".into()
            ));
        }
    }

    // SECURITY (C-9 / H-18): Reject inputs with invalid key images.
    // A zero key image or non-curve-point key image bypasses double-spend detection.
    // Historical precedent: Monero key image validation bug (April 2017).
    if !tx.is_coinbase() {
        for (idx, input) in tx.inputs.iter().enumerate() {
            let ki_bytes = input.key_image.as_bytes();
            if ki_bytes == &[0u8; 32] {
                return Err(Error::InvalidTransaction(format!(
                    "input {} has zero key image (double-spend detection bypass)", idx
                )));
            }
            if crate::crypto::PublicPoint::from_bytes(*ki_bytes).is_none() {
                return Err(Error::InvalidTransaction(format!(
                    "input {} key image is not a valid curve point", idx
                )));
            }
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The validator selects its "expected network magic" at compile time
    /// via `#[cfg(feature = "testnet")]`. Tests must therefore build blocks
    /// whose magic matches the active feature set — otherwise the very
    /// first check in `validate_block` rejects on magic and masks any
    /// other assertion. Pre-audit, these tests hardcoded `TESTNET_MAGIC`
    /// and silently broke whenever `cargo test` ran without `--features
    /// testnet` (which is the default, since `default = ["randomx"]`).
    fn test_magic() -> [u8; 4] {
        #[cfg(feature = "testnet")]
        { crate::constants::TESTNET_MAGIC }
        #[cfg(not(feature = "testnet"))]
        { crate::constants::MAINNET_MAGIC }
    }

    fn test_genesis() -> Block {
        #[cfg(feature = "testnet")]
        { crate::testnet::testnet_genesis() }
        #[cfg(not(feature = "testnet"))]
        { crate::mainnet::mainnet_genesis() }
    }

    #[test]
    fn test_genesis_validation() {
        let genesis = test_genesis();
        let utxos = UtxoSet::new();

        let result = validate_block(&genesis, None, &utxos).unwrap();
        assert!(result.valid, "Genesis should be valid: {:?}", result.errors);
    }

    #[test]
    fn test_runtime_network_magic_enforced() {
        let mut genesis = test_genesis();
        let utxos = UtxoSet::new();

        genesis.header.network_magic = crate::config::NetworkType::Testnet.magic_bytes();
        let result = validate_block_with_checkpoint_for_network(
            &genesis,
            None,
            &utxos,
            None,
            crate::config::NetworkType::Mainnet,
        ).unwrap();
        assert!(!result.valid);
        assert!(result
            .errors
            .iter()
            .any(|e| e.contains("Wrong network magic")));
    }

    #[test]
    fn test_empty_block_invalid() {
        let header = BlockHeader {
            network_magic: test_magic(),
            version: 1,
            height: 1,
            timestamp: 0,
            prev_hash: Hash::zero(),
            tx_root: Hash::zero(),
            anchor: Hash::zero(),
            algorithm: 0,
            nonce: 0,
            target: Hash::from_bytes([0xFF; 32]),
            miner_pubkey: crate::primitives::PublicKey::from_bytes([0u8; 32]),
            supply_commitment: [0u8; 32],
            checkpoint_vote: None,
            spark_set_root: [0u8; 32],
            mw_kernel_root: [0u8; 32],
        };

        let block = Block::new(header, vec![]);
        let utxos = UtxoSet::new();

        let result = validate_block(&block, None, &utxos).unwrap();
        assert!(!result.valid, "empty block must not validate");
        // An empty block has no coinbase — check that the validator surfaces
        // that specific reason, not some other earlier rejection. If this
        // assertion ever fires it means a new check landed BEFORE the
        // coinbase check and is masking it; the right fix is then to widen
        // this assertion, not to weaken the coinbase rule.
        assert!(
            result.errors.iter().any(|e| e.to_lowercase().contains("coinbase")),
            "expected a coinbase-related error, got: {:?}",
            result.errors
        );
    }
}
