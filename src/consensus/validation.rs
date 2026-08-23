//! # Block Validation
//!
//! Comprehensive block and transaction validation with parallel verification.
//!
//! Uses rayon for parallel cryptographic verification to maximize throughput
//! on multi-core systems. Transaction signatures and range proofs are verified
//! concurrently when validating blocks.

use super::difficulty::max_target;
use super::fee_market::distribute_fee;
use super::pow::verify_pow;
use super::{Block, BlockHeader};
use crate::constants::{
    block_version_at_height, MAX_BLOCK_SIZE, MAX_TIMESTAMP_DRIFT, MAX_TXS_PER_BLOCK,
};
use crate::emission::calculate_block_reward;
use crate::error::{Error, Result};
use crate::primitives::{merkle_root, Amount, Hash};
use crate::storage::UtxoSet;
use crate::transaction::{Transaction, TxType};

use rayon::prelude::*;
use std::sync::atomic::{AtomicBool, Ordering};

/// Whether fast-sync checkpoint crypto skip is enabled.
///
/// AUDIT-CRITICAL: this is the only path that lets validation skip cryptographic
/// verification of blocks. Previously controlled by a runtime env var
/// (`COINCYNC_ALLOW_CHECKPOINT_CRYPTO_SKIP`) — an attacker or misconfigured
/// operator setting that variable could silently allow invalid blocks past
/// validation. Replaced with a compile-time feature (`insecure-fast-sync`) so
/// production builds physically cannot enable the skip.
///
/// Design comparison (upstream specifics UNVERIFIED this session):
/// Bitcoin Core exposes an `-assumevalid` mechanism as a command-line /
/// config-file argument (not an environment variable), which is a
/// stricter surface than the pre-fix runtime env var here. The precise
/// scope of what `-assumevalid` skips vs re-verifies was not re-read
/// this session and is not asserted below. This function's compile-
/// time-feature gating is the safer design regardless of the specific
/// upstream shape.
///
/// To build with fast-sync (dev/testnet bootstrap only):
///   cargo build --features insecure-fast-sync
/// Production release builds MUST NOT enable this feature. CI must reject any
/// release artifact built with it.
#[cfg(feature = "insecure-fast-sync")]
fn allow_checkpoint_crypto_skip() -> bool {
    tracing::warn!(
        "SECURITY: build has insecure-fast-sync feature enabled — crypto \
         verification may be skipped for blocks under checkpoint. NEVER ship \
         a release binary with this feature."
    );
    true
}

#[cfg(not(feature = "insecure-fast-sync"))]
fn allow_checkpoint_crypto_skip() -> bool {
    false
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

/// Returns whether the v1.0.12 tightening rules are active for a network and height.
#[inline]
pub const fn v1_0_12_rules_active(network: crate::config::NetworkType, height: u64) -> bool {
    match network {
        crate::config::NetworkType::Mainnet | crate::config::NetworkType::Regtest => true,
        crate::config::NetworkType::Testnet => height >= crate::constants::HARD_FORK_V1_0_12_HEIGHT,
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
/// **Checkpoint fast-sync**: When `checkpoint_height` is Some and the block
/// height is at or below it, ALL expensive cryptographic verification is
/// skipped — not just PoW/VDF, but also CLSAG ring signatures, Bulletproofs
/// range proofs, balance proofs, and asset surjection proofs. Only structural
/// checks are performed (header chain, height, coinbase amount, merkle root,
/// timestamps). This is safe because:
/// 1. The block hash was already verified against the checkpoint chain
/// 2. If any transaction were invalid, the block hash would differ
///
/// (Monero's hardcoded-checkpoint fast-sync mode uses a similar
/// approach in spirit; specific upstream identifiers were not re-read
/// this session, so the reference is left qualitative.)
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
    // AUDIT (2026-07-01, follow-on to H1): validate_block was a ~600-line
    // monolith of 19 distinct checks. Refactored to a driver + named
    // sub-check helpers that mirror validate_transaction's structure. Each
    // helper returns early (via `bool` sentinel or `Option`) if the check
    // is fatal enough that later checks would produce meaningless errors
    // — the same short-circuit behavior the original had, made explicit.
    //
    // Prior art: Bitcoin Core splits block validation into `CheckBlock`
    // (validation.cpp:3928 in the master read this session — context-
    // free structural checks) and `ContextualCheckBlock` (validation.cpp
    // :4139 — contextual header/pindex-aware checks). The driver +
    // named sub-check layout below mirrors that separation.

    let mut result = BlockValidation::ok();

    if !check_block_network_magic(block, expected_network, &mut result) {
        return Ok(result);
    }
    if !check_block_consensus_checkpoint(block, &mut result) {
        return Ok(result);
    }

    let v1_0_12_active = v1_0_12_rules_active(expected_network, block.height());

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
                tracing::trace!(
                    "Block {} PoW skipped (below checkpoint {})",
                    block.height(),
                    checkpoint_height.unwrap_or(0)
                );
            } else if fast_sync_requested {
                tracing::warn!(
                    "Checkpoint crypto skip requested at height {} but this build \
                     does not have the insecure-fast-sync feature — full verification \
                     will run. Rebuild with `--features insecure-fast-sync` only for \
                     explicitly trusted dev/testnet bootstrap flows.",
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

    let size = block.size();
    check_block_size(size, &mut result);
    check_block_weight(block, &mut result);
    check_block_tx_count(block, &mut result);
    if !check_block_has_coinbase(block, &mut result) {
        return Ok(result);
    }
    check_block_first_tx_is_coinbase(block, &mut result);
    let tx_hashes: Vec<Hash> = block.transactions.iter().map(|tx| tx.hash()).collect();
    check_block_merkle_root(block, &tx_hashes, &mut result);
    check_block_privacy_policy(block, &mut result);

    // Validate coinbase reward
    let expected_reward = calculate_block_reward(block.height());
    let total_fees: Amount = block
        .transactions
        .iter()
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
    let max_coinbase = if block.height() >= crate::constants::FEE_DISTRIBUTION_HEIGHT
        && total_fees.as_atomic() > 0
    {
        let congestion_pct = ((size as u128 * 100) / MAX_BLOCK_SIZE as u128) as u64;
        let congested = congestion_pct >= crate::constants::CONGESTION_THRESHOLD;
        let dist = distribute_fee(total_fees, congested);
        match expected_reward.checked_add(dist.to_miner) {
            Ok(v) => v,
            Err(_) => {
                result.add_error(format!(
                    "Coinbase max overflow: reward={} + miner_share={} > u64::MAX",
                    expected_reward.as_atomic(),
                    dist.to_miner.as_atomic()
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
                    expected_reward.as_atomic(),
                    total_fees.as_atomic()
                ));
                return Ok(result);
            }
        }
    };

    check_block_tail_supply(block, expected_reward, &mut result);

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
        use crate::crypto::{BlindingFactor, PedersenCommitment};
        use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
        use curve25519_dalek::traits::Identity;

        // Skip genesis block (height 0) which has placeholder commitments
        // Also skip below checkpoint (fast sync mode)
        if block.height() > 0 && !fast_sync {
            // SECURITY (C19-FIX): Verify EACH coinbase output individually, not just the sum.
            // Previously only the sum of commitments was checked against commit(max_coinbase, 0).
            // A miner could use non-zero blinding factors that cancel in sum (b1 + b2 = 0),
            // hiding arbitrary per-output amounts while the sum appeared correct.
            // Coinbase outputs must be transparent: each commitment must
            // equal commit(declared_amount, zero_blinding). (Monero's
            // RCT type distinguishes non-RCT coinbase outputs from RCT
            // spends in an analogous spirit; the specific enum
            // identifier was not re-read this session, so no upstream
            // identifier is asserted here.)
            let mut total_declared: u64 = 0;
            let mut all_valid = true;

            // v1.0.12 audit-follow-up #5 (backport of v1.0.12-release
            // 3507a1cd): coinbase encrypted_amount must be exactly 8
            // bytes post-fork. Honest coinbase construction always
            // emits exactly 8 (LE u64). The pre-fork `>= 8` silently
            // accepted longer payloads and used only the first 8
            // bytes — bounded chain bloat that compounds across every
            // block forever. Tightened at HARD_FORK_V1_0_12_HEIGHT.
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
                    let expected_msg = if v1_0_12_active {
                        "exactly 8 bytes"
                    } else {
                        "8 bytes"
                    };
                    result.add_error(format!(
                        "Coinbase output {} has invalid amount encoding (expected {}, got {})",
                        idx,
                        expected_msg,
                        output.encrypted_amount.len()
                    ));
                    all_valid = false;
                    continue;
                };

                // SECURITY (C19-FIX): Verify this output's commitment equals
                // commit(declared_amount, zero_blinding). This prevents the blinding
                // trick where non-zero blindings cancel in sum.
                let expected_commitment =
                    PedersenCommitment::commit(declared_amount, &BlindingFactor::zero());

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
                            "Coinbase output {} has zero commitment (identity point)",
                            idx
                        ));
                        all_valid = false;
                    }
                    None => {
                        result.add_error(format!(
                            "Coinbase output {} has invalid commitment (not on curve)",
                            idx
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
                        total_declared,
                        max_coinbase.as_atomic(),
                        expected_reward,
                        total_fees
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

    check_block_duplicate_tx_hashes(&tx_hashes, &mut result);
    check_block_duplicate_key_images(block, &mut result);

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
    if v1_0_12_active {
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

        // audit H-2: per-tx congestion-fee adequacy is NO LONGER a block-validity
        // rule. Making it consensus (a per-tx fee floor scaled by BLOCK fullness)
        // while the block builders did not apply that scaling during selection let
        // ~1 MB of valid minimum-fee txs be packed into a >=50%-full block that the
        // miner's OWN validator then rejected — a near-zero-cost chain stall. This
        // adopts the Bitcoin posture: fee adequacy is mining/relay policy, not
        // block validity. The static per-byte floor and the congestion multiplier
        // are still enforced at mempool admission and honored by the builder's
        // fee-sorted selection; they simply no longer gate block validity.
        // `congestion_pct` is retained solely for the coinbase fee-distribution
        // split below.

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
                block.height(),
                total_fees,
                dist.to_miner,
                dist.burned,
                dist.to_protocol,
                congested
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
                result.add_error(format!(
                    "Invalid transaction {}: Multiple coinbase transactions",
                    idx
                ));
            }
        }
    } else {
        let tx_errors: Vec<(usize, String)> = block
            .transactions
            .par_iter()
            .enumerate()
            .skip(1) // Skip coinbase
            .filter_map(|(idx, tx)| {
                if tx.is_coinbase() {
                    return Some((idx, "Multiple coinbase transactions".to_string()));
                }

                match validate_transaction_for_network(tx, utxos, block.height(), expected_network)
                {
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

// ── validate_block sub-checks (AUDIT 2026-07-01, follow-on to H1) ──
//
// Each helper is called in the same order the previous monolithic
// function used, with bit-identical error strings. Helpers that return
// `bool` return `false` when the check is fatal enough that later
// checks would produce meaningless errors (matches the original's
// `return Ok(result)` short-circuit pattern).

/// FIRST CHECK: network magic. A 4-byte comparison that catches
/// misconfigured peers, cross-network attacks, and testnet/mainnet
/// contamination instantly. Runs before any expensive crypto.
///
/// FIX #43: check against THIS node's specific network magic, not just
/// "any known network" — previously a testnet node would accept a
/// mainnet block as having "valid magic". Genesis blocks (height 0)
/// with zero magic are accepted for backwards compat.
///
/// Returns `false` on failure — mismatched magic is fatal and no
/// subsequent check would make sense.
fn check_block_network_magic(
    block: &Block,
    expected_network: crate::config::NetworkType,
    result: &mut BlockValidation,
) -> bool {
    if block.header.network_magic == [0u8; 4] && block.height() == 0 {
        return true;
    }
    let expected_magic = expected_network.magic_bytes();
    if block.header.network_magic != expected_magic {
        result.add_error(format!(
            "Wrong network magic {:?} — expected {:?} (this is a {} node)",
            block.header.network_magic,
            expected_magic,
            expected_network.name()
        ));
        return false;
    }
    true
}

/// CIP-009 Path B consensus checkpoint: reject any block at a hardcoded
/// (height, hash) pair whose hash doesn't match. Runs before any
/// cryptographic verification.
///
/// Distinct from the fast-sync `checkpoint_height` parameter, which
/// controls whether to SKIP crypto for blocks under a known-good
/// ancestor. Consensus checkpoints REJECT chains that rewrite past
/// them; fast-sync checkpoints just speed up verification.
///
/// Returns `false` on failure — checkpoint mismatch is fatal.
fn check_block_consensus_checkpoint(block: &Block, result: &mut BlockValidation) -> bool {
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
            return false;
        }
    }
    true
}

/// Block size within `MAX_BLOCK_SIZE`.
fn check_block_size(size: usize, result: &mut BlockValidation) {
    if size > MAX_BLOCK_SIZE {
        result.add_error(format!("Block too large: {} > {}", size, MAX_BLOCK_SIZE));
    }
}

/// Block weight accounts for ring-signature verification cost, not
/// just byte size. Weight = sum of (ring_members_count * RING_SIG_WEIGHT
/// + byte_size) per tx. Max weight is 4× the max block size
/// (prevents CPU-exhaustion attacks).
///
/// FIX #46: runs UNCONDITIONALLY (not only outside fast-sync). The
/// weight check is a pure structural check with no cryptographic cost
/// — fast-sync is exactly the path where DoS risk is highest and a
/// cheap pre-flight check is most valuable.
fn check_block_weight(block: &Block, result: &mut BlockValidation) {
    const RING_SIG_WEIGHT: usize = 256; // ~cost of verifying one ring member
    const MAX_BLOCK_WEIGHT: usize = MAX_BLOCK_SIZE * 4;

    let block_weight: usize = block
        .transactions
        .iter()
        .map(|tx| {
            let ring_members: usize = tx.inputs.iter().map(|input| input.ring_members.len()).sum();
            tx.size() + ring_members * RING_SIG_WEIGHT
        })
        .sum();

    if block_weight > MAX_BLOCK_WEIGHT {
        result.add_error(format!(
            "Block weight too high: {} > {} (ring sig verification cost exceeds limit)",
            block_weight, MAX_BLOCK_WEIGHT
        ));
    }
}

/// Transaction count within `MAX_TXS_PER_BLOCK`.
fn check_block_tx_count(block: &Block, result: &mut BlockValidation) {
    if block.transactions.len() > MAX_TXS_PER_BLOCK {
        result.add_error(format!(
            "Too many transactions: {} > {}",
            block.transactions.len(),
            MAX_TXS_PER_BLOCK
        ));
    }
}

/// Block has at least one transaction (a coinbase).
///
/// Returns `false` if the block has no transactions — no later check
/// would make sense.
fn check_block_has_coinbase(block: &Block, result: &mut BlockValidation) -> bool {
    if block.transactions.is_empty() {
        result.add_error("Missing coinbase transaction");
        return false;
    }
    true
}

/// First transaction must be a coinbase.
fn check_block_first_tx_is_coinbase(block: &Block, result: &mut BlockValidation) {
    match block.transactions.first() {
        Some(first_tx) if !first_tx.is_coinbase() => {
            result.add_error("First transaction must be coinbase");
        }
        None => {
            // check_block_has_coinbase should have caught this, but be safe.
            result.add_error("Block has no transactions");
        }
        _ => {}
    }
}

/// Merkle root of transaction hashes matches the header's `tx_root`.
fn check_block_merkle_root(block: &Block, tx_hashes: &[Hash], result: &mut BlockValidation) {
    let computed_root = merkle_root(tx_hashes);
    if computed_root != block.header.tx_root {
        result.add_error("Invalid merkle root");
    }
}

/// Constitution Article III (mandatory privacy): every non-coinbase
/// tx must have Pedersen-committed amounts, a stealth address, and at
/// least one privacy-preserving input. Structural check only — no
/// ring-sig / range-proof verification here.
fn check_block_privacy_policy(block: &Block, result: &mut BlockValidation) {
    if let Err(e) = crate::consensus::privacy_policy::enforce_privacy_policy(block) {
        result.add_error(format!("Privacy policy violation: {}", e));
    }
}

/// H6 defense-in-depth: bound the emission curve's output for this block's
/// height within `[TAIL_EMISSION, calculate_block_reward(0)]`. This is
/// redundant with the emission-curve calculation but catches a mis-calibrated
/// curve:
///   - a reward BELOW `TAIL_EMISSION` means the curve's tail floor regressed;
///   - a reward ABOVE the height-0 reward means the curve returned an inflated
///     value (the emission curve is monotonically non-increasing in height, so
///     no legitimate reward ever exceeds the genesis reward).
///
/// BUGFIX (2026-08-13): the previous form rejected any block past
/// `BLOCKS_PER_YEAR * 12` whose reward merely exceeded `TAIL_EMISSION`. That
/// premise was false. The asymptotic curve `(cap - supply) / EMISSION_DIVISOR`
/// does not decay to `TAIL_EMISSION` (0.6 CYNC) until supply ~= 98.8M CYNC
/// (~height 8.8M, ~year 33), so from ~height 3.15M (~year 12) onward EVERY
/// curve-correct block carries a reward > `TAIL_EMISSION` and was rejected — a
/// permanent, network-wide chain halt. These bounds never reject a
/// curve-correct reward while still catching a genuinely broken curve.
fn check_block_tail_supply(block: &Block, expected_reward: Amount, result: &mut BlockValidation) {
    let reward = expected_reward.as_atomic();
    if reward < crate::constants::TAIL_EMISSION {
        result.add_error(format!(
            "Emission reward {} below tail floor {} at height {}",
            reward,
            crate::constants::TAIL_EMISSION,
            block.height()
        ));
    }
    // The curve is monotonically non-increasing, so the height-0 reward is the
    // absolute maximum any block may legitimately carry.
    let genesis_reward = calculate_block_reward(0).as_atomic();
    if reward > genesis_reward {
        result.add_error(format!(
            "Emission reward {} exceeds the height-0 maximum {} at height {} (emission curve must be non-increasing)",
            reward,
            genesis_reward,
            block.height()
        ));
    }
}

/// Duplicate transaction hashes within a block — a malicious miner
/// could try to include the same tx twice to double-count fees or
/// cause state inconsistencies.
///
/// FIX #48: reuses the `tx_hashes` vec computed for the merkle-root
/// check rather than calling `tx.hash()` a second time per tx.
fn check_block_duplicate_tx_hashes(tx_hashes: &[Hash], result: &mut BlockValidation) {
    let mut seen = std::collections::HashSet::with_capacity(tx_hashes.len());
    for hash in tx_hashes {
        if !seen.insert(*hash) {
            result.add_error("Duplicate transaction hash in block".to_string());
        }
    }
}

/// Phase 1 key image validation: reject blocks with in-block duplicate
/// key images. Phase 2 (per-tx UTXO check) runs in `validate_transaction`.
///
/// Fast O(n) HashSet check — rejects blocks with internal double-spends
/// before expensive cryptographic verification.
fn check_block_duplicate_key_images(block: &Block, result: &mut BlockValidation) {
    let mut seen = std::collections::HashSet::new();
    for tx in &block.transactions {
        for ki in tx.key_images() {
            if !seen.insert(ki) {
                result.add_error(format!("Duplicate key image in block: {}", ki));
            }
        }
    }
}

/// Validate block header.
///
/// AUDIT (2026-07-01, follow-on to validate_block refactor): split into
/// named sub-checks that mirror `validate_block_with_checkpoint_for_network`'s
/// structure. Each sub-check accumulates errors into the same
/// `BlockValidation` sink and returns early only when a later check would
/// depend on the earlier one (currently: system-clock failure short-
/// circuits the future-timestamp check).
fn validate_header(
    header: &BlockHeader,
    prev_header: Option<&BlockHeader>,
    result: &mut BlockValidation,
) {
    check_header_version_min(header, result);
    check_header_vs_prev(header, prev_header, result);
    check_header_checkpoint_vote(header, result);
    check_header_future_timestamp(header, result);
}

/// FIX #47: treat `block_version_at_height` as a MINIMUM, not strict
/// equality. Previously `header.version != expected_version` rejected any
/// version-bump block mined the block BEFORE fork activation — a miner
/// producing a V2 block at `activation_height - 1` was refused even
/// though the block was otherwise valid for the upgrade. Accepting any
/// version >= min allows smooth activation; downgrades are still
/// rejected via `check_header_vs_prev`.
fn check_header_version_min(header: &BlockHeader, result: &mut BlockValidation) {
    let min_version = block_version_at_height(header.height);
    if header.version < min_version {
        result.add_error(format!(
            "Block version {} below minimum {} for height {}",
            header.version, min_version, header.height
        ));
    }
}

/// Header-vs-previous-header checks:
/// * Version cannot decrease (downgrade attack protection).
/// * Height must be exactly `prev.height + 1`.
/// * `prev_hash` must equal `prev.hash()`.
/// * Timestamp must be strictly greater than previous. Combined with
///   height-by-height validation during block processing, this
///   guarantees chain-wide timestamp monotonicity by induction. During
///   reorgs, the new chain is validated block-by-block from the fork
///   point so monotonicity is maintained on the new chain too.
///
/// Genesis (no prev_header): only checks that height is 0.
fn check_header_vs_prev(
    header: &BlockHeader,
    prev_header: Option<&BlockHeader>,
    result: &mut BlockValidation,
) {
    let Some(prev) = prev_header else {
        if header.height != 0 {
            result.add_error("Non-genesis block without parent");
        }
        return;
    };
    if header.version < prev.version {
        result.add_error(format!(
            "Block version cannot decrease: v{} -> v{}",
            prev.version, header.version
        ));
    }
    if header.height != prev.height + 1 {
        result.add_error(format!(
            "Invalid height: expected {}, got {}",
            prev.height + 1,
            header.height
        ));
    }
    if header.prev_hash != prev.hash() {
        result.add_error("Previous hash mismatch");
    }
    if header.timestamp <= prev.timestamp {
        result.add_error("Timestamp not greater than previous block");
    }
}

/// SECURITY (CC-L1): `checkpoint_vote` must reference a height that
/// already exists — not the current block's height and not any future
/// height. Voting for a block that hasn't been mined yet is either a
/// bug or an attack.
fn check_header_checkpoint_vote(header: &BlockHeader, result: &mut BlockValidation) {
    if let Some((cp_height, _cp_hash)) = &header.checkpoint_vote {
        if *cp_height >= header.height {
            result.add_error(format!(
                "checkpoint_vote references future height {} (block height {})",
                cp_height, header.height
            ));
        }
    }
}

/// Reject block timestamps too far in the future.
///
/// SPEC: the bound is INCLUSIVE — `timestamp == current_time +
/// MAX_TIMESTAMP_DRIFT` is accepted, only strictly-greater is rejected.
/// Matches the semantics of Bitcoin Core's `MAX_FUTURE_BLOCK_TIME`
/// constant (chain.h:29 in the master read this session — 2 * 60 * 60
/// seconds; also aliased at chain.h:37 as `TIMESTAMP_WINDOW`). The prior
/// comment misattributed the constant to `pow.cpp` and used the older
/// Hungarian-notation name `nMaxFutureBlockTime`, which is not present
/// in current upstream. The bound is inclusive, matching the NTP/
/// RFC 5905 convention where the drift bound IS the tolerable window,
/// not one tick less. Switching to `>=` would reject legitimate blocks
/// whose timestamp exactly hits the boundary with no security gain.
///
/// SECURITY: genesis (height 0) is exempt. The genesis timestamp is a
/// protocol constant hardcoded in the binary (`{testnet,mainnet}_genesis`)
/// with trust established by the `{TESTNET,MAINNET}_GENESIS_HASH` match
/// in `Blockchain::init_genesis`. Mainnet genesis intentionally carries
/// a future-dated activation timestamp (launch date) and must not be
/// rejected on pre-launch clock comparisons.
///
/// SECURITY: system clock failure adds an error but does NOT panic —
/// nodes on badly-configured hosts still process blocks (validation of
/// crypto and consensus rules is orthogonal to wall-clock).
fn check_header_future_timestamp(header: &BlockHeader, result: &mut BlockValidation) {
    let current_time = match std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH) {
        Ok(d) => d.as_secs(),
        Err(e) => {
            result.add_error(format!(
                "System clock error: {}. Cannot validate block timestamps.",
                e
            ));
            return;
        }
    };
    // Sanity: current time should be reasonably recent (after 2020).
    const MIN_REASONABLE_TIME: u64 = 1577836800; // 2020-01-01 00:00:00 UTC
    if current_time < MIN_REASONABLE_TIME {
        result.add_warning("System clock appears to be set incorrectly (before 2020)");
    }
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
pub fn validate_transaction(tx: &Transaction, utxos: &UtxoSet, current_height: u64) -> Result<()> {
    #[cfg(feature = "testnet")]
    let expected_network = crate::config::NetworkType::Testnet;
    #[cfg(not(feature = "testnet"))]
    let expected_network = crate::config::NetworkType::Mainnet;

    validate_transaction_for_network(tx, utxos, current_height, expected_network)
}

/// Validate a transaction using the activation schedule for `expected_network`.
pub fn validate_transaction_for_network(
    tx: &Transaction,
    utxos: &UtxoSet,
    current_height: u64,
    expected_network: crate::config::NetworkType,
) -> Result<()> {
    let v1_0_12_active = v1_0_12_rules_active(expected_network, current_height);
    // AUDIT (2026-06-30 H1): the previous single-function form was 640
    // lines and reviewer-hostile. Broken into named sub-checks. Evaluation
    // order and error types are BIT-IDENTICAL to the previous flow — this
    // is a mechanical extraction, not a semantic change. Each sub-check
    // is a private helper in this file with a docstring explaining what
    // it enforces. Prior art: Bitcoin Core factors transaction validity
    // into `CheckTransaction()` and adjacent helpers (referenced from
    // validation.cpp:802 and :3971 in the master read this session);
    // the same driver + named-sub-check pattern is applied here. The
    // prior comment asserted a specific line-count for the upstream
    // helper; that count was not re-measured this session and is not
    // repeated.

    // Version range: reject version==0 or version > MAX_TX_VERSION. Runs
    // BEFORE the coinbase early return so a version-99 coinbase is still
    // rejected. See detailed rationale in check_tx_version_range.
    check_tx_version_range(tx)?;

    // Coinbase has no inputs — everything below this line assumes
    // non-coinbase inputs exist.
    if tx.is_coinbase() {
        return Ok(());
    }

    check_tx_v2_activation(tx, current_height)?;
    check_tx_input_output_counts(tx, v1_0_12_active)?;
    check_tx_io_ratio_legacy(tx)?;
    check_tx_uniform_shape(tx, current_height)?;
    check_tx_no_double_spend(tx, utxos)?;
    check_tx_ring_members(tx, utxos, current_height, v1_0_12_active)?;
    check_tx_ring_size_and_unique_members(tx, utxos, current_height, v1_0_12_active)?;
    check_tx_ring_signatures(tx)?;
    check_tx_range_proofs(tx, current_height)?;
    check_tx_balance_proof(tx)?;
    Ok(())
}

// ── validate_transaction sub-checks (AUDIT 2026-06-30 H1) ──────────
//
// Each sub-check is called in the exact same order the previous monolithic
// function used. Errors are the same types. Semantic behavior is identical.
// Kept as private helpers in this file (not moved to a sub-module) so
// they retain access to file-private types and don't force `pub(crate)`
// changes on internal helpers.

/// Version range: `1 <= tx.version <= MAX_TX_VERSION`.
///
/// Runs BEFORE the coinbase early-return so a coinbase with an unknown
/// version can't sneak past.
///
/// 2026-06-03 bug found during critical-file review: previously this
/// function only checked the V2 *activation* gate. The upper bound and
/// the version==0 reject lived ONLY in `validate_transaction_basic`,
/// which runs on mempool admission — not on block validation. A miner
/// could therefore include a tx with version=0 or version=255 directly
/// in a mined block; block validation calls `validate_transaction` (see
/// validate_block), which would let any future / unknown version through
/// as long as the crypto held.
///
/// Why this matters for future hard forks: a v1.0 node receiving a
/// version=3 tx in a v1.1 block must NOT accept it (the on-wire shape
/// could differ across versions, and silent acceptance would split
/// consensus at the fork).
fn check_tx_version_range(tx: &Transaction) -> Result<()> {
    if tx.version == 0 || tx.version > MAX_TX_VERSION {
        return Err(Error::InvalidTxVersion(tx.version));
    }
    Ok(())
}

/// V2 transactions are only valid at or above `V2_TX_ACTIVATION_HEIGHT`.
/// V1 transactions remain valid at all heights (backward compat).
/// Rejecting V2 below activation prevents pre-fork asset tx injection.
fn check_tx_v2_activation(tx: &Transaction, current_height: u64) -> Result<()> {
    if tx.version >= 2 && current_height < crate::constants::V2_TX_ACTIVATION_HEIGHT {
        return Err(Error::InvalidState(format!(
            "V2 transactions not allowed below activation height {} (current: {})",
            crate::constants::V2_TX_ACTIVATION_HEIGHT,
            current_height
        )));
    }
    Ok(())
}

/// Non-empty inputs + outputs, both within `MAX_TX_INPUTS`/`MAX_TX_OUTPUTS`.
///
/// `v1_0_12_active` gates the encrypted_amount and encrypted_memo size checks.
fn check_tx_input_output_counts(tx: &Transaction, v1_0_12_active: bool) -> Result<()> {
    if tx.inputs.is_empty() {
        return Err(Error::InvalidInputCount {
            count: 0,
            max: crate::constants::MAX_TX_INPUTS,
        });
    }
    if tx.outputs.is_empty() {
        return Err(Error::InvalidOutputCount {
            count: 0,
            max: crate::constants::MAX_TX_OUTPUTS,
        });
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
    if v1_0_12_active {
        for (out_idx, output) in tx.outputs.iter().enumerate() {
            // v1.0.12 #3/8 (cf. commit 9c8633e7): encrypted_amount must be
            // exactly 8 bytes post-fork.
            if output.encrypted_amount.len() != 8 {
                return Err(Error::InvalidTransaction(format!(
                    "output {} encrypted_amount must be exactly 8 bytes, got {}",
                    out_idx,
                    output.encrypted_amount.len()
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
    if tx.outputs.len() > crate::constants::MAX_TX_OUTPUTS {
        return Err(Error::InvalidOutputCount {
            count: tx.outputs.len(),
            max: crate::constants::MAX_TX_OUTPUTS,
        });
    }
    Ok(())
}

/// Legacy 32:1 input/output ratio check.
///
/// AUDIT (2026-06-30 M4): redundant with `check_tx_uniform_shape`, which
/// enforces exact 2-in/2-out or 2-in/3-out for the dominant Transfer/Churn
/// types starting at height 0 (`UNIFORM_TX_SHAPE_HEIGHT`). This check only
/// fires for non-Transfer/Churn tx types.
///
/// Original justification ("dust attacks or chain analysis attempts") was
/// weak — CoinJoin/Whirlpool-style batching legitimately exceed high ratios
/// in transparent chains. On CoinCync the uniform-shape rule blocks the
/// theoretical dust vector at genesis, so this check is functionally dead
/// code for all typical traffic.
///
/// Left in place because REMOVING a consensus rule requires a hard fork
/// and the removal has no observable benefit (uniform-shape dominates).
/// (The prior comment asserted "Bitcoin has no I/O ratio rule; Monero
/// has no I/O ratio rule (uses TX_MAX_SIZE instead)". Those broad
/// negative claims were not re-verified against upstream this session,
/// so they are removed rather than perpetuated. The rule is retained
/// here on its own merits: removing a consensus rule requires a hard
/// fork, and the uniform-shape rule already dominates the dust vector.)
fn check_tx_io_ratio_legacy(tx: &Transaction) -> Result<()> {
    let ratio_limit = 32usize;
    if tx.inputs.len() > tx.outputs.len().saturating_mul(ratio_limit) {
        return Err(Error::InvalidTransaction(format!(
            "Input/output ratio too high: {} inputs to {} outputs (max {}:1)",
            tx.inputs.len(),
            tx.outputs.len(),
            ratio_limit
        )));
    }
    if tx.outputs.len() > tx.inputs.len().saturating_mul(ratio_limit) {
        return Err(Error::InvalidTransaction(format!(
            "Output/input ratio too high: {} outputs to {} inputs (max {}:1)",
            tx.outputs.len(),
            tx.inputs.len(),
            ratio_limit
        )));
    }
    Ok(())
}

/// Uniform-shape enforcement (M6, forward-looking bug fix).
///
/// CoinCync has TWO standard transaction shapes that BOTH form their own
/// anonymity set:
///   - CYNC Transfer/Churn: 2 inputs, 2 outputs
///   - Asset Transfer:      2 inputs, 3 outputs (CYNC fee in, asset out +
///                                               CYNC change + asset change)
///
/// Both are `TxType::Transfer` at the borsh level (no separate AssetTransfer
/// variant exists, and adding one would be a hard-fork-only consensus
/// change). The wallet builds asset txs as 2-in/3-out — see
/// `create_asset_transaction` in `src/wallet/send.rs`.
///
/// Without this dual-shape allowance, all asset transfers would start
/// failing validation at `UNIFORM_TX_SHAPE_HEIGHT` — the previous code only
/// accepted 2-in/2-out, which would brick the asset subsystem at block
/// 50,000.
///
/// Privacy: each shape has its own anonymity set. A 2-in/2-out tx is one
/// of many CYNC transfers; a 2-in/3-out tx is one of many asset transfers.
/// An observer cannot distinguish individual asset txs from each other,
/// and cannot tell which specific asset is being transferred (the asset
/// commitments hide that). The privacy story remains intact.
fn check_tx_uniform_shape(tx: &Transaction, current_height: u64) -> Result<()> {
    if current_height < crate::constants::UNIFORM_TX_SHAPE_HEIGHT {
        return Ok(());
    }
    let requires_uniform = matches!(tx.tx_type, TxType::Transfer | TxType::Churn);
    if !requires_uniform {
        return Ok(());
    }
    // Inputs must always be exactly STANDARD_INPUT_COUNT (== 2).
    if tx.inputs.len() != crate::constants::STANDARD_INPUT_COUNT {
        return Err(Error::InvalidTransaction(format!(
            "Post-activation Transfer/Churn must have exactly {} inputs, got {}",
            crate::constants::STANDARD_INPUT_COUNT,
            tx.inputs.len()
        )));
    }
    // Outputs must be EITHER STANDARD_OUTPUT_COUNT (CYNC, == 2) OR
    // STANDARD_OUTPUT_COUNT + 1 (asset transfer == 3). Anything else is
    // non-uniform and reduces privacy.
    let cync_shape = crate::constants::STANDARD_OUTPUT_COUNT;
    let asset_shape = crate::constants::STANDARD_OUTPUT_COUNT + 1;
    if tx.outputs.len() != cync_shape && tx.outputs.len() != asset_shape {
        return Err(Error::InvalidTransaction(format!(
            "Post-activation Transfer/Churn must have exactly {} outputs (CYNC) \
             or {} outputs (asset), got {}",
            cync_shape,
            asset_shape,
            tx.outputs.len()
        )));
    }
    // Churn is always pure CYNC — if a churn tx tries to use the asset
    // shape (3 outputs), reject it. Churns by definition spend and
    // re-receive the SAME CYNC, never assets.
    if matches!(tx.tx_type, TxType::Churn) && tx.outputs.len() != cync_shape {
        return Err(Error::InvalidTransaction(format!(
            "Churn must have exactly {} outputs (CYNC shape), got {}",
            cync_shape,
            tx.outputs.len()
        )));
    }
    Ok(())
}

/// Double-spend check: in-tx duplicate key_images + chain-level key_image
/// collision.
///
/// 2026-06-03 bug fix: previously only checked against
/// `utxos.contains_key_image()` — which is empty for the current tx's own
/// inputs since they're not committed yet. So a tx with inputs [K, K, X]
/// would pass mempool admission (waste capacity) and only fail at
/// block-validation time (`validate_block` has its own cross-tx duplicate
/// check). DoS vector, not a theft vector (the block-level check still
/// catches it), but worth closing at admission.
///
/// SECURITY (M-18 echo): the error message is intentionally generic and
/// doesn't reveal the duplicated key_image to the submitter.
fn check_tx_no_double_spend(tx: &Transaction, utxos: &UtxoSet) -> Result<()> {
    let mut seen_in_tx = std::collections::HashSet::with_capacity(tx.inputs.len());
    for input in &tx.inputs {
        if !seen_in_tx.insert(input.key_image) {
            return Err(Error::DuplicateKeyImage(
                "duplicate key image detected".into(),
            ));
        }
        if utxos.contains_key_image(&input.key_image) {
            return Err(Error::DuplicateKeyImage(
                "duplicate key image detected".into(),
            ));
        }
    }
    Ok(())
}

/// Validate every ring member of every input.
///
/// SECURITY (CRIT-5 + HIGH-4): ring members must (a) exist as an output on
/// this chain, (b) have a commitment matching the on-chain output, (c)
/// respect coinbase maturity if the output is a coinbase, and (d) respect
/// the output's time-lock.
///
/// Ring members referencing non-existent outputs could be used to forge
/// ring signatures. Immature coinbase outputs must not appear in rings to
/// prevent miners from spending rewards immediately.
///
/// CRIT-R4-1: verifying the on-chain commitment matches the ring-member
/// commitment closes an inflation vector — without it, an attacker could
/// substitute a forged commitment with an inflated amount, and the CLSAG
/// + balance proof would still verify (they're internally consistent).
///
/// Two lookup paths: live UTXO set (`get_output_by_stealth`), then the
/// permanent output index that retains ALL historical outputs
/// (`get_output_index_entry`). Pre-`STRICT_RING_MEMBER_HEIGHT`, ring
/// members not found in either are logged and allowed (bootstrap gap).
///
/// v1.0.12 #5/8 (fork-gated by HARD_FORK_V1_0_12_HEIGHT): also runs the
/// dup-stealth-address check on tx.outputs at the top of this function,
/// since we already have (tx, utxos, current_height) in scope here. See
/// the inline docstring below for the full rationale.
fn check_tx_ring_members(
    tx: &Transaction,
    utxos: &UtxoSet,
    current_height: u64,
    v1_0_12_active: bool,
) -> Result<()> {
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
    if v1_0_12_active {
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

    for (input_idx, input) in tx.inputs.iter().enumerate() {
        for (member_idx, member) in input.ring_members.iter().enumerate() {
            let stealth_bytes = member.public_key.as_bytes();
            match utxos.get_output_by_stealth(stealth_bytes) {
                Some(output_ref) => {
                    if member.commitment != output_ref.output.commitment {
                        return Err(Error::InvalidTransaction(format!(
                            "Input {} ring member {} commitment mismatch \
                             (transaction commitment does not match on-chain UTXO)",
                            input_idx, member_idx
                        )));
                    }
                    check_ring_member_coinbase_maturity(
                        output_ref.is_coinbase,
                        output_ref.height,
                        current_height,
                        input_idx,
                        member_idx,
                    )?;
                    check_ring_member_time_lock(
                        output_ref.output.lock_height,
                        current_height,
                        input_idx,
                        member_idx,
                    )?;
                }
                None => {
                    // Not in live UTXO — try the permanent output index.
                    match utxos.get_output_index_entry(stealth_bytes) {
                        Some(idx_entry) => {
                            if member.commitment != idx_entry.commitment {
                                return Err(Error::InvalidTransaction(format!(
                                    "Input {} ring member {} commitment mismatch \
                                     (spent output commitment does not match on-chain record)",
                                    input_idx, member_idx
                                )));
                            }
                            // BUG FIX 2026-06-03: previously used the raw
                            // `MIN_OUTPUT_AGE` constant (always 10) on this
                            // branch instead of the height-keyed helper —
                            // spent coinbase outputs as ring decoys never
                            // got the post-fork 100-block floor. Now both
                            // branches use the shared helper below.
                            check_ring_member_coinbase_maturity(
                                idx_entry.is_coinbase,
                                idx_entry.height,
                                current_height,
                                input_idx,
                                member_idx,
                            )?;
                            check_ring_member_time_lock(
                                idx_entry.lock_height,
                                current_height,
                                input_idx,
                                member_idx,
                            )?;
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
                                // H3: Pre-activation known bootstrap gap.
                                tracing::warn!(
                                    "Ring member {}.{} not found in output index \
                                     (pre-activation height {}, allowing — \
                                     known gap, closes at STRICT_RING_MEMBER_HEIGHT)",
                                    input_idx,
                                    member_idx,
                                    current_height
                                );
                            }
                        }
                    }
                }
            }
        }
    }
    Ok(())
}

/// Coinbase maturity check for a ring member.
///
/// Extracted 2026-07-01: previously duplicated between the live-UTXO
/// and spent-output-index branches of `check_tx_ring_members`, with a
/// silent bug where the spent-index branch used the raw `MIN_OUTPUT_AGE`
/// constant (always 10) instead of the height-keyed helper. Unifying
/// through this function guarantees both branches enforce the same
/// hard-fork ramp.
///
/// CONSENSUS HARD FORK: MIN_OUTPUT_AGE 10 → 100 activates at
/// `MIN_OUTPUT_AGE_HARDFORK_HEIGHT`. The height-keyed helper returns 10
/// before activation and 100 after, so blocks before the fork validate
/// against the old floor and blocks at/after enforce the new one.
///
/// Prior art: Bitcoin's coinbase maturity (`COINBASE_MATURITY = 100`
/// blocks) uses the same pattern — enforced identically wherever a
/// coinbase output is spent, whether live or historical.
fn check_ring_member_coinbase_maturity(
    is_coinbase: bool,
    output_height: u64,
    current_height: u64,
    input_idx: usize,
    member_idx: usize,
) -> Result<()> {
    if !is_coinbase {
        return Ok(());
    }
    let age = current_height.saturating_sub(output_height);
    let required = crate::constants::min_output_age_at_height(current_height);
    if age < required {
        return Err(Error::InvalidTransaction(format!(
            "Input {} ring member {} references immature coinbase output \
             (height {}, age {} < required {})",
            input_idx, member_idx, output_height, age, required
        )));
    }
    Ok(())
}

/// Time-lock check for a ring member.
///
/// Extracted 2026-07-01: previously duplicated between the live-UTXO
/// and spent-output-index branches of `check_tx_ring_members`.
///
/// Time-locked outputs cannot appear in rings because using a locked
/// output as a decoy reveals it is NOT the real spend — the spending
/// tx must be spending a spendable output, so a locked ring member
/// gives away the anonymity set.
fn check_ring_member_time_lock(
    lock_height: Option<u64>,
    current_height: u64,
    input_idx: usize,
    member_idx: usize,
) -> Result<()> {
    if let Some(lh) = lock_height {
        if current_height < lh {
            return Err(Error::InvalidTransaction(format!(
                "Input {} ring member {} references time-locked output \
                 (unlocks at height {}, current {})",
                input_idx, member_idx, lh, current_height
            )));
        }
    }
    Ok(())
}

/// Ring size matches `effective_ring_size(current_height, output_count)`
/// AND ring members are unique per-input.
///
/// Duplicate public keys would reduce the effective ring size, degrading
/// privacy and potentially enabling signature forgery.
fn check_tx_ring_size_and_unique_members(
    tx: &Transaction,
    utxos: &UtxoSet,
    current_height: u64,
    v1_0_12_active: bool,
) -> Result<()> {
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
        let available = if v1_0_12_active {
            // DETERMINISM (2026-08-16): total_outputs_ever is monotonic and is
            // NOT decremented on reorg (utxos.rs "L2" design), so on its own it
            // is PATH-DEPENDENT — two nodes on an identical canonical tip reached
            // via different reorg histories hold different values. In the young-
            // chain window (available < target) that feeds a different required
            // ring size and would FORK the chain (same class as the fixed
            // total_difficulty divergence). Subtracting reorg_disconnects_total
            // yields canonical-outputs-ever (every orphaned add is matched by its
            // disconnect), which is order-independent AND still pruned/archival-
            // invariant — preserving the v1.0.12 intent without the reorg-history
            // divergence. Once the chain matures (available >= target) the value
            // saturates to the target either way, so this is behaviour-neutral
            // outside the bootstrap window.
            utxos
                .total_outputs_ever()
                .saturating_sub(utxos.reorg_disconnects_total()) as usize
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
        let mut seen_keys = std::collections::HashSet::new();
        for member in &input.ring_members {
            if !seen_keys.insert(*member.public_key.as_bytes()) {
                return Err(Error::InvalidSignature(format!(
                    "Duplicate ring member in input {}",
                    input_idx
                )));
            }
        }
    }
    Ok(())
}

/// Verify every input's CLSAG ring signature in parallel via rayon.
///
/// SECURITY: uses `SeqCst` ordering on the shared failure flag so threads
/// see the "abort" signal reliably. Relaxed ordering could let threads
/// miss the failure flag being set, potentially allowing invalid
/// signatures to pass validation in edge cases.
fn check_tx_ring_signatures(tx: &Transaction) -> Result<()> {
    let all_sigs_valid = AtomicBool::new(true);
    let failed_idx = std::sync::atomic::AtomicUsize::new(usize::MAX);
    tx.inputs.par_iter().enumerate().for_each(|(idx, input)| {
        if all_sigs_valid.load(Ordering::SeqCst) {
            if !verify_ring_signature(tx, input, idx) {
                all_sigs_valid.store(false, Ordering::SeqCst);
                failed_idx.fetch_min(idx, Ordering::SeqCst);
            }
        }
    });
    if !all_sigs_valid.load(Ordering::SeqCst) {
        let idx = failed_idx.load(Ordering::SeqCst);
        return Err(Error::InvalidSignature(format!(
            "Ring signature verification failed for input {}",
            idx
        )));
    }
    Ok(())
}

/// Verify range proofs for all outputs (proves amounts are non-negative).
///
/// C-2 fix: passes `current_height` to enforce the Bulletproofs+ activation
/// gate — pre-activation uses the legacy proof format, post-activation
/// uses BP+ which is ~50% smaller.
fn check_tx_range_proofs(tx: &Transaction, current_height: u64) -> Result<()> {
    if !verify_output_range_proofs(tx, current_height) {
        return Err(Error::RangeProofInvalid);
    }
    Ok(())
}

/// Verify balance proof: sum(input commitments) == sum(output commitments)
/// + fee_commitment. Core privacy-preserving balance check via Pedersen
/// commitment arithmetic.
fn check_tx_balance_proof(tx: &Transaction) -> Result<()> {
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
pub(crate) fn verify_ring_signature(
    tx: &Transaction,
    input: &crate::transaction::TxInput,
    _idx: usize,
) -> bool {
    use crate::crypto::{
        clsag_verify, global_cache, ring_sig_cache_key, ClsagRingMember, EcCommitment, PublicPoint,
    };

    // SECURITY (audit C-2): bind the double-spend key image to the signed one.
    // The double-spend set is keyed on `input.key_image`, but the CLSAG proves
    // ownership of `input.signature.key_image`. If they are not identical, a
    // signer can present an honest signature while placing an arbitrary point in
    // `input.key_image`, so the same output spends repeatedly under fresh key
    // images (inflation). This check runs BEFORE the signature cache — the cache
    // is keyed only on (message, signature) and would otherwise return a
    // cached-valid verdict for a mismatched `input.key_image`. The only prior
    // enforcement lived in `transaction::validator::validate_transaction`, which
    // is not on any live path.
    if input.signature.key_image.to_bytes() != *input.key_image.as_bytes() {
        return false;
    }

    // Message is the transaction hash (excluding signatures)
    let message = tx.signing_hash();

    // Serialize signature for cache key. AUDIT (2026-06-30 H3): to_bytes
    // now returns Result — a serialization failure at this point means the
    // signature struct is corrupted in memory (impossible for a validated
    // signature, but a real audit finding if we silently continued with
    // empty bytes). Fail closed.
    let sig_bytes = match input.signature.to_bytes() {
        Ok(b) => b,
        Err(e) => {
            tracing::error!(
                "ClsagSignature serialization failed during verification (bug): {}",
                e
            );
            return false;
        }
    };

    // Check cache first
    let cache_key = ring_sig_cache_key(message.as_bytes(), &sig_bytes);
    let cache = global_cache();

    if let Some(cached_result) = cache.check_ring_sig(&cache_key) {
        return cached_result;
    }

    // Build CLSAG ring from transaction ring member references
    let ring: Vec<ClsagRingMember> = match input
        .ring_members
        .iter()
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
        global_cache, proof_cache_key, verify_range_proofs_dispatch, PedersenCommitment, RangeProof,
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
    let commitments: Vec<PedersenCommitment> = match tx
        .outputs
        .iter()
        .map(|o| PedersenCommitment::from_bytes_checked(o.commitment))
        .collect::<Option<Vec<_>>>()
    {
        Some(c) => c,
        None => {
            tracing::warn!(
                "Transaction contains invalid commitment point (not on Ristretto curve)"
            );
            return false;
        }
    };

    // Build commitment data for cache key
    let commitment_bytes: Vec<u8> = commitments.iter().flat_map(|c| c.to_bytes()).collect();

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
    use crate::crypto::{BlindingFactor, PedersenCommitment};
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
                // (Reference implementations reject identity pseudo-
                // outputs for the same reason; specific upstream
                // identifier UNVERIFIED this session.)
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
                "Transaction {} failed: {}",
                idx, e
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
        return Err(Error::InvalidTransaction(
            "transaction has no inputs".into(),
        ));
    }
    if tx.outputs.is_empty() {
        return Err(Error::InvalidTransaction(
            "transaction has no outputs".into(),
        ));
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
                    input.ring_members.len(),
                    crate::constants::BOOTSTRAP_MIN_RING_SIZE
                )));
            }
        }
        // Range proof must exist (Bill of Rights I — Bulletproofs required)
        if tx.range_proof.is_empty() {
            return Err(Error::InvalidTransaction(
                "UNCONSTITUTIONAL: missing range proof (Bill of Rights I — Bulletproofs required)"
                    .into(),
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
                    "duplicate key image within transaction".into(),
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
            return Err(Error::InvalidTransaction(format!(
                "encrypted_amount too large: {} bytes (max 64)",
                output.encrypted_amount.len()
            )));
        }
        // encrypted_memo: optional, max 256 bytes to prevent blockchain bloat
        if output.encrypted_memo.len() > 256 {
            return Err(Error::InvalidTransaction(format!(
                "encrypted_memo too large: {} bytes (max 256)",
                output.encrypted_memo.len()
            )));
        }

        // SECURITY (H-19): Reject outputs with invalid curve points as stealth address.
        // An invalid Ristretto point (e.g., all-0xFF, random non-curve bytes) creates
        // an unspendable output — enabling burning attacks where an attacker destroys
        // another user's funds by sending to addresses nobody can spend from.
        // Historical incident referenced from public record: Monero
        // burning bug (September 2018). Details not re-fetched this
        // session; the check below stands on its own security
        // reasoning above.
        if output.stealth_address.as_bytes() == &[0u8; 32] {
            return Err(Error::InvalidTransaction(
                "output stealth address is zero (unspendable — potential burning attack)".into(),
            ));
        }
        if crate::crypto::PublicPoint::from_bytes(*output.stealth_address.as_bytes()).is_none() {
            return Err(Error::InvalidTransaction(
                "output stealth address is not a valid Ristretto point (unspendable)".into(),
            ));
        }

        // SECURITY (H-19): Reject zero or invalid commitments.
        // A zero commitment (identity point) breaks the balance equation.
        if output.commitment == [0u8; 32] {
            return Err(Error::InvalidTransaction(
                "output commitment is zero (identity point — balance equation breakable)".into(),
            ));
        }
        if crate::crypto::PublicPoint::from_bytes(output.commitment).is_none() {
            return Err(Error::InvalidTransaction(
                "output commitment is not a valid Ristretto point".into(),
            ));
        }
    }

    // SECURITY (C-9 / H-18): Reject inputs with invalid key images.
    // A zero key image or non-curve-point key image bypasses double-spend detection.
    // Historical incident referenced from public record: Monero key
    // image validation bug (April 2017). Details not re-fetched this
    // session; the check below stands on its own security reasoning
    // above.
    if !tx.is_coinbase() {
        for (idx, input) in tx.inputs.iter().enumerate() {
            let ki_bytes = input.key_image.as_bytes();
            if ki_bytes == &[0u8; 32] {
                return Err(Error::InvalidTransaction(format!(
                    "input {} has zero key image (double-spend detection bypass)",
                    idx
                )));
            }
            if crate::crypto::PublicPoint::from_bytes(*ki_bytes).is_none() {
                return Err(Error::InvalidTransaction(format!(
                    "input {} key image is not a valid curve point",
                    idx
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
        {
            crate::constants::TESTNET_MAGIC
        }
        #[cfg(not(feature = "testnet"))]
        {
            crate::constants::MAINNET_MAGIC
        }
    }

    fn test_genesis() -> Block {
        #[cfg(feature = "testnet")]
        {
            crate::testnet::testnet_genesis()
        }
        #[cfg(not(feature = "testnet"))]
        {
            crate::mainnet::mainnet_genesis()
        }
    }

    fn block_at_height(height: u64) -> Block {
        let header = BlockHeader {
            network_magic: test_magic(),
            version: 1,
            height,
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
        Block::new(header, vec![])
    }

    #[test]
    fn tail_supply_gate_does_not_halt_after_year_12() {
        // Regression (2026-08-13): the prior tail-supply gate rejected every
        // curve-correct block past `BLOCKS_PER_YEAR * 12` whose reward exceeded
        // TAIL_EMISSION. But the asymptotic curve does not decay to the tail
        // floor until supply ~= 98.8M CYNC (~height 8.8M / ~year 33), so from
        // ~height 3.15M (~year 12) on, every legitimate block carries a reward
        // > TAIL_EMISSION and was rejected — a permanent chain halt.
        let height = crate::constants::BLOCKS_PER_YEAR * 12 + 1;
        let reward = calculate_block_reward(height);
        assert!(
            reward.as_atomic() > crate::constants::TAIL_EMISSION,
            "precondition: curve reward at year-12 height {} is {} and must still exceed TAIL_EMISSION {} — this is exactly what the old gate wrongly rejected",
            height,
            reward.as_atomic(),
            crate::constants::TAIL_EMISSION
        );
        let block = block_at_height(height);
        let mut result = BlockValidation::ok();
        check_block_tail_supply(&block, reward, &mut result);
        assert!(
            result.valid,
            "curve-correct reward past year 12 must NOT be rejected (this was the chain-halt bug): {:?}",
            result.errors
        );
    }

    #[test]
    fn tail_supply_gate_rejects_out_of_band_rewards() {
        let block = block_at_height(crate::constants::BLOCKS_PER_YEAR * 20);
        // Below the tail floor => the curve's floor guarantee regressed.
        let mut below = BlockValidation::ok();
        check_block_tail_supply(
            &block,
            Amount::from_atomic(crate::constants::TAIL_EMISSION - 1),
            &mut below,
        );
        assert!(!below.valid, "reward below the tail floor must be rejected");
        // Above the height-0 maximum => an inflated (non-monotonic) curve.
        let mut above = BlockValidation::ok();
        let too_high = calculate_block_reward(0).as_atomic() + 1;
        check_block_tail_supply(&block, Amount::from_atomic(too_high), &mut above);
        assert!(
            !above.valid,
            "reward above the genesis maximum must be rejected"
        );
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
        )
        .unwrap();
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
            result
                .errors
                .iter()
                .any(|e| e.to_lowercase().contains("coinbase")),
            "expected a coinbase-related error, got: {:?}",
            result.errors
        );
    }

    // ── Regression tests for the ring-member helpers ──────────────
    //
    // These extract-and-test tests exist because the 2026-06-03 bug
    // in this same file's `check_tx_ring_members` (spent-index branch
    // using MIN_OUTPUT_AGE constant while live-UTXO branch used the
    // height-keyed helper) went undetected until manual review. Now
    // that the maturity check is a single shared helper, one test
    // covers both branches. Adding these regression tests documents
    // the exact semantics: coinbase-only, height-keyed floor, time-
    // lock rejection.

    #[test]
    fn ring_member_non_coinbase_maturity_always_ok() {
        // Non-coinbase outputs: maturity check must be a no-op regardless
        // of age or current_height. Only coinbase outputs are gated.
        assert!(check_ring_member_coinbase_maturity(
            /* is_coinbase */ false, /* output_height */ 0, /* current_height */ 0,
            0, 0,
        )
        .is_ok());
        assert!(check_ring_member_coinbase_maturity(false, 100, 100, 0, 0,).is_ok());
    }

    #[test]
    fn ring_member_coinbase_matures_after_min_age() {
        // Get the height-keyed floor at height 1000 (should be MIN_OUTPUT_AGE
        // or 100 depending on activation status). We construct a coinbase
        // output at (current_height - required_age) which is exactly at the
        // maturity threshold — must pass.
        let current = 1_000u64;
        let required = crate::constants::min_output_age_at_height(current);
        let output_height = current - required; // exactly at maturity
        assert!(
            check_ring_member_coinbase_maturity(true, output_height, current, 0, 0,).is_ok(),
            "coinbase at exactly minimum age must validate"
        );
    }

    #[test]
    fn ring_member_coinbase_immature_below_floor() {
        // One below the maturity floor: must return an error mentioning
        // "immature coinbase".
        let current = 1_000u64;
        let required = crate::constants::min_output_age_at_height(current);
        // Guard against underflow if `required` is somehow larger than
        // current in a weird constants edit — the test would still be
        // meaningful, just needs different arithmetic.
        assert!(required > 0, "test invariant: required age > 0");
        let output_height = current - required + 1; // one block too young
        let err = check_ring_member_coinbase_maturity(true, output_height, current, 3, 7)
            .expect_err("immature coinbase must be rejected");
        let msg = err.to_string();
        assert!(
            msg.contains("immature coinbase"),
            "expected 'immature coinbase' in error, got: {}",
            msg
        );
        assert!(
            msg.contains("Input 3") && msg.contains("ring member 7"),
            "error must include the input+member indices, got: {}",
            msg
        );
    }

    #[test]
    fn ring_member_time_lock_none_is_ok() {
        // No lock set — must be OK at any height.
        assert!(check_ring_member_time_lock(None, 0, 0, 0).is_ok());
        assert!(check_ring_member_time_lock(None, u64::MAX, 0, 0).is_ok());
    }

    #[test]
    fn ring_member_time_lock_past_unlock_ok() {
        // Lock height has passed — output is spendable AND usable as a
        // ring member decoy.
        assert!(
            check_ring_member_time_lock(Some(100), 100, 0, 0).is_ok(),
            "current_height == lock_height must be OK (unlocks at that height)"
        );
        assert!(check_ring_member_time_lock(Some(100), 200, 0, 0).is_ok());
    }

    #[test]
    fn ring_member_time_lock_before_unlock_rejected() {
        // Lock height still ahead — must reject with a "time-locked" error.
        let err = check_ring_member_time_lock(Some(200), 100, 5, 3)
            .expect_err("time-locked output must not be usable as ring member");
        let msg = err.to_string();
        assert!(
            msg.contains("time-locked"),
            "expected 'time-locked' in error, got: {}",
            msg
        );
        assert!(
            msg.contains("Input 5") && msg.contains("ring member 3"),
            "error must include the input+member indices, got: {}",
            msg
        );
    }
}
