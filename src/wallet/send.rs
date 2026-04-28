//! # Transaction Creation for CoinCync 2.0
//!
//! High-level transaction creation with:
//! - UTXO selection (coin control)
//! - Automatic change handling
//! - Fee calculation
//! - Ring member selection

use crate::primitives::{Amount, Address, PublicKey};
use crate::transaction::{
    Transaction, TransactionBuilder, TxType,
    SpendableInput, Recipient, DecoyOutput,
};
use crate::crypto::{
    BlindingFactor,
    StealthAddress, compute_one_time_secret,
    RingSelector, RingSelectionConfig,
    OutputRef as RingOutputRef,
};
use crate::constants::{
    BOOTSTRAP_MIN_RING_SIZE, ring_size_at_height, effective_ring_size, MIN_OUTPUT_AGE, MIN_FEE_PER_BYTE, MIN_OUTPUT_AMOUNT,
    UNIFORM_TX_SHAPE_HEIGHT, STANDARD_INPUT_COUNT, STANDARD_OUTPUT_COUNT,
};
use crate::error::{Error, Result};
use super::{Balance, UTXO, KeyEpoch};

use rand::{Rng, RngCore, CryptoRng, seq::SliceRandom};

fn strict_wallet_privacy_enabled() -> bool {
    std::env::var("COINCYNC_WALLET_ALLOW_WEAK_PRIVACY")
        .ok()
        .map(|v| {
            let t = v.trim();
            !(t == "1" || t.eq_ignore_ascii_case("true") || t.eq_ignore_ascii_case("yes"))
        })
        .unwrap_or(true)
}

fn enforce_wallet_privacy_policy(
    ring_size: usize,
    available_unique_outputs: usize,
) -> Result<()> {
    if !strict_wallet_privacy_enabled() {
        return Ok(());
    }
    if ring_size < BOOTSTRAP_MIN_RING_SIZE {
        return Err(Error::InvalidState(format!(
            "privacy policy: effective ring size {} below minimum {}. \
             Refusing weak-privacy spend; wait for more decoys or set \
             COINCYNC_WALLET_ALLOW_WEAK_PRIVACY=1.",
            ring_size, BOOTSTRAP_MIN_RING_SIZE
        )));
    }
    if available_unique_outputs + 1 < BOOTSTRAP_MIN_RING_SIZE {
        return Err(Error::InvalidState(format!(
            "privacy policy: only {} unique decoys available (need at least {}). \
             Refusing weak-privacy spend; wait for chain growth or set \
             COINCYNC_WALLET_ALLOW_WEAK_PRIVACY=1.",
            available_unique_outputs,
            BOOTSTRAP_MIN_RING_SIZE - 1
        )));
    }
    Ok(())
}

/// Coin selection strategy
#[derive(Clone, Copy, Debug, Default)]
#[allow(dead_code)]
pub enum CoinSelection {
    /// Use oldest UTXOs first (better privacy)
    #[default]
    OldestFirst,
    /// Use newest UTXOs first
    NewestFirst,
    /// Use largest UTXOs first (fewer inputs)
    LargestFirst,
    /// Use smallest UTXOs first (consolidation)
    SmallestFirst,
    /// Random selection (good privacy)
    Random,
}

/// Create a transaction from the wallet (simplified, without ring signatures)
///
/// This builds a structurally valid transaction with proper UTXO selection,
/// fee calculation, and outputs, but without ring signatures or stealth
/// address cryptography. For full privacy transactions, use
/// [`create_privacy_transaction`] or [`SharedWallet::create_transfer`].
#[deprecated(note = "Use create_privacy_transaction or SharedWallet::create_transfer instead — \
    this builder produces outputs with placeholder commitments that fail consensus validation")]
#[allow(dead_code, deprecated)]
pub fn create_transaction(
    balance: &Balance,
    recipients: &[(Address, Amount)],
    current_height: u64,
) -> Result<Transaction> {
    // Calculate totals
    let total_send: Amount = recipients.iter().map(|(_, a)| *a).sum();
    let available = balance.spendable(current_height, MIN_OUTPUT_AGE);

    let ring_size = ring_size_at_height(current_height);
    let estimated_size = estimate_tx_size(1, recipients.len() + 1, ring_size);
    let fee = Amount::from_atomic(estimated_size as u64 * MIN_FEE_PER_BYTE);
    let total_needed = total_send.saturating_add(fee);

    if available < total_needed {
        return Err(Error::InsufficientBalance {
            have: available.as_atomic(),
            need: total_needed.as_atomic(),
        });
    }

    // Select UTXOs
    let utxos = balance.available_utxos(current_height, MIN_OUTPUT_AGE);
    // SECURITY: UTXO selection ordering is a privacy signal — always OsRng,
    // even on the legacy convenience path. Defence in depth: if a test caller
    // ever promotes this helper to non-test use, the privacy boundary is safe.
    let selected = select_utxos(&utxos, total_needed, CoinSelection::OldestFirst, &mut rand::rngs::OsRng)?;

    // Build transaction with selected inputs and recipient outputs
    let mut builder = crate::transaction::SimpleTransactionBuilder::new(TxType::Transfer);
    builder.set_fee(fee);

    // Add outputs for each recipient (using placeholder commitments)
    for (addr, amount) in recipients {
        builder.add_output(
            addr.spend_public_key,
            addr.view_public_key,
            [0u8; 32], // commitment placeholder
            amount.as_atomic().to_le_bytes().to_vec(),
            0, // view_tag placeholder
        );
    }

    // Add change output if needed
    let input_sum: Amount = selected.iter().map(|u| u.amount).sum();
    let change = input_sum.as_atomic().saturating_sub(total_needed.as_atomic());
    if change >= MIN_OUTPUT_AMOUNT {
        builder.add_output(
            crate::primitives::PublicKey::from_bytes([0u8; 32]), // change stealth placeholder
            crate::primitives::PublicKey::from_bytes([0u8; 32]),
            [0u8; 32],
            change.to_le_bytes().to_vec(),
            0,
        );
    }

    builder.build()
}

/// Create a full privacy transaction with all cryptographic operations
#[allow(dead_code)]
pub fn create_privacy_transaction<R: RngCore + CryptoRng>(
    balance: &Balance,
    recipients: &[(PublicKey, PublicKey, Amount)], // (spend_pub, view_pub, amount)
    keys: &KeyEpoch,
    decoy_pool: &[DecoyOutput],
    current_height: u64,
    rng: &mut R,
) -> Result<Transaction> {
    create_privacy_transaction_with_fee(balance, recipients, keys, decoy_pool, current_height, 1.0, rng)
}

/// Create a full privacy transaction with a fee multiplier for priority/RBF
#[allow(dead_code)]
pub fn create_privacy_transaction_with_fee<R: RngCore + CryptoRng>(
    balance: &Balance,
    recipients: &[(PublicKey, PublicKey, Amount)], // (spend_pub, view_pub, amount)
    keys: &KeyEpoch,
    decoy_pool: &[DecoyOutput],
    current_height: u64,
    fee_multiplier: f64, // wallet-side only, NOT consensus. 1.0 = normal, 2.0 = double fee
    rng: &mut R,
) -> Result<Transaction> {
    let total_send: Amount = recipients.iter().map(|(_, _, a)| *a).sum();
    let available = balance.spendable(current_height, MIN_OUTPUT_AGE);

    // Uniform 2-in/2-out: post-activation, Transfer txs must have exactly 2 inputs
    // and 2 outputs. Multi-recipient transfers must be split into separate txs.
    let uniform = current_height >= UNIFORM_TX_SHAPE_HEIGHT;
    if uniform && recipients.len() > 1 {
        return Err(Error::InvalidState(
            "Post-activation: Transfer must have exactly 1 recipient (2-in/2-out). Split into multiple transactions.".into()
        ));
    }

    // Deduplicate the decoy pool by public_key before computing ring size.
    // Old coinbase outputs all share stealth_address = miner_pubkey, so the raw
    // pool can be large but have very few unique keys.
    let mut dedup_seen = std::collections::HashSet::new();
    let deduped_pool: Vec<DecoyOutput> = decoy_pool.iter()
        .filter(|d| dedup_seen.insert(*d.public_key.as_bytes()))
        .cloned()
        .collect();

    // Adapt ring size to the unique decoy pool.  On young chains the pool may be
    // smaller than the target — effective_ring_size lowers the requirement
    // (minimum 2) during the bootstrap period (height < 10,000).
    let ring_size = effective_ring_size(current_height, deduped_pool.len() + 1);
    enforce_wallet_privacy_policy(ring_size, deduped_pool.len())?;

    // Post-activation: fixed 2 inputs, 2 outputs. Pre-activation: variable.
    let input_count_est = if uniform { STANDARD_INPUT_COUNT } else { 1 };
    let output_count = if uniform { STANDARD_OUTPUT_COUNT } else { recipients.len() + 3 };
    let initial_size = estimate_tx_size(input_count_est, output_count, ring_size);

    // Integer-only fee calculation: scale multiplier to avoid float arithmetic.
    // fee_multiplier=1.0 → 100, 1.5 → 150, etc. Clamp minimum at 1.0 (100).
    let multiplier_x100 = (fee_multiplier.max(1.0) * 100.0).min(10000.0) as u64;
    let initial_fee = Amount::from_atomic(
        (initial_size as u64)
            .saturating_mul(MIN_FEE_PER_BYTE)
            .saturating_mul(multiplier_x100) / 100,
    );

    let initial_needed = total_send.saturating_add(initial_fee);

    if available < initial_needed {
        return Err(Error::InsufficientBalance {
            have: available.as_atomic(),
            need: initial_needed.as_atomic(),
        });
    }

    // SECURITY: Filter to native CYNC UTXOs only. available_utxos() returns ALL
    // assets, so a CYNC transfer could accidentally select non-native UTXOs,
    // creating an invalid transaction or burning user assets.
    let utxos: Vec<&UTXO> = balance.available_utxos(current_height, MIN_OUTPUT_AGE);
    let mut selected = if uniform {
        select_utxos_uniform(&utxos, initial_needed, rng)?
    } else {
        select_utxos(&utxos, initial_needed, CoinSelection::OldestFirst, rng)?
    };

    // Re-estimate fee with actual input count — multi-input txs are significantly larger
    let actual_size = estimate_tx_size(selected.len(), output_count, ring_size);
    let estimated_fee = Amount::from_atomic(
        (actual_size as u64)
            .saturating_mul(MIN_FEE_PER_BYTE)
            .saturating_mul(multiplier_x100) / 100,
    );
    let total_needed = total_send.saturating_add(estimated_fee);

    // Re-select if the updated fee requires more funds
    if selected.iter().map(|u| u.amount).sum::<Amount>() < total_needed {
        selected = if uniform {
            select_utxos_uniform(&utxos, total_needed, rng)?
        } else {
            select_utxos(&utxos, total_needed, CoinSelection::OldestFirst, rng)?
        };
    }

    // Calculate actual totals using safe arithmetic
    let input_sum: Amount = selected.iter().map(|u| u.amount).sum();
    let output_total = total_send.as_atomic().saturating_add(estimated_fee.as_atomic());

    // Sanity check: input_sum should always be >= output_total due to earlier selection
    if input_sum.as_atomic() < output_total {
        return Err(Error::InsufficientBalance {
            have: input_sum.as_atomic(),
            need: output_total,
        });
    }

    let change_amount = input_sum.as_atomic().saturating_sub(output_total);

    // SECURITY: Validate ring_size before any arithmetic to prevent panics
    if ring_size == 0 {
        return Err(Error::InvalidRingSize {
            expected: 1,
            got: 0,
        });
    }

    // Check if we have enough unique decoys
    if deduped_pool.len() < ring_size - 1 {
        return Err(Error::InvalidRingSize {
            expected: ring_size,
            got: deduped_pool.len() + 1,
        });
    }

    // Build the transaction (BP+ range proofs at/above activation height)
    let mut builder = TransactionBuilder::transfer()
        .with_target_height(current_height);

    // Add inputs with ring signatures
    for utxo in &selected {
        let stealth = StealthAddress {
            public_key: utxo.tx_public_key, // placeholder; only tx_public_key is used by compute_one_time_secret
            tx_public_key: utxo.tx_public_key,
        };
        let one_time_secret = compute_one_time_secret(
            &stealth, &keys.view_secret, &keys.spend_secret, utxo.output_index,
        )?;
        let real_pubkey = one_time_secret.public_key();
        let input = SpendableInput {
            tx_hash: utxo.tx_hash,
            output_index: utxo.output_index,
            amount: utxo.amount,
            one_time_secret,
            blinding: BlindingFactor::from_bytes(utxo.amount_blinding_bytes),
            height: utxo.height,
        };

        // Select decoys via gamma distribution (RingSelector handles filtering + positioning)
        let (decoys, real_position) = select_ring_decoys(
            &real_pubkey, utxo.height, &deduped_pool, ring_size, current_height, rng,
        )?;
        builder.add_input(input, decoys, real_position)?;
    }

    // Add recipient outputs
    for (i, (spend_pub, view_pub, amount)) in recipients.iter().enumerate() {
        let recipient = Recipient {
            spend_public: *spend_pub,
            view_public: *view_pub,
            amount: *amount,
            lock_height: None,
        };
        builder.add_output(&recipient, i as u8, rng)?;
    }

    // Add change output and dummy outputs
    let final_fee = if uniform {
        // Uniform 2-in/2-out: always exactly 2 outputs total.
        // Output 0 is the recipient (added above).
        // Output 1 is either change (if above dust) or a dummy (zero-value to self).
        if change_amount >= MIN_OUTPUT_AMOUNT {
            builder.add_change(
                &keys.spend_public,
                &keys.view_public,
                Amount::from_atomic(change_amount),
                recipients.len() as u8,
                rng,
            )?;
            estimated_fee
        } else {
            // Change is dust — absorb into fee, add dummy for uniform shape
            let _ = builder.add_dummy_output(rng);
            Amount::from_atomic(estimated_fee.as_atomic().saturating_add(change_amount))
        }
    } else {
        // Pre-activation: variable outputs with random dummies for fingerprint resistance
        let fee = if change_amount >= MIN_OUTPUT_AMOUNT {
            builder.add_change(
                &keys.spend_public,
                &keys.view_public,
                Amount::from_atomic(change_amount),
                recipients.len() as u8,
                rng,
            )?;
            estimated_fee
        } else {
            // Change is dust - add it to fee
            Amount::from_atomic(estimated_fee.as_atomic().saturating_add(change_amount))
        };

        // Add 0-2 dummy outputs for output-count privacy
        let dummy_count = rng.gen_range(0..=2usize);
        for _ in 0..dummy_count {
            let _ = builder.add_dummy_output(rng);
        }
        fee
    };

    // Set fee
    builder.set_fee(final_fee);

    // Build and sign
    builder.build(rng)
}

/// Create a privacy transaction with a time lock on the recipient output.
///
/// The recipient cannot spend the output until `unlock_height` is reached.
/// The amount remains hidden behind a Pedersen commitment.
#[allow(dead_code)]
pub fn create_vesting_transaction<R: RngCore + CryptoRng>(
    balance: &Balance,
    recipient_spend: PublicKey,
    recipient_view: PublicKey,
    amount: Amount,
    unlock_height: u64,
    keys: &KeyEpoch,
    decoy_pool: &[DecoyOutput],
    current_height: u64,
    rng: &mut R,
) -> Result<Transaction> {
    let available = balance.spendable(current_height, MIN_OUTPUT_AGE);

    let mut dedup_seen = std::collections::HashSet::new();
    let deduped_pool: Vec<DecoyOutput> = decoy_pool.iter()
        .filter(|d| dedup_seen.insert(*d.public_key.as_bytes()))
        .cloned()
        .collect();

    let ring_size = effective_ring_size(current_height, deduped_pool.len() + 1);
    enforce_wallet_privacy_policy(ring_size, deduped_pool.len())?;
    let initial_size = estimate_tx_size(1, 4, ring_size); // 1 vesting + 1 change + up to 2 dummies
    let initial_fee = Amount::from_atomic(initial_size as u64 * MIN_FEE_PER_BYTE);
    let total_needed = amount.saturating_add(initial_fee);

    if available < total_needed {
        return Err(Error::InsufficientBalance {
            have: available.as_atomic(),
            need: total_needed.as_atomic(),
        });
    }

    // SECURITY (BUG-13): Filter to native CYNC UTXOs only. Previously used
    // available_utxos() which returns ALL asset types, potentially burning
    // non-native asset tokens in a CYNC vesting transaction.
    let utxos: Vec<&UTXO> = balance.available_utxos(current_height, MIN_OUTPUT_AGE);
    let selected = select_utxos(&utxos, total_needed, CoinSelection::OldestFirst, rng)?;

    // Re-estimate fee based on actual input count (may be > 1)
    let estimated_size = estimate_tx_size(selected.len(), 4, ring_size);
    let estimated_fee = Amount::from_atomic(estimated_size as u64 * MIN_FEE_PER_BYTE);

    let input_sum: Amount = selected.iter().map(|u| u.amount).sum();
    let output_total = amount.as_atomic().saturating_add(estimated_fee.as_atomic());
    let change_amount = input_sum.as_atomic().saturating_sub(output_total);

    if ring_size == 0 || deduped_pool.len() < ring_size - 1 {
        return Err(Error::InvalidRingSize {
            expected: ring_size,
            got: deduped_pool.len() + 1,
        });
    }

    let mut builder = TransactionBuilder::transfer()
        .with_target_height(current_height);

    // Add inputs with ring signatures
    for utxo in &selected {
        let stealth = StealthAddress {
            public_key: utxo.tx_public_key,
            tx_public_key: utxo.tx_public_key,
        };
        let one_time_secret = compute_one_time_secret(
            &stealth, &keys.view_secret, &keys.spend_secret, utxo.output_index,
        )?;
        let real_pubkey = one_time_secret.public_key();
        let input = SpendableInput {
            tx_hash: utxo.tx_hash,
            output_index: utxo.output_index,
            amount: utxo.amount,
            one_time_secret,
            blinding: BlindingFactor::from_bytes(utxo.amount_blinding_bytes),
            height: utxo.height,
        };
        let (decoys, real_position) = select_ring_decoys(
            &real_pubkey, utxo.height, &deduped_pool, ring_size, current_height, rng,
        )?;
        builder.add_input(input, decoys, real_position)?;
    }

    // Add vesting output with lock_height
    let recipient = Recipient {
        spend_public: recipient_spend,
        view_public: recipient_view,
        amount,
        lock_height: Some(unlock_height),
    };
    builder.add_output(&recipient, 0, rng)?;

    // Add change output (no lock)
    let final_fee = if change_amount >= MIN_OUTPUT_AMOUNT {
        builder.add_change(
            &keys.spend_public, &keys.view_public,
            Amount::from_atomic(change_amount), 1, rng,
        )?;
        estimated_fee
    } else {
        Amount::from_atomic(estimated_fee.as_atomic().saturating_add(change_amount))
    };

    // Add dummy outputs for output-count privacy
    let dummy_count = rng.gen_range(0..=2usize);
    for _ in 0..dummy_count {
        let _ = builder.add_dummy_output(rng);
    }

    builder.set_fee(final_fee);
    builder.build(rng)
}

/// Create a churn transaction (self-send) for graph analysis resistance
///
/// Sends all spendable funds back to the wallet using fresh stealth addresses
/// and new ring members. This breaks transaction graph links by making the
/// outputs appear as a transfer to a new recipient.
///
/// Uses `TxType::Churn` and random coin selection for maximum unlinkability.
#[allow(dead_code)]
pub fn create_churn_transaction<R: RngCore + CryptoRng>(
    balance: &Balance,
    keys: &KeyEpoch,
    decoy_pool: &[DecoyOutput],
    current_height: u64,
    rng: &mut R,
) -> Result<Transaction> {
    let available = balance.spendable(current_height, MIN_OUTPUT_AGE);
    if available.as_atomic() == 0 {
        return Err(Error::InsufficientBalance { have: 0, need: 1 });
    }

    // Deduplicate the decoy pool by public_key (same as create_privacy_transaction).
    let mut dedup_seen = std::collections::HashSet::new();
    let deduped_pool: Vec<DecoyOutput> = decoy_pool.iter()
        .filter(|d| dedup_seen.insert(*d.public_key.as_bytes()))
        .cloned()
        .collect();

    // Use effective_ring_size to handle young chains with few unique outputs
    let ring_size = effective_ring_size(current_height, deduped_pool.len() + 1);
    enforce_wallet_privacy_policy(ring_size, deduped_pool.len())?;

    let uniform = current_height >= UNIFORM_TX_SHAPE_HEIGHT;

    // SECURITY (BUG-13): Filter to native CYNC UTXOs only for churn transactions.
    let utxos: Vec<&UTXO> = balance.available_utxos(current_height, MIN_OUTPUT_AGE);
    let selected = if uniform {
        // Uniform mode: exactly 2 inputs
        let est_size = estimate_tx_size(STANDARD_INPUT_COUNT, STANDARD_OUTPUT_COUNT, ring_size);
        let est_fee = Amount::from_atomic(est_size as u64 * MIN_FEE_PER_BYTE);
        let min_target = Amount::from_atomic(est_fee.as_atomic().saturating_add(MIN_OUTPUT_AMOUNT));
        select_utxos_uniform(&utxos, min_target, rng)?
    } else {
        // Pre-activation: pick a small random batch (not all UTXOs).
        // Churning all at once links every UTXO in one tx — terrible for privacy.
        // Small batches (2-4 inputs) are stealthier; run churn repeatedly to
        // consolidate more. Cap at 4 to keep the tx size reasonable.
        const CHURN_BATCH_SIZE: usize = 4;
        let batch_count = CHURN_BATCH_SIZE.min(utxos.len());
        use rand::seq::SliceRandom;
        let mut shuffled: Vec<&UTXO> = utxos.to_vec();
        shuffled.shuffle(rng);
        shuffled.truncate(batch_count);
        shuffled
    };

    // Compute fee based on actual input count (2 outputs: self-send + change)
    let actual_input_count = selected.len();
    let estimated_size = estimate_tx_size(actual_input_count, 2, ring_size);
    let fee = Amount::from_atomic(estimated_size as u64 * MIN_FEE_PER_BYTE);

    let input_sum: Amount = selected.iter().map(|u| u.amount).sum();
    let churn_amount = Amount::from_atomic(input_sum.as_atomic().saturating_sub(fee.as_atomic()));
    if churn_amount.as_atomic() < MIN_OUTPUT_AMOUNT {
        return Err(Error::InsufficientBalance {
            have: available.as_atomic(),
            need: fee.as_atomic().saturating_add(MIN_OUTPUT_AMOUNT),
        });
    }

    // Validate ring size
    if ring_size == 0 {
        return Err(Error::InvalidRingSize { expected: 1, got: 0 });
    }
    if deduped_pool.len() < ring_size - 1 {
        return Err(Error::InvalidRingSize {
            expected: ring_size,
            got: deduped_pool.len() + 1,
        });
    }

    let mut builder = TransactionBuilder::new(TxType::Churn)
        .with_target_height(current_height);

    // Add inputs with ring signatures
    for utxo in &selected {
        let stealth = StealthAddress {
            public_key: utxo.tx_public_key,
            tx_public_key: utxo.tx_public_key,
        };
        let one_time_secret = compute_one_time_secret(
            &stealth, &keys.view_secret, &keys.spend_secret, utxo.output_index,
        )?;
        let real_pubkey = one_time_secret.public_key();
        let input = SpendableInput {
            tx_hash: utxo.tx_hash,
            output_index: utxo.output_index,
            amount: utxo.amount,
            one_time_secret,
            blinding: BlindingFactor::from_bytes(utxo.amount_blinding_bytes),
            height: utxo.height,
        };
        let (decoys, real_position) = select_ring_decoys(
            &real_pubkey, utxo.height, &deduped_pool, ring_size, current_height, rng,
        )?;
        builder.add_input(input, decoys, real_position)?;
    }

    // Single output to self with fresh stealth address
    let recipient = Recipient {
        spend_public: keys.spend_public,
        view_public: keys.view_public,
        amount: churn_amount,
        lock_height: None,
    };
    builder.add_output(&recipient, 0, rng)?;

    // Handle change (input_sum - churn_amount - fee)
    let output_total = churn_amount.as_atomic().saturating_add(fee.as_atomic());
    let change = input_sum.as_atomic().saturating_sub(output_total);
    let final_fee = if uniform {
        // Uniform 2-in/2-out: always exactly 2 outputs (self-send + change/dummy)
        if change >= MIN_OUTPUT_AMOUNT {
            builder.add_change(
                &keys.spend_public, &keys.view_public,
                Amount::from_atomic(change), 1, rng,
            )?;
            fee
        } else {
            let _ = builder.add_dummy_output(rng);
            Amount::from_atomic(fee.as_atomic().saturating_add(change))
        }
    } else {
        // Pre-activation: variable outputs
        let f = if change >= MIN_OUTPUT_AMOUNT {
            builder.add_change(
                &keys.spend_public, &keys.view_public,
                Amount::from_atomic(change), 1, rng,
            )?;
            fee
        } else {
            Amount::from_atomic(fee.as_atomic().saturating_add(change))
        };
        // Add dummy outputs for count uniformity
        let dummy_count = rng.gen_range(0..=2usize);
        for _ in 0..dummy_count {
            let _ = builder.add_dummy_output(rng);
        }
        f
    };

    builder.set_fee(final_fee);
    builder.build(rng)
}

// ─── Asset transaction creation ──────────────────────────────────────────────

/// Create a confidential asset transfer transaction.
///
/// Builds a transaction that sends `asset_amount` of `asset_id` tokens to
/// `recipient`, paying the fee in native CYNC.  Both the asset type and amount
/// are kept hidden on-chain through blinded asset commitments and Asset
/// Surjection Proofs.
///
/// # Requirements
/// - `cync_balance` must contain spendable CYNC UTXOs for fee payment.
/// - `asset_balance` must contain spendable asset UTXOs of the given `asset_id`.
/// - If `asset_id.is_native()`, use `create_privacy_transaction_with_fee` instead.
#[allow(dead_code)]

/// Select UTXOs to cover the required amount
///
/// PRIVACY: Uses randomization within each strategy to prevent fingerprinting.
/// Even deterministic strategies shuffle UTXOs of equal priority.
///
/// FIX: Accepts `rng: &mut R` so callers control randomness throughout.
/// Previously created `rand::thread_rng()` internally, making selection
/// non-deterministic even when callers passed a seeded test RNG.
fn select_utxos<'a, R: RngCore + CryptoRng>(
    utxos: &[&'a UTXO],
    target: Amount,
    strategy: CoinSelection,
    rng: &mut R,
) -> Result<Vec<&'a UTXO>> {
    if utxos.is_empty() {
        return Err(Error::NoOutputsAvailable);
    }

    let mut sorted: Vec<&UTXO> = utxos.to_vec();

    // First shuffle to break any ordering bias, then stable sort by strategy
    sorted.shuffle(rng);

    // Sort based on strategy (stable sort preserves random order for equal keys)
    match strategy {
        CoinSelection::OldestFirst => {
            sorted.sort_by_key(|u| u.height);
        }
        CoinSelection::NewestFirst => {
            sorted.sort_by_key(|u| std::cmp::Reverse(u.height));
        }
        CoinSelection::LargestFirst => {
            sorted.sort_by_key(|u| std::cmp::Reverse(u.amount.as_atomic()));
        }
        CoinSelection::SmallestFirst => {
            sorted.sort_by_key(|u| u.amount.as_atomic());
        }
        CoinSelection::Random => {
            // Already shuffled above - no additional sorting needed
        }
    }

    // Select UTXOs until we have enough
    let mut selected = Vec::new();
    let mut sum = Amount::ZERO;

    for utxo in sorted {
        selected.push(utxo);
        sum = sum.saturating_add(utxo.amount);
        if sum >= target {
            return Ok(selected);
        }
    }

    // Not enough funds
    Err(Error::InsufficientBalance {
        have: sum.as_atomic(),
        need: target.as_atomic(),
    })
}

/// Select exactly 2 UTXOs whose combined value covers `target`.
///
/// Required for uniform 2-in/2-out transaction shape post-activation.
/// Strategy: sort descending, find all valid pairs via two-pointer sweep,
/// then randomly select among the best candidates for privacy.
/// Complexity: O(n log n) instead of the naive O(n²).
/// Returns `InsufficientInputs` if no valid pair exists.
fn select_utxos_uniform<'a, R: RngCore + CryptoRng>(
    utxos: &[&'a UTXO],
    target: Amount,
    rng: &mut R,
) -> Result<Vec<&'a UTXO>> {
    use rand::seq::SliceRandom;

    if utxos.len() < STANDARD_INPUT_COUNT {
        return Err(Error::InsufficientInputs {
            have: utxos.len(),
            need: STANDARD_INPUT_COUNT,
        });
    }

    let target_val = target.as_atomic();

    // Sort indices by amount descending for efficient two-pointer sweep
    let mut indices: Vec<usize> = (0..utxos.len()).collect();
    indices.sort_by(|a, b| utxos[*b].amount.as_atomic().cmp(&utxos[*a].amount.as_atomic()));

    // Two-pointer: find all valid pairs, collect candidates with reasonable excess
    let mut candidates: Vec<(usize, usize, u64)> = Vec::new();
    let mut best_excess = u64::MAX;

    let mut lo = 0usize;
    let mut hi = indices.len() - 1;
    while lo < hi {
        let sum = utxos[indices[lo]].amount.as_atomic()
            .saturating_add(utxos[indices[hi]].amount.as_atomic());
        if sum >= target_val {
            let excess = sum - target_val;
            if excess < best_excess {
                best_excess = excess;
            }
            candidates.push((indices[lo], indices[hi], excess));
            hi -= 1;
        } else {
            lo += 1;
        }
    }

    if candidates.is_empty() {
        return Err(Error::InsufficientInputs {
            have: utxos.len(),
            need: STANDARD_INPUT_COUNT,
        });
    }

    // PRIVACY: randomly select among candidates within 20% of the best excess
    // to prevent deterministic fingerprinting of UTXO selection
    let threshold = best_excess.saturating_add(best_excess / 5).max(best_excess.saturating_add(1));
    let good_candidates: Vec<_> = candidates.iter()
        .filter(|(_, _, e)| *e <= threshold)
        .collect();

    // SECURITY: UTXO-pair selection is a privacy signal (bigger pair vs smaller,
    // age profile). Use the caller-supplied rng — every public callsite in
    // the wallet binary already passes `OsRng` (verified at audit time).
    // The previous code constructed a fresh `thread_rng()` here, which both
    // (a) ignored the caller's intent and (b) downgraded the entropy source
    // for the privacy boundary. Both are now fixed.
    let &&(i, j, _) = good_candidates.choose(rng).unwrap_or(&&candidates[0]);
    Ok(vec![utxos[i], utxos[j]])
}

/// Select decoys using temporal binning for improved privacy.
///
/// Select ring decoys using gamma distribution via RingSelector.
///
/// Delegates to `crypto::RingSelector` which uses a gamma distribution
/// (shape=19.28, scale=0.621) to bias decoy selection toward recent outputs,
/// matching real spending patterns. This makes the real signer statistically
/// indistinguishable from decoys.
///
/// Returns (decoys, real_position) — the decoy list and the index where
/// the real output should be inserted in the ring.
fn select_ring_decoys<R: RngCore + CryptoRng>(
    real_pubkey: &PublicKey,
    real_height: u64,
    pool: &[DecoyOutput],
    ring_size: usize,
    current_height: u64,
    rng: &mut R,
) -> Result<(Vec<DecoyOutput>, usize)> {
    use crate::primitives::Hash;

    // Derive a unique global_index from public key bytes (for deduplication).
    let pubkey_to_gi = |pk: &PublicKey| -> u64 {
        let b = pk.as_bytes();
        u64::from_le_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]])
    };

    // Convert real output to OutputRef
    let real_ref = RingOutputRef {
        height: real_height,
        tx_hash: Hash::default(),
        output_index: 0,
        public_key: *real_pubkey,
        commitment: [0u8; 32],
        global_index: pubkey_to_gi(real_pubkey),
    };

    // Convert pool to OutputRef
    let pool_refs: Vec<RingOutputRef> = pool.iter().map(|d| {
        RingOutputRef {
            height: d.height,
            tx_hash: Hash::default(),
            output_index: 0,
            public_key: d.public_key,
            commitment: d.commitment,
            global_index: pubkey_to_gi(&d.public_key),
        }
    }).collect();

    // Configure selector: non-strict mode, min_decoy_age=0 for young chains
    let config = RingSelectionConfig {
        target_ring_size: ring_size,
        min_ring_size: ring_size,
        max_ring_size: ring_size,
        min_decoy_age: 0,
        ..RingSelectionConfig::default()
    };
    let selector = RingSelector::new(config);

    let (ring, real_index, _stats) = selector.select_ring(
        &real_ref, &pool_refs, current_height, rng,
    )?;

    // Extract decoys (all ring members except the real output)
    let decoys: Vec<DecoyOutput> = ring.into_iter()
        .enumerate()
        .filter(|(i, _)| *i != real_index)
        .map(|(_, r)| DecoyOutput {
            public_key: r.public_key,
            commitment: r.commitment,
            height: r.height,
        })
        .collect();

    Ok((decoys, real_index))
}

/// Estimate transaction size in bytes
pub fn estimate_tx_size(input_count: usize, output_count: usize, ring_size: usize) -> usize {
    // Base overhead (tx_type + fee + payment_id option + borsh vec headers)
    let base = 32;

    // Input (borsh): key_image (32) + ring_members vec (4 + 64*ring_size)
    //   + CLSAG sig (key_image 32 + commitment_image 32 + c1 32 + responses vec 4+32*ring_size)
    //   + pseudo_output_commitment (32) + asset_commitment (32)
    let input_size = 32 + 4 + 64 * ring_size + 32 + 32 + 32 + 4 + 32 * ring_size + 32 + 32;
    let inputs_total = input_count * input_size;

    // Output (borsh): stealth (32) + tx_pub (32) + commitment (32) + enc_amount vec (4+8)
    //   + view_tag (1) + asset_commitment (32) + encrypted_asset vec (4+32)
    //   + asset_surjection_proof vec (4+0) + encrypted_asset_audit vec (4+0)
    //   + lock_height Option<u64> (1+8)
    let output_size = 32 + 32 + 32 + 12 + 1 + 32 + 36 + 4 + 4 + 9;
    let outputs_total = output_count * output_size;

    // Range proof: ~672 base + 64 per output for aggregated proof
    let range_proof = 672 + 64 * output_count;

    // Apply 2x safety margin — borsh encoding adds vec-length prefixes,
    // Option discriminants, and padding that are hard to predict exactly.
    // Dummy outputs (0-2 random) also make the actual size unpredictable.
    (base + inputs_total + outputs_total + range_proof) * 2
}

/// Calculate recommended fee for a transaction.
///
/// Returns the estimated fee without building the transaction or generating proofs.
/// Useful for previewing fees before committing to a send.
#[allow(dead_code)]
pub fn calculate_fee(input_count: usize, output_count: usize, current_height: u64) -> Amount {
    let ring_size = ring_size_at_height(current_height);
    let size = estimate_tx_size(input_count, output_count, ring_size);
    Amount::from_atomic(size as u64 * MIN_FEE_PER_BYTE)
}

/// Estimate fee with a fee multiplier applied.
///
/// `fee_multiplier` defaults to 1.0 for normal priority.
/// Higher values (1.5, 2.0) for faster confirmation during congestion.
pub fn estimate_fee_with_multiplier(
    input_count: usize,
    output_count: usize,
    current_height: u64,
    fee_multiplier: f64,
) -> Amount {
    let ring_size = ring_size_at_height(current_height);
    let size = estimate_tx_size(input_count, output_count, ring_size);
    let base_fee = size as u64 * MIN_FEE_PER_BYTE;
    let multiplier_x100 = (fee_multiplier.max(1.0) * 100.0).min(10000.0) as u64;
    Amount::from_atomic(base_fee.saturating_mul(multiplier_x100) / 100)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    static ENV_LOCK: Mutex<()> = Mutex::new(());

    #[test]
    fn test_estimate_tx_size() {
        // Standard transfer: 1 input, 2 outputs, ring size 11
        let size = estimate_tx_size(1, 2, 11);
        assert!(size > 1000);
        assert!(size < 5000);
    }

    #[test]
    fn test_calculate_fee() {
        let fee = calculate_fee(1, 2, 0);
        assert!(fee.as_atomic() > 0);
    }

    #[test]
    fn test_coin_selection_empty() {
        let utxos: Vec<&UTXO> = vec![];
        let result = select_utxos(&utxos, Amount::from_atomic(100), CoinSelection::OldestFirst, &mut rand::rngs::OsRng);
        assert!(result.is_err());
    }

    #[test]
    fn test_privacy_policy_rejects_weak_ring_when_strict() {
        let _guard = ENV_LOCK.lock().expect("env lock");
        std::env::remove_var("COINCYNC_WALLET_ALLOW_WEAK_PRIVACY");
        let err = enforce_wallet_privacy_policy(2, 1).unwrap_err();
        assert!(format!("{err}").contains("privacy policy"));
    }

    #[test]
    fn test_privacy_policy_can_be_overridden_for_dev() {
        let _guard = ENV_LOCK.lock().expect("env lock");
        std::env::set_var("COINCYNC_WALLET_ALLOW_WEAK_PRIVACY", "1");
        let ok = enforce_wallet_privacy_policy(2, 1);
        std::env::remove_var("COINCYNC_WALLET_ALLOW_WEAK_PRIVACY");
        assert!(ok.is_ok());
    }
}
