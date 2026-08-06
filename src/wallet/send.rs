//! # Transaction Creation for CoinCync 1.0
//!
//! High-level transaction creation with:
//! - UTXO selection (coin control)
//! - Automatic change handling
//! - Fee calculation
//! - Ring member selection

use super::{Balance, KeyEpoch, UTXO};
use crate::constants::{
    effective_ring_size, min_output_age_at_height, ring_size_at_height, BOOTSTRAP_MIN_RING_SIZE,
    MIN_FEE_PER_BYTE, MIN_OUTPUT_AMOUNT, STANDARD_INPUT_COUNT, STANDARD_OUTPUT_COUNT,
    UNIFORM_TX_SHAPE_HEIGHT,
};
use crate::crypto::{
    compute_one_time_secret, BlindingFactor, OutputRef as RingOutputRef, PedersenCommitment,
    RingSelectionConfig, RingSelectionPool, RingSelector, StealthAddress,
};
use crate::error::{Error, Result};
use crate::primitives::{Address, Amount, PublicKey};
use crate::transaction::{
    DecoyOutput, Recipient, SpendableInput, Transaction, TransactionBuilder, TxType,
};
use crate::wallet::decoy_selection::{AllocatedRing, RealOutputIdentity};

use rand::{seq::SliceRandom, CryptoRng, Rng, RngCore};

#[derive(Clone)]
struct PreparedInput {
    input: SpendableInput,
    real_output: RealOutputIdentity,
}

pub struct PreparedPrivacyTransaction {
    inputs: Vec<PreparedInput>,
    recipients: Vec<(PublicKey, PublicKey, Amount)>,
    change_amount: u64,
    estimated_fee: Amount,
    current_height: u64,
    uniform: bool,
    drip_pair: bool,
    spend_public: PublicKey,
    view_public: PublicKey,
    memo: Option<Vec<u8>>,
    extra: Vec<u8>,
    ring_size: usize,
}

impl PreparedPrivacyTransaction {
    pub fn real_outputs(&self) -> Vec<RealOutputIdentity> {
        self.inputs.iter().map(|input| input.real_output).collect()
    }

    pub fn ring_size(&self) -> usize {
        self.ring_size
    }

    pub fn input_count(&self) -> usize {
        self.inputs.len()
    }
}

pub struct PreparedVestingTransaction {
    inputs: Vec<PreparedInput>,
    recipient_spend: PublicKey,
    recipient_view: PublicKey,
    amount: Amount,
    unlock_height: u64,
    change_amount: u64,
    estimated_fee: Amount,
    current_height: u64,
    spend_public: PublicKey,
    view_public: PublicKey,
    ring_size: usize,
}

impl PreparedVestingTransaction {
    pub fn real_outputs(&self) -> Vec<RealOutputIdentity> {
        self.inputs.iter().map(|input| input.real_output).collect()
    }

    pub fn ring_size(&self) -> usize {
        self.ring_size
    }

    pub fn input_count(&self) -> usize {
        self.inputs.len()
    }
}

/// AUDIT (R-105 note, 2026-07-03): `COINCYNC_WALLET_ALLOW_WEAK_PRIVACY`
/// is an ENVIRONMENT VARIABLE that disables the strict-privacy policy
/// GLOBALLY for the whole process — the wallet daemon starts under a
/// specific env, and every send() in the process inherits the setting.
/// A per-invocation consent flow (the user acknowledges the reduced
/// privacy for THIS specific tx via a CLI flag / RPC parameter) would
/// be safer, because the operator's decision to enable weak privacy
/// for one debug session persists across all future sends without
/// re-prompting.
///
/// Pre-fix code had no comment about the risk. Now, if the fallback
/// fires, we emit a LOUD error log naming the env variable — so at
/// least the operator sees each degraded-privacy tx in structured
/// logs and can page. A structural fix (per-invocation flag) is
/// deferred pending an RPC schema decision.
fn strict_wallet_privacy_enabled() -> bool {
    let allow_weak = std::env::var("COINCYNC_WALLET_ALLOW_WEAK_PRIVACY").ok();
    if let Some(ref v) = allow_weak {
        let t = v.trim();
        if t == "1" || t.eq_ignore_ascii_case("true") || t.eq_ignore_ascii_case("yes") {
            // R-105: loud + structured so log aggregation catches it.
            tracing::error!(
                target: "wallet::send::R105",
                env_var = "COINCYNC_WALLET_ALLOW_WEAK_PRIVACY",
                env_value = %v,
                "R-105: strict-privacy policy DISABLED via env var. \
                 Every send() in this process runs with weakened \
                 anonymity-set + ring-size constraints. This is \
                 process-global, NOT per-invocation. If you didn't \
                 intend this, unset the env var and restart."
            );
            return false;
        }
    }
    true
}

/// Per-invocation privacy consent.
///
/// R-105 SURGICAL FIX (2026-07-03): callers can opt into weak
/// privacy for a SINGLE tx via `PrivacyConsent::AllowWeakThisTx`.
/// Previous env-var-only path stays as the process-wide override,
/// but a per-tx toggle avoids the "one debug session leaks into
/// every future send" trap.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum PrivacyConsent {
    /// Strict privacy required. Default.
    #[default]
    Strict,
    /// Allow weak privacy for THIS invocation only. Emit an
    /// error-level log so ops see the consent event.
    AllowWeakThisTx,
}

fn enforce_wallet_privacy_policy(
    ring_size: usize,
    available_unique_outputs: usize,
    consent: PrivacyConsent,
) -> Result<()> {
    // R-105: per-invocation consent short-circuits the strict
    // check. Emit a distinct log so audit trails can distinguish
    // per-tx consent from process-global env override.
    if consent == PrivacyConsent::AllowWeakThisTx {
        tracing::error!(
            target: "wallet::send::R105",
            event = "per_tx_weak_privacy_consent",
            ring_size = ring_size,
            available_unique_outputs = available_unique_outputs,
            "R-105: per-tx weak-privacy consent granted for this send. \
             Recorded so the audit trail carries the consent event."
        );
        return Ok(());
    }
    if !strict_wallet_privacy_enabled() {
        return Ok(());
    }
    if ring_size < BOOTSTRAP_MIN_RING_SIZE {
        return Err(Error::InvalidState(format!(
            "privacy policy: effective ring size {} below minimum {}. \
             Refusing weak-privacy spend; wait for more decoys, set \
             COINCYNC_WALLET_ALLOW_WEAK_PRIVACY=1, or pass \
             PrivacyConsent::AllowWeakThisTx.",
            ring_size, BOOTSTRAP_MIN_RING_SIZE
        )));
    }
    if available_unique_outputs + 1 < BOOTSTRAP_MIN_RING_SIZE {
        return Err(Error::InvalidState(format!(
            "privacy policy: only {} unique decoys available (need at least {}). \
             Refusing weak-privacy spend; wait for chain growth, set \
             COINCYNC_WALLET_ALLOW_WEAK_PRIVACY=1, or pass \
             PrivacyConsent::AllowWeakThisTx.",
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
#[deprecated(
    note = "Use create_privacy_transaction or SharedWallet::create_transfer instead — \
    this builder produces outputs with placeholder commitments that fail consensus validation"
)]
#[allow(dead_code, deprecated)]
pub fn create_transaction(
    balance: &Balance,
    recipients: &[(Address, Amount)],
    current_height: u64,
) -> Result<Transaction> {
    // CONSENSUS-COUPLED: maturity floor flips at the MIN_OUTPUT_AGE
    // hard-fork height. Use the helper so wallet selection agrees
    // with the validator at every height.
    let min_age = min_output_age_at_height(current_height);
    // Calculate totals
    let total_send: Amount = recipients.iter().map(|(_, a)| *a).sum();
    let available = balance.spendable(current_height, min_age);

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
    let utxos = balance.available_utxos(current_height, min_age);
    // SECURITY: UTXO selection ordering is a privacy signal — always OsRng,
    // even on the legacy convenience path. Defence in depth: if a test caller
    // ever promotes this helper to non-test use, the privacy boundary is safe.
    let selected = select_utxos(
        &utxos,
        total_needed,
        CoinSelection::OldestFirst,
        &mut rand::rngs::OsRng,
    )?;

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
    let change = input_sum
        .as_atomic()
        .saturating_sub(total_needed.as_atomic());
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
    create_privacy_transaction_with_fee(
        balance,
        recipients,
        keys,
        decoy_pool,
        current_height,
        1.0,
        rng,
    )
}

/// Create a full privacy transaction with a fee multiplier for priority/RBF.
///
/// Wrapper that calls the options-bearing variant with `memo = None` and
/// `extra = Vec::new()`. Preserves the no-extras call shape used by
/// `wallet::churn` and other callers that don't need a memo or recovery
/// metadata. New callers that DO need either should call
/// `create_privacy_transaction_with_options` directly.
#[allow(dead_code)]
pub fn create_privacy_transaction_with_fee<R: RngCore + CryptoRng>(
    balance: &Balance,
    recipients: &[(PublicKey, PublicKey, Amount)],
    keys: &KeyEpoch,
    decoy_pool: &[DecoyOutput],
    current_height: u64,
    fee_multiplier: f64,
    rng: &mut R,
) -> Result<Transaction> {
    create_privacy_transaction_with_options(
        balance,
        recipients,
        keys,
        decoy_pool,
        current_height,
        fee_multiplier,
        None,
        Vec::new(),
        rng,
    )
}

/// Create a full privacy transaction with optional encrypted memo and
/// optional `tx.extra` bytes.
///
/// `memo` (if `Some`) is encrypted on the first recipient output and
/// recoverable by anyone holding the recipient's view key (max 256
/// bytes plaintext per consensus rules).
///
/// `extra` is embedded into `tx.extra` verbatim. The current production
/// use is `RecoveryMeta::encode_all(&[meta])` for the dead-man's-switch
/// flow — `set-recovery` configures the recovery pubkey + timeout,
/// `send --recovery-address X --recovery-timeout Y` produces the
/// 42-byte encoding, and the chain validator persists it so the
/// recovery wallet can detect expiry and sweep.
#[allow(dead_code)]
pub fn create_privacy_transaction_with_options<R: RngCore + CryptoRng>(
    balance: &Balance,
    recipients: &[(PublicKey, PublicKey, Amount)], // (spend_pub, view_pub, amount)
    keys: &KeyEpoch,
    decoy_pool: &[DecoyOutput],
    current_height: u64,
    fee_multiplier: f64, // wallet-side only, NOT consensus. 1.0 = normal, 2.0 = double fee
    memo: Option<&[u8]>,
    extra: Vec<u8>,
    rng: &mut R,
) -> Result<Transaction> {
    // CONSENSUS-COUPLED: maturity floor flips at MIN_OUTPUT_AGE
    // hard-fork height. Resolve once per call so every downstream
    // path (spendable, pending-maturity error, decoy filter) reads
    // the same value.
    let min_age = min_output_age_at_height(current_height);
    let total_send: Amount = recipients.iter().map(|(_, _, a)| *a).sum();
    let available = balance.spendable(current_height, min_age);

    // Uniform 2-in/2-out: post-activation, Transfer txs must have exactly 2 inputs
    // and 2 outputs. There are TWO valid shapes that satisfy this:
    //
    //   (a) Standard: 1 recipient + 1 change output (the common case).
    //   (b) Drip-pair: 2 outputs to the SAME recipient address, no change. Used
    //       by the testnet faucet to give a first-time recipient two UTXOs in
    //       a single tx (otherwise they'd hold one UTXO and the uniform
    //       2-input rule would lock them out from spending until they receive
    //       a second payment).
    //
    // Anything else (truly multi-recipient) must be split into separate txs.
    let uniform = current_height >= UNIFORM_TX_SHAPE_HEIGHT;
    let drip_pair = uniform && recipients.len() == STANDARD_OUTPUT_COUNT && {
        // All entries point to the same (spend, view) destination.
        recipients.windows(2).all(|w| {
            w[0].0.as_bytes() == w[1].0.as_bytes() && w[0].1.as_bytes() == w[1].1.as_bytes()
        })
    };
    if uniform && recipients.len() > 1 && !drip_pair {
        return Err(Error::InvalidState(
            "Post-activation: Transfer must have exactly 1 recipient (2-in/2-out). \
             Multi-recipient must be split into separate txs. To send a drip-pair \
             (two outputs to the same address in one tx, used by the faucet for \
             first-time recipients), pass the recipient twice with amounts that \
             together cover the desired drip total — change becomes fee."
                .into(),
        ));
    }

    let ring_pool = ring_selection_pool(decoy_pool);

    // Adapt ring size to the unique decoy pool.  On young chains the pool may be
    // smaller than the target — effective_ring_size lowers the requirement
    // (minimum 2) during the bootstrap period (height < 10,000).
    let ring_size = effective_ring_size(current_height, ring_pool.len() + 1);
    enforce_wallet_privacy_policy(ring_size, ring_pool.len(), PrivacyConsent::Strict)?;

    // Post-activation: fixed 2 inputs, 2 outputs. Pre-activation: variable.
    let input_count_est = if uniform { STANDARD_INPUT_COUNT } else { 1 };
    let output_count = if uniform {
        STANDARD_OUTPUT_COUNT
    } else {
        recipients.len() + 3
    };
    let initial_size = estimate_tx_size(input_count_est, output_count, ring_size);

    // Integer-only fee calculation: scale multiplier to avoid float arithmetic.
    // fee_multiplier=1.0 → 100, 1.5 → 150, etc. Clamp minimum at 1.0 (100).
    //
    // AUDIT (R-106 fix, 2026-07-03): pre-fix code was
    //   `(fee_multiplier.max(1.0) * 100.0).min(10000.0) as u64;`
    // Problem: `NaN.max(1.0)` returns NaN (IEEE 754 quirk — max
    // propagates NaN, doesn't collapse to the operand). Then
    // `NaN * 100.0` is NaN, `NaN.min(10000.0)` is NaN, and
    // `NaN as u64` is 0. Result: an accidental NaN multiplier
    // (caller passes an uninitialized float, JSON parser returns
    // NaN for the string "NaN", etc.) produces ZERO FEE — the
    // wallet then submits a tx that will be REJECTED by mempool's
    // minimum-fee rule, silently. Explicit NaN check with a
    // fallback to 1.0 (the neutral multiplier), plus a warn so
    // the caller sees it happened.
    let sanitized_multiplier = if fee_multiplier.is_nan() {
        tracing::warn!(
            target: "wallet::send::R106",
            "R-106: fee_multiplier is NaN; falling back to 1.0 (neutral). \
             Caller likely passed an uninitialized or malformed float."
        );
        1.0
    } else {
        fee_multiplier
    };
    let multiplier_x100 = (sanitized_multiplier.max(1.0) * 100.0).min(10000.0) as u64;
    let initial_fee = Amount::from_atomic(
        (initial_size as u64)
            .saturating_mul(MIN_FEE_PER_BYTE)
            .saturating_mul(multiplier_x100)
            / 100,
    );

    let initial_needed = total_send.saturating_add(initial_fee);

    if available < initial_needed {
        // Distinguish "no funds" from "funds present but not yet mature":
        //   - If total balance covers `need`, the user has the money but
        //     some UTXOs haven't reached MIN_OUTPUT_AGE yet. Tell them how
        //     long to wait instead of "have 0", which sent users into a
        //     panic loop during 2026-05-07 testnet onboarding.
        //   - If total balance is also short, return InsufficientBalance.
        let total = balance.total();
        if total >= initial_needed {
            // We have it; it's just not mature. Find the youngest unspent
            // UTXO that's currently below `min_age` — its
            // earliest-spendable height is the upper bound on how long the
            // user has to wait. (More precise would be "the youngest UTXO
            // whose maturation tips us over the threshold", but this
            // bound is correct and simple.)
            let pending_utxos: Vec<&UTXO> = balance
                .unspent_utxos()
                .into_iter()
                .filter(|u| current_height < u.height.saturating_add(min_age))
                .collect();
            let pending_atomic: u64 = pending_utxos.iter().map(|u| u.amount.as_atomic()).sum();
            // Latest pending UTXO height = the most-recently-confirmed pending one.
            // earliest_full_maturity = max(pending heights) + min_age.
            // blocks_to_wait = earliest_full_maturity - current_height.
            // (Subset coverage might mature earlier, but reporting the
            // pessimistic full-maturity bound never under-promises.)
            let latest_pending_height = pending_utxos
                .iter()
                .map(|u| u.height)
                .max()
                .unwrap_or(current_height);
            let earliest_full_maturity = latest_pending_height.saturating_add(min_age);
            let blocks_to_wait = earliest_full_maturity.saturating_sub(current_height);
            let seconds_to_wait =
                blocks_to_wait.saturating_mul(crate::constants::TARGET_BLOCK_TIME);
            return Err(Error::BalancePendingMaturity {
                spendable_atomic: available.as_atomic(),
                pending_atomic,
                pending_utxos: pending_utxos.len(),
                need_atomic: initial_needed.as_atomic(),
                blocks_to_wait,
                seconds_to_wait,
            });
        }
        return Err(Error::InsufficientBalance {
            have: available.as_atomic(),
            need: initial_needed.as_atomic(),
        });
    }

    // AUDIT (R-107 fix, 2026-07-02): the prior comment here claimed a
    // "SECURITY: Filter to native CYNC UTXOs only" security check —
    // but the code that follows performs no filter. The claim was
    // stale: v2's confidential-asset layer was removed in the asset
    // strip (commit 46f0437, see wallet::balance module docstring), so
    // every UTXO the wallet holds is implicitly CYNC and there's
    // nothing to filter against. Keeping the false-security comment
    // was worse than no comment at all — it read to auditors like a
    // defense that isn't there.
    let utxos: Vec<&UTXO> = balance.available_utxos(current_height, min_age);
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
            .saturating_mul(multiplier_x100)
            / 100,
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
    let output_total = total_send
        .as_atomic()
        .saturating_add(estimated_fee.as_atomic());

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
    if ring_pool.len() < ring_size - 1 {
        return Err(Error::InvalidRingSize {
            expected: ring_size,
            got: ring_pool.len() + 1,
        });
    }

    // Build the transaction (BP+ range proofs at/above activation height)
    let mut builder = TransactionBuilder::transfer().with_target_height(current_height);
    if let Some(m) = memo {
        builder = builder.with_memo(m);
    }
    if !extra.is_empty() {
        builder = builder.with_extra(extra.clone());
    }

    // Add inputs with ring signatures
    for utxo in &selected {
        let stealth = StealthAddress {
            public_key: utxo.tx_public_key, // placeholder; only tx_public_key is used by compute_one_time_secret
            tx_public_key: utxo.tx_public_key,
        };
        let one_time_secret = compute_one_time_secret(
            &stealth,
            &keys.view_secret,
            &keys.spend_secret,
            utxo.output_index,
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
            &real_pubkey,
            utxo.height,
            &ring_pool,
            ring_size,
            current_height,
            rng,
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
        if drip_pair {
            // Drip-pair shape: both outputs ARE the recipient outputs (already added).
            // No change, no dummy. Any input excess goes to fee. This is constitutional
            // because the tx still presents as a normal 2-in/2-out — chain analysts
            // can't distinguish a drip-pair tx from a standard "recipient + change" tx.
            Amount::from_atomic(estimated_fee.as_atomic().saturating_add(change_amount))
        } else if change_amount >= MIN_OUTPUT_AMOUNT {
            // Standard: output[0] = recipient (already added), output[1] = change.
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

pub fn prepare_privacy_transaction_with_options<R: RngCore + CryptoRng>(
    balance: &Balance,
    recipients: &[(PublicKey, PublicKey, Amount)],
    keys: &KeyEpoch,
    current_height: u64,
    ring_size: usize,
    fee_multiplier: f64,
    memo: Option<&[u8]>,
    extra: Vec<u8>,
    rng: &mut R,
) -> Result<PreparedPrivacyTransaction> {
    if ring_size < 2 {
        return Err(Error::InvalidRingSize {
            expected: 2,
            got: ring_size,
        });
    }
    let min_age = min_output_age_at_height(current_height);
    let total_send: Amount = recipients.iter().map(|(_, _, amount)| *amount).sum();
    let available = balance.spendable(current_height, min_age);
    let uniform = current_height >= UNIFORM_TX_SHAPE_HEIGHT;
    let drip_pair = uniform
        && recipients.len() == STANDARD_OUTPUT_COUNT
        && recipients.windows(2).all(|pair| {
            pair[0].0.as_bytes() == pair[1].0.as_bytes()
                && pair[0].1.as_bytes() == pair[1].1.as_bytes()
        });
    if uniform && recipients.len() > 1 && !drip_pair {
        return Err(Error::InvalidState(
            "Post-activation transfers must have one recipient or a same-address drip pair".into(),
        ));
    }

    let input_count_estimate = if uniform { STANDARD_INPUT_COUNT } else { 1 };
    let output_count = if uniform {
        STANDARD_OUTPUT_COUNT
    } else {
        recipients.len() + 3
    };
    let multiplier = if fee_multiplier.is_nan() {
        1.0
    } else {
        fee_multiplier
    };
    let multiplier_x100 = (multiplier.max(1.0) * 100.0).min(10_000.0) as u64;
    let initial_fee = Amount::from_atomic(
        (estimate_tx_size(input_count_estimate, output_count, ring_size) as u64)
            .saturating_mul(MIN_FEE_PER_BYTE)
            .saturating_mul(multiplier_x100)
            / 100,
    );
    let initial_needed = total_send.saturating_add(initial_fee);
    if available < initial_needed {
        if balance.total() >= initial_needed {
            let pending_utxos: Vec<&UTXO> = balance
                .unspent_utxos()
                .into_iter()
                .filter(|utxo| current_height < utxo.height.saturating_add(min_age))
                .collect();
            let pending_atomic = pending_utxos
                .iter()
                .map(|utxo| utxo.amount.as_atomic())
                .sum();
            let latest_pending_height = pending_utxos
                .iter()
                .map(|utxo| utxo.height)
                .max()
                .unwrap_or(current_height);
            let blocks_to_wait = latest_pending_height
                .saturating_add(min_age)
                .saturating_sub(current_height);
            return Err(Error::BalancePendingMaturity {
                spendable_atomic: available.as_atomic(),
                pending_atomic,
                pending_utxos: pending_utxos.len(),
                need_atomic: initial_needed.as_atomic(),
                blocks_to_wait,
                seconds_to_wait: blocks_to_wait.saturating_mul(crate::constants::TARGET_BLOCK_TIME),
            });
        }
        return Err(Error::InsufficientBalance {
            have: available.as_atomic(),
            need: initial_needed.as_atomic(),
        });
    }

    let utxos: Vec<&UTXO> = balance.available_utxos(current_height, min_age);
    let mut selected = if uniform {
        select_utxos_uniform(&utxos, initial_needed, rng)?
    } else {
        select_utxos(&utxos, initial_needed, CoinSelection::OldestFirst, rng)?
    };
    let estimated_fee = Amount::from_atomic(
        (estimate_tx_size(selected.len(), output_count, ring_size) as u64)
            .saturating_mul(MIN_FEE_PER_BYTE)
            .saturating_mul(multiplier_x100)
            / 100,
    );
    let total_needed = total_send.saturating_add(estimated_fee);
    if selected.iter().map(|utxo| utxo.amount).sum::<Amount>() < total_needed {
        selected = if uniform {
            select_utxos_uniform(&utxos, total_needed, rng)?
        } else {
            select_utxos(&utxos, total_needed, CoinSelection::OldestFirst, rng)?
        };
    }
    let input_sum: Amount = selected.iter().map(|utxo| utxo.amount).sum();
    if input_sum < total_needed {
        return Err(Error::InsufficientBalance {
            have: input_sum.as_atomic(),
            need: total_needed.as_atomic(),
        });
    }

    Ok(PreparedPrivacyTransaction {
        inputs: selected
            .into_iter()
            .map(|utxo| prepare_input(utxo, keys))
            .collect::<Result<_>>()?,
        recipients: recipients.to_vec(),
        change_amount: input_sum
            .as_atomic()
            .saturating_sub(total_needed.as_atomic()),
        estimated_fee,
        current_height,
        uniform,
        drip_pair,
        spend_public: keys.spend_public,
        view_public: keys.view_public,
        memo: memo.map(ToOwned::to_owned),
        extra,
        ring_size,
    })
}

pub fn build_prepared_privacy_transaction<R: RngCore + CryptoRng>(
    prepared: PreparedPrivacyTransaction,
    rings: Vec<AllocatedRing>,
    rng: &mut R,
) -> Result<Transaction> {
    let PreparedPrivacyTransaction {
        inputs,
        recipients,
        change_amount,
        estimated_fee,
        current_height,
        uniform,
        drip_pair,
        spend_public,
        view_public,
        memo,
        extra,
        ring_size,
    } = prepared;
    let mut builder = TransactionBuilder::transfer().with_target_height(current_height);
    if let Some(memo) = memo.as_deref() {
        builder = builder.with_memo(memo);
    }
    if !extra.is_empty() {
        builder = builder.with_extra(extra);
    }
    add_prepared_inputs(&mut builder, inputs, rings, ring_size)?;
    for (index, (spend_public, view_public, amount)) in recipients.iter().enumerate() {
        builder.add_output(
            &Recipient {
                spend_public: *spend_public,
                view_public: *view_public,
                amount: *amount,
                lock_height: None,
            },
            index as u8,
            rng,
        )?;
    }
    let final_fee = if uniform {
        if drip_pair {
            Amount::from_atomic(estimated_fee.as_atomic().saturating_add(change_amount))
        } else if change_amount >= MIN_OUTPUT_AMOUNT {
            builder.add_change(
                &spend_public,
                &view_public,
                Amount::from_atomic(change_amount),
                recipients.len() as u8,
                rng,
            )?;
            estimated_fee
        } else {
            let _ = builder.add_dummy_output(rng);
            Amount::from_atomic(estimated_fee.as_atomic().saturating_add(change_amount))
        }
    } else {
        let fee = if change_amount >= MIN_OUTPUT_AMOUNT {
            builder.add_change(
                &spend_public,
                &view_public,
                Amount::from_atomic(change_amount),
                recipients.len() as u8,
                rng,
            )?;
            estimated_fee
        } else {
            Amount::from_atomic(estimated_fee.as_atomic().saturating_add(change_amount))
        };
        for _ in 0..rng.gen_range(0..=2usize) {
            let _ = builder.add_dummy_output(rng);
        }
        fee
    };
    builder.set_fee(final_fee);
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
    // CONSENSUS-COUPLED: see comment in create_privacy_transaction_with_options.
    let min_age = min_output_age_at_height(current_height);
    let available = balance.spendable(current_height, min_age);

    let ring_pool = ring_selection_pool(decoy_pool);

    let ring_size = effective_ring_size(current_height, ring_pool.len() + 1);
    enforce_wallet_privacy_policy(ring_size, ring_pool.len(), PrivacyConsent::Strict)?;
    let initial_size = estimate_tx_size(1, 4, ring_size); // 1 vesting + 1 change + up to 2 dummies
    let initial_fee = Amount::from_atomic(initial_size as u64 * MIN_FEE_PER_BYTE);
    let total_needed = amount.saturating_add(initial_fee);

    if available < total_needed {
        return Err(Error::InsufficientBalance {
            have: available.as_atomic(),
            need: total_needed.as_atomic(),
        });
    }

    // AUDIT (R-107 fix, 2026-07-02): same stale "SECURITY (BUG-13):
    // Filter to native CYNC UTXOs only" comment as the equivalent
    // callsite in `create_privacy_transaction_with_options`. Asset
    // support was removed in the asset strip, so no filter is
    // needed or applied here. Wording corrected so auditors don't
    // read a not-present filter as an actual security check.
    let utxos: Vec<&UTXO> = balance.available_utxos(current_height, min_age);
    let selected = select_utxos(&utxos, total_needed, CoinSelection::OldestFirst, rng)?;

    // Re-estimate fee based on actual input count (may be > 1)
    let estimated_size = estimate_tx_size(selected.len(), 4, ring_size);
    let estimated_fee = Amount::from_atomic(estimated_size as u64 * MIN_FEE_PER_BYTE);

    let input_sum: Amount = selected.iter().map(|u| u.amount).sum();
    let output_total = amount.as_atomic().saturating_add(estimated_fee.as_atomic());
    let change_amount = input_sum.as_atomic().saturating_sub(output_total);

    if ring_size == 0 || ring_pool.len() < ring_size - 1 {
        return Err(Error::InvalidRingSize {
            expected: ring_size,
            got: ring_pool.len() + 1,
        });
    }

    let mut builder = TransactionBuilder::transfer().with_target_height(current_height);

    // Add inputs with ring signatures
    for utxo in &selected {
        let stealth = StealthAddress {
            public_key: utxo.tx_public_key,
            tx_public_key: utxo.tx_public_key,
        };
        let one_time_secret = compute_one_time_secret(
            &stealth,
            &keys.view_secret,
            &keys.spend_secret,
            utxo.output_index,
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
            &real_pubkey,
            utxo.height,
            &ring_pool,
            ring_size,
            current_height,
            rng,
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
            &keys.spend_public,
            &keys.view_public,
            Amount::from_atomic(change_amount),
            1,
            rng,
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

pub fn prepare_vesting_transaction<R: RngCore + CryptoRng>(
    balance: &Balance,
    recipient_spend: PublicKey,
    recipient_view: PublicKey,
    amount: Amount,
    unlock_height: u64,
    keys: &KeyEpoch,
    current_height: u64,
    ring_size: usize,
    rng: &mut R,
) -> Result<PreparedVestingTransaction> {
    if ring_size < 2 {
        return Err(Error::InvalidRingSize {
            expected: 2,
            got: ring_size,
        });
    }
    let min_age = min_output_age_at_height(current_height);
    let available = balance.spendable(current_height, min_age);
    let initial_fee =
        Amount::from_atomic(estimate_tx_size(1, 4, ring_size) as u64 * MIN_FEE_PER_BYTE);
    let total_needed = amount.saturating_add(initial_fee);
    if available < total_needed {
        return Err(Error::InsufficientBalance {
            have: available.as_atomic(),
            need: total_needed.as_atomic(),
        });
    }
    let utxos: Vec<&UTXO> = balance.available_utxos(current_height, min_age);
    let selected = select_utxos(&utxos, total_needed, CoinSelection::OldestFirst, rng)?;
    let estimated_fee = Amount::from_atomic(
        estimate_tx_size(selected.len(), 4, ring_size) as u64 * MIN_FEE_PER_BYTE,
    );
    let input_sum: Amount = selected.iter().map(|utxo| utxo.amount).sum();
    let output_total = amount.as_atomic().saturating_add(estimated_fee.as_atomic());
    if input_sum.as_atomic() < output_total {
        return Err(Error::InsufficientBalance {
            have: input_sum.as_atomic(),
            need: output_total,
        });
    }

    Ok(PreparedVestingTransaction {
        inputs: selected
            .into_iter()
            .map(|utxo| prepare_input(utxo, keys))
            .collect::<Result<_>>()?,
        recipient_spend,
        recipient_view,
        amount,
        unlock_height,
        change_amount: input_sum.as_atomic().saturating_sub(output_total),
        estimated_fee,
        current_height,
        spend_public: keys.spend_public,
        view_public: keys.view_public,
        ring_size,
    })
}

pub fn build_prepared_vesting_transaction<R: RngCore + CryptoRng>(
    prepared: PreparedVestingTransaction,
    rings: Vec<AllocatedRing>,
    rng: &mut R,
) -> Result<Transaction> {
    let PreparedVestingTransaction {
        inputs,
        recipient_spend,
        recipient_view,
        amount,
        unlock_height,
        change_amount,
        estimated_fee,
        current_height,
        spend_public,
        view_public,
        ring_size,
    } = prepared;
    let mut builder = TransactionBuilder::transfer().with_target_height(current_height);
    add_prepared_inputs(&mut builder, inputs, rings, ring_size)?;
    builder.add_output(
        &Recipient {
            spend_public: recipient_spend,
            view_public: recipient_view,
            amount,
            lock_height: Some(unlock_height),
        },
        0,
        rng,
    )?;
    let final_fee = if change_amount >= MIN_OUTPUT_AMOUNT {
        builder.add_change(
            &spend_public,
            &view_public,
            Amount::from_atomic(change_amount),
            1,
            rng,
        )?;
        estimated_fee
    } else {
        Amount::from_atomic(estimated_fee.as_atomic().saturating_add(change_amount))
    };
    for _ in 0..rng.gen_range(0..=2usize) {
        let _ = builder.add_dummy_output(rng);
    }
    builder.set_fee(final_fee);
    builder.build(rng)
}

fn prepare_input(utxo: &UTXO, keys: &KeyEpoch) -> Result<PreparedInput> {
    let locator = utxo
        .output_locator
        .ok_or_else(|| Error::InvalidState("wallet output has no canonical locator".into()))?;
    let stealth = StealthAddress {
        public_key: utxo.tx_public_key,
        tx_public_key: utxo.tx_public_key,
    };
    let one_time_secret = compute_one_time_secret(
        &stealth,
        &keys.view_secret,
        &keys.spend_secret,
        utxo.output_index,
    )?;
    let blinding = BlindingFactor::from_bytes(utxo.amount_blinding_bytes);
    Ok(PreparedInput {
        real_output: RealOutputIdentity {
            locator,
            public_key: one_time_secret.public_key(),
            commitment: PedersenCommitment::commit(utxo.amount.as_atomic(), &blinding).to_bytes(),
        },
        input: SpendableInput {
            tx_hash: utxo.tx_hash,
            output_index: utxo.output_index,
            amount: utxo.amount,
            one_time_secret,
            blinding,
            height: utxo.height,
        },
    })
}

fn add_prepared_inputs(
    builder: &mut TransactionBuilder,
    inputs: Vec<PreparedInput>,
    rings: Vec<AllocatedRing>,
    ring_size: usize,
) -> Result<()> {
    if inputs.len() != rings.len() {
        return Err(Error::InvalidState(
            "ring allocation does not match selected inputs".into(),
        ));
    }
    for (prepared, ring) in inputs.into_iter().zip(rings) {
        if ring.decoys.len() + 1 != ring_size {
            return Err(Error::InvalidRingSize {
                expected: ring_size,
                got: ring.decoys.len() + 1,
            });
        }
        builder.add_input(prepared.input, ring.decoys, ring.real_position)?;
    }
    Ok(())
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
    // CONSENSUS-COUPLED: see comment in create_privacy_transaction_with_options.
    let min_age = min_output_age_at_height(current_height);
    let available = balance.spendable(current_height, min_age);
    if available.as_atomic() == 0 {
        return Err(Error::InsufficientBalance { have: 0, need: 1 });
    }

    let ring_pool = ring_selection_pool(decoy_pool);

    // Use effective_ring_size to handle young chains with few unique outputs
    let ring_size = effective_ring_size(current_height, ring_pool.len() + 1);
    enforce_wallet_privacy_policy(ring_size, ring_pool.len(), PrivacyConsent::Strict)?;

    let uniform = current_height >= UNIFORM_TX_SHAPE_HEIGHT;

    // AUDIT (R-107 fix, 2026-07-02): third and last stale asset-strip
    // residue comment in this file. Same shape as the two earlier
    // sites — asset support was removed and no filter is applied
    // (or needed).
    let utxos: Vec<&UTXO> = balance.available_utxos(current_height, min_age);
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
        return Err(Error::InvalidRingSize {
            expected: 1,
            got: 0,
        });
    }
    if ring_pool.len() < ring_size - 1 {
        return Err(Error::InvalidRingSize {
            expected: ring_size,
            got: ring_pool.len() + 1,
        });
    }

    let mut builder = TransactionBuilder::new(TxType::Churn).with_target_height(current_height);

    // Add inputs with ring signatures
    for utxo in &selected {
        let stealth = StealthAddress {
            public_key: utxo.tx_public_key,
            tx_public_key: utxo.tx_public_key,
        };
        let one_time_secret = compute_one_time_secret(
            &stealth,
            &keys.view_secret,
            &keys.spend_secret,
            utxo.output_index,
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
            &real_pubkey,
            utxo.height,
            &ring_pool,
            ring_size,
            current_height,
            rng,
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
                &keys.spend_public,
                &keys.view_public,
                Amount::from_atomic(change),
                1,
                rng,
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
                &keys.spend_public,
                &keys.view_public,
                Amount::from_atomic(change),
                1,
                rng,
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
///
/// # Algorithm
/// 1. Sort UTXOs descending by amount.
/// 2. **Full two-pointer sweep**: for each `lo` index, advance `hi` from the
///    end inward, recording every (lo, hi) pair where `lo + hi >= target`,
///    then advance `lo` and reset `hi`. This finds all O(n²) candidate pairs
///    in O(n²) worst case but typically O(n) when amounts vary, **without
///    missing pairs that don't include the largest UTXO** (the prior
///    single-pass sweep collapsed `hi` permanently and missed these).
/// 3. Tighten to candidates with excess within 20% of the best excess
///    (privacy: avoids deterministic fingerprinting on excess size).
/// 4. Randomly choose among the tightened candidates with the caller-supplied
///    RNG.
///
/// # Errors
/// - `InsufficientInputs` when fewer than 2 UTXOs exist (count problem).
/// - `NoUtxoPairCovers` when 2+ UTXOs exist but no pair covers the target
///   (amount problem). Includes diagnostics so the user knows the largest
///   safe send and what to do next.
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

    // Sort indices by amount descending. Sorted view enables both the candidate
    // sweep and the trivial "largest pair" calculation for diagnostics.
    let mut indices: Vec<usize> = (0..utxos.len()).collect();
    indices.sort_by(|a, b| {
        utxos[*b]
            .amount
            .as_atomic()
            .cmp(&utxos[*a].amount.as_atomic())
    });

    // Largest pair = top two UTXOs (sorted descending). Used for both the
    // "covers target?" early bailout and the diagnostic error if no pair
    // covers — the user can always fall back to "send <= largest_pair - fee".
    let largest_pair_sum = utxos[indices[0]]
        .amount
        .as_atomic()
        .saturating_add(utxos[indices[1]].amount.as_atomic());

    if largest_pair_sum < target_val {
        let total: u64 = utxos.iter().map(|u| u.amount.as_atomic()).sum();
        // `max_safe` reports the largest target the user could send right now
        // and have it succeed. Subtracts a generous fee bound; the actual fee
        // depends on output count and ring size but a conservative bound here
        // keeps the suggestion safe.
        let conservative_fee_bound = 50_000_000u64; // 0.05 CYNC (well above typical ~7e-6)
        let max_safe = largest_pair_sum.saturating_sub(conservative_fee_bound);
        return Err(Error::NoUtxoPairCovers {
            target_atomic: target_val,
            utxo_count: utxos.len(),
            total_atomic: total,
            largest_pair_atomic: largest_pair_sum,
            max_safe_atomic: max_safe,
        });
    }

    // Full pair sweep: O(n²) worst case but typically O(n log n) when most
    // UTXOs are similar size. The previous implementation used a single-pass
    // two-pointer that locked `lo` at the largest UTXO and missed valid pairs
    // not containing it (e.g. with [100, 80, 60, 40], target=90, the previous
    // pass found only (100, 20-equiv) variants and missed the optimal (60,40)
    // and (80, 40) pairs which have lower excess). Correctness > microseconds.
    let mut candidates: Vec<(usize, usize, u64)> = Vec::new();
    let mut best_excess = u64::MAX;

    for i in 0..indices.len() {
        for j in (i + 1)..indices.len() {
            let sum = utxos[indices[i]]
                .amount
                .as_atomic()
                .saturating_add(utxos[indices[j]].amount.as_atomic());
            if sum >= target_val {
                let excess = sum - target_val;
                if excess < best_excess {
                    best_excess = excess;
                }
                candidates.push((indices[i], indices[j], excess));
            }
            // No early termination on `sum < target` because the OUTER index
            // i is the larger UTXO; for fixed i, smaller j's give smaller sums.
            // But across DIFFERENT i values, more pairs may exist, so we keep
            // sweeping. (Outer-loop early-exit is safe only if we'd already
            // failed to cover with the largest UTXO + smallest, which is
            // exactly what the largest_pair_sum check above already rejects.)
        }
    }

    // Defensive: largest_pair_sum >= target_val should guarantee non-empty.
    // Keeping the check rather than .expect() so a future regression in the
    // bound calculation surfaces as a clean error instead of a panic.
    if candidates.is_empty() {
        let total: u64 = utxos.iter().map(|u| u.amount.as_atomic()).sum();
        return Err(Error::NoUtxoPairCovers {
            target_atomic: target_val,
            utxo_count: utxos.len(),
            total_atomic: total,
            largest_pair_atomic: largest_pair_sum,
            max_safe_atomic: largest_pair_sum.saturating_sub(50_000_000),
        });
    }

    // PRIVACY: randomly select among candidates within 20% of the best excess
    // to prevent deterministic fingerprinting of UTXO selection.
    let threshold = best_excess
        .saturating_add(best_excess / 5)
        .max(best_excess.saturating_add(1));
    let good_candidates: Vec<_> = candidates
        .iter()
        .filter(|(_, _, e)| *e <= threshold)
        .collect();

    // SECURITY: UTXO-pair selection is a privacy signal (bigger pair vs smaller,
    // age profile). Use the caller-supplied rng — every public callsite in
    // the wallet binary already passes `OsRng` (verified at audit time).
    let &&(i, j, _) = good_candidates.choose(rng).unwrap_or(&&candidates[0]);
    Ok(vec![utxos[i], utxos[j]])
}

fn ring_selection_pool(decoy_pool: &[DecoyOutput]) -> RingSelectionPool<'_> {
    RingSelectionPool::new(
        decoy_pool
            .iter()
            .map(|decoy| RingOutputRef::new(decoy.height, &decoy.public_key, &decoy.commitment)),
    )
}

/// Uses uniform sampling without replacement so every eligible output has
/// the same inclusion probability and no output can occupy multiple slots.
///
/// Prior art (academic papers in the public record; specific
/// numerical results not re-verified this session):
///   • Miller et al. 2017 — "An Empirical Analysis of Linkability in
///     the Monero Blockchain" (arXiv:1704.04299)
///   • Möser et al. 2018 — "An Empirical Analysis of Traceability in
///     the Monero Blockchain" (PoPETS 2018)
///   • Monero Research Lab uniform-selection recommendations from
///     subsequent MRL work.
///
/// Returns (decoys, real_position) — the decoy list and the index where
/// the real output should be inserted in the ring.
fn select_ring_decoys<R: RngCore + CryptoRng>(
    real_pubkey: &PublicKey,
    real_height: u64,
    pool: &RingSelectionPool<'_>,
    ring_size: usize,
    current_height: u64,
    rng: &mut R,
) -> Result<(Vec<DecoyOutput>, usize)> {
    let config = RingSelectionConfig {
        target_ring_size: ring_size,
        min_decoy_age: 0,
        ..RingSelectionConfig::default()
    };
    let selector = RingSelector::new(config);

    let (selected, real_position, _stats) =
        selector.select_decoys(real_pubkey, real_height, pool, current_height, rng)?;

    let decoys = selected
        .into_iter()
        .map(|output| DecoyOutput {
            public_key: *output.public_key,
            commitment: *output.commitment,
            height: output.height,
        })
        .collect();

    Ok((decoys, real_position))
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
    //   + view_tag (1) + lock_height Option<u64> (1+8)
    //
    // AUDIT (R-109 fix, 2026-07-03): pre-fix code included
    //   + asset_commitment (32) + encrypted_asset vec (4+32)
    //   + asset_surjection_proof vec (4+0) + encrypted_asset_audit vec (4+0)
    // → total = 32 + 32 + 32 + 12 + 1 + 32 + 36 + 4 + 4 + 9 = 194 bytes/output
    // But asset support was STRIPPED in commit 46f0437 — the TxOutput
    // struct no longer carries asset_commitment / encrypted_asset /
    // surjection_proof / audit fields. The pre-fix estimator kept
    // counting those bytes and overestimated the wire size by
    // 32+36+4+4 = 76 bytes per output. With a 2x safety margin
    // that's ~152 bytes/output of PHANTOM SIZE. At MIN_FEE_PER_BYTE
    // the wallet overpays fees by ~152 * MIN_FEE_PER_BYTE per output
    // on every send.
    // Corrected: 32 + 32 + 32 + 12 + 1 + 9 = 118 bytes/output.
    let output_size = 32 + 32 + 32 + 12 + 1 + 9;
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
        let result = select_utxos(
            &utxos,
            Amount::from_atomic(100),
            CoinSelection::OldestFirst,
            &mut rand::rngs::OsRng,
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_privacy_policy_rejects_weak_ring_when_strict() {
        let _guard = ENV_LOCK.lock().expect("env lock");
        std::env::remove_var("COINCYNC_WALLET_ALLOW_WEAK_PRIVACY");
        let err = enforce_wallet_privacy_policy(2, 1, PrivacyConsent::Strict).unwrap_err();
        assert!(format!("{err}").contains("privacy policy"));
    }

    #[test]
    fn test_privacy_policy_can_be_overridden_for_dev() {
        let _guard = ENV_LOCK.lock().expect("env lock");
        std::env::set_var("COINCYNC_WALLET_ALLOW_WEAK_PRIVACY", "1");
        let ok = enforce_wallet_privacy_policy(2, 1, PrivacyConsent::Strict);
        std::env::remove_var("COINCYNC_WALLET_ALLOW_WEAK_PRIVACY");
        assert!(ok.is_ok());
    }

    // --- helpers + tests for select_utxos_uniform (Bug #1 + Bug #2 fixes) ---

    fn make_utxo(amount: u64, idx: u8) -> UTXO {
        UTXO {
            tx_hash: crate::primitives::Hash::from_bytes([idx; 32]),
            output_index: idx,
            output_locator: None,
            amount: Amount::from_atomic(amount),
            height: 100,
            key_image: crate::primitives::KeyImage::from_bytes([idx; 32]),
            spent: false,
            amount_blinding_bytes: [0u8; 32],
            tx_public_key: crate::primitives::PublicKey::from_bytes([0u8; 32]),
            lock_height: None,
        }
    }

    /// Bug #1 regression: when the target cannot be covered by the sum of the
    /// largest two UTXOs, `select_utxos_uniform` must return the diagnostic
    /// `NoUtxoPairCovers` (with largest_pair_atomic, total, etc.) rather than
    /// the misleading old `InsufficientInputs { have: 4, need: 2 }`. The
    /// real-world hit was 4 ~50-CYNC UTXOs and a 100-CYNC target with fee:
    /// no pair covers (50+50 == 100 < 100+fee), but the wallet has 200 CYNC
    /// total and 4 UTXOs — neither count nor balance is the actual problem.
    #[test]
    fn test_uniform_select_no_pair_covers_returns_diagnostic_error() {
        let utxos: Vec<UTXO> = (0..4).map(|i| make_utxo(50, i)).collect();
        let refs: Vec<&UTXO> = utxos.iter().collect();
        // Target slightly above what any pair can cover (50 + 50 = 100; ask 101).
        let target = Amount::from_atomic(101);
        let mut rng = rand::rngs::OsRng;
        let err = select_utxos_uniform(&refs, target, &mut rng).unwrap_err();
        match err {
            Error::NoUtxoPairCovers {
                target_atomic,
                utxo_count,
                total_atomic,
                largest_pair_atomic,
                max_safe_atomic: _,
            } => {
                assert_eq!(target_atomic, 101);
                assert_eq!(utxo_count, 4);
                assert_eq!(total_atomic, 200);
                assert_eq!(largest_pair_atomic, 100);
            }
            other => panic!("expected NoUtxoPairCovers, got {:?}", other),
        }
    }

    /// `InsufficientInputs` is now ONLY for the count-based failure (fewer
    /// than 2 UTXOs total). It must not fire when the count is fine but no
    /// pair sums high enough — that path now returns `NoUtxoPairCovers`.
    #[test]
    fn test_uniform_select_insufficient_inputs_only_when_too_few_utxos() {
        let single = vec![make_utxo(1_000_000, 0)];
        let refs: Vec<&UTXO> = single.iter().collect();
        let mut rng = rand::rngs::OsRng;
        let err = select_utxos_uniform(&refs, Amount::from_atomic(100), &mut rng).unwrap_err();
        match err {
            Error::InsufficientInputs { have, need } => {
                assert_eq!(have, 1);
                assert_eq!(need, STANDARD_INPUT_COUNT);
            }
            other => panic!("expected InsufficientInputs, got {:?}", other),
        }
    }

    /// Bug #2 regression: the prior single-pass two-pointer sweep collapsed
    /// `hi` whenever `lo+hi >= target`, locking `lo` at the largest UTXO and
    /// missing valid pairs that don't include it. With UTXOs [100, 80, 60, 40]
    /// and target=90, the optimal (lowest-excess) pair is (60, 40) summing to
    /// exactly 100 — excess 10 — which the prior sweep never considered.
    /// The new full sweep MUST find it. Privacy-side, the random choice
    /// within the 20%-of-best-excess threshold prevents fingerprinting; the
    /// 60/40 pair is the only one within that threshold here so the choice
    /// is deterministic.
    #[test]
    fn test_uniform_select_finds_optimal_non_largest_pair() {
        let utxos = vec![
            make_utxo(100, 0),
            make_utxo(80, 1),
            make_utxo(60, 2),
            make_utxo(40, 3),
        ];
        let refs: Vec<&UTXO> = utxos.iter().collect();
        let target = Amount::from_atomic(90);
        let mut rng = rand::rngs::OsRng;
        let chosen = select_utxos_uniform(&refs, target, &mut rng).unwrap();
        assert_eq!(chosen.len(), 2);
        let sum: u64 = chosen.iter().map(|u| u.amount.as_atomic()).sum();
        // Best (lowest-excess) pair is 60+40 = 100. The 20%-threshold widens
        // to include excess up to 12 (10 + best/5=2, max with best+1=11),
        // which still only admits the (60, 40) pair (next-best is (80,40)
        // = 120, excess 30).
        assert_eq!(sum, 100, "selector should pick the optimal (60, 40) pair");
    }

    /// Sanity: when the target is comfortably below largest_pair, selection
    /// succeeds and returns exactly 2 UTXOs whose sum >= target. (No
    /// regression in the happy path.)
    #[test]
    fn test_uniform_select_happy_path() {
        let utxos = vec![
            make_utxo(1_000_000, 0),
            make_utxo(2_000_000, 1),
            make_utxo(3_000_000, 2),
        ];
        let refs: Vec<&UTXO> = utxos.iter().collect();
        let target = Amount::from_atomic(2_500_000);
        let mut rng = rand::rngs::OsRng;
        let chosen = select_utxos_uniform(&refs, target, &mut rng).unwrap();
        assert_eq!(chosen.len(), 2);
        let sum: u64 = chosen.iter().map(|u| u.amount.as_atomic()).sum();
        assert!(sum >= 2_500_000);
    }
}
