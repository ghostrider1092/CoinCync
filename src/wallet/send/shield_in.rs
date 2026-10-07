//! # Shield-in (transparent → shielded) transaction builder — #172 PR2
//!
//! Builds a `TxType::Shielded` transaction that funds `amount` atomic units into
//! the Spark pool out of the wallet's TRANSPARENT UTXOs. The tx carries:
//! - transparent ring-signed inputs (the funding, exactly like a normal spend),
//! - a transparent CHANGE output (or a dummy when the change is dust),
//! - an authenticated libspark MINT bundle in `tx.extra` (a `SparkPayload` whose
//!   coins' total value equals `amount`), and
//! - `value_balance = -amount`, the public bridge the node checks.
//!
//! The node then verifies, at block level (post-activation; the path is
//! fail-closed under `SHIELDED_TX_ACTIVATION_HEIGHT = u64::MAX`):
//! - `verify_transparent_shielded_balance`: `Σ pseudo_outputs == Σ output_commitments
//!   + (fee − value_balance)·H`, i.e. the transparent inputs exceed the transparent
//!   outputs + fee by exactly `amount`, and
//! - `verify_mint_shield_in`: the mint bundle's authenticated coin values sum to
//!   `amount = −value_balance`.
//!
//! Split into `prepare_shield_in` (select inputs + build the mint bundle bound to
//! those inputs' key-image outpoints) and `build_shield_in_transaction` (resolve
//! rings → sign), mirroring the transparent prepare/assembly seam so the CLI can
//! fetch decoys from the node in between.
//!
//! CRITICAL: the mint bundle's serial context is derived from the tx's transparent
//! input outpoints, which the chain re-derives at apply as `borsh(key_image)` for
//! every input. We compute the SAME key images here (via `SoftwareSigner`, the
//! builder's own path) so the apply-time context matches — otherwise the minted
//! coins would be unspendable (block validation does not catch that mismatch).

use rand::{CryptoRng, RngCore};

use super::super::decoy_selection::{AllocatedRings, RealOutputIdentity};
use super::super::{Balance, KeyEpoch, UTXO};
use super::fee::estimate_tx_size;
use super::inputs::{add_prepared_inputs, prepare_input};
use super::selection::{ensure_spendable, select_utxos};
use super::types::{CoinSelection, PreparedInput, SpendContext};
use crate::consensus::spark_payload::build::build_mint_payload;
use crate::constants::{MIN_FEE_PER_BYTE, MIN_OUTPUT_AMOUNT};
use crate::error::{Error, Result};
use crate::primitives::{Amount, PublicKey};
use crate::transaction::{
    OneTimeKeyRef, SoftwareSigner, Transaction, TransactionBuilder, TxSigner, TxType,
};

/// Fixed byte margin added to the estimated tx size when deriving the fee, so the
/// fee always clears the node's `size × MIN_FEE_PER_BYTE` relay floor despite the
/// estimate not modelling borsh framing exactly.
const FEE_SIZE_MARGIN_BYTES: usize = 512;

/// Phase-1 result: selected transparent inputs + the mint bundle bound to them.
pub struct PreparedShieldIn {
    inputs: Vec<PreparedInput>,
    change_amount: u64,
    fee: Amount,
    /// The value shielded in (`value_balance = -amount`).
    amount: u64,
    /// Encoded mint `SparkPayload` → `tx.extra`.
    extra: Vec<u8>,
    spend_public: PublicKey,
    view_public: PublicKey,
    context: SpendContext,
}

impl PreparedShieldIn {
    /// The real outputs being spent — the decoy locators are built over these.
    pub fn real_outputs(&self) -> Vec<RealOutputIdentity> {
        self.inputs.iter().map(|input| input.real_output).collect()
    }

    pub fn ring_size(&self) -> usize {
        self.context.ring_size()
    }

    pub fn input_count(&self) -> usize {
        self.inputs.len()
    }

    /// Fee + change for display.
    pub fn fee(&self) -> Amount {
        self.fee
    }
    pub fn change_amount(&self) -> u64 {
        self.change_amount
    }
    pub fn amount(&self) -> u64 {
        self.amount
    }
}

#[cfg(test)]
impl PreparedShieldIn {
    /// Test constructor: assemble a `PreparedShieldIn` from parts (the real
    /// `prepare_shield_in` path needs a funded `Balance`; tests use synthetic
    /// inputs). Not compiled outside tests.
    #[allow(clippy::too_many_arguments)]
    pub(super) fn from_parts_for_test(
        inputs: Vec<PreparedInput>,
        change_amount: u64,
        fee: Amount,
        amount: u64,
        extra: Vec<u8>,
        spend_public: PublicKey,
        view_public: PublicKey,
        context: SpendContext,
    ) -> Self {
        PreparedShieldIn {
            inputs,
            change_amount,
            fee,
            amount,
            extra,
            spend_public,
            view_public,
            context,
        }
    }
}

/// Compute the key image a transparent input will carry — identical to what the
/// `TransactionBuilder` computes internally (`SoftwareSigner::key_image`), so the
/// mint bundle's outpoints match the chain's apply-time `borsh(key_image)` set.
pub(super) fn input_key_image_outpoint(prepared: &PreparedInput) -> Result<Vec<u8>> {
    let ki = SoftwareSigner.key_image(&OneTimeKeyRef::from_secret(
        prepared.input.one_time_secret.clone(),
    ))?;
    borsh::to_vec(&ki)
        .map_err(|e| Error::SerializationError(format!("key image outpoint: {e}")))
}

/// Phase 1: select transparent UTXOs funding `amount + fee`, derive their key
/// images, and build the authenticated mint bundle bound to those inputs.
///
/// The fee is size-based (`size × MIN_FEE_PER_BYTE`) and the tx carries a ~KB
/// mint bundle in `extra`; the mint bundle's SIZE depends only on `amount` (one
/// coin), not on which inputs fund it, so we can size the fee before the final
/// input set is fixed and grow the selection target until it is covered.
pub fn prepare_shield_in<R: RngCore + CryptoRng>(
    balance: &Balance,
    seed: &[u8],
    amount: u64,
    keys: &KeyEpoch,
    current_height: u64,
    ring_size: usize,
    rng: &mut R,
) -> Result<PreparedShieldIn> {
    if amount == 0 {
        return Err(Error::InvalidTransaction(
            "shield-in amount must be greater than zero".into(),
        ));
    }
    let context = SpendContext::with_ring_size(current_height, ring_size)?;
    let min_age = context.min_output_age();

    // Probe the mint-bundle size (independent of the funding inputs — one coin of
    // value `amount`). A dummy outpoint only feeds the serial-context hash.
    let (probe_payload, _) = build_mint_payload(seed, &[amount], &[vec![0u8; 32]])
        .ok_or_else(|| Error::CryptoError("failed to build mint bundle (probe)".into()))?;
    let extra_len = probe_payload.encode().len();

    let utxos: Vec<&UTXO> = balance.available_utxos(current_height, min_age);

    // Grow the selection target until the inputs cover `amount + fee`, where the
    // fee is recomputed from the actual selected input count each round.
    let fee_for = |n_inputs: usize| -> u64 {
        let est = estimate_tx_size(n_inputs, 2, ring_size) + extra_len + FEE_SIZE_MARGIN_BYTES;
        (est as u64).saturating_mul(MIN_FEE_PER_BYTE)
    };
    let mut required = amount.saturating_add(fee_for(1));
    let (selected, fee, input_sum) = loop {
        ensure_spendable(balance, current_height, min_age, Amount::from_atomic(required))?;
        let selected = select_utxos(&utxos, Amount::from_atomic(required), CoinSelection::OldestFirst, rng)?;
        let fee = fee_for(selected.len());
        let input_sum: u64 = selected
            .iter()
            .map(|u| u.amount.as_atomic())
            .fold(0u64, |a, b| a.saturating_add(b));
        if input_sum >= amount.saturating_add(fee) {
            break (selected, fee, input_sum);
        }
        required = amount.saturating_add(fee);
    };

    let inputs: Vec<PreparedInput> = selected
        .into_iter()
        .map(|utxo| prepare_input(utxo, keys))
        .collect::<Result<_>>()?;

    // Build the REAL mint bundle, bound to the actual inputs' key-image outpoints
    // (the exact set the chain re-derives at apply). Same coin count as the probe
    // → same size, so the fee still covers it.
    let outpoints: Vec<Vec<u8>> = inputs
        .iter()
        .map(input_key_image_outpoint)
        .collect::<Result<_>>()?;
    let (payload, _contexts) = build_mint_payload(seed, &[amount], &outpoints)
        .ok_or_else(|| Error::CryptoError("failed to build mint bundle".into()))?;
    debug_assert_eq!(payload.value_balance, -(amount as i64));

    let change_amount = input_sum.saturating_sub(amount.saturating_add(fee));

    Ok(PreparedShieldIn {
        inputs,
        change_amount,
        fee: Amount::from_atomic(fee),
        amount,
        extra: payload.encode(),
        spend_public: keys.spend_public,
        view_public: keys.view_public,
        context,
    })
}

/// Phase 2: bind the prepared inputs to their allocated rings, add the transparent
/// change (or a dummy when the change is dust, folding it into the fee), and sign.
/// The result is a `TxType::Shielded` transaction ready for `send_raw_transaction`.
pub fn build_shield_in_transaction<R: RngCore + CryptoRng>(
    prepared: PreparedShieldIn,
    rings: AllocatedRings,
    rng: &mut R,
) -> Result<Transaction> {
    let PreparedShieldIn {
        inputs,
        change_amount,
        fee,
        amount,
        extra,
        spend_public,
        view_public,
        context,
    } = prepared;

    let mut builder = TransactionBuilder::new(TxType::Shielded)
        .with_target_height(context.target_height())
        .with_value_balance(-(amount as i64))
        .with_extra(extra);
    add_prepared_inputs(&mut builder, inputs, rings, context.ring_size())?;

    // Transparent change back to the sender when above dust; otherwise a dummy
    // output and the dust folds into the fee (keeping ≥1 output so the builder's
    // range proof + balance have something to bind, exactly like the transparent
    // UniformStandard path).
    let final_fee = if change_amount >= MIN_OUTPUT_AMOUNT {
        builder.add_change(&spend_public, &view_public, Amount::from_atomic(change_amount), 0, rng)?;
        fee
    } else {
        builder.add_dummy_output(rng)?;
        Amount::from_atomic(fee.as_atomic().saturating_add(change_amount))
    };
    builder.set_fee(final_fee);
    builder.build(rng)
}
