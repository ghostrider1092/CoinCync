//! # Vesting (time-locked) transaction preparation and assembly
//!
//! Prepares and builds transactions whose recipient output carries a
//! `lock_height`, so the funds are unspendable until the unlock boundary.
//!
//! ## Audit map
//! Each `§` is a code section below; it states the INVARIANT it guarantees, the
//! THREAT it defends, and the TESTS that prove it.
//!
//! - **§1 `prepare_vesting_transaction`** — INVARIANT: the positional-arg shim builds an
//!   equivalent `VestingRequest` and delegates to `prepare_vesting` unchanged.
//!   THREAT: shim drift silently changes vesting semantics for legacy callers.
//!   TESTS: (gap — tests call `prepare_vesting` directly; the shim is untested).
//! - **§2 `prepare_vesting` (balance)** — INVARIANT: on success
//!   `sum(inputs) == amount + estimated_fee + change_amount` exactly.
//!   THREAT: value created or destroyed before signing → fund loss / inflation.
//!   TESTS: `prepare_vesting_stamps_unlock_height_onto_output_lock_height`.
//! - **§3 `prepare_vesting` (fee-growth loop)** — INVARIANT: re-selects and grows `required`
//!   until inputs cover `amount + fee`, since each added input raises the fee.
//!   THREAT: settling under-funded → a rejected tx.
//!   TESTS: `prepare_vesting_fee_growth_loop_reselects_until_inputs_cover_fee`.
//! - **§4 `build_prepared_vesting_transaction` (lock stamping)** — INVARIANT: exactly one
//!   output carries `lock_height == unlock_height`.
//!   THREAT: a missing/wrong lock lets vested funds be spent early.
//!   TESTS: `prepare_vesting_stamps_unlock_height_onto_output_lock_height`.
//! - **§5 `build_prepared_vesting_transaction` (change/dummies)** — INVARIANT: change ≥ MIN is a
//!   real output (fee unchanged); below MIN it folds into the fee, plus 0..=2 dummy outputs.
//!   THREAT: dust change output, or value silently lost.
//!   TESTS: `prepare_vesting_stamps_unlock_height_onto_output_lock_height`.
//! - **§6 lock-height spendability** — INVARIANT: the balance layer treats a vesting output as
//!   unspendable before `unlock_height` and spendable at/after it.
//!   THREAT: early spend of still-locked funds.
//!   TESTS: `vesting_output_lock_height_gates_spendability_at_unlock_boundary`.

use super::super::decoy_selection::AllocatedRings;
use super::super::{Balance, KeyEpoch, UTXO};
use super::fee::estimate_tx_size;
use super::inputs::{add_prepared_inputs, prepare_input};
use super::selection::{ensure_spendable, select_utxos};
use super::types::{
    CoinSelection, Payment, PreparedVestingTransaction, SpendContext, VestingRequest,
};
use crate::constants::{MIN_FEE_PER_BYTE, MIN_OUTPUT_AMOUNT};
use crate::error::Result;
use crate::primitives::{Amount, PublicKey};
use crate::transaction::{Recipient, Transaction, TransactionBuilder};
use rand::{CryptoRng, Rng, RngCore};

const VESTING_ESTIMATED_OUTPUT_COUNT: usize = 4;

/// Compatibility entry point for positional vesting parameters.
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
    let context = SpendContext::with_ring_size(current_height, ring_size)?;
    let request = VestingRequest::new(
        Payment::new(recipient_spend, recipient_view, amount),
        unlock_height,
        context,
    );
    prepare_vesting(balance, request, keys, rng)
}

pub fn prepare_vesting<R: RngCore + CryptoRng>(
    balance: &Balance,
    request: VestingRequest,
    keys: &KeyEpoch,
    rng: &mut R,
) -> Result<PreparedVestingTransaction> {
    let context = request.context;
    let mut required = request.payment.amount.saturating_add(Amount::from_atomic(
        estimate_tx_size(1, VESTING_ESTIMATED_OUTPUT_COUNT, context.ring_size()) as u64
            * MIN_FEE_PER_BYTE,
    ));
    ensure_spendable(
        balance,
        context.target_height(),
        context.min_output_age(),
        required,
    )?;
    let utxos: Vec<&UTXO> =
        balance.available_utxos(context.target_height(), context.min_output_age());

    let (selected, estimated_fee, output_total, input_sum) = loop {
        ensure_spendable(
            balance,
            context.target_height(),
            context.min_output_age(),
            required,
        )?;
        let selected = select_utxos(&utxos, required, CoinSelection::OldestFirst, rng)?;
        let estimated_fee = Amount::from_atomic(
            estimate_tx_size(
                selected.len(),
                VESTING_ESTIMATED_OUTPUT_COUNT,
                context.ring_size(),
            ) as u64
                * MIN_FEE_PER_BYTE,
        );
        let output_total = request
            .payment
            .amount
            .as_atomic()
            .saturating_add(estimated_fee.as_atomic());
        let input_sum: Amount = selected.iter().map(|utxo| utxo.amount).sum();
        if input_sum.as_atomic() >= output_total {
            break (selected, estimated_fee, output_total, input_sum);
        }
        required = Amount::from_atomic(output_total);
    };

    Ok(PreparedVestingTransaction {
        inputs: selected
            .into_iter()
            .map(|utxo| prepare_input(utxo, keys))
            .collect::<Result<_>>()?,
        request,
        change_amount: input_sum.as_atomic().saturating_sub(output_total),
        estimated_fee,
        spend_public: keys.spend_public,
        view_public: keys.view_public,
    })
}

pub fn build_prepared_vesting_transaction<R: RngCore + CryptoRng>(
    prepared: PreparedVestingTransaction,
    rings: AllocatedRings,
    rng: &mut R,
) -> Result<Transaction> {
    let PreparedVestingTransaction {
        inputs,
        request,
        change_amount,
        estimated_fee,
        spend_public,
        view_public,
    } = prepared;
    let context = request.context;

    let mut builder =
        TransactionBuilder::transfer().with_target_height(context.target_height());
    add_prepared_inputs(&mut builder, inputs, rings, context.ring_size())?;
    builder.add_output(
        &Recipient {
            spend_public: request.payment.spend_public,
            view_public: request.payment.view_public,
            amount: request.payment.amount,
            lock_height: Some(request.unlock_height),
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
        builder.add_dummy_output(rng)?;
    }
    builder.set_fee(final_fee);
    builder.build(rng)
}
