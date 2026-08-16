use super::fee::{scaled_fee, FeeMultiplier};
use super::inputs::prepare_input;
use super::selection::{ensure_spendable, select_utxos, select_utxos_uniform};
use super::types::{
    CoinSelection, Payment, PreparedPrivacyTransaction, SendRequest, SpendContext, TransferShape,
};
use super::super::{Balance, KeyEpoch, UTXO};
use crate::constants::{STANDARD_INPUT_COUNT, STANDARD_OUTPUT_COUNT};
use crate::error::Result;
use crate::primitives::{Amount, PublicKey};
use rand::{CryptoRng, RngCore};

const LEGACY_OUTPUT_PADDING: usize = 3;

/// Compatibility entry point for callers still passing positional options.
/// New code should construct a [`SendRequest`] and call
/// [`prepare_privacy_transaction`].
pub fn prepare_privacy_transaction_with_options<R: RngCore + CryptoRng>(
    balance: &Balance,
    // (spend_public, view_public, amount, is_subaddress). The trailing bool
    // MUST be true when the destination is a subaddress (Address.address_type
    // == Subaddress): subaddress outputs use tx pubkey R = r*D_i so the
    // recipient can detect/spend them against their view key C_i = a*D_i.
    // Getting it wrong makes the payment unspendable by the recipient.
    recipients: &[(PublicKey, PublicKey, Amount, bool)],
    keys: &KeyEpoch,
    current_height: u64,
    ring_size: usize,
    fee_multiplier: f64,
    memo: Option<&[u8]>,
    extra: Vec<u8>,
    rng: &mut R,
) -> Result<PreparedPrivacyTransaction> {
    let context = SpendContext::with_ring_size(current_height, ring_size)?;
    let payments = recipients
        .iter()
        .map(|&(spend, view, amount, is_subaddress)| {
            Payment::new(spend, view, amount).with_subaddress(is_subaddress)
        })
        .collect();
    let request = SendRequest::new(payments, context)
        .with_fee_multiplier(fee_multiplier)
        .with_memo(memo.map(ToOwned::to_owned))
        .with_extra(extra);

    prepare_privacy_transaction(balance, request, keys, rng)
}

pub fn prepare_privacy_transaction<R: RngCore + CryptoRng>(
    balance: &Balance,
    request: SendRequest,
    keys: &KeyEpoch,
    rng: &mut R,
) -> Result<PreparedPrivacyTransaction> {
    let SendRequest {
        payments,
        context,
        fee_multiplier,
        memo,
        extra,
    } = request;
    let shape = TransferShape::classify(&payments, context.target_height())?;
    let total_send: Amount = payments.iter().map(|payment| payment.amount).sum();
    let output_count = if shape.is_uniform() {
        STANDARD_OUTPUT_COUNT
    } else {
        payments.len() + LEGACY_OUTPUT_PADDING
    };
    let input_count_estimate = if shape.is_uniform() {
        STANDARD_INPUT_COUNT
    } else {
        1
    };

    if fee_multiplier.is_nan() {
        tracing::warn!(
            target: "wallet::send",
            "fee multiplier is NaN; using the neutral 1.0 multiplier"
        );
    }
    let fee_multiplier = FeeMultiplier::from_f64(fee_multiplier);
    let initial_fee = scaled_fee(
        input_count_estimate,
        output_count,
        context.ring_size(),
        fee_multiplier,
    );
    let mut required = total_send.saturating_add(initial_fee);
    ensure_spendable(
        balance,
        context.target_height(),
        context.min_output_age(),
        required,
    )?;

    let utxos: Vec<&UTXO> =
        balance.available_utxos(context.target_height(), context.min_output_age());
    let (selected, estimated_fee, total_needed, input_sum) = loop {
        ensure_spendable(
            balance,
            context.target_height(),
            context.min_output_age(),
            required,
        )?;
        let selected = if shape.is_uniform() {
            select_utxos_uniform(&utxos, required, rng)?
        } else {
            select_utxos(&utxos, required, CoinSelection::OldestFirst, rng)?
        };
        let estimated_fee = scaled_fee(
            selected.len(),
            output_count,
            context.ring_size(),
            fee_multiplier,
        );
        let total_needed = total_send.saturating_add(estimated_fee);
        let input_sum: Amount = selected.iter().map(|utxo| utxo.amount).sum();
        if input_sum >= total_needed {
            break (selected, estimated_fee, total_needed, input_sum);
        }
        required = total_needed;
    };

    Ok(PreparedPrivacyTransaction {
        inputs: selected
            .into_iter()
            .map(|utxo| prepare_input(utxo, keys))
            .collect::<Result<_>>()?,
        payments,
        change_amount: input_sum
            .as_atomic()
            .saturating_sub(total_needed.as_atomic()),
        estimated_fee,
        context,
        shape,
        spend_public: keys.spend_public,
        view_public: keys.view_public,
        memo,
        extra,
    })
}
