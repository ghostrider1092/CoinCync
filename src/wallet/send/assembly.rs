use super::inputs::add_prepared_inputs;
use super::types::{PreparedPrivacyTransaction, TransferShape};
use super::super::decoy_selection::AllocatedRing;
use crate::constants::MIN_OUTPUT_AMOUNT;
use crate::error::Result;
use crate::primitives::Amount;
use crate::transaction::{Recipient, Transaction, TransactionBuilder};
use rand::{CryptoRng, Rng, RngCore};

pub fn build_prepared_privacy_transaction<R: RngCore + CryptoRng>(
    prepared: PreparedPrivacyTransaction,
    rings: Vec<AllocatedRing>,
    rng: &mut R,
) -> Result<Transaction> {
    let PreparedPrivacyTransaction {
        inputs,
        payments,
        change_amount,
        estimated_fee,
        context,
        shape,
        spend_public,
        view_public,
        memo,
        extra,
    } = prepared;

    let mut builder =
        TransactionBuilder::transfer().with_target_height(context.target_height());
    if let Some(memo) = memo.as_deref() {
        builder = builder.with_memo(memo);
    }
    if !extra.is_empty() {
        builder = builder.with_extra(extra);
    }
    add_prepared_inputs(&mut builder, inputs, rings, context.ring_size())?;

    for (index, payment) in payments.iter().enumerate() {
        builder.add_output(
            &Recipient {
                spend_public: payment.spend_public,
                view_public: payment.view_public,
                amount: payment.amount,
                lock_height: None,
            },
            index as u8,
            rng,
        )?;
    }

    let final_fee = match shape {
        TransferShape::UniformDripPair => {
            Amount::from_atomic(estimated_fee.as_atomic().saturating_add(change_amount))
        }
        TransferShape::UniformStandard if change_amount >= MIN_OUTPUT_AMOUNT => {
            builder.add_change(
                &spend_public,
                &view_public,
                Amount::from_atomic(change_amount),
                payments.len() as u8,
                rng,
            )?;
            estimated_fee
        }
        TransferShape::UniformStandard => {
            builder.add_dummy_output(rng)?;
            Amount::from_atomic(estimated_fee.as_atomic().saturating_add(change_amount))
        }
        TransferShape::Legacy => {
            let fee = if change_amount >= MIN_OUTPUT_AMOUNT {
                builder.add_change(
                    &spend_public,
                    &view_public,
                    Amount::from_atomic(change_amount),
                    payments.len() as u8,
                    rng,
                )?;
                estimated_fee
            } else {
                Amount::from_atomic(estimated_fee.as_atomic().saturating_add(change_amount))
            };
            for _ in 0..rng.gen_range(0..=2usize) {
                builder.add_dummy_output(rng)?;
            }
            fee
        }
    };

    builder.set_fee(final_fee);
    builder.build(rng)
}
