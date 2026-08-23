use super::super::decoy_selection::AllocatedRings;
use super::inputs::add_prepared_inputs;
use super::types::{PreparedPrivacyTransaction, TransferShape};
use crate::constants::MIN_OUTPUT_AMOUNT;
use crate::error::Result;
use crate::primitives::Amount;
use crate::transaction::{Recipient, Transaction, TransactionBuilder};
use rand::{CryptoRng, Rng, RngCore};

pub fn build_prepared_privacy_transaction<R: RngCore + CryptoRng>(
    prepared: PreparedPrivacyTransaction,
    rings: AllocatedRings,
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
        builder.add_output_ext(
            &Recipient {
                spend_public: payment.spend_public,
                view_public: payment.view_public,
                amount: payment.amount,
                lock_height: None,
            },
            index as u8,
            payment.is_subaddress,
            rng,
        )?;
    }

    let final_fee = match shape {
        TransferShape::UniformDripPair => {
            let total_send: u64 = payments
                .iter()
                .map(|p| p.amount.as_atomic())
                .fold(0u64, |a, b| a.saturating_add(b));
            drip_pair_final_fee(estimated_fee.as_atomic(), change_amount, total_send)?
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

/// Final fee for the `UniformDripPair` shape, with a catastrophic-loss guard.
///
/// The drip-pair emits two equal outputs and NO change output, folding any
/// input excess into the fee so the two outputs stay uniform (a change output
/// would break that uniformity). Folding a small/dust excess is the intended,
/// documented behaviour. But we fail closed if selection could only find a
/// UTXO pair whose excess exceeds the amount actually being sent — burning
/// more to fee than we pay the recipient is never intended, and silently
/// destroying that value would be a fund-loss footgun. The error is actionable
/// (consolidate, or use a standard send). Small excesses still flow to fee.
fn drip_pair_final_fee(
    estimated_fee: u64,
    change_amount: u64,
    total_send: u64,
) -> Result<Amount> {
    if change_amount > total_send {
        return Err(crate::error::Error::InvalidTransaction(format!(
            "drip-pair (--split-output) would burn {} atomic to fee — more than the {} atomic \
             being sent. Consolidate your outputs or use a standard send to avoid the loss.",
            change_amount, total_send
        )));
    }
    Ok(Amount::from_atomic(estimated_fee.saturating_add(change_amount)))
}

#[cfg(test)]
mod drip_guard_tests {
    use super::drip_pair_final_fee;
    use crate::error::Error;

    #[test]
    fn small_excess_flows_to_fee() {
        // Excess (change) below the amount sent is the intended behaviour:
        // it folds into the fee and the tx is built.
        let fee = drip_pair_final_fee(1_000, 500, 1_000_000).expect("small excess ok");
        assert_eq!(fee.as_atomic(), 1_500, "fee = estimated_fee + folded excess");
    }

    #[test]
    fn excess_equal_to_send_is_allowed_boundary() {
        // change_amount == total_send is the inclusive boundary (not > ), so
        // it is still permitted.
        let fee = drip_pair_final_fee(1_000, 40_000, 40_000).expect("boundary ok");
        assert_eq!(fee.as_atomic(), 41_000);
    }

    #[test]
    fn large_excess_is_rejected_not_silently_burned() {
        // Excess exceeding the amount sent (e.g. sending 1 CYNC but the only
        // available pair leaves ~99 CYNC change) must fail closed.
        let err = drip_pair_final_fee(1_000, 99_000_000, 1_000_000)
            .expect_err("large burn must be rejected");
        match err {
            Error::InvalidTransaction(msg) => {
                assert!(msg.contains("99000000"), "message names the burn: {msg}");
                assert!(msg.contains("1000000"), "message names the send: {msg}");
            }
            other => panic!("expected InvalidTransaction, got {other:?}"),
        }
    }
}
