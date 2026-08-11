use super::fee::estimate_tx_size;
use super::selection::select_utxos;
use super::types::CoinSelection;
use super::super::Balance;
use crate::constants::{
    min_output_age_at_height, ring_size_at_height, MIN_FEE_PER_BYTE, MIN_OUTPUT_AMOUNT,
};
use crate::error::{Error, Result};
use crate::primitives::{Address, Amount, PublicKey};
use crate::transaction::{Transaction, TxType};

/// Create a structurally valid transaction without ring signatures or stealth
/// address cryptography.
///
/// Production callers must use `SharedWallet::create_transfer`, or the
/// prepare/covered-allocation/build flow in this module.
#[deprecated(
    note = "Use SharedWallet::create_transfer or the prepared covered-allocation flow; \
    this builder emits placeholder commitments that fail consensus validation"
)]
#[allow(dead_code, deprecated)]
pub fn create_transaction(
    balance: &Balance,
    recipients: &[(Address, Amount)],
    current_height: u64,
) -> Result<Transaction> {
    let min_age = min_output_age_at_height(current_height);
    let total_send: Amount = recipients.iter().map(|(_, amount)| *amount).sum();
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

    let utxos = balance.available_utxos(current_height, min_age);
    let selected = select_utxos(
        &utxos,
        total_needed,
        CoinSelection::OldestFirst,
        &mut rand::rngs::OsRng,
    )?;

    let mut builder = crate::transaction::SimpleTransactionBuilder::new(TxType::Transfer);
    builder.set_fee(fee);
    for (address, amount) in recipients {
        builder.add_output(
            address.spend_public_key,
            address.view_public_key,
            [0u8; 32],
            amount.as_atomic().to_le_bytes().to_vec(),
            0,
        );
    }

    let input_sum: Amount = selected.iter().map(|utxo| utxo.amount).sum();
    let change = input_sum
        .as_atomic()
        .saturating_sub(total_needed.as_atomic());
    if change >= MIN_OUTPUT_AMOUNT {
        builder.add_output(
            PublicKey::from_bytes([0u8; 32]),
            PublicKey::from_bytes([0u8; 32]),
            [0u8; 32],
            change.to_le_bytes().to_vec(),
            0,
        );
    }

    builder.build()
}
