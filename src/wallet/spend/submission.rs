use super::super::balance::{Balance, RESERVATION_EXPIRY_BLOCKS};
use super::super::node_rpc::SubmissionOutcome;
use super::super::Wallet;
use super::types::{BuiltSpend, SpendInputBinding, SpendSubmission};
use super::SpendCoordinator;
use crate::error::{Error, Result};
use crate::primitives::Hash;

impl SpendCoordinator {
    /// Reserve, persist, submit and reconcile one signed transaction.
    ///
    /// The build artifact already contains its encoded payload and exact input
    /// bindings. Those bindings are checked against the current wallet under
    /// the same exclusive borrow used to reserve them. Reservations are then
    /// written before bytes leave the process and released only after a
    /// definitive rejection. An indeterminate network result keeps them because
    /// the node may already have accepted the transaction.
    pub async fn submit_reserved(
        &self,
        wallet: &mut Wallet,
        password: &str,
        built: BuiltSpend,
    ) -> Result<SpendSubmission> {
        let BuiltSpend {
            encoded_transaction,
            tx_hash,
            target_height,
            input_bindings,
            ..
        } = built;
        let selected_outputs = validate_input_bindings(wallet.balance_ref(), &input_bindings)?;

        wallet
            .reserve_utxos(&selected_outputs, tx_hash, target_height)
            .map_err(|conflict| Error::InvalidState(format!("reservation conflict: {conflict}")))?;

        if let Err(error) = wallet.save(Some(password)) {
            let released_reservations = wallet.release_reservations_by_tx(tx_hash);
            let rollback_error = wallet
                .save(Some(password))
                .err()
                .map(|rollback| rollback.to_string());
            let rollback_note = rollback_error
                .map(|rollback| {
                    format!(
                        "; released {released_reservations} reservation(s) in memory, \
                         but failed to persist the rollback: {rollback}"
                    )
                })
                .unwrap_or_else(|| {
                    format!(
                        "; released and persisted {released_reservations} reservation(s) without broadcasting"
                    )
                });
            return Err(Error::InvalidState(format!(
                "failed to persist input reservation before submission: {error}{rollback_note}"
            )));
        }

        let retained_reservations = selected_outputs.len();
        let reservation_expires_at =
            target_height.saturating_add(RESERVATION_EXPIRY_BLOCKS);

        match self
            .rpc
            .submit_encoded_transaction(&encoded_transaction)
            .await
        {
            // Mempool acceptance is not chain confirmation. Keep the durable
            // reservation in place; the scanner consumes it when the key image
            // confirms, or normal expiry releases it if the transaction drops.
            SubmissionOutcome::Accepted => Ok(SpendSubmission::MempoolAccepted {
                tx_hash,
                retained_reservations,
                reservation_expires_at,
            }),
            SubmissionOutcome::Rejected { reason } => {
                let released_reservations = wallet.release_reservations_by_tx(tx_hash);
                let reservation_release_save_error = wallet
                    .save(Some(password))
                    .err()
                    .map(|error| error.to_string());

                Ok(SpendSubmission::Rejected {
                    tx_hash,
                    reason,
                    released_reservations,
                    reservation_release_save_error,
                })
            }
            SubmissionOutcome::Unknown { reason } => Ok(SpendSubmission::Unknown {
                tx_hash,
                reason,
                retained_reservations,
                reservation_expires_at,
            }),
        }
    }
}

fn validate_input_bindings(
    balance: &Balance,
    bindings: &[SpendInputBinding],
) -> Result<Vec<(Hash, u8)>> {
    if bindings.is_empty() {
        return Err(Error::InvalidState(
            "built spend contains no input bindings".into(),
        ));
    }

    let mut selected_outputs = Vec::with_capacity(bindings.len());
    for binding in bindings {
        match balance.lookup_by_key_image(&binding.key_image) {
            Some(current) if current == binding.output => selected_outputs.push(binding.output),
            Some(current) => {
                return Err(Error::InvalidState(format!(
                    "built transaction key image {} was bound to wallet output {}, \
                     but the current wallet maps it to {}; rebuild before submitting",
                    hex::encode(binding.key_image.as_bytes()),
                    format_output_key(binding.output),
                    format_output_key(current),
                )))
            }
            None => {
                return Err(Error::InvalidState(format!(
                    "built transaction input {} ({}) is no longer an unspent wallet output; rebuild before submitting",
                    format_output_key(binding.output),
                    hex::encode(binding.key_image.as_bytes()),
                )))
            }
        }
    }

    Ok(selected_outputs)
}

fn format_output_key((tx_hash, output_index): (Hash, u8)) -> String {
    format!("{}:{output_index}", hex::encode(tx_hash.as_bytes()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::primitives::{Amount, KeyImage, PublicKey};
    use crate::wallet::UTXO;

    fn make_utxo(id: u8) -> UTXO {
        UTXO {
            tx_hash: Hash::from_bytes([id; 32]),
            output_index: id,
            output_locator: None,
            amount: Amount::from_atomic(1_000),
            height: 10,
            key_image: KeyImage::from_bytes([id.wrapping_add(32); 32]),
            spent: false,
            amount_blinding_bytes: [0; 32],
            tx_public_key: PublicKey::from_bytes([id.wrapping_add(64); 32]),
            lock_height: None,
        }
    }

    fn binding(utxo: &UTXO) -> SpendInputBinding {
        SpendInputBinding {
            output: (utxo.tx_hash, utxo.output_index),
            key_image: utxo.key_image,
        }
    }

    #[test]
    fn current_wallet_binding_is_accepted() {
        let utxo = make_utxo(1);
        let expected = (utxo.tx_hash, utxo.output_index);
        let mut balance = Balance::new();
        balance.add_utxo(utxo.clone());

        assert_eq!(
            validate_input_bindings(&balance, &[binding(&utxo)]).unwrap(),
            vec![expected]
        );
    }

    #[test]
    fn spent_input_requires_rebuild() {
        let utxo = make_utxo(2);
        let mut balance = Balance::new();
        balance.add_utxo(utxo.clone());
        balance.mark_spent(utxo.tx_hash, utxo.output_index);

        let error = validate_input_bindings(&balance, &[binding(&utxo)]).unwrap_err();
        assert!(error.to_string().contains("no longer an unspent wallet output"));
    }

    #[test]
    fn removed_input_requires_rebuild() {
        let utxo = make_utxo(3);
        let balance = Balance::new();

        let error = validate_input_bindings(&balance, &[binding(&utxo)]).unwrap_err();
        assert!(error.to_string().contains("no longer an unspent wallet output"));
    }

    #[test]
    fn key_image_cannot_be_rebound_to_another_output() {
        let first = make_utxo(4);
        let second = make_utxo(5);
        let mut balance = Balance::new();
        balance.add_utxo(first.clone());
        balance.add_utxo(second.clone());

        let forged = SpendInputBinding {
            output: (first.tx_hash, first.output_index),
            key_image: second.key_image,
        };
        let error = validate_input_bindings(&balance, &[forged]).unwrap_err();
        assert!(error.to_string().contains("current wallet maps it to"));
    }
}
