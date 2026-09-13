//! Reserved spend submission.
//!
//! Takes a sealed [`BuiltSpend`], revalidates its input bindings against the
//! live wallet under one exclusive borrow, reserves and persists those inputs
//! before any bytes leave the process, then submits through the typed
//! coordinator RPC and reconciles reservations against the network outcome.
//!
//! ## Audit map
//! Each `§` is a code section below; it states the INVARIANT it guarantees, the
//! THREAT it defends, and the TESTS that prove it.
//!
//! - **§1 `submit_reserved`** — INVARIANT: inputs are reserved and persisted
//!   before any transaction bytes leave the process, and reservations are
//!   released only on a definitive rejection while an indeterminate result
//!   retains them. THREAT: broadcasting without a durable reservation, so a
//!   crash strands or double-spends the inputs.
//!   TESTS: `submit_reserved_retains_reservation_on_indeterminate_network_result`,
//!   `submit_reserved_reservation_survives_crash_and_reload`,
//!   `submit_reserved_releases_and_reports_rollback_when_persistence_fails`.
//! - **§2 reservation-conflict guard** — INVARIANT: an input already reserved
//!   by another transaction aborts before submission, leaving the prior claim
//!   untouched. THREAT: double-reservation of one UTXO across two spends.
//!   TESTS: `submit_reserved_aborts_on_reservation_conflict`.
//! - **§3 persist-before-broadcast rollback** — INVARIANT: a failed reservation
//!   persist releases the reservation in memory and reports the rollback
//!   without broadcasting anything. THREAT: a silent broadcast after
//!   persistence failed. TESTS: `submit_reserved_releases_and_reports_rollback_when_persistence_fails`.
//! - **§4 empty-bindings guard** — INVARIANT: a built spend with no input
//!   bindings is rejected before anything is reserved. THREAT: reserving or
//!   submitting a spend that binds no wallet inputs.
//!   TESTS: `submit_reserved_rejects_empty_input_bindings_before_reserving`.
//! - **§5 `validate_input_bindings`** — INVARIANT: every bound key image still
//!   maps to its exact bound wallet output under the same exclusive borrow used
//!   to reserve, else the caller must rebuild. THREAT: a build/submit race that
//!   rediscovers or rebinds different inputs. TESTS: `current_wallet_binding_is_accepted`,
//!   `spent_input_requires_rebuild`, `removed_input_requires_rebuild`,
//!   `key_image_cannot_be_rebound_to_another_output`.
//! - **§6 transport classification (`self.rpc.submit_encoded_transaction`)** —
//!   INVARIANT: the outcome flows through the typed coordinator RPC, which maps
//!   a remote error to a definitive rejection but keeps transport/protocol
//!   failures Unknown so their reservations are retained. THREAT: a
//!   misclassified network result that releases reservations prematurely.
//!   TESTS: `remote_submission_error_is_a_definitive_rejection`,
//!   `transport_and_protocol_failures_keep_submission_unknown`.

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
    use crate::transaction::{Transaction, TxType};
    use crate::wallet::decoy_selection::SnapshotId;
    use crate::wallet::UTXO;
    use tempfile::tempdir;

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
            subaddress_account: None,
            subaddress_index: None,
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

    // ===== submit_reserved reservation lifecycle =========================
    //
    // The Accepted and definitive-Rejected network branches require a node
    // that returns a specific JSON-RPC result. `NodeRpcClient` has no
    // injectable transport and the workspace ships no HTTP mock, so those two
    // branches are exercised at the classification layer in `node_rpc.rs`
    // (`classify_submission_result`) instead. The tests below cover every
    // branch reachable without a live node: pre-submit validation, reservation
    // conflict, the persist-before-broadcast guarantee, the indeterminate
    // (Unknown) transport branch, crash survival, and the save-failure
    // rollback path — none of which broadcast.

    fn spend_coordinator(endpoint: &str) -> SpendCoordinator {
        SpendCoordinator::for_node(endpoint).unwrap()
    }

    fn sample_snapshot_id() -> SnapshotId {
        use crate::decoy::{
            DecoyDistributionSnapshot, HeightOutputCount, DECOY_LOCATOR_POLICY_VERSION,
        };
        crate::wallet::decoy_selection::ValidatedDecoySnapshot::try_from(
            DecoyDistributionSnapshot {
                snapshot_height: 10,
                snapshot_hash: Hash::from_bytes([3u8; 32]),
                policy_version: DECOY_LOCATOR_POLICY_VERSION,
                heights: vec![HeightOutputCount {
                    height: 0,
                    count: 1,
                }],
            },
        )
        .unwrap()
        .snapshot_id()
    }

    fn empty_transaction() -> Transaction {
        Transaction {
            version: 1,
            tx_type: TxType::Transfer,
            inputs: vec![],
            outputs: vec![],
            fee: Amount::from_atomic(0),
            range_proof: vec![],
            extra: vec![],
        }
    }

    // submit_reserved reads only encoded_transaction, tx_hash, target_height
    // and input_bindings from the BuiltSpend; the transaction and snapshot_id
    // are placeholders here.
    fn built_spend(
        tx_hash: Hash,
        target_height: u64,
        bindings: Vec<SpendInputBinding>,
    ) -> BuiltSpend {
        BuiltSpend {
            transaction: empty_transaction(),
            encoded_transaction: "00".to_string(),
            tx_hash,
            snapshot_id: sample_snapshot_id(),
            target_height,
            input_bindings: bindings,
        }
    }

    fn funded_wallet(dir: &std::path::Path, utxos: &[UTXO]) -> (Wallet, std::path::PathBuf) {
        let path = dir.join("test.wallet");
        let (mut wallet, _) = Wallet::create(path.clone(), Some("pw"), "testnet").unwrap();
        for utxo in utxos {
            wallet.add_utxo(utxo.clone());
        }
        (wallet, path)
    }

    #[tokio::test]
    async fn submit_reserved_rejects_empty_input_bindings_before_reserving() {
        let dir = tempdir().unwrap();
        let (mut wallet, _path) = funded_wallet(dir.path(), &[make_utxo(40)]);
        let coordinator = spend_coordinator("http://127.0.0.1:1");

        let built = built_spend(Hash::from_bytes([1u8; 32]), 11, Vec::new());
        let error = coordinator
            .submit_reserved(&mut wallet, "pw", built)
            .await
            .unwrap_err();

        assert!(error.to_string().contains("no input bindings"));
        assert!(
            wallet.balance_ref().all_reservations().is_empty(),
            "an empty built spend must not reserve anything"
        );
    }

    #[tokio::test]
    async fn submit_reserved_aborts_on_reservation_conflict() {
        let dir = tempdir().unwrap();
        let utxo = make_utxo(41);
        let output = (utxo.tx_hash, utxo.output_index);
        let (mut wallet, _path) = funded_wallet(dir.path(), &[utxo.clone()]);

        // Another transaction already holds this UTXO.
        let other_tx = Hash::from_bytes([0xAB; 32]);
        wallet.reserve_utxos(&[output], other_tx, 11).unwrap();

        let coordinator = spend_coordinator("http://127.0.0.1:1");
        let built = built_spend(Hash::from_bytes([0xCD; 32]), 11, vec![binding(&utxo)]);
        let error = coordinator
            .submit_reserved(&mut wallet, "pw", built)
            .await
            .unwrap_err();

        assert!(error.to_string().contains("reservation conflict"));
        // The pre-existing claim is untouched; no second reservation was added.
        let reservations = wallet.balance_ref().all_reservations();
        assert_eq!(reservations.len(), 1);
        assert_eq!(reservations[0].1.by_tx, other_tx);
    }

    #[tokio::test]
    async fn submit_reserved_retains_reservation_on_indeterminate_network_result() {
        let dir = tempdir().unwrap();
        let utxo = make_utxo(42);
        let output = (utxo.tx_hash, utxo.output_index);
        let (mut wallet, path) = funded_wallet(dir.path(), &[utxo.clone()]);

        // Nothing is listening on this address, so the submit attempt fails at
        // the transport layer. That is classified as Unknown (the node may or
        // may not have received the bytes) and the reservation is retained.
        let coordinator = spend_coordinator("http://127.0.0.1:1");
        let target_height = 11;
        let built = built_spend(Hash::from_bytes([0x11; 32]), target_height, vec![binding(&utxo)]);

        let submission = coordinator
            .submit_reserved(&mut wallet, "pw", built)
            .await
            .unwrap();

        match submission {
            SpendSubmission::Unknown {
                retained_reservations,
                reservation_expires_at,
                ..
            } => {
                assert_eq!(retained_reservations, 1);
                assert_eq!(
                    reservation_expires_at,
                    target_height + RESERVATION_EXPIRY_BLOCKS
                );
            }
            other => panic!("expected an Unknown submission, got {other:?}"),
        }

        assert!(wallet.balance_ref().is_reserved(&output, target_height));
        // The reservation was persisted before the transaction bytes left the
        // process, independent of the network outcome.
        assert!(path.with_extension("reservations").exists());
    }

    #[tokio::test]
    async fn submit_reserved_reservation_survives_crash_and_reload() {
        let dir = tempdir().unwrap();
        let utxo = make_utxo(43);
        let output = (utxo.tx_hash, utxo.output_index);
        let (mut wallet, path) = funded_wallet(dir.path(), &[utxo.clone()]);

        let coordinator = spend_coordinator("http://127.0.0.1:1");
        let target_height = 11;
        let built = built_spend(Hash::from_bytes([0x22; 32]), target_height, vec![binding(&utxo)]);
        let submission = coordinator
            .submit_reserved(&mut wallet, "pw", built)
            .await
            .unwrap();
        assert!(matches!(submission, SpendSubmission::Unknown { .. }));
        drop(wallet);

        // Reopen from disk exactly as a restarted process would.
        let mut reopened = Wallet::open(path.clone()).unwrap();
        reopened.unlock("pw").unwrap();
        assert!(
            reopened.balance_ref().is_reserved(&output, target_height),
            "an in-flight reservation must survive a crash via the .reservations sidecar"
        );
    }

    #[tokio::test]
    async fn submit_reserved_releases_and_reports_rollback_when_persistence_fails() {
        let dir = tempdir().unwrap();
        let utxo = make_utxo(44);
        let (mut wallet, _path) = funded_wallet(dir.path(), &[utxo.clone()]);

        // Destroy the wallet directory so every save() attempt fails: both the
        // reservation persist and the rollback persist.
        std::fs::remove_dir_all(dir.path()).unwrap();

        let coordinator = spend_coordinator("http://127.0.0.1:1");
        let built = built_spend(Hash::from_bytes([0x33; 32]), 11, vec![binding(&utxo)]);
        let error = coordinator
            .submit_reserved(&mut wallet, "pw", built)
            .await
            .unwrap_err();

        let message = error.to_string();
        assert!(message.contains("failed to persist input reservation before submission"));
        assert!(message.contains("failed to persist the rollback"));
        // The reservation was released in memory and nothing was broadcast.
        assert!(wallet.balance_ref().all_reservations().is_empty());
    }
}
