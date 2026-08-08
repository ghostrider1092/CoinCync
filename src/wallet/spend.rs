//! Wallet spend orchestration.
//!
//! This module owns the application-level sequence shared by interactive sends
//! and auto-churn:
//!
//! 1. bind a spend to one validated decoy-distribution snapshot,
//! 2. select inputs and build one typed covered locator request,
//! 3. resolve and validate the covered response,
//! 4. allocate transaction-wide unique rings and sign,
//! 5. reserve inputs before broadcast, and
//! 6. apply accepted/rejected/unknown submission semantics consistently.

use super::decoy_selection::{
    allocate_unique_rings, build_covered_request, validate_covered_response,
    ValidatedDecoySnapshot,
};
use super::node_rpc::{NodeRpcClient, SubmissionOutcome};
use super::send::{
    build_prepared_privacy_transaction, prepare_privacy_transaction, Payment, SendRequest,
    SpendContext,
};
use super::{Balance, KeyEpoch, Wallet};
use crate::error::{Error, Result};
use crate::primitives::Hash;
use crate::transaction::Transaction;
use rand::{CryptoRng, RngCore};
use std::collections::HashSet;

/// User-level data needed to build a normal privacy transaction.
#[derive(Clone)]
pub struct SpendIntent {
    payments: Vec<Payment>,
    fee_multiplier: f64,
    memo: Option<Vec<u8>>,
    extra: Vec<u8>,
}

impl SpendIntent {
    /// Start an intent with neutral fee policy and no auxiliary metadata.
    pub fn new(payments: Vec<Payment>) -> Self {
        Self {
            payments,
            fee_multiplier: 1.0,
            memo: None,
            extra: Vec::new(),
        }
    }

    /// Apply the caller's fee multiplier.
    pub fn with_fee_multiplier(mut self, fee_multiplier: f64) -> Self {
        self.fee_multiplier = fee_multiplier;
        self
    }

    /// Attach an already validated plaintext memo for output encryption.
    pub fn with_memo(mut self, memo: Option<Vec<u8>>) -> Self {
        self.memo = memo;
        self
    }

    /// Attach transaction-extra bytes such as recovery metadata.
    pub fn with_extra(mut self, extra: Vec<u8>) -> Self {
        self.extra = extra;
        self
    }

    fn into_request(self, context: SpendContext) -> SendRequest {
        SendRequest::new(self.payments, context)
            .with_fee_multiplier(self.fee_multiplier)
            .with_memo(self.memo)
            .with_extra(self.extra)
    }
}

/// Snapshot and consensus context shared by every step of one build attempt.
///
/// A session is intentionally not constructible by callers. It can only be
/// obtained from [`SpendCoordinator::begin`], which validates the distribution
/// once and keeps the target height, ring size, maturity floor and snapshot
/// identity from drifting apart.
pub struct SpendSession {
    snapshot: ValidatedDecoySnapshot,
    context: SpendContext,
}

impl SpendSession {
    /// Consensus parameters bound to this snapshot.
    pub fn context(&self) -> SpendContext {
        self.context
    }

    /// Height at which the transaction is intended to become valid.
    pub fn target_height(&self) -> u64 {
        self.context.target_height()
    }
}

/// A signed transaction plus the height against which its inputs and rings
/// were validated.
pub struct BuiltSpend {
    transaction: Transaction,
    target_height: u64,
}

impl BuiltSpend {
    /// Borrow the signed transaction for display or inspection.
    pub fn transaction(&self) -> &Transaction {
        &self.transaction
    }

    /// Height used when selecting and validating its inputs.
    pub fn target_height(&self) -> u64 {
        self.target_height
    }
}

/// Final submission state after the coordinator has applied wallet-side
/// reservation and persistence rules.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SpendSubmission {
    Accepted {
        tx_hash: Hash,
        /// The node accepted the transaction, but persisting the local spent
        /// state failed. The pre-submit reservation remains durable and a
        /// subsequent scan can reconcile the wallet safely.
        wallet_save_error: Option<String>,
    },
    Rejected {
        tx_hash: Hash,
        reason: String,
        released_reservations: usize,
        /// A failed save can leave the old durable reservation in place until
        /// it expires. This is inconvenient but safe and must be surfaced.
        wallet_save_error: Option<String>,
    },
    Unknown {
        tx_hash: Hash,
        reason: String,
    },
}

/// Coordinates snapshot-bound transaction construction and submission.
#[derive(Clone)]
pub struct SpendCoordinator {
    rpc: NodeRpcClient,
}

impl SpendCoordinator {
    /// Construct from an existing typed RPC client.
    pub fn new(rpc: NodeRpcClient) -> Self {
        Self { rpc }
    }

    /// Construct with the wallet's standard transport policy.
    pub fn for_node(endpoint: impl Into<String>) -> Result<Self> {
        Ok(Self::new(NodeRpcClient::new(endpoint)?))
    }

    /// Borrow the shared client, primarily for diagnostics.
    pub fn rpc(&self) -> &NodeRpcClient {
        &self.rpc
    }

    /// Start one validated, snapshot-bound build attempt.
    pub async fn begin(&self) -> Result<SpendSession> {
        let snapshot = ValidatedDecoySnapshot::try_from(self.rpc.decoy_distribution().await?)?;
        let context = SpendContext::for_target_height(snapshot.spend_height());

        Ok(SpendSession { snapshot, context })
    }

    /// Select inputs, perform the one covered lookup and build a signed
    /// transaction without submitting it.
    pub async fn build_privacy_transaction<R>(
        &self,
        session: &SpendSession,
        balance: &Balance,
        keys: &KeyEpoch,
        intent: SpendIntent,
        rng: &mut R,
    ) -> Result<BuiltSpend>
    where
        R: RngCore + CryptoRng,
    {
        let prepared = prepare_privacy_transaction(
            balance,
            intent.into_request(session.context),
            keys,
            rng,
        )?;
        let real_outputs = prepared.real_outputs();
        let real_locators = real_outputs
            .iter()
            .map(|output| output.locator())
            .collect::<Vec<_>>();
        let request = build_covered_request(
            &session.snapshot,
            &real_locators,
            prepared.ring_size(),
            session.context.min_output_age(),
            rng,
        )?;
        let response = self.rpc.resolve_outputs(&request).await?;
        let response = validate_covered_response(request, response)?;
        let rings = allocate_unique_rings(response, &real_outputs, rng)?;
        let transaction = build_prepared_privacy_transaction(prepared, rings, rng)?;

        Ok(BuiltSpend {
            transaction,
            target_height: session.target_height(),
        })
    }

    /// Reserve, persist, submit and reconcile one signed transaction.
    ///
    /// Reservations are written before bytes leave the process. They are
    /// released only after a definitive rejection. An indeterminate network
    /// result keeps the reservation because the node may already have the tx.
    pub async fn submit_reserved(
        &self,
        wallet: &mut Wallet,
        password: &str,
        built: BuiltSpend,
    ) -> Result<SpendSubmission> {
        let BuiltSpend {
            transaction,
            target_height,
        } = built;
        // Serialize before creating a durable reservation. If encoding fails,
        // no bytes can have left the process and the inputs remain immediately
        // selectable.
        let encoded_transaction = NodeRpcClient::encode_transaction(&transaction)?;
        let tx_hash = transaction.hash();
        let key_images = transaction.key_images();
        let mut input_keys = Vec::with_capacity(key_images.len());
        let mut unique_input_keys = HashSet::with_capacity(key_images.len());

        for key_image in &key_images {
            let key = wallet
                .balance_ref()
                .lookup_by_key_image(key_image)
                .ok_or_else(|| {
                    Error::InvalidState(format!(
                        "transaction input {} is not an unspent wallet output; rescan before submitting",
                        hex::encode(key_image.as_bytes())
                    ))
                })?;
            if !unique_input_keys.insert(key) {
                return Err(Error::InvalidState(
                    "transaction maps multiple inputs to the same wallet output".into(),
                ));
            }
            input_keys.push(key);
        }

        if input_keys.len() != transaction.inputs.len() {
            return Err(Error::InvalidState(format!(
                "mapped {}/{} transaction inputs to wallet outputs",
                input_keys.len(),
                transaction.inputs.len()
            )));
        }

        wallet
            .reserve_utxos(&input_keys, tx_hash, target_height)
            .map_err(|conflict| Error::InvalidState(format!("reservation conflict: {conflict}")))?;

        if let Err(error) = wallet.save(Some(password)) {
            wallet.release_reservations_by_tx(tx_hash);
            return Err(Error::InvalidState(format!(
                "failed to persist input reservation before submission: {error}"
            )));
        }

        match self
            .rpc
            .submit_encoded_transaction(&encoded_transaction)
            .await
        {
            SubmissionOutcome::Accepted => {
                for key_image in &key_images {
                    wallet.mark_spent_by_key_image(key_image);
                }
                let wallet_save_error = wallet
                    .save(Some(password))
                    .err()
                    .map(|error| error.to_string());

                Ok(SpendSubmission::Accepted {
                    tx_hash,
                    wallet_save_error,
                })
            }
            SubmissionOutcome::Rejected { reason } => {
                let released_reservations = wallet.release_reservations_by_tx(tx_hash);
                let wallet_save_error = wallet
                    .save(Some(password))
                    .err()
                    .map(|error| error.to_string());

                Ok(SpendSubmission::Rejected {
                    tx_hash,
                    reason,
                    released_reservations,
                    wallet_save_error,
                })
            }
            SubmissionOutcome::Unknown { reason } => {
                Ok(SpendSubmission::Unknown { tx_hash, reason })
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::primitives::{Amount, PublicKey};

    #[test]
    fn intent_defaults_are_neutral() {
        let payment = Payment::new(
            PublicKey::from_bytes([1; 32]),
            PublicKey::from_bytes([2; 32]),
            Amount::from_atomic(3),
        );
        let request = SpendIntent::new(vec![payment])
            .into_request(SpendContext::for_target_height(10));

        assert_eq!(request.payments().len(), 1);
        assert_eq!(request.context().target_height(), 10);
    }

    #[test]
    fn unknown_submission_is_not_a_rejection() {
        let hash = Hash::from_bytes([7; 32]);
        assert_ne!(
            SpendSubmission::Unknown {
                tx_hash: hash,
                reason: "timeout".into(),
            },
            SpendSubmission::Rejected {
                tx_hash: hash,
                reason: "policy".into(),
                released_reservations: 1,
                wallet_save_error: None,
            }
        );
    }
}
