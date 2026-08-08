use super::super::decoy_selection::{SnapshotId, ValidatedDecoySnapshot};
use super::super::node_rpc::NodeRpcClient;
use super::super::send::{Payment, SendRequest, SpendContext};
use crate::error::{Error, Result};
use crate::primitives::{Hash, KeyImage};
use crate::transaction::Transaction;
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

    pub(super) fn into_request(self, context: SpendContext) -> SendRequest {
        SendRequest::new(self.payments, context)
            .with_fee_multiplier(self.fee_multiplier)
            .with_memo(self.memo)
            .with_extra(self.extra)
    }
}

/// Snapshot and consensus context shared by every step of one build attempt.
///
/// A session is intentionally not constructible by callers. It can only be
/// obtained from `SpendCoordinator::begin`, which validates the
/// distribution once and keeps target height, ring size, maturity floor and
/// snapshot identity from drifting apart.
#[must_use = "a spend session should be used to build a transaction or deliberately discarded"]
pub struct SpendSession {
    pub(super) snapshot: ValidatedDecoySnapshot,
    context: SpendContext,
}

impl SpendSession {
    pub(super) fn new(snapshot: ValidatedDecoySnapshot, context: SpendContext) -> Self {
        debug_assert_eq!(context.target_height(), snapshot.spend_height());
        Self { snapshot, context }
    }

    /// Consensus parameters bound to this snapshot.
    pub fn context(&self) -> SpendContext {
        self.context
    }

    /// Canonical identity of the node snapshot used for decoy selection.
    pub fn snapshot_id(&self) -> SnapshotId {
        self.snapshot.snapshot_id()
    }

    /// Height at which the transaction is intended to become valid.
    pub fn target_height(&self) -> u64 {
        self.context.target_height()
    }
}

/// One wallet output and the exact key image generated for it in the signed
/// transaction. Bindings are created only while sealing a [`BuiltSpend`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct SpendInputBinding {
    pub(super) output: (Hash, u8),
    pub(super) key_image: KeyImage,
}

/// A signed transaction sealed with every value required for safe submission.
///
/// The encoded payload is produced before wallet reservations exist. Input
/// bindings preserve the selected output order and are revalidated against the
/// current wallet immediately before reservation, closing the build/submit
/// race without rediscovering inputs from the transaction alone.
#[must_use = "a built spend should be submitted or deliberately discarded"]
pub struct BuiltSpend {
    pub(super) transaction: Transaction,
    pub(super) encoded_transaction: String,
    pub(super) tx_hash: Hash,
    pub(super) snapshot_id: SnapshotId,
    pub(super) target_height: u64,
    pub(super) input_bindings: Vec<SpendInputBinding>,
}

impl BuiltSpend {
    pub(super) fn try_new(
        transaction: Transaction,
        snapshot_id: SnapshotId,
        target_height: u64,
        selected_outputs: Vec<(Hash, u8)>,
    ) -> Result<Self> {
        let expected_target_height = snapshot_id.height().checked_add(1).ok_or_else(|| {
            Error::InvalidState("spend snapshot cannot advance to its target height".into())
        })?;
        if target_height != expected_target_height {
            return Err(Error::InvalidState(format!(
                "built spend target height {target_height} does not match \
                 snapshot-derived height {expected_target_height}"
            )));
        }

        let input_bindings = bind_transaction_inputs(selected_outputs, transaction.key_images())?;
        let encoded_transaction = NodeRpcClient::encode_transaction(&transaction)?;
        let tx_hash = transaction.hash();

        Ok(Self {
            transaction,
            encoded_transaction,
            tx_hash,
            snapshot_id,
            target_height,
            input_bindings,
        })
    }

    /// Borrow the signed transaction for display or inspection.
    pub fn transaction(&self) -> &Transaction {
        &self.transaction
    }

    /// Canonical hash of the signed transaction that will be submitted.
    pub fn tx_hash(&self) -> Hash {
        self.tx_hash
    }

    /// Snapshot identity used to sample and resolve this transaction's rings.
    pub fn snapshot_id(&self) -> SnapshotId {
        self.snapshot_id
    }

    /// Height used when selecting and validating its inputs.
    pub fn target_height(&self) -> u64 {
        self.target_height
    }

    /// Canonical serialized transaction size in bytes.
    pub fn serialized_size(&self) -> usize {
        self.encoded_transaction.len() / 2
    }

    /// Number of wallet inputs bound into this transaction.
    pub fn input_count(&self) -> usize {
        self.input_bindings.len()
    }
}

fn bind_transaction_inputs(
    selected_outputs: Vec<(Hash, u8)>,
    key_images: Vec<KeyImage>,
) -> Result<Vec<SpendInputBinding>> {
    if selected_outputs.is_empty() {
        return Err(Error::InvalidState(
            "built spend contains no wallet inputs".into(),
        ));
    }
    if selected_outputs.len() != key_images.len() {
        return Err(Error::InvalidState(format!(
            "built spend has {} selected wallet outputs but {} transaction inputs",
            selected_outputs.len(),
            key_images.len()
        )));
    }

    let mut seen_outputs = HashSet::with_capacity(selected_outputs.len());
    let mut seen_key_images = HashSet::with_capacity(key_images.len());
    let mut bindings = Vec::with_capacity(selected_outputs.len());

    for (output, key_image) in selected_outputs.into_iter().zip(key_images) {
        if !seen_outputs.insert(output) {
            return Err(Error::InvalidState(format!(
                "built spend selects wallet output {}:{} more than once",
                hex::encode(output.0.as_bytes()),
                output.1
            )));
        }
        if !seen_key_images.insert(key_image) {
            return Err(Error::InvalidState(format!(
                "built spend contains duplicate key image {}",
                hex::encode(key_image.as_bytes())
            )));
        }
        bindings.push(SpendInputBinding { output, key_image });
    }

    Ok(bindings)
}

/// Final submission state after the coordinator has applied wallet-side
/// reservation and persistence rules.
#[must_use = "submission outcomes must be handled so reservation state remains visible"]
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SpendSubmission {
    /// The node accepted the transaction into its mempool. This is not chain
    /// confirmation, so every input remains reserved.
    MempoolAccepted {
        tx_hash: Hash,
        /// Number of input reservations retained until chain confirmation.
        retained_reservations: usize,
        /// Height at which the reservation may be released if the transaction
        /// never confirms.
        reservation_expires_at: u64,
    },
    Rejected {
        tx_hash: Hash,
        reason: String,
        released_reservations: usize,
        /// A failed save can leave the old durable reservation in place until
        /// it expires. This is inconvenient but safe and must be surfaced.
        reservation_release_save_error: Option<String>,
    },
    /// The node may have received the transaction, but the wallet could not
    /// determine the outcome. Inputs remain reserved for the same reason as a
    /// mempool acceptance.
    Unknown {
        tx_hash: Hash,
        reason: String,
        retained_reservations: usize,
        reservation_expires_at: u64,
    },
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
    fn input_bindings_preserve_selected_order() {
        let first = (Hash::from_bytes([1; 32]), 3);
        let second = (Hash::from_bytes([2; 32]), 4);
        let first_image = KeyImage::from_bytes([11; 32]);
        let second_image = KeyImage::from_bytes([12; 32]);

        let bindings = bind_transaction_inputs(
            vec![first, second],
            vec![first_image, second_image],
        )
        .unwrap();

        assert_eq!(bindings[0].output, first);
        assert_eq!(bindings[0].key_image, first_image);
        assert_eq!(bindings[1].output, second);
        assert_eq!(bindings[1].key_image, second_image);
    }

    #[test]
    fn input_bindings_reject_count_mismatch() {
        let error = bind_transaction_inputs(
            vec![(Hash::from_bytes([1; 32]), 0)],
            Vec::new(),
        )
        .unwrap_err();
        assert!(error.to_string().contains("selected wallet outputs"));
    }

    #[test]
    fn input_bindings_reject_duplicate_outputs_and_key_images() {
        let output = (Hash::from_bytes([1; 32]), 0);
        let image = KeyImage::from_bytes([9; 32]);

        let duplicate_output =
            bind_transaction_inputs(vec![output, output], vec![image, KeyImage::from_bytes([10; 32])])
                .unwrap_err();
        assert!(duplicate_output.to_string().contains("more than once"));

        let duplicate_image = bind_transaction_inputs(
            vec![output, (Hash::from_bytes([2; 32]), 1)],
            vec![image, image],
        )
        .unwrap_err();
        assert!(duplicate_image.to_string().contains("duplicate key image"));
    }

    #[test]
    fn unknown_submission_is_not_a_rejection() {
        let hash = Hash::from_bytes([7; 32]);
        assert_ne!(
            SpendSubmission::Unknown {
                tx_hash: hash,
                reason: "timeout".into(),
                retained_reservations: 1,
                reservation_expires_at: 310,
            },
            SpendSubmission::Rejected {
                tx_hash: hash,
                reason: "policy".into(),
                released_reservations: 1,
                reservation_release_save_error: None,
            }
        );
    }
}
