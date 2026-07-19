//! Transaction types for CoinCync 1.0 (single-asset — asset layer stripped).

use crate::primitives::{hash_concat, Amount, Hash, KeyImage, PublicKey};
use borsh::{BorshDeserialize, BorshSerialize};
use serde::{Deserialize, Serialize};

#[derive(
    Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, BorshSerialize, BorshDeserialize,
)]
pub enum TxType {
    Coinbase,
    Transfer,
    Churn,
}

/// Ring member for ring signatures.
#[derive(Clone, Debug, Serialize, Deserialize, BorshSerialize, BorshDeserialize)]
pub struct RingMemberRef {
    pub public_key: PublicKey,
    pub commitment: [u8; 32],
}

#[derive(Clone, Debug, Serialize, Deserialize, BorshSerialize, BorshDeserialize)]
pub struct TxInput {
    pub key_image: KeyImage,
    pub ring_members: Vec<RingMemberRef>,
    pub signature: crate::crypto::ClsagSignature,
    /// Pseudo-output commitment for balance verification.
    /// Used in balance equation: sum(pseudo_outputs) = sum(outputs) + fee_commitment.
    pub pseudo_output_commitment: [u8; 32],
}

#[derive(Clone, Debug, Serialize, Deserialize, BorshSerialize, BorshDeserialize)]
pub struct TxOutput {
    pub stealth_address: PublicKey,
    pub tx_public_key: PublicKey,
    pub commitment: [u8; 32],
    pub encrypted_amount: Vec<u8>,
    pub view_tag: u8,
    /// Optional time lock: output cannot be spent until this block height.
    pub lock_height: Option<u64>,
    /// ECDH-encrypted memo (max 256 + 28 overhead = 284 bytes).
    pub encrypted_memo: Vec<u8>,
}

#[derive(Clone, Debug, Serialize, Deserialize, BorshSerialize, BorshDeserialize)]
pub struct Transaction {
    pub version: u8,
    pub tx_type: TxType,
    pub inputs: Vec<TxInput>,
    pub outputs: Vec<TxOutput>,
    pub fee: Amount,
    pub range_proof: Vec<u8>,
    pub extra: Vec<u8>,
}

impl Transaction {
    /// Compute transaction hash. If serialization fails (shouldn't happen with valid tx),
    /// we produce a unique hash from available fields to prevent hash collisions.
    pub fn hash(&self) -> Hash {
        match borsh::to_vec(self) {
            Ok(data) => hash_concat(&[&data]),
            Err(_) => {
                // Fallback: create deterministic hash from key fields
                // This should never happen with a valid transaction
                let mut fallback_data = Vec::with_capacity(64);
                fallback_data.extend_from_slice(&[self.version, self.tx_type as u8]);
                fallback_data.extend_from_slice(&(self.inputs.len() as u32).to_le_bytes());
                fallback_data.extend_from_slice(&(self.outputs.len() as u32).to_le_bytes());
                fallback_data.extend_from_slice(&self.fee.as_atomic().to_le_bytes());
                for input in &self.inputs {
                    fallback_data.extend_from_slice(input.key_image.as_bytes());
                }
                hash_concat(&[&fallback_data])
            }
        }
    }

    /// Get transaction size in bytes. Returns minimum valid size on serialization failure.
    pub fn size(&self) -> usize {
        match borsh::to_vec(self) {
            Ok(v) => v.len(),
            Err(_) => {
                // Return minimum transaction size to ensure fee checks aren't bypassed
                crate::constants::MIN_TX_SIZE
            }
        }
    }

    pub fn is_coinbase(&self) -> bool {
        self.tx_type == TxType::Coinbase
    }
    pub fn input_count(&self) -> usize {
        self.inputs.len()
    }
    pub fn output_count(&self) -> usize {
        self.outputs.len()
    }

    pub fn key_images(&self) -> Vec<KeyImage> {
        self.inputs.iter().map(|i| i.key_image).collect()
    }

    /// Compute the signing hash — the preimage binding every field of the
    /// transaction *except* the ring signatures themselves. Used as the CLSAG
    /// message, so any malleability here means a signature that validates on
    /// a different transaction.
    ///
    /// The preimage is prefixed with the domain-separation tag
    /// [`TX_SIGN_DOMAIN_TAG`] so this hash can never collide with any other
    /// hash in the protocol.
    ///
    /// ## Field coverage
    ///
    /// Every field of `Transaction`, `TxInput` (except `signature`) and
    /// `TxOutput` is included. Variable-length fields are length-prefixed to
    /// prevent prefix-collision / reshuffle attacks.
    ///
    /// Callers building a transaction before the CLSAG signatures exist must
    /// use [`Transaction::compute_signing_hash`] with the same arguments to
    /// guarantee byte-identical preimage.
    pub fn signing_hash(&self) -> Hash {
        Self::compute_signing_hash(
            self.version,
            self.tx_type,
            self.fee,
            self.inputs.iter().map(SigningInputView::from_txinput),
            &self.outputs,
            &self.range_proof,
            &self.extra,
        )
    }

    /// Canonical signing-hash preimage, usable before signatures exist.
    ///
    /// This is the single source of truth for the CLSAG signing message.
    /// Both [`Transaction::signing_hash`] (verifier path) and
    /// `TransactionBuilder::build_with_proofs` (signer path) funnel through
    /// here so the preimage bytes are identical.
    pub fn compute_signing_hash<'a, I>(
        version: u8,
        tx_type: TxType,
        fee: Amount,
        inputs: I,
        outputs: &[TxOutput],
        range_proof: &[u8],
        extra: &[u8],
    ) -> Hash
    where
        I: IntoIterator<Item = SigningInputView<'a>>,
    {
        let mut data = Vec::with_capacity(TX_SIGN_DOMAIN_TAG.len() + 256);
        // Domain separator — must be first.
        data.extend_from_slice(TX_SIGN_DOMAIN_TAG);
        data.push(version);
        data.push(tx_type as u8);
        data.extend_from_slice(&fee.as_atomic().to_le_bytes());

        // Collect inputs into a Vec so we can length-prefix (IntoIterator is
        // single-pass and the count would otherwise be unknown up front).
        let inputs: Vec<SigningInputView<'a>> = inputs.into_iter().collect();
        data.extend_from_slice(&(inputs.len() as u32).to_le_bytes());
        for input in &inputs {
            data.extend_from_slice(input.key_image.as_bytes());
            data.extend_from_slice(input.pseudo_output_commitment);
            data.extend_from_slice(&(input.ring_members.len() as u32).to_le_bytes());
            for member in input.ring_members {
                data.extend_from_slice(member.public_key.as_bytes());
                data.extend_from_slice(&member.commitment);
            }
        }

        data.extend_from_slice(&(outputs.len() as u32).to_le_bytes());
        for output in outputs {
            data.extend_from_slice(output.stealth_address.as_bytes());
            data.extend_from_slice(output.tx_public_key.as_bytes());
            data.extend_from_slice(&output.commitment);
            data.extend_from_slice(&(output.encrypted_amount.len() as u32).to_le_bytes());
            data.extend_from_slice(&output.encrypted_amount);
            data.push(output.view_tag);
            // Lock height: encode Some/None explicitly so Some(0) and None differ.
            match output.lock_height {
                Some(h) => {
                    data.push(1);
                    data.extend_from_slice(&h.to_le_bytes());
                }
                None => {
                    data.push(0);
                }
            }
            data.extend_from_slice(&(output.encrypted_memo.len() as u32).to_le_bytes());
            data.extend_from_slice(&output.encrypted_memo);
        }

        data.extend_from_slice(&(range_proof.len() as u32).to_le_bytes());
        data.extend_from_slice(range_proof);

        data.extend_from_slice(&(extra.len() as u32).to_le_bytes());
        data.extend_from_slice(extra);

        hash_concat(&[&data])
    }
}

/// View of the input fields that contribute to the signing hash preimage.
/// Used by [`Transaction::compute_signing_hash`] so the builder can compute
/// the signing hash before any `ClsagSignature` exists.
pub struct SigningInputView<'a> {
    pub key_image: &'a KeyImage,
    pub pseudo_output_commitment: &'a [u8; 32],
    pub ring_members: &'a [RingMemberRef],
}

impl<'a> SigningInputView<'a> {
    /// Build a view from a fully-constructed `TxInput` (verifier path).
    pub fn from_txinput(input: &'a TxInput) -> Self {
        Self {
            key_image: &input.key_image,
            pseudo_output_commitment: &input.pseudo_output_commitment,
            ring_members: &input.ring_members,
        }
    }

    /// Build a view from raw parts (signer path — signatures don't exist yet).
    pub fn from_parts(
        key_image: &'a KeyImage,
        pseudo_output_commitment: &'a [u8; 32],
        ring_members: &'a [RingMemberRef],
    ) -> Self {
        Self {
            key_image,
            pseudo_output_commitment,
            ring_members,
        }
    }
}

/// Domain-separation tag for the transaction signing hash preimage. Must be
/// prefixed to any bytes fed into CLSAG as the message. Never reuse this tag
/// for any other preimage in the protocol.
pub(crate) const TX_SIGN_DOMAIN_TAG: &[u8] = b"coincync/tx-sign/v1";

#[cfg(test)]
mod tests {
    use super::*;
    use crate::primitives::Amount;

    fn make_minimal_tx() -> Transaction {
        Transaction {
            version: 1,
            tx_type: TxType::Coinbase,
            inputs: vec![],
            outputs: vec![TxOutput {
                stealth_address: PublicKey::from_bytes([1u8; 32]),
                tx_public_key: PublicKey::from_bytes([2u8; 32]),
                commitment: [3u8; 32],
                encrypted_amount: vec![0u8; 8],
                view_tag: 0,
                lock_height: None,
                encrypted_memo: vec![],
            }],
            fee: Amount::ZERO,
            range_proof: vec![],
            extra: vec![],
        }
    }

    #[test]
    fn test_transaction_hash_determinism() {
        let tx = make_minimal_tx();
        let h1 = tx.hash();
        let h2 = tx.hash();
        assert_eq!(h1, h2, "same transaction must produce the same hash");
    }

    #[test]
    fn test_coinbase_detection() {
        let tx = make_minimal_tx();
        assert!(tx.is_coinbase());
    }

    #[test]
    fn test_tx_type_variants() {
        assert_ne!(TxType::Coinbase, TxType::Transfer);
        assert_ne!(TxType::Transfer, TxType::Churn);
    }

    #[test]
    fn test_version_bytes_affect_signing_hash() {
        // The version byte is the first byte of the preimage, so different
        // versions must produce distinct signing hashes for otherwise-identical
        // transactions.
        let mut tx1 = make_minimal_tx();
        tx1.version = 1;
        let mut tx2 = make_minimal_tx();
        tx2.version = 2;
        assert_ne!(
            tx1.signing_hash(),
            tx2.signing_hash(),
            "version byte must be covered by signing_hash"
        );
    }
}
