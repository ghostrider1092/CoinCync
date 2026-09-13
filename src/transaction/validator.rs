//! Transaction validation for CoinCync 1.0
//!
//! Comprehensive transaction validation including structural checks,
//! ring signature verification, and balance verification.

use super::Transaction;
use crate::constants::*;
use crate::error::{Error, Result};
use std::collections::HashSet;

/// Validate transaction structure and basic constraints
///
/// This performs fast structural validation that doesn't require
/// chain state (UTXO set, key image database, etc.)
pub fn validate_transaction(tx: &Transaction, height: u64) -> Result<()> {
    // Check version
    if tx.version != 1 {
        return Err(Error::InvalidTxVersion(tx.version));
    }

    // Check size
    let size = tx.size();
    if size > MAX_TX_SIZE {
        return Err(Error::TransactionTooLarge {
            size,
            max: MAX_TX_SIZE,
        });
    }
    if size < MIN_TX_SIZE && !tx.is_coinbase() {
        return Err(Error::TransactionTooSmall {
            size,
            min: MIN_TX_SIZE,
        });
    }

    // Check input/output counts
    if tx.inputs.len() > MAX_TX_INPUTS {
        return Err(Error::InvalidInputCount {
            count: tx.inputs.len(),
            max: MAX_TX_INPUTS,
        });
    }
    if tx.outputs.len() > MAX_TX_OUTPUTS {
        return Err(Error::InvalidOutputCount {
            count: tx.outputs.len(),
            max: MAX_TX_OUTPUTS,
        });
    }
    if tx.outputs.is_empty() {
        return Err(Error::InvalidOutputCount {
            count: 0,
            max: MAX_TX_OUTPUTS,
        });
    }

    // Validate lock_height is reasonable (not absurdly far in the future)
    for output in &tx.outputs {
        if let Some(lh) = output.lock_height {
            // ~2 years at 120-second blocks
            if lh > height + 525_960 {
                return Err(Error::InvalidTransaction(format!(
                    "lock_height {} is too far in the future (current: {})",
                    lh, height
                )));
            }
        }
    }

    // SECURITY: Check for duplicate key images within the same transaction
    // This prevents spending the same output twice in one tx
    let mut seen_key_images = HashSet::new();
    for input in &tx.inputs {
        if !seen_key_images.insert(input.key_image) {
            // SECURITY (M-18): Generic message to avoid revealing which key image
            return Err(Error::DuplicateKeyImage(
                "duplicate key image detected".into(),
            ));
        }
    }

    // Check ring size for each input.
    // On young chains (height < 10,000), the ring can be smaller than the
    // target when there aren't enough unique outputs yet.  We infer the
    // effective ring size from the actual ring_members presented — the full
    // consensus validator (`consensus::validation::validate_transaction`)
    // performs the definitive check using the UTXO set's output_count().
    let target_ring_size = ring_size_at_height(height);
    for (i, input) in tx.inputs.iter().enumerate() {
        let actual = input.ring_members.len();
        // On young chains, allow smaller rings (min 2). After height 10k,
        // enforce the full target.
        if height < 10_000 {
            if actual < 2 || actual > target_ring_size {
                return Err(Error::InvalidRingSize {
                    expected: target_ring_size,
                    got: actual,
                });
            }
        } else if actual != target_ring_size {
            return Err(Error::InvalidRingSize {
                expected: target_ring_size,
                got: actual,
            });
        }

        // SECURITY: Verify ring signature matches ring size
        if input.signature.ring_size() != actual {
            return Err(Error::InvalidSignature(format!(
                "ring signature size mismatch in input {}: expected {}, got {}",
                i,
                actual,
                input.signature.ring_size()
            )));
        }

        // SECURITY: Verify key image in signature matches input key image
        // Compare via bytes since ClsagSignature uses curve::KeyImage while TxInput uses primitives::KeyImage
        if input.signature.key_image.to_bytes() != *input.key_image.as_bytes() {
            return Err(Error::InvalidSignature(format!(
                "key image mismatch in input {}",
                i
            )));
        }
    }

    // Check fee
    let min_fee = (size as u64) * MIN_FEE_PER_BYTE;
    if tx.fee.as_atomic() < min_fee && !tx.is_coinbase() {
        return Err(Error::FeeTooLow {
            fee: tx.fee.as_atomic(),
            min: min_fee,
        });
    }

    // SECURITY: Validate range proof size is reasonable
    if tx.range_proof.len() > MAX_TX_SIZE {
        return Err(Error::RangeProofInvalid);
    }

    // SECURITY: Validate extra data size
    if tx.extra.len() > 256 {
        return Err(Error::InvalidMessage("extra data too large".into()));
    }

    // Validate dead man's switch recovery metadata (if present in extra).
    if !tx.extra.is_empty() {
        if let Err(e) = super::recovery::validate_recovery_extra(&tx.extra, tx.outputs.len()) {
            return Err(Error::InvalidTransaction(format!(
                "invalid recovery metadata: {}",
                e
            )));
        }
    }

    Ok(())
}

// NOTE: `validate_transaction_full` was removed (previously dead code).
// Full cryptographic validation (ring sigs, range proofs, balance proof) is
// performed by `consensus::validation::validate_transaction()`.  The old
// function only verified ring signatures and was missing range-proof and
// balance-proof checks, making it a dangerous trap for future callers.

#[cfg(test)]
mod tests {
    use super::*;
    use crate::constants::{
        MAX_TX_INPUTS, MAX_TX_OUTPUTS, MAX_TX_SIZE, MIN_FEE_PER_BYTE, MIN_TX_SIZE,
    };
    use crate::crypto::{ClsagSignature, KeyImage as CurveKeyImage, PublicPoint};
    use crate::error::Error;
    use crate::primitives::{Amount, KeyImage, PublicKey};
    use crate::transaction::{RingMemberRef, Transaction, TxInput, TxOutput, TxType};

    fn make_coinbase_tx() -> Transaction {
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
    fn test_coinbase_passes_structural_validation() {
        let tx = make_coinbase_tx();
        assert!(validate_transaction(&tx, 0).is_ok());
    }

    #[test]
    fn test_invalid_version_rejected() {
        let mut tx = make_coinbase_tx();
        tx.version = 99;
        assert!(validate_transaction(&tx, 0).is_err());
    }

    #[test]
    fn test_empty_outputs_rejected() {
        let mut tx = make_coinbase_tx();
        tx.outputs.clear();
        assert!(validate_transaction(&tx, 0).is_err());
    }

    // ─── shared helpers for input/output-driven cases ───────────────────

    fn make_output() -> TxOutput {
        TxOutput {
            stealth_address: PublicKey::from_bytes([1u8; 32]),
            tx_public_key: PublicKey::from_bytes([2u8; 32]),
            commitment: [3u8; 32],
            encrypted_amount: vec![0u8; 8],
            view_tag: 0,
            lock_height: None,
            encrypted_memo: vec![],
        }
    }

    /// Build a transfer input with explicit control over the ring length, the
    /// number of CLSAG responses, and the two key-image byte strings the
    /// validator cross-checks. `sig_key_image` must be valid ristretto point
    /// bytes; the all-zero encoding is the identity point.
    fn make_transfer_input(
        ring_len: usize,
        resp_len: usize,
        input_key_image: [u8; 32],
        sig_key_image: [u8; 32],
    ) -> TxInput {
        let member = RingMemberRef {
            public_key: PublicKey::from_bytes([9u8; 32]),
            commitment: [0u8; 32],
        };
        TxInput {
            key_image: KeyImage::from_bytes(input_key_image),
            ring_members: vec![member; ring_len],
            signature: ClsagSignature {
                key_image: CurveKeyImage::from_bytes(sig_key_image)
                    .expect("identity is a valid ristretto point"),
                commitment_image: PublicPoint::identity(),
                c1: [0u8; 32],
                responses: vec![[0u8; 32]; resp_len],
            },
            pseudo_output_commitment: [0u8; 32],
        }
    }

    /// A structurally valid single-input transfer whose fee clears the
    /// per-byte minimum. The signature's key image matches the input's, and
    /// ring/response counts agree, so it passes every check when the ring
    /// length is legal for the target height.
    fn make_valid_transfer(ring_len: usize) -> Transaction {
        let ki = [0u8; 32]; // identity bytes shared by input + signature
        let mut tx = Transaction {
            version: 1,
            tx_type: TxType::Transfer,
            inputs: vec![make_transfer_input(ring_len, ring_len, ki, ki)],
            outputs: vec![make_output()],
            fee: Amount::ZERO,
            range_proof: vec![],
            extra: vec![],
        };
        // Amount is a fixed 8 bytes regardless of value, so setting the fee
        // after measuring the size does not change the size.
        let min_fee = tx.size() as u64 * MIN_FEE_PER_BYTE;
        tx.fee = Amount::from_atomic(min_fee + 1);
        tx
    }

    #[test]
    fn test_oversized_transaction_rejected() {
        let mut tx = make_coinbase_tx();
        tx.range_proof = vec![0u8; MAX_TX_SIZE + 1];
        assert!(matches!(
            validate_transaction(&tx, 0),
            Err(Error::TransactionTooLarge { .. })
        ));
    }

    #[test]
    fn test_undersized_non_coinbase_rejected() {
        let tx = Transaction {
            version: 1,
            tx_type: TxType::Transfer,
            inputs: vec![],
            outputs: vec![],
            fee: Amount::ZERO,
            range_proof: vec![],
            extra: vec![],
        };
        assert!(tx.size() < MIN_TX_SIZE);
        assert!(matches!(
            validate_transaction(&tx, 0),
            Err(Error::TransactionTooSmall { .. })
        ));
    }

    #[test]
    fn test_too_many_inputs_rejected() {
        let input = make_transfer_input(2, 2, [0u8; 32], [0u8; 32]);
        let mut tx = make_coinbase_tx();
        tx.tx_type = TxType::Transfer;
        tx.inputs = vec![input; MAX_TX_INPUTS + 1];
        assert!(matches!(
            validate_transaction(&tx, 0),
            Err(Error::InvalidInputCount { .. })
        ));
    }

    #[test]
    fn test_too_many_outputs_rejected() {
        let mut tx = make_coinbase_tx();
        tx.outputs = vec![make_output(); MAX_TX_OUTPUTS + 1];
        assert!(matches!(
            validate_transaction(&tx, 0),
            Err(Error::InvalidOutputCount { .. })
        ));
    }

    #[test]
    fn test_lock_height_far_future_rejected() {
        let mut tx = make_coinbase_tx();
        // one past the accepted horizon of height + 525_960 at height 0
        tx.outputs[0].lock_height = Some(525_961);
        assert!(matches!(
            validate_transaction(&tx, 0),
            Err(Error::InvalidTransaction(_))
        ));
    }

    #[test]
    fn test_lock_height_at_boundary_accepted() {
        let mut tx = make_coinbase_tx();
        // exactly height + 525_960 is accepted
        tx.outputs[0].lock_height = Some(525_960);
        assert!(validate_transaction(&tx, 0).is_ok());
    }

    #[test]
    fn test_duplicate_key_image_within_tx_rejected() {
        let input = make_transfer_input(2, 2, [7u8; 32], [0u8; 32]);
        let mut tx = make_coinbase_tx();
        tx.tx_type = TxType::Transfer;
        tx.inputs = vec![input.clone(), input];
        assert!(matches!(
            validate_transaction(&tx, 0),
            Err(Error::DuplicateKeyImage(_))
        ));
    }

    #[test]
    fn test_young_chain_small_ring_accepted() {
        // height < 10_000 allows a ring smaller than the target (min 2)
        let tx = make_valid_transfer(2);
        assert!(validate_transaction(&tx, 0).is_ok());
    }

    #[test]
    fn test_mature_chain_wrong_ring_size_rejected() {
        // At height >= 10_000 the exact target ring size (16) is required, so a
        // ring of 2 that is fine on a young chain is now rejected.
        let tx = make_valid_transfer(2);
        assert!(matches!(
            validate_transaction(&tx, 10_000),
            Err(Error::InvalidRingSize { .. })
        ));
    }

    #[test]
    fn test_young_chain_ring_too_small_rejected() {
        // a ring of 1 is below the minimum of 2 even on a young chain
        let tx = make_valid_transfer(1);
        assert!(matches!(
            validate_transaction(&tx, 0),
            Err(Error::InvalidRingSize { .. })
        ));
    }

    #[test]
    fn test_ring_signature_size_mismatch_rejected() {
        // ring_members has 2 entries but the CLSAG signature carries 3 responses
        let mut tx = make_valid_transfer(2);
        tx.inputs = vec![make_transfer_input(2, 3, [0u8; 32], [0u8; 32])];
        assert!(matches!(
            validate_transaction(&tx, 0),
            Err(Error::InvalidSignature(_))
        ));
    }

    #[test]
    fn test_signature_key_image_mismatch_rejected() {
        // ring/response counts agree, but the signature's key-image bytes differ
        // from the input's key-image bytes
        let mut tx = make_valid_transfer(2);
        tx.inputs = vec![make_transfer_input(2, 2, [1u8; 32], [0u8; 32])];
        assert!(matches!(
            validate_transaction(&tx, 0),
            Err(Error::InvalidSignature(_))
        ));
    }

    #[test]
    fn test_fee_below_minimum_rejected() {
        let tx = Transaction {
            version: 1,
            tx_type: TxType::Transfer,
            inputs: vec![],
            outputs: vec![make_output()],
            fee: Amount::ZERO,
            range_proof: vec![],
            extra: vec![],
        };
        assert!(matches!(
            validate_transaction(&tx, 0),
            Err(Error::FeeTooLow { .. })
        ));
    }

    #[test]
    fn test_non_recovery_invalid_extra_rejected() {
        // A recovery entry pointing at output index 5 in a 1-output tx is
        // invalid; validate_transaction surfaces it as InvalidTransaction with
        // the "invalid recovery metadata" prefix.
        let mut tx = make_coinbase_tx();
        let mut extra = vec![0xDEu8, 5]; // RECOVERY_TAG, output_index = 5
        extra.extend_from_slice(&[0xABu8; 32]); // recovery_address
        extra.extend_from_slice(&262_800u64.to_le_bytes()); // valid timeout
        tx.extra = extra;
        match validate_transaction(&tx, 0) {
            Err(Error::InvalidTransaction(msg)) => {
                assert!(msg.contains("invalid recovery metadata"), "got: {msg}");
            }
            other => panic!("expected InvalidTransaction, got {other:?}"),
        }
    }
}
