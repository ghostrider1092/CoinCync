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
    use crate::primitives::{Amount, PublicKey};
    use crate::transaction::{Transaction, TxOutput, TxType};

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
}
