//! # Privacy Policy — Mandatory Privacy Enforcement
//!
//! Pirate Chain's core insight applied to CoinCync: **there is no
//! transparent transaction type**. Every non-coinbase transaction must
//! hide the amount, the recipient, and the sender. Enforcement is at
//! the consensus level — a miner who includes a transparent or naked
//! transaction produces an invalid block.
//!
//! This module implements [Constitution Article III — Mandatory
//! Privacy](../../../CONSTITUTION.md#article-iii--mandatory-privacy).
//! The three compile-time flags it reads (`MANDATORY_CONFIDENTIAL`,
//! `MANDATORY_STEALTH`, `MIN_RING_SIZE`) are all constitutional guards
//! declared in `src/constants.rs`, protected by `critical_files.lock`,
//! and verified by `build.rs` on every build.
//!
//! ## The three rules (all Article III)
//!
//! 1. **Hidden amounts** (`MANDATORY_CONFIDENTIAL`): every output must
//!    carry a non-zero Pedersen commitment. In the CoinCync transaction
//!    schema every `TxOutput` already has a 32-byte `commitment` field,
//!    so the rule degenerates to a check that the commitment is not the
//!    identity point (all zeros).
//!
//! 2. **Hidden recipients** (`MANDATORY_STEALTH`): every output must
//!    use a stealth address or a Spark address — never a raw public
//!    key. In the current schema every `TxOutput` has a
//!    `stealth_address: PublicKey`, so this rule is mostly enforced by
//!    the type system. Once Spark outputs land in Phase 2, this module
//!    will additionally accept Spark-output types.
//!
//! 3. **Hidden senders** (`UnshieldedForbidden`): every non-coinbase
//!    transaction must have at least one privacy-preserving input —
//!    ring-signature inputs (current), shielded-pool actions (Phase 2
//!    Halo2), or Lelantus Spark spend proofs (Phase 2). A tx with zero
//!    inputs of any kind is forbidden.
//!
//! ## Where this fits in the validation pipeline
//!
//! Stage 6 of `consensus::validation::validate_block`. Called after
//! structural checks (Stages 1–5) and before expensive cryptographic
//! verification (Stages 8+). Cheap to run, fails fast.

use crate::consensus::Block;
use crate::constants::{MANDATORY_CONFIDENTIAL, MANDATORY_STEALTH};
use crate::error::{Error, Result};
use crate::transaction::{Transaction, TxType};

/// Enforce mandatory privacy on every transaction in a block.
///
/// Returns `Ok(())` if every non-coinbase transaction satisfies the
/// three rules above, otherwise returns the specific violation as an
/// `Error::TransparentOutputForbidden`, `Error::RawPubkeyForbidden`,
/// or `Error::UnshieldedForbidden`.
pub fn enforce_privacy_policy(block: &Block) -> Result<()> {
    for tx in &block.transactions {
        if tx.tx_type == TxType::Coinbase {
            continue;
        }
        check_tx_privacy(tx)?;
    }
    Ok(())
}

/// Check a single non-coinbase transaction against the three privacy rules.
pub fn check_tx_privacy(tx: &Transaction) -> Result<()> {
    // ── Rule 1: Hidden amounts (Article III) ───────────────────
    if MANDATORY_CONFIDENTIAL {
        for output in &tx.outputs {
            // M-6 FIX: Use Ristretto decompression to detect the identity point
            // instead of a weak all-zeros byte check. The identity element [0;32]
            // is a valid Ristretto encoding but several other byte patterns also
            // decompress to identity via the Ristretto map. The old check only
            // caught the canonical encoding.
            use curve25519_dalek::ristretto::CompressedRistretto;
            let point = CompressedRistretto(output.commitment).decompress();
            match point {
                None => {
                    // Not a valid Ristretto point at all — reject as transparent.
                    return Err(Error::TransparentOutputForbidden);
                }
                Some(p) => {
                    if p == curve25519_dalek::ristretto::RistrettoPoint::default() {
                        // Identity point — no amount is actually committed.
                        return Err(Error::TransparentOutputForbidden);
                    }
                }
            }
        }
    }

    // ── Rule 2: Hidden recipients (Article III) ────────────────
    if MANDATORY_STEALTH {
        for output in &tx.outputs {
            // M-3 FIX: The old all-zeros byte check only caught one specific
            // invalid encoding. Validate the full Ristretto curve point so that
            // any non-zero but invalid byte sequence (malformed encoding, low-order
            // subgroup point that happens to be non-zero) is also rejected.
            //
            // This mirrors Rule 1 (commitment validation) which already uses
            // CompressedRistretto decompression for the same reason.
            use curve25519_dalek::ristretto::CompressedRistretto;
            let stealth_arr = *output.stealth_address.as_bytes(); // &[u8;32] → [u8;32]
            match CompressedRistretto(stealth_arr).decompress() {
                None => {
                    // Byte sequence does not decode to any Ristretto point.
                    return Err(Error::RawPubkeyForbidden);
                }
                Some(p) => {
                    if p == curve25519_dalek::ristretto::RistrettoPoint::default() {
                        // Identity element — cannot be a valid stealth address.
                        return Err(Error::RawPubkeyForbidden);
                    }
                }
            }
        }
    }

    // ── Rule 3: Hidden senders (Article III) ───────────────────
    //
    // At least one privacy-preserving input must be present. For the
    // current 1.0 transaction schema that's a ring-signature input
    // (`tx.inputs` is non-empty). Phase 2 adds shielded-pool actions
    // (Halo2) and Lelantus Spark spend proofs as additional accepted
    // input kinds — add them here once the Transaction struct carries
    // those fields.
    let has_ring_inputs = !tx.inputs.is_empty();
    // TODO (Phase 2): accept shielded or Spark inputs here too.
    if !has_ring_inputs {
        return Err(Error::UnshieldedForbidden);
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::primitives::{Amount, PublicKey};
    use crate::transaction::{TxInput, TxOutput};

    /// Generate a valid non-identity Ristretto point for test commitments.
    fn valid_commitment() -> [u8; 32] {
        use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
        use curve25519_dalek::scalar::Scalar;
        let s = Scalar::from(42u64);
        (s * RISTRETTO_BASEPOINT_POINT).compress().to_bytes()
    }

    fn mk_output(commitment: [u8; 32], stealth: [u8; 32]) -> TxOutput {
        TxOutput {
            stealth_address: PublicKey::from_bytes(stealth),
            tx_public_key: PublicKey::from_bytes([1u8; 32]),
            commitment,
            encrypted_amount: vec![],
            view_tag: 0,
            lock_height: None,
            encrypted_memo: vec![],
        }
    }

    fn mk_tx(inputs: Vec<TxInput>, outputs: Vec<TxOutput>) -> Transaction {
        Transaction {
            version: 1,
            tx_type: TxType::Transfer,
            inputs,
            outputs,
            fee: Amount::ZERO,
            range_proof: vec![],
            extra: vec![],
        }
    }

    #[test]
    fn zero_commitment_rejected() {
        let tx = mk_tx(
            vec![/* inputs intentionally empty for this test */],
            vec![mk_output([0u8; 32], [2u8; 32])],
        );
        // Rule 1 should fire before Rule 3, even though inputs are empty.
        assert!(matches!(
            check_tx_privacy(&tx),
            Err(Error::TransparentOutputForbidden)
        ));
    }

    #[test]
    fn zero_stealth_rejected() {
        let c = valid_commitment();
        let tx = mk_tx(vec![], vec![mk_output(c, [0u8; 32])]);
        assert!(matches!(
            check_tx_privacy(&tx),
            Err(Error::RawPubkeyForbidden)
        ));
    }

    #[test]
    fn empty_inputs_rejected() {
        let c = valid_commitment();
        let s = valid_commitment(); // valid stealth so rules 1+2 pass
        let tx = mk_tx(vec![], vec![mk_output(c, s)]);
        assert!(matches!(
            check_tx_privacy(&tx),
            Err(Error::UnshieldedForbidden)
        ));
    }
}
