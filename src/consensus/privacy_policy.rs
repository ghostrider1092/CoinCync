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
//!
//! ## Audit map
//! Each `§` is a code section below; it states the INVARIANT it guarantees, the
//! THREAT it defends, and the TESTS that prove it. (Renders in `cargo doc`.)
//!
//! - **§1 `enforce_privacy_policy` (block sweep / coinbase skip)** —
//!   INVARIANT: every `TxType::Coinbase` tx is skipped; every other tx is passed
//!   through `check_tx_privacy`, and the first violation short-circuits the block.
//!   THREAT: a transparent/naked transfer smuggled into an otherwise-valid block,
//!   or the coinbase (legitimately transparent) being wrongly rejected.
//!   TESTS: `enforce_skips_coinbase_and_accepts_valid_block`,
//!   `enforce_all_valid_block_ok`, `enforce_rejects_violating_transfer`.
//! - **§2 Rule 1 — Hidden amounts (`MANDATORY_CONFIDENTIAL`)** —
//!   INVARIANT: every output commitment must decompress to a non-identity
//!   Ristretto point; identity OR non-decompressable ⇒ `TransparentOutputForbidden`.
//!   THREAT: M-6 non-canonical-identity commitment — a non-`[0;32]` byte pattern
//!   that maps to the identity point (or is not a curve point at all) would slip
//!   past the old all-zeros byte check and commit to no amount.
//!   TESTS: `zero_commitment_rejected`, `non_decompressable_commitment_rejected`,
//!   `rule1_fires_before_rule3_when_both_violated`, `valid_tx_is_accepted`.
//! - **§3 Rule 2 — Hidden recipients (`MANDATORY_STEALTH`)** —
//!   INVARIANT: every stealth address must decompress to a non-identity Ristretto
//!   point; identity OR non-decompressable ⇒ `RawPubkeyForbidden`.
//!   THREAT: M-3 — a non-zero but invalid/low-order stealth encoding (raw pubkey)
//!   would evade the old all-zeros check and expose the recipient.
//!   TESTS: `zero_stealth_rejected`, `non_decompressable_stealth_rejected`,
//!   `valid_tx_is_accepted`.
//! - **§4 Rule 3 — Hidden senders (`UnshieldedForbidden`)** —
//!   INVARIANT: a non-coinbase tx must carry ≥1 privacy-preserving input
//!   (`tx.inputs` non-empty); zero inputs ⇒ `UnshieldedForbidden`.
//!   THREAT: an input-less "mint" tx with no ring signature de-anonymizing the
//!   sender (or forging value). Rule 1 is evaluated before Rule 3 by construction.
//!   TESTS: `empty_inputs_rejected`, `valid_tx_is_accepted`.

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
        // Shielded (Spark) spends provide sender/amount/recipient privacy via
        // their own proof model, not the transparent CLSAG-ring rules below
        // (whose §4 would reject a shielded tx for having no ring inputs). Their
        // privacy is enforced by the shielded verifier in
        // `validation::check_shielded_tx`. This is the "Phase 2" branch the §4
        // TODO anticipated. (Shielded is itself fail-closed until activation.)
        if tx.tx_type == TxType::Shielded {
            continue;
        }
        check_tx_privacy(tx)?;
    }
    Ok(())
}

/// Check a single non-coinbase transaction against the three privacy rules.
pub fn check_tx_privacy(tx: &Transaction) -> Result<()> {
    // ── §2 Rule 1: Hidden amounts (Article III) ───────────────────
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

    // ── §3 Rule 2: Hidden recipients (Article III) ────────────────
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

    // ── §4 Rule 3: Hidden senders (Article III) ───────────────────
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

    // ── Additional helpers ──────────────────────────────────────────
    // NOTE: `Block` is already in scope via `use super::*` (the module imports
    // `crate::consensus::Block`); only pull in the names not already visible.
    use crate::consensus::BlockHeader;
    use crate::primitives::{Hash, KeyImage};

    /// A well-formed ring-signature input (satisfies Rule 3). The key image is
    /// the only field the privacy policy cares about being present (non-empty
    /// `tx.inputs`); the rest is structurally valid filler.
    fn mk_input(ki: u8) -> TxInput {
        TxInput {
            key_image: KeyImage::from_bytes([ki; 32]),
            ring_members: vec![],
            signature: crate::crypto::ClsagSignature {
                key_image: crate::crypto::KeyImage::from_bytes(
                    crate::crypto::PublicPoint::identity().to_bytes(),
                )
                .expect("identity is a valid curve point"),
                commitment_image: crate::crypto::PublicPoint::identity(),
                c1: [0u8; 32],
                responses: vec![],
            },
            pseudo_output_commitment: [0u8; 32],
        }
    }

    fn mk_header() -> BlockHeader {
        BlockHeader {
            network_magic: [0, 0, 0, 0],
            version: 1,
            height: 1,
            timestamp: 1,
            prev_hash: Hash::zero(),
            tx_root: Hash::zero(),
            anchor: Hash::zero(),
            algorithm: 0,
            nonce: 0,
            target: Hash::from_bytes([0xFF; 32]),
            miner_pubkey: PublicKey::from_bytes([0u8; 32]),
            supply_commitment: [0u8; 32],
            checkpoint_vote: None,
            spark_set_root: [0u8; 32],
            mw_kernel_root: [0u8; 32],
        }
    }

    fn coinbase_tx() -> Transaction {
        Transaction {
            version: 1,
            tx_type: TxType::Coinbase,
            inputs: vec![],
            outputs: vec![],
            fee: Amount::ZERO,
            range_proof: vec![],
            extra: vec![],
        }
    }

    // ── check_tx_privacy happy + error branches ─────────────────────

    #[test]
    fn valid_tx_is_accepted() {
        // Non-identity commitment + non-identity stealth + a ring input.
        let tx = mk_tx(
            vec![mk_input(1)],
            vec![mk_output(valid_commitment(), valid_commitment())],
        );
        assert!(check_tx_privacy(&tx).is_ok());
    }

    #[test]
    fn non_decompressable_commitment_rejected() {
        // M-6: the fix upgraded the weak all-zeros byte check to full Ristretto
        // decompression. A NON-ZERO byte pattern that is not a valid Ristretto
        // encoding (here [0xFF; 32], whose high bit makes `s` non-canonical) is
        // now rejected — the old all-zeros-only check would have let it through.
        let tx = mk_tx(vec![mk_input(1)], vec![mk_output([0xFF; 32], valid_commitment())]);
        assert!(matches!(
            check_tx_privacy(&tx),
            Err(Error::TransparentOutputForbidden)
        ));
    }

    #[test]
    fn non_decompressable_stealth_rejected() {
        // M-3 counterpart of the commitment check: a non-zero, non-decodable
        // stealth address is rejected as a raw/invalid pubkey.
        let tx = mk_tx(vec![mk_input(1)], vec![mk_output(valid_commitment(), [0xFF; 32])]);
        assert!(matches!(
            check_tx_privacy(&tx),
            Err(Error::RawPubkeyForbidden)
        ));
    }

    #[test]
    fn rule1_fires_before_rule3_when_both_violated() {
        // Commitment is identity (Rule 1 violation) AND inputs are empty (Rule 3
        // violation). Rule 1 is evaluated first, so the reported error must be
        // TransparentOutputForbidden, not UnshieldedForbidden.
        let tx = mk_tx(vec![], vec![mk_output([0u8; 32], valid_commitment())]);
        assert!(matches!(
            check_tx_privacy(&tx),
            Err(Error::TransparentOutputForbidden)
        ));
    }

    // ── enforce_privacy_policy ───────────────────────────────────────

    #[test]
    fn enforce_skips_coinbase_and_accepts_valid_block() {
        // Coinbase is not subject to the privacy rules; the single transfer is
        // fully valid → whole block Ok.
        let transfer = mk_tx(
            vec![mk_input(1)],
            vec![mk_output(valid_commitment(), valid_commitment())],
        );
        let block = Block::new(mk_header(), vec![coinbase_tx(), transfer]);
        assert!(enforce_privacy_policy(&block).is_ok());
    }

    #[test]
    fn enforce_all_valid_block_ok() {
        let t1 = mk_tx(
            vec![mk_input(1)],
            vec![mk_output(valid_commitment(), valid_commitment())],
        );
        let t2 = mk_tx(
            vec![mk_input(2)],
            vec![mk_output(valid_commitment(), valid_commitment())],
        );
        let block = Block::new(mk_header(), vec![coinbase_tx(), t1, t2]);
        assert!(enforce_privacy_policy(&block).is_ok());
    }

    #[test]
    fn enforce_rejects_violating_transfer() {
        // Valid coinbase + one transfer with a transparent (identity) commitment
        // → the block is rejected with the transfer's specific violation.
        let bad_transfer = mk_tx(vec![mk_input(1)], vec![mk_output([0u8; 32], valid_commitment())]);
        let block = Block::new(mk_header(), vec![coinbase_tx(), bad_transfer]);
        assert!(matches!(
            enforce_privacy_policy(&block),
            Err(Error::TransparentOutputForbidden)
        ));
    }
}
