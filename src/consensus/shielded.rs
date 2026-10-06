//! Shielded (Spark) transaction payload + apply path — CIP-Shielded Increment 2.
//!
//! A `TxType::Shielded` transaction carries its shielded data in `tx.extra` as a
//! borsh [`ShieldedPayload`]. [`apply_shielded_payload`] applies a *already-
//! verified* payload to the real accumulator/nullifier store
//! ([`crate::storage::ShieldedStore`], a `bridgetree` Merkle accumulator + a
//! spent-serial-tag set with checkpoint/rewind) — NOT the transparent UTXO set.
//!
//! Split of concerns (mirrors the transparent path):
//!   - STATELESS spend-proof verification lives in
//!     `consensus::validation::check_shielded_tx` (still fail-closed: the current
//!     `lelantus_spark` proof is an unaudited O(n) Schnorr stand-in, and shielded
//!     is gated off via `SHIELDED_TX_ACTIVATION_HEIGHT = u64::MAX`).
//!   - STATEFUL apply (serial-tag double-spend + accumulator append) lives here,
//!     against the store the `Blockchain` owns; reorg-rewind is handled by the
//!     existing `checkpoint_phase2_stores` / `rewind_phase2_stores` plumbing.
//!
//! Nothing here runs in production yet: shielded txs are rejected in validation
//! before apply is ever reached. This is the reviewed, tested apply architecture
//! the real verifier plugs into. See docs/design/cip-shielded-txtype.md.

use crate::error::{Error, Result};
use crate::storage::shielded::{NoteCommitmentEntry, ShieldedStore};
use borsh::{BorshDeserialize, BorshSerialize};

/// Current shielded-payload wire version.
pub const SHIELDED_PAYLOAD_VERSION: u8 = 1;

/// One spent input in a shielded transaction.
///
/// Each input anchors to an anonymity-set bucket (`bucket_index`, the fixed-size
/// coin group of cip-shielded-anonset.md), publishes its `nullifier`
/// (double-spend tag), and carries its spend `proof`. The proof is opaque bytes
/// (a borsh `crypto::groth_kohlweiss::SparkSpendProofV2`) so this non-gated
/// consensus payload does not depend on the gated proof type; the gated stateful
/// verifier (`shielded_pipeline::gk::verify_shielded_spend`) resolves the bucket
/// and decodes + verifies it. Empty proofs today (shielded gated off).
#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct ShieldedInput {
    /// The anonymity-set bucket this input's membership proof anchors to.
    pub bucket_index: u64,
    /// The published double-spend nullifier (bound to `spend_proof`).
    pub nullifier: [u8; 32],
    /// Opaque, borsh-encoded value-bound spend proof
    /// (`crypto::groth_kohlweiss::SparkSpendProofV3`).
    pub spend_proof: Vec<u8>,
    /// Opaque range binding for the spent value commitment
    /// (`crypto::spark_range::ShieldedRangeProof`).
    pub range_proof: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct ShieldedOutput {
    /// The bound coin `C = v·Gv + s·H + r·K` appended to the accumulator.
    pub note_commitment: [u8; 32],
    /// The published value commitment `V = v·Gv + b·K` used by the balance proof.
    pub value_commitment: [u8; 32],
    /// Opaque range binding for `value_commitment`.
    pub range_proof: Vec<u8>,
    /// Opaque mint-binding tying `note_commitment`'s value to `value_commitment`
    /// (`crypto::groth_kohlweiss::MintBindingProof`).
    pub mint_binding: Vec<u8>,
}

/// The consensus payload a `TxType::Shielded` transaction carries in `tx.extra`:
/// the inputs it spends (each with its bucket anchor, nullifier, spend proof, and
/// range binding), the outputs it creates (each a bound coin appended to the
/// accumulator, with its value commitment, range binding, and mint-binding), and
/// the transaction-wide value-balance proof. Double-spend-guarded against the
/// store; the full cryptographic check is `shielded_pipeline::gk::verify_shielded_payload`.
#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct ShieldedPayload {
    pub version: u8,
    pub inputs: Vec<ShieldedInput>,
    pub outputs: Vec<ShieldedOutput>,
    /// Public net value crossing the transparent⇄shielded boundary for this tx
    /// (Sapling `valueBalance`): positive = an unshield (value leaves the pool),
    /// negative = a shield (value enters), 0 = a pure shielded tx. Bound into the
    /// balance proof; the supply-turnstile rule (`ShieldedPoolValue`) keeps the
    /// running pool total `≥ 0`.
    pub value_balance: i64,
    /// Opaque, borsh-encoded `crypto::spark_balance::BalanceProof`.
    pub balance_proof: Vec<u8>,
}

/// The shielded pool's running value total — the supply turnstile's accounting
/// state. Every shielded tx moves `value_balance` across the veil; the pool total
/// is `Σ value_balance` and must never go negative (you cannot unshield more than
/// was ever shielded in — the "no inflation across the veil" invariant). Tracked
/// as `i128` headroom over `i64` deltas so a block's aggregate cannot overflow.
///
/// This is the pure accounting primitive. Committing the total into the header
/// (PoW-bound, reorg-durable) and wiring it into chain state is the remaining
/// consensus integration (touches the hash-locked supply commitment).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ShieldedPoolValue(i128);

impl ShieldedPoolValue {
    pub fn new() -> Self {
        ShieldedPoolValue(0)
    }
    /// Current pool total.
    pub fn total(&self) -> i128 {
        self.0
    }
    /// Apply one tx's `value_balance` (positive unshields out, negative shields
    /// in). Fails if it would drive the pool negative — an attempt to unshield
    /// more value than the pool holds.
    pub fn apply(&mut self, value_balance: i64) -> Result<()> {
        // total_after = total − value_balance (value_balance>0 removes from pool).
        let after = self.0 - value_balance as i128;
        if after < 0 {
            return Err(Error::InvalidTransaction(format!(
                "shielded pool underflow: total {} − value_balance {} = {} < 0 \
                 (cannot unshield more than the pool holds)",
                self.0, value_balance, after
            )));
        }
        self.0 = after;
        Ok(())
    }
}

impl ShieldedPayload {
    /// Decode a shielded payload from `tx.extra`, rejecting an unknown version
    /// or trailing/garbage bytes (borsh requires full consumption).
    pub fn decode(extra: &[u8]) -> Result<Self> {
        let payload: ShieldedPayload = borsh::from_slice(extra)
            .map_err(|e| Error::InvalidTransaction(format!("shielded payload decode: {e}")))?;
        if payload.version != SHIELDED_PAYLOAD_VERSION {
            return Err(Error::InvalidTransaction(format!(
                "unsupported shielded payload version {}",
                payload.version
            )));
        }
        Ok(payload)
    }

    /// Encode into the bytes carried by `tx.extra`.
    pub fn encode(&self) -> Vec<u8> {
        borsh::to_vec(self).expect("shielded payload borsh serialization is infallible into a Vec")
    }
}

/// Apply an already-verified shielded payload to the accumulator/nullifier
/// store: spend each serial tag (fail-closed on a repeat = double spend) BEFORE
/// appending any note, then append each new note commitment to the accumulator.
///
/// MUST be called only after the spend proof has been verified. Reorg-safety is
/// provided by the store's checkpoint/rewind (taken per block by
/// `checkpoint_phase2_stores`); this function does not checkpoint.
pub fn apply_shielded_payload(
    store: &ShieldedStore,
    payload: &ShieldedPayload,
    height: u64,
    tx_index: u32,
) -> Result<()> {
    // 1. Spend nullifiers first — a double-spend must add nothing to the tree.
    for input in &payload.inputs {
        if !store.mark_nullifier_spent(input.nullifier, height) {
            return Err(Error::DuplicateNullifier);
        }
    }
    // 2. Append each output's bound coin commitment to the accumulator.
    for out in &payload.outputs {
        store.append_commitment(NoteCommitmentEntry {
            commitment: out.note_commitment,
            height,
            tx_index,
            position: 0, // assigned by the tree on append
        });
    }
    Ok(())
}

/// Contextual double-spend check for a block's shielded txs — the pre-apply
/// guard that mirrors the transparent key-image check. Every serial tag in
/// every shielded tx must be (a) unspent in the current nullifier set and
/// (b) unique within the block. Rejecting here (before `apply_shielded_payload`
/// mutates the store) means an invalid shielded block is turned away like any
/// other validation failure, rather than faulting mid-apply.
///
/// `is_spent` queries the live nullifier set (`ShieldedStore::is_nullifier_spent`).
/// Pure over `transactions` + that predicate, so it is unit-testable with a mock.
pub fn check_block_shielded_double_spends(
    transactions: &[crate::transaction::Transaction],
    is_spent: impl Fn(&[u8; 32]) -> bool,
) -> Result<()> {
    let mut seen_in_block = std::collections::HashSet::new();
    for tx in transactions {
        if !tx.is_shielded() {
            continue;
        }
        let payload = ShieldedPayload::decode(&tx.extra)?;
        for input in &payload.inputs {
            if is_spent(&input.nullifier) {
                return Err(Error::DuplicateNullifier); // already spent on-chain
            }
            if !seen_in_block.insert(input.nullifier) {
                return Err(Error::DuplicateNullifier); // double-spent within the block
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A shielded input spending `nullifier` (bucket 0, empty proofs — the apply
    /// / double-spend paths are proof-agnostic; proof verification is the gated
    /// stateful step tested in `shielded_pipeline`).
    fn input(nullifier: [u8; 32]) -> ShieldedInput {
        ShieldedInput {
            bucket_index: 0,
            nullifier,
            spend_proof: vec![],
            range_proof: vec![],
        }
    }

    /// A shielded output appending `note_commitment` (empty value proofs — see above).
    fn output(note_commitment: [u8; 32]) -> ShieldedOutput {
        ShieldedOutput {
            note_commitment,
            value_commitment: [0u8; 32],
            range_proof: vec![],
            mint_binding: vec![],
        }
    }

    #[test]
    fn shielded_pool_value_never_goes_negative() {
        let mut pool = ShieldedPoolValue::new();
        assert_eq!(pool.total(), 0);
        // Shield 100 in (value_balance = -100) → pool holds 100.
        pool.apply(-100).unwrap();
        assert_eq!(pool.total(), 100);
        // Shield 50 more → 150.
        pool.apply(-50).unwrap();
        assert_eq!(pool.total(), 150);
        // Unshield 120 out (value_balance = +120) → 30.
        pool.apply(120).unwrap();
        assert_eq!(pool.total(), 30);
        // Unshielding 31 (more than the pool holds) is rejected — the
        // no-inflation-across-the-veil invariant.
        assert!(pool.apply(31).is_err());
        assert_eq!(pool.total(), 30, "a rejected apply must not mutate the pool");
        // Exactly draining the pool is fine.
        pool.apply(30).unwrap();
        assert_eq!(pool.total(), 0);
    }

    #[test]
    fn payload_roundtrips_and_rejects_bad_version() {
        let p = ShieldedPayload {
            version: SHIELDED_PAYLOAD_VERSION,
            inputs: vec![input([9u8; 32])],
            outputs: vec![output([1u8; 32]), output([2u8; 32])],
            value_balance: 0,
            balance_proof: vec![],
        };
        let bytes = p.encode();
        assert_eq!(ShieldedPayload::decode(&bytes).unwrap(), p);

        // Unknown version rejected.
        let mut bad = p.clone();
        bad.version = 2;
        assert!(ShieldedPayload::decode(&bad.encode()).is_err());
        // Garbage / trailing bytes rejected (borsh requires full consumption).
        assert!(ShieldedPayload::decode(&[0xFFu8; 3]).is_err());
    }

    fn shielded_tx(nullifiers: Vec<[u8; 32]>) -> crate::transaction::Transaction {
        use crate::transaction::{Transaction, TxType};
        let payload = ShieldedPayload {
            version: SHIELDED_PAYLOAD_VERSION,
            inputs: nullifiers.into_iter().map(input).collect(),
            outputs: vec![],
            value_balance: 0,
            balance_proof: vec![],
        };
        Transaction {
            version: 1,
            tx_type: TxType::Shielded,
            inputs: vec![],
            outputs: vec![],
            fee: crate::primitives::Amount::from_atomic(0),
            range_proof: vec![],
            extra: payload.encode(),
        }
    }

    #[test]
    fn block_shielded_double_spends_are_detected_pre_apply() {
        // Unspent + unique across the block → OK.
        let ok = vec![shielded_tx(vec![[1u8; 32]]), shielded_tx(vec![[2u8; 32]])];
        assert!(check_block_shielded_double_spends(&ok, |_| false).is_ok());

        // A tag already spent on-chain → rejected.
        let spent = [1u8; 32];
        let vs_chain = vec![shielded_tx(vec![spent])];
        assert!(matches!(
            check_block_shielded_double_spends(&vs_chain, |t| *t == spent).unwrap_err(),
            Error::DuplicateNullifier
        ));

        // Same tag twice within the block → rejected.
        let dup = vec![shielded_tx(vec![[7u8; 32]]), shielded_tx(vec![[7u8; 32]])];
        assert!(matches!(
            check_block_shielded_double_spends(&dup, |_| false).unwrap_err(),
            Error::DuplicateNullifier
        ));
    }

    #[test]
    fn apply_appends_notes_spends_tags_and_rejects_double_spend() {
        let store = ShieldedStore::new();
        let p = ShieldedPayload {
            version: SHIELDED_PAYLOAD_VERSION,
            inputs: vec![input([9u8; 32])],
            outputs: vec![output([1u8; 32]), output([2u8; 32])],
            value_balance: 0,
            balance_proof: vec![],
        };
        apply_shielded_payload(&store, &p, 10, 0).unwrap();
        assert_eq!(store.tree_size(), 2, "both notes appended to the accumulator");
        assert!(store.is_nullifier_spent(&[9u8; 32]), "serial tag marked spent");

        // Re-spending the same serial tag is a double spend → fail-closed, and
        // its note must NOT have been appended (tag spent before append).
        let dbl = ShieldedPayload {
            version: SHIELDED_PAYLOAD_VERSION,
            inputs: vec![input([9u8; 32])],
            outputs: vec![output([3u8; 32])],
            value_balance: 0,
            balance_proof: vec![],
        };
        let err = apply_shielded_payload(&store, &dbl, 11, 0).unwrap_err();
        assert!(matches!(err, Error::DuplicateNullifier), "got: {err:?}");
        assert_eq!(store.tree_size(), 2, "double-spend must not append its note");
    }
}
