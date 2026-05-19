//! Property-based invariants for `coincync::transaction::validate_transaction`.
//!
//! The validator is consensus-critical and attacker-reachable: every
//! peer-relayed transaction passes through it. A validation rule that
//! silently accepts garbage = forks, DoS surface, or fund-loss vectors.
//!
//! Strategy: start from a known-valid coinbase fixture (mirrors the
//! pattern in the in-crate unit tests), then mutate exactly one field
//! to an invalid value and assert rejection. Each property tests a
//! single rejection rule independently.
//!
//! Coverage target: take `src/transaction/validator.rs` from baseline
//! 64.34% region coverage to 85%+.
//!
//! **Every property below is grounded in the actual implementation at
//! `src/transaction/validator.rs:15-129`** — read first, then test.

#![cfg(not(miri))]

use proptest::prelude::*;

use coincync::primitives::{Amount, PublicKey};
use coincync::transaction::{validate_transaction, Transaction, TxOutput, TxType};

// ─── Fixture: minimal valid coinbase tx ──────────────────────────

/// Mirrors the in-crate test pattern at `validator.rs:143-161`.
/// Produces a coinbase tx that `validate_transaction(..., height=0)`
/// accepts — the baseline for mutation testing below.
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

proptest! {
    #![proptest_config(ProptestConfig {
        cases: 256,
        .. ProptestConfig::default()
    })]

    // ─── Baseline: the fixture must be accepted ───────────────────

    /// Sanity property — the unmutated baseline coinbase tx passes
    /// at height 0. If THIS fails, our fixture itself is invalid and
    /// every other property below is meaningless.
    #[test]
    fn baseline_coinbase_passes_validation(_unused in 0u8..1) {
        let tx = make_coinbase_tx();
        let result = validate_transaction(&tx, 0);
        prop_assert!(result.is_ok(), "baseline fixture rejected: {:?}", result);
    }

    // ─── Version field ────────────────────────────────────────────

    /// Any version byte ≠ 1 is rejected (per `validator.rs:17-19`).
    #[test]
    fn nonstandard_version_is_rejected(bad_version in any::<u8>().prop_filter("not 1", |v| *v != 1)) {
        let mut tx = make_coinbase_tx();
        tx.version = bad_version;
        let result = validate_transaction(&tx, 0);
        prop_assert!(result.is_err(), "version {} was accepted", bad_version);
    }

    // ─── Output count ─────────────────────────────────────────────

    /// Empty outputs are rejected (per `validator.rs:37-39`).
    #[test]
    fn empty_outputs_rejected(_unused in 0u8..1) {
        let mut tx = make_coinbase_tx();
        tx.outputs.clear();
        let result = validate_transaction(&tx, 0);
        prop_assert!(result.is_err(),
            "tx with zero outputs accepted — expected rejection");
    }

    // ─── Lock height ──────────────────────────────────────────────

    /// `lock_height > current_height + 525_960` is rejected
    /// (per `validator.rs:42-51`). 525_960 ≈ 2 years at 120s blocks.
    /// We test the boundary: any height above the threshold rejects;
    /// any height ≤ threshold accepts (modulo other constraints).
    #[test]
    fn lock_height_too_far_in_future_rejected(
        chain_height in 0u64..1_000_000_u64,
        excess in 1u64..1_000_000_u64,
    ) {
        let mut tx = make_coinbase_tx();
        tx.outputs[0].lock_height = Some(chain_height + 525_960 + excess);
        let result = validate_transaction(&tx, chain_height);
        prop_assert!(result.is_err(),
            "lock_height = {} accepted at chain height {} (limit: {})",
            chain_height + 525_960 + excess, chain_height, chain_height + 525_960);
    }

    /// `lock_height ≤ current_height + 525_960` is NOT rejected for
    /// this reason. (Other validation rules may still reject; we just
    /// assert the lock_height check itself doesn't fail.)
    #[test]
    fn lock_height_within_window_is_accepted(
        chain_height in 0u64..1_000_000_u64,
        offset in 0u64..525_960_u64,
    ) {
        let mut tx = make_coinbase_tx();
        tx.outputs[0].lock_height = Some(chain_height + offset);
        let result = validate_transaction(&tx, chain_height);
        prop_assert!(result.is_ok(),
            "lock_height = {} (offset {}) at chain height {} was rejected: {:?}",
            chain_height + offset, offset, chain_height, result);
    }

    // ─── Extra data ───────────────────────────────────────────────

    /// `extra.len() > 256` is rejected (per `validator.rs:117-119`).
    #[test]
    fn extra_too_large_rejected(excess in 1usize..512usize) {
        let mut tx = make_coinbase_tx();
        // 256 + 1..512 bytes — guaranteed over the 256-byte limit.
        tx.extra = vec![0u8; 256 + excess];
        let result = validate_transaction(&tx, 0);
        prop_assert!(result.is_err(),
            "extra of {} bytes accepted (max: 256)", 256 + excess);
    }

    /// `extra.len() ≤ 256` is NOT rejected for this reason. (Note:
    /// non-empty extra triggers recovery-metadata validation, which
    /// rejects anything that's not a valid `RecoveryMeta` borsh blob.
    /// So we only test `extra = []` for "accepted" — non-empty extras
    /// require knowing the recovery-metadata format.)
    #[test]
    fn empty_extra_is_accepted(_unused in 0u8..1) {
        let tx = make_coinbase_tx();
        // The baseline already has extra=vec![] — just confirm.
        let result = validate_transaction(&tx, 0);
        prop_assert!(result.is_ok());
    }

    // ─── Range proof size ─────────────────────────────────────────

    /// `range_proof.len() > MAX_TX_SIZE` is rejected
    /// (per `validator.rs:112-114`). MAX_TX_SIZE is large (consensus
    /// constant); we use a value clearly above any plausible limit.
    /// The validator's earlier `size > MAX_TX_SIZE` check (`validator.rs:23-25`)
    /// catches this too because range_proof contributes to tx.size().
    /// Either rejection path is correct.
    #[test]
    fn huge_range_proof_rejected(extra_bytes in 1usize..1024usize) {
        let mut tx = make_coinbase_tx();
        // Use 1 MB + extra to exceed any reasonable MAX_TX_SIZE.
        // The exact MAX_TX_SIZE constant is internal; this value is
        // chosen to exceed every plausible setting.
        tx.range_proof = vec![0u8; 16_000_000 + extra_bytes];
        let result = validate_transaction(&tx, 0);
        prop_assert!(result.is_err(),
            "range_proof of {} bytes accepted", tx.range_proof.len());
    }

    // NOTE: Duplicate-key-image rejection (the intra-tx double-spend
    // check at `validator.rs:55-61`) is a CRITICAL consensus rule
    // worth property-testing — but constructing two TxInputs with the
    // same key image requires building a valid ClsagSignature, which
    // isn't accessible from an external integration test. That
    // property is exercised by the in-crate tests in
    // `src/transaction/validator.rs::tests` and by the consensus-layer
    // validator's existing tests.

    // ─── Lock height: `None` is always OK ─────────────────────────

    /// `lock_height = None` is always accepted at any chain height
    /// (the check at `validator.rs:43` short-circuits on None).
    #[test]
    fn lock_height_none_is_always_accepted(chain_height in 0u64..1_000_000_u64) {
        let tx = make_coinbase_tx();
        // The baseline already has lock_height=None.
        let result = validate_transaction(&tx, chain_height);
        prop_assert!(result.is_ok(),
            "tx with lock_height=None rejected at chain height {}: {:?}",
            chain_height, result);
    }
}
