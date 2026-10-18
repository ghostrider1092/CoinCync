//! Integration test for the shielded mempool-admission bypass.
//!
//! A pure shielded transfer carries empty transparent inputs/outputs and
//! `tx.fee == 0` (the pool-internal fee + conservation live inside the libspark
//! bundle and the cross-veil value bridge). The contextless mempool prechecks
//! (`validate_transaction_basic` + `check_tx_privacy`) assume the transparent
//! shape and would reject it (empty inputs, fee < size*MIN_FEE_PER_BYTE); the
//! bypass lets it through so the authoritative, activation-gated shielded path
//! (`validate_transaction` -> `check_shielded_tx`) decides.
//!
//! The in-process unit tests cover each gate in isolation; this drives the REAL
//! `SharedMempool::add_with_chain` path (what `send_raw_transaction` calls) on a
//! Beta chain seeded past the shielded activation height, proving the gates
//! compose and a shielded transfer is actually admissible end to end — while a
//! transparent empty-input tx is still rejected (the bypass is shielded-only).
//!
//! Gated on `sketch-gk-proof + libspark-ffi` (needs the v2 `SparkPayload` type
//! and the active shielded verifier); run with
//! `--features "testnet sketch-gk-proof libspark-ffi"`.

#![cfg(all(feature = "sketch-gk-proof", feature = "libspark-ffi"))]

use coincync::chain::{Blockchain, SharedBlockchain};
use coincync::config::NetworkType;
use coincync::consensus::spark_payload::{SparkPayload, SpendBundle, SPARK_PAYLOAD_VERSION};
use coincync::mempool::SharedMempool;
use coincync::primitives::Amount;
use coincync::transaction::{Transaction, TxType};
use std::sync::Arc;

/// Build a Beta chain seeded past the shielded activation height (Beta = 5), so
/// `shielded_tx_active_at_height(Beta, tip)` is true and `check_shielded_tx`
/// routes to the v2 structural check instead of the inactive-height reject.
fn beta_chain_active() -> SharedBlockchain {
    let chain: SharedBlockchain = Arc::new(Blockchain::new_with_network(NetworkType::Beta));
    chain.init_genesis().expect("init genesis");
    // No real PoW: seed headers to height 6 (> Beta activation 5).
    chain.seed_linear_chain_for_testing(6, 60);
    chain
}

/// A pure shielded transfer: empty transparent inputs/outputs, tx.fee 0, a
/// well-formed v2 `SparkPayload` in `extra`. The bundle bytes are not verified at
/// mempool admission (the v2 path only decodes structurally), and the padding
/// keeps the tx above MIN_TX_SIZE so the size guard in the bypass passes.
fn shielded_transfer_tx() -> Transaction {
    let payload = SparkPayload {
        version: SPARK_PAYLOAD_VERSION,
        mint: None,
        outputs: vec![],
        spend: Some(SpendBundle {
            cover_set_id: 0,
            anchor_height: 1,
            bundle: vec![0u8; 256],
        }),
        value_balance: 0,
    };
    Transaction {
        version: 1,
        tx_type: TxType::Shielded,
        inputs: vec![],
        outputs: vec![],
        fee: Amount::ZERO,
        range_proof: vec![],
        extra: payload.encode(),
    }
}

#[test]
fn shielded_transfer_is_admitted_through_add_with_chain() {
    let chain = beta_chain_active();
    let mempool = SharedMempool::new();

    let tx = shielded_transfer_tx();
    let expected = tx.hash();

    let result = mempool.add_with_chain(tx, &chain);
    assert!(
        result.is_ok(),
        "a pure shielded transfer must be admitted through the real mempool submit \
         path (send_raw_transaction -> add_with_chain) on an active Beta chain; got {:?}",
        result.err()
    );
    assert_eq!(result.unwrap(), expected, "returned hash matches the tx");
}

#[test]
fn transparent_empty_input_tx_is_still_rejected() {
    // Regression: the empty-input/min-fee bypass is shielded-ONLY. A transparent
    // tx with empty inputs must still be rejected by the same submit path.
    let chain = beta_chain_active();
    let mempool = SharedMempool::new();

    let mut tx = shielded_transfer_tx();
    tx.tx_type = TxType::Transfer; // same empty shape, but NOT shielded

    let result = mempool.add_with_chain(tx, &chain);
    assert!(
        result.is_err(),
        "a transparent tx with empty inputs must still be rejected (bypass is shielded-only)"
    );
}
