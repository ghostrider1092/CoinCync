//! Skeleton smoke test for the CyncHub crate.
//!
//! Asserts the crate compiles, the status sentinel reports unimplemented,
//! and every public stub returns `Error::NotImplemented` with the
//! expected `stage` value. This test exists so that a CI-blocking
//! "skeleton sanity" gate fires the moment an implementation slice
//! lands (because the matching `stage` arm will no longer return
//! `NotImplemented` after the slice is in).
//!
//! The pattern matches `crates/coincync-swap/src/lib.rs`'s
//! `skeleton_advertises_unimplemented_status` test.

use cynchub::consensus::{self, Block, BlockHeader};
use cynchub::orderbook::{self, OrderBook};
use cynchub::tx::{self, Cancel, LockRef, Order, Side, Transaction};
use cynchub::{is_implemented, mergemining, Error};

#[test]
fn crate_advertises_skeleton_status() {
    assert!(
        !is_implemented(),
        "is_implemented() must return false until CIP-002 V1 ships + audits"
    );
}

#[test]
fn consensus_stubs_return_not_implemented() {
    let header = BlockHeader {
        prev_hash: [0u8; 32],
        merkle_root: [0u8; 32],
        timestamp: 0,
        height: 1,
        cync_block_hash: [0u8; 32],
        merkle_path_to_coinbase_commitment: Vec::new(),
    };
    let block = Block { header: header.clone(), body: Vec::new() };

    assert!(matches!(
        consensus::validate_block(&block, &header).unwrap_err(),
        Error::NotImplemented { stage: "consensus.validate_block" }
    ));
    assert!(matches!(
        consensus::target_for_height(1).unwrap_err(),
        Error::NotImplemented { stage: "consensus.target_for_height" }
    ));
    assert!(matches!(
        consensus::verify_pow(&block).unwrap_err(),
        Error::NotImplemented { stage: "consensus.verify_pow" }
    ));
}

#[test]
fn tx_validate_stub_returns_not_implemented() {
    let tx = Transaction::Cancel(Cancel {
        order_id: LockRef { chain: "cync".to_string(), lock_id: [0u8; 32] },
        owner_sig: Vec::new(),
    });
    assert!(matches!(
        tx::validate(&tx).unwrap_err(),
        Error::NotImplemented { stage: "tx.validate" }
    ));
}

#[test]
fn orderbook_stubs_return_not_implemented() {
    let mut book = OrderBook::new();
    let order = Order {
        side: Side::Ask,
        amount_cync: 1,
        price_sat_per_cync: 1,
        lock_ref: LockRef { chain: "cync".to_string(), lock_id: [0u8; 32] },
        expiry_block: 1,
    };

    assert!(matches!(
        orderbook::insert(&mut book, order.clone(), 1).unwrap_err(),
        Error::NotImplemented { stage: "orderbook.insert" }
    ));
    assert!(matches!(
        orderbook::next_match(&book).unwrap_err(),
        Error::NotImplemented { stage: "orderbook.next_match" }
    ));
    assert!(matches!(
        orderbook::mark_matched(&mut book, &order.lock_ref, 2).unwrap_err(),
        Error::NotImplemented { stage: "orderbook.mark_matched" }
    ));
    assert!(matches!(
        orderbook::remove(&mut book, &order.lock_ref).unwrap_err(),
        Error::NotImplemented { stage: "orderbook.remove" }
    ));
}

#[test]
fn mergemining_stubs_return_not_implemented() {
    assert!(matches!(
        mergemining::parse_commitment(&[0u8; mergemining::COMMITMENT_LEN]).unwrap_err(),
        Error::NotImplemented { stage: "mergemining.parse_commitment" }
    ));
    let commitment = mergemining::Commitment { cynchub_block_hash: [0u8; 32] };
    assert!(matches!(
        mergemining::verify_commitment(&commitment, &[], &[]).unwrap_err(),
        Error::NotImplemented { stage: "mergemining.verify_commitment" }
    ));
}
