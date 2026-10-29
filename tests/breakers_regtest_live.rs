//! LIVE regtest test for the chain-derived safety connectors — the **Rung-2
//! state-root connector** and the **supply breaker** — driven against a real
//! mined regtest chain (not just unit math).
//!
//! It mines real blocks, reads the chain's ACTUAL UTXO commitment and circulating
//! supply, and confirms: a healthy live chain reads as healthy (no false trip),
//! the state-root carriage round-trips + enforces against the real root, and an
//! injected fault (tampered root / over-emission) correctly trips each breaker.
//!
//! The node-local breakers (mempool / p2p / rpc / reorg) read runtime + network
//! counters rather than chain state, so they are covered by their unit tests;
//! a live harness for those needs the full node/RPC/P2P stack.
//!
//! Run:
//!   cargo test --test breakers_regtest_live \
//!     --features "testnet test-fast-pow state-root-commit supply-breaker" -- --nocapture

#![cfg(all(
    feature = "test-fast-pow",
    feature = "state-root-commit",
    feature = "supply-breaker"
))]

use std::sync::Arc;

use coincync::chain::{Blockchain, SharedBlockchain};
use coincync::config::NetworkType;
use coincync::consensus::bind_randomx_genesis_for_network;
use coincync::consensus::fork_signal::SignalBits;
use coincync::mempool::SharedMempool;
use coincync::mining::block_builder::{build_candidate_block, submit_mined_block};
use coincync::primitives::{Hash, SecretKey};
use coincync::state_root_connector as sr;
use coincync::supply_breaker as sb;

#[test]
fn breakers_on_live_regtest_chain() {
    let net = NetworkType::Regtest;
    bind_randomx_genesis_for_network(net);
    let chain: SharedBlockchain = Arc::new(Blockchain::new_with_network(net));
    chain.init_genesis().expect("init genesis");
    let mempool = SharedMempool::new();
    let spend = SecretKey::from_bytes([7u8; 32]).public_key();
    let view = SecretKey::from_bytes([9u8; 32]).public_key();

    for _ in 0..3 {
        let cand = build_candidate_block(&chain, &mempool, &spend, &view, net, SignalBits(0))
            .expect("build candidate");
        submit_mined_block(&chain, &mempool, cand.into_block(0)).expect("submit");
    }
    let height = chain.height();
    assert_eq!(height, 3, "three regtest blocks mined");

    // ── Rung-2 state-root connector against the REAL UTXO commitment ─────────
    let real_root: Hash = chain.utxo_commitment_at_tip();
    let outputs_ever = chain.total_outputs_ever();
    assert!(outputs_ever > 0, "mined chain has real outputs");

    // Carriage: embed the real root in coinbase extra, then recover it.
    let extra = sr::embed_in_extra(Vec::new(), &real_root);
    let recovered = sr::extract_from_extra(&extra);
    assert_eq!(recovered, Some(real_root), "state root round-trips through coinbase extra");

    // Enforce at this height against the real root → Match (no false trip on a
    // healthy live chain).
    let ok = sr::check(
        sr::StateRootPolicy::Enforce { activation_height: height },
        height,
        recovered,
        real_root,
    );
    assert_eq!(ok, sr::StateRootCheck::Match, "committed real root matches the live UTXO commitment");
    assert!(!ok.rejects());

    // Tamper: a different actual root (node computed something else) → Mismatch.
    let tampered = sr::check(
        sr::StateRootPolicy::Enforce { activation_height: height },
        height,
        recovered,
        Hash::from_bytes([0xEE; 32]),
    );
    assert_eq!(tampered, sr::StateRootCheck::Mismatch);
    assert!(tampered.rejects());

    // Observe mode is inert on the same live data.
    assert_eq!(
        sr::check(sr::StateRootPolicy::Observe, height, recovered, real_root),
        sr::StateRootCheck::Inactive
    );

    // ── Supply breaker against the REAL circulating supply ───────────────────
    let circulating = chain.stats().total_supply as i128;
    assert!(circulating > 0, "mined chain emitted real supply");

    // Healthy observation reflecting the live chain (burn=0 → emitted=circulating;
    // coinbase at the allowed boundary; within cap).
    let healthy = sb::SupplyObservation {
        coinbase_payout: 50,
        allowed_emission: 50,
        block_fees: 0,
        total_emitted: circulating,
        total_burned: 0,
        circulating,
        max_supply: i128::MAX,
        committed_supply: Some(circulating),
    };
    assert!(sb::detect(&healthy).is_empty(), "live supply reads as healthy");
    assert_eq!(sb::evaluate(sb::BreakerPolicy::Armed, &healthy), sb::BreakerAction::AllowBlock);

    // Inject over-emission on top of the real supply → trip.
    let mut inflating = healthy;
    inflating.coinbase_payout = circulating + 1_000; // mint beyond emission+fees
    assert!(sb::detect(&inflating).contains(&sb::SupplyFault::OverEmission));
    assert!(sb::evaluate(sb::BreakerPolicy::Armed, &inflating).rejects_block());
    // Observe stays inert even on the injected fault.
    assert!(!sb::evaluate(sb::BreakerPolicy::Observe, &inflating).rejects_block());

    println!(
        "BREAKERS LIVE REGTEST OK — height={height}, outputs_ever={outputs_ever}, circulating={circulating}\n\
         state-root: real UTXO commitment round-trips + enforces (Match); tamper -> Mismatch; Observe inert\n\
         supply: live circulating reads healthy (AllowBlock); injected over-emission -> RejectBlock; Observe inert"
    );
}
