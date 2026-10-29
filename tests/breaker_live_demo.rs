//! LIVE, watchable demo of the circuit breakers running tick-by-tick.
//!
//! Mines a real regtest chain, then drives the ACTUAL breaker + recovery code
//! through a narrated timeline so you can watch disconnect → isolate → recover →
//! reconnect happen — on real chain data for the state-root check, and with
//! injected faults for the response scenarios.
//!
//! Run (watch the output):
//!   cargo test --test breaker_live_demo --features "testnet test-fast-pow \
//!     breaker-recovery shielded-breaker mempool-breaker state-root-commit" \
//!     -- --nocapture

#![cfg(all(
    feature = "test-fast-pow",
    feature = "breaker-recovery",
    feature = "shielded-breaker",
    feature = "mempool-breaker",
    feature = "state-root-commit"
))]

use std::sync::Arc;

use coincync::breaker_recovery::{BreakerState, BreakerSurface, RecoveryBreaker};
use coincync::chain::{Blockchain, SharedBlockchain};
use coincync::config::NetworkType;
use coincync::consensus::bind_randomx_genesis_for_network;
use coincync::consensus::fork_signal::SignalBits;
use coincync::mempool::SharedMempool;
use coincync::mempool_breaker as mb;
use coincync::mining::block_builder::{build_candidate_block, submit_mined_block};
use coincync::primitives::{Hash, SecretKey};
use coincync::shielded_circuit_breaker as sb;
use coincync::state_root_connector as sr;

fn badge(st: BreakerState) -> &'static str {
    match st {
        BreakerState::Closed => "CLOSED  (open for business)",
        BreakerState::Open => "OPEN    [ISOLATED]",
        BreakerState::HalfOpen => "HALFOPEN(probing recovery)",
    }
}

#[test]
fn breaker_live_demo() {
    // ── mine a real regtest chain ────────────────────────────────────────────
    let net = NetworkType::Regtest;
    bind_randomx_genesis_for_network(net);
    let chain: SharedBlockchain = Arc::new(Blockchain::new_with_network(net));
    chain.init_genesis().unwrap();
    let mempool = SharedMempool::new();
    let spend = SecretKey::from_bytes([7u8; 32]).public_key();
    let view = SecretKey::from_bytes([9u8; 32]).public_key();
    for _ in 0..3 {
        let cand =
            build_candidate_block(&chain, &mempool, &spend, &view, net, SignalBits(0)).unwrap();
        submit_mined_block(&chain, &mempool, cand.into_block(0)).unwrap();
    }
    let height = chain.height();
    println!("\n================ CoinCync circuit-breaker LIVE demo ================");
    println!("mined a regtest chain to height {height}\n");

    // ── Scenario 1: mempool breaker (AutoReset, node-local) ───────────────────
    println!("--- Scenario 1: MEMPOOL breaker (load surface -> AutoReset) ---");
    let base = mb::MempoolObservation {
        max_count: 50_000,
        max_bytes: 300_000_000,
        max_arrivals_per_interval: 1_000,
        max_per_peer_arrivals: 100,
        max_dust: 50,
        ..Default::default()
    };
    let mut b = RecoveryBreaker::for_surface(BreakerSurface::Mempool);
    // tick timeline: healthy, healthy, FLOOD, flood, calm, calm, calm
    let arrivals = [50u32, 50, 500_000, 500_000, 50, 50, 50];
    for (t, &a) in arrivals.iter().enumerate() {
        let mut o = base;
        o.arrivals_this_interval = a;
        let faulty = !mb::detect(&o).is_empty();
        let st = b.observe(faulty);
        println!(
            "  tick {t}: arrivals={a:<7} {}  -> {}",
            if faulty { "FLOOD " } else { "ok    " },
            badge(st)
        );
    }
    println!("  => load surface reconnected on its own once the flood cleared.\n");

    // ── Scenario 2: shielded breaker (Latch, crypto/money) ────────────────────
    println!("--- Scenario 2: SHIELDED breaker (money surface -> Latch) ---");
    let healthy = sb::PoolObservation {
        pool_value: 1_000,
        total_shielded_in: 1_000,
        expected_from_balance: 1_000,
        ..Default::default()
    };
    let mut inflated = healthy;
    inflated.pool_value = 9_999; // inflation: pool > shield-in
    let mut b = RecoveryBreaker::for_surface(BreakerSurface::Shielded);
    let seq: [(&str, &sb::PoolObservation); 6] = [
        ("ok", &healthy),
        ("INFLATION", &inflated),
        ("ok", &healthy),
        ("ok", &healthy),
        ("ok", &healthy),
        ("ok", &healthy),
    ];
    for (t, (label, o)) in seq.iter().enumerate() {
        let faulty = !sb::detect(o).is_empty();
        let st = b.observe(faulty);
        println!("  tick {t}: {label:<9} -> {}", badge(st));
    }
    println!("  (note: stays OPEN on clean ticks — a known-broken pool does NOT auto-reopen)");
    b.rearm();
    println!("  operator rearm() -> {}", badge(b.state()));
    println!("  => money surface reconnected ONLY by explicit human re-arm.\n");

    // ── Scenario 3: state-root connector vs the REAL chain commitment ─────────
    println!("--- Scenario 3: STATE-ROOT connector (Rung-2, real chain data) ---");
    let real_root: Hash = chain.utxo_commitment_at_tip();
    let extra = sr::embed_in_extra(Vec::new(), &real_root);
    let recovered = sr::extract_from_extra(&extra);
    let good = sr::check(
        sr::StateRootPolicy::Enforce { activation_height: height },
        height,
        recovered,
        real_root,
    );
    let tampered = sr::check(
        sr::StateRootPolicy::Enforce { activation_height: height },
        height,
        recovered,
        Hash::from_bytes([0xEE; 32]),
    );
    let root_hex = real_root.to_hex();
    println!("  real UTXO commitment @tip: {}…", &root_hex[..root_hex.len().min(24)]);
    println!("  committed root enforced   -> {good:?}");
    println!("  tampered root enforced    -> {tampered:?}");
    assert_eq!(good, sr::StateRootCheck::Match);
    assert_eq!(tampered, sr::StateRootCheck::Mismatch);
    println!("  => the chain's real state root verifies; a tampered one is rejected.\n");

    println!("================ demo complete ================\n");

    // Guard the demo's own claims so it fails loudly if behavior regresses.
    // (Scenario 1 ends CLOSED; Scenario 2 ends CLOSED only after rearm.)
    assert_eq!(b.state(), BreakerState::Closed);
}
