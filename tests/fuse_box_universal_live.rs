//! UNIVERSAL FUSE BOX — live, end-to-end across every surface.
//!
//! Proves the fuse box is now *universal*: one process-wide box into which every
//! breaker is registered and through which every surface's REAL feed adapter
//! reports. Each surface is driven through its actual `*_live_breaker` feed
//! function (the same code the node calls), then the ONE shared box is inspected
//! via `fuse::snapshot()` — all seven compartments in one place — and each
//! surface's recovery policy is verified (AutoReset load surfaces reconnect on a
//! healthy streak; the Latch money/integrity surface stays open until `rearm`).
//!
//! Run:
//!   cargo test --test fuse_box_universal_live --features "testnet fuse" -- --nocapture

#![cfg(feature = "fuse")]

use std::net::SocketAddr;

use coincync::breaker_recovery::{BreakerState, BreakerSurface};
use coincync::{
    block_integrity_live_breaker as integrity, fuse, mempool_live_breaker as mempool,
    p2p_live_breaker as p2p, reorg_live_breaker as reorg, rpc_live_breaker as rpc,
};

fn addr(s: &str) -> SocketAddr {
    s.parse().unwrap()
}

fn state(surface: BreakerSurface) -> Option<BreakerState> {
    fuse::snapshot().into_iter().find(|(s, _)| *s == surface).map(|(_, st)| st)
}

#[test]
fn every_surface_flows_through_one_shared_box() {
    // Deterministic telemetry thresholds for the test.
    std::env::set_var("COINCYNC_MEMPOOL_BREAKER_MAX_COUNT", "5");
    std::env::set_var("COINCYNC_RPC_BREAKER_MAX_BODY_BYTES", "10");
    std::env::set_var("COINCYNC_RPC_BREAKER_INTERVAL_SECS", "0"); // fresh window each call
    std::env::remove_var("COINCYNC_P2P_BREAKER_MIN_PEERS");

    // Fresh box: install every surface, all Closed.
    fuse::reset();
    mempool::reset();
    p2p::reset();
    reorg::reset();
    rpc::reset();
    integrity::reset();

    let snap = fuse::snapshot();
    assert_eq!(snap.len(), BreakerSurface::ALL.len(), "the box registers EVERY surface");
    assert!(snap.iter().all(|(_, st)| *st == BreakerState::Closed), "all start Closed");

    println!("\n== UNIVERSAL FUSE BOX: tripping each surface through its real feed ==");

    // 1) Mempool — real admission feed, count over cap.
    mempool::on_admission(6, 0);
    assert_eq!(state(BreakerSurface::Mempool), Some(BreakerState::Open), "mempool flood trips");

    // 2) P2P — real heartbeat feed, a single peer (eclipse risk).
    p2p::observe_from_addrs(&[addr("1.2.3.4:28080")]);
    assert_eq!(state(BreakerSurface::P2p), Some(BreakerState::Open), "too-few-peers trips");

    // 3) RPC — real per-request feed, body over cap.
    rpc::on_request(100);
    assert_eq!(state(BreakerSurface::Rpc), Some(BreakerState::Open), "oversize body trips");

    // 4) Reorg — real reorg-accept feed, depth over the safe max.
    reorg::on_reorg(/*depth*/ 1000, /*max_safe*/ 100, /*fork_point*/ 50, /*finalized*/ 10, 200, 100);
    assert_eq!(state(BreakerSurface::Reorg), Some(BreakerState::Open), "deep reorg trips");

    // 5) Block-integrity — real connect feed, availability underflow (money/integrity → Latch).
    integrity::on_block_connected(/*ever*/ 5, /*disconnects*/ 10, /*live*/ 3);
    assert_eq!(
        state(BreakerSurface::BlockIntegrity),
        Some(BreakerState::Open),
        "availability underflow trips"
    );

    // One box, five of seven compartments isolating at once (supply + shielded
    // are registered but fed only at the coordinated activation).
    let isolating: Vec<_> = fuse::snapshot().into_iter().filter(|(_, st)| *st != BreakerState::Closed).collect();
    println!("  isolating now: {isolating:?}");
    assert_eq!(isolating.len(), 5, "exactly the five live-fed surfaces are isolating");

    println!("== recovery: load surfaces reconnect on a healthy streak; integrity latches ==");

    // AutoReset load/attack surfaces: feed healthy ticks → reconnect.
    let good_peers = [
        addr("1.2.3.4:28080"),
        addr("5.6.7.8:28080"),
        addr("9.10.11.12:28080"),
        addr("13.14.15.16:28080"),
    ];
    for _ in 0..5 {
        mempool::on_admission(1, 0); // under cap
        p2p::observe_from_addrs(&good_peers); // diverse
        rpc::on_request(1); // small body, fresh window
        reorg::on_reorg(1, 100, 90, 10, 100, 100); // shallow, above finality
    }
    for s in [BreakerSurface::Mempool, BreakerSurface::P2p, BreakerSurface::Rpc, BreakerSurface::Reorg] {
        assert_eq!(state(s), Some(BreakerState::Closed), "{s:?} (AutoReset) reconnects after a healthy streak");
    }

    // Latch surface: healthy connects do NOT reconnect it.
    for _ in 0..10 {
        integrity::on_block_connected(100, 0, 50); // perfectly healthy
    }
    assert_eq!(
        state(BreakerSurface::BlockIntegrity),
        Some(BreakerState::Open),
        "block-integrity LATCHES — a clean next block does not undo corruption"
    );

    // Only an explicit operator rearm reconnects a latched surface.
    fuse::rearm(BreakerSurface::BlockIntegrity);
    assert_eq!(state(BreakerSurface::BlockIntegrity), Some(BreakerState::Closed), "rearm reconnects");

    println!("  => one universal box: every surface fed through its real adapter, ");
    println!("     AutoReset surfaces self-healed, the integrity fuse latched until rearm.\n");
}
