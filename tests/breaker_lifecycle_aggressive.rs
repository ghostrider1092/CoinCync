//! AGGRESSIVE lifecycle test for the circuit breakers + recovery machine.
//!
//! Beyond "does it trip": this hammers the full **disconnect → isolate →
//! recover → reconnect** cycle and asserts, against independently-derived
//! invariants (not a re-implementation), that:
//!   - any fault disconnects immediately (fail-closed),
//!   - **Latch** (crypto/money) surfaces NEVER reconnect on their own — only via
//!     `rearm()`,
//!   - **AutoReset** (load/attack) surfaces reconnect only after a full healthy
//!     streak (hysteresis), and re-trip instantly on any fault while healing,
//!   - the breakers disconnect and connect again, repeatedly, without flapping,
//!   - the whole pipeline works through each breaker's REAL `detect()`.
//!
//! Run:
//!   cargo test --test breaker_lifecycle_aggressive --features "testnet \
//!     breaker-recovery shielded-breaker supply-breaker mempool-breaker \
//!     p2p-breaker reorg-breaker rpc-breaker" -- --nocapture

#![cfg(all(
    feature = "breaker-recovery",
    feature = "shielded-breaker",
    feature = "supply-breaker",
    feature = "mempool-breaker",
    feature = "p2p-breaker",
    feature = "reorg-breaker",
    feature = "rpc-breaker"
))]

use coincync::breaker_recovery::{
    recommended_recovery, BreakerState, BreakerSurface, RecoveryBreaker, RecoveryPolicy,
};

/// Tiny deterministic xorshift64 PRNG (no external dep).
struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.0 = x;
        x
    }
    /// true with probability p_num/256.
    fn chance(&mut self, p_num: u64) -> bool {
        (self.next() & 0xFF) < p_num
    }
}

// ── Part A: randomized property fuzz vs independent invariants ───────────────

#[test]
fn part_a_recovery_property_fuzz() {
    let policies = [
        RecoveryPolicy::Latch,
        RecoveryPolicy::AutoReset { heal_streak: 1 },
        RecoveryPolicy::AutoReset { heal_streak: 3 },
        RecoveryPolicy::AutoReset { heal_streak: 5 },
    ];
    for (pi, &policy) in policies.iter().enumerate() {
        let mut b = RecoveryBreaker::new(policy);
        let mut rng = Rng(0x9E3779B97F4A7C15 ^ (pi as u64 + 1));

        // Independent reference model.
        let mut tripped = false; // has faulted since last rearm
        let mut cc: u64 = 0; // consecutive clean observations since last fault/rearm

        for step in 0..100_000u64 {
            // ~35% fault, ~3% rearm, else clean.
            let faulty = rng.chance(90); // 90/256 ≈ 35%
            let do_rearm = !faulty && rng.chance(8); // 8/256 ≈ 3%

            if do_rearm {
                b.rearm();
                tripped = false;
                cc = 0;
                assert_eq!(b.state(), BreakerState::Closed, "rearm must close (step {step}, policy {pi})");
                assert!(!b.is_isolating());
                continue;
            }

            let state = b.observe(faulty);

            // Update the independent model.
            if faulty {
                tripped = true;
                cc = 0;
            } else {
                cc += 1;
            }

            // Invariant 1: is_isolating() iff not Closed.
            assert_eq!(
                b.is_isolating(),
                state != BreakerState::Closed,
                "isolating must track state (step {step}, policy {pi})"
            );

            // Invariant 2: a fault disconnects immediately.
            if faulty {
                assert_eq!(state, BreakerState::Open, "fault must trip (step {step}, policy {pi})");
                continue;
            }

            // Clean tick: expected state is fully determined by (tripped, cc, policy).
            let expected = if !tripped {
                BreakerState::Closed
            } else {
                match policy {
                    RecoveryPolicy::Latch => BreakerState::Open, // never auto-recovers
                    RecoveryPolicy::AutoReset { heal_streak } => {
                        let s = heal_streak.max(1) as u64;
                        if cc < s {
                            BreakerState::Open // not enough healing yet
                        } else if cc == s {
                            BreakerState::HalfOpen // probing
                        } else {
                            BreakerState::Closed // recovered
                        }
                    }
                }
            };
            assert_eq!(
                state, expected,
                "state mismatch (step {step}, policy {pi:?}, tripped={tripped}, cc={cc})"
            );

            // Once recovered under AutoReset, the model's `tripped` is cleared so
            // the next trip starts a fresh cycle.
            if expected == BreakerState::Closed {
                tripped = false;
            }
        }
    }
}

// ── Part B: disconnect and connect again, repeatedly ─────────────────────────

#[test]
fn part_b_autoreset_cycles_disconnect_and_reconnect() {
    let streak = 2u32;
    let mut b = RecoveryBreaker::new(RecoveryPolicy::AutoReset { heal_streak: streak });
    let cycles = 50;
    let mut reconnects = 0;
    for _ in 0..cycles {
        // Disconnect.
        b.observe(true);
        assert!(b.is_isolating(), "must isolate after fault");
        // Heal: streak ticks to Half-Open, +1 to Closed.
        for _ in 0..streak {
            b.observe(false);
        }
        assert_eq!(b.state(), BreakerState::HalfOpen);
        b.observe(false);
        assert_eq!(b.state(), BreakerState::Closed, "must reconnect after a healthy streak");
        assert!(!b.is_isolating());
        reconnects += 1;
    }
    assert_eq!(reconnects, cycles, "breaker disconnected and reconnected every cycle");
}

#[test]
fn part_b_latch_stays_down_until_rearm_repeatedly() {
    let mut b = RecoveryBreaker::new(RecoveryPolicy::Latch);
    for _ in 0..20 {
        b.observe(true); // trip
        for _ in 0..100 {
            b.observe(false);
            assert!(b.is_isolating(), "latch must NOT auto-reconnect a crypto/money fault");
        }
        b.rearm(); // only manual recovery
        assert!(!b.is_isolating());
    }
}

// ── Part C: end-to-end through each breaker's REAL detect() ──────────────────

/// Drive a surface's recovery breaker with a real faulty→healthy sequence and
/// assert the right reconnect behavior for its policy.
fn drive_end_to_end(surface: BreakerSurface, faulty_tick: bool, healthy_tick: bool) {
    // Sanity: the caller gave us a real faulty and a real healthy detect result.
    assert!(faulty_tick, "the faulty observation must actually trip detect()");
    assert!(!healthy_tick, "the healthy observation must be clean");

    let mut b = RecoveryBreaker::for_surface(surface);
    // Disconnect via a real fault.
    b.observe(faulty_tick);
    assert!(b.is_isolating(), "{surface:?} must isolate on a real fault");

    match recommended_recovery(surface) {
        RecoveryPolicy::Latch => {
            // Crypto/money: never auto-reconnects, even over many clean ticks.
            for _ in 0..50 {
                b.observe(healthy_tick);
                assert!(b.is_isolating(), "{surface:?} (Latch) must stay sealed until rearm");
            }
            b.rearm();
            assert!(!b.is_isolating(), "{surface:?} reconnects only via rearm");
        }
        RecoveryPolicy::AutoReset { heal_streak } => {
            // Load/attack: reconnects after streak+1 healthy ticks.
            for _ in 0..heal_streak {
                b.observe(healthy_tick);
            }
            assert_eq!(b.state(), BreakerState::HalfOpen, "{surface:?} probes after the streak");
            b.observe(healthy_tick);
            assert_eq!(b.state(), BreakerState::Closed, "{surface:?} (AutoReset) reconnects");
            assert!(!b.is_isolating());
        }
    }
}

#[test]
fn part_c_end_to_end_shielded() {
    use coincync::shielded_circuit_breaker as s;
    let healthy = s::PoolObservation {
        pool_value: 1_000,
        total_shielded_in: 1_000,
        expected_from_balance: 1_000,
        ..Default::default()
    };
    let mut faulty = healthy;
    faulty.pool_value = 9_999; // inflation
    drive_end_to_end(
        BreakerSurface::Shielded,
        !s::detect(&faulty).is_empty(),
        !s::detect(&healthy).is_empty(),
    );
}

#[test]
fn part_c_end_to_end_supply() {
    use coincync::supply_breaker as s;
    let healthy = s::SupplyObservation {
        coinbase_payout: 50,
        allowed_emission: 50,
        block_fees: 0,
        total_emitted: 1_000,
        total_burned: 100,
        circulating: 900,
        max_supply: i128::MAX,
        committed_supply: Some(900),
    };
    let mut faulty = healthy;
    faulty.coinbase_payout = 10_000; // over-emission
    drive_end_to_end(
        BreakerSurface::Supply,
        !s::detect(&faulty).is_empty(),
        !s::detect(&healthy).is_empty(),
    );
}

#[test]
fn part_c_end_to_end_mempool() {
    use coincync::mempool_breaker as m;
    let healthy = m::MempoolObservation {
        max_count: 50_000,
        max_bytes: 300_000_000,
        max_arrivals_per_interval: 1_000,
        max_per_peer_arrivals: 100,
        max_dust: 50,
        ..Default::default()
    };
    let mut faulty = healthy;
    faulty.arrivals_this_interval = 1_000_000; // flood
    drive_end_to_end(
        BreakerSurface::Mempool,
        !m::detect(&faulty).is_empty(),
        !m::detect(&healthy).is_empty(),
    );
}

#[test]
fn part_c_end_to_end_p2p() {
    use coincync::p2p_breaker as p;
    let healthy = p::PeerObservation {
        total_peers: 12,
        min_peers: 3,
        distinct_netgroups: 8,
        min_netgroups: 3,
        worst_ip_conns: 1,
        max_conns_per_ip: 2,
        max_stall_blocks: 120,
        handshake_completions: 5,
        ..Default::default()
    };
    let mut faulty = healthy;
    faulty.ibd_target_from_banned = true; // phantom-IBD target
    drive_end_to_end(
        BreakerSurface::P2p,
        !p::detect(&faulty).is_empty(),
        !p::detect(&healthy).is_empty(),
    );
}

#[test]
fn part_c_end_to_end_rpc() {
    use coincync::rpc_breaker as r;
    let healthy = r::RpcObservation {
        max_requests_per_interval: 10_000,
        max_per_client_requests: 500,
        max_expensive_calls: 50,
        max_in_flight: 256,
        max_body_bytes: 1_000_000,
        ..Default::default()
    };
    let mut faulty = healthy;
    faulty.requests_this_interval = 9_999_999; // flood
    drive_end_to_end(
        BreakerSurface::Rpc,
        !r::detect(&faulty).is_empty(),
        !r::detect(&healthy).is_empty(),
    );
}

#[test]
fn part_c_end_to_end_reorg() {
    use coincync::reorg_breaker as r;
    let healthy = r::ReorgObservation {
        reorg_depth: 2,
        max_safe_depth: 100,
        fork_point_height: 10_000,
        finalized_height: 9_800,
        reorgs_in_window: 1,
        max_reorgs_in_window: 10,
        incoming_work_ratio_pct: 101,
        max_work_ratio_pct: 300,
    };
    let mut faulty = healthy;
    faulty.reorg_depth = 5_000; // deep reorg
    drive_end_to_end(
        BreakerSurface::Reorg,
        !r::detect(&faulty).is_empty(),
        !r::detect(&healthy).is_empty(),
    );
}
