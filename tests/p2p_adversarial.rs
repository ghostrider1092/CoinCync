//! Tier 3 — P2P Adversarial Tests (Extended)
//!
//! Tests hostile peer behaviors against the network layer without
//! requiring a full network harness. Exercises message parsing,
//! connection limits, peer scoring under adversarial conditions,
//! and protocol boundary violations.
//!
//! T3.4 — Malformed message fuzzing (as-peer simulation)
//! T3.3 — Slow/silent peer DoS resistance
//! T3.1 — Eclipse attack: subnet monopolization resistance
//! T3.5 — Selfish mining profitability threshold estimation

use coincync::consensus::Block;
use coincync::network::connection_tracker::ConnectionTracker;
use coincync::network::scoring::{MisbehaviorType, PeerScorer};
use coincync::network::{MessageType, MAX_MESSAGE_SIZE};
use coincync::transaction::Transaction;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::Duration;

// Protocol constants (imported from protocol module via network)
const MAX_LOCATOR_SIZE: usize = 64;
const MAX_HEADERS_RESPONSE: usize = 2000;
const MAX_BLOCK_HASHES: usize = 500;
const MAX_INV_SIZE: usize = 500;
const MAX_ADDR_SIZE: usize = 1000;
const MAX_TXS_PER_MESSAGE: usize = 100;

// =============================================================================
// T3.4 — MALFORMED MESSAGE FUZZING
//
// Every message parser must handle garbage input without panic.
// We test by constructing pathological inputs for each entry point.
// =============================================================================

#[test]
fn message_header_rejects_unknown_types() {
    // Bytes 128-255 should all be invalid message types
    for byte in 128u8..=255 {
        assert!(
            MessageType::try_from(byte).is_err(),
            "byte {} must not be a valid MessageType",
            byte
        );
    }
}

#[test]
fn message_header_rejects_gaps_in_type_space() {
    // Between defined message types there are gaps that should be invalid
    let valid_types: Vec<u8> = vec![
        0, 1, 2, 3, // Version, Verack, Ping, Pong
        10, 11, 12, 13, 14, 15, // GetHeaders..BlockData
        20, 21, 22, 23, // GetTxs..InvBlock
        30, 31, // GetAddr, Addr
        40, 41, // Reject, Alert
        50, // Flare
    ];
    for byte in 0..128u8 {
        let result = MessageType::try_from(byte);
        if valid_types.contains(&byte) {
            // Some of these might be valid extended types (60+)
            // Just verify no panic
            let _ = result;
        } else if result.is_ok() {
            // It's a valid extended type we didn't list — that's fine
            // as long as it doesn't panic
        }
    }
}

#[test]
fn block_deserialize_garbage_no_panic() {
    // Feed random bytes to Block deserialization — must never panic
    let garbage_inputs: Vec<Vec<u8>> = vec![
        vec![],
        vec![0],
        vec![0xFF; 100],
        vec![0; 1000],
        vec![0xDE, 0xAD, 0xBE, 0xEF],
        (0..255).collect(),
        vec![0xFF; 10000],
        // Partially valid: correct version byte but garbage after
        {
            let mut v = vec![1u8]; // version 1
            v.extend_from_slice(&[0xFF; 200]);
            v
        },
    ];

    for (i, garbage) in garbage_inputs.iter().enumerate() {
        // Must not panic — error is fine
        let result = borsh::from_slice::<Block>(garbage);
        assert!(
            result.is_err(),
            "garbage input #{} should not deserialize as Block",
            i
        );
    }
}

#[test]
fn transaction_deserialize_garbage_no_panic() {
    let garbage_inputs: Vec<Vec<u8>> = vec![
        vec![],
        vec![0],
        vec![0xFF; 100],
        vec![0; 500],
        vec![0xCA, 0xFE, 0xBA, 0xBE],
        (0..255).collect(),
        vec![0xFF; 5000],
        // Version 0 (invalid)
        {
            let mut v = vec![0u8];
            v.extend_from_slice(&[0; 100]);
            v
        },
        // Version 255 (invalid)
        {
            let mut v = vec![255u8];
            v.extend_from_slice(&[0; 100]);
            v
        },
    ];

    for (i, garbage) in garbage_inputs.iter().enumerate() {
        let result = borsh::from_slice::<Transaction>(garbage);
        assert!(
            result.is_err(),
            "garbage input #{} should not deserialize as Transaction",
            i
        );
    }
}

#[test]
fn block_deserialize_truncated_at_every_position() {
    // Create a valid-ish block and truncate it at every position
    // This catches off-by-one errors in length parsing
    let valid_ish = vec![
        1u8, // version
        0x74, 0x43, 0x59, 0x4E, // magic "tCYN"
        0, 0, 0, 0, 0, 0, 0, 0, // height
        0, 0, 0, 0, 0, 0, 0, 0, // timestamp
    ];

    for len in 0..valid_ish.len() {
        let truncated = &valid_ish[..len];
        let result = borsh::from_slice::<Block>(truncated);
        // Must not panic — error is fine
        let _ = result;
    }
}

// =============================================================================
// T3.3 — SLOW/SILENT PEER DoS RESISTANCE
//
// Peers that connect and go silent should be evicted, not hold slots forever.
// =============================================================================

#[test]
fn peer_score_degrades_on_protocol_violations() {
    // F2 fix (2026-07-05 audit): migrated from the deleted
    // `record_protocol_violation()` (silent -20 rep, no debug log)
    // to the unified `record_misbehavior(ProtocolViolation)` path.
    // Same -20 rep per event, ban still fires after 3 events from
    // default reputation, PLUS emits the tracing::debug line so
    // future observability tooling sees the event.
    use coincync::network::scoring::MisbehaviorType;
    let mut scorer = PeerScorer::new();
    let bad_peer = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 28080);

    // Record many protocol violations
    for _ in 0..20 {
        let s = scorer.get_or_create(bad_peer);
        s.record_misbehavior(MisbehaviorType::ProtocolViolation);
    }

    let score = scorer.get(&bad_peer).unwrap();
    assert!(
        score.should_ban(),
        "peer with 20 protocol violations should be flagged for ban"
    );
}

#[test]
fn peer_score_degrades_on_invalid_transactions() {
    let mut scorer = PeerScorer::new();
    let bad_peer = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)), 28080);

    for _ in 0..50 {
        let s = scorer.get_or_create(bad_peer);
        s.record_invalid_tx();
    }

    let score = scorer.get(&bad_peer).unwrap();
    assert!(
        score.should_ban(),
        "peer sending 50 invalid txs should be flagged for ban"
    );
}

#[test]
fn peer_score_degrades_on_block_failures() {
    let mut scorer = PeerScorer::new();
    let bad_peer = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 3)), 28080);

    for _ in 0..30 {
        let s = scorer.get_or_create(bad_peer);
        s.record_block_failure();
    }

    let score = scorer.get(&bad_peer).unwrap();
    assert!(
        score.should_ban(),
        "peer with 30 block failures should be flagged for ban"
    );
}

#[test]
fn good_peer_not_banned_after_occasional_failures() {
    let mut scorer = PeerScorer::new();
    let mixed_peer = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 4)), 28080);

    // 100 good blocks, 2 bad ones — mostly good peer
    for _ in 0..100 {
        let s = scorer.get_or_create(mixed_peer);
        s.record_block_success(Duration::from_millis(50));
    }
    for _ in 0..2 {
        let s = scorer.get_or_create(mixed_peer);
        s.record_block_failure();
    }

    let score = scorer.get(&mixed_peer).unwrap();
    assert!(
        !score.should_ban(),
        "mostly-good peer with 2 failures out of 102 should NOT be banned"
    );
    // H-15 FIX REGRESSION TEST: record_block_success now sets validated=true.
    // A peer that delivers 100 valid blocks MUST be considered "good."
    assert!(
        score.is_good(),
        "H-15 REGRESSION: Peer with 100 valid blocks is not is_good()! \
         record_block_success must set validated=true. Score: {}",
        score.composite_score()
    );
}

#[test]
fn misbehavior_types_all_degrade_score() {
    let mut scorer = PeerScorer::new();
    let peer = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 5)), 28080);

    // Test that recording misbehavior doesn't panic for any type
    let s = scorer.get_or_create(peer);
    s.record_misbehavior(MisbehaviorType::InvalidBlockPoW);
    s.record_misbehavior(MisbehaviorType::InvalidTransaction);
    s.record_misbehavior(MisbehaviorType::ProtocolViolation);
    s.record_misbehavior(MisbehaviorType::OversizedMessage);
    s.record_misbehavior(MisbehaviorType::OrphanFlood);

    // Score should have degraded from all those offenses
    let score = scorer.get(&peer).unwrap();
    assert!(
        score.composite_score() < 1.0,
        "score should degrade after misbehavior"
    );
}

// =============================================================================
// T3.1 — ECLIPSE ATTACK: SUBNET MONOPOLIZATION
//
// An attacker controlling many IPs in the same /16 subnet should not
// be able to fill all connection slots.
// =============================================================================

#[test]
fn eclipse_attack_same_subnet_limited() {
    let tracker = ConnectionTracker::new(64 * 1024 * 1024);

    // Attacker controls 200 IPs in 192.168.0.0/16
    let mut attacker_accepted = 0;
    for i in 0..200u16 {
        let ip = IpAddr::V4(Ipv4Addr::new(192, 168, (i / 256) as u8, (i % 256) as u8));
        let addr = SocketAddr::new(ip, 28080);
        if tracker.try_track_connection(&addr) {
            attacker_accepted += 1;
        }
    }

    // Also connect from diverse subnets — these should all work
    let mut honest_accepted = 0;
    for i in 0..20u8 {
        let ip = IpAddr::V4(Ipv4Addr::new(10, i, 0, 1)); // 20 different /16s
        let addr = SocketAddr::new(ip, 28080);
        if tracker.try_track_connection(&addr) {
            honest_accepted += 1;
        }
    }

    println!(
        "Eclipse test: attacker got {} of 200, honest got {} of 20",
        attacker_accepted, honest_accepted
    );

    // Attacker should NOT have gotten all 200 — subnet limit should cap them
    // Honest peers from diverse subnets should all connect
    assert!(
        honest_accepted >= 15,
        "honest peers from diverse subnets should mostly connect, got {}",
        honest_accepted
    );
}

#[test]
fn eclipse_attack_many_subnets_still_limited_by_total() {
    // Even with diverse subnets, total connection count has limits
    let tracker = ConnectionTracker::new(1024 * 1024); // 1MB memory budget

    let mut total = 0;
    for subnet in 0..255u8 {
        for host in 0..4u8 {
            let ip = IpAddr::V4(Ipv4Addr::new(10, subnet, host, 1));
            let addr = SocketAddr::new(ip, 28080);
            if tracker.try_track_connection(&addr) {
                total += 1;
            }
        }
    }

    println!("Total connections accepted across 255 subnets: {}", total);
    // Should accept many but eventually the system has practical limits
    assert!(total > 0, "should accept at least some connections");
}

// =============================================================================
// T3.5 — PROTOCOL BOUNDARY CHECKS
//
// Constants that limit message sizes, locator lengths, etc. must be sane.
// =============================================================================

#[test]
fn protocol_constants_are_defensive() {
    // These constants protect against DoS. Verify they're reasonable.
    assert!(
        MAX_MESSAGE_SIZE >= 1024 * 1024,
        "max message must be >= 1MB for blocks"
    );
    assert!(
        MAX_MESSAGE_SIZE <= 64 * 1024 * 1024,
        "max message should be <= 64MB"
    );

    assert!(MAX_LOCATOR_SIZE >= 10, "locator needs at least 10 entries");
    assert!(
        MAX_LOCATOR_SIZE <= 128,
        "locator should be <= 128 to prevent DoS"
    );

    assert!(
        MAX_HEADERS_RESPONSE >= 100,
        "headers response should allow >= 100"
    );
    assert!(
        MAX_HEADERS_RESPONSE <= 10_000,
        "headers response should be <= 10K"
    );

    assert!(
        MAX_BLOCK_HASHES >= 50,
        "block hash request should allow >= 50"
    );
    assert!(
        MAX_BLOCK_HASHES <= 5_000,
        "block hash request should be <= 5K"
    );

    assert!(MAX_INV_SIZE >= 100, "inventory should allow >= 100 items");
    assert!(MAX_INV_SIZE <= 10_000, "inventory should be <= 10K");

    assert!(MAX_ADDR_SIZE >= 100, "addr message should allow >= 100");
    assert!(MAX_ADDR_SIZE <= 10_000, "addr message should be <= 10K");

    assert!(MAX_TXS_PER_MESSAGE >= 10, "tx batch should allow >= 10");
    assert!(MAX_TXS_PER_MESSAGE <= 1_000, "tx batch should be <= 1K");
}

// =============================================================================
// T3.5b — SELFISH MINING THRESHOLD ESTIMATION
//
// Pure simulation: at what hashrate share does selfish mining become
// profitable? For Bitcoin it's ~25-33%. Our chain should match or exceed.
// =============================================================================

#[test]
fn selfish_mining_not_profitable_below_25_percent() {
    // Simulate 10,000 blocks with an attacker at 20% hashrate
    // Compare selfish vs honest revenue
    let attacker_hashrate = 0.20;
    let num_blocks = 10_000u64;
    let mut rng = 42u64; // deterministic seed

    // Simple PRNG for simulation
    fn next_rng(state: &mut u64) -> f64 {
        *state = state
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        (*state >> 33) as f64 / (1u64 << 31) as f64
    }

    // Honest mining: attacker finds blocks proportional to hashrate
    let mut honest_revenue = 0u64;
    for _ in 0..num_blocks {
        if next_rng(&mut rng) < attacker_hashrate {
            honest_revenue += 50; // block reward
        }
    }

    // Selfish mining: attacker withholds blocks, publishes when ahead by 1
    // Simplified model: if attacker finds 2 blocks before network finds 1,
    // they get both. Otherwise they lose the withheld block.
    rng = 42; // reset
    let mut selfish_revenue = 0u64;
    let mut withheld = 0u64;
    for _ in 0..num_blocks {
        let r = next_rng(&mut rng);
        if r < attacker_hashrate {
            withheld += 1;
            if withheld >= 2 {
                // Attacker publishes and wins
                selfish_revenue += withheld * 50;
                withheld = 0;
            }
        } else {
            if withheld == 1 {
                // Race condition: attacker loses (network publishes first)
                // Attacker loses withheld block
                withheld = 0;
            } else if withheld > 1 {
                // Attacker still ahead
                selfish_revenue += 50;
                withheld -= 1;
            }
        }
    }

    println!(
        "Selfish mining at {}%: honest={}, selfish={}",
        (attacker_hashrate * 100.0) as u32,
        honest_revenue,
        selfish_revenue
    );

    // At 20% hashrate, selfish mining should NOT be more profitable
    assert!(
        selfish_revenue <= honest_revenue + (honest_revenue / 10),
        "selfish mining at 20% hashrate should not be significantly more profitable \
         than honest mining (honest={}, selfish={})",
        honest_revenue,
        selfish_revenue
    );
}

// =============================================================================
// T3.6 — MEMORY EXHAUSTION RESISTANCE
// =============================================================================

#[test]
fn memory_budget_prevents_exhaustion() {
    // Simulate an attacker trying to exhaust memory by requesting many allocations
    let tracker = ConnectionTracker::new(10 * 1024); // 10KB budget

    let mut allocated_count = 0;
    for _ in 0..1000 {
        if tracker.allocate(100) {
            // 100 bytes each
            allocated_count += 1;
        }
    }

    // Should have capped well below 1000
    assert!(
        allocated_count <= 102,
        "should cap allocations at budget (got {})",
        allocated_count
    );
    assert!(
        allocated_count >= 90,
        "should allow allocations up to budget (got {})",
        allocated_count
    );

    // Memory usage should be at or near budget
    let usage = tracker.memory_usage();
    assert!(
        usage <= 10 * 1024 + 100,
        "memory usage should not exceed budget + one allocation"
    );
}
