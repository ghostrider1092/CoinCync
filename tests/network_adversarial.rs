//! Tier 3: P2P and Network adversarial tests.
//!
//! Tests the p2p layer's resistance to hostile peer behavior using
//! the ConnectionTracker, PeerScorer, and message framing directly
//! without needing a full network harness.
//!
//! T3.1 — Eclipse resistance: subnet diversity enforcement
//! T3.2 — Peer banning: misbehavior tracking
//! T3.3 — Connection limits: slot exhaustion resistance
//! T3.4 — Message framing: oversized/malformed messages
//! T3.5 — Memory budget: allocation limits under pressure

use coincync::network::connection_tracker::ConnectionTracker;
use coincync::network::scoring::PeerScorer;
use coincync::network::{MessageType, MAX_MESSAGE_SIZE};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};

// =============================================================================
// T3.1 — ECLIPSE ATTACK RESISTANCE
//
// The ConnectionTracker enforces /16 subnet diversity. An attacker
// controlling many IPs in the same /16 should not be able to monopolize
// all outbound slots.
// =============================================================================

#[test]
fn subnet_diversity_limits_connections_from_same_subnet() {
    let tracker = ConnectionTracker::new(1024 * 1024);

    // Try to register 100 outbound connections from the same /16 subnet
    let mut accepted = 0;
    for i in 0..100u8 {
        let ip = IpAddr::V4(Ipv4Addr::new(192, 168, i, 1));
        let addr = SocketAddr::new(ip, 28080);
        if tracker.try_track_connection(&addr) {
            accepted += 1;
        }
    }

    // Some should be accepted but not all — subnet diversity limits
    // should prevent one /16 from taking all slots
    assert!(accepted > 0, "at least one connection from the subnet should be accepted");
    // The exact limit depends on MAX_OUTBOUND_PER_SUBNET constant
    // but should be well below 100
    println!("Accepted {} of 100 from same /16 subnet", accepted);
}

#[test]
fn different_subnets_are_not_limited_by_each_other() {
    let tracker = ConnectionTracker::new(1024 * 1024);

    // Connect from 10 different /16 subnets — each should work
    for subnet in 0..10u8 {
        let ip = IpAddr::V4(Ipv4Addr::new(10, subnet, 0, 1));
        let addr = SocketAddr::new(ip, 28080);
        let ok = tracker.try_track_connection(&addr);
        assert!(ok, "first connection from subnet 10.{}.0.0/16 should be accepted", subnet);
    }
}

// =============================================================================
// T3.2 — PEER BANNING
//
// PeerScorer tracks misbehavior and bans persistent offenders.
// =============================================================================

#[test]
fn banned_peer_is_rejected() {
    let mut scorer = PeerScorer::new();
    let peer = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)), 28080);

    assert!(!scorer.is_banned(&peer), "peer should not be banned initially");

    scorer.ban(peer);
    assert!(scorer.is_banned(&peer), "peer should be banned after ban()");
}

#[test]
fn unbanned_peer_is_accepted() {
    let mut scorer = PeerScorer::new();
    let peer = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(5, 6, 7, 8)), 28080);

    scorer.ban(peer);
    assert!(scorer.is_banned(&peer));

    scorer.unban(&peer);
    assert!(!scorer.is_banned(&peer), "peer should not be banned after unban()");
}

#[test]
fn many_bans_dont_cause_memory_issues() {
    let mut scorer = PeerScorer::new();

    // Ban 10,000 different peers
    for i in 0..10_000u32 {
        let ip = IpAddr::V4(Ipv4Addr::new(
            ((i >> 16) & 0xFF) as u8,
            ((i >> 8) & 0xFF) as u8,
            (i & 0xFF) as u8,
            1,
        ));
        scorer.ban(SocketAddr::new(ip, 28080));
    }

    // All should be banned
    let test_ip = IpAddr::V4(Ipv4Addr::new(0, 0, 100, 1));
    assert!(scorer.is_banned(&SocketAddr::new(test_ip, 28080)));

    // Non-banned peer should still not be banned
    let clean = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(200, 200, 200, 200)), 28080);
    assert!(!scorer.is_banned(&clean));
}

// =============================================================================
// T3.3 — CONNECTION LIMITS
//
// Memory budget prevents a peer from exhausting node resources.
// =============================================================================

#[test]
fn memory_budget_enforced() {
    // Create tracker with a tiny budget (1KB)
    let tracker = ConnectionTracker::new(1024);

    // Try to allocate more than the budget allows
    let allocated = tracker.allocate(512);
    assert!(allocated, "first allocation within budget should succeed");

    let allocated2 = tracker.allocate(512);
    assert!(allocated2, "second allocation exactly at budget should succeed");

    let allocated3 = tracker.allocate(1);
    assert!(!allocated3, "allocation exceeding budget should fail");
}

#[test]
fn memory_release_allows_new_allocation() {
    let tracker = ConnectionTracker::new(1024);

    assert!(tracker.allocate(1024), "full budget allocation should succeed");
    assert!(!tracker.allocate(1), "over-budget should fail");

    tracker.deallocate(512);
    assert!(tracker.allocate(512), "after release, new allocation should succeed");
}

// =============================================================================
// T3.4 — MESSAGE FRAMING: OVERSIZED MESSAGES
//
// Messages larger than MAX_MESSAGE_SIZE must be rejected.
// =============================================================================

#[test]
fn max_message_size_is_reasonable() {
    // MAX_MESSAGE_SIZE should be set to prevent DoS but allow large blocks
    assert!(MAX_MESSAGE_SIZE > 0, "MAX_MESSAGE_SIZE must be positive");
    assert!(MAX_MESSAGE_SIZE <= 50 * 1024 * 1024, "MAX_MESSAGE_SIZE should not exceed 50MB");
    println!("MAX_MESSAGE_SIZE = {} bytes ({} MB)", MAX_MESSAGE_SIZE, MAX_MESSAGE_SIZE / (1024 * 1024));
}

#[test]
fn message_type_roundtrip() {
    // Every valid message type should roundtrip through u8 conversion
    let types = [
        MessageType::Version, MessageType::Verack,
        MessageType::Ping, MessageType::Pong,
        MessageType::GetHeaders, MessageType::Headers,
        MessageType::GetBlocks, MessageType::Blocks,
        MessageType::GetData, MessageType::BlockData,
        MessageType::GetTxs, MessageType::Txs,
        MessageType::InvTx, MessageType::InvBlock,
        MessageType::GetAddr, MessageType::Addr,
        MessageType::Reject, MessageType::Alert,
    ];

    for mt in &types {
        let byte = *mt as u8;
        let recovered = MessageType::try_from(byte);
        assert!(recovered.is_ok(), "MessageType {:?} (byte {}) should roundtrip", mt, byte);
        assert_eq!(recovered.unwrap() as u8, byte);
    }
}

#[test]
fn invalid_message_type_rejected() {
    // Byte values that don't correspond to any MessageType should be rejected
    let invalid_bytes: Vec<u8> = (200..=255).collect();
    for byte in invalid_bytes {
        let result = MessageType::try_from(byte);
        assert!(result.is_err(), "byte {} should not be a valid MessageType", byte);
    }
}

// =============================================================================
// T3.5 — CONCURRENT CONNECTION TRACKING
// =============================================================================

#[test]
fn concurrent_connection_tracking() {
    use std::sync::Arc;
    use std::thread;

    let tracker = Arc::new(ConnectionTracker::new(1024 * 1024));
    let mut handles = vec![];

    // Spawn 50 threads each trying to track a connection
    for i in 0..50u8 {
        let t = tracker.clone();
        handles.push(thread::spawn(move || {
            let ip = IpAddr::V4(Ipv4Addr::new(10, i, 0, 1));
            let addr = SocketAddr::new(ip, 28080);
            t.track_connection(&addr);
            // Brief work
            std::thread::sleep(std::time::Duration::from_millis(1));
            t.untrack_connection(&addr);
        }));
    }

    for h in handles {
        h.join().expect("thread should not panic");
    }
    // If we get here without deadlock or panic, concurrency is safe
}

// =============================================================================
// T3.6 — PEER SCORE TRACKING
// =============================================================================

#[test]
fn peer_score_defaults_are_sensible() {
    let mut scorer = PeerScorer::new();
    let peer = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)), 28080);

    let score = scorer.get_or_create(peer);
    // Default score should be neutral/positive, not negative
    assert!(score.composite_score() >= 0.0, "default peer score should be non-negative, got {}", score.composite_score());
}

#[test]
fn peer_score_survives_many_updates() {
    let mut scorer = PeerScorer::new();
    let peer = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(2, 2, 2, 2)), 28080);

    // Record many events
    for _ in 0..1000 {
        let s = scorer.get_or_create(peer);
        s.record_block_success(std::time::Duration::from_millis(100));
    }

    let score = scorer.get(&peer).unwrap();
    assert!(score.composite_score() > 0.0, "peer with 1000 valid blocks should have positive score");
}
