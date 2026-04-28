//! Tests for PeerMessageRateTracker (per-peer message rate limiting).
//!
//! Validates that the rate tracker correctly:
//! - Allows messages under the limit
//! - Detects and flags messages over the limit
//! - Resets after the window expires
//! - Handles multiple message types independently

use coincync::network::PeerMessageRateTracker;

// Message type IDs (from scoring.rs MSG_RATE_LIMITS)
const MSG_VERSION: u8 = 0x01;     // Limit: 50 per 10s window
const MSG_GET_HEADERS: u8 = 0x03; // Limit: 100 per 10s
const MSG_INV_TX: u8 = 0x09;      // Limit: 500 per 10s

#[test]
fn test_under_limit_not_flagged() {
    let mut tracker = PeerMessageRateTracker::new();

    // Send 49 Version messages (limit is 50) — all should pass
    for _ in 0..49 {
        assert!(!tracker.record(MSG_VERSION), "Should not flag under-limit messages");
    }
}

#[test]
fn test_at_limit_flagged() {
    let mut tracker = PeerMessageRateTracker::new();

    // Send exactly 50 Version messages — 50th is at limit, 51st exceeds
    for i in 0..50 {
        let flagged = tracker.record(MSG_VERSION);
        assert!(!flagged, "Message {} should not be flagged (limit is 50)", i + 1);
    }

    // 51st message should be flagged
    assert!(tracker.record(MSG_VERSION), "Message 51 should exceed the limit");
}

#[test]
fn test_different_types_independent() {
    let mut tracker = PeerMessageRateTracker::new();

    // Send 49 Version messages (under limit of 50)
    for _ in 0..49 {
        tracker.record(MSG_VERSION);
    }

    // Send 99 GetHeaders messages (under limit of 100)
    for _ in 0..99 {
        assert!(!tracker.record(MSG_GET_HEADERS), "GetHeaders should not be flagged");
    }

    // Version is still under limit — 50th is ok
    assert!(!tracker.record(MSG_VERSION), "50th Version should not be flagged");

    // 51st Version exceeds
    assert!(tracker.record(MSG_VERSION), "51st Version should be flagged");

    // GetHeaders 100th is ok, 101st exceeds
    assert!(!tracker.record(MSG_GET_HEADERS), "100th GetHeaders should not be flagged");
    assert!(tracker.record(MSG_GET_HEADERS), "101st GetHeaders should be flagged");
}

#[test]
fn test_window_reset() {
    let mut tracker = PeerMessageRateTracker::new();

    // Exceed the limit
    for _ in 0..51 {
        tracker.record(MSG_VERSION);
    }
    assert!(tracker.record(MSG_VERSION), "Should be flagged after exceeding limit");

    // Wait for window to expire (tracker uses 10-second window internally;
    // we simulate by sleeping). In production this is ~10s but for tests
    // we just verify the API contract.
    std::thread::sleep(std::time::Duration::from_secs(11));

    // After window reset, messages should be accepted again
    assert!(!tracker.record(MSG_VERSION), "Should accept messages after window reset");
}

#[test]
fn test_unknown_type_not_rate_limited() {
    let mut tracker = PeerMessageRateTracker::new();

    // Message type 0xFF is not in MSG_RATE_LIMITS — should never be flagged
    for _ in 0..1000 {
        assert!(!tracker.record(0xFF), "Unknown message type should not be rate limited");
    }
}

#[test]
fn test_inv_tx_high_limit() {
    let mut tracker = PeerMessageRateTracker::new();

    // InvTx has a high limit (500 per 10s) — verify it tolerates burst
    for _ in 0..500 {
        assert!(!tracker.record(MSG_INV_TX), "InvTx within 500 limit should pass");
    }

    // 501st should exceed
    assert!(tracker.record(MSG_INV_TX), "501st InvTx should be flagged");
}

#[test]
fn test_default_impl() {
    // PeerMessageRateTracker implements Default
    let tracker = PeerMessageRateTracker::default();
    assert_eq!(std::mem::size_of_val(&tracker), std::mem::size_of::<PeerMessageRateTracker>());
}
