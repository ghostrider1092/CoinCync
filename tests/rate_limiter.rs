//! Tests for PeerMessageRateTracker (per-peer message rate limiting).
//!
//! Validates that the rate tracker correctly:
//! - Allows messages under the limit
//! - Detects and flags messages over the limit
//! - Resets after the window expires
//! - Handles multiple message types independently

use coincync::network::protocol::MessageType;
use coincync::network::PeerMessageRateTracker;

// F21 fix (2026-07-05 audit): use ACTUAL `#[repr(u8)]` discriminants
// from `network::protocol::MessageType`, not hand-picked hex values.
// Pre-audit these consts were `0x01` (Verack, not Version!), `0x03`
// (Pong, not GetHeaders!), `0x09` (undefined, not InvTx!). The tests
// still passed because the tracker mechanics fired on ANY consistent
// u8 within its limits table — but the tests proved nothing about
// real per-message-type rate limiting. Post-fix these tie back to the
// enum so a future refactor of `MessageType` variants forces the
// tests to update in lockstep. Same pattern locked by the unit tests
// `msg_rate_limits_use_real_msg_type_discriminants` and
// `msg_rate_limits_cover_the_attacker_amplification_types` inside
// scoring.rs.
const MSG_VERSION: u8 = MessageType::Version as u8; // 0  — Limit: 50 per 10s window
const MSG_GET_HEADERS: u8 = MessageType::GetHeaders as u8; // 10 — Limit: 100 per 10s
const MSG_INV_TX: u8 = MessageType::InvTx as u8; // 22 — Limit: 500 per 10s

#[test]
fn test_under_limit_not_flagged() {
    let mut tracker = PeerMessageRateTracker::new();

    // Send 49 Version messages (limit is 50) — all should pass
    for _ in 0..49 {
        assert!(
            !tracker.record(MSG_VERSION).over_limit,
            "Should not flag under-limit messages"
        );
    }
}

#[test]
fn test_at_limit_flagged() {
    let mut tracker = PeerMessageRateTracker::new();

    // Send exactly 50 Version messages — 50th is at limit, 51st exceeds
    for i in 0..50 {
        let flagged = tracker.record(MSG_VERSION).over_limit;
        assert!(
            !flagged,
            "Message {} should not be flagged (limit is 50)",
            i + 1
        );
    }

    // 51st message should be flagged
    assert!(
        tracker.record(MSG_VERSION).over_limit,
        "Message 51 should exceed the limit"
    );
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
        assert!(
            !tracker.record(MSG_GET_HEADERS).over_limit,
            "GetHeaders should not be flagged"
        );
    }

    // Version is still under limit — 50th is ok
    assert!(
        !tracker.record(MSG_VERSION).over_limit,
        "50th Version should not be flagged"
    );

    // 51st Version exceeds
    assert!(
        tracker.record(MSG_VERSION).over_limit,
        "51st Version should be flagged"
    );

    // GetHeaders 100th is ok, 101st exceeds
    assert!(
        !tracker.record(MSG_GET_HEADERS).over_limit,
        "100th GetHeaders should not be flagged"
    );
    assert!(
        tracker.record(MSG_GET_HEADERS).over_limit,
        "101st GetHeaders should be flagged"
    );
}

#[test]
fn test_window_reset() {
    let mut tracker = PeerMessageRateTracker::new();

    // Fill exactly to the limit (50): none over the limit yet.
    for _ in 0..50 {
        assert!(!tracker.record(MSG_VERSION).over_limit);
    }
    // The 51st exceeds the limit: it is `over_limit` (the caller DROPS it) AND
    // the first over-limit message this window, so it also `penalize`s.
    let first = tracker.record(MSG_VERSION);
    assert!(first.over_limit, "first over-limit message must be dropped");
    assert!(first.penalize, "first over-limit message must penalize");

    // A FURTHER over-limit message in the SAME window is STILL `over_limit`
    // (dropped) but is NOT penalized again. This is the drop-every /
    // penalize-once split: collapsing them (as ccbf066 did) let every message
    // after the first flow through, disabling the rate limit.
    let second = tracker.record(MSG_VERSION);
    assert!(
        second.over_limit,
        "every over-limit message must be dropped, not just the first"
    );
    assert!(
        !second.penalize,
        "the warn+penalty must fire at most once per window"
    );

    // Wait for the 10-second window to expire (tracker uses a 10s window
    // internally; we exercise the real wall-clock reset path here).
    std::thread::sleep(std::time::Duration::from_secs(11));

    // After window reset, both the counter and the flag clear, so messages
    // are accepted (and unflagged) again.
    let after = tracker.record(MSG_VERSION);
    assert!(!after.over_limit, "should accept messages after window reset");
    assert!(!after.penalize);
}

#[test]
fn test_unknown_type_not_rate_limited() {
    let mut tracker = PeerMessageRateTracker::new();

    // Message type 0xFF is not in MSG_RATE_LIMITS — should never be flagged
    for _ in 0..1000 {
        assert!(
            !tracker.record(0xFF).over_limit,
            "Unknown message type should not be rate limited"
        );
    }
}

#[test]
fn test_inv_tx_high_limit() {
    let mut tracker = PeerMessageRateTracker::new();

    // InvTx has a high limit (500 per 10s) — verify it tolerates burst
    for _ in 0..500 {
        assert!(
            !tracker.record(MSG_INV_TX).over_limit,
            "InvTx within 500 limit should pass"
        );
    }

    // 501st should exceed
    assert!(
        tracker.record(MSG_INV_TX).over_limit,
        "501st InvTx should be flagged"
    );
}

#[test]
fn test_default_impl() {
    // PeerMessageRateTracker implements Default
    let tracker = PeerMessageRateTracker::default();
    assert_eq!(
        std::mem::size_of_val(&tracker),
        std::mem::size_of::<PeerMessageRateTracker>()
    );
}
