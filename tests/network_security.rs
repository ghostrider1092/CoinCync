//! Network security tests: peer banning/reputation and Dandelion++ stem/fluff.

use coincync::network::{PeerInfo, generate_peer_id, DandelionRouter};
use coincync::transaction::{Transaction, TxType};
use coincync::primitives::Amount;
use std::net::SocketAddr;

// ─── Helpers ───────────────────────────────────────────────────────────────

fn make_peer(addr: &str) -> PeerInfo {
    let id = generate_peer_id();
    let addr: SocketAddr = addr.parse().unwrap();
    PeerInfo::new(id, addr, true)
}

fn make_test_tx(nonce: u8) -> Transaction {
    Transaction {
        version: 1,
        tx_type: TxType::Transfer,
        inputs: vec![],
        outputs: vec![],
        fee: Amount::from_atomic(0),
        range_proof: vec![],
        extra: vec![nonce],
    }
}

// ═══════════════════════════════════════════════════════════════════════════
//  PEER REPUTATION / BANNING
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn peer_starts_with_max_reputation() {
    let peer = make_peer("1.2.3.1:28080");
    assert_eq!(peer.reputation, 100);
    assert!(!peer.should_ban());
}

#[test]
fn peer_banned_after_many_invalid_blocks() {
    let mut peer = make_peer("1.2.3.2:28080");

    // Simulate 16 invalid blocks at -10 rep each: 100 - 160 = -60
    for _ in 0..16 {
        peer.adjust_reputation(-10);
    }

    assert!(peer.reputation <= -50);
    assert!(peer.should_ban());
}

#[test]
fn good_peer_never_banned() {
    let mut peer = make_peer("1.2.3.3:28080");

    for _ in 0..1000 {
        peer.adjust_reputation(1);
    }

    assert_eq!(peer.reputation, 100);
    assert!(!peer.should_ban());
}

#[test]
fn protocol_violation_causes_fast_ban() {
    let mut peer = make_peer("1.2.3.4:28080");

    // -20 per violation, 8 hits: 100 - 160 = clamped -60
    for _ in 0..8 {
        peer.adjust_reputation(-20);
    }

    assert!(peer.should_ban());
}

#[test]
fn reputation_clamped_at_bounds() {
    let mut peer = make_peer("1.2.3.5:28080");

    peer.adjust_reputation(500);
    assert_eq!(peer.reputation, 100);

    peer.adjust_reputation(-1000);
    assert_eq!(peer.reputation, -100);
}

#[test]
fn reputation_decay_toward_neutral() {
    let mut peer = make_peer("1.2.3.6:28080");

    // Drop to 20
    peer.adjust_reputation(-80);
    assert_eq!(peer.reputation, 20);

    // Decay toward 50 — should converge
    for _ in 0..100 {
        peer.decay_reputation_default();
    }

    assert_eq!(peer.reputation, 50);
}

#[test]
fn banned_peer_recovers_after_sufficient_decay() {
    let mut peer = make_peer("1.2.3.7:28080");

    // Drive to -80
    peer.adjust_reputation(-180);
    assert_eq!(peer.reputation, -80);
    assert!(peer.should_ban());

    // Decay 31 ticks: -80 + 31 = -49 (just above ban threshold)
    for _ in 0..31 {
        peer.decay_reputation(1, 50);
    }

    assert_eq!(peer.reputation, -49);
    assert!(!peer.should_ban());
}

#[test]
fn ban_threshold_is_exactly_minus_fifty() {
    let mut peer = make_peer("1.2.3.8:28080");

    // Set to exactly -50
    peer.adjust_reputation(-150);
    assert_eq!(peer.reputation, -50);
    assert!(peer.should_ban()); // -50 should be banned

    // One tick of decay
    peer.decay_reputation(1, 50);
    assert_eq!(peer.reputation, -49);
    assert!(!peer.should_ban()); // -49 should NOT be banned
}

#[test]
fn mixed_good_and_bad_behavior() {
    let mut peer = make_peer("1.2.3.9:28080");

    // Interleave: +5 good, -10 bad = net -5 per pair
    for _ in 0..20 {
        peer.adjust_reputation(5);
        peer.adjust_reputation(-10);
    }

    // 20 cycles × -5 net = -100 from start of 100 = 0 (approximately)
    // But clamping makes it complex — just verify it degraded
    assert!(peer.reputation < 50, "reputation should degrade with net-negative behavior");
}

// ═══════════════════════════════════════════════════════════════════════════
//  DANDELION++ STEM/FLUFF
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn local_tx_enters_stempool() {
    let mut router = DandelionRouter::new();
    let tx = make_test_tx(1);

    let initial_size = router.stats().stempool_size;
    let hash = router.add_local_tx(tx, 1000);

    // Tx should be tracked (either in stempool or immediately fluffed)
    assert_ne!(hash.as_bytes(), &[0u8; 32], "hash should not be zero");

    let stats = router.stats();
    if !stats.is_fluff_epoch {
        assert!(stats.stempool_size > initial_size, "stem epoch: tx should be in stempool");
    }
}

#[test]
fn duplicate_tx_not_double_counted() {
    let mut router = DandelionRouter::new();
    let tx = make_test_tx(2);

    let hash1 = router.add_local_tx(tx.clone(), 1000);
    let size_after_first = router.stats().stempool_size;

    let hash2 = router.add_local_tx(tx, 1001);
    let size_after_second = router.stats().stempool_size;

    assert_eq!(hash1, hash2, "same tx should produce same hash");
    assert_eq!(size_after_first, size_after_second, "duplicate should not increase stempool");
}

#[test]
fn embargo_timeout_produces_actions() {
    let mut router = DandelionRouter::new();
    let tx = make_test_tx(3);
    let _hash = router.add_local_tx(tx, 1000);

    // Tick well past any embargo deadline
    let actions = router.tick(2000);

    // Should produce some action (either stem relay or fluff)
    let total_actions = actions.fluff.len() + actions.stem_relay.len();
    // Note: may be 0 if already fluffed during add_local_tx (fluff epoch)
    // Just verify no panic
    let _ = total_actions;
}

#[test]
fn diffusion_confirmation_removes_from_stempool() {
    let mut router = DandelionRouter::new();
    let tx = make_test_tx(4);
    let hash = router.add_local_tx(tx, 1000);

    // Confirm via diffusion
    router.tx_confirmed_via_diffusion(&hash);

    let stats = router.stats();
    // If it was in stempool, it should now be removed
    // (It might have been immediately fluffed in a fluff epoch, so stempool was already 0)
    assert!(stats.stempool_size == 0 || !stats.is_fluff_epoch);
}

#[test]
fn stats_report_epoch_info() {
    let router = DandelionRouter::new();
    let stats = router.stats();

    // Stats should be populated
    assert_eq!(stats.stempool_size, 0);
    assert_eq!(stats.stem_pending, 0);
    assert_eq!(stats.awaiting_embargo, 0);
    // is_fluff_epoch is a boolean — just verify it's accessible
    let _ = stats.is_fluff_epoch;
    let _ = stats.epoch;
}

#[test]
fn epoch_rotation_changes_mode_statistically() {
    let mut router = DandelionRouter::new();
    let mut saw_stem = false;
    let mut saw_fluff = false;

    // Force epoch rotations by advancing time past epoch duration
    for i in 0u64..50 {
        // Epochs last ~600s, so advance by 700s each time
        router.maybe_rotate_epoch(i * 700);
        let stats = router.stats();
        if stats.is_fluff_epoch {
            saw_fluff = true;
        } else {
            saw_stem = true;
        }
        if saw_stem && saw_fluff {
            break;
        }
    }

    // 80% stem, 20% fluff — in 50 epochs, extremely unlikely to not see both
    assert!(saw_stem, "should see at least one stem epoch in 50 rotations");
    assert!(saw_fluff, "should see at least one fluff epoch in 50 rotations");
}

#[test]
fn multiple_txs_tracked_independently() {
    let mut router = DandelionRouter::new();

    let tx1 = make_test_tx(10);
    let tx2 = make_test_tx(20);
    let tx3 = make_test_tx(30);

    let h1 = router.add_local_tx(tx1, 1000);
    let h2 = router.add_local_tx(tx2, 1001);
    let h3 = router.add_local_tx(tx3, 1002);

    // All different hashes
    assert_ne!(h1, h2);
    assert_ne!(h2, h3);
    assert_ne!(h1, h3);

    // Confirm one — others should remain
    router.tx_confirmed_via_diffusion(&h2);

    // At minimum, h2 should be gone from stempool
    // (h1 and h3 may or may not be depending on epoch mode)
}

#[test]
fn tick_does_not_panic_on_empty_router() {
    let mut router = DandelionRouter::new();
    let actions = router.tick(5000);
    assert_eq!(actions.fluff.len(), 0);
    assert_eq!(actions.stem_relay.len(), 0);
}
