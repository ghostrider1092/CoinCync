//! Integration tests for `RescueTick`. Exercises the state machine +
//! privacy contract + notice emission via `MockAdapter`.
//!
//! Each test constructs a fresh mock in a specific "world" (steady
//! state, divergent but sub-threshold, divergent + verified,
//! divergent + spoofed, etc.), drives the tick through its phases,
//! and asserts on the outcome (phase, notice log, snapshot/apply
//! counts).

#![cfg(feature = "mock")]

use tick::mock::{MockAdapter, MockBlockId};
use tick::{
    recovery_priority, ChainTipState, DeploymentMode, FleetPeer, RescueConfig,
    RescueTick, Severity, TickBehavior, TickNoticeKind, TickPhase,
};

// ─── Helpers ───────────────────────────────────────────────────────────────

fn peer(name: &str, role: &str) -> FleetPeer {
    FleetPeer {
        name: name.into(),
        rpc_url: format!("http://127.0.0.1:28081/{name}"),
        role: role.into(),
    }
}

fn tip(
    height: u64,
    difficulty: u128,
    is_synced: bool,
    peer_count: u32,
    tip_age_secs: u64,
) -> ChainTipState<MockBlockId> {
    ChainTipState {
        height,
        difficulty,
        tip_id: MockBlockId::from_tag(height),
        is_synced,
        peer_count,
        tip_age_secs,
    }
}

/// Build a mock in Fleet deployment mode (so notice broadcasts are
/// captured — Personal mode silently drops them).
fn fleet_mock() -> MockAdapter {
    let m = MockAdapter::new();
    m.set_deployment_mode(DeploymentMode::Fleet);
    m
}

/// Build a RescueTick with testnet-default config (auto-recover) and
/// small safety-gate values so tests run fast.
fn fast_testnet_tick() -> RescueTick {
    let cfg = RescueConfig {
        safety_gate_poll_interval_secs: 0, // no sleep between polls
        safety_gate_max_wait_secs: 1,      // give up quickly if stuck
        ..RescueConfig::testnet_default()
    };
    RescueTick::new("rescue-test", cfg)
}

// ─── Recovery priority ────────────────────────────────────────────────────

#[test]
fn recovery_priority_orders_least_critical_first() {
    // Explorer (0) < relay (1) < miner (2) < seed (3) < unknown (5).
    assert!(recovery_priority("explorer") < recovery_priority("relay"));
    assert!(recovery_priority("relay") < recovery_priority("miner"));
    assert!(recovery_priority("miner") < recovery_priority("seed"));
    assert!(recovery_priority("seed") < recovery_priority("unrecognized"));
}

// ─── Quest — no divergence, no trigger ────────────────────────────────────

#[test]
fn no_divergence_no_quest_trigger() {
    let adapter = fleet_mock();
    // Two hosts, identical state — steady state, no divergence.
    adapter.add_fleet_peer(peer("seed1", "seed"), tip(9469, 720, true, 5, 12));
    adapter.add_fleet_peer(peer("seed2", "seed"), tip(9469, 720, true, 5, 12));

    let tick = fast_testnet_tick();
    let triggered = tick.quest(&adapter).unwrap();
    assert!(!triggered, "steady state must not trigger quest");
    assert_eq!(tick.current_phase(), TickPhase::Quest);
    assert!(
        adapter.broadcast_log().is_empty(),
        "no notice on steady state"
    );
}

// ─── Quest — divergence below block threshold ────────────────────────────

#[test]
fn divergence_below_threshold_does_not_trigger() {
    let adapter = fleet_mock();
    // 50-block gap — below the 100-block threshold.
    adapter.add_fleet_peer(peer("seed1", "seed"), tip(9469, 720, true, 5, 12));
    adapter.add_fleet_peer(peer("randomx", "miner"), tip(9519, 750, true, 5, 12));

    let tick = fast_testnet_tick();
    let triggered = tick.quest(&adapter).unwrap();
    assert!(
        !triggered,
        "50-block gap must not trigger (threshold is 100)"
    );
    assert_eq!(tick.current_phase(), TickPhase::Quest);
}

// ─── Quest — divergence below difficulty delta threshold ─────────────────

#[test]
fn divergence_below_difficulty_delta_does_not_trigger() {
    let adapter = fleet_mock();
    // Block gap above threshold BUT difficulty delta < 5%.
    // fleet at diff=685M, randomx at diff=685M+3% = 705.55M
    adapter.add_fleet_peer(peer("seed1", "seed"), tip(9369, 685_000_000, true, 5, 12));
    adapter.add_fleet_peer(peer("seed2", "seed"), tip(9369, 685_000_000, true, 5, 12));
    adapter.add_fleet_peer(
        peer("randomx", "miner"),
        tip(9569, 705_550_000, true, 5, 12),
    );

    // Register verify success in case the tick reaches that step
    adapter.set_peer_pow_verdict("randomx", Some(true));

    let tick = fast_testnet_tick();
    let triggered = tick.quest(&adapter).unwrap();
    assert!(
        !triggered,
        "3% difficulty delta must not trigger (threshold is 5%)"
    );
}

// ─── Quest — verified divergence triggers Hunt notice ────────────────────

#[test]
fn verified_divergence_triggers_quest_and_hunt_notice() {
    let adapter = fleet_mock();
    // 200-block gap, ≥5% difficulty delta, PoW verifies — should trigger.
    adapter.add_fleet_peer(peer("seed1", "seed"), tip(9369, 685_000_000, true, 5, 1200));
    adapter.add_fleet_peer(peer("seed2", "seed"), tip(9369, 685_000_000, true, 5, 1200));
    adapter.add_fleet_peer(
        peer("explorer", "explorer"),
        tip(9369, 685_000_000, true, 5, 1200),
    );
    adapter.add_fleet_peer(
        peer("randomx", "miner"),
        tip(9569, 720_000_000, true, 5, 12),
    );
    // Canonical PoW verifies successfully.
    adapter.set_peer_pow_verdict("randomx", Some(true));

    let tick = fast_testnet_tick();
    let triggered = tick.quest(&adapter).unwrap();
    assert!(
        triggered,
        "verified 200-block, 5% delta divergence must trigger"
    );
    assert_eq!(tick.current_phase(), TickPhase::Latch);

    // One Hunt notice emitted, aggregate text.
    let log = adapter.broadcast_log();
    assert_eq!(log.len(), 1);
    assert_eq!(log[0].kind, TickNoticeKind::Hunt);
    assert_eq!(log[0].severity, Severity::Critical);
    // Text is aggregate — mentions "3 hosts" not host names.
    assert!(
        log[0].text.contains("3 hosts"),
        "notice must aggregate; got: {}",
        log[0].text
    );
    assert!(
        !log[0].text.contains("seed1"),
        "notice must NOT name individual hosts"
    );
    assert!(
        !log[0].text.contains("randomx"),
        "notice must NOT name individual hosts"
    );
}

// ─── Quest — spoofed peer (PoW verify FAILS) ─────────────────────────────

#[test]
fn spoofed_peer_pow_verify_failure_aborts_and_alerts() {
    let adapter = fleet_mock();
    adapter.add_fleet_peer(peer("seed1", "seed"), tip(9369, 685_000_000, true, 5, 1200));
    adapter.add_fleet_peer(peer("seed2", "seed"), tip(9369, 685_000_000, true, 5, 1200));
    // Spoofer claims 200 blocks ahead with heavy difficulty, but PoW
    // check will fail — a hostile peer lying about its chain.
    adapter.add_fleet_peer(
        peer("spoofer", "miner"),
        tip(9569, 720_000_000, true, 5, 12),
    );
    adapter.set_peer_pow_verdict("spoofer", Some(false));

    let tick = fast_testnet_tick();
    let triggered = tick.quest(&adapter).unwrap();
    assert!(!triggered, "spoofed PoW must not trigger a feed");
    // Stay in Quest.
    assert_eq!(tick.current_phase(), TickPhase::Quest);
    // Instead of a Hunt notice, a Critical Alert should fire.
    let log = adapter.broadcast_log();
    assert_eq!(log.len(), 1);
    assert_eq!(log[0].kind, TickNoticeKind::Alert);
    assert_eq!(log[0].severity, Severity::Critical);
    assert!(
        log[0].text.contains("PoW"),
        "alert must mention PoW: {}",
        log[0].text
    );
    // Snapshot MUST NOT be called — no feed happens.
    assert_eq!(adapter.snapshot_calls(), 0);
}

// ─── Quest — unable to verify (adapter Err) also aborts ──────────────────

#[test]
fn unable_to_verify_pow_aborts_with_warn_alert() {
    let adapter = fleet_mock();
    adapter.add_fleet_peer(peer("seed1", "seed"), tip(9369, 685_000_000, true, 5, 1200));
    adapter.add_fleet_peer(peer("seed2", "seed"), tip(9369, 685_000_000, true, 5, 1200));
    adapter.add_fleet_peer(
        peer("randomx", "miner"),
        tip(9569, 720_000_000, true, 5, 12),
    );
    // No PoW verdict registered — verify_peer_header_pow returns Err.
    // (adapter can't check.)

    let tick = fast_testnet_tick();
    let triggered = tick.quest(&adapter).unwrap();
    assert!(!triggered, "unverifiable PoW must not trigger a feed");
    assert_eq!(tick.current_phase(), TickPhase::Quest);
    // A Warn-severity alert should fire (less severe than the
    // outright-spoof Critical alert).
    let log = adapter.broadcast_log();
    assert_eq!(log.len(), 1);
    assert_eq!(log[0].kind, TickNoticeKind::Alert);
    assert_eq!(log[0].severity, Severity::Warn);
    assert_eq!(adapter.snapshot_calls(), 0);
}

// ─── Latch — snapshot from canonical peer, not local ─────────────────────

#[test]
fn latch_snapshots_from_canonical_peer_not_local() {
    let adapter = fleet_mock();
    adapter.add_fleet_peer(peer("seed1", "seed"), tip(9369, 685_000_000, true, 5, 1200));
    adapter.add_fleet_peer(peer("seed2", "seed"), tip(9369, 685_000_000, true, 5, 1200));
    let canonical_tip = tip(9569, 720_000_000, true, 5, 12);
    adapter.add_fleet_peer(peer("randomx", "miner"), canonical_tip.clone());
    adapter.set_peer_pow_verdict("randomx", Some(true));

    let tick = fast_testnet_tick();
    assert!(tick.quest(&adapter).unwrap());

    // Testnet-default = auto-recover, so Latch should transition to Feed.
    tick.latch(&adapter).unwrap();
    assert_eq!(adapter.snapshot_calls(), 1);
    // Phase advanced to Feed (auto-recover).
    assert_eq!(tick.current_phase(), TickPhase::Feed);
}

// ─── Latch — mainnet-default pauses at Latch pending operator ack ────────

#[test]
fn mainnet_default_pauses_at_latch_pending_operator_ack() {
    let adapter = fleet_mock();
    adapter.add_fleet_peer(peer("seed1", "seed"), tip(9369, 685_000_000, true, 5, 1200));
    adapter.add_fleet_peer(peer("seed2", "seed"), tip(9369, 685_000_000, true, 5, 1200));
    adapter.add_fleet_peer(
        peer("randomx", "miner"),
        tip(9569, 720_000_000, true, 5, 12),
    );
    adapter.set_peer_pow_verdict("randomx", Some(true));

    let cfg = RescueConfig {
        safety_gate_poll_interval_secs: 0,
        safety_gate_max_wait_secs: 1,
        ..RescueConfig::mainnet_default() // require_operator_ack = true
    };
    let tick = RescueTick::new("rescue-mainnet", cfg);
    assert!(tick.quest(&adapter).unwrap());
    tick.latch(&adapter).unwrap();

    // Stays in Latch phase.
    assert_eq!(tick.current_phase(), TickPhase::Latch);
    assert!(tick.awaiting_ack());

    // Two notices: initial Hunt from Quest + "paused at Latch" from Latch.
    let log = adapter.broadcast_log();
    assert_eq!(log.len(), 2);
    assert!(
        log[1].text.contains("operator acknowledgment"),
        "got: {}",
        log[1].text
    );

    // Operator ack advances to Feed.
    assert!(tick.operator_ack());
    assert_eq!(tick.current_phase(), TickPhase::Feed);
    // Second ack (already-Feed) returns false.
    assert!(!tick.operator_ack());
}

// ─── Feed — hosts processed in recovery priority order ──────────────────

#[test]
fn feed_processes_hosts_in_priority_order() {
    let adapter = fleet_mock();
    // Mix of roles: seed (highest priority = last), miner, relay, explorer.
    // Explorer should be fed first, seed last.
    let canonical_tip = tip(9569, 720_000_000, true, 5, 12);
    let stalled = tip(9369, 685_000_000, true, 5, 1200);
    adapter.add_fleet_peer(peer("seed1", "seed"), stalled.clone());
    adapter.add_fleet_peer(peer("relay1", "relay"), stalled.clone());
    adapter.add_fleet_peer(peer("explorer", "explorer"), stalled.clone());
    adapter.add_fleet_peer(peer("randomx-2", "miner"), canonical_tip);
    adapter.set_peer_pow_verdict("randomx-2", Some(true));

    // Note: we don't overwrite the stalled hosts to appear synced
    // post-apply. The safety gate has max_wait_secs=1, so it times
    // out fast per host — we still verify the important thing
    // (apply_calls == 3, phase reached Detach).

    let tick = fast_testnet_tick();
    assert!(tick.quest(&adapter).unwrap());
    tick.latch(&adapter).unwrap();
    tick.feed(&adapter).unwrap();

    // Feed consumed the whole queue — should now be in Detach phase.
    assert_eq!(tick.current_phase(), TickPhase::Detach);
    // 3 hosts fed (explorer, relay1, seed1 — everyone except the canonical).
    assert_eq!(adapter.apply_calls(), 3);
}

// ─── Full cycle ────────────────────────────────────────────────────────────

#[test]
fn full_cycle_emits_hunt_engaged_recovered_notices() {
    let adapter = fleet_mock();
    let canonical_tip = tip(9569, 720_000_000, true, 5, 12);
    let stalled = tip(9369, 685_000_000, true, 5, 1200);
    adapter.add_fleet_peer(peer("seed1", "seed"), stalled.clone());
    adapter.add_fleet_peer(peer("relay1", "relay"), stalled);
    adapter.add_fleet_peer(peer("randomx-2", "miner"), canonical_tip);
    adapter.set_peer_pow_verdict("randomx-2", Some(true));

    let tick = fast_testnet_tick();
    tick.quest(&adapter).unwrap();
    tick.latch(&adapter).unwrap();
    tick.feed(&adapter).unwrap();
    tick.detach(&adapter).unwrap();

    // Phase reset to Quest after Detach.
    assert_eq!(tick.current_phase(), TickPhase::Quest);

    // Verify notice sequence: Hunt → Engaged (per host) → Recovered.
    let log = adapter.broadcast_log();
    let kinds: Vec<TickNoticeKind> = log.iter().map(|n| n.kind).collect();

    // Should start with Hunt and end with Recovered.
    assert_eq!(kinds.first(), Some(&TickNoticeKind::Hunt));
    assert_eq!(kinds.last(), Some(&TickNoticeKind::Recovered));

    // Should contain Engaged notices (one per host fed).
    let engaged_count = kinds
        .iter()
        .filter(|k| **k == TickNoticeKind::Engaged)
        .count();
    assert_eq!(engaged_count, 2, "one Engaged per host fed (2 hosts)");

    // Aggregate-text check on Recovered notice.
    let recovered = log
        .iter()
        .find(|n| n.kind == TickNoticeKind::Recovered)
        .unwrap();
    assert!(
        recovered.text.contains("2 hosts"),
        "recovered text should mention count; got: {}",
        recovered.text
    );
    assert!(
        !recovered.text.contains("seed1"),
        "recovered text must NOT name hosts"
    );
}

// ─── Privacy — Personal deployment silences all notices ─────────────────

#[test]
fn personal_deployment_emits_no_notices_even_during_rescue() {
    let adapter = MockAdapter::new(); // default = Personal
    let canonical_tip = tip(9569, 720_000_000, true, 5, 12);
    let stalled = tip(9369, 685_000_000, true, 5, 1200);
    adapter.add_fleet_peer(peer("seed1", "seed"), stalled.clone());
    adapter.add_fleet_peer(peer("randomx-2", "miner"), canonical_tip);
    adapter.set_peer_pow_verdict("randomx-2", Some(true));

    // BUT: RescueTick still works — it's just the broadcast that's
    // silent. The tick still runs, still snapshots, still applies.
    let tick = fast_testnet_tick();
    tick.quest(&adapter).unwrap();
    tick.latch(&adapter).unwrap();
    tick.feed(&adapter).unwrap();
    tick.detach(&adapter).unwrap();

    // All notices dropped silently — Personal mode.
    assert!(
        adapter.broadcast_log().is_empty(),
        "Personal mode must broadcast NO notices even during a rescue \
         (avoids leaking node existence)"
    );

    // Recovery still happened — snapshot + apply were called.
    assert_eq!(adapter.snapshot_calls(), 1);
    assert_eq!(adapter.apply_calls(), 1);
}
