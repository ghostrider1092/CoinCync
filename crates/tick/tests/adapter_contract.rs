//! Integration tests that exercise the `ChainAdapter` contract via
//! `MockAdapter`. These tests are the primary evidence that the trait
//! shape is usable — if you can implement `MockAdapter` cleanly and
//! call every method, downstream chains can too.
//!
//! Phase 1a scope: exercise the trait surface + the privacy-relevant
//! defaults. RescueTick / HealthTick / PropagationTick tests land in
//! their respective phase PRs.

#![cfg(feature = "mock")]

use tick::{
    AggregateFleetHealth, ChainAdapter, ChainTipState, DeploymentMode, FleetPeer,
    HealthSnapshot, MockAdapter, Severity, TickNotice, TickNoticeKind,
};
use tick::mock::{MockBlockId, MockPeerId, MockTxId};

// ─── Trait-shape smoke tests ───────────────────────────────────────────────

#[test]
fn adapter_returns_default_state_out_of_the_box() {
    let adapter = MockAdapter::new();
    let tip = adapter.tip_state().expect("mock tip should always succeed");
    assert_eq!(tip.height, 0);
    assert_eq!(tip.difficulty, 0);
    assert!(tip.is_synced);
    assert_eq!(adapter.fleet_peers().len(), 0);
    assert_eq!(adapter.stem_relay_peers().len(), 0);
}

#[test]
fn adapter_reports_configured_tip() {
    let adapter = MockAdapter::new();
    adapter.set_tip(ChainTipState {
        height: 9469,
        difficulty: 720_000_000,
        tip_id: MockBlockId::from_tag(9469),
        is_synced: true,
        peer_count: 8,
        tip_age_secs: 12,
    });
    let tip = adapter.tip_state().unwrap();
    assert_eq!(tip.height, 9469);
    assert_eq!(tip.difficulty, 720_000_000);
    assert_eq!(tip.peer_count, 8);
}

#[test]
fn probe_peer_returns_registered_state() {
    let adapter = MockAdapter::new();
    let peer = FleetPeer {
        name: "seed1".into(),
        rpc_url: "http://127.0.0.1:28081".into(),
        role: "seed".into(),
    };
    let expected = ChainTipState {
        height: 9369,
        difficulty: 685_000_000,
        tip_id: MockBlockId::from_tag(9369),
        is_synced: true,
        peer_count: 5,
        tip_age_secs: 1200,
    };
    adapter.add_fleet_peer(peer.clone(), expected.clone());
    assert_eq!(adapter.probe_peer(&peer).unwrap(), expected);
}

#[test]
fn probe_peer_returns_unreachable_for_unknown_host() {
    let adapter = MockAdapter::new();
    let peer = FleetPeer {
        name: "ghost".into(),
        rpc_url: "http://127.0.0.1:28081".into(),
        role: "seed".into(),
    };
    let err = adapter.probe_peer(&peer).unwrap_err();
    assert!(format!("{}", err).contains("unreachable"));
}

// ─── Privacy contract: stem-phase & stem-relays ─────────────────────────

#[test]
fn is_stem_phase_returns_true_only_for_marked_txs() {
    let adapter = MockAdapter::new();
    let stem_tx = MockTxId::from_tag(1);
    let fluff_tx = MockTxId::from_tag(2);
    adapter.mark_stem_tx(stem_tx.clone());
    assert!(adapter.is_stem_phase(&stem_tx));
    assert!(!adapter.is_stem_phase(&fluff_tx));
}

#[test]
fn stem_relays_are_reported_faithfully() {
    let adapter = MockAdapter::new();
    let relay_a = MockPeerId(1);
    let relay_b = MockPeerId(2);
    adapter.add_stem_relay(relay_a.clone());
    adapter.add_stem_relay(relay_b.clone());
    let reported = adapter.stem_relay_peers();
    assert_eq!(reported.len(), 2);
    assert!(reported.contains(&relay_a));
    assert!(reported.contains(&relay_b));
}

// ─── Privacy contract: DeploymentMode default is Personal ───────────────

#[test]
fn deployment_mode_defaults_to_personal() {
    let adapter = MockAdapter::new();
    assert_eq!(adapter.deployment_mode(), DeploymentMode::Personal);
}

#[test]
fn deployment_mode_default_impl_is_personal() {
    // This asserts the `impl Default for DeploymentMode` matches the
    // Personal-is-safer discipline. If someone flips this, wallets on
    // home nodes might start broadcasting anomaly notices — a network
    // existence leak. The test is intentionally strict.
    assert_eq!(DeploymentMode::default(), DeploymentMode::Personal);
}

#[test]
fn deployment_mode_can_be_switched_to_fleet() {
    let adapter = MockAdapter::new();
    adapter.set_deployment_mode(DeploymentMode::Fleet);
    assert_eq!(adapter.deployment_mode(), DeploymentMode::Fleet);
}

// ─── Privacy contract: personal mode suppresses broadcasts ──────────────

#[test]
fn broadcast_notice_is_silent_on_personal_deployment() {
    let adapter = MockAdapter::new();
    // Default is Personal — the broadcast must be a no-op.
    let notice = TickNotice {
        kind: TickNoticeKind::Alert,
        text: "tip_age_secs elevated on 3 of 9 hosts".into(),
        severity: Severity::Warn,
        tick_id: "test-tick".into(),
        mode: 1,
        emitted_at: 100,
        expires_at: 200,
        signature: [0u8; 64],
    };
    adapter.broadcast_notice(&notice).unwrap();
    assert!(
        adapter.broadcast_log().is_empty(),
        "Personal-mode adapter must silently drop broadcasts; broadcasting would leak node existence"
    );
}

#[test]
fn broadcast_notice_appears_on_fleet_deployment() {
    let adapter = MockAdapter::new();
    adapter.set_deployment_mode(DeploymentMode::Fleet);
    let notice = TickNotice {
        kind: TickNoticeKind::Hunt,
        text: "1 host feeding 8 hosts on canonical fork".into(),
        severity: Severity::Critical,
        tick_id: "randomx-tick".into(),
        mode: 0,
        emitted_at: 500,
        expires_at: 700,
        signature: [0u8; 64],
    };
    adapter.broadcast_notice(&notice).unwrap();
    let log = adapter.broadcast_log();
    assert_eq!(log.len(), 1);
    assert_eq!(log[0].tick_id, "randomx-tick");
}

// ─── Aggregate-fleet-health surface ────────────────────────────────────

#[test]
fn aggregate_fleet_health_returns_configured_snapshot() {
    let adapter = MockAdapter::new();
    let agg = AggregateFleetHealth {
        total_hosts: 9,
        stalled_count: 8,
        low_peer_count: 0,
        divergent_count: 1,
        median_difficulty: 685_000_000,
        high_ram_count: 0,
        high_disk_count: 0,
    };
    adapter.set_aggregate_health(agg.clone());
    assert_eq!(adapter.aggregate_fleet_health().unwrap(), agg);
}

#[test]
fn aggregate_health_has_no_per_host_field() {
    // Compile-time evidence that the aggregate type is aggregate. If a
    // future change added a per-host field, this test would need to be
    // updated — which is a review-visible signal that privacy might be
    // regressing.
    let agg = AggregateFleetHealth {
        total_hosts: 9,
        stalled_count: 8,
        low_peer_count: 0,
        divergent_count: 1,
        median_difficulty: 685_000_000,
        high_ram_count: 0,
        high_disk_count: 0,
    };
    // All fields are counts or medians; no `Vec<HealthSnapshot>` or
    // `HashMap<HostName, ...>`.
    let _: u16 = agg.total_hosts;
    let _: u16 = agg.stalled_count;
    let _: u128 = agg.median_difficulty;
}

// ─── Health snapshot surface ──────────────────────────────────────────

#[test]
fn health_snapshot_reports_local_metrics() {
    let adapter = MockAdapter::new();
    adapter.set_health(HealthSnapshot {
        ram_used_pct: 87,
        disk_used_pct: 45,
        swap_used_pct: 5,
        hashrate_hs: Some(520),
        mempool_txs: 3,
        cpu_used_pct: 65,
        uptime_secs: 3600,
    });
    let health = adapter.health_snapshot().unwrap();
    assert_eq!(health.ram_used_pct, 87);
    assert_eq!(health.hashrate_hs, Some(520));
}

// ─── Snapshot / apply surface ─────────────────────────────────────────

#[test]
fn snapshot_and_apply_are_recorded() {
    let adapter = MockAdapter::new();
    let dest = std::path::PathBuf::from("/tmp/tick-test.tgz");
    // Local snapshot (source == None).
    let snap = adapter.snapshot_chaindata(None, &dest).unwrap();
    assert_eq!(snap.tarball_path, dest);
    assert_eq!(adapter.snapshot_calls(), 1);
    adapter.apply_chaindata(&dest).unwrap();
    assert_eq!(adapter.apply_calls(), 1);
}

#[test]
fn snapshot_from_specific_peer_records_peer_tip() {
    let adapter = MockAdapter::new();
    let peer = FleetPeer {
        name: "randomx-2".into(),
        rpc_url: "http://127.0.0.1:28081".into(),
        role: "miner".into(),
    };
    let peer_tip = ChainTipState {
        height: 9469,
        difficulty: 720_000_000,
        tip_id: MockBlockId::from_tag(9469),
        is_synced: true,
        peer_count: 5,
        tip_age_secs: 30,
    };
    adapter.add_fleet_peer(peer.clone(), peer_tip.clone());

    let dest = std::path::PathBuf::from("/tmp/canonical.tgz");
    let snap = adapter.snapshot_chaindata(Some(&peer), &dest).unwrap();
    // source_tip in the snapshot should reflect the peer's tip, not
    // the local tick's tip. Confirms `snapshot_chaindata(source=Some)`
    // is genuinely sourcing from the canonical, not from local.
    assert_eq!(snap.source_tip, peer_tip.tip_id.0.to_vec());
}

// ─── Rebroadcast surface ──────────────────────────────────────────────

#[test]
fn rebroadcast_block_is_logged() {
    let adapter = MockAdapter::new();
    let block = MockBlockId::from_tag(42);
    let peer = MockPeerId(7);
    adapter.rebroadcast_block(&block, &peer).unwrap();
    let log = adapter.rebroadcast_log();
    assert_eq!(log.len(), 1);
    assert_eq!(log[0].0, block);
    assert_eq!(log[0].1, peer);
}

// ─── TickNotice helpers ───────────────────────────────────────────────

#[test]
fn tick_notice_is_expired_reports_correctly() {
    let notice = TickNotice {
        kind: TickNoticeKind::Alert,
        text: "test".into(),
        severity: Severity::Info,
        tick_id: "t".into(),
        mode: 0,
        emitted_at: 100,
        expires_at: 200,
        signature: [0u8; 64],
    };
    assert!(!notice.is_expired(150));
    assert!(notice.is_expired(200));
    assert!(notice.is_expired(500));
}
