//! colony_live — exercise every colony caste against a live node, end to end.
//!
//! Runs the REAL caste decision cores (not a reimplementation) on public signals
//! pulled from a running node's RPC, then feeds the detection castes' output
//! through the act-phase spine (honeybee quorum → guards) and prints what each
//! caste advises and whether the guard would let it fire.
//!
//! It is a *harness*, not a node change: it only reads RPC and prints. Nothing
//! it does touches consensus, the mempool, or peer behavior — the same
//! observe-only posture the live castes run in today.
//!
//! Usage:
//!   cargo run --release --features "randomx testnet" --example colony_live -- http://127.0.0.1:29112
//!
//! The URL defaults to http://127.0.0.1:28081 (the standard node RPC).

use std::time::{SystemTime, UNIX_EPOCH};

use coincync::colony::{
    army_ant, centipede, cicada, firefly, forager, guards, honeybee, locust, mantis, pheromone,
    sensor, spider, stick_insect,
};
use serde_json::{json, Value};
use tick::{AggregateFleetHealth, ChainTipState};

fn now_secs() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

/// One JSON-RPC call. Returns the `result` value or a string error.
fn rpc(client: &reqwest::blocking::Client, url: &str, method: &str, params: Value) -> Result<Value, String> {
    let body = json!({"jsonrpc": "2.0", "method": method, "params": params, "id": 1});
    let resp = client
        .post(url)
        .json(&body)
        .send()
        .map_err(|e| format!("{method}: request failed: {e}"))?;
    let v: Value = resp.json().map_err(|e| format!("{method}: bad json: {e}"))?;
    if let Some(err) = v.get("error").filter(|e| !e.is_null()) {
        return Err(format!("{method}: rpc error: {err}"));
    }
    v.get("result").cloned().ok_or_else(|| format!("{method}: no result"))
}

/// IPv4 /16 netgroup key from "a.b.c.d:port"; loopback and non-IPv4 fold to 0.
fn netgroup_of(addr: &str) -> u16 {
    let host = addr.rsplit_once(':').map(|(h, _)| h).unwrap_or(addr);
    let mut it = host.split('.');
    match (it.next().and_then(|x| x.parse::<u8>().ok()), it.next().and_then(|x| x.parse::<u8>().ok())) {
        (Some(a), Some(b)) => ((a as u16) << 8) | b as u16,
        _ => 0,
    }
}

fn main() {
    let url = std::env::args().nth(1).unwrap_or_else(|| "http://127.0.0.1:28081".to_string());
    let client = reqwest::blocking::Client::builder()
        .timeout(std::time::Duration::from_secs(15))
        .build()
        .expect("http client");

    println!("colony_live — real caste cores against {url}\n");

    let info = match rpc(&client, &url, "get_info", json!([])) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("FATAL: {e}\n(is a node listening on that RPC port?)");
            std::process::exit(1);
        }
    };
    let peers = rpc(&client, &url, "get_peers", json!([])).unwrap_or(Value::Null);

    let local_height = info.get("height").and_then(Value::as_u64).unwrap_or(0);
    let peer_count = info.get("peer_count").and_then(Value::as_u64).unwrap_or(0) as u32;
    let is_synced = info.get("is_synced").and_then(Value::as_bool).unwrap_or(true);
    println!("node: height={local_height} peers={peer_count} synced={is_synced}\n");

    let peer_list: Vec<Value> = peers
        .get("peers")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();

    // ── Detection castes ─────────────────────────────────────────────────────

    // spider: eclipse/flood/partition signatures from local topology.
    let mut ng_counts: std::collections::BTreeMap<u16, u32> = Default::default();
    let mut inbound = 0u32;
    for p in &peer_list {
        if p.get("outbound").and_then(Value::as_bool) == Some(false) {
            inbound += 1;
            let addr = p.get("addr").and_then(Value::as_str).unwrap_or("");
            *ng_counts.entry(netgroup_of(addr)).or_default() += 1;
        }
    }
    let largest_ng = ng_counts.values().copied().max().unwrap_or(0);
    let largest_ng_pct = if inbound > 0 { (largest_ng * 100 / inbound) as u8 } else { 0 };
    let reading = spider::SentinelReading {
        inbound_new_per_min: inbound, // proxy: current inbound count (no rate over RPC)
        largest_netgroup_pct: largest_ng_pct,
        duplicate_msg_pct: 0, // not exposed over RPC
        unreachable_sentinel_pct: 0,
    };
    let sigs = spider::assess(&reading);
    println!("spider   (local topology): inbound={inbound} largest_netgroup={largest_ng_pct}% -> {sigs:?}");

    // sensor: fleet health. A single node has no fleet, so we build a
    // DEMONSTRATION aggregate from connected peers' heights (divergent = >5
    // blocks from ours). Labeled as such; real fleet health comes from the
    // sidecar polling real hosts.
    let mut divergent = 0u16;
    for p in &peer_list {
        let h = p.get("height").and_then(Value::as_u64).unwrap_or(local_height);
        if local_height.abs_diff(h) > 5 {
            divergent += 1;
        }
    }
    let agg = AggregateFleetHealth {
        total_hosts: peer_list.len() as u16,
        stalled_count: 0,
        low_peer_count: 0,
        divergent_count: divergent,
        median_difficulty: 0,
        high_ram_count: 0,
        high_disk_count: 0,
    };
    let net = sensor::classify(&agg);
    println!("sensor   (peer-derived fleet view, demo): hosts={} divergent={divergent} -> {net:?}", peer_list.len());

    // ── Advisory / resilience castes ─────────────────────────────────────────

    // forager: pheromone deposit per peer from its public tip, then rank.
    let mut pmap = pheromone::PheromoneMap::new();
    for (i, p) in peer_list.iter().enumerate() {
        let h = p.get("height").and_then(Value::as_u64).unwrap_or(0);
        let tip: ChainTipState<[u8; 32]> = ChainTipState {
            height: h,
            difficulty: 0,
            tip_id: [0u8; 32],
            is_synced: true,
            peer_count,
            tip_age_secs: 0,
        };
        let score = forager::deposit_for_probe(local_height, &tip);
        let key = p.get("addr").and_then(Value::as_str).map(|a| a.to_string()).unwrap_or_else(|| format!("peer{i}"));
        pmap.deposit(pheromone::PeerKey(key), score);
    }
    let ranked = pmap.ranked();
    println!("forager  (peer relay scores): top {:?}", ranked.iter().take(3).collect::<Vec<_>>());

    // army_ant: netgroup-diverse bridge selection from peers.
    let bridges: Vec<army_ant::BridgeCandidate> = peer_list
        .iter()
        .map(|p| {
            let addr = p.get("addr").and_then(Value::as_str).unwrap_or("");
            army_ant::BridgeCandidate::new(addr.to_string(), netgroup_of(addr), 0)
        })
        .collect();
    let chosen = army_ant::select_bridges(&bridges, 4);
    println!("army_ant (partition bridges): {} candidates -> {} chosen", bridges.len(), chosen.len());

    // centipede: netgroup-diverse relay legs.
    let legs: Vec<centipede::Leg> = peer_list
        .iter()
        .map(|p| {
            let addr = p.get("addr").and_then(Value::as_str).unwrap_or("");
            centipede::Leg::new(addr.to_string(), netgroup_of(addr))
        })
        .collect();
    let sel = centipede::select_legs(&legs, 3);
    let leg_diversity = centipede::distinct_netgroups(&sel);
    println!("centipede(relay legs): {} legs, {} distinct netgroups", sel.len(), leg_diversity);

    // locust: density-adaptive relay mode. density ~ peer_count saturating at 100.
    let mut swarm = locust::Locust::new();
    let density = (peer_count.min(100)) as u8;
    let under_attack = !sigs.is_empty();
    let mode = swarm.update(density, under_attack);
    println!("locust   (relay mode): density={density}% under_attack={under_attack} -> {mode:?}");

    // cicada: prime-interval housekeeping cadence (no tx/stem timing).
    let intervals: Vec<u64> = (0..4).map(|c| cicada::prime_interval_secs(600, c)).collect();
    println!("cicada   (housekeeping cadence, base 600s): next intervals {intervals:?}");

    // firefly: cover-traffic flash cadence (bounded coupling).
    // increment chosen so the flash is legible over a short window (PHASE_MAX
    // is 10_000; the sidecar would pace real ticks far slower).
    let mut flasher = firefly::Firefly::new(2500);
    let mut flashes = Vec::new();
    for t in 0..20 {
        if flasher.tick() {
            flashes.push(t);
        }
    }
    println!("firefly  (cover flash cadence, incr 2500/10000): fired at ticks {flashes:?}");

    // mantis: escalating tarpit holds.
    let holds: Vec<u64> = (1..=4).map(mantis::hold_secs).collect();
    println!("mantis   (tarpit escalation, offenses 1..4): {holds:?}s");

    // stick_insect: canonical wire fingerprint.
    let ua = stick_insect::normalize_user_agent("/coincync-debug:2.0.0-dirty/");
    println!("stick_insect(wire fingerprint): any UA -> {ua:?}, canonical={}", stick_insect::is_canonical_user_agent(ua));

    // ── The act-phase spine: honeybee quorum → guards ────────────────────────
    println!("\n── act-phase spine (trust before action) ──");
    let now = now_secs();
    let qp = honeybee::QuorumParams::standard();
    let mut obs: Vec<honeybee::Observation> = Vec::new();

    // Map detection-caste output into quorum evidence. spider = LocalTopology
    // dimension (our single vantage = source_group 0). sensor = FleetHealth
    // dimension. Peers that look divergent add independent PeerLiveness evidence,
    // one source_group per peer netgroup.
    if sigs.contains(&spider::ThreatSignature::EclipsePressure) {
        obs.push(honeybee::Observation { threat: honeybee::Threat::Eclipse, kind: honeybee::EvidenceKind::LocalTopology, source_group: 0, observed_at: now });
    }
    if sigs.contains(&spider::ThreatSignature::FloodPattern) {
        obs.push(honeybee::Observation { threat: honeybee::Threat::Flood, kind: honeybee::EvidenceKind::LocalTopology, source_group: 0, observed_at: now });
    }
    if matches!(net, sensor::NetSignal::PartitionSuspected(_)) {
        obs.push(honeybee::Observation { threat: honeybee::Threat::Partition, kind: honeybee::EvidenceKind::FleetHealth, source_group: 0, observed_at: now });
    }
    for p in &peer_list {
        let h = p.get("height").and_then(Value::as_u64).unwrap_or(local_height);
        if local_height.abs_diff(h) > 5 {
            let addr = p.get("addr").and_then(Value::as_str).unwrap_or("");
            obs.push(honeybee::Observation {
                threat: honeybee::Threat::Partition,
                kind: honeybee::EvidenceKind::PeerLiveness,
                source_group: netgroup_of(addr) as u64 + 1, // +1 so it never collides with vantage 0
                observed_at: now,
            });
        }
    }

    let verdicts = honeybee::assess_all(&obs, now, &qp);
    if verdicts.is_empty() {
        println!("honeybee: no threat reached quorum confidence (nothing would act) — {} raw observations", obs.len());
    }
    let mut gstate = guards::GuardState::new();
    let gp = guards::GuardParams::standard();
    for (threat, conf) in &verdicts {
        // Represent a plausible response per threat and show the guard verdict.
        let (label, effect) = match threat {
            honeybee::Threat::Partition => ("army_ant-bridge", guards::PeerEffect::ResultingNetgroups(leg_diversity.max(1) as u32)),
            honeybee::Threat::Eclipse => ("peer-rotate", guards::PeerEffect::ResultingNetgroups(leg_diversity.max(1) as u32)),
            honeybee::Threat::Flood => ("tarpit-escalate", guards::PeerEffect::None),
        };
        let req = guards::ActionRequest {
            label,
            kind: guards::ActionKind::Posture,
            confidence: *conf,
            min_confidence: 50, // act threshold
            peer_effect: effect,
        };
        let decision = guards::authorize(&req, &mut gstate, now, &gp);
        println!("honeybee: {threat:?} confidence={conf}  ->  guard[{label}]: {decision:?}");
    }

    // ── Spine verification: the guard allow / deny paths ────────────────────
    //
    // Loopback peers are not independent (all one netgroup), so a single-host
    // live run cannot manufacture cross-dimension quorum — which is exactly why
    // honeybee stayed at zero above. To show the OTHER side of the spine (a
    // corroborated threat reaching confidence, the guard allowing it, and the
    // diversity floor refusing a floor-breaking response), here is a synthetic
    // corroborated scenario — labelled as such, not live data.
    println!("\n── spine verification (synthetic corroborated scenario) ──");
    let scenario = [
        honeybee::Observation { threat: honeybee::Threat::Partition, kind: honeybee::EvidenceKind::FleetHealth, source_group: 10, observed_at: now },
        honeybee::Observation { threat: honeybee::Threat::Partition, kind: honeybee::EvidenceKind::PeerLiveness, source_group: 11, observed_at: now },
        honeybee::Observation { threat: honeybee::Threat::Partition, kind: honeybee::EvidenceKind::RelayFailure, source_group: 12, observed_at: now },
        honeybee::Observation { threat: honeybee::Threat::Partition, kind: honeybee::EvidenceKind::PeerLiveness, source_group: 13, observed_at: now },
        honeybee::Observation { threat: honeybee::Threat::Partition, kind: honeybee::EvidenceKind::FleetHealth, source_group: 14, observed_at: now },
    ];
    let conf = honeybee::confidence_for(honeybee::Threat::Partition, &scenario, now, &qp);
    println!("honeybee: 5 independent sources / 3 dimensions -> Partition confidence={conf}");
    let mut gs = guards::GuardState::new();
    let ok_req = guards::ActionRequest { label: "army_ant-bridge", kind: guards::ActionKind::Posture, confidence: conf, min_confidence: 50, peer_effect: guards::PeerEffect::ResultingNetgroups(6) };
    println!("guard[army_ant-bridge, resulting 6 netgroups]: {:?}", guards::authorize(&ok_req, &mut gs, now, &gp));
    let bad_req = guards::ActionRequest { label: "peer-rotate", kind: guards::ActionKind::Posture, confidence: conf, min_confidence: 50, peer_effect: guards::PeerEffect::ResultingNetgroups(2) };
    println!("guard[peer-rotate, resulting 2 netgroups]: {:?}  (diversity floor = {})", guards::authorize(&bad_req, &mut gs, now, &gp), gp.diversity_floor);
    gs.set_kill_switch(true);
    println!("guard[army_ant-bridge, kill switch engaged]: {:?}", guards::authorize(&ok_req, &mut gs, now, &gp));

    println!("\nDONE — every caste core exercised against live signals; act-phase advice gated by the spine.");
}
