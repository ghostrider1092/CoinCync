//! Act phase — the gated bridge from caste decision cores to node effects.
//!
//! [`ColonyActor`] owns the stateful castes (tarpit, firefly, locust, cicada,
//! pheromone) and, each round, runs every caste to a [`Recommendation`],
//! converts it to a guard-facing action, and asks
//! [`ColonyGuards::authorize`](crate::colony::guard::ColonyGuards::authorize).
//! **Only on `Allow`** does it call the corresponding [`ColonyActuator`] method;
//! on `Deny` it records the reason and does nothing.
//!
//! The actor is deliberately decoupled from the node: it talks to the world
//! only through the [`ColonyActuator`] trait, so its full logic is unit-tested
//! against a mock (asserting, above all, that a disarmed guard set produces
//! **zero** actuator calls). The node supplies the real actuator.
//!
//! Non-consensus, public-signal-only: no input here is a transaction or
//! stem-phase datum, and no actuator method touches block validity, the
//! mempool, or Dandelion.

use std::sync::Arc;

use crate::colony::advise::Recommendation;
use crate::colony::army_ant::{self, BridgeCandidate};
use crate::colony::centipede::{self, Leg};
use crate::colony::cicada::CicadaSchedule;
use crate::colony::firefly::Firefly;
use crate::colony::forager;
use crate::colony::guard::{ColonyGuards, GuardDecision, NetgroupCensus};
use crate::colony::locust::{Locust, SwarmMode};
use crate::colony::mantis::{MantisTarpit, TarpitKey};
use crate::colony::pheromone::{PeerKey, PheromoneMap};
use crate::colony::spider::{self, SentinelReading, ThreatSignature};

/// Public signals fed to the actor each round. Everything here is derived from
/// block relay / connection topology / chain tip — never a transaction.
#[derive(Clone, Debug, Default)]
pub struct ColonySignals {
    /// Sanitized sentinel reading (spider input). Must have passed through
    /// `guard::telemetry::sanitize_reading` before it reaches here.
    pub sentinel: SentinelReading,
    /// Relay density, 0..=100 (locust input).
    pub density_pct: u8,
    /// Netgroup-diverse reconnection candidates (army_ant), when partitioned.
    pub bridge_candidates: Vec<BridgeCandidate>,
    /// Candidate relay legs (centipede).
    pub leg_candidates: Vec<Leg>,
    /// Peers that misbehaved this round (mantis tarpit input).
    pub offenders: Vec<TarpitKey>,
    /// Current outbound diversity census (for the diversity floor).
    pub census: NetgroupCensus,
    /// Caps.
    pub max_prefer: usize,
    pub max_legs: usize,
    pub max_bridges: usize,
}

/// The node effects a caste can request. The node implements this; tests mock
/// it. Every method is called *only after* `authorize` returned `Allow`.
pub trait ColonyActuator {
    /// forager: bias retention/download toward these peers.
    fn prefer_peers(&self, peers: &[PeerKey]);
    /// mantis: apply an escalating slow-hold to a misbehaving peer.
    fn tarpit_peer(&self, peer: &TarpitKey, hold_secs: u64);
    /// army_ant: open reconnections across these netgroup-diverse peers.
    fn open_bridges(&self, candidates: &[BridgeCandidate]);
    /// centipede: relay the next block over these diverse legs.
    fn set_relay_legs(&self, legs: &[Leg]);
    /// locust: adopt this relay/padding mode.
    fn set_swarm_mode(&self, mode: SwarmMode);
    /// cicada: schedule the next node-local housekeeping this many seconds out.
    fn schedule_housekeep(&self, next_secs: u64);
    /// firefly: emit a synchronized cover-traffic pulse.
    fn cover_pulse(&self);
    /// stick_insect: (re)assert the canonical wire profile.
    fn assert_wire_profile(&self);
}

/// What happened in one `tick` — for logging and tests.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ActReport {
    pub allowed: Vec<String>,
    pub denied: Vec<(String, &'static str)>,
}

impl ActReport {
    fn record(&mut self, label: &str, decision: GuardDecision) -> bool {
        match decision {
            GuardDecision::Allow => {
                self.allowed.push(label.to_string());
                true
            }
            GuardDecision::Deny(reason) => {
                self.denied.push((label.to_string(), reason));
                false
            }
        }
    }
}

/// Owns the stateful castes and drives them through the guards each round.
pub struct ColonyActor {
    guards: Arc<ColonyGuards>,
    pheromone: PheromoneMap,
    tarpit: MantisTarpit,
    locust: Locust,
    firefly: Firefly,
    cicada: CicadaSchedule,
}

impl ColonyActor {
    pub fn new(guards: Arc<ColonyGuards>, cicada_base_secs: u64, firefly_increment: u32) -> Self {
        Self {
            guards,
            pheromone: PheromoneMap::new(),
            tarpit: MantisTarpit::new(),
            locust: Locust::new(),
            firefly: Firefly::new(firefly_increment),
            cicada: CicadaSchedule::new(cicada_base_secs),
        }
    }

    /// Deposit this round's peer relay-quality observations into the pheromone
    /// map (with evaporation), mirroring `forager::observe_round`. Deposits are
    /// `(peer, amount)` from public block/tip signals only.
    pub fn observe_peers(&mut self, deposits: &[(PeerKey, u32)]) {
        self.pheromone.evaporate();
        for (peer, amount) in deposits {
            self.pheromone.deposit(peer.clone(), *amount);
        }
    }

    /// Absorb a cover-traffic pulse from an (already authenticated) peer, so
    /// firefly can couple. Bounded internally.
    pub fn absorb_firefly_pulse(&mut self) {
        let _ = self.firefly.absorb_pulse();
    }

    /// Run one Act round. Every caste's recommendation is gated; the actuator is
    /// touched only for allowed actions. Returns a report of allow/deny.
    pub fn tick(&mut self, signals: &ColonySignals, act: &dyn ColonyActuator) -> ActReport {
        let mut report = ActReport::default();
        let census = &signals.census;

        // spider: detection only — derive attack/partition flags for locust/army_ant.
        let threats = spider::assess(&signals.sentinel);
        let under_attack = threats
            .iter()
            .any(|t| matches!(t, ThreatSignature::EclipsePressure | ThreatSignature::FloodPattern));
        let partition = threats
            .iter()
            .any(|t| matches!(t, ThreatSignature::PartitionOnset));

        // locust: density/attack-adaptive relay mode.
        let mode = self.locust.update(signals.density_pct, under_attack);
        if let Some(action) = Recommendation::Mode(mode).to_action() {
            if report.record(&action.detail, self.guards.authorize(&action, census)) {
                act.set_swarm_mode(mode);
            }
        }

        // forager: prefer high-relay-quality peers.
        let advice = forager::advise(&self.pheromone, signals.max_prefer);
        let rec = Recommendation::PreferPeers(advice.prefer.clone());
        if let Some(action) = rec.to_action() {
            if report.record(&action.detail, self.guards.authorize(&action, census)) {
                act.prefer_peers(&advice.prefer);
            }
        }

        // mantis: tarpit each misbehaving peer on an escalating hold.
        for offender in &signals.offenders {
            let hold = self.tarpit.record_offense(offender.clone());
            let rec = Recommendation::Tarpit {
                peer: offender.clone(),
                hold_secs: hold,
            };
            if let Some(action) = rec.to_action() {
                if report.record(&action.detail, self.guards.authorize(&action, census)) {
                    act.tarpit_peer(offender, hold);
                }
            }
        }

        // army_ant: on partition, reconnect across diverse fresh peers.
        if partition && !signals.bridge_candidates.is_empty() {
            let bridges = army_ant::select_bridges(&signals.bridge_candidates, signals.max_bridges);
            let rec = Recommendation::Bridge(bridges.clone());
            if let Some(action) = rec.to_action() {
                if report.record(&action.detail, self.guards.authorize(&action, census)) {
                    act.open_bridges(&bridges);
                }
            }
        }

        // centipede: fan the next block over diverse legs (blocks only).
        if !signals.leg_candidates.is_empty() {
            let legs = centipede::select_legs(&signals.leg_candidates, signals.max_legs);
            let rec = Recommendation::Legs(legs.clone());
            if let Some(action) = rec.to_action() {
                if report.record(&action.detail, self.guards.authorize(&action, census)) {
                    act.set_relay_legs(&legs);
                }
            }
        }

        // cicada: pace node-local housekeeping on prime-varied jitter.
        let next = self.cicada.advance();
        if let Some(action) = (Recommendation::Housekeep { next_secs: next }).to_action() {
            if report.record(&action.detail, self.guards.authorize(&action, census)) {
                act.schedule_housekeep(next);
            }
        }

        // firefly: fire a synchronized cover pulse when the phase wraps.
        if self.firefly.tick() {
            if let Some(action) = Recommendation::Pulse.to_action() {
                if report.record(&action.detail, self.guards.authorize(&action, census)) {
                    act.cover_pulse();
                }
            }
        }

        // stick_insect: reassert the canonical wire profile (idempotent).
        if let Some(action) = Recommendation::Wire.to_action() {
            if report.record(&action.detail, self.guards.authorize(&action, census)) {
                act.assert_wire_profile();
            }
        }

        report
    }
}

/// A completely inert actuator: every requested action is only *logged*
/// (`target: "colony::act"`, INFO) as "colony would: …", and nothing on the
/// network is touched. This is the safe Act host for a live node/sidecar — it
/// runs the full caste→guard→action pipeline as an observable **dry run**, so
/// the colony can be exercised end-to-end on a real network with zero risk
/// while a real, network-mutating actuator is designed and reviewed
/// separately. When the kill switch is armed, this reports exactly what the
/// colony *would* do; it never does it.
#[derive(Clone, Copy, Debug, Default)]
pub struct LoggingActuator;

impl ColonyActuator for LoggingActuator {
    fn prefer_peers(&self, peers: &[PeerKey]) {
        tracing::info!(target: "colony::act", "would prefer {} peer(s)", peers.len());
    }
    fn tarpit_peer(&self, peer: &TarpitKey, hold_secs: u64) {
        tracing::info!(target: "colony::act", "would tarpit {} for {}s", peer.0, hold_secs);
    }
    fn open_bridges(&self, candidates: &[BridgeCandidate]) {
        tracing::info!(target: "colony::act", "would open {} bridge(s)", candidates.len());
    }
    fn set_relay_legs(&self, legs: &[Leg]) {
        tracing::info!(target: "colony::act", "would relay over {} leg(s)", legs.len());
    }
    fn set_swarm_mode(&self, mode: SwarmMode) {
        tracing::info!(target: "colony::act", "would set relay mode {mode:?}");
    }
    fn schedule_housekeep(&self, next_secs: u64) {
        tracing::info!(target: "colony::act", "would housekeep in {next_secs}s");
    }
    fn cover_pulse(&self) {
        tracing::info!(target: "colony::act", "would emit cover pulse");
    }
    fn assert_wire_profile(&self) {
        tracing::debug!(target: "colony::act", "would assert canonical wire profile");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;

    /// Records every actuator call so tests can assert exactly what fired.
    #[derive(Default)]
    struct SpyActuator {
        calls: RefCell<Vec<&'static str>>,
    }
    impl SpyActuator {
        fn calls(&self) -> Vec<&'static str> {
            self.calls.borrow().clone()
        }
    }
    impl ColonyActuator for SpyActuator {
        fn prefer_peers(&self, _: &[PeerKey]) {
            self.calls.borrow_mut().push("prefer_peers");
        }
        fn tarpit_peer(&self, _: &TarpitKey, _: u64) {
            self.calls.borrow_mut().push("tarpit_peer");
        }
        fn open_bridges(&self, _: &[BridgeCandidate]) {
            self.calls.borrow_mut().push("open_bridges");
        }
        fn set_relay_legs(&self, _: &[Leg]) {
            self.calls.borrow_mut().push("set_relay_legs");
        }
        fn set_swarm_mode(&self, _: SwarmMode) {
            self.calls.borrow_mut().push("set_swarm_mode");
        }
        fn schedule_housekeep(&self, _: u64) {
            self.calls.borrow_mut().push("schedule_housekeep");
        }
        fn cover_pulse(&self) {
            self.calls.borrow_mut().push("cover_pulse");
        }
        fn assert_wire_profile(&self) {
            self.calls.borrow_mut().push("assert_wire_profile");
        }
    }

    fn signals_with_activity() -> ColonySignals {
        ColonySignals {
            sentinel: SentinelReading {
                inbound_new_per_min: 5,
                largest_netgroup_pct: 20,
                duplicate_msg_pct: 2,
                unreachable_sentinel_pct: 5,
            },
            density_pct: 10,
            bridge_candidates: vec![BridgeCandidate::new("a", 1, 5)],
            leg_candidates: vec![Leg::new("l1", 2), Leg::new("l2", 3)],
            offenders: vec![TarpitKey("bad".into())],
            census: NetgroupCensus {
                distinct_netgroups: 8,
                total_outbound: 8,
            },
            max_prefer: 4,
            max_legs: 2,
            max_bridges: 2,
        }
    }

    /// THE critical Act test: with the guards DISARMED (default), a full tick
    /// makes ZERO actuator calls no matter what the signals are.
    #[test]
    fn disarmed_guards_make_zero_actuator_calls() {
        let guards = Arc::new(ColonyGuards::with_defaults()); // disarmed
        let mut actor = ColonyActor::new(guards, 30, 7);
        let spy = SpyActuator::default();
        let report = actor.tick(&signals_with_activity(), &spy);
        assert!(spy.calls().is_empty(), "disarmed colony must not act");
        assert!(report.allowed.is_empty());
        assert!(!report.denied.is_empty());
        assert!(report.denied.iter().all(|(_, r)| *r == "kill_switch"));
    }

    /// Armed, with healthy diversity, the low-risk always-on castes fire.
    #[test]
    fn armed_guards_allow_actions() {
        let guards = Arc::new(ColonyGuards::with_defaults());
        guards.arm();
        let mut actor = ColonyActor::new(guards, 30, 7);
        let spy = SpyActuator::default();
        actor.tick(&signals_with_activity(), &spy);
        let calls = spy.calls();
        // Housekeep (cicada), swarm mode (locust), wire profile (stick_insect),
        // and the tarpit for the offender all clear their guards.
        assert!(calls.contains(&"schedule_housekeep"));
        assert!(calls.contains(&"set_swarm_mode"));
        assert!(calls.contains(&"assert_wire_profile"));
        assert!(calls.contains(&"tarpit_peer"));
    }

    /// The logging (dry-run) actuator runs the whole armed pipeline without
    /// panicking — the safe way to exercise every caste on a live network.
    #[test]
    fn logging_actuator_runs_full_pipeline_armed() {
        let guards = Arc::new(ColonyGuards::with_defaults());
        guards.arm();
        let mut actor = ColonyActor::new(guards, 30, 7);
        let report = actor.tick(&signals_with_activity(), &LoggingActuator);
        // Something cleared its guard (housekeep/mode/wire at minimum).
        assert!(!report.allowed.is_empty());
    }

    /// The diversity floor stops a topology-narrowing act even when armed.
    #[test]
    fn diversity_floor_blocks_bridges_at_minimum() {
        let guards = Arc::new(ColonyGuards::with_defaults());
        guards.arm();
        let mut actor = ColonyActor::new(guards, 30, 7);
        let spy = SpyActuator::default();
        let mut sig = signals_with_activity();
        // Force a partition so army_ant proposes bridges, but pin diversity AT
        // the floor so the guard must refuse the reconnect.
        sig.sentinel.unreachable_sentinel_pct = 90; // partition-onset tell
        sig.census = NetgroupCensus {
            distinct_netgroups: 4,
            total_outbound: 4,
        };
        actor.tick(&sig, &spy);
        assert!(
            !spy.calls().contains(&"open_bridges"),
            "bridges must be refused at the diversity floor"
        );
    }
}
