//! Colony Act-phase guard layer.
//!
//! **Every** Act-phase behavior a caste would perform on the live node routes
//! through [`ColonyGuards::authorize`] and *only* through it. The guards
//! enforce, in order:
//!
//! 1. the global **kill switch** — default DISARMED, so a fresh binary on the
//!    live network can never act ([`kill_switch`]);
//! 2. per-action **rate limits** — a caste cannot spam an action ([`rate_limit`]);
//! 3. **diversity floors** — no action may drop outbound peer/netgroup
//!    diversity below a minimum ([`diversity`]).
//!
//! Peer-supplied telemetry is separately wrapped [`telemetry::Untrusted`] at
//! ingest and can only be unwrapped through a clamping sanitizer, so "treat
//! peer input as adversarial" is a type-level requirement, not a convention.
//!
//! This whole layer is **non-consensus**: it can gate/deny colony behavior but
//! can never affect block validity. A guard bug degrades *margin*, never
//! *validity* (colony README invariant B.3 — "never weaken a defense").

pub mod diversity;
pub mod kill_switch;
pub mod rate_limit;
pub mod telemetry;

use std::sync::Mutex;

pub use diversity::{DiversityFloor, NetgroupCensus};
pub use kill_switch::KillSwitch;
pub use rate_limit::ActionRateLimiter;

/// The kind of Act a caste wants to perform. Used to key rate limits and to
/// decide whether the diversity floor applies.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum ColonyActionKind {
    /// forager: bias peer retention/download toward high-relay-quality peers.
    PreferPeers,
    /// mantis: apply an escalating slow-hold (tarpit) to a misbehaving peer.
    Tarpit,
    /// army_ant: open reconnections to netgroup-diverse fresh peers on partition.
    BridgeReconnect,
    /// centipede: fan a block-announce over several netgroup-diverse legs.
    RelayLegs,
    /// locust: change the density-adaptive relay/padding mode.
    SwarmMode,
    /// cicada: pace node-local (never tx/stem) housekeeping on prime intervals.
    Housekeep,
    /// firefly: emit a synchronized cover-traffic pulse.
    CoverPulse,
    /// stick_insect: (re)assert the canonical wire fingerprint / size buckets.
    WireProfile,
}

impl ColonyActionKind {
    /// True for actions that can concentrate or reduce outbound peer diversity
    /// and must therefore pass the diversity floor.
    pub fn affects_diversity(self) -> bool {
        matches!(
            self,
            ColonyActionKind::PreferPeers
                | ColonyActionKind::Tarpit
                | ColonyActionKind::BridgeReconnect
                | ColonyActionKind::RelayLegs
        )
    }
}

/// A guard-facing description of a single Act a caste wants to perform. The
/// typed *recommendation* lives in the Advise layer; this carries only what the
/// guards need to make an allow/deny decision.
#[derive(Clone, Debug)]
pub struct ColonyAction {
    pub kind: ColonyActionKind,
    /// Netgroups this action touches (for diagnostics; the diversity floor
    /// inspects the live census, not this list).
    pub netgroups: Vec<u16>,
    /// Human-readable label for the deny/allow log line.
    pub detail: String,
}

impl ColonyAction {
    pub fn new(kind: ColonyActionKind, detail: impl Into<String>) -> Self {
        Self {
            kind,
            netgroups: Vec::new(),
            detail: detail.into(),
        }
    }

    pub fn with_netgroups(mut self, netgroups: Vec<u16>) -> Self {
        self.netgroups = netgroups;
        self
    }
}

/// Result of [`ColonyGuards::authorize`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GuardDecision {
    Allow,
    /// Denied, with a short static reason for logging/metrics.
    Deny(&'static str),
}

impl GuardDecision {
    pub fn is_allowed(self) -> bool {
        matches!(self, GuardDecision::Allow)
    }
}

/// The single authorization gate every colony Act passes through.
#[derive(Debug)]
pub struct ColonyGuards {
    kill: KillSwitch,
    rate: Mutex<ActionRateLimiter>,
    floor: DiversityFloor,
}

impl ColonyGuards {
    /// Construct guards from a config. The kill switch starts **disarmed**
    /// regardless of config; call [`ColonyGuards::arm`] explicitly (only when
    /// the operator has opted in) to allow Act.
    pub fn new(floor: DiversityFloor, rate: ActionRateLimiter) -> Self {
        Self {
            kill: KillSwitch::new_disarmed(),
            rate: Mutex::new(rate),
            floor,
        }
    }

    /// Sensible defaults: Act OFF, floor of 4 netgroups / 4 outbound, default
    /// per-action budgets.
    pub fn with_defaults() -> Self {
        Self::new(DiversityFloor::default(), ActionRateLimiter::with_default_budgets())
    }

    /// Arm the kill switch (allow Act). Only ever called on explicit operator
    /// opt-in; a fresh binary never calls this.
    pub fn arm(&self) {
        self.kill.arm();
    }

    /// Disarm the kill switch (block all Act). Reversible, instant.
    pub fn disarm(&self) {
        self.kill.disarm();
    }

    pub fn is_armed(&self) -> bool {
        self.kill.is_armed()
    }

    /// Authorize one Act. **Returns `Deny` unless the kill switch is armed AND
    /// the per-action rate budget allows AND the diversity floor is satisfied.**
    /// The order matters: the kill switch is checked first, so a disarmed node
    /// consumes no rate budget and never inspects the census.
    pub fn authorize(&self, action: &ColonyAction, census: &NetgroupCensus) -> GuardDecision {
        if !self.kill.is_armed() {
            return self.denied(action, "kill_switch");
        }
        // Rate limit is checked before the diversity floor so a denied-by-floor
        // action doesn't also burn a token (avoids double-penalizing a caste
        // whose action the floor rejects for reasons outside its control).
        if !self.floor.permits(census, action) {
            return self.denied(action, "diversity_floor");
        }
        if !self
            .rate
            .lock()
            .expect("colony rate limiter mutex poisoned")
            .try_consume(action.kind)
        {
            return self.denied(action, "rate_limit");
        }
        tracing::trace!(kind = ?action.kind, detail = %action.detail, "colony act: allowed");
        GuardDecision::Allow
    }

    fn denied(&self, action: &ColonyAction, reason: &'static str) -> GuardDecision {
        tracing::debug!(
            kind = ?action.kind,
            detail = %action.detail,
            reason,
            "colony act: denied"
        );
        GuardDecision::Deny(reason)
    }
}

impl Default for ColonyGuards {
    fn default() -> Self {
        Self::with_defaults()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn act() -> ColonyAction {
        ColonyAction::new(ColonyActionKind::WireProfile, "test")
    }

    fn healthy_census() -> NetgroupCensus {
        NetgroupCensus {
            distinct_netgroups: 8,
            total_outbound: 8,
        }
    }

    /// THE most important test: a fresh guard set (kill switch disarmed) denies
    /// every action. A new binary on the live network is inert by construction.
    #[test]
    fn fresh_guards_deny_everything() {
        let g = ColonyGuards::with_defaults();
        assert!(!g.is_armed());
        assert_eq!(
            g.authorize(&act(), &healthy_census()),
            GuardDecision::Deny("kill_switch")
        );
        // Even a diversity-affecting action is denied at the kill switch first.
        let prefer = ColonyAction::new(ColonyActionKind::PreferPeers, "prefer");
        assert_eq!(
            g.authorize(&prefer, &healthy_census()),
            GuardDecision::Deny("kill_switch")
        );
    }

    #[test]
    fn arm_disarm_flips_authorization() {
        let g = ColonyGuards::with_defaults();
        g.arm();
        assert!(g.authorize(&act(), &healthy_census()).is_allowed());
        g.disarm();
        assert_eq!(
            g.authorize(&act(), &healthy_census()),
            GuardDecision::Deny("kill_switch")
        );
    }

    #[test]
    fn diversity_floor_blocks_when_at_minimum() {
        let g = ColonyGuards::with_defaults();
        g.arm();
        let at_floor = NetgroupCensus {
            distinct_netgroups: 4, // == default min; not strictly above
            total_outbound: 4,
        };
        let prefer = ColonyAction::new(ColonyActionKind::PreferPeers, "prefer");
        assert_eq!(
            g.authorize(&prefer, &at_floor),
            GuardDecision::Deny("diversity_floor")
        );
        // A non-diversity action (wire profile) is still allowed at the floor.
        assert!(g.authorize(&act(), &at_floor).is_allowed());
    }

    #[test]
    fn rate_limit_denies_after_budget() {
        let g = ColonyGuards::new(
            DiversityFloor::default(),
            ActionRateLimiter::for_test_single_shot(ColonyActionKind::CoverPulse),
        );
        g.arm();
        let pulse = ColonyAction::new(ColonyActionKind::CoverPulse, "pulse");
        assert!(g.authorize(&pulse, &healthy_census()).is_allowed());
        // Second within the window: denied by rate limit.
        assert_eq!(
            g.authorize(&pulse, &healthy_census()),
            GuardDecision::Deny("rate_limit")
        );
    }
}
