//! Advise phase — one typed recommendation shape for every caste.
//!
//! Each caste's pure decision core already returns its own advice type
//! ([`PeerAdvice`], [`SwarmMode`], a tarpit hold, a bridge/leg set, …). This
//! module unifies them into a single [`Recommendation`] enum so the sidecar can
//! log them uniformly and the (gated) Act phase can consume them through one
//! path — without changing any core logic.
//!
//! A `Recommendation` is *advice only*: producing one changes nothing. It
//! becomes a candidate action solely by passing [`Recommendation::to_action`]
//! and then `guard::ColonyGuards::authorize`. Every advice type is a **public
//! signal** derivative; nothing here carries transaction or stem-phase data.

use crate::colony::army_ant::BridgeCandidate;
use crate::colony::centipede::Leg;
use crate::colony::guard::{ColonyAction, ColonyActionKind};
use crate::colony::locust::SwarmMode;
use crate::colony::mantis::TarpitKey;
use crate::colony::pheromone::PeerKey;

/// The unified advice a caste surfaces in a round. `None` = "nothing to do".
#[derive(Clone, Debug)]
pub enum Recommendation {
    /// forager: prefer these (high relay-quality) peers for retention/download.
    PreferPeers(Vec<PeerKey>),
    /// mantis: apply an escalating slow-hold to a misbehaving peer.
    Tarpit { peer: TarpitKey, hold_secs: u64 },
    /// army_ant: reconnect across these netgroup-diverse fresh peers (partition heal).
    Bridge(Vec<BridgeCandidate>),
    /// centipede: fan a block over these netgroup-diverse legs.
    Legs(Vec<Leg>),
    /// locust: adopt this density-adaptive relay mode.
    Mode(SwarmMode),
    /// cicada: schedule the next node-local housekeeping this many seconds out.
    Housekeep { next_secs: u64 },
    /// firefly: fire a synchronized cover-traffic pulse now.
    Pulse,
    /// stick_insect: (re)assert the canonical wire fingerprint / size buckets.
    Wire,
    /// No recommendation this round.
    None,
}

impl Recommendation {
    /// Convert advice into a guard-facing [`ColonyAction`], or `None` if the
    /// advice is a no-op (empty peer set, `Recommendation::None`, …). The
    /// action still has to clear `authorize` before anything happens.
    pub fn to_action(&self) -> Option<ColonyAction> {
        match self {
            Recommendation::PreferPeers(peers) if !peers.is_empty() => Some(ColonyAction::new(
                ColonyActionKind::PreferPeers,
                format!("prefer {} peer(s)", peers.len()),
            )),
            Recommendation::Tarpit { peer, hold_secs } => Some(ColonyAction::new(
                ColonyActionKind::Tarpit,
                format!("tarpit {} for {}s", peer.0, hold_secs),
            )),
            Recommendation::Bridge(cands) if !cands.is_empty() => Some(
                ColonyAction::new(
                    ColonyActionKind::BridgeReconnect,
                    format!("bridge across {} peer(s)", cands.len()),
                )
                .with_netgroups(cands.iter().map(|b| b.netgroup).collect()),
            ),
            Recommendation::Legs(legs) if !legs.is_empty() => Some(
                ColonyAction::new(
                    ColonyActionKind::RelayLegs,
                    format!("{} relay leg(s)", legs.len()),
                )
                .with_netgroups(legs.iter().map(|l| l.netgroup).collect()),
            ),
            Recommendation::Mode(mode) => Some(ColonyAction::new(
                ColonyActionKind::SwarmMode,
                format!("relay mode {mode:?}"),
            )),
            Recommendation::Housekeep { next_secs } => Some(ColonyAction::new(
                ColonyActionKind::Housekeep,
                format!("housekeep in {next_secs}s"),
            )),
            Recommendation::Pulse => Some(ColonyAction::new(
                ColonyActionKind::CoverPulse,
                "cover-traffic pulse",
            )),
            Recommendation::Wire => Some(ColonyAction::new(
                ColonyActionKind::WireProfile,
                "assert canonical wire profile",
            )),
            // No-op advice: empty peer/bridge/leg sets and `None`.
            _ => None,
        }
    }

    /// One-line human summary for Advise-phase logging (`caste (advise): …`).
    pub fn describe(&self) -> String {
        match self.to_action() {
            Some(a) => a.detail,
            None => "no-op".to_string(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_prefer_is_noop() {
        assert!(Recommendation::PreferPeers(vec![]).to_action().is_none());
        assert!(Recommendation::None.to_action().is_none());
    }

    #[test]
    fn tarpit_maps_to_tarpit_action() {
        let r = Recommendation::Tarpit {
            peer: TarpitKey("abc".into()),
            hold_secs: 4,
        };
        let a = r.to_action().unwrap();
        assert_eq!(a.kind, ColonyActionKind::Tarpit);
    }

    #[test]
    fn bridge_carries_netgroups_for_the_diversity_floor() {
        let r = Recommendation::Bridge(vec![
            BridgeCandidate::new("a", 7, 10),
            BridgeCandidate::new("b", 42, 20),
        ]);
        let a = r.to_action().unwrap();
        assert_eq!(a.kind, ColonyActionKind::BridgeReconnect);
        assert_eq!(a.netgroups, vec![7, 42]);
    }

    #[test]
    fn mode_and_pulse_and_wire_map_through() {
        assert_eq!(
            Recommendation::Mode(SwarmMode::Gregarious)
                .to_action()
                .unwrap()
                .kind,
            ColonyActionKind::SwarmMode
        );
        assert_eq!(
            Recommendation::Pulse.to_action().unwrap().kind,
            ColonyActionKind::CoverPulse
        );
        assert_eq!(
            Recommendation::Wire.to_action().unwrap().kind,
            ColonyActionKind::WireProfile
        );
    }
}
