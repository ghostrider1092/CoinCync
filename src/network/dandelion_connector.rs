//! Dandelion++ privacy-policy connector.
//!
//! All adaptive privacy logic lives HERE, behind a swappable policy, so the
//! tuned [`crate::network::dandelion::DandelionRouter`] core is never edited to
//! change behavior — it only asks this connector a question. The default policy
//! ([`PrivacyPolicy::Fixed`]) reproduces the historical strict decision (below
//! the target ⇒ degraded), so enabling the connector with the default changes
//! nothing about *when* we consider privacy reduced; an [`PrivacyPolicy::Adaptive`]
//! policy can be injected (gated) to make the SIGNAL honest on a small network.
//!
//! ## Scope (V1): assessment + honest classification only
//! This connector decides how to *describe* the current peer set, which drives
//! the router's (edge-triggered) log line. The router's actual stem/fluff
//! ROUTING decision is deliberately left untouched and fail-safe (stem only
//! when truly adequate). Routing-parameter adaptation — stretching the stem
//! embargo when peers are scarce (timing decorrelation), and later cover
//! traffic — is a deliberate step 2 that this connector already reserves a slot
//! for ([`PrivacyPolicy::stem_embargo_scale`]) but the router does not yet
//! consult. Adding those features means extending THIS module, not the router.
//!
//! Catalogued on the Manifold (the connector catalog) under the valve name
//! [`CONNECTOR_NAME`] — see [`crate::connectors`].

/// This connector's name on the Manifold catalog ([`crate::connectors`]).
/// Mechanical/valve theme: a *baffle* regulates and obscures flow — exactly
/// what this does to transaction dispersal for sender privacy.
pub const CONNECTOR_NAME: &str = "Baffle";

/// How well the current outbound peer set supports Dandelion++ stem anonymity.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PrivacyLevel {
    /// At or above the anonymity target — full stem privacy.
    Adequate,
    /// Below target, but the network itself has not offered more this run —
    /// expected on a small network, NOT an actionable misconfiguration.
    SizeLimited,
    /// Below target AND fewer peers than this node has actually had this run —
    /// a real connectivity regression worth surfacing.
    Degraded,
}

/// Result of assessing a given outbound peer count.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PrivacyAssessment {
    pub level: PrivacyLevel,
    /// Whether this state warrants a WARN-level log (true only for `Degraded`
    /// with at least one peer — full isolation is the re-bootstrap path's job).
    pub warn: bool,
    /// The CONFIGURED anonymity target (what "adequate" means). Use this for
    /// display — it is always the real target (e.g. 3), never collapsed by the
    /// network's current capacity.
    pub target: usize,
    /// Anonymity target effective for this network's observed capacity: never
    /// above the configured target, and never claiming more than the network
    /// has actually offered. An internal capacity figure, not for the "N-peer
    /// target" wording (it is 0 when no peers have ever been seen).
    pub effective_target: usize,
    pub observed: usize,
}

/// Swappable privacy policy. `Fixed` keeps the historical strict classification;
/// `Adaptive` scales the SIGNAL to the network's observed capacity so a
/// genuinely small network is not reported as misconfigured.
#[derive(Debug, Clone)]
pub enum PrivacyPolicy {
    /// Historical behavior: below `target` (and non-empty) ⇒ `Degraded`.
    Fixed { target: usize },
    /// Size-aware: remembers the peak outbound count seen this run as a proxy
    /// for what the network can actually provide, and distinguishes "small
    /// network" (`SizeLimited`, expected) from a real drop (`Degraded`).
    Adaptive { target: usize, peak_outbound: usize },
}

impl PrivacyPolicy {
    pub fn fixed(target: usize) -> Self {
        PrivacyPolicy::Fixed { target }
    }

    pub fn adaptive(target: usize) -> Self {
        PrivacyPolicy::Adaptive {
            target,
            peak_outbound: 0,
        }
    }

    /// Assess the current outbound peer count. Takes `&mut self` because the
    /// adaptive policy updates the peak it has seen this run (its network-size
    /// proxy).
    pub fn assess(&mut self, outbound: usize) -> PrivacyAssessment {
        match self {
            PrivacyPolicy::Fixed { target } => {
                let target = *target;
                let level = if outbound >= target {
                    PrivacyLevel::Adequate
                } else {
                    PrivacyLevel::Degraded
                };
                PrivacyAssessment {
                    level,
                    warn: level == PrivacyLevel::Degraded && outbound > 0,
                    target,
                    effective_target: target,
                    observed: outbound,
                }
            }
            PrivacyPolicy::Adaptive {
                target,
                peak_outbound,
            } => {
                let target = *target;
                if outbound > *peak_outbound {
                    *peak_outbound = outbound;
                }
                let peak = *peak_outbound;
                let level = if outbound >= target {
                    PrivacyLevel::Adequate
                } else if outbound < peak {
                    // We have HAD more peers this run → this is a real drop.
                    PrivacyLevel::Degraded
                } else {
                    // Never had more → the network is simply small; expected.
                    PrivacyLevel::SizeLimited
                };
                PrivacyAssessment {
                    level,
                    warn: level == PrivacyLevel::Degraded && outbound > 0,
                    target,
                    effective_target: target.min(peak.max(outbound)),
                    observed: outbound,
                }
            }
        }
    }

    /// Step-2 reservation (the router does NOT consult this yet): how much to
    /// stretch the stem embargo when peers are scarce, to add timing
    /// decorrelation where stem-path diversity is unavailable. Bounded to 3×.
    /// `Fixed` never changes timing (returns 1.0), so it is a strict no-op.
    pub fn stem_embargo_scale(&self, outbound: usize) -> f64 {
        match self {
            PrivacyPolicy::Fixed { .. } => 1.0,
            PrivacyPolicy::Adaptive { target, .. } => {
                if outbound >= *target {
                    1.0
                } else {
                    ((*target as f64) / (outbound.max(1) as f64)).min(3.0)
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fixed_policy_matches_historical_strict_classification() {
        let mut p = PrivacyPolicy::fixed(3);
        assert_eq!(p.assess(3).level, PrivacyLevel::Adequate);
        assert!(!p.assess(3).warn);
        assert_eq!(p.assess(2).level, PrivacyLevel::Degraded);
        assert!(p.assess(2).warn, "below target must warn, as before");
        // Full isolation is the re-bootstrap path's concern, not this warn.
        assert!(!p.assess(0).warn);
    }

    #[test]
    fn adaptive_distinguishes_small_network_from_a_real_drop() {
        let mut p = PrivacyPolicy::adaptive(3);
        // Small network, never had >2 peers → size-limited, NOT alarmed.
        assert_eq!(p.assess(1).level, PrivacyLevel::SizeLimited);
        assert!(!p.assess(2).warn);
        assert_eq!(p.assess(2).level, PrivacyLevel::SizeLimited);
        // Network grew to the target → adequate.
        assert_eq!(p.assess(3).level, PrivacyLevel::Adequate);
        // Then collapsed to 1 AFTER having had 3 → a real regression → warn.
        let dropped = p.assess(1);
        assert_eq!(dropped.level, PrivacyLevel::Degraded);
        assert!(dropped.warn);
    }

    #[test]
    fn embargo_scales_with_scarcity_only_under_adaptive() {
        let fixed = PrivacyPolicy::fixed(3);
        assert_eq!(fixed.stem_embargo_scale(1), 1.0, "fixed is a strict no-op");
        assert_eq!(fixed.stem_embargo_scale(5), 1.0);

        let adaptive = PrivacyPolicy::adaptive(3);
        assert!(adaptive.stem_embargo_scale(1) > 1.0, "scarce peers stretch embargo");
        assert!(adaptive.stem_embargo_scale(1) <= 3.0, "but bounded");
        assert_eq!(adaptive.stem_embargo_scale(5), 1.0, "adequate peers → no change");
    }

    #[test]
    fn baffle_is_registered_on_the_manifold() {
        // The connector's own name must resolve to its Manifold entry, so the
        // catalog cannot silently drift from the code.
        let entry = crate::connectors::get(CONNECTOR_NAME)
            .expect("Baffle must be catalogued on the Manifold");
        assert_eq!(entry.name, CONNECTOR_NAME);
        assert_eq!(entry.domain, crate::connectors::Domain::Network);
    }
}
