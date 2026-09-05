//! guards — the non-bypassable middleware every colony action passes through.
//!
//! honeybee ([`super::honeybee`]) decides *whether a threat is real*. guards
//! decides *whether a response may fire*, and it is the layer that keeps the act
//! phase from becoming an attack surface even when a threat is genuine. Written
//! **once**, here, and wrapped around every caste's advice — never
//! reimplemented per caste, so there is exactly one place these invariants live
//! and exactly one place to audit.
//!
//! Five guards, each closing a specific way an automated response can be turned
//! against its own network:
//!
//! 1. **Kill switch.** An operator can disable all colony action instantly.
//!    Deny-all when set. The escape hatch every autonomous subsystem must have.
//! 2. **Confidence gate.** An action names the minimum honeybee confidence it
//!    requires; below it, deny. Ties every response to quorum-gated trust so
//!    nothing fires on a forgeable single signal.
//! 3. **Rate limit.** Bounds how often an action class may fire in a window, so
//!    even a genuine-but-flapping signal cannot make the colony thrash the
//!    network (or amplify a flood by reacting to it repeatedly).
//! 4. **Max-dwell.** The subtle one. An attacker's goal is often not to defeat a
//!    defense but to **trap you in it** — hold you in an expensive
//!    battened-down/quarantine/swarm posture indefinitely, burning bandwidth and
//!    shrinking connectivity. A defensive posture auto-releases after
//!    `max_dwell_secs` unless quorum **re-confirms with fresh evidence**.
//!    Defensive modes are sticky enough not to flap, never a one-way door.
//! 5. **Diversity floor.** Any action that drops/rotates/limits peers must never
//!    reduce netgroup diversity below a hard floor — otherwise the anti-eclipse
//!    machinery (army_ant bridges, aphid rotation, pillbug batten-down) becomes
//!    an eclipse *vector*. Diversity is the one thing no response may spend.
//!
//! ## Purity
//!
//! Deterministic given `(request, state, now)`. `now` and the rate-limit ledger
//! are passed in; there is no clock read and no RNG. The sidecar owns the
//! [`GuardState`] and the wall clock; the decision itself is a pure function, so
//! every guard is exhaustively testable.

use super::honeybee::Confidence;

/// What a response would do to the peer set, so the diversity guard can check
/// it. Actions that don't touch peers use [`PeerEffect::None`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PeerEffect {
    /// Does not change peer connectivity (e.g. adjusting relay legs).
    None,
    /// Would leave the node connected to this many distinct netgroups. The
    /// diversity floor rejects the action if this drops below the floor.
    ResultingNetgroups(u32),
}

/// Whether an action holds a defensive posture (subject to max-dwell) or is a
/// one-shot response.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ActionKind {
    /// One-shot: fire and forget (rate-limited, but no dwell).
    OneShot,
    /// Enters/holds a defensive posture: subject to max-dwell auto-release.
    Posture,
}

/// A proposed colony action, presented to the guards for authorization.
#[derive(Clone, Copy, Debug)]
pub struct ActionRequest {
    /// Stable label identifying the action class (rate-limit key + logging).
    pub label: &'static str,
    pub kind: ActionKind,
    /// honeybee confidence backing this action (`0..=100`).
    pub confidence: Confidence,
    /// Minimum confidence this action requires to fire.
    pub min_confidence: u8,
    /// Effect on peer connectivity, for the diversity floor.
    pub peer_effect: PeerEffect,
}

/// Guard policy.
#[derive(Clone, Copy, Debug)]
pub struct GuardParams {
    /// Never let a peer-affecting action drop netgroup diversity below this.
    pub diversity_floor: u32,
    /// Max authorizations per action label within `window_secs`.
    pub max_per_window: u32,
    pub window_secs: u64,
    /// A held posture auto-releases after this long without re-confirmation.
    pub max_dwell_secs: u64,
}

impl GuardParams {
    /// Conservative defaults: keep at least 4 netgroups, at most 6 actions per
    /// class per 10 minutes, postures auto-release after 30 minutes unless
    /// re-confirmed.
    pub fn standard() -> Self {
        GuardParams {
            diversity_floor: 4,
            max_per_window: 6,
            window_secs: 600,
            max_dwell_secs: 1800,
        }
    }
}

/// Why an action was denied. Distinct variants so the sidecar can log/act on the
/// specific reason (a rate-limit is routine; a diversity-floor breach is a
/// caste trying to do something it must never do).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DenyReason {
    /// The operator kill switch is engaged.
    KillSwitch,
    /// Confidence below the action's threshold.
    BelowConfidence { have: u8, need: u8 },
    /// Too many actions of this class in the window.
    RateLimited,
    /// Would drop netgroup diversity below the floor.
    WouldBreakDiversityFloor { resulting: u32, floor: u32 },
}

/// A single label's recent authorization timestamps, for the rate-limit window.
#[derive(Clone, Debug, Default)]
struct LabelLedger {
    label: &'static str,
    /// Unix seconds of recent allows, pruned to the window on each check.
    recent: Vec<u64>,
}

/// Mutable guard state owned by the sidecar. Not `Copy`; passed by `&mut`.
#[derive(Clone, Debug, Default)]
pub struct GuardState {
    kill_switch: bool,
    ledgers: Vec<LabelLedger>,
}

impl GuardState {
    pub fn new() -> Self {
        GuardState::default()
    }

    /// Engage/disengage the operator kill switch. While engaged, [`authorize`]
    /// denies everything.
    pub fn set_kill_switch(&mut self, engaged: bool) {
        self.kill_switch = engaged;
    }

    pub fn kill_switch_engaged(&self) -> bool {
        self.kill_switch
    }

    fn ledger_mut(&mut self, label: &'static str) -> &mut LabelLedger {
        if let Some(i) = self.ledgers.iter().position(|l| l.label == label) {
            return &mut self.ledgers[i];
        }
        self.ledgers.push(LabelLedger { label, recent: Vec::new() });
        self.ledgers.last_mut().unwrap()
    }
}

/// Authorize (or deny) a proposed action, and — on allow — record it against the
/// rate-limit ledger. Order of checks is deliberate: cheapest and most absolute
/// first (kill switch), then confidence, then the stateful rate limit, then the
/// diversity floor. The ledger is only touched on an otherwise-successful allow,
/// so a denied action never consumes rate budget.
pub fn authorize(
    req: &ActionRequest,
    state: &mut GuardState,
    now: u64,
    p: &GuardParams,
) -> Result<(), DenyReason> {
    // 1. Kill switch — absolute.
    if state.kill_switch {
        return Err(DenyReason::KillSwitch);
    }

    // 2. Confidence gate — ties every response to quorum-gated trust.
    if req.confidence < req.min_confidence {
        return Err(DenyReason::BelowConfidence {
            have: req.confidence,
            need: req.min_confidence,
        });
    }

    // 3. Diversity floor — a response may never spend below-floor connectivity.
    //    Checked before the rate ledger is touched so a floor-breaking request
    //    is rejected without consuming budget.
    if let PeerEffect::ResultingNetgroups(n) = req.peer_effect {
        if n < p.diversity_floor {
            return Err(DenyReason::WouldBreakDiversityFloor {
                resulting: n,
                floor: p.diversity_floor,
            });
        }
    }

    // 4. Rate limit — prune the window, then check, then (on allow) record.
    let ledger = state.ledger_mut(req.label);
    let cutoff = now.saturating_sub(p.window_secs);
    ledger.recent.retain(|&t| t >= cutoff);
    if ledger.recent.len() as u32 >= p.max_per_window {
        return Err(DenyReason::RateLimited);
    }
    ledger.recent.push(now);
    Ok(())
}

/// Should a held defensive posture be released?
///
/// Max-dwell: a posture entered at `entered_at` and last re-confirmed by fresh
/// quorum at `last_reconfirm_at` must auto-release once `max_dwell_secs` have
/// passed *since the last re-confirmation*. Re-confirmation resets the clock;
/// absent it, the posture cannot be held open indefinitely — the defense against
/// an attacker trapping the node in an expensive mode.
///
/// Returns `true` when the posture has dwelt past its budget without fresh
/// re-confirmation and should be released back toward normal.
pub fn posture_expired(entered_at: u64, last_reconfirm_at: u64, now: u64, p: &GuardParams) -> bool {
    let anchor = entered_at.max(last_reconfirm_at);
    now.saturating_sub(anchor) > p.max_dwell_secs
}

#[cfg(test)]
mod tests {
    use super::*;

    const NOW: u64 = 100_000;

    fn req(label: &'static str, confidence: u8, min: u8) -> ActionRequest {
        ActionRequest {
            label,
            kind: ActionKind::OneShot,
            confidence,
            min_confidence: min,
            peer_effect: PeerEffect::None,
        }
    }

    #[test]
    fn kill_switch_denies_everything() {
        let p = GuardParams::standard();
        let mut s = GuardState::new();
        s.set_kill_switch(true);
        // Even a maximally-confident action is denied.
        let r = req("anything", 100, 0);
        assert_eq!(authorize(&r, &mut s, NOW, &p), Err(DenyReason::KillSwitch));
    }

    #[test]
    fn confidence_gate_blocks_low_confidence() {
        let p = GuardParams::standard();
        let mut s = GuardState::new();
        let r = req("tarpit", 40, 50);
        assert_eq!(
            authorize(&r, &mut s, NOW, &p),
            Err(DenyReason::BelowConfidence { have: 40, need: 50 })
        );
        // At/above threshold it passes.
        assert!(authorize(&req("tarpit", 50, 50), &mut s, NOW, &p).is_ok());
    }

    #[test]
    fn rate_limit_caps_actions_per_window() {
        let p = GuardParams::standard(); // max 6 / 600s
        let mut s = GuardState::new();
        for i in 0..p.max_per_window {
            assert!(
                authorize(&req("relay-legs", 100, 0), &mut s, NOW + i as u64, &p).is_ok(),
                "action {i} within budget"
            );
        }
        // One more within the window is denied.
        assert_eq!(
            authorize(&req("relay-legs", 100, 0), &mut s, NOW + 10, &p),
            Err(DenyReason::RateLimited)
        );
        // After the window slides past, budget is restored.
        assert!(authorize(&req("relay-legs", 100, 0), &mut s, NOW + p.window_secs + 11, &p).is_ok());
    }

    /// A denied action must not consume rate budget — otherwise a stream of
    /// low-confidence (denied) requests could exhaust the window and lock out a
    /// legitimate high-confidence action.
    #[test]
    fn denied_actions_do_not_consume_budget() {
        let p = GuardParams::standard();
        let mut s = GuardState::new();
        for i in 0..20 {
            // all denied on confidence
            let _ = authorize(&req("tarpit", 0, 50), &mut s, NOW + i, &p);
        }
        // budget is still fully available for a valid action
        for i in 0..p.max_per_window {
            assert!(authorize(&req("tarpit", 60, 50), &mut s, NOW + 100 + i as u64, &p).is_ok());
        }
    }

    /// The diversity floor is the one a caste must never cross: an action that
    /// would leave the node under the floor is rejected, and it does not consume
    /// rate budget.
    #[test]
    fn diversity_floor_is_never_crossed() {
        let p = GuardParams::standard(); // floor 4
        let mut s = GuardState::new();
        let breaking = ActionRequest {
            label: "peer-rotate",
            kind: ActionKind::OneShot,
            confidence: 100,
            min_confidence: 0,
            peer_effect: PeerEffect::ResultingNetgroups(3),
        };
        assert_eq!(
            authorize(&breaking, &mut s, NOW, &p),
            Err(DenyReason::WouldBreakDiversityFloor { resulting: 3, floor: 4 })
        );
        // At the floor it is allowed.
        let ok = ActionRequest { peer_effect: PeerEffect::ResultingNetgroups(4), ..breaking };
        assert!(authorize(&ok, &mut s, NOW, &p).is_ok());
    }

    // ─── max-dwell: the "trap me in defensive mode" defense ──────────────────

    #[test]
    fn posture_auto_releases_after_max_dwell() {
        let p = GuardParams::standard(); // 1800s
        let entered = NOW;
        // Within dwell, no reconfirmation yet: held.
        assert!(!posture_expired(entered, entered, NOW + 1000, &p));
        // Past dwell without reconfirmation: released.
        assert!(posture_expired(entered, entered, NOW + p.max_dwell_secs + 1, &p));
    }

    #[test]
    fn reconfirmation_resets_the_dwell_clock() {
        let p = GuardParams::standard();
        let entered = NOW;
        let reconfirm = NOW + p.max_dwell_secs - 10; // fresh quorum just before expiry
        // Just after the original budget but soon after reconfirmation: still held.
        assert!(!posture_expired(entered, reconfirm, NOW + p.max_dwell_secs + 5, &p));
        // But it cannot be held forever: past dwell since the LAST reconfirm, released.
        assert!(posture_expired(entered, reconfirm, reconfirm + p.max_dwell_secs + 1, &p));
    }
}
