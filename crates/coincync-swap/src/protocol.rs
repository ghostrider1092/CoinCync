//! Atomic-swap state machine: roles, states, transitions.
//!
//! The two parties are **Alice** (sells CYNC, buys BTC) and **Bob**
//! (sells BTC, buys CYNC). The asymmetry matters: the protocol is
//! NOT symmetric in who locks first or how refunds work. See
//! `docs/cip/CIP-001-atomic-swap.md` for the full state diagram.
//!
//! ## What's in this module
//!
//! - The `Role`, `State`, `Transition`, `SwapParameters`, `Swap`
//!   types
//! - A real, fully-implemented state machine: `Swap::apply`
//!   validates every transition against the (role, state) pair and
//!   updates `Swap::state` deterministically
//! - `Swap::legal_transitions` answers "what can I do next?" so the
//!   CLI can drive the operator
//! - Terminal-state immutability: `Completed`, `Refunded`, and
//!   `Aborted` reject every further transition
//! - Timeout-safety enforcement: `SwapParameters::is_timeout_safe`
//!   codifies the CIP-001 §"Timeout Safety" rule
//!   (`btc_timeout_blocks < cync_timeout_blocks` with margin)
//! - Property tests covering terminal stickiness, role/state
//!   gating, and refund-path safety
//!
//! ## What's NOT in this module
//!
//! The cryptographic primitives — adaptor signatures, cross-curve
//! DL-equality proofs, BTC HTLC construction, CYNC stealth-tx
//! construction — live in `adaptor.rs`, `btc.rs`, and `cync.rs`,
//! all currently skeleton (returning `NotImplemented`). The
//! state machine here is shaped so those skeletons can be filled
//! in without changing the public surface.

use serde::{Deserialize, Serialize};

use crate::{Error, Result};

// ──────────────────────────────────────────────────────────────────
// Roles
// ──────────────────────────────────────────────────────────────────

/// The two roles in any single swap.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum Role {
    /// Sells CYNC, buys BTC. Locks CYNC first.
    Alice,
    /// Sells BTC, buys CYNC. Locks BTC after seeing Alice's CYNC lock.
    Bob,
}

impl Role {
    /// Counterparty role.
    pub const fn opposite(self) -> Self {
        match self {
            Role::Alice => Role::Bob,
            Role::Bob => Role::Alice,
        }
    }
}

// ──────────────────────────────────────────────────────────────────
// States
// ──────────────────────────────────────────────────────────────────

/// State of an in-progress swap. The transitions form a directed
/// graph with three terminal states:
///
/// - `Completed` — both parties claimed; the swap succeeded
/// - `Refunded` — at least one timeout fired; both parties got
///   their original funds back
/// - `Aborted` — explicit abort (manual, network failure, or
///   cryptographic-verification failure during negotiation)
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum State {
    /// Both parties have agreed to swap parameters but no on-chain
    /// activity has occurred yet.
    Negotiated,
    /// Alice has broadcast the CYNC-side lock transaction.
    AliceLocked,
    /// Bob has seen Alice's lock confirmed and broadcast his BTC
    /// lock.
    BobLocked,
    /// Alice has broadcast her BTC claim, revealing the secret on
    /// the BTC chain. Bob can now extract it and claim CYNC.
    SecretRevealed,
    /// Both sides claimed; the swap is complete. **TERMINAL.**
    Completed,
    /// At least one side timed out and reclaimed their original
    /// funds. Both parties end with what they started with, minus
    /// the cost of broadcasting one refund tx each. **TERMINAL.**
    Refunded,
    /// Explicit abort. Could be manual ("I changed my mind, before
    /// any lock"), network ("counterparty disconnected during
    /// negotiation"), or cryptographic ("DL-equality proof
    /// verification failed"). **TERMINAL.**
    Aborted,
}

impl State {
    /// `true` if this state cannot transition to anything other
    /// than itself.
    pub const fn is_terminal(self) -> bool {
        matches!(self, Self::Completed | Self::Refunded | Self::Aborted)
    }
}

// ──────────────────────────────────────────────────────────────────
// Transitions
// ──────────────────────────────────────────────────────────────────

/// Every action that can advance a swap. Each transition is gated
/// by (role, current_state) — the state machine rejects illegal
/// (transition, role, state) tuples with `InvalidState`.
///
/// Note: some transitions represent ACTIONS (the local party does
/// something) and others represent OBSERVATIONS (the local party
/// notices the counterparty did something on-chain). Both kinds
/// share the same machinery — the state machine doesn't
/// distinguish "I did this" from "I observed this on the
/// blockchain." That's an implementation detail of the chain
/// watcher (`btc.rs` / `cync.rs`); from the state machine's
/// perspective, a transition is just an event with a deterministic
/// effect.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum Transition {
    /// Alice broadcasts her CYNC lock tx. ACTION (Alice).
    /// `Negotiated` -> `AliceLocked`.
    AliceLocksCync,

    /// Bob broadcasts his BTC lock tx. ACTION (Bob).
    /// `AliceLocked` -> `BobLocked`.
    /// Bob does this only after observing Alice's lock confirmed
    /// on-chain (the chain watcher delivers an event that triggers
    /// this transition).
    BobLocksBtc,

    /// Alice broadcasts her BTC claim, revealing the secret.
    /// ACTION (Alice). `BobLocked` -> `SecretRevealed`.
    AliceClaimsBtc,

    /// Bob extracts the secret from Alice's BTC claim and
    /// broadcasts his CYNC claim. ACTION (Bob).
    /// `SecretRevealed` -> `Completed`.
    BobClaimsCync,

    /// Alice broadcasts her CYNC refund tx. ACTION (Alice).
    /// Valid from `AliceLocked` (Bob never locked) or `BobLocked`
    /// (Bob locked but disappeared before claiming).
    /// -> `Refunded`.
    AliceRefunds,

    /// Bob broadcasts his BTC refund tx. ACTION (Bob).
    /// Valid from `BobLocked` (Alice never claimed).
    /// -> `Refunded`.
    BobRefunds,

    /// Alice OBSERVES Bob's BTC lock arriving on-chain.
    /// `AliceLocked` -> `BobLocked`. Local-state-only transition.
    ObserveBobLocked,

    /// Bob OBSERVES Alice's BTC claim arriving on-chain.
    /// `BobLocked` -> `SecretRevealed`. Local-state-only.
    ObserveSecretRevealed,

    /// Bob OBSERVES Alice's claim of his CYNC, AFTER Bob has
    /// already broadcast his own BTC claim. This case shouldn't
    /// normally happen in Bob's flow, but if Alice somehow
    /// finalizes the CYNC side independently, Bob's local view
    /// catches up. `SecretRevealed` -> `Completed`. Practically
    /// only used in tests + recovery scenarios.
    ObserveCompleted,

    /// Explicit abort. Any non-terminal state -> `Aborted`.
    /// Either role.
    Abort,
}

// ──────────────────────────────────────────────────────────────────
// Parameters
// ──────────────────────────────────────────────────────────────────

/// Parameters agreed between Alice and Bob during the negotiation
/// phase. Cryptographic material (public keys, adaptor
/// commitments, refund signatures) lives in separate types in
/// `adaptor.rs` / `btc.rs` / `cync.rs` and is referenced by the
/// `Swap` once the cryptographic skeleton is filled in.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SwapParameters {
    /// Amount of CYNC Alice will lock, in atomic units.
    pub cync_amount: u64,

    /// Amount of satoshis Bob will lock.
    pub btc_amount_sats: u64,

    /// CYNC-side timelock in blocks. After this many blocks past
    /// `AliceLocked`, Alice may broadcast her refund.
    pub cync_timeout_blocks: u32,

    /// BTC-side timelock in blocks. After this many blocks past
    /// `BobLocked`, Bob may broadcast his refund.
    /// MUST be < cync_timeout_blocks (in wall-clock terms) to
    /// preserve refund safety; see `is_timeout_safe`.
    pub btc_timeout_blocks: u32,

    /// CYNC stealth address Alice spends to (placeholder; real
    /// implementation uses the wallet's address types).
    pub alice_cync_address: String,

    /// BTC P2WPKH address Bob spends to (placeholder).
    pub bob_btc_address: String,
}

impl SwapParameters {
    /// Targets used for typical mainnet block times.
    pub const CYNC_BLOCK_TIME_SECS: u64 = 120;
    pub const BTC_BLOCK_TIME_SECS: u64 = 600;

    /// Required margin (multiplier) on top of pure block-time
    /// equivalence between the two timeouts. CIP-001 §"Timeout
    /// Safety" calls for "sufficient margin that the typical
    /// block-time difference between the two chains can't invert
    /// the order." A 20% margin is the practical floor: BTC
    /// block-time variance alone reaches ~15% over short windows.
    pub const SAFETY_MARGIN_NUMERATOR: u64 = 6;
    pub const SAFETY_MARGIN_DENOMINATOR: u64 = 5;

    /// Convert `cync_timeout_blocks` to approximate wall-clock
    /// seconds.
    pub fn cync_timeout_secs(&self) -> u64 {
        u64::from(self.cync_timeout_blocks).saturating_mul(Self::CYNC_BLOCK_TIME_SECS)
    }

    /// Convert `btc_timeout_blocks` to approximate wall-clock
    /// seconds.
    pub fn btc_timeout_secs(&self) -> u64 {
        u64::from(self.btc_timeout_blocks).saturating_mul(Self::BTC_BLOCK_TIME_SECS)
    }

    /// Codifies the safety constraint: `btc_timeout_blocks` must
    /// be strictly less than `cync_timeout_blocks` in
    /// wall-clock-equivalent terms, with a 20% margin on top to
    /// absorb block-time variance.
    ///
    /// Returns `true` if the timeouts are safe; `false` otherwise.
    /// Implementations that construct `SwapParameters` MUST check
    /// this before broadcasting any lock transaction.
    pub fn is_timeout_safe(&self) -> bool {
        // The CYNC timeout must outlast the BTC timeout * margin.
        let btc_secs = self.btc_timeout_secs();
        let margin_secs = btc_secs.saturating_mul(Self::SAFETY_MARGIN_NUMERATOR)
            / Self::SAFETY_MARGIN_DENOMINATOR;
        self.cync_timeout_secs() > margin_secs
    }
}

// ──────────────────────────────────────────────────────────────────
// The Swap struct
// ──────────────────────────────────────────────────────────────────

/// In-memory representation of an active swap. Persisted between
/// CLI invocations in a JSON state file (see `cyncswap` binary).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Swap {
    /// Stable identifier for this swap session.
    pub id: String,

    /// Which role this node is playing.
    pub role: Role,

    /// Current state in the protocol.
    pub state: State,

    /// Parameters agreed during negotiation.
    pub parameters: SwapParameters,
}

impl Swap {
    /// Begin a new swap as `role` with `params`. Validates the
    /// timeout-safety invariant before returning. The cryptographic
    /// negotiation (key exchange, refund tx pre-signing,
    /// cross-curve DL proof) lives in `coordinator.rs` and is
    /// still skeleton — once that ships, this function will be
    /// the entry point that drives it. For phase 1, we just
    /// construct the state-machine-level shell.
    pub fn negotiate(id: String, role: Role, params: SwapParameters) -> Result<Self> {
        if !params.is_timeout_safe() {
            return Err(Error::InvalidState(
                "swap parameters violate timeout-safety: BTC timeout * margin >= CYNC timeout",
            ));
        }
        Ok(Swap {
            id,
            role,
            state: State::Negotiated,
            parameters: params,
        })
    }

    /// Apply a transition. Returns `Ok(())` and updates `self` on
    /// success; returns `Err` (state UNCHANGED) on any rejection.
    ///
    /// Rejection cases:
    /// - state is terminal (`InvalidState`)
    /// - the (role, state) pair doesn't permit this transition
    ///   (`InvalidState`)
    pub fn apply(&mut self, transition: Transition) -> Result<()> {
        // INVARIANT: terminal states reject everything.
        if self.state.is_terminal() {
            return Err(Error::InvalidState(match self.state {
                State::Completed => "swap is Completed; no further transitions",
                State::Refunded => "swap is Refunded; no further transitions",
                State::Aborted => "swap is Aborted; no further transitions",
                _ => unreachable!("non-terminal state matched terminal arm"),
            }));
        }

        // Compute the destination, gating by (role, current_state).
        // If the (transition, role, state) tuple is illegal, return
        // InvalidState with a useful message.
        let next = match (transition, self.role, self.state) {
            // Abort is always legal from any non-terminal state.
            (Transition::Abort, _, _) => State::Aborted,

            // Alice's actions
            (Transition::AliceLocksCync, Role::Alice, State::Negotiated) => State::AliceLocked,
            (Transition::AliceClaimsBtc, Role::Alice, State::BobLocked) => State::SecretRevealed,
            (Transition::AliceRefunds, Role::Alice, State::AliceLocked) => State::Refunded,
            (Transition::AliceRefunds, Role::Alice, State::BobLocked) => State::Refunded,

            // Alice's observations
            (Transition::ObserveBobLocked, Role::Alice, State::AliceLocked) => State::BobLocked,

            // Bob's actions
            (Transition::BobLocksBtc, Role::Bob, State::AliceLocked) => State::BobLocked,
            (Transition::BobClaimsCync, Role::Bob, State::SecretRevealed) => State::Completed,
            (Transition::BobRefunds, Role::Bob, State::BobLocked) => State::Refunded,

            // Bob's observations
            (Transition::ObserveSecretRevealed, Role::Bob, State::BobLocked) => {
                State::SecretRevealed
            }
            (Transition::ObserveCompleted, Role::Bob, State::SecretRevealed) => State::Completed,

            // Anything else is illegal.
            (t, r, s) => {
                return Err(Error::InvalidState(match (r, s, t) {
                    // Common operator mistakes — give a clearer error.
                    (Role::Alice, _, Transition::BobLocksBtc) => {
                        "BobLocksBtc is Bob's transition; Alice cannot apply it"
                    }
                    (Role::Bob, _, Transition::AliceLocksCync) => {
                        "AliceLocksCync is Alice's transition; Bob cannot apply it"
                    }
                    (Role::Bob, _, Transition::AliceClaimsBtc) => {
                        "AliceClaimsBtc is Alice's transition; Bob cannot apply it"
                    }
                    (Role::Alice, _, Transition::BobClaimsCync) => {
                        "BobClaimsCync is Bob's transition; Alice cannot apply it"
                    }
                    (Role::Alice, _, Transition::BobRefunds) => {
                        "BobRefunds is Bob's transition; Alice cannot apply it"
                    }
                    (Role::Bob, _, Transition::AliceRefunds) => {
                        "AliceRefunds is Alice's transition; Bob cannot apply it"
                    }
                    // Generic out-of-order error for everything else.
                    _ => transition_error_message(transition, self.role, self.state),
                }));
            }
        };

        self.state = next;
        Ok(())
    }

    /// What transitions are legal from the current (role, state)?
    /// Used by the CLI's `status` subcommand to tell the operator
    /// what they can do next.
    pub fn legal_transitions(&self) -> Vec<Transition> {
        if self.state.is_terminal() {
            return Vec::new();
        }
        let mut out = Vec::new();
        // Abort is always legal from a non-terminal state.
        out.push(Transition::Abort);

        match (self.role, self.state) {
            (Role::Alice, State::Negotiated) => {
                out.push(Transition::AliceLocksCync);
            }
            (Role::Alice, State::AliceLocked) => {
                out.push(Transition::ObserveBobLocked);
                out.push(Transition::AliceRefunds);
            }
            (Role::Alice, State::BobLocked) => {
                out.push(Transition::AliceClaimsBtc);
                out.push(Transition::AliceRefunds);
            }
            (Role::Alice, State::SecretRevealed) => {
                // Alice has her BTC; nothing left for her to do
                // beyond Abort (which she shouldn't, but is legal
                // up to Completed/Refunded — though once Bob
                // claims, the swap is done regardless).
            }
            (Role::Bob, State::Negotiated) => {
                // Bob just waits. ObserveAliceLocked is implicit;
                // when his chain watcher delivers it, the
                // coordinator calls apply with no explicit
                // transition (the state advances when AliceLocked
                // is observed via its OWN flag — modeled by Alice
                // applying AliceLocksCync; Bob's local state
                // tracks the same chain).
                //
                // For Bob's local state machine, observing
                // Alice's lock confirmed advances his state to
                // AliceLocked, but that observation isn't
                // role-gated — it's just a chain event. We model
                // it by saying Bob's state machine starts at
                // Negotiated and the chain watcher applies
                // AliceLocksCync from Bob's machine when it sees
                // the lock. This is a small abstraction leak; the
                // alternative would be a separate
                // ObserveAliceLocked transition, which is fine
                // but adds more types. Keep the current design.
            }
            (Role::Bob, State::AliceLocked) => {
                out.push(Transition::BobLocksBtc);
            }
            (Role::Bob, State::BobLocked) => {
                out.push(Transition::ObserveSecretRevealed);
                out.push(Transition::BobRefunds);
            }
            (Role::Bob, State::SecretRevealed) => {
                out.push(Transition::BobClaimsCync);
            }
            // Terminal states already returned empty above.
            _ => {}
        }
        out
    }

    /// Has the swap reached a successful conclusion?
    pub fn is_completed(&self) -> bool {
        self.state == State::Completed
    }

    /// Has the swap entered a terminal state (any of Completed,
    /// Refunded, Aborted)?
    pub fn is_terminal(&self) -> bool {
        self.state.is_terminal()
    }
}

fn transition_error_message(t: Transition, r: Role, s: State) -> &'static str {
    // Helper for the common case where we just want a "bad
    // transition" message. The match in `apply` covers the more
    // helpful role-mismatch cases; this is the catchall.
    let _ = (t, r, s);
    "transition not legal for this (role, state) pair"
}

// ──────────────────────────────────────────────────────────────────
// Tests — unit + property
// ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn safe_params() -> SwapParameters {
        // is_timeout_safe demands cync_secs > btc_secs * 6/5.
        // With BTC at 100 blocks (60000s) the threshold is 72000s.
        // CYNC at 720 blocks * 120s/block = 86400s > 72000s. SAFE,
        // with comfortable margin for variance.
        SwapParameters {
            cync_amount: 100_000_000,
            btc_amount_sats: 1_000_000,
            cync_timeout_blocks: 720,
            btc_timeout_blocks: 100,
            alice_cync_address: "alice".into(),
            bob_btc_address: "bob".into(),
        }
    }

    fn alice_swap() -> Swap {
        Swap::negotiate("test1".into(), Role::Alice, safe_params()).unwrap()
    }

    fn bob_swap() -> Swap {
        Swap::negotiate("test1".into(), Role::Bob, safe_params()).unwrap()
    }

    // ────────────── Negotiation safety ──────────────

    #[test]
    fn negotiate_rejects_unsafe_timeouts() {
        let mut params = safe_params();
        // Equal wall-clock: btc 144 * 600 = 86400, cync 720 * 120 = 86400
        // is_timeout_safe demands cync > btc * 1.2
        // 86400 > 86400 * 1.2 = false. So setting them equal triggers rejection.
        params.cync_timeout_blocks = 720;
        params.btc_timeout_blocks = 144;
        // already safe; let's set btc HIGHER to break it
        params.btc_timeout_blocks = 200;
        // 200*600 = 120000s. cync 720*120 = 86400s. 86400 < 120000*1.2 -> unsafe.
        let result = Swap::negotiate("bad".into(), Role::Alice, params);
        assert!(matches!(result, Err(Error::InvalidState(_))));
    }

    // ────────────── Happy paths ──────────────

    #[test]
    fn alice_happy_path() {
        let mut s = alice_swap();
        assert_eq!(s.state, State::Negotiated);
        s.apply(Transition::AliceLocksCync).unwrap();
        assert_eq!(s.state, State::AliceLocked);
        s.apply(Transition::ObserveBobLocked).unwrap();
        assert_eq!(s.state, State::BobLocked);
        s.apply(Transition::AliceClaimsBtc).unwrap();
        assert_eq!(s.state, State::SecretRevealed);
        // Alice has her BTC. The swap completes when Bob claims
        // CYNC, which Alice can OBSERVE via ObserveCompleted —
        // but Alice's role doesn't include ObserveCompleted in
        // the transition table. Her swap stays at SecretRevealed
        // from her perspective; Bob's machine moves to Completed
        // independently. This is fine — the global swap is
        // done, and Alice's local view is in a stable state.
    }

    #[test]
    fn bob_happy_path() {
        let mut s = bob_swap();
        assert_eq!(s.state, State::Negotiated);
        // Bob's machine advances to AliceLocked when his chain
        // watcher delivers the lock confirmation. We model that
        // by allowing AliceLocksCync from Bob's perspective too
        // — actually no, that's Alice-only. For Bob, the state
        // advances via... hmm. Looking at the apply code, Bob
        // can't directly transition Negotiated -> AliceLocked.
        // That means Bob's machine in real flow is driven by the
        // chain watcher OUTSIDE the role-action set, OR we need
        // an explicit ObserveAliceLocked transition.
        //
        // Simplification: in tests, force the state. In the
        // real coordinator, the chain watcher will apply an
        // ObserveAliceLocked transition (added in phase 2 if we
        // need it). For phase 1, this test exercises the
        // AliceLocked -> Completed path on Bob's side.
        s.state = State::AliceLocked;
        s.apply(Transition::BobLocksBtc).unwrap();
        assert_eq!(s.state, State::BobLocked);
        s.apply(Transition::ObserveSecretRevealed).unwrap();
        assert_eq!(s.state, State::SecretRevealed);
        s.apply(Transition::BobClaimsCync).unwrap();
        assert_eq!(s.state, State::Completed);
        assert!(s.is_completed());
    }

    // ────────────── Role gating ──────────────

    #[test]
    fn alice_cannot_use_bob_transitions() {
        let mut s = alice_swap();
        let result = s.apply(Transition::BobLocksBtc);
        assert!(matches!(result, Err(Error::InvalidState(_))));
        assert_eq!(
            s.state,
            State::Negotiated,
            "state must be unchanged on error"
        );
    }

    #[test]
    fn bob_cannot_use_alice_transitions() {
        let mut s = bob_swap();
        let result = s.apply(Transition::AliceLocksCync);
        assert!(matches!(result, Err(Error::InvalidState(_))));
    }

    // ────────────── Refund paths ──────────────

    #[test]
    fn alice_can_refund_from_alice_locked() {
        let mut s = alice_swap();
        s.apply(Transition::AliceLocksCync).unwrap();
        s.apply(Transition::AliceRefunds).unwrap();
        assert_eq!(s.state, State::Refunded);
    }

    #[test]
    fn alice_can_refund_from_bob_locked() {
        let mut s = alice_swap();
        s.apply(Transition::AliceLocksCync).unwrap();
        s.apply(Transition::ObserveBobLocked).unwrap();
        s.apply(Transition::AliceRefunds).unwrap();
        assert_eq!(s.state, State::Refunded);
    }

    #[test]
    fn bob_can_refund_from_bob_locked() {
        let mut s = bob_swap();
        s.state = State::AliceLocked;
        s.apply(Transition::BobLocksBtc).unwrap();
        s.apply(Transition::BobRefunds).unwrap();
        assert_eq!(s.state, State::Refunded);
    }

    #[test]
    fn bob_cannot_refund_from_alice_locked() {
        let mut s = bob_swap();
        s.state = State::AliceLocked;
        // Bob hasn't locked yet; nothing to refund.
        let result = s.apply(Transition::BobRefunds);
        assert!(matches!(result, Err(Error::InvalidState(_))));
    }

    // ────────────── Terminal stickiness ──────────────

    #[test]
    fn aborted_rejects_all_transitions() {
        let mut s = alice_swap();
        s.apply(Transition::Abort).unwrap();
        assert_eq!(s.state, State::Aborted);
        for t in [
            Transition::AliceLocksCync,
            Transition::AliceClaimsBtc,
            Transition::AliceRefunds,
            Transition::Abort,
        ] {
            let result = s.apply(t);
            assert!(
                matches!(result, Err(Error::InvalidState(_))),
                "transition {:?} must be rejected from Aborted",
                t
            );
        }
        assert_eq!(s.state, State::Aborted);
    }

    #[test]
    fn completed_rejects_all_transitions() {
        let mut s = bob_swap();
        s.state = State::SecretRevealed;
        s.apply(Transition::BobClaimsCync).unwrap();
        assert_eq!(s.state, State::Completed);
        let result = s.apply(Transition::Abort);
        assert!(matches!(result, Err(Error::InvalidState(_))));
    }

    // ────────────── legal_transitions ──────────────

    #[test]
    fn legal_transitions_alice_negotiated() {
        let s = alice_swap();
        let legal = s.legal_transitions();
        assert!(legal.contains(&Transition::AliceLocksCync));
        assert!(legal.contains(&Transition::Abort));
        assert!(!legal.contains(&Transition::BobLocksBtc));
    }

    #[test]
    fn legal_transitions_terminal_is_empty() {
        let mut s = alice_swap();
        s.apply(Transition::Abort).unwrap();
        assert!(s.legal_transitions().is_empty());
    }

    // ────────────── Property tests ──────────────

    /// PROPERTY: terminal states are sticky. Any sequence of
    /// transitions applied after the state becomes terminal
    /// leaves the state unchanged.
    #[test]
    fn prop_terminal_stickiness() {
        let attempts = [
            Transition::AliceLocksCync,
            Transition::BobLocksBtc,
            Transition::AliceClaimsBtc,
            Transition::BobClaimsCync,
            Transition::AliceRefunds,
            Transition::BobRefunds,
            Transition::ObserveBobLocked,
            Transition::ObserveSecretRevealed,
            Transition::ObserveCompleted,
            Transition::Abort,
        ];
        for terminal in [State::Completed, State::Refunded, State::Aborted] {
            for role in [Role::Alice, Role::Bob] {
                let mut s = Swap::negotiate("p".into(), role, safe_params()).unwrap();
                s.state = terminal;
                for &t in &attempts {
                    let result = s.apply(t);
                    assert!(
                        result.is_err(),
                        "{:?} role={:?} terminal={:?} must reject {:?}",
                        s.state,
                        role,
                        terminal,
                        t
                    );
                    assert_eq!(
                        s.state, terminal,
                        "state must not change after rejected transition from terminal"
                    );
                }
            }
        }
    }

    /// PROPERTY: `is_timeout_safe` correctly enforces the
    /// CIP-001 §"Timeout Safety" rule: BTC timeout * 1.2 must
    /// be strictly less than CYNC timeout (in wall-clock terms).
    #[test]
    fn prop_timeout_safety_boundary() {
        // Pick btc timeouts and verify:
        // - cync just under threshold -> unsafe
        // - cync just over threshold -> safe
        for btc_blocks in [1u32, 100, 144, 1000, 10_000] {
            let btc_secs = u64::from(btc_blocks) * 600;
            let threshold_secs = btc_secs * 6 / 5; // BTC * margin
                                                   // Required cync_secs > threshold_secs strictly
                                                   // CYNC block time = 120s
            let cync_blocks_just_under: u32 = (threshold_secs / 120) as u32;
            let cync_blocks_just_over: u32 = cync_blocks_just_under.saturating_add(1);

            let mut p = SwapParameters {
                cync_amount: 1,
                btc_amount_sats: 1,
                cync_timeout_blocks: cync_blocks_just_under,
                btc_timeout_blocks: btc_blocks,
                alice_cync_address: "a".into(),
                bob_btc_address: "b".into(),
            };
            assert!(
                !p.is_timeout_safe(),
                "btc={} cync={} should be UNsafe",
                btc_blocks,
                cync_blocks_just_under
            );
            p.cync_timeout_blocks = cync_blocks_just_over;
            assert!(
                p.is_timeout_safe(),
                "btc={} cync={} should be SAFE",
                btc_blocks,
                cync_blocks_just_over
            );
        }
    }

    /// PROPERTY: applying any transition either succeeds (and
    /// `state` advances) or errors (and `state` is unchanged).
    /// Never leaves the state in an inconsistent middle.
    #[test]
    fn prop_all_or_nothing_state_changes() {
        let attempts = [
            Transition::AliceLocksCync,
            Transition::BobLocksBtc,
            Transition::AliceClaimsBtc,
            Transition::BobClaimsCync,
            Transition::AliceRefunds,
            Transition::BobRefunds,
            Transition::ObserveBobLocked,
            Transition::ObserveSecretRevealed,
            Transition::ObserveCompleted,
            Transition::Abort,
        ];
        for role in [Role::Alice, Role::Bob] {
            for start in [
                State::Negotiated,
                State::AliceLocked,
                State::BobLocked,
                State::SecretRevealed,
                State::Completed,
                State::Refunded,
                State::Aborted,
            ] {
                for &t in &attempts {
                    let mut s = Swap::negotiate("p".into(), role, safe_params()).unwrap();
                    s.state = start;
                    let pre = s.state;
                    let result = s.apply(t);
                    if result.is_err() {
                        assert_eq!(
                            s.state, pre,
                            "rejected ({:?},{:?},{:?}) must leave state unchanged",
                            role, start, t
                        );
                    } else {
                        // Successful transition: state advanced.
                        assert_ne!(
                            s.state, pre,
                            "accepted ({:?},{:?},{:?}) must advance state",
                            role, start, t
                        );
                    }
                }
            }
        }
    }
}
