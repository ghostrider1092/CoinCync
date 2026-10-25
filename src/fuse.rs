//! The **fuse box** — the *one* registry every circuit breaker plugs into, and
//! the single mediation layer between the breakers and the node code. Breakers
//! are pluggable **extensions**; the consensus / hot path is never edited to add
//! or change one.
//!
//! ## The idea
//!
//! A fuse box in a house sits between the wiring and the appliances: you add or
//! swap breakers in the box, you don't rewire the house. Here:
//!
//!   - Every surface's breaker lives in **one** box, keyed by
//!     [`BreakerSurface`]. One place holds all breaker state; one
//!     [`snapshot`](FuseBox::snapshot) shows every compartment at once.
//!   - A surface is fed through the **universal** entry point
//!     [`observe_fault`](FuseBox::observe_fault): the feed point runs that
//!     surface's own pure `detect()` on real data, wraps the result in a
//!     [`FaultReport`], and hands it to the box. The box never needs to know the
//!     surface's observation type — so adding a breaker is `install` + one feed
//!     call, not a box change.
//!   - For surfaces whose signal is already on the node's event stream
//!     (mempool arrival-rate, peer count), a thin [`FuseSignal`] adapter maps the
//!     existing `NodeEvent`s onto the box, so even those need no new hot-path
//!     plumbing.
//!   - A process-wide [`global`](global()) instance ties every feed point
//!     (mempool admit, p2p heartbeat, block-connect, rpc, shielded) to the same
//!     box: one source of truth, one status view.
//!
//! ## Honest scope
//!
//! Observe-only: the box runs the breakers and records/logs their state; it does
//! NOT feed back into consensus (that would be the gated activation). The
//! node-local load surfaces (mempool, p2p, rpc) are safe to observe (and later,
//! per-node, to act on) with no fork risk. The consensus surfaces (supply,
//! reorg, block-integrity, shielded) stay **detection-only** here until a
//! coordinated, post-audit activation — a node-local trip on a consensus value
//! would fork the chain. Gated on `breaker-recovery`; the convenience `fuse`
//! feature turns on every breaker at once. See `docs/design/cip-circuit-breakers.md`.

use std::collections::HashMap;

use crate::breaker_recovery::{BreakerState, BreakerSurface, RecoveryBreaker};

/// A surface-agnostic fault report — the one thing the universal box consumes.
///
/// A feed point computes it from its surface's pure `detect()`:
/// `FaultReport::from_labels(detect(&obs).iter().map(|f| format!("{f:?}")))`.
/// The box reads only `faulty`; `faults` is carried for the transition log so an
/// operator can see *why* a compartment tripped.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct FaultReport {
    /// At least one fault was detected this tick.
    pub faulty: bool,
    /// Human-readable fault labels (for logging/telemetry only).
    pub faults: Vec<String>,
}

impl FaultReport {
    /// A clean tick (no fault).
    pub fn healthy() -> Self {
        Self { faulty: false, faults: Vec::new() }
    }

    /// Build from any iterator of fault labels. `faulty` is set iff non-empty —
    /// this is the single rule the whole box relies on, so a feed point can never
    /// report "faults present but not faulty".
    pub fn from_labels<I, S>(labels: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        let faults: Vec<String> = labels.into_iter().map(Into::into).collect();
        Self { faulty: !faults.is_empty(), faults }
    }
}

/// The fuse's own event vocabulary. A node-side adapter maps the node's existing
/// `NodeEvent` stream onto these, so the fuse never depends on network types.
/// This is the *convenience* path for the two surfaces whose signal is already
/// on the event stream; every other surface uses [`FuseBox::observe_fault`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FuseSignal {
    /// A peer finished connecting.
    PeerConnected,
    /// A peer disconnected.
    PeerDisconnected,
    /// A transaction arrived for admission (mempool arrival-rate sample).
    TxArrived,
    /// A periodic window boundary: flush the arrival-rate sample to the mempool
    /// breaker and reset the window.
    WindowTick,
}

// Used only by the feature-gated event-derived feeds below; keep quiet when a
// breaker feature is off and the helper is momentarily unused.
#[allow(dead_code)]
fn env_u32(name: &str, default: u32) -> u32 {
    std::env::var(name).ok().and_then(|v| v.parse().ok()).unwrap_or(default)
}
#[allow(dead_code)]
fn env_usize(name: &str, default: usize) -> usize {
    std::env::var(name).ok().and_then(|v| v.parse().ok()).unwrap_or(default)
}

/// The fuse box: one registry of recovery breakers keyed by surface, plus the
/// small amount of event-derived live state (peer count, arrival window) the
/// convenience [`FuseSignal`] path needs. Observe-only.
#[derive(Default)]
pub struct FuseBox {
    breakers: HashMap<BreakerSurface, RecoveryBreaker>,
    peer_count: usize,
    tx_arrivals: u32,
}

impl FuseBox {
    pub fn new() -> Self {
        Self::default()
    }

    /// Install a breaker for one surface (the "extension"), with that surface's
    /// recommended recovery policy.
    pub fn install(&mut self, surface: BreakerSurface) {
        self.breakers.insert(surface, RecoveryBreaker::for_surface(surface));
    }

    /// Install a breaker for **every** surface — the universal box. Idempotent
    /// per surface (re-installing resets that surface to Closed).
    pub fn install_all(&mut self) {
        for s in BreakerSurface::ALL {
            self.install(s);
        }
    }

    /// Whether a surface's breaker is currently isolating. `false` if not
    /// installed.
    pub fn isolating(&self, surface: BreakerSurface) -> bool {
        self.breakers.get(&surface).map(|b| b.is_isolating()).unwrap_or(false)
    }

    /// A surface's current state, or `None` if not installed.
    pub fn state(&self, surface: BreakerSurface) -> Option<BreakerState> {
        self.breakers.get(&surface).map(|b| b.state())
    }

    /// Snapshot of every installed breaker's state (sorted, stable order).
    pub fn snapshot(&self) -> Vec<(BreakerSurface, BreakerState)> {
        let mut v: Vec<_> = self.breakers.iter().map(|(s, b)| (*s, b.state())).collect();
        v.sort_by_key(|(s, _)| format!("{s:?}"));
        v
    }

    /// Manual recovery for a latched (or any) surface — the operator "we've
    /// investigated and fixed it" decision. No-op if the surface isn't installed.
    pub fn rearm(&mut self, surface: BreakerSurface) {
        if let Some(b) = self.breakers.get_mut(&surface) {
            b.rearm();
        }
    }

    /// **The universal feed.** A surface's feed point computes a [`FaultReport`]
    /// from its own `detect()` and hands it here; the box advances that surface's
    /// breaker and logs any transition (with the fault labels). Auto-installs the
    /// surface on first sight so a feed can never be silently dropped. Returns the
    /// new state. Observe-only — nothing the caller must act on.
    pub fn observe_fault(&mut self, surface: BreakerSurface, report: &FaultReport) -> BreakerState {
        let b = self
            .breakers
            .entry(surface)
            .or_insert_with(|| RecoveryBreaker::for_surface(surface));
        let prev = b.state();
        let now = b.observe(report.faulty);
        if now != prev {
            tracing::warn!(
                target: "fuse",
                "FUSE {:?} {:?} -> {:?} (faults={:?})",
                surface, prev, now, report.faults
            );
        }
        now
    }

    /// Feed one event-stream signal (the convenience path for mempool/p2p).
    /// Updates event-derived state and advances the relevant breaker via the same
    /// [`observe_fault`](Self::observe_fault) universal path.
    pub fn observe_signal(&mut self, signal: FuseSignal) {
        match signal {
            FuseSignal::PeerConnected => {
                self.peer_count += 1;
                self.feed_p2p();
            }
            FuseSignal::PeerDisconnected => {
                self.peer_count = self.peer_count.saturating_sub(1);
                self.feed_p2p();
            }
            FuseSignal::TxArrived => {
                self.tx_arrivals = self.tx_arrivals.saturating_add(1);
            }
            FuseSignal::WindowTick => {
                self.feed_mempool_arrivals();
                self.tx_arrivals = 0;
            }
        }
    }

    #[cfg(feature = "p2p-breaker")]
    fn feed_p2p(&mut self) {
        use crate::p2p_breaker::{detect, PeerObservation};
        let obs = PeerObservation {
            total_peers: self.peer_count,
            min_peers: env_usize("COINCYNC_FUSE_MIN_PEERS", 3),
            // Events carry PeerId, not addresses, so netgroup diversity is NOT
            // decidable here — the heartbeat P2P wire owns that. Set it
            // non-tripping so the fuse only judges the peer-COUNT eclipse signal.
            distinct_netgroups: self.peer_count,
            min_netgroups: 0,
            worst_ip_conns: 0,
            max_conns_per_ip: usize::MAX,
            ibd_target_from_banned: false,
            blocks_since_progress: 0,
            max_stall_blocks: u64::MAX,
            handshake_queue_depth: 0,
            handshake_completions: 1,
        };
        let report = FaultReport::from_labels(detect(&obs).iter().map(|f| format!("{f:?}")));
        self.observe_fault(BreakerSurface::P2p, &report);
    }
    #[cfg(not(feature = "p2p-breaker"))]
    fn feed_p2p(&mut self) {}

    #[cfg(feature = "mempool-breaker")]
    fn feed_mempool_arrivals(&mut self) {
        use crate::mempool_breaker::{detect, MempoolObservation};
        let obs = MempoolObservation {
            // Count/bytes aren't event-derivable; only the arrival RATE is.
            pending_count: 0,
            max_count: usize::MAX,
            pending_bytes: 0,
            max_bytes: usize::MAX,
            arrivals_this_interval: self.tx_arrivals,
            max_arrivals_per_interval: env_u32("COINCYNC_FUSE_MAX_ARRIVALS", 10_000),
            worst_peer_arrivals: 0,
            max_per_peer_arrivals: u32::MAX,
            dust_arrivals: 0,
            max_dust: u32::MAX,
        };
        let report = FaultReport::from_labels(detect(&obs).iter().map(|f| format!("{f:?}")));
        self.observe_fault(BreakerSurface::Mempool, &report);
    }
    #[cfg(not(feature = "mempool-breaker"))]
    fn feed_mempool_arrivals(&mut self) {}
}

// ── The process-wide universal fuse box ─────────────────────────────────────
//
// One shared instance every feed point reaches, so all breaker state lives in a
// single place with a single snapshot. Lazily installs all surfaces on first
// use. Poisoned-lock-safe (a panic in one feed must not wedge the box).

use std::sync::{Mutex, OnceLock};

static GLOBAL: OnceLock<Mutex<FuseBox>> = OnceLock::new();

fn global_box() -> &'static Mutex<FuseBox> {
    GLOBAL.get_or_init(|| {
        let mut fb = FuseBox::new();
        fb.install_all();
        Mutex::new(fb)
    })
}

/// Lock the process-wide fuse box (installing all surfaces on first use).
pub fn global() -> std::sync::MutexGuard<'static, FuseBox> {
    global_box().lock().unwrap_or_else(|p| p.into_inner())
}

/// **Universal feed into the shared box.** Every surface's live feed point calls
/// this with the surface and a [`FaultReport`] from its own `detect()`.
pub fn observe(surface: BreakerSurface, report: &FaultReport) -> BreakerState {
    global().observe_fault(surface, report)
}

/// Convenience: build the report from fault labels and feed it in one call.
pub fn observe_labels<I, S>(surface: BreakerSurface, labels: I) -> BreakerState
where
    I: IntoIterator<Item = S>,
    S: Into<String>,
{
    observe(surface, &FaultReport::from_labels(labels))
}

/// Whether a surface is isolating in the shared box.
pub fn isolating(surface: BreakerSurface) -> bool {
    global().isolating(surface)
}

/// A surface's state in the shared box.
pub fn surface_state(surface: BreakerSurface) -> Option<BreakerState> {
    global().state(surface)
}

/// Snapshot of the whole shared box — every compartment's state at once.
pub fn snapshot() -> Vec<(BreakerSurface, BreakerState)> {
    global().snapshot()
}

/// Operator rearm of one surface in the shared box.
pub fn rearm(surface: BreakerSurface) {
    global().rearm(surface);
}

/// Reset one surface to Closed in the shared box (fresh observation window /
/// test isolation) — re-installs that surface only.
pub fn reset_surface(surface: BreakerSurface) {
    global().install(surface);
}

/// Reset the ENTIRE shared box (test isolation). Re-installs all surfaces Closed.
pub fn reset() {
    global().install_all();
}

// ── Arm switch (Observe → Enforcing) ────────────────────────────────────────
//
// The breakers above are Observe-only: they detect and record, never act. The
// ARM SWITCH is the gate that turns a *consensus* breaker's detection into a
// fail-closed rejection/halt. Per docs/design/breaker-arm-switch.md it is NOT a
// runtime control: a surface's arm height is a network/governance constant
// (default `u64::MAX` = off), so arming is a deliberate, reviewed code change,
// uniform across nodes and undisarmable at runtime. Only the Latch money /
// integrity surfaces are consensus-armable; load/local surfaces
// (mempool/p2p/rpc/reorg) are armed by local config and never use this gate.

/// Consensus arm height for a surface — the POLICY SLOT. `u64::MAX` = never
/// armed (Observe only). Every surface defaults to OFF pending the activation
/// decision and the external audit; arming a surface is a deliberate code change
/// here (or wiring from the activation registry), never a runtime switch.
pub const fn default_arm_height(surface: BreakerSurface) -> u64 {
    match surface {
        // Latch money/integrity surfaces are consensus-armable — all OFF today.
        BreakerSurface::Shielded
        | BreakerSurface::Supply
        | BreakerSurface::BlockIntegrity => u64::MAX,
        // Load/local surfaces are never consensus-armed (local config instead).
        _ => u64::MAX,
    }
}

/// Pure arm decision — no global state, so it is unit-testable in isolation and
/// parallel-safe. A fail-closed action is due iff the surface is armed
/// (`arm_height != u64::MAX` AND `current_height >= arm_height`) AND its breaker
/// is currently `isolating`. Default-off: with `arm_height == u64::MAX` it is
/// always `false`.
pub fn fail_closed_due(current_height: u64, arm_height: u64, isolating: bool) -> bool {
    arm_height != u64::MAX && current_height >= arm_height && isolating
}

/// Whether a fail-closed rejection/halt is due for `surface` at `current_height`,
/// consulting the shared box's isolating state. Thin wrapper over
/// [`fail_closed_due`] + [`isolating`]. Default-off until an arm height is set.
pub fn enforce_trips(surface: BreakerSurface, current_height: u64, arm_height: u64) -> bool {
    fail_closed_due(current_height, arm_height, isolating(surface))
}

#[cfg(test)]
mod arm_tests {
    use super::*;

    #[test]
    fn arm_heights_default_off_for_every_surface() {
        for s in BreakerSurface::ALL {
            assert_eq!(
                default_arm_height(s),
                u64::MAX,
                "{s:?} must default to OFF (u64::MAX) pending the activation decision"
            );
        }
    }

    #[test]
    fn fail_closed_is_off_by_default_even_when_isolating() {
        // Isolating, but the arm height is the default OFF sentinel -> never fires.
        assert!(!fail_closed_due(1_000_000, u64::MAX, true));
    }

    #[test]
    fn fail_closed_only_when_armed_at_height_and_isolating() {
        assert!(!fail_closed_due(49, 50, true), "below the arm height");
        assert!(!fail_closed_due(100, 50, false), "at height but not isolating");
        assert!(fail_closed_due(50, 50, true), "exactly at the arm height + isolating");
        assert!(fail_closed_due(100, 50, true), "past the arm height + isolating -> fail closed");
        assert!(!fail_closed_due(100, u64::MAX, true), "u64::MAX = off");
    }
}

#[cfg(all(test, feature = "mempool-breaker", feature = "p2p-breaker"))]
mod tests {
    use super::*;

    #[test]
    fn install_all_registers_every_surface() {
        let mut fb = FuseBox::new();
        assert!(fb.snapshot().is_empty());
        fb.install_all();
        assert_eq!(fb.snapshot().len(), BreakerSurface::ALL.len());
        for s in BreakerSurface::ALL {
            assert_eq!(fb.state(s), Some(BreakerState::Closed));
            assert!(!fb.isolating(s));
        }
    }

    #[test]
    fn universal_observe_fault_trips_any_surface() {
        let mut fb = FuseBox::new();
        fb.install_all();
        // A fault report on a consensus surface trips it (detection-only, but the
        // box records it) — the generic path works for a surface with no event.
        let r = FaultReport::from_labels(["OverEmission"]);
        fb.observe_fault(BreakerSurface::Supply, &r);
        assert!(fb.isolating(BreakerSurface::Supply));
        // Supply latches: clean ticks don't reconnect it.
        for _ in 0..10 {
            fb.observe_fault(BreakerSurface::Supply, &FaultReport::healthy());
        }
        assert!(fb.isolating(BreakerSurface::Supply), "money surface must latch");
        fb.rearm(BreakerSurface::Supply);
        assert!(!fb.isolating(BreakerSurface::Supply));
    }

    #[test]
    fn observe_fault_auto_installs_unknown_surface() {
        let mut fb = FuseBox::new();
        // No install_all; feeding an unknown surface must register it, not drop it.
        fb.observe_fault(BreakerSurface::Reorg, &FaultReport::from_labels(["DeepReorg"]));
        assert!(fb.isolating(BreakerSurface::Reorg));
    }

    #[test]
    fn fault_report_faulty_iff_nonempty() {
        assert!(!FaultReport::from_labels(Vec::<String>::new()).faulty);
        assert!(FaultReport::from_labels(["x"]).faulty);
        assert!(!FaultReport::healthy().faulty);
    }

    #[test]
    fn peer_count_eclipse_trips_and_recovers_via_events() {
        std::env::set_var("COINCYNC_FUSE_MIN_PEERS", "3");
        let mut fb = FuseBox::new();
        fb.install(BreakerSurface::P2p);
        // One peer connects → below min 3 → eclipse risk → isolating.
        fb.observe_signal(FuseSignal::PeerConnected);
        assert!(fb.isolating(BreakerSurface::P2p), "too few peers must trip");
        // Enough peers connect → healthy; AutoReset recovers after the streak.
        for _ in 0..6 {
            fb.observe_signal(FuseSignal::PeerConnected);
        }
        assert!(!fb.isolating(BreakerSurface::P2p), "a diverse-enough peer count reconnects");
    }

    #[test]
    fn mempool_arrival_flood_trips_on_window_tick() {
        std::env::set_var("COINCYNC_FUSE_MAX_ARRIVALS", "5");
        let mut fb = FuseBox::new();
        fb.install(BreakerSurface::Mempool);
        // A flood of arrivals within one window.
        for _ in 0..20 {
            fb.observe_signal(FuseSignal::TxArrived);
        }
        fb.observe_signal(FuseSignal::WindowTick); // flush → 20 > 5 → flood
        assert!(fb.isolating(BreakerSurface::Mempool), "an arrival flood trips the fuse");
        // Quiet windows → recover (heal streak + probe).
        for _ in 0..5 {
            fb.observe_signal(FuseSignal::WindowTick);
        }
        assert!(!fb.isolating(BreakerSurface::Mempool), "quiet windows reconnect the mempool fuse");
    }
}
