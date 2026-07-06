//! The `TickBehavior` trait — every tick mode (Rescue, Health,
//! Propagation) implements it. Also `TickPhase` — the shared state
//! machine that maps the biological metaphor to explicit software
//! states.

use crate::adapter::ChainAdapter;
use crate::types::TickResult;

/// The four phases of a tick's lifecycle, in the biological order.
///
/// A tick starts in `Quest`, transitions to `Latch` when a target is
/// identified, then `Feed` when delivery is in progress, then `Detach`
/// after cleanup. `Quest` is the idle steady state — most of a tick's
/// lifetime is spent here.
///
/// The state machine is deliberately explicit: a tick that skips
/// `Latch` (jumps straight from `Quest` to `Feed`) has a bug in its
/// verification logic. Same for a tick that never returns to `Quest`
/// after a `Detach` — that's a "stuck feeding" state which the
/// heartbeat check should page on.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TickPhase {
    /// Passive discovery. Polling metrics, listening to gossip. This
    /// is where the tick spends most of its time.
    Quest,
    /// A target has been identified and verified; establishing a
    /// durable channel to it. Short-lived phase (seconds to a minute).
    Latch,
    /// Payload delivery in progress. Can be seconds (a Discord webhook
    /// post) to tens of minutes (a chaindata swap across 8 hosts).
    Feed,
    /// Clean release. Closing channels, pruning state, emitting the
    /// completion notice. Returns to `Quest` when done.
    Detach,
}

impl TickPhase {
    /// True if the phase is one where the tick is actively engaged
    /// with a target (Latch, Feed, or Detach). Used by the heartbeat
    /// path to include an "engaged" flag alongside the standard alive
    /// signal.
    pub fn is_engaged(&self) -> bool {
        !matches!(self, TickPhase::Quest)
    }
}

/// Trait every concrete tick mode implements. Provides the mode-
/// specific quest / latch / feed / detach semantics; the shared
/// runtime (Phase 1b onward) drives the state transitions.
///
/// Every method takes `&self` because ticks are cloneable-Arc handles
/// in practice — the runtime drives them concurrently.
///
/// # Contract
///
/// Implementations MUST:
///
/// 1. Return `Ok(true)` from `quest` ONLY when a target is genuinely
///    identified and verified. False positives waste the runtime's
///    latch/feed budget; more importantly, false-positive rescues
///    can push a WRONG chain to healthy peers.
///
/// 2. Return promptly from `quest`. This method is called on the
///    tick's polling interval; slow quests block the runtime's ability
///    to check other ticks. Adapter-side blocking work (RPC probes,
///    disk snapshots) is fine; adapter-side spin-waits are not.
///
/// 3. Not mutate persistent state during `quest`. The quest phase is
///    read-only from the adapter's perspective. State changes belong
///    in `latch` / `feed` / `detach`.
///
/// 4. Emit tick notices at appropriate transitions (`Hunt` on
///    successful quest, `Engaged` when feed starts, `Recovered` on
///    detach). The runtime provides a notice-broadcast helper; ticks
///    don't touch adapters directly for notice emission.
pub trait TickBehavior<A: ChainAdapter>: Send + Sync + 'static {
    /// Human-readable name for logs. Should be stable across process
    /// restarts (e.g., `"RescueTick"`, `"HealthTick"`, `"PropagationTick"`).
    fn name(&self) -> &'static str;

    /// The current phase this tick is in.
    ///
    /// The runtime uses this to gate transitions — a tick already in
    /// `Feed` won't have its `quest` re-invoked.
    fn phase(&self) -> TickPhase;

    /// Quest phase: passively look for a target.
    ///
    /// Returns `Ok(true)` if a target is identified and the runtime
    /// should proceed to `latch`. Returns `Ok(false)` if no target
    /// exists (steady state — return immediately). Returns `Err` on
    /// adapter failure; the runtime logs and stays in `Quest`.
    fn quest(&self, adapter: &A) -> TickResult<bool>;

    /// Latch phase: establish a durable channel to the identified
    /// target. Called only after `quest` returned `Ok(true)`.
    ///
    /// Returns `Ok(())` on successful latch. Returns `Err` on failure;
    /// the runtime logs, emits an alert, and transitions back to
    /// `Quest`.
    fn latch(&self, adapter: &A) -> TickResult<()>;

    /// Feed phase: deliver the payload.
    ///
    /// Long-running: RescueTick's feed can take tens of minutes across
    /// 8 hosts. The runtime doesn't cancel a running feed except on
    /// process shutdown.
    ///
    /// Returns `Ok(())` on successful delivery. Returns `Err` on
    /// partial failure; the runtime logs and transitions to `Detach`
    /// (partial failures still need cleanup).
    fn feed(&self, adapter: &A) -> TickResult<()>;

    /// Detach phase: close channels, prune state, emit completion
    /// notice.
    ///
    /// This method should NEVER return `Err`. Cleanup is best-effort;
    /// a `Detach` that leaves state behind is a bug in the tick, not
    /// a runtime failure to surface to the operator. Implementations
    /// swallow adapter errors here and log them locally.
    ///
    /// Returns `Ok(())` unconditionally in a well-behaved
    /// implementation. The `TickResult` return is retained for
    /// future flexibility (e.g., detach may need to return metrics).
    fn detach(&self, adapter: &A) -> TickResult<()>;
}
