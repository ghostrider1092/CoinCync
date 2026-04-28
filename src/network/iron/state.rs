//! # IronConsensus State Machine
//!
//! Explicit states with logged transitions.

use std::fmt;
use std::time::{Instant, SystemTime, UNIX_EPOCH};
use serde::{Deserialize, Serialize};
use tracing::{info, warn};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum EngineState {
    Nominal,
    Syncing,
    Forked,
    Partitioned,
    Recovering,
    AdminLocked,
}

impl fmt::Display for EngineState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            EngineState::Nominal     => write!(f, "Nominal"),
            EngineState::Syncing     => write!(f, "Syncing"),
            EngineState::Forked      => write!(f, "Forked"),
            EngineState::Partitioned => write!(f, "Partitioned"),
            EngineState::Recovering  => write!(f, "Recovering"),
            EngineState::AdminLocked => write!(f, "AdminLocked"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Transition {
    pub from:      EngineState,
    pub to:        EngineState,
    pub reason:    String,
    pub unix_secs: u64,
    pub height:    u64,
}

/// FIX #20: cap on the number of retained transitions. Previously the log
/// was an unbounded `Vec<Transition>` that grew for the lifetime of the
/// process — on a long-running node with frequent fork detection it would
/// accumulate thousands of entries and eventually exhaust memory. 1000 is
/// enough for any realistic forensic history while bounding the footprint.
const MAX_TRANSITIONS: usize = 1_000;

pub struct StateMachine {
    current:     EngineState,
    entered_at:  Instant,
    log:         std::collections::VecDeque<Transition>,
    height:      u64,
}

impl StateMachine {
    pub fn new() -> Self {
        StateMachine {
            current:    EngineState::Nominal,
            entered_at: Instant::now(),
            log:        std::collections::VecDeque::with_capacity(MAX_TRANSITIONS),
            height:     0,
        }
    }

    pub fn current(&self) -> EngineState { self.current }

    pub fn secs_in_state(&self) -> u64 {
        self.entered_at.elapsed().as_secs()
    }

    pub fn transition(&mut self, to: EngineState, reason: &str, height: u64) {
        if to == self.current { return; }

        let t = Transition {
            from:      self.current,
            to,
            reason:    reason.to_string(),
            unix_secs: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
            height,
        };

        match to {
            EngineState::Nominal     => info!("IronConsensus: {} -> Nominal ({})", self.current, reason),
            EngineState::Syncing     => info!("IronConsensus: {} -> Syncing ({})", self.current, reason),
            EngineState::Forked      => warn!("IronConsensus: {} -> Forked ({})", self.current, reason),
            EngineState::Partitioned => warn!("IronConsensus: {} -> Partitioned ({})", self.current, reason),
            EngineState::Recovering  => info!("IronConsensus: {} -> Recovering ({})", self.current, reason),
            EngineState::AdminLocked => warn!("IronConsensus: {} -> AdminLocked ({})", self.current, reason),
        }

        self.log.push_back(t);
        // FIX #20: cap the ring buffer at MAX_TRANSITIONS.
        if self.log.len() > MAX_TRANSITIONS {
            self.log.pop_front();
        }
        self.current    = to;
        self.entered_at = Instant::now();
        self.height     = height;
    }

    /// Returns transitions in insertion order as a Vec. Previously this
    /// returned a `&[Transition]` slice; with the bounded VecDeque we
    /// materialise a Vec on demand so callers are insulated from the
    /// storage change. For the typical "serialize to JSONL on shutdown"
    /// path this is fine.
    pub fn history(&self) -> Vec<Transition> {
        self.log.iter().cloned().collect()
    }

    pub fn recent(&self, n: usize) -> Vec<Transition> {
        let len = self.log.len();
        let start = len.saturating_sub(n);
        self.log.iter().skip(start).cloned().collect()
    }

    pub fn count(&self, state: EngineState) -> usize {
        self.log.iter().filter(|t| t.to == state).count()
    }

    pub fn to_jsonl(&self) -> String {
        self.log.iter()
            .filter_map(|t| serde_json::to_string(t).ok())
            .collect::<Vec<_>>()
            .join("\n")
    }

    // -- Named transitions --

    pub fn on_synced(&mut self, height: u64) {
        self.transition(EngineState::Nominal, "chain synced", height);
    }

    pub fn on_lag_detected(&mut self, height: u64, behind: u64) {
        let reason = format!("{behind} blocks behind");
        self.transition(EngineState::Syncing, &reason, height);
    }

    pub fn on_fork_detected(&mut self, height: u64, peer_height: u64) {
        let reason = format!("fork at height {height}, peer at {peer_height}");
        self.transition(EngineState::Forked, &reason, height);
    }

    pub fn on_rollback_complete(&mut self, height: u64) {
        let reason = format!("rolled back to {height}, re-syncing");
        self.transition(EngineState::Recovering, &reason, height);
    }

    pub fn on_partition(&mut self, height: u64, peers: usize) {
        let reason = format!("only {peers} peers connected");
        self.transition(EngineState::Partitioned, &reason, height);
    }

    pub fn on_partition_healed(&mut self, height: u64, peers: usize) {
        let reason = format!("partition healed, {peers} peers");
        self.transition(EngineState::Nominal, &reason, height);
    }

    pub fn on_admin_locked(&mut self, height: u64) {
        self.transition(EngineState::AdminLocked, "ForceHeight rate limit exceeded", height);
    }
}

impl Default for StateMachine {
    fn default() -> Self { Self::new() }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn transitions_are_logged() {
        let mut sm = StateMachine::new();
        assert_eq!(sm.current(), EngineState::Nominal);
        sm.on_lag_detected(100, 5);
        assert_eq!(sm.current(), EngineState::Syncing);
        assert_eq!(sm.history().len(), 1);
    }

    #[test]
    fn noop_transition_not_logged() {
        let mut sm = StateMachine::new();
        sm.transition(EngineState::Nominal, "test", 0);
        assert_eq!(sm.history().len(), 0);
    }

    #[test]
    fn count_tracks_state_visits() {
        let mut sm = StateMachine::new();
        sm.on_lag_detected(100, 5);
        sm.on_synced(105);
        sm.on_lag_detected(106, 3);
        sm.on_synced(109);
        assert_eq!(sm.count(EngineState::Syncing), 2);
        assert_eq!(sm.count(EngineState::Nominal), 2);
    }
}
