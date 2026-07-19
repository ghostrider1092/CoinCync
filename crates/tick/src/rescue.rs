//! RescueTick — the tick mode that quests for stalled fleet peers with
//! divergent chain state, verifies the canonical chain via PoW, then
//! feeds chaindata to stalled hosts in a runbook-safe order.
//!
//! Anchored to the 2026-07-04 hard-finality-stuck partition class
//! (see `docs/operations/runbook-hard-finality-stuck.md` and
//! `docs/architecture/tick.md`'s RescueTick section).
//!
//! # State machine
//!
//! ```text
//!  Quest ─────┐ divergence detected + PoW verified
//!    ▲        ▼
//!    │      Latch — snapshot canonical chaindata
//!    │        │
//!    │        ▼
//!    │      Feed  — iterate hosts (priority order) with safety gate
//!    │        │
//!    │        ▼
//!    └── Detach — emit Recovered notice, clear state
//! ```
//!
//! # Privacy contract enforcement
//!
//! - **Notices are aggregate**: "1 host feeding N hosts on canonical
//!   fork" — never names individual hosts.
//! - **`require_operator_ack` gates auto-recovery**: mainnet default
//!   is `true`, so this method calls `latch()` and stops there,
//!   emitting a Hunt notice. Testnet default `false` proceeds to feed.
//! - **PoW verification is mandatory**: divergence WITHOUT successful
//!   `verify_peer_header_pow` never triggers a feed — the tick
//!   downgrades to a `Critical` alert instead. This is the defense
//!   against a hostile RescueTick pointing at a spoofed chain.

use std::collections::VecDeque;
use std::sync::{Arc, Mutex};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use crate::adapter::ChainAdapter;
use crate::tick::{TickBehavior, TickPhase};
use crate::types::*;

// ─── Config ────────────────────────────────────────────────────────────────

/// Configuration for `RescueTick`. Defaults match the
/// mainnet-conservative posture from the design doc.
#[derive(Clone, Debug)]
pub struct RescueConfig {
    /// Block-gap threshold above which divergence is considered
    /// meaningful. Default 100 (matches the `hard_finality=100`
    /// gate — anything less can recover via normal p2p reorg).
    pub divergence_block_threshold: u64,

    /// Minimum difficulty delta (as a percent of the fleet median)
    /// above which the diverging host is treated as canonical.
    /// Default 5% — same threshold as HealthTick's `divergent_count`.
    pub canonical_min_difficulty_delta_pct: u8,

    /// When `true`, RescueTick pauses at Latch and emits a Hunt
    /// notice; the operator must manually resume. When `false`,
    /// RescueTick proceeds to Feed autonomously. **Default is `true`
    /// (safer)** — testnet configs override to `false`.
    pub require_operator_ack: bool,

    /// Rate limit on self-triggered recoveries. Default 2/hr — a
    /// misbehaving RescueTick that keeps triggering can't cascade
    /// into a fleet-wide restart storm. Not enforced in Phase 1b
    /// (needs a per-tick persistent counter which lands with the
    /// runtime in Phase 1c); documented here for the config surface.
    pub max_recovery_hosts_per_hour: u32,

    /// Directory where RescueTick stages snapshot tarballs. Must be
    /// writable by the tick user + not on the same filesystem as
    /// `/var/lib/coincync` (avoid disk pressure racing with node I/O).
    pub snapshot_dir: std::path::PathBuf,

    /// Wait between polls of a host during the between-host safety
    /// gate. Default 15s. Longer waits shorter recovery; shorter
    /// waits risk spurious "not ready" triggers.
    pub safety_gate_poll_interval_secs: u64,

    /// Maximum total time to wait for a fed host to catch up before
    /// giving up and emitting a warning. Default 600s (10 min) —
    /// long enough for a full chain re-verify on a slow host, short
    /// enough that a truly-stuck host doesn't block the whole
    /// recovery.
    pub safety_gate_max_wait_secs: u64,

    /// Minimum `peer_count` a fed host must reach before RescueTick
    /// proceeds to the next host. Default 3 (matches the standing
    /// `feedback_no_bulk_rolling_restart` rule).
    pub safety_gate_min_peer_count: u32,

    /// Maximum `tip_age_secs` a fed host may report before
    /// RescueTick considers it caught up. Default 300s.
    pub safety_gate_max_tip_age_secs: u64,
}

impl RescueConfig {
    /// Mainnet-conservative default: manual ack, 100-block threshold,
    /// 5% difficulty delta.
    pub fn mainnet_default() -> Self {
        RescueConfig {
            divergence_block_threshold: 100,
            canonical_min_difficulty_delta_pct: 5,
            require_operator_ack: true,
            max_recovery_hosts_per_hour: 2,
            snapshot_dir: std::path::PathBuf::from("/var/lib/coincync-tick/snapshots"),
            safety_gate_poll_interval_secs: 15,
            safety_gate_max_wait_secs: 600,
            safety_gate_min_peer_count: 3,
            safety_gate_max_tip_age_secs: 300,
        }
    }

    /// Testnet default: auto-recover, same thresholds.
    pub fn testnet_default() -> Self {
        Self {
            require_operator_ack: false,
            ..Self::mainnet_default()
        }
    }
}

impl Default for RescueConfig {
    /// The safer default — mainnet-conservative posture.
    fn default() -> Self {
        Self::mainnet_default()
    }
}

// ─── Recovery priority (least-critical first) ─────────────────────────────

/// Priority order for recovering hosts. Lower value = recover EARLIER.
///
/// Least-critical hosts recover first so that if the recovery
/// procedure itself has a bug, it manifests on non-load-bearing infra
/// (explorer, api) before touching the seeds that name the network.
///
/// Ordering:
///
/// - 0 = explorer (frontend, no p2p critical role)
/// - 1 = relay (gossip redundancy, but not name-serving)
/// - 2 = miner (block production — a stalled miner doesn't take down
///   the mesh, so recovering it later is fine)
/// - 3 = seed (name-serving, most critical)
/// - 5 = unknown role (last — safer default)
///
/// Excluded roles (api = nginx-only, not a coincync-node peer) never
/// enter the recovery pool because they don't run `coincync-node`.
pub fn recovery_priority(role: &str) -> u8 {
    match role {
        "explorer" => 0,
        "relay" => 1,
        "miner" => 2,
        "seed" => 3,
        _ => 5,
    }
}

// ─── State ────────────────────────────────────────────────────────────────

/// The identified canonical target once quest has verified divergence.
///
/// Only the peer identity is retained here — `hosts_to_feed` (a
/// sibling field on `RescueState`) holds the actual per-host work
/// list, and `RescueState.hosts_fed` tracks progress. Height /
/// difficulty at quest time are computed on-the-fly in `quest()` for
/// the Hunt notice text; storing them would be redundant.
#[derive(Debug, Clone)]
struct CanonicalTarget {
    /// Which fleet peer holds the canonical chain.
    canonical_peer: FleetPeer,
}

/// Internal state shared across a RescueTick's phase transitions.
#[derive(Debug)]
struct RescueState {
    phase: TickPhase,
    /// Set at end of Quest, cleared at Detach.
    canonical: Option<CanonicalTarget>,
    /// Hosts to feed, ordered by recovery priority.
    hosts_to_feed: VecDeque<FleetPeer>,
    /// Timestamp when Feed phase started (for stall detection).
    feed_started_at: Option<Instant>,
    /// Snapshot handle taken during Latch, consumed during Feed.
    snapshot: Option<Snapshot>,
    /// Count of hosts successfully fed so far in this cycle. Used in
    /// the Recovered notice text.
    hosts_fed: usize,
}

impl Default for RescueState {
    fn default() -> Self {
        RescueState {
            phase: TickPhase::Quest,
            canonical: None,
            hosts_to_feed: VecDeque::new(),
            feed_started_at: None,
            snapshot: None,
            hosts_fed: 0,
        }
    }
}

// ─── The tick ─────────────────────────────────────────────────────────────

/// RescueTick — automates recovery from the 2026-07-04-class partition
/// pattern. See module-level docs for state machine + privacy contract.
#[derive(Clone)]
pub struct RescueTick {
    /// Human-readable identifier used in notice `tick_id` field. Not a
    /// per-host name — a tick's own identifier (e.g., `"rescue-tick"`).
    tick_id: String,
    config: RescueConfig,
    state: Arc<Mutex<RescueState>>,
}

impl RescueTick {
    /// Build a new RescueTick with the given config.
    pub fn new(tick_id: impl Into<String>, config: RescueConfig) -> Self {
        RescueTick {
            tick_id: tick_id.into(),
            config,
            state: Arc::new(Mutex::new(RescueState::default())),
        }
    }

    /// Manually acknowledge a Hunt-in-progress and proceed to Feed.
    /// Used when `require_operator_ack = true` (mainnet default). The
    /// Phase 1c binary exposes this via an admin RPC / signal handler.
    ///
    /// Returns `false` if the tick isn't currently in Latch (i.e., no
    /// pending ack).
    pub fn operator_ack(&self) -> bool {
        let mut state = self.state.lock().unwrap();
        if state.phase == TickPhase::Latch {
            state.phase = TickPhase::Feed;
            state.feed_started_at = Some(Instant::now());
            true
        } else {
            false
        }
    }

    /// True if the tick is currently blocked waiting for an operator
    /// ack. Phase 1c binary polls this to know whether to expose the
    /// ack path in an admin UI.
    pub fn awaiting_ack(&self) -> bool {
        self.state.lock().unwrap().phase == TickPhase::Latch
    }

    /// Inherent accessor for the current phase, matching the
    /// `TickBehavior::phase` trait method. Both exist because the
    /// trait method is generic over `A: ChainAdapter` (needed for the
    /// runtime driver), which makes calling `tick.phase()` in
    /// non-adapter-context code type-ambiguous. This inherent method
    /// disambiguates.
    pub fn current_phase(&self) -> TickPhase {
        self.state.lock().unwrap().phase
    }

    /// Compute the current wall-clock in Unix seconds. Used for notice
    /// `emitted_at` / `expires_at`. Kept as a method rather than a
    /// free function so tests can override behavior via a subclass or
    /// wrapper if needed.
    fn now_secs(&self) -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0)
    }

    /// Emit a signed tick notice via the adapter. Signature is a
    /// placeholder in Phase 1b — Phase 1c wires the real Ed25519
    /// key from the tick's config.
    fn emit_notice<A: ChainAdapter>(
        &self,
        adapter: &A,
        kind: TickNoticeKind,
        severity: Severity,
        text: String,
        ttl_secs: u64,
    ) {
        let now = self.now_secs();
        let notice = TickNotice {
            kind,
            text,
            severity,
            tick_id: self.tick_id.clone(),
            mode: 0, // RescueTick
            emitted_at: now,
            expires_at: now + ttl_secs,
            // Placeholder — Phase 1c wires real Ed25519 signing.
            // MockAdapter accepts placeholders; production adapter
            // MUST verify before propagating.
            signature: [0u8; 64],
        };
        // Deliberately swallow broadcast errors — notice emission is
        // best-effort. A tick that couldn't broadcast is still doing
        // its actual job (recovery); we don't want notice-broadcast
        // failure to abort recovery.
        let _ = adapter.broadcast_notice(&notice);
    }
}

// ─── TickBehavior impl ────────────────────────────────────────────────────

impl<A: ChainAdapter> TickBehavior<A> for RescueTick {
    fn name(&self) -> &'static str {
        "RescueTick"
    }

    fn phase(&self) -> TickPhase {
        self.state.lock().unwrap().phase
    }

    fn quest(&self, adapter: &A) -> TickResult<bool> {
        // Only run quest if we're actually in the Quest phase. Runtime
        // guards this too, but we're defensive.
        {
            let state = self.state.lock().unwrap();
            if state.phase != TickPhase::Quest {
                return Ok(false);
            }
        }

        // Poll every fleet peer for its tip.
        let fleet = adapter.fleet_peers();
        if fleet.len() < 2 {
            // Can't detect divergence with fewer than 2 hosts.
            return Ok(false);
        }

        let mut tips: Vec<(FleetPeer, ChainTipState<A::BlockId>)> = Vec::new();
        for peer in fleet {
            match adapter.probe_peer(&peer) {
                Ok(tip) => tips.push((peer, tip)),
                Err(_) => {
                    // Unreachable host is a HealthTick concern, not a
                    // RescueTick trigger. Skip it.
                    continue;
                }
            }
        }

        if tips.len() < 2 {
            return Ok(false);
        }

        // Find max-difficulty peer (candidate canonical).
        let (candidate_peer, candidate_tip) = tips
            .iter()
            .max_by_key(|(_, t)| t.difficulty)
            .cloned()
            .expect("tips.len() >= 2");

        // Divergence check 1: block-gap threshold.
        let max_height_others = tips
            .iter()
            .filter(|(p, _)| p.name != candidate_peer.name)
            .map(|(_, t)| t.height)
            .max()
            .unwrap_or(0);

        let block_gap = candidate_tip.height.saturating_sub(max_height_others);
        if block_gap < self.config.divergence_block_threshold {
            return Ok(false);
        }

        // Divergence check 2: difficulty delta vs. max of OTHERS (not
        // vs median of all). Using median-of-all would give
        // delta == 0 for a 2-host fleet (median lands on the max),
        // false-negativing every real 2-host divergence. What we care
        // about is: is candidate CLEARLY separated from the
        // second-heaviest? max-of-others is the correct baseline for
        // that.
        let max_others_difficulty = tips
            .iter()
            .filter(|(p, _)| p.name != candidate_peer.name)
            .map(|(_, t)| t.difficulty)
            .max()
            .unwrap_or(0);

        let delta = candidate_tip
            .difficulty
            .saturating_sub(max_others_difficulty);
        let delta_pct = if max_others_difficulty == 0 {
            100u8 // pathological case; treat as diverging
        } else {
            // Scale delta by 100 and divide. Saturating cast to u8 —
            // any delta ≥ 255% clamps at 255, which is well above
            // our 5% threshold.
            let pct_u128 = (delta * 100) / max_others_difficulty;
            pct_u128.min(255) as u8
        };
        if delta_pct < self.config.canonical_min_difficulty_delta_pct {
            return Ok(false);
        }

        // Verify PoW on the candidate's tip header. This is the
        // safety-critical step — a spoofed peer that just LIES about
        // being ahead has no valid PoW to back it up.
        match adapter.verify_peer_header_pow(&candidate_peer, candidate_tip.height) {
            Ok(true) => {} // proceed
            Ok(false) => {
                // Peer is lying. Emit a Critical alert and stay in
                // Quest. This is exactly the case where a hostile
                // tick would try to feed a wrong chain — the local
                // PoW check refuses to accept the spoof.
                self.emit_notice(
                    adapter,
                    TickNoticeKind::Alert,
                    Severity::Critical,
                    "candidate canonical failed PoW verify — refusing to feed. \
                         1 host claimed a heavier chain but header PoW is INVALID".to_string(),
                    3600,
                );
                return Ok(false);
            }
            Err(_) => {
                // Adapter couldn't check. Refuse to feed on the
                // "safer than sorry" principle (per adapter method
                // docstring).
                self.emit_notice(
                    adapter,
                    TickNoticeKind::Alert,
                    Severity::Warn,
                    "unable to verify canonical PoW; refusing to feed until adapter recovers".into(),
                    1800,
                );
                return Ok(false);
            }
        }

        // All three checks passed. Latch onto this candidate.
        let stalled_count = tips
            .iter()
            .filter(|(p, _)| p.name != candidate_peer.name)
            .count();
        let mut state = self.state.lock().unwrap();
        state.canonical = Some(CanonicalTarget {
            canonical_peer: candidate_peer.clone(),
        });
        // Populate hosts_to_feed with everyone EXCEPT the canonical.
        // Sort by recovery_priority (ascending: least-critical first).
        let mut to_feed: Vec<FleetPeer> = tips
            .into_iter()
            .filter(|(p, _)| p.name != candidate_peer.name)
            .map(|(p, _)| p)
            .collect();
        to_feed.sort_by_key(|p| recovery_priority(&p.role));
        state.hosts_to_feed = to_feed.into();
        state.phase = TickPhase::Latch;
        state.hosts_fed = 0;
        drop(state);

        // Emit Hunt notice — aggregate text per privacy contract.
        self.emit_notice(
            adapter,
            TickNoticeKind::Hunt,
            Severity::Critical,
            format!(
                "RescueTick engaging: 1 host feeding {stalled_count} hosts on canonical fork"
            ),
            2 * 3600,
        );
        Ok(true)
    }

    fn latch(&self, adapter: &A) -> TickResult<()> {
        // Confirm we're in Latch phase.
        {
            let state = self.state.lock().unwrap();
            if state.phase != TickPhase::Latch {
                return Ok(());
            }
        }

        // Snapshot canonical chaindata from the canonical peer (not
        // the local host — RescueTick doesn't run ON the canonical
        // host, it orchestrates recovery TOWARD it).
        let canonical_peer = {
            let state = self.state.lock().unwrap();
            state
                .canonical
                .as_ref()
                .map(|c| c.canonical_peer.clone())
                .ok_or_else(|| {
                    TickError::InconsistentState(
                        "Latch entered without a canonical target from Quest".into(),
                    )
                })?
        };
        let dest = self.config.snapshot_dir.join(format!(
            "rescue-{}.tgz",
            self.now_secs()
        ));
        let snapshot = adapter.snapshot_chaindata(Some(&canonical_peer), &dest)?;

        {
            let mut state = self.state.lock().unwrap();
            state.snapshot = Some(snapshot);
        }

        // If auto-recover is disabled, stop here. Operator must call
        // `operator_ack()` to proceed. The runtime's tick loop will
        // observe `phase == Latch` and just wait.
        if self.config.require_operator_ack {
            // Emit a distinct notice so a wallet UI can highlight
            // "awaiting operator acknowledgment."
            self.emit_notice(
                adapter,
                TickNoticeKind::Hunt,
                Severity::Critical,
                "RescueTick paused at Latch — operator acknowledgment required to proceed".into(),
                2 * 3600,
            );
            return Ok(());
        }

        // Auto-recover: transition to Feed.
        let mut state = self.state.lock().unwrap();
        state.phase = TickPhase::Feed;
        state.feed_started_at = Some(Instant::now());
        Ok(())
    }

    fn feed(&self, adapter: &A) -> TickResult<()> {
        // Confirm Feed phase.
        {
            let state = self.state.lock().unwrap();
            if state.phase != TickPhase::Feed {
                return Ok(());
            }
        }

        // Extract the snapshot handle (needed for apply_chaindata calls).
        let snapshot_path = {
            let state = self.state.lock().unwrap();
            state
                .snapshot
                .as_ref()
                .map(|s| s.tarball_path.clone())
                .ok_or_else(|| {
                    TickError::InconsistentState(
                        "Feed entered without a snapshot from Latch".into(),
                    )
                })?
        };

        // Iterate hosts_to_feed in priority order (already sorted).
        // Per-host: apply_chaindata then wait for safety gate.
        loop {
            let next_host = {
                let mut state = self.state.lock().unwrap();
                state.hosts_to_feed.pop_front()
            };
            let host = match next_host {
                Some(h) => h,
                None => break, // done feeding
            };

            // Apply chaindata on this host. Adapter is responsible for
            // stopping the node → moving old chaindata → extracting →
            // restarting → running the receiving node's own validator.
            adapter.apply_chaindata(&snapshot_path)?;

            // Safety gate: wait until the fed host reports
            // is_synced + peer_count >= min AND tip_age < max.
            let gate_start = Instant::now();
            loop {
                if gate_start.elapsed().as_secs()
                    >= self.config.safety_gate_max_wait_secs
                {
                    // Give up on this host; emit a warning notice but
                    // continue with the rest. A slow host isn't worth
                    // blocking the whole recovery.
                    self.emit_notice(
                        adapter,
                        TickNoticeKind::Alert,
                        Severity::Warn,
                        "one host slow to catch up post-swap; continuing to next".into(),
                        1800,
                    );
                    break;
                }

                match adapter.probe_peer(&host) {
                    Ok(tip) => {
                        if tip.is_synced
                            && tip.peer_count
                                >= self.config.safety_gate_min_peer_count
                            && tip.tip_age_secs
                                <= self.config.safety_gate_max_tip_age_secs
                        {
                            break;
                        }
                    }
                    Err(_) => {
                        // Host still restarting; keep waiting.
                    }
                }

                std::thread::sleep(std::time::Duration::from_secs(
                    self.config.safety_gate_poll_interval_secs,
                ));
            }

            // Increment fed count + emit Engaged progress notice.
            let (fed_count, remaining) = {
                let mut state = self.state.lock().unwrap();
                state.hosts_fed += 1;
                (state.hosts_fed, state.hosts_to_feed.len())
            };
            self.emit_notice(
                adapter,
                TickNoticeKind::Engaged,
                Severity::Critical,
                format!(
                    "recovery in progress: {fed_count} hosts swapped, {remaining} remaining"
                ),
                1800,
            );
        }

        // All hosts fed. Transition to Detach.
        let mut state = self.state.lock().unwrap();
        state.phase = TickPhase::Detach;
        Ok(())
    }

    fn detach(&self, adapter: &A) -> TickResult<()> {
        // Detach never fails per the trait contract — swallow adapter
        // errors and log locally.
        let (canonical_count, elapsed_secs) = {
            let state = self.state.lock().unwrap();
            let elapsed = state
                .feed_started_at
                .map(|t| t.elapsed().as_secs())
                .unwrap_or(0);
            let count = state.hosts_fed;
            (count, elapsed)
        };

        // Emit Recovered notice — aggregate text.
        self.emit_notice(
            adapter,
            TickNoticeKind::Recovered,
            Severity::Info,
            format!(
                "fleet recovered to canonical chain — {canonical_count} hosts swapped in {elapsed_secs}s"
            ),
            24 * 3600,
        );

        // Reset state, return to Quest.
        let mut state = self.state.lock().unwrap();
        *state = RescueState::default();
        Ok(())
    }
}
