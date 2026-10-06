//! # Security details — a chain-wide protection pattern
//!
//! The "Secret Service" pattern, generalized. Every subsystem with an attack
//! surface — the shielded pool, the UTXO set, the mempool, the peer set, the
//! Phase-2 accumulator stores — shares the same shape of defense:
//!
//! - **Guards**: fail-closed invariants that an honest node must never break.
//!   A violation is a *critical* alert — evidence of corruption or an attack.
//! - **Scan**: surveillance that surfaces *soft* anomalies (velocity, ratios,
//!   saturation). Worth a look; not, alone, proof of a fault.
//!
//! A [`SecurityDetail`] implements that shape for one subsystem; the
//! [`SecurityCommand`] runs many details and aggregates their [`Alert`]s into
//! one [`SecurityReport`]. This is **read-only, reporting-only** infrastructure:
//! a detail observes and raises alerts; it never mutates consensus state. A
//! caller decides what a critical alert means (log, page, or halt).
//!
//! The framework itself is dependency-free and always compiled; individual
//! details live with their subsystems (e.g. the shielded pool's detail is gated
//! with the pool).

use std::collections::VecDeque;
use std::fmt;

use parking_lot::RwLock;

/// Supply-integrity detail (inflation surface). See [`supply`].
pub mod supply;

/// How serious an alert is.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Severity {
    /// Informational — a normal observation.
    Info,
    /// A soft anomaly — worth investigating, not proof of a fault.
    Warning,
    /// A broken invariant — an honest node should never reach this state.
    Critical,
}

impl fmt::Display for Severity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Severity::Info => write!(f, "INFO"),
            Severity::Warning => write!(f, "WARN"),
            Severity::Critical => write!(f, "CRITICAL"),
        }
    }
}

/// Whether an alert may influence consensus. This is the load-bearing
/// distinction (Stage 2): mixing the two is how a security layer either lets
/// corruption through or becomes a DoS / consensus-divergence vector.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AlertClass {
    /// A broken invariant that MUST hold identically on every honest node.
    /// Its check is deterministic (no wall-clock, no node-local state) and
    /// cheap (O(1) on the hot path), so it is safe to HALT/reject on. A
    /// `Consensus` + `Critical` alert is a genuine halt condition.
    Consensus,
    /// A local operational heuristic (velocity, ratios, peer churn). May be
    /// non-deterministic and O(n); it is only ever logged/paged — NEVER halts
    /// the node, or a heuristic false-positive would wedge the chain.
    Operational,
}

/// The recommended RESPONSE to a finding — a graduated ladder, so security does
/// more than log-or-halt. Ordered weakest→strongest; a caller maps it to a
/// concrete action for its context (a validator rejects, a peer manager bans, a
/// node halts). Graduating the response also shrinks the "trip a guard to halt
/// the network" DoS surface: most findings quarantine or ban, and only a proven
/// self-corruption halts.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Disposition {
    /// Nothing to do.
    Accept,
    /// Record for the operator; no active response.
    Log,
    /// Rate-limit the source (soft operational pressure).
    Throttle,
    /// Reject this item WITHOUT halting (a bad block/tx pre-apply, an over-cap
    /// mempool) — prevention, not a network-wide stop.
    Quarantine,
    /// Ban the offending peer — a repeated/abusive operational signal.
    BanPeer,
    /// Stop the node to preserve on-disk state — a proven self-corruption.
    Halt,
}

impl fmt::Display for Disposition {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Disposition::Accept => "accept",
            Disposition::Log => "log",
            Disposition::Throttle => "throttle",
            Disposition::Quarantine => "quarantine",
            Disposition::BanPeer => "ban-peer",
            Disposition::Halt => "halt",
        };
        write!(f, "{s}")
    }
}

/// One finding from a security detail.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Alert {
    /// The detail that raised it (e.g. `"shielded-pool"`, `"utxo-set"`).
    pub detail: &'static str,
    pub severity: Severity,
    /// Whether this alert may drive a consensus halt, or is operational-only.
    pub class: AlertClass,
    /// A short stable code for the invariant/anomaly (e.g. `"coin-from-future"`).
    pub code: &'static str,
    /// Human-readable specifics.
    pub message: String,
}

impl Alert {
    /// The default graduated response for this alert. A consensus-critical is a
    /// `Halt` (or, pre-apply, a `Quarantine`/reject — the caller decides which
    /// point it is at); an operational critical bans the source; a warning
    /// throttles; info is logged. Details may special-case, but this is the
    /// safe default ladder.
    pub fn disposition(&self) -> Disposition {
        match (self.severity, self.class) {
            (Severity::Critical, AlertClass::Consensus) => Disposition::Halt,
            (Severity::Critical, AlertClass::Operational) => Disposition::BanPeer,
            (Severity::Warning, _) => Disposition::Throttle,
            (Severity::Info, _) => Disposition::Log,
        }
    }
}

/// The aggregated findings of one or more details' sweeps.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SecurityReport {
    pub alerts: Vec<Alert>,
}

impl SecurityReport {
    /// An empty (clean) report.
    pub fn clean() -> Self {
        Self { alerts: Vec::new() }
    }

    /// Raise a **consensus-critical** invariant alert (deterministic, cheap —
    /// safe to halt on when `Critical`).
    pub fn raise_consensus(&mut self, detail: &'static str, severity: Severity, code: &'static str, message: impl Into<String>) {
        self.alerts.push(Alert { detail, severity, class: AlertClass::Consensus, code, message: message.into() });
    }

    /// Raise an **operational** heuristic alert (log/page only — never halts).
    pub fn raise_operational(&mut self, detail: &'static str, severity: Severity, code: &'static str, message: impl Into<String>) {
        self.alerts.push(Alert { detail, severity, class: AlertClass::Operational, code, message: message.into() });
    }

    /// Fold another report's alerts in.
    pub fn merge(&mut self, other: SecurityReport) {
        self.alerts.extend(other.alerts);
    }

    /// Any critical alert of any class present (for paging/visibility).
    pub fn has_critical(&self) -> bool {
        self.alerts.iter().any(|a| a.severity == Severity::Critical)
    }

    /// A **consensus** halt condition: a `Critical` alert of class `Consensus`.
    /// This — not `has_critical` — is what a node acts on. An operational
    /// critical never halts.
    pub fn has_consensus_halt(&self) -> bool {
        self.alerts
            .iter()
            .any(|a| a.severity == Severity::Critical && a.class == AlertClass::Consensus)
    }

    /// The critical alerts of any class, if any.
    pub fn criticals(&self) -> impl Iterator<Item = &Alert> {
        self.alerts.iter().filter(|a| a.severity == Severity::Critical)
    }

    /// True iff nothing at all was raised.
    pub fn is_clean(&self) -> bool {
        self.alerts.is_empty()
    }

    /// Count of alerts at or above a severity.
    pub fn count_at_least(&self, severity: Severity) -> usize {
        self.alerts.iter().filter(|a| a.severity >= severity).count()
    }

    /// The strongest recommended response across all alerts (graduated
    /// response). `Accept` when clean. The caller acts on this: pre-apply,
    /// `Halt`/`Quarantine` both mean "reject the block"; post-apply, `Halt`
    /// stops the node; `BanPeer`/`Throttle` are peer/rate actions.
    pub fn disposition(&self) -> Disposition {
        self.alerts.iter().map(Alert::disposition).max().unwrap_or(Disposition::Accept)
    }

    /// The distinct detail labels that fired — the *breadth* of the incident.
    pub fn distinct_details(&self) -> usize {
        use std::collections::HashSet;
        self.alerts.iter().map(|a| a.detail).collect::<HashSet<_>>().len()
    }

    /// Cross-surface correlation: a coordinated attack is suspected when
    /// multiple DISTINCT subsystems raise alerts together (e.g. peer isolation
    /// AND a pool anomaly) with at least one at Critical. A single noisy detail
    /// is not enough — breadth across surfaces is the signal a real, staged
    /// attack leaves.
    pub fn coordinated_attack_suspected(&self) -> bool {
        self.distinct_details() >= 2 && self.count_at_least(Severity::Critical) >= 1
    }
}

/// A protection detail for one subsystem. Holds its own read-only view of the
/// subsystem (a borrow of its store + any context) and reports on a sweep.
pub trait SecurityDetail {
    /// Stable label for this detail (used as the alert's `detail`).
    fn label(&self) -> &'static str;

    /// Observe the subsystem and raise any guard violations (critical) and scan
    /// anomalies (warning). Never mutates state.
    fn sweep(&self) -> SecurityReport;
}

/// The coordinator — "HQ". Runs a set of details and aggregates their reports.
pub struct SecurityCommand;

impl SecurityCommand {
    /// Sweep every detail and merge the findings into one report. The order of
    /// `details` is preserved in the merged alerts.
    pub fn sweep_all(details: &[&dyn SecurityDetail]) -> SecurityReport {
        let mut report = SecurityReport::clean();
        for d in details {
            report.merge(d.sweep());
        }
        report
    }

    /// Sweep and return `Err(report)` iff a **consensus** halt condition is
    /// present (a `Critical` + `Consensus` alert). This is the fail-closed entry
    /// point a node wires into block-apply to halt on corruption. Operational
    /// alerts — even `Critical` ones — never trip this; they are for paging.
    pub fn assert_consensus_safe(
        details: &[&dyn SecurityDetail],
    ) -> Result<SecurityReport, SecurityReport> {
        let report = Self::sweep_all(details);
        if report.has_consensus_halt() {
            Err(report)
        } else {
            Ok(report)
        }
    }
}

/// An adaptive baseline for one operational metric: an exponentially-weighted
/// moving mean + variance. A detail feeds observations in and asks whether a
/// new value is anomalous *relative to the learned norm*, instead of comparing
/// to a hard-coded threshold that is wrong for regtest and wrong for mainnet.
///
/// EWMA variance (Finch/West form): keeps recent behavior weighted over old, so
/// the baseline tracks a drifting chain. Never flags during a warmup window
/// (too few samples to have a norm yet).
#[derive(Clone, Debug)]
pub struct Baseline {
    mean: f64,
    var: f64,
    alpha: f64,
    samples: u64,
    warmup: u64,
}

impl Baseline {
    /// `alpha` in (0,1] is the smoothing factor (higher = more reactive).
    /// `warmup` observations must accrue before anything is flagged.
    pub fn new(alpha: f64, warmup: u64) -> Self {
        Self { mean: 0.0, var: 0.0, alpha: alpha.clamp(f64::MIN_POSITIVE, 1.0), samples: 0, warmup }
    }

    /// Fold one observation into the baseline.
    pub fn update(&mut self, x: f64) {
        if self.samples == 0 {
            self.mean = x;
        } else {
            let diff = x - self.mean;
            let incr = self.alpha * diff;
            self.mean += incr;
            self.var = (1.0 - self.alpha) * (self.var + diff * incr);
        }
        self.samples += 1;
    }

    pub fn mean(&self) -> f64 {
        self.mean
    }

    pub fn stddev(&self) -> f64 {
        self.var.max(0.0).sqrt()
    }

    pub fn samples(&self) -> u64 {
        self.samples
    }

    /// Is `x` anomalous — more than `k` standard deviations from the mean —
    /// given enough history? Returns false during warmup (no norm yet). With a
    /// (near-)zero variance, only an exact-mean value is non-anomalous.
    pub fn is_anomalous(&self, x: f64, k: f64) -> bool {
        if self.samples < self.warmup {
            return false;
        }
        (x - self.mean).abs() > k * self.stddev()
    }
}

/// One recorded security event: a monotonic sequence number, the chain height
/// it was observed at, and the alert. The incident log is the operator's
/// audit trail — what the guards saw, when.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Incident {
    pub seq: u64,
    pub height: u64,
    pub alert: Alert,
}

/// A bounded, thread-safe, append-only record of security events, plus the
/// running totals an operator's console reads. Bounded (oldest evicted past the
/// cap) so a long-running node's memory stays flat; durable persistence to a
/// column family is a follow-up (the shape here is the source of truth).
pub struct IncidentLog {
    inner: RwLock<Inner>,
    cap: usize,
}

struct Inner {
    seq: u64,
    total: u64,
    total_consensus_halts: u64,
    ring: VecDeque<Incident>,
}

impl IncidentLog {
    /// A log retaining the most recent `cap` incidents.
    pub fn new(cap: usize) -> Self {
        Self {
            inner: RwLock::new(Inner {
                seq: 0,
                total: 0,
                total_consensus_halts: 0,
                ring: VecDeque::new(),
            }),
            cap: cap.max(1),
        }
    }

    /// Record one alert observed at `height`. Also emits it to `tracing` at the
    /// right level (a consensus halt is an error; operational is a warning).
    /// Returns the assigned sequence number.
    pub fn record(&self, height: u64, alert: Alert) -> u64 {
        match (alert.severity, alert.class) {
            (Severity::Critical, AlertClass::Consensus) => tracing::error!(
                target: "security",
                detail = alert.detail, code = alert.code, height, "CONSENSUS HALT: {}", alert.message
            ),
            (Severity::Critical, AlertClass::Operational) => tracing::warn!(
                target: "security",
                detail = alert.detail, code = alert.code, height, "critical anomaly: {}", alert.message
            ),
            (Severity::Warning, _) => tracing::warn!(
                target: "security",
                detail = alert.detail, code = alert.code, height, "{}", alert.message
            ),
            (Severity::Info, _) => tracing::info!(
                target: "security",
                detail = alert.detail, code = alert.code, height, "{}", alert.message
            ),
        }
        let mut g = self.inner.write();
        g.seq += 1;
        g.total += 1;
        if alert.severity == Severity::Critical && alert.class == AlertClass::Consensus {
            g.total_consensus_halts += 1;
        }
        let seq = g.seq;
        g.ring.push_back(Incident { seq, height, alert });
        while g.ring.len() > self.cap {
            g.ring.pop_front();
        }
        seq
    }

    /// Record every alert in a sweep report (with tracing emission).
    pub fn record_report(&self, height: u64, report: &SecurityReport) {
        for a in &report.alerts {
            self.record(height, a.clone());
        }
    }

    /// The most recent `n` incidents, newest last.
    pub fn recent(&self, n: usize) -> Vec<Incident> {
        let g = self.inner.read();
        let start = g.ring.len().saturating_sub(n);
        g.ring.iter().skip(start).cloned().collect()
    }

    /// Recent incidents at or above a severity, newest last.
    pub fn recent_at_least(&self, severity: Severity, n: usize) -> Vec<Incident> {
        let g = self.inner.read();
        let mut out: Vec<Incident> =
            g.ring.iter().filter(|i| i.alert.severity >= severity).cloned().collect();
        let start = out.len().saturating_sub(n);
        out.drain(..start);
        out
    }

    /// Total incidents ever recorded (including evicted ones).
    pub fn total(&self) -> u64 {
        self.inner.read().total
    }

    /// Total consensus-halt events ever recorded — the number an operator most
    /// wants to see is zero.
    pub fn total_consensus_halts(&self) -> u64 {
        self.inner.read().total_consensus_halts
    }

    // ── Correlation ──────────────────────────────────────────────────────────
    // A single operational warning is noise; the *same* warning firing over and
    // over, or many distinct alerts firing together, is signal. These queries
    // run over the retained window (stateful where the state already lives), so
    // a console can escalate a repeated/broad pattern without extra bookkeeping.

    /// How many retained incidents carry `code`.
    pub fn repeat_count(&self, code: &str) -> usize {
        self.inner.read().ring.iter().filter(|i| i.alert.code == code).count()
    }

    /// Distinct `(detail, code)` pairs in the retained window — the *breadth* of
    /// what is firing. Many distinct alerts at once is a correlation signal.
    pub fn distinct_alert_kinds(&self) -> usize {
        use std::collections::HashSet;
        let g = self.inner.read();
        g.ring
            .iter()
            .map(|i| (i.alert.detail, i.alert.code))
            .collect::<HashSet<_>>()
            .len()
    }

    /// Codes whose retained-window count reaches `threshold` — an escalation
    /// list a console promotes above single-shot noise (paired with each code's
    /// count). Deterministic order (by count desc, then code).
    pub fn escalations(&self, threshold: usize) -> Vec<(String, usize)> {
        use std::collections::HashMap;
        let g = self.inner.read();
        let mut counts: HashMap<&str, usize> = HashMap::new();
        for i in g.ring.iter() {
            *counts.entry(i.alert.code).or_insert(0) += 1;
        }
        let mut out: Vec<(String, usize)> = counts
            .into_iter()
            .filter(|(_, n)| *n >= threshold)
            .map(|(c, n)| (c.to_string(), n))
            .collect();
        out.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
        out
    }
}

impl Default for IncidentLog {
    /// A reasonable default retention for an operator console.
    fn default() -> Self {
        Self::new(1024)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct MockDetail {
        label: &'static str,
        consensus_critical: bool,
        operational_critical: bool,
        warnings: usize,
    }
    impl SecurityDetail for MockDetail {
        fn label(&self) -> &'static str {
            self.label
        }
        fn sweep(&self) -> SecurityReport {
            let mut r = SecurityReport::clean();
            if self.consensus_critical {
                r.raise_consensus(self.label, Severity::Critical, "mock-crit", "invariant broken");
            }
            if self.operational_critical {
                r.raise_operational(self.label, Severity::Critical, "mock-op-crit", "severe anomaly");
            }
            for _ in 0..self.warnings {
                r.raise_operational(self.label, Severity::Warning, "mock-warn", "anomaly");
            }
            r
        }
    }

    #[test]
    fn command_aggregates_details_and_halts_only_on_consensus_critical() {
        let clean = MockDetail { label: "a", consensus_critical: false, operational_critical: false, warnings: 1 };
        let broken = MockDetail { label: "b", consensus_critical: true, operational_critical: false, warnings: 2 };
        let details: [&dyn SecurityDetail; 2] = [&clean, &broken];

        let report = SecurityCommand::sweep_all(&details);
        assert_eq!(report.alerts.len(), 1 + 1 + 2, "all alerts aggregated");
        assert!(report.has_critical());
        assert!(report.has_consensus_halt());
        assert_eq!(report.count_at_least(Severity::Warning), 4);

        // A consensus-critical trips the halt.
        assert!(SecurityCommand::assert_consensus_safe(&details).is_err());
    }

    #[test]
    fn operational_critical_pages_but_never_halts() {
        // The load-bearing Stage-2 property: an operational heuristic firing at
        // Critical severity is visible (has_critical) but must NOT halt the node
        // — otherwise a false-positive heuristic wedges the chain.
        let noisy = MockDetail { label: "a", consensus_critical: false, operational_critical: true, warnings: 3 };
        let details: [&dyn SecurityDetail; 1] = [&noisy];
        let report = SecurityCommand::assert_consensus_safe(&details).expect("operational critical does not halt");
        assert!(report.has_critical(), "still visible for paging");
        assert!(!report.has_consensus_halt(), "but never a consensus halt");
    }

    #[test]
    fn all_clean_details_pass() {
        let a = MockDetail { label: "a", consensus_critical: false, operational_critical: false, warnings: 0 };
        let b = MockDetail { label: "b", consensus_critical: false, operational_critical: false, warnings: 0 };
        let details: [&dyn SecurityDetail; 2] = [&a, &b];
        let ok = SecurityCommand::assert_consensus_safe(&details).expect("no consensus halt");
        assert!(ok.is_clean());
    }

    #[test]
    fn incident_log_records_bounds_and_queries() {
        let log = IncidentLog::new(3); // small cap to exercise eviction
        for h in 1..=5u64 {
            log.push_alert("t", Severity::Warning, AlertClass::Operational, "warn", format!("at {h}"));
        }
        // Bounded to the last 3; total counts all 5.
        assert_eq!(log.total(), 5);
        let recent = log.recent(10);
        assert_eq!(recent.len(), 3, "ring bounded to cap");
        assert_eq!(recent.first().unwrap().alert.message, "at 3");
        assert_eq!(recent.last().unwrap().alert.message, "at 5");
        assert_eq!(recent.last().unwrap().seq, 5, "monotonic seq survives eviction");

        // A consensus halt is counted separately.
        assert_eq!(log.total_consensus_halts(), 0);
        log.push_alert("t", Severity::Critical, AlertClass::Consensus, "crit", "broke");
        assert_eq!(log.total_consensus_halts(), 1);
        assert_eq!(log.recent_at_least(Severity::Critical, 10).len(), 1);
    }

    // Convenience so the tests can push alerts without building structs.
    impl IncidentLog {
        fn push_alert(&self, detail: &'static str, sev: Severity, class: AlertClass, code: &'static str, msg: impl Into<String>) -> u64 {
            self.record(0, Alert { detail, severity: sev, class, code, message: msg.into() })
        }
    }

    #[test]
    fn record_report_emits_all_alerts() {
        let log = IncidentLog::default();
        let mut r = SecurityReport::clean();
        r.raise_consensus("pool", Severity::Critical, "c", "x");
        r.raise_operational("pool", Severity::Warning, "w", "y");
        log.record_report(42, &r);
        assert_eq!(log.total(), 2);
        assert_eq!(log.total_consensus_halts(), 1);
        assert!(log.recent(10).iter().all(|i| i.height == 42));
    }

    #[test]
    fn baseline_learns_a_norm_and_flags_deviation() {
        let mut b = Baseline::new(0.3, 5);
        // Warmup: even a wild value is not flagged (no norm yet).
        assert!(!b.is_anomalous(9999.0, 3.0));
        // Feed a stable-ish series around 100.
        for x in [100.0, 101.0, 99.0, 100.0, 101.0, 99.0, 100.0, 100.0] {
            b.update(x);
        }
        assert!((b.mean() - 100.0).abs() < 5.0, "mean settled near 100");
        // A value near the norm is fine; a large excursion is anomalous.
        assert!(!b.is_anomalous(101.0, 3.0), "within-norm value is not anomalous");
        assert!(b.is_anomalous(1000.0, 3.0), "10x excursion is anomalous");
    }

    #[test]
    fn incident_log_correlates_repeats_and_breadth() {
        let log = IncidentLog::new(100);
        // Same code five times → repeat signal.
        for _ in 0..5 {
            log.push_alert("pool", Severity::Warning, AlertClass::Operational, "high-mint-velocity", "burst");
        }
        // Two other distinct codes once each.
        log.push_alert("pool", Severity::Warning, AlertClass::Operational, "high-spend-ratio", "drain");
        log.push_alert("utxo", Severity::Warning, AlertClass::Operational, "dust-flood", "spam");

        assert_eq!(log.repeat_count("high-mint-velocity"), 5);
        assert_eq!(log.repeat_count("nope"), 0);
        assert_eq!(log.distinct_alert_kinds(), 3);

        // Escalate only codes seen >= 3 times → just the repeated one.
        let esc = log.escalations(3);
        assert_eq!(esc, vec![("high-mint-velocity".to_string(), 5)]);
    }

    #[test]
    fn redteam_baseline_and_log_survive_hostile_input() {
        // Baseline: extreme + degenerate inputs must not panic.
        let mut b = Baseline::new(0.5, 3);
        b.update(f64::MAX);
        b.update(f64::MIN_POSITIVE);
        b.update(0.0);
        b.update(1e300);
        let _ = b.is_anomalous(f64::MAX, 3.0); // no panic
        let _ = b.is_anomalous(f64::NAN, 3.0); // NaN comparison → false, no panic
        assert!(!Baseline::new(0.5, 1000).is_anomalous(1e18, 3.0), "still in warmup, never flags");

        // IncidentLog with the minimum cap floods to a bounded ring but counts all.
        let log = IncidentLog::new(0); // clamped to >= 1
        for _ in 0..1000 {
            log.push_alert("x", Severity::Warning, AlertClass::Operational, "flood", "");
        }
        assert_eq!(log.recent(100).len(), 1, "ring stays bounded under flood");
        assert_eq!(log.total(), 1000, "totals count everything");
        assert_eq!(log.repeat_count("flood"), 1, "only retained window counts");

        // Correlation on an empty log is empty, not a panic.
        let empty = IncidentLog::default();
        assert!(empty.escalations(1).is_empty());
        assert_eq!(empty.distinct_alert_kinds(), 0);
    }

    #[test]
    fn graduated_response_ladder_and_report_disposition() {
        // Per-alert ladder.
        let halt = Alert { detail: "d", severity: Severity::Critical, class: AlertClass::Consensus, code: "c", message: String::new() };
        let ban = Alert { detail: "d", severity: Severity::Critical, class: AlertClass::Operational, code: "c", message: String::new() };
        let thr = Alert { detail: "d", severity: Severity::Warning, class: AlertClass::Operational, code: "c", message: String::new() };
        assert_eq!(halt.disposition(), Disposition::Halt);
        assert_eq!(ban.disposition(), Disposition::BanPeer);
        assert_eq!(thr.disposition(), Disposition::Throttle);
        assert!(Disposition::Halt > Disposition::BanPeer && Disposition::BanPeer > Disposition::Throttle);

        // Report takes the strongest response present.
        let mut r = SecurityReport::clean();
        assert_eq!(r.disposition(), Disposition::Accept);
        r.raise_operational("d", Severity::Warning, "w", "x");
        assert_eq!(r.disposition(), Disposition::Throttle);
        r.raise_consensus("d", Severity::Critical, "c", "y");
        assert_eq!(r.disposition(), Disposition::Halt, "strongest wins");
    }

    #[test]
    fn cross_surface_correlation_needs_breadth() {
        // One noisy detail, even with a critical, is not "coordinated".
        let mut single = SecurityReport::clean();
        single.raise_operational("mempool", Severity::Critical, "flood", "x");
        assert!(!single.coordinated_attack_suspected(), "one surface is not coordinated");

        // Two distinct surfaces + a critical → coordinated attack suspected
        // (e.g. peer isolation while the pool misbehaves — a staged attack).
        let mut multi = SecurityReport::clean();
        multi.raise_operational("peer-set", Severity::Warning, "low-peers", "eclipse?");
        multi.raise_consensus("shielded-pool", Severity::Critical, "coin-from-future", "!");
        assert_eq!(multi.distinct_details(), 2);
        assert!(multi.coordinated_attack_suspected());
    }

    #[test]
    fn severity_orders_and_displays() {
        assert!(Severity::Critical > Severity::Warning);
        assert!(Severity::Warning > Severity::Info);
        assert_eq!(Severity::Critical.to_string(), "CRITICAL");
    }
}
