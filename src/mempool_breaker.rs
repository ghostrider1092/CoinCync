//! CoinCync mempool **circuit breaker** — the DoS / load-shedding bulkhead.
//!
//! Protects a node from mempool flooding and resource exhaustion by **shedding
//! admission** (refusing/throttling *new* transactions) when a safety threshold
//! is crossed — while block production and the chain keep running. That is the
//! bulkhead here: seal the intake valve, keep mining.
//!
//! ## Key difference from the shielded / supply breakers
//!
//! Mempool admission is **node-local policy, not consensus.** Two honest nodes
//! may hold different mempools and still agree on the chain. So this breaker is
//! safe to **arm per-node on the live network** — throttling intake cannot fork
//! the chain. (The shielded and supply breakers *are* consensus and need a
//! coordinated, activation-gated arming; this one does not.) It is still built to
//! the same bar: pure, fail-closed, feature-gated, declared from `lib.rs` (not
//! the hash-locked consensus core), default policy `Observe`.
//!
//! Complements the existing admission limits (per-IP connection caps, fee floor,
//! admission gates) by packaging the *shed-load response* as one tested slot.

/// A mempool safety threshold breach.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MempoolFault {
    /// Pending transaction count exceeded the cap.
    CountExhaustion,
    /// Pending byte footprint exceeded the cap.
    ByteExhaustion,
    /// Total arrivals this interval exceeded the safe rate (global flood).
    ArrivalFlood,
    /// A single peer's arrivals this interval exceeded its per-peer share
    /// (targeted flood / spam source).
    PerPeerFlood,
    /// Below-fee-floor ("dust") arrivals this interval exceeded the tolerance —
    /// cheap-spam pressure.
    DustSpam,
}

/// What the node observed about its mempool over one sampling interval. All
/// already tracked by the node; the breaker only reasons over it.
#[derive(Clone, Copy, Debug, Default)]
pub struct MempoolObservation {
    /// Current pending transaction count and its cap.
    pub pending_count: usize,
    pub max_count: usize,
    /// Current pending byte footprint and its cap.
    pub pending_bytes: usize,
    pub max_bytes: usize,
    /// Transaction arrivals this interval and the safe ceiling.
    pub arrivals_this_interval: u32,
    pub max_arrivals_per_interval: u32,
    /// Arrivals from the single busiest peer and the per-peer ceiling.
    pub worst_peer_arrivals: u32,
    pub max_per_peer_arrivals: u32,
    /// Below-fee-floor arrivals this interval and the tolerance.
    pub dust_arrivals: u32,
    pub max_dust: u32,
}

/// Collect every mempool threshold breach (empty = healthy). Pure.
pub fn detect(o: &MempoolObservation) -> Vec<MempoolFault> {
    let mut f = Vec::new();
    if o.pending_count > o.max_count {
        f.push(MempoolFault::CountExhaustion);
    }
    if o.pending_bytes > o.max_bytes {
        f.push(MempoolFault::ByteExhaustion);
    }
    if o.arrivals_this_interval > o.max_arrivals_per_interval {
        f.push(MempoolFault::ArrivalFlood);
    }
    if o.worst_peer_arrivals > o.max_per_peer_arrivals {
        f.push(MempoolFault::PerPeerFlood);
    }
    if o.dust_arrivals > o.max_dust {
        f.push(MempoolFault::DustSpam);
    }
    f
}

/// Breaker policy. **Default `Observe`** — detect + log, never throttle.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BreakerPolicy {
    /// Detect + log only; never throttle. Default.
    Observe,
    /// Shed load (throttle admission) on any detected breach. Safe to set
    /// per-node on the live net — mempool policy is local, not consensus.
    Armed,
}

impl Default for BreakerPolicy {
    fn default() -> Self {
        BreakerPolicy::Observe
    }
}

/// The breaker's decision. Isolation scope = the admission valve; block
/// production is never in scope.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum BreakerAction {
    /// Admit new transactions normally.
    AdmitNormally,
    /// Shed load: stop/throttle admitting new transactions until pressure eases.
    /// Existing mempool contents and block production are unaffected.
    ThrottleAdmission { faults: Vec<MempoolFault> },
}

impl BreakerAction {
    /// Whether the node should throttle new-transaction admission.
    pub fn throttles_admission(&self) -> bool {
        matches!(self, BreakerAction::ThrottleAdmission { .. })
    }

    /// The bulkhead guarantee: throttling intake never halts block production.
    /// Always false — stated explicitly so callers can rely on it.
    pub fn halts_mining(&self) -> bool {
        false
    }
}

/// Evaluate: detect breaches, then apply policy. `Observe` always admits (logs);
/// `Armed` throttles iff any breach is present.
pub fn evaluate(policy: BreakerPolicy, o: &MempoolObservation) -> BreakerAction {
    let faults = detect(o);
    match policy {
        BreakerPolicy::Observe => BreakerAction::AdmitNormally,
        BreakerPolicy::Armed if faults.is_empty() => BreakerAction::AdmitNormally,
        BreakerPolicy::Armed => BreakerAction::ThrottleAdmission { faults },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A mempool comfortably under every limit.
    fn healthy() -> MempoolObservation {
        MempoolObservation {
            pending_count: 100,
            max_count: 50_000,
            pending_bytes: 1_000_000,
            max_bytes: 300_000_000,
            arrivals_this_interval: 50,
            max_arrivals_per_interval: 1_000,
            worst_peer_arrivals: 10,
            max_per_peer_arrivals: 100,
            dust_arrivals: 0,
            max_dust: 50,
        }
    }

    #[test]
    fn default_policy_is_observe() {
        assert_eq!(BreakerPolicy::default(), BreakerPolicy::Observe);
    }

    #[test]
    fn healthy_mempool_admits_in_both_modes() {
        assert!(detect(&healthy()).is_empty());
        assert_eq!(evaluate(BreakerPolicy::Observe, &healthy()), BreakerAction::AdmitNormally);
        assert_eq!(evaluate(BreakerPolicy::Armed, &healthy()), BreakerAction::AdmitNormally);
    }

    #[test]
    fn global_flood_throttles_but_never_halts_mining() {
        let mut o = healthy();
        o.arrivals_this_interval = 5_000; // > 1000
        assert!(detect(&o).contains(&MempoolFault::ArrivalFlood));
        // Observe logs only.
        assert!(!evaluate(BreakerPolicy::Observe, &o).throttles_admission());
        // Armed sheds load but keeps producing blocks.
        let a = evaluate(BreakerPolicy::Armed, &o);
        assert!(a.throttles_admission());
        assert!(!a.halts_mining());
    }

    #[test]
    fn per_peer_flood_is_isolated() {
        let mut o = healthy();
        o.worst_peer_arrivals = 10_000; // one abusive peer
        assert!(detect(&o).contains(&MempoolFault::PerPeerFlood));
        assert!(evaluate(BreakerPolicy::Armed, &o).throttles_admission());
    }

    #[test]
    fn count_byte_and_dust_exhaustion_detected() {
        let mut o = healthy();
        o.pending_count = o.max_count + 1;
        assert!(detect(&o).contains(&MempoolFault::CountExhaustion));

        let mut o2 = healthy();
        o2.pending_bytes = o2.max_bytes + 1;
        assert!(detect(&o2).contains(&MempoolFault::ByteExhaustion));

        let mut o3 = healthy();
        o3.dust_arrivals = o3.max_dust + 1;
        assert!(detect(&o3).contains(&MempoolFault::DustSpam));
    }

    #[test]
    fn multiple_breaches_all_reported() {
        let mut o = healthy();
        o.arrivals_this_interval = 9_999;
        o.worst_peer_arrivals = 9_999;
        o.pending_count = o.max_count + 1;
        if let BreakerAction::ThrottleAdmission { faults } = evaluate(BreakerPolicy::Armed, &o) {
            assert!(faults.len() >= 3);
        } else {
            panic!("expected ThrottleAdmission");
        }
    }
}
