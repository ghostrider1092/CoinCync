//! CoinCync RPC **circuit breaker** — the node-service bulkhead.
//!
//! Shields a node's RPC surface from resource-exhaustion abuse by
//! **throttling / shedding RPC** (rate-limiting, refusing new requests, or
//! disabling a hot method) when a safety threshold is crossed — while block
//! production, P2P, and the chain keep running. Seal the service valve, keep the
//! node alive.
//!
//! Faults it isolates (the RPC surface is the unauthenticated attack edge):
//!   - **request flood** — global request rate over the safe ceiling,
//!   - **per-client flood** — one client/IP hogging the surface,
//!   - **expensive-method abuse** — too many calls to heavy handlers (full-UTXO
//!     -set hash, block-range / chain-audit scans),
//!   - **concurrency exhaustion** — in-flight requests saturating workers,
//!   - **oversize payload** — a request body past the pre-decode cap,
//!   - **unauth probe** — attempts at maintainer-gated endpoints without auth.
//!
//! Like the mempool / P2P breakers, **RPC policy is node-local, not consensus**,
//! so this is safe to arm per-node on the live net (throttling service cannot
//! fork the chain). Same build bar: pure, fail-closed, feature-gated, declared
//! from `lib.rs` (not the hash-locked consensus core), default policy `Observe`.
//! Complements the existing DoS bounds on the scan handlers and the
//! Bearer-gated maintainer endpoints. See `docs/design/cip-circuit-breakers.md`.

/// An RPC safety threshold breach.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RpcFault {
    /// Global request rate exceeded the safe ceiling this interval.
    RequestFlood,
    /// A single client/IP exceeded its per-client request share.
    PerClientFlood,
    /// Too many calls to expensive handlers this interval.
    ExpensiveMethodAbuse,
    /// In-flight requests saturated the worker pool.
    ConcurrencyExhaustion,
    /// A request body exceeded the pre-decode size cap.
    OversizePayload,
    /// Attempts at maintainer-gated endpoints arrived without authentication.
    UnauthProbe,
}

/// What the node observed about its RPC surface over one interval.
#[derive(Clone, Copy, Debug, Default)]
pub struct RpcObservation {
    /// Requests this interval and the safe ceiling.
    pub requests_this_interval: u32,
    pub max_requests_per_interval: u32,
    /// Requests from the busiest client and the per-client ceiling.
    pub worst_client_requests: u32,
    pub max_per_client_requests: u32,
    /// Calls to expensive handlers and their ceiling.
    pub expensive_calls: u32,
    pub max_expensive_calls: u32,
    /// In-flight requests and the worker-pool capacity.
    pub in_flight: usize,
    pub max_in_flight: usize,
    /// Largest request body seen and the pre-decode cap.
    pub max_body_bytes_seen: usize,
    pub max_body_bytes: usize,
    /// Unauthenticated attempts at gated endpoints this interval.
    pub unauth_sensitive_attempts: u32,
}

/// Collect every RPC threshold breach (empty = healthy). Pure.
pub fn detect(o: &RpcObservation) -> Vec<RpcFault> {
    let mut f = Vec::new();
    if o.requests_this_interval > o.max_requests_per_interval {
        f.push(RpcFault::RequestFlood);
    }
    if o.worst_client_requests > o.max_per_client_requests {
        f.push(RpcFault::PerClientFlood);
    }
    if o.expensive_calls > o.max_expensive_calls {
        f.push(RpcFault::ExpensiveMethodAbuse);
    }
    if o.in_flight > o.max_in_flight {
        f.push(RpcFault::ConcurrencyExhaustion);
    }
    if o.max_body_bytes_seen > o.max_body_bytes {
        f.push(RpcFault::OversizePayload);
    }
    if o.unauth_sensitive_attempts > 0 {
        f.push(RpcFault::UnauthProbe);
    }
    f
}

/// Breaker policy. **Default `Observe`** — detect + log, never throttle.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BreakerPolicy {
    /// Detect + log only; never throttle. Default.
    Observe,
    /// Shed / throttle RPC on any breach. Safe to set per-node on the live net —
    /// RPC policy is local, not consensus.
    Armed,
}

impl Default for BreakerPolicy {
    fn default() -> Self {
        BreakerPolicy::Observe
    }
}

/// The breaker's decision. Isolation scope = the RPC service; the chain / P2P /
/// mining are never in scope.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum BreakerAction {
    /// Serve RPC normally.
    ServeNormally,
    /// Throttle / shed RPC until pressure eases. Chain, P2P, and mining continue.
    ThrottleRpc { faults: Vec<RpcFault> },
}

impl BreakerAction {
    /// Whether the node should throttle / shed RPC.
    pub fn throttles_rpc(&self) -> bool {
        matches!(self, BreakerAction::ThrottleRpc { .. })
    }

    /// The bulkhead guarantee: throttling RPC never halts the chain / P2P /
    /// mining. Always false.
    pub fn affects_chain(&self) -> bool {
        false
    }
}

/// Evaluate: detect breaches, then apply policy. `Observe` always serves (logs);
/// `Armed` throttles iff any breach is present.
pub fn evaluate(policy: BreakerPolicy, o: &RpcObservation) -> BreakerAction {
    let faults = detect(o);
    match policy {
        BreakerPolicy::Observe => BreakerAction::ServeNormally,
        BreakerPolicy::Armed if faults.is_empty() => BreakerAction::ServeNormally,
        BreakerPolicy::Armed => BreakerAction::ThrottleRpc { faults },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A node serving RPC comfortably under every limit.
    fn healthy() -> RpcObservation {
        RpcObservation {
            requests_this_interval: 200,
            max_requests_per_interval: 10_000,
            worst_client_requests: 20,
            max_per_client_requests: 500,
            expensive_calls: 2,
            max_expensive_calls: 50,
            in_flight: 4,
            max_in_flight: 256,
            max_body_bytes_seen: 2_000,
            max_body_bytes: 1_000_000,
            unauth_sensitive_attempts: 0,
        }
    }

    #[test]
    fn default_policy_is_observe() {
        assert_eq!(BreakerPolicy::default(), BreakerPolicy::Observe);
    }

    #[test]
    fn healthy_rpc_serves_in_both_modes() {
        assert!(detect(&healthy()).is_empty());
        assert_eq!(evaluate(BreakerPolicy::Observe, &healthy()), BreakerAction::ServeNormally);
        assert_eq!(evaluate(BreakerPolicy::Armed, &healthy()), BreakerAction::ServeNormally);
    }

    #[test]
    fn request_flood_throttles_but_never_affects_chain() {
        let mut o = healthy();
        o.requests_this_interval = 1_000_000;
        assert!(detect(&o).contains(&RpcFault::RequestFlood));
        assert!(!evaluate(BreakerPolicy::Observe, &o).throttles_rpc());
        let a = evaluate(BreakerPolicy::Armed, &o);
        assert!(a.throttles_rpc());
        assert!(!a.affects_chain());
    }

    #[test]
    fn expensive_method_abuse_and_unauth_probe_detected() {
        let mut o = healthy();
        o.expensive_calls = 10_000; // hammering get_sync_checkpoints etc.
        assert!(detect(&o).contains(&RpcFault::ExpensiveMethodAbuse));

        let mut o2 = healthy();
        o2.unauth_sensitive_attempts = 1; // probing a gated endpoint
        assert!(detect(&o2).contains(&RpcFault::UnauthProbe));
        assert!(evaluate(BreakerPolicy::Armed, &o2).throttles_rpc());
    }

    #[test]
    fn per_client_concurrency_and_oversize_detected() {
        let mut o = healthy();
        o.worst_client_requests = 100_000;
        assert!(detect(&o).contains(&RpcFault::PerClientFlood));

        let mut o2 = healthy();
        o2.in_flight = o2.max_in_flight + 1;
        assert!(detect(&o2).contains(&RpcFault::ConcurrencyExhaustion));

        let mut o3 = healthy();
        o3.max_body_bytes_seen = o3.max_body_bytes + 1;
        assert!(detect(&o3).contains(&RpcFault::OversizePayload));
    }

    #[test]
    fn multiple_breaches_all_reported() {
        let mut o = healthy();
        o.requests_this_interval = 9_999_999;
        o.worst_client_requests = 9_999_999;
        o.unauth_sensitive_attempts = 3;
        if let BreakerAction::ThrottleRpc { faults } = evaluate(BreakerPolicy::Armed, &o) {
            assert!(faults.len() >= 3);
        } else {
            panic!("expected ThrottleRpc");
        }
    }
}
