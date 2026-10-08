//! # Connector registry (Warren Phase 0 — §3.4 Burrow / §3.7)
//!
//! Generalizes the single `backend()` swap point in
//! `src/consensus/shielded_connector.rs` so multiple privacy-verify engines
//! register under a name and are selected / swapped cleanly: the fail-closed
//! [`StubBackend`] always, the libspark FFI engine today, a future recursive
//! prover (Warren Phase 2) later — each a `SparkBackend` implementation that
//! slots in without touching call sites.
//!
//! ## Fail-closed, by construction
//! * Resolving an **unregistered** engine id yields the `StubBackend` — every
//!   op errors `NotWired`, never a silent accept.
//! * [`select`](ConnectorRegistry::select) refuses an id that is not registered
//!   (returns `false`, active unchanged), so the active engine is always one
//!   that was explicitly registered — you cannot "swap to" a missing backend.
//! * A fresh registry's active engine is the stub. On a platform without
//!   `libspark-ffi`, [`with_platform_default`](ConnectorRegistry::with_platform_default)
//!   leaves it the stub — identical to the old compile-time `backend()` choice.
//!
//! A mis-wired or missing engine can therefore only make the shielded path
//! REJECT, never accept — the same guarantee the hard-coded swap point gave,
//! now as swappable data.
//!
//! ## Status
//! Phase-0 scaffold, non-gated. NOT yet wired into `shielded_connector::backend`
//! (that stays the compile-time swap today); this is the seam a runtime-swap
//! migration drops into. Lives in `crypto::` with the other Warren Phase-0
//! sketches; its eventual home is the consensus connector layer.

use std::collections::HashMap;
use std::sync::Arc;

use spark_connector::{SparkBackend, StubBackend};

/// Canonical engine ids.
pub const ENGINE_STUB: &str = "stub";
pub const ENGINE_LIBSPARK: &str = "libspark";

/// A shareable, thread-safe privacy-verify engine behind the connector.
pub type SharedBackend = Arc<dyn SparkBackend + Send + Sync>;

/// Registry of named privacy-verify engines with a selected "active" one.
pub struct ConnectorRegistry {
    engines: HashMap<String, SharedBackend>,
    /// Id of the active engine. Always either [`ENGINE_STUB`] or an id present
    /// in `engines` (enforced by [`select`](Self::select)).
    active: String,
    /// The fail-closed fallback, returned for any unregistered id.
    stub: SharedBackend,
}

impl ConnectorRegistry {
    /// A fresh registry: only the fail-closed stub, which is also the active
    /// engine. Nothing can be accepted until a real engine is registered AND
    /// selected.
    pub fn new() -> Self {
        Self {
            engines: HashMap::new(),
            active: ENGINE_STUB.to_string(),
            stub: Arc::new(StubBackend),
        }
    }

    /// The platform default, mirroring the old compile-time `backend()`:
    /// with `libspark-ffi`, register + select the libspark engine; otherwise
    /// stay on the fail-closed stub.
    pub fn with_platform_default() -> Self {
        // `mut` is used only when the libspark branch below compiles in.
        #[cfg_attr(not(feature = "libspark-ffi"), allow(unused_mut))]
        let mut r = Self::new();
        #[cfg(feature = "libspark-ffi")]
        {
            r.register(ENGINE_LIBSPARK, Arc::new(spark_connector::ffi::LibsparkBackend));
            let _ = r.select(ENGINE_LIBSPARK);
        }
        r
    }

    /// Register (or replace) an engine under `id`.
    pub fn register(&mut self, id: impl Into<String>, backend: SharedBackend) {
        self.engines.insert(id.into(), backend);
    }

    /// Whether an engine is registered under `id`.
    pub fn is_registered(&self, id: &str) -> bool {
        self.engines.contains_key(id)
    }

    /// Registered engine ids, sorted (deterministic for display/tests). The stub
    /// fallback is implicit and not listed unless explicitly registered.
    pub fn engine_ids(&self) -> Vec<String> {
        let mut ids: Vec<String> = self.engines.keys().cloned().collect();
        ids.sort();
        ids
    }

    /// Make `id` the active engine. Fail-closed: refuses (returns `false`,
    /// leaves the active engine unchanged) if `id` is not registered — you
    /// cannot select a backend that was never wired in. Selecting
    /// [`ENGINE_STUB`] is always allowed (back to fail-closed).
    #[must_use]
    pub fn select(&mut self, id: &str) -> bool {
        if id == ENGINE_STUB {
            self.active = ENGINE_STUB.to_string();
            return true;
        }
        if self.engines.contains_key(id) {
            self.active = id.to_string();
            true
        } else {
            false
        }
    }

    /// The active engine's id.
    pub fn active_id(&self) -> &str {
        &self.active
    }

    /// Resolve an engine by id, falling back to the fail-closed stub for any
    /// unregistered id (never a silent accept).
    pub fn resolve(&self, id: &str) -> &(dyn SparkBackend + Send + Sync) {
        match self.engines.get(id) {
            Some(b) => b.as_ref(),
            None => self.stub.as_ref(),
        }
    }

    /// The active engine (the single swap point a migrated `backend()` returns).
    pub fn active(&self) -> &(dyn SparkBackend + Send + Sync) {
        self.resolve(&self.active)
    }
}

impl Default for ConnectorRegistry {
    fn default() -> Self {
        Self::with_platform_default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use spark_connector::{CoinBytes, IdentifiedCoin, Nullifier, Result, SpendBytes};

    /// A test double that ACCEPTS — distinguishable from the stub (which errors)
    /// so a test can prove `resolve`/`active` route to the registered instance.
    struct AcceptingBackend;
    impl SparkBackend for AcceptingBackend {
        fn create_output(&self, _a: &[u8], _v: u64, _m: &[u8]) -> Result<CoinBytes> {
            Ok(CoinBytes(vec![]))
        }
        fn build_spend(&self, _c: &[CoinBytes], _s: &[u8], _f: u64, _vb: i64) -> Result<SpendBytes> {
            Ok(SpendBytes(vec![]))
        }
        fn verify_spend(
            &self,
            _c: &[CoinBytes],
            _s: &SpendBytes,
            _f: u64,
            _vb: i64,
        ) -> Result<Vec<Nullifier>> {
            Ok(vec![])
        }
        fn identify(&self, _v: &[u8], _c: &CoinBytes, _ctx: &[u8]) -> Result<Option<IdentifiedCoin>> {
            Ok(None)
        }
    }

    fn rejects(b: &(dyn SparkBackend + Send + Sync)) -> bool {
        b.verify_spend(&[], &SpendBytes(vec![]), 0, 0).is_err()
    }

    #[test]
    fn fresh_registry_is_fail_closed_stub() {
        let r = ConnectorRegistry::new();
        assert_eq!(r.active_id(), ENGINE_STUB);
        assert!(rejects(r.active()), "fresh registry's active engine must reject");
        assert!(rejects(r.resolve("anything-unregistered")), "unknown id → stub → reject");
        assert!(r.engine_ids().is_empty());
    }

    #[test]
    fn register_and_swap_routes_to_the_registered_engine() {
        let mut r = ConnectorRegistry::new();
        r.register("accept", Arc::new(AcceptingBackend));
        assert!(r.is_registered("accept"));
        assert_eq!(r.engine_ids(), vec!["accept".to_string()]);

        // Resolving the registered id reaches the accepting backend...
        assert!(!rejects(r.resolve("accept")), "registered engine accepts");
        // ...but the active engine is still the stub until we select.
        assert!(rejects(r.active()), "active is still the fail-closed stub pre-select");

        assert!(r.select("accept"), "selecting a registered engine succeeds");
        assert_eq!(r.active_id(), "accept");
        assert!(!rejects(r.active()), "after swap, the active engine is the registered one");
    }

    #[test]
    fn cannot_select_an_unregistered_engine() {
        let mut r = ConnectorRegistry::new();
        r.register("accept", Arc::new(AcceptingBackend));
        assert!(r.select("accept"));
        assert!(!r.select("ghost"), "selecting an unregistered id is refused");
        assert_eq!(r.active_id(), "accept", "active unchanged after a refused select");
        // And we can always fall back to the stub explicitly.
        assert!(r.select(ENGINE_STUB));
        assert!(rejects(r.active()));
    }

    #[test]
    fn platform_default_without_libspark_is_the_stub() {
        let r = ConnectorRegistry::with_platform_default();
        #[cfg(not(feature = "libspark-ffi"))]
        {
            assert_eq!(r.active_id(), ENGINE_STUB);
            assert!(rejects(r.active()), "no libspark feature → fail-closed stub active");
        }
        #[cfg(feature = "libspark-ffi")]
        {
            assert_eq!(r.active_id(), ENGINE_LIBSPARK);
            assert!(r.is_registered(ENGINE_LIBSPARK));
        }
    }
}
