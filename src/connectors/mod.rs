//! # The Manifold — CoinCync's connector catalog
//!
//! Connectors are CoinCync's upgrade seam: a new behavior is built as a named,
//! swappable **valve** mounted on the Manifold, with the tuned/locked core given
//! only a tiny fail-safe call into it — never surgery on the heart of the code.
//! The Manifold is the single place every connector is *named and catalogued*,
//! so the family is enumerable, discoverable, and audit-legible regardless of
//! which domain module implements each one.
//!
//! This catalog is deliberately **pure metadata** (`&'static` specs), not a
//! runtime dispatch table: a connector's live code lives in its own domain
//! module (and typed registries like [`crate::crypto::connector_registry`] do
//! the runtime swap for their family), but all of them *register their name
//! here* so there is one index of the whole set. A connector module asserts its
//! own `CONNECTOR_NAME` matches its Manifold entry (see the Baffle test), so the
//! catalog cannot silently drift from the code.
//!
//! ## Invariant: fail-safe by default
//! Every `Active`/`Gated` connector's DEFAULT policy reproduces the historical
//! behavior, so cataloguing/enabling/rolling-back a connector can never regress
//! what already works. `Reserved` entries are named-but-unimplemented.

/// Which layer a connector mounts on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Domain {
    /// P2P / relay / Dandelion++ (network-layer privacy & behavior).
    Network,
    /// Shielded (Spark) consensus admission & verification.
    Shielded,
    /// PoW / mining engine.
    Mining,
}

/// Lifecycle of a catalogued connector.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Status {
    /// Wired and selectable; default policy preserves historical behavior.
    Active,
    /// Implemented but opt-in / gated off by default (fail-safe until enabled).
    Gated,
    /// Named and reserved on the Manifold; not yet implemented.
    Reserved,
}

/// A catalogued connector (a valve on the Manifold).
#[derive(Debug, Clone, Copy)]
pub struct Connector {
    /// Mechanical/valve name — the id used to refer to this connector.
    pub name: &'static str,
    pub domain: Domain,
    pub status: Status,
    /// The swappable interface type path (for humans & audit).
    pub interface: &'static str,
    /// What the fail-safe default does when nothing is swapped in.
    pub default_behavior: &'static str,
    pub summary: &'static str,
}

/// The catalog. Valve-themed names; the Manifold is the block they mount on.
pub const MANIFOLD: &[Connector] = &[
    Connector {
        name: "Baffle",
        domain: Domain::Network,
        status: Status::Gated,
        interface: "network::dandelion_connector::PrivacyPolicy",
        default_behavior: "Fixed(3): historical strict privacy classification + unchanged stem timing",
        summary: "Size-aware Dandelion++ stem privacy signal + adaptive stem-embargo timing.",
    },
    Connector {
        name: "Sluicegate",
        domain: Domain::Shielded,
        status: Status::Gated,
        interface: "consensus::shielded_pipeline::SpendVerifier + crypto::connector_registry",
        default_behavior: "FailClosedVerifier / stub engine: rejects every shielded spend",
        summary: "Shielded spend admission — which Spark spend proof the chain accepts.",
    },
    Connector {
        name: "Bleeder",
        domain: Domain::Network,
        status: Status::Reserved,
        interface: "(reserved) Baffle cover-traffic extension",
        default_behavior: "off: no cover traffic",
        summary: "Metered dummy stem traffic for small-network sender privacy (step-2b).",
    },
    Connector {
        name: "Gauge",
        domain: Domain::Mining,
        status: Status::Reserved,
        interface: "consensus::pow::recheck_dataset_after_rejection (#235 self-check)",
        default_behavior: "n/a (a probe, not a swappable policy)",
        summary: "RandomX full-mem dataset self-check vs an independent light build.",
    },
];

/// Look up a connector by its Manifold name.
pub fn get(name: &str) -> Option<&'static Connector> {
    MANIFOLD.iter().find(|c| c.name == name)
}

/// All catalogued connector names (declaration order).
pub fn names() -> impl Iterator<Item = &'static str> {
    MANIFOLD.iter().map(|c| c.name)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn manifold_names_are_unique_and_lookups_resolve() {
        let mut seen = std::collections::HashSet::new();
        for c in MANIFOLD {
            assert!(seen.insert(c.name), "duplicate connector name: {}", c.name);
            assert!(!c.name.is_empty());
            assert_eq!(get(c.name).map(|g| g.name), Some(c.name));
        }
        assert!(get("nope").is_none());
    }

    #[test]
    fn baffle_is_catalogued_as_a_gated_network_connector() {
        let b = get("Baffle").expect("Baffle must be on the Manifold");
        assert_eq!(b.domain, Domain::Network);
        assert_eq!(b.status, Status::Gated);
    }
}
