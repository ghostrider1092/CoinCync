//! Firework — lightweight P2P capability negotiation.
//!
//! Right after the Version/Verack handshake, each peer sends a `Flare`
//! message ([`crate::network::protocol::FlareMessage`]) carrying a `u64`
//! bitfield of the optional features it supports. The received bitfield is
//! stored in [`crate::network::peer::PeerInfo::capabilities`] and queried
//! with [`has_cap`].
//!
//! ## Forward/backward compatibility
//!
//! Capabilities are ADVISORY and OPTIONAL. Two invariants keep this safe to
//! evolve without flag-day upgrades:
//!
//! 1. **Unknown bits are ignored.** A peer may advertise bits we don't
//!    recognize; we only ever test the specific bits we care about via
//!    [`has_cap`]. New capabilities can be added over time.
//! 2. **A missing Flare means zero capabilities.** A peer that never sends a
//!    Flare (an older node from before the capability layer was
//!    reintroduced, or an external implementation) has `capabilities == 0`,
//!    and every feature gated on a capability bit falls back to its
//!    pre-capability behavior for that peer. Nothing disconnects for lack of
//!    a Flare.
//!
//! Flare was part of the original "Firework" convergence engine, trimmed for
//! the 1.0 snapshot; the `peer.capabilities` field and the `Flare = 50`
//! message discriminant survived. This module reintroduces the negotiation
//! as the foundation for Phase 2 total-difficulty sync trust
//! (see docs/architecture/sync-total-difficulty-trust-design.md).

/// Peer advertises its cumulative chain work via the `ChainWork` message
/// (Phase 2 total-difficulty sync trust). A peer with this capability lets
/// us recognize a heavier chain even when that chain is shorter in height —
/// closing the higher-block/lower-work private-fork trap that height-only
/// sync cannot recover from.
pub const CAP_CHAINWORK: u64 = 1 << 0;

/// The capability set THIS node supports and advertises in its Flare.
///
/// `const` so it is a single source of truth; extend the OR-set as new
/// capability bits are added.
pub const fn local_capabilities() -> u64 {
    CAP_CHAINWORK
}

/// True if `caps` advertises every bit set in `cap`.
///
/// `cap` is normally a single `CAP_*` constant, but testing a combined mask
/// (all bits required) is also supported.
#[inline]
pub fn has_cap(caps: u64, cap: u64) -> bool {
    caps & cap == cap
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn local_node_advertises_chainwork() {
        assert!(has_cap(local_capabilities(), CAP_CHAINWORK));
    }

    #[test]
    fn zero_capabilities_supports_nothing() {
        // The backward-compat contract: a peer that never sent a Flare
        // (capabilities == 0) must report support for no feature.
        assert!(!has_cap(0, CAP_CHAINWORK));
    }

    #[test]
    fn unknown_bits_do_not_affect_known_queries() {
        // A peer advertising future/unknown bits alongside a known one is
        // still correctly seen as supporting the known capability.
        let caps = CAP_CHAINWORK | (1 << 40) | (1 << 63);
        assert!(has_cap(caps, CAP_CHAINWORK));
        // And a peer advertising only unknown bits supports no known cap.
        assert!(!has_cap((1 << 40) | (1 << 63), CAP_CHAINWORK));
    }
}
