//! # CoinCync Phase-2 Orchard (skeleton)
//!
//! Halo2-based shielded pool — the **Action circuit** that proves
//! ownership and authorisation of shielded notes without revealing
//! them on-chain. CoinCync Phase-2 reuses Zcash Orchard's circuit
//! design near-verbatim because:
//!
//! 1. It is the most-audited zk-SNARK in production (Zcash NU5,
//!    May 2022; multiple multi-month audits by NCC Group, Trail of
//!    Bits, ECC, and Halborn).
//! 2. The Halo2 toolchain (recursive PLONK, Pasta curves, no
//!    trusted setup) sidesteps the trusted-setup ceremony burden
//!    of Groth16-based ZK chains.
//! 3. The `bridgetree` / `incrementalmerkletree` storage layer in
//!    [`coincync::storage::shielded`] already speaks the Orchard
//!    note-commitment-tree interface, so the crypto and storage
//!    sides meet at a stable boundary.
//!
//! ## Status: SKELETON
//!
//! Every public function in this crate returns
//! [`Error::NotImplemented`]. The crate exists so that:
//!
//! - Downstream code (wallet ZK send/receive, the consensus action
//!   verifier in `src/chain.rs`, the bridge in `crates/bridge/`)
//!   can be written against stable type signatures *now*.
//! - The Halo2 toolchain (heavy: ~50 transitive crates including
//!   `pasta_curves`, `ff`, `group`, `halo2_proofs`, `halo2_gadgets`)
//!   is **isolated to this workspace member** rather than polluting
//!   the main `coincync` binary's default dep graph. The node ships
//!   without Phase-2 until the activation hard fork lands.
//! - The eventual implementation has a load-bearing module layout
//!   to fill in stage-by-stage rather than reorganising everything.
//!
//! See [`is_implemented`] for the activation sentinel — wallets and
//! UI should gate Phase-2 features on it.
//!
//! ## Module layout
//!
//! - [`action`]       — Action statement + proof construction +
//!   verification (the Halo2 circuit itself).
//! - [`note`]         — Note structure (recipient, value, ρ, ψ
//!   randomness, memo placeholder).
//! - [`nullifier`]    — Nullifier derivation from note + nk.
//! - [`commitment`]   — Note commitment derivation (Sinsemilla).
//! - [`value_commit`] — Pedersen-style value commitments with
//!   homomorphic add for balance proofs.
//! - [`spend_key`]    — Hierarchical key derivation: spending key
//!   → spending validating key → full viewing
//!   key → incoming viewing key → diversified
//!   address.
//! - [`proof`]        — Halo2 proof envelope + (de)serialization.
//!
//! ## What this crate does NOT own
//!
//! - **Note commitment Merkle tree.** Lives in
//!   `src/storage/shielded.rs` (already shipped, dormant — the
//!   storage rewrite that paired with the activation prep landed
//!   in commit `ef4f48c`). This crate consumes anchors from there
//!   via opaque [`bridge::BridgeCommitment`].
//! - **Consensus integration.** The action verifier will be called
//!   from `src/chain.rs` once the activation height is set in
//!   `src/constants.rs`. This crate exposes the *function* to
//!   call; chain.rs does the calling.
//! - **Wallet integration.** The Tauri wallet's shielded send /
//!   receive UI is a separate workstream that consumes this
//!   crate's types.
//!
//! ## Reference
//!
//! [Zcash Protocol Spec §4.7 (Orchard)](https://zips.z.cash/protocol/protocol.pdf)
//! and the `orchard` Rust crate (zcash/orchard on GitHub) are the
//! direct technical references. Where this crate's API diverges
//! from the orchard crate it is documented per-function.

#![forbid(unsafe_code)]

pub mod action;
pub mod binding_sig;
pub mod commitment;
pub mod error;
pub mod note;
pub mod nullifier;
pub mod proof;
pub mod spend_key;
pub mod value_commit;

pub use error::Error;

/// Result alias used throughout the crate.
pub type Result<T> = std::result::Result<T, Error>;

/// Crate-level activation sentinel. Returns `false` until the Halo2
/// Action circuit is implemented and audited. The wallet should gate
/// Phase-2 features on this; today the only legal use is to display
/// "Shielded transactions: coming in v2.0" rather than offering an
/// operation that returns [`Error::NotImplemented`].
///
/// **Non-circuit primitive set is byte-for-byte conformant with
/// Zcash NU5** as of 2026-05-18 — see
/// `tests/zcash_conformance.rs` (6 tests, 60 byte-equality
/// assertions against the 10 vendored `zcash-hackworks/zcash-test-vectors`
/// key-component vectors). Circuit constraint roadmap Steps 2-8 are
/// the gating work for flipping this sentinel to `true`.
pub const fn is_implemented() -> bool {
    false
}

/// Marker constant: how many shielded actions are permitted per
/// transaction. Mirrors Zcash Orchard's `MaxActionsPerTransaction`
/// constant (currently uncapped in the spec but in practice limited
/// by block size). Concrete value lands with the chain-format hard
/// fork; today it's a sentinel so callers can structure their loops.
pub const MAX_ACTIONS_PER_TX: usize = 64;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn skeleton_advertises_unimplemented_status() {
        assert!(
            !is_implemented(),
            "is_implemented() must remain false until the Halo2 Action circuit \
             is implemented and audited"
        );
    }

    // Intentional tripwire on a compile-time constant: if MAX_ACTIONS_PER_TX is
    // ever fat-fingered out of range, `>= 2` / `<= 1024` turns const-false and
    // this test fails. clippy flags const asserts as no-ops, which is expected.
    #[allow(clippy::assertions_on_constants)]
    #[test]
    fn max_actions_per_tx_is_sane() {
        // The exact ceiling will be tuned with block-size budgeting,
        // but a value of 0 or absurdly large is wrong. This is a
        // tripwire so future PRs that fat-finger the constant get
        // caught by CI.
        assert!(
            MAX_ACTIONS_PER_TX >= 2,
            "must permit at least spend + dummy"
        );
        assert!(
            MAX_ACTIONS_PER_TX <= 1024,
            "absurdly large = block-budget bug"
        );
    }
}
