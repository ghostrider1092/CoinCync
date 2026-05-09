//! # CoinCync Atomic Swap (skeleton)
//!
//! Trustless cross-chain atomic swap between **CYNC** and **BTC**.
//!
//! ## Status: SKELETON
//!
//! This crate is **not** a working swap. It is the module structure,
//! type signatures, and CLI surface that the eventual protocol
//! implementation will fill in. Calling any operation here today
//! returns `Error::NotImplemented` — the public surface exists so
//! downstream code (wallet UI, CLI, tests, documentation) can be
//! written against stable types while the cryptographic protocol
//! is implemented in stages.
//!
//! ## Protocol reference
//!
//! See `docs/cip/CIP-001-atomic-swap.md` for the design specification.
//! In summary: an adaptor-signature-based protocol modeled on the
//! Comit / Farcaster XMR↔BTC swap (working in production since 2021,
//! ~2 years of focused implementation work). CYNC's CLSAG ring
//! signatures are similar enough to Monero's that the cryptographic
//! techniques transfer directly.
//!
//! ## Why this exists in v1.0 (testnet skeleton, mainnet hard
//! requirement)
//!
//! The Constitution forbids the compliance features (transaction
//! blacklists, Travel Rule hooks) that major US/EU exchanges demand
//! for listing — see `project_atomic_swap_mainnet_blocker.md` and
//! Articles VI, IX, XIV plus Right X. CYNC will end up in roughly
//! Monero's listing position: present on RoW + privacy-friendly
//! exchanges, delisted from Coinbase / Kraken-EU / Binance over
//! time. Atomic swaps are how the project compensates: once
//! CYNC↔BTC swaps work, every Bitcoin holder is one transaction
//! away from holding CYNC trustlessly, and major-CEX listings stop
//! being load-bearing for liquidity.
//!
//! ## Module layout (planned)
//!
//! - [`protocol`] — state machine + role types + transition rules
//! - [`adaptor`] — adaptor-signature primitives shared by both sides
//! - [`btc`]      — Bitcoin-side: HTLC construction, broadcasting, watching
//! - [`cync`]     — CoinCync-side: tx construction with adaptor binding
//! - [`coordinator`] — peer-to-peer messaging skeleton between Alice / Bob
//! - [`error`]    — typed errors for the swap state machine
//!
//! Today every module is a stub. Each function returns
//! `Error::NotImplemented` with a structured note about what the
//! eventual implementation will do. This keeps downstream type
//! signatures stable while the cryptography is still being built.

#![forbid(unsafe_code)]

pub mod adaptor;
pub mod btc;
pub mod coordinator;
pub mod cync;
pub mod error;
pub mod protocol;
pub mod state;

pub use error::Error;
pub use state::{SwapStore, StateError, STATE_VERSION};

/// Result alias used throughout the crate.
pub type Result<T> = std::result::Result<T, Error>;

/// Crate-level status sentinel. Returns `false` until the protocol
/// implementation is complete and audited. Downstream callers can
/// gate user-facing swap UI on this; the wallet should display
/// "Coming soon" rather than offering a swap that returns
/// `NotImplemented` errors.
pub const fn is_implemented() -> bool {
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn skeleton_advertises_unimplemented_status() {
        assert!(!is_implemented(),
            "is_implemented() must remain false until CIP-001 is fully shipped + audited");
    }
}
