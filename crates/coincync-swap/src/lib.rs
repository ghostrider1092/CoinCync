//! # CoinCync Atomic Swap
//!
//! Trustless cross-chain atomic swap between **CYNC** and **BTC**.
//!
//! ## Status: substantially implemented, GATED off pending audit
//!
//! This crate is NO LONGER a skeleton — the protocol is substantially
//! complete (~16.5k LOC: adaptor signatures on both curves, cross-curve
//! DLEQ binding, the BTC HTLC/CSV path, the Noise/Tor transport, and the
//! full state machine), with ~350 passing tests (`--features strict-dleq`)
//! and ~97% coverage. It is nonetheless **deliberately gated OFF** for this
//! release: `is_implemented()` returns `false` and the wallet's swap
//! commands sit behind `#[cfg(feature = "cyncswap")]`. Per the 2026-05-20
//! staged-mainnet decision, cyncswap ships as **v1.1 after a dedicated
//! audit**, not with the v1.0/2.0 base chain. Do not flip the gate without
//! that audit — the `is_implemented() == false` return is the safety valve,
//! not a statement that the code is missing.
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
//! ## Module layout
//!
//! - [`protocol`] — state machine + role types + transition rules
//! - [`adaptor`] — adaptor-signature primitives shared by both sides
//! - [`strict_dleq`] — mandatory same-secret cross-curve proof
//! - [`safety`]   — BTC-first two-path contract and verification capabilities
//! - [`btc`]      — Bitcoin RPC plus legacy diagnostic construction helpers
//! - [`cync`]     — CoinCync RPC and joint-key derivation
//! - [`coordinator`] — authenticated peer-to-peer negotiation transport
//! - [`error`]    — typed errors for the swap state machine
//!
//! Wallet-entangled CYNC construction lives behind the root crate's
//! `cyncswap` feature. The release sentinel remains false until the dedicated
//! audit and live dual-daemon exercise are complete.

#![forbid(unsafe_code)]

pub mod adaptor;
pub mod btc;
pub mod coordinator;
pub mod cync;
pub mod error;
pub mod protocol;
#[cfg(feature = "strict-dleq")]
pub mod safety;
pub mod state;

/// Strict-binding cross-curve DLEQ (Noether 2018). Enabled by default because
/// the pre-CYNC-lock safety gate must prove that each Bitcoin adaptor point
/// and CYNC spend share encode the same scalar.
#[cfg(feature = "strict-dleq")]
pub mod strict_dleq;

pub use error::Error;
pub use state::{StateError, SwapStore, STATE_VERSION};

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
        assert!(
            !is_implemented(),
            "is_implemented() must remain false until CIP-001 is fully shipped + audited"
        );
    }
}
