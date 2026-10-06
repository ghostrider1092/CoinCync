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
//! release: `is_implemented()` returns `false`. Swap is reachable only via this
//! crate's own standalone `cyncswap` binary — the main `coincync` wallet has
//! **no `coincync-swap` dependency and no swap subcommand**, so there is no
//! wallet↔swap integration in the base build. (The `#[cfg(feature = "cyncswap")]`
//! gate exists in the *desktop wallet* `coincync-wallet-v2`, not in the core
//! wallet CLI.) Per the 2026-05-20 staged-mainnet decision, cyncswap ships as
//! **v1.1 after a dedicated audit**, not with the v1.0/2.0 base chain. Do not
//! flip the gate without that audit — the `is_implemented() == false` return is
//! the safety valve, not a statement that the code is missing.
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
//! - [`adaptor`] — adaptor-signature primitives shared by both sides.
//!                 **BTC-side primitives (BIP-340 Schnorr adaptors)
//!                 are real as of the 2026-05-17 slice — see the
//!                 module docs.** CYNC adaptor + cross-curve DL
//!                 proof are still stubs.
//! - [`btc`]      — Bitcoin-side: HTLC construction, broadcasting, watching (stub)
//! - [`cync`]     — CoinCync-side: tx construction with adaptor binding (stub)
//! - [`coordinator`] — peer-to-peer messaging skeleton between Alice / Bob (stub)
//! - [`error`]    — typed errors for the swap state machine
//!
//! The remaining stubbed functions return `Error::NotImplemented` with
//! a structured `stage` note. This keeps downstream type signatures
//! stable while the rest of the cryptography is built. Once all
//! `NotImplemented` returns have been replaced and the dual-testnet
//! smoke passes, [`is_implemented`] flips to `true`.

#![forbid(unsafe_code)]

pub mod adaptor;
pub mod btc;
pub mod coordinator;
pub mod cync;
pub mod error;
pub mod protocol;
pub mod state;

/// Strict-binding cross-curve DLEQ (Noether 2018). **Opt-in** via the
/// `strict-dleq` Cargo feature. The default fast-floor proof in
/// [`adaptor`] is operationally sufficient for the atomic-swap
/// protocol; the strict variant is here for audit-team-requested
/// cryptographic-level same-secret binding. See `Cargo.toml`'s
/// `[features]` section and `docs/cip/CIP-001-atomic-swap.md`
/// §"Pre-audit hardening" for the rationale.
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
