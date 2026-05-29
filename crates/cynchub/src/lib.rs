//! # CyncHub — merge-mined PoW liquidity layer (skeleton)
//!
//! Trustless on-chain order book for **CYNC↔BTC** swaps, secured by the
//! CoinCync mining set via merge-mining (no separate hashrate, no
//! cold-start). Settlement uses the [`coincync_swap`] adaptor-signature
//! primitive directly — CyncHub never holds user funds.
//!
//! ## Status: SKELETON
//!
//! This crate is **not** a working chain. It is the module structure,
//! type signatures, error variants, and CLI surface that the eventual
//! implementation will fill in. Calling any operation here today
//! returns [`Error::NotImplemented`] — the public surface exists so
//! downstream code (CIP work, fuzz targets, doc examples) can be
//! written against stable types while the consensus + orderbook are
//! implemented in stages.
//!
//! ## Protocol reference
//!
//! See [`docs/cip/CIP-002-cynchub-merge-mined-liquidity-layer.md`](../../../docs/cip/CIP-002-cynchub-merge-mined-liquidity-layer.md)
//! for the full design specification. In one paragraph: a separate
//! proof-of-work blockchain merge-mined with CoinCync, hosting an on-chain
//! order book for trustless cross-chain trades. Every trade settles via
//! HTLCs (on Bitcoin) and adaptor-signature-bound stealth-address
//! transactions (on CYNC). CyncHub coordinates orders and witnesses
//! matches; it never holds, signs for, or has keys to user funds.
//!
//! ## Why this exists in v1.0 (post-mainnet phase-2)
//!
//! CIP-001 atomic swaps give every CYNC holder a trustless P2P swap
//! primitive, but they require finding a counterparty off-chain. CyncHub
//! fills that gap with an on-chain order book secured by the same
//! hashrate. The chain has no native token: fees are paid in the assets
//! being traded (CYNC + BTC); 100% goes to the matching miner. The
//! Constitution's no-federation, no-admin, no-governance-token posture
//! extends naturally — there is nothing for a future maintainer to
//! "improve" into an algorithmic-capture surface.
//!
//! ## Module layout
//!
//! - [`consensus`] — chain consensus: block, header, PoW validation,
//!                   difficulty retargeting, merge-mining commitment.
//! - [`tx`]        — the five V1 transaction types (`LockBtc`, `LockCync`,
//!                   `Order`, `Match`, `Cancel`).
//! - [`orderbook`] — CLOB state machine, price-time priority matching.
//! - [`mergemining`] — Namecoin-style auxiliary-PoW commitment parsing
//!                     + validation against CYNC coinbase.
//! - [`spv`]       — Bitcoin SPV light-client + CYNC SPV light-client
//!                   traits used by `LockBtc` / `LockCync` validation.
//! - [`error`]     — typed errors for the consensus + orderbook surfaces.
//!
//! Every stubbed function returns [`Error::NotImplemented`] with a
//! structured `stage` note identifying which CIP-002 component it would
//! belong to once shipped. This keeps downstream type signatures stable
//! while the rest of the implementation lands in slices. Once all
//! `NotImplemented` returns have been replaced and the dual-testnet
//! smoke passes, [`is_implemented`] flips to `true`.

#![forbid(unsafe_code)]

pub mod consensus;
pub mod error;
pub mod mergemining;
pub mod orderbook;
pub mod spv;
pub mod tx;

pub use error::Error;

/// Result alias used throughout the crate.
pub type Result<T> = std::result::Result<T, Error>;

/// Crate-level status sentinel. Returns `false` until the protocol
/// implementation is complete and audited. Downstream callers (wallet
/// "Trade" tab, fuzz targets, integration tests) should gate
/// user-facing features on this; CyncHub UI should display "Coming
/// soon" rather than offering trades that return `NotImplemented`
/// errors.
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
            "is_implemented() must remain false until CIP-002 V1 is fully shipped + audited"
        );
    }
}
