// src/lib.rs
#![allow(unsafe_code)]
#![allow(clippy::all)]
// Raised from the default 128 to accommodate nightly's stricter HRTB
// resolver evaluating the `for<'v> &'v Simd<_, _>: Add` chain in
// tari_bulletproofs_plus 0.4.1 (called from src/crypto/bulletproofs.rs
// at lines 470, 534, 576, 631). Stable 1.88 doesn't need this — but
// fuzz CI uses nightly (cargo-fuzz requires `-Zsanitizer=address`),
// and recent nightlies tightened HRTB inference enough to hit the
// default limit on this 126-deep `Value<Value<...>>` chain. Reproduces
// as `error[E0275]: overflow evaluating the requirement`; the compiler
// itself suggests this fix. Remove once tari_bulletproofs_plus 0.5+
// is adopted (blocked on utoipa-swagger-ui 9.0.2 compat).
#![recursion_limit = "1024"]
#![doc = "CoinCync 1.0 — compliant privacy cryptocurrency with CPU-only proof of work."]

// ── Foundation ──────────────────────────────────────────────
pub mod constants;
pub mod error;

// Kani proof harnesses for top-level helpers in constants.rs.
// Compiled only under cfg(kani); see docs/security/KANI_SETUP.md.
pub mod build_info;
pub mod config;
pub mod helpers;
#[cfg(kani)]
mod kani_proofs;
pub mod net_time;
pub mod prelude;

// ── Primitives + types ──────────────────────────────────────
pub mod decoy;
pub mod primitives;
pub mod transaction;

// ── Consensus + emission ────────────────────────────────────
pub mod consensus;
pub mod emission;

// ── Chain state ─────────────────────────────────────────────
pub mod chain;
pub mod mempool;
pub mod metrics;

// ── Crypto + wallet ─────────────────────────────────────────
pub mod crypto;
pub mod wallet;

// ── Storage ─────────────────────────────────────────────────
pub mod db;
pub mod snapshot;
pub mod storage;

// ── Network + mining ────────────────────────────────────────
pub mod mining;
pub mod network;

// ── RPC + CLI ───────────────────────────────────────────────
pub mod cli;
pub mod rpc;

// ── Runtime observability ───────────────────────────────────
pub mod runtime_watchdog;

// ── Tick sidecar adapter ────────────────────────────────────
// CoincyncAdapter — the `tick::ChainAdapter` bridge that lets the
// sidecar `coincync-tick` binary drive RescueTick / HealthTick /
// PropagationTick against a running coincync-node. Phase 1c ships
// the shell only; RPC integration lands in Phase 1d.
pub mod tick_adapter;

// ── Colony — biomimetic swarm agents ────────────────────────
// Advisory-only, non-consensus network-resilience agents hosted by the
// coincync-tick sidecar. Phase 1: forager in observe mode (scores peers on
// public block/tip signals; sends nothing). See docs/architecture/colony.md.
pub mod colony;

// ── Network genesis definitions ─────────────────────────────
pub mod mainnet;
pub mod testnet;

// ── Re-exports ──────────────────────────────────────────────
pub use config::{Network, NodeConfig};
pub use error::{Error, Result};

/// Crate version string, used in P2P `user_agent` and diagnostics.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
