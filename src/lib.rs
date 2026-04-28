// src/lib.rs
#![allow(unsafe_code)]
#![allow(clippy::all)]
#![doc = "CoinCync 1.0 — compliant privacy cryptocurrency with CPU-only proof of work."]

// ── Foundation ──────────────────────────────────────────────
pub mod constants;
pub mod error;
pub mod config;
pub mod helpers;
pub mod build_info;
pub mod prelude;

// ── Primitives + types ──────────────────────────────────────
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
pub mod storage;
pub mod db;

// ── Network + mining ────────────────────────────────────────
pub mod network;
pub mod mining;

// ── RPC + CLI ───────────────────────────────────────────────
pub mod rpc;
pub mod cli;

// ── Network genesis definitions ─────────────────────────────
pub mod testnet;
pub mod mainnet;

// ── Re-exports ──────────────────────────────────────────────
pub use error::{Error, Result};
pub use config::{Network, NodeConfig};

/// Crate version string, used in P2P `user_agent` and diagnostics.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
