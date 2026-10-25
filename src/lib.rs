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
//
// Bumped 1024 -> 8192: enabling the bulletproofs/halo2-heavy sketch features
// (`sketch-lelantus-spark`, `sketch-gk-proof`, and combinations) re-triggers the
// same `&'v Simd: Add` overflow at a deeper type-recursion depth. 8192 covers
// every current feature combination; it is a compile-time-only limit with no
// runtime or consensus effect.
#![recursion_limit = "8192"]
#![doc = "CoinCync 1.0 — compliant privacy cryptocurrency with CPU-only proof of work."]

// CoinCync's proof of work is RandomX-only by design: the non-`randomx` PoW
// path in src/consensus/pow.rs deliberately returns an error at runtime, so a
// node built without `randomx` can neither mine nor validate PoW. A no-`randomx`
// build also cannot even compile — it re-triggers the known tari_bulletproofs_plus
// 0.4 SIMD trait overflow (`error[E0275]: overflow evaluating for<'v> &'v Simd:
// Add`; see the recursion_limit note below and rust-toolchain). Fail fast here
// with an actionable message instead of that cryptic dependency error. Every
// supported build enables `randomx` (it is part of `default`, `testnet`, and
// `mainnet`).
#[cfg(not(feature = "randomx"))]
compile_error!(
    "CoinCync must be built with the `randomx` feature (included in the default, \
     `testnet`, and `mainnet` features). Proof of work is RandomX-only: a build \
     without it cannot mine or validate PoW and does not compile. Build with, \
     e.g., `cargo build --release --features testnet`."
);

// ── Foundation ──────────────────────────────────────────────
pub mod clock;
pub mod constants;
pub mod diagnostics;
pub mod error;

// Kani proof harnesses for top-level helpers in constants.rs.
// Compiled only under cfg(kani); see docs/security/KANI_SETUP.md.
pub mod build_info;
pub mod config;
pub mod helpers;
/// Boot-time self-preflight guards (compiled-network vs runtime `--network`,
/// data-dir network marker). Fail-fast, no consensus impact. See
/// `docs/design/self-preflight-boot-guard.md`.
pub mod preflight;
#[cfg(kani)]
mod kani_proofs;
pub mod prelude;

// ── Primitives + types ──────────────────────────────────────
pub mod decoy;
pub mod flight_recorder;
pub mod primitives;
pub mod rng;
pub mod transaction;

// ── Consensus + emission ────────────────────────────────────
pub mod consensus;
pub mod emission;

// ── Chain state ─────────────────────────────────────────────
pub mod chain;
pub mod mempool;
pub mod metrics;
/// Network-adjusted time (audit M-4) for the future-block timestamp cap, with
/// clock-poisoning defenses (per-netgroup dedup, sample-after-validate,
/// out-of-range→0). See `src/net_time.rs`.
pub mod net_time;
/// Portable, versioned chain-vitals health schema (`get_vitals`). Observability
/// only, no consensus impact. See `docs/design/chain-vitals-schema.md`.
pub mod vitals;

// ── Crypto + wallet ─────────────────────────────────────────
pub mod crypto;
pub mod wallet;

// ── Storage ─────────────────────────────────────────────────
pub mod db;
pub mod release;
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
pub mod compliance; // auditor-facing disclosure packages (compliant-privacy use case)
pub mod security; // chain-wide "security detail" pattern: guards + scan over attack surfaces

// ── Network genesis definitions ─────────────────────────────
pub mod mainnet;
pub mod testnet;

// ── Resilience / safety connectors ──────────────────────────
// The circuit-breaker suite + the universal fuse box + the Rung-2 state-root
// connector. Every one is a fail-closed, default-OFF policy slot declared HERE
// (never in the hash-locked consensus core), Observe-default, wired into the
// node only through thin feature-gated seams. See
// docs/design/cip-circuit-breakers.md + cip-fuse-box-resilience-standard.md.

// Rung-2 UTXO state-root commitment connector (feature `state-root-commit`):
// a fail-closed, default-OFF policy slot for committing/enforcing the UTXO state
// root. Inert until a planned post-audit activation. See cip-rung2-state-root.md.
#[cfg(feature = "state-root-commit")]
pub mod state_root_connector;

// Shielded-pool circuit breaker (feature `shielded-breaker`): isolates the Spark
// shielded pool on a safety-invariant violation. CONSENSUS surface — detection
// only until coordinated post-audit activation.
#[cfg(feature = "shielded-breaker")]
pub mod shielded_circuit_breaker;

// Supply / emission circuit breaker (feature `supply-breaker`): the monetary
// bulkhead against silent inflation. CONSENSUS surface — detection only.
#[cfg(feature = "supply-breaker")]
pub mod supply_breaker;

// Mempool DoS / load-shedding circuit breaker (feature `mempool-breaker`).
// Node-local policy (not consensus).
#[cfg(feature = "mempool-breaker")]
pub mod mempool_breaker;

// P2P / IBD circuit breaker (feature `p2p-breaker`). Node-local policy.
#[cfg(feature = "p2p-breaker")]
pub mod p2p_breaker;

// Reorg / finality circuit breaker (feature `reorg-breaker`). CONSENSUS surface —
// coordinated, activation-gated arming (aligns with CIP-011).
#[cfg(feature = "reorg-breaker")]
pub mod reorg_breaker;

// RPC DoS / service circuit breaker (feature `rpc-breaker`). Node-local policy.
#[cfg(feature = "rpc-breaker")]
pub mod rpc_breaker;

// Block-connect / apply integrity breaker (feature `block-integrity-breaker`):
// post-apply UTXO-set invariants. CONSENSUS surface — detection only.
#[cfg(feature = "block-integrity-breaker")]
pub mod block_integrity_breaker;

// Shared breaker recovery state machine (feature `breaker-recovery`): the
// three-state Closed/Open/Half-Open recovery with per-surface policy that
// composes with any breaker's pure detect().
#[cfg(feature = "breaker-recovery")]
pub mod breaker_recovery;

// The universal FUSE BOX: the one registry every breaker plugs into, keyed by
// surface; feed via `fuse::observe(surface, &FaultReport)`, one `snapshot()` for
// all compartments. Available whenever the recovery machine is; the `fuse`
// convenience feature turns on every breaker at once. Observe-only, gated OFF.
#[cfg(feature = "breaker-recovery")]
pub mod fuse;

// LIVE feed adapters — one thin feed point per surface at its real source, each
// routing through the universal fuse box. All Observe-mode, node-local, gated OFF.
#[cfg(all(feature = "mempool-breaker", feature = "breaker-recovery"))]
pub mod mempool_live_breaker;
#[cfg(all(feature = "p2p-breaker", feature = "breaker-recovery"))]
pub mod p2p_live_breaker;
#[cfg(all(feature = "block-integrity-breaker", feature = "breaker-recovery"))]
pub mod block_integrity_live_breaker;
#[cfg(all(feature = "reorg-breaker", feature = "breaker-recovery"))]
pub mod reorg_live_breaker;
#[cfg(all(feature = "rpc-breaker", feature = "breaker-recovery"))]
pub mod rpc_live_breaker;
#[cfg(all(feature = "supply-breaker", feature = "breaker-recovery"))]
pub mod supply_live_breaker;
#[cfg(all(feature = "shielded-breaker", feature = "breaker-recovery"))]
pub mod shielded_live_breaker;

// ── Re-exports ──────────────────────────────────────────────
pub use config::{Network, NodeConfig};
pub use error::{Error, Result};

/// Crate version string, used in P2P `user_agent` and diagnostics.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
