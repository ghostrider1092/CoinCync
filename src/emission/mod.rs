//! # Emission Module for CoinCync
//!
//! Asymptotic emission curve; 100M CYNC is the asymptote (soft target), NOT a hard cap:
//!     reward = max(0.6 CYNC, (100M - already_mined) / 2,000,000)
//!
//! No eras. No halvings. Smooth decay from 50 CYNC to 0.6 CYNC tail.
//! With 30% fee burn, the chain becomes deflationary when fees exceed
//! ~2 CYNC/block.
//!
//! ## Audit map
//! Each `§` is a code section below; it states the INVARIANT it guarantees, the
//! THREAT it defends, and the TESTS that prove it. (Renders in `cargo doc`.)
//! This module has no in-file `#[cfg(test)]`; TESTS cite the integration suites
//! that cover the re-exported surface.
//!
//! - **§1 Public re-export surface** — INVARIANT: the emission API exposed to the
//!   rest of the crate is exactly `curve::{base_reward, base_reward_from_supply,
//!   block_reward, emission_phase, EmissionPhase}` and `supply::{
//!   calculate_supply_commitment, SupplyStats}`; the `kani_proofs` sibling is
//!   `cfg(kani)`-only so proof harnesses never touch the lockfile-locked
//!   `curve.rs`. THREAT: an unintended symbol or a proof-harness edit disturbing
//!   the consensus-hash-locked curve module. TESTS: see `curve.rs` §1–§6 and
//!   `supply.rs` §1–§4 for the re-exported items.
//! - **§2 `calculate_block_reward`** — INVARIANT: the height→`Amount` subsidy
//!   accessor delegates to `curve::base_reward(height)` and returns bit-identical
//!   results (thin inline wrapper); consensus-critical paths use
//!   `base_reward_from_supply` with real chain state instead. THREAT: the block
//!   template / explorer helper drifting from the canonical reward curve.
//!   TESTS: `tests/consensus_edges.rs::emission_reward_approaches_tail`,
//!   `tests/phase1_critical.rs::genesis_reward_correct`,
//!   `tests/phase1_critical.rs::supply_cap_correct`, and the
//!   `tests/emission_reference_oracle.rs` spec-formula suite.

pub mod curve;
pub mod supply;

// Kani proof harnesses. Compiled only when targeting kani (cfg(kani)).
// Lives in a sibling file so changes don't touch the lockfile-locked
// curve.rs. See docs/security/KANI_SETUP.md.
#[cfg(kani)]
mod kani_proofs;

pub use curve::{
    base_reward, base_reward_from_supply, block_reward, emission_phase, EmissionPhase,
};
pub use supply::{calculate_supply_commitment, SupplyStats};

use crate::primitives::Amount;

/// Calculate the block subsidy at a given height as an `Amount`.
/// Uses height-based supply estimation. For consensus-critical paths,
/// prefer `base_reward_from_supply()` with actual chain state.
#[inline]
pub fn calculate_block_reward(height: u64) -> Amount {
    curve::base_reward(height)
}
