//! # Emission Module for CoinCync
//!
//! Asymptotic emission curve with 100M CYNC supply cap:
//!     reward = max(0.6 CYNC, (100M - already_mined) / 2,000,000)
//!
//! No eras. No halvings. Smooth decay from 50 CYNC to 0.6 CYNC tail.
//! With 30% fee burn, the chain becomes deflationary when fees exceed
//! ~2 CYNC/block.

pub mod curve;
pub mod supply;

pub use curve::{base_reward, base_reward_from_supply, block_reward, emission_phase, EmissionPhase};
pub use supply::{SupplyStats, calculate_supply_commitment};

use crate::primitives::Amount;

/// Calculate the block subsidy at a given height as an `Amount`.
/// Uses height-based supply estimation. For consensus-critical paths,
/// prefer `base_reward_from_supply()` with actual chain state.
#[inline]
pub fn calculate_block_reward(height: u64) -> Amount {
    curve::base_reward(height)
}
