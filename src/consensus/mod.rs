//! # Consensus Module for CoinCync 1.0
//!
//! RandomX-only Proof of Work consensus with:
//! - Single algorithm (RandomX)
//! - LWMA difficulty adjustment
//! - Halving emission curve

pub mod block;
pub mod header;
pub mod pow;
pub mod difficulty;
pub mod finality;
pub mod validation;
pub mod fee_market;
pub mod fork_signal;
pub mod privacy_policy;

// CIP-009.D rolling soft-finality adapter. Gated behind the
// off-by-default `rolling-finality` feature (see Cargo.toml). With
// the feature disabled this module is not compiled and node
// behaviour is byte-identical to a build without it. CIP-011 phase 3.
#[cfg(feature = "rolling-finality")]
pub mod rolling_finality;

// Kani proof harnesses for the pure consensus helpers used by
// validate_block / validate_transaction. Compiled only under
// cfg(kani); see docs/security/KANI_SETUP.md.
#[cfg(kani)]
mod kani_proofs;

pub use block::Block;
pub use header::BlockHeader;
pub use pow::{
    Anchor, PowAlgorithm,
    bind_randomx_genesis_for_network,
    compute_full_anchor, compute_pow_hash,
    verify_pow, meets_difficulty, work_from_target,
};
pub use difficulty::{
    calculate_difficulty, DifficultyAdjustment, DifficultyBlock,
    max_target, min_target, target_to_difficulty, estimate_hashrate,
};
// M-1: finality module is dead code; re-exports removed.
pub use validation::{
    validate_block, validate_block_with_checkpoint, validate_block_with_checkpoint_for_network,
    validate_transaction, validate_transaction_basic,
    BlockValidation,
};
pub(crate) use validation::{verify_output_range_proofs, verify_balance_proof, verify_ring_signature};

// Re-export Transaction from transaction module so old imports that say
// `use crate::consensus::Transaction` continue to work.
pub use crate::transaction::Transaction;

pub use fee_market::{
    FeeTier, FeeContext, FeeEstimate, FeeCalculator,
    FeeDistribution, FeeDistributionSnapshot, BlockFeeStats,
    distribute_fee, is_congested,
};

pub use fork_signal::{ForkSignaler, SignalBits, DeploymentState, DEPLOYMENTS};

// Mandatory privacy enforcement (Pirate Chain-style).
pub use privacy_policy::{enforce_privacy_policy, check_tx_privacy};
