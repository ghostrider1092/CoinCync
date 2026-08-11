//! # Consensus Module for CoinCync 1.0
//!
//! RandomX-only Proof of Work consensus with:
//! - Single algorithm (RandomX)
//! - Dual-Anchor ASERT-i3-2d difficulty adjustment (see difficulty.rs)
//! - Asymptotic-with-tail emission curve (see emission/curve.rs)
//!
//! AUDIT (2026-07-02 line-by-line pass): fixed two stale doc claims here.
//! Previous version said "LWMA difficulty adjustment" — that has been
//! ASERT-i3-2d since well before v1.0.0 and the algorithm-tag was never
//! updated in this docstring. difficulty.rs's own module header names
//! the algorithm correctly. Same class of doc-vs-code drift as the
//! ring_selection.rs gamma cleanup landed in a1b62ec6. Also renamed
//! "Halving emission curve" to "Asymptotic-with-tail" because that's
//! what emission/curve.rs actually implements — see base_reward_from_supply
//! (remaining / EMISSION_DIVISOR, floored at TAIL_EMISSION); there's no
//! discrete halving event, the curve is continuous with a tail floor.

pub mod block;
pub mod difficulty;
pub mod fee_market;
pub mod finality;
pub mod fork_signal;
pub mod header;
pub mod pow;
pub mod privacy_policy;
pub mod validation;

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
pub use difficulty::{
    calculate_difficulty, estimate_hashrate, max_target, min_target, target_to_difficulty,
    DifficultyAdjustment, DifficultyBlock,
};
pub use header::BlockHeader;
pub use pow::{
    bind_randomx_genesis_for_network, compute_full_anchor, compute_pow_hash, meets_difficulty,
    verify_pow, work_from_target, Anchor, PowAlgorithm,
};
// M-1: finality module is dead code; re-exports removed.
pub use validation::{
    v1_0_12_rules_active, validate_block, validate_block_with_checkpoint,
    validate_block_with_checkpoint_for_network, validate_transaction, validate_transaction_basic,
    validate_transaction_for_network, BlockValidation,
};
pub(crate) use validation::{
    verify_balance_proof, verify_output_range_proofs, verify_ring_signature,
};

// Re-export Transaction from transaction module so old imports that say
// `use crate::consensus::Transaction` continue to work.
pub use crate::transaction::Transaction;

pub use fee_market::{
    distribute_fee, is_congested, BlockFeeStats, FeeCalculator, FeeContext, FeeDistribution,
    FeeDistributionSnapshot, FeeEstimate, FeeTier,
};

pub use fork_signal::{DeploymentState, ForkSignaler, SignalBits, DEPLOYMENTS};

// Mandatory privacy enforcement (Pirate Chain-style).
pub use privacy_policy::{check_tx_privacy, enforce_privacy_policy};
