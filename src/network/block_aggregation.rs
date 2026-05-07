//! # Block-level Aggregation — CIP-003 stub
//!
//! Reserved interface for [CIP-003 — Cut-Through and Block-Level
//! Aggregation][cip].
//!
//! Combines the kernels of every transaction in a candidate block
//! into a single aggregate kernel. The block's published form has
//! one input set, one output set, and one aggregate signature —
//! observers cannot pair an input with the output it funds via
//! transaction structure. Existing CLSAG-16 ring signatures continue
//! to hide each spend within its ring; this stub adds graph privacy
//! at block granularity on top.
//!
//! ## Status
//!
//! This module is intentionally a stub. Every aggregation method
//! panics with `unimplemented!`. The trait surface is stable so
//! storage / mempool / consensus code can reference these types
//! without churn when CIP-003 reaches Active.
//!
//! Compiled only when the `sketch-block-aggregation` cargo feature is
//! enabled. The feature is off by default, so this module does not
//! appear in the production audit perimeter.
//!
//! Pairs with [`crate::crypto::mw_cutthrough::MwKernel`] — the
//! per-transaction kernel type that cut-through already defines.
//!
//! [cip]: ../../docs/cip/CIP-003-cut-through-and-aggregation.md

use crate::crypto::mw_cutthrough::MwKernel;
use crate::primitives::Amount;

/// A block-level aggregate of every transaction kernel in the block.
#[derive(Clone, Debug)]
pub struct AggregateKernel {
    /// Sum of every per-transaction kernel excess.
    pub excess: [u8; 32],
    /// MuSig2 aggregate Schnorr signature over the per-tx signatures.
    pub signature: [u8; 64],
    /// Sum of every per-transaction fee.
    pub fee: Amount,
}

/// Aggregator that folds individual kernels into a single block-level
/// aggregate. Order-independence is required: any permutation of the
/// input kernel set must yield the same `AggregateKernel`.
pub struct BlockAggregator;

impl BlockAggregator {
    /// Combine the kernels of every transaction in a candidate block.
    ///
    /// Reference implementation will use a MuSig2-style signature
    /// aggregation. The implementation must be order-independent
    /// (verified via property test in CIP-003 reference impl).
    pub fn aggregate(_kernels: &[MwKernel]) -> AggregateKernel {
        unimplemented!(
            "CIP-003 not active; see docs/cip/CIP-003-cut-through-and-aggregation.md"
        )
    }

    /// Verify an aggregate kernel without re-aggregating from parts.
    /// Used by full nodes validating an incoming block.
    pub fn verify(_aggregate: &AggregateKernel, _block_hash: &[u8; 32]) -> bool {
        unimplemented!(
            "CIP-003 not active; see docs/cip/CIP-003-cut-through-and-aggregation.md"
        )
    }
}
