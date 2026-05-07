//! # Kernel Offsets — CIP-004 stub
//!
//! Reserved interface for [CIP-004 — Kernel Offsets][cip].
//!
//! Kernel offsets are a single 32-byte curve point added to a
//! transaction's kernel excess at signing time. The published kernel
//! signature is over `excess - offset`; verifiers re-add the offset
//! during verification. The offset breaks the otherwise-direct
//! linkage between input and output blinding factors, providing an
//! unlinkability layer that does not depend on CLSAG ring soundness.
//!
//! ## Status
//!
//! This module is intentionally a stub. Every public method panics
//! with `unimplemented!` so a wallet that tries to call it will fail
//! loud rather than silently signing without an offset. The types
//! are stable so storage / wallet schema reservations downstream can
//! reference them without churn when CIP-004 reaches Active.
//!
//! Compiled only when the `sketch-kernel-offsets` cargo feature is
//! enabled. The feature is off by default, so this module does not
//! appear in the production audit perimeter.
//!
//! [cip]: ../../docs/cip/CIP-004-kernel-offsets.md

use crate::primitives::Hash;

/// A kernel offset — fresh random scalar masking a transaction's
/// blinding-factor excess.
///
/// Stored as the 32-byte scalar; the curve-point form `offset * G`
/// is computed at verification time.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct KernelOffset(pub [u8; 32]);

/// The combined offset across an aggregated block — sum of every
/// per-transaction offset in that block.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AggregateOffset(pub [u8; 32]);

impl KernelOffset {
    /// Generate a fresh random offset using the platform CSPRNG.
    ///
    /// Reference implementation: pull 32 bytes from `getrandom` and
    /// reduce mod the ed25519 group order.
    pub fn generate() -> Self {
        unimplemented!("CIP-004 not active; see docs/cip/CIP-004-kernel-offsets.md")
    }

    /// Aggregate this offset with another. Addition is commutative,
    /// so block-level aggregation order does not matter.
    pub fn aggregate(self, _other: Self) -> AggregateOffset {
        unimplemented!("CIP-004 not active; see docs/cip/CIP-004-kernel-offsets.md")
    }

    /// Verify a kernel signature against `excess + offset*G`.
    ///
    /// Returns true iff the signature was produced by the holder of
    /// the unblinded excess scalar, given the published offset.
    pub fn verify_against(&self, _excess: &[u8; 32], _signature: &[u8; 64], _msg: &Hash) -> bool {
        unimplemented!("CIP-004 not active; see docs/cip/CIP-004-kernel-offsets.md")
    }
}

impl AggregateOffset {
    /// The neutral aggregate — sum of zero offsets. Used as the
    /// identity element for fold operations.
    pub const ZERO: Self = AggregateOffset([0u8; 32]);
}
