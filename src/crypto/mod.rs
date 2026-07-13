//! # Cryptographic Operations for CoinCync 1.0

// The cross-stack byte-level interface lives in the `bridge`
// workspace member at crates/bridge/. Re-export it here so existing
// consumers can keep writing `crate::crypto::bridge::*` without
// caring that the types are defined in a sibling crate.
pub mod bridge {
    pub use ::bridge::*;
}

mod bulletproofs;
mod stealth;
mod view_keys;
mod curve;
mod clsag;
pub mod clsag_multisig;

/// Re-exports for the out-of-tree adversarial/benchmark testbed at
/// `audit-suite/sketches/`. Lets sandbox crates wrap CoinCync's CLSAG
/// and curve primitives without making the internal `crypto::clsag`
/// and `crypto::curve` modules themselves public.
///
/// This doesn't widen the audit perimeter — the underlying code is
/// the same code the audit firm reviews regardless. The named module
/// just gives the sandbox a stable, documented entry point.
///
/// See `audit-suite/sketches/cross-primitive-bench/` for the consumer.
pub mod testbed {
    pub use super::clsag::{clsag_sign, clsag_verify, ClsagSignature, RingMember};
    pub use super::curve::{Commitment, KeyImage, PublicPoint, SecretScalar};
}
mod secure;
mod ring_selection;
mod audit;
mod cache;
mod batch_verify;
mod parallel_proofs;
mod disclosure;
pub mod memo;

// Canonical-decode-enforced wrappers for peer-controlled crypto values.
// See the module docstring for the class of bug they prevent.
mod peer_scalars;
pub use peer_scalars::{PeerScalar, PeerPoint};

// ── Phase 2 additions (yourcoin_combined) ───────────────────────
// `mw_cutthrough` exposes the cut-through engine and `MwKernel`
// type. The engine is constructed but inert in v1.0.x — see CIP-003.
pub mod mw_cutthrough;

// ── Sketch / future-CIP modules (gated, off by default) ─────────
// These are real implementations behind feature flags. They do not
// appear in the production audit perimeter unless their feature is
// explicitly enabled. See docs/cip/ for activation paths.
#[cfg(feature = "sketch-kernel-offsets")]
pub mod kernel_offset;        // CIP-004
#[cfg(feature = "sketch-lelantus-spark")]
pub mod lelantus_spark;       // CIP-005

pub use bulletproofs::{
    RangeProof, PedersenCommitment, BlindingFactor,
    commit, verify_commitment,
    create_range_proof, verify_range_proof, verify_coinbase_output,
    create_aggregated_range_proof, verify_range_proofs,
    batch_verify_range_proofs,
    RANGE_BITS, MAX_AGGREGATION,
    create_range_proof_bp_plus, verify_range_proof_bp_plus,
    create_aggregated_range_proof_bp_plus, verify_range_proofs_bp_plus,
    create_range_proof_for_height, create_aggregated_range_proof_for_height,
    verify_range_proof_dispatch, verify_range_proofs_dispatch,
};

pub use stealth::{
    // 2026-06-03: `generate_stealth_address` removed from the public re-
    // export. It was the legacy `.expect()`-on-invalid-curve-point variant
    // that panics on malformed input — the new code uses
    // `generate_stealth_address_checked` (Result-returning), and no
    // production caller still references the panicking form (repo-wide
    // grep shows only internal tests). Keeping it cfg(test)-gated inside
    // stealth.rs preserves the test fixtures without exposing a
    // panic-on-RPC-input surface to downstream crates.
    StealthAddress, is_output_ours, OutputScanContext,
    generate_stealth_address_for, generate_stealth_address_checked,
    generate_stealth_outputs, is_output_ours_with_epoch,
    compute_one_time_secret, scan_outputs,
    coinbase_stealth_address,
    RecipientKeys, ViewOnlyScanner, ScanOutput, ScanResult,
    Subaddress, SubaddressManager,
    StealthIndex, IndexedOutput,
    AuditKey, AuditKeyExport,
};
pub use view_keys::{ViewKey, ViewKeyScope};

pub use curve::{
    SecretScalar, PublicPoint, Commitment as EcCommitment, KeyImage,
    generator, generator_h, hash_to_point, hash_to_scalar,
};

pub use clsag::{
    ClsagSignature, SimpleRingSignature,
    RingMember as ClsagRingMember,
    clsag_sign, clsag_verify,
    simple_ring_sign, simple_ring_verify,
};

pub use secure::{
    SecureBytes, SecureArray,
    ct_eq, ct_cmp, ct_select_u8, ct_select_u64, ct_select_slice, ct_copy_if,
    secure_random, secure_random_32, secure_random_64,
    secure_zero, is_zero,
    verify_hash, verify_mac,
};

// `ring_selection` is consumed by the wallet's send path
// (`src/wallet/send.rs::select_ring_decoys`) which delegates UNIFORM
// (Fisher-Yates) decoy selection. Prior comment here said "gamma-
// distribution" — that was stale after the Wave 15 gamma→uniform
// migration and is now corrected. See `ring_selection.rs` module
// docstring (L3-22) for the Möser-2018 rationale behind the switch.
// Do NOT prune these re-exports — their absence from the
// `src/consensus/` grep is expected since consensus code verifies
// rings, doesn't select them.
pub use ring_selection::{
    RingSelector, RingSelectionConfig, RingSelectionStats,
    RingQualityReport, OutputRef,
};

pub use audit::{
    SupplyCommitment, SupplyAuditResult, SupplySnapshot,
    BlockSupplyDelta,
};

pub use cache::{
    VerificationCache, CacheStats,
    global_cache, proof_cache_key, ring_sig_cache_key,
};

pub use batch_verify::{
    BatchVerifier, BatchVerifyResult, SignatureData,
    ParallelTxValidator, VerificationStats,
};

pub use parallel_proofs::{
    ProofTask, ParallelVerifyResult, ParallelProofVerifier,
    VerifierStats, AggregatedProofVerifier,
    verify_block_proofs,
};

// `disclosure` is consumed by the wallet CLI (`src/bin/wallet.rs`)
// which exposes selective-disclosure proofs (balance / ownership / sum
// / source) to end users via `coincync-wallet disclose ...` subcommands.
// See `src/bin/wallet.rs:1962+` for concrete callers. NOT dead code
// despite zero references from the consensus / mempool / RPC layers.
pub use disclosure::{
    DisclosureProof, DisclosureType,
    BalanceProof as DisclosureBalanceProof,
    OwnershipProof, SumProof, SourceProof,
    OutputRef as DisclosureOutputRef,
    create_balance_proof, verify_balance_proof,
    create_ownership_proof, verify_ownership_proof,
    create_sum_proof, verify_sum_proof,
    create_source_proof, verify_source_proof,
};

pub use memo::{
    encrypt_memo, decrypt_memo,
    MAX_MEMO_SIZE, MEMO_OVERHEAD, MAX_ENCRYPTED_MEMO_SIZE,
};
