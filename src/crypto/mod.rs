//! # Cryptographic Operations for CoinCync 1.0

// The cross-stack byte-level interface lives in the `bridge`
// workspace member at crates/bridge/. Re-export it here so existing
// consumers can keep writing `crate::crypto::bridge::*` without
// caring that the types are defined in a sibling crate.
pub mod bridge {
    pub use ::bridge::*;
}

mod bulletproofs;
mod clsag;
pub mod clsag_multisig;
mod curve;
mod stealth;
mod view_keys;

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
mod audit;
mod batch_verify;
mod cache;
mod disclosure;
pub mod memo;
mod parallel_proofs;
mod ring_selection;
mod secure;

// Canonical-decode-enforced wrappers for peer-controlled crypto values.
// See the module docstring for the class of bug they prevent.
mod peer_scalars;
pub use peer_scalars::{PeerPoint, PeerScalar};

// ── Phase 2 additions (yourcoin_combined) ───────────────────────
// `mw_cutthrough` exposes the cut-through engine and `MwKernel`
// type. The engine is constructed but inert in v1.0.x — see CIP-003.
pub mod mw_cutthrough;

// ── Sketch / future-CIP modules (gated, off by default) ─────────
// These are real implementations behind feature flags. They do not
// appear in the production audit perimeter unless their feature is
// explicitly enabled. See docs/cip/ for activation paths.
#[cfg(feature = "sketch-kernel-offsets")]
pub mod kernel_offset; // CIP-004
#[cfg(feature = "sketch-lelantus-spark")]
pub mod lelantus_spark; // CIP-005

pub use bulletproofs::{
    batch_verify_range_proofs, commit, create_aggregated_range_proof,
    create_aggregated_range_proof_bp_plus, create_aggregated_range_proof_for_height,
    create_range_proof, create_range_proof_bp_plus, create_range_proof_for_height,
    verify_coinbase_output, verify_commitment, verify_range_proof, verify_range_proof_bp_plus,
    verify_range_proof_dispatch, verify_range_proofs, verify_range_proofs_bp_plus,
    verify_range_proofs_dispatch, BlindingFactor, PedersenCommitment, RangeProof, MAX_AGGREGATION,
    RANGE_BITS,
};

pub use stealth::{
    coinbase_stealth_address,
    compute_one_time_secret,
    generate_stealth_address_checked,
    generate_stealth_address_for,
    generate_stealth_outputs,
    is_output_ours,
    is_output_ours_with_epoch,
    scan_outputs,
    AuditKey,
    AuditKeyExport,
    IndexedOutput,
    RecipientKeys,
    ScanOutput,
    ScanResult,
    // 2026-06-03: `generate_stealth_address` removed from the public re-
    // export. It was the legacy `.expect()`-on-invalid-curve-point variant
    // that panics on malformed input — the new code uses
    // `generate_stealth_address_checked` (Result-returning), and no
    // production caller still references the panicking form (repo-wide
    // grep shows only internal tests). Keeping it cfg(test)-gated inside
    // stealth.rs preserves the test fixtures without exposing a
    // panic-on-RPC-input surface to downstream crates.
    StealthAddress,
    StealthIndex,
    Subaddress,
    SubaddressManager,
    ViewOnlyScanner,
};
pub use view_keys::{ViewKey, ViewKeyScope};

pub use curve::{
    generator, generator_h, hash_to_point, hash_to_scalar, Commitment as EcCommitment, KeyImage,
    PublicPoint, SecretScalar,
};

pub use clsag::{
    clsag_sign, clsag_verify, simple_ring_sign, simple_ring_verify, ClsagSignature,
    RingMember as ClsagRingMember, SimpleRingSignature,
};

pub use secure::{
    ct_cmp, ct_copy_if, ct_eq, ct_select_slice, ct_select_u64, ct_select_u8, is_zero,
    secure_random, secure_random_32, secure_random_64, secure_zero, verify_hash, verify_mac,
    SecureArray, SecureBytes,
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
    OutputRef, RingQualityReport, RingSelectionConfig, RingSelectionPool, RingSelectionStats,
    RingSelector,
};

pub use audit::{BlockSupplyDelta, SupplyAuditResult, SupplyCommitment, SupplySnapshot};

pub use cache::{global_cache, proof_cache_key, ring_sig_cache_key, CacheStats, VerificationCache};

pub use batch_verify::{
    BatchVerifier, BatchVerifyResult, ParallelTxValidator, SignatureData, VerificationStats,
};

pub use parallel_proofs::{
    verify_block_proofs, AggregatedProofVerifier, ParallelProofVerifier, ParallelVerifyResult,
    ProofTask, VerifierStats,
};

// `disclosure` is consumed by the wallet CLI (`src/bin/wallet.rs`)
// which exposes selective-disclosure proofs (balance / ownership / sum
// / source) to end users via `coincync-wallet disclose ...` subcommands.
// See `src/bin/wallet.rs:1962+` for concrete callers. NOT dead code
// despite zero references from the consensus / mempool / RPC layers.
pub use disclosure::{
    create_balance_proof, create_ownership_proof, create_source_proof, create_sum_proof,
    verify_balance_proof, verify_balance_proof_anchored, verify_ownership_proof,
    verify_ownership_proof_anchored, verify_source_proof, verify_source_proof_anchored,
    verify_sum_proof, verify_sum_proof_anchored, AnchorVerdict, BalanceProof as DisclosureBalanceProof,
    ChainAnchor, DisclosureProof, DisclosureType, OutputRef as DisclosureOutputRef, OwnershipProof,
    SourceProof, SumProof,
};

pub use memo::{decrypt_memo, encrypt_memo, MAX_ENCRYPTED_MEMO_SIZE, MAX_MEMO_SIZE, MEMO_OVERHEAD};
