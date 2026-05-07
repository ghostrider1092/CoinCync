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
mod secure;
mod ring_selection;
mod audit;
mod cache;
mod batch_verify;
mod parallel_proofs;
mod disclosure;
pub mod memo;

// ── Phase 2 additions (yourcoin_combined) ───────────────────────
pub mod lelantus_spark;
pub mod mw_cutthrough;

// ── Sketch / future-CIP stubs (gated, off by default) ───────────
#[cfg(feature = "sketch-kernel-offsets")]
pub mod kernel_offset;

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
    StealthAddress, generate_stealth_address, is_output_ours,
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

pub use ring_selection::{
    RingSelector, RingSelectionConfig, RingSelectionStats,
    RingQualityReport, OutputRef,
};

pub use audit::{
    SupplyCommitment, SupplyAuditResult, SupplyAuditProof,
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
