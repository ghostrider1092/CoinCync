//! # Bulletproofs Range Proofs
//!
//! Bulletproofs+ (BP+) range proofs for proving amounts are in valid range
//! without revealing them. Uses the tari_bulletproofs_plus crate; standard
//! Bulletproofs are not used (BP+ active from genesis, BULLETPROOFS_PLUS_HEIGHT=0).
//!
//! ## Security Properties:
//! - BlindingFactor is securely zeroized on drop using the zeroize crate
//! - Commitment operations return Option/Result to handle invalid points
//!
//! ## Audit map
//! Each `§` is a code section below; it states the INVARIANT it guarantees, the
//! THREAT it defends, and the TESTS that prove it.
//!
//! - **§1 `verify_commitment`** — INVARIANT: `commit`/`verify_commitment` implement the Monero-convention
//!   Pedersen commitment `C = v·H + r·G` with an independent value generator `H` (crypto H1), so a
//!   commitment binds to exactly one `(value, blinding)` opening and is homomorphic under addition.
//!   THREAT: a corrupted/swapped `H` (≡ G or identity) collapses hiding+binding and lets an
//!   attacker forge openings; `verify_commitment` uses constant-time compare to deny a timing oracle.
//!   TESTS: `test_commitment_creation`, `pedersen_commitment_is_homomorphic`, `h_generator_is_canonical_bulletproofs_b_blinding_and_independent_of_g`.
//! - **§2 `create_range_proof_bp_plus`** — INVARIANT: a proof produced for amount `v` (via BP+
//!   `create_range_proof_bp_plus`) attests `v ∈ [0, 2^RANGE_BITS)` and is byte-reproducible for
//!   fixed inputs + RNG seed (KAT, crypto C1). THREAT: without a sound range proof a miner mints
//!   money via out-of-range / negative amounts (value overflow inflation).
//!   TESTS: `test_create_and_verify_range_proof`, `range_proof_bp_plus_kat_deterministic_and_golden`, `range_proof_valid_amount_verifies`, `range_proof_large_value_verifies`.
//! - **§3 `verify_range_proof_bp_plus`** — INVARIANT: verification accepts a proof ONLY against the exact
//!   commitment it was created for and rejects an empty proof or a wrong/non-canonical commitment.
//!   THREAT: accepting a proof against a mismatched or malformed commitment breaks binding and admits
//!   forged/inflated outputs into the chain.
//!   TESTS: `test_wrong_commitment_fails`, `range_proof_wrong_commitment_fails`, `test_bp_plus_single_proof`.
//! - **§4 `create_aggregated_range_proof_bp_plus`** — INVARIANT: an aggregated proof over N outputs
//!   (zero/identity padded to the next power of two) verifies iff every real committed amount is in
//!   range, for non-power-of-two N too. THREAT: mis-padding or an unsound aggregate lets an
//!   out-of-range output hide among valid ones, enabling inflation.
//!   TESTS: `test_aggregated_proof`, `test_aggregated_proof_three_outputs`, `test_power_of_2_padding_boundary`, `aggregated_range_proof_multi_output_verifies`.
//! - **§5 `verify_range_proofs_dispatch`** — INVARIANT (C-2 FIX): activation-height gating — before
//!   `BULLETPROOFS_PLUS_HEIGHT` only v2 proofs validate, at/after it only v3 (BP+); the version byte
//!   alone never bypasses the height gate. THREAT: without gating a miner includes a BP+ proof in a
//!   pre-fork block (or a stale v2 post-fork), splitting the chain between updated and legacy nodes.
//!   TESTS: `verify_range_proofs_dispatch_gates_off_wrong_version`, `test_height_dispatch_creation`, `test_bp_plus_aggregated_proof`.
//! - **§6 `verify_coinbase_output`** — INVARIANT: a coinbase output must commit to the exact expected
//!   subsidy under a ZERO blinding factor, checked in constant time. THREAT: accepting a
//!   random-blinded or wrong-amount coinbase commitment lets a miner pay themselves more than the
//!   consensus subsidy (coinbase inflation).
//!   TESTS: `verify_coinbase_output_matches_zero_blinding`.
//! - **§7 `batch_verify_range_proofs` (bounds: `MAX_AGGREGATION`/`RANGE_BITS`)** — INVARIANT:
//!   `batch_verify_range_proofs` accepts a set iff every `(commitment, proof)` pair verifies, and
//!   aggregation refuses length mismatch and any batch exceeding `MAX_AGGREGATION`, with `RANGE_BITS`
//!   fixing the 64-bit proving width. THREAT: an oversized/mismatched batch is a DoS or padding-abuse
//!   vector, a lenient batch check lets one bad proof slip through, and a wrong bit width would prove
//!   the wrong range.
//!   TESTS: `create_aggregated_range_proof_rejects_length_mismatch`, `create_aggregated_range_proof_rejects_over_max_aggregation`, `create_aggregated_range_proof_empty_returns_empty_proof`, `range_proof_at_u64_max`.
//! - **§8 `from_bytes_checked`** — INVARIANT (R-5 / H7-FIX): the checked constructor decompresses and
//!   rejects non-canonical bytes, `checked_add`/`checked_sub` return `None` on invalid points, and the
//!   `Add` operator falls back to identity instead of panicking. THREAT: the `from_bytes_unchecked`
//!   footgun creates an "invalid but stored" wedge (passes bytewise dedup, fails validation) and an
//!   unchecked point op panics the node from the consensus path (crash DoS).
//!   TESTS: `commitment_from_bytes_checked_accepts_valid_rejects_noncanonical`, `checked_add_sub_return_none_on_invalid_point`, `add_operator_returns_identity_on_invalid_point`.

use borsh::{BorshDeserialize, BorshSerialize};
use merlin::Transcript;
use once_cell::sync::Lazy;
use rand::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

use crate::crypto::secure::ct_eq;
use crate::error::{Error, Result};
use crate::primitives::Amount;

// MIGRATION: All types now use curve25519-dalek v4 (no more dalek-ng)
use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
use curve25519_dalek::scalar::Scalar;

/// Range proof version
pub const RANGE_PROOF_VERSION: u8 = 2;

/// Range proof bit length (64 bits = max ~18 quintillion)
pub const RANGE_BITS: usize = 64;

/// Maximum outputs in a single aggregated proof
pub const MAX_AGGREGATION: usize = 16;

/// H generator (value base) — hardcoded compressed Ristretto point.
/// This is the standard bulletproofs H: SHA-512(compressed_basepoint) mapped to Ristretto.
/// Extracted from bulletproofs::PedersenGens::default().B_blinding.
/// Hardcoding eliminates the dependency on the old bulletproofs crate.
const H_GENERATOR_COMPRESSED: [u8; 32] = [
    0x8c, 0x92, 0x40, 0xb4, 0x56, 0xa9, 0xe6, 0xdc, 0x65, 0xc3, 0x77, 0xa1, 0x04, 0x8d, 0x74, 0x5f,
    0x94, 0xa0, 0x8c, 0xdb, 0x7f, 0x44, 0xcb, 0xcd, 0x7b, 0x46, 0xf3, 0x40, 0x48, 0x87, 0x11, 0x34,
];

/// Decompressed H generator (value base) — cached
static H_POINT: Lazy<RistrettoPoint> = Lazy::new(|| {
    CompressedRistretto::from_slice(&H_GENERATOR_COMPRESSED)
        .expect("H_GENERATOR_COMPRESSED is valid")
        .decompress()
        .expect("H generator must decompress")
});

/// Decompressed G generator (blinding base) — the Ristretto basepoint
fn g_point() -> RistrettoPoint {
    use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
    RISTRETTO_BASEPOINT_POINT
}

/// The value generator `H` of the range-proof Pedersen commitment `C = v·H + r·G`.
/// Exposed so a shielded value commitment can be linked (via a value-equality
/// proof) to a range-provable commitment on this exact basis.
pub fn value_generator() -> RistrettoPoint {
    *H_POINT
}
/// The blinding generator `G` (Ristretto basepoint) of the range-proof
/// Pedersen commitment `C = v·H + r·G`.
pub fn blinding_generator() -> RistrettoPoint {
    g_point()
}

/// Commit using Monero convention: C = v*H + r*G
fn pedersen_commit(value: u64, blinding: &Scalar) -> RistrettoPoint {
    Scalar::from(value) * *H_POINT + blinding * g_point()
}

/// Blinding factor for commitments (wrapper around Scalar)
///
/// SECURITY: Implements `Zeroize` and `Drop` to ensure secret scalar
/// data is securely erased from memory when no longer needed.
#[derive(Clone)]
pub struct BlindingFactor(Scalar);

impl BlindingFactor {
    /// Generate a random blinding factor
    pub fn random<R: RngCore + CryptoRng>(rng: &mut R) -> Self {
        let mut bytes = [0u8; 64];
        rng.fill_bytes(&mut bytes);
        let scalar = Scalar::from_bytes_mod_order_wide(&bytes);
        use zeroize::Zeroize;
        bytes.zeroize();
        BlindingFactor(scalar)
    }

    /// Create from bytes (32 bytes, reduced mod l)
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        BlindingFactor(Scalar::from_bytes_mod_order(bytes))
    }

    /// Convert to bytes
    pub fn to_bytes(&self) -> [u8; 32] {
        self.0.to_bytes()
    }

    /// Get as bytes slice
    pub fn as_bytes(&self) -> &[u8] {
        self.0.as_bytes()
    }

    /// Get the internal scalar
    pub fn as_scalar(&self) -> &Scalar {
        &self.0
    }

    /// Create a zero blinding factor
    pub fn zero() -> Self {
        BlindingFactor(Scalar::ZERO)
    }

    /// Add two blinding factors (scalar addition mod l)
    pub fn add(&self, other: &BlindingFactor) -> BlindingFactor {
        BlindingFactor(self.0 + other.0)
    }

    /// Subtract another blinding factor (scalar subtraction mod l)
    pub fn sub(&self, other: &BlindingFactor) -> BlindingFactor {
        BlindingFactor(self.0 - other.0)
    }
}

impl Zeroize for BlindingFactor {
    fn zeroize(&mut self) {
        // Overwrite the scalar with zero bytes and enforce a compiler fence
        // to prevent the optimizer from eliding the write.
        let mut bytes = self.0.to_bytes();
        bytes.zeroize();
        std::sync::atomic::compiler_fence(std::sync::atomic::Ordering::SeqCst);
        self.0 = Scalar::from_bytes_mod_order(bytes);
    }
}

impl Drop for BlindingFactor {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl std::fmt::Debug for BlindingFactor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "BlindingFactor([REDACTED])")
    }
}

/// Pedersen commitment — now uses curve25519-dalek v4 types exclusively
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct PedersenCommitment(CompressedRistretto);

impl PedersenCommitment {
    /// Create commitment: C = v*H + r*G (Monero convention)
    pub fn commit(value: u64, blinding: &BlindingFactor) -> Self {
        let point = pedersen_commit(value, &blinding.0);
        PedersenCommitment(point.compress())
    }

    /// Create from bytes WITHOUT validating that the encoded point
    /// is a canonical Ristretto element.
    ///
    /// # DANGER (R-5 fix, 2026-07-02)
    ///
    /// This constructor is a well-known API footgun. The
    /// `CompressedRistretto` wrapper stores the 32 bytes verbatim;
    /// no canonicalisation, no subgroup check, no decompress attempt.
    /// A caller who feeds a non-canonical byte string produces a
    /// `PedersenCommitment` that:
    ///   - Compares unequal to the canonical form of the same point.
    ///   - Fails `decompress()` at every downstream site
    ///     (bulletproof verification, transaction validation).
    ///   - Silently passes any code path that only checks bytewise
    ///     equality (e.g. mempool dedup, DB lookup keys).
    ///
    /// This produces the "invalid but stored" wedge state where a
    /// mempool tx passes bytewise dedup but fails validation on
    /// mining. Callers with adversarial byte input MUST use
    /// [`PedersenCommitment::from_bytes_checked`] instead — it runs
    /// the decompression validation and returns `None` on non-canonical
    /// bytes. This unchecked form remains ONLY for the internal
    /// serde/borsh round-trip path where the bytes have already been
    /// validated elsewhere (see the decode paths that call
    /// `from_bytes_checked` immediately after construction).
    ///
    /// AUDIT (R-5 SURGICAL FIX, 2026-07-03): renamed the unchecked
    /// variant to `from_bytes_unchecked` so its danger is
    /// unmissable in code review. Every in-tree caller ALREADY uses
    /// `from_bytes_checked` (verified 2026-07-03 across
    /// consensus/validation.rs, crypto/disclosure.rs, and
    /// crypto/parallel_proofs.rs — 5 sites, all validated). This
    /// unchecked form remains only for the internal borsh
    /// round-trip path where the encoder produced the bytes.
    pub fn from_bytes_unchecked(bytes: [u8; 32]) -> Self {
        PedersenCommitment(CompressedRistretto(bytes))
    }

    /// Create from bytes with validation
    /// Returns None if bytes don't represent a valid Ristretto point
    pub fn from_bytes_checked(bytes: [u8; 32]) -> Option<Self> {
        let compressed = CompressedRistretto(bytes);
        // Try to decompress to validate the point
        compressed.decompress()?;
        Some(PedersenCommitment(compressed))
    }

    /// Convert to bytes
    pub fn to_bytes(&self) -> [u8; 32] {
        self.0.to_bytes()
    }

    /// Get as bytes slice
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0 .0
    }

    /// Get compressed point
    pub fn as_point(&self) -> &CompressedRistretto {
        &self.0
    }

    /// Zero commitment
    pub fn zero() -> Self {
        PedersenCommitment(CompressedRistretto([0u8; 32]))
    }

    /// To hex string
    pub fn to_hex(&self) -> String {
        hex::encode(self.to_bytes())
    }
}

impl std::fmt::Debug for PedersenCommitment {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Commitment({}...)", hex::encode(&self.to_bytes()[..8]))
    }
}

impl std::hash::Hash for PedersenCommitment {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.0 .0.hash(state);
    }
}

impl std::ops::Add for PedersenCommitment {
    type Output = Self;

    /// Add two commitments using the + operator.
    ///
    /// SECURITY (H7-FIX): Returns identity point on invalid input instead of panicking.
    /// Like Grin's commitment arithmetic, invalid points produce a safe default
    /// rather than crashing the node. Callers doing validation should use
    /// `checked_add()` to detect invalid points explicitly.
    fn add(self, other: Self) -> Self {
        self.checked_add(&other).unwrap_or_else(|| {
            tracing::warn!("PedersenCommitment::add: invalid curve point, returning identity");
            PedersenCommitment({
                use curve25519_dalek::traits::Identity;
                curve25519_dalek::ristretto::RistrettoPoint::identity().compress()
            })
        })
    }
}

impl std::ops::Add<&PedersenCommitment> for PedersenCommitment {
    type Output = Self;

    /// SECURITY (H7-FIX): Returns identity on invalid input instead of panicking.
    fn add(self, other: &PedersenCommitment) -> Self {
        self.checked_add(other).unwrap_or_else(|| {
            tracing::warn!("PedersenCommitment::add: invalid curve point, returning identity");
            PedersenCommitment({
                use curve25519_dalek::traits::Identity;
                curve25519_dalek::ristretto::RistrettoPoint::identity().compress()
            })
        })
    }
}

impl PedersenCommitment {
    /// Add another commitment to this one (returns new commitment)
    /// Returns None if either commitment contains an invalid point
    pub fn checked_add(&self, other: &PedersenCommitment) -> Option<Self> {
        let a = self.0.decompress()?;
        let b = other.0.decompress()?;
        Some(PedersenCommitment((a + b).compress()))
    }

    /// Subtract another commitment from this one (returns new commitment)
    /// Returns None if either commitment contains an invalid point
    pub fn checked_sub(&self, other: &PedersenCommitment) -> Option<Self> {
        let a = self.0.decompress()?;
        let b = other.0.decompress()?;
        Some(PedersenCommitment((a - b).compress()))
    }

    // AUDIT (2026-07-01): removed the deprecated `add`/`sub` methods
    // that unwrapped `checked_add`/`checked_sub` with `.expect("invalid
    // commitment point")`. Repo-wide grep confirmed zero external callers
    // — `#[deprecated]` had done its job and all users migrated to the
    // checked variants. The deprecated wrappers were a live panic
    // footgun (any future caller who ignored the deprecation warning
    // would panic-on-invalid-input, crashing the node from the
    // consensus verification path). Callers must use `checked_add`/
    // `checked_sub` and handle the `Option::None` case explicitly.
}

/// Range proof wrapper
#[derive(Clone, Serialize, Deserialize, BorshSerialize, BorshDeserialize)]
pub struct RangeProof {
    /// Proof version
    pub version: u8,
    /// Serialized proof data
    pub data: Vec<u8>,
}

impl RangeProof {
    /// Create an empty proof (for coinbase transactions)
    pub fn empty() -> Self {
        RangeProof {
            version: RANGE_PROOF_VERSION,
            data: vec![],
        }
    }

    /// Get proof size in bytes
    pub fn size(&self) -> usize {
        1 + self.data.len()
    }

    /// Check if proof is empty (coinbase)
    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }

    /// R-6 SURGICAL FIX (2026-07-03): the panicking `to_bytes()` form
    /// has been REMOVED. All callers (tx-builder, test suite) have
    /// been migrated to `try_to_bytes` and propagate errors via `?`.
    /// The remaining `try_to_bytes` is the ONLY serialization entry
    /// point.
    pub fn try_to_bytes(&self) -> Result<Vec<u8>> {
        borsh::to_vec(self).map_err(|e| Error::SerializationError(e.to_string()))
    }

    /// Deserialize from bytes
    pub fn from_bytes(data: &[u8]) -> Result<Self> {
        borsh::from_slice(data).map_err(|_| Error::RangeProofInvalid)
    }
}

impl std::fmt::Debug for RangeProof {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "RangeProof(v{}, {} bytes)", self.version, self.size())
    }
}

/// Create a Pedersen commitment and blinding factor
pub fn commit<R: RngCore + CryptoRng>(
    rng: &mut R,
    amount: Amount,
) -> (PedersenCommitment, BlindingFactor) {
    let blinding = BlindingFactor::random(rng);
    let commitment = PedersenCommitment::commit(amount.as_atomic(), &blinding);

    // SECURITY: Removed logging of commitment bytes (unnecessary in production,
    // leaks cryptographic material to log files).
    tracing::debug!("Created Pedersen commitment (amount hidden)");

    (commitment, blinding)
}

/// Verify a Pedersen commitment opens to the given value
///
/// SECURITY: Uses constant-time comparison to prevent timing attacks.
pub fn verify_commitment(
    commitment: &PedersenCommitment,
    amount: Amount,
    blinding: &BlindingFactor,
) -> bool {
    let expected = PedersenCommitment::commit(amount.as_atomic(), blinding);
    // SECURITY: Use constant-time comparison to prevent timing side-channels
    ct_eq(commitment.as_bytes(), expected.as_bytes())
}

// ─── Legacy API (delegates to BP+) ──────────────────────────────────────
// With BULLETPROOFS_PLUS_HEIGHT = 0, all range proofs use BP+ from genesis.
// These functions maintain the old API for callers that haven't migrated.

/// Round up to the next power of two
fn next_power_of_two(n: usize) -> usize {
    if n == 0 {
        return 1;
    }
    n.next_power_of_two()
}

/// Create a range proof (delegates to BP+)
pub fn create_range_proof<R: RngCore + CryptoRng>(
    amount: Amount,
    blinding: &BlindingFactor,
    rng: &mut R,
) -> Result<RangeProof> {
    create_range_proof_bp_plus(amount, blinding, rng)
}

/// Create an aggregated range proof (delegates to BP+)
pub fn create_aggregated_range_proof<R: RngCore + CryptoRng>(
    amounts: &[Amount],
    blindings: &[BlindingFactor],
    rng: &mut R,
) -> Result<RangeProof> {
    create_aggregated_range_proof_bp_plus(amounts, blindings, rng)
}

/// Verify a range proof (delegates to BP+)
pub fn verify_range_proof(commitment: &PedersenCommitment, proof: &RangeProof) -> bool {
    if proof.is_empty() {
        return false;
    }
    verify_range_proof_bp_plus(commitment, proof)
}

/// Verify a coinbase output commitment
pub fn verify_coinbase_output(commitment: &PedersenCommitment, expected_amount: u64) -> bool {
    let expected = PedersenCommitment::commit(expected_amount, &BlindingFactor::zero());
    ct_eq(commitment.as_bytes(), expected.as_bytes())
}

/// Verify an aggregated range proof (delegates to BP+)
pub fn verify_range_proofs(commitments: &[PedersenCommitment], proof: &RangeProof) -> bool {
    if commitments.is_empty() {
        return proof.is_empty();
    }
    if proof.is_empty() {
        return false;
    }
    verify_range_proofs_bp_plus(commitments, proof)
}

/// Batch verify multiple independent range proofs
pub fn batch_verify_range_proofs(
    commitments_and_proofs: &[(PedersenCommitment, RangeProof)],
) -> bool {
    commitments_and_proofs
        .iter()
        .all(|(c, p)| verify_range_proof(c, p))
}

// ─── Bulletproofs+ (BP+) range proofs ────────────────────────────────────────
//
// BP+ (Chung et al. 2022) produces proofs ~96 bytes shorter than standard
// Bulletproofs and verifies ~10% faster.  Uses `tari_bulletproofs_plus` crate
// with the same Ristretto/curve25519-dalek v4 used by the rest of CoinCync.
//
// Activation: proofs with version=3 are required at height >= BULLETPROOFS_PLUS_HEIGHT.
// Below that height, version=2 (standard Bulletproofs) proofs are accepted.

use tari_bulletproofs_plus::{
    commitment_opening::CommitmentOpening as BpPlusOpening,
    generators::pedersen_gens::{ExtensionDegree, PedersenGens as BpPlusPedersenGens},
    range_parameters::RangeParameters as BpPlusParams,
    range_proof::RangeProof as BpPlusProof,
    range_proof::VerifyAction,
    range_statement::RangeStatement as BpPlusStatement,
    range_witness::RangeWitness as BpPlusWitness,
};

use crate::constants::{BULLETPROOFS_PLUS_HEIGHT, RANGE_PROOF_VERSION_BP_PLUS};

/// BP+ Pedersen generators (cached), matching our swapped-generator convention.
/// Uses hardcoded H bytes and the standard Ristretto basepoint G.
/// No more cross-crate boundary — all curve25519-dalek v4.
static BP_PLUS_PC_GENS: Lazy<BpPlusPedersenGens<RistrettoPoint>> = Lazy::new(|| {
    let h_base = *H_POINT;
    let g_base = g_point();

    BpPlusPedersenGens {
        h_base,
        h_base_compressed: h_base.compress(),
        g_base_vec: vec![g_base],
        g_base_compressed_vec: vec![g_base.compress()],
        extension_degree: ExtensionDegree::DefaultPedersen,
    }
});

/// Create a single BP+ range proof.
pub fn create_range_proof_bp_plus<R: RngCore + CryptoRng>(
    amount: Amount,
    blinding: &BlindingFactor,
    rng: &mut R,
) -> Result<RangeProof> {
    let opening = BpPlusOpening::new(amount.as_atomic(), vec![*blinding.as_scalar()]);
    let witness = BpPlusWitness::init(vec![opening])
        .map_err(|e| Error::CryptoError(format!("BP+ witness: {e}")))?;

    let params = BpPlusParams::init(RANGE_BITS, 1, BP_PLUS_PC_GENS.clone())
        .map_err(|e| Error::CryptoError(format!("BP+ params: {e}")))?;

    let c = PedersenCommitment::commit(amount.as_atomic(), blinding);
    let commitment = c.as_point().decompress().ok_or(Error::RangeProofInvalid)?;

    let statement = BpPlusStatement::init(params, vec![commitment], vec![None], None)
        .map_err(|e| Error::CryptoError(format!("BP+ statement: {e}")))?;

    let mut transcript = Transcript::new(b"CoinCync_RangeProof_BPPlus");
    let proof = BpPlusProof::prove_with_rng(&mut transcript, &statement, &witness, rng)
        .map_err(|e| Error::CryptoError(format!("BP+ prove: {e}")))?;

    let proof_bytes = proof.to_bytes();
    tracing::info!(
        "BP+ range proof created ({} bytes) — ~96 bytes shorter than standard",
        proof_bytes.len()
    );

    Ok(RangeProof {
        version: RANGE_PROOF_VERSION_BP_PLUS,
        data: proof_bytes,
    })
}

/// Create an aggregated BP+ range proof for multiple outputs.
pub fn create_aggregated_range_proof_bp_plus<R: RngCore + CryptoRng>(
    amounts: &[Amount],
    blindings: &[BlindingFactor],
    rng: &mut R,
) -> Result<RangeProof> {
    if amounts.len() != blindings.len() {
        return Err(Error::RangeProofInvalid);
    }
    if amounts.is_empty() {
        return Ok(RangeProof {
            version: RANGE_PROOF_VERSION_BP_PLUS,
            data: vec![],
        });
    }
    if amounts.len() > MAX_AGGREGATION {
        return Err(Error::RangeProofInvalid);
    }

    let real_count = amounts.len();
    let padded_count = next_power_of_two(real_count);

    // Build openings (real + zero-padding)
    let mut openings: Vec<BpPlusOpening> = amounts
        .iter()
        .zip(blindings.iter())
        .map(|(a, b)| BpPlusOpening::new(a.as_atomic(), vec![*b.as_scalar()]))
        .collect();
    for _ in real_count..padded_count {
        openings.push(BpPlusOpening::new(0, vec![Scalar::ZERO]));
    }

    let witness = BpPlusWitness::init(openings)
        .map_err(|e| Error::CryptoError(format!("BP+ witness: {e}")))?;

    let params = BpPlusParams::init(RANGE_BITS, padded_count, BP_PLUS_PC_GENS.clone())
        .map_err(|e| Error::CryptoError(format!("BP+ params: {e}")))?;

    // Build commitments (real + identity padding)
    let mut commitments: Vec<RistrettoPoint> = Vec::with_capacity(padded_count);
    for (a, b) in amounts.iter().zip(blindings.iter()) {
        let c = PedersenCommitment::commit(a.as_atomic(), b);
        commitments.push(c.as_point().decompress().ok_or(Error::RangeProofInvalid)?);
    }
    let identity = PedersenCommitment::commit(0, &BlindingFactor::from_bytes([0u8; 32]))
        .as_point()
        .decompress()
        .ok_or(Error::RangeProofInvalid)?;
    for _ in real_count..padded_count {
        commitments.push(identity);
    }

    let statement = BpPlusStatement::init(params, commitments, vec![None; padded_count], None)
        .map_err(|e| Error::CryptoError(format!("BP+ statement: {e}")))?;

    let mut transcript = Transcript::new(b"CoinCync_AggregatedRangeProof_BPPlus");
    let proof = BpPlusProof::prove_with_rng(&mut transcript, &statement, &witness, rng)
        .map_err(|e| Error::CryptoError(format!("BP+ prove: {e}")))?;

    let proof_bytes = proof.to_bytes();
    tracing::info!(
        "BP+ aggregated range proof ({} bytes) for {} outputs (padded to {})",
        proof_bytes.len(),
        real_count,
        padded_count,
    );

    Ok(RangeProof {
        version: RANGE_PROOF_VERSION_BP_PLUS,
        data: proof_bytes,
    })
}

/// Verify a single BP+ range proof.
pub fn verify_range_proof_bp_plus(commitment: &PedersenCommitment, proof: &RangeProof) -> bool {
    if proof.is_empty() || proof.version != RANGE_PROOF_VERSION_BP_PLUS {
        return false;
    }

    let bp_proof = match BpPlusProof::<RistrettoPoint>::from_bytes(&proof.data) {
        Ok(p) => p,
        Err(_) => return false,
    };

    let point = match commitment.as_point().decompress() {
        Some(p) => p,
        None => return false,
    };

    let params = match BpPlusParams::init(RANGE_BITS, 1, BP_PLUS_PC_GENS.clone()) {
        Ok(p) => p,
        Err(_) => return false,
    };

    let statement = match BpPlusStatement::init(params, vec![point], vec![None], None) {
        Ok(s) => s,
        Err(_) => return false,
    };

    let transcript = Transcript::new(b"CoinCync_RangeProof_BPPlus");
    BpPlusProof::verify_batch(
        &mut [transcript],
        &[statement],
        &[bp_proof],
        VerifyAction::VerifyOnly,
    )
    .is_ok()
}

/// Verify an aggregated BP+ range proof for multiple commitments.
pub fn verify_range_proofs_bp_plus(commitments: &[PedersenCommitment], proof: &RangeProof) -> bool {
    if commitments.is_empty() {
        return proof.is_empty();
    }
    if proof.is_empty() || proof.version != RANGE_PROOF_VERSION_BP_PLUS {
        return false;
    }

    let bp_proof = match BpPlusProof::<RistrettoPoint>::from_bytes(&proof.data) {
        Ok(p) => p,
        Err(_) => return false,
    };

    let real_count = commitments.len();
    let padded_count = next_power_of_two(real_count);

    let mut points: Vec<RistrettoPoint> = Vec::with_capacity(padded_count);
    for c in commitments {
        match c.as_point().decompress() {
            Some(p) => points.push(p),
            None => return false,
        }
    }
    let identity = match PedersenCommitment::commit(0, &BlindingFactor::from_bytes([0u8; 32]))
        .as_point()
        .decompress()
    {
        Some(p) => p,
        None => return false,
    };
    for _ in real_count..padded_count {
        points.push(identity);
    }

    let params = match BpPlusParams::init(RANGE_BITS, padded_count, BP_PLUS_PC_GENS.clone()) {
        Ok(p) => p,
        Err(_) => return false,
    };

    let statement = match BpPlusStatement::init(params, points, vec![None; padded_count], None) {
        Ok(s) => s,
        Err(_) => return false,
    };

    let transcript = Transcript::new(b"CoinCync_AggregatedRangeProof_BPPlus");
    BpPlusProof::verify_batch(
        &mut [transcript],
        &[statement],
        &[bp_proof],
        VerifyAction::VerifyOnly,
    )
    .is_ok()
}

// ─── Height-aware dispatch ──────────────────────────────────────────────────

/// Create a single range proof, dispatching to BP+ or standard based on height.
pub fn create_range_proof_for_height<R: RngCore + CryptoRng>(
    amount: Amount,
    blinding: &BlindingFactor,
    rng: &mut R,
    height: u64,
) -> Result<RangeProof> {
    if height >= BULLETPROOFS_PLUS_HEIGHT {
        create_range_proof_bp_plus(amount, blinding, rng)
    } else {
        create_range_proof(amount, blinding, rng)
    }
}

/// Create an aggregated range proof, dispatching based on height.
pub fn create_aggregated_range_proof_for_height<R: RngCore + CryptoRng>(
    amounts: &[Amount],
    blindings: &[BlindingFactor],
    rng: &mut R,
    height: u64,
) -> Result<RangeProof> {
    if height >= BULLETPROOFS_PLUS_HEIGHT {
        create_aggregated_range_proof_bp_plus(amounts, blindings, rng)
    } else {
        create_aggregated_range_proof(amounts, blindings, rng)
    }
}

/// Verify a range proof, dispatching based on the proof's version byte.
///
/// SECURITY (C-2 FIX): Height-gated dispatch — see `verify_range_proofs_dispatch`.
pub fn verify_range_proof_dispatch(
    commitment: &PedersenCommitment,
    proof: &RangeProof,
    current_height: u64,
) -> bool {
    let bp_plus_active = current_height >= crate::constants::BULLETPROOFS_PLUS_HEIGHT;
    match proof.version {
        RANGE_PROOF_VERSION if !bp_plus_active => verify_range_proof(commitment, proof),
        RANGE_PROOF_VERSION_BP_PLUS if bp_plus_active => {
            verify_range_proof_bp_plus(commitment, proof)
        }
        _ => false,
    }
}

/// Verify an aggregated range proof, dispatching based on the proof's version byte.
///
/// SECURITY (C-2 FIX): Enforces activation-height gating. Before `BULLETPROOFS_PLUS_HEIGHT`,
/// only v2 proofs are valid. At or after that height, only v3 (BP+) proofs are valid.
/// Without this check, a miner could include BP+ proofs in pre-fork blocks, causing
/// a chain split between updated and non-updated nodes.
pub fn verify_range_proofs_dispatch(
    commitments: &[PedersenCommitment],
    proof: &RangeProof,
    current_height: u64,
) -> bool {
    let bp_plus_active = current_height >= crate::constants::BULLETPROOFS_PLUS_HEIGHT;
    match proof.version {
        RANGE_PROOF_VERSION if !bp_plus_active => verify_range_proofs(commitments, proof),
        RANGE_PROOF_VERSION_BP_PLUS if bp_plus_active => {
            verify_range_proofs_bp_plus(commitments, proof)
        }
        v => {
            tracing::warn!(
                "Range proof version {} not active at height {} (BP+ active: {})",
                v,
                current_height,
                bp_plus_active
            );
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::OsRng;

    /// AUDIT ANCHOR (crypto H1): the value generator `H` is a hardcoded 32-byte
    /// literal (here and duplicated in `crypto::curve::generator_h`). Every
    /// commitment and range proof derives from it, so a corrupted/swapped `H`
    /// is internally self-consistent — all round-trip tests pass — while being
    /// wrong. This pins it three ways:
    ///
    ///  1. Known-answer vector: `H` must equal the canonical dalek-cryptography
    ///     `bulletproofs::PedersenGens::default().B_blinding` compressed point.
    ///     That value is declared here as a SEPARATE literal sourced from the
    ///     upstream crate (not `H_GENERATOR_COMPRESSED`), so editing the real
    ///     constant fails this test. Note the value cannot be re-derived from
    ///     scratch with the current toolchain: upstream computes it as
    ///     `RistrettoPoint::hash_from_bytes::<Sha512>(RISTRETTO_BASEPOINT_COMPRESSED)`
    ///     under the OLD curve25519-dalek whose Ristretto hash-to-point differs
    ///     from v4's — which is exactly why the point was frozen as a literal.
    ///  2. The two independent in-tree copies must be byte-identical.
    ///  3. `H` must be an independent generator (≠ G, ≠ identity) or the
    ///     commitment `C = v·H + r·G` collapses (value and blinding share a base
    ///     / value drops out), breaking hiding+binding.
    #[test]
    fn h_generator_is_canonical_bulletproofs_b_blinding_and_independent_of_g() {
        use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
        use curve25519_dalek::traits::Identity;

        // Canonical dalek bulletproofs `PedersenGens::default().B_blinding`,
        // compressed. Sourced from upstream; intentionally a distinct literal
        // from `H_GENERATOR_COMPRESSED` so an accidental edit to the real
        // constant is caught here.
        const CANONICAL_B_BLINDING: [u8; 32] = [
            0x8c, 0x92, 0x40, 0xb4, 0x56, 0xa9, 0xe6, 0xdc, 0x65, 0xc3, 0x77, 0xa1, 0x04, 0x8d,
            0x74, 0x5f, 0x94, 0xa0, 0x8c, 0xdb, 0x7f, 0x44, 0xcb, 0xcd, 0x7b, 0x46, 0xf3, 0x40,
            0x48, 0x87, 0x11, 0x34,
        ];
        assert_eq!(
            H_GENERATOR_COMPRESSED, CANONICAL_B_BLINDING,
            "H must be the canonical bulletproofs B_blinding known-answer vector"
        );
        // The two independent hardcoded copies must agree with each other.
        assert_eq!(
            H_POINT.compress().to_bytes(),
            crate::crypto::curve::generator_h().compress().to_bytes(),
            "the bulletproofs and curve.rs H copies must be byte-identical"
        );
        // Independent generator: not G, not identity.
        assert_ne!(*H_POINT, RISTRETTO_BASEPOINT_POINT, "H must differ from G");
        assert_ne!(
            *H_POINT,
            RistrettoPoint::identity(),
            "H must not be the identity point"
        );
    }

    /// AUDIT KAT (crypto C1): a deterministic, portable BP+ range-proof vector.
    /// Pins (1) reproducibility for fixed (amount, blinding, RNG seed) — required
    /// for any golden vector, (2) the proof verifies against its commitment and
    /// is REJECTED against a different one, and (3) a SHA-256 digest of the
    /// serialized proof, frozen so any change to the BP+ prover / wire format is
    /// caught. An auditor can regenerate this from the fixed inputs and
    /// cross-check the encoding against a reference BP+ implementation.
    #[test]
    fn range_proof_bp_plus_kat_deterministic_and_golden() {
        use rand::SeedableRng;
        use rand_chacha::ChaCha20Rng;
        use sha2::{Digest, Sha256};

        let amount = Amount::from_atomic(1_000_000);
        let blinding = BlindingFactor::from_bytes({
            let mut b = [0u8; 32];
            b[0] = 0xAB;
            b[1] = 0xCD;
            b
        });
        let commitment = PedersenCommitment::commit(amount.as_atomic(), &blinding);
        let make =
            || create_range_proof(amount, &blinding, &mut ChaCha20Rng::seed_from_u64(7)).unwrap();

        let proof = make();
        assert!(
            verify_range_proof(&commitment, &proof),
            "KAT range proof must verify against its commitment"
        );
        let wrong = PedersenCommitment::commit(amount.as_atomic() + 1, &blinding);
        assert!(
            !verify_range_proof(&wrong, &proof),
            "range proof must NOT verify against a different commitment"
        );
        let bytes = borsh::to_vec(&proof).unwrap();
        assert_eq!(
            bytes,
            borsh::to_vec(&make()).unwrap(),
            "BP+ proof must be byte-reproducible for fixed inputs + RNG seed"
        );
        assert_eq!(hex::encode(Sha256::digest(&bytes)), "4dee4016c291c6246c381f509b70f94f94819f81e19bd212018a01bdff239ac0");
    }

    #[test]
    fn test_commitment_creation() {
        let amount = Amount::from_atomic(1_000_000_000);
        let (commitment, blinding) = commit(&mut OsRng, amount);

        // Verify the commitment
        assert!(verify_commitment(&commitment, amount, &blinding));

        // Wrong amount should fail
        let wrong_amount = Amount::from_atomic(999_999_999);
        assert!(!verify_commitment(&commitment, wrong_amount, &blinding));
    }

    #[test]
    fn test_create_and_verify_range_proof() {
        let amount = Amount::from_atomic(500_000_000);
        let (commitment, blinding) = commit(&mut OsRng, amount);

        let proof = create_range_proof(amount, &blinding, &mut OsRng).unwrap();

        // With BP+ from genesis, all proofs are version 3
        assert_eq!(proof.version, RANGE_PROOF_VERSION_BP_PLUS);
        assert!(!proof.is_empty());
        assert!(verify_range_proof(&commitment, &proof));
    }

    #[test]
    fn test_range_proof_prevents_overflow() {
        // This should work - valid amount
        let valid_amount = Amount::from_atomic(u64::MAX / 2);
        let (commitment, blinding) = commit(&mut OsRng, valid_amount);
        let proof = create_range_proof(valid_amount, &blinding, &mut OsRng).unwrap();
        assert!(verify_range_proof(&commitment, &proof));
    }

    #[test]
    fn test_empty_proof() {
        let proof = RangeProof::empty();
        assert!(proof.is_empty());
        assert_eq!(proof.size(), 1);
    }

    #[test]
    fn test_aggregated_proof() {
        // Use 2 outputs (typical transaction: recipient + change)
        let amounts = vec![
            Amount::from_atomic(100_000_000),
            Amount::from_atomic(200_000_000),
        ];

        let blindings: Vec<BlindingFactor> =
            (0..2).map(|_| BlindingFactor::random(&mut OsRng)).collect();

        let commitments: Vec<PedersenCommitment> = amounts
            .iter()
            .zip(blindings.iter())
            .map(|(a, b)| PedersenCommitment::commit(a.as_atomic(), b))
            .collect();

        let proof = create_aggregated_range_proof(&amounts, &blindings, &mut OsRng).unwrap();

        assert!(!proof.is_empty());
        assert!(verify_range_proofs(&commitments, &proof));
    }

    #[test]
    fn test_wrong_commitment_fails() {
        let amount = Amount::from_atomic(1_000_000);
        let (_, blinding) = commit(&mut OsRng, amount);

        let proof = create_range_proof(amount, &blinding, &mut OsRng).unwrap();

        // Create a different commitment
        let wrong_amount = Amount::from_atomic(2_000_000);
        let (wrong_commitment, _) = commit(&mut OsRng, wrong_amount);

        // Verification should fail
        assert!(!verify_range_proof(&wrong_commitment, &proof));
    }

    #[test]
    fn test_proof_serialization() {
        let amount = Amount::from_atomic(123_456_789);
        let (_, blinding) = commit(&mut OsRng, amount);

        let proof = create_range_proof(amount, &blinding, &mut OsRng).unwrap();
        // R-6: try_to_bytes — panicking form deprecated.
        let bytes = proof.try_to_bytes().unwrap();
        let restored = RangeProof::from_bytes(&bytes).unwrap();

        assert_eq!(proof.version, restored.version);
        assert_eq!(proof.data, restored.data);
    }

    #[test]
    fn test_aggregated_proof_three_outputs() {
        // 3 outputs: asset recipient + CYNC change + asset change
        // Non-power-of-2; verifies that padding works correctly.
        let amounts = vec![
            Amount::from_atomic(50_000_000),
            Amount::from_atomic(100_000_000),
            Amount::from_atomic(50_000_000),
        ];

        let blindings: Vec<BlindingFactor> =
            (0..3).map(|_| BlindingFactor::random(&mut OsRng)).collect();

        let commitments: Vec<PedersenCommitment> = amounts
            .iter()
            .zip(blindings.iter())
            .map(|(a, b)| PedersenCommitment::commit(a.as_atomic(), b))
            .collect();

        let proof = create_aggregated_range_proof(&amounts, &blindings, &mut OsRng).unwrap();

        assert!(!proof.is_empty());
        assert!(verify_range_proofs(&commitments, &proof));
    }

    #[test]
    fn test_aggregated_proof_five_outputs() {
        // 5 outputs: verifies padding to 8
        let amounts: Vec<Amount> = (1..=5)
            .map(|i| Amount::from_atomic(i * 1_000_000))
            .collect();

        let blindings: Vec<BlindingFactor> =
            (0..5).map(|_| BlindingFactor::random(&mut OsRng)).collect();

        let commitments: Vec<PedersenCommitment> = amounts
            .iter()
            .zip(blindings.iter())
            .map(|(a, b)| PedersenCommitment::commit(a.as_atomic(), b))
            .collect();

        let proof = create_aggregated_range_proof(&amounts, &blindings, &mut OsRng).unwrap();

        assert!(!proof.is_empty());
        assert!(verify_range_proofs(&commitments, &proof));
    }

    // ─── BP+ tests ──────────────────────────────────────────────────────

    #[test]
    fn test_bp_plus_single_proof() {
        let amount = Amount::from_atomic(500_000_000);
        let (commitment, blinding) = commit(&mut OsRng, amount);

        let proof = create_range_proof_bp_plus(amount, &blinding, &mut OsRng).unwrap();
        assert_eq!(proof.version, RANGE_PROOF_VERSION_BP_PLUS);
        assert!(!proof.is_empty());
        assert!(verify_range_proof_bp_plus(&commitment, &proof));

        // With BP+ from genesis, verify_range_proof also delegates to BP+
        assert!(verify_range_proof(&commitment, &proof));
        assert!(verify_range_proof_dispatch(
            &commitment,
            &proof,
            BULLETPROOFS_PLUS_HEIGHT
        ));
    }

    #[test]
    fn test_bp_plus_aggregated_proof() {
        let amounts = vec![
            Amount::from_atomic(100_000_000),
            Amount::from_atomic(200_000_000),
        ];
        let blindings: Vec<BlindingFactor> =
            (0..2).map(|_| BlindingFactor::random(&mut OsRng)).collect();
        let commitments: Vec<PedersenCommitment> = amounts
            .iter()
            .zip(blindings.iter())
            .map(|(a, b)| PedersenCommitment::commit(a.as_atomic(), b))
            .collect();

        let proof =
            create_aggregated_range_proof_bp_plus(&amounts, &blindings, &mut OsRng).unwrap();
        assert_eq!(proof.version, RANGE_PROOF_VERSION_BP_PLUS);
        assert!(verify_range_proofs_bp_plus(&commitments, &proof));
        assert!(verify_range_proofs_dispatch(
            &commitments,
            &proof,
            BULLETPROOFS_PLUS_HEIGHT
        ));
    }

    #[test]
    fn test_bp_plus_proof_not_empty() {
        // With BP+ from genesis, verify proofs are non-empty and valid
        let amount = Amount::from_atomic(1_000_000);
        let blinding = BlindingFactor::random(&mut OsRng);
        let commitment = PedersenCommitment::commit(amount.as_atomic(), &blinding);

        let proof = create_range_proof_bp_plus(amount, &blinding, &mut OsRng).unwrap();
        assert!(!proof.is_empty());
        assert!(proof.data.len() > 0);
        assert!(verify_range_proof_bp_plus(&commitment, &proof));
    }

    #[test]
    fn test_height_dispatch_creation() {
        let amount = Amount::from_atomic(42_000_000);
        let blinding = BlindingFactor::random(&mut OsRng);
        let commitment = PedersenCommitment::commit(amount.as_atomic(), &blinding);

        // With BULLETPROOFS_PLUS_HEIGHT = 0, all heights produce BP+ proofs
        let proof = create_range_proof_for_height(amount, &blinding, &mut OsRng, 0).unwrap();
        assert_eq!(proof.version, RANGE_PROOF_VERSION_BP_PLUS);
        assert!(verify_range_proof_dispatch(&commitment, &proof, 0));

        let proof_high =
            create_range_proof_for_height(amount, &blinding, &mut OsRng, 100_000).unwrap();
        assert_eq!(proof_high.version, RANGE_PROOF_VERSION_BP_PLUS);
        assert!(verify_range_proof_dispatch(
            &commitment,
            &proof_high,
            100_000
        ));
    }

    #[test]
    fn test_bp_plus_wrong_commitment_fails() {
        let amount = Amount::from_atomic(1_000_000);
        let blinding = BlindingFactor::random(&mut OsRng);
        let proof = create_range_proof_bp_plus(amount, &blinding, &mut OsRng).unwrap();

        let (wrong_commitment, _) = commit(&mut OsRng, Amount::from_atomic(2_000_000));
        assert!(!verify_range_proof_bp_plus(&wrong_commitment, &proof));
    }

    #[test]
    fn test_bp_plus_three_outputs() {
        // 3 outputs: non-power-of-2 padding test
        let amounts = vec![
            Amount::from_atomic(50_000_000),
            Amount::from_atomic(100_000_000),
            Amount::from_atomic(50_000_000),
        ];
        let blindings: Vec<BlindingFactor> =
            (0..3).map(|_| BlindingFactor::random(&mut OsRng)).collect();
        let commitments: Vec<PedersenCommitment> = amounts
            .iter()
            .zip(blindings.iter())
            .map(|(a, b)| PedersenCommitment::commit(a.as_atomic(), b))
            .collect();

        let proof =
            create_aggregated_range_proof_bp_plus(&amounts, &blindings, &mut OsRng).unwrap();
        assert!(verify_range_proofs_bp_plus(&commitments, &proof));
    }

    #[test]
    fn test_power_of_2_padding_boundary() {
        // 4 outputs (power of 2) - no padding needed
        let amounts_4: Vec<Amount> = (1..=4)
            .map(|i| Amount::from_atomic(i * 1_000_000))
            .collect();
        let blindings_4: Vec<BlindingFactor> =
            (0..4).map(|_| BlindingFactor::random(&mut OsRng)).collect();
        let commitments_4: Vec<PedersenCommitment> = amounts_4
            .iter()
            .zip(blindings_4.iter())
            .map(|(a, b)| PedersenCommitment::commit(a.as_atomic(), b))
            .collect();
        let proof_4 = create_aggregated_range_proof(&amounts_4, &blindings_4, &mut OsRng).unwrap();
        assert!(verify_range_proofs(&commitments_4, &proof_4));

        // 5 outputs (not power of 2) - must pad to 8
        let amounts_5: Vec<Amount> = (1..=5)
            .map(|i| Amount::from_atomic(i * 1_000_000))
            .collect();
        let blindings_5: Vec<BlindingFactor> =
            (0..5).map(|_| BlindingFactor::random(&mut OsRng)).collect();
        let commitments_5: Vec<PedersenCommitment> = amounts_5
            .iter()
            .zip(blindings_5.iter())
            .map(|(a, b)| PedersenCommitment::commit(a.as_atomic(), b))
            .collect();
        let proof_5 = create_aggregated_range_proof(&amounts_5, &blindings_5, &mut OsRng).unwrap();
        assert!(verify_range_proofs(&commitments_5, &proof_5));
    }

    // ─── Missing-behavior coverage (appended) ───────────────────────────

    #[test]
    fn commitment_from_bytes_checked_accepts_valid_rejects_noncanonical() {
        // Valid canonical commitment round-trips through the checked constructor.
        let (c, _) = commit(&mut OsRng, Amount::from_atomic(123_456));
        assert!(PedersenCommitment::from_bytes_checked(c.to_bytes()).is_some());

        // Non-canonical 32 bytes that do not decompress to a Ristretto point.
        assert!(PedersenCommitment::from_bytes_checked([0xFFu8; 32]).is_none());
    }

    #[test]
    fn checked_add_sub_return_none_on_invalid_point() {
        let (valid, _) = commit(&mut OsRng, Amount::from_atomic(7_000));
        let (valid2, _) = commit(&mut OsRng, Amount::from_atomic(9_000));
        // Operand whose bytes never decompress to a valid point.
        let invalid = PedersenCommitment::from_bytes_unchecked([0xFFu8; 32]);

        // Invalid operand on either side yields None (no panic).
        assert!(valid.checked_add(&invalid).is_none());
        assert!(invalid.checked_add(&valid).is_none());
        assert!(valid.checked_sub(&invalid).is_none());
        assert!(invalid.checked_sub(&valid).is_none());

        // Sanity: two valid commitments still combine.
        assert!(valid.checked_add(&valid2).is_some());
        assert!(valid.checked_sub(&valid2).is_some());
    }

    #[test]
    fn add_operator_returns_identity_on_invalid_point() {
        use curve25519_dalek::traits::Identity;

        let (valid, _) = commit(&mut OsRng, Amount::from_atomic(11_000));
        let invalid = PedersenCommitment::from_bytes_unchecked([0xFFu8; 32]);
        // The identity fallback the operator uses (H7-FIX).
        let identity =
            PedersenCommitment::from_bytes_unchecked(RistrettoPoint::identity().compress().to_bytes());

        // Both the by-value and by-ref Add impls fall back to identity, no panic.
        assert_eq!(invalid + valid, identity);
        assert_eq!(valid + invalid, identity);
        assert_eq!(valid + &invalid, identity);
    }

    #[test]
    fn create_aggregated_range_proof_rejects_length_mismatch() {
        let amounts = vec![Amount::from_atomic(1_000), Amount::from_atomic(2_000)];
        let blindings = vec![BlindingFactor::random(&mut OsRng)]; // len 1 != 2
        assert!(create_aggregated_range_proof(&amounts, &blindings, &mut OsRng).is_err());
    }

    #[test]
    fn create_aggregated_range_proof_empty_returns_empty_proof() {
        let proof = create_aggregated_range_proof(&[], &[], &mut OsRng).unwrap();
        assert!(proof.is_empty());
        assert_eq!(proof.version, RANGE_PROOF_VERSION_BP_PLUS);
    }

    #[test]
    fn create_aggregated_range_proof_rejects_over_max_aggregation() {
        let count = MAX_AGGREGATION + 1;
        let amounts: Vec<Amount> = (0..count)
            .map(|i| Amount::from_atomic((i as u64) + 1))
            .collect();
        let blindings: Vec<BlindingFactor> =
            (0..count).map(|_| BlindingFactor::random(&mut OsRng)).collect();
        assert!(create_aggregated_range_proof(&amounts, &blindings, &mut OsRng).is_err());
    }

    #[test]
    fn verify_range_proofs_empty_commitments_requires_empty_proof() {
        // Empty commitments accepted only with an empty proof.
        assert!(verify_range_proofs(&[], &RangeProof::empty()));

        // Empty commitments with a non-empty proof must be rejected.
        let amount = Amount::from_atomic(5_000);
        let (_, blinding) = commit(&mut OsRng, amount);
        let nonempty = create_range_proof(amount, &blinding, &mut OsRng).unwrap();
        assert!(!nonempty.is_empty());
        assert!(!verify_range_proofs(&[], &nonempty));
    }

    #[test]
    fn verify_range_proofs_dispatch_gates_off_wrong_version() {
        // Build a real BP+ (v3) aggregated proof + its commitments.
        let amounts = vec![Amount::from_atomic(100_000), Amount::from_atomic(200_000)];
        let blindings: Vec<BlindingFactor> =
            (0..2).map(|_| BlindingFactor::random(&mut OsRng)).collect();
        let commitments: Vec<PedersenCommitment> = amounts
            .iter()
            .zip(blindings.iter())
            .map(|(a, b)| PedersenCommitment::commit(a.as_atomic(), b))
            .collect();
        let proof = create_aggregated_range_proof(&amounts, &blindings, &mut OsRng).unwrap();

        // Correct version at a height where BP+ is active verifies.
        assert!(verify_range_proofs_dispatch(
            &commitments,
            &proof,
            BULLETPROOFS_PLUS_HEIGHT
        ));

        // C-2: a v2-tagged proof at a BP+-active height is gated off (false),
        // preventing a pre-fork proof version from validating post-activation.
        let wrong_version = RangeProof {
            version: RANGE_PROOF_VERSION,
            data: proof.data.clone(),
        };
        assert!(!verify_range_proofs_dispatch(
            &commitments,
            &wrong_version,
            BULLETPROOFS_PLUS_HEIGHT
        ));
    }

    #[test]
    fn verify_coinbase_output_matches_zero_blinding() {
        let amount = 1_000_000u64;
        // Coinbase commitment uses a zero blinding factor.
        let c = PedersenCommitment::commit(amount, &BlindingFactor::zero());
        assert!(verify_coinbase_output(&c, amount));

        // Wrong expected amount must not match.
        assert!(!verify_coinbase_output(&c, amount + 1));

        // A random-blinding commitment to the same amount must not match the
        // zero-blinding coinbase form.
        let (random_blinded, _) = commit(&mut OsRng, Amount::from_atomic(amount));
        assert!(!verify_coinbase_output(&random_blinded, amount));
    }

    #[test]
    fn blinding_factor_zeroize_wipes_scalar() {
        use zeroize::Zeroize;
        let mut bf = BlindingFactor::from_bytes([7u8; 32]);
        assert_ne!(bf.to_bytes(), [0u8; 32]);
        bf.zeroize();
        assert_eq!(bf.to_bytes(), [0u8; 32]);
    }

    #[test]
    fn blinding_factor_scalar_arithmetic() {
        let a = BlindingFactor::from_bytes([3u8; 32]);
        let b = BlindingFactor::from_bytes([5u8; 32]);

        // (a + b) - b == a
        let sum = a.add(&b);
        let back = sum.sub(&b);
        assert_eq!(back.to_bytes(), a.to_bytes());

        // zero is the additive identity, and encodes to all-zero bytes.
        let z = BlindingFactor::zero();
        assert_eq!(z.to_bytes(), [0u8; 32]);
        assert_eq!(a.add(&z).to_bytes(), a.to_bytes());
    }
}
