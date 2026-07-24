//! # Selective Disclosure Proofs for CoinCync 1.0
//!
//! Allows wallet holders to prove specific facts about their transactions
//! and balances WITHOUT revealing private data. Enables:
//! - Exchange compliance (prove balance >= threshold)
//! - Output ownership (prove you control a stealth address)
//! - Tax reporting (prove total received in a period)
//! - Source attestation (prove a key image came from your wallet)
//!
//! All proofs are:
//! - Non-interactive (Fiat-Shamir transform)
//! - Domain-separated (no cross-proof forgery)
//! - Self-contained (verifier only needs proof + public chain data)

use borsh::{BorshDeserialize, BorshSerialize};
use curve25519_dalek::{ristretto::CompressedRistretto, scalar::Scalar};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use sha3::{Digest, Sha3_512};
use std::collections::HashSet;
use zeroize::Zeroize;

use crate::crypto::{
    create_range_proof, hash_to_point, hash_to_scalar, verify_range_proof, BlindingFactor,
    KeyImage, PedersenCommitment, PublicPoint, RangeProof, SecretScalar,
};
use crate::error::{Error, Result};
use crate::primitives::{hash_domain, Hash, PublicKey, SecretKey};
use subtle::ConstantTimeEq;

// =============================================================================
// PROOF TYPES
// =============================================================================

/// Disclosure proof type identifier
#[derive(
    Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, BorshSerialize, BorshDeserialize,
)]
#[borsh(use_discriminant = true)]
pub enum DisclosureType {
    /// Prove balance >= threshold
    Balance = 1,
    /// Prove ownership of a specific output
    Ownership = 2,
    /// Prove total received in a time range
    Sum = 3,
    /// Prove a key image came from your wallet
    Source = 4,
}

/// Reference to an on-chain output
#[derive(
    Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize, BorshSerialize, BorshDeserialize,
)]
pub struct OutputRef {
    pub tx_hash: Hash,
    pub output_index: u8,
}

// =============================================================================
// 1. BALANCE PROOF - "My balance is at least X"
// =============================================================================

/// Proves that a Pedersen commitment hides a value >= threshold.
///
/// Protocol:
/// 1. Prover knows: C = v*H + r*G, value v, blinding r
/// 2. Prover creates: C' = (v - threshold)*H + r'*G with fresh blinding r'
/// 3. Prover provides Bulletproof range proof on C' (proves v - threshold >= 0)
/// 4. Prover creates Schnorr proof that C - threshold*H and C' commit to the
///    same value (i.e., prover knows the blinding factor difference r - r')
///
/// Verifier:
/// 1. Compute delta = C - threshold*H
/// 2. Check Schnorr proof: prover knows `d` such that `delta - C' = d*G`
/// 3. Check range proof on C' (proves the adjusted value is non-negative)
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BalanceProof {
    /// The minimum balance being proved
    pub threshold: u64,
    /// Adjusted commitment C' = commit(v - threshold, r')
    pub adjusted_commitment: [u8; 32],
    /// Bulletproof range proof on the adjusted commitment
    pub range_proof: RangeProof,
    /// Schnorr proof of blinding factor difference: (R, s)
    /// Proves knowledge of d such that (C - threshold*H) - C' = d*G
    pub schnorr_r: [u8; 32],
    pub schnorr_s: [u8; 32],
    /// The original on-chain commitment
    pub original_commitment: [u8; 32],
    /// When this proof was created
    pub timestamp: u64,
}

/// Create a proof that a commitment hides a value >= threshold.
///
/// # Arguments
/// * `value` - The actual value committed to
/// * `blinding` - The blinding factor for the commitment
/// * `commitment` - The on-chain Pedersen commitment
/// * `threshold` - The minimum value to prove
///
/// # Returns
/// A `BalanceProof` that can be verified without knowing the actual value.
pub fn create_balance_proof(
    value: u64,
    blinding: &BlindingFactor,
    commitment: &PedersenCommitment,
    threshold: u64,
) -> Result<BalanceProof> {
    if value < threshold {
        return Err(Error::CryptoError(
            "Cannot prove balance: value is less than threshold".into(),
        ));
    }

    let adjusted_value = value - threshold;
    let adjusted_blinding = BlindingFactor::random(&mut OsRng);

    // C' = commit(v - threshold, r')
    let adjusted_commitment = PedersenCommitment::commit(adjusted_value, &adjusted_blinding);

    // Range proof on C' (proves v - threshold >= 0)
    let range_proof = create_range_proof(
        crate::primitives::Amount::from_atomic(adjusted_value),
        &adjusted_blinding,
        &mut OsRng,
    )?;

    // Schnorr proof that (C - threshold*H) - C' = d*G where d = r - r'
    // delta = C - threshold*H = v*H + r*G - threshold*H = (v-threshold)*H + r*G
    // delta - C' = (v-threshold)*H + r*G - (v-threshold)*H - r'*G = (r - r')*G
    // So d = r - r'
    let d = blinding.sub(&adjusted_blinding);

    // Schnorr: R = k*G, c = H(R || delta || C'), s = k - c*d
    //
    // AUDIT (R-18 fix, 2026-07-02): the pre-fix code did
    //   `let k_scalar = SecretScalar::random(...); let k = *k_scalar.as_scalar();`
    // which copies the Schnorr nonce OUT of its `ZeroizeOnDrop`
    // wrapper into a raw `Scalar` on the stack. When `k_scalar`
    // dropped, its ZeroizeOnDrop wiped its own copy — but the raw
    // `k: Scalar` at L137 remained on the stack unzeroized. Schnorr
    // nonce recovery is fatal (nonce reveal → private key: see
    // Sony PS3 ECDSA disaster 2010, MtGox ECDSA-r reuse 2013,
    // Bitcoin's BIP 340 §Security "Any leakage of k is fatal"). We
    // now operate on `k_scalar.as_scalar()` throughout and explicitly
    // zeroize the derived `d_scalar` + `blinding_diff_bytes` (R-19)
    // before return.
    let k_scalar = SecretScalar::random(&mut OsRng);

    let r_point =
        (k_scalar.as_scalar() * curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT).compress();

    // Challenge (64-byte SHA3-512 hash to avoid modular reduction bias)
    let mut challenge_hasher = Sha3_512::new();
    challenge_hasher.update(b"COINCYNC_BALANCE_PROOF_v1");
    challenge_hasher.update(r_point.as_bytes());
    challenge_hasher.update(commitment.as_bytes());
    challenge_hasher.update(adjusted_commitment.as_bytes());
    challenge_hasher.update(&threshold.to_le_bytes());
    let c = Scalar::from_bytes_mod_order_wide(&challenge_hasher.finalize().into());

    // Response: s = k - c * d.
    //
    // AUDIT (R-19 fix, 2026-07-02): `d.to_bytes()` materialises the
    // blinding difference (r - r') as raw bytes on the stack. The
    // difference is not itself a private key, but it's linear in
    // both blinding factors — an attacker who learns `d` and knows
    // one of the blindings recovers the other. Zeroize the byte
    // buffer explicitly after we're done deriving `d_scalar`.
    let mut blinding_diff_bytes = d.to_bytes();
    let d_scalar = Scalar::from_bytes_mod_order(blinding_diff_bytes);
    blinding_diff_bytes.zeroize();
    let s = k_scalar.as_scalar() - c * d_scalar;

    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    Ok(BalanceProof {
        threshold,
        adjusted_commitment: adjusted_commitment.to_bytes(),
        range_proof,
        schnorr_r: *r_point.as_bytes(),
        schnorr_s: s.to_bytes(),
        original_commitment: commitment.to_bytes(),
        timestamp,
    })
}

/// Verify a balance proof.
///
/// Checks that the prover knows a value >= threshold committed in the
/// original commitment, without learning the actual value.
pub fn verify_balance_proof(proof: &BalanceProof) -> Result<bool> {
    // Reconstruct points
    let original = CompressedRistretto(proof.original_commitment)
        .decompress()
        .ok_or_else(|| Error::CryptoError("Invalid original commitment".into()))?;

    let adjusted = CompressedRistretto(proof.adjusted_commitment)
        .decompress()
        .ok_or_else(|| Error::CryptoError("Invalid adjusted commitment".into()))?;

    let r_point = CompressedRistretto(proof.schnorr_r)
        .decompress()
        .ok_or_else(|| Error::CryptoError("Invalid Schnorr R point".into()))?;

    // Compute delta = C - threshold*H
    // H is the value generator (generator_h in our convention)
    let h = crate::crypto::curve::generator_h();
    let threshold_scalar = Scalar::from(proof.threshold);
    let delta = original - threshold_scalar * h;

    // Recompute challenge (64-byte SHA3-512 hash to avoid modular reduction bias)
    let mut challenge_hasher = Sha3_512::new();
    challenge_hasher.update(b"COINCYNC_BALANCE_PROOF_v1");
    challenge_hasher.update(&proof.schnorr_r);
    challenge_hasher.update(&proof.original_commitment);
    challenge_hasher.update(&proof.adjusted_commitment);
    challenge_hasher.update(&proof.threshold.to_le_bytes());
    let c = Scalar::from_bytes_mod_order_wide(&challenge_hasher.finalize().into());

    // Verify Schnorr: s*G + c*(delta - C') == R.
    //
    // Canonical scalar decode via PeerScalar (2026-07-02 structural fix
    // consolidating the site-by-site canonical checks introduced earlier
    // the same day). See src/crypto/peer_scalars.rs for the class-of-bug
    // rationale (documented Monero non-canonical scalar handling class;
    // specific CVE identifier UNVERIFIED — the previously-cited
    // CVE-2017-14428 turned out to be a D-Link firmware issue, not the
    // Monero scalar bug). PeerScalar::decode returns
    // Err if the 32-byte input isn't a canonical curve25519 encoding — no
    // silent mod-order reduction.
    let s = crate::crypto::PeerScalar::decode(proof.schnorr_s)?;
    let diff = delta - adjusted;
    let lhs = s.as_scalar() * curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT + c * diff;

    // SECURITY (C11-FIX): Constant-time comparison prevents timing side-channel attacks
    if lhs
        .compress()
        .as_bytes()
        .ct_eq(r_point.compress().as_bytes())
        .unwrap_u8()
        != 1
    {
        return Ok(false);
    }

    // Verify range proof on adjusted commitment
    // Already validated via decompress() above, but use checked variant for defense-in-depth
    let adj_commitment = PedersenCommitment::from_bytes_checked(proof.adjusted_commitment)
        .ok_or_else(|| Error::CryptoError("Invalid adjusted commitment for range proof".into()))?;
    Ok(verify_range_proof(&adj_commitment, &proof.range_proof))
}

// =============================================================================
// 2. OWNERSHIP PROOF - "I own this output"
// =============================================================================

/// Proves ownership of a transaction output by demonstrating knowledge of
/// the one-time secret key corresponding to the stealth address.
///
/// Protocol (Schnorr signature):
/// 1. Prover knows: secret key x such that P = x*G (stealth address)
/// 2. Prover creates: R = k*G for random k
/// 3. Challenge: c = H("COINCYNC_OWNERSHIP_v1" || R || P || tx_hash || idx || message)
/// 4. Response: s = k + c*x
/// 5. Verifier checks: s*G == R + c*P
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct OwnershipProof {
    /// Transaction containing the output
    pub tx_hash: Hash,
    /// Index of the output in the transaction
    pub output_index: u8,
    /// The stealth address (one-time public key) on-chain
    pub stealth_address: PublicKey,
    /// Schnorr R = k*G
    pub schnorr_r: [u8; 32],
    /// Schnorr s = k + c*x
    pub schnorr_s: [u8; 32],
    /// Challenge message (e.g., "Exchange XYZ compliance check 2024-01-15")
    pub message: Vec<u8>,
    /// When this proof was created
    pub timestamp: u64,
}

/// Create a proof of ownership for a transaction output.
///
/// # Arguments
/// * `tx_hash` - Hash of the transaction containing the output
/// * `output_index` - Index of the output
/// * `stealth_address` - The on-chain stealth address (public key)
/// * `one_time_secret` - The secret key for this stealth address
/// * `message` - Challenge message (binds proof to a specific context)
pub fn create_ownership_proof(
    tx_hash: &Hash,
    output_index: u8,
    stealth_address: &PublicKey,
    one_time_secret: &SecretKey,
    message: &[u8],
) -> Result<OwnershipProof> {
    // Verify the secret key matches the stealth address
    let secret_scalar = SecretScalar::from_bytes(*one_time_secret.as_bytes());
    let expected_public = secret_scalar.to_public();
    if expected_public.to_bytes() != *stealth_address.as_bytes() {
        return Err(Error::CryptoError(
            "Secret key does not match stealth address".into(),
        ));
    }

    // Generate random nonce k
    let k = SecretScalar::random(&mut OsRng);
    let r_point = k.to_public();

    // Challenge: c = H(domain || R || P || tx_hash || idx || message)
    let challenge_hash = hash_domain(
        b"COINCYNC_OWNERSHIP_v1",
        &[
            &r_point.to_bytes()[..],
            stealth_address.as_bytes().as_slice(),
            tx_hash.as_bytes(),
            &[output_index],
            message,
        ]
        .concat(),
    );
    let c = hash_to_scalar(challenge_hash.as_bytes());

    // Response: s = k + c*x
    let c_scalar = SecretScalar::from_scalar(c);
    let cx = c_scalar.mul(&secret_scalar);
    let s = k.add(&cx);

    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    Ok(OwnershipProof {
        tx_hash: *tx_hash,
        output_index,
        stealth_address: *stealth_address,
        schnorr_r: r_point.to_bytes(),
        schnorr_s: s.to_bytes(),
        message: message.to_vec(),
        timestamp,
    })
}

/// Verify an ownership proof.
///
/// Checks that the prover knows the secret key for the stealth address.
/// The verifier should confirm that stealth_address matches the on-chain output.
pub fn verify_ownership_proof(proof: &OwnershipProof) -> Result<bool> {
    // Decompress points
    let r_point = PublicPoint::from_bytes(proof.schnorr_r)
        .ok_or_else(|| Error::CryptoError("Invalid Schnorr R point".into()))?;

    let p_point = PublicPoint::from_bytes(*proof.stealth_address.as_bytes())
        .ok_or_else(|| Error::CryptoError("Invalid stealth address point".into()))?;

    // Recompute challenge
    let challenge_hash = hash_domain(
        b"COINCYNC_OWNERSHIP_v1",
        &[
            &proof.schnorr_r[..],
            proof.stealth_address.as_bytes().as_slice(),
            proof.tx_hash.as_bytes(),
            &[proof.output_index],
            &proof.message,
        ]
        .concat(),
    );
    let c = hash_to_scalar(challenge_hash.as_bytes());

    // Verify: s*G == R + c*P.
    // Canonical scalar decode via PeerScalar (2026-07-02 structural consolidation).
    let s = crate::crypto::PeerScalar::decode(proof.schnorr_s)?;
    let s_wrapped = crate::crypto::SecretScalar::from_scalar(*s.as_scalar());
    let lhs = s_wrapped.to_public(); // s*G

    let c_scalar = SecretScalar::from_scalar(c);
    let cp = p_point.mul(&c_scalar); // c*P
    let rhs = r_point.add(&cp); // R + c*P

    // SECURITY (C11-FIX): Constant-time comparison prevents timing side-channel attacks
    Ok(lhs.to_bytes().ct_eq(&rhs.to_bytes()).unwrap_u8() == 1)
}

// =============================================================================
// 3. SUM PROOF - "I received exactly X in this time range"
// =============================================================================

/// Proves the total amount received across multiple outputs equals a claimed value.
///
/// Protocol (homomorphic commitment opening):
/// 1. Prover has N outputs with commitments C_i = v_i*H + r_i*G
/// 2. Prover reveals: total = sum(v_i) and r_sum = sum(r_i)
/// 3. Verifier checks: sum(C_i) == commit(total, r_sum)
///
/// This leverages the homomorphic property of Pedersen commitments:
/// sum(C_i) = sum(v_i)*H + sum(r_i)*G = total*H + r_sum*G
///
/// # SECURITY WARNING (R-20 fix, 2026-07-02)
///
/// `sum_blinding` (r_sum) is TRANSMITTED IN CLEARTEXT as part of this
/// struct. `r_sum` is the algebraic sum of every included output's
/// blinding factor. Whoever sees a SumProof:
///
///   - Can recompute every included output's commitment opening if
///     they ALSO know the per-output amounts (from other disclosures
///     or on-chain view keys).
///   - Can PROVE that a wallet controls those outputs by re-checking
///     `sum(C_i) == commit(claimed_total, r_sum)`.
///   - CANNOT decrypt other unrelated outputs (r_sum only covers the
///     N declared outputs).
///
/// This trade-off is deliberate — the SumProof is designed for audit
/// / tax-reporting flows where the wallet holder VOLUNTARILY discloses
/// ownership of a batch of outputs. But callers must understand:
/// sending a SumProof over an insecure channel gives the recipient
/// PERMANENT provable evidence that this wallet received these
/// specific outputs. Do NOT create SumProofs for reasons other than
/// intentional disclosure, and do NOT store them alongside the wallet
/// file (a leaked file leaks r_sum → cross-audit-scenario correlation).
///
/// The pre-fix docstring was silent on the secret-transmission
/// property, which made it look like a zero-knowledge proof (which it
/// isn't — this is a disclosure proof, not a ZK proof).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SumProof {
    /// Sum-proof transcript version.
    pub version: u8,
    /// The claimed total amount
    pub claimed_total: u64,
    /// References to the on-chain outputs included in the sum
    pub output_refs: Vec<OutputRef>,
    /// Combined blinding factor: r_sum = sum(r_i)
    pub sum_blinding: [u8; 32],
    /// Block height range these outputs fall within
    pub height_range: (u64, u64),
    /// When this proof was created
    pub timestamp: u64,
    /// Domain-separated challenge hash (binds all proof fields)
    pub challenge: Hash,
}

const SUM_PROOF_VERSION: u8 = 2;

fn sum_output_refs_are_unique(output_refs: &[OutputRef]) -> bool {
    let mut seen = HashSet::with_capacity(output_refs.len());
    output_refs
        .iter()
        .all(|output_ref| seen.insert((output_ref.tx_hash, output_ref.output_index)))
}

fn sum_proof_challenge(
    version: u8,
    claimed_total: u64,
    output_refs: &[OutputRef],
    sum_blinding: &[u8; 32],
    height_range: (u64, u64),
    timestamp: u64,
) -> Hash {
    let mut transcript = Vec::with_capacity(65 + output_refs.len() * 33);
    transcript.push(version);
    transcript.extend_from_slice(&claimed_total.to_le_bytes());
    transcript.extend_from_slice(sum_blinding);
    transcript.extend_from_slice(&(output_refs.len() as u32).to_le_bytes());
    for output_ref in output_refs {
        transcript.extend_from_slice(output_ref.tx_hash.as_bytes());
        transcript.push(output_ref.output_index);
    }
    transcript.extend_from_slice(&height_range.0.to_le_bytes());
    transcript.extend_from_slice(&height_range.1.to_le_bytes());
    transcript.extend_from_slice(&timestamp.to_le_bytes());
    hash_domain(b"COINCYNC_SUM_PROOF_v2", &transcript)
}

fn sum_proof_transcript_is_valid(proof: &SumProof) -> bool {
    proof.version == SUM_PROOF_VERSION
        && proof.height_range.0 <= proof.height_range.1
        && sum_output_refs_are_unique(&proof.output_refs)
        && proof.challenge
            == sum_proof_challenge(
                proof.version,
                proof.claimed_total,
                &proof.output_refs,
                &proof.sum_blinding,
                proof.height_range,
                proof.timestamp,
            )
}

/// Create a proof of total received amount.
///
/// # Arguments
/// * `outputs` - List of (amount, blinding_factor, tx_hash, output_index) tuples
/// * `height_range` - Block height range the outputs fall within
pub fn create_sum_proof(
    outputs: &[(u64, BlindingFactor, Hash, u8)],
    height_range: (u64, u64),
) -> Result<SumProof> {
    if outputs.is_empty() {
        return Err(Error::CryptoError(
            "Cannot create sum proof with no outputs".into(),
        ));
    }
    if height_range.0 > height_range.1 {
        return Err(Error::CryptoError("Invalid sum-proof height range".into()));
    }

    // Compute total and combined blinding
    let mut total: u64 = 0;
    let mut blinding_sum = BlindingFactor::zero();
    let mut output_refs = Vec::with_capacity(outputs.len());

    for (amount, blinding, tx_hash, idx) in outputs {
        total = total
            .checked_add(*amount)
            .ok_or_else(|| Error::CryptoError("Sum overflow".into()))?;
        blinding_sum = blinding_sum.add(blinding);
        output_refs.push(OutputRef {
            tx_hash: *tx_hash,
            output_index: *idx,
        });
    }
    if !sum_output_refs_are_unique(&output_refs) {
        return Err(Error::CryptoError(
            "A sum proof cannot include the same output more than once".into(),
        ));
    }

    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    let version = SUM_PROOF_VERSION;
    let sum_blinding = blinding_sum.to_bytes();
    let challenge = sum_proof_challenge(
        version,
        total,
        &output_refs,
        &sum_blinding,
        height_range,
        timestamp,
    );

    Ok(SumProof {
        version,
        claimed_total: total,
        output_refs,
        sum_blinding,
        height_range,
        timestamp,
        challenge,
    })
}

/// Verify a sum proof against on-chain commitments.
///
/// # Arguments
/// * `proof` - The sum proof to verify
/// * `on_chain_commitments` - The Pedersen commitments from the blockchain,
///   in the same order as proof.output_refs
///
/// The verifier must look up the commitments from the chain independently.
pub fn verify_sum_proof(
    proof: &SumProof,
    on_chain_commitments: &[PedersenCommitment],
) -> Result<bool> {
    if proof.output_refs.len() != on_chain_commitments.len() {
        return Err(Error::CryptoError(
            "Output ref count doesn't match commitment count".into(),
        ));
    }

    if on_chain_commitments.is_empty() {
        return Ok(false);
    }
    if !sum_proof_transcript_is_valid(proof) {
        return Ok(false);
    }

    let blinding = BlindingFactor::from_bytes(proof.sum_blinding);

    // Sum all on-chain commitments: sum(C_i)
    // Use curve25519-dalek-ng (same library as PedersenCommitment internals)
    use curve25519_dalek::traits::Identity;
    let mut sum_point = curve25519_dalek::ristretto::RistrettoPoint::identity();
    for c in on_chain_commitments {
        match curve25519_dalek::ristretto::CompressedRistretto(c.to_bytes()).decompress() {
            Some(point) => sum_point = sum_point + point,
            None => {
                return Err(Error::CryptoError(
                    "Invalid on-chain commitment point".into(),
                ))
            }
        }
    }

    // Compute expected: commit(total, r_sum)
    let expected = PedersenCommitment::commit(proof.claimed_total, &blinding);
    let expected_point =
        match curve25519_dalek::ristretto::CompressedRistretto(expected.to_bytes()).decompress() {
            Some(p) => p,
            None => return Err(Error::CryptoError("Invalid expected commitment".into())),
        };

    // Check: sum(C_i) == commit(total, r_sum)
    // SECURITY (C11-FIX): Constant-time comparison prevents timing side-channel attacks
    Ok(sum_point
        .compress()
        .as_bytes()
        .ct_eq(expected_point.compress().as_bytes())
        .unwrap_u8()
        == 1)
}

// =============================================================================
// 4. SOURCE PROOF - "This key image came from my wallet"
// =============================================================================

/// Proves that a key image was generated from a specific public key,
/// demonstrating the prover controls the spending key.
///
/// Protocol (dual-base Schnorr):
/// Given public key P = x*G and key image I = x*H_p(P):
/// 1. Prover picks random k
/// 2. R1 = k*G, R2 = k*H_p(P)
/// 3. c = H("COINCYNC_SOURCE_v1" || R1 || R2 || P || I || message)
/// 4. s = k - c*x
/// 5. Verifier checks: s*G + c*P == R1 AND s*H_p(P) + c*I == R2
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SourceProof {
    /// The key image being claimed
    pub key_image: KeyImage,
    /// The public key P = x*G
    pub public_key: PublicKey,
    /// R1 = k*G
    pub r1: [u8; 32],
    /// R2 = k*H_p(P)
    pub r2: [u8; 32],
    /// Response scalar s = k - c*x
    pub s: [u8; 32],
    /// Challenge message (binds proof to context)
    pub message: Vec<u8>,
    /// When this proof was created
    pub timestamp: u64,
}

/// Create a proof that a key image was generated from your secret key.
///
/// # Arguments
/// * `secret_key` - The secret key x
/// * `public_key` - The corresponding public key P = x*G
/// * `key_image` - The key image I = x*H_p(P)
/// * `message` - Context-binding message
pub fn create_source_proof(
    secret_key: &SecretKey,
    public_key: &PublicKey,
    key_image: &KeyImage,
    message: &[u8],
) -> Result<SourceProof> {
    let x = SecretScalar::from_bytes(*secret_key.as_bytes());

    // Verify P = x*G
    let expected_p = x.to_public();
    if expected_p.to_bytes() != *public_key.as_bytes() {
        return Err(Error::CryptoError(
            "Secret key doesn't match public key".into(),
        ));
    }

    // Verify I = x*H_p(P)
    let hp = hash_to_point(public_key.as_bytes());
    let expected_i = PublicPoint::from_point(x.as_scalar() * &hp);
    if expected_i.to_bytes() != key_image.to_bytes() {
        return Err(Error::CryptoError(
            "Key image doesn't match key pair".into(),
        ));
    }

    // Random nonce k
    let k = SecretScalar::random(&mut OsRng);

    // R1 = k*G
    let r1 = k.to_public();

    // R2 = k*H_p(P)
    let r2 = PublicPoint::from_point(k.as_scalar() * &hp);

    // Challenge: c = H(domain || R1 || R2 || P || I || message)
    let challenge_hash = hash_domain(
        b"COINCYNC_SOURCE_v1",
        &[
            &r1.to_bytes()[..],
            &r2.to_bytes()[..],
            public_key.as_bytes().as_slice(),
            &key_image.to_bytes()[..],
            message,
        ]
        .concat(),
    );
    let c = hash_to_scalar(challenge_hash.as_bytes());

    // s = k - c*x
    let c_scalar = SecretScalar::from_scalar(c);
    let cx = c_scalar.mul(&x);
    let s = k.sub(&cx);

    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    Ok(SourceProof {
        key_image: *key_image,
        public_key: *public_key,
        r1: r1.to_bytes(),
        r2: r2.to_bytes(),
        s: s.to_bytes(),
        message: message.to_vec(),
        timestamp,
    })
}

/// Verify a source proof.
///
/// Checks that the prover knows the secret key behind both the public key
/// and the key image, proving they generated that key image.
pub fn verify_source_proof(proof: &SourceProof) -> Result<bool> {
    // Decompress all points
    let r1 = PublicPoint::from_bytes(proof.r1)
        .ok_or_else(|| Error::CryptoError("Invalid R1 point".into()))?;
    let r2 = PublicPoint::from_bytes(proof.r2)
        .ok_or_else(|| Error::CryptoError("Invalid R2 point".into()))?;
    let p = PublicPoint::from_bytes(*proof.public_key.as_bytes())
        .ok_or_else(|| Error::CryptoError("Invalid public key point".into()))?;
    let i = PublicPoint::from_bytes(proof.key_image.to_bytes())
        .ok_or_else(|| Error::CryptoError("Invalid key image point".into()))?;

    // Recompute H_p(P)
    let hp = PublicPoint::from_point(hash_to_point(proof.public_key.as_bytes()));

    // Recompute challenge
    let challenge_hash = hash_domain(
        b"COINCYNC_SOURCE_v1",
        &[
            &proof.r1[..],
            &proof.r2[..],
            proof.public_key.as_bytes().as_slice(),
            &proof.key_image.to_bytes()[..],
            &proof.message,
        ]
        .concat(),
    );
    let c = hash_to_scalar(challenge_hash.as_bytes());

    // Canonical scalar decode via PeerScalar (2026-07-02 structural consolidation).
    let s_peer = crate::crypto::PeerScalar::decode(proof.s)?;
    let s = crate::crypto::SecretScalar::from_scalar(*s_peer.as_scalar());
    let c_scalar = SecretScalar::from_scalar(c);

    // Check 1: s*G + c*P == R1
    let sg = s.to_public();
    let cp = p.mul(&c_scalar);
    let check1 = sg.add(&cp);

    // R-21 fix (2026-07-02): use constant-time comparison for BOTH
    // check1 and check2. The pre-fix code used raw `!=` on check1,
    // which is a non-ct byte comparison and breaks the C11-FIX
    // policy the check2 comment cites. Under the pre-fix code, an
    // attacker with fine-grained timing access could distinguish
    // "check1 failed early" from "check1 passed, check2 ran" —
    // narrowing the failure mode leaks structural information about
    // the proof state. Also: we must NOT short-circuit — compute
    // both checks in constant time and AND them, or the wall-clock
    // still leaks (fewer instructions when check1 fails).
    let check1_ok = check1.to_bytes().ct_eq(&r1.to_bytes());

    // Check 2: s*H_p(P) + c*I == R2
    let s_hp = hp.mul(&s);
    let c_i = i.mul(&c_scalar);
    let check2 = s_hp.add(&c_i);

    // SECURITY (C11-FIX + R-21): both comparisons ct_eq, ANDed with
    // constant-time subtle::Choice.
    let check2_ok = check2.to_bytes().ct_eq(&r2.to_bytes());
    Ok((check1_ok & check2_ok).unwrap_u8() == 1)
}

// =============================================================================
// CONTAINER TYPE
// =============================================================================

/// A self-contained disclosure proof that can be exported and shared.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DisclosureProof {
    /// Protocol version
    pub version: u8,
    /// Type of proof
    pub proof_type: DisclosureType,
    /// Serialized inner proof data
    pub proof_data: Vec<u8>,
    /// Creation timestamp
    pub created_at: u64,
    /// Optional expiry timestamp
    pub expires_at: Option<u64>,
    /// Human-readable label
    pub prover_label: String,
}

impl DisclosureProof {
    /// Wrap a BalanceProof into a DisclosureProof container
    pub fn from_balance(
        proof: &BalanceProof,
        label: &str,
        expires_at: Option<u64>,
    ) -> Result<Self> {
        let data =
            serde_json::to_vec(proof).map_err(|e| Error::SerializationError(e.to_string()))?;
        Ok(DisclosureProof {
            version: 1,
            proof_type: DisclosureType::Balance,
            proof_data: data,
            created_at: proof.timestamp,
            expires_at,
            prover_label: label.to_string(),
        })
    }

    /// Wrap an OwnershipProof
    pub fn from_ownership(
        proof: &OwnershipProof,
        label: &str,
        expires_at: Option<u64>,
    ) -> Result<Self> {
        let data =
            serde_json::to_vec(proof).map_err(|e| Error::SerializationError(e.to_string()))?;
        Ok(DisclosureProof {
            version: 1,
            proof_type: DisclosureType::Ownership,
            proof_data: data,
            created_at: proof.timestamp,
            expires_at,
            prover_label: label.to_string(),
        })
    }

    /// Wrap a SumProof
    pub fn from_sum(proof: &SumProof, label: &str, expires_at: Option<u64>) -> Result<Self> {
        let data =
            serde_json::to_vec(proof).map_err(|e| Error::SerializationError(e.to_string()))?;
        Ok(DisclosureProof {
            version: 1,
            proof_type: DisclosureType::Sum,
            proof_data: data,
            created_at: proof.timestamp,
            expires_at,
            prover_label: label.to_string(),
        })
    }

    /// Wrap a SourceProof
    pub fn from_source(proof: &SourceProof, label: &str, expires_at: Option<u64>) -> Result<Self> {
        let data =
            serde_json::to_vec(proof).map_err(|e| Error::SerializationError(e.to_string()))?;
        Ok(DisclosureProof {
            version: 1,
            proof_type: DisclosureType::Source,
            proof_data: data,
            created_at: proof.timestamp,
            expires_at,
            prover_label: label.to_string(),
        })
    }

    /// Export to JSON string
    pub fn to_json(&self) -> Result<String> {
        serde_json::to_string_pretty(self).map_err(|e| Error::SerializationError(e.to_string()))
    }

    /// Import from JSON string
    pub fn from_json(json: &str) -> Result<Self> {
        serde_json::from_str(json).map_err(|e| Error::SerializationError(e.to_string()))
    }

    /// Check if the proof has expired
    pub fn is_expired(&self) -> bool {
        if let Some(expires) = self.expires_at {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();
            now > expires
        } else {
            false
        }
    }

    /// Verify the contained proof (dispatches to the appropriate verifier)
    pub fn verify(&self) -> Result<bool> {
        if self.is_expired() {
            return Ok(false);
        }

        match self.proof_type {
            DisclosureType::Balance => {
                let inner: BalanceProof = serde_json::from_slice(&self.proof_data)
                    .map_err(|e| Error::SerializationError(e.to_string()))?;
                verify_balance_proof(&inner)
            }
            DisclosureType::Ownership => {
                let inner: OwnershipProof = serde_json::from_slice(&self.proof_data)
                    .map_err(|e| Error::SerializationError(e.to_string()))?;
                verify_ownership_proof(&inner)
            }
            DisclosureType::Sum => {
                // Sum proof requires on-chain commitments, can't verify standalone
                Err(Error::CryptoError(
                    "SumProof requires on-chain commitments for verification. Use verify_sum_proof() directly.".into()
                ))
            }
            DisclosureType::Source => {
                let inner: SourceProof = serde_json::from_slice(&self.proof_data)
                    .map_err(|e| Error::SerializationError(e.to_string()))?;
                verify_source_proof(&inner)
            }
        }
    }
}

// =============================================================================
// CHAIN ANCHORING
// =============================================================================
//
// The `verify_*` functions above prove only that a disclosure proof is
// *internally consistent*: the range-proof math holds, the Schnorr signature
// verifies, the homomorphic sum balances. Every one of them reads the on-chain
// reference (`original_commitment`, `stealth_address`, the output commitments)
// from data the PROVER supplied. That is sufficient to prove "I know a secret
// for this commitment/key", but NOT "this commitment/key is a real output in
// CoinCync's canonical chain history" (issues #252 / #253, junbyjun1238).
//
// A prover can hand you a fully-valid `OwnershipProof` for a stealth key they
// genuinely control that was never mined, or a `BalanceProof` over a commitment
// they invented. The offline verifiers return `true` for all of these.
//
// The `*_anchored` functions below close that gap. They take a `ChainAnchor` —
// the real on-chain output, resolved by the verifier from THEIR OWN trusted
// chain view — and enforce that the proof's self-declared reference matches it.
//
// Where the anchor comes from is load-bearing for privacy. It MUST come from:
//   - the verifier's own full-node canonical chain view, or
//   - a block/transaction the verifier obtained and hash-checked themselves.
// It must NEVER be self-supplied by the prover, and asking a *remote* node for
// the specific output leaks which outputs the verifier cares about — callers
// that anchor against a remote source must warn the operator (see the wallet
// CLI's `disclose verify-*` commands).

/// A real on-chain output, resolved from the verifier's own trusted chain view,
/// used to anchor a disclosure proof to actual chain state.
///
/// All fields come from the same `TxOutput` at the referenced `(tx_hash,
/// output_index)`: `commitment` is `TxOutput::commitment`, `stealth_address` is
/// `TxOutput::stealth_address.as_bytes()`. Construct it from the verifier's own
/// chain view — never from prover-supplied data.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ChainAnchor {
    /// The exact output this anchor was resolved from.
    pub output_ref: OutputRef,
    /// The on-chain Pedersen commitment for the referenced output.
    pub commitment: [u8; 32],
    /// The on-chain stealth (one-time) address for the referenced output.
    pub stealth_address: [u8; 32],
    /// Canonical-chain height containing the output.
    pub block_height: u64,
}

impl ChainAnchor {
    /// Build an anchor from one output resolved through a trusted chain view.
    pub fn new(
        output_ref: OutputRef,
        commitment: [u8; 32],
        stealth_address: [u8; 32],
        block_height: u64,
    ) -> Self {
        Self {
            output_ref,
            commitment,
            stealth_address,
            block_height,
        }
    }
}

/// Outcome of an anchored disclosure-proof check. Distinguishing the two failure
/// modes matters: a forged/malformed proof is a different thing to report than a
/// cryptographically-sound proof that simply doesn't correspond to the on-chain
/// output it claims.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AnchorVerdict {
    /// The proof's cryptography holds AND it binds to the supplied on-chain output.
    Valid,
    /// The proof's cryptography is malformed or forged — it fails even offline.
    CryptoInvalid,
    /// The cryptography is sound, but the on-chain reference the prover declared
    /// does not match the trusted on-chain output. The proof is unanchored: it
    /// proves knowledge of a secret for *some* commitment/key, not the one on chain.
    AnchorMismatch,
}

impl AnchorVerdict {
    /// True only for [`AnchorVerdict::Valid`].
    pub fn is_valid(self) -> bool {
        matches!(self, AnchorVerdict::Valid)
    }
}

/// Verify a balance proof against an output in canonical chain history.
///
/// Returns [`AnchorVerdict::AnchorMismatch`] when the proof is cryptographically
/// valid but the commitment differs from the referenced output. Ring signatures
/// hide which member was spent, so this deliberately makes no unspentness claim.
pub fn verify_balance_proof_anchored(
    proof: &BalanceProof,
    anchor: &ChainAnchor,
) -> Result<AnchorVerdict> {
    match verify_balance_proof(proof) {
        Ok(true) => {}
        Ok(false) | Err(_) => return Ok(AnchorVerdict::CryptoInvalid),
    }
    // Commitments are public on-chain values; a plain compare is correct here
    // (no secret-dependent branch).
    if proof.original_commitment != anchor.commitment {
        return Ok(AnchorVerdict::AnchorMismatch);
    }
    Ok(AnchorVerdict::Valid)
}

/// Verify an ownership proof AND that its stealth address is the one on chain.
///
/// The caller resolves `anchor` for the proof's own `(tx_hash, output_index)`:
/// look up that output in the trusted chain view and pass its real
/// `stealth_address`. A cryptographically-valid proof whose declared stealth
/// address is not the on-chain one yields [`AnchorVerdict::AnchorMismatch`].
pub fn verify_ownership_proof_anchored(
    proof: &OwnershipProof,
    anchor: &ChainAnchor,
) -> Result<AnchorVerdict> {
    match verify_ownership_proof(proof) {
        Ok(true) => {}
        Ok(false) | Err(_) => return Ok(AnchorVerdict::CryptoInvalid),
    }
    let proof_output_ref = OutputRef {
        tx_hash: proof.tx_hash,
        output_index: proof.output_index,
    };
    if proof_output_ref != anchor.output_ref
        || *proof.stealth_address.as_bytes() != anchor.stealth_address
    {
        return Ok(AnchorVerdict::AnchorMismatch);
    }
    Ok(AnchorVerdict::Valid)
}

/// Verify a sum proof against on-chain outputs resolved from its `output_refs`.
///
/// Each anchor must carry the exact [`OutputRef`] it was independently resolved
/// from. References must be unique and every anchor height must fall within the
/// proof's declared range.
pub fn verify_sum_proof_anchored<F>(
    proof: &SumProof,
    mut resolve_anchor: F,
) -> Result<AnchorVerdict>
where
    F: FnMut(&OutputRef) -> Result<Option<ChainAnchor>>,
{
    if !sum_proof_transcript_is_valid(proof) {
        return Ok(AnchorVerdict::CryptoInvalid);
    }
    let mut commitments = Vec::with_capacity(proof.output_refs.len());
    for output_ref in &proof.output_refs {
        let Some(anchor) = resolve_anchor(output_ref)? else {
            return Ok(AnchorVerdict::AnchorMismatch);
        };
        if output_ref != &anchor.output_ref
            || !(proof.height_range.0..=proof.height_range.1).contains(&anchor.block_height)
        {
            return Ok(AnchorVerdict::AnchorMismatch);
        }
        match PedersenCommitment::from_bytes_checked(anchor.commitment) {
            Some(c) => commitments.push(c),
            // An anchor that isn't a valid curve point can't be a real on-chain
            // commitment — treat it as a mismatch, not a crypto forgery.
            None => return Ok(AnchorVerdict::AnchorMismatch),
        }
    }
    match verify_sum_proof(proof, &commitments) {
        Ok(true) => Ok(AnchorVerdict::Valid),
        Ok(false) => Ok(AnchorVerdict::AnchorMismatch),
        Err(_) => Ok(AnchorVerdict::CryptoInvalid),
    }
}

/// Verify a source proof AND that its key image is actually spent on chain.
///
/// `key_image_spent_on_chain` is resolved by the caller from their own chain view
/// (`UtxoDb::is_spent`). A cryptographically-valid proof for a key image that
/// does not appear in the chain's spent set yields [`AnchorVerdict::AnchorMismatch`]:
/// the prover proved they *could* generate that key image, not that it was ever
/// used to spend a real output.
pub fn verify_source_proof_anchored(
    proof: &SourceProof,
    key_image_spent_on_chain: bool,
) -> Result<AnchorVerdict> {
    match verify_source_proof(proof) {
        Ok(true) => {}
        Ok(false) | Err(_) => return Ok(AnchorVerdict::CryptoInvalid),
    }
    if !key_image_spent_on_chain {
        return Ok(AnchorVerdict::AnchorMismatch);
    }
    Ok(AnchorVerdict::Valid)
}

// =============================================================================
// TESTS
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::{KeyImage as CurveKeyImage, SecretScalar as CurveSecretScalar};
    use rand::rngs::OsRng;

    fn make_test_keys() -> (SecretKey, PublicKey) {
        let secret = CurveSecretScalar::random(&mut OsRng);
        let public = secret.to_public();
        let sk = SecretKey::from_bytes(secret.to_bytes());
        let pk = PublicKey::from_bytes(public.to_bytes());
        (sk, pk)
    }

    // ---- Balance Proof ----

    #[test]
    fn test_balance_proof_valid() {
        let value = 1_000_000u64;
        let blinding = BlindingFactor::random(&mut OsRng);
        let commitment = PedersenCommitment::commit(value, &blinding);

        let threshold = 500_000u64;
        let proof = create_balance_proof(value, &blinding, &commitment, threshold).unwrap();

        assert!(verify_balance_proof(&proof).unwrap());
        assert_eq!(proof.threshold, threshold);
    }

    #[test]
    fn test_balance_proof_exact_threshold() {
        let value = 1_000_000u64;
        let blinding = BlindingFactor::random(&mut OsRng);
        let commitment = PedersenCommitment::commit(value, &blinding);

        // Proving balance >= exact amount should work (v - threshold = 0, which is valid)
        let proof = create_balance_proof(value, &blinding, &commitment, value).unwrap();
        assert!(verify_balance_proof(&proof).unwrap());
    }

    #[test]
    fn test_balance_proof_insufficient() {
        let value = 100u64;
        let blinding = BlindingFactor::random(&mut OsRng);
        let commitment = PedersenCommitment::commit(value, &blinding);

        // Trying to prove balance >= 200 when we only have 100 should fail
        let result = create_balance_proof(value, &blinding, &commitment, 200);
        assert!(result.is_err());
    }

    #[test]
    fn test_balance_proof_wrong_commitment() {
        let value = 1_000_000u64;
        let blinding = BlindingFactor::random(&mut OsRng);
        let commitment = PedersenCommitment::commit(value, &blinding);

        // Create valid proof
        let proof = create_balance_proof(value, &blinding, &commitment, 500_000).unwrap();

        // Tamper with the original commitment
        let mut tampered = proof.clone();
        let fake_blinding = BlindingFactor::random(&mut OsRng);
        let fake_commitment = PedersenCommitment::commit(2_000_000, &fake_blinding);
        tampered.original_commitment = fake_commitment.to_bytes();

        // Should fail verification
        assert!(!verify_balance_proof(&tampered).unwrap());
    }

    // ---- Ownership Proof ----

    #[test]
    fn test_ownership_proof_valid() {
        let (sk, pk) = make_test_keys();
        let tx_hash = Hash::from_bytes([1u8; 32]);
        let message = b"Exchange compliance check 2024";

        let proof = create_ownership_proof(&tx_hash, 0, &pk, &sk, message).unwrap();
        assert!(verify_ownership_proof(&proof).unwrap());
    }

    #[test]
    fn test_ownership_proof_wrong_key() {
        let (_sk, pk) = make_test_keys();
        let (wrong_sk, _) = make_test_keys();
        let tx_hash = Hash::from_bytes([1u8; 32]);

        // Try to create proof with wrong secret key
        let result = create_ownership_proof(&tx_hash, 0, &pk, &wrong_sk, b"test");
        assert!(result.is_err());
    }

    #[test]
    fn test_ownership_proof_different_message() {
        let (sk, pk) = make_test_keys();
        let tx_hash = Hash::from_bytes([1u8; 32]);

        let proof = create_ownership_proof(&tx_hash, 0, &pk, &sk, b"message 1").unwrap();

        // Tamper with the message
        let mut tampered = proof;
        tampered.message = b"message 2".to_vec();

        // Should fail because challenge changes
        assert!(!verify_ownership_proof(&tampered).unwrap());
    }

    // ---- Sum Proof ----

    #[test]
    fn test_sum_proof_valid() {
        let b1 = BlindingFactor::random(&mut OsRng);
        let b2 = BlindingFactor::random(&mut OsRng);
        let b3 = BlindingFactor::random(&mut OsRng);

        let v1 = 100_000u64;
        let v2 = 200_000u64;
        let v3 = 300_000u64;

        let c1 = PedersenCommitment::commit(v1, &b1);
        let c2 = PedersenCommitment::commit(v2, &b2);
        let c3 = PedersenCommitment::commit(v3, &b3);

        let h1 = Hash::from_bytes([1u8; 32]);
        let h2 = Hash::from_bytes([2u8; 32]);
        let h3 = Hash::from_bytes([3u8; 32]);

        let outputs = vec![(v1, b1, h1, 0u8), (v2, b2, h2, 1u8), (v3, b3, h3, 0u8)];

        let proof = create_sum_proof(&outputs, (0, 100)).unwrap();
        assert_eq!(proof.claimed_total, 600_000);

        let commitments = vec![c1, c2, c3];
        assert!(verify_sum_proof(&proof, &commitments).unwrap());
    }

    #[test]
    fn test_sum_proof_wrong_total() {
        let b1 = BlindingFactor::random(&mut OsRng);
        let v1 = 100_000u64;
        let c1 = PedersenCommitment::commit(v1, &b1);
        let h1 = Hash::from_bytes([1u8; 32]);

        let outputs = vec![(v1, b1, h1, 0u8)];
        let mut proof = create_sum_proof(&outputs, (0, 100)).unwrap();

        // Tamper with claimed total
        proof.claimed_total = 999_999;

        // Should fail because challenge hash won't match
        assert!(!verify_sum_proof(&proof, &[c1]).unwrap());
    }

    #[test]
    fn test_sum_proof_wrong_commitments() {
        let b1 = BlindingFactor::random(&mut OsRng);
        let v1 = 100_000u64;
        let h1 = Hash::from_bytes([1u8; 32]);

        let outputs = vec![(v1, b1, h1, 0u8)];
        let proof = create_sum_proof(&outputs, (0, 100)).unwrap();

        // Provide wrong commitment
        let wrong_blinding = BlindingFactor::random(&mut OsRng);
        let wrong_commitment = PedersenCommitment::commit(200_000, &wrong_blinding);

        assert!(!verify_sum_proof(&proof, &[wrong_commitment]).unwrap());
    }

    // ---- Source Proof ----

    #[test]
    fn test_source_proof_valid() {
        let secret = CurveSecretScalar::random(&mut OsRng);
        let public = secret.to_public();
        let ki = CurveKeyImage::from_secret(&secret);

        let sk = SecretKey::from_bytes(secret.to_bytes());
        let pk = PublicKey::from_bytes(public.to_bytes());

        let proof = create_source_proof(&sk, &pk, &ki, b"compliance check").unwrap();
        assert!(verify_source_proof(&proof).unwrap());
    }

    #[test]
    fn test_source_proof_wrong_key() {
        let secret = CurveSecretScalar::random(&mut OsRng);
        let public = secret.to_public();
        let ki = CurveKeyImage::from_secret(&secret);

        let wrong_secret = CurveSecretScalar::random(&mut OsRng);
        let wrong_sk = SecretKey::from_bytes(wrong_secret.to_bytes());
        let pk = PublicKey::from_bytes(public.to_bytes());

        // Wrong secret key should fail
        let result = create_source_proof(&wrong_sk, &pk, &ki, b"test");
        assert!(result.is_err());
    }

    #[test]
    fn test_source_proof_tampered_message() {
        let secret = CurveSecretScalar::random(&mut OsRng);
        let public = secret.to_public();
        let ki = CurveKeyImage::from_secret(&secret);

        let sk = SecretKey::from_bytes(secret.to_bytes());
        let pk = PublicKey::from_bytes(public.to_bytes());

        let mut proof = create_source_proof(&sk, &pk, &ki, b"original").unwrap();
        proof.message = b"tampered".to_vec();

        assert!(!verify_source_proof(&proof).unwrap());
    }

    // ---- Container ----

    #[test]
    fn test_disclosure_serialization() {
        let (sk, pk) = make_test_keys();
        let tx_hash = Hash::from_bytes([1u8; 32]);

        let ownership = create_ownership_proof(&tx_hash, 0, &pk, &sk, b"test").unwrap();
        let container = DisclosureProof::from_ownership(&ownership, "test proof", None).unwrap();

        // Round-trip JSON
        let json = container.to_json().unwrap();
        let recovered = DisclosureProof::from_json(&json).unwrap();

        assert_eq!(recovered.version, 1);
        assert_eq!(recovered.proof_type, DisclosureType::Ownership);
        assert_eq!(recovered.prover_label, "test proof");

        // Verify recovered proof
        assert!(recovered.verify().unwrap());
    }

    #[test]
    fn test_disclosure_expiry() {
        let (sk, pk) = make_test_keys();
        let tx_hash = Hash::from_bytes([1u8; 32]);

        let ownership = create_ownership_proof(&tx_hash, 0, &pk, &sk, b"test").unwrap();

        // Create with already-expired timestamp
        let container = DisclosureProof::from_ownership(&ownership, "expired", Some(1)).unwrap();

        assert!(container.is_expired());
        assert!(!container.verify().unwrap());
    }

    #[test]
    fn test_proofs_domain_separated() {
        // Ensure ownership proof data can't be verified as a source proof
        let (sk, pk) = make_test_keys();
        let tx_hash = Hash::from_bytes([1u8; 32]);

        let ownership = create_ownership_proof(&tx_hash, 0, &pk, &sk, b"test").unwrap();
        let container = DisclosureProof::from_ownership(&ownership, "test", None).unwrap();

        // Manually change the type to Source
        let mut tampered = container;
        tampered.proof_type = DisclosureType::Source;

        // Should fail because the inner data is an OwnershipProof, not a SourceProof
        let result = tampered.verify();
        assert!(result.is_err() || !result.unwrap());
    }

    #[test]
    fn test_expired_proof_rejected() {
        let (sk, pk) = make_test_keys();
        let tx_hash = Hash::from_bytes([1u8; 32]);

        let ownership = create_ownership_proof(&tx_hash, 0, &pk, &sk, b"expiry test").unwrap();

        // Expire timestamp = 1 (epoch second 1, long in the past)
        let container =
            DisclosureProof::from_ownership(&ownership, "should expire", Some(1)).unwrap();

        assert!(
            container.is_expired(),
            "Proof with timestamp=1 should be expired"
        );
        assert!(
            !container.verify().unwrap(),
            "Expired proof must fail verification"
        );

        // Non-expired proof should pass
        let future_ts = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
            + 86400;
        let valid_container =
            DisclosureProof::from_ownership(&ownership, "valid", Some(future_ts)).unwrap();
        assert!(!valid_container.is_expired());
        assert!(valid_container.verify().unwrap());
    }

    // ---- Chain anchoring (issues #252 / #253) ----

    fn test_chain_anchor(
        tx_hash: Hash,
        output_index: u8,
        commitment: [u8; 32],
        stealth_address: [u8; 32],
        block_height: u64,
    ) -> ChainAnchor {
        ChainAnchor::new(
            OutputRef {
                tx_hash,
                output_index,
            },
            commitment,
            stealth_address,
            block_height,
        )
    }

    fn resolve_test_anchor(
        anchors: &[ChainAnchor],
        output_ref: &OutputRef,
    ) -> Result<Option<ChainAnchor>> {
        Ok(anchors
            .iter()
            .find(|anchor| &anchor.output_ref == output_ref)
            .cloned())
    }

    #[test]
    fn test_balance_anchored_valid() {
        let value = 1_000_000u64;
        let blinding = BlindingFactor::random(&mut OsRng);
        let commitment = PedersenCommitment::commit(value, &blinding);
        let proof = create_balance_proof(value, &blinding, &commitment, 500_000).unwrap();

        // Anchor: the on-chain output's real commitment == the one in the proof.
        let anchor = test_chain_anchor(
            Hash::from_bytes([1u8; 32]),
            0,
            commitment.to_bytes(),
            [0u8; 32],
            10,
        );
        let verdict = verify_balance_proof_anchored(&proof, &anchor).unwrap();
        assert_eq!(verdict, AnchorVerdict::Valid);
        assert!(verdict.is_valid());
    }

    #[test]
    fn test_balance_anchored_mismatch_is_the_253_attack() {
        // The prover commits to a value they do NOT hold on chain and produces a
        // perfectly valid range proof over it. Offline verification says "valid".
        let value = 5_000_000u64;
        let blinding = BlindingFactor::random(&mut OsRng);
        let invented = PedersenCommitment::commit(value, &blinding);
        let proof = create_balance_proof(value, &blinding, &invented, 1_000_000).unwrap();
        assert!(
            verify_balance_proof(&proof).unwrap(),
            "offline still passes"
        );

        // But the real on-chain output has a different commitment. Anchoring
        // rejects the proof as unanchored — this is the #253 fix.
        let on_chain = PedersenCommitment::commit(42, &BlindingFactor::random(&mut OsRng));
        let anchor = test_chain_anchor(
            Hash::from_bytes([1u8; 32]),
            0,
            on_chain.to_bytes(),
            [0u8; 32],
            10,
        );
        let verdict = verify_balance_proof_anchored(&proof, &anchor).unwrap();
        assert_eq!(verdict, AnchorVerdict::AnchorMismatch);
        assert!(!verdict.is_valid());
    }

    #[test]
    fn test_balance_anchored_crypto_invalid() {
        let value = 1_000_000u64;
        let blinding = BlindingFactor::random(&mut OsRng);
        let commitment = PedersenCommitment::commit(value, &blinding);
        let mut proof = create_balance_proof(value, &blinding, &commitment, 500_000).unwrap();
        // Corrupt the range proof so the crypto itself fails.
        let fake = PedersenCommitment::commit(9, &BlindingFactor::random(&mut OsRng));
        proof.original_commitment = fake.to_bytes();
        let anchor = test_chain_anchor(
            Hash::from_bytes([1u8; 32]),
            0,
            fake.to_bytes(),
            [0u8; 32],
            10,
        );
        let verdict = verify_balance_proof_anchored(&proof, &anchor).unwrap();
        // Even though the anchor now matches the (tampered) commitment, the
        // Schnorr/range math no longer holds → CryptoInvalid takes precedence.
        assert_eq!(verdict, AnchorVerdict::CryptoInvalid);
    }

    #[test]
    fn test_ownership_anchored_valid() {
        let (sk, pk) = make_test_keys();
        let tx_hash = Hash::from_bytes([7u8; 32]);
        let proof = create_ownership_proof(&tx_hash, 2, &pk, &sk, b"audit").unwrap();

        let anchor = test_chain_anchor(tx_hash, 2, [0u8; 32], *pk.as_bytes(), 10);
        let verdict = verify_ownership_proof_anchored(&proof, &anchor).unwrap();
        assert_eq!(verdict, AnchorVerdict::Valid);
    }

    #[test]
    fn test_ownership_anchored_mismatch_is_the_253_attack() {
        // Prover controls key K and makes a valid ownership proof binding K to
        // (tx_hash, idx). Offline verification passes.
        let (sk, pk) = make_test_keys();
        let tx_hash = Hash::from_bytes([7u8; 32]);
        let proof = create_ownership_proof(&tx_hash, 2, &pk, &sk, b"audit").unwrap();
        assert!(
            verify_ownership_proof(&proof).unwrap(),
            "offline still passes"
        );

        // But the real on-chain output at (tx_hash, idx) has a DIFFERENT stealth
        // address. The prover never owned that output. Anchoring rejects it.
        let (_other_sk, other_pk) = make_test_keys();
        let anchor = test_chain_anchor(tx_hash, 2, [0u8; 32], *other_pk.as_bytes(), 10);
        let verdict = verify_ownership_proof_anchored(&proof, &anchor).unwrap();
        assert_eq!(verdict, AnchorVerdict::AnchorMismatch);
    }

    #[test]
    fn test_ownership_anchored_rejects_wrong_output_ref() {
        let (sk, pk) = make_test_keys();
        let tx_hash = Hash::from_bytes([7u8; 32]);
        let proof = create_ownership_proof(&tx_hash, 2, &pk, &sk, b"audit").unwrap();
        let anchor = test_chain_anchor(tx_hash, 3, [0u8; 32], *pk.as_bytes(), 10);

        assert_eq!(
            verify_ownership_proof_anchored(&proof, &anchor).unwrap(),
            AnchorVerdict::AnchorMismatch
        );
    }

    #[test]
    fn test_sum_anchored_valid_and_mismatch() {
        let b1 = BlindingFactor::random(&mut OsRng);
        let b2 = BlindingFactor::random(&mut OsRng);
        let (v1, v2) = (100_000u64, 250_000u64);
        let c1 = PedersenCommitment::commit(v1, &b1);
        let c2 = PedersenCommitment::commit(v2, &b2);
        let outputs = vec![
            (v1, b1, Hash::from_bytes([1u8; 32]), 0u8),
            (v2, b2, Hash::from_bytes([2u8; 32]), 1u8),
        ];
        let proof = create_sum_proof(&outputs, (0, 100)).unwrap();

        // Correct anchors → Valid.
        let anchors = vec![
            test_chain_anchor(outputs[0].2, outputs[0].3, c1.to_bytes(), [0u8; 32], 10),
            test_chain_anchor(outputs[1].2, outputs[1].3, c2.to_bytes(), [0u8; 32], 20),
        ];
        assert_eq!(
            verify_sum_proof_anchored(&proof, |output_ref| {
                resolve_test_anchor(&anchors, output_ref)
            })
            .unwrap(),
            AnchorVerdict::Valid
        );

        // A missing independently-resolved reference is an anchor mismatch.
        assert_eq!(
            verify_sum_proof_anchored(&proof, |output_ref| {
                resolve_test_anchor(&anchors[..1], output_ref)
            })
            .unwrap(),
            AnchorVerdict::AnchorMismatch
        );

        // Right count, one wrong on-chain commitment → AnchorMismatch.
        let wrong = PedersenCommitment::commit(999, &BlindingFactor::random(&mut OsRng));
        let bad_anchors = vec![
            test_chain_anchor(outputs[0].2, outputs[0].3, c1.to_bytes(), [0u8; 32], 10),
            test_chain_anchor(outputs[1].2, outputs[1].3, wrong.to_bytes(), [0u8; 32], 20),
        ];
        assert_eq!(
            verify_sum_proof_anchored(&proof, |output_ref| {
                resolve_test_anchor(&bad_anchors, output_ref)
            })
            .unwrap(),
            AnchorVerdict::AnchorMismatch
        );

        let mut swapped = anchors.clone();
        swapped.swap(0, 1);
        assert_eq!(
            verify_sum_proof_anchored(&proof, |output_ref| {
                resolve_test_anchor(&swapped, output_ref)
            })
            .unwrap(),
            AnchorVerdict::Valid
        );

        let mut wrong_height = anchors;
        wrong_height[0].block_height = 101;
        assert_eq!(
            verify_sum_proof_anchored(&proof, |output_ref| {
                resolve_test_anchor(&wrong_height, output_ref)
            })
            .unwrap(),
            AnchorVerdict::AnchorMismatch
        );
    }

    #[test]
    fn test_sum_proof_rejects_duplicate_outputs_and_ref_tampering() {
        let blinding = BlindingFactor::random(&mut OsRng);
        let tx_hash = Hash::from_bytes([1u8; 32]);
        let duplicate_outputs = vec![
            (100_000u64, blinding.clone(), tx_hash, 0u8),
            (100_000u64, blinding.clone(), tx_hash, 0u8),
        ];
        assert!(create_sum_proof(&duplicate_outputs, (0, 100)).is_err());

        let proof = create_sum_proof(&duplicate_outputs[..1], (0, 100)).unwrap();
        let commitment = PedersenCommitment::commit(100_000, &blinding);
        let mut duplicated = proof.clone();
        duplicated.claimed_total = 200_000;
        duplicated
            .output_refs
            .push(duplicated.output_refs[0].clone());
        duplicated.sum_blinding = blinding.add(&blinding).to_bytes();
        duplicated.challenge = sum_proof_challenge(
            duplicated.version,
            duplicated.claimed_total,
            &duplicated.output_refs,
            &duplicated.sum_blinding,
            duplicated.height_range,
            duplicated.timestamp,
        );
        assert!(!verify_sum_proof(&duplicated, &[commitment, commitment]).unwrap());

        let mut tampered = proof.clone();
        tampered.output_refs[0].output_index = 1;
        assert!(!verify_sum_proof(&tampered, &[commitment]).unwrap());
        let anchor = test_chain_anchor(tx_hash, 1, commitment.to_bytes(), [0u8; 32], 10);
        assert_eq!(
            verify_sum_proof_anchored(&tampered, |output_ref| {
                resolve_test_anchor(std::slice::from_ref(&anchor), output_ref)
            })
            .unwrap(),
            AnchorVerdict::CryptoInvalid
        );
    }

    #[test]
    fn test_source_anchored_valid_and_mismatch() {
        let secret = CurveSecretScalar::random(&mut OsRng);
        let public = secret.to_public();
        let ki = CurveKeyImage::from_secret(&secret);
        let sk = SecretKey::from_bytes(secret.to_bytes());
        let pk = PublicKey::from_bytes(public.to_bytes());
        let proof = create_source_proof(&sk, &pk, &ki, b"compliance").unwrap();

        // Key image is in the chain's spent set → Valid.
        assert_eq!(
            verify_source_proof_anchored(&proof, true).unwrap(),
            AnchorVerdict::Valid
        );
        // Key image was never actually spent on chain → AnchorMismatch: the
        // prover proved they *could* generate it, not that a real spend used it.
        assert_eq!(
            verify_source_proof_anchored(&proof, false).unwrap(),
            AnchorVerdict::AnchorMismatch
        );
    }
}
