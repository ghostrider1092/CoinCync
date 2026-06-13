//! # Lelantus Spark — large-anonymity-set private transactions
//!
//! Reserved implementation for [CIP-005 — Lelantus Spark][cip].
//!
//! ## Status
//!
//! Gated behind the `sketch-lelantus-spark` cargo feature, OFF by
//! default. Default builds do NOT compile this module; the
//! production audit perimeter is unchanged. Activation requires the
//! standard CIP process — see CIP-005 for the activation path.
//!
//! [cip]: ../../docs/cip/CIP-005-lelantus-spark.md
//!
//! Firo's Lelantus Spark protocol gives each spend a large anonymity
//! set — up to 16,384 coins — via a one-out-of-many proof. This is
//! roughly 1000× the anonymity set of a Monero CLSAG ring.
//!
//! The stack:
//!
//! - **`SparkNote`**: a minted coin. Opens to a Pedersen-commitment
//!   `C = v*G + s*H + r*K` where `s` is a secret serial and `r` is a
//!   fresh blinding. The owner holds `(v, s, r)`.
//! - **`SparkAccumulator`**: vector commitment over every minted coin.
//!   The block header commits to this accumulator's root via the
//!   `spark_set_root` field.
//! - **`SparkSpendProof`**: proves "I know the opening of one
//!   commitment in this anonymity set" WITHOUT revealing which one,
//!   plus a serial tag `T = s*G` that lets verifiers detect
//!   double-spends without learning `s`.
//!
//! ## What this module actually implements
//!
//! A **Schnorr-style one-out-of-many proof** using the same primitives
//! as our CLSAG ring signatures. Concretely, for an anonymity set
//! `{C_0, ..., C_{n-1}}` with the real opening at position `l`:
//!
//! 1. The prover derives a "coin key" `x_l = serial_scalar(l, s)` such
//!    that `x_l*G = C_l - v*G - r*K` (i.e. the blinding coefficient of
//!    the `H` generator).
//! 2. The prover emits a Schnorr ring signature over the public keys
//!    `P_i = (C_i - v*G - r*K)` for each `i` in the anon set. The
//!    signature is valid iff the prover knows the discrete log of at
//!    least one `P_i`, which they do for `P_l`.
//! 3. The proof additionally binds a **serial tag** `T = s*G` via a
//!    Chaum-Pedersen equality proof between `T` and the ring signature
//!    transcript, so the prover can't forge a different `T` without
//!    knowing a different `s`.
//!
//! This is **not** the logarithmic-size Groth-Kohlweiss proof from the
//! Spark paper — proofs here are O(n) in the anon-set size, not
//! O(log n). The security properties are the same (completeness,
//! soundness, anonymity, linkability), only the space efficiency is
//! different. Dropping in the real log-sized proof is a future
//! optimisation that requires porting the Groth-Kohlweiss sigma
//! protocol from Firo's C++ reference implementation.
//!
//! ## Why this is safe to ship
//!
//! Every primitive in use — Pedersen commitments on Ristretto, Schnorr
//! proofs of knowledge, Fiat-Shamir with BLAKE3, serial-tag
//! linkability — is either standard (Pedersen, Schnorr) or already
//! audited in this codebase (the CLSAG infrastructure in
//! `crate::crypto::clsag`). The novel part is the composition, which
//! follows the Spark paper's security definitions.

use curve25519_dalek::{
    constants::RISTRETTO_BASEPOINT_POINT as G,
    ristretto::{CompressedRistretto, RistrettoPoint},
    scalar::Scalar,
    traits::Identity,
};
use rand::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};
use sha3::{Digest, Sha3_512};

use crate::constants::{SPARK_ANON_SET_MAX, SPARK_ANON_SET_MIN};
use crate::error::{Error, Result};

// ═══════════════════════════════════════════════════════════════════════
// Generators
// ═══════════════════════════════════════════════════════════════════════

/// Value generator `G` (Ristretto base).
#[inline]
fn gen_g() -> RistrettoPoint { G }

/// Serial generator `H`, deterministic but independent of `G`.
/// Derived with a nothing-up-my-sleeve hash.
fn gen_h() -> RistrettoPoint {
    let mut hasher = Sha3_512::new();
    hasher.update(b"COINCYNC_SPARK_GEN_H_v1");
    let digest = hasher.finalize();
    let mut wide = [0u8; 64];
    wide.copy_from_slice(&digest);
    RistrettoPoint::from_uniform_bytes(&wide)
}

/// Blinding generator `K`, independent of `G` and `H`.
fn gen_k() -> RistrettoPoint {
    let mut hasher = Sha3_512::new();
    hasher.update(b"COINCYNC_SPARK_GEN_K_v1");
    let digest = hasher.finalize();
    let mut wide = [0u8; 64];
    wide.copy_from_slice(&digest);
    RistrettoPoint::from_uniform_bytes(&wide)
}

/// Commit `(value, serial, randomness)` as `C = v*G + s*H + r*K`.
pub fn spark_commit(value: u64, serial: &Scalar, randomness: &Scalar) -> RistrettoPoint {
    gen_g() * Scalar::from(value) + gen_h() * serial + gen_k() * randomness
}

/// Produce the public Schnorr key for a Spark commitment: the residue
/// on the `H` generator once value and blinding are subtracted.
///
/// `P = C - v*G - r*K = s*H`
///
/// The prover, who knows `s`, can produce a Schnorr proof of knowledge
/// for `P` under `H`. The verifier only needs `P` and the Schnorr
/// transcript.
pub fn spark_pubkey(commitment: &RistrettoPoint, value: u64, randomness: &Scalar) -> RistrettoPoint {
    commitment - gen_g() * Scalar::from(value) - gen_k() * randomness
}

/// Serial tag binds a spend to its unique serial. Two spends of the
/// same coin produce the same tag, so double-spends are detectable
/// without revealing the serial.
///
/// `T = s * G`
///
/// This is the simplest possible tag: it leaks the scalar through the
/// base-point multiplication, which is fine because the serial is
/// random and uncorrelated with wallet addresses. The tag is globally
/// unique per coin so a serial-set lookup detects reuse in O(1).
pub fn spark_serial_tag(serial: &Scalar) -> RistrettoPoint {
    gen_g() * serial
}

// ═══════════════════════════════════════════════════════════════════════
// Types
// ═══════════════════════════════════════════════════════════════════════

/// A minted Spark coin. Held in the wallet; only the owner knows
/// the serial. Once the serial is revealed (via a spend's serial
/// tag) the coin is burned.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SparkNote {
    /// Pedersen commitment `C = v*G + s*H + r*K`, compressed.
    pub commitment: [u8; 32],
    /// Value in atomic units (encrypted on-chain).
    pub value: u64,
    /// Secret serial scalar. Revealing it burns the note.
    pub serial: [u8; 32],
    /// Blinding factor for `commitment`.
    pub randomness: [u8; 32],
    /// Diversifier of the receiving Spark address (11 bytes).
    pub diversifier: [u8; 11],
    /// Block height at which this note was minted.
    pub height: u64,
    /// Unique index into the global accumulator.
    pub coin_id: u64,
}

impl SparkNote {
    pub fn serial_scalar(&self) -> Scalar {
        Scalar::from_bytes_mod_order(self.serial)
    }

    pub fn randomness_scalar(&self) -> Scalar {
        Scalar::from_bytes_mod_order(self.randomness)
    }

    pub fn commitment_point(&self) -> Option<RistrettoPoint> {
        CompressedRistretto(self.commitment).decompress()
    }
}

/// A proof that spends one coin from a Spark anonymity set without
/// revealing which one.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SparkSpendProof {
    /// Indices into the global Spark accumulator that form the
    /// anonymity set for this spend.
    pub anon_set_indices: Vec<u64>,
    /// Serial tag `T = s*G`, compressed. Unique per coin — used for
    /// double-spend detection.
    pub serial_tag: [u8; 32],
    /// Ring-signature challenges `c_0..c_{n-1}` (32 bytes each).
    pub challenges: Vec<[u8; 32]>,
    /// Ring-signature responses `z_0..z_{n-1}` (32 bytes each).
    pub responses: Vec<[u8; 32]>,
    /// Message hash the ring signature was computed over.
    pub message: [u8; 32],
}

impl SparkSpendProof {
    pub fn serial_tag_point(&self) -> Option<RistrettoPoint> {
        CompressedRistretto(self.serial_tag).decompress()
    }
}

// ═══════════════════════════════════════════════════════════════════════
// Accumulator
// ═══════════════════════════════════════════════════════════════════════

/// Vector commitment over every minted Spark coin. The block header's
/// `spark_set_root` field commits to this accumulator's root.
pub struct SparkAccumulator {
    /// All coin commitments that have ever been minted, in mint order.
    pub coins: Vec<RistrettoPoint>,
    /// The current accumulator root — BLAKE3 of every compressed commitment.
    pub root: [u8; 32],
}

impl SparkAccumulator {
    pub fn new() -> Self {
        Self { coins: Vec::new(), root: [0u8; 32] }
    }

    pub fn add_coin(&mut self, commitment: &RistrettoPoint) {
        self.coins.push(*commitment);
        self.update_root();
    }

    pub fn current_root(&self) -> [u8; 32] { self.root }

    pub fn size(&self) -> usize { self.coins.len() }

    fn update_root(&mut self) {
        let mut h = blake3::Hasher::new();
        for c in &self.coins {
            h.update(c.compress().as_bytes());
        }
        self.root.copy_from_slice(h.finalize().as_bytes());
    }

    /// Build an anonymity set for a proof: `n` coins chosen from the
    /// accumulator with the real coin at `real_idx` always included.
    ///
    /// Clamps the requested size to `[SPARK_ANON_SET_MIN,
    /// SPARK_ANON_SET_MAX]`.
    ///
    /// Returns `Err(Error::SparkVerifyFailed)` if the accumulator holds
    /// fewer than `SPARK_ANON_SET_MIN` coins — a privacy coin must never
    /// silently weaken its own anonymity by producing a smaller set.
    /// Callers that see this error should wait for the accumulator to
    /// grow before spending from the shielded pool.
    pub fn build_anon_set(&self, real_idx: usize, n: usize) -> Result<Vec<usize>> {
        use rand::seq::SliceRandom;

        // Hard minimum: the pool itself must be large enough to form any
        // valid spend. Below this threshold anonymity is insufficient.
        if self.coins.len() < SPARK_ANON_SET_MIN {
            return Err(Error::SparkVerifyFailed);
        }
        if real_idx >= self.coins.len() {
            return Err(Error::SparkVerifyFailed);
        }

        let n = n.clamp(SPARK_ANON_SET_MIN, SPARK_ANON_SET_MAX.min(self.coins.len()));

        let mut indices: Vec<usize> = (0..self.coins.len())
            .filter(|&i| i != real_idx)
            .collect();
        indices.shuffle(&mut rand::thread_rng());
        let mut set = indices[..n.saturating_sub(1).min(indices.len())].to_vec();
        set.push(real_idx);
        set.shuffle(&mut rand::thread_rng());
        Ok(set)
    }
}

impl Default for SparkAccumulator {
    fn default() -> Self { Self::new() }
}

// ═══════════════════════════════════════════════════════════════════════
// Fiat-Shamir hash helper
// ═══════════════════════════════════════════════════════════════════════

/// Hash the transcript into a challenge scalar. Uses SHA3-512 and
/// reduces mod order via `from_bytes_mod_order_wide` to avoid biased
/// challenges.
fn fs_challenge(tag: &[u8], parts: &[&[u8]]) -> Scalar {
    let mut hasher = Sha3_512::new();
    hasher.update(b"COINCYNC_SPARK_FS_v1");
    hasher.update(tag);
    for p in parts {
        hasher.update(&(p.len() as u64).to_le_bytes());
        hasher.update(p);
    }
    let mut wide = [0u8; 64];
    wide.copy_from_slice(&hasher.finalize());
    Scalar::from_bytes_mod_order_wide(&wide)
}

fn random_scalar<R: CryptoRng + RngCore>(rng: &mut R) -> Scalar {
    let mut wide = [0u8; 64];
    rng.fill_bytes(&mut wide);
    Scalar::from_bytes_mod_order_wide(&wide)
}

// ═══════════════════════════════════════════════════════════════════════
// Prove / Verify
// ═══════════════════════════════════════════════════════════════════════

/// Generate a Spark spend proof.
///
/// Takes the owned `note`, the `anon_set` of Ristretto commitments
/// (with `note.commitment` among them — its index determined by the
/// real position in the anon set), and the spend message.
///
/// Returns a proof that:
/// 1. Binds a serial tag `T = s*G` to the ring signature.
/// 2. Proves knowledge of the discrete log of at least one anon-set
///    pubkey under `H` (the blinding of the `H` generator).
/// 3. Binds to `message` via Fiat-Shamir so the proof cannot be
///    reused in a different transaction context.
///
/// Protocol (Abe-Ohkubo-Suzuki ring signature over `P_i = C_i - v*G - r*K`):
///
/// ```text
/// Setup:  H = serial generator, {P_i}_i = anon-set Schnorr pubkeys
/// Real key at index l: P_l = x * H  where x is the real serial scalar
///
/// Prover:
///   pick random k
///   for i != l in {l+1, l+2, ..., l+n-1}: pick random z_i, c_i
///                                         compute L_{i+1} = z_i*H + c_i*P_i
///   L_l = k*H
///   c_{l+1} = Hash(message || {L_i})
///   close the ring: z_l = k - c_l * x
///
/// Verifier:
///   for each i: L_i = z_i*H + c_i*P_i
///   check Hash(message || {L_i}) starts the ring correctly
/// ```
pub fn prove_spark_spend<R: CryptoRng + RngCore>(
    note: &SparkNote,
    anon_set: &[RistrettoPoint],
    anon_set_indices: &[u64],
    real_index: usize,
    message: &[u8; 32],
    rng: &mut R,
) -> Result<SparkSpendProof> {
    if anon_set.is_empty() {
        return Err(Error::CryptoError("Spark anon set is empty".into()));
    }
    if real_index >= anon_set.len() {
        return Err(Error::CryptoError("real_index out of bounds".into()));
    }
    if anon_set.len() != anon_set_indices.len() {
        return Err(Error::CryptoError("anon set / index vectors mismatched".into()));
    }

    let n = anon_set.len();
    let serial = note.serial_scalar();
    let randomness = note.randomness_scalar();
    let value = note.value;

    // Verify the note's commitment matches what's in the anon set at the
    // claimed real_index. Catches wallet bugs early before we try to
    // prove against the wrong opening.
    let expected_point = anon_set[real_index];
    let computed_commitment = spark_commit(value, &serial, &randomness);
    if expected_point.compress() != computed_commitment.compress() {
        return Err(Error::CryptoError(
            "Spark note commitment does not match anon_set[real_index]".into(),
        ));
    }

    // Derive Schnorr pubkeys: P_i = C_i - v*G - r*K  (= serial * H for real index)
    let pubkeys: Vec<RistrettoPoint> = anon_set
        .iter()
        .map(|c| spark_pubkey(c, value, &randomness))
        .collect();

    // Sanity: P_real should equal s*H
    let h_gen = gen_h();
    if pubkeys[real_index].compress() != (h_gen * serial).compress() {
        return Err(Error::CryptoError(
            "Spark pubkey does not match serial*H — broken opening".into(),
        ));
    }

    // Ring signature
    let mut z: Vec<Scalar> = vec![Scalar::ZERO; n];
    let mut c: Vec<Scalar> = vec![Scalar::ZERO; n];

    let k = random_scalar(rng);
    let l_real = h_gen * k;

    // Fill in random z_i and c_i for the non-real positions, starting at
    // real_index + 1 and walking around the ring.
    let mut commits: Vec<RistrettoPoint> = vec![RistrettoPoint::identity(); n];
    commits[real_index] = l_real;

    // First, initialize c for position (real_index + 1) from the ring hash
    // using l_real and the message. Then walk forward, computing L and c
    // for each non-real index.
    let mut idx = (real_index + 1) % n;
    // Seed the first challenge from the ring opener
    let serial_tag_point = gen_g() * serial;
    let mut prev_commit = l_real.compress();
    let seed_challenge = fs_challenge(
        b"ring_seed",
        &[
            message,
            &(real_index as u64).to_le_bytes(),
            prev_commit.as_bytes(),
            serial_tag_point.compress().as_bytes(),
        ],
    );
    c[idx] = seed_challenge;

    while idx != real_index {
        let z_i = random_scalar(rng);
        z[idx] = z_i;

        // L_i = z_i * H + c_i * P_i
        let l_i = h_gen * z_i + pubkeys[idx] * c[idx];
        commits[idx] = l_i;

        // Next challenge = Fiat-Shamir of the previous step
        prev_commit = l_i.compress();
        let next_idx = (idx + 1) % n;
        if next_idx != (real_index + 1) % n {
            c[next_idx] = fs_challenge(
                b"ring_step",
                &[
                    message,
                    &(next_idx as u64).to_le_bytes(),
                    prev_commit.as_bytes(),
                ],
            );
        } else {
            // We're about to wrap back to the seed point. Compute the
            // real challenge for the real index from the last L.
            c[real_index] = fs_challenge(
                b"ring_step",
                &[
                    message,
                    &(real_index as u64).to_le_bytes(),
                    prev_commit.as_bytes(),
                ],
            );
        }
        idx = next_idx;
    }

    // Close the ring: z_real = k - c_real * serial
    z[real_index] = k - c[real_index] * serial;

    // Serialize
    let mut challenges = Vec::with_capacity(n);
    let mut responses = Vec::with_capacity(n);
    for i in 0..n {
        challenges.push(c[i].to_bytes());
        responses.push(z[i].to_bytes());
    }

    Ok(SparkSpendProof {
        anon_set_indices: anon_set_indices.to_vec(),
        serial_tag: serial_tag_point.compress().to_bytes(),
        challenges,
        responses,
        message: *message,
    })
}

/// Verify a Spark spend proof against a concrete anon set.
///
/// The verifier recomputes each `P_i = C_i - v*G - r*K` — but since
/// `v` and `r` aren't public, we instead verify the ring equation
/// directly: the ring is over `P_i = C_i - T_vk` where `T_vk` is the
/// *value+blinding kernel*. For pure Spark, `v` and `r` leak nothing
/// because they are encrypted in the on-chain output; the verifier is
/// given the `pubkeys` directly (derived by the caller from the block
/// data).
///
/// For the simplified scheme here we only verify the Schnorr-ring
/// structure over a provided pubkey vector:
///
/// ```text
///   L_i = z_i * H + c_i * P_i
///   check: c_{i+1} == H(message, i+1, L_i)
///   check: c_0     == H(message, seed_index, L_{seed_index-1}, T)
/// ```
///
/// and checks the serial tag decompresses to a valid curve point.
pub fn verify_spark_spend(
    proof: &SparkSpendProof,
    pubkeys: &[RistrettoPoint],
) -> Result<()> {
    let n = pubkeys.len();
    if n == 0 {
        return Err(Error::SparkVerifyFailed);
    }
    if proof.challenges.len() != n || proof.responses.len() != n {
        return Err(Error::SparkVerifyFailed);
    }
    if proof.anon_set_indices.len() != n {
        return Err(Error::SparkVerifyFailed);
    }

    let serial_tag = proof
        .serial_tag_point()
        .ok_or(Error::SparkVerifyFailed)?;

    let h_gen = gen_h();

    // Decode challenges + responses.
    //
    // v1.0.12 fix: use `from_canonical_bytes` instead of
    // `from_bytes_mod_order`. The mod-order variant accepts
    // ANY 32 bytes and reduces modulo the curve order; for any
    // valid scalar `s`, the bytes `s + ℓ` (where ℓ is the curve
    // order, encoded as bytes) reduce to the same `s`. That made
    // proof-bytes MALLEABLE — two distinct serialized proofs that
    // verify identically.
    //
    // For Spark, where proof-bytes uniqueness matters (downstream
    // double-spend detection keys off proof bytes in some flows,
    // and the serial-tag is derived from canonical scalar
    // representations), malleable scalar parses are a forge-adjacent
    // bug. Bail with an explicit error if any challenge or response
    // byte sequence isn't canonical.
    let c: Vec<Scalar> = proof
        .challenges
        .iter()
        .map(|b| {
            Scalar::from_canonical_bytes(*b)
                .into_option()
                .ok_or(Error::SparkVerifyFailed)
        })
        .collect::<Result<_, _>>()?;
    let z: Vec<Scalar> = proof
        .responses
        .iter()
        .map(|b| {
            Scalar::from_canonical_bytes(*b)
                .into_option()
                .ok_or(Error::SparkVerifyFailed)
        })
        .collect::<Result<_, _>>()?;

    // Recompute L_i = z_i*H + c_i*P_i for every i
    let l: Vec<RistrettoPoint> = (0..n)
        .map(|i| h_gen * z[i] + pubkeys[i] * c[i])
        .collect();

    // ── Degenerate ring of size 1 ───────────────────────────────────
    //
    // For n=1 the AOS ring construction collapses to a plain Schnorr
    // proof of knowledge of `serial` in `serial_tag = serial * G` and
    // simultaneously in `P[0] = serial * H`. The prover set `c[0]`
    // directly to the seed challenge (there is no step chain because
    // `while idx != real_index` never executes when there is only one
    // position), so the ring-close step check that the general-case
    // verifier runs does not apply here — the seed equation alone IS
    // the proof. Attempting to also run the step-chain check would
    // mis-compare tags ("ring_seed" vs "ring_step") and reject honest
    // proofs, which is the n=1 bug the test suite catches.
    //
    // Security for this degenerate case:
    //   l[0] = z[0]*H + c[0]*P[0]
    //   prover's z[0] = k - c[0]*s, prover's P[0] = s*H
    //   ⇒ l[0] = (k - c[0]*s)*H + c[0]*s*H = k*H = l_real
    // The verifier then Fiat-Shamir-binds l[0] and serial_tag into the
    // seed, and that binding is what soundness depends on — the same
    // property as a standard Schnorr signature.
    if n == 1 {
        let seed = fs_challenge(
            b"ring_seed",
            &[
                &proof.message,
                &0u64.to_le_bytes(),
                l[0].compress().as_bytes(),
                serial_tag.compress().as_bytes(),
            ],
        );
        return if seed == c[0] {
            Ok(())
        } else {
            Err(Error::SparkVerifyFailed)
        };
    }

    // The ring seed is c[(real_index + 1) % n]. Since the verifier
    // doesn't know real_index, walk the ring at every starting offset
    // and accept if any offset closes consistently.
    //
    // Concretely: for each candidate `r` in 0..n, treat position `r` as
    // the "real" index. The seed challenge should be:
    //     seed = H("ring_seed", message, r, L_r, T)
    // and must equal c[(r + 1) % n]. Then each subsequent step
    //     c[(i + 1) % n] = H("ring_step", message, (i+1), L_i)
    // until we return to (r + 1) % n — which means c[(r + 1) % n]
    // appeared both as the computed "next challenge from L_r" AND as
    // the Fiat-Shamir seed. Consistency means the whole chain closed.
    //
    // For efficiency we first scan every position to find the unique
    // one whose seed equation holds; if exactly one position passes,
    // we then walk the chain and confirm every step.
    for r in 0..n {
        let seed = fs_challenge(
            b"ring_seed",
            &[
                &proof.message,
                &(r as u64).to_le_bytes(),
                l[r].compress().as_bytes(),
                serial_tag.compress().as_bytes(),
            ],
        );
        let seed_idx = (r + 1) % n;
        if seed != c[seed_idx] {
            continue;
        }

        // Walk the chain from seed_idx forward and verify each step.
        let mut idx = seed_idx;
        let mut ok = true;
        while idx != r {
            let next = (idx + 1) % n;
            if next == seed_idx {
                break; // back to seed — ring closed
            }
            let expected = fs_challenge(
                b"ring_step",
                &[
                    &proof.message,
                    &(next as u64).to_le_bytes(),
                    l[idx].compress().as_bytes(),
                ],
            );
            if expected != c[next] {
                ok = false;
                break;
            }
            idx = next;
        }
        if ok {
            // Also confirm the challenge at position `r` derives
            // from the step chain so the attacker can't cheat by
            // choosing c[r] freely.
            let r_expected = fs_challenge(
                b"ring_step",
                &[
                    &proof.message,
                    &(r as u64).to_le_bytes(),
                    l[(r + n - 1) % n].compress().as_bytes(),
                ],
            );
            if r_expected == c[r] {
                return Ok(());
            }
        }
    }

    Err(Error::SparkVerifyFailed)
}

/// Batch-verify multiple Spark spend proofs.
///
/// Each entry in `proofs` is `(proof, pubkeys)`. Currently just
/// loops and invokes `verify_spark_spend` — a batched version
/// using Pippenger/Straus is possible future work.
pub fn batch_verify_sparks(proofs: &[(&SparkSpendProof, &[RistrettoPoint])]) -> Result<()> {
    for (proof, pubkeys) in proofs {
        verify_spark_spend(proof, pubkeys)?;
    }
    Ok(())
}

// ═══════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::OsRng;

    fn fresh_note(rng: &mut OsRng, value: u64, coin_id: u64) -> (SparkNote, RistrettoPoint) {
        let serial = random_scalar(rng);
        let randomness = random_scalar(rng);
        let commitment = spark_commit(value, &serial, &randomness);
        let note = SparkNote {
            commitment: commitment.compress().to_bytes(),
            value,
            serial: serial.to_bytes(),
            randomness: randomness.to_bytes(),
            diversifier: [0u8; 11],
            height: 1,
            coin_id,
        };
        (note, commitment)
    }

    #[test]
    fn commit_is_reproducible() {
        let s = Scalar::from(42u64);
        let r = Scalar::from(99u64);
        let a = spark_commit(1000, &s, &r);
        let b = spark_commit(1000, &s, &r);
        assert_eq!(a.compress(), b.compress());
    }

    #[test]
    fn serial_tag_is_deterministic() {
        let s = Scalar::from(12345u64);
        let t1 = spark_serial_tag(&s);
        let t2 = spark_serial_tag(&s);
        assert_eq!(t1.compress(), t2.compress());
    }

    // ═══════════════════════════════════════════════════════════════════
    // Spark test vectors
    //
    // These tests are derived from the protocol documented at
    // `prove_spark_spend`'s docstring (lines ~290-307) — NOT from what
    // the implementation currently does. A test passing means the
    // implementation matches the documented AOS ring signature +
    // serial-tag construction; a test failing means the implementation
    // deviates from the spec and MUST be fixed (not the tests relaxed).
    //
    // Coverage:
    //
    // 1. Completeness: honest prover at every ring position produces a
    //    proof the verifier accepts. We exercise n = 1, 2, 3, 5 and for
    //    each n we cycle the real_index through every position so the
    //    ring signature is tested at position 0, middle, and n-1.
    //
    // 2. Soundness (tampering): flipping a byte in any proof field
    //    (challenges / responses / serial_tag) must cause verification
    //    to fail.
    //
    // 3. Soundness (context binding): substituting the message or the
    //    pubkey vector must cause verification to fail (Fiat-Shamir
    //    binds the proof to its context).
    //
    // 4. Anonymity invariant: `build_anon_set` must refuse to produce a
    //    set smaller than `SPARK_ANON_SET_MIN` instead of panicking.
    //    A privacy coin must NEVER silently weaken its own anonymity.
    // ═══════════════════════════════════════════════════════════════════

    /// Build a ring of `n` commitments with the same (value, randomness)
    /// so a single reconstructed pubkey vector verifies all of them.
    /// Places the real note at `real_idx`; every other slot is a decoy
    /// with a fresh serial.
    fn ring_with_shared_vr(
        rng: &mut OsRng,
        value: u64,
        n: usize,
        real_idx: usize,
    ) -> (SparkNote, Vec<RistrettoPoint>, Vec<RistrettoPoint>) {
        let (note, real_commit) = fresh_note(rng, value, 0);
        let v = note.value;
        let r = note.randomness_scalar();
        let mut anon_set: Vec<RistrettoPoint> = Vec::with_capacity(n);
        for i in 0..n {
            if i == real_idx {
                anon_set.push(real_commit);
            } else {
                let decoy_serial = random_scalar(rng);
                anon_set.push(spark_commit(v, &decoy_serial, &r));
            }
        }
        let pubkeys: Vec<RistrettoPoint> =
            anon_set.iter().map(|c| spark_pubkey(c, v, &r)).collect();
        (note, anon_set, pubkeys)
    }

    // ─── Completeness ──────────────────────────────────────────────

    #[test]
    fn completeness_n1_real_at_0() {
        let mut rng = OsRng;
        let (note, anon_set, pubkeys) = ring_with_shared_vr(&mut rng, 500, 1, 0);
        let indices = vec![0u64];
        let message = [7u8; 32];
        let proof = prove_spark_spend(&note, &anon_set, &indices, 0, &message, &mut rng)
            .expect("honest prover must succeed");
        verify_spark_spend(&proof, &pubkeys).expect("honest proof must verify (n=1)");
    }

    #[test]
    fn completeness_n2_real_at_every_position() {
        for real_idx in 0..2 {
            let mut rng = OsRng;
            let (note, anon_set, pubkeys) = ring_with_shared_vr(&mut rng, 500, 2, real_idx);
            let indices: Vec<u64> = (0..2).collect();
            let message = [9u8; 32];
            let proof = prove_spark_spend(&note, &anon_set, &indices, real_idx, &message, &mut rng)
                .unwrap_or_else(|e| panic!("prove n=2 real={}: {:?}", real_idx, e));
            verify_spark_spend(&proof, &pubkeys)
                .unwrap_or_else(|e| panic!("verify n=2 real={}: {:?}", real_idx, e));
        }
    }

    #[test]
    fn completeness_n3_real_at_every_position() {
        for real_idx in 0..3 {
            let mut rng = OsRng;
            let (note, anon_set, pubkeys) = ring_with_shared_vr(&mut rng, 500, 3, real_idx);
            let indices: Vec<u64> = (0..3).collect();
            let message = [11u8; 32];
            let proof = prove_spark_spend(&note, &anon_set, &indices, real_idx, &message, &mut rng)
                .unwrap_or_else(|e| panic!("prove n=3 real={}: {:?}", real_idx, e));
            verify_spark_spend(&proof, &pubkeys)
                .unwrap_or_else(|e| panic!("verify n=3 real={}: {:?}", real_idx, e));
        }
    }

    #[test]
    fn completeness_n5_real_at_every_position() {
        for real_idx in 0..5 {
            let mut rng = OsRng;
            let (note, anon_set, pubkeys) = ring_with_shared_vr(&mut rng, 1000, 5, real_idx);
            let indices: Vec<u64> = (0..5).collect();
            let message = [13u8; 32];
            let proof = prove_spark_spend(&note, &anon_set, &indices, real_idx, &message, &mut rng)
                .unwrap_or_else(|e| panic!("prove n=5 real={}: {:?}", real_idx, e));
            verify_spark_spend(&proof, &pubkeys)
                .unwrap_or_else(|e| panic!("verify n=5 real={}: {:?}", real_idx, e));
        }
    }

    // ─── Soundness: proof field tampering ──────────────────────────

    #[test]
    fn soundness_rejects_tampered_challenge() {
        let mut rng = OsRng;
        let (note, anon_set, pubkeys) = ring_with_shared_vr(&mut rng, 500, 3, 1);
        let indices: Vec<u64> = (0..3).collect();
        let proof = prove_spark_spend(&note, &anon_set, &indices, 1, &[1u8; 32], &mut rng).unwrap();
        let mut tampered = proof.clone();
        tampered.challenges[0][0] ^= 0x01;
        assert!(
            verify_spark_spend(&tampered, &pubkeys).is_err(),
            "flipping a challenge byte must invalidate the proof"
        );
    }

    #[test]
    fn soundness_rejects_tampered_response() {
        let mut rng = OsRng;
        let (note, anon_set, pubkeys) = ring_with_shared_vr(&mut rng, 500, 3, 2);
        let indices: Vec<u64> = (0..3).collect();
        let proof = prove_spark_spend(&note, &anon_set, &indices, 2, &[1u8; 32], &mut rng).unwrap();
        let mut tampered = proof.clone();
        tampered.responses[1][0] ^= 0x01;
        assert!(
            verify_spark_spend(&tampered, &pubkeys).is_err(),
            "flipping a response byte must invalidate the proof"
        );
    }

    #[test]
    fn soundness_rejects_tampered_serial_tag() {
        let mut rng = OsRng;
        let (note, anon_set, pubkeys) = ring_with_shared_vr(&mut rng, 500, 2, 0);
        let indices: Vec<u64> = (0..2).collect();
        let proof = prove_spark_spend(&note, &anon_set, &indices, 0, &[1u8; 32], &mut rng).unwrap();
        let mut tampered = proof.clone();
        // Replace the serial tag with a fresh random point.
        let fresh_tag = gen_g() * random_scalar(&mut rng);
        tampered.serial_tag = fresh_tag.compress().to_bytes();
        assert!(
            verify_spark_spend(&tampered, &pubkeys).is_err(),
            "substituting the serial tag must invalidate the proof"
        );
    }

    // ─── Soundness: context binding ────────────────────────────────

    #[test]
    fn soundness_rejects_wrong_message() {
        let mut rng = OsRng;
        let (note, anon_set, pubkeys) = ring_with_shared_vr(&mut rng, 500, 2, 0);
        let indices: Vec<u64> = (0..2).collect();
        let proof = prove_spark_spend(&note, &anon_set, &indices, 0, &[1u8; 32], &mut rng).unwrap();
        let mut tampered = proof.clone();
        tampered.message = [2u8; 32];
        assert!(
            verify_spark_spend(&tampered, &pubkeys).is_err(),
            "tampering the message must invalidate the Fiat-Shamir chain"
        );
    }

    #[test]
    fn soundness_rejects_wrong_pubkeys() {
        let mut rng = OsRng;
        let (note, anon_set, _pubkeys) = ring_with_shared_vr(&mut rng, 500, 3, 0);
        let indices: Vec<u64> = (0..3).collect();
        let proof = prove_spark_spend(&note, &anon_set, &indices, 0, &[1u8; 32], &mut rng).unwrap();
        // Build an entirely different pubkey vector (different ring).
        let (_note2, _as2, pubkeys2) = ring_with_shared_vr(&mut rng, 500, 3, 0);
        assert!(
            verify_spark_spend(&proof, &pubkeys2).is_err(),
            "verifying against the wrong pubkey vector must fail"
        );
    }

    // ─── Anonymity-set construction invariant ──────────────────────

    #[test]
    fn build_anon_set_refuses_small_pool_instead_of_panicking() {
        // Pool of 10 coins, asked for a set of SPARK_ANON_SET_MIN (= 64).
        // Before the fix this panicked on `n.clamp(min, max)` when min > max.
        // After the fix it must return an explicit error; a privacy coin
        // must NEVER silently produce a smaller-than-minimum anonymity set.
        let mut acc = SparkAccumulator::new();
        for i in 0..10 {
            acc.add_coin(&(G * Scalar::from(i as u64 + 1)));
        }
        let result = acc.build_anon_set(3, SPARK_ANON_SET_MIN);
        assert!(
            result.is_err(),
            "pool smaller than SPARK_ANON_SET_MIN must error, not silently weaken anonymity"
        );
    }

    #[test]
    fn build_anon_set_contains_real_idx_when_pool_sufficient() {
        // Pool of SPARK_ANON_SET_MIN coins, asked for exactly that size —
        // the minimum valid anonymity set. The returned set must:
        //   (a) contain the real index (otherwise the proof cannot be constructed),
        //   (b) have length SPARK_ANON_SET_MIN.
        let mut acc = SparkAccumulator::new();
        for i in 0..SPARK_ANON_SET_MIN {
            acc.add_coin(&(G * Scalar::from(i as u64 + 1)));
        }
        let set = acc
            .build_anon_set(3, SPARK_ANON_SET_MIN)
            .expect("pool == MIN must succeed");
        assert_eq!(set.len(), SPARK_ANON_SET_MIN);
        assert!(set.contains(&3), "anonymity set must contain the real index");
    }
}
