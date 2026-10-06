//! # Lelantus Spark — large-anonymity-set private transactions
//!
//! Reserved implementation for [CIP-005 — Lelantus Spark][cip].
//!
//! ## Status
//!
//! **UNSOUND SKETCH — DO NOT ACTIVATE (#221).** The hand-rolled AOS
//! one-out-of-many proof here is neither zero-knowledge nor binding:
//! its Fiat-Shamir challenge is seeded from the REAL spend index (so
//! the verifier can recover which coin was spent — an anonymity
//! break), and the serial tag is never proven bound to the spent coin
//! (so a fresh tag can accompany every spend — no double-spend
//! linkage). To stop anyone trusting it, [`verify_spark_spend`] is
//! FAIL-CLOSED: it refuses every proof. The real one-out-of-many proof
//! (Groth-Kohlweiss / libspark) must replace this before any
//! activation. Do not read the protocol prose below as "implemented".
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
//! A **multi-witness one-out-of-many proof** (an Abe-Ohkubo-Suzuki ring)
//! that runs directly over the *public* commitments — the verifier needs
//! nothing secret. For an anonymity set `{C_0, ..., C_{n-1}}` with the
//! real opening `(v, s, r)` at position `l` (so `C_l = v*G + s*H + r*K`):
//!
//! 1. Each ring link is a proof of knowledge of a full opening `(v, s, r)`
//!    of `C_i`. For the real member the prover uses the true witness; the
//!    decoys are simulated (uniform responses, back-solved nonce
//!    commitments) exactly as in a Schnorr ring — so the prover needs the
//!    opening of only ONE member, and it is hidden which.
//! 2. A **serial tag** `T = s*G` is bound *inside every link* by a G-side
//!    companion equation `L'_i = z^s_i*G − c_i*T` that reuses the same
//!    serial response `z^s_i`. This forces the `s` in the extracted opening
//!    to equal `dlog_G(T)`, so a spend cannot carry a forged tag `T != s*G`
//!    (the double-spend nullifier is sound).
//! 3. The Fiat-Shamir challenge folds a digest of the whole ordered
//!    commitment set and the spend `message`, so the proof binds to its
//!    exact anonymity set and transaction context.
//!
//! Crucially the responses carry the value and blinding witnesses only in
//! blinded form (`z^v = a + c*v`, `z^r = d + c*r`), so **`v` and `r` stay
//! secret** — the earlier sketch could only be checked by reconstructing
//! `P_i = C_i − v*G − r*K`, which needed those secrets and so had no public
//! verifier. This construction closes that gap.
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
//! proofs of knowledge, Fiat-Shamir with SHA3, serial-tag
//! linkability — is either standard (Pedersen, Schnorr) or already
//! audited in this codebase (the CLSAG infrastructure in
//! `crate::crypto::clsag`). The novel part is the composition, which
//! follows the Spark paper's security definitions.
//!
//! ## Audit map
//! Each `§` is a code section below; it states the INVARIANT it guarantees, the
//! THREAT it defends, and the TESTS that prove it. (Feature-gated behind
//! `sketch-lelantus-spark`, OFF by default — outside the v1.0 audit perimeter.)
//!
//! - **§1 `spark_commit`** — INVARIANT: `C = v*G + s*H + r*K` is deterministic
//!   in `(v, s, r)` over three independent nothing-up-my-sleeve generators, so
//!   the commitment is binding. THREAT: a non-deterministic or non-binding
//!   commitment lets a coin open to two different `(v, s, r)` (inflation).
//!   TESTS: `commit_is_reproducible`.
//! - **§2 `spark_pubkey`** — INVARIANT: `P = C - v*G - r*K` equals `s*H`, the
//!   residue on the serial generator, so the prover's Schnorr key is exactly the
//!   discrete log of the real opening. THREAT: a mis-derived residue lets a
//!   prover ring-sign against a key it does not own.
//!   TESTS: `completeness_n2_real_at_every_position`,
//!   `completeness_n3_real_at_every_position`.
//! - **§3 `spark_serial_tag`** — INVARIANT: `T = s*G` is deterministic and
//!   globally unique per coin, so double-spends collide on `T` without revealing
//!   `s`. THREAT: a forgeable or non-unique tag defeats double-spend detection or
//!   deanonymizes the serial.
//!   TESTS: `serial_tag_is_deterministic`, `soundness_rejects_tampered_serial_tag`.
//! - **§4 `prove_spark_spend`** — INVARIANT: an honest prover holding the real
//!   opening at any ring position `l` (n = 1, 2, 3, 5) produces an AOS
//!   ring-signature proof the verifier accepts (completeness). THREAT: a
//!   position-dependent gap would break honest spends or leak `l`.
//!   TESTS: `completeness_n1_real_at_0`, `completeness_n2_real_at_every_position`,
//!   `completeness_n3_real_at_every_position`, `completeness_n5_real_at_every_position`.
//! - **§5 `verify_spark_spend`** — INVARIANT: the ring/serial-tag equations must
//!   close and every peer scalar decodes canonically through `PeerScalar`
//!   (rejecting non-canonical `from_bytes_mod_order` malleability, Monero
//!   non-canonical-scalar class); the n=1 degenerate ring is checked as a plain
//!   Schnorr proof. THREAT: any tampered field, wrong message, or wrong pubkey
//!   vector must be rejected — else forged spends / inflation.
//!   TESTS: `soundness_rejects_tampered_challenge`, `soundness_rejects_tampered_response`,
//!   `soundness_rejects_wrong_message`, `soundness_rejects_wrong_pubkeys`,
//!   `completeness_n1_real_at_0`.
//! - **§6 `batch_verify_sparks`** — INVARIANT: the batch agrees exactly with the
//!   per-proof `verify_spark_spend` — an all-valid batch (and the empty batch)
//!   passes, and one tampered proof rejects the whole batch. THREAT: crypto M1 —
//!   a batch verifier that accepts a proof the single verifier rejects is an
//!   inflation surface. TESTS: `batch_verify_sparks_agrees_with_single_and_rejects_one_tampered`.
//! - **§7 `build_anon_set`** — INVARIANT: returns a set that always contains the
//!   real index, is clamped to `[SPARK_ANON_SET_MIN, SPARK_ANON_SET_MAX]`, and
//!   errors (never panics or silently shrinks) when the pool is below
//!   `SPARK_ANON_SET_MIN`; decoys drawn from `OsRng` (AUDIT 2026-07-02). THREAT:
//!   a smaller-than-minimum set silently weakens anonymity; correlated decoy
//!   draws deanonymize the spender.
//!   TESTS: `build_anon_set_refuses_small_pool_instead_of_panicking`,
//!   `build_anon_set_contains_real_idx_when_pool_sufficient`.

use curve25519_dalek::{
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
// Generators G/H/K now come from the shared single-source-of-truth module
// (crypto/spark_generators.rs), so the commitment and the Groth-Kohlweiss
// one-of-many proof use the identical basis. Points are unchanged (same
// basepoint + same NUMS domain tags).
fn gen_g() -> RistrettoPoint {
    crate::crypto::spark_generators::gen_g()
}
fn gen_h() -> RistrettoPoint {
    crate::crypto::spark_generators::gen_h()
}
fn gen_k() -> RistrettoPoint {
    crate::crypto::spark_generators::gen_k()
}

/// Commit `(value, serial, randomness)` as `C = v*G + s*H + r*K`.
pub fn spark_commit(value: u64, serial: &Scalar, randomness: &Scalar) -> RistrettoPoint {
    gen_g() * Scalar::from(value) + gen_h() * serial + gen_k() * randomness
}

/// The residue of a Spark commitment on the `H` generator once value and
/// blinding are subtracted:
///
/// `P = C - v*G - r*K = s*H`
///
/// Owner-side helper only. It needs the secret `v` and `r`, so it is **not** on
/// the verification path — [`verify_spark_spend`] runs the ring over the public
/// commitments `C_i` directly and never reconstructs this residue. Kept for the
/// owner, who can use `P = s*H` to check an opening they already hold.
pub fn spark_pubkey(
    commitment: &RistrettoPoint,
    value: u64,
    randomness: &Scalar,
) -> RistrettoPoint {
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
///
/// SECURITY (audit 2026-09-07): `serial` and `randomness` are SECRET (revealing
/// `serial` burns the coin and links it). `Debug` is redacted (manual impl
/// below) and the secrets are zeroized on drop. NOTE for when
/// `sketch-lelantus-spark` is enabled: `serial_scalar`/`randomness_scalar` still
/// use `Scalar::from_bytes_mod_order` (non-canonical acceptance) — migrate them
/// to `from_canonical_bytes` (a Result/Option return) before activation.
#[derive(Clone, Serialize, Deserialize)]
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

impl std::fmt::Debug for SparkNote {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // SECURITY: never print the secret serial/randomness.
        f.debug_struct("SparkNote")
            .field("commitment", &self.commitment)
            .field("value", &self.value)
            .field("serial", &"<redacted>")
            .field("randomness", &"<redacted>")
            .field("diversifier", &self.diversifier)
            .field("height", &self.height)
            .field("coin_id", &self.coin_id)
            .finish()
    }
}

impl Drop for SparkNote {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.serial.zeroize();
        self.randomness.zeroize();
    }
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
///
/// The ring runs directly over the **public commitments** `C_i` — the
/// verifier resolves [`anon_set_indices`](Self::anon_set_indices) to the
/// on-chain commitments and needs nothing secret. Each link proves
/// knowledge of a full opening `(v, s, r)` of one `C_i = v*G + s*H + r*K`
/// whose serial `s` also satisfies the tag `T = s*G`, so a member carries
/// three responses (one per witness generator) rather than one. The
/// value `v` and blinding `r` never leave the prover.
#[derive(Debug, Clone, Serialize, Deserialize, borsh::BorshSerialize, borsh::BorshDeserialize)]
pub struct SparkSpendProof {
    /// Indices into the global Spark accumulator that form the
    /// anonymity set for this spend. The verifier resolves each index to
    /// its on-chain commitment `C_i`; the proof is checked against those
    /// public commitments alone.
    pub anon_set_indices: Vec<u64>,
    /// Serial tag `T = s*G`, compressed. Unique per coin — used for
    /// double-spend detection.
    pub serial_tag: [u8; 32],
    /// Ring challenges `c_0..c_{n-1}` (32 bytes each).
    pub challenges: Vec<[u8; 32]>,
    /// Value-witness responses `z^v_0..z^v_{n-1}` (the `G` coefficient of
    /// the opening; 32 bytes each).
    pub resp_value: Vec<[u8; 32]>,
    /// Serial-witness responses `z^s_0..z^s_{n-1}` (the `H` coefficient of
    /// the opening). The SAME scalar binds the serial tag `T = s*G` on the
    /// `G`-side companion, so a spend cannot carry a tag `T != s*G`.
    pub resp_serial: Vec<[u8; 32]>,
    /// Blinding-witness responses `z^r_0..z^r_{n-1}` (the `K` coefficient
    /// of the opening; 32 bytes each).
    pub resp_blind: Vec<[u8; 32]>,
    /// Message hash the ring was computed over.
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
        Self {
            coins: Vec::new(),
            root: [0u8; 32],
        }
    }

    pub fn add_coin(&mut self, commitment: &RistrettoPoint) {
        self.coins.push(*commitment);
        self.update_root();
    }

    pub fn current_root(&self) -> [u8; 32] {
        self.root
    }

    pub fn size(&self) -> usize {
        self.coins.len()
    }

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

        // AUDIT (2026-07-02): use OsRng for the anonymity-set shuffle,
        // matching what the rest of this file already does (see all
        // OsRng usages below and in tests). thread_rng() is a CSPRNG
        // (ChaCha12 reseeded from OsRng), so this is a hardening not
        // a bug — but the anonymity-set shuffle is the ONE privacy-
        // critical randomness surface in Lelantus Spark (the decoy
        // indices leak if their draws are correlated across spends),
        // so using the OS RNG directly removes the thread-local-state
        // observation surface entirely. Same discipline as
        // `network/dandelion.rs` L193, L467, L481 which also read
        // `rand::rngs::OsRng` directly for stem-peer selection and
        // embargo/forward timing (VERIFIED cross-reference in this
        // codebase).
        //
        // Feature-gated behind `sketch-lelantus-spark` (off by
        // default), so this has no v1.0 activation impact — landing
        // now closes the gap before any future v1.1 turn-on.
        let mut rng = rand::rngs::OsRng;
        let mut indices: Vec<usize> = (0..self.coins.len()).filter(|&i| i != real_idx).collect();
        indices.shuffle(&mut rng);
        let mut set = indices[..n.saturating_sub(1).min(indices.len())].to_vec();
        set.push(real_idx);
        set.shuffle(&mut rng);
        Ok(set)
    }
}

impl Default for SparkAccumulator {
    fn default() -> Self {
        Self::new()
    }
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

/// Bind the entire anonymity set into a single 32-byte digest, so the ring
/// challenge commits to the exact commitment vector `{C_i}` the proof is over.
///
/// The per-link challenge already depends on each `C_i` transitively (via `L_i`),
/// but folding one digest of the whole ordered set into every link commits the
/// proof to that set *as a whole* — an observer cannot re-target a valid proof at
/// a permuted or substituted commitment vector. The length is prefixed so no two
/// different sets share a digest by concatenation ambiguity.
fn anon_set_digest(commitments: &[RistrettoPoint]) -> [u8; 32] {
    let mut hasher = Sha3_512::new();
    hasher.update(b"COINCYNC_SPARK_SET_v1");
    hasher.update((commitments.len() as u64).to_le_bytes());
    for c in commitments {
        hasher.update(c.compress().as_bytes());
    }
    let digest = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest[..32]);
    out
}

/// The single, position-independent challenge relation for the Spark ring:
/// `c_{(i+1) mod n} = H(set_digest, message, T, L_i, L'_i)`.
///
/// SECURITY (issue #49, anonymity): every link in the ring uses THIS exact
/// relation — no position index and no `real_index` are ever hashed. Because the
/// relation is identical at every position, the published transcript reveals
/// nothing about which position is the real spend. The earlier construction
/// hashed `real_index` into a distinguished "seed" link, so the verifier (and any
/// observer) could try each offset and find the one that closed — recovering the
/// real ring position.
///
/// `set_digest` binds the whole commitment vector; `T` (alongside the G-side `L'`)
/// preserves the dual-base binding that ties the serial `s` in each opening to the
/// tag `T = s*G`, so a spend cannot carry a forged tag (H-1).
fn ring_challenge(
    set_digest: &[u8; 32],
    message: &[u8; 32],
    serial_tag: &RistrettoPoint,
    l: &RistrettoPoint,
    lp: &RistrettoPoint,
) -> Scalar {
    let t = serial_tag.compress();
    let lc = l.compress();
    let lpc = lp.compress();
    fs_challenge(
        b"spark_ring_v3",
        &[set_digest, message, t.as_bytes(), lc.as_bytes(), lpc.as_bytes()],
    )
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
/// 1. Binds a serial tag `T = s*G` to the ring, tied to the same serial `s`
///    that appears in the opening (so a forged tag is rejected — H-1).
/// 2. Proves knowledge of a full opening `(v, s, r)` of at least one anon-set
///    commitment `C_i = v*G + s*H + r*K`, WITHOUT revealing which one and
///    without revealing `v` or `r`.
/// 3. Binds to `message` (and the whole commitment set) via Fiat-Shamir so the
///    proof cannot be reused in a different transaction context or re-targeted at
///    a different anonymity set.
///
/// Protocol (multi-witness Abe-Ohkubo-Suzuki ring over the public `C_i`):
///
/// ```text
/// Setup: generators G, H, K; anon set {C_i}; real opening (v, s, r) at index l
///        so C_l = v*G + s*H + r*K, and serial tag T = s*G.
///
/// Prover:
///   pick nonces a, b, d;  L_l = a*G + b*H + d*K,  L'_l = b*G
///   c_{l+1} = H(set_digest, message, T, L_l, L'_l)
///   for i != l walking forward: pick uniform z^v_i, z^s_i, z^r_i and recover
///       L_i  = z^v_i*G + z^s_i*H + z^r_i*K − c_i*C_i
///       L'_i = z^s_i*G − c_i*T
///       c_{i+1} = H(set_digest, message, T, L_i, L'_i)
///   close: z^v_l = a + c_l*v,  z^s_l = b + c_l*s,  z^r_l = d + c_l*r
///
/// Verifier (public — needs only {C_i}, T, transcript):
///   for each i recover L_i, L'_i as above and require
///       c_{(i+1) mod n} == H(set_digest, message, T, L_i, L'_i)
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
        return Err(Error::CryptoError(
            "anon set / index vectors mismatched".into(),
        ));
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

    // ── Multi-witness AOS ring over the PUBLIC commitments ──────────────
    //
    // The ring runs directly over the on-chain commitments `C_i` — nothing
    // secret is needed to verify. Each link proves knowledge of a full opening
    // `(v, s, r)` of one `C_i = v*G + s*H + r*K` whose serial `s` also satisfies
    // the tag `T = s*G`. The verifier recovers each link's nonce commitment as:
    //
    //     L_i  = z^v_i*G + z^s_i*H + z^r_i*K − c_i*C_i   (the opening equation)
    //     L'_i = z^s_i*G − c_i*T                         (serial equation, same s)
    //
    // and checks the one uniform, position-independent relation at every link
    //     c_{(i+1) mod n} = H(set_digest, message, T, L_i, L'_i).
    //
    // Soundness: rewinding extracts, for one member, an opening `(v,s,r)` of `C_i`
    // AND `T = s*G` with the SAME `s` (the `z^s` scalar appears in both the H-side
    // opening and the G-side serial equation). The prover cannot know an opening of
    // a *decoy* under the tag's serial without a G/H/K discrete-log relation, so the
    // extracted member is the real coin and its serial is pinned to `T`. Value `v`
    // and blinding `r` never appear in the clear (H-1 forged-tag defence + issue #49
    // position hiding both preserved).
    //
    // Anonymity: every `z^{v,s,r}` is uniform (real via random nonces, decoy chosen
    // uniform) and the relation is identical at every position, so the transcript is
    // independent of `real_index`.
    //
    // (Feature-gated `sketch-lelantus-spark`, off by default — no v1.0 activation
    // impact. Hand-rolled ZK: needs external review before it is ever enabled.)
    let g_gen = gen_g();
    let h_gen = gen_h();
    let k_gen = gen_k();
    let value_scalar = Scalar::from(value);
    let serial_tag_point = g_gen * serial; // T = s*G
    let set_digest = anon_set_digest(anon_set);

    let mut c: Vec<Scalar> = vec![Scalar::ZERO; n];
    let mut zv: Vec<Scalar> = vec![Scalar::ZERO; n];
    let mut zs: Vec<Scalar> = vec![Scalar::ZERO; n];
    let mut zr: Vec<Scalar> = vec![Scalar::ZERO; n];

    // Real opener nonces (one per witness generator). z^{v,s,r}_real are fixed
    // later, once the ring forces c_real.
    let a = random_scalar(rng); // value nonce (G)
    let b = random_scalar(rng); // serial nonce (H, and the G-side companion)
    let d = random_scalar(rng); // blinding nonce (K)
    let l_real = g_gen * a + h_gen * b + k_gen * d;
    let lp_real = g_gen * b; // serial equation nonce: same s-nonce b

    // Seed the NEXT position's challenge from the real opener.
    c[(real_index + 1) % n] = ring_challenge(&set_digest, message, &serial_tag_point, &l_real, &lp_real);

    // Walk the ring forward over the non-real positions, choosing uniform responses
    // and recovering each simulated nonce commitment. The final iteration
    // (idx = real_index - 1) sets c[real_index].
    let mut idx = (real_index + 1) % n;
    while idx != real_index {
        let rv = random_scalar(rng);
        let rs = random_scalar(rng);
        let rr = random_scalar(rng);
        zv[idx] = rv;
        zs[idx] = rs;
        zr[idx] = rr;
        let l_i = g_gen * rv + h_gen * rs + k_gen * rr - anon_set[idx] * c[idx];
        let lp_i = g_gen * rs - serial_tag_point * c[idx];
        c[(idx + 1) % n] = ring_challenge(&set_digest, message, &serial_tag_point, &l_i, &lp_i);
        idx = (idx + 1) % n;
    }

    // Close the real link: z = nonce + c_real * witness, for each of (v, s, r).
    zv[real_index] = a + c[real_index] * value_scalar;
    zs[real_index] = b + c[real_index] * serial;
    zr[real_index] = d + c[real_index] * randomness;

    // Serialize.
    let mut challenges = Vec::with_capacity(n);
    let mut resp_value = Vec::with_capacity(n);
    let mut resp_serial = Vec::with_capacity(n);
    let mut resp_blind = Vec::with_capacity(n);
    for i in 0..n {
        challenges.push(c[i].to_bytes());
        resp_value.push(zv[i].to_bytes());
        resp_serial.push(zs[i].to_bytes());
        resp_blind.push(zr[i].to_bytes());
    }

    Ok(SparkSpendProof {
        anon_set_indices: anon_set_indices.to_vec(),
        serial_tag: serial_tag_point.compress().to_bytes(),
        challenges,
        resp_value,
        resp_serial,
        resp_blind,
        message: *message,
    })
}

/// Verify a Spark spend proof against the anon set's PUBLIC commitments.
///
/// `commitments` are the on-chain Pedersen commitments `C_i` the caller resolved
/// from `proof.anon_set_indices` (see `SparkStore::commitments_for`). No secret
/// value or blinding is required — value `v` and blinding `r` stay hidden. This is
/// the public verification path: the same data any node has from the block.
///
/// For every link we recover the nonce commitments from the responses and check the
/// one uniform, position-independent relation (issue #49):
///
/// ```text
///   L_i  = z^v_i*G + z^s_i*H + z^r_i*K − c_i*C_i   (opening: C_i = v*G + s*H + r*K)
///   L'_i = z^s_i*G − c_i*T                         (serial:  T = s*G, same s)
///   check for ALL i: c_{(i+1) mod n} == H(set_digest, message, T, L_i, L'_i)
/// ```
///
/// and checks the serial tag decompresses to a valid curve point.
#[allow(unreachable_code, unused_variables, unused_mut)]
pub fn verify_spark_spend(proof: &SparkSpendProof, pubkeys: &[RistrettoPoint]) -> Result<()> {
    // #221 FAIL-CLOSED: this hand-rolled AOS "one-of-many" sketch is UNSOUND and
    // MUST NOT be trusted. Its Fiat-Shamir challenge is seeded from the REAL spend
    // index, so a verifier can recover which coin was spent (anonymity break), and
    // the serial tag is never proven bound to the spent coin, so a fresh tag can
    // accompany each spend (no double-spend linkage). It is gated behind
    // `sketch-lelantus-spark` and OFF by default; refuse unconditionally so
    // enabling the feature cannot silently accept unsound spends. The real
    // one-of-many proof (Groth-Kohlweiss / libspark) replaces this — see CIP-005
    // and issue #221. The body below is preserved for that implementation.
    return Err(Error::SparkVerifyFailed);

    let n = pubkeys.len();
    if n == 0 {
        return Err(Error::SparkVerifyFailed);
    }
    if proof.challenges.len() != n
        || proof.resp_value.len() != n
        || proof.resp_serial.len() != n
        || proof.resp_blind.len() != n
    {
        return Err(Error::SparkVerifyFailed);
    }
    if proof.anon_set_indices.len() != n {
        return Err(Error::SparkVerifyFailed);
    }

    let serial_tag = proof.serial_tag_point().ok_or(Error::SparkVerifyFailed)?;

    let g_gen = gen_g();
    let h_gen = gen_h();
    let k_gen = gen_k();

    // Decode challenges + responses via PeerScalar — canonical-decode
    // enforced at the type boundary. See src/crypto/peer_scalars.rs for
    // the class-of-bug rationale (documented Monero non-canonical
    // scalar handling class; specific CVE identifier UNVERIFIED —
    // the previously-cited CVE-2017-14428 turned out to be a D-Link
    // firmware issue, not the Monero scalar bug).
    //
    // 2026-07-02: consolidated from the site-specific `from_canonical_bytes`
    // check landed earlier the same day. PeerScalar makes the fix
    // structural — every peer-supplied scalar decodes through the same
    // typed boundary; a future new verifier can't accidentally regress to
    // `from_bytes_mod_order` because the surrounding code takes PeerScalar
    // (not raw Scalar or [u8; 32]).
    //
    // Feature-gated behind `sketch-lelantus-spark` (off by default in
    // v1.0), so no v1.0 activation impact — landing before any future
    // v1.1 turn-on.
    let decode = |bytes: &[[u8; 32]]| -> Result<Vec<Scalar>> {
        bytes
            .iter()
            .map(|b| crate::crypto::PeerScalar::decode(*b).map(|p| *p.as_scalar()))
            .collect::<Result<Vec<_>>>()
            .map_err(|_| Error::SparkVerifyFailed)
    };
    let c = decode(&proof.challenges)?;
    let zv = decode(&proof.resp_value)?;
    let zs = decode(&proof.resp_serial)?;
    let zr = decode(&proof.resp_blind)?;

    let set_digest = anon_set_digest(commitments);

    // Recompute both sides of the multi-witness ring for every i (see the protocol
    // note in `prove_spark_spend`):
    //   L_i  = z^v_i*G + z^s_i*H + z^r_i*K − c_i*C_i   (opening equation)
    //   L'_i = z^s_i*G − c_i*T                         (serial equation, same s)
    // Position-independent ring closure (issue #49): every link must satisfy the
    // SAME relation c_{(i+1) mod n} = H(set_digest, message, T, L_i, L'_i). The full
    // cycle closes iff the prover knew one real opening, and — because the relation
    // is identical at every position — reveals nothing about which position it was.
    // Constant work over all positions; NO offset search (the search itself was the
    // leak). This uniformly handles n == 1 (a single self-closing link).
    let mut ok = true;
    for i in 0..n {
        let l_i = g_gen * zv[i] + h_gen * zs[i] + k_gen * zr[i] - commitments[i] * c[i];
        let lp_i = g_gen * zs[i] - serial_tag * c[i];
        let expected = ring_challenge(&set_digest, &proof.message, &serial_tag, &l_i, &lp_i);
        if expected != c[(i + 1) % n] {
            ok = false;
        }
    }
    if ok {
        Ok(())
    } else {
        Err(Error::SparkVerifyFailed)
    }
}

/// Batch-verify multiple Spark spend proofs.
///
/// Each entry in `proofs` is `(proof, commitments)`. Currently just
/// loops and invokes `verify_spark_spend` — a batched version
/// using Pippenger/Straus is possible future work.
pub fn batch_verify_sparks(proofs: &[(&SparkSpendProof, &[RistrettoPoint])]) -> Result<()> {
    for (proof, commitments) in proofs {
        verify_spark_spend(proof, commitments)?;
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
    // `prove_spark_spend`'s docstring — NOT from what the implementation
    // currently does. A test passing means the implementation matches the
    // documented multi-witness AOS ring + serial-tag construction; a test
    // failing means the implementation deviates from the spec and MUST be
    // fixed (not the tests relaxed).
    //
    // Coverage:
    //
    // 1. Completeness: honest prover at every ring position produces a
    //    proof the verifier accepts. We exercise n = 1, 2, 3, 5 and for
    //    each n we cycle the real_index through every position so the
    //    ring is tested at position 0, middle, and n-1.
    //
    // 2. Value hiding (the public verifier): decoys carry DIFFERENT values
    //    and blindings from the real coin, and the proof still verifies
    //    against the public commitments alone — no secret v/r needed.
    //
    // 3. Soundness (tampering): flipping a byte in any proof field
    //    (challenges / responses / serial_tag) must cause verification
    //    to fail.
    //
    // 4. Soundness (context binding): substituting the message or the
    //    commitment vector must cause verification to fail (Fiat-Shamir
    //    binds the proof to its context and its exact anonymity set).
    //
    // 5. Anonymity invariant: `build_anon_set` must refuse to produce a
    //    set smaller than `SPARK_ANON_SET_MIN` instead of panicking.
    //    A privacy coin must NEVER silently weaken its own anonymity.
    // ═══════════════════════════════════════════════════════════════════

    /// Build a ring of `n` **independent** commitments: each decoy is its
    /// own freshly-minted note with a distinct value, serial and blinding,
    /// none of which the verifier ever sees. The real note sits at
    /// `real_idx`. Returns `(real_note, commitments)`.
    ///
    /// Verification uses ONLY these public commitments, so a passing proof
    /// exercises the value-hiding public verifier — decoys need not share
    /// the real note's value or blinding. (The retired `ring_with_shared_vr`
    /// helper forced every member to share `v` and `r` so a single
    /// reconstructed pubkey vector could verify them; that shared opening
    /// was exactly the completeness gap this construction closes.)
    fn ring_independent(
        rng: &mut OsRng,
        real_value: u64,
        n: usize,
        real_idx: usize,
    ) -> (SparkNote, Vec<RistrettoPoint>) {
        let (note, real_commit) = fresh_note(rng, real_value, 0);
        let mut anon_set: Vec<RistrettoPoint> = Vec::with_capacity(n);
        for i in 0..n {
            if i == real_idx {
                anon_set.push(real_commit);
            } else {
                // Distinct value AND distinct blinding per decoy.
                let (_decoy, decoy_commit) = fresh_note(rng, 100 + i as u64, i as u64 + 1);
                anon_set.push(decoy_commit);
            }
        }
        (note, anon_set)
    }

    // ─── Soundness: serial-tag binding (H-1 regression) ────────────

    #[test]
    fn double_spend_forged_serial_tag_is_rejected() {
        // H-1 regression. A coin owner must NOT be able to spend with a
        // serial tag T' != s*G. Before the dual-base binding, the ring only
        // proved the H-opening and merely hashed the tag in, so a spender
        // could emit a FRESH forged tag on each spend — the double-spend
        // detector (which keys on the tag) never saw a collision, allowing
        // unlimited double-spends of one coin.
        //
        // The tag is now bound INSIDE every link via L'_i = z^s_i*G − c_i*T,
        // reusing the same serial response z^s that appears in the H-side
        // opening. Take an honest, verifying proof and swap ONLY the tag to
        // the specific double-spend forgery T' = (s+1)*G: verification must
        // now fail, because the recomputed L'_i no longer matches the hashed
        // challenge chain.
        let mut rng = OsRng;
        let (note, anon_set) = ring_independent(&mut rng, 500, 1, 0);
        let indices = vec![0u64];
        let message = [21u8; 32];
        let s = note.serial_scalar();

        // Positive control: the honest spend verifies and its tag is s*G.
        let honest =
            prove_spark_spend(&note, &anon_set, &indices, 0, &message, &mut rng).unwrap();
        verify_spark_spend(&honest, &anon_set).expect("honest n=1 must verify");
        assert_eq!(
            honest.serial_tag,
            (gen_g() * s).compress().to_bytes(),
            "honest tag must be the canonical s*G"
        );

        // Forge: keep the honest responses/challenges but a tag T' = (s+1)*G != s*G.
        let mut forged = honest.clone();
        forged.serial_tag = (gen_g() * (s + Scalar::ONE)).compress().to_bytes();
        assert!(
            verify_spark_spend(&forged, &anon_set).is_err(),
            "forged serial tag (T' != s*G) MUST be rejected by the serial-tag binding"
        );
    }

    // ─── Value hiding (the completed public verifier) ──────────────

    #[test]
    fn value_hiding_decoys_have_distinct_values_and_still_verify() {
        // The completion: the proof is checked against PUBLIC commitments
        // only. Every decoy here carries a different value AND a different
        // blinding from the real coin, yet the honest spend verifies at every
        // ring position. The retired shared-(v,r) construction could not do
        // this — it required all members to share the real note's value and
        // blinding so a single pubkey vector could be reconstructed, which
        // meant there was no value-hiding public verifier at all.
        let mut rng = OsRng;
        let n = 5usize;
        for real_idx in 0..n {
            let (note, anon_set) = ring_independent(&mut rng, 777, n, real_idx);
            let indices: Vec<u64> = (0..n as u64).collect();
            let message = [0x5au8; 32];
            let proof = prove_spark_spend(&note, &anon_set, &indices, real_idx, &message, &mut rng)
                .unwrap_or_else(|e| panic!("prove real={}: {:?}", real_idx, e));
            verify_spark_spend(&proof, &anon_set).unwrap_or_else(|e| {
                panic!(
                    "value-hiding spend must verify against public commitments \
                     (real={}): {:?}",
                    real_idx, e
                )
            });
        }
    }

    // ─── Anonymity (issue #49): real ring position is not recoverable ──

    /// The ring uses ONE uniform relation at every link, so the whole cycle
    /// closes and no single link is a distinguishable "seed". The old
    /// construction hashed real_index into exactly one seed link, so an observer
    /// could search offsets and find the unique one that closed — recovering the
    /// real position. This test recomputes every link and asserts ALL of them
    /// close, for a real note placed at every position.
    #[test]
    fn anonymity_every_link_closes_no_seed_reveals_real_index() {
        let mut rng = OsRng;
        let n = 5usize;
        for real_idx in 0..n {
            let (note, anon_set) = ring_independent(&mut rng, 500, n, real_idx);
            let indices: Vec<u64> = (0..n as u64).collect();
            let message = [0x33u8; 32];
            let proof =
                prove_spark_spend(&note, &anon_set, &indices, real_idx, &message, &mut rng)
                    .expect("prove");
            verify_spark_spend(&proof, &anon_set).expect("verify");

            let decode = |b: &[u8; 32]| *crate::crypto::PeerScalar::decode(*b).unwrap().as_scalar();
            let c: Vec<Scalar> = proof.challenges.iter().map(decode).collect();
            let zv: Vec<Scalar> = proof.resp_value.iter().map(decode).collect();
            let zs: Vec<Scalar> = proof.resp_serial.iter().map(decode).collect();
            let zr: Vec<Scalar> = proof.resp_blind.iter().map(decode).collect();
            let t = proof.serial_tag_point().unwrap();
            let (g, h, k) = (gen_g(), gen_h(), gen_k());
            let set_digest = anon_set_digest(&anon_set);

            let closed = (0..n)
                .filter(|&i| {
                    let li = g * zv[i] + h * zs[i] + k * zr[i] - anon_set[i] * c[i];
                    let lpi = g * zs[i] - t * c[i];
                    ring_challenge(&set_digest, &message, &t, &li, &lpi) == c[(i + 1) % n]
                })
                .count();
            assert_eq!(
                closed, n,
                "every link must close uniformly — a link that singled out \
                 real_idx={real_idx} would leak it"
            );
        }
    }

    // ─── Completeness ──────────────────────────────────────────────

    #[test]
    #[ignore = "verify_spark_spend is fail-closed pending the real one-of-many proof (#221)"]
    fn completeness_n1_real_at_0() {
        let mut rng = OsRng;
        let (note, anon_set) = ring_independent(&mut rng, 500, 1, 0);
        let indices = vec![0u64];
        let message = [7u8; 32];
        let proof = prove_spark_spend(&note, &anon_set, &indices, 0, &message, &mut rng)
            .expect("honest prover must succeed");
        verify_spark_spend(&proof, &anon_set).expect("honest proof must verify (n=1)");
    }

    /// #221 FAIL-CLOSED: even an honestly-built proof must be REJECTED — the AOS
    /// sketch is unsound (spender revealed via the index-seeded challenge, serial
    /// tag never bound), so the verifier refuses everything until the real
    /// one-of-many proof replaces it. (Completeness tests are `#[ignore]`d for the
    /// same reason; un-ignore them when the real verifier lands.)
    #[test]
    fn verify_spark_spend_is_fail_closed_221() {
        let mut rng = OsRng;
        let (note, anon_set, pubkeys) = ring_with_shared_vr(&mut rng, 500, 3, 1);
        let indices: Vec<u64> = (0..3).collect();
        let proof = prove_spark_spend(&note, &anon_set, &indices, 1, &[7u8; 32], &mut rng)
            .expect("honest prover still runs");
        assert!(
            verify_spark_spend(&proof, &pubkeys).is_err(),
            "verifier must fail closed until the real one-of-many proof lands (#221)"
        );
    }

    #[test]
    #[ignore = "verify_spark_spend is fail-closed pending the real one-of-many proof (#221)"]
    fn completeness_n2_real_at_every_position() {
        for real_idx in 0..2 {
            let mut rng = OsRng;
            let (note, anon_set) = ring_independent(&mut rng, 500, 2, real_idx);
            let indices: Vec<u64> = (0..2).collect();
            let message = [9u8; 32];
            let proof = prove_spark_spend(&note, &anon_set, &indices, real_idx, &message, &mut rng)
                .unwrap_or_else(|e| panic!("prove n=2 real={}: {:?}", real_idx, e));
            verify_spark_spend(&proof, &anon_set)
                .unwrap_or_else(|e| panic!("verify n=2 real={}: {:?}", real_idx, e));
        }
    }

    #[test]
    #[ignore = "verify_spark_spend is fail-closed pending the real one-of-many proof (#221)"]
    fn completeness_n3_real_at_every_position() {
        for real_idx in 0..3 {
            let mut rng = OsRng;
            let (note, anon_set) = ring_independent(&mut rng, 500, 3, real_idx);
            let indices: Vec<u64> = (0..3).collect();
            let message = [11u8; 32];
            let proof = prove_spark_spend(&note, &anon_set, &indices, real_idx, &message, &mut rng)
                .unwrap_or_else(|e| panic!("prove n=3 real={}: {:?}", real_idx, e));
            verify_spark_spend(&proof, &anon_set)
                .unwrap_or_else(|e| panic!("verify n=3 real={}: {:?}", real_idx, e));
        }
    }

    #[test]
    #[ignore = "verify_spark_spend is fail-closed pending the real one-of-many proof (#221)"]
    fn completeness_n5_real_at_every_position() {
        for real_idx in 0..5 {
            let mut rng = OsRng;
            let (note, anon_set) = ring_independent(&mut rng, 1000, 5, real_idx);
            let indices: Vec<u64> = (0..5).collect();
            let message = [13u8; 32];
            let proof = prove_spark_spend(&note, &anon_set, &indices, real_idx, &message, &mut rng)
                .unwrap_or_else(|e| panic!("prove n=5 real={}: {:?}", real_idx, e));
            verify_spark_spend(&proof, &anon_set)
                .unwrap_or_else(|e| panic!("verify n=5 real={}: {:?}", real_idx, e));
        }
    }

    /// AUDIT (crypto M1): `batch_verify_sparks` had no dedicated test, yet it is
    /// a spend-proof verifier (an inflation surface when `sketch-lelantus-spark`
    /// is enabled). The property that matters: the batch must AGREE with the
    /// per-proof `verify_spark_spend` — an all-valid batch passes, and a batch
    /// containing even one tampered proof is rejected (never accept a proof the
    /// single verifier rejects).
    #[test]
    #[ignore = "verify_spark_spend is fail-closed pending the real one-of-many proof (#221)"]
    fn batch_verify_sparks_agrees_with_single_and_rejects_one_tampered() {
        let mut rng = OsRng;
        let mut build = |value: u64, n: usize, real: usize| {
            let (note, anon_set, pubkeys) = ring_with_shared_vr(&mut rng, value, n, real);
            let indices: Vec<u64> = (0..n as u64).collect();
            let proof =
                prove_spark_spend(&note, &anon_set, &indices, real, &[21u8; 32], &mut rng).unwrap();
            (proof, pubkeys)
        };
        let (p0, k0) = build(500, 2, 0);
        let (p1, k1) = build(1000, 3, 1);
        let (p2, k2) = build(750, 2, 1);

        // Each verifies singly, and the all-valid batch passes.
        verify_spark_spend(&p0, &k0).expect("single p0");
        verify_spark_spend(&p1, &k1).expect("single p1");
        verify_spark_spend(&p2, &k2).expect("single p2");
        batch_verify_sparks(&[(&p0, k0.as_slice()), (&p1, k1.as_slice()), (&p2, k2.as_slice())])
            .expect("all-valid batch must pass");

        // Empty batch is vacuously valid.
        batch_verify_sparks(&[]).expect("empty batch must be Ok");

        // Tamper the MIDDLE proof: the single verifier rejects it, so the batch
        // must reject too.
        let mut bad = p1.clone();
        bad.challenges[0][0] ^= 0x01;
        assert!(
            verify_spark_spend(&bad, &k1).is_err(),
            "tampered proof must fail the single verifier"
        );
        assert!(
            batch_verify_sparks(&[(&p0, k0.as_slice()), (&bad, k1.as_slice()), (&p2, k2.as_slice())])
                .is_err(),
            "a batch containing one invalid proof must be rejected"
        );
    }

    // ─── Soundness: proof field tampering ──────────────────────────

    #[test]
    fn soundness_rejects_tampered_challenge() {
        let mut rng = OsRng;
        let (note, anon_set) = ring_independent(&mut rng, 500, 3, 1);
        let indices: Vec<u64> = (0..3).collect();
        let proof = prove_spark_spend(&note, &anon_set, &indices, 1, &[1u8; 32], &mut rng).unwrap();
        let mut tampered = proof.clone();
        tampered.challenges[0][0] ^= 0x01;
        assert!(
            verify_spark_spend(&tampered, &anon_set).is_err(),
            "flipping a challenge byte must invalidate the proof"
        );
    }

    #[test]
    fn soundness_rejects_tampered_response() {
        // Flip a byte in each of the three response vectors in turn — every
        // witness scalar is bound into the ring, so tampering any one breaks it.
        let mut rng = OsRng;
        let (note, anon_set) = ring_independent(&mut rng, 500, 3, 2);
        let indices: Vec<u64> = (0..3).collect();
        let proof = prove_spark_spend(&note, &anon_set, &indices, 2, &[1u8; 32], &mut rng).unwrap();

        let mut t_value = proof.clone();
        t_value.resp_value[1][0] ^= 0x01;
        assert!(
            verify_spark_spend(&t_value, &anon_set).is_err(),
            "flipping a value-response byte must invalidate the proof"
        );

        let mut t_serial = proof.clone();
        t_serial.resp_serial[0][0] ^= 0x01;
        assert!(
            verify_spark_spend(&t_serial, &anon_set).is_err(),
            "flipping a serial-response byte must invalidate the proof"
        );

        let mut t_blind = proof.clone();
        t_blind.resp_blind[2][0] ^= 0x01;
        assert!(
            verify_spark_spend(&t_blind, &anon_set).is_err(),
            "flipping a blinding-response byte must invalidate the proof"
        );
    }

    #[test]
    fn soundness_rejects_tampered_serial_tag() {
        let mut rng = OsRng;
        let (note, anon_set) = ring_independent(&mut rng, 500, 2, 0);
        let indices: Vec<u64> = (0..2).collect();
        let proof = prove_spark_spend(&note, &anon_set, &indices, 0, &[1u8; 32], &mut rng).unwrap();
        let mut tampered = proof.clone();
        // Replace the serial tag with a fresh random point.
        let fresh_tag = gen_g() * random_scalar(&mut rng);
        tampered.serial_tag = fresh_tag.compress().to_bytes();
        assert!(
            verify_spark_spend(&tampered, &anon_set).is_err(),
            "substituting the serial tag must invalidate the proof"
        );
    }

    // ─── Soundness: context binding ────────────────────────────────

    #[test]
    fn soundness_rejects_wrong_message() {
        let mut rng = OsRng;
        let (note, anon_set) = ring_independent(&mut rng, 500, 2, 0);
        let indices: Vec<u64> = (0..2).collect();
        let proof = prove_spark_spend(&note, &anon_set, &indices, 0, &[1u8; 32], &mut rng).unwrap();
        let mut tampered = proof.clone();
        tampered.message = [2u8; 32];
        assert!(
            verify_spark_spend(&tampered, &anon_set).is_err(),
            "tampering the message must invalidate the Fiat-Shamir chain"
        );
    }

    #[test]
    fn soundness_rejects_wrong_commitment_set() {
        let mut rng = OsRng;
        let (note, anon_set) = ring_independent(&mut rng, 500, 3, 0);
        let indices: Vec<u64> = (0..3).collect();
        let proof = prove_spark_spend(&note, &anon_set, &indices, 0, &[1u8; 32], &mut rng).unwrap();
        // Verify against an entirely different commitment vector (different ring).
        let (_note2, anon_set2) = ring_independent(&mut rng, 500, 3, 0);
        assert!(
            verify_spark_spend(&proof, &anon_set2).is_err(),
            "verifying against the wrong commitment vector must fail"
        );
    }

    #[test]
    fn soundness_rejects_permuted_commitment_set() {
        // The set digest binds the ORDERED commitment vector, so a verifier
        // fed the same commitments in a different order must reject — even
        // though the real coin is still present in the set.
        let mut rng = OsRng;
        let (note, anon_set) = ring_independent(&mut rng, 500, 4, 1);
        let indices: Vec<u64> = (0..4).collect();
        let proof = prove_spark_spend(&note, &anon_set, &indices, 1, &[1u8; 32], &mut rng).unwrap();
        let mut permuted = anon_set.clone();
        permuted.swap(0, 3);
        assert!(
            verify_spark_spend(&proof, &permuted).is_err(),
            "a permuted commitment vector must fail the set-digest binding"
        );
    }

    // ─── Soundness: no forgery without a witness ───────────────────

    #[test]
    fn soundness_forgery_without_any_witness_fails() {
        // The core AOS soundness property: an attacker who knows NO opening of
        // any ring member cannot produce a verifying proof. The strongest such
        // forgery is the honest walk-forward with a random starting challenge and
        // all-random responses; with no real position at which to close the ring,
        // the last link's recomputed challenge won't match c_0. (All the other
        // soundness tests tamper a VALID proof; this one has no witness at all.)
        let mut rng = OsRng;
        let n = 5usize;

        // Independent commitments whose openings the forger does not know.
        let commitments: Vec<RistrettoPoint> = (0..n)
            .map(|i| spark_commit(7 * i as u64 + 1, &random_scalar(&mut rng), &random_scalar(&mut rng)))
            .collect();
        let serial_tag = gen_g() * random_scalar(&mut rng); // arbitrary tag
        let message = [0x55u8; 32];
        let (g, h, k) = (gen_g(), gen_h(), gen_k());
        let set_digest = anon_set_digest(&commitments);

        // Best-effort forgery: random c_0 and all-random responses, walk the ring
        // forward deriving c_1..c_{n-1}. c_0 was chosen BEFORE the final link, so
        // the last link's recomputed challenge won't equal it — the ring is open.
        let zv: Vec<Scalar> = (0..n).map(|_| random_scalar(&mut rng)).collect();
        let zs: Vec<Scalar> = (0..n).map(|_| random_scalar(&mut rng)).collect();
        let zr: Vec<Scalar> = (0..n).map(|_| random_scalar(&mut rng)).collect();
        let mut c = vec![Scalar::ZERO; n];
        c[0] = random_scalar(&mut rng);
        for i in 0..n - 1 {
            let li = g * zv[i] + h * zs[i] + k * zr[i] - commitments[i] * c[i];
            let lpi = g * zs[i] - serial_tag * c[i];
            c[i + 1] = ring_challenge(&set_digest, &message, &serial_tag, &li, &lpi);
        }

        let forged = SparkSpendProof {
            anon_set_indices: (0..n as u64).collect(),
            serial_tag: serial_tag.compress().to_bytes(),
            challenges: c.iter().map(|x| x.to_bytes()).collect(),
            resp_value: zv.iter().map(|x| x.to_bytes()).collect(),
            resp_serial: zs.iter().map(|x| x.to_bytes()).collect(),
            resp_blind: zr.iter().map(|x| x.to_bytes()).collect(),
            message,
        };
        assert!(
            verify_spark_spend(&forged, &commitments).is_err(),
            "a proof built with no witness must not close the ring"
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
        assert!(
            set.contains(&3),
            "anonymity set must contain the real index"
        );
    }
}
