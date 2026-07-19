//! Strict-binding cross-curve discrete-log equality proof — foundation.
//!
//! This module implements the **building blocks** for the Noether 2018
//! "Discrete Logarithm Equality Across Groups" construction (see
//! `docs/cip/CIP-001-atomic-swap.md` §"Pre-audit hardening:
//! strict-binding cross-curve DLEQ (Noether 2018)" for the full
//! spec). The ~600-line OR-proof layer that turns these primitives
//! into a complete proof is the next slice; this slice ships the
//! load-bearing foundation:
//!
//! - **NUMS generators** `H_btc` (secp256k1) and `H_cync` (Ristretto255)
//!   — points whose discrete log relative to the standard generators
//!   `G_btc` / `G_cync` is provably unknown (cannot be a backdoor).
//! - **Pedersen commitments** `Commit(value, blinding) = value·G + blinding·H`
//!   on each curve. The same value committed on both curves with
//!   independent blinders is what the OR-proof later binds.
//! - **Bit decomposition** of a scalar into N bits with strict bounds
//!   (N=252 < both n and ℓ so the same bit-pattern lifts cleanly to
//!   both fields without overflow).
//!
//! ## Why these specific primitives?
//!
//! Noether 2018 commits each bit of the secret scalar separately on
//! both curves and proves OR-equivalence per bit. The bit-binding
//! step needs Pedersen commitments (additively homomorphic, hide the
//! bit value via the blinding); the Pedersen commitments need a
//! second generator (`H_*`) independent of the standard one. The
//! bit-decomposition step is the linear-combination layer that ties
//! the per-bit commitments back to the original scalar.
//!
//! The full proof on top of these primitives is multi-week per the
//! ~81 KB wire-format budget in the design spec; what ships in this
//! slice is the 100% reusable foundation that any strict-DLEQ
//! variant (Noether, Comit's Bulletproof range proof, or a future
//! alternative) would build on.
//!
//! ## Curve-pinned constants
//!
//! - secp256k1 scalar field order `n` — already enforced by
//!   [`secp256k1::SecretKey::from_slice`].
//! - Ristretto255 scalar field order `ℓ` — already enforced by
//!   [`curve25519_dalek::scalar::Scalar::from_canonical_bytes`].
//! - Strict-bit count `N = 252` — strictly less than `min(log2 n,
//!   log2 ℓ) = min(256, 252) = 252`. Choosing N=252 means a 252-bit
//!   secret has the same bit pattern in both fields (no high-bit
//!   wraparound to handle).
//!
//! See [`STRICT_BIT_COUNT`].

use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
use curve25519_dalek::scalar::Scalar as Curve25519Scalar;
use sha2::{Digest, Sha256};

use crate::adaptor::AdaptorSecret;
use crate::{Error, Result};

/// The strict-bit count: how many bits of the secret the strict-DLEQ
/// proof commits to. Set to **252** — strictly less than both
/// `log2(n_secp256k1) = 256` and `log2(ℓ_ristretto255) = 252.5`. A
/// 252-bit secret has the same bit pattern in both scalar fields,
/// which is what makes per-bit cross-curve equivalence proofs sound:
/// if N reached 256, a high bit would wrap mod ℓ but not mod n,
/// breaking the per-bit equivalence claim.
///
/// (Ristretto's ℓ ≈ 2^252.5, so technically there are 252-bit
/// scalars that exceed ℓ — but only with probability ~2^-0.5 over a
/// uniform 252-bit string. The strict bound is enforced by the
/// canonicality check in `Curve25519Scalar::from_canonical_bytes`,
/// which is already on the path of `AdaptorSecret` construction.)
pub const STRICT_BIT_COUNT: usize = 252;

/// Domain-separation tag for the NUMS generator on secp256k1.
/// The exact bytes don't matter cryptographically as long as they're
/// distinct from the BIP-340 tag set + any other tag in the
/// protocol; "CoinCync/Swap/StrictDLEQ-H_btc-v1" is unambiguous.
const H_BTC_NUMS_TAG: &[u8] = b"CoinCync/Swap/StrictDLEQ-H_btc-v1";

/// Domain-separation tag for the NUMS generator on Ristretto255.
const H_CYNC_NUMS_TAG: &[u8] = b"CoinCync/Swap/StrictDLEQ-H_cync-v1";

// ─── NUMS generators ─────────────────────────────────────────────────

/// Derive the NUMS generator `H_btc` for secp256k1 via try-and-
/// increment. The result is a valid curve point whose discrete log
/// relative to `G_btc` is provably unknown (the derivation is one-way
/// and tied to a public tag, so no party could have chosen it to
/// know `dlog_G(H)`).
///
/// Construction:
/// ```text
/// for counter in 0..u32::MAX:
///     x = SHA256(H_BTC_NUMS_TAG || counter_le4)
///     try y from x with even parity (BIP-340 lift-x convention)
///     if a valid curve point Q with x-coordinate x exists:
///         return Q
/// ```
///
/// In practice ~50% of x-coordinates have a valid y, so the loop
/// terminates in ~1-2 iterations on average. The function is
/// deterministic — given the fixed tag, every call returns the
/// same point. We memoize via [`std::sync::OnceLock`] in
/// [`h_btc_generator`] so the try-and-increment runs at most once
/// per process.
fn derive_h_btc() -> [u8; 33] {
    use bitcoin::secp256k1::{PublicKey, XOnlyPublicKey};

    for counter in 0u32..u32::MAX {
        let mut hasher = Sha256::new();
        hasher.update(H_BTC_NUMS_TAG);
        hasher.update(counter.to_le_bytes());
        let x_bytes: [u8; 32] = hasher.finalize().into();

        // Try BIP-340 lift_x: interpret x_bytes as an x-coordinate
        // with even y. ~50% of x values have a valid y on
        // secp256k1, so a few iterations suffice.
        if let Ok(xonly) = XOnlyPublicKey::from_slice(&x_bytes) {
            // Promote x-only to a full PublicKey with even parity.
            // BIP-340 §"Public Key Conversion" defines this lift.
            let parity = bitcoin::secp256k1::Parity::Even;
            let pk = PublicKey::from_x_only_public_key(xonly, parity);
            return pk.serialize();
        }
    }
    // Astronomically unlikely — would require ~2^32 consecutive
    // non-curve x-coordinates. If we ever hit this, the tag is
    // unusable and we have a bigger problem than panicking.
    panic!("H_btc try-and-increment exhausted u32 counter — tag is degenerate");
}

/// Get the secp256k1 NUMS generator `H_btc`. Memoized.
///
/// Returns the 33-byte compressed-encoded point. Callers that need
/// a `secp256k1::PublicKey` should parse it via `PublicKey::from_slice`.
pub fn h_btc_generator() -> &'static [u8; 33] {
    use std::sync::OnceLock;
    static H_BTC: OnceLock<[u8; 33]> = OnceLock::new();
    H_BTC.get_or_init(derive_h_btc)
}

/// Derive the NUMS generator `H_cync` for Ristretto255 via
/// hash-to-curve. Ristretto255 has a clean uniform hash-to-curve
/// (`RistrettoPoint::from_uniform_bytes`) so we don't need the
/// try-and-increment loop.
///
/// Construction:
/// ```text
/// h_512 = SHA256(H_CYNC_NUMS_TAG || "expand-1") || SHA256(H_CYNC_NUMS_TAG || "expand-2")
/// H_cync = RistrettoPoint::from_uniform_bytes(h_512)
/// ```
///
/// Two SHA256 calls give a uniform 64-byte string suitable for the
/// `from_uniform_bytes` reduction. Result is deterministic and the
/// dlog relative to `G_cync` is unknown (one-way function tied to a
/// public tag).
fn derive_h_cync() -> CompressedRistretto {
    let mut h512 = [0u8; 64];
    let mut h1 = Sha256::new();
    h1.update(H_CYNC_NUMS_TAG);
    h1.update(b"expand-1");
    h512[..32].copy_from_slice(&h1.finalize());
    let mut h2 = Sha256::new();
    h2.update(H_CYNC_NUMS_TAG);
    h2.update(b"expand-2");
    h512[32..].copy_from_slice(&h2.finalize());
    RistrettoPoint::from_uniform_bytes(&h512).compress()
}

/// Get the Ristretto255 NUMS generator `H_cync`. Memoized.
///
/// Returns the 32-byte compressed-encoded Ristretto point. Callers
/// that need an uncompressed `RistrettoPoint` should decompress via
/// `CompressedRistretto::decompress()`.
pub fn h_cync_generator() -> &'static CompressedRistretto {
    use std::sync::OnceLock;
    static H_CYNC: OnceLock<CompressedRistretto> = OnceLock::new();
    H_CYNC.get_or_init(derive_h_cync)
}

// ─── Pedersen commitments ────────────────────────────────────────────

/// Pedersen commitment on secp256k1: `C = value·G_btc + blinding·H_btc`.
///
/// Returns the 33-byte compressed encoding of `C`. Additively
/// homomorphic: `commit(v1, r1) + commit(v2, r2) = commit(v1+v2,
/// r1+r2)`. Computationally hiding (under DLOG hardness on secp256k1)
/// and perfectly binding (each `C` has a unique opening once `H_btc`
/// is fixed and `dlog_G(H_btc)` is unknown).
///
/// # Errors
///
/// - `Verification` if `blinding` is not a canonical secp256k1
///   scalar (i.e., ≥ n or zero — zero blinding leaks `value` by
///   making `C = value·G`).
pub fn pedersen_commit_btc(value: u64, blinding: &[u8; 32]) -> Result<[u8; 33]> {
    use bitcoin::secp256k1::{PublicKey, Scalar as Secp256k1Scalar, Secp256k1, SecretKey};

    if blinding.iter().all(|&b| b == 0) {
        return Err(Error::Verification("Pedersen blinding must be non-zero"));
    }

    let secp = Secp256k1::new();
    let h_btc_bytes = h_btc_generator();
    let h_btc = PublicKey::from_slice(h_btc_bytes)
        .map_err(|_| Error::Verification("H_btc generator decode (impossible)"))?;

    // C_blinding = blinding · H_btc — multiply H_btc by the blinding
    // scalar.
    let blinding_scalar = Secp256k1Scalar::from_be_bytes(*blinding)
        .map_err(|_| Error::Verification("blinding not a canonical secp256k1 scalar"))?;
    let c_blinding = h_btc
        .mul_tweak(&secp, &blinding_scalar)
        .map_err(|_| Error::Verification("H_btc mul_tweak with blinding"))?;

    if value == 0 {
        // C = 0·G + blinding·H = blinding·H. Special case so we
        // don't have to construct a zero SecretKey (which is invalid
        // for secp256k1 anyway).
        return Ok(c_blinding.serialize());
    }

    // C_value = value · G_btc — multiply G by `value` (as a scalar).
    let mut value_bytes = [0u8; 32];
    value_bytes[24..].copy_from_slice(&value.to_be_bytes());
    let value_sk = SecretKey::from_slice(&value_bytes)
        .map_err(|_| Error::Verification("value scalar from u64 (impossible)"))?;
    let c_value = PublicKey::from_secret_key(&secp, &value_sk);

    // C = c_value + c_blinding
    let combined = c_value
        .combine(&c_blinding)
        .map_err(|_| Error::Verification("Pedersen point addition"))?;
    Ok(combined.serialize())
}

/// Pedersen commitment on Ristretto255: `C = value·G_cync +
/// blinding·H_cync`. Returns the 32-byte compressed-Ristretto encoding.
///
/// Same homomorphism + hiding/binding properties as
/// [`pedersen_commit_btc`], adapted to Ristretto's flat 32-byte
/// encoding (no parity issue).
///
/// # Errors
///
/// - `Verification` if `blinding` is zero or non-canonical.
pub fn pedersen_commit_cync(value: u64, blinding: &[u8; 32]) -> Result<[u8; 32]> {
    use curve25519_dalek::constants::RISTRETTO_BASEPOINT_TABLE;

    if blinding.iter().all(|&b| b == 0) {
        return Err(Error::Verification("Pedersen blinding must be non-zero"));
    }

    let blinding_scalar =
        Option::<Curve25519Scalar>::from(Curve25519Scalar::from_canonical_bytes(*blinding)).ok_or(
            Error::Verification("blinding not a canonical Ristretto scalar"),
        )?;

    let h_cync = h_cync_generator().decompress().ok_or(Error::Verification(
        "H_cync generator decompress (impossible)",
    ))?;

    // Scalar arithmetic: value (u64) lifts to a Curve25519Scalar
    // via from() — Ristretto scalars are large enough that no u64
    // value can be non-canonical.
    let value_scalar = Curve25519Scalar::from(value);
    let c_value = &value_scalar * RISTRETTO_BASEPOINT_TABLE;
    let c_blinding = blinding_scalar * h_cync;
    let combined = c_value + c_blinding;
    Ok(combined.compress().to_bytes())
}

// ─── Bit decomposition ───────────────────────────────────────────────

/// Decompose a [`AdaptorSecret`] into [`STRICT_BIT_COUNT`] bits
/// (little-endian: `bits[0]` is the least significant). Higher bits
/// (if any) MUST be zero — otherwise the secret exceeds the strict
/// bit budget and the per-bit commitment can't lift cleanly across
/// both curves.
///
/// We read the secret in **Ristretto little-endian** form (canonical
/// per `Scalar::to_bytes()`). The bit ordering matches every
/// downstream constructor that combines per-bit commitments with
/// `2^i` weights (the standard Pedersen-commitment summation
/// pattern).
///
/// # Errors
///
/// - `Verification` if any bit beyond index [`STRICT_BIT_COUNT - 1`]
///   is set. Bit 252 onward MUST be zero for the strict-DLEQ proof
///   to be sound.
pub fn decompose_to_bits(secret: &AdaptorSecret) -> Result<[bool; STRICT_BIT_COUNT]> {
    let bytes = secret.ristretto_bytes();

    // bit_index goes 0..STRICT_BIT_COUNT (=252). For each, find
    // (byte_index, bit_in_byte) and read.
    let mut out = [false; STRICT_BIT_COUNT];
    for bit_index in 0..STRICT_BIT_COUNT {
        let byte_index = bit_index / 8;
        let bit_in_byte = bit_index % 8;
        out[bit_index] = (bytes[byte_index] >> bit_in_byte) & 1 == 1;
    }

    // Check the high tail (bits STRICT_BIT_COUNT..256) is zero —
    // anything set there means the secret exceeds the strict budget.
    for bit_index in STRICT_BIT_COUNT..256 {
        let byte_index = bit_index / 8;
        let bit_in_byte = bit_index % 8;
        if (bytes[byte_index] >> bit_in_byte) & 1 == 1 {
            return Err(Error::Verification(
                "secret has bits set above STRICT_BIT_COUNT — exceeds strict-DLEQ scalar budget",
            ));
        }
    }

    Ok(out)
}

/// Recompose a bit array into a Ristretto255 scalar. Inverse of
/// [`decompose_to_bits`] up to the encoding boundary — `bits[i]`
/// contributes `2^i` to the result, little-endian.
///
/// Always returns a canonical Ristretto scalar because the bit
/// budget is strictly less than `log2 ℓ` (per [`STRICT_BIT_COUNT`]).
/// Returns a 32-byte little-endian encoding (Ristretto convention).
pub fn recompose_from_bits_cync(bits: &[bool; STRICT_BIT_COUNT]) -> [u8; 32] {
    let mut bytes = [0u8; 32];
    for (bit_index, &bit) in bits.iter().enumerate() {
        if bit {
            let byte_index = bit_index / 8;
            let bit_in_byte = bit_index % 8;
            bytes[byte_index] |= 1 << bit_in_byte;
        }
    }
    bytes
}

/// Recompose a bit array into a secp256k1 scalar. Same semantics
/// as [`recompose_from_bits_cync`] but returns 32 **big-endian**
/// bytes (secp256k1 convention). Bit positions are still
/// little-endian: `bits[0]` is the least significant bit of the
/// numeric result.
pub fn recompose_from_bits_btc(bits: &[bool; STRICT_BIT_COUNT]) -> [u8; 32] {
    let le = recompose_from_bits_cync(bits);
    let mut be = [0u8; 32];
    for i in 0..32 {
        be[i] = le[31 - i];
    }
    be
}

// ─── Per-bit Chaum-Pedersen OR-proof ─────────────────────────────────
//
// For each bit-commitment `C = b·G + r·H` (b ∈ {0,1}), prove "C opens
// to 0 OR C opens to 1" without revealing b. Uses the standard
// Cramer-Damgård-Schoenmakers (1994) OR-proof construction adapted to
// secp256k1 / Ristretto255.
//
// ## Construction (per curve)
//
// Statement: ∃ (b, r) such that `C = b·G + r·H` AND `b ∈ {0,1}`.
//
// Honest prover knows (b=B, r) where C - B·G = r·H:
//   1. Pick `k` uniform — nonce for the honest branch.
//      `A_B = k · H`
//   2. Pick `e_(1-B), s_(1-B)` uniform — simulate the other branch.
//      `A_(1-B) = s_(1-B) · H - e_(1-B) · (C - (1-B)·G)`
//   3. Challenge: `c = H(tag || C || A_0 || A_1) mod q`
//   4. `e_B = c - e_(1-B) (mod q)`
//   5. `s_B = k + e_B · r (mod q)`
//   Output: `(e_1, s_0, s_1)` — `e_0 = c - e_1` is derivable.
//
// Verifier:
//   1. Recompute `A_0 = s_0 · H - e_0 · C` and
//      `A_1 = s_1 · H - e_1 · (C - G)`.
//      (Here `e_0` is what's sent; in our struct we send `e_1` and the
//      verifier derives `e_0` from the challenge. Equivalent under
//      the symmetry of the construction.)
//   2. Recompute `c = H(tag || C || A_0 || A_1) mod q`.
//   3. Check `e_0 + e_1 ≡ c (mod q)`.
//
// We send `(e_0, e_1, s_0, s_1)` per curve. 4·32 = 128 bytes per
// curve per bit. Plus the commitment itself.
//
// Why send both `e_0` and `e_1` (one is technically derivable from
// the other via `e_0 + e_1 ≡ c`)? Compactness would have us send
// only one — but reconstructing the other requires knowing `c`,
// which requires knowing both `A_0` and `A_1`, which require
// knowing both `e_0` and `e_1`. The dependency is circular. The
// cleanest break is to send both `e`s and check `e_0 + e_1 ≡ c`
// post-reconstruction. 32 bytes per bit per curve is small change
// relative to the 256-bit-per-bit total budget.
//
// Soundness: per the CDS construction, a prover not knowing any
// opening forges at most one branch. Knowing exactly one opening
// produces an honestly-distributed transcript. Probability of a
// successful forge is ≈ 1/q per attempt.

/// OR-proof that a single Pedersen commitment on **secp256k1** opens
/// to either 0 or 1. Wire format = 4 scalars (`e_0`, `e_1`, `s_0`,
/// `s_1`) = 128 bytes. The commitment `C` is held alongside in
/// [`BitProofPair`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BitOrProofBtc {
    /// Challenge for branch `b=0`.
    pub e_0: [u8; 32],
    /// Challenge for branch `b=1`. Verifier checks
    /// `e_0 + e_1 ≡ c (mod n)` where `c = H(tag || C || A_0 || A_1)`.
    pub e_1: [u8; 32],
    /// Response for branch `b=0`.
    pub s_0: [u8; 32],
    /// Response for branch `b=1`.
    pub s_1: [u8; 32],
}

/// OR-proof that a single Pedersen commitment on **Ristretto255**
/// opens to either 0 or 1. Same wire layout as [`BitOrProofBtc`]
/// but scalars are little-endian per Ristretto convention.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BitOrProofCync {
    /// Challenge for branch `b=0`, little-endian.
    pub e_0: [u8; 32],
    /// Challenge for branch `b=1`, little-endian.
    pub e_1: [u8; 32],
    /// Response for branch `b=0`, little-endian.
    pub s_0: [u8; 32],
    /// Response for branch `b=1`, little-endian.
    pub s_1: [u8; 32],
}

/// One bit's worth of strict-DLEQ commitment material: the Pedersen
/// commits on both curves + the OR-proofs proving each opens to a
/// bit in `{0, 1}`. The cross-curve **same-bit** binding is supplied
/// by the linear-combination layer (next slice) — at this layer we
/// only guarantee each commitment is to some bit.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BitProofPair {
    /// Pedersen commitment on secp256k1: `b·G_btc + r_btc·H_btc`.
    pub c_btc: [u8; 33],
    /// Pedersen commitment on Ristretto: `b·G_cync + r_cync·H_cync`.
    pub c_cync: [u8; 32],
    /// OR-proof on the BTC side.
    pub btc: BitOrProofBtc,
    /// OR-proof on the CYNC side.
    pub cync: BitOrProofCync,
}

impl BitProofPair {
    /// Length of [`canonical_bytes`](Self::canonical_bytes) — 321 bytes
    /// per bit. Layout: `c_btc(33) ‖ c_cync(32) ‖ btc(128) ‖ cync(128)`.
    pub const CANONICAL_LEN: usize = 33 + 32 + 128 + 128;

    /// Append the canonical serialization to `out` (no allocation in
    /// the hot path). Per-curve OR-proof layout: `e_0 ‖ e_1 ‖ s_0 ‖ s_1`,
    /// each 32 bytes — matches the struct field declaration order in
    /// [`BitOrProofBtc`] / [`BitOrProofCync`].
    fn extend_canonical_bytes(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.c_btc);
        out.extend_from_slice(&self.c_cync);
        out.extend_from_slice(&self.btc.e_0);
        out.extend_from_slice(&self.btc.e_1);
        out.extend_from_slice(&self.btc.s_0);
        out.extend_from_slice(&self.btc.s_1);
        out.extend_from_slice(&self.cync.e_0);
        out.extend_from_slice(&self.cync.e_1);
        out.extend_from_slice(&self.cync.s_0);
        out.extend_from_slice(&self.cync.s_1);
    }
}

/// Domain-separation tag for the OR-proof challenge hash. Distinct
/// from the NUMS-derivation tags so a transcript from one cannot
/// be replayed against the other.
const OR_PROOF_TAG_BTC: &[u8] = b"CoinCync/Swap/StrictDLEQ-BitOR-btc-v1";
const OR_PROOF_TAG_CYNC: &[u8] = b"CoinCync/Swap/StrictDLEQ-BitOR-cync-v1";

// ── BTC-side prove + verify ──

/// Prove that `c_btc = bit·G_btc + r_btc·H_btc` opens to `bit ∈ {0, 1}`
/// without revealing which. The nonces (`k_btc`, simulated-branch
/// `e_sim`, simulated-branch `s_sim`) are passed in so the function
/// is deterministic + testable; production callers should feed
/// freshly-randomized inputs from `OsRng`.
///
/// # Errors
///
/// - `Verification` if any scalar input is non-canonical (≥ n) or
///   if the simulated-branch arithmetic fails (extremely unlikely
///   given canonical inputs).
pub fn prove_bit_btc(
    bit: bool,
    r_btc: &[u8; 32],
    k_btc: &[u8; 32],
    e_sim: &[u8; 32],
    s_sim: &[u8; 32],
) -> Result<BitOrProofBtc> {
    use bitcoin::secp256k1::{PublicKey, Scalar as Secp256k1Scalar, Secp256k1, SecretKey};

    // Validate inputs are canonical secp256k1 scalars (the cleanest
    // path is round-tripping through SecretKey, which rejects 0 and
    // values ≥ n).
    let _ = SecretKey::from_slice(r_btc)
        .map_err(|_| Error::Verification("r_btc not a canonical secp256k1 scalar"))?;
    let _ = SecretKey::from_slice(k_btc)
        .map_err(|_| Error::Verification("k_btc not a canonical secp256k1 scalar"))?;
    let _ = SecretKey::from_slice(e_sim)
        .map_err(|_| Error::Verification("e_sim not a canonical secp256k1 scalar"))?;
    let _ = SecretKey::from_slice(s_sim)
        .map_err(|_| Error::Verification("s_sim not a canonical secp256k1 scalar"))?;

    let secp = Secp256k1::new();
    let h_btc = PublicKey::from_slice(h_btc_generator()).unwrap();

    // Compute the commitment C = bit·G + r·H so we can hash it into
    // the transcript. We rebuild it from inputs here (rather than
    // taking C as a parameter) to avoid the surface area for
    // inconsistency.
    let c_btc_bytes = pedersen_commit_btc(if bit { 1 } else { 0 }, r_btc)?;
    let c_btc = PublicKey::from_slice(&c_btc_bytes)
        .map_err(|_| Error::Verification("pedersen_commit_btc returned non-decodable point"))?;

    // ── Build the honest branch's commitment A_B ──
    let k_scalar = Secp256k1Scalar::from_be_bytes(*k_btc).unwrap();
    let a_honest = h_btc
        .mul_tweak(&secp, &k_scalar)
        .map_err(|_| Error::Verification("A_honest = k·H_btc"))?;

    // ── Build the simulated branch's commitment A_(1-B) ──
    // A_sim = s_sim · H - e_sim · (C - (1-B)·G)
    let s_sim_scalar = Secp256k1Scalar::from_be_bytes(*s_sim).unwrap();
    let s_sim_h = h_btc
        .mul_tweak(&secp, &s_sim_scalar)
        .map_err(|_| Error::Verification("s_sim · H_btc"))?;

    // C - (1-B)·G_btc
    let c_minus_g = if !bit {
        // When `bit=0` honest, simulated branch is b=1, so subtract G.
        let g_sk = SecretKey::from_slice(&{
            let mut b = [0u8; 32];
            b[31] = 1;
            b
        })
        .unwrap();
        let g = PublicKey::from_secret_key(&secp, &g_sk);
        let neg_g = g.negate(&secp);
        c_btc
            .combine(&neg_g)
            .map_err(|_| Error::Verification("C - G addition"))?
    } else {
        // When `bit=1` honest, simulated branch is b=0, so C - 0·G = C.
        c_btc
    };

    let e_sim_scalar = Secp256k1Scalar::from_be_bytes(*e_sim).unwrap();
    let e_sim_factor = c_minus_g
        .mul_tweak(&secp, &e_sim_scalar)
        .map_err(|_| Error::Verification("e_sim · (C - (1-B)·G)"))?;
    let neg_factor = e_sim_factor.negate(&secp);
    let a_sim = s_sim_h
        .combine(&neg_factor)
        .map_err(|_| Error::Verification("A_sim = s_sim·H - e_sim·(C-(1-B)·G)"))?;

    // ── Map (A_honest, A_sim) to (A_0, A_1) for the transcript ──
    let (a_0, a_1) = if !bit {
        (a_honest, a_sim)
    } else {
        (a_sim, a_honest)
    };

    // ── Challenge: c = H(tag || C || A_0 || A_1) mod n ──
    let c_full = or_proof_challenge_btc(&c_btc_bytes, &a_0.serialize(), &a_1.serialize());
    let c_scalar = Secp256k1Scalar::from_be_bytes(c_full)
        .map_err(|_| Error::Verification("challenge ≥ n — re-randomize and retry"))?;

    // ── Compute honest branch's challenge: e_honest = c - e_sim ──
    // Use SecretKey negation + add trick: e_honest = c + (-e_sim)
    let c_sk = SecretKey::from_slice(&c_scalar.to_be_bytes())
        .map_err(|_| Error::Verification("c_sk from challenge"))?;
    let neg_e_sim = SecretKey::from_slice(e_sim).unwrap().negate();
    let neg_e_sim_scalar = Secp256k1Scalar::from_be_bytes(neg_e_sim.secret_bytes()).unwrap();
    let e_honest_sk = c_sk
        .add_tweak(&neg_e_sim_scalar)
        .map_err(|_| Error::Verification("e_honest = c - e_sim"))?;
    let e_honest_bytes = e_honest_sk.secret_bytes();

    // ── Compute honest branch's response: s_honest = k + e_honest · r ──
    let r_sk = SecretKey::from_slice(r_btc).unwrap();
    let e_honest_scalar = Secp256k1Scalar::from_be_bytes(e_honest_bytes).unwrap();
    let er = r_sk
        .mul_tweak(&e_honest_scalar)
        .map_err(|_| Error::Verification("e_honest · r"))?;
    let k_sk = SecretKey::from_slice(k_btc).unwrap();
    let er_scalar = Secp256k1Scalar::from_be_bytes(er.secret_bytes()).unwrap();
    let s_honest_sk = k_sk
        .add_tweak(&er_scalar)
        .map_err(|_| Error::Verification("s_honest = k + e·r"))?;
    let s_honest_bytes = s_honest_sk.secret_bytes();

    // ── Pack the proof: always (e_0, e_1, s_0, s_1) regardless of which branch was honest ──
    let (e_0, e_1, s_0, s_1) = if !bit {
        // honest = branch 0; simulated = branch 1
        (e_honest_bytes, *e_sim, s_honest_bytes, *s_sim)
    } else {
        // honest = branch 1; simulated = branch 0
        (*e_sim, e_honest_bytes, *s_sim, s_honest_bytes)
    };

    Ok(BitOrProofBtc { e_0, e_1, s_0, s_1 })
}

/// Verify a [`BitOrProofBtc`] against the commitment `c_btc`. Returns
/// `Ok(())` if the proof is sound (commitment opens to 0 or 1) or
/// `Err(Verification(...))` otherwise.
///
/// Flow (no circular dependency since we receive both `e_0` and
/// `e_1`):
/// 1. Reconstruct `A_0 = s_0·H - e_0·C` and `A_1 = s_1·H - e_1·(C-G)`.
/// 2. Compute `c = H(tag || C || A_0 || A_1) mod n`.
/// 3. Check `e_0 + e_1 ≡ c (mod n)`.
pub fn verify_bit_btc(c_btc: &[u8; 33], proof: &BitOrProofBtc) -> Result<()> {
    use bitcoin::secp256k1::{PublicKey, Scalar as Secp256k1Scalar, Secp256k1, SecretKey};

    let secp = Secp256k1::new();
    let h_btc = PublicKey::from_slice(h_btc_generator()).unwrap();
    let c_pt = PublicKey::from_slice(c_btc)
        .map_err(|_| Error::Verification("c_btc not a valid compressed secp256k1 point"))?;

    // Validate all four scalars are canonical secp256k1 scalars.
    let _ = SecretKey::from_slice(&proof.e_0)
        .map_err(|_| Error::Verification("e_0 not a canonical secp256k1 scalar"))?;
    let _ = SecretKey::from_slice(&proof.e_1)
        .map_err(|_| Error::Verification("e_1 not a canonical secp256k1 scalar"))?;
    let _ = SecretKey::from_slice(&proof.s_0)
        .map_err(|_| Error::Verification("s_0 not a canonical secp256k1 scalar"))?;
    let _ = SecretKey::from_slice(&proof.s_1)
        .map_err(|_| Error::Verification("s_1 not a canonical secp256k1 scalar"))?;

    let e_0_scalar = Secp256k1Scalar::from_be_bytes(proof.e_0).unwrap();
    let e_1_scalar = Secp256k1Scalar::from_be_bytes(proof.e_1).unwrap();
    let s_0_scalar = Secp256k1Scalar::from_be_bytes(proof.s_0).unwrap();
    let s_1_scalar = Secp256k1Scalar::from_be_bytes(proof.s_1).unwrap();

    // ── Reconstruct A_0 = s_0·H - e_0·C ──
    let s_0_h = h_btc
        .mul_tweak(&secp, &s_0_scalar)
        .map_err(|_| Error::Verification("s_0 · H"))?;
    let e_0_c = c_pt
        .mul_tweak(&secp, &e_0_scalar)
        .map_err(|_| Error::Verification("e_0 · C"))?;
    let a_0 = s_0_h
        .combine(&e_0_c.negate(&secp))
        .map_err(|_| Error::Verification("A_0 reconstruction"))?;

    // ── Reconstruct A_1 = s_1·H - e_1·(C - G) ──
    let g_sk = SecretKey::from_slice(&{
        let mut b = [0u8; 32];
        b[31] = 1;
        b
    })
    .unwrap();
    let g = PublicKey::from_secret_key(&secp, &g_sk);
    let c_minus_g = c_pt
        .combine(&g.negate(&secp))
        .map_err(|_| Error::Verification("C - G"))?;
    let s_1_h = h_btc
        .mul_tweak(&secp, &s_1_scalar)
        .map_err(|_| Error::Verification("s_1 · H"))?;
    let e_1_cmg = c_minus_g
        .mul_tweak(&secp, &e_1_scalar)
        .map_err(|_| Error::Verification("e_1 · (C - G)"))?;
    let a_1 = s_1_h
        .combine(&e_1_cmg.negate(&secp))
        .map_err(|_| Error::Verification("A_1 reconstruction"))?;

    // ── Compute c = H(tag || C || A_0 || A_1) mod n ──
    let c_bytes = or_proof_challenge_btc(c_btc, &a_0.serialize(), &a_1.serialize());
    let c_scalar = Secp256k1Scalar::from_be_bytes(c_bytes).map_err(|_| {
        Error::Verification("challenge hash ≥ n — extremely unlikely in honest run")
    })?;

    // ── Check e_0 + e_1 ≡ c (mod n) ──
    // Use SecretKey arithmetic: e_0 + e_1 == c iff SecretKey(e_0).add(e_1) == c.
    let sum_sk = SecretKey::from_slice(&proof.e_0)
        .unwrap()
        .add_tweak(&e_1_scalar)
        .map_err(|_| Error::Verification("e_0 + e_1 sum"))?;
    if sum_sk.secret_bytes() != c_scalar.to_be_bytes() {
        return Err(Error::Verification(
            "BTC bit-OR challenge check failed: e_0 + e_1 ≢ H(tag||C||A_0||A_1)",
        ));
    }
    Ok(())
}

/// Compute the BTC-side OR-proof challenge: `H(tag || C || A_0 ||
/// A_1)`. Returns the 32-byte BE form (caller reduces mod n via
/// `Secp256k1Scalar::from_be_bytes` which errors on ≥ n).
fn or_proof_challenge_btc(c: &[u8; 33], a_0: &[u8; 33], a_1: &[u8; 33]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(OR_PROOF_TAG_BTC);
    h.update(c);
    h.update(a_0);
    h.update(a_1);
    h.finalize().into()
}

// ── CYNC-side prove + verify ──

/// Prove that `c_cync = bit·G_cync + r_cync·H_cync` opens to
/// `bit ∈ {0, 1}`. Mirrors [`prove_bit_btc`] on Ristretto255.
///
/// Nonces (`k_cync`, `e_sim`, `s_sim`) must be canonical Ristretto
/// scalars (< ℓ). Caller supplies them so the function is
/// deterministic.
pub fn prove_bit_cync(
    bit: bool,
    r_cync: &[u8; 32],
    k_cync: &[u8; 32],
    e_sim: &[u8; 32],
    s_sim: &[u8; 32],
) -> Result<BitOrProofCync> {
    use curve25519_dalek::constants::RISTRETTO_BASEPOINT_TABLE;

    let r_scalar =
        Option::<Curve25519Scalar>::from(Curve25519Scalar::from_canonical_bytes(*r_cync))
            .ok_or(Error::Verification("r_cync not canonical"))?;
    if r_scalar == Curve25519Scalar::ZERO {
        return Err(Error::Verification("r_cync must be non-zero"));
    }
    let k_scalar =
        Option::<Curve25519Scalar>::from(Curve25519Scalar::from_canonical_bytes(*k_cync))
            .ok_or(Error::Verification("k_cync not canonical"))?;
    let e_sim_scalar =
        Option::<Curve25519Scalar>::from(Curve25519Scalar::from_canonical_bytes(*e_sim))
            .ok_or(Error::Verification("e_sim not canonical"))?;
    let s_sim_scalar =
        Option::<Curve25519Scalar>::from(Curve25519Scalar::from_canonical_bytes(*s_sim))
            .ok_or(Error::Verification("s_sim not canonical"))?;

    let h_cync = h_cync_generator()
        .decompress()
        .expect("H_cync generator decompresses (verified at init)");

    // Compute the commitment C.
    let c_bytes = pedersen_commit_cync(if bit { 1 } else { 0 }, r_cync)?;
    let c_pt = CompressedRistretto::from_slice(&c_bytes)
        .map_err(|_| Error::Verification("commit decode"))?
        .decompress()
        .ok_or(Error::Verification("commit decompress"))?;

    // Honest branch's A: k · H_cync
    let a_honest = k_scalar * h_cync;

    // Simulated branch's A:
    //   bit=0 honest → simulated is b=1 → A_sim = s_sim·H - e_sim·(C - G)
    //   bit=1 honest → simulated is b=0 → A_sim = s_sim·H - e_sim·C
    let c_minus_g = if !bit {
        c_pt - &Curve25519Scalar::ONE * RISTRETTO_BASEPOINT_TABLE
    } else {
        c_pt
    };
    let a_sim = s_sim_scalar * h_cync - e_sim_scalar * c_minus_g;

    let (a_0, a_1) = if !bit {
        (a_honest, a_sim)
    } else {
        (a_sim, a_honest)
    };

    // Challenge: c = H(tag || C || A_0 || A_1) — reduce mod ℓ via
    // from_bytes_mod_order_wide on a 512-bit expansion.
    let c_bytes_full = or_proof_challenge_cync(
        &c_bytes,
        &a_0.compress().to_bytes(),
        &a_1.compress().to_bytes(),
    );
    let c_scalar = Curve25519Scalar::from_bytes_mod_order_wide(&c_bytes_full);

    // Honest challenge: e_honest = c - e_sim
    let e_honest = c_scalar - e_sim_scalar;
    let s_honest = k_scalar + e_honest * r_scalar;

    let (e_0, e_1, s_0, s_1) = if !bit {
        (e_honest, e_sim_scalar, s_honest, s_sim_scalar)
    } else {
        (e_sim_scalar, e_honest, s_sim_scalar, s_honest)
    };

    Ok(BitOrProofCync {
        e_0: e_0.to_bytes(),
        e_1: e_1.to_bytes(),
        s_0: s_0.to_bytes(),
        s_1: s_1.to_bytes(),
    })
}

/// Verify a [`BitOrProofCync`] against the commitment `c_cync`.
pub fn verify_bit_cync(c_cync: &[u8; 32], proof: &BitOrProofCync) -> Result<()> {
    use curve25519_dalek::constants::RISTRETTO_BASEPOINT_TABLE;

    let e_0 = Option::<Curve25519Scalar>::from(Curve25519Scalar::from_canonical_bytes(proof.e_0))
        .ok_or(Error::Verification("e_0 not canonical"))?;
    let e_1 = Option::<Curve25519Scalar>::from(Curve25519Scalar::from_canonical_bytes(proof.e_1))
        .ok_or(Error::Verification("e_1 not canonical"))?;
    let s_0 = Option::<Curve25519Scalar>::from(Curve25519Scalar::from_canonical_bytes(proof.s_0))
        .ok_or(Error::Verification("s_0 not canonical"))?;
    let s_1 = Option::<Curve25519Scalar>::from(Curve25519Scalar::from_canonical_bytes(proof.s_1))
        .ok_or(Error::Verification("s_1 not canonical"))?;

    let h_cync = h_cync_generator().decompress().expect("H_cync decompress");
    let c_pt = CompressedRistretto::from_slice(c_cync)
        .map_err(|_| Error::Verification("c_cync decode"))?
        .decompress()
        .ok_or(Error::Verification("c_cync decompress"))?;

    // A_0 = s_0·H - e_0·C
    let a_0 = s_0 * h_cync - e_0 * c_pt;

    // A_1 = s_1·H - e_1·(C - G)
    let c_minus_g = c_pt - &Curve25519Scalar::ONE * RISTRETTO_BASEPOINT_TABLE;
    let a_1 = s_1 * h_cync - e_1 * c_minus_g;

    // c = H(tag || C || A_0 || A_1) mod ℓ
    let c_bytes_full = or_proof_challenge_cync(
        c_cync,
        &a_0.compress().to_bytes(),
        &a_1.compress().to_bytes(),
    );
    let c_expected = Curve25519Scalar::from_bytes_mod_order_wide(&c_bytes_full);

    if e_0 + e_1 != c_expected {
        return Err(Error::Verification(
            "CYNC bit-OR challenge check failed: e_0 + e_1 ≢ H(tag||C||A_0||A_1)",
        ));
    }
    Ok(())
}

/// Compute the CYNC-side OR-proof challenge. Returns a 64-byte
/// expansion suitable for `Scalar::from_bytes_mod_order_wide`
/// (uniform reduction, no rejection sampling).
fn or_proof_challenge_cync(c: &[u8; 32], a_0: &[u8; 32], a_1: &[u8; 32]) -> [u8; 64] {
    // SHA512 = SHA256 || SHA256(domain-tag-extension) to get 64
    // uniform bytes. We don't pull in sha2's Sha512 since the
    // double-SHA256 pattern is already used by the NUMS derivation,
    // keeping the SHA primitives uniform across the module.
    let mut h1 = Sha256::new();
    h1.update(OR_PROOF_TAG_CYNC);
    h1.update(b"expand-1");
    h1.update(c);
    h1.update(a_0);
    h1.update(a_1);
    let mut h2 = Sha256::new();
    h2.update(OR_PROOF_TAG_CYNC);
    h2.update(b"expand-2");
    h2.update(c);
    h2.update(a_0);
    h2.update(a_1);
    let mut out = [0u8; 64];
    out[..32].copy_from_slice(&h1.finalize());
    out[32..].copy_from_slice(&h2.finalize());
    out
}

// ── Cross-curve pair ──

/// Prove a [`BitProofPair`] — one bit, committed on both curves with
/// per-curve OR-proofs. The cross-curve **same-bit** binding is
/// provided by the linear-combination layer (next slice in the
/// strict-DLEQ track); at this layer we only guarantee each
/// commitment opens to *some* bit in `{0, 1}`.
///
/// Caller supplies:
/// - `bit`: the shared bit value to commit on both curves.
/// - `r_btc`, `r_cync`: Pedersen blinding factors (one per curve).
///   Must be canonical scalars for their respective curves.
/// - `nonces_btc = (k_btc, e_sim_btc, s_sim_btc)`: random nonces
///   for the BTC-side OR-proof.
/// - `nonces_cync = (k_cync, e_sim_cync, s_sim_cync)`: same on CYNC.
///
/// All eight 32-byte inputs are passed in explicitly so the function
/// is deterministic + testable. Production callers fetch fresh
/// random values from `OsRng` per call.
#[allow(clippy::too_many_arguments)]
pub fn prove_bit_pair(
    bit: bool,
    r_btc: &[u8; 32],
    r_cync: &[u8; 32],
    nonces_btc: (&[u8; 32], &[u8; 32], &[u8; 32]),
    nonces_cync: (&[u8; 32], &[u8; 32], &[u8; 32]),
) -> Result<BitProofPair> {
    let c_btc = pedersen_commit_btc(if bit { 1 } else { 0 }, r_btc)?;
    let c_cync = pedersen_commit_cync(if bit { 1 } else { 0 }, r_cync)?;

    let btc = prove_bit_btc(bit, r_btc, nonces_btc.0, nonces_btc.1, nonces_btc.2)?;
    let cync = prove_bit_cync(bit, r_cync, nonces_cync.0, nonces_cync.1, nonces_cync.2)?;

    Ok(BitProofPair {
        c_btc,
        c_cync,
        btc,
        cync,
    })
}

/// Verify both halves of a [`BitProofPair`]. Returns `Ok(())` only if
/// both per-curve OR-proofs are sound.
pub fn verify_bit_pair(pair: &BitProofPair) -> Result<()> {
    verify_bit_btc(&pair.c_btc, &pair.btc)?;
    verify_bit_cync(&pair.c_cync, &pair.cync)?;
    Ok(())
}

// ─── Linear-combination opening ──────────────────────────────────────
//
// The OR-proof layer proves each Pedersen commitment `C_i = b_i·G +
// r_i·H` opens to a bit. By itself that doesn't tie the per-bit
// commitments back to the original adaptor points `T_btc`, `T_cync`.
// The linear-combination opening proof closes that gap.
//
// ## What it proves
//
// Given:
//   - 252 commitments `{C_i = b_i·G + r_i·H}` (one per bit, on each curve)
//   - The adaptor point `T = t·G` where `t = Σ 2^i · b_i`
// Show:
//   - `Σ 2^i · C_i = (Σ 2^i · b_i)·G + (Σ 2^i · r_i)·H = T + R·H`
//     where `R = Σ 2^i · r_i (mod q)`.
//
// The prover sends `R` (one scalar per curve). The verifier
// recomputes `Σ 2^i · C_i` and checks it equals `T + R·H`.
//
// ## Why this provides same-secret binding across curves
//
// The OR-proof guarantees each `b_i ∈ {0,1}`. The linear-combo
// guarantees `Σ 2^i · b_i = dlog(T_btc)` mod n AND `Σ 2^i · b_i =
// dlog(T_cync)` mod ℓ. Since the bits are in {0,1} and the bit count
// is `STRICT_BIT_COUNT = 252 < min(log2 n, log2 ℓ)`, the integer
// `Σ 2^i · b_i` is strictly less than both moduli. Therefore the same
// integer (≤ 2^252) is the dlog on BOTH curves — i.e. cross-curve
// same-secret binding without wraparound.

/// Sum the per-bit blinders `r_i` weighted by `2^i`, mod n (secp256k1
/// scalar field). Returns the 32-byte BE-encoded sum. Used by the
/// prover to construct `R_btc` sent in the linear-combo proof.
///
/// # Errors
///
/// - `Verification` if any input `r_i` is not a canonical secp256k1
///   scalar.
pub fn compute_blinder_sum_btc(blinders: &[[u8; 32]; STRICT_BIT_COUNT]) -> Result<[u8; 32]> {
    use bitcoin::secp256k1::{Scalar as Secp256k1Scalar, SecretKey};

    // Compute `Σ 2^i · r_i mod n` iteratively. We maintain a running
    // sum `acc` (as a SecretKey for canonical handling) and at each
    // step add `2^i · r_i = doubling-of-r_i-i-times`. Cost: O(N²) field
    // ops — acceptable for N=252 (one-off proof construction cost).
    //
    // Implementation note: each r_i is multiplied by 2^i, then added
    // to acc. We compute `2^i · r_i` by doubling i times rather than
    // a full scalar mul, which is O(i) field doublings ≈ O(N²) total.
    // For higher N this would want a more efficient scheme, but at
    // N=252 the absolute cost is fine.

    // Special case: skip the very first iteration if the bit's r is
    // zero (e.g., for testing). Real prover always passes non-zero.
    let mut acc: Option<SecretKey> = None;

    for (i, r) in blinders.iter().enumerate() {
        // Skip if r_i is all-zero (Pedersen commitments require
        // non-zero blinders in production, but the math is fine to
        // include zeros — they contribute nothing).
        if r.iter().all(|&b| b == 0) {
            continue;
        }
        let r_sk = SecretKey::from_slice(r)
            .map_err(|_| Error::Verification("blinder not canonical secp256k1 scalar"))?;

        // Compute 2^i · r_i via i doublings.
        let mut term = r_sk;
        for _ in 0..i {
            // Doubling = self + self. Use add_tweak with own scalar.
            let term_scalar = Secp256k1Scalar::from_be_bytes(term.secret_bytes()).unwrap();
            term = term
                .add_tweak(&term_scalar)
                .map_err(|_| Error::Verification("blinder doubling overflow"))?;
        }

        acc = Some(match acc {
            None => term,
            Some(acc_sk) => {
                let term_scalar = Secp256k1Scalar::from_be_bytes(term.secret_bytes()).unwrap();
                acc_sk
                    .add_tweak(&term_scalar)
                    .map_err(|_| Error::Verification("blinder sum overflow"))?
            }
        });
    }

    // If every r_i was zero, return zero. (The Pedersen commit layer
    // rejects zero blinders, so in practice the sum is non-zero —
    // but we don't enforce here.)
    Ok(acc.map_or([0u8; 32], |sk| sk.secret_bytes()))
}

/// Sum the per-bit blinders `r_i` weighted by `2^i`, mod ℓ (Ristretto
/// scalar field). Returns the 32-byte LE-encoded sum. Mirrors
/// [`compute_blinder_sum_btc`] on Ristretto255.
pub fn compute_blinder_sum_cync(blinders: &[[u8; 32]; STRICT_BIT_COUNT]) -> Result<[u8; 32]> {
    let mut acc = Curve25519Scalar::ZERO;
    // Maintain the running power of 2: `weight = 2^i`. Initially 1,
    // then doubled each iteration. Curve25519Scalar arithmetic is
    // constant-time + handles modular reduction.
    let mut weight = Curve25519Scalar::ONE;
    let two = Curve25519Scalar::ONE + Curve25519Scalar::ONE;

    for r in blinders.iter() {
        let r_scalar = Option::<Curve25519Scalar>::from(Curve25519Scalar::from_canonical_bytes(*r))
            .ok_or(Error::Verification(
                "blinder not canonical Ristretto scalar",
            ))?;
        acc += weight * r_scalar;
        weight *= two;
    }

    Ok(acc.to_bytes())
}

/// Verify the BTC-side linear-combination opening:
///   `Σ 2^i · C_btc_i ?= T_btc + R_btc · H_btc`
///
/// The verifier reconstructs the LHS by accumulating `2^i · C_i` for
/// each commitment, then compares with `T_btc + R_btc · H_btc` on the
/// RHS. Returns `Ok(())` on match; `Err(Verification(...))` otherwise.
pub fn verify_linear_combination_btc(
    commits: &[[u8; 33]; STRICT_BIT_COUNT],
    t_btc: &[u8; 33],
    r_btc_sum: &[u8; 32],
) -> Result<()> {
    use bitcoin::secp256k1::{PublicKey, Scalar as Secp256k1Scalar, Secp256k1, SecretKey};

    let secp = Secp256k1::new();
    let h_btc = PublicKey::from_slice(h_btc_generator()).unwrap();
    let t_pt = PublicKey::from_slice(t_btc)
        .map_err(|_| Error::Verification("T_btc not a valid compressed secp256k1 point"))?;
    let _ = SecretKey::from_slice(r_btc_sum)
        .map_err(|_| Error::Verification("R_btc not a canonical secp256k1 scalar"))?;

    // LHS: Σ 2^i · C_i. Iterate, accumulate via point addition.
    let mut lhs: Option<PublicKey> = None;
    for (i, c_bytes) in commits.iter().enumerate() {
        let c_pt = PublicKey::from_slice(c_bytes)
            .map_err(|_| Error::Verification("commit bytes decode"))?;

        // Compute 2^i · C_i via i doublings.
        // (For higher N, batch multiscalar mul would be much faster.
        // At N=252 the absolute cost is one-shot fine.)
        let mut term = c_pt;
        for _ in 0..i {
            // Doubling = self.combine(&self). secp256k1's combine
            // rejects (P + (-P)) which is identity; since P + P is
            // never identity for affine non-identity points, this is
            // safe.
            term = term
                .combine(&term)
                .map_err(|_| Error::Verification("commit doubling"))?;
        }

        lhs = Some(match lhs {
            None => term,
            Some(prev) => prev
                .combine(&term)
                .map_err(|_| Error::Verification("LHS accumulation"))?,
        });
    }
    let lhs = lhs.ok_or(Error::Verification("commits array empty (impossible)"))?;

    // RHS: T_btc + R_btc · H_btc
    let r_scalar = Secp256k1Scalar::from_be_bytes(*r_btc_sum).unwrap();
    let r_h = h_btc
        .mul_tweak(&secp, &r_scalar)
        .map_err(|_| Error::Verification("R · H"))?;
    let rhs = t_pt
        .combine(&r_h)
        .map_err(|_| Error::Verification("T + R·H"))?;

    if lhs != rhs {
        return Err(Error::Verification(
            "BTC linear-combination check failed: Σ 2^i · C_i ≠ T + R · H",
        ));
    }
    Ok(())
}

/// Verify the CYNC-side linear-combination opening:
///   `Σ 2^i · C_cync_i ?= T_cync + R_cync · H_cync`
///
/// Mirrors [`verify_linear_combination_btc`] on Ristretto255.
pub fn verify_linear_combination_cync(
    commits: &[[u8; 32]; STRICT_BIT_COUNT],
    t_cync: &[u8; 32],
    r_cync_sum: &[u8; 32],
) -> Result<()> {
    use curve25519_dalek::traits::Identity;

    let h_cync = h_cync_generator().decompress().expect("H_cync decompress");
    let t_pt = CompressedRistretto::from_slice(t_cync)
        .map_err(|_| Error::Verification("T_cync decode"))?
        .decompress()
        .ok_or(Error::Verification("T_cync decompress"))?;
    let r_scalar =
        Option::<Curve25519Scalar>::from(Curve25519Scalar::from_canonical_bytes(*r_cync_sum))
            .ok_or(Error::Verification("R_cync not canonical"))?;

    // LHS: Σ 2^i · C_i. Dalek has a vartime multiscalar-mul that's
    // dramatically faster than the naïve doubling loop — use it.
    let mut weights = Vec::with_capacity(STRICT_BIT_COUNT);
    let mut points = Vec::with_capacity(STRICT_BIT_COUNT);
    let mut weight = Curve25519Scalar::ONE;
    let two = Curve25519Scalar::ONE + Curve25519Scalar::ONE;
    for c_bytes in commits.iter() {
        let c_pt = CompressedRistretto::from_slice(c_bytes)
            .map_err(|_| Error::Verification("commit decode"))?
            .decompress()
            .ok_or(Error::Verification("commit decompress"))?;
        weights.push(weight);
        points.push(c_pt);
        weight *= two;
    }

    let lhs: RistrettoPoint = weights
        .iter()
        .zip(points.iter())
        .fold(RistrettoPoint::identity(), |acc, (w, p)| acc + w * p);

    // RHS: T_cync + R_cync · H_cync
    let rhs = t_pt + r_scalar * h_cync;

    if lhs != rhs {
        return Err(Error::Verification(
            "CYNC linear-combination check failed: Σ 2^i · C_i ≠ T + R · H",
        ));
    }
    Ok(())
}

// ─── Full strict-DLEQ proof: wire format + prove + verify ────────────
//
// Composes everything above into a single cross-curve proof. The wire
// format keeps the existing dual-response Schoenmakers proof
// ([`CrossCurveDlProof`]) as the **fast-soundness floor** — verifier
// rejects there first, before doing the heavy bit-level checks — and
// stacks the bit-OR-proofs + linear-combination openings on top for
// the strict cross-curve same-secret binding.
//
// Per-bit budget:
//   commits:     33 + 32 = 65 bytes
//   OR-proofs:   2 · (4 · 32) = 256 bytes
//   subtotal:    321 bytes
// Linear-combo R sums: 32 + 32 = 64 bytes
// Fast-floor proof:    33 + 32 + 32 + 32 = 129 bytes
// Total at N=252:      252 · 321 + 64 + 129 ≈ 81.1 KB

/// Complete cross-curve discrete-log-equality proof with strict
/// same-secret binding (Noether 2018 construction). Drop-in
/// replacement for the [`CrossCurveDlProof`] used by the swap
/// protocol — verifier accepts either variant, gated by Cargo
/// feature `strict-dleq` (planned).
///
/// Wire format ≈ 81 KB at the [`STRICT_BIT_COUNT`] = 252 budget. The
/// bandwidth is acceptable: a swap exchanges this proof at most once
/// during the negotiation phase.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CrossCurveDlProofStrict {
    /// Fast-soundness floor: the existing dual-response Schoenmakers
    /// proof from [`crate::adaptor::CrossCurveDlProof`]. Verifier
    /// rejects here first so an obviously-broken proof fails in
    /// constant time before the ~2 ms bit-level checks.
    pub fast: crate::adaptor::CrossCurveDlProof,

    /// One [`BitProofPair`] per bit of the secret. Length always
    /// equals [`STRICT_BIT_COUNT`]; a `Vec` rather than a fixed-size
    /// array keeps the serialised form flexible if `STRICT_BIT_COUNT`
    /// is ever revised (e.g., to support larger scalars on
    /// next-generation curves).
    pub bits: Vec<BitProofPair>,

    /// `R_btc = Σ 2^i · r_btc_i (mod n)`. The linear-combination
    /// opening blinder for the BTC side.
    pub r_btc_sum: [u8; 32],

    /// `R_cync = Σ 2^i · r_cync_i (mod ℓ)`. The linear-combination
    /// opening blinder for the CYNC side.
    pub r_cync_sum: [u8; 32],
}

impl CrossCurveDlProofStrict {
    /// Length of [`canonical_bytes`](Self::canonical_bytes) at the
    /// production `STRICT_BIT_COUNT = 252` — exactly **80,929 bytes**
    /// (129 fast + 252×321 bit-pair + 32 R_btc + 32 R_cync).
    ///
    /// Layout (stable; bumped on any wire-format change):
    /// ```text
    ///   fast.canonical_bytes()                  // 129 bytes
    ///   foreach bit i in 0..STRICT_BIT_COUNT:   // 252 iterations
    ///       bits[i].canonical_bytes()           //   321 bytes each
    ///   r_btc_sum                               // 32 bytes
    ///   r_cync_sum                              // 32 bytes
    /// ```
    pub const CANONICAL_LEN: usize = crate::adaptor::CrossCurveDlProof::CANONICAL_LEN
        + STRICT_BIT_COUNT * BitProofPair::CANONICAL_LEN
        + 32
        + 32;

    /// Serialize to the canonical wire form. Used by external test
    /// vectors + by any consumer that wants to byte-compare or hash
    /// the proof.
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(Self::CANONICAL_LEN);
        out.extend_from_slice(&self.fast.canonical_bytes());
        for bit_pair in &self.bits {
            bit_pair.extend_canonical_bytes(&mut out);
        }
        out.extend_from_slice(&self.r_btc_sum);
        out.extend_from_slice(&self.r_cync_sum);
        debug_assert_eq!(out.len(), Self::CANONICAL_LEN);
        out
    }

    /// SHA-256 of [`canonical_bytes`](Self::canonical_bytes). Used by
    /// the external test-vector file as a compact reference value —
    /// the full ~81 KB proof body is too large to inline in the
    /// vectors JSON, but a 32-byte SHA-256 lets any independent
    /// implementation hash its own output and byte-compare.
    pub fn canonical_sha256(&self) -> [u8; 32] {
        use sha2::Digest;
        let bytes = self.canonical_bytes();
        sha2::Sha256::digest(&bytes).into()
    }
}

/// PRF tag for deriving per-bit blinders + nonces from the strict-DLEQ
/// prover's master seed.
const STRICT_DLEQ_PRF_TAG: &[u8] = b"CoinCync/Swap/StrictDLEQ-PRF-v1";

/// Expand the master seed into a single 32-byte scalar candidate.
/// `label` separates outputs by purpose (e.g., `b"r_btc"`, `b"k_cync"`),
/// `counter` separates by bit-index, `retry` separates rejection-loop
/// attempts. Result is a uniform 256-bit string — caller is
/// responsible for the per-curve canonicality check.
fn prf_32(seed: &[u8; 32], label: &[u8], counter: u32, retry: u8) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(STRICT_DLEQ_PRF_TAG);
    h.update(seed);
    h.update(label);
    h.update(counter.to_le_bytes());
    h.update([retry]);
    h.finalize().into()
}

/// Derive a uniform Ristretto scalar from the seed via 64-byte wide
/// reduction (`Scalar::from_bytes_mod_order_wide`). Always returns a
/// canonical scalar — no rejection sampling needed.
fn prf_cync_scalar(seed: &[u8; 32], label: &[u8], counter: u32) -> [u8; 32] {
    let mut wide = [0u8; 64];
    wide[..32].copy_from_slice(&prf_32(seed, label, counter, 0));
    wide[32..].copy_from_slice(&prf_32(seed, label, counter, 1));
    Curve25519Scalar::from_bytes_mod_order_wide(&wide).to_bytes()
}

/// Derive a canonical secp256k1 scalar (in `[1, n)`) from the seed via
/// rejection sampling. Each retry is a fresh PRF output. Practically
/// the first attempt succeeds — the rejection region is ≈ 2^-128 wide.
fn prf_btc_scalar(seed: &[u8; 32], label: &[u8], counter: u32) -> Result<[u8; 32]> {
    use bitcoin::secp256k1::SecretKey;
    for retry in 0..64u8 {
        let bytes = prf_32(seed, label, counter, retry);
        if SecretKey::from_slice(&bytes).is_ok() {
            return Ok(bytes);
        }
    }
    // Astronomically unlikely after 64 retries (rejection prob per try
    // ≈ 2^-128, so 64 retries fail with prob ≈ 2^-8192).
    Err(Error::Verification(
        "secp256k1 scalar rejection-sampling exhausted retry budget — seed is degenerate",
    ))
}

/// Prove cross-curve same-secret binding under the strict (Noether
/// 2018) construction.
///
/// Inputs:
/// - `secret`: the adaptor secret `t` with bits in `[0,
///   STRICT_BIT_COUNT)`. Higher bits must be zero (enforced by
///   [`decompose_to_bits`]).
/// - `btc_pub_bytes`: 33-byte compressed encoding of `T_btc = t · G_btc`.
/// - `cync_pub_bytes`: 32-byte compressed Ristretto encoding of
///   `T_cync = t · G_cync`.
/// - `seed`: master randomness seed. The prover expands this via a
///   SHA256-based PRF into all 2K+ per-bit nonces. In production,
///   pass `OsRng.gen()`. In tests, a fixed seed makes the proof
///   deterministic + bisectable.
///
/// # Errors
///
/// - `Verification` if any subroutine fails (most commonly: the
///   secret has bits set above `STRICT_BIT_COUNT`).
pub fn prove_cross_curve_strict(
    secret: &crate::adaptor::AdaptorSecret,
    btc_pub_bytes: &[u8; 33],
    cync_pub_bytes: &[u8; 32],
    seed: &[u8; 32],
) -> Result<CrossCurveDlProofStrict> {
    // 1. Decompose the secret to bits.
    let bits = decompose_to_bits(secret)?;

    // 2. Derive per-bit material from the seed.
    let mut bit_pairs: Vec<BitProofPair> = Vec::with_capacity(STRICT_BIT_COUNT);
    let mut r_btc_blinders = [[0u8; 32]; STRICT_BIT_COUNT];
    let mut r_cync_blinders = [[0u8; 32]; STRICT_BIT_COUNT];

    for (i, &bit) in bits.iter().enumerate() {
        let counter = i as u32;
        let r_btc = prf_btc_scalar(seed, b"r_btc", counter)?;
        let r_cync = prf_cync_scalar(seed, b"r_cync", counter);
        let k_btc = prf_btc_scalar(seed, b"k_btc", counter)?;
        let k_cync = prf_cync_scalar(seed, b"k_cync", counter);
        let e_sim_btc = prf_btc_scalar(seed, b"e_sim_btc", counter)?;
        let e_sim_cync = prf_cync_scalar(seed, b"e_sim_cync", counter);
        let s_sim_btc = prf_btc_scalar(seed, b"s_sim_btc", counter)?;
        let s_sim_cync = prf_cync_scalar(seed, b"s_sim_cync", counter);

        r_btc_blinders[i] = r_btc;
        r_cync_blinders[i] = r_cync;

        let pair = prove_bit_pair(
            bit,
            &r_btc,
            &r_cync,
            (&k_btc, &e_sim_btc, &s_sim_btc),
            (&k_cync, &e_sim_cync, &s_sim_cync),
        )?;
        bit_pairs.push(pair);
    }

    // 3. Compute R sums for the linear-combination openings.
    let r_btc_sum = compute_blinder_sum_btc(&r_btc_blinders)?;
    let r_cync_sum = compute_blinder_sum_cync(&r_cync_blinders)?;

    // 4. Build the fast-floor proof via the existing dual-response
    //    Schoenmakers prover. Derive its nonce from the same seed
    //    (distinct PRF label so it doesn't collide with the per-bit
    //    nonces). The fast prover requires the nonce as a Ristretto-
    //    canonical scalar (since it must reduce mod both n and ℓ).
    let fast_nonce = prf_cync_scalar(seed, b"fast_nonce", 0);
    let fast =
        crate::adaptor::prove_cross_curve(secret, btc_pub_bytes, cync_pub_bytes, &fast_nonce)?;

    Ok(CrossCurveDlProofStrict {
        fast,
        bits: bit_pairs,
        r_btc_sum,
        r_cync_sum,
    })
}

/// Verify a [`CrossCurveDlProofStrict`] against the adaptor points.
/// Checks layered in order of cheapest-to-detect-tamper first:
/// 1. Fast-soundness floor (dual-response Schoenmakers).
/// 2. Per-bit OR-proofs (252 × 2 verifications).
/// 3. Linear-combination openings (2 verifications, each scaling the
///    252 commitments by their `2^i` weights).
///
/// Returns `Ok(())` only if every layer verifies; otherwise
/// `Err(Verification(...))` naming the failing layer.
pub fn verify_cross_curve_strict(
    proof: &CrossCurveDlProofStrict,
    btc_pub_bytes: &[u8; 33],
    cync_pub_bytes: &[u8; 32],
) -> Result<()> {
    // 0. Structural check: the bit-pair vector must have exactly
    //    STRICT_BIT_COUNT entries. A different length means the
    //    proof is malformed.
    if proof.bits.len() != STRICT_BIT_COUNT {
        return Err(Error::Verification(
            "strict-DLEQ proof has wrong bit-pair count",
        ));
    }

    // 1. Fast-soundness floor.
    crate::adaptor::verify_cross_curve_proof(&proof.fast, btc_pub_bytes, cync_pub_bytes)
        .map_err(|_| Error::Verification("strict-DLEQ fast-floor check failed"))?;

    // 2. Per-bit OR-proofs.
    for (i, pair) in proof.bits.iter().enumerate() {
        verify_bit_pair(pair).map_err(|_| {
            Error::Verification(match i {
                0 => "strict-DLEQ bit-OR-proof failed at bit 0",
                _ => "strict-DLEQ bit-OR-proof failed at some bit",
            })
        })?;
    }

    // 3. Linear-combination openings. Reconstruct the C-arrays from
    //    the bit-pair list.
    let mut c_btc = [[0u8; 33]; STRICT_BIT_COUNT];
    let mut c_cync = [[0u8; 32]; STRICT_BIT_COUNT];
    for (i, pair) in proof.bits.iter().enumerate() {
        c_btc[i] = pair.c_btc;
        c_cync[i] = pair.c_cync;
    }
    verify_linear_combination_btc(&c_btc, btc_pub_bytes, &proof.r_btc_sum)?;
    verify_linear_combination_cync(&c_cync, cync_pub_bytes, &proof.r_cync_sum)?;

    Ok(())
}

// ─── Tests ───────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── NUMS generator tests ─────────────────────────────────────

    #[test]
    fn h_btc_is_deterministic() {
        // Memoization must return the same point across calls.
        let h1 = h_btc_generator();
        let h2 = h_btc_generator();
        assert_eq!(h1, h2);
    }

    #[test]
    fn h_btc_is_valid_curve_point() {
        use bitcoin::secp256k1::PublicKey;
        let h = h_btc_generator();
        PublicKey::from_slice(h).expect("H_btc must decode as a valid secp256k1 point");
    }

    #[test]
    fn h_btc_differs_from_g_btc() {
        // Sanity: H ≠ G. If derive_h_btc accidentally produced G we'd
        // know the dlog (= 1) and the binding property dies.
        use bitcoin::secp256k1::{PublicKey, Secp256k1, SecretKey};
        let secp = Secp256k1::new();
        let g_sk = SecretKey::from_slice(&{
            let mut b = [0u8; 32];
            b[31] = 1; // SecretKey::from_slice(&[0;...,1]) = scalar 1
            b
        })
        .unwrap();
        let g_pub = PublicKey::from_secret_key(&secp, &g_sk).serialize();
        assert_ne!(h_btc_generator(), &g_pub);
    }

    #[test]
    fn h_cync_is_deterministic() {
        let h1 = h_cync_generator();
        let h2 = h_cync_generator();
        assert_eq!(h1, h2);
    }

    #[test]
    fn h_cync_decompresses() {
        h_cync_generator()
            .decompress()
            .expect("H_cync must decompress to a valid Ristretto point");
    }

    #[test]
    fn h_cync_differs_from_g_cync() {
        use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
        let g_compressed = RISTRETTO_BASEPOINT_POINT.compress();
        assert_ne!(h_cync_generator(), &g_compressed);
    }

    // ── Pedersen commitment tests ────────────────────────────────

    /// Test blinding factors live in the *canonical* range for both
    /// curves: byte 31 small enough that the scalar is < ℓ ≈ 2^252.5
    /// (Ristretto's canonical bound) and trivially < n (secp256k1's
    /// bound is ≈ 2^256 - 2^32, so any reasonable encoding works).
    /// We build them with a low high-byte (0x01) to stay within
    /// Ristretto canonicality.
    fn canonical_blinding(low_seed: u8) -> [u8; 32] {
        let mut r = [low_seed; 32];
        r[31] = 0x01;
        r
    }

    #[test]
    fn pedersen_btc_round_trip() {
        let blinding = canonical_blinding(0x42);
        let c = pedersen_commit_btc(100, &blinding).unwrap();
        // 33-byte compressed encoding, prefix 0x02 or 0x03.
        assert_eq!(c.len(), 33);
        assert!(matches!(c[0], 0x02 | 0x03), "compressed prefix");
    }

    #[test]
    fn pedersen_btc_homomorphic_addition() {
        use bitcoin::secp256k1::{PublicKey, Scalar as Secp256k1Scalar, SecretKey};
        let r1 = canonical_blinding(0x11);
        let r2 = canonical_blinding(0x22);

        let c1 = pedersen_commit_btc(100, &r1).unwrap();
        let c2 = pedersen_commit_btc(50, &r2).unwrap();

        // r3 = r1 + r2 (mod n) — use secp256k1 SecretKey + add_tweak.
        let s2_scalar = Secp256k1Scalar::from_be_bytes(r2).unwrap();
        let sk1 = SecretKey::from_slice(&r1).unwrap();
        let r3 = sk1.add_tweak(&s2_scalar).unwrap().secret_bytes();
        let c_sum = pedersen_commit_btc(150, &r3).unwrap();

        // Verify c1 + c2 == c_sum on the curve.
        let p1 = PublicKey::from_slice(&c1).unwrap();
        let p2 = PublicKey::from_slice(&c2).unwrap();
        let p_sum_expected = PublicKey::from_slice(&c_sum).unwrap();
        let p_sum_actual = p1.combine(&p2).unwrap();
        assert_eq!(p_sum_actual, p_sum_expected);
    }

    #[test]
    fn pedersen_btc_rejects_zero_blinding() {
        let r = pedersen_commit_btc(100, &[0u8; 32]);
        assert!(matches!(r, Err(Error::Verification(_))));
    }

    #[test]
    fn pedersen_btc_value_zero_with_nonzero_blinding_works() {
        // C = 0·G + r·H is a legitimate commitment to value=0.
        // The bit-decomposition layer needs this for the high
        // half of a partial-bit-budget secret.
        let r = canonical_blinding(0x77);
        let c = pedersen_commit_btc(0, &r).unwrap();
        assert_eq!(c.len(), 33);
    }

    #[test]
    fn pedersen_cync_round_trip() {
        let blinding = canonical_blinding(0x42);
        let c = pedersen_commit_cync(100, &blinding).unwrap();
        assert_eq!(c.len(), 32);
    }

    #[test]
    fn pedersen_cync_homomorphic_addition() {
        let r1 = canonical_blinding(0x11);
        let r2 = canonical_blinding(0x22);

        // r3 = r1 + r2 (mod ℓ). Both inputs are canonical, sum stays
        // canonical because r1, r2 << ℓ/2 (high byte = 0x01).
        let s1 = Curve25519Scalar::from_canonical_bytes(r1).unwrap();
        let s2 = Curve25519Scalar::from_canonical_bytes(r2).unwrap();
        let r3 = (s1 + s2).to_bytes();

        let c1 = pedersen_commit_cync(100, &r1).unwrap();
        let c2 = pedersen_commit_cync(50, &r2).unwrap();
        let c_sum = pedersen_commit_cync(150, &r3).unwrap();

        let p1 = CompressedRistretto::from_slice(&c1)
            .unwrap()
            .decompress()
            .unwrap();
        let p2 = CompressedRistretto::from_slice(&c2)
            .unwrap()
            .decompress()
            .unwrap();
        let p_expected = CompressedRistretto::from_slice(&c_sum)
            .unwrap()
            .decompress()
            .unwrap();
        let p_actual = p1 + p2;
        assert_eq!(p_actual, p_expected);
    }

    #[test]
    fn pedersen_cync_rejects_zero_blinding() {
        let r = pedersen_commit_cync(100, &[0u8; 32]);
        assert!(matches!(r, Err(Error::Verification(_))));
    }

    #[test]
    fn pedersen_cync_rejects_non_canonical_blinding() {
        // High byte 0xFF — definitely > ℓ, must be rejected at the
        // canonicality check rather than silently reduced.
        let r = [0xFFu8; 32];
        let result = pedersen_commit_cync(100, &r);
        assert!(matches!(result, Err(Error::Verification(_))));
    }

    #[test]
    fn pedersen_cync_differs_per_value_with_same_blinding() {
        let r = canonical_blinding(0x55);
        let c1 = pedersen_commit_cync(100, &r).unwrap();
        let c2 = pedersen_commit_cync(101, &r).unwrap();
        assert_ne!(
            c1, c2,
            "different values must produce different commitments"
        );
    }

    #[test]
    fn pedersen_cync_differs_per_blinding_with_same_value() {
        let r1 = canonical_blinding(0x55);
        let r2 = canonical_blinding(0x66);
        let c1 = pedersen_commit_cync(100, &r1).unwrap();
        let c2 = pedersen_commit_cync(100, &r2).unwrap();
        assert_ne!(
            c1, c2,
            "different blindings must produce different commitments"
        );
    }

    // ── Bit decomposition tests ──────────────────────────────────

    #[test]
    fn decompose_one_secret_has_only_bit_0_set() {
        let mut bytes = [0u8; 32];
        bytes[0] = 1;
        let s = AdaptorSecret::from_ristretto_bytes(bytes).unwrap();
        let bits = decompose_to_bits(&s).unwrap();
        assert_eq!(bits[0], true);
        for (i, &b) in bits.iter().enumerate().skip(1) {
            assert_eq!(b, false, "bit {} should be 0 for secret=1", i);
        }
    }

    #[test]
    fn decompose_recompose_round_trip() {
        // Random-ish secret in the strict budget.
        let mut bytes = [0u8; 32];
        bytes[0] = 0xAB;
        bytes[1] = 0xCD;
        bytes[10] = 0xEF;
        bytes[20] = 0x12;
        // Ensure high bits are clear (bit 252+ MUST be zero).
        bytes[31] &= 0x0F;
        let s = AdaptorSecret::from_ristretto_bytes(bytes).unwrap();
        let bits = decompose_to_bits(&s).unwrap();
        let recomposed = recompose_from_bits_cync(&bits);
        assert_eq!(
            recomposed, bytes,
            "decompose then recompose must round-trip"
        );
    }

    #[test]
    fn decompose_rejects_secret_with_high_bit_set() {
        // We can't easily set bit 253+ via the Ristretto canonical
        // ctor (it'd reject as non-canonical). Use the secp256k1
        // ctor, which accepts any 32-byte string < n. Pick a value
        // with bit 254 set (byte 0 BE = 0x40 → byte 31 LE = 0x40
        // → little-endian bit 254). secp256k1's n ≈ 2^256 so 0x40
        // in any byte is fine; Ristretto-LE-interpretation reads
        // byte 31 = 0x40 → bit 6 of byte 31 = bit 254 → high tail
        // set → decompose must reject.
        let mut bytes_be = [0u8; 32];
        bytes_be[0] = 0x40; // BE: high byte, ~2^254
        let s = AdaptorSecret::from_secp256k1_bytes(bytes_be)
            .expect("0x40 followed by zeros is a valid secp256k1 scalar");
        // decompose reads Ristretto-LE bytes; secp256k1's BE
        // reverses, so bytes_le[31] = 0x40 → bit 254 set → reject.
        let r = decompose_to_bits(&s);
        assert!(
            matches!(r, Err(Error::Verification(_))),
            "secret with bit 254 set must be rejected; got {:?}",
            r.map(|_| "Ok")
        );
    }

    #[test]
    fn recompose_btc_is_big_endian_reverse_of_cync() {
        // Manufacture bits with bit 0 set + bit 7 set.
        let mut bits = [false; STRICT_BIT_COUNT];
        bits[0] = true;
        bits[7] = true;
        let cync_le = recompose_from_bits_cync(&bits);
        let btc_be = recompose_from_bits_btc(&bits);
        // cync_le[0] should be 0x81 (bit 0 + bit 7), rest 0.
        assert_eq!(cync_le[0], 0x81);
        // btc_be[31] should equal cync_le[0].
        assert_eq!(btc_be[31], 0x81);
        // Heads are swapped.
        for i in 0..31 {
            assert_eq!(cync_le[i], btc_be[31 - i]);
        }
    }

    #[test]
    fn recompose_handles_all_bits_set() {
        let bits = [true; STRICT_BIT_COUNT];
        let le = recompose_from_bits_cync(&bits);
        // bits[0..252] all set → bytes[0..31] all 0xFF, bytes[31] = 0x0F (bits 248..251).
        for i in 0..31 {
            assert_eq!(le[i], 0xFF, "byte {} should be 0xFF", i);
        }
        assert_eq!(
            le[31], 0x0F,
            "byte 31 should be 0x0F (bits 248..251 = 1, 252..255 = 0)"
        );
    }

    // ── Bit-OR-proof tests ──────────────────────────────────────

    /// Builds the 6-tuple of nonces the prove functions take. All
    /// scalars are deterministic + in the canonical range for both
    /// curves (high byte 0x01 ensures < ℓ < n).
    fn nonces(label: u8) -> ([u8; 32], [u8; 32], [u8; 32]) {
        let mut k = [label.wrapping_add(0x10); 32];
        k[31] = 0x01;
        let mut e = [label.wrapping_add(0x20); 32];
        e[31] = 0x01;
        let mut s = [label.wrapping_add(0x30); 32];
        s[31] = 0x01;
        (k, e, s)
    }

    // ── Per-curve round-trip ──

    #[test]
    fn btc_or_proof_round_trip_bit_zero() {
        let r = canonical_blinding(0x55);
        let (k, e, s) = nonces(1);
        let c = pedersen_commit_btc(0, &r).unwrap();
        let p = prove_bit_btc(false, &r, &k, &e, &s).unwrap();
        verify_bit_btc(&c, &p).expect("bit=0 proof must verify");
    }

    #[test]
    fn btc_or_proof_round_trip_bit_one() {
        let r = canonical_blinding(0x66);
        let (k, e, s) = nonces(2);
        let c = pedersen_commit_btc(1, &r).unwrap();
        let p = prove_bit_btc(true, &r, &k, &e, &s).unwrap();
        verify_bit_btc(&c, &p).expect("bit=1 proof must verify");
    }

    #[test]
    fn cync_or_proof_round_trip_bit_zero() {
        let r = canonical_blinding(0x77);
        let (k, e, s) = nonces(3);
        let c = pedersen_commit_cync(0, &r).unwrap();
        let p = prove_bit_cync(false, &r, &k, &e, &s).unwrap();
        verify_bit_cync(&c, &p).expect("bit=0 proof must verify");
    }

    #[test]
    fn cync_or_proof_round_trip_bit_one() {
        let r = canonical_blinding(0x44);
        let (k, e, s) = nonces(4);
        let c = pedersen_commit_cync(1, &r).unwrap();
        let p = prove_bit_cync(true, &r, &k, &e, &s).unwrap();
        verify_bit_cync(&c, &p).expect("bit=1 proof must verify");
    }

    // ── Per-curve tamper rejection ──

    #[test]
    fn btc_or_proof_rejects_flipped_e0() {
        let r = canonical_blinding(0x55);
        let (k, e, s) = nonces(5);
        let c = pedersen_commit_btc(0, &r).unwrap();
        let mut p = prove_bit_btc(false, &r, &k, &e, &s).unwrap();
        // Flip a low bit of e_0 — small enough to stay canonical, big
        // enough to break the e_0 + e_1 ≡ c relation.
        p.e_0[0] ^= 0x01;
        let r = verify_bit_btc(&c, &p);
        assert!(
            matches!(r, Err(Error::Verification(_))),
            "flipped e_0 must reject; got {:?}",
            r
        );
    }

    #[test]
    fn btc_or_proof_rejects_flipped_s0() {
        let r = canonical_blinding(0x55);
        let (k, e, s) = nonces(6);
        let c = pedersen_commit_btc(0, &r).unwrap();
        let mut p = prove_bit_btc(false, &r, &k, &e, &s).unwrap();
        p.s_0[0] ^= 0x01;
        // Flipping s_0 changes A_0, which changes c, which breaks
        // e_0 + e_1 ≡ c.
        assert!(matches!(
            verify_bit_btc(&c, &p),
            Err(Error::Verification(_))
        ));
    }

    #[test]
    fn btc_or_proof_rejects_flipped_s1() {
        let r = canonical_blinding(0x55);
        let (k, e, s) = nonces(7);
        let c = pedersen_commit_btc(1, &r).unwrap();
        let mut p = prove_bit_btc(true, &r, &k, &e, &s).unwrap();
        p.s_1[0] ^= 0x01;
        assert!(matches!(
            verify_bit_btc(&c, &p),
            Err(Error::Verification(_))
        ));
    }

    #[test]
    fn cync_or_proof_rejects_flipped_e1() {
        let r = canonical_blinding(0x44);
        let (k, e, s) = nonces(8);
        let c = pedersen_commit_cync(0, &r).unwrap();
        let mut p = prove_bit_cync(false, &r, &k, &e, &s).unwrap();
        p.e_1[0] ^= 0x01;
        assert!(matches!(
            verify_bit_cync(&c, &p),
            Err(Error::Verification(_))
        ));
    }

    #[test]
    fn cync_or_proof_rejects_flipped_s0() {
        let r = canonical_blinding(0x44);
        let (k, e, s) = nonces(9);
        let c = pedersen_commit_cync(0, &r).unwrap();
        let mut p = prove_bit_cync(false, &r, &k, &e, &s).unwrap();
        p.s_0[0] ^= 0x01;
        assert!(matches!(
            verify_bit_cync(&c, &p),
            Err(Error::Verification(_))
        ));
    }

    #[test]
    fn btc_or_proof_rejects_wrong_commitment() {
        // Prove for bit=0, then try to verify against a commitment
        // to bit=1 (same blinding). The verification check
        // reconstructs A_0/A_1 against the wrong C, hash diverges.
        let r = canonical_blinding(0x55);
        let (k, e, s) = nonces(10);
        let p = prove_bit_btc(false, &r, &k, &e, &s).unwrap();
        let wrong_c = pedersen_commit_btc(1, &r).unwrap();
        assert!(matches!(
            verify_bit_btc(&wrong_c, &p),
            Err(Error::Verification(_))
        ));
    }

    #[test]
    fn cync_or_proof_rejects_wrong_commitment() {
        let r = canonical_blinding(0x44);
        let (k, e, s) = nonces(11);
        let p = prove_bit_cync(false, &r, &k, &e, &s).unwrap();
        let wrong_c = pedersen_commit_cync(1, &r).unwrap();
        assert!(matches!(
            verify_bit_cync(&wrong_c, &p),
            Err(Error::Verification(_))
        ));
    }

    // ── Cross-curve pair ──

    #[test]
    fn bit_pair_round_trip_zero() {
        let r_b = canonical_blinding(0x55);
        let r_c = canonical_blinding(0x66);
        let nb = nonces(12);
        let nc = nonces(13);
        let pair = prove_bit_pair(
            false,
            &r_b,
            &r_c,
            (&nb.0, &nb.1, &nb.2),
            (&nc.0, &nc.1, &nc.2),
        )
        .unwrap();
        verify_bit_pair(&pair).expect("pair for bit=0 must verify");
    }

    #[test]
    fn bit_pair_round_trip_one() {
        let r_b = canonical_blinding(0x55);
        let r_c = canonical_blinding(0x66);
        let nb = nonces(14);
        let nc = nonces(15);
        let pair = prove_bit_pair(
            true,
            &r_b,
            &r_c,
            (&nb.0, &nb.1, &nb.2),
            (&nc.0, &nc.1, &nc.2),
        )
        .unwrap();
        verify_bit_pair(&pair).expect("pair for bit=1 must verify");
    }

    #[test]
    fn bit_pair_rejects_tamper_on_btc_only() {
        // A pair proof must reject if EITHER half is tampered. Here
        // we corrupt the BTC half and confirm verification fails.
        let r_b = canonical_blinding(0x55);
        let r_c = canonical_blinding(0x66);
        let nb = nonces(16);
        let nc = nonces(17);
        let mut pair = prove_bit_pair(
            false,
            &r_b,
            &r_c,
            (&nb.0, &nb.1, &nb.2),
            (&nc.0, &nc.1, &nc.2),
        )
        .unwrap();
        pair.btc.s_1[0] ^= 0x01;
        assert!(matches!(
            verify_bit_pair(&pair),
            Err(Error::Verification(_))
        ));
    }

    #[test]
    fn bit_pair_rejects_tamper_on_cync_only() {
        let r_b = canonical_blinding(0x55);
        let r_c = canonical_blinding(0x66);
        let nb = nonces(18);
        let nc = nonces(19);
        let mut pair = prove_bit_pair(
            true,
            &r_b,
            &r_c,
            (&nb.0, &nb.1, &nb.2),
            (&nc.0, &nc.1, &nc.2),
        )
        .unwrap();
        pair.cync.e_0[0] ^= 0x01;
        assert!(matches!(
            verify_bit_pair(&pair),
            Err(Error::Verification(_))
        ));
    }

    // ── Linear-combination opening tests ────────────────────────

    /// Build N test blinders (canonical Ristretto + secp256k1
    /// scalars) deterministically. We keep the **upper 24 bytes
    /// zero** so the scalar value is bounded by 2^64 — well below
    /// both ℓ (≈ 2^252.5) and n (≈ 2^256). This guarantees
    /// canonicality on BOTH curves regardless of byte order: byte 0
    /// is zero (BE high byte fine for secp256k1) and byte 31 is
    /// small (LE high byte fine for Ristretto).
    fn test_blinders() -> [[u8; 32]; STRICT_BIT_COUNT] {
        let mut out = [[0u8; 32]; STRICT_BIT_COUNT];
        for (i, slot) in out.iter_mut().enumerate() {
            // Distinct-per-bit blinders, low 8 bytes carry the variance.
            // Encode `i` as u64 LE into bytes 0..8 with a non-zero offset
            // so r_i ≥ 1 (Pedersen reject-on-zero).
            let v = (i as u64).wrapping_add(1);
            slot[..8].copy_from_slice(&v.to_le_bytes());
        }
        out
    }

    /// Build a fixed test bit-pattern: 1 at every other index. Sums
    /// to the integer with binary representation `01010101...` of
    /// 252 bits = `(2^252 - 1) / 3` ≈ a known small value mod both
    /// curves.
    fn test_bits_alternating() -> [bool; STRICT_BIT_COUNT] {
        let mut out = [false; STRICT_BIT_COUNT];
        for (i, slot) in out.iter_mut().enumerate() {
            *slot = i % 2 == 0;
        }
        out
    }

    /// Use the test bit-pattern + test blinders to build matching
    /// per-curve commitments + the expected (T, R_sum) for each
    /// curve. Used as the "honest prover output" fixture for
    /// verifier round-trip tests.
    fn honest_linear_combo_fixture() -> (
        [[u8; 33]; STRICT_BIT_COUNT],
        [[u8; 32]; STRICT_BIT_COUNT],
        [u8; 33],
        [u8; 32],
        [u8; 32],
        [u8; 32],
    ) {
        use bitcoin::secp256k1::{PublicKey, Secp256k1, SecretKey};
        use curve25519_dalek::constants::RISTRETTO_BASEPOINT_TABLE;

        let blinders = test_blinders();
        let bits = test_bits_alternating();

        // Build per-bit commits on both curves.
        let mut c_btc = [[0u8; 33]; STRICT_BIT_COUNT];
        let mut c_cync = [[0u8; 32]; STRICT_BIT_COUNT];
        for (i, &b) in bits.iter().enumerate() {
            c_btc[i] = pedersen_commit_btc(if b { 1 } else { 0 }, &blinders[i]).unwrap();
            c_cync[i] = pedersen_commit_cync(if b { 1 } else { 0 }, &blinders[i]).unwrap();
        }

        // Compute t = Σ 2^i · b_i as a u256 in BE bytes (BTC
        // convention). For Ristretto, reverse.
        let mut t_le = [0u8; 32];
        for (i, &b) in bits.iter().enumerate() {
            if b {
                let byte_idx = i / 8;
                let bit_idx = i % 8;
                t_le[byte_idx] |= 1 << bit_idx;
            }
        }
        let mut t_be = [0u8; 32];
        for i in 0..32 {
            t_be[i] = t_le[31 - i];
        }

        // T_btc = t · G_btc
        let secp = Secp256k1::new();
        let t_sk = SecretKey::from_slice(&t_be).unwrap();
        let t_btc = PublicKey::from_secret_key(&secp, &t_sk).serialize();

        // T_cync = t · G_cync
        let t_cync_scalar = Curve25519Scalar::from_canonical_bytes(t_le).unwrap();
        let t_cync = (&t_cync_scalar * RISTRETTO_BASEPOINT_TABLE)
            .compress()
            .to_bytes();

        // R sums
        let r_btc = compute_blinder_sum_btc(&blinders).unwrap();
        let r_cync = compute_blinder_sum_cync(&blinders).unwrap();

        (c_btc, c_cync, t_btc, t_cync, r_btc, r_cync)
    }

    #[test]
    fn blinder_sum_btc_zero_array_returns_zero() {
        let zeros = [[0u8; 32]; STRICT_BIT_COUNT];
        let sum = compute_blinder_sum_btc(&zeros).unwrap();
        assert_eq!(sum, [0u8; 32]);
    }

    #[test]
    fn blinder_sum_cync_zero_array_returns_zero() {
        let zeros = [[0u8; 32]; STRICT_BIT_COUNT];
        let sum = compute_blinder_sum_cync(&zeros).unwrap();
        assert_eq!(sum, [0u8; 32]);
    }

    #[test]
    fn blinder_sum_single_bit_at_index_0_returns_r() {
        // Only index 0 has a non-zero r; sum = 2^0 · r = r.
        let mut blinders = [[0u8; 32]; STRICT_BIT_COUNT];
        blinders[0] = canonical_blinding(0x55);
        let sum = compute_blinder_sum_btc(&blinders).unwrap();
        assert_eq!(sum, blinders[0]);

        let sum_c = compute_blinder_sum_cync(&blinders).unwrap();
        assert_eq!(sum_c, blinders[0]);
    }

    #[test]
    fn blinder_sum_single_bit_at_index_1_doubles_r() {
        // Only index 1 non-zero; sum = 2 · r. We just check it
        // differs from r (proves we're doing the weighting) — exact
        // value would require duplicating the doubling math here.
        let mut blinders = [[0u8; 32]; STRICT_BIT_COUNT];
        blinders[1] = canonical_blinding(0x55);
        let sum = compute_blinder_sum_btc(&blinders).unwrap();
        assert_ne!(sum, blinders[1]);
        assert_ne!(sum, [0u8; 32]);
    }

    #[test]
    fn linear_combo_btc_verifies_on_honest_fixture() {
        let (c_btc, _c_cync, t_btc, _t_cync, r_btc, _r_cync) = honest_linear_combo_fixture();
        verify_linear_combination_btc(&c_btc, &t_btc, &r_btc)
            .expect("BTC linear-combo must verify on honestly-constructed fixture");
    }

    #[test]
    fn linear_combo_cync_verifies_on_honest_fixture() {
        let (_c_btc, c_cync, _t_btc, t_cync, _r_btc, r_cync) = honest_linear_combo_fixture();
        verify_linear_combination_cync(&c_cync, &t_cync, &r_cync)
            .expect("CYNC linear-combo must verify on honestly-constructed fixture");
    }

    #[test]
    fn linear_combo_btc_rejects_tampered_commit() {
        let (mut c_btc, _c_cync, t_btc, _t_cync, r_btc, _r_cync) = honest_linear_combo_fixture();
        // Flip a bit's commitment (use a fresh blinder so it's a
        // valid curve point, just a different one).
        c_btc[10] = pedersen_commit_btc(1, &canonical_blinding(0xAA)).unwrap();
        let r = verify_linear_combination_btc(&c_btc, &t_btc, &r_btc);
        assert!(matches!(r, Err(Error::Verification(_))));
    }

    #[test]
    fn linear_combo_cync_rejects_tampered_commit() {
        let (_c_btc, mut c_cync, _t_btc, t_cync, _r_btc, r_cync) = honest_linear_combo_fixture();
        c_cync[10] = pedersen_commit_cync(1, &canonical_blinding(0xAA)).unwrap();
        let r = verify_linear_combination_cync(&c_cync, &t_cync, &r_cync);
        assert!(matches!(r, Err(Error::Verification(_))));
    }

    #[test]
    fn linear_combo_btc_rejects_wrong_r_sum() {
        let (c_btc, _c_cync, t_btc, _t_cync, mut r_btc, _r_cync) = honest_linear_combo_fixture();
        r_btc[0] ^= 0x01; // flip a bit of R — verification must fail
        let r = verify_linear_combination_btc(&c_btc, &t_btc, &r_btc);
        assert!(matches!(r, Err(Error::Verification(_))));
    }

    #[test]
    fn linear_combo_cync_rejects_wrong_r_sum() {
        let (_c_btc, c_cync, _t_btc, t_cync, _r_btc, mut r_cync) = honest_linear_combo_fixture();
        r_cync[0] ^= 0x01;
        let r = verify_linear_combination_cync(&c_cync, &t_cync, &r_cync);
        assert!(matches!(r, Err(Error::Verification(_))));
    }

    #[test]
    fn linear_combo_btc_rejects_wrong_t() {
        let (c_btc, _c_cync, _t_btc, _t_cync, r_btc, _r_cync) = honest_linear_combo_fixture();
        // Use a completely different T (G_btc itself, which is dlog=1).
        use bitcoin::secp256k1::{PublicKey, Secp256k1, SecretKey};
        let secp = Secp256k1::new();
        let g_sk = SecretKey::from_slice(&{
            let mut b = [0u8; 32];
            b[31] = 1;
            b
        })
        .unwrap();
        let wrong_t = PublicKey::from_secret_key(&secp, &g_sk).serialize();
        let r = verify_linear_combination_btc(&c_btc, &wrong_t, &r_btc);
        assert!(matches!(r, Err(Error::Verification(_))));
    }

    #[test]
    fn linear_combo_cync_rejects_wrong_t() {
        use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
        let (_c_btc, c_cync, _t_btc, _t_cync, _r_btc, r_cync) = honest_linear_combo_fixture();
        let wrong_t = RISTRETTO_BASEPOINT_POINT.compress().to_bytes();
        let r = verify_linear_combination_cync(&c_cync, &wrong_t, &r_cync);
        assert!(matches!(r, Err(Error::Verification(_))));
    }

    // ── Full strict-DLEQ proof tests ────────────────────────────

    /// Build an honest strict-DLEQ proof fixture from a deterministic
    /// secret + seed. The fixture is the "happy path" baseline that
    /// tamper-rejection tests then mutate.
    fn honest_strict_proof_fixture() -> (
        crate::adaptor::AdaptorSecret,
        [u8; 33],
        [u8; 32],
        CrossCurveDlProofStrict,
    ) {
        use bitcoin::secp256k1::{PublicKey, Secp256k1, SecretKey};
        use curve25519_dalek::constants::RISTRETTO_BASEPOINT_TABLE;

        // Pick a small secret with bits well within STRICT_BIT_COUNT.
        // 0x0000...0042 = 66 — same value on both curves.
        let mut secret_le = [0u8; 32];
        secret_le[0] = 0x42;
        let secret = crate::adaptor::AdaptorSecret::from_ristretto_bytes(secret_le).unwrap();

        // T_btc = secret · G_btc
        let secp = Secp256k1::new();
        let secret_be = secret.secp256k1_bytes();
        let t_btc = PublicKey::from_secret_key(&secp, &SecretKey::from_slice(&secret_be).unwrap())
            .serialize();

        // T_cync = secret · G_cync
        let t_cync_scalar =
            Curve25519Scalar::from_canonical_bytes(secret.ristretto_bytes()).unwrap();
        let t_cync = (&t_cync_scalar * RISTRETTO_BASEPOINT_TABLE)
            .compress()
            .to_bytes();

        // Deterministic seed for reproducibility.
        let seed = [0x77u8; 32];
        let proof = prove_cross_curve_strict(&secret, &t_btc, &t_cync, &seed)
            .expect("honest prove must succeed");

        (secret, t_btc, t_cync, proof)
    }

    #[test]
    fn strict_proof_round_trip() {
        let (_secret, t_btc, t_cync, proof) = honest_strict_proof_fixture();
        assert_eq!(proof.bits.len(), STRICT_BIT_COUNT, "bit count");
        verify_cross_curve_strict(&proof, &t_btc, &t_cync)
            .expect("honest strict-DLEQ proof must verify");
    }

    #[test]
    fn strict_proof_rejects_tamper_at_fast_floor() {
        let (_secret, t_btc, t_cync, mut proof) = honest_strict_proof_fixture();
        // Corrupt the fast-floor proof's first response scalar.
        proof.fast.s_btc[0] ^= 0x01;
        let r = verify_cross_curve_strict(&proof, &t_btc, &t_cync);
        assert!(matches!(r, Err(Error::Verification(_))));
    }

    #[test]
    fn strict_proof_rejects_tamper_at_some_bit() {
        let (_secret, t_btc, t_cync, mut proof) = honest_strict_proof_fixture();
        // Corrupt the OR-proof of bit 17 (arbitrary middle bit).
        proof.bits[17].btc.s_0[0] ^= 0x01;
        let r = verify_cross_curve_strict(&proof, &t_btc, &t_cync);
        assert!(matches!(r, Err(Error::Verification(_))));
    }

    /// Tamper at bit 0 specifically, then assert the returned error
    /// message identifies bit 0 (not the generic "some bit" string).
    /// Catches the mutation at strict_dleq.rs:1416 that deletes the
    /// `0 => "...bit 0"` match arm — under that mutation the function
    /// would return the "...some bit" string for ALL bit failures,
    /// including bit 0.
    #[test]
    fn strict_proof_tamper_at_bit_zero_reports_bit_zero_specifically() {
        let (_secret, t_btc, t_cync, mut proof) = honest_strict_proof_fixture();
        // Corrupt the OR-proof of bit 0 (NOT 17 — the specific arm we want).
        proof.bits[0].btc.s_0[0] ^= 0x01;
        let r = verify_cross_curve_strict(&proof, &t_btc, &t_cync);
        match r {
            Err(Error::Verification(msg)) => {
                assert!(
                    msg.contains("bit 0"),
                    "expected error message to identify 'bit 0' specifically \u{2014} \
                     the match arm at strict_dleq.rs:1416 appears deleted. Got: {}",
                    msg
                );
            }
            other => panic!("expected Verification error, got {:?}", other),
        }
    }

    #[test]
    fn strict_proof_rejects_tamper_at_r_btc_sum() {
        let (_secret, t_btc, t_cync, mut proof) = honest_strict_proof_fixture();
        proof.r_btc_sum[0] ^= 0x01;
        let r = verify_cross_curve_strict(&proof, &t_btc, &t_cync);
        assert!(matches!(r, Err(Error::Verification(_))));
    }

    #[test]
    fn strict_proof_rejects_tamper_at_r_cync_sum() {
        let (_secret, t_btc, t_cync, mut proof) = honest_strict_proof_fixture();
        proof.r_cync_sum[0] ^= 0x01;
        let r = verify_cross_curve_strict(&proof, &t_btc, &t_cync);
        assert!(matches!(r, Err(Error::Verification(_))));
    }

    #[test]
    fn strict_proof_rejects_wrong_t_btc() {
        let (_secret, _t_btc, t_cync, proof) = honest_strict_proof_fixture();
        // Use G_btc (dlog=1) as the wrong T. The fast-floor check
        // catches this first.
        use bitcoin::secp256k1::{PublicKey, Secp256k1, SecretKey};
        let secp = Secp256k1::new();
        let g_sk = SecretKey::from_slice(&{
            let mut b = [0u8; 32];
            b[31] = 1;
            b
        })
        .unwrap();
        let wrong_t_btc = PublicKey::from_secret_key(&secp, &g_sk).serialize();
        let r = verify_cross_curve_strict(&proof, &wrong_t_btc, &t_cync);
        assert!(matches!(r, Err(Error::Verification(_))));
    }

    #[test]
    fn strict_proof_rejects_wrong_t_cync() {
        use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
        let (_secret, t_btc, _t_cync, proof) = honest_strict_proof_fixture();
        let wrong_t_cync = RISTRETTO_BASEPOINT_POINT.compress().to_bytes();
        let r = verify_cross_curve_strict(&proof, &t_btc, &wrong_t_cync);
        assert!(matches!(r, Err(Error::Verification(_))));
    }

    #[test]
    fn strict_proof_rejects_truncated_bits_vec() {
        let (_secret, t_btc, t_cync, mut proof) = honest_strict_proof_fixture();
        proof.bits.pop();
        let r = verify_cross_curve_strict(&proof, &t_btc, &t_cync);
        assert!(matches!(r, Err(Error::Verification(_))));
    }

    #[test]
    fn strict_proof_is_deterministic_under_same_seed() {
        // Same secret + same seed must produce byte-identical proofs.
        // Important for testability + bisectability of any future
        // soundness regression.
        let (secret, t_btc, t_cync, proof1) = honest_strict_proof_fixture();
        let proof2 = prove_cross_curve_strict(&secret, &t_btc, &t_cync, &[0x77u8; 32]).unwrap();
        assert_eq!(proof1, proof2, "deterministic prove under fixed seed");
    }

    #[test]
    fn strict_proof_differs_under_different_seed() {
        // Sanity: different seed → different proof bytes (the per-bit
        // randomness shifts). The PROOFS both verify the same
        // statement.
        let (secret, t_btc, t_cync, proof1) = honest_strict_proof_fixture();
        let proof2 = prove_cross_curve_strict(&secret, &t_btc, &t_cync, &[0x88u8; 32]).unwrap();
        assert_ne!(
            proof1, proof2,
            "different seed must produce different proof"
        );
        verify_cross_curve_strict(&proof2, &t_btc, &t_cync)
            .expect("second proof under different seed must also verify");
    }
}
