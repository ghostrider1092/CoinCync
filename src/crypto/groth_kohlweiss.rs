//! Groth-Kohlweiss log-size one-out-of-many spend proof — CIP-Shielded 2c#1.
//!
//! Replaces the O(n) Schnorr stand-in in `lelantus_spark.rs` with an
//! O(log n) proof (see `docs/design/cip-shielded-proof.md`). Gated behind the
//! off-by-default `sketch-gk-proof` feature — NEVER compiled into a production
//! node — and unwired from consensus (`check_shielded_tx` stays fail-closed)
//! until implemented, property-tested, and externally audited.
//!
//! ## Phase status
//! - Phase 1 (THIS): the wire struct [`GkOneOfManyProof`] + a strict
//!   canonical-decode gate ([`GkOneOfManyProof::decode`]) — every field is
//!   canonically decoded (`PeerScalar`/`PeerPoint`, rejecting non-canonical
//!   encodings and identity commitments) and the log-size shape is checked.
//! - Phase 2 (NEXT): the prover + verifier math over the decoded proof.
//!
//! A proof for an anonymity set of `N = 2^m` coins has all vectors of length
//! `m = log2(N)`, so its size is O(log N).

use crate::crypto::peer_scalars::{PeerPoint, PeerScalar};
use crate::error::{Error, Result};
use borsh::{BorshDeserialize, BorshSerialize};
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use rand::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};
use sha3::{Digest, Sha3_256, Sha3_512};

// ── Generators ─────────────────────────────────────────────────────────────
// The one-of-many proof uses the SHARED Spark generators `G`/`K` (see
// crypto/spark_generators.rs), so it proves membership in the exact same basis
// as the Spark coin commitment `C = v·G + s·H + r·K`. `Com(b; r) = b·G + r·K` is
// the auxiliary Pedersen commitment used inside the proof.
use crate::crypto::spark_generators::{gen_g, gen_gv, gen_h, gen_k};

/// Auxiliary Pedersen commitment `Com(b; r) = b·G + r·K`.
fn commit(b: &Scalar, r: &Scalar) -> RistrettoPoint {
    gen_g() * b + gen_k() * r
}

/// Fiat-Shamir challenge over an optional caller `context` + the full statement
/// + round-1 transcript. Derived deterministically by both prover and verifier
/// (a self-computed reduction, so `from_bytes_mod_order_wide` is correct here —
/// this is not peer-input decoding). `context` lets a higher-level proof (the
/// Spark spend) bind extra data — the spend message, the revealed serial — into
/// the challenge, making the proof non-malleable with respect to it.
fn challenge(
    context: &[u8],
    commitments: &[RistrettoPoint],
    cl: &[[u8; 32]],
    ca: &[[u8; 32]],
    cb: &[[u8; 32]],
    gk: &[[u8; 32]],
) -> Scalar {
    let mut h = Sha3_512::new();
    h.update(b"COINCYNC_GK_FS_v1");
    // Length-prefixed context so it cannot blur into the commitment bytes.
    h.update((context.len() as u64).to_le_bytes());
    h.update(context);
    for c in commitments {
        h.update(c.compress().as_bytes());
    }
    for v in [cl, ca, cb, gk] {
        for p in v {
            h.update(p);
        }
    }
    let mut wide = [0u8; 64];
    wide.copy_from_slice(&h.finalize());
    Scalar::from_bytes_mod_order_wide(&wide)
}

/// Multiply a polynomial (coeffs low→high) by the linear form `(c0 + c1·x)`.
fn poly_mul_linear(poly: &[Scalar], c0: Scalar, c1: Scalar) -> Vec<Scalar> {
    let mut out = vec![Scalar::ZERO; poly.len() + 1];
    for (i, &coeff) in poly.iter().enumerate() {
        out[i] += coeff * c0;
        out[i + 1] += coeff * c1;
    }
    out
}

/// Prove that `commitments[l]` is a commitment to zero (`= r·K`) among
/// `commitments` (length `N = 2^m`), without revealing `l` — the Groth-Kohlweiss
/// one-out-of-many proof. `r` is the randomness of that commitment-to-zero.
///
/// This is the cryptographic core; the Spark spend (serial binding, value,
/// deriving `commitments` from coin commitments) layers on top in Phase 2b.
pub fn prove_one_of_many<R: CryptoRng + RngCore>(
    commitments: &[RistrettoPoint],
    l: usize,
    r: &Scalar,
    rng: &mut R,
) -> Result<GkOneOfManyProof> {
    prove_one_of_many_ctx(commitments, l, r, &[], rng)
}

/// As [`prove_one_of_many`], but binds an opaque `context` into the Fiat-Shamir
/// challenge (see [`challenge`]). The verifier must supply the identical context
/// to [`verify_one_of_many_ctx`].
pub fn prove_one_of_many_ctx<R: CryptoRng + RngCore>(
    commitments: &[RistrettoPoint],
    l: usize,
    r: &Scalar,
    context: &[u8],
    rng: &mut R,
) -> Result<GkOneOfManyProof> {
    let n = commitments.len();
    if n == 0 || !n.is_power_of_two() {
        return Err(Error::CryptoError(
            "GK: commitment set size must be a power of two >= 1".into(),
        ));
    }
    let m = n.trailing_zeros() as usize;
    if m == 0 || m > MAX_GK_ROUNDS {
        return Err(Error::CryptoError("GK: rounds out of range".into()));
    }
    if l >= n {
        return Err(Error::CryptoError("GK: index out of range".into()));
    }

    let k_gen = gen_k();
    let bit = |j: usize| -> u8 { ((l >> j) & 1) as u8 };

    // Round 1: per-bit commitments + saved randomness.
    let mut lj = Vec::with_capacity(m);
    let mut aj = Vec::with_capacity(m);
    let mut rj = Vec::with_capacity(m);
    let mut sj = Vec::with_capacity(m);
    let mut tj = Vec::with_capacity(m);
    let (mut cl, mut ca, mut cb) = (Vec::new(), Vec::new(), Vec::new());
    for j in 0..m {
        let l_j = Scalar::from(bit(j) as u64);
        let a_j = Scalar::random(&mut *rng);
        let r_j = Scalar::random(&mut *rng);
        let s_j = Scalar::random(&mut *rng);
        let t_j = Scalar::random(&mut *rng);
        cl.push(commit(&l_j, &r_j).compress().to_bytes());
        ca.push(commit(&a_j, &s_j).compress().to_bytes());
        cb.push(commit(&(l_j * a_j), &t_j).compress().to_bytes());
        lj.push(l_j);
        aj.push(a_j);
        rj.push(r_j);
        sj.push(s_j);
        tj.push(t_j);
    }

    // Polynomial coefficients p_{i,k}: for each i, expand ∏_j f_{j,i_j}(x) where
    // f_{j,1}(x) = a_j + l_j·x  and  f_{j,0}(x) = -a_j + (1-l_j)·x.
    // The degree-m coefficient equals δ(i,l); we need coefficients 0..m-1.
    let mut gk = Vec::with_capacity(m);
    let rho: Vec<Scalar> = (0..m).map(|_| Scalar::random(&mut *rng)).collect();
    // Accumulate Σ_i p_{i,k}·c_i for k in 0..m into `coeff_sum[k]`.
    let mut coeff_sum = vec![RistrettoPoint::default(); m];
    for (i, c_i) in commitments.iter().enumerate() {
        let mut poly = vec![Scalar::ONE]; // degree-0: 1
        for j in 0..m {
            let i_j = (i >> j) & 1;
            let (c0, c1) = if i_j == 1 {
                (aj[j], lj[j]) // a_j + l_j·x
            } else {
                (-aj[j], Scalar::ONE - lj[j]) // -a_j + (1-l_j)·x
            };
            poly = poly_mul_linear(&poly, c0, c1);
        }
        // poly has degree m (length m+1); use coefficients 0..m-1.
        for k in 0..m {
            coeff_sum[k] += c_i * poly[k];
        }
    }
    for k in 0..m {
        gk.push((coeff_sum[k] + k_gen * rho[k]).compress().to_bytes());
    }

    let x = challenge(context, commitments, &cl, &ca, &cb, &gk);

    // Round 2 responses.
    let mut f = Vec::with_capacity(m);
    let mut za = Vec::with_capacity(m);
    let mut zb = Vec::with_capacity(m);
    for j in 0..m {
        let f_j = lj[j] * x + aj[j];
        f.push(f_j.to_bytes());
        za.push((rj[j] * x + sj[j]).to_bytes());
        zb.push((rj[j] * (x - f_j) + tj[j]).to_bytes());
    }
    // z_d = r·x^m − Σ_k ρ_k·x^k
    let mut x_pow = Scalar::ONE;
    let mut sum_rho = Scalar::ZERO;
    for k in 0..m {
        sum_rho += rho[k] * x_pow;
        x_pow *= x;
    }
    // x_pow is now x^m
    let zd = (*r * x_pow - sum_rho).to_bytes();

    Ok(GkOneOfManyProof {
        cl,
        ca,
        cb,
        gk,
        f,
        za,
        zb,
        zd,
    })
}

/// Verify a one-out-of-many proof against `commitments` (length `N = 2^m`).
/// Returns `Ok(())` iff the prover knew a commitment-to-zero at some hidden
/// index. Fail-closed on any check.
pub fn verify_one_of_many(commitments: &[RistrettoPoint], proof: &GkOneOfManyProof) -> Result<()> {
    verify_one_of_many_ctx(commitments, proof, &[])
}

/// As [`verify_one_of_many`], but with the `context` that was bound into the
/// proof's Fiat-Shamir challenge at prove time. A mismatched context fails the
/// verification (the challenge no longer reproduces).
pub fn verify_one_of_many_ctx(
    commitments: &[RistrettoPoint],
    proof: &GkOneOfManyProof,
    context: &[u8],
) -> Result<()> {
    let n = commitments.len();
    if n == 0 || !n.is_power_of_two() {
        return Err(Error::SparkVerifyFailed);
    }
    let m = n.trailing_zeros() as usize;
    let d = proof.decode()?;
    if d.m != m {
        return Err(Error::SparkVerifyFailed);
    }

    let g = gen_g();
    let k_gen = gen_k();
    let x = challenge(context, commitments, &proof.cl, &proof.ca, &proof.cb, &proof.gk);

    // Per-bit checks (bit-ness).
    for j in 0..m {
        let cl_j = *d.cl[j].as_point();
        let f_j = *d.f[j].as_scalar();
        // (a) x·cl_j + ca_j == f_j·G + z_a_j·K
        if x * cl_j + *d.ca[j].as_point() != g * f_j + k_gen * *d.za[j].as_scalar() {
            return Err(Error::SparkVerifyFailed);
        }
        // (b) (x − f_j)·cl_j + cb_j == z_b_j·K
        if (x - f_j) * cl_j + *d.cb[j].as_point() != k_gen * *d.zb[j].as_scalar() {
            return Err(Error::SparkVerifyFailed);
        }
    }

    // One-of-many equation:
    //   Σ_i (∏_j (f_j if i_j=1 else x−f_j))·c_i − Σ_k x^k·G_k == z_d·K
    let f_scalars: Vec<Scalar> = d.f.iter().map(|s| *s.as_scalar()).collect();
    let mut lhs = RistrettoPoint::default();
    for (i, c_i) in commitments.iter().enumerate() {
        let mut prod = Scalar::ONE;
        for (j, f_j) in f_scalars.iter().enumerate() {
            let factor = if (i >> j) & 1 == 1 { *f_j } else { x - f_j };
            prod *= factor;
        }
        lhs += c_i * prod;
    }
    let mut x_pow = Scalar::ONE;
    for j in 0..m {
        lhs -= *d.gk[j].as_point() * x_pow;
        x_pow *= x;
    }
    if lhs != k_gen * *d.zd.as_scalar() {
        return Err(Error::SparkVerifyFailed);
    }
    Ok(())
}

/// The log-size one-out-of-many proof, in wire form (canonical 32-byte
/// encodings). Decode with [`GkOneOfManyProof::decode`] before use — the raw
/// bytes are peer-controlled and must never be trusted without canonical
/// validation.
///
/// Field roles (`m = log2(N)`):
/// - `cl`, `ca`, `cb`: the per-bit commitments proving each index bit ∈ {0,1}.
/// - `gk`: the `G_k` polynomial-coefficient commitments.
/// - `f`, `za`, `zb`: the per-bit response scalars.
/// - `zd`: the final one-of-many response scalar.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, BorshSerialize, BorshDeserialize)]
pub struct GkOneOfManyProof {
    pub cl: Vec<[u8; 32]>,
    pub ca: Vec<[u8; 32]>,
    pub cb: Vec<[u8; 32]>,
    pub gk: Vec<[u8; 32]>,
    pub f: Vec<[u8; 32]>,
    pub za: Vec<[u8; 32]>,
    pub zb: Vec<[u8; 32]>,
    pub zd: [u8; 32],
}

/// A [`GkOneOfManyProof`] whose every field has been canonically decoded to
/// curve types and whose shape has been validated. Only constructible via
/// [`GkOneOfManyProof::decode`], so downstream (Phase-2) verification code can
/// assume canonical, well-shaped inputs.
#[derive(Clone, Debug)]
pub struct DecodedGkProof {
    /// `m = log2(N)` — the number of index bits / proof rounds.
    pub m: usize,
    pub cl: Vec<PeerPoint>,
    pub ca: Vec<PeerPoint>,
    pub cb: Vec<PeerPoint>,
    pub gk: Vec<PeerPoint>,
    pub f: Vec<PeerScalar>,
    pub za: Vec<PeerScalar>,
    pub zb: Vec<PeerScalar>,
    pub zd: PeerScalar,
}

/// Upper bound on `m` (so `N = 2^m` up to 2^20 ≈ 1M coins). Bounds the work a
/// peer can force a verifier to do and rejects absurd proofs early.
pub const MAX_GK_ROUNDS: usize = 20;

impl GkOneOfManyProof {
    /// Canonically decode + shape-check the proof. Rejects:
    /// - a non-power-of-two-implied shape (all point/scalar vectors must share
    ///   the same length `m`, with `1 <= m <= MAX_GK_ROUNDS`),
    /// - any non-canonical scalar (`PeerScalar`) or point (`PeerPoint`) encoding,
    /// - identity commitments (`cl`/`ca`/`cb`/`gk` use `decode_non_identity`;
    ///   an identity commitment is degenerate and never produced by an honest
    ///   prover with CSPRNG randomness).
    pub fn decode(&self) -> Result<DecodedGkProof> {
        let m = self.cl.len();
        if m == 0 || m > MAX_GK_ROUNDS {
            return Err(Error::CryptoError(format!(
                "GK proof rounds m={} out of range 1..={}",
                m, MAX_GK_ROUNDS
            )));
        }
        // Every vector field must have exactly m entries.
        for (name, len) in [
            ("ca", self.ca.len()),
            ("cb", self.cb.len()),
            ("gk", self.gk.len()),
            ("f", self.f.len()),
            ("za", self.za.len()),
            ("zb", self.zb.len()),
        ] {
            if len != m {
                return Err(Error::CryptoError(format!(
                    "GK proof field `{}` length {} != m {}",
                    name, len, m
                )));
            }
        }

        let points = |v: &[[u8; 32]]| -> Result<Vec<PeerPoint>> {
            v.iter().copied().map(PeerPoint::decode_non_identity).collect()
        };
        let scalars = |v: &[[u8; 32]]| -> Result<Vec<PeerScalar>> {
            v.iter().copied().map(PeerScalar::decode).collect()
        };

        Ok(DecodedGkProof {
            m,
            cl: points(&self.cl)?,
            ca: points(&self.ca)?,
            cb: points(&self.cb)?,
            gk: points(&self.gk)?,
            f: scalars(&self.f)?,
            za: scalars(&self.za)?,
            zb: scalars(&self.zb)?,
            zd: PeerScalar::decode(self.zd)?,
        })
    }
}

/// The full shielded spend proof, wire form — a Zerocoin/Lelantus serial-reveal
/// one-out-of-many spend over the shared `{G, K}` basis (see
/// docs/design/cip-shielded-proof.md, cip-shielded-anonset.md).
///
/// Coin: `C = m·G + r·K` — a Pedersen commitment to serial `m` with blinding
/// `r`. To spend coin `l` in the anonymity set `{C_0..C_{N-1}}`, the prover
/// reveals the serial `m` (whose hash, [`SparkSpendProofV2::nullifier`], is the
/// double-spend tag) and proves one-out-of-many that the *shifted* set
/// `D_i = C_i − m·G` holds a commitment-to-zero at the hidden index `l`
/// (`D_l = r·K`). Because `G` and `K` are NUMS generators with no known
/// discrete-log relation, a verifying proof **forces** the revealed `m` to equal
/// the spent coin's serial (the extractor yields `r` for `D_l`, and any residual
/// `(m_l − m)·G` term could only be absorbed with an unknown `dlog_K(G)`), so:
/// the nullifier is unique per coin (double-spend safe), ownership requires
/// knowing the opening `(m, r)`, and `l` stays hidden (the one-of-many is
/// witness-indistinguishable; in a prime-order group revealing `m` does not
/// reveal which `D_i` is the zero-commitment). The spend `message`
/// (fee/outputs/anchor digest) is bound into the Fiat-Shamir challenge, so the
/// proof is non-malleable with respect to it.
///
/// SCOPE: this proves **membership + serial/nullifier** — the anonymity and
/// double-spend core. **Value conservation (balance + range) is a SEPARATE
/// proof still required before activation**, layered on a parallel value
/// commitment using CoinCync's existing bulletproofs machinery. Gated
/// `sketch-gk-proof`, **unaudited**, and unwired: `check_shielded_tx` stays
/// fail-closed and shielded is gated off (`SHIELDED_TX_ACTIVATION_HEIGHT =
/// u64::MAX`) until this is externally audited and the 24h soak passes.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, BorshSerialize, BorshDeserialize)]
pub struct SparkSpendProofV2 {
    /// The one-out-of-many membership proof over the shifted set `{C_i − m·G}`.
    pub one_of_many: GkOneOfManyProof,
    /// The revealed coin serial `m`, canonical scalar. Its hashed
    /// [`SparkSpendProofV2::nullifier`] is published as the double-spend tag.
    pub serial: [u8; 32],
    /// The spend message this proof is bound to (fee/outputs/anchor digest).
    pub message: [u8; 32],
}

/// Fiat-Shamir context binding the revealed serial + spend message into the
/// one-of-many challenge. Shared verbatim by [`prove_spend`] and
/// [`verify_spend`] so the challenge reproduces iff both agree on `(serial,
/// message)`.
fn spend_context(serial: &Scalar, message: &[u8; 32]) -> [u8; 32] {
    let mut h = Sha3_256::new();
    h.update(b"COINCYNC_SPARK_SPEND_CTX_v1");
    h.update(serial.to_bytes());
    h.update(message);
    let mut out = [0u8; 32];
    out.copy_from_slice(&h.finalize());
    out
}

/// Prove a spend of coin `l` in `commitments`, where the spender knows the
/// opening `commitments[l] = serial·G + blinding·K`. Returns `Err` on an
/// out-of-range index, an invalid set shape, or an inconsistent opening (a
/// caller bug — not a security check).
pub fn prove_spend<R: CryptoRng + RngCore>(
    commitments: &[RistrettoPoint],
    l: usize,
    serial: &Scalar,
    blinding: &Scalar,
    message: &[u8; 32],
    rng: &mut R,
) -> Result<SparkSpendProofV2> {
    if l >= commitments.len() {
        return Err(Error::CryptoError("spend: index out of range".into()));
    }
    let g = gen_g();
    // Consistency: the claimed opening must match the coin, so that shifting by
    // serial·G lands `D_l` on a pure K-commitment (`blinding·K`).
    if commitments[l] != g * serial + gen_k() * blinding {
        return Err(Error::CryptoError(
            "spend: opening (serial, blinding) does not match commitments[l]".into(),
        ));
    }
    let s_g = g * serial;
    let shifted: Vec<RistrettoPoint> = commitments.iter().map(|c| c - s_g).collect();
    let ctx = spend_context(serial, message);
    let one_of_many = prove_one_of_many_ctx(&shifted, l, blinding, &ctx, rng)?;
    Ok(SparkSpendProofV2 {
        one_of_many,
        serial: serial.to_bytes(),
        message: *message,
    })
}

/// Verify a spend against `commitments` and the expected `message`. Fail-closed
/// on a non-canonical serial, a message mismatch, or a failing one-of-many.
pub fn verify_spend(
    commitments: &[RistrettoPoint],
    proof: &SparkSpendProofV2,
    message: &[u8; 32],
) -> Result<()> {
    if &proof.message != message {
        return Err(Error::SparkVerifyFailed);
    }
    // Canonical scalar decode of the peer-controlled revealed serial.
    let serial = *PeerScalar::decode(proof.serial)
        .map_err(|_| Error::SparkVerifyFailed)?
        .as_scalar();
    let s_g = gen_g() * serial;
    let shifted: Vec<RistrettoPoint> = commitments.iter().map(|c| c - s_g).collect();
    let ctx = spend_context(&serial, message);
    verify_one_of_many_ctx(&shifted, &proof.one_of_many, &ctx)
}

impl SparkSpendProofV2 {
    /// Encode to the opaque bytes carried in `ShieldedPayload::proof`.
    pub fn encode(&self) -> Vec<u8> {
        borsh::to_vec(self).expect("SparkSpendProofV2 borsh serialization is infallible into a Vec")
    }

    /// Decode from `ShieldedPayload::proof` bytes, rejecting trailing/garbage
    /// bytes (borsh requires full consumption).
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        borsh::from_slice(bytes)
            .map_err(|e| Error::CryptoError(format!("SparkSpendProofV2 decode: {e}")))
    }

    /// The double-spend nullifier published in `ShieldedPayload::serial_tags`:
    /// a domain-separated hash of the revealed serial, so the stored tag does
    /// not expose the raw serial encoding. Deterministic in the serial — the
    /// same coin always yields the same nullifier (independent of `message`),
    /// so a second spend of the same coin collides.
    pub fn nullifier(&self) -> [u8; 32] {
        let mut h = Sha3_256::new();
        h.update(b"COINCYNC_SPARK_NULLIFIER_v1");
        h.update(self.serial);
        let mut out = [0u8; 32];
        out.copy_from_slice(&h.finalize());
        out
    }

    /// Structural + canonical validation (NOT the full spend verification): the
    /// one-of-many decodes canonically and the revealed serial is a canonical
    /// scalar. Returns the decoded one-of-many + serial scalar.
    pub fn decode(&self) -> Result<(DecodedGkProof, Scalar)> {
        let oom = self.one_of_many.decode()?;
        let serial = *PeerScalar::decode(self.serial)?.as_scalar();
        Ok((oom, serial))
    }
}

// ── Value-bound spend (binds the coin's VALUE to the balance proof) ──────────
// `SparkSpendProofV2` proves membership + serial only. The BOUND spend
// additionally binds the spent coin's value to a published value commitment `V`
// (consumed by `crypto::spark_balance`), closing the inflation gap: a spender
// cannot prove membership of a low-value coin while feeding a high-value
// commitment into the balance.
//
// Bound coin:  C = v·Gv + s·H + r·K   (value on Gv, serial on H, blinding on K).
// To spend coin `l`, publish `V = v·Gv + b·K` (same value, fresh blinding `b`),
// reveal serial `s`, and prove one-out-of-many that `W_i = C_i − s·H − V` has a
// pure-`K` term at the hidden `l`:  `W_l = (r − b)·K`. For any other `i`, a
// wrong serial, or a `V` committing to a different value, `W` carries an `H` or
// `Gv` component and (since Gv/H are independent of K) no *known* K-multiple
// exists → the proof fails. So a verifying proof forces both `s` = the coin's
// serial (⇒ unique nullifier) and `V`'s value = the coin's value (the binding),
// while `l` stays hidden (the one-of-many is witness-indistinguishable).

/// A value-bound shielded coin commitment `C = value·Gv + serial·H + blinding·K`.
pub fn bound_coin_commitment(value: u64, serial: &Scalar, blinding: &Scalar) -> RistrettoPoint {
    gen_gv() * Scalar::from(value) + gen_h() * serial + gen_k() * blinding
}

/// A value-bound shielded spend proof: membership + serial (nullifier) + a
/// published value commitment bound to the spent coin's value.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, BorshSerialize, BorshDeserialize)]
pub struct SparkSpendProofV3 {
    /// One-out-of-many over the shifted set `{C_i − s·H − V}`.
    pub one_of_many: GkOneOfManyProof,
    /// Revealed serial `s` (canonical scalar); its hash is the nullifier.
    pub serial: [u8; 32],
    /// Published value commitment `V = v·Gv + b·K`, bound to the coin's value —
    /// the input value commitment fed to the balance proof.
    pub value_commitment: [u8; 32],
    /// The spend message this proof is bound to.
    pub message: [u8; 32],
}

fn spend_context_v3(serial: &Scalar, value_commitment: &[u8; 32], message: &[u8; 32]) -> [u8; 32] {
    let mut h = Sha3_256::new();
    h.update(b"COINCYNC_SPARK_SPEND_V3_CTX_v1");
    h.update(serial.to_bytes());
    h.update(value_commitment);
    h.update(message);
    let mut out = [0u8; 32];
    out.copy_from_slice(&h.finalize());
    out
}

/// Prove a value-bound spend of coin `l`. The spender knows the full opening
/// `coins[l] = value·Gv + serial·H + blinding·K` and draws a fresh
/// `value_blinding` for the published value commitment.
pub fn prove_spend_bound<R: CryptoRng + RngCore>(
    coins: &[RistrettoPoint],
    l: usize,
    value: u64,
    serial: &Scalar,
    blinding: &Scalar,
    value_blinding: &Scalar,
    message: &[u8; 32],
    rng: &mut R,
) -> Result<SparkSpendProofV3> {
    if l >= coins.len() {
        return Err(Error::CryptoError("bound spend: index out of range".into()));
    }
    if coins[l] != bound_coin_commitment(value, serial, blinding) {
        return Err(Error::CryptoError(
            "bound spend: opening (value, serial, blinding) does not match coins[l]".into(),
        ));
    }
    let v_point = gen_gv() * Scalar::from(value) + gen_k() * value_blinding;
    let v_bytes = v_point.compress().to_bytes();
    // W_i = C_i − s·H − V ; at l this is (blinding − value_blinding)·K.
    let shift = gen_h() * serial + v_point;
    let shifted: Vec<RistrettoPoint> = coins.iter().map(|c| c - shift).collect();
    let rho = blinding - value_blinding;
    let ctx = spend_context_v3(serial, &v_bytes, message);
    let one_of_many = prove_one_of_many_ctx(&shifted, l, &rho, &ctx, rng)?;
    Ok(SparkSpendProofV3 {
        one_of_many,
        serial: serial.to_bytes(),
        value_commitment: v_bytes,
        message: *message,
    })
}

/// Verify a value-bound spend against `coins` and the expected `message`. On
/// success returns the bound value commitment `V`, to be used as this input's
/// commitment in the balance proof. Fail-closed otherwise.
pub fn verify_spend_bound(
    coins: &[RistrettoPoint],
    proof: &SparkSpendProofV3,
    message: &[u8; 32],
) -> Result<RistrettoPoint> {
    if &proof.message != message {
        return Err(Error::SparkVerifyFailed);
    }
    let serial = *PeerScalar::decode(proof.serial)
        .map_err(|_| Error::SparkVerifyFailed)?
        .as_scalar();
    let v_point = PeerPoint::decode_non_identity(proof.value_commitment)
        .map_err(|_| Error::SparkVerifyFailed)?
        .into_point();
    let shift = gen_h() * serial + v_point;
    let shifted: Vec<RistrettoPoint> = coins.iter().map(|c| c - shift).collect();
    let ctx = spend_context_v3(&serial, &proof.value_commitment, message);
    verify_one_of_many_ctx(&shifted, &proof.one_of_many, &ctx)?;
    Ok(v_point)
}

// ── HK one-of-many: membership + value binding WITHOUT revealing the serial ──
//
// The V3 bound spend REVEALS the serial `s` (to shift `s·H` out and prove the
// remainder is pure-`K`). Revealing `s` is fatal to scan ≠ spend (see
// docs/design/cip-shielded-spend-composition.md). This variant proves the spent
// coin's shifted point `W_l = C_l − V` lies in `⟨H, K⟩` (i.e. has ZERO `Gv`
// component ⇒ `V`'s value equals the coin's value), while HIDING both the `H`
// coefficient (the serial `s_pub + x`) and the `K` coefficient (`r − b`).
//
// The Groth-Bootle machinery is unchanged except the final relation, which is
// blinded on BOTH admissible generators: `gk_k = Σ_i p_{i,k}·W_i + ρh_k·H +
// ρk_k·K`, and the two final responses `z_dh, z_dk` each subtract their own
// `Σ ρ·x^k`, so neither reveals `x^m · coefficient`. A nonzero `Gv` component in
// `W_l` cannot be matched by `z_dh·H + z_dk·K` (Gv ⟂ H,K, NUMS) ⇒ value binding.
//
// SCOPE: this is membership + value binding, serial hidden. It publishes NO
// nullifier — the spend-key-bound linking tag fused over the hidden index (the
// Triptych step, `cip-shielded-spend-composition.md`) is the remaining
// audit-critical piece. Gated, unaudited, unwired.

/// Wire form of the HK one-of-many (membership in `⟨H,K⟩`). Mirrors
/// [`GkOneOfManyProof`] but the single `zd` becomes `(zdh, zdk)` — the blinded
/// responses for the `H` and `K` coefficients.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, BorshSerialize, BorshDeserialize)]
pub struct GkOneOfManyHkProof {
    pub cl: Vec<[u8; 32]>,
    pub ca: Vec<[u8; 32]>,
    pub cb: Vec<[u8; 32]>,
    pub gk: Vec<[u8; 32]>,
    pub f: Vec<[u8; 32]>,
    pub za: Vec<[u8; 32]>,
    pub zb: Vec<[u8; 32]>,
    pub zdh: [u8; 32],
    pub zdk: [u8; 32],
}

struct DecodedGkHkProof {
    m: usize,
    cl: Vec<PeerPoint>,
    ca: Vec<PeerPoint>,
    cb: Vec<PeerPoint>,
    gk: Vec<PeerPoint>,
    f: Vec<PeerScalar>,
    za: Vec<PeerScalar>,
    zb: Vec<PeerScalar>,
    zdh: PeerScalar,
    zdk: PeerScalar,
}

impl GkOneOfManyHkProof {
    fn decode(&self) -> Result<DecodedGkHkProof> {
        let m = self.cl.len();
        if m == 0 || m > MAX_GK_ROUNDS {
            return Err(Error::SparkVerifyFailed);
        }
        for len in [self.ca.len(), self.cb.len(), self.gk.len(), self.f.len(), self.za.len(), self.zb.len()] {
            if len != m {
                return Err(Error::SparkVerifyFailed);
            }
        }
        let points = |v: &[[u8; 32]]| -> Result<Vec<PeerPoint>> {
            v.iter().copied().map(PeerPoint::decode_non_identity).collect()
        };
        let scalars = |v: &[[u8; 32]]| -> Result<Vec<PeerScalar>> {
            v.iter().copied().map(PeerScalar::decode).collect()
        };
        Ok(DecodedGkHkProof {
            m,
            cl: points(&self.cl).map_err(|_| Error::SparkVerifyFailed)?,
            ca: points(&self.ca).map_err(|_| Error::SparkVerifyFailed)?,
            cb: points(&self.cb).map_err(|_| Error::SparkVerifyFailed)?,
            gk: points(&self.gk).map_err(|_| Error::SparkVerifyFailed)?,
            f: scalars(&self.f).map_err(|_| Error::SparkVerifyFailed)?,
            za: scalars(&self.za).map_err(|_| Error::SparkVerifyFailed)?,
            zb: scalars(&self.zb).map_err(|_| Error::SparkVerifyFailed)?,
            zdh: PeerScalar::decode(self.zdh).map_err(|_| Error::SparkVerifyFailed)?,
            zdk: PeerScalar::decode(self.zdk).map_err(|_| Error::SparkVerifyFailed)?,
        })
    }
}

/// Prove `commitments[l] = h_coef·H + k_coef·K` (membership in `⟨H,K⟩`) without
/// revealing `l`, `h_coef`, or `k_coef`.
pub fn prove_one_of_many_hk_ctx<R: CryptoRng + RngCore>(
    commitments: &[RistrettoPoint],
    l: usize,
    h_coef: &Scalar,
    k_coef: &Scalar,
    context: &[u8],
    rng: &mut R,
) -> Result<GkOneOfManyHkProof> {
    let n = commitments.len();
    if n == 0 || !n.is_power_of_two() {
        return Err(Error::CryptoError("GK-HK: set size must be a power of two >= 1".into()));
    }
    let m = n.trailing_zeros() as usize;
    if m == 0 || m > MAX_GK_ROUNDS {
        return Err(Error::CryptoError("GK-HK: rounds out of range".into()));
    }
    if l >= n {
        return Err(Error::CryptoError("GK-HK: index out of range".into()));
    }
    let bit = |j: usize| -> u8 { ((l >> j) & 1) as u8 };

    // Round 1: per-bit commitments (identical to the base one-of-many).
    let (mut lj, mut aj, mut rj, mut sj, mut tj) =
        (Vec::with_capacity(m), Vec::with_capacity(m), Vec::with_capacity(m), Vec::with_capacity(m), Vec::with_capacity(m));
    let (mut cl, mut ca, mut cb) = (Vec::new(), Vec::new(), Vec::new());
    for j in 0..m {
        let l_j = Scalar::from(bit(j) as u64);
        let a_j = Scalar::random(&mut *rng);
        let r_j = Scalar::random(&mut *rng);
        let s_j = Scalar::random(&mut *rng);
        let t_j = Scalar::random(&mut *rng);
        cl.push(commit(&l_j, &r_j).compress().to_bytes());
        ca.push(commit(&a_j, &s_j).compress().to_bytes());
        cb.push(commit(&(l_j * a_j), &t_j).compress().to_bytes());
        lj.push(l_j);
        aj.push(a_j);
        rj.push(r_j);
        sj.push(s_j);
        tj.push(t_j);
    }

    // Polynomial coefficient sums Σ_i p_{i,k}·c_i, then blind on BOTH H and K.
    let rho_h: Vec<Scalar> = (0..m).map(|_| Scalar::random(&mut *rng)).collect();
    let rho_k: Vec<Scalar> = (0..m).map(|_| Scalar::random(&mut *rng)).collect();
    let mut coeff_sum = vec![RistrettoPoint::default(); m];
    for (i, c_i) in commitments.iter().enumerate() {
        let mut poly = vec![Scalar::ONE];
        for j in 0..m {
            let i_j = (i >> j) & 1;
            let (c0, c1) = if i_j == 1 { (aj[j], lj[j]) } else { (-aj[j], Scalar::ONE - lj[j]) };
            poly = poly_mul_linear(&poly, c0, c1);
        }
        for k in 0..m {
            coeff_sum[k] += c_i * poly[k];
        }
    }
    let mut gk = Vec::with_capacity(m);
    for k in 0..m {
        gk.push((coeff_sum[k] + gen_h() * rho_h[k] + gen_k() * rho_k[k]).compress().to_bytes());
    }

    let x = challenge(context, commitments, &cl, &ca, &cb, &gk);

    let (mut f, mut za, mut zb) = (Vec::with_capacity(m), Vec::with_capacity(m), Vec::with_capacity(m));
    for j in 0..m {
        let f_j = lj[j] * x + aj[j];
        f.push(f_j.to_bytes());
        za.push((rj[j] * x + sj[j]).to_bytes());
        zb.push((rj[j] * (x - f_j) + tj[j]).to_bytes());
    }
    // z_dh = h_coef·x^m − Σ ρh_k·x^k ; z_dk likewise for k_coef.
    let (mut x_pow, mut sum_h, mut sum_k) = (Scalar::ONE, Scalar::ZERO, Scalar::ZERO);
    for k in 0..m {
        sum_h += rho_h[k] * x_pow;
        sum_k += rho_k[k] * x_pow;
        x_pow *= x;
    }
    // x_pow == x^m
    let zdh = (*h_coef * x_pow - sum_h).to_bytes();
    let zdk = (*k_coef * x_pow - sum_k).to_bytes();

    Ok(GkOneOfManyHkProof { cl, ca, cb, gk, f, za, zb, zdh, zdk })
}

/// Verify an HK one-of-many: `commitments[l] ∈ ⟨H,K⟩` at some hidden `l`.
pub fn verify_one_of_many_hk_ctx(
    commitments: &[RistrettoPoint],
    proof: &GkOneOfManyHkProof,
    context: &[u8],
) -> Result<()> {
    let n = commitments.len();
    if n == 0 || !n.is_power_of_two() {
        return Err(Error::SparkVerifyFailed);
    }
    let m = n.trailing_zeros() as usize;
    let d = proof.decode()?;
    if d.m != m {
        return Err(Error::SparkVerifyFailed);
    }
    let g = gen_g();
    let k_gen = gen_k();
    let x = challenge(context, commitments, &proof.cl, &proof.ca, &proof.cb, &proof.gk);

    // Per-bit bit-ness checks (identical to the base proof).
    for j in 0..m {
        let cl_j = *d.cl[j].as_point();
        let f_j = *d.f[j].as_scalar();
        if x * cl_j + *d.ca[j].as_point() != g * f_j + k_gen * *d.za[j].as_scalar() {
            return Err(Error::SparkVerifyFailed);
        }
        if (x - f_j) * cl_j + *d.cb[j].as_point() != k_gen * *d.zb[j].as_scalar() {
            return Err(Error::SparkVerifyFailed);
        }
    }

    // Final: Σ_i prod_i·c_i − Σ_k x^k·gk_k == z_dh·H + z_dk·K.
    let f_scalars: Vec<Scalar> = d.f.iter().map(|s| *s.as_scalar()).collect();
    let mut lhs = RistrettoPoint::default();
    for (i, c_i) in commitments.iter().enumerate() {
        let mut prod = Scalar::ONE;
        for (j, f_j) in f_scalars.iter().enumerate() {
            let factor = if (i >> j) & 1 == 1 { *f_j } else { x - f_j };
            prod *= factor;
        }
        lhs += c_i * prod;
    }
    let mut x_pow = Scalar::ONE;
    for j in 0..m {
        lhs -= *d.gk[j].as_point() * x_pow;
        x_pow *= x;
    }
    if lhs != gen_h() * *d.zdh.as_scalar() + k_gen * *d.zdk.as_scalar() {
        return Err(Error::SparkVerifyFailed);
    }
    Ok(())
}

/// A serial-HIDING value-bound spend: membership + value binding with the serial
/// kept secret (unlike [`SparkSpendProofV3`], which reveals it). The published
/// `V` is the input value commitment for the balance proof. This is the
/// membership+value HALF of the end-state spend; the spend-key linking tag /
/// nullifier is fused in the (deferred, audit-critical) Triptych step.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, BorshSerialize, BorshDeserialize)]
pub struct SparkSpendProofV4 {
    /// HK one-of-many over the shifted set `{C_i − V}`.
    pub membership: GkOneOfManyHkProof,
    /// Published value commitment `V = v·Gv + b·K`.
    pub value_commitment: [u8; 32],
    /// The spend message this proof is bound to.
    pub message: [u8; 32],
}

fn spend_context_v4(value_commitment: &[u8; 32], message: &[u8; 32]) -> Vec<u8> {
    let mut h = Sha3_256::new();
    h.update(b"COINCYNC_SPARK_SPEND_V4_CTX_v1");
    h.update(value_commitment);
    h.update(message);
    h.finalize().to_vec()
}

/// Prove a serial-hiding value-bound spend of coin `l`. The spender knows the
/// full opening `coins[l] = value·Gv + h_coef·H + blinding·K` (where `h_coef` is
/// the coin's total serial coefficient `s_pub + spend_secret`) and draws a fresh
/// `value_blinding` for the published `V`.
pub fn prove_spend_value_hidden<R: CryptoRng + RngCore>(
    coins: &[RistrettoPoint],
    l: usize,
    value: u64,
    h_coef: &Scalar,
    blinding: &Scalar,
    value_blinding: &Scalar,
    message: &[u8; 32],
    rng: &mut R,
) -> Result<SparkSpendProofV4> {
    if l >= coins.len() {
        return Err(Error::CryptoError("v4 spend: index out of range".into()));
    }
    if coins[l] != gen_gv() * Scalar::from(value) + gen_h() * h_coef + gen_k() * blinding {
        return Err(Error::CryptoError("v4 spend: opening does not match coins[l]".into()));
    }
    let v_point = gen_gv() * Scalar::from(value) + gen_k() * value_blinding;
    let v_bytes = v_point.compress().to_bytes();
    // W_i = C_i − V ; at l this is h_coef·H + (blinding − value_blinding)·K ∈ ⟨H,K⟩.
    let shifted: Vec<RistrettoPoint> = coins.iter().map(|c| c - v_point).collect();
    let k_coef = blinding - value_blinding;
    let ctx = spend_context_v4(&v_bytes, message);
    let membership = prove_one_of_many_hk_ctx(&shifted, l, h_coef, &k_coef, &ctx, rng)?;
    Ok(SparkSpendProofV4 { membership, value_commitment: v_bytes, message: *message })
}

/// Verify a serial-hiding value-bound spend. Returns the bound value commitment
/// `V` on success. Fail-closed.
pub fn verify_spend_value_hidden(
    coins: &[RistrettoPoint],
    proof: &SparkSpendProofV4,
    message: &[u8; 32],
) -> Result<RistrettoPoint> {
    if &proof.message != message {
        return Err(Error::SparkVerifyFailed);
    }
    let v_point = PeerPoint::decode_non_identity(proof.value_commitment)
        .map_err(|_| Error::SparkVerifyFailed)?
        .into_point();
    let shifted: Vec<RistrettoPoint> = coins.iter().map(|c| c - v_point).collect();
    let ctx = spend_context_v4(&proof.value_commitment, message);
    verify_one_of_many_hk_ctx(&shifted, &proof.membership, &ctx)?;
    Ok(v_point)
}

/// Proof that a bound coin `C = v·Gv + s·H + r·K` (appended to the tree) and a
/// published value commitment `V = v·Gv + b·K` (used by the balance proof) commit
/// the **same value** `v` — the OUTPUT mint-binding, the mirror of the input
/// value-binding in `verify_spend_bound`. Without it, a minter could store value
/// `X` in the tree coin while declaring value `Y` in the balance, then later
/// spend the `X` coin — inflation. A two-statement Schnorr whose shared value
/// response `z_v` forces the two values equal.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, BorshSerialize, BorshDeserialize)]
pub struct MintBindingProof {
    r1: [u8; 32],
    r2: [u8; 32],
    zv: [u8; 32],
    zs: [u8; 32],
    zr: [u8; 32],
    zb: [u8; 32],
}

fn mint_challenge(
    c_out: &RistrettoPoint,
    v_out: &RistrettoPoint,
    r1: &RistrettoPoint,
    r2: &RistrettoPoint,
) -> Scalar {
    let mut h = Sha3_512::new();
    h.update(b"COINCYNC_SPARK_MINT_BIND_FS_v1");
    h.update(c_out.compress().as_bytes());
    h.update(v_out.compress().as_bytes());
    h.update(r1.compress().as_bytes());
    h.update(r2.compress().as_bytes());
    let mut wide = [0u8; 64];
    wide.copy_from_slice(&h.finalize());
    Scalar::from_bytes_mod_order_wide(&wide)
}

/// Prove the output mint-binding: `C_out = value·Gv + serial·H + coin_blinding·K`
/// and `V_out = value·Gv + value_blinding·K` share `value`.
pub fn prove_mint_binding<R: CryptoRng + RngCore>(
    value: u64,
    serial: &Scalar,
    coin_blinding: &Scalar,
    value_blinding: &Scalar,
    rng: &mut R,
) -> MintBindingProof {
    let (gv, h_gen, k) = (gen_gv(), gen_h(), gen_k());
    let v = Scalar::from(value);
    let c_out = gv * v + h_gen * serial + k * coin_blinding;
    let v_out = gv * v + k * value_blinding;
    let kv = Scalar::random(&mut *rng);
    let ks = Scalar::random(&mut *rng);
    let kr = Scalar::random(&mut *rng);
    let kb = Scalar::random(&mut *rng);
    let r1 = gv * kv + h_gen * ks + k * kr;
    let r2 = gv * kv + k * kb;
    let c = mint_challenge(&c_out, &v_out, &r1, &r2);
    MintBindingProof {
        r1: r1.compress().to_bytes(),
        r2: r2.compress().to_bytes(),
        zv: (kv + c * v).to_bytes(),
        zs: (ks + c * serial).to_bytes(),
        zr: (kr + c * coin_blinding).to_bytes(),
        zb: (kb + c * value_blinding).to_bytes(),
    }
}

/// Verify the output mint-binding for tree coin `c_out` and value commitment
/// `v_out`. Fail-closed.
pub fn verify_mint_binding(
    c_out: &RistrettoPoint,
    v_out: &RistrettoPoint,
    proof: &MintBindingProof,
) -> Result<()> {
    let (gv, h_gen, k) = (gen_gv(), gen_h(), gen_k());
    let r1 = PeerPoint::decode_non_identity(proof.r1)
        .map_err(|_| Error::SparkVerifyFailed)?
        .into_point();
    let r2 = PeerPoint::decode_non_identity(proof.r2)
        .map_err(|_| Error::SparkVerifyFailed)?
        .into_point();
    let zv = *PeerScalar::decode(proof.zv).map_err(|_| Error::SparkVerifyFailed)?.as_scalar();
    let zs = *PeerScalar::decode(proof.zs).map_err(|_| Error::SparkVerifyFailed)?.as_scalar();
    let zr = *PeerScalar::decode(proof.zr).map_err(|_| Error::SparkVerifyFailed)?.as_scalar();
    let zb = *PeerScalar::decode(proof.zb).map_err(|_| Error::SparkVerifyFailed)?.as_scalar();
    let c = mint_challenge(c_out, v_out, &r1, &r2);
    // Shared z_v across both equations ⇒ the two commitments share their value.
    if gv * zv + h_gen * zs + k * zr != r1 + c_out * c {
        return Err(Error::SparkVerifyFailed);
    }
    if gv * zv + k * zb != r2 + v_out * c {
        return Err(Error::SparkVerifyFailed);
    }
    Ok(())
}

impl MintBindingProof {
    pub fn encode(&self) -> Vec<u8> {
        borsh::to_vec(self).expect("MintBindingProof borsh serialization is infallible into a Vec")
    }
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        borsh::from_slice(bytes)
            .map_err(|e| Error::CryptoError(format!("MintBindingProof decode: {e}")))
    }
}

impl SparkSpendProofV3 {
    /// Encode to opaque payload bytes.
    pub fn encode(&self) -> Vec<u8> {
        borsh::to_vec(self).expect("SparkSpendProofV3 borsh serialization is infallible into a Vec")
    }
    /// Decode from payload bytes, rejecting trailing/garbage bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        borsh::from_slice(bytes)
            .map_err(|e| Error::CryptoError(format!("SparkSpendProofV3 decode: {e}")))
    }
    /// The double-spend nullifier (domain-separated hash of the revealed serial).
    pub fn nullifier(&self) -> [u8; 32] {
        let mut h = Sha3_256::new();
        h.update(b"COINCYNC_SPARK_NULLIFIER_v1");
        h.update(self.serial);
        let mut out = [0u8; 32];
        out.copy_from_slice(&h.finalize());
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
    use curve25519_dalek::scalar::Scalar;
    use rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;

    /// A commitment to zero with randomness `r`: `Com(0; r) = r·K`.
    fn zero_commitment(r: &Scalar) -> RistrettoPoint {
        gen_k() * r
    }
    /// An arbitrary (generally non-zero) commitment, deterministic per seed.
    fn filler(seed: u64) -> RistrettoPoint {
        RISTRETTO_BASEPOINT_POINT * Scalar::from(seed + 1) + gen_k() * Scalar::from(seed * 7 + 3)
    }
    fn tweak(bytes: [u8; 32]) -> [u8; 32] {
        (Scalar::from_bytes_mod_order(bytes) + Scalar::ONE).to_bytes()
    }

    fn coin(m: &Scalar, r: &Scalar) -> RistrettoPoint {
        gen_g() * m + gen_k() * r
    }

    /// A bound coin `C = v·Gv + h·H + r·K`.
    fn bound(v: u64, h: &Scalar, r: &Scalar) -> RistrettoPoint {
        gen_gv() * Scalar::from(v) + gen_h() * h + gen_k() * r
    }

    #[test]
    fn hk_one_of_many_round_trip_and_context_binding() {
        let mut rng = ChaCha20Rng::seed_from_u64(700);
        let h = Scalar::random(&mut rng);
        let k = Scalar::random(&mut rng);
        let mut coins: Vec<RistrettoPoint> =
            (0..4u64).map(|s| bound(s + 2, &Scalar::from(s + 3), &Scalar::from(s + 4))).collect();
        let l = 2;
        coins[l] = gen_h() * h + gen_k() * k; // member in ⟨H,K⟩
        let proof = prove_one_of_many_hk_ctx(&coins, l, &h, &k, b"ctx", &mut rng).unwrap();
        assert!(verify_one_of_many_hk_ctx(&coins, &proof, b"ctx").is_ok());
        // A different context no longer reproduces the challenge → fail.
        assert!(verify_one_of_many_hk_ctx(&coins, &proof, b"other").is_err());
    }

    #[test]
    fn hk_rejects_member_with_gv_component() {
        // The proof asserts the member lies in ⟨H,K⟩; a Gv term (nonzero value)
        // cannot be absorbed by z_dh·H + z_dk·K (Gv ⟂ H,K).
        let mut rng = ChaCha20Rng::seed_from_u64(701);
        let h = Scalar::random(&mut rng);
        let k = Scalar::random(&mut rng);
        let mut coins: Vec<RistrettoPoint> = (0..4u64).map(|s| gen_k() * Scalar::from(s * 5 + 2)).collect();
        let l = 1;
        coins[l] = gen_h() * h + gen_k() * k;
        let proof = prove_one_of_many_hk_ctx(&coins, l, &h, &k, b"c", &mut rng).unwrap();
        assert!(verify_one_of_many_hk_ctx(&coins, &proof, b"c").is_ok());
        let mut tampered = coins.clone();
        tampered[l] += gen_gv() * Scalar::from(1u64); // inject value
        assert!(verify_one_of_many_hk_ctx(&tampered, &proof, b"c").is_err());
    }

    #[test]
    fn hk_tampered_response_rejected() {
        let mut rng = ChaCha20Rng::seed_from_u64(702);
        let h = Scalar::random(&mut rng);
        let k = Scalar::random(&mut rng);
        let mut coins: Vec<RistrettoPoint> = (0..8u64).map(|s| gen_k() * Scalar::from(s + 1)).collect();
        let l = 5;
        coins[l] = gen_h() * h + gen_k() * k;
        let mut proof = prove_one_of_many_hk_ctx(&coins, l, &h, &k, b"", &mut rng).unwrap();
        proof.zdh = tweak(proof.zdh);
        assert!(verify_one_of_many_hk_ctx(&coins, &proof, b"").is_err());
    }

    #[test]
    fn spark_spend_v4_round_trip_and_value_binding() {
        let mut rng = ChaCha20Rng::seed_from_u64(703);
        let value = 1_000_000u64;
        let h_coef = Scalar::random(&mut rng); // s_pub + spend_secret (hidden)
        let r = Scalar::random(&mut rng);
        let vb = Scalar::random(&mut rng);
        let mut coins: Vec<RistrettoPoint> =
            (0..4u64).map(|s| bound(s + 5, &Scalar::from(s + 6), &Scalar::from(s + 7))).collect();
        let l = 3;
        coins[l] = bound(value, &h_coef, &r);

        let msg = [7u8; 32];
        let proof = prove_spend_value_hidden(&coins, l, value, &h_coef, &r, &vb, &msg, &mut rng).unwrap();
        let v = verify_spend_value_hidden(&coins, &proof, &msg).unwrap();
        // The returned V is the published value commitment v·Gv + vb·K.
        assert_eq!(v, gen_gv() * Scalar::from(value) + gen_k() * vb);
        // Wrong message rejected (Fiat-Shamir binding).
        assert!(verify_spend_value_hidden(&coins, &proof, &[8u8; 32]).is_err());
        // Tampered value commitment rejected.
        let mut bad = proof.clone();
        bad.value_commitment = tweak(bad.value_commitment);
        assert!(verify_spend_value_hidden(&coins, &bad, &msg).is_err());
    }

    #[test]
    fn spark_spend_v2_round_trips_and_structurally_decodes() {
        let p = SparkSpendProofV2 {
            one_of_many: well_formed(3),
            serial: canon_scalar(),
            message: [9u8; 32],
        };
        // Wire round-trip through the opaque payload bytes.
        let bytes = p.encode();
        assert_eq!(SparkSpendProofV2::from_bytes(&bytes).unwrap(), p);
        // Structural/canonical decode (not the full verify) succeeds.
        let (oom, _serial) = p.decode().unwrap();
        assert_eq!(oom.m, 3);
        // Non-canonical serial rejected.
        let mut bad = p.clone();
        bad.serial = [0xFFu8; 32];
        assert!(bad.decode().is_err(), "non-canonical serial rejected");
        // Trailing bytes rejected (borsh full-consumption).
        let mut extra = bytes.clone();
        extra.push(0);
        assert!(SparkSpendProofV2::from_bytes(&extra).is_err());
    }

    #[test]
    fn spend_completeness() {
        let mut rng = ChaCha20Rng::seed_from_u64(10);
        let message = [3u8; 32];
        for m_bits in 1..=3usize {
            let n = 1usize << m_bits;
            let openings: Vec<(Scalar, Scalar)> = (0..n)
                .map(|_| (Scalar::random(&mut rng), Scalar::random(&mut rng)))
                .collect();
            let coins: Vec<RistrettoPoint> = openings.iter().map(|(m, r)| coin(m, r)).collect();
            for l in [0usize, n / 2, n - 1] {
                let (ml, rl) = &openings[l];
                let proof = prove_spend(&coins, l, ml, rl, &message, &mut rng).unwrap();
                assert!(
                    verify_spend(&coins, &proof, &message).is_ok(),
                    "honest spend must verify (m_bits={m_bits}, l={l})"
                );
            }
        }
    }

    #[test]
    fn spend_soundness_and_binding() {
        let mut rng = ChaCha20Rng::seed_from_u64(11);
        let message = [7u8; 32];
        let n = 8usize;
        let openings: Vec<(Scalar, Scalar)> = (0..n)
            .map(|_| (Scalar::random(&mut rng), Scalar::random(&mut rng)))
            .collect();
        let coins: Vec<RistrettoPoint> = openings.iter().map(|(m, r)| coin(m, r)).collect();
        let l = 5usize;
        let (ml, rl) = (openings[l].0, openings[l].1);
        let proof = prove_spend(&coins, l, &ml, &rl, &message, &mut rng).unwrap();
        assert!(verify_spend(&coins, &proof, &message).is_ok());

        // Message is bound in the challenge: verifying under a different message
        // fails, and tampering the proof's own message field fails either way.
        assert!(verify_spend(&coins, &proof, &[0u8; 32]).is_err(), "wrong message rejected");
        let mut m2 = proof.clone();
        m2.message = [0u8; 32];
        assert!(verify_spend(&coins, &m2, &message).is_err());
        assert!(verify_spend(&coins, &m2, &[0u8; 32]).is_err());

        // Tampered serial → the shifted set differs → one-of-many fails (this is
        // the double-spend/serial binding: the serial cannot be moved).
        let mut s2 = proof.clone();
        s2.serial = (ml + Scalar::ONE).to_bytes();
        assert!(verify_spend(&coins, &s2, &message).is_err(), "tampered serial rejected");

        // Tampered one-of-many response → rejected.
        let mut t2 = proof.clone();
        t2.one_of_many.f[0] = tweak(t2.one_of_many.f[0]);
        assert!(verify_spend(&coins, &t2, &message).is_err(), "tampered proof rejected");

        // Bound to the exact anon set: changing a non-spent member → rejected.
        let mut other = coins.clone();
        other[0] = coin(&Scalar::random(&mut rng), &Scalar::random(&mut rng));
        assert!(verify_spend(&other, &proof, &message).is_err(), "proof is set-bound");

        // Ownership: a prover cannot claim a wrong opening — wrong blinding,
        // wrong serial, or the opening of a different coin all fail the check.
        assert!(prove_spend(&coins, l, &ml, &Scalar::random(&mut rng), &message, &mut rng).is_err());
        assert!(prove_spend(&coins, l, &(ml + Scalar::ONE), &rl, &message, &mut rng).is_err());
        let (m0, r0) = (openings[0].0, openings[0].1);
        assert!(
            prove_spend(&coins, l, &m0, &r0, &message, &mut rng).is_err(),
            "opening of the wrong coin rejected"
        );
    }

    #[test]
    fn nullifier_is_deterministic_per_coin_and_message_independent() {
        let mut rng = ChaCha20Rng::seed_from_u64(12);
        let n = 4usize;
        let openings: Vec<(Scalar, Scalar)> = (0..n)
            .map(|_| (Scalar::random(&mut rng), Scalar::random(&mut rng)))
            .collect();
        let coins: Vec<RistrettoPoint> = openings.iter().map(|(m, r)| coin(m, r)).collect();
        let l = 2usize;
        let (ml, rl) = (openings[l].0, openings[l].1);

        // Same coin spent under two different messages (+ fresh randomness) →
        // SAME nullifier, so a double-spend is detectable regardless of message.
        let p_a = prove_spend(&coins, l, &ml, &rl, &[1u8; 32], &mut rng).unwrap();
        let p_b = prove_spend(&coins, l, &ml, &rl, &[2u8; 32], &mut rng).unwrap();
        assert_eq!(p_a.nullifier(), p_b.nullifier(), "same coin → same nullifier");

        // A different coin → different nullifier.
        let (m0, r0) = (openings[0].0, openings[0].1);
        let p_other = prove_spend(&coins, 0, &m0, &r0, &[1u8; 32], &mut rng).unwrap();
        assert_ne!(p_a.nullifier(), p_other.nullifier(), "distinct coins → distinct nullifiers");
        assert_ne!(p_a.nullifier(), [0u8; 32]);
    }

    // ── Value-bound spend (SparkSpendProofV3) ───────────────────────────────

    #[test]
    fn bound_spend_completeness_and_returns_value_commitment() {
        let mut rng = ChaCha20Rng::seed_from_u64(20);
        let message = [4u8; 32];
        for m_bits in 1..=3usize {
            let n = 1usize << m_bits;
            let vals: Vec<u64> = (0..n).map(|i| (i as u64 + 1) * 10).collect();
            let sers: Vec<Scalar> = (0..n).map(|_| Scalar::random(&mut rng)).collect();
            let blinds: Vec<Scalar> = (0..n).map(|_| Scalar::random(&mut rng)).collect();
            let coins: Vec<RistrettoPoint> = (0..n)
                .map(|i| bound_coin_commitment(vals[i], &sers[i], &blinds[i]))
                .collect();
            for l in [0usize, n - 1] {
                let vb = Scalar::random(&mut rng);
                let proof =
                    prove_spend_bound(&coins, l, vals[l], &sers[l], &blinds[l], &vb, &message, &mut rng)
                        .unwrap();
                let v = verify_spend_bound(&coins, &proof, &message).unwrap();
                // Returned commitment is exactly V = v_l·Gv + vb·K.
                assert_eq!(v, gen_gv() * Scalar::from(vals[l]) + gen_k() * vb);
            }
        }
    }

    #[test]
    fn bound_spend_binds_value_serial_message_and_set() {
        let mut rng = ChaCha20Rng::seed_from_u64(21);
        let message = [7u8; 32];
        let n = 8usize;
        let vals: Vec<u64> = (0..n).map(|i| (i as u64 + 1) * 7).collect();
        let sers: Vec<Scalar> = (0..n).map(|_| Scalar::random(&mut rng)).collect();
        let blinds: Vec<Scalar> = (0..n).map(|_| Scalar::random(&mut rng)).collect();
        let coins: Vec<RistrettoPoint> = (0..n)
            .map(|i| bound_coin_commitment(vals[i], &sers[i], &blinds[i]))
            .collect();
        let l = 5usize;
        let vb = Scalar::random(&mut rng);
        let proof =
            prove_spend_bound(&coins, l, vals[l], &sers[l], &blinds[l], &vb, &message, &mut rng).unwrap();
        assert!(verify_spend_bound(&coins, &proof, &message).is_ok());

        // THE BINDING: swap in a value commitment for a DIFFERENT value → the
        // shifted W_l gains a Gv term → one-of-many fails. A spender cannot feed
        // the balance a value other than the spent coin's.
        let mut wrong_value = proof.clone();
        wrong_value.value_commitment =
            (gen_gv() * Scalar::from(vals[l] + 1) + gen_k() * vb).compress().to_bytes();
        assert!(
            verify_spend_bound(&coins, &wrong_value, &message).is_err(),
            "value is bound to the spent coin"
        );

        // Serial/message/set/canonicality all bound.
        assert!(verify_spend_bound(&coins, &proof, &[0u8; 32]).is_err());
        let mut tam = proof.clone();
        tam.one_of_many.f[0] = tweak(tam.one_of_many.f[0]);
        assert!(verify_spend_bound(&coins, &tam, &message).is_err());
        let mut other = coins.clone();
        other[0] = bound_coin_commitment(999, &Scalar::random(&mut rng), &Scalar::random(&mut rng));
        assert!(verify_spend_bound(&other, &proof, &message).is_err());
        let mut nid = proof.clone();
        nid.value_commitment = [0u8; 32];
        assert!(verify_spend_bound(&coins, &nid, &message).is_err());

        // Prover cannot claim a wrong opening.
        assert!(prove_spend_bound(
            &coins,
            l,
            vals[l] + 1,
            &sers[l],
            &blinds[l],
            &vb,
            &message,
            &mut rng
        )
        .is_err());
    }

    #[test]
    fn bound_spend_plus_balance_prevents_inflation() {
        use crate::crypto::spark_balance::{prove_balance, value_commitment, verify_balance};
        let mut rng = ChaCha20Rng::seed_from_u64(22);
        let message = [9u8; 32];
        // 4-coin anon set; spend coins 0 and 1 (values 5 and 3 → 8 in).
        let n = 4usize;
        let vals = [5u64, 3, 11, 2];
        let sers: Vec<Scalar> = (0..n).map(|_| Scalar::random(&mut rng)).collect();
        let blinds: Vec<Scalar> = (0..n).map(|_| Scalar::random(&mut rng)).collect();
        let coins: Vec<RistrettoPoint> = (0..n)
            .map(|i| bound_coin_commitment(vals[i], &sers[i], &blinds[i]))
            .collect();

        let (vb0, vb1) = (Scalar::random(&mut rng), Scalar::random(&mut rng));
        let p0 =
            prove_spend_bound(&coins, 0, vals[0], &sers[0], &blinds[0], &vb0, &message, &mut rng).unwrap();
        let p1 =
            prove_spend_bound(&coins, 1, vals[1], &sers[1], &blinds[1], &vb1, &message, &mut rng).unwrap();
        // Bound spends yield the value-bound input commitments.
        let vin0 = verify_spend_bound(&coins, &p0, &message).unwrap();
        let vin1 = verify_spend_bound(&coins, &p1, &message).unwrap();

        // Honest tx: one output of 6, fee 2 (= 8 in). Balance over the SAME input
        // commitments the bound spends produced.
        let fee = 2u64;
        let out_b = Scalar::random(&mut rng);
        let vout = vec![value_commitment(6, &out_b)];
        let bal =
            prove_balance(&[vals[0], vals[1]], &[vb0, vb1], &[6], &[out_b], fee, &message, &mut rng)
                .unwrap();
        assert!(verify_balance(&[vin0, vin1], &vout, fee, &bal, &message).is_ok());

        // INFLATION: claim a 100 output from 8 in. The prover cannot build a
        // balance proof (values don't conserve), and the honest proof does not
        // verify against inflated outputs.
        assert!(prove_balance(
            &[vals[0], vals[1]],
            &[vb0, vb1],
            &[100],
            &[Scalar::random(&mut rng)],
            fee,
            &message,
            &mut rng
        )
        .is_err());
        let vout_big = vec![value_commitment(100, &out_b)];
        assert!(verify_balance(&[vin0, vin1], &vout_big, fee, &bal, &message).is_err());
    }

    #[test]
    fn mint_binding_ties_tree_coin_value_to_published_value_commitment() {
        let mut rng = ChaCha20Rng::seed_from_u64(30);
        let value = 250u64;
        let serial = Scalar::random(&mut rng);
        let coin_blinding = Scalar::random(&mut rng);
        let value_blinding = Scalar::random(&mut rng);

        let c_out = bound_coin_commitment(value, &serial, &coin_blinding);
        let v_out = gen_gv() * Scalar::from(value) + gen_k() * value_blinding;
        let proof = prove_mint_binding(value, &serial, &coin_blinding, &value_blinding, &mut rng);
        assert!(verify_mint_binding(&c_out, &v_out, &proof).is_ok());

        // Wire round-trip.
        assert_eq!(MintBindingProof::from_bytes(&proof.encode()).unwrap(), proof);

        // A V_out committing a DIFFERENT value than the tree coin → rejected.
        let v_wrong = gen_gv() * Scalar::from(value + 1) + gen_k() * value_blinding;
        assert!(
            verify_mint_binding(&c_out, &v_wrong, &proof).is_err(),
            "tree-coin value must equal the published value commitment"
        );
        // A tree coin committing a different value → rejected.
        let c_wrong = bound_coin_commitment(value + 1, &serial, &coin_blinding);
        assert!(verify_mint_binding(&c_wrong, &v_out, &proof).is_err());
        // Tampered response → rejected.
        let mut tam = proof.clone();
        tam.zv = tweak(tam.zv);
        assert!(verify_mint_binding(&c_out, &v_out, &tam).is_err());
    }

    #[test]
    fn one_of_many_completeness() {
        let mut rng = ChaCha20Rng::seed_from_u64(1);
        for m in 1..=4usize {
            let n = 1usize << m;
            for l in [0usize, n / 2, n - 1] {
                let r = Scalar::random(&mut rng);
                let mut commits: Vec<RistrettoPoint> =
                    (0..n).map(|i| filler(i as u64)).collect();
                commits[l] = zero_commitment(&r);
                let proof = prove_one_of_many(&commits, l, &r, &mut rng).unwrap();
                assert!(
                    verify_one_of_many(&commits, &proof).is_ok(),
                    "honest proof must verify (m={m}, l={l})"
                );
            }
        }
    }

    #[test]
    fn one_of_many_soundness() {
        let mut rng = ChaCha20Rng::seed_from_u64(2);
        let (m, l) = (3usize, 5usize);
        let n = 1usize << m;
        let r = Scalar::random(&mut rng);
        let mut commits: Vec<RistrettoPoint> = (0..n).map(|i| filler(i as u64)).collect();
        commits[l] = zero_commitment(&r);
        let proof = prove_one_of_many(&commits, l, &r, &mut rng).unwrap();
        assert!(verify_one_of_many(&commits, &proof).is_ok());

        // Tampered response scalar (f_j) → bit-ness check fails.
        let mut bad = proof.clone();
        bad.f[0] = tweak(bad.f[0]);
        assert!(verify_one_of_many(&commits, &bad).is_err(), "tampered f rejected");

        // Tampered final response (z_d) → one-of-many equation fails.
        let mut bad_zd = proof.clone();
        bad_zd.zd = tweak(bad_zd.zd);
        assert!(verify_one_of_many(&commits, &bad_zd).is_err(), "tampered zd rejected");

        // Wrong witness: the "hidden" commitment is NOT a commitment to zero
        // (carries a value term v·G). The prover can build a proof, but the
        // one-of-many equation leaves an uncancelled v·x^m·G term → rejected.
        let mut nonzero = commits.clone();
        nonzero[l] = zero_commitment(&r) + gen_g() * Scalar::from(3u64);
        let forged = prove_one_of_many(&nonzero, l, &r, &mut rng).unwrap();
        assert!(
            verify_one_of_many(&nonzero, &forged).is_err(),
            "a non-zero hidden commitment must fail the one-of-many equation"
        );

        // Proof is bound to its exact commitment set (a changed member reshapes
        // the Fiat-Shamir challenge + the sum) → rejected.
        let mut other = commits.clone();
        other[0] = filler(9999);
        assert!(
            verify_one_of_many(&other, &proof).is_err(),
            "proof must not verify against a different commitment set"
        );
    }

    fn canon_point() -> [u8; 32] {
        // A canonical, non-identity Ristretto encoding.
        (RISTRETTO_BASEPOINT_POINT * Scalar::from(7u64))
            .compress()
            .to_bytes()
    }
    fn canon_scalar() -> [u8; 32] {
        Scalar::from(5u64).to_bytes()
    }

    fn well_formed(m: usize) -> GkOneOfManyProof {
        GkOneOfManyProof {
            cl: vec![canon_point(); m],
            ca: vec![canon_point(); m],
            cb: vec![canon_point(); m],
            gk: vec![canon_point(); m],
            f: vec![canon_scalar(); m],
            za: vec![canon_scalar(); m],
            zb: vec![canon_scalar(); m],
            zd: canon_scalar(),
        }
    }

    #[test]
    fn borsh_round_trips() {
        let p = well_formed(4);
        let bytes = borsh::to_vec(&p).unwrap();
        let back: GkOneOfManyProof = borsh::from_slice(&bytes).unwrap();
        assert_eq!(p, back);
    }

    #[test]
    fn decode_accepts_well_formed_and_reports_m() {
        let decoded = well_formed(3).decode().unwrap();
        assert_eq!(decoded.m, 3);
        assert_eq!(decoded.cl.len(), 3);
        assert_eq!(decoded.f.len(), 3);
    }

    #[test]
    fn decode_rejects_bad_shape() {
        assert!(well_formed(0).decode().is_err(), "m=0 rejected");
        assert!(
            well_formed(MAX_GK_ROUNDS + 1).decode().is_err(),
            "m over cap rejected"
        );
        let mut p = well_formed(3);
        p.ca.pop(); // now len 2 != m 3
        assert!(p.decode().is_err(), "mismatched field length rejected");
    }

    #[test]
    fn decode_rejects_non_canonical_scalar_and_point() {
        // Non-canonical scalar: all-0xFF exceeds the group order.
        let mut p = well_formed(2);
        p.f[0] = [0xFFu8; 32];
        assert!(p.decode().is_err(), "non-canonical scalar rejected");

        // Invalid / identity point rejected.
        let mut p2 = well_formed(2);
        p2.cl[0] = [0u8; 32]; // Ristretto identity — rejected by decode_non_identity
        assert!(p2.decode().is_err(), "identity commitment rejected");

        let mut p3 = well_formed(2);
        p3.gk[1] = [0xFFu8; 32]; // not a valid Ristretto encoding
        assert!(p3.decode().is_err(), "invalid point rejected");
    }
}
