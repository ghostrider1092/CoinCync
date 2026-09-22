//! Shielded value **range** binding (gap #2): prove a shielded value commitment
//! `V = v·Gv + b·K` hides a value `v ∈ [0, 2^64)`, so the value-balance proof
//! (`crypto::spark_balance`) is sound against a *malicious* prover.
//!
//! ## Why this is needed
//! The balance proof only shows `Σ v_in = Σ v_out + fee` **in the scalar field**.
//! Without a range bound, an attacker could commit to a value scalar ≥ 2^64 (or
//! a field-negative amount) so the field sum balances while the real integer
//! amounts do not — minting money. A 64-bit range proof on every value forces
//! each `v` to be a genuine integer in `[0, 2^64)`; then, because only a handful
//! of such values are summed, field balance ⇔ integer balance.
//!
//! ## Construction (generator alignment)
//! CoinCync's audited range proofs (`crypto::bulletproofs`, BP+) prove range for
//! a commitment on the *Monero-convention* basis `C = v·H + r·G` (value `H`,
//! blinding `G`). The shielded value commitment `V` lives on a *different* basis
//! (`v·Gv + b·K`). Rather than reimplement range proofs on the shielded basis,
//! we:
//!   1. build a range-basis commitment `C = v·H + r·G` to the same `v`,
//!   2. range-prove `C` with the existing BP+ machinery, and
//!   3. prove — with a [`ValueEqualityProof`] (a two-basis Schnorr sharing the
//!      value response `z_v`) — that `V` and `C` commit the **same** `v`.
//! So the range bound on `C` transfers to `V`, which the balance/spend proofs
//! use. Nothing here trusts the caller: a `V`/`C` value mismatch fails the
//! equality proof, and a wrong/tampered range proof fails BP+ verification.
//!
//! Gated `sketch-gk-proof`, **unaudited**, unwired.

use crate::crypto::bulletproofs::{
    blinding_generator, create_range_proof, value_generator, verify_range_proof, BlindingFactor,
    PedersenCommitment, RangeProof,
};
use crate::crypto::spark_generators::{gen_gv, gen_k};
use crate::crypto::{PeerPoint, PeerScalar};
use crate::error::{Error, Result};
use crate::primitives::Amount;
use borsh::{BorshDeserialize, BorshSerialize};
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use rand::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};
use sha3::{Digest, Sha3_512};

/// Proof that two commitments on different bases hide the same value `v`:
/// `V = v·Gv + b·K` (shielded value commitment) and `C = v·H + r·G` (range-proof
/// basis). A two-basis Schnorr; the shared value response `z_v` is what binds
/// the values equal.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, BorshSerialize, BorshDeserialize)]
pub struct ValueEqualityProof {
    r1: [u8; 32],
    r2: [u8; 32],
    zv: [u8; 32],
    zb: [u8; 32],
    zr: [u8; 32],
}

/// A shielded value's range binding: the range-basis commitment, its BP+ range
/// proof, and the equality proof tying it to the shielded value commitment `V`.
#[derive(Clone, Debug, Serialize, Deserialize, BorshSerialize, BorshDeserialize)]
pub struct ShieldedRangeProof {
    /// Range-basis commitment `C = v·H + r·G`, compressed.
    pub c_range: [u8; 32],
    /// BP+ range proof attesting `C` commits a value in `[0, 2^64)`.
    pub range: RangeProof,
    /// Proof that `C` and the shielded `V` commit the same value.
    pub eq: ValueEqualityProof,
}

impl ShieldedRangeProof {
    /// Encode to opaque payload bytes.
    pub fn encode(&self) -> Vec<u8> {
        borsh::to_vec(self).expect("ShieldedRangeProof borsh serialization is infallible into a Vec")
    }
    /// Decode from payload bytes, rejecting trailing/garbage bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        borsh::from_slice(bytes)
            .map_err(|e| Error::CryptoError(format!("ShieldedRangeProof decode: {e}")))
    }
}

fn eq_challenge(v: &RistrettoPoint, c: &RistrettoPoint, r1: &RistrettoPoint, r2: &RistrettoPoint) -> Scalar {
    let mut h = Sha3_512::new();
    h.update(b"COINCYNC_SPARK_VALUE_EQ_FS_v1");
    h.update(v.compress().as_bytes());
    h.update(c.compress().as_bytes());
    h.update(r1.compress().as_bytes());
    h.update(r2.compress().as_bytes());
    let mut wide = [0u8; 64];
    wide.copy_from_slice(&h.finalize());
    Scalar::from_bytes_mod_order_wide(&wide)
}

/// **Value bridge** — the reusable cross-basis equality primitive: prove a Spark
/// value commitment `V = v·Gv + spark_blinding·K` and a Monero-basis commitment
/// `C = v·H + bp_blinding·G` hide the SAME value `v`. This is the connector core
/// used by the range binding here AND by the shield/unshield turnstile
/// (`crypto::spark_turnstile`), where `C` is a transparent Pedersen commitment.
pub fn prove_value_bridge<R: CryptoRng + RngCore>(
    value: u64,
    spark_blinding: &Scalar,
    bp_blinding: &Scalar,
    rng: &mut R,
) -> ValueEqualityProof {
    prove_value_equality(value, spark_blinding, bp_blinding, rng)
}

/// Verify a [`prove_value_bridge`] proof: `spark_v = v·Gv + b·K` and `bp_c =
/// v·H + r·G` share their value `v`.
pub fn verify_value_bridge(
    spark_v: &RistrettoPoint,
    bp_c: &RistrettoPoint,
    proof: &ValueEqualityProof,
) -> Result<()> {
    verify_value_equality(spark_v, bp_c, proof)
}

/// Prove `V = v·Gv + v_blinding·K` and `C = v·H + range_blinding·G` share `v`.
fn prove_value_equality<R: CryptoRng + RngCore>(
    value: u64,
    v_blinding: &Scalar,
    range_blinding: &Scalar,
    rng: &mut R,
) -> ValueEqualityProof {
    let (gv, k) = (gen_gv(), gen_k());
    let (h, g) = (value_generator(), blinding_generator());
    let v = Scalar::from(value);
    let v_point = gv * v + k * v_blinding;
    let c_point = h * v + g * range_blinding;

    let kv = Scalar::random(&mut *rng);
    let kb = Scalar::random(&mut *rng);
    let kr = Scalar::random(&mut *rng);
    let r1 = gv * kv + k * kb;
    let r2 = h * kv + g * kr;
    let c = eq_challenge(&v_point, &c_point, &r1, &r2);
    let zv = kv + c * v;
    let zb = kb + c * v_blinding;
    let zr = kr + c * range_blinding;
    ValueEqualityProof {
        r1: r1.compress().to_bytes(),
        r2: r2.compress().to_bytes(),
        zv: zv.to_bytes(),
        zb: zb.to_bytes(),
        zr: zr.to_bytes(),
    }
}

/// Verify the value-equality proof for shielded commitment `v_point` and
/// range-basis commitment `c_point`.
fn verify_value_equality(
    v_point: &RistrettoPoint,
    c_point: &RistrettoPoint,
    proof: &ValueEqualityProof,
) -> Result<()> {
    let (gv, k) = (gen_gv(), gen_k());
    let (h, g) = (value_generator(), blinding_generator());
    let r1 = PeerPoint::decode_non_identity(proof.r1)
        .map_err(|_| Error::SparkVerifyFailed)?
        .into_point();
    let r2 = PeerPoint::decode_non_identity(proof.r2)
        .map_err(|_| Error::SparkVerifyFailed)?
        .into_point();
    let zv = *PeerScalar::decode(proof.zv).map_err(|_| Error::SparkVerifyFailed)?.as_scalar();
    let zb = *PeerScalar::decode(proof.zb).map_err(|_| Error::SparkVerifyFailed)?.as_scalar();
    let zr = *PeerScalar::decode(proof.zr).map_err(|_| Error::SparkVerifyFailed)?.as_scalar();
    let c = eq_challenge(v_point, c_point, &r1, &r2);
    // Same z_v in both equations ⇒ same v across the two bases.
    if gv * zv + k * zb != r1 + v_point * c {
        return Err(Error::SparkVerifyFailed);
    }
    if h * zv + g * zr != r2 + c_point * c {
        return Err(Error::SparkVerifyFailed);
    }
    Ok(())
}

/// Produce a range binding for a shielded value: `value` committed as
/// `V = value·Gv + v_blinding·K` is proven to lie in `[0, 2^64)`. `v_blinding`
/// is the blinding of the shielded value commitment used by the balance/spend
/// proofs (so the range bound applies to the *same* `V`).
pub fn prove_value_range<R: CryptoRng + RngCore>(
    value: u64,
    v_blinding: &Scalar,
    rng: &mut R,
) -> Result<ShieldedRangeProof> {
    let range_bf = BlindingFactor::random(rng);
    let c_commit = PedersenCommitment::commit(value, &range_bf);
    let range = create_range_proof(Amount::from_atomic(value), &range_bf, rng)?;
    let eq = prove_value_equality(value, v_blinding, range_bf.as_scalar(), rng);
    Ok(ShieldedRangeProof {
        c_range: c_commit.to_bytes(),
        range,
        eq,
    })
}

/// Verify a shielded value's range binding against its value commitment `v_point`
/// (`= value·Gv + v_blinding·K`). Confirms (a) the range-basis commitment is
/// in `[0, 2^64)` and (b) it commits the same value as `v_point`. Fail-closed.
pub fn verify_value_range(v_point: &RistrettoPoint, proof: &ShieldedRangeProof) -> Result<()> {
    let c_commit =
        PedersenCommitment::from_bytes_checked(proof.c_range).ok_or(Error::SparkVerifyFailed)?;
    if !verify_range_proof(&c_commit, &proof.range) {
        return Err(Error::SparkVerifyFailed);
    }
    let c_point = c_commit
        .as_point()
        .decompress()
        .ok_or(Error::SparkVerifyFailed)?;
    verify_value_equality(v_point, &c_point, &proof.eq)
}

// ── The "translator" connector ──────────────────────────────────────────────
// A commitment-language translator: bulletproofs "pushes in" a range fact in its
// own basis (`C = v·H + r·G`), and the connector translates that `v ∈ [0,2^64)`
// guarantee onto Spark's value commitment (`V = v·Gv + b·K`) via the equality
// proof — so every downstream Spark station (balance, spend) consumes a
// range-bound `V` without ever speaking bulletproofs. Naming it as a seam lets
// other translators (e.g. transparent-Pedersen ↔ Spark) plug in the same way.

/// A translator that carries a range guarantee from one commitment language onto
/// a Spark value commitment.
pub trait RangeTranslator {
    /// Prove side: emit the translated range binding for a Spark value `value`
    /// committed as `V = value·Gv + spark_blinding·K`.
    fn translate<R: CryptoRng + RngCore>(
        &self,
        value: u64,
        spark_blinding: &Scalar,
        rng: &mut R,
    ) -> Result<ShieldedRangeProof>;

    /// Verify side: confirm the translated binding holds for `spark_v` — i.e.
    /// `spark_v` provably hides a value in `[0, 2^64)`.
    fn verify(&self, spark_v: &RistrettoPoint, proof: &ShieldedRangeProof) -> Result<()>;
}

/// The bulletproofs ⇄ Spark range translator (BP+ range proof + value-equality).
pub struct BulletproofSparkBridge;

impl RangeTranslator for BulletproofSparkBridge {
    fn translate<R: CryptoRng + RngCore>(
        &self,
        value: u64,
        spark_blinding: &Scalar,
        rng: &mut R,
    ) -> Result<ShieldedRangeProof> {
        prove_value_range(value, spark_blinding, rng)
    }
    fn verify(&self, spark_v: &RistrettoPoint, proof: &ShieldedRangeProof) -> Result<()> {
        verify_value_range(spark_v, proof)
    }
}

// ── The generalized bridge: one connector, many boundaries ───────────────────
// A `CommitmentBridge` proves a Monero-convention value commitment (`v·H + r·G` —
// the basis used by the transparent pool, bulletproofs, AND MimbleWimble kernels)
// and a Spark value commitment (`v·Gv + b·K`) hide the same value. The crypto is
// identical at every boundary (they all share the Monero basis on the `C` side);
// each boundary is a named seam so the assembly line has an explicit station for
// it. New boundaries are a one-line `impl`.

/// A value-commitment bridge between a Monero-basis commitment and a Spark value
/// commitment. Default methods delegate to [`prove_value_bridge`] /
/// [`verify_value_bridge`]; an impl only names its boundary.
pub trait CommitmentBridge {
    /// A short label for the boundary this bridge spans (diagnostics).
    fn boundary(&self) -> &'static str;

    /// Prove the Monero-basis commitment `value·H + monero_blinding·G` and the
    /// Spark commitment `value·Gv + spark_blinding·K` hide the same `value`.
    fn prove<R: CryptoRng + RngCore>(
        &self,
        value: u64,
        monero_blinding: &Scalar,
        spark_blinding: &Scalar,
        rng: &mut R,
    ) -> ValueEqualityProof {
        prove_value_bridge(value, spark_blinding, monero_blinding, rng)
    }

    /// Verify a bridge proof between Monero-basis `monero_c` and Spark `spark_v`.
    fn verify(
        &self,
        monero_c: &RistrettoPoint,
        spark_v: &RistrettoPoint,
        proof: &ValueEqualityProof,
    ) -> Result<()> {
        verify_value_bridge(spark_v, monero_c, proof)
    }
}

/// The transparent-pool ⇄ shielded boundary (shield / unshield). See
/// `crypto::spark_turnstile` for the value-crossing semantics on top of this.
pub struct TransparentBridge;
impl CommitmentBridge for TransparentBridge {
    fn boundary(&self) -> &'static str {
        "transparent<->shielded"
    }
}

/// The MimbleWimble-kernel ⇄ shielded boundary — `storage::KernelStore` Pedersen
/// commitments (`v·H + r·G`) bridged to Spark value commitments, so a coin can be
/// cut-through in MW and shielded in Spark. Same crypto as `TransparentBridge`;
/// distinct seam.
pub struct KernelBridge;
impl CommitmentBridge for KernelBridge {
    fn boundary(&self) -> &'static str {
        "mw-kernel<->shielded"
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;

    /// The shielded value commitment V = value·Gv + b·K (matches balance/spend).
    fn v_commit(value: u64, b: &Scalar) -> RistrettoPoint {
        gen_gv() * Scalar::from(value) + gen_k() * b
    }

    #[test]
    fn honest_value_range_binding_verifies() {
        let mut rng = ChaCha20Rng::seed_from_u64(1);
        let value = 1_000_000u64;
        let b = Scalar::random(&mut rng);
        let proof = prove_value_range(value, &b, &mut rng).unwrap();
        let v = v_commit(value, &b);
        assert!(verify_value_range(&v, &proof).is_ok());
    }

    #[test]
    fn commitment_bridges_span_their_boundaries() {
        use crate::crypto::bulletproofs::{blinding_generator, value_generator};
        let mut rng = ChaCha20Rng::seed_from_u64(77);
        let value = 9_000u64;
        let r_m = Scalar::random(&mut rng); // Monero-side blinding
        let b = Scalar::random(&mut rng); // Spark-side blinding
        let monero_c = value_generator() * Scalar::from(value) + blinding_generator() * r_m;
        let spark_v = v_commit(value, &b);
        let spark_wrong = v_commit(value + 1, &b);

        // Both boundaries use the identical crypto; each spans correctly and
        // rejects a value mismatch.
        let t = TransparentBridge;
        let pt = t.prove(value, &r_m, &b, &mut rng);
        assert!(t.verify(&monero_c, &spark_v, &pt).is_ok(), "{}", t.boundary());
        assert!(t.verify(&monero_c, &spark_wrong, &pt).is_err(), "{}", t.boundary());

        let k = KernelBridge;
        let pk = k.prove(value, &r_m, &b, &mut rng);
        assert!(k.verify(&monero_c, &spark_v, &pk).is_ok(), "{}", k.boundary());
        assert!(k.verify(&monero_c, &spark_wrong, &pk).is_err(), "{}", k.boundary());
    }

    #[test]
    fn translator_connector_round_trips() {
        // The named connector: bulletproofs' range fact is translated onto the
        // Spark value commitment; verifying speaks only Spark (a point + proof).
        let mut rng = ChaCha20Rng::seed_from_u64(9);
        let bridge = BulletproofSparkBridge;
        let value = 500_000u64;
        let b = Scalar::random(&mut rng);
        let translated = bridge.translate(value, &b, &mut rng).unwrap();
        assert!(bridge.verify(&v_commit(value, &b), &translated).is_ok());
        // Wire round-trip of the translated binding (rides in the payload).
        let bytes = translated.encode();
        assert!(bridge
            .verify(&v_commit(value, &b), &ShieldedRangeProof::from_bytes(&bytes).unwrap())
            .is_ok());
        // Mismatched Spark value → translation does not hold.
        assert!(bridge.verify(&v_commit(value + 1, &b), &translated).is_err());
    }

    #[test]
    fn equality_binds_value_to_the_shielded_commitment() {
        let mut rng = ChaCha20Rng::seed_from_u64(2);
        let value = 42u64;
        let b = Scalar::random(&mut rng);
        let proof = prove_value_range(value, &b, &mut rng).unwrap();

        // Correct V verifies.
        assert!(verify_value_range(&v_commit(value, &b), &proof).is_ok());
        // A V committing a DIFFERENT value (same blinding) fails — the range
        // bound cannot be transferred to a mismatched value commitment.
        assert!(verify_value_range(&v_commit(value + 1, &b), &proof).is_err());
        // A V with a different blinding also fails (equation 1 breaks).
        let b2 = Scalar::random(&mut rng);
        assert!(verify_value_range(&v_commit(value, &b2), &proof).is_err());
    }

    #[test]
    fn tampered_range_or_equality_is_rejected() {
        let mut rng = ChaCha20Rng::seed_from_u64(3);
        let value = 7u64;
        let b = Scalar::random(&mut rng);
        let v = v_commit(value, &b);
        let good = prove_value_range(value, &b, &mut rng).unwrap();
        assert!(verify_value_range(&v, &good).is_ok());

        // Tampered equality response → rejected.
        let mut e = good.eq.clone();
        e.zv = (Scalar::from_bytes_mod_order(e.zv) + Scalar::ONE).to_bytes();
        let bad_eq = ShieldedRangeProof {
            c_range: good.c_range,
            range: good.range.clone(),
            eq: e,
        };
        assert!(verify_value_range(&v, &bad_eq).is_err());

        // Range proof pointed at a different commitment (re-commit same value,
        // fresh blinding) → range proof no longer matches c_range → rejected.
        let other = prove_value_range(value, &b, &mut rng).unwrap();
        let mismatched = ShieldedRangeProof {
            c_range: good.c_range,
            range: other.range,
            eq: good.eq.clone(),
        };
        assert!(verify_value_range(&v, &mismatched).is_err());

        // Non-canonical equality point → rejected.
        let mut nc = good.eq.clone();
        nc.r1 = [0u8; 32];
        let bad_pt = ShieldedRangeProof {
            c_range: good.c_range,
            range: good.range,
            eq: nc,
        };
        assert!(verify_value_range(&v, &bad_pt).is_err());
    }
}
