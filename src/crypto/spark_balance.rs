//! Shielded value-balance (confidential-transaction excess) proof — the value
//! half of a shielded spend, complementing the membership/serial proof in
//! `groth_kohlweiss.rs`. See docs/design/cip-shielded-proof.md.
//!
//! ## Value commitment
//! A shielded value is a Pedersen commitment `V = v·Gv + b·K` (value `v`,
//! blinding `b`), on generators independent of the serial-commitment basis.
//!
//! ## What this proves
//! For a shielded transaction with input value commitments `{V_in}` and output
//! value commitments `{V_out}` and a public `fee`, the **excess**
//! `E = Σ V_in − Σ V_out − fee·Gv` is a commitment to the value
//! `Σ v_in − Σ v_out − fee`. If the transaction conserves value that excess is
//! zero, so `E = Δ·K` for `Δ = Σ b_in − Σ b_out`. [`BalanceProof`] is a Schnorr
//! proof of knowledge of `Δ` with `E = Δ·K`. Because `Gv` and `K` are
//! independent NUMS generators, a verifying proof forces the `Gv` (value)
//! component of `E` to zero — i.e. `Σ v_in = Σ v_out + fee` — so value cannot be
//! created or destroyed.
//!
//! ## SCOPE / what this does NOT do (still required before activation)
//! 1. **Range proofs.** Balance alone is sound only when every value lies in
//!    `[0, 2^64)` — otherwise a value could "wrap" mod the group order. Each
//!    output `V_out` needs a range proof; CoinCync's `crypto::bulletproofs`
//!    provides them (to be wired on the value generators here).
//! 2. **Binding inputs to the spent coins.** `verify_balance` takes the input
//!    value commitments as given; binding each `V_in` to the coin the
//!    membership proof spent (so a spender cannot substitute a different-value
//!    commitment) is the audit-critical linkage between this proof and the
//!    one-of-many (a linked/parallel one-of-many over the value commitments, or
//!    the full Spark coin binding). NOT done here.
//!
//! Gated `sketch-gk-proof`, **unaudited**, and unwired: the consensus spend
//! verifier does not yet call this, and shielded stays gated off.

use crate::crypto::spark_generators::{gen_gv, gen_k};
use crate::crypto::{PeerPoint, PeerScalar};
use crate::error::{Error, Result};
use borsh::{BorshDeserialize, BorshSerialize};
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use rand::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};
use sha3::{Digest, Sha3_512};

/// A shielded value commitment `V = v·Gv + b·K`.
pub fn value_commitment(value: u64, blinding: &Scalar) -> RistrettoPoint {
    gen_gv() * Scalar::from(value) + gen_k() * blinding
}

/// The value-balance (excess) proof: a Schnorr PoK that the transaction excess
/// `E = Σ V_in − Σ V_out − fee·Gv` is a commitment to zero value (`E = Δ·K`).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, BorshSerialize, BorshDeserialize)]
pub struct BalanceProof {
    /// Schnorr commitment `R = k·K`, compressed.
    pub r_commit: [u8; 32],
    /// Schnorr response `z = k + c·Δ`, canonical scalar.
    pub z: [u8; 32],
}

impl BalanceProof {
    /// Encode to opaque payload bytes.
    pub fn encode(&self) -> Vec<u8> {
        borsh::to_vec(self).expect("BalanceProof borsh serialization is infallible into a Vec")
    }
    /// Decode from payload bytes, rejecting trailing/garbage bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        borsh::from_slice(bytes)
            .map_err(|e| Error::CryptoError(format!("BalanceProof decode: {e}")))
    }
}

/// Fiat-Shamir challenge over the excess statement + the tx `context` (bind the
/// balance proof to the specific transaction, e.g. the shielded spend message).
fn balance_challenge(e: &RistrettoPoint, r: &RistrettoPoint, context: &[u8]) -> Scalar {
    let mut h = Sha3_512::new();
    h.update(b"COINCYNC_SPARK_BALANCE_FS_v1");
    h.update((context.len() as u64).to_le_bytes());
    h.update(context);
    h.update(gen_k().compress().as_bytes());
    h.update(e.compress().as_bytes());
    h.update(r.compress().as_bytes());
    let mut wide = [0u8; 64];
    wide.copy_from_slice(&h.finalize());
    Scalar::from_bytes_mod_order_wide(&wide)
}

/// Prove value balance for a transaction. `input_values`/`output_values` are the
/// cleartext amounts (the prover's witness) and `*_blindings` their commitment
/// blindings; `fee` is public. Returns `Err` if the values do not conserve — the
/// prover cannot produce a balance proof for an unbalanced transaction.
pub fn prove_balance<R: CryptoRng + RngCore>(
    input_values: &[u64],
    input_blindings: &[Scalar],
    output_values: &[u64],
    output_blindings: &[Scalar],
    fee: u64,
    context: &[u8],
    rng: &mut R,
) -> Result<BalanceProof> {
    // A pure-shielded tx: no value crosses the transparent boundary.
    prove_balance_with_delta(
        input_values,
        input_blindings,
        output_values,
        output_blindings,
        fee,
        0,
        context,
        rng,
    )
}

/// The public net value moving OUT of the shielded pool to the transparent pool
/// (Sapling `valueBalance` convention): positive = an **unshield** (value leaves
/// the shielded pool), negative = a **shield** (value enters), `0` = a pure
/// shielded transaction. The shielded pool's running total is `Σ value_balance`,
/// which the (still-to-wire) supply-turnstile consensus rule keeps `≥ 0`.
fn public_value_scalar(fee: u64, value_balance: i64) -> Scalar {
    let f = Scalar::from(fee);
    if value_balance >= 0 {
        f + Scalar::from(value_balance as u64)
    } else {
        f - Scalar::from(value_balance.unsigned_abs())
    }
}

/// As [`prove_balance`], but with a public `value_balance` moving value across the
/// transparent⇄shielded boundary. Conservation is
/// `Σ v_in = Σ v_out + fee + value_balance`.
pub fn prove_balance_with_delta<R: CryptoRng + RngCore>(
    input_values: &[u64],
    input_blindings: &[Scalar],
    output_values: &[u64],
    output_blindings: &[Scalar],
    fee: u64,
    value_balance: i64,
    context: &[u8],
    rng: &mut R,
) -> Result<BalanceProof> {
    if input_values.len() != input_blindings.len() || output_values.len() != output_blindings.len()
    {
        return Err(Error::CryptoError("balance: values/blindings length mismatch".into()));
    }
    // Value conservation (i128, signed): Σ in − Σ out − fee − value_balance = 0.
    // The caller's range proofs keep each value in [0,2^64) so this is meaningful.
    let sin: i128 = input_values.iter().map(|&v| v as i128).sum();
    let sout: i128 = output_values.iter().map(|&v| v as i128).sum();
    if sin - sout - fee as i128 - value_balance as i128 != 0 {
        return Err(Error::CryptoError("balance: values do not conserve".into()));
    }
    // Δ = Σ b_in − Σ b_out ; when balanced, the excess is E = Δ·K.
    let mut delta = Scalar::ZERO;
    for b in input_blindings {
        delta += b;
    }
    for b in output_blindings {
        delta -= b;
    }
    let kb = gen_k();
    let e = kb * delta;
    let k = Scalar::random(rng);
    let r = kb * k;
    let c = balance_challenge(&e, &r, context);
    let z = k + c * delta;
    Ok(BalanceProof {
        r_commit: r.compress().to_bytes(),
        z: z.to_bytes(),
    })
}

/// Verify a value-balance proof against the input/output value commitments and
/// the public `fee`. Fail-closed on a non-canonical proof or a failing Schnorr
/// check (which is what an unbalanced transaction produces).
pub fn verify_balance(
    input_commitments: &[RistrettoPoint],
    output_commitments: &[RistrettoPoint],
    fee: u64,
    proof: &BalanceProof,
    context: &[u8],
) -> Result<()> {
    verify_balance_with_delta(input_commitments, output_commitments, fee, 0, proof, context)
}

/// As [`verify_balance`], but with the public `value_balance` crossing the
/// transparent⇄shielded boundary (see [`prove_balance_with_delta`]).
pub fn verify_balance_with_delta(
    input_commitments: &[RistrettoPoint],
    output_commitments: &[RistrettoPoint],
    fee: u64,
    value_balance: i64,
    proof: &BalanceProof,
    context: &[u8],
) -> Result<()> {
    let gv = gen_gv();
    let kb = gen_k();
    // Excess E = Σ V_in − Σ V_out − (fee + value_balance)·Gv.
    let mut e = RistrettoPoint::default();
    for v in input_commitments {
        e += v;
    }
    for v in output_commitments {
        e -= v;
    }
    e -= gv * public_value_scalar(fee, value_balance);

    // Canonical decode of the peer-controlled proof.
    let r = PeerPoint::decode_non_identity(proof.r_commit)
        .map_err(|_| Error::SparkVerifyFailed)?
        .into_point();
    let z = *PeerScalar::decode(proof.z)
        .map_err(|_| Error::SparkVerifyFailed)?
        .as_scalar();

    let c = balance_challenge(&e, &r, context);
    // z·K == R + c·E  ⇔  knowledge of Δ with E = Δ·K ⇔ value component of E is 0.
    if kb * z == r + e * c {
        Ok(())
    } else {
        Err(Error::SparkVerifyFailed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;

    fn commits(values: &[u64], blindings: &[Scalar]) -> Vec<RistrettoPoint> {
        values
            .iter()
            .zip(blindings)
            .map(|(&v, b)| value_commitment(v, b))
            .collect()
    }

    #[test]
    fn balanced_transaction_verifies() {
        let mut rng = ChaCha20Rng::seed_from_u64(1);
        // 5 + 3 = 6 + 2(fee).
        let iv = [5u64, 3];
        let ov = [6u64];
        let fee = 2u64;
        let ib: Vec<Scalar> = (0..iv.len()).map(|_| Scalar::random(&mut rng)).collect();
        let ob: Vec<Scalar> = (0..ov.len()).map(|_| Scalar::random(&mut rng)).collect();
        let ctx = b"tx-1";

        let proof = prove_balance(&iv, &ib, &ov, &ob, fee, ctx, &mut rng).unwrap();
        let vin = commits(&iv, &ib);
        let vout = commits(&ov, &ob);
        assert!(verify_balance(&vin, &vout, fee, &proof, ctx).is_ok());
    }

    #[test]
    fn prover_refuses_unbalanced_values() {
        let mut rng = ChaCha20Rng::seed_from_u64(2);
        // 5 != 6 + 2.
        let iv = [5u64];
        let ov = [6u64];
        let ib = [Scalar::random(&mut rng)];
        let ob = [Scalar::random(&mut rng)];
        assert!(prove_balance(&iv, &ib, &ov, &ob, 2, b"x", &mut rng).is_err());
    }

    #[test]
    fn verifier_rejects_unbalanced_commitments_and_tampering() {
        let mut rng = ChaCha20Rng::seed_from_u64(3);
        let iv = [10u64];
        let ov = [7u64];
        let fee = 3u64; // 10 == 7 + 3, balanced
        let ib = [Scalar::random(&mut rng)];
        let ob = [Scalar::random(&mut rng)];
        let ctx = b"tx-2";
        let proof = prove_balance(&iv, &ib, &ov, &ob, fee, ctx, &mut rng).unwrap();
        let vin = commits(&iv, &ib);
        let vout = commits(&ov, &ob);
        assert!(verify_balance(&vin, &vout, fee, &proof, ctx).is_ok());

        // Wrong fee → excess has a Gv term → rejected.
        assert!(verify_balance(&vin, &vout, fee + 1, &proof, ctx).is_err());
        // Different context → challenge differs → rejected.
        assert!(verify_balance(&vin, &vout, fee, &proof, b"other").is_err());
        // Tampered response → rejected.
        let mut bad = proof.clone();
        bad.z = (Scalar::from_bytes_mod_order(bad.z) + Scalar::ONE).to_bytes();
        assert!(verify_balance(&vin, &vout, fee, &bad, ctx).is_err());
        // An unbalanced output set (inflated value) → excess has a Gv term →
        // the honest proof does not verify against it.
        let inflated = commits(&[9u64], &ob); // claims 9 out instead of 7
        assert!(verify_balance(&vin, &inflated, fee, &proof, ctx).is_err());

        // Non-canonical proof bytes rejected.
        let mut nc = proof.clone();
        nc.z = [0xFFu8; 32];
        assert!(verify_balance(&vin, &vout, fee, &nc, ctx).is_err());
        let mut nid = proof.clone();
        nid.r_commit = [0u8; 32]; // identity R rejected by decode_non_identity
        assert!(verify_balance(&vin, &vout, fee, &nid, ctx).is_err());
    }

    #[test]
    fn shield_and_unshield_value_balance() {
        let mut rng = ChaCha20Rng::seed_from_u64(5);
        // Shield: 10 enters the shielded pool (value_balance = -10). One shielded
        // output of 10, no shielded inputs.
        let ob = Scalar::random(&mut rng);
        let out = commits(&[10], std::slice::from_ref(&ob));
        let proof =
            prove_balance_with_delta(&[], &[], &[10], std::slice::from_ref(&ob), 0, -10, b"shield", &mut rng)
                .unwrap();
        assert!(verify_balance_with_delta(&[], &out, 0, -10, &proof, b"shield").is_ok());
        // A wrong declared value_balance is rejected.
        assert!(verify_balance_with_delta(&[], &out, 0, -9, &proof, b"shield").is_err());

        // Unshield: 7 leaves the pool (value_balance = +7). One shielded input of 7.
        let ib = Scalar::random(&mut rng);
        let inp = commits(&[7], std::slice::from_ref(&ib));
        let p2 =
            prove_balance_with_delta(&[7], std::slice::from_ref(&ib), &[], &[], 0, 7, b"unshield", &mut rng)
                .unwrap();
        assert!(verify_balance_with_delta(&inp, &[], 0, 7, &p2, b"unshield").is_ok());

        // Prover refuses an inconsistent value_balance.
        assert!(prove_balance_with_delta(&[7], std::slice::from_ref(&ib), &[], &[], 0, 5, b"x", &mut rng)
            .is_err());
    }

    #[test]
    fn many_inputs_and_outputs_balance() {
        let mut rng = ChaCha20Rng::seed_from_u64(4);
        // 100 + 50 + 25 = 60 + 110 + 5(fee) = 175.
        let iv = [100u64, 50, 25];
        let ov = [60u64, 110];
        let fee = 5u64;
        let ib: Vec<Scalar> = (0..iv.len()).map(|_| Scalar::random(&mut rng)).collect();
        let ob: Vec<Scalar> = (0..ov.len()).map(|_| Scalar::random(&mut rng)).collect();
        let ctx = b"tx-3";
        let proof = prove_balance(&iv, &ib, &ov, &ob, fee, ctx, &mut rng).unwrap();
        assert!(verify_balance(&commits(&iv, &ib), &commits(&ov, &ob), fee, &proof, ctx).is_ok());
    }
}
