//! Shield / unshield **turnstile** — the connector for value crossing the
//! transparent ⇄ shielded boundary.
//!
//! CoinCync's transparent pool commits value as a Monero-convention Pedersen
//! commitment `T = v·H + r·G` (CLSAG, bulletproofs). The shielded pool commits
//! value as `V = v·Gv + b·K` (Spark). When value is **shielded** (a transparent
//! output consumed, a shielded note created) or **unshielded** (the reverse),
//! the turnstile proves `T` and `V` hide the **same value** `v` — so no value is
//! created or destroyed crossing the veil.
//!
//! This is the [`crate::crypto::spark_range::prove_value_bridge`] connector
//! applied at the pool boundary: the transparent commitment plays the Monero-basis
//! side, the shielded value commitment plays the Spark side. Shield and unshield
//! prove the *same* relation (`T.value == V.value`); the direction (which side is
//! consumed vs created) is a transaction-level concern, not a proof concern.
//!
//! Gated `sketch-gk-proof`, **unaudited**, unwired. NOTE (scope): the transparent
//! side's own range/ownership (bulletproofs range proof, CLSAG) is proven where
//! that output lives; the shielded side's range is the `spark_range` binding. The
//! turnstile only bridges the *values*.

use crate::crypto::spark_range::{prove_value_bridge, verify_value_bridge, ValueEqualityProof};
use crate::error::Result;
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use rand::{CryptoRng, RngCore};

/// A turnstile crossing proof: value equality between a transparent Pedersen
/// commitment and a shielded value commitment.
pub type TurnstileProof = ValueEqualityProof;

/// Prove a value crossing (shield or unshield): the transparent commitment
/// `T = value·H + transparent_blinding·G` and the shielded value commitment
/// `V = value·Gv + shielded_blinding·K` hide the same `value`.
pub fn prove_value_crossing<R: CryptoRng + RngCore>(
    value: u64,
    transparent_blinding: &Scalar,
    shielded_blinding: &Scalar,
    rng: &mut R,
) -> TurnstileProof {
    // Spark side uses `shielded_blinding`; Monero (transparent) side uses
    // `transparent_blinding`.
    prove_value_bridge(value, shielded_blinding, transparent_blinding, rng)
}

/// Verify a value crossing: the transparent commitment `T` and the shielded value
/// commitment `V` hide the same value. Used for both shield (T consumed → V
/// created) and unshield (V consumed → T created). Fail-closed.
pub fn verify_value_crossing(
    transparent_commitment: &RistrettoPoint,
    shielded_value_commitment: &RistrettoPoint,
    proof: &TurnstileProof,
) -> Result<()> {
    verify_value_bridge(shielded_value_commitment, transparent_commitment, proof)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::bulletproofs::{blinding_generator, value_generator};
    use crate::crypto::spark_generators::{gen_gv, gen_k};
    use rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;

    /// Transparent Pedersen commitment T = v·H + r·G (Monero convention).
    fn transparent(v: u64, r: &Scalar) -> RistrettoPoint {
        value_generator() * Scalar::from(v) + blinding_generator() * r
    }
    /// Shielded value commitment V = v·Gv + b·K.
    fn shielded(v: u64, b: &Scalar) -> RistrettoPoint {
        gen_gv() * Scalar::from(v) + gen_k() * b
    }

    #[test]
    fn shield_crossing_conserves_value() {
        let mut rng = ChaCha20Rng::seed_from_u64(1);
        let value = 1_234_567u64;
        let r_t = Scalar::random(&mut rng); // transparent blinding
        let b = Scalar::random(&mut rng); // shielded blinding
        let proof = prove_value_crossing(value, &r_t, &b, &mut rng);

        let t = transparent(value, &r_t);
        let v = shielded(value, &b);
        assert!(verify_value_crossing(&t, &v, &proof).is_ok());
    }

    #[test]
    fn crossing_rejects_value_mismatch_and_tampering() {
        let mut rng = ChaCha20Rng::seed_from_u64(2);
        let value = 500u64;
        let r_t = Scalar::random(&mut rng);
        let b = Scalar::random(&mut rng);
        let proof = prove_value_crossing(value, &r_t, &b, &mut rng);
        let t = transparent(value, &r_t);
        assert!(verify_value_crossing(&t, &shielded(value, &b), &proof).is_ok());

        // Shielded note claiming a DIFFERENT value than the transparent input →
        // rejected (this is the anti-inflation guarantee of the turnstile).
        assert!(verify_value_crossing(&t, &shielded(value + 1, &b), &proof).is_err());
        // Transparent input of a different value → rejected.
        assert!(verify_value_crossing(&transparent(value + 1, &r_t), &shielded(value, &b), &proof).is_err());
    }
}
