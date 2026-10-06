//! Shared Spark commitment generators `G`, `H`, `K`.
//!
//! The Spark coin commitment is `C = v·G + s·H + r·K` (value, serial, blinding).
//! For the Groth-Kohlweiss one-out-of-many spend proof to prove membership over
//! those commitments, it MUST use the *same* generators. This module is the
//! single source of truth, shared by `crypto/lelantus_spark.rs` (the commitment)
//! and `crypto/groth_kohlweiss.rs` (the proof), so the two can never drift apart.
//!
//! Deterministic NUMS ("nothing up my sleeve") points with no known discrete-log
//! relation. Non-gated (pure generators — no cryptographic-protocol risk), so it
//! compiles and is tested in the default build.

use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
use curve25519_dalek::ristretto::RistrettoPoint;
use sha3::{Digest, Sha3_512};

fn nums(domain: &[u8]) -> RistrettoPoint {
    let mut hasher = Sha3_512::new();
    hasher.update(domain);
    let mut wide = [0u8; 64];
    wide.copy_from_slice(&hasher.finalize());
    RistrettoPoint::from_uniform_bytes(&wide)
}

/// Value generator `G` — the Ristretto basepoint.
pub fn gen_g() -> RistrettoPoint {
    RISTRETTO_BASEPOINT_POINT
}
/// Serial generator `H` — NUMS, independent of `G`.
pub fn gen_h() -> RistrettoPoint {
    nums(b"COINCYNC_SPARK_GEN_H_v1")
}
/// Blinding generator `K` — NUMS, independent of `G` and `H`.
pub fn gen_k() -> RistrettoPoint {
    nums(b"COINCYNC_SPARK_GEN_K_v1")
}

/// Value generator `Gv` for the shielded value commitment `V = v·Gv + b·Kv`.
/// NUMS, independent of the serial-commitment basis {G,H,K} and of `Kv`, so the
/// value-balance (excess) proof cannot express a nonzero value term as a
/// `Kv`-multiple.
pub fn gen_gv() -> RistrettoPoint {
    nums(b"COINCYNC_SPARK_GEN_GV_v1")
}
/// Value blinding generator `Kv` — NUMS, independent of `Gv`.
pub fn gen_kv() -> RistrettoPoint {
    nums(b"COINCYNC_SPARK_GEN_KV_v1")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generators_are_deterministic_distinct_and_nonidentity() {
        let gens = [gen_g(), gen_h(), gen_k(), gen_gv(), gen_kv()];
        // deterministic
        assert_eq!(gens, [gen_g(), gen_h(), gen_k(), gen_gv(), gen_kv()]);
        // pairwise distinct
        for i in 0..gens.len() {
            for j in (i + 1)..gens.len() {
                assert_ne!(gens[i], gens[j], "generators {i} and {j} must differ");
            }
        }
        // non-identity
        let id = RistrettoPoint::default();
        for g in gens {
            assert_ne!(g, id);
        }
    }
}
