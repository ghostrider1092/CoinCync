//! # Underground — Privacy Manifold (uniform-face transaction envelope)
//!
//! ## Status
//!
//! Gated behind the `sketch-privacy-manifold` cargo feature, OFF by default.
//! Default builds do NOT compile this module; it is not part of the production
//! audit perimeter. See `docs/design/privacy-manifold-uniform-face.md`.
//!
//! ## What this is
//!
//! The "one face for many schemes" layer. On an oil rig, many wells feed one
//! manifold and, once commingled into the export pipeline, you cannot tell which
//! well a barrel came from. This module is that manifold for CoinCync's privacy
//! schemes: whatever scheme actually produced a spend (CLSAG, Spark, shielded),
//! the transaction that leaves is **byte-indistinguishable** from every other, so
//! an outside observer cannot sort users by scheme — which is how privacy
//! features stop eating each other's anonymity set.
//!
//! ## Scope of THIS module (honest)
//!
//! This is the **format / engineering MVP** — the four invariants that need no
//! new cryptography:
//!
//! - **#1 One envelope.** There is no per-scheme transaction type; a spend is one
//!   opaque, fixed-layout envelope. The scheme is never written on the wire.
//! - **#2 Fixed size.** Every proof is padded to `MANIFOLD_PROOF_LEN`, so proof
//!   length never distinguishes schemes ("standard fittings").
//! - **#4 One nullifier format.** Every spend exposes a uniform 32-byte nullifier
//!   ("check valve" — no double-spend backflow), whatever the scheme's native tag.
//! - **#5 Uniform fee schedule.** One size means one fee schedule; the fee cannot
//!   leak the scheme.
//!
//! Invariant **#3 (one shared anonymity set — the manifold proper)** is new
//! cryptography and is **NOT implemented here**: it must be prototyped and
//! externally audited before it is live. This module only makes the schemes look
//! identical; it does not yet make them share one hiding set.
//!
//! ## The selector, and why there isn't one
//!
//! The single most dangerous mistake would be a plaintext "scheme = 2" byte — it
//! would be the exact fingerprint this design removes. So the wire carries **no
//! scheme tag at all.** Verification uses [`ManifoldEnvelope::verify_dispatch`],
//! which trials each registered scheme's verifier over that scheme's proof prefix
//! and accepts iff exactly one accepts. The scheme is recovered by *doing the
//! verification*, never by reading a field — so there is nothing to leak. The
//! cost is running each candidate verifier; a committed-selector optimisation is
//! future work (and must not reintroduce a public discriminator).

use rand::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};

/// Fixed on-wire length of the opaque proof field, in bytes. Every scheme's
/// spend proof is padded to this ceiling so proof *length* never distinguishes
/// schemes. Must exceed the largest supported scheme proof. (A real deployment
/// sizes this to the largest intended proof; the O(n) Spark proof is exactly why
/// a log-sized proof matters before this ceiling is comfortable.)
pub const MANIFOLD_PROOF_LEN: usize = 3072;

/// Total fixed length of a serialized envelope: proof ‖ nullifier(32) ‖ fee(8).
/// Constant for EVERY envelope, so serialized length is never a distinguisher.
pub const MANIFOLD_ENVELOPE_LEN: usize = MANIFOLD_PROOF_LEN + 32 + 8;

/// Uniform minimum fee for the fixed transaction size. Scheme-independent by
/// construction (there is only one size, hence one schedule), so the fee cannot
/// leak the scheme. Callers may pay more for priority; they may not pay a
/// scheme-specific *rate*, because there is only one rate.
pub const MANIFOLD_MIN_FEE: u64 = 1_000;

/// Uniform nullifier: 32 bytes, identical format for every scheme. Each scheme's
/// native double-spend tag (CLSAG key image, Spark serial tag, shielded
/// nullifier) is mapped into this single space by the sealing scheme; on the wire
/// it is just 32 bytes.
pub type Nullifier = [u8; 32];

/// Internal scheme identifier. Used ONLY by the verifier's dispatch; it is NEVER
/// serialized on the wire (see the module docs — a plaintext scheme tag is the
/// exact fingerprint this design removes).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SchemeId {
    Clsag,
    Spark,
    Shielded,
}

impl SchemeId {
    /// Public, fixed proof length for this scheme, in bytes. A real deployment
    /// pins these to each proof system's own fixed size; here they model
    /// distinctly-sized schemes precisely so the length-hiding property can be
    /// tested. Every value MUST be `<= MANIFOLD_PROOF_LEN`.
    pub fn proof_len(self) -> usize {
        match self {
            SchemeId::Clsag => 1024,
            SchemeId::Spark => 2800,
            SchemeId::Shielded => 1536,
        }
    }

    /// Every scheme registered in the manifold. Dispatch trials these in order.
    pub fn all() -> [SchemeId; 3] {
        [SchemeId::Clsag, SchemeId::Spark, SchemeId::Shielded]
    }
}

/// The uniform transaction face. Byte-identical layout regardless of the scheme
/// that produced it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ManifoldEnvelope {
    /// Opaque proof field, ALWAYS `MANIFOLD_PROOF_LEN` bytes: the scheme's real
    /// proof in the low bytes, cryptographically-random padding up to the
    /// ceiling. Real proofs (Ristretto points/scalars) are indistinguishable
    /// from random and the pad is random, so the whole field is uniform — the
    /// proof/pad boundary is invisible, which is why proof length does not leak.
    pub proof: Vec<u8>,
    /// Uniform 32-byte nullifier (double-spend tag), same format for all schemes.
    pub nullifier: Nullifier,
    /// Fee (`>= MANIFOLD_MIN_FEE`). Scheme-independent schedule.
    pub fee: u64,
}

/// The complete set of fields a passive network observer can see. If two
/// envelopes produced by different schemes have equal `ObservableShape`, then no
/// observer using wire features can tell them apart. Note: it contains no scheme
/// information, and `proof_len`/`nullifier_len`/`serialized_len` are constants —
/// that is the point.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ObservableShape {
    pub serialized_len: usize,
    pub proof_len: usize,
    pub nullifier_len: usize,
    pub fee: u64,
}

impl ManifoldEnvelope {
    /// Seal a scheme's spend proof into the uniform envelope: place the real
    /// proof in the low bytes and fill to `MANIFOLD_PROOF_LEN` with fresh random
    /// padding. Fails if the proof is not the scheme's fixed length, exceeds the
    /// ceiling, or the fee is below the uniform minimum.
    pub fn seal<R: CryptoRng + RngCore>(
        scheme: SchemeId,
        proof: &[u8],
        nullifier: Nullifier,
        fee: u64,
        rng: &mut R,
    ) -> Result<Self> {
        if proof.len() != scheme.proof_len() {
            return Err(Error::CryptoError(format!(
                "manifold: proof length {} != scheme fixed length {}",
                proof.len(),
                scheme.proof_len()
            )));
        }
        if proof.len() > MANIFOLD_PROOF_LEN {
            return Err(Error::CryptoError(
                "manifold: proof exceeds fixed ceiling".into(),
            ));
        }
        if fee < MANIFOLD_MIN_FEE {
            return Err(Error::CryptoError(
                "manifold: fee below uniform minimum".into(),
            ));
        }
        let mut buf = vec![0u8; MANIFOLD_PROOF_LEN];
        buf[..proof.len()].copy_from_slice(proof);
        // Random pad, indistinguishable from the real proof bytes, so the
        // proof/pad boundary — and therefore the true proof length — is hidden.
        rng.fill_bytes(&mut buf[proof.len()..]);
        Ok(Self {
            proof: buf,
            nullifier,
            fee,
        })
    }

    /// Seal an already-serialized, VARIABLE-length scheme proof into the uniform
    /// envelope. Unlike [`seal`], the proof may be any length up to the ceiling —
    /// the real proof systems (a Spark spend proof, a CLSAG signature) produce
    /// variable-size proofs, and this is the path a real spend uses. Recover it by
    /// deserializing your scheme's proof from [`proof`](Self::proof) with a reader
    /// (e.g. `borsh`'s `deserialize_reader`), which consumes exactly the proof and
    /// ignores the random pad.
    ///
    /// NOTE (size uniformity): full indistinguishability for variable-length
    /// schemes still requires each scheme to pad its own proof to a fixed
    /// per-scheme size *before* sealing — see `docs/design/privacy-manifold-uniform-face.md`.
    /// This method carries real proofs end-to-end at the uniform envelope size; it
    /// does not by itself make two different-length proofs mutually indistinguishable.
    pub fn seal_serialized<R: CryptoRng + RngCore>(
        proof: &[u8],
        nullifier: Nullifier,
        fee: u64,
        rng: &mut R,
    ) -> Result<Self> {
        if proof.len() > MANIFOLD_PROOF_LEN {
            return Err(Error::CryptoError(format!(
                "manifold: serialized proof {} exceeds ceiling {}",
                proof.len(),
                MANIFOLD_PROOF_LEN
            )));
        }
        if fee < MANIFOLD_MIN_FEE {
            return Err(Error::CryptoError(
                "manifold: fee below uniform minimum".into(),
            ));
        }
        let mut buf = vec![0u8; MANIFOLD_PROOF_LEN];
        buf[..proof.len()].copy_from_slice(proof);
        rng.fill_bytes(&mut buf[proof.len()..]);
        Ok(Self {
            proof: buf,
            nullifier,
            fee,
        })
    }

    /// Recover the scheme's proof bytes (the verifier side, which knows the
    /// candidate scheme). Strips the random padding using the scheme's public
    /// fixed length.
    pub fn recover_proof(&self, scheme: SchemeId) -> &[u8] {
        &self.proof[..scheme.proof_len()]
    }

    /// The observer-visible shape. Constant across schemes for a given fee.
    pub fn observable_shape(&self) -> ObservableShape {
        ObservableShape {
            serialized_len: MANIFOLD_ENVELOPE_LEN,
            proof_len: self.proof.len(),
            nullifier_len: self.nullifier.len(),
            fee: self.fee,
        }
    }

    /// Deterministic fixed-length wire encoding: proof ‖ nullifier ‖ fee(LE).
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(MANIFOLD_ENVELOPE_LEN);
        out.extend_from_slice(&self.proof);
        out.extend_from_slice(&self.nullifier);
        out.extend_from_slice(&self.fee.to_le_bytes());
        out
    }

    /// Decode a wire envelope. Rejects anything that is not exactly
    /// `MANIFOLD_ENVELOPE_LEN` bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != MANIFOLD_ENVELOPE_LEN {
            return Err(Error::CryptoError(format!(
                "manifold: envelope must be {} bytes, got {}",
                MANIFOLD_ENVELOPE_LEN,
                bytes.len()
            )));
        }
        let proof = bytes[..MANIFOLD_PROOF_LEN].to_vec();
        let mut nullifier = [0u8; 32];
        nullifier.copy_from_slice(&bytes[MANIFOLD_PROOF_LEN..MANIFOLD_PROOF_LEN + 32]);
        let mut fee_bytes = [0u8; 8];
        fee_bytes.copy_from_slice(&bytes[MANIFOLD_PROOF_LEN + 32..]);
        Ok(Self {
            proof,
            nullifier,
            fee: u64::from_le_bytes(fee_bytes),
        })
    }

    /// Leak-free scheme dispatch: there is NO scheme tag on the wire, so the
    /// verifier trials each registered scheme's verifier over that scheme's proof
    /// prefix and returns the one that accepts. Accepts iff exactly one verifier
    /// accepts (an ambiguous envelope is rejected as `None`). The scheme is
    /// recovered by *doing* the verification, never by reading a field — so
    /// nothing about the scheme leaks. The cost is running each candidate.
    pub fn verify_dispatch(
        &self,
        verifiers: &[(SchemeId, &dyn Fn(&[u8]) -> bool)],
    ) -> Option<SchemeId> {
        let mut found = None;
        for (scheme, verify) in verifiers {
            if verify(self.recover_proof(*scheme)) {
                if found.is_some() {
                    return None; // ambiguous — two schemes accepted; fail closed
                }
                found = Some(*scheme);
            }
        }
        found
    }
}

// ═══════════════════════════════════════════════════════════════════════
// Tests — the property that matters is: an observer cannot classify by scheme.
// ═══════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::OsRng;
    use std::collections::HashSet;

    fn random_proof(rng: &mut OsRng, len: usize) -> Vec<u8> {
        let mut v = vec![0u8; len];
        rng.fill_bytes(&mut v);
        v
    }

    fn random_nullifier(rng: &mut OsRng) -> Nullifier {
        let mut n = [0u8; 32];
        rng.fill_bytes(&mut n);
        n
    }

    // ── #2 fixed size / length hiding ──────────────────────────────────

    #[test]
    fn every_envelope_serializes_to_one_constant_length() {
        let mut rng = OsRng;
        for &s in &SchemeId::all() {
            let env = ManifoldEnvelope::seal(
                s,
                &random_proof(&mut rng, s.proof_len()),
                random_nullifier(&mut rng),
                MANIFOLD_MIN_FEE,
                &mut rng,
            )
            .unwrap();
            assert_eq!(env.proof.len(), MANIFOLD_PROOF_LEN);
            assert_eq!(env.to_bytes().len(), MANIFOLD_ENVELOPE_LEN);
        }
    }

    #[test]
    fn wildly_different_proof_sizes_hide_to_the_same_length() {
        // CLSAG proof is 1024 bytes, Spark 2800 — a 2.7x difference that would be
        // trivially classifiable without the manifold. After sealing, identical.
        let mut rng = OsRng;
        let clsag = ManifoldEnvelope::seal(
            SchemeId::Clsag,
            &random_proof(&mut rng, SchemeId::Clsag.proof_len()),
            random_nullifier(&mut rng),
            MANIFOLD_MIN_FEE,
            &mut rng,
        )
        .unwrap();
        let spark = ManifoldEnvelope::seal(
            SchemeId::Spark,
            &random_proof(&mut rng, SchemeId::Spark.proof_len()),
            random_nullifier(&mut rng),
            MANIFOLD_MIN_FEE,
            &mut rng,
        )
        .unwrap();
        assert_eq!(clsag.to_bytes().len(), spark.to_bytes().len());
        assert_eq!(clsag.proof.len(), spark.proof.len());
    }

    // ── The headline property: an observer cannot classify by scheme ───

    #[test]
    fn observer_cannot_classify_by_wire_shape() {
        let mut rng = OsRng;
        let fee = MANIFOLD_MIN_FEE;
        let mut shapes = HashSet::new();
        let mut serialized_lens = HashSet::new();

        // A mixed batch: every scheme, different real proofs, same fee schedule.
        for &s in &SchemeId::all() {
            for _ in 0..8 {
                let env = ManifoldEnvelope::seal(
                    s,
                    &random_proof(&mut rng, s.proof_len()),
                    random_nullifier(&mut rng),
                    fee,
                    &mut rng,
                )
                .unwrap();
                shapes.insert(env.observable_shape());
                serialized_lens.insert(env.to_bytes().len());
            }
        }

        // A single observable shape / single serialized length across ALL
        // schemes means an observer partitioning by wire features gets exactly
        // one bucket — it cannot separate the schemes at all.
        assert_eq!(
            serialized_lens.len(),
            1,
            "serialized length must be scheme-independent"
        );
        assert_eq!(
            shapes.len(),
            1,
            "observable wire shape must be identical across all schemes"
        );
    }

    // ── #2 the pad is not itself a fingerprint ─────────────────────────

    #[test]
    fn padding_is_random_between_seals() {
        let mut rng = OsRng;
        let proof = random_proof(&mut rng, SchemeId::Clsag.proof_len());
        let nf = random_nullifier(&mut rng);
        let a =
            ManifoldEnvelope::seal(SchemeId::Clsag, &proof, nf, MANIFOLD_MIN_FEE, &mut rng).unwrap();
        let b =
            ManifoldEnvelope::seal(SchemeId::Clsag, &proof, nf, MANIFOLD_MIN_FEE, &mut rng).unwrap();
        // Same logical proof recovers identically...
        assert_eq!(a.recover_proof(SchemeId::Clsag), b.recover_proof(SchemeId::Clsag));
        // ...but the full field differs, so the padded blob is not a reproducible
        // fingerprint an observer could match against.
        assert_ne!(a.proof, b.proof);
    }

    // ── round-trips ────────────────────────────────────────────────────

    #[test]
    fn recover_proof_round_trips_per_scheme() {
        let mut rng = OsRng;
        for &s in &SchemeId::all() {
            let proof = random_proof(&mut rng, s.proof_len());
            let env = ManifoldEnvelope::seal(
                s,
                &proof,
                random_nullifier(&mut rng),
                MANIFOLD_MIN_FEE,
                &mut rng,
            )
            .unwrap();
            assert_eq!(env.recover_proof(s), &proof[..], "scheme {:?}", s);
        }
    }

    #[test]
    fn wire_round_trips() {
        let mut rng = OsRng;
        let env = ManifoldEnvelope::seal(
            SchemeId::Spark,
            &random_proof(&mut rng, SchemeId::Spark.proof_len()),
            random_nullifier(&mut rng),
            MANIFOLD_MIN_FEE + 25,
            &mut rng,
        )
        .unwrap();
        let decoded = ManifoldEnvelope::from_bytes(&env.to_bytes()).unwrap();
        assert_eq!(decoded, env);
        // Wrong length is rejected.
        assert!(ManifoldEnvelope::from_bytes(&[0u8; 10]).is_err());
    }

    // ── #1 leak-free dispatch: no scheme tag anywhere on the wire ──────

    #[test]
    fn verify_dispatch_finds_scheme_without_any_wire_tag() {
        let mut rng = OsRng;
        // Tag the real proof so exactly one mock verifier accepts it.
        let mut proof = random_proof(&mut rng, SchemeId::Spark.proof_len());
        proof[0] = 0xAB;
        let env = ManifoldEnvelope::seal(
            SchemeId::Spark,
            &proof,
            random_nullifier(&mut rng),
            MANIFOLD_MIN_FEE,
            &mut rng,
        )
        .unwrap();

        let spark_v =
            |p: &[u8]| p.len() == SchemeId::Spark.proof_len() && p.first() == Some(&0xAB);
        let clsag_v =
            |p: &[u8]| p.len() == SchemeId::Clsag.proof_len() && p.first() == Some(&0xCD);
        let verifiers: [(SchemeId, &dyn Fn(&[u8]) -> bool); 2] =
            [(SchemeId::Spark, &spark_v), (SchemeId::Clsag, &clsag_v)];

        // Dispatch recovers the scheme by verification alone — nothing in the
        // serialized bytes names "spark".
        assert_eq!(env.verify_dispatch(&verifiers), Some(SchemeId::Spark));
        let wire = env.to_bytes();
        assert_eq!(wire.len(), MANIFOLD_ENVELOPE_LEN); // and it's the uniform length
    }

    #[test]
    fn ambiguous_envelope_is_rejected() {
        let mut rng = OsRng;
        let env = ManifoldEnvelope::seal(
            SchemeId::Clsag,
            &random_proof(&mut rng, SchemeId::Clsag.proof_len()),
            random_nullifier(&mut rng),
            MANIFOLD_MIN_FEE,
            &mut rng,
        )
        .unwrap();
        // Two verifiers that BOTH accept anything → ambiguous → None (fail closed).
        let yes_a = |_p: &[u8]| true;
        let yes_b = |_p: &[u8]| true;
        let verifiers: [(SchemeId, &dyn Fn(&[u8]) -> bool); 2] =
            [(SchemeId::Clsag, &yes_a), (SchemeId::Spark, &yes_b)];
        assert_eq!(env.verify_dispatch(&verifiers), None);
    }

    // ── input validation ───────────────────────────────────────────────

    #[test]
    fn rejects_wrong_length_and_low_fee() {
        let mut rng = OsRng;
        let nf = random_nullifier(&mut rng);
        // Wrong proof length for the scheme.
        assert!(ManifoldEnvelope::seal(
            SchemeId::Clsag,
            &vec![0u8; 999],
            nf,
            MANIFOLD_MIN_FEE,
            &mut rng
        )
        .is_err());
        // Fee below the uniform minimum.
        let ok_proof = vec![0u8; SchemeId::Clsag.proof_len()];
        assert!(ManifoldEnvelope::seal(
            SchemeId::Clsag,
            &ok_proof,
            nf,
            MANIFOLD_MIN_FEE - 1,
            &mut rng
        )
        .is_err());
    }

    #[test]
    fn all_scheme_proof_lengths_fit_the_ceiling() {
        for &s in &SchemeId::all() {
            assert!(
                s.proof_len() <= MANIFOLD_PROOF_LEN,
                "scheme {:?} proof {} exceeds ceiling {}",
                s,
                s.proof_len(),
                MANIFOLD_PROOF_LEN
            );
        }
    }

    // ── REAL integration: an actual Spark spend proof through the manifold ──
    //
    // This is the step past the format MVP: a genuine `SparkSpendProof` (the
    // completed one-out-of-many spend proof) is serialized, sealed into the
    // uniform envelope, recovered by deserializing from the padded blob, and
    // verified by the REAL `verify_spark_spend` — proving real crypto flows
    // through the uniform face, not a mock verifier. Gated on the Spark feature.
    #[cfg(feature = "sketch-lelantus-spark")]
    #[test]
    fn real_spark_proof_flows_through_manifold_and_verifies() {
        use crate::crypto::lelantus_spark::{
            prove_spark_spend, spark_commit, verify_spark_spend, SparkNote, SparkSpendProof,
        };
        use borsh::BorshDeserialize;
        use curve25519_dalek::{ristretto::RistrettoPoint, scalar::Scalar};
        use rand::RngCore;

        let mut rng = OsRng;
        let rnd = |r: &mut OsRng| {
            let mut b = [0u8; 64];
            r.fill_bytes(&mut b);
            Scalar::from_bytes_mod_order_wide(&b)
        };

        // A real anonymity set of INDEPENDENT Spark coins (distinct values).
        let n = 8usize;
        let real_index = 3usize;
        let real_serial = rnd(&mut rng);
        let real_randomness = rnd(&mut rng);
        let real_value = 1000u64;
        let anon: Vec<RistrettoPoint> = (0..n)
            .map(|i| {
                if i == real_index {
                    spark_commit(real_value, &real_serial, &real_randomness)
                } else {
                    spark_commit(100 + i as u64, &rnd(&mut rng), &rnd(&mut rng))
                }
            })
            .collect();
        let note = SparkNote {
            commitment: anon[real_index].compress().to_bytes(),
            value: real_value,
            serial: real_serial.to_bytes(),
            randomness: real_randomness.to_bytes(),
            diversifier: [0u8; 11],
            height: 1,
            coin_id: real_index as u64,
        };
        let indices: Vec<u64> = (0..n as u64).collect();
        let message = [9u8; 32];
        let proof = prove_spark_spend(&note, &anon, &indices, real_index, &message, &mut rng)
            .expect("prove real spark spend");
        verify_spark_spend(&proof, &anon).expect("sanity: proof verifies directly");

        // Seal the REAL serialized proof into the uniform manifold envelope. The
        // Spark serial tag IS the uniform 32-byte nullifier (invariant #4).
        let proof_bytes = borsh::to_vec(&proof).expect("serialize spark proof");
        let env = ManifoldEnvelope::seal_serialized(
            &proof_bytes,
            proof.serial_tag,
            MANIFOLD_MIN_FEE,
            &mut rng,
        )
        .expect("seal real proof");
        assert_eq!(
            env.to_bytes().len(),
            MANIFOLD_ENVELOPE_LEN,
            "on the wire the real-proof envelope is the uniform size"
        );

        // Recover by deserializing the proof from the padded blob (the reader
        // consumes exactly the proof and ignores the random pad), then verify with
        // the REAL verifier against the public commitments.
        let mut slice = &env.proof[..];
        let recovered =
            SparkSpendProof::deserialize_reader(&mut slice).expect("deserialize real proof");
        assert_eq!(recovered.serial_tag, env.nullifier, "nullifier round-trips");
        verify_spark_spend(&recovered, &anon).expect(
            "a REAL Spark proof carried inside the uniform manifold envelope must \
             verify end-to-end against the public commitments",
        );
    }
}
