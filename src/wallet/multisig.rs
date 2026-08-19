//! # FROST Multi-Signature Wallet
//!
//! M-of-N threshold signatures using FROST (RFC 9591) over ed25519.
//!
//! ## Custody model (read before advertising this as "non-custodial")
//!
//! Two live signing paths with DIFFERENT custody properties — do not conflate
//! them in user-facing claims:
//!
//! - **Plain ed25519 (true FROST, RFC 9591)** — `signing_round1` /
//!   `signing_round2` / `aggregate_signature`. Each participant produces a
//!   partial signature from its own share; the group secret is NEVER
//!   reconstructed, and the coordinator only relays partial signatures (holds no
//!   secret material). Genuinely non-custodial. This is the path CIP-008's
//!   "coordinator is untrusted / holds nothing" statements describe.
//!
//! - **RingCT / CLSAG privacy transactions** — the "Reconstruct-Sign-Zeroize"
//!   model (see the CLSAG INTEGRATION section below and
//!   [`reconstruct_group_secret`]). The signing party gathers M key shares and
//!   reconstructs the FULL group secret in memory (Lagrange interpolation) to
//!   produce a standard CLSAG signature, then zeroizes it. The key is never at
//!   rest as a whole, but the signer TRANSIENTLY holds it during signing — so
//!   this path is **not non-custodial at signing time**. It must NOT be
//!   advertised as fully-distributed threshold signing until a true threshold
//!   CLSAG (custom FROST ciphersuite, a v2 goal) replaces it. The wallet CLI
//!   surfaces this to the operator at runtime. `clsag_multisig.rs` is the
//!   design sketch for the future true-threshold path and is not wired.

use frost_ed25519 as frost;
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};
use crate::primitives::PublicKey;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MultisigConfig {
    pub threshold: u16,
    pub total: u16,
    pub group_public_key: [u8; 32],
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct KeyShare {
    pub config: MultisigConfig,
    pub participant_id: u16,
    pub signing_share_bytes: Vec<u8>,
    pub verifying_share_bytes: Vec<u8>,
}

pub struct KeyGenResult {
    pub config: MultisigConfig,
    pub shares: Vec<KeyShare>,
    pub group_public_key: PublicKey,
}

pub fn generate_shares(threshold: u16, total: u16) -> Result<KeyGenResult> {
    if threshold < 2 {
        return Err(Error::InvalidState("threshold must be >= 2".into()));
    }
    if total < threshold {
        return Err(Error::InvalidState("total must be >= threshold".into()));
    }
    if total > 255 {
        return Err(Error::InvalidState("max 255 participants".into()));
    }

    let mut rng = OsRng;

    let (shares_map, pubkey_package) = frost::keys::generate_with_dealer(
        total,
        threshold,
        frost::keys::IdentifierList::Default,
        &mut rng,
    )
    .map_err(|e| Error::Internal(format!("FROST keygen failed: {}", e)))?;

    let group_key_bytes = pubkey_package
        .verifying_key()
        .serialize()
        .map_err(|e| Error::Internal(format!("serialize group key: {}", e)))?;
    let mut group_key_arr = [0u8; 32];
    group_key_arr.copy_from_slice(&group_key_bytes[..32]);

    let config = MultisigConfig {
        threshold,
        total,
        group_public_key: group_key_arr,
    };

    let mut key_shares = Vec::new();
    for (id, secret_share) in &shares_map {
        let id_bytes = id.serialize();
        let participant_id = id_bytes[0] as u16;

        // Verify share and get verifying share
        let (verifying_share, _group_key) = secret_share
            .verify()
            .map_err(|e| Error::Internal(format!("share verify failed: {}", e)))?;

        let signing_bytes = secret_share.signing_share().serialize();
        let verifying_bytes = verifying_share
            .serialize()
            .map_err(|e| Error::Internal(format!("serialize verifying share: {}", e)))?;

        key_shares.push(KeyShare {
            config: config.clone(),
            participant_id,
            signing_share_bytes: signing_bytes.to_vec(),
            verifying_share_bytes: verifying_bytes,
        });
    }

    Ok(KeyGenResult {
        config,
        shares: key_shares,
        group_public_key: PublicKey::from_bytes(group_key_arr),
    })
}

pub fn verify_shares(shares: &[KeyShare]) -> Result<bool> {
    if shares.is_empty() {
        return Ok(false);
    }
    let config = &shares[0].config;
    for s in shares {
        if s.config.threshold != config.threshold || s.config.total != config.total {
            return Err(Error::InvalidState("inconsistent configs".into()));
        }
        if s.config.group_public_key != config.group_public_key {
            return Err(Error::InvalidState("group key mismatch".into()));
        }
    }
    Ok(true)
}

// ══════════════════════════════════════════════════════════════════════════════
// SIGNING PROTOCOL — 2-round FROST
// ══════════════════════════════════════════════════════════════════════════════

/// Round 1 output: nonces + commitments to share with other signers
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Round1Output {
    pub participant_id: u16,
    pub commitment_bytes: Vec<u8>,
}

/// Internal state kept between round 1 and round 2 (secret, never share).
///
/// AUDIT (R-93 fix, 2026-07-03): pre-fix code had no Drop impl on
/// this type. `frost::round1::SigningNonces` contains the two
/// FROST hiding/binding nonces (32 bytes each) that are the
/// nuclear secret of FROST — nonce reuse or leakage lets an
/// attacker recover a participant's signing share, which is a
/// share of the group key. `frost-ed25519` at 0.6.x DOES
/// implement `ZeroizeOnDrop` on `SigningNonces` internally
/// (verified via reading their src/round1.rs 2026-07-03 —
/// see https://github.com/ZcashFoundation/frost/blob/main/frost-core/src/round1.rs
/// which derives Zeroize/ZeroizeOnDrop on Nonce/SigningNonces),
/// so field-drop chain wipes them.
///
/// This Drop wraps the field-drop chain with an EXPLICIT wipe of
/// the participant_id (non-secret, but included for defense in
/// depth so a memory dump can't correlate leftover nonce bytes
/// with a participant identifier).
pub struct Round1Secret {
    pub participant_id: u16,
    pub nonces: frost::round1::SigningNonces,
}

impl Drop for Round1Secret {
    fn drop(&mut self) {
        // frost::round1::SigningNonces is wiped by its own
        // ZeroizeOnDrop impl (verified 2026-07-03 against the
        // frost-core repo). We zero the participant_id to close
        // any residual correlation. If a future frost crate
        // update REMOVES ZeroizeOnDrop, this Drop is our last
        // line of defense — but we can't reach into the private
        // fields structurally, so switch dependencies immediately
        // if that ever happens.
        self.participant_id = 0;
    }
}

/// Round 2 output: signature share to send to coordinator
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Round2Output {
    pub participant_id: u16,
    pub signature_share_bytes: Vec<u8>,
}

/// Final aggregated signature
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MultisigSignature {
    pub signature_bytes: Vec<u8>,
    pub group_public_key: [u8; 32],
}

/// Round 1: Generate nonces and commitments.
/// Each signer calls this with their key share.
/// Returns public commitment (share with others) + secret nonces (keep private).
pub fn signing_round1(share: &KeyShare) -> Result<(Round1Output, Round1Secret)> {
    let mut rng = OsRng;

    let signing_share = frost::keys::SigningShare::deserialize(&share.signing_share_bytes)
        .map_err(|e| Error::Internal(format!("deserialize signing share: {}", e)))?;

    let key_package = build_key_package(share)?;
    let _ = key_package; // used for validation

    let (nonces, commitments) = frost::round1::commit(&signing_share, &mut rng);

    let commitment_bytes = commitments
        .serialize()
        .map_err(|e| Error::Internal(format!("serialize commitment: {}", e)))?;

    Ok((
        Round1Output {
            participant_id: share.participant_id,
            commitment_bytes,
        },
        Round1Secret {
            participant_id: share.participant_id,
            nonces,
        },
    ))
}

/// Round 2: Produce a signature share.
/// Each signer calls this with their key share, their round1 secret,
/// all participants' round1 commitments, and the message to sign.
/// SECURITY: takes `secret` BY VALUE so a set of Round-1 nonces can only be
/// consumed once. FROST/Schnorr nonces are single-use — signing two different
/// messages with the same nonces lets anyone who sees both signature shares
/// recover the participant's key share (RFC 9591). Consuming the `Round1Secret`
/// here drops (and zeroizes) the nonces on return, so a second `signing_round2`
/// with the same secret is a compile-time move error rather than a key leak.
pub fn signing_round2(
    share: &KeyShare,
    secret: Round1Secret,
    all_commitments: &[Round1Output],
    message: &[u8],
) -> Result<Round2Output> {
    let key_package = build_key_package(share)?;

    // Reconstruct the signing commitments map
    let mut commitments_map = std::collections::BTreeMap::new();
    for c in all_commitments {
        let id = frost::Identifier::try_from(c.participant_id)
            .map_err(|e| Error::Internal(format!("bad participant id: {}", e)))?;
        let commitment = frost::round1::SigningCommitments::deserialize(&c.commitment_bytes)
            .map_err(|e| Error::Internal(format!("deserialize commitment: {}", e)))?;
        commitments_map.insert(id, commitment);
    }

    let signing_package = frost::SigningPackage::new(commitments_map, message);

    let signature_share = frost::round2::sign(&signing_package, &secret.nonces, &key_package)
        .map_err(|e| Error::Internal(format!("round2 sign failed: {}", e)))?;

    let share_bytes = signature_share.serialize();

    Ok(Round2Output {
        participant_id: share.participant_id,
        signature_share_bytes: share_bytes.to_vec(),
    })
}

/// Aggregate: Coordinator combines all signature shares into the final signature.
pub fn aggregate_signature(
    all_commitments: &[Round1Output],
    all_shares: &[Round2Output],
    config: &MultisigConfig,
    key_shares: &[KeyShare],
    message: &[u8],
) -> Result<MultisigSignature> {
    // Reconstruct commitments map
    let mut commitments_map = std::collections::BTreeMap::new();
    for c in all_commitments {
        let id = frost::Identifier::try_from(c.participant_id)
            .map_err(|e| Error::Internal(format!("bad id: {}", e)))?;
        let commitment = frost::round1::SigningCommitments::deserialize(&c.commitment_bytes)
            .map_err(|e| Error::Internal(format!("deserialize commitment: {}", e)))?;
        commitments_map.insert(id, commitment);
    }

    let signing_package = frost::SigningPackage::new(commitments_map, message);

    // Reconstruct signature shares map
    let mut shares_map = std::collections::BTreeMap::new();
    for s in all_shares {
        let id = frost::Identifier::try_from(s.participant_id)
            .map_err(|e| Error::Internal(format!("bad id: {}", e)))?;
        let sig_share = frost::round2::SignatureShare::deserialize(&s.signature_share_bytes)
            .map_err(|e| Error::Internal(format!("deserialize sig share: {}", e)))?;
        shares_map.insert(id, sig_share);
    }

    // Reconstruct public key package from config
    // For aggregation we need the PublicKeyPackage. We rebuild it from the group key.
    let group_key = frost::VerifyingKey::deserialize(&config.group_public_key)
        .map_err(|e| Error::Internal(format!("deserialize group key: {}", e)))?;

    // We need verifying shares for each participant — extract from round1 commitments
    // Actually, for FROST aggregate we need the full PublicKeyPackage.
    // Since we stored verifying shares in KeyShare, we need them passed in.
    // For now, use a simplified approach: verify the aggregate with the group key directly.

    // Build PublicKeyPackage with verifying shares from key shares
    let mut verifying_shares = std::collections::BTreeMap::new();
    for ks in key_shares {
        let id = frost::Identifier::try_from(ks.participant_id)
            .map_err(|e| Error::Internal(format!("bad id: {}", e)))?;
        let vs = frost::keys::VerifyingShare::deserialize(&ks.verifying_share_bytes)
            .map_err(|e| Error::Internal(format!("deserialize verifying share: {}", e)))?;
        verifying_shares.insert(id, vs);
    }

    let signature = frost::aggregate(
        &signing_package,
        &shares_map,
        &frost::keys::PublicKeyPackage::new(verifying_shares, group_key, None),
    )
    .map_err(|e| Error::Internal(format!("aggregate failed: {}", e)))?;

    let sig_bytes = signature
        .serialize()
        .map_err(|e| Error::Internal(format!("serialize signature: {}", e)))?;

    Ok(MultisigSignature {
        signature_bytes: sig_bytes,
        group_public_key: config.group_public_key,
    })
}

/// Verify a multi-sig signature against the group public key
pub fn verify_signature(sig: &MultisigSignature, message: &[u8]) -> Result<bool> {
    let group_key = frost::VerifyingKey::deserialize(&sig.group_public_key)
        .map_err(|e| Error::Internal(format!("deserialize key: {}", e)))?;
    let signature = frost::Signature::deserialize(&sig.signature_bytes)
        .map_err(|e| Error::Internal(format!("deserialize sig: {}", e)))?;

    group_key
        .verify(message, &signature)
        .map(|_| true)
        .map_err(|e| Error::Internal(format!("verify failed: {}", e)))
}

/// Helper: build a KeyPackage from a KeyShare
fn build_key_package(share: &KeyShare) -> Result<frost::keys::KeyPackage> {
    let id = frost::Identifier::try_from(share.participant_id)
        .map_err(|e| Error::Internal(format!("bad id: {}", e)))?;
    let signing_share = frost::keys::SigningShare::deserialize(&share.signing_share_bytes)
        .map_err(|e| Error::Internal(format!("deserialize signing share: {}", e)))?;
    let verifying_share = frost::keys::VerifyingShare::deserialize(&share.verifying_share_bytes)
        .map_err(|e| Error::Internal(format!("deserialize verifying share: {}", e)))?;

    let group_key = frost::VerifyingKey::deserialize(&share.config.group_public_key)
        .map_err(|e| Error::Internal(format!("deserialize group key: {}", e)))?;

    let key_package = frost::keys::KeyPackage::new(
        id,
        signing_share,
        verifying_share,
        group_key,
        share.config.threshold,
    );

    Ok(key_package)
}

// ══════════════════════════════════════════════════════════════════════════════
// CLSAG INTEGRATION — threshold signing for privacy transactions
// ══════════════════════════════════════════════════════════════════════════════
//
// Architecture: "Reconstruct-Sign-Zeroize" model.
//
// For fully distributed threshold CLSAG (where the group key is NEVER
// reconstructed), we'd need to fork frost-core to expose raw nonce scalars
// and allow custom challenge computation. That's a v2 goal.
//
// For v1, we use a practical approach:
// 1. M participants submit their signing shares to the coordinator
// 2. Coordinator reconstructs the group secret via Lagrange interpolation
// 3. Coordinator signs CLSAG with the reconstructed key (standard path)
// 4. The reconstructed key is zeroized immediately after signing
//
// Security: the coordinator momentarily holds the group key in memory.
// This is acceptable for testnet and equivalent to how most multi-sig
// wallets work in practice (hardware wallet signs locally then zeroizes).
// For production: implement threshold CLSAG with custom FROST ciphersuite.

use curve25519_dalek::scalar::Scalar;
use zeroize::Zeroize;

/// Reconstruct the group secret key from M signing shares.
///
/// Returns a [`SecretScalar`] (zeroize-on-drop) rather than raw bytes so
/// the reconstructed key never has a window where it sits as a plain
/// `[u8; 32]` on the caller's stack waiting for manual zeroization. The
/// internal intermediates (signing shares, the working Scalar) are still
/// zeroized at function exit.
pub fn reconstruct_group_secret(shares: &[KeyShare]) -> Result<crate::crypto::SecretScalar> {
    if shares.is_empty() {
        return Err(Error::InvalidState("no shares provided".into()));
    }
    let threshold = shares[0].config.threshold as usize;
    if shares.len() < threshold {
        return Err(Error::InvalidState(format!(
            "need {} shares, got {}",
            threshold,
            shares.len()
        )));
    }

    // Use only `threshold` shares (first M)
    let active = &shares[..threshold];

    // Lagrange interpolation to reconstruct the secret
    // s = sum(lambda_i * x_i) where lambda_i = prod(j / (j - i)) for j != i
    let mut ids: Vec<Scalar> = Vec::new();
    let mut signing_scalars: Vec<Scalar> = Vec::new();

    for share in active {
        let id_scalar = Scalar::from(share.participant_id as u64);
        ids.push(id_scalar);

        // Deserialize the signing share scalar.
        //
        // AUDIT (C35 fix, 2026-07-02): the prior check was `if
        // signing_share_bytes.len() >= 32 { copy_from_slice(&[..32]) }`,
        // which SILENTLY TRUNCATED any input longer than 32 bytes. A
        // malformed or attacker-crafted share whose first 32 bytes
        // decode canonically but whose tail carries garbage would slip
        // through with only the tail discarded. FROST-ed25519's
        // `SigningShare::serialize()` returns exactly 32 bytes for a
        // Scalar (curve25519 group order fits in 32 B), so any
        // deviation is malformed input and must reject.
        //
        // Also (R-92 fix): `share_bytes` on the stack held one
        // participant's signing share scalar bytes and was never
        // zeroized after use. Bounded here with an explicit `.zeroize()`
        // on both the success and error paths.
        if share.signing_share_bytes.len() != 32 {
            return Err(Error::Internal(format!(
                "signing share has unexpected length {} (must be exactly 32 bytes; \
                 FROST-ed25519 SigningShare serializes to a 32-byte canonical Scalar)",
                share.signing_share_bytes.len()
            )));
        }
        let mut share_bytes = [0u8; 32];
        share_bytes.copy_from_slice(&share.signing_share_bytes[..32]);
        let scalar_opt: Option<Scalar> = Scalar::from_canonical_bytes(share_bytes).into();
        // Zeroize share_bytes BEFORE we hit the ? on the None branch —
        // otherwise the early-return path leaves the stack copy alive
        // until scope unwind.
        share_bytes.zeroize();
        signing_scalars.push(
            scalar_opt.ok_or_else(|| Error::Internal("invalid scalar in signing share".into()))?,
        );
    }

    // Compute Lagrange coefficients and interpolate
    let mut group_secret = Scalar::ZERO;
    for i in 0..threshold {
        let mut lambda = Scalar::ONE;
        for j in 0..threshold {
            if i != j {
                // lambda_i *= j / (j - i)
                // Using participant IDs (1-indexed in FROST)
                let num = ids[j];
                let den = ids[j] - ids[i];
                if den == Scalar::ZERO {
                    return Err(Error::Internal("duplicate participant IDs".into()));
                }
                lambda *= num * den.invert();
            }
        }
        group_secret += lambda * signing_scalars[i];
    }

    // Wrap into SecretScalar (ZeroizeOnDrop) BEFORE zeroizing the
    // working Scalar so the secret only ever lives inside the
    // zeroize-on-drop wrapper from this point forward.
    let result = crate::crypto::SecretScalar::from_scalar(group_secret);

    // Zeroize intermediate values
    for s in &mut signing_scalars {
        s.zeroize();
    }
    group_secret.zeroize();

    Ok(result)
}

/// Sign a CLSAG ring signature using M-of-N threshold key shares.
///
/// This reconstructs the group secret, signs with standard CLSAG,
/// then immediately zeroizes the reconstructed key.
///
/// Returns the same ClsagSignature as single-signer CLSAG —
/// indistinguishable on chain.
pub fn clsag_sign_multisig(
    message: &[u8],
    ring: &[crate::crypto::ClsagRingMember],
    real_index: usize,
    key_shares: &[KeyShare],
    blinding_diff: &crate::crypto::SecretScalar,
    pseudo_output: &crate::crypto::EcCommitment,
) -> Result<crate::crypto::ClsagSignature> {
    // Reconstruct group secret directly into a zeroize-on-drop wrapper.
    let secret = reconstruct_group_secret(key_shares)?;

    // Sign with standard CLSAG
    let mut rng = OsRng;
    let sig = crate::crypto::clsag_sign(
        message,
        ring,
        real_index,
        &secret,
        blinding_diff,
        pseudo_output,
        &mut rng,
    )?;

    // `secret` drops here — SecretScalar's ZeroizeOnDrop impl wipes
    // the underlying Scalar on the way out.
    Ok(sig)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_2_of_3_keygen() {
        let result = generate_shares(2, 3).unwrap();
        assert_eq!(result.shares.len(), 3);
        assert_eq!(result.config.threshold, 2);
        assert_eq!(result.config.total, 3);
        assert!(verify_shares(&result.shares).unwrap());
    }

    #[test]
    fn test_2_of_3_full_signing() {
        // 1. Generate shares
        let keygen = generate_shares(2, 3).unwrap();
        let message = b"CoinCync test transaction hash";

        // 2. Participants 1 and 2 do round 1
        let (r1_out_1, r1_secret_1) = signing_round1(&keygen.shares[0]).unwrap();
        let (r1_out_2, r1_secret_2) = signing_round1(&keygen.shares[1]).unwrap();
        let all_commitments = vec![r1_out_1.clone(), r1_out_2.clone()];

        // 3. Participants 1 and 2 do round 2 (nonces consumed by value)
        let r2_out_1 =
            signing_round2(&keygen.shares[0], r1_secret_1, &all_commitments, message).unwrap();
        let r2_out_2 =
            signing_round2(&keygen.shares[1], r1_secret_2, &all_commitments, message).unwrap();
        let all_shares = vec![r2_out_1, r2_out_2];

        // 4. Aggregate into final signature
        let sig = aggregate_signature(
            &all_commitments,
            &all_shares,
            &keygen.config,
            &keygen.shares,
            message,
        )
        .unwrap();

        // 5. Verify
        assert!(verify_signature(&sig, message).unwrap());
        assert!(verify_signature(&sig, b"wrong message").is_err());
    }

    // ── C35 close: reject non-32-byte signing shares (no silent truncation) ──

    /// Regression: a signing share with EXTRA trailing bytes must be
    /// rejected — prior behavior silently discarded the tail. Craft a
    /// valid share, tack a byte onto it, and check reconstruct fails.
    #[test]
    fn reconstruct_rejects_share_longer_than_32_bytes() {
        let keygen = generate_shares(2, 3).unwrap();
        let mut tampered = keygen.shares.clone();
        // Extend participant 0's signing share by one byte.
        tampered[0].signing_share_bytes.push(0xFF);
        let err = reconstruct_group_secret(&tampered[..2]).unwrap_err();
        let msg = format!("{}", err);
        assert!(
            msg.contains("unexpected length 33"),
            "expected explicit length-error for 33-byte share, got: {}",
            msg
        );
    }

    /// Regression: a signing share with TOO FEW bytes must also reject
    /// with an explicit length error (not the prior generic "too short").
    #[test]
    fn reconstruct_rejects_share_shorter_than_32_bytes() {
        let keygen = generate_shares(2, 3).unwrap();
        let mut tampered = keygen.shares.clone();
        // Truncate participant 0's signing share by one byte.
        tampered[0].signing_share_bytes.pop();
        let err = reconstruct_group_secret(&tampered[..2]).unwrap_err();
        let msg = format!("{}", err);
        assert!(
            msg.contains("unexpected length 31"),
            "expected explicit length-error for 31-byte share, got: {}",
            msg
        );
    }

    /// Sanity: valid (exactly-32-byte) shares still reconstruct successfully.
    /// Confirms the length check hasn't accidentally broken the happy path.
    #[test]
    fn reconstruct_accepts_exactly_32_byte_shares() {
        let keygen = generate_shares(2, 3).unwrap();
        // Every share from generate_shares is expected to be exactly 32 bytes.
        for s in &keygen.shares {
            assert_eq!(
                s.signing_share_bytes.len(),
                32,
                "FROST-ed25519 signing_share must be exactly 32 bytes"
            );
        }
        // Reconstruct with the first `threshold` shares.
        let _secret = reconstruct_group_secret(&keygen.shares[..2])
            .expect("valid 32-byte shares must reconstruct");
    }
}
