//! Transaction input signer abstraction — the seam between the transaction
//! builder and whatever holds spend authority (hardware-wallet support, slice 1).
//!
//! Today the builder calls `clsag_sign` / `KeyImage::from_secret` directly on the
//! per-input one-time secret. This module introduces a [`TxSigner`] trait and a
//! [`SoftwareSigner`] that reproduces exactly that behavior, so
//! `TransactionBuilder::build` can route through the trait without any change in
//! output (the CLSAG golden KAT still holds).
//!
//! A future `HardwareSigner` (Ledger/Trezor) will implement the same trait,
//! deriving the one-time secret and producing the CLSAG signature ON-DEVICE so
//! the spend key never reaches the host. Such a signer leaves
//! [`OneTimeKeyRef::secret`] `None` and re-derives from device-held keys plus the
//! output coordinates (added in a later slice); the software signer is the only
//! implementation that carries the raw secret.

use rand::{CryptoRng, RngCore};

use crate::crypto::{
    clsag_sign, ClsagRingMember, ClsagSignature, EcCommitment, KeyImage as CryptoKeyImage,
    SecretScalar,
};
use crate::error::{Error, Result};
use crate::primitives::{KeyImage, SecretKey};

/// Identifies the one-time key to act with for a single input, without forcing
/// the raw secret across the boundary.
///
/// The software signer populates `secret`; a hardware signer leaves it `None`
/// and re-derives the one-time secret on-device. (Derivation coordinates —
/// `tx_public_key`, `output_index`, subaddress index — are added in the slice
/// that moves one-time-secret derivation behind the device.)
#[derive(Clone)]
pub struct OneTimeKeyRef {
    /// The per-output one-time secret `x = H(a·R‖idx) + b (+ m)`. Present for the
    /// software signer; `None` for a device signer, which never receives it.
    pub secret: Option<SecretKey>,
}

impl OneTimeKeyRef {
    /// Reference a one-time key by its raw secret (software-signer path).
    pub fn from_secret(secret: SecretKey) -> Self {
        Self {
            secret: Some(secret),
        }
    }

    /// EC scalar for the software path; errors if no secret is present (i.e. this
    /// ref was built for a device signer and handed to the software signer).
    fn scalar(&self) -> Result<SecretScalar> {
        let s = self.secret.as_ref().ok_or_else(|| {
            Error::CryptoError("software signer requires the one-time secret".into())
        })?;
        Ok(SecretScalar::from_bytes(*s.as_bytes()))
    }
}

/// Everything needed to produce one input's CLSAG signature. Borrows so the
/// builder passes its existing values through without extra allocation.
pub struct ClsagSignRequest<'a> {
    /// The signing preimage (`Transaction::compute_signing_hash` bytes).
    pub message: &'a [u8],
    /// The input's ring (real member at `real_index`).
    pub ring: &'a [ClsagRingMember],
    /// Index of the real spend within `ring`.
    pub real_index: usize,
    /// The one-time key that authorizes the real member.
    pub key: &'a OneTimeKeyRef,
    /// `z_real - z_pseudo`, the commitment blinding difference.
    pub blinding_diff: &'a SecretScalar,
    /// The pseudo-output commitment for this input.
    pub pseudo_output: &'a EcCommitment,
}

/// The spend-authority operations the transaction builder needs. A software
/// keystore and a hardware device both implement this; the builder is agnostic.
pub trait TxSigner {
    /// Key image `I = x·Hp(x·G)` for the referenced one-time key.
    fn key_image(&self, key: &OneTimeKeyRef) -> Result<KeyImage>;

    /// One CLSAG signature for one input.
    fn sign_clsag_input<R: RngCore + CryptoRng>(
        &self,
        req: &ClsagSignRequest<'_>,
        rng: &mut R,
    ) -> Result<ClsagSignature>;
}

/// The default in-process signer. Stateless: it operates on the per-input
/// one-time secret carried in [`OneTimeKeyRef`], exactly as the builder did
/// inline before this seam existed. Behavior is byte-for-byte identical.
#[derive(Clone, Copy, Default, Debug)]
pub struct SoftwareSigner;

impl TxSigner for SoftwareSigner {
    fn key_image(&self, key: &OneTimeKeyRef) -> Result<KeyImage> {
        let scalar = key.scalar()?;
        Ok(KeyImage::from_bytes(
            CryptoKeyImage::from_secret(&scalar).to_bytes(),
        ))
    }

    fn sign_clsag_input<R: RngCore + CryptoRng>(
        &self,
        req: &ClsagSignRequest<'_>,
        rng: &mut R,
    ) -> Result<ClsagSignature> {
        let scalar = req.key.scalar()?;
        clsag_sign(
            req.message,
            req.ring,
            req.real_index,
            &scalar,
            req.blinding_diff,
            req.pseudo_output,
            rng,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn software_signer_key_image_matches_direct_call() {
        // Slice-1 behavior-preservation: routing the key image through the signer
        // yields exactly what the builder computed inline (I = x·Hp(x·G)).
        let secret = SecretKey::from_bytes([7u8; 32]);
        let via_signer = SoftwareSigner
            .key_image(&OneTimeKeyRef::from_secret(secret.clone()))
            .expect("software signer key image");
        let scalar = SecretScalar::from_bytes(*secret.as_bytes());
        let direct = KeyImage::from_bytes(CryptoKeyImage::from_secret(&scalar).to_bytes());
        assert_eq!(via_signer.as_bytes(), direct.as_bytes());
    }

    #[test]
    fn software_signer_rejects_missing_secret() {
        // A secret-less ref is meant for a device signer; the software signer must
        // refuse it rather than silently sign with the wrong key.
        assert!(SoftwareSigner
            .key_image(&OneTimeKeyRef { secret: None })
            .is_err());
    }
}
