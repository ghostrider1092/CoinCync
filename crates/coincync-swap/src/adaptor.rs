//! Adaptor signature primitives shared by both swap sides.
//!
//! Adaptor signatures are what make CYNC↔BTC atomic swaps work without
//! revealing the swap to chain analysts. Instead of requiring matching
//! HTLC scripts on both chains (which would leak the swap on the
//! privacy chain), each chain runs its native primitive — Bitcoin
//! Schnorr/ECDSA signatures, CoinCync CLSAG ring signatures — and the
//! two are *bound* by an adaptor: a signature that's "encrypted" under
//! a secret, where revealing the secret on one chain reveals the full
//! signature on the other. The chain analyst sees only normal
//! transactions on each side; only the swap participants know they
//! were linked.
//!
//! ## Status: SKELETON
//!
//! The eventual implementation will provide:
//! - secp256k1 Schnorr / ECDSA adaptor sigs (BTC side)
//! - Ed25519 / CLSAG adaptor sigs (CYNC side, modeled on Monero's
//!   Comit / Farcaster designs which work in production since 2021)
//! - Cross-curve discrete-log equality proofs (CDLP) so both sides
//!   can verify the adaptors are bound to the same secret without
//!   revealing it
//!
//! All of these are well-understood cryptographic constructions but
//! getting any one of them subtly wrong loses funds. The
//! implementation belongs in a focused work session with security
//! review — this file's job is to hold the type signatures.

use crate::{Error, Result};

/// Opaque secret shared between Alice and Bob via the protocol.
/// Bytes never appear in plaintext on either chain — they're encoded
/// in adaptor signatures and revealed only by the act of claiming.
#[derive(Clone, Debug)]
pub struct AdaptorSecret(#[allow(dead_code)] pub(crate) [u8; 32]);

/// An adaptor signature on the Bitcoin side (Schnorr or ECDSA;
/// implementation will pick one based on BIP-340 deployment status).
#[derive(Clone, Debug)]
pub struct BtcAdaptorSig {
    #[allow(dead_code)]
    pub(crate) bytes: Vec<u8>,
}

/// An adaptor signature on the CoinCync side (CLSAG-compatible).
#[derive(Clone, Debug)]
pub struct CyncAdaptorSig {
    #[allow(dead_code)]
    pub(crate) bytes: Vec<u8>,
}

/// Cross-curve discrete-log-equality proof. Used during negotiation
/// to prove that the BTC adaptor and CYNC adaptor are bound to the
/// same underlying secret without revealing it.
#[derive(Clone, Debug)]
pub struct CrossCurveDlProof {
    #[allow(dead_code)]
    pub(crate) bytes: Vec<u8>,
}

/// Verify a cross-curve DL-equality proof. This is the gating check
/// at the end of negotiation — both parties must verify before
/// either commits an on-chain transaction. A bad proof here means
/// "abort the swap, don't lock funds".
pub fn verify_cross_curve_proof(
    _proof: &CrossCurveDlProof,
    _btc_pub: &[u8],
    _cync_pub: &[u8],
) -> Result<()> {
    Err(Error::not_implemented("adaptor.verify_cross_curve_proof"))
}

/// Decrypt a Bitcoin adaptor signature into a complete signature
/// using the revealed secret. This is the operation Alice performs
/// to claim the BTC after Bob has locked it.
pub fn decrypt_btc_adaptor(_adaptor: &BtcAdaptorSig, _secret: &AdaptorSecret) -> Result<Vec<u8>> {
    Err(Error::not_implemented("adaptor.decrypt_btc_adaptor"))
}

/// Recover the secret from a Bitcoin adaptor + the complete signature
/// that decrypted it. This is the operation Bob performs by watching
/// the BTC chain — once Alice publishes her claim, Bob extracts the
/// secret and uses it to claim Alice's CYNC.
pub fn recover_secret_from_btc_sig(
    _adaptor: &BtcAdaptorSig,
    _final_sig: &[u8],
) -> Result<AdaptorSecret> {
    Err(Error::not_implemented(
        "adaptor.recover_secret_from_btc_sig",
    ))
}
