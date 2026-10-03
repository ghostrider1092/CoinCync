//! Adaptor signature primitives shared by both swap sides.
//!
//! Adaptor signatures are what make CYNCâ†”BTC atomic swaps work without
//! revealing the swap to chain analysts. Instead of requiring matching
//! HTLC scripts on both chains (which would leak the swap on the
//! privacy chain), each chain runs its native primitive â€” Bitcoin
//! Schnorr/ECDSA signatures, CoinCync CLSAG ring signatures â€” and the
//! two are *bound* by an adaptor: a signature that's "encrypted" under
//! a secret, where revealing the secret on one chain reveals the full
//! signature on the other. The chain analyst sees only normal
//! transactions on each side; only the swap participants know they
//! were linked.
//!
//! ## Status: BTC-side primitives implemented (2026-05-17 slice).
//!
//! What lands in this file:
//! - Real **BIP-340 Schnorr adaptor signatures** for the Bitcoin side
//!   (create / verify / decrypt / extract).
//! - Round-trip test exercising the full
//!   `create â†’ verify â†’ decrypt â†’ recover_secret` cycle on real
//!   secp256k1 points.
//!
//! What also lands in this file (CYNC side, added 2026-05-17 same
//! session as the BTC-side BIP-340 closure):
//! - Real **Schnorr adaptor signatures over Ristretto255** for the
//!   CoinCync side (create / verify / decrypt / extract). Ristretto
//!   is a prime-order group, so the CYNC side is simpler than the
//!   BTC side â€” no parity dance, no retry loop.
//! - Symmetric round-trip tests covering the create â†’ verify â†’
//!   decrypt â†’ recover cycle on real Ristretto points.
//!
//! The cross-curve proof that both adaptor points share one secret `t`
//! lives in [`crate::cross_curve_dleq`]. The v1 "fast" DLEQ that used
//! to be here shared one nonce between the curves and leaked `t` from a
//! single proof; it was removed, not deprecated.
//!
//! What is still skeleton:
//! - CLSAG ring-binding for the CYNC side. The functions here
//!   produce a stand-alone Schnorr adaptor; folding it into a CLSAG
//!   c-value so the swap is invisible on the CYNC chain belongs to
//!   the protocol-integration slice that follows.
//!
//! ## The construction (single-signer Schnorr adaptor)
//!
//! Reference: Aumayr et al. *"Generalized Channels from Limited
//! Blockchain Scripts and Adaptor Signatures"* (Asiacrypt 2021),
//! plus the version used in production by Comit/Farcaster XMRâ†”BTC.
//! All arithmetic is over the secp256k1 group with order `n`.
//!
//! Given keypair `(x, X = xÂ·G)`, message `m`, adaptor `(t, T = tÂ·G)`:
//!
//! 1. **Create pre-sig** â€” pick nonce `r`, set `R = rÂ·G`.
//!    Challenge `e = H_BIP340/challenge(R + T || X_x || m)` where
//!    `X_x` is the x-only public key. Pre-signature scalar
//!    `s_pre = r + eÂ·x  (mod n)`. Publish `(R, s_pre)` together
//!    with `T` (T is part of the adaptor agreement out-of-band).
//!
//! 2. **Verify pre-sig** â€” recompute `e = H(R + T || X_x || m)`.
//!    Check `s_preÂ·G == R + eÂ·X`. (Note: NOT `R + T + eÂ·X` â€” the
//!    pre-sig commits to `r`, not `r + t`.)
//!
//! 3. **Adapt / decrypt** â€” given `s_pre` and adaptor secret `t`,
//!    compute `s = s_pre + t  (mod n)`. The resulting BIP-340
//!    signature is `(R + T, s)`. Verifier of the final on-chain sig
//!    checks `sÂ·G == (R + T) + eÂ·X` with `e = H((R+T) || X_x || m)`,
//!    which expands to `(r + t)Â·G + eÂ·xÂ·G = (s_pre + t)Â·G + eÂ·xÂ·G`
//!    â€” consistent because `s_pre = r + eÂ·x`.
//!
//! 4. **Extract** â€” given pre-sig `s_pre` and the final on-chain
//!    signature scalar `s`, the adaptor secret is `t = s - s_pre
//!    (mod n)`. This is the operation Bob runs by watching the BTC
//!    chain: when Alice claims, her published signature reveals `t`,
//!    and Bob uses `t` to claim the CYNC-side adaptor's funds.
//!
//! ## What is deliberately NOT done in this slice
//!
//! - **Pre-sig serialization for wire format.** `BtcAdaptorSig`
//!   here is a Rust struct, not a defined byte layout. The wire
//!   format belongs in a CIP-001 protocol-encoding addendum.
//! - **CYNC adaptor.** Stubbed elsewhere.
//! - **Cross-curve proof.** See [`crate::cross_curve_dleq`].
//!
//! ## BIP-340 parity handling â€” handled by [`create_pre_sig_bip340`]
//!
//! BIP-340 requires two parity adjustments:
//!
//! 1. **Signer-key y-parity.** If `X = dÂ·G` has odd y, the verifier
//!    lifts `X.x` with even y, so the signer must internally use
//!    `d' = n âˆ’ d`. [`create_pre_sig_bip340`] computes `d_even`
//!    from `seckey` and uses it for the pre-signature.
//!
//! 2. **Final-nonce y-parity.** The on-chain encoding sends only
//!    `(R + T).x`; the verifier lifts it with even y. So the
//!    signer must pick `r` such that `R + T` has even y. We do
//!    this by deriving the nonce deterministically from
//!    `(aux_rand, msg, X_even, counter)` via a tagged SHA-256, and
//!    incrementing the counter on odd parity. With independent
//!    bits, eight retries miss with probability ~0.4 %.
//!
//! The lower-level [`create_pre_sig`] still takes an explicit
//! nonce for use in tests and protocol experiments where the
//! caller wants full control. Its output is correct adaptor-sig
//! math but is not guaranteed to verify under the BIP-340
//! consensus verifier â€” for that, use [`create_pre_sig_bip340`].

use secp256k1::{PublicKey, Scalar, Secp256k1, SecretKey, XOnlyPublicKey};
use sha2::{Digest, Sha256};

use crate::{Error, Result};

// â”€â”€ Public types â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

/// Which curve's byte-order convention the stored bytes are in.
///
/// secp256k1 and Ristretto255 disagree on scalar serialization:
/// secp256k1's `SecretKey::secret_bytes()` is big-endian; Ristretto's
/// `Scalar::to_bytes()` is little-endian. The same scalar value has
/// **different byte representations** in the two crates. An
/// [`AdaptorSecret`] tracks which encoding its bytes are in so
/// helpers that consume the secret can transparently produce the
/// right form for their target curve.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SecretEncoding {
    /// Big-endian â€” matches secp256k1's `SecretKey::secret_bytes()`.
    Secp256k1BigEndian,
    /// Little-endian â€” matches Ristretto's `Scalar::to_bytes()`.
    RistrettoLittleEndian,
}

/// Opaque adaptor secret. The bytes never appear in plaintext on
/// either chain â€” they're encoded in adaptor signatures and revealed
/// only by the act of claiming.
///
/// ## Byte-order convention
///
/// secp256k1 stores scalars big-endian; Ristretto stores them
/// little-endian. The same scalar value has different byte
/// representations in the two crates. To prevent silent
/// cross-curve mismatches, `AdaptorSecret` tracks the encoding of
/// its stored bytes:
///
/// - [`AdaptorSecret::from_bytes`] /
///   [`AdaptorSecret::from_secp256k1_bytes`] â€” caller has secp256k1
///   big-endian bytes (e.g. from `SecretKey::secret_bytes()`).
/// - [`AdaptorSecret::from_ristretto_bytes`] â€” caller has Ristretto
///   little-endian bytes (e.g. from `Scalar::to_bytes()`).
///
/// Use [`AdaptorSecret::secp256k1_bytes`] /
/// [`AdaptorSecret::ristretto_bytes`] to retrieve the bytes in
/// whichever form the consuming code needs â€” the conversion
/// reverses the byte order if the requested form differs from the
/// stored form.
///
/// For a secret to be valid on **both curves** (the cross-curve
/// adaptor case), the underlying scalar must fit in the stricter
/// field â€” Ristretto's `â„“ â‰ˆ 2^252`. Constructors that take
/// secp256k1 bytes do **not** check this (the value might be
/// `n > x > â„“`, valid for secp256k1 alone); for cross-curve use
/// prefer [`from_ristretto_bytes`] which enforces the stricter
/// check.
///
/// [`from_ristretto_bytes`]: AdaptorSecret::from_ristretto_bytes
#[derive(Clone, Debug)]
pub struct AdaptorSecret {
    bytes: [u8; 32],
    encoding: SecretEncoding,
}

impl PartialEq for AdaptorSecret {
    /// Two adaptor secrets compare equal iff they represent the
    /// **same scalar value**, regardless of the encoding their
    /// bytes are stored in. Compares the secp256k1 big-endian
    /// canonical form, which is well-defined for every value either
    /// constructor admits.
    ///
    /// **Constant-time** via [`subtle::ConstantTimeEq`] — the
    /// branch / return-value timing does not depend on which
    /// bytes of the secrets agree. Use
    /// [`AdaptorSecret::ct_eq`] for the explicit
    /// `subtle::Choice` return when integrating with downstream
    /// constant-time logic.
    fn eq(&self, other: &Self) -> bool {
        use subtle::ConstantTimeEq;
        self.secp256k1_bytes()
            .ct_eq(&other.secp256k1_bytes())
            .into()
    }
}
impl Eq for AdaptorSecret {}

impl subtle::ConstantTimeEq for AdaptorSecret {
    fn ct_eq(&self, other: &Self) -> subtle::Choice {
        self.secp256k1_bytes().ct_eq(&other.secp256k1_bytes())
    }
}

impl AdaptorSecret {
    /// Constant-time equality returning [`subtle::Choice`] —
    /// useful when the result needs to flow into further
    /// constant-time arithmetic (`Choice::conditional_select`,
    /// `CtOption`, etc.) without the `bool`-materialization
    /// branch the `==` operator would introduce.
    ///
    /// `==` (via `PartialEq`) is also constant-time but eagerly
    /// returns `bool`; use this method when you need the
    /// `Choice` directly.
    pub fn ct_eq(&self, other: &Self) -> subtle::Choice {
        <Self as subtle::ConstantTimeEq>::ct_eq(self, other)
    }

    /// Build an adaptor secret from secp256k1 big-endian bytes.
    /// Alias for [`from_secp256k1_bytes`] kept for backward
    /// compatibility with the original API.
    ///
    /// [`from_secp256k1_bytes`]: AdaptorSecret::from_secp256k1_bytes
    pub fn from_bytes(bytes: [u8; 32]) -> Result<Self> {
        Self::from_secp256k1_bytes(bytes)
    }

    /// Build an adaptor secret from secp256k1 big-endian bytes
    /// (the form `SecretKey::secret_bytes()` returns). Validates
    /// the value is in `[1, n)`. Stored bytes carry the
    /// `Secp256k1BigEndian` tag; callers using CYNC adaptor
    /// helpers transparently get the little-endian form via
    /// [`ristretto_bytes`].
    ///
    /// [`ristretto_bytes`]: AdaptorSecret::ristretto_bytes
    pub fn from_secp256k1_bytes(bytes: [u8; 32]) -> Result<Self> {
        SecretKey::from_slice(&bytes)
            .map_err(|_| Error::Verification("adaptor secret out of secp256k1 range"))?;
        Ok(Self {
            bytes,
            encoding: SecretEncoding::Secp256k1BigEndian,
        })
    }

    /// Build an adaptor secret from Ristretto canonical (little-
    /// endian) bytes â€” the form `Scalar::to_bytes()` returns.
    /// Validates the value is canonical (`< â„“`), which is the
    /// stricter constraint and guarantees the secret is also a
    /// valid secp256k1 scalar (since `â„“ < n`).
    ///
    /// Prefer this constructor for **cross-curve** use; the
    /// `from_secp256k1_bytes` variant doesn't enforce `< â„“`.
    pub fn from_ristretto_bytes(bytes: [u8; 32]) -> Result<Self> {
        // Canonical-check via curve25519_dalek.
        let _scalar =
            Option::<Curve25519Scalar>::from(Curve25519Scalar::from_canonical_bytes(bytes)).ok_or(
                Error::Verification("adaptor secret not canonical Ristretto"),
            )?;
        Ok(Self {
            bytes,
            encoding: SecretEncoding::RistrettoLittleEndian,
        })
    }

    /// The encoding tag of the stored bytes. Useful for tests and
    /// for callers that need to thread encoding through their own
    /// data structures.
    pub fn encoding(&self) -> SecretEncoding {
        self.encoding
    }

    /// Raw stored bytes in their original encoding. Avoid this in
    /// new code â€” prefer [`secp256k1_bytes`] / [`ristretto_bytes`]
    /// which deliver the right form for the consuming curve.
    /// Retained for back-compat with code that doesn't care about
    /// encoding (e.g. hashing for transcripts).
    ///
    /// [`secp256k1_bytes`]: AdaptorSecret::secp256k1_bytes
    /// [`ristretto_bytes`]: AdaptorSecret::ristretto_bytes
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.bytes
    }

    /// Bytes in secp256k1 big-endian form. Reverses internally if
    /// the secret is stored as Ristretto little-endian.
    pub fn secp256k1_bytes(&self) -> [u8; 32] {
        match self.encoding {
            SecretEncoding::Secp256k1BigEndian => self.bytes,
            SecretEncoding::RistrettoLittleEndian => {
                let mut out = self.bytes;
                out.reverse();
                out
            }
        }
    }

    /// Bytes in Ristretto little-endian form. Reverses internally
    /// if the secret is stored as secp256k1 big-endian.
    ///
    /// **Range note:** the result may not be canonical (`< â„“`) if
    /// the secret was constructed from secp256k1 bytes that exceed
    /// `â„“`. Cross-curve callers should construct via
    /// [`from_ristretto_bytes`] to get the canonical-check up
    /// front.
    pub fn ristretto_bytes(&self) -> [u8; 32] {
        match self.encoding {
            SecretEncoding::RistrettoLittleEndian => self.bytes,
            SecretEncoding::Secp256k1BigEndian => {
                let mut out = self.bytes;
                out.reverse();
                out
            }
        }
    }

    /// Public adaptor point `T = tÂ·G_secp256k1`. The counterparty
    /// commits to this ahead of the swap; the secret stays with
    /// whoever generated it.
    pub fn public_point(&self) -> PublicKey {
        let secp = Secp256k1::new();
        let sk = SecretKey::from_slice(&self.secp256k1_bytes())
            .expect("validated in from_secp256k1_bytes / from_ristretto_bytes");
        PublicKey::from_secret_key(&secp, &sk)
    }
}

/// A Bitcoin-side adaptor signature: the nonce point `R` (NOT `R + T`)
/// plus the pre-signature scalar `s_pre`. Verifier reconstructs `R + T`
/// using the adaptor point `T` supplied out-of-band; the on-chain
/// final signature is `(R + T, s_pre + t)`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BtcAdaptorSig {
    /// `R = rÂ·G` â€” the nonce commitment, *without* the adaptor offset.
    pub r_point: PublicKey,
    /// `s_pre = r + eÂ·x  (mod n)` â€” the pre-signature scalar.
    /// Stored as bytes so that `Eq` and copy/clone are cheap and
    /// the secret-key representation never escapes.
    pub s_pre: [u8; 32],
}

/// A CoinCync-side adaptor signature over Ristretto255.
///
/// Mirrors [`BtcAdaptorSig`] but on a prime-order group: the nonce
/// point `R = rÂ·G` (NOT `R + T`) plus the pre-signature scalar
/// `s_pre = r + eÂ·x  (mod â„“)` where `â„“` is the Ed25519 group order.
/// The final on-chain signature is `(R + T, s_pre + t)`. Ristretto's
/// canonical encoding has no parity dance, so this side needs no
/// retry loop.
///
/// CLSAG ring signatures sit on the same Ristretto255 group; once
/// the swap protocol's ring-binding piece lands, this struct is the
/// adaptor scalar that gets folded into the CLSAG response, not a
/// stand-alone Schnorr sig.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CyncAdaptorSig {
    /// `R = rÂ·G` â€” the nonce commitment without the adaptor offset.
    /// 32-byte compressed Ristretto point.
    pub r_point: [u8; 32],
    /// `s_pre` â€” the pre-signature scalar mod â„“.
    pub s_pre: [u8; 32],
}

// â”€â”€ Schnorr adaptor: BTC side â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

/// Create a Schnorr adaptor pre-signature.
///
/// # Arguments
/// - `seckey`     â€” signer's private key `x`.
/// - `msg`        â€” 32-byte sighash of the BTC transaction being
///                  pre-signed (NOT the raw transaction).
/// - `adaptor_pt` â€” `T = tÂ·G`, the adaptor point. The counterparty
///                  holds `t`; this signer only knows `T`.
/// - `nonce`      â€” fresh signing nonce `r`. **Caller is responsible
///                  for nonce uniqueness per `(seckey, msg)` pair.**
///                  Reusing a nonce across messages leaks the private
///                  key (textbook Schnorr nonce-reuse attack).
///                  Production use should derive `r` from RFC-6979 or
///                  BIP-340-aux; tests pass an explicit nonce so the
///                  round-trip is deterministic.
///
/// Returns `(BtcAdaptorSig, signer_pubkey)` so callers can hand both
/// to a verifier without a round-trip back through the signer.
pub fn create_pre_sig(
    seckey: &SecretKey,
    msg: &[u8; 32],
    adaptor_pt: &PublicKey,
    nonce: &SecretKey,
) -> Result<(BtcAdaptorSig, XOnlyPublicKey)> {
    let secp = Secp256k1::new();
    let signer_pub = PublicKey::from_secret_key(&secp, seckey);
    let signer_x = signer_pub.x_only_public_key().0;

    // R = rÂ·G
    let r_point = PublicKey::from_secret_key(&secp, nonce);

    // R + T â€” the nonce commitment used for the challenge.
    let r_plus_t = r_point
        .combine(adaptor_pt)
        .map_err(|_| Error::Verification("R + T combine failed"))?;

    // e = H_BIP340/challenge( (R+T)_x || X_x || m )
    let e = bip340_challenge(&r_plus_t, &signer_x, msg)?;

    // s_pre = r + eÂ·x  (mod n)
    //       = r + Scalar(e)Â·x
    // Implemented as `nonce + (e * seckey)` where `*` is scalar mul
    // mod n and `+` is scalar add mod n.
    let e_x = seckey
        .mul_tweak(&e)
        .map_err(|_| Error::Verification("eÂ·x multiplication failed"))?;
    let s_pre = nonce
        .add_tweak(&secret_to_scalar(&e_x))
        .map_err(|_| Error::Verification("r + eÂ·x addition failed"))?;

    Ok((
        BtcAdaptorSig {
            r_point,
            s_pre: s_pre.secret_bytes(),
        },
        signer_x,
    ))
}

/// Create a BIP-340-conformant Schnorr adaptor pre-signature.
///
/// Wraps [`create_pre_sig`] with the two parity adjustments BIP-340
/// requires for the resulting [`decrypt_btc_adaptor`] output to
/// verify under Bitcoin's consensus verifier (and thus to be
/// broadcast in an atomic-swap claim transaction):
///
///   1. Internally lifts `seckey` to its even-y form `d_even`.
///   2. Derives the nonce from `(aux_rand, msg, X_even, counter)`
///      and retries with `counter += 1` until `(R + T).y` is even.
///
/// Returns the pre-sig, the signer's x-only pubkey (the verifier's
/// input), AND the adaptor point `T` (for convenience â€” the
/// decryptor must combine `R + T` and the caller often wants both
/// values bundled). On the rare event of 8 consecutive odd-y
/// candidates the function returns
/// [`Error::Verification`] rather than looping forever; callers
/// can rotate `aux_rand` and retry.
///
/// `aux_rand` must be 32 bytes of cryptographically random data,
/// fresh per signing operation. Tests can use a constant seed for
/// determinism; production callers MUST source it from a CSPRNG.
pub fn create_pre_sig_bip340(
    seckey: &SecretKey,
    msg: &[u8; 32],
    adaptor_pt: &PublicKey,
    aux_rand: &[u8; 32],
) -> Result<(BtcAdaptorSig, XOnlyPublicKey)> {
    let secp = Secp256k1::new();

    // 1. Lift the signer's key to even-y form.
    let signer_pub = PublicKey::from_secret_key(&secp, seckey);
    let (signer_x, parity) = signer_pub.x_only_public_key();
    let d_even = match parity {
        secp256k1::Parity::Even => *seckey,
        secp256k1::Parity::Odd => seckey.negate(),
    };

    // 2. Derive a nonce whose R + T has even y. Up to 8 tries.
    const MAX_RETRIES: u32 = 8;
    let (nonce, _r_plus_t) = (0..MAX_RETRIES)
        .find_map(|counter| {
            let n = match derive_bip340_nonce(&d_even, aux_rand, msg, &signer_x, adaptor_pt, counter)
            {
                Ok(n) => n,
                Err(_) => return None,
            };
            let r_point = PublicKey::from_secret_key(&secp, &n);
            let r_plus_t = match r_point.combine(adaptor_pt) {
                Ok(pt) => pt,
                Err(_) => return None,
            };
            let (_, p) = r_plus_t.x_only_public_key();
            if p == secp256k1::Parity::Even {
                Some((n, r_plus_t))
            } else {
                None
            }
        })
        .ok_or(Error::Verification(
            "BIP-340 nonce parity miss Ã— 8 â€” rotate aux_rand and retry",
        ))?;

    // 3. Build pre-sig using d_even (NOT the original seckey).
    //    Re-implements the body of create_pre_sig with d_even so
    //    we never depend on the public function's seckey argument.
    let r_point = PublicKey::from_secret_key(&secp, &nonce);
    let r_plus_t = r_point
        .combine(adaptor_pt)
        .map_err(|_| Error::Verification("R + T combine failed"))?;
    let e = bip340_challenge(&r_plus_t, &signer_x, msg)?;
    let e_d = d_even
        .mul_tweak(&e)
        .map_err(|_| Error::Verification("eÂ·d_even multiplication failed"))?;
    let s_pre = nonce
        .add_tweak(&secret_to_scalar(&e_d))
        .map_err(|_| Error::Verification("nonce + eÂ·d_even addition failed"))?;

    Ok((
        BtcAdaptorSig {
            r_point,
            s_pre: s_pre.secret_bytes(),
        },
        signer_x,
    ))
}

/// Deterministic nonce derivation for [`create_pre_sig_bip340`], BIP-340
/// synthetic-nonce form extended to bind the adaptor point.
///
/// `k = H_nonce( (d_even XOR H_aux(aux_rand)) || X_even || T || msg || counter )`
///
/// SECURITY (crypto-cluster #1, 2026-08-30). The previous form hashed only
/// `(aux_rand, msg, X_even, counter)` — it bound the message and pubkey (so the
/// "reuse aux_rand across different messages ⇒ same k" attack never applied),
/// but it did NOT bind the secret key or the adaptor point:
///
/// - **Secret key now bound (BIP-340 masking `d ⊕ H_aux(aux_rand)`).** Nonce
///   secrecy no longer depends on `aux_rand` entropy: even with a reused, zero,
///   or predictable `aux_rand`, `k` stays secret because `d_even` is in the
///   preimage. Previously a weak/predictable `aux_rand` could expose `k` (hence
///   the key) from a single signature.
/// - **Adaptor point `T` now bound.** A pre-signature and a plain signature
///   under the same key and message can no longer share a nonce.
///
/// The `counter` still lets us retry for an even-y `R + T` without re-rolling
/// inputs; it is domain-separated so it cannot collide with any other CoinCync
/// hash output. `d_even` is the even-lifted secret the caller already computed,
/// matching BIP-340's use of `d'` (the private key negated to the even-y form).
///
/// GATED / UNREVIEWED-CRYPTO: CoinCync domain tags, not yet validated against a
/// reference by a cryptographer (see
/// `docs/audit/2026-08-30-crypto-cluster-expert-briefing.md`, item #1). The swap
/// crate is not linked into the node binary; do not enable swaps on mainnet
/// until that review returns YES with a reference test vector.
fn derive_bip340_nonce(
    d_even: &SecretKey,
    aux_rand: &[u8; 32],
    msg: &[u8; 32],
    x_even: &XOnlyPublicKey,
    adaptor_pt: &PublicKey,
    counter: u32,
) -> Result<SecretKey> {
    // BIP-340 aux masking: aux_tag = H("…/Aux-v2", aux_rand), then t = d ⊕ aux_tag.
    let aux_seed: [u8; 32] = {
        let mut h = Sha256::new();
        h.update(b"CoinCync/SwapAdaptor/Aux-v2");
        h.finalize().into()
    };
    let aux_tag: [u8; 32] = {
        let mut h = Sha256::new();
        h.update(aux_seed);
        h.update(aux_seed);
        h.update(aux_rand);
        h.finalize().into()
    };
    let mut t = d_even.secret_bytes();
    for (tb, ab) in t.iter_mut().zip(aux_tag.iter()) {
        *tb ^= ab;
    }

    // k = H_nonce(t || X_even || T || msg || counter), tag hashed twice.
    let nonce_seed: [u8; 32] = {
        let mut h = Sha256::new();
        h.update(b"CoinCync/SwapAdaptor/Nonce-v2");
        h.finalize().into()
    };
    let mut h = Sha256::new();
    h.update(nonce_seed);
    h.update(nonce_seed);
    h.update(t);
    h.update(x_even.serialize());
    h.update(adaptor_pt.serialize());
    h.update(msg);
    h.update(counter.to_be_bytes());
    let bytes: [u8; 32] = h.finalize().into();

    // Best-effort wipe of the secret-derived mask (the crate has no zeroize
    // dep; SecretKey itself zeroizes on drop — this only clears our XOR copy).
    for b in t.iter_mut() {
        *b = 0;
    }

    SecretKey::from_slice(&bytes)
        .map_err(|_| Error::Verification("derived nonce out of secp256k1 scalar range"))
}

/// Verify a Schnorr adaptor pre-signature.
///
/// Checks `s_preÂ·G == R + eÂ·X` where `e = H((R+T)_x || X_x || m)` and
/// `X` is the signer's full public key (lifted from the x-only key per
/// BIP-340 rules: take the y-coordinate that is even).
///
/// Returns `Ok(())` if valid, `Err(Verification)` if not.
pub fn verify_pre_sig(
    adaptor: &BtcAdaptorSig,
    signer_x: &XOnlyPublicKey,
    adaptor_pt: &PublicKey,
    msg: &[u8; 32],
) -> Result<()> {
    let secp = Secp256k1::new();

    // R + T
    let r_plus_t = adaptor
        .r_point
        .combine(adaptor_pt)
        .map_err(|_| Error::Verification("R + T combine failed"))?;
    let e = bip340_challenge(&r_plus_t, signer_x, msg)?;

    // Lift signer_x to a full PublicKey with even y (BIP-340 convention).
    let signer_pub = signer_x.public_key(secp256k1::Parity::Even);

    // LHS: s_pre Â· G
    let s_pre_sk = SecretKey::from_slice(&adaptor.s_pre)
        .map_err(|_| Error::Verification("invalid s_pre scalar"))?;
    let lhs = PublicKey::from_secret_key(&secp, &s_pre_sk);

    // RHS: R + eÂ·X
    let e_x = signer_pub
        .mul_tweak(&secp, &e)
        .map_err(|_| Error::Verification("eÂ·X scalar mul failed"))?;
    let rhs = adaptor
        .r_point
        .combine(&e_x)
        .map_err(|_| Error::Verification("R + eÂ·X combine failed"))?;

    if lhs == rhs {
        Ok(())
    } else {
        Err(Error::Verification("pre-signature verification failed"))
    }
}

/// Decrypt the pre-signature into a complete BIP-340 Schnorr signature
/// using the adaptor secret.
///
/// Returns the 64-byte BIP-340 signature: `(R + T)_x || s` where
/// `s = s_pre + t (mod n)`. This is what gets put in a Bitcoin
/// taproot script-path / key-path witness.
///
/// This is the operation Alice performs to claim the BTC after Bob has
/// locked it: Bob handed her the pre-sig already; she combines with
/// her secret `t` and the resulting sig is broadcast.
pub fn decrypt_btc_adaptor(
    adaptor: &BtcAdaptorSig,
    secret: &AdaptorSecret,
    adaptor_pt: &PublicKey,
) -> Result<[u8; 64]> {
    let s_pre = SecretKey::from_slice(&adaptor.s_pre)
        .map_err(|_| Error::Verification("invalid s_pre scalar"))?;
    let t = SecretKey::from_slice(&secret.secp256k1_bytes())
        .map_err(|_| Error::Verification("invalid adaptor secret"))?;

    // s = s_pre + t
    let s = s_pre
        .add_tweak(&secret_to_scalar(&t))
        .map_err(|_| Error::Verification("s_pre + t failed"))?;

    // The final BIP-340 nonce commitment is R + T (x-only).
    let r_plus_t = adaptor
        .r_point
        .combine(adaptor_pt)
        .map_err(|_| Error::Verification("R + T combine failed"))?;
    let (r_plus_t_x, _parity) = r_plus_t.x_only_public_key();

    let mut sig = [0u8; 64];
    sig[0..32].copy_from_slice(&r_plus_t_x.serialize());
    sig[32..64].copy_from_slice(&s.secret_bytes());
    Ok(sig)
}

/// Recover the adaptor secret `t` from a published final signature.
///
/// Given the original pre-sig `s_pre` and the on-chain final signature
/// `(R+T, s)`, compute `t = s - s_pre (mod n)`. This is the operation
/// Bob performs by watching the BTC chain: when Alice broadcasts her
/// claim, Bob extracts `t` from her signature and uses it to claim the
/// CYNC-side counterpart.
///
/// `final_sig` is the full 64-byte BIP-340 signature (R+T || s); only
/// the `s` half is used here â€” the R+T half is implicitly trusted by
/// having been broadcast on-chain.
pub fn recover_secret_from_btc_sig(
    adaptor: &BtcAdaptorSig,
    final_sig: &[u8; 64],
) -> Result<AdaptorSecret> {
    let s_real = SecretKey::from_slice(&final_sig[32..64])
        .map_err(|_| Error::Verification("invalid s in final sig"))?;
    let s_pre = SecretKey::from_slice(&adaptor.s_pre)
        .map_err(|_| Error::Verification("invalid s_pre scalar"))?;

    // t = s_real - s_pre  =  s_real + (-s_pre)
    let neg_s_pre = s_pre.negate();
    let t = s_real
        .add_tweak(&secret_to_scalar(&neg_s_pre))
        .map_err(|_| Error::Verification("s_real - s_pre failed"))?;

    // Recovered from secp256k1 arithmetic â†’ bytes are big-endian.
    AdaptorSecret::from_secp256k1_bytes(t.secret_bytes())
}

// â”€â”€ Schnorr adaptor: CYNC side (Ristretto255) â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
//
// Symmetric to the BTC side mathematically. Ristretto255 is a
// prime-order group, which removes BIP-340's two parity headaches:
// every point has a unique canonical encoding, every scalar has a
// unique representation, and there is no "even/odd y" lift. The
// final signature reads back identically from compressed bytes.
//
// Hash-to-scalar uses SHA-512 + Ristretto's scalar-from-512-bit-hash
// reduction, which is what Ed25519 and ed25519-dalek's HashEd25519
// implementations use. We hash a domain-separated label so the
// output cannot be confused with a CLSAG c-value or an Ed25519
// signature challenge.

use curve25519_dalek::constants::RISTRETTO_BASEPOINT_TABLE;
use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
use curve25519_dalek::scalar::Scalar as Curve25519Scalar;
use sha2::Sha512;

/// Compute the adaptor point `T = tÂ·G` (Ristretto basepoint).
/// Helper used by callers that hold the secret and need to publish
/// the point.
pub fn cync_adaptor_point(secret: &AdaptorSecret) -> Result<[u8; 32]> {
    // `ristretto_bytes()` reverses internally if the secret was
    // constructed from secp256k1 BE bytes, so this works for both
    // origins transparently.
    let t = ristretto_scalar_from_bytes(&secret.ristretto_bytes())?;
    let point = &t * RISTRETTO_BASEPOINT_TABLE;
    Ok(point.compress().to_bytes())
}

/// Create a Schnorr adaptor pre-signature on the CYNC (Ristretto)
/// side.
///
/// # Arguments
/// - `seckey_bytes` â€” 32-byte canonical scalar; the signer's secret
///                    key (a Curve25519 scalar).
/// - `msg`          â€” 32-byte sighash of the CYNC transaction being
///                    pre-signed.
/// - `adaptor_pt_bytes` â€” compressed Ristretto encoding of `T`.
/// - `nonce_bytes`  â€” fresh signing nonce as a 32-byte scalar.
///                    **Caller is responsible for nonce uniqueness
///                    per `(seckey, msg)` pair.** Production callers
///                    should derive `r` from RFC-6979-style hashing
///                    of `(seckey, msg, aux_rand)`; tests pass a
///                    deterministic value.
///
/// Returns the pre-sig and the signer's public-key bytes (compressed
/// Ristretto) so callers can hand both to a verifier without an extra
/// derivation step.
pub fn cync_create_pre_sig(
    seckey_bytes: &[u8; 32],
    msg: &[u8; 32],
    adaptor_pt_bytes: &[u8; 32],
    nonce_bytes: &[u8; 32],
) -> Result<(CyncAdaptorSig, [u8; 32])> {
    let x = ristretto_scalar_from_bytes(seckey_bytes)?;
    let r = ristretto_scalar_from_bytes(nonce_bytes)?;
    let t_point = ristretto_point_from_bytes(adaptor_pt_bytes)?;

    let signer_point = &x * RISTRETTO_BASEPOINT_TABLE;
    let signer_pub = signer_point.compress().to_bytes();

    let r_point = &r * RISTRETTO_BASEPOINT_TABLE;
    let r_plus_t = r_point + t_point;

    let e = cync_challenge(&r_plus_t, &signer_point, msg);

    // s_pre = r + eÂ·x  (mod â„“)
    let s_pre = r + (e * x);

    Ok((
        CyncAdaptorSig {
            r_point: r_point.compress().to_bytes(),
            s_pre: s_pre.to_bytes(),
        },
        signer_pub,
    ))
}

/// Verify a CYNC-side adaptor pre-signature.
///
/// Checks `s_preÂ·G == R + eÂ·X` where `e` is the domain-separated
/// challenge `H( (R+T) || X || msg )` reduced into the Ristretto
/// scalar field.
pub fn cync_verify_pre_sig(
    adaptor: &CyncAdaptorSig,
    signer_pub: &[u8; 32],
    adaptor_pt_bytes: &[u8; 32],
    msg: &[u8; 32],
) -> Result<()> {
    let signer_point = ristretto_point_from_bytes(signer_pub)?;
    let t_point = ristretto_point_from_bytes(adaptor_pt_bytes)?;
    let r_point = ristretto_point_from_bytes(&adaptor.r_point)?;
    let s_pre = ristretto_scalar_from_bytes(&adaptor.s_pre)?;

    let r_plus_t = r_point + t_point;
    let e = cync_challenge(&r_plus_t, &signer_point, msg);

    // LHS: s_pre Â· G
    let lhs = &s_pre * RISTRETTO_BASEPOINT_TABLE;
    // RHS: R + eÂ·X
    let rhs = r_point + (e * signer_point);

    if lhs == rhs {
        Ok(())
    } else {
        Err(Error::Verification(
            "CYNC pre-signature verification failed",
        ))
    }
}

/// Decrypt a CYNC adaptor pre-signature into the complete signature
/// using the adaptor secret.
///
/// Returns the 64-byte final signature: `(R + T) || s` where
/// `s = s_pre + t  (mod â„“)`. Format mirrors Ed25519's
/// `(R, s)` 64-byte encoding so a CLSAG verifier expecting that
/// shape can accept the output directly once the ring-binding piece
/// lands.
pub fn cync_decrypt_adaptor(
    adaptor: &CyncAdaptorSig,
    secret: &AdaptorSecret,
    adaptor_pt_bytes: &[u8; 32],
) -> Result<[u8; 64]> {
    let s_pre = ristretto_scalar_from_bytes(&adaptor.s_pre)?;
    let t = ristretto_scalar_from_bytes(&secret.ristretto_bytes())?;
    let r_point = ristretto_point_from_bytes(&adaptor.r_point)?;
    let t_point = ristretto_point_from_bytes(adaptor_pt_bytes)?;

    let s = s_pre + t;
    let r_plus_t = (r_point + t_point).compress().to_bytes();
    let s_bytes = s.to_bytes();

    let mut out = [0u8; 64];
    out[0..32].copy_from_slice(&r_plus_t);
    out[32..64].copy_from_slice(&s_bytes);
    Ok(out)
}

/// Recover the adaptor secret from a published CYNC final signature.
///
/// `t = s - s_pre  (mod â„“)`. The operation Bob performs by watching
/// the CYNC chain: once Alice's claim signature is broadcast, Bob
/// extracts `t` and uses it to claim the BTC-side adaptor's funds.
pub fn cync_recover_secret(
    adaptor: &CyncAdaptorSig,
    final_sig: &[u8; 64],
) -> Result<AdaptorSecret> {
    let s =
        ristretto_scalar_from_bytes(final_sig[32..64].try_into().expect("constant slice length"))?;
    let s_pre = ristretto_scalar_from_bytes(&adaptor.s_pre)?;
    let t = s - s_pre;
    // Recovered from Ristretto arithmetic â†’ bytes are little-endian.
    // `t.to_bytes()` is always canonical because Curve25519Scalar
    // arithmetic stays inside the field.
    AdaptorSecret::from_ristretto_bytes(t.to_bytes())
}

// â”€â”€ CYNC adaptor helpers â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

/// Domain-separated challenge for the CYNC adaptor.
///
/// `e = scalar_from_512bit_hash( SHA-512( tag || tag || (R+T)||X||msg ) )`
///
/// where `tag = SHA-512("CoinCync/SwapAdaptor/CyncChallenge-v1")`.
/// Same double-tag construction Ed25519/BIP-340 use, but with a
/// CoinCync-specific label so the output can't collide with any
/// other CYNC signature challenge (CLSAG c-values, Ed25519 sigs).
fn cync_challenge(
    r_plus_t: &RistrettoPoint,
    signer_pub: &RistrettoPoint,
    msg: &[u8; 32],
) -> Curve25519Scalar {
    use sha2::Digest;

    let tag_hash: [u8; 64] = {
        let mut h = Sha512::new();
        h.update(b"CoinCync/SwapAdaptor/CyncChallenge-v1");
        h.finalize().into()
    };

    let mut h = Sha512::new();
    h.update(tag_hash);
    h.update(tag_hash);
    h.update(r_plus_t.compress().to_bytes());
    h.update(signer_pub.compress().to_bytes());
    h.update(msg);

    // `from_hash` reduces a 512-bit digest into the Ristretto scalar
    // field with uniform distribution â€” the canonical hash-to-scalar
    // for Ed25519 / Ristretto.
    Curve25519Scalar::from_hash(h)
}

fn ristretto_scalar_from_bytes(bytes: &[u8; 32]) -> Result<Curve25519Scalar> {
    Option::<Curve25519Scalar>::from(Curve25519Scalar::from_canonical_bytes(*bytes))
        .ok_or(Error::Verification("non-canonical Ristretto scalar"))
}

fn ristretto_point_from_bytes(bytes: &[u8; 32]) -> Result<RistrettoPoint> {
    CompressedRistretto::from_slice(bytes)
        .map_err(|_| Error::Verification("Ristretto point slice length"))?
        .decompress()
        .ok_or(Error::Verification("Ristretto point decode failed"))
}

// â”€â”€ Helpers â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

/// BIP-340 tagged hash `H_BIP340/challenge(R_x || P_x || m) mod n`.
/// Returns a `Scalar` (secp256k1 scalar mod the curve order, with the
/// `mod n` reduction handled by `Scalar::from_be_bytes`).
fn bip340_challenge(r: &PublicKey, p: &XOnlyPublicKey, m: &[u8; 32]) -> Result<Scalar> {
    let (r_x, _) = r.x_only_public_key();

    // BIP-340 tagged hash: SHA256(SHA256(tag) || SHA256(tag) || data).
    let tag_hash: [u8; 32] = {
        let mut h = Sha256::new();
        h.update(b"BIP0340/challenge");
        h.finalize().into()
    };

    let mut h = Sha256::new();
    h.update(tag_hash);
    h.update(tag_hash);
    h.update(r_x.serialize());
    h.update(p.serialize());
    h.update(m);
    let digest: [u8; 32] = h.finalize().into();

    // Reduce the 32-byte digest mod n. `Scalar::from_be_bytes` is
    // strict (rejects values >= n); for the challenge we want
    // reduction. The probability of a uniformly-random 256-bit
    // value falling in `[n, 2^256)` is ~2^-128, so we accept the
    // strict variant â€” on the astronomically rare reject, the
    // tagged hash itself would have to be unsafe anyway, and the
    // caller can retry with a fresh nonce. This matches what
    // libsecp256k1 does for BIP-340.
    Scalar::from_be_bytes(digest)
        .map_err(|_| Error::Verification("BIP-340 challenge outside scalar range â€” retry"))
}

/// Helper: convert a `SecretKey` to a `Scalar` for tweak operations.
/// `SecretKey` and `Scalar` are both 32-byte mod-n values, but the
/// secp256k1 API insists on distinct types so private keys can't be
/// accidentally consumed by tweak APIs without an explicit conversion.
fn secret_to_scalar(sk: &SecretKey) -> Scalar {
    // SecretKey by construction is in `[1, n)`, so this never fails.
    Scalar::from_be_bytes(sk.secret_bytes()).expect("SecretKey is always a valid Scalar")
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::StdRng;
    use rand::{RngCore, SeedableRng};
    use secp256k1::Secp256k1;

    /// Deterministic test keys so failures are bisectable.
    fn test_keys(seed: u64) -> (SecretKey, SecretKey, SecretKey, [u8; 32]) {
        let mut rng = StdRng::seed_from_u64(seed);
        let secp = Secp256k1::new();
        let (seckey, _) = secp.generate_keypair(&mut rng);
        let (nonce, _) = secp.generate_keypair(&mut rng);
        let (t, _) = secp.generate_keypair(&mut rng);
        let mut msg = [0u8; 32];
        rng.fill_bytes(&mut msg);
        (seckey, nonce, t, msg)
    }

    #[test]
    fn round_trip_pre_sig_verifies() {
        let (seckey, nonce, t_sk, msg) = test_keys(0xC01CC); // "COICC"
        let secp = Secp256k1::new();
        let adaptor_pt = PublicKey::from_secret_key(&secp, &t_sk);

        let (pre_sig, signer_x) =
            create_pre_sig(&seckey, &msg, &adaptor_pt, &nonce).expect("create_pre_sig");
        verify_pre_sig(&pre_sig, &signer_x, &adaptor_pt, &msg)
            .expect("verify_pre_sig should accept a freshly-created pre-sig");
    }

    #[test]
    fn nonce_binds_secret_message_and_adaptor_point() {
        // crypto-cluster #1: the derived nonce must depend on the secret key,
        // the message, AND the adaptor point — not on aux_rand alone.
        let secp = Secp256k1::new();
        let sk = SecretKey::from_slice(&[0x11; 32]).unwrap();
        let (x, _) = PublicKey::from_secret_key(&secp, &sk).x_only_public_key();
        let t = PublicKey::from_secret_key(&secp, &SecretKey::from_slice(&[0x22; 32]).unwrap());
        let aux = [0x33u8; 32];
        let m1 = [1u8; 32];
        let m2 = [2u8; 32];

        let k = |sk: &SecretKey, aux: &[u8; 32], m: &[u8; 32], x: &XOnlyPublicKey, t: &PublicKey| {
            derive_bip340_nonce(sk, aux, m, x, t, 0)
                .unwrap()
                .secret_bytes()
        };

        let base = k(&sk, &aux, &m1, &x, &t);
        // deterministic given identical inputs (a bad RNG can't silently reuse)
        assert_eq!(base, k(&sk, &aux, &m1, &x, &t));
        // message diverges the nonce even with the SAME aux_rand
        assert_ne!(base, k(&sk, &aux, &m2, &x, &t));
        // adaptor point diverges the nonce (no pre-sig / plain-sig collision)
        let t2 = PublicKey::from_secret_key(&secp, &SecretKey::from_slice(&[0x44; 32]).unwrap());
        assert_ne!(base, k(&sk, &aux, &m1, &x, &t2));
        // secret binding: a different key yields a different nonce for the same
        // aux_rand/message — nonce secrecy no longer rests on aux_rand alone
        let sk2 = SecretKey::from_slice(&[0x55; 32]).unwrap();
        let (x2, _) = PublicKey::from_secret_key(&secp, &sk2).x_only_public_key();
        assert_ne!(base, k(&sk2, &aux, &m1, &x2, &t));
        // aux_rand still contributes entropy: changing it changes the nonce
        assert_ne!(base, k(&sk, &[0x99; 32], &m1, &x, &t));
    }

    #[test]
    fn decrypt_then_recover_yields_original_secret() {
        let (seckey, nonce, t_sk, msg) = test_keys(42);
        let secp = Secp256k1::new();
        let adaptor_pt = PublicKey::from_secret_key(&secp, &t_sk);
        let secret = AdaptorSecret::from_bytes(t_sk.secret_bytes()).unwrap();

        let (pre_sig, _signer_x) = create_pre_sig(&seckey, &msg, &adaptor_pt, &nonce).unwrap();

        // Alice decrypts using `t` she holds.
        let final_sig = decrypt_btc_adaptor(&pre_sig, &secret, &adaptor_pt).unwrap();

        // Bob, watching the chain, recovers `t` from the published sig.
        let recovered = recover_secret_from_btc_sig(&pre_sig, &final_sig).unwrap();
        assert_eq!(recovered, secret, "recovered secret must equal original");
    }

    #[test]
    fn decrypt_via_bip340_path_produces_valid_bip340_signature() {
        // The load-bearing property: a swap claim tx carries this
        // sig in its witness and Bitcoin consensus must accept it.
        // Uses the BIP-340-conformant `create_pre_sig_bip340` which
        // handles both signer-key and final-nonce parity.
        let (seckey, _ignored_nonce, t_sk, msg) = test_keys(7);
        let secp = Secp256k1::new();
        let adaptor_pt = PublicKey::from_secret_key(&secp, &t_sk);
        let secret = AdaptorSecret::from_bytes(t_sk.secret_bytes()).unwrap();
        let aux_rand = [0xaa; 32];

        let (pre_sig, signer_x) =
            create_pre_sig_bip340(&seckey, &msg, &adaptor_pt, &aux_rand).unwrap();
        let final_sig_bytes = decrypt_btc_adaptor(&pre_sig, &secret, &adaptor_pt).unwrap();

        let sig =
            secp256k1::schnorr::Signature::from_slice(&final_sig_bytes).expect("BIP-340 sig parse");
        let msg_obj = secp256k1::Message::from_digest(msg);
        secp.verify_schnorr(&sig, &msg_obj, &signer_x)
            .expect("BIP-340 verification of the decrypted sig must succeed");
    }

    #[test]
    fn bip340_path_round_trip_recovers_secret() {
        // Same round-trip property as the explicit-nonce path, but
        // through the BIP-340 conformant entry point.
        let (seckey, _ignored, t_sk, msg) = test_keys(123);
        let secp = Secp256k1::new();
        let adaptor_pt = PublicKey::from_secret_key(&secp, &t_sk);
        let secret = AdaptorSecret::from_bytes(t_sk.secret_bytes()).unwrap();
        let aux_rand = [0x55; 32];

        let (pre_sig, _signer_x) =
            create_pre_sig_bip340(&seckey, &msg, &adaptor_pt, &aux_rand).unwrap();
        let final_sig = decrypt_btc_adaptor(&pre_sig, &secret, &adaptor_pt).unwrap();
        let recovered = recover_secret_from_btc_sig(&pre_sig, &final_sig).unwrap();
        assert_eq!(recovered, secret);
    }

    #[test]
    fn bip340_path_handles_many_different_keys() {
        // The parity retry loop should converge in â‰¤8 tries with
        // overwhelming probability. Sweep 32 random seeds and
        // assert every one succeeds; if any hit the 8-retry
        // ceiling we want to know.
        let secp = Secp256k1::new();
        for seed in 0..32u64 {
            let (seckey, _, t_sk, msg) = test_keys(seed);
            let adaptor_pt = PublicKey::from_secret_key(&secp, &t_sk);
            let aux_rand = {
                let mut a = [0u8; 32];
                a[0..8].copy_from_slice(&seed.to_be_bytes());
                a
            };

            let (pre_sig, signer_x) = create_pre_sig_bip340(&seckey, &msg, &adaptor_pt, &aux_rand)
                .unwrap_or_else(|e| panic!("seed {seed} hit parity retry ceiling: {e}"));

            // Also verify the pre-sig itself is well-formed.
            verify_pre_sig(&pre_sig, &signer_x, &adaptor_pt, &msg)
                .unwrap_or_else(|e| panic!("seed {seed} verify_pre_sig failed: {e}"));
        }
    }

    #[test]
    fn verify_rejects_wrong_message() {
        let (seckey, nonce, t_sk, msg) = test_keys(99);
        let secp = Secp256k1::new();
        let adaptor_pt = PublicKey::from_secret_key(&secp, &t_sk);

        let (pre_sig, signer_x) = create_pre_sig(&seckey, &msg, &adaptor_pt, &nonce).unwrap();
        let mut bad_msg = msg;
        bad_msg[0] ^= 0x01;
        let r = verify_pre_sig(&pre_sig, &signer_x, &adaptor_pt, &bad_msg);
        assert!(r.is_err(), "verify must reject when the message changes");
    }

    #[test]
    fn verify_rejects_wrong_adaptor_point() {
        let (seckey, nonce, t_sk, msg) = test_keys(101);
        let secp = Secp256k1::new();
        let adaptor_pt = PublicKey::from_secret_key(&secp, &t_sk);

        let (pre_sig, signer_x) = create_pre_sig(&seckey, &msg, &adaptor_pt, &nonce).unwrap();

        // Different T â€” verifier supplies a wrong adaptor point.
        let mut rng = StdRng::seed_from_u64(101 ^ 0xDEAD);
        let (wrong_t, _) = secp.generate_keypair(&mut rng);
        let wrong_pt = PublicKey::from_secret_key(&secp, &wrong_t);

        let r = verify_pre_sig(&pre_sig, &signer_x, &wrong_pt, &msg);
        assert!(r.is_err(), "verify must reject when T differs");
    }

    #[test]
    fn adaptor_secret_round_trip_bytes() {
        let bytes = [
            1u8, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23,
            24, 25, 26, 27, 28, 29, 30, 31, 32,
        ];
        let s = AdaptorSecret::from_bytes(bytes).unwrap();
        assert_eq!(s.as_bytes(), &bytes);
    }

    #[test]
    fn adaptor_secret_ct_eq_returns_choice() {
        // Sanity-check both code paths through the
        // ConstantTimeEq impl: equal secrets → Choice(1);
        // different secrets → Choice(0). The actual constant-
        // time property is a code-review claim (subtle's
        // implementation is the audited primitive); this test
        // pins the correctness of our boolean-equivalence
        // wrapper.
        let mut be_a = [0x01u8; 32];
        be_a[0] = 0x01; // already canonical
        let s1 = AdaptorSecret::from_secp256k1_bytes(be_a).unwrap();
        let s2 = AdaptorSecret::from_secp256k1_bytes(be_a).unwrap();
        let s3 = {
            let mut other = be_a;
            other[31] ^= 0x01;
            AdaptorSecret::from_secp256k1_bytes(other).unwrap()
        };

        assert_eq!(s1.ct_eq(&s2).unwrap_u8(), 1, "same secret → Choice(1)");
        assert_eq!(s1.ct_eq(&s3).unwrap_u8(), 0, "different secret → Choice(0)");
        // PartialEq still returns bool and stays consistent with ct_eq.
        assert!(s1 == s2);
        assert!(s1 != s3);
    }

    #[test]
    fn adaptor_secret_equal_across_encodings() {
        // The same scalar value stored as Secp256k1BE vs.
        // RistrettoLE must compare equal. This is the property the
        // cross-curve recovery flow depends on: a secret recovered
        // from a BTC sig (BE-tagged) must compare equal to the
        // original secret (LE-tagged) by value.
        let mut be = [
            0x01, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
            0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
            0xaa, 0xaa, 0xaa, 0xaa,
        ];
        // Make it Ristretto-canonical (mask top bit). The exact
        // value doesn't matter; we just need it < ℓ.
        be[0] = 0x01;
        let mut le = be;
        le.reverse();
        let s_be = AdaptorSecret::from_secp256k1_bytes(be).unwrap();
        let s_le = AdaptorSecret::from_ristretto_bytes(le).unwrap();
        assert_eq!(
            s_be, s_le,
            "same scalar value must compare equal across encodings"
        );
        assert_ne!(
            s_be.encoding(),
            s_le.encoding(),
            "but the encoding tags differ"
        );
    }

    #[test]
    fn adaptor_secret_rejects_zero() {
        let zero = [0u8; 32];
        assert!(
            AdaptorSecret::from_bytes(zero).is_err(),
            "zero scalar must be rejected (would produce a known-bad keypair)"
        );
    }

    // â”€â”€ CYNC side (Ristretto255) â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    fn test_cync_keys(seed: u64) -> ([u8; 32], [u8; 32], [u8; 32], [u8; 32]) {
        let mut rng = StdRng::seed_from_u64(seed ^ 0xCC0FCC);
        let mut sk = [0u8; 32];
        let mut nonce = [0u8; 32];
        let mut t = [0u8; 32];
        let mut msg = [0u8; 32];
        // Curve25519 scalars must be canonical (< â„“). The cleanest
        // way to get a canonical random scalar without pulling in
        // dalek's RNG trait wiring is to mask off the top three
        // bits + fold: matches the construction Ed25519 uses for
        // private-key derivation. For these tests we use the
        // standard Scalar::from_bytes_mod_order over 32 random bytes
        // â€” guaranteed canonical, slight non-uniformity at the top
        // of the field is irrelevant for a test fixture.
        rng.fill_bytes(&mut sk);
        rng.fill_bytes(&mut nonce);
        rng.fill_bytes(&mut t);
        rng.fill_bytes(&mut msg);
        let canonical = |bytes: [u8; 32]| Curve25519Scalar::from_bytes_mod_order(bytes).to_bytes();
        (canonical(sk), canonical(nonce), canonical(t), msg)
    }

    #[test]
    fn cync_round_trip_pre_sig_verifies() {
        let (sk, nonce, t_bytes, msg) = test_cync_keys(0xC01CC);
        let secret = AdaptorSecret::from_ristretto_bytes(t_bytes).unwrap();
        let adaptor_pt = cync_adaptor_point(&secret).unwrap();

        let (pre_sig, signer_pub) = cync_create_pre_sig(&sk, &msg, &adaptor_pt, &nonce).unwrap();
        cync_verify_pre_sig(&pre_sig, &signer_pub, &adaptor_pt, &msg)
            .expect("CYNC pre-sig should verify");
    }

    #[test]
    fn cync_decrypt_then_recover_yields_original_secret() {
        let (sk, nonce, t_bytes, msg) = test_cync_keys(0xBEEF);
        let secret = AdaptorSecret::from_ristretto_bytes(t_bytes).unwrap();
        let adaptor_pt = cync_adaptor_point(&secret).unwrap();

        let (pre_sig, _signer_pub) = cync_create_pre_sig(&sk, &msg, &adaptor_pt, &nonce).unwrap();

        let final_sig = cync_decrypt_adaptor(&pre_sig, &secret, &adaptor_pt).unwrap();
        let recovered = cync_recover_secret(&pre_sig, &final_sig).unwrap();
        assert_eq!(
            recovered, secret,
            "recovered CYNC secret must equal original"
        );
    }

    #[test]
    fn cync_verify_rejects_wrong_message() {
        let (sk, nonce, t_bytes, msg) = test_cync_keys(33);
        let secret = AdaptorSecret::from_ristretto_bytes(t_bytes).unwrap();
        let adaptor_pt = cync_adaptor_point(&secret).unwrap();

        let (pre_sig, signer_pub) = cync_create_pre_sig(&sk, &msg, &adaptor_pt, &nonce).unwrap();
        let mut bad_msg = msg;
        bad_msg[31] ^= 0x80;
        let r = cync_verify_pre_sig(&pre_sig, &signer_pub, &adaptor_pt, &bad_msg);
        assert!(r.is_err(), "CYNC verify must reject when msg changes");
    }

    #[test]
    fn cync_verify_rejects_wrong_adaptor_point() {
        let (sk, nonce, t_bytes, msg) = test_cync_keys(77);
        let secret = AdaptorSecret::from_ristretto_bytes(t_bytes).unwrap();
        let adaptor_pt = cync_adaptor_point(&secret).unwrap();

        let (pre_sig, signer_pub) = cync_create_pre_sig(&sk, &msg, &adaptor_pt, &nonce).unwrap();

        // Synthesize a different T from a fresh secret.
        let (_, _, wrong_t, _) = test_cync_keys(78);
        let wrong_secret = AdaptorSecret::from_ristretto_bytes(wrong_t).unwrap();
        let wrong_pt = cync_adaptor_point(&wrong_secret).unwrap();

        let r = cync_verify_pre_sig(&pre_sig, &signer_pub, &wrong_pt, &msg);
        assert!(r.is_err(), "CYNC verify must reject when T differs");
    }

    #[test]
    fn cync_adaptor_point_matches_secret() {
        // Smoke-check: deriving T from the secret and then deriving
        // a fresh T from the same bytes should produce identical
        // output. (Catches a future change that accidentally
        // randomises T derivation.)
        let secret = AdaptorSecret::from_ristretto_bytes([
            0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42,
            0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42,
            0x42, 0x42, 0x42, 0x02,
        ])
        .unwrap();
        let pt1 = cync_adaptor_point(&secret).unwrap();
        let pt2 = cync_adaptor_point(&secret).unwrap();
        assert_eq!(pt1, pt2, "adaptor point derivation must be deterministic");
    }
}
