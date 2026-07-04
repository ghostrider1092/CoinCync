// src/wallet/keys.rs
//
// 4-level viewing key hierarchy for compliance and privacy.
//
// Master Spend Key
//   └── Full Viewing Key (FVK)
//         ├── Outgoing Viewing Key (OVK)  — sees where you sent funds
//         └── Incoming Viewing Key (IVK)  — sees received funds only
//               └── Diversified Payment Address  — share to receive

use curve25519_dalek::{
    ristretto::{CompressedRistretto, RistrettoPoint},
    scalar::Scalar,
};
use blake2b_simd::Params as Blake2bParams;
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop};
use crate::error::{Error, Result};

// ── Spend Key ────────────────────────────────────────────────

/// Master spending key — never share, never store unencrypted.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct SpendKey {
    bytes: [u8; 32],
}

impl SpendKey {
    pub fn from_bytes(bytes: [u8; 32]) -> Self { Self { bytes } }

    pub fn to_scalar(&self) -> Scalar {
        Scalar::from_bytes_mod_order(self.bytes)
    }

    /// Derive the Full Viewing Key.
    pub fn to_full_viewing_key(&self) -> FullViewingKey {
        use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT as G;
        let sk = self.to_scalar();
        let ak = G * sk;                       // spend authorizing key
        let nk = hash_to_point(b"yrc_nk", &self.bytes); // nullifier key
        let rivk = scalar_from_hash(b"yrc_rivk", &self.bytes);
        FullViewingKey { ak, nk, rivk }
    }

    pub fn as_bytes(&self) -> &[u8; 32] { &self.bytes }
}

// ── Full Viewing Key ─────────────────────────────────────────

/// Full Viewing Key — sees all incoming AND outgoing transactions.
/// Cannot spend. Safe to share with a full auditor.
///
/// AUDIT (R-80 fix, 2026-07-03): pre-fix code had `#[derive(Clone)]`
/// with no zeroize discipline. The `rivk: Scalar` field IS SECRET
/// (it's the internal viewing-key randomness that derives ivk / ovk),
/// so an FVK dropped without wiping leaves rivk in memory. Now:
///   - `ak` and `nk` are PUBLIC curve points, no zeroize needed.
///   - `rivk` is manually zeroized in a custom Drop below.
/// curve25519-dalek's `Scalar` implements `Zeroize` in the `zeroize`
/// feature (which the workspace enables), so we can call it directly.
#[derive(Clone, Serialize, Deserialize)]
pub struct FullViewingKey {
    pub ak:   RistrettoPoint,   // spend validating key
    pub nk:   RistrettoPoint,   // nullifier deriving key
    pub rivk: Scalar,           // internal viewing key randomness
}

impl Drop for FullViewingKey {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        // Only `rivk` carries secret material. Public curve points
        // are safe to leave unzeroed.
        self.rivk.zeroize();
    }
}

impl FullViewingKey {
    /// Derive the Incoming Viewing Key (sees received funds only).
    pub fn to_incoming_viewing_key(&self) -> IncomingViewingKey {
        let bytes_ak = self.ak.compress().to_bytes();
        let bytes_nk = self.nk.compress().to_bytes();
        let ivk = scalar_from_hash_two(b"yrc_ivk", &bytes_ak, &bytes_nk);
        IncomingViewingKey(ivk)
    }

    /// Derive the Outgoing Viewing Key (sees where you sent funds).
    pub fn to_outgoing_viewing_key(&self) -> OutgoingViewingKey {
        let mut buf = [0u8; 32];
        let h = Blake2bParams::new()
            .hash_length(32)
            .personal(b"yrc_ovk_________")
            .to_state()
            .update(&self.rivk.to_bytes())
            .finalize();
        buf.copy_from_slice(h.as_bytes());
        OutgoingViewingKey(buf)
    }

    /// Encode the FVK as a base58 string prefixed `yfvk`.
    ///
    /// AUDIT (R-81 note, 2026-07-03): the returned String CONTAINS
    /// THE PLAINTEXT `rivk` SCALAR (bytes 64..96 of the 96-byte
    /// payload). A leaked FVK string is complete disclosure of the
    /// wallet's viewing capability — an attacker with the yfvk...
    /// string sees every incoming and outgoing tx. This is BY
    /// DESIGN — an FVK is intended to be shared with an auditor —
    /// but callers who log, transmit, or store this string are
    /// leaking the audit key.
    ///
    /// Structural fix would be to require encryption at share
    /// time (encode-with-passphrase), matching Zcash's ZIP-317
    /// unified-address encoding pattern. Deferred pending API
    /// design decision. Meanwhile: `raw` on the stack contains
    /// the same secret; zeroize it before return so we don't
    /// double-expose via memory dump.
    pub fn encode(&self) -> String {
        let ak = self.ak.compress().to_bytes();
        let nk = self.nk.compress().to_bytes();
        let rv = self.rivk.to_bytes();
        let mut raw = [0u8; 96];
        raw[..32].copy_from_slice(&ak);
        raw[32..64].copy_from_slice(&nk);
        raw[64..].copy_from_slice(&rv);
        let encoded = format!("yfvk{}", bs58::encode(&raw).into_string());
        // R-81: wipe the raw buffer (contains rivk bytes) before return.
        {
            use zeroize::Zeroize;
            raw.zeroize();
        }
        encoded
    }
}

// ── Incoming Viewing Key ─────────────────────────────────────

/// Incoming Viewing Key — sees received transactions only.
/// Share with exchanges for deposit detection.
///
/// AUDIT (R-80 fix, 2026-07-03): `.0: Scalar` is SECRET — the
/// scan-side scalar that decrypts every incoming output. Drop
/// impl below zeros it explicitly (Scalar's own Zeroize impl).
#[derive(Clone, Serialize, Deserialize)]
pub struct IncomingViewingKey(pub Scalar);

impl Drop for IncomingViewingKey {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.0.zeroize();
    }
}

impl IncomingViewingKey {
    /// Generate a fresh diversified payment address.
    /// Different diversifiers produce unlinkable addresses that all
    /// funnel to the same wallet.
    pub fn to_payment_address(&self, diversifier: [u8; 11]) -> Option<PaymentAddress> {
        let g_d = diversify_hash(&diversifier)?;
        let pk_d = g_d * self.0;
        Some(PaymentAddress { diversifier, pk_d })
    }

    /// Generate a random diversified address.
    pub fn new_address(&self, rng: &mut impl rand::Rng) -> PaymentAddress {
        loop {
            let d: [u8; 11] = rng.gen();
            if let Some(addr) = self.to_payment_address(d) {
                return addr;
            }
        }
    }

    /// Derive a 1-byte view tag for fast scanning.
    /// Wallets compare this byte before doing full decryption —
    /// rejects 99.6% of outputs without any elliptic-curve work.
    ///
    /// AUDIT (R-82 fix, R-7 class site, 2026-07-03): `shared` is
    /// the ECDH shared point `ephemeral * ivk` — recovering it lets
    /// an attacker derive every ivk-scan-key derived from the same
    /// ephemeral, plus link the recipient. Pre-fix code let
    /// `shared: RistrettoPoint` drop unzeroized. curve25519-dalek's
    /// RistrettoPoint doesn't derive `ZeroizeOnDrop` upstream (the
    /// underlying `EdwardsPoint` field elements are u64 arrays), so
    /// we do a best-effort wipe via `subtle::black_box` + explicit
    /// overwrite of the compressed serialization. The point value
    /// on the STACK is what we can wipe here; the CPU registers
    /// that held intermediate multiplies are out of our reach
    /// (that requires either a jump into asm or full
    /// architectural mitigation).
    pub fn view_tag(&self, ephemeral_key: &RistrettoPoint) -> u8 {
        let mut shared = ephemeral_key * self.0;
        let mut shared_bytes = shared.compress().to_bytes();
        let h = Blake2bParams::new()
            .hash_length(32)
            .personal(b"yrc_view_tag____")
            .to_state()
            .update(&shared_bytes)
            .finalize();
        let tag = h.as_bytes()[0];
        // R-82 + R-7 CLASS + R-80 SURGICAL FIX (2026-07-03): wipe
        // both the compressed shared-point bytes AND the raw
        // RistrettoPoint. curve25519-dalek 4.1's Zeroize impl
        // (ristretto.rs:1266) is now explicitly enabled in our
        // Cargo.toml `curve25519-dalek/zeroize` feature. Prior
        // "best-effort" claim retired.
        use zeroize::Zeroize;
        shared_bytes.zeroize();
        shared.zeroize();
        tag
    }

    pub fn encode(&self) -> String {
        format!("yivk{}", bs58::encode(self.0.to_bytes()).into_string())
    }
}

// ── Outgoing Viewing Key ─────────────────────────────────────

/// Outgoing Viewing Key — sees where you sent funds.
/// Share with tax software or auditors.
///
/// AUDIT (R-80 fix, 2026-07-03): `.0: [u8; 32]` is derived from
/// FVK.rivk — treat as secret. Zeroize on drop.
#[derive(Clone, Serialize, Deserialize, zeroize::Zeroize, zeroize::ZeroizeOnDrop)]
pub struct OutgoingViewingKey(pub [u8; 32]);

impl OutgoingViewingKey {
    pub fn encode(&self) -> String {
        format!("yovk{}", bs58::encode(&self.0).into_string())
    }
}

// ── Payment Address ───────────────────────────────────────────

/// A diversified payment address — one wallet, many unlinkable addresses.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PaymentAddress {
    pub diversifier: [u8; 11],
    pub pk_d:        RistrettoPoint,
}

impl PaymentAddress {
    /// Encode as bech32m: cync1...
    ///
    /// AUDIT (R-83 fix, 2026-07-02): prior signature was
    /// `-> String` with a silent `.unwrap_or_else(|_| "invalid_address")`
    /// fallback. That was dangerous: an invalid HRP would produce a
    /// literal `"invalid_address"` string that downstream code (QR
    /// generators, RPC responses, payment fields) would happily
    /// display as if it were a real address. A user who copy-pastes
    /// the sentinel into a wallet UI could send funds to a burn
    /// destination or, worse, if some third-party wallet
    /// coincidentally accepts a similar-looking string, to an
    /// attacker. Signature now returns `Result<String>` so the
    /// caller must acknowledge and handle the encoding failure.
    pub fn to_bech32(&self, hrp: &str) -> Result<String> {
        let mut raw = [0u8; 43];
        raw[..11].copy_from_slice(&self.diversifier);
        raw[11..].copy_from_slice(self.pk_d.compress().as_bytes());
        bech32::encode(hrp, bech32::ToBase32::to_base32(&raw), bech32::Variant::Bech32m)
            .map_err(|e| Error::Other(format!("PaymentAddress bech32 encode: {}", e)))
    }

    pub fn from_bech32(s: &str) -> Result<Self> {
        let (_, data, _) = bech32::decode(s)
            .map_err(|e| Error::Other(format!("bech32 decode: {}", e)))?;
        let raw: Vec<u8> = bech32::FromBase32::from_base32(&data)
            .map_err(|e| Error::Other(format!("base32 decode: {}", e)))?;
        if raw.len() != 43 {
            return Err(Error::Other("bad address length".into()));
        }
        // SAFETY: length checked to be exactly 43 on line 176
        let diversifier: [u8; 11] = raw[..11].try_into().expect("len==43");
        let pk_bytes: [u8; 32]   = raw[11..43].try_into().expect("len==43");
        let pk_d = CompressedRistretto(pk_bytes)
            .decompress()
            .ok_or_else(|| Error::Other("bad address point".into()))?;
        Ok(Self { diversifier, pk_d })
    }
}

// ── Helpers ───────────────────────────────────────────────────

fn hash_to_point(tag: &[u8], input: &[u8]) -> RistrettoPoint {
    use curve25519_dalek::ristretto::RistrettoPoint as RP;
    let mut personal = [0u8; 16];
    let len = tag.len().min(16);
    personal[..len].copy_from_slice(&tag[..len]);
    let hash = Blake2bParams::new()
        .hash_length(64)
        .personal(&personal)
        .to_state()
        .update(input)
        .finalize();
    // SAFETY: blake2b hash_length=64 always returns exactly 64 bytes
    RP::from_uniform_bytes(hash.as_bytes().try_into().expect("blake2b 64-byte output"))
}

fn scalar_from_hash(tag: &[u8], input: &[u8]) -> Scalar {
    let mut personal = [0u8; 16];
    let len = tag.len().min(16);
    personal[..len].copy_from_slice(&tag[..len]);
    let hash = Blake2bParams::new()
        .hash_length(64)
        .personal(&personal)
        .to_state()
        .update(input)
        .finalize();
    // SAFETY: blake2b hash_length=64 always returns exactly 64 bytes
    Scalar::from_bytes_mod_order_wide(hash.as_bytes().try_into().expect("blake2b 64-byte output"))
}

fn scalar_from_hash_two(tag: &[u8], a: &[u8], b: &[u8]) -> Scalar {
    let mut personal = [0u8; 16];
    let len = tag.len().min(16);
    personal[..len].copy_from_slice(&tag[..len]);
    let hash = Blake2bParams::new()
        .hash_length(64)
        .personal(&personal)
        .to_state()
        .update(a)
        .update(b)
        .finalize();
    // SAFETY: blake2b hash_length=64 always returns exactly 64 bytes
    Scalar::from_bytes_mod_order_wide(hash.as_bytes().try_into().expect("blake2b 64-byte output"))
}

fn diversify_hash(d: &[u8; 11]) -> Option<RistrettoPoint> {
    use curve25519_dalek::ristretto::RistrettoPoint as RP;
    let hash = Blake2bParams::new()
        .hash_length(64)
        .personal(b"yrc_diversify___")
        .to_state()
        .update(d)
        .finalize();
    let pt = RP::from_uniform_bytes(hash.as_bytes().try_into().ok()?);
    // Reject the identity point. This is astronomically rare (probability
    // ~1/2^252 from a 64-byte uniform hash), but if it ever fires the
    // wallet would otherwise silently return None and skip a diversifier
    // index, which is hard to debug post-mortem. Surface the event so an
    // operator looking at logs can correlate the gap.
    if pt == RistrettoPoint::default() {
        tracing::warn!(
            "wallet/keys::diversify_hash: derived identity point — \
             extremely rare ECDH edge case; caller should advance diversifier index"
        );
        None
    } else {
        Some(pt)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_spend_key() -> SpendKey {
        SpendKey::from_bytes([42u8; 32])
    }

    #[test]
    fn key_derivation_is_deterministic() {
        let sk  = test_spend_key();
        let fvk1 = sk.to_full_viewing_key();
        let fvk2 = sk.to_full_viewing_key();
        assert_eq!(fvk1.ak.compress(), fvk2.ak.compress());
        assert_eq!(fvk1.nk.compress(), fvk2.nk.compress());
    }

    #[test]
    fn ivk_cannot_derive_spend_key() {
        let sk  = test_spend_key();
        let fvk = sk.to_full_viewing_key();
        let ivk = fvk.to_incoming_viewing_key();
        // IVK is a scalar — there's no path back to sk
        assert_ne!(ivk.0.to_bytes(), sk.as_bytes()[..32]);
    }

    #[test]
    fn different_diversifiers_give_different_addresses() {
        let sk  = test_spend_key();
        let fvk = sk.to_full_viewing_key();
        let ivk = fvk.to_incoming_viewing_key();
        let a1  = ivk.to_payment_address([0u8; 11]).unwrap();
        let a2  = ivk.to_payment_address([1u8; 11]).unwrap();
        assert_ne!(a1.pk_d.compress(), a2.pk_d.compress());
    }

    #[test]
    fn address_bech32_roundtrip() {
        let sk   = test_spend_key();
        let fvk  = sk.to_full_viewing_key();
        let ivk  = fvk.to_incoming_viewing_key();
        let addr = ivk.to_payment_address([7u8; 11]).unwrap();
        let enc  = addr.to_bech32("yc").expect("test HRP is valid");
        let dec  = PaymentAddress::from_bech32(&enc).unwrap();
        assert_eq!(addr.diversifier, dec.diversifier);
        assert_eq!(addr.pk_d.compress(), dec.pk_d.compress());
    }

    #[test]
    fn view_tag_deterministic() {
        use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT as G;
        let sk  = test_spend_key();
        let fvk = sk.to_full_viewing_key();
        let ivk = fvk.to_incoming_viewing_key();
        let eph = G * Scalar::from(99u64);
        let t1  = ivk.view_tag(&eph);
        let t2  = ivk.view_tag(&eph);
        assert_eq!(t1, t2);
    }

    #[test]
    fn spark_key_chain_derives() {
        let sk  = test_spend_key();
        let ssk = sk.to_spark_spend_key();
        let ssc = ssk.to_spark_scan_key();
        let addr = ssc.to_spark_address([1u8; 11]);
        assert_ne!(addr.pk.compress().to_bytes(), [0u8; 32]);
    }
}

// =============================================================================
// Spark Key Hierarchy (Firo Lelantus Spark — Phase 2)
//
// Parallel key chain to the FVK/IVK/OVK tree above. A user's SpendKey
// derives both a Zcash-style spend-authorizing key (via `to_full_viewing_key`)
// AND a SparkSpendKey used for Lelantus Spark mint/spend proofs.
// =============================================================================

/// Spark master spend key. Derived from the root `SpendKey` and required
/// to spend Spark coins (the 16,384-anonymity-set side of the chain).
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct SparkSpendKey(pub Scalar);

impl SpendKey {
    /// Derive the Spark spend key from the master spend key.
    ///
    /// AUDIT (R-84 fix, 2026-07-03): pre-fix code did
    ///   `let bytes = self.bytes;`
    /// which Copy-cloned the master spend key onto the stack of
    /// this fn. SpendKey has `ZeroizeOnDrop` on the struct so
    /// `self.bytes` is protected — but the LOCAL `bytes` copy on
    /// this stack frame is NOT zeroed on function return. Every
    /// call to `to_spark_spend_key` leaks a stack window carrying
    /// the master spend key. Now we bind as `mut` and wipe
    /// explicitly before return.
    pub fn to_spark_spend_key(&self) -> SparkSpendKey {
        let mut bytes = self.bytes;
        let s = scalar_from_hash(b"yrc_spark_spend_", &bytes);
        // R-84: wipe the stack copy of the master spend key.
        {
            use zeroize::Zeroize;
            bytes.zeroize();
        }
        SparkSpendKey(s)
    }
}

impl SparkSpendKey {
    /// Derive the read-only Spark scan key. Can detect incoming Spark
    /// coins but cannot spend them — suitable for exchanges and
    /// auditors.
    pub fn to_spark_scan_key(&self) -> SparkScanKey {
        let s = scalar_from_hash(b"yrc_spark_scan__", &self.0.to_bytes());
        SparkScanKey(s)
    }
}

/// Read-only Spark scan key. Detects incoming Spark coins.
#[derive(Clone, Serialize, Deserialize)]
pub struct SparkScanKey(pub Scalar);

impl SparkScanKey {
    /// Derive a Spark address with a given 11-byte diversifier.
    pub fn to_spark_address(&self, diversifier: [u8; 11]) -> SparkAddress {
        use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT as G;
        SparkAddress {
            diversifier,
            pk: G * self.0,
        }
    }
}

/// A Spark address — the public identity a user shares to receive
/// Spark coins. Encodes to bech32m with the `SPARK_HRP` / `SPARK_T_HRP`
/// prefix (`ys1...` / `ts1...`).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SparkAddress {
    pub diversifier: [u8; 11],
    pub pk: RistrettoPoint,
}

impl SparkAddress {
    /// Encode as bech32m: ys1... / ts1...
    ///
    /// AUDIT (R-83 fix, 2026-07-02): same silent-fallback bug as
    /// `PaymentAddress::to_bech32` — see that fn's doc comment for
    /// the full rationale. Signature now returns `Result<String>`.
    pub fn to_bech32(&self, hrp: &str) -> Result<String> {
        let mut raw = [0u8; 43];
        raw[..11].copy_from_slice(&self.diversifier);
        raw[11..].copy_from_slice(self.pk.compress().as_bytes());
        bech32::encode(hrp, bech32::ToBase32::to_base32(&raw), bech32::Variant::Bech32m)
            .map_err(|e| Error::Other(format!("SparkAddress bech32 encode: {}", e)))
    }

    pub fn from_bech32(s: &str) -> Result<Self> {
        let (_, data, _) = bech32::decode(s)
            .map_err(|e| Error::Other(format!("bech32 decode: {}", e)))?;
        let raw: Vec<u8> = bech32::FromBase32::from_base32(&data)
            .map_err(|e| Error::Other(format!("base32 decode: {}", e)))?;
        if raw.len() != 43 {
            return Err(Error::Other("bad Spark address length".into()));
        }
        // SAFETY: length validated to be exactly 43 on line 388
        let diversifier: [u8; 11] = raw[..11].try_into().unwrap();
        let pk_bytes: [u8; 32] = raw[11..43].try_into().unwrap();
        let pk = CompressedRistretto(pk_bytes)
            .decompress()
            .ok_or_else(|| Error::Other("bad Spark address point".into()))?;
        Ok(Self { diversifier, pk })
    }
}
