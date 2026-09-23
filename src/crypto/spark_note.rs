//! The **Note Connector** — the stealth ⇄ bound-coin translator.
//!
//! See `docs/design/cip-shielded-notes.md`. This is the connector that closes
//! the wallet ⇄ flagship gap: a bound coin `C = v·Gv + s·H + r·K`
//! ([`crate::crypto::groth_kohlweiss::bound_coin_commitment`]) has no
//! key-derived opening, so the wallet's scan key cannot detect or recover its
//! own coins. The connector derives the opening deterministically from a
//! stealth ECDH shared secret, in the same family as the bulletproof⇄Spark
//! "talking connector" ([`crate::crypto::spark_range::CommitmentBridge`]).
//!
//! # One shared rail (the anti-drift guarantee)
//!
//! Both directions traverse the **same** [`derive_note`] function:
//!
//! * `create` (sender): `ss = ECDH(e, Q_scan)` → `derive_note(ss, Q_spend)` →
//!   publish `(C, R, enc_value, view_tag)`.
//! * `scan` (recipient): `ss = ECDH(scan_secret, R)` → the **same**
//!   `derive_note` → recompute `C'` and accept iff `C' == C`.
//!
//! Because scan runs the identical rail as create, detection is the exact
//! inverse of creation *by construction* — the "wallet can't find its own coin"
//! / "recomputed C ≠ tree C" bug class is designed out, not tested against.
//!
//! # scan ≠ spend is a TYPE property
//!
//! The connector emits only the value-recovering half — [`RecoveredNote`], which
//! **carries no nullifier and no spend witness**. Spend authority binds
//! [`SparkSpendKey`]-equivalent secret material on a separate rail: the coin's
//! serial is `s_full = s_pub + spend_secret`, so a view-only holder (scan secret
//! + *public* `Q_spend`) recovers the value but cannot compute `s_full`, hence
//! cannot spend. The view-key-steals-funds class is closed at the type boundary.
//!
//! # Status
//!
//! Gated `sketch-gk-proof`, **unaudited**, unwired. The detection/recovery
//! envelope here is the audited transparent stealth pattern
//! (`wallet/lightsync.rs`: `compute_shared_secret_light` / `decrypt_amount_light`
//! / `compute_view_tag_light`) pointed at the Spark basis. The **nullifier ↔
//! spend-secret binding** (the spend rail) is deliberately NOT in this file — it
//! is the audit-critical fill-in pinned to the Lelantus-Spark paper.

use crate::crypto::peer_scalars::PeerPoint;
use crate::crypto::spark_generators::{gen_gv, gen_h, gen_k};
use crate::error::Result;
use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use rand::{CryptoRng, RngCore};
use sha3::{Digest, Sha3_256, Sha3_512};
use subtle::ConstantTimeEq;

/// The base generator for address/scan keys (`Q_scan = scan_secret·G`). Distinct
/// from the coin generators `Gv, H, K`; this is the "G for keys".
#[inline]
fn key_base() -> RistrettoPoint {
    RISTRETTO_BASEPOINT_POINT
}

// ---------------------------------------------------------------------------
// Address & keys (seam-local; unified with wallet/keys.rs SparkAddress /
// SparkScanKey in the wiring step — see CIP §"Address").
// ---------------------------------------------------------------------------

/// A two-point ("diversified") shielded address: detection key + spend-authority
/// key. The extension of the wallet's single-point `SparkAddress` that the CIP
/// calls for so that *detect* and *spend* separate.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SparkAddr2 {
    /// Diversifier (distinct-looking addresses under one scan key).
    pub diversifier: [u8; 11],
    /// `Q_scan = scan_secret·G` — the incoming-view / detection key.
    pub q_scan: [u8; 32],
    /// `Q_spend = spend_secret·H` — the spend-authority key, in the coin's
    /// serial basis so it slots into `s_full·H = s_pub·H + Q_spend`.
    pub q_spend: [u8; 32],
}

impl SparkAddr2 {
    /// Build an address from raw secrets (test / wiring helper). In the wallet
    /// these come from the `SparkScanKey` / `SparkSpendKey` chain.
    pub fn from_secrets(diversifier: [u8; 11], scan_secret: &Scalar, spend_secret: &Scalar) -> Self {
        let q_scan = (key_base() * scan_secret).compress().to_bytes();
        let q_spend = (gen_h() * spend_secret).compress().to_bytes();
        SparkAddr2 { diversifier, q_scan, q_spend }
    }
}

/// The scan-side key material: the incoming-view secret plus the *public*
/// spend-authority point. A holder of this can detect + recover value but has no
/// `spend_secret`, so cannot spend — this is the view-only capability.
#[derive(Clone, Debug)]
pub struct NoteScanKey {
    /// Incoming-view secret (`Q_scan = scan_secret·G`).
    pub scan_secret: Scalar,
    /// The owner's *public* spend key `Q_spend` (needed to recompute the coin).
    pub q_spend: [u8; 32],
}

impl NoteScanKey {
    /// View-only key from the scan secret and the public spend point.
    pub fn new(scan_secret: Scalar, q_spend: [u8; 32]) -> Self {
        NoteScanKey { scan_secret, q_spend }
    }
}

// ---------------------------------------------------------------------------
// Wire & recovered types
// ---------------------------------------------------------------------------

/// The published note that travels with a transaction and pins a tree coin.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "sketch-gk-proof", derive(borsh::BorshSerialize, borsh::BorshDeserialize))]
pub struct PublishedNote {
    /// The bound coin `C` appended to the shielded tree (compressed Ristretto).
    pub coin: [u8; 32],
    /// Ephemeral tx public `R = e·G` (compressed Ristretto).
    pub tx_public: [u8; 32],
    /// Amount encrypted with the derived pad: `enc = value.to_le_bytes() ⊕ pad`.
    pub enc_value: [u8; 8],
    /// 1-byte detection tag — the Stage-1 O(1) filter (see `derive_note`).
    pub view_tag: u8,
}

/// What a scan yields on a match: the **value-recovering** opening only.
/// Deliberately carries no nullifier / spend witness — see module docs.
#[derive(Clone, Debug)]
pub struct RecoveredNote {
    /// Recovered amount.
    pub value: u64,
    /// Coin blinding `r` (for `C = v·Gv + s·H + r·K`).
    pub coin_blinding: Scalar,
    /// Value-commitment blinding `b` (for the balance `V = v·Gv + b·K`).
    pub value_blinding: Scalar,
    /// The scan-derivable part of the serial. The *spendable* serial is
    /// `s_pub + spend_secret` — recovering that needs the spend secret this
    /// type does not carry.
    pub serial_public: Scalar,
}

/// The intermediate secrets the shared rail produces from a shared secret.
struct NoteSecrets {
    coin_blinding: Scalar, // r
    value_blinding: Scalar, // b
    serial_public: Scalar, // s_pub
    amount_pad: [u8; 8],
    view_tag: u8,
}

// ---------------------------------------------------------------------------
// Crypto rails
// ---------------------------------------------------------------------------

/// ECDH shared secret, hashed with domain separation (never the raw point bytes).
/// Sender calls `ecdh(e, Q_scan)`; recipient calls `ecdh(scan_secret, R)` —
/// both equal `e·scan_secret·G`.
fn ecdh_shared_secret(secret: &Scalar, public: &RistrettoPoint) -> [u8; 32] {
    let shared = (secret * public).compress();
    let mut h = Sha3_256::new();
    h.update(b"COINCYNC_NOTE_ECDH_v1");
    h.update(shared.as_bytes());
    h.finalize().into()
}

/// Hash-to-scalar over `domain ‖ ss ‖ extra` (wide reduction, uniform).
fn hash_to_scalar(domain: &[u8], ss: &[u8; 32], extra: &[u8]) -> Scalar {
    let mut h = Sha3_512::new();
    h.update(domain);
    h.update(ss);
    h.update(extra);
    let mut wide = [0u8; 64];
    wide.copy_from_slice(&h.finalize());
    Scalar::from_bytes_mod_order_wide(&wide)
}

/// The single rail both `create` and `scan` traverse. Given the shared secret
/// and the recipient's public spend key, derive every per-note secret
/// deterministically. This function IS the connector's anti-drift guarantee.
fn derive_note(ss: &[u8; 32], q_spend: &[u8; 32]) -> NoteSecrets {
    let coin_blinding = hash_to_scalar(b"COINCYNC_NOTE_r_v1", ss, &[]);
    let value_blinding = hash_to_scalar(b"COINCYNC_NOTE_b_v1", ss, &[]);
    // s_pub binds Q_spend, so the serial (and thus the coin) is addressed to a
    // specific spend key — see CIP §"Note creation" step 4.
    let serial_public = hash_to_scalar(b"COINCYNC_NOTE_s_v1", ss, q_spend);

    let mut ph = Sha3_256::new();
    ph.update(b"COINCYNC_NOTE_amt_v1");
    ph.update(ss);
    let pad_full: [u8; 32] = ph.finalize().into();
    let mut amount_pad = [0u8; 8];
    amount_pad.copy_from_slice(&pad_full[..8]);

    let mut th = Sha3_256::new();
    th.update(b"COINCYNC_NOTE_tag_v1");
    th.update(ss);
    let view_tag = <[u8; 32]>::from(th.finalize())[0];

    NoteSecrets { coin_blinding, value_blinding, serial_public, amount_pad, view_tag }
}

/// The bound coin a note pins: `C = v·Gv + s_pub·H + Q_spend + r·K`. Note the
/// serial term is `s_pub·H + Q_spend = (s_pub + spend_secret)·H`, so the coin's
/// effective serial is `s_full = s_pub + spend_secret` — computable in full only
/// by the holder of `spend_secret`.
fn note_coin(value: u64, secrets: &NoteSecrets, q_spend: &RistrettoPoint) -> RistrettoPoint {
    gen_gv() * Scalar::from(value)
        + gen_h() * secrets.serial_public
        + q_spend
        + gen_k() * secrets.coin_blinding
}

#[inline]
fn xor8(value: u64, pad: &[u8; 8]) -> [u8; 8] {
    let v = value.to_le_bytes();
    let mut out = [0u8; 8];
    for i in 0..8 {
        out[i] = v[i] ^ pad[i];
    }
    out
}

// ---------------------------------------------------------------------------
// The connector
// ---------------------------------------------------------------------------

/// The stealth ⇄ bound-coin connector. `create` and `scan` share [`derive_note`].
pub trait NoteConnector {
    /// Sender rail: address + value → a published note pinning a fresh coin.
    fn create<R: CryptoRng + RngCore>(
        &self,
        addr: &SparkAddr2,
        value: u64,
        rng: &mut R,
    ) -> Result<PublishedNote>;

    /// Recipient rail: scan key + published note → recovered opening iff owned.
    /// `None` for a non-owned note (Stage-1 tag miss or Stage-2 coin mismatch).
    fn scan(&self, key: &NoteScanKey, note: &PublishedNote) -> Option<RecoveredNote>;
}

/// The concrete connector for CoinCync bound coins.
pub struct SparkNoteConnector;

impl NoteConnector for SparkNoteConnector {
    fn create<R: CryptoRng + RngCore>(
        &self,
        addr: &SparkAddr2,
        value: u64,
        rng: &mut R,
    ) -> Result<PublishedNote> {
        let q_scan = PeerPoint::decode_non_identity(addr.q_scan)?.into_point();
        let q_spend = PeerPoint::decode_non_identity(addr.q_spend)?.into_point();

        let e = Scalar::random(rng);
        let tx_public = (key_base() * e).compress().to_bytes();
        let ss = ecdh_shared_secret(&e, &q_scan);
        let secrets = derive_note(&ss, &addr.q_spend);

        let coin = note_coin(value, &secrets, &q_spend).compress().to_bytes();
        let enc_value = xor8(value, &secrets.amount_pad);

        Ok(PublishedNote { coin, tx_public, enc_value, view_tag: secrets.view_tag })
    }

    fn scan(&self, key: &NoteScanKey, note: &PublishedNote) -> Option<RecoveredNote> {
        // Malformed points on a peer note are simply "not ours".
        let r_point = PeerPoint::decode_non_identity(note.tx_public).ok()?;
        let q_spend = PeerPoint::decode_non_identity(key.q_spend).ok()?;

        let ss = ecdh_shared_secret(&key.scan_secret, r_point.as_point());
        let secrets = derive_note(&ss, &key.q_spend);

        // Stage-1: cheap 1-byte filter, no point math on a miss.
        if secrets.view_tag != note.view_tag {
            return None;
        }

        // Recover the amount, then Stage-2: recompute the coin and compare.
        let value = u64::from_le_bytes(xor8_bytes(&note.enc_value, &secrets.amount_pad));
        let recomputed = note_coin(value, &secrets, q_spend.as_point()).compress().to_bytes();
        if !bool::from(recomputed.ct_eq(&note.coin)) {
            return None;
        }

        Some(RecoveredNote {
            value,
            coin_blinding: secrets.coin_blinding,
            value_blinding: secrets.value_blinding,
            serial_public: secrets.serial_public,
        })
    }
}

#[inline]
fn xor8_bytes(enc: &[u8; 8], pad: &[u8; 8]) -> [u8; 8] {
    let mut out = [0u8; 8];
    for i in 0..8 {
        out[i] = enc[i] ^ pad[i];
    }
    out
}

/// The scan ≠ spend boundary, made explicit: the spendable serial is
/// `s_full = s_pub + spend_secret`. This helper needs `spend_secret`, which a
/// [`NoteScanKey`] does not carry — so a view-only holder physically cannot call
/// it with the right input.
///
/// NOTE: the **nullifier** derived from `s_full` (and its exact binding to the
/// spend secret) is the audit-critical piece pinned to the Lelantus-Spark paper;
/// it is intentionally NOT implemented here.
pub fn spend_serial(recovered: &RecoveredNote, spend_secret: &Scalar) -> Scalar {
    recovered.serial_public + spend_secret
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::groth_kohlweiss::bound_coin_commitment;
    use rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;

    fn recipient(seed: u64) -> (Scalar, Scalar, SparkAddr2, NoteScanKey) {
        let mut rng = ChaCha20Rng::seed_from_u64(seed);
        let scan_secret = Scalar::random(&mut rng);
        let spend_secret = Scalar::random(&mut rng);
        let addr = SparkAddr2::from_secrets([seed as u8; 11], &scan_secret, &spend_secret);
        // View-only key: scan secret + PUBLIC spend point (no spend_secret).
        let scan_key = NoteScanKey::new(scan_secret, addr.q_spend);
        (scan_secret, spend_secret, addr, scan_key)
    }

    #[test]
    fn create_scan_round_trip_recovers_value_and_openings() {
        let mut rng = ChaCha20Rng::seed_from_u64(100);
        let (_ss, spend_secret, addr, scan_key) = recipient(1);
        let c = SparkNoteConnector;

        let value = 4_242_000u64;
        let note = c.create(&addr, value, &mut rng).unwrap();
        let rec = c.scan(&scan_key, &note).expect("owner recovers its note");

        assert_eq!(rec.value, value);
        // The recovered opening reconstructs the exact tree coin, using the FULL
        // serial s_full = s_pub + spend_secret (only the spender can form it).
        let s_full = spend_serial(&rec, &spend_secret);
        let coin = bound_coin_commitment(value, &s_full, &rec.coin_blinding)
            .compress()
            .to_bytes();
        assert_eq!(coin, note.coin, "opening must reproduce the tree coin");
    }

    #[test]
    fn wrong_recipient_does_not_detect() {
        let mut rng = ChaCha20Rng::seed_from_u64(101);
        let (_s, _sp, addr, _key) = recipient(2);
        let (_s2, _sp2, _addr2, other_key) = recipient(3);
        let c = SparkNoteConnector;

        let note = c.create(&addr, 999u64, &mut rng).unwrap();
        assert!(c.scan(&other_key, &note).is_none(), "stranger must not detect");
    }

    #[test]
    fn tampered_amount_is_rejected_by_coin_check() {
        let mut rng = ChaCha20Rng::seed_from_u64(102);
        let (_s, _sp, addr, scan_key) = recipient(4);
        let c = SparkNoteConnector;

        let mut note = c.create(&addr, 7_000_000u64, &mut rng).unwrap();
        // Flip an encrypted-amount byte: recovered value changes → recomputed
        // coin no longer matches the (untampered) tree coin → rejected.
        note.enc_value[0] ^= 0x01;
        assert!(c.scan(&scan_key, &note).is_none(), "amount binding must hold");
    }

    #[test]
    fn derive_note_is_deterministic() {
        let ss = [7u8; 32];
        let q_spend = [9u8; 32];
        let a = derive_note(&ss, &q_spend);
        let b = derive_note(&ss, &q_spend);
        assert_eq!(a.view_tag, b.view_tag);
        assert_eq!(a.amount_pad, b.amount_pad);
        assert_eq!(a.coin_blinding, b.coin_blinding);
        assert_eq!(a.serial_public, b.serial_public);
    }

    #[test]
    fn view_only_key_recovers_but_cannot_form_spendable_serial() {
        // The scan key holds NO spend_secret. It recovers value, but the
        // spendable serial requires spend_secret — demonstrated by the fact
        // that scan yields only s_pub, and spend_serial needs the extra secret.
        let mut rng = ChaCha20Rng::seed_from_u64(103);
        let (_s, spend_secret, addr, scan_key) = recipient(5);
        let c = SparkNoteConnector;

        let note = c.create(&addr, 55u64, &mut rng).unwrap();
        let rec = c.scan(&scan_key, &note).unwrap();

        // s_pub alone does NOT reproduce the coin; only s_pub + spend_secret does.
        let with_pub_only = bound_coin_commitment(rec.value, &rec.serial_public, &rec.coin_blinding)
            .compress()
            .to_bytes();
        assert_ne!(with_pub_only, note.coin, "scan-derivable serial must not spend");
        let with_full = bound_coin_commitment(
            rec.value,
            &spend_serial(&rec, &spend_secret),
            &rec.coin_blinding,
        )
        .compress()
        .to_bytes();
        assert_eq!(with_full, note.coin, "only spend_secret completes the serial");
    }
}
