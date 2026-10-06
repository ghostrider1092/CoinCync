//! Hardware-wallet (Ledger/Trezor) host-side support — slice 2 skeleton.
//!
//! Gated behind the `hardware` cargo feature, so the default build pulls no
//! USB/HID dependencies. This slice establishes the *host* pieces that don't
//! need a device:
//!
//! - [`Apdu`] short-form command encoding and the [`ins`] command set (mirrors
//!   the future on-device CoinCync app),
//! - a small [`LedgerTransport`] trait (one APDU exchange) that decouples us
//!   from any specific vendor crate — the real USB-HID adapter
//!   (`ledger-transport-hid`) plugs in behind this in a later slice, and tests
//!   use a mock,
//! - [`HardwareSigner`], which implements [`crate::transaction::TxSigner`] so it
//!   can be handed to `TransactionBuilder::build_with_signer`. One read-only
//!   command ([`HardwareSigner::app_config`]) is wired end-to-end now; the key
//!   image and CLSAG signing land in the device slices (3–4) and currently
//!   return an error.
//!
//! Design invariant: the spend key never reaches the host. The signer produces
//! [`OneTimeKeyRef`]s with `secret: None`; all secret-key math happens on-device.

use std::cell::RefCell;

use rand::{CryptoRng, RngCore};

use crate::crypto::ClsagSignature;
use crate::error::{Error, Result};
use crate::primitives::{KeyImage, PublicKey, SecretKey};
use crate::transaction::{ClsagSignRequest, OneTimeKeyRef, TxSigner};

/// Take the first 32 bytes of a device response as a fixed array.
fn take_32(resp: &[u8]) -> Result<[u8; 32]> {
    if resp.len() < 32 {
        return Err(Error::CryptoError(
            "device response too short (need 32 bytes)".into(),
        ));
    }
    let mut a = [0u8; 32];
    a.copy_from_slice(&resp[..32]);
    Ok(a)
}

/// Parse a 64-byte device response as two on-curve public keys.
fn split_two_pubkeys(resp: &[u8]) -> Result<(PublicKey, PublicKey)> {
    if resp.len() < 64 {
        return Err(Error::CryptoError(
            "device pubkey response too short (need 64 bytes)".into(),
        ));
    }
    let first = PublicKey::from_bytes_checked(take_32(&resp[0..32])?)
        .map_err(|_| Error::CryptoError("device public key #1 not on curve".into()))?;
    let second = PublicKey::from_bytes_checked(take_32(&resp[32..64])?)
        .map_err(|_| Error::CryptoError("device public key #2 not on curve".into()))?;
    Ok((first, second))
}

/// APDU class byte for the CoinCync device app.
pub const CLA: u8 = 0xE0;

/// APDU instruction bytes — the command set the on-device app exposes. Only
/// `GET_APP_CONFIG` is exercised in slice 2; the rest are reserved for the
/// device slices so the wire protocol is defined in one place.
pub mod ins {
    pub const GET_APP_CONFIG: u8 = 0x00;
    pub const GET_PUBLIC_KEYS: u8 = 0x02;
    pub const GET_VIEW_KEY: u8 = 0x04;
    pub const GET_SUBADDRESS: u8 = 0x06;
    pub const GEN_KEY_IMAGE: u8 = 0x08;
    pub const CLSAG_INIT: u8 = 0x10;
    pub const CLSAG_UPDATE: u8 = 0x12;
    pub const CLSAG_FINAL: u8 = 0x14;
    pub const SIGN_TX_CONFIRM: u8 = 0x1A;
}

/// A short-form APDU command (`CLA INS P1 P2 Lc DATA`).
#[derive(Clone, Debug)]
pub struct Apdu {
    pub cla: u8,
    pub ins: u8,
    pub p1: u8,
    pub p2: u8,
    pub data: Vec<u8>,
}

impl Apdu {
    /// Build an APDU on the CoinCync app's class byte.
    pub fn new(ins: u8, p1: u8, p2: u8, data: Vec<u8>) -> Self {
        Self {
            cla: CLA,
            ins,
            p1,
            p2,
            data,
        }
    }

    /// Serialize as a short APDU. Data is capped at 255 bytes; larger payloads
    /// (e.g. streaming a ring in CLSAG_UPDATE) are chunked by the caller.
    pub fn serialize(&self) -> Result<Vec<u8>> {
        if self.data.len() > u8::MAX as usize {
            return Err(Error::InvalidState(
                "APDU data exceeds 255-byte short form; chunk it".into(),
            ));
        }
        let mut out = Vec::with_capacity(5 + self.data.len());
        out.extend_from_slice(&[self.cla, self.ins, self.p1, self.p2, self.data.len() as u8]);
        out.extend_from_slice(&self.data);
        Ok(out)
    }
}

/// Exchanges one APDU with a device and returns the response payload. The
/// implementation is responsible for validating the trailing status word (a
/// non-`0x9000` SW must map to an `Err`) and stripping it, so callers see only
/// the data. A real USB-HID adapter implements this in a later slice.
pub trait LedgerTransport {
    fn exchange(&mut self, apdu: &Apdu) -> Result<Vec<u8>>;
}

/// A [`TxSigner`] backed by a hardware device over a [`LedgerTransport`].
///
/// Interior mutability (`RefCell`) lets the `&self` `TxSigner` methods drive the
/// stateful device exchange. Slice 2 wires the transport + one read-only command;
/// key images and CLSAG signing are added in the device slices.
pub struct HardwareSigner<T: LedgerTransport> {
    transport: RefCell<T>,
    account: u32,
}

impl<T: LedgerTransport> HardwareSigner<T> {
    /// Signer for the default account (0).
    pub fn new(transport: T) -> Self {
        Self::with_account(transport, 0)
    }

    /// Signer for a specific account index.
    pub fn with_account(transport: T, account: u32) -> Self {
        Self {
            transport: RefCell::new(transport),
            account,
        }
    }

    /// The account index this signer acts for.
    pub fn account(&self) -> u32 {
        self.account
    }

    fn exchange(&self, apdu: &Apdu) -> Result<Vec<u8>> {
        self.transport.borrow_mut().exchange(apdu)
    }

    /// Read the device app's `(major, minor, patch)` version — a cheap liveness
    /// check that exercises the full APDU → transport → parse path.
    pub fn app_config(&self) -> Result<(u8, u8, u8)> {
        let resp = self.exchange(&Apdu::new(ins::GET_APP_CONFIG, 0, 0, Vec::new()))?;
        if resp.len() < 3 {
            return Err(Error::CryptoError(
                "device app config response too short".into(),
            ));
        }
        Ok((resp[0], resp[1], resp[2]))
    }

    // ── read-only device ops (slice 3) ──────────────────────────────────────
    // These fetch PUBLIC material the host needs for scanning and address
    // display. The spend SECRET never leaves the device; the view secret is
    // released only after on-device user confirmation.

    /// Device-held public spend and view keys for this signer's account
    /// (`GET_PUBLIC_KEYS`). Returns `(spend_public, view_public)`.
    pub fn account_pubkeys(&self) -> Result<(PublicKey, PublicKey)> {
        let resp = self.exchange(&Apdu::new(
            ins::GET_PUBLIC_KEYS,
            0,
            0,
            self.account.to_le_bytes().to_vec(),
        ))?;
        split_two_pubkeys(&resp)
    }

    /// Public keys `(D_i, C_i)` for a subaddress under `account`
    /// (`GET_SUBADDRESS`).
    pub fn subaddress_pubkeys(&self, account: u32, index: u32) -> Result<(PublicKey, PublicKey)> {
        let mut data = Vec::with_capacity(8);
        data.extend_from_slice(&account.to_le_bytes());
        data.extend_from_slice(&index.to_le_bytes());
        let resp = self.exchange(&Apdu::new(ins::GET_SUBADDRESS, 0, 0, data))?;
        split_two_pubkeys(&resp)
    }

    /// The account VIEW secret key for host-side output scanning
    /// (`GET_VIEW_KEY`). Standard for Monero-family hardware wallets: the host
    /// scans with the view key while the device holds the spend key and does all
    /// signing. The device releases this only after on-screen user confirmation.
    pub fn view_secret(&self) -> Result<SecretKey> {
        let resp = self.exchange(&Apdu::new(ins::GET_VIEW_KEY, 0, 0, Vec::new()))?;
        Ok(SecretKey::from_bytes(take_32(&resp)?))
    }
}

impl<T: LedgerTransport> TxSigner for HardwareSigner<T> {
    fn key_image(&self, _key: &OneTimeKeyRef) -> Result<KeyImage> {
        Err(Error::InvalidState(
            "hardware key image not implemented yet (device slice)".into(),
        ))
    }

    fn sign_clsag_input<R: RngCore + CryptoRng>(
        &self,
        _req: &ClsagSignRequest<'_>,
        _rng: &mut R,
    ) -> Result<ClsagSignature> {
        Err(Error::InvalidState(
            "hardware CLSAG signing not implemented yet (device slice)".into(),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Serializes the command (to exercise `Apdu::serialize`) and returns a
    /// canned payload.
    struct MockTransport {
        response: Vec<u8>,
    }
    impl LedgerTransport for MockTransport {
        fn exchange(&mut self, apdu: &Apdu) -> Result<Vec<u8>> {
            let _wire = apdu.serialize()?;
            Ok(self.response.clone())
        }
    }

    #[test]
    fn apdu_serializes_short_form() {
        let a = Apdu::new(ins::GET_SUBADDRESS, 1, 2, vec![0xAA, 0xBB]);
        assert_eq!(
            a.serialize().unwrap(),
            vec![CLA, ins::GET_SUBADDRESS, 1, 2, 2, 0xAA, 0xBB]
        );
    }

    #[test]
    fn apdu_rejects_oversized_data() {
        let a = Apdu::new(ins::CLSAG_UPDATE, 0, 0, vec![0u8; 256]);
        assert!(a.serialize().is_err());
    }

    #[test]
    fn app_config_roundtrips_through_transport() {
        let signer = HardwareSigner::new(MockTransport {
            response: vec![1, 4, 2],
        });
        assert_eq!(signer.app_config().unwrap(), (1, 4, 2));
        assert_eq!(signer.account(), 0);
    }

    #[test]
    fn signing_ops_error_until_device_slice() {
        let signer = HardwareSigner::new(MockTransport {
            response: Vec::new(),
        });
        assert!(signer.key_image(&OneTimeKeyRef { secret: None }).is_err());
    }

    #[test]
    fn account_pubkeys_parses_two_oncurve_points() {
        let spend = SecretKey::from_bytes([3u8; 32]).public_key();
        let view = SecretKey::from_bytes([4u8; 32]).public_key();
        let mut resp = Vec::new();
        resp.extend_from_slice(spend.as_bytes());
        resp.extend_from_slice(view.as_bytes());
        let signer = HardwareSigner::new(MockTransport { response: resp });
        let (s, v) = signer.account_pubkeys().unwrap();
        assert_eq!(s.as_bytes(), spend.as_bytes());
        assert_eq!(v.as_bytes(), view.as_bytes());
    }

    #[test]
    fn subaddress_pubkeys_parses_device_response() {
        let d = SecretKey::from_bytes([5u8; 32]).public_key();
        let c = SecretKey::from_bytes([6u8; 32]).public_key();
        let mut resp = Vec::new();
        resp.extend_from_slice(d.as_bytes());
        resp.extend_from_slice(c.as_bytes());
        let signer = HardwareSigner::new(MockTransport { response: resp });
        let (di, ci) = signer.subaddress_pubkeys(0, 7).unwrap();
        assert_eq!((di.as_bytes(), ci.as_bytes()), (d.as_bytes(), c.as_bytes()));
    }

    #[test]
    fn view_secret_parses_32_bytes() {
        let signer = HardwareSigner::new(MockTransport {
            response: vec![9u8; 32],
        });
        assert_eq!(signer.view_secret().unwrap().as_bytes(), &[9u8; 32]);
    }

    #[test]
    fn pubkey_response_rejects_offcurve_or_short() {
        // 64 bytes of non-point data must be rejected, not silently accepted.
        let signer = HardwareSigner::new(MockTransport {
            response: vec![0xFFu8; 64],
        });
        assert!(signer.account_pubkeys().is_err());
        // A too-short response is rejected as well.
        let short = HardwareSigner::new(MockTransport {
            response: vec![1u8; 10],
        });
        assert!(short.account_pubkeys().is_err());
    }
}
