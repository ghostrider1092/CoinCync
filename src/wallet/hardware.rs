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
use crate::primitives::KeyImage;
use crate::transaction::{ClsagSignRequest, OneTimeKeyRef, TxSigner};

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
}
