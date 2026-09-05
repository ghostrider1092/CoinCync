//! Shim `KeyEpoch` type used by `crypto::stealth` for ECDH-based output
//! detection. This is the CoinCync 1.0 shape, kept as its own file so the
//! Zcash-style FVK/IVK/OVK code in `wallet::keys` is not disturbed.

use crate::primitives::{PublicKey, SecretKey};

/// Key epoch: spend and view keypairs for a wallet at a given rotation.
///
/// The view keypair identifies outputs sent to this wallet; the spend
/// keypair is required to actually spend them.
///
/// AUDIT (R-72 fix, 2026-07-02): the prior doc said "Both secrets are
/// wiped on drop (see the Drop impl) as a defence-in-depth measure —
/// the underlying SecretKey type already zeroes on drop." That was
/// misleading. The `Drop` impl at the bottom of this module ONLY
/// zeros the (non-secret) `epoch: u64` field; the secret wiping
/// happens through the field-drop chain (each `SecretKey` field runs
/// its own `ZeroizeOnDrop`). The custom Drop was cosmetic — its
/// presence made auditors think there was a defense-in-depth layer
/// on top of the SecretKey chain when there wasn't. Documented
/// truthfully now so future readers don't rely on a phantom layer.
#[derive(Clone)]
pub struct KeyEpoch {
    pub epoch: u64,
    pub spend_secret: SecretKey,
    pub spend_public: PublicKey,
    pub view_secret: SecretKey,
    pub view_public: PublicKey,
}

impl Drop for KeyEpoch {
    fn drop(&mut self) {
        self.epoch = 0;
    }
}

/// Watch-only epoch — view keys only, no spending capability.
#[derive(Clone)]
pub struct ViewOnlyEpoch {
    pub epoch: u64,
    pub view_secret: SecretKey,
    pub view_public: PublicKey,
    pub spend_public: PublicKey,
}

impl Drop for ViewOnlyEpoch {
    fn drop(&mut self) {
        self.epoch = 0;
    }
}
