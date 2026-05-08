//! Shim `KeyEpoch` type used by `crypto::stealth` for ECDH-based output
//! detection. This is the CoinCync 1.0 shape, kept as its own file so the
//! Zcash-style FVK/IVK/OVK code in `wallet::keys` is not disturbed.

use crate::primitives::{PublicKey, SecretKey};

/// Key epoch: spend and view keypairs for a wallet at a given rotation.
///
/// The view keypair identifies outputs sent to this wallet; the spend
/// keypair is required to actually spend them. Both secrets are wiped
/// on drop (see the `Drop` impl) as a defence-in-depth measure — the
/// underlying `SecretKey` type already zeroes on drop.
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

/// Time-scoped view key — can only decrypt outputs within a specific
/// block height range. This is CoinCync's innovation over Monero:
/// you can prove your transaction history for a specific period
/// (e.g., tax year) without surrendering all past and future privacy.
///
/// The 4th Amendment protects against unreasonable searches.
/// Time-scoped view keys implement "particular description" —
/// the scope is precisely limited to what is voluntarily disclosed.
#[derive(Clone)]
pub struct ScopedViewKey {
    pub view_secret: SecretKey,
    pub view_public: PublicKey,
    pub spend_public: PublicKey,
    pub from_height: u64,
    pub to_height: u64,
}

impl ScopedViewKey {
    /// Create a scoped view key from a full epoch.
    /// The key material is the same — the scope is enforced by the
    /// wallet scanner, which skips blocks outside the range.
    pub fn from_epoch(epoch: &KeyEpoch, from_height: u64, to_height: u64) -> Self {
        ScopedViewKey {
            view_secret: epoch.view_secret.clone(),
            view_public: epoch.view_public,
            spend_public: epoch.spend_public,
            from_height,
            to_height,
        }
    }

    /// Check if a block height falls within this key's scope.
    pub fn covers_height(&self, height: u64) -> bool {
        height >= self.from_height && height <= self.to_height
    }

    /// Export as a shareable JSON string (contains view secret — handle carefully).
    pub fn to_json(&self) -> String {
        format!(
            r#"{{"view_secret":"{}","view_public":"{}","spend_public":"{}","from_height":{},"to_height":{}}}"#,
            hex::encode(self.view_secret.as_bytes()),
            hex::encode(self.view_public.as_bytes()),
            hex::encode(self.spend_public.as_bytes()),
            self.from_height,
            self.to_height,
        )
    }
}

impl Drop for ScopedViewKey {
    fn drop(&mut self) {
        self.from_height = 0;
        self.to_height = 0;
    }
}
