//! # WalletKeys — master seed + derived key epochs
//!
//! 2.0's flat wallet-key model, ported into the 1.0 tree so that the
//! rest of the ported wallet code (scanner, send, persistence, wallet.rs)
//! has the `WalletKeys` type it imports. Reuses the existing
//! `key_epoch::KeyEpoch` / `key_epoch::ViewOnlyEpoch` types so there's
//! a single canonical representation for an epoch.
//!
//! The 1.0 tree also has a Zcash-style key hierarchy in
//! [wallet/keys.rs](crate::wallet::keys) (`SpendKey` → `FullViewingKey`
//! → `IncomingViewingKey` + `OutgoingViewingKey`) that was added in
//! Phase 1b for the shielded pool. The two are parallel and coexist —
//! the flat `WalletKeys` drives transparent ring transactions, the
//! Zcash-style tree drives shielded actions when Phase 2 ships.

use rand::{CryptoRng, RngCore};
use zeroize::Zeroize;

use crate::primitives::{PublicKey, SecretKey};
use crate::wallet::key_epoch::KeyEpoch;

/// Wallet keys manager.
///
/// SECURITY: Contains the master seed. The seed can derive ALL wallet
/// keys, so its exposure means complete loss of funds and privacy.
pub struct WalletKeys {
    /// Master seed — NEVER expose except for backup purposes.
    master_seed: [u8; 32],
    current_epoch: u64,
    epochs: Vec<KeyEpoch>,
    /// Watch-only mode (no spending capability).
    watch_only: bool,
}

impl WalletKeys {
    /// Generate a fresh wallet with a cryptographically-random seed.
    pub fn new<R: RngCore + CryptoRng>(rng: &mut R) -> Self {
        let mut seed = [0u8; 32];
        rng.fill_bytes(&mut seed);
        let mut wallet = WalletKeys {
            master_seed: seed,
            current_epoch: 0,
            epochs: Vec::new(),
            watch_only: false,
        };
        wallet.derive_epoch(0);
        wallet
    }

    /// Restore a wallet from a 32-byte master seed.
    pub fn from_seed(seed: [u8; 32]) -> Self {
        let mut wallet = WalletKeys {
            master_seed: seed,
            current_epoch: 0,
            epochs: Vec::new(),
            watch_only: false,
        };
        wallet.derive_epoch(0);
        wallet
    }

    /// Create a watch-only wallet from a view key and spend public key.
    ///
    /// Can monitor incoming tx, compute balance, and export history.
    /// Cannot spend, sign, or access the master seed.
    pub fn watch_only(view_secret: SecretKey, spend_public: PublicKey) -> Self {
        let view_public = view_secret.public_key();

        // Derive a deterministic non-zero placeholder `spend_secret` so
        // that if watch-only guards are ever bypassed the key won't be
        // the trivially guessable all-zero scalar. It's still unusable
        // because it won't match `spend_public`, but an attacker can't
        // predict it from the constant alone.
        let placeholder_hash = blake3::hash(
            &[
                b"COINCYNC_WATCHONLY_PLACEHOLDER_v1".as_slice(),
                view_secret.as_bytes(),
            ]
            .concat(),
        );
        let epoch = KeyEpoch {
            epoch: 0,
            spend_secret: SecretKey::from_bytes(*placeholder_hash.as_bytes()),
            spend_public,
            view_secret,
            view_public,
        };

        WalletKeys {
            master_seed: [0xFFu8; 32], // Sentinel — no real seed for watch-only
            current_epoch: 0,
            epochs: vec![epoch],
            watch_only: true,
        }
    }

    /// True if this wallet cannot spend.
    pub fn is_watch_only(&self) -> bool {
        self.watch_only
    }

    /// Derive keys for a specific epoch.
    ///
    /// Uses domain-separated HMAC-SHA256 so spend and view keys are
    /// cryptographically independent. Intermediate scalar bytes are
    /// zeroized after the `SecretKey` wrapper takes ownership.
    pub fn derive_epoch(&mut self, epoch: u64) {
        use hmac::{Hmac, Mac};
        use sha2::Sha256;

        type HmacSha256 = Hmac<Sha256>;

        // Spend key
        let mut spend_mac = HmacSha256::new_from_slice(&self.master_seed)
            .expect("HMAC accepts any key size");
        spend_mac.update(b"COINCYNC_SPEND_v2");
        spend_mac.update(&epoch.to_le_bytes());
        let mut spend_bytes = [0u8; 32];
        spend_bytes.copy_from_slice(&spend_mac.finalize().into_bytes()[..32]);
        let spend_secret = SecretKey::from_bytes(spend_bytes);
        spend_bytes.zeroize();

        // View key
        let mut view_mac = HmacSha256::new_from_slice(&self.master_seed)
            .expect("HMAC accepts any key size");
        view_mac.update(b"COINCYNC_VIEW_v2");
        view_mac.update(&epoch.to_le_bytes());
        let mut view_bytes = [0u8; 32];
        view_bytes.copy_from_slice(&view_mac.finalize().into_bytes()[..32]);
        let view_secret = SecretKey::from_bytes(view_bytes);
        view_bytes.zeroize();

        self.epochs.push(KeyEpoch {
            epoch,
            spend_public: spend_secret.public_key(),
            view_public: view_secret.public_key(),
            spend_secret,
            view_secret,
        });
        self.current_epoch = epoch;
    }

    /// Most recently derived epoch.
    pub fn current(&self) -> Option<&KeyEpoch> {
        self.epochs.last()
    }

    /// Look up a specific epoch by number.
    pub fn get_epoch(&self, epoch: u64) -> Option<&KeyEpoch> {
        self.epochs.iter().find(|e| e.epoch == epoch)
    }

    /// Returns the master seed for backup / migration purposes.
    ///
    /// **CRITICAL**: the seed derives every key in the wallet. Exposure
    /// means complete loss of funds and privacy. Never log, transmit
    /// unencrypted, or copy to swap / clipboard.
    pub fn master_seed_for_backup(&self) -> &[u8; 32] {
        tracing::trace!("Master seed accessed - ensure proper security handling");
        &self.master_seed
    }

    pub fn is_initialized(&self) -> bool {
        !self.epochs.is_empty()
    }
}

impl Drop for WalletKeys {
    fn drop(&mut self) {
        // KeyEpoch already zeros the epoch field on drop, and SecretKey
        // implements ZeroizeOnDrop. Zero the master seed explicitly
        // because it lives in this struct, not inside an epoch.
        self.master_seed.zeroize();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn derivation_is_deterministic() {
        let seed = [99u8; 32];
        let w1 = WalletKeys::from_seed(seed);
        let w2 = WalletKeys::from_seed(seed);
        let e1 = w1.current().unwrap();
        let e2 = w2.current().unwrap();
        assert_eq!(e1.spend_public.as_bytes(), e2.spend_public.as_bytes());
        assert_eq!(e1.view_public.as_bytes(), e2.view_public.as_bytes());
    }

    #[test]
    fn different_seeds_produce_different_keys() {
        let w1 = WalletKeys::from_seed([1u8; 32]);
        let w2 = WalletKeys::from_seed([2u8; 32]);
        assert_ne!(
            w1.current().unwrap().spend_public.as_bytes(),
            w2.current().unwrap().spend_public.as_bytes()
        );
    }

    #[test]
    fn watch_only_is_marked() {
        let w = WalletKeys::from_seed([42u8; 32]);
        let epoch = w.current().unwrap();
        let wo = WalletKeys::watch_only(epoch.view_secret.clone(), epoch.spend_public);
        assert!(wo.is_watch_only());
        assert!(wo.is_initialized());
    }

    #[test]
    fn epochs_diverge() {
        let mut w = WalletKeys::from_seed([10u8; 32]);
        w.derive_epoch(1);
        let e0 = w.get_epoch(0).unwrap();
        let e1 = w.get_epoch(1).unwrap();
        assert_ne!(e0.spend_public.as_bytes(), e1.spend_public.as_bytes());
    }
}
