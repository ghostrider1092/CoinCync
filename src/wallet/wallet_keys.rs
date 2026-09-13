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
//!
//! ## Audit map
//! Each `§` is a code section below; it states the INVARIANT it guarantees, the
//! THREAT it defends, and the TESTS that prove it.
//!
//! - **§1 `new` / `from_seed`** — INVARIANT: key derivation is deterministic in
//!   the master seed — the same seed reproduces the same epoch-0 keys, and
//!   distinct seeds produce distinct keys.
//!   THREAT: non-reproducible derivation would make seed backup / restore fail
//!   to recover the wallet's funds.
//!   TESTS: `derivation_is_deterministic`, `different_seeds_produce_different_keys`,
//!   `tier7_key_derivation_deterministic`.
//! - **§2 `derive_epoch`** — INVARIANT: spend and view secrets use distinct HMAC
//!   domain tags, so within an epoch they are cryptographically independent —
//!   the view secret is not the spend secret and cannot reproduce it.
//!   THREAT: a shared/derivable spend secret would let a shared view key spend.
//!   TESTS: `derive_epoch_separates_spend_and_view_domains`, `tier7_view_key_cannot_derive_spend`.
//! - **§3 `derive_epoch` (rotation) / `get_epoch`** — INVARIANT: distinct epoch
//!   numbers derive fully independent spend AND view key material.
//!   THREAT: epoch collisions would defeat key rotation, linking rotated
//!   identities. TESTS: `epochs_diverge`, `derive_epoch_distinct_across_epochs`.
//! - **§4 `watch_only` / `is_watch_only` / `is_initialized`** — INVARIANT: a
//!   watch-only wallet is flagged watch-only yet initialized, carries no usable
//!   spend authority, and holds the `[0xFF; 32]` seed sentinel (never a real seed).
//!   THREAT: a watch-only wallet that could spend, or leaked a real seed, breaks
//!   the view-only custody boundary.
//!   TESTS: `watch_only_is_marked`, `is_watch_only_and_is_initialized_reflect_construction`,
//!   `tier7_watch_only_cannot_spend`.
//! - **§5 `master_seed_for_backup` / `raw_master_seed_or_sentinel`** — INVARIANT:
//!   backup returns `Some(seed)` only for a real wallet and `None` for watch-only,
//!   so the `[0xFF; 32]` sentinel is never serialized as if it were a seed.
//!   THREAT: R-75 — backing up the sentinel silently produces a well-formed but
//!   WRONG restored wallet.
//!   TESTS: `master_seed_for_backup_some_for_real_none_for_watch_only`.
//! - **§6 `set_mnemonic_phrase` / `mnemonic_phrase`** — INVARIANT: the phrase a
//!   wallet was created from is stored (in a `Zeroizing<String>`) and read back,
//!   or `None` when the wallet never carried one.
//!   THREAT: R-115 — losing the phrase across save cycles breaks mnemonic backup.
//!   TESTS: (gap — accessor exercised only indirectly via `Wallet::save`; no unit test).

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
    /// R-115 SURGICAL FIX (2026-07-03): BIP39 mnemonic phrase
    /// this wallet was created / restored FROM. Kept in memory so
    /// `Wallet::save` can persist it through `WalletData.mnemonic_phrase`
    /// on every save cycle, rather than always writing `None`.
    /// Wrapped in `Zeroizing<String>` so heap bytes are wiped when
    /// the WalletKeys drops. `None` for wallets that never carried
    /// a mnemonic (e.g. watch-only, restored-from-seed-only).
    mnemonic_phrase: Option<zeroize::Zeroizing<String>>,
}

impl WalletKeys {
    /// Generate a fresh wallet with a cryptographically-random seed.
    ///
    /// AUDIT (R-73 fix, 2026-07-03): the pre-fix code did
    ///   let mut seed = [0u8; 32];
    ///   rng.fill_bytes(&mut seed);
    ///   let mut wallet = WalletKeys { master_seed: seed, ... };
    /// The `seed` was `Copy`-moved into the struct field. The stack
    /// slot for `seed` still contained the raw master-seed bytes,
    /// unzeroized after the copy. Every subsequent stack frame that
    /// reused that memory could observe the seed until overwritten.
    /// Explicit zeroize of the stack copy AFTER the field write closes
    /// the window.
    pub fn new<R: RngCore + CryptoRng>(rng: &mut R) -> Self {
        let mut seed = [0u8; 32];
        rng.fill_bytes(&mut seed);
        let mut wallet = WalletKeys {
            master_seed: seed,
            current_epoch: 0,
            epochs: Vec::new(),
            watch_only: false,
            mnemonic_phrase: None,
        };
        // R-73: wipe the stack copy of the master seed. The copy in
        // wallet.master_seed remains (wrapped in a Zeroize-on-Drop
        // field type at the struct level — see struct definition).
        use zeroize::Zeroize;
        seed.zeroize();
        wallet.derive_epoch(0);
        wallet
    }

    /// Restore a wallet from a 32-byte master seed.
    ///
    /// AUDIT (R-73 fix, 2026-07-03): same class as `new` above. The
    /// caller-provided `seed: [u8; 32]` is Copy-moved into the struct
    /// field; the caller's stack copy is out of our reach, but the
    /// parameter binding here IS. Zeroize it after the field write.
    pub fn from_seed(mut seed: [u8; 32]) -> Self {
        let mut wallet = WalletKeys {
            master_seed: seed,
            current_epoch: 0,
            epochs: Vec::new(),
            watch_only: false,
            mnemonic_phrase: None,
        };
        // R-73: wipe the local `seed` binding. The caller is
        // responsible for wiping their own upstream copy.
        use zeroize::Zeroize;
        seed.zeroize();
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
        //
        // AUDIT (R-74 fix, 2026-07-03): the pre-fix code did
        //   [b"...", view_secret.as_bytes()].concat()
        // which allocates a heap Vec<u8> containing the raw
        // view_secret bytes. The Vec is dropped after hashing but
        // NOT zeroized — the freed heap block sits in the allocator
        // pool with plaintext view_secret bytes readable by the next
        // allocation that lands on the same slot. Now we build the
        // buffer explicitly and zeroize it before it goes out of scope.
        let mut hash_input = Vec::with_capacity(b"COINCYNC_WATCHONLY_PLACEHOLDER_v1".len() + 32);
        hash_input.extend_from_slice(b"COINCYNC_WATCHONLY_PLACEHOLDER_v1");
        hash_input.extend_from_slice(view_secret.as_bytes());
        let placeholder_hash = blake3::hash(&hash_input);
        {
            use zeroize::Zeroize;
            hash_input.zeroize();
        }
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
            mnemonic_phrase: None,
        }
    }

    /// True if this wallet cannot spend.
    pub fn is_watch_only(&self) -> bool {
        self.watch_only
    }

    /// R-115 SURGICAL FIX (2026-07-03): set the mnemonic phrase
    /// this wallet was created from. Called by `Wallet::create` /
    /// `Wallet::restore_from_mnemonic` after key derivation.
    /// Subsequent `Wallet::save` calls will persist this phrase
    /// through `WalletData.mnemonic_phrase`.
    pub fn set_mnemonic_phrase(&mut self, phrase: String) {
        self.mnemonic_phrase = Some(zeroize::Zeroizing::new(phrase));
    }

    /// R-115: read back the stored phrase. `None` if this wallet
    /// was never annotated with one (watch-only, restored from
    /// raw seed, loaded from a pre-R-115 save file).
    pub fn mnemonic_phrase(&self) -> Option<&str> {
        self.mnemonic_phrase.as_deref().map(|s| s.as_str())
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
        let mut spend_mac =
            HmacSha256::new_from_slice(&self.master_seed).expect("HMAC accepts any key size");
        spend_mac.update(b"COINCYNC_SPEND_v2");
        spend_mac.update(&epoch.to_le_bytes());
        let mut spend_bytes = [0u8; 32];
        spend_bytes.copy_from_slice(&spend_mac.finalize().into_bytes()[..32]);
        let spend_secret = SecretKey::from_bytes(spend_bytes);
        spend_bytes.zeroize();

        // View key
        let mut view_mac =
            HmacSha256::new_from_slice(&self.master_seed).expect("HMAC accepts any key size");
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
    ///
    /// AUDIT (R-75 fix, 2026-07-03): the pre-fix impl returned
    /// `&self.master_seed` unconditionally. For a watch-only wallet
    /// (see `watch_only()` at ~L66), `master_seed` is the SENTINEL
    /// value `[0xFF; 32]` — that's not a real seed. A caller that
    /// invokes `master_seed_for_backup()` on a watch-only wallet
    /// gets back a `[0xFF; 32]` block that looks like a valid seed;
    /// if the caller writes it to a backup file, restores from it
    /// later, and rederives keys from `[0xFF; 32]`, they get a
    /// well-formed but WRONG wallet — a silent corruption of the
    /// backup semantics. Return `None` for watch-only wallets so
    /// callers explicitly branch on availability rather than
    /// serialize a sentinel by accident.
    ///
    /// Callers that need the raw sentinel for internal reasons can
    /// use `raw_master_seed_or_sentinel()` (which is deliberately
    /// named to make the misuse loud in code review).
    pub fn master_seed_for_backup(&self) -> Option<&[u8; 32]> {
        if self.watch_only {
            tracing::warn!(
                target: "wallet::keys::R75",
                "master_seed_for_backup called on watch-only wallet — \
                 returning None to prevent backup of the [0xFF; 32] sentinel"
            );
            return None;
        }
        tracing::trace!("Master seed accessed - ensure proper security handling");
        Some(&self.master_seed)
    }

    /// Raw access to the master seed field for internal callers that
    /// KNOW they may receive the watch-only sentinel and handle it
    /// correctly (e.g. the WalletData serialization path preserves
    /// the sentinel so load can reconstruct a watch-only wallet).
    /// Do NOT use for backups.
    pub fn raw_master_seed_or_sentinel(&self) -> &[u8; 32] {
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

    /// `derive_epoch` uses domain-separated HMAC tags ("COINCYNC_SPEND_v2" vs
    /// "COINCYNC_VIEW_v2"), so within a single epoch the spend and view keys
    /// are cryptographically independent, not the same secret reused.
    #[test]
    fn derive_epoch_separates_spend_and_view_domains() {
        let w = WalletKeys::from_seed([21u8; 32]);
        let e = w.current().unwrap();
        assert_ne!(
            e.spend_secret.as_bytes(),
            e.view_secret.as_bytes(),
            "spend and view secrets must differ (HMAC domain separation)"
        );
        assert_ne!(
            e.spend_public.as_bytes(),
            e.view_public.as_bytes(),
            "spend and view public keys must differ"
        );
    }

    /// Distinct epoch numbers derive distinct spend AND view keys, so rotation
    /// produces genuinely independent key material.
    #[test]
    fn derive_epoch_distinct_across_epochs() {
        let mut w = WalletKeys::from_seed([22u8; 32]);
        w.derive_epoch(5);
        let e0 = w.get_epoch(0).unwrap();
        let e5 = w.get_epoch(5).unwrap();
        assert_ne!(e0.spend_public.as_bytes(), e5.spend_public.as_bytes());
        assert_ne!(e0.view_public.as_bytes(), e5.view_public.as_bytes());
    }

    /// `master_seed_for_backup` returns `Some(seed)` for a real wallet but
    /// `None` for a watch-only wallet (whose stored seed is the `[0xFF; 32]`
    /// sentinel). The raw accessor still exposes that sentinel for internal
    /// callers (R-75).
    #[test]
    fn master_seed_for_backup_some_for_real_none_for_watch_only() {
        let real = WalletKeys::from_seed([33u8; 32]);
        assert!(
            real.master_seed_for_backup().is_some(),
            "real wallet must expose its backup seed"
        );
        assert_ne!(
            real.raw_master_seed_or_sentinel(),
            &[0xFFu8; 32],
            "real wallet's raw seed must not be the sentinel"
        );

        let e = real.current().unwrap();
        let wo = WalletKeys::watch_only(e.view_secret.clone(), e.spend_public);
        assert!(
            wo.master_seed_for_backup().is_none(),
            "watch-only wallet must not expose a backup seed"
        );
        assert_eq!(
            wo.raw_master_seed_or_sentinel(),
            &[0xFFu8; 32],
            "watch-only wallet's raw seed is the sentinel"
        );
    }

    /// `is_watch_only` / `is_initialized` reflect the construction path: a
    /// seed-derived wallet is spendable + initialized; a watch-only wallet is
    /// flagged watch-only but still initialized.
    #[test]
    fn is_watch_only_and_is_initialized_reflect_construction() {
        let real = WalletKeys::from_seed([44u8; 32]);
        assert!(!real.is_watch_only());
        assert!(real.is_initialized());

        let e = real.current().unwrap();
        let wo = WalletKeys::watch_only(e.view_secret.clone(), e.spend_public);
        assert!(wo.is_watch_only());
        assert!(wo.is_initialized());
    }
}
