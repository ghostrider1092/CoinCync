//! # Wallet Module for CoinCync 1.0
//!
//! P0 scope: just the key types and BIP39 mnemonic support. The heavy
//! wallet modules (scanner, send, persistence, history, background_sync,
//! lightsync, wallet) need substantial cascade fixes against the trimmed
//! 1.0 types (asset strip, anchor/stamps strip, emission API change,
//! WalletKeys vs Zcash-style key tree) and come back in P1.

pub mod keys;
pub mod key_epoch;
pub mod wallet_keys;
pub mod mnemonic;
pub mod subaddress;
pub mod persistence;
pub mod balance;
pub mod scanner;
pub mod send;
pub mod history;
pub mod background_sync;
pub mod multisig;
pub mod churn;
// `lightsync` is type-wired but the network handler for `GetOutputDigests`
// is intentionally a no-op in P0 (see `crate::network::node` — it logs and
// drops). Do not assume `LightWalletSync::scan_digest` is ever called on a
// running P0 node. Activated in P1 by removing the handler early-return.
pub mod lightsync;
pub mod wallet;

pub use keys::{
    SpendKey, FullViewingKey, IncomingViewingKey, OutgoingViewingKey, PaymentAddress,
    // Lelantus Spark key chain (Phase 2)
    SparkSpendKey, SparkScanKey, SparkAddress,
};
pub use key_epoch::{KeyEpoch, ViewOnlyEpoch};
pub use wallet_keys::WalletKeys;
pub use balance::{Balance, UTXO};
pub use scanner::{WalletScanner, ScanKeys, DecryptedOutput, ScanStats, encrypt_amount, generate_view_tag};
pub use wallet::{Wallet, SharedWallet, WalletState, WalletInfo};
pub use persistence::{
    WalletData, WalletHeader,
    save_wallet, load_wallet, wallet_exists, change_password,
    generate_mnemonic, mnemonic_to_seed,
    derive_key, derive_key_default, decrypt_sidecar_with_fallback,
    encrypt, decrypt,
};
// Re-export subaddress types at the `wallet::` level so `persistence.rs`
// can reach `super::SubaddressData` and other modules don't need the
// deeper path.
pub use subaddress::{SubaddressData, Subaddress, SubaddressManager, SubaddressIndex, SubaddressRecord};
