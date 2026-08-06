//! # Wallet Module for CoinCync 1.0
//!
//! P0 scope: just the key types and BIP39 mnemonic support. The heavy
//! wallet modules (scanner, send, persistence, history, background_sync,
//! lightsync, wallet) need substantial cascade fixes against the trimmed
//! 1.0 types (asset strip, anchor/stamps strip, emission API change,
//! WalletKeys vs Zcash-style key tree) and come back in P1.

pub mod background_sync;
pub mod balance;
pub mod churn;
pub mod decoy_selection;
pub mod history;
pub mod key_epoch;
pub mod keys;
pub mod mnemonic;
pub mod multisig;
pub mod persistence;
pub mod scanner;
pub mod send;
pub mod subaddress;
pub mod wallet_keys;
// `lightsync` is the SPV path. Network handler for `GetOutputDigests`
// is wired in `crate::network::node` (serves up to 100 blocks/request);
// JSON-RPC handler is in `crate::rpc::lightwallet`. Privacy posture vs
// BIP-157 is documented in docs/security/LIGHTSYNC_AUDIT.md — server
// learns only the height range, never the wallet's address set.
pub mod lightsync;
pub mod wallet;

pub use balance::{Balance, UTXO};
pub use key_epoch::{KeyEpoch, ScopedViewKey, ViewOnlyEpoch};
pub use keys::{
    FullViewingKey,
    IncomingViewingKey,
    OutgoingViewingKey,
    PaymentAddress,
    SparkAddress,
    SparkScanKey,
    // Lelantus Spark key chain (Phase 2)
    SparkSpendKey,
    SpendKey,
};
pub use persistence::{
    change_password, decrypt, decrypt_sidecar_with_fallback, derive_key, derive_key_default,
    encrypt, generate_mnemonic, load_wallet, mnemonic_to_seed, save_wallet, wallet_exists,
    WalletData, WalletHeader,
};
pub use scanner::{
    encrypt_amount, generate_view_tag, DecryptedOutput, ScanKeys, ScanStats, WalletScanner,
};
pub use wallet::{SharedWallet, Wallet, WalletInfo, WalletState};
pub use wallet_keys::WalletKeys;
// Re-export subaddress types at the `wallet::` level so `persistence.rs`
// can reach `super::SubaddressData` and other modules don't need the
// deeper path.
pub use subaddress::{
    Subaddress, SubaddressData, SubaddressIndex, SubaddressManager, SubaddressRecord,
};
