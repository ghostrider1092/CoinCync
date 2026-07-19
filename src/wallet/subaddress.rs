//! # Subaddress Implementation for CoinCync 1.0
//!
//! Subaddresses allow generating unlimited receiving addresses from a single wallet.
//! Each subaddress has:
//! - Unique spend public key (derived deterministically)
//! - Shared view key (same as main wallet)
//!
//! ## Derivation Scheme
//!
//! For subaddress at (account=i, index=j):
//! ```text
//! m = H("COINCYNC_SUBADDR_v1" || view_secret || i || j)
//! subaddress_spend_public = m*G + spend_public
//! ```
//!
//! The view key remains the same, allowing the wallet to scan for all
//! subaddresses with a single view key.
//!
//! ## Security
//!
//! - Subaddresses cannot be linked to each other or the main address by observers
//! - Only the wallet owner (with view key) can identify which subaddresses belong together
//! - Spending requires the original spend_secret plus the derivation scalar m

use borsh::{BorshDeserialize, BorshSerialize};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use crate::crypto::{PublicPoint, SecretScalar};
use crate::primitives::{hash_domain, Address, Network, PublicKey, SecretKey};

/// Maximum number of subaddresses per account (to prevent DoS).
///
/// Hard limit at 10,000 keeps the lookahead scan O(10K) per account in the
/// worst case (see `extend_lookahead` at line ~287). Wallet UI typically
/// stays below 100 indices per account; 10K is ~100× headroom.
///
/// NOTE: this is a WALLET-INTERNAL bound, not a consensus constant — the
/// chain has no knowledge of subaddress indices, only stealth addresses.
/// If a future format negotiates higher caps over the wallet wire protocol,
/// this can be raised without a hard fork. Coupled lock-step with
/// MAX_ACCOUNTS below.
pub const MAX_SUBADDRESSES_PER_ACCOUNT: u32 = 10_000;

/// Maximum number of accounts.
///
/// Wallet-internal cap (see notes on MAX_SUBADDRESSES_PER_ACCOUNT). 100
/// accounts × 10,000 subaddresses = 1,000,000 max derivations per wallet,
/// which bounds the in-memory subaddress index size at ~64 MB worst case
/// (each entry ≈ 64 bytes for the (account, index) → spend_pub map).
pub const MAX_ACCOUNTS: u32 = 100;

/// A subaddress index (account, index within account)
#[derive(
    Clone,
    Copy,
    Debug,
    PartialEq,
    Eq,
    Hash,
    Serialize,
    Deserialize,
    BorshSerialize,
    BorshDeserialize,
)]
pub struct SubaddressIndex {
    /// Account index (0 = main account)
    pub account: u32,
    /// Subaddress index within account (0 = main address for account 0)
    pub index: u32,
}

impl SubaddressIndex {
    /// Main address (account 0, index 0)
    pub const MAIN: SubaddressIndex = SubaddressIndex {
        account: 0,
        index: 0,
    };

    /// Create a new subaddress index
    pub fn new(account: u32, index: u32) -> Self {
        SubaddressIndex { account, index }
    }

    /// Check if this is the main address
    pub fn is_main(&self) -> bool {
        self.account == 0 && self.index == 0
    }
}

impl std::fmt::Display for SubaddressIndex {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}/{}", self.account, self.index)
    }
}

/// A generated subaddress with its keys
#[derive(Clone)]
pub struct Subaddress {
    /// The subaddress index
    pub index: SubaddressIndex,
    /// The derived spend public key
    pub spend_public: PublicKey,
    /// The view public key (same as main wallet)
    pub view_public: PublicKey,
    /// Optional label for this subaddress
    pub label: String,
    /// Whether this subaddress has been used (received funds)
    pub used: bool,
}

impl Subaddress {
    /// Get the full address for this subaddress
    pub fn address(&self, network: Network) -> Address {
        let mut addr = Address::new(network, self.spend_public, self.view_public);
        // Mark as subaddress type (except for main address)
        if !self.index.is_main() {
            addr.address_type = crate::primitives::AddressType::Subaddress;
        }
        addr
    }
}

/// Subaddress manager for a wallet
pub struct SubaddressManager {
    /// View secret key (for derivation)
    view_secret: SecretKey,
    /// Spend public key (main wallet)
    spend_public: PublicKey,
    /// View public key (shared by all subaddresses)
    view_public: PublicKey,
    /// Generated subaddresses by index
    subaddresses: HashMap<SubaddressIndex, Subaddress>,
    /// Spend public key -> index mapping (for fast lookup during scanning)
    spend_to_index: HashMap<[u8; 32], SubaddressIndex>,
    /// Highest generated index per account
    highest_index: HashMap<u32, u32>,
}

impl SubaddressManager {
    /// Create a new subaddress manager
    pub fn new(view_secret: SecretKey, spend_public: PublicKey, view_public: PublicKey) -> Self {
        let mut manager = SubaddressManager {
            view_secret,
            spend_public,
            view_public,
            subaddresses: HashMap::new(),
            spend_to_index: HashMap::new(),
            highest_index: HashMap::new(),
        };

        // Add main address (0/0)
        manager.add_main_address();

        manager
    }

    /// Add the main address (0/0)
    fn add_main_address(&mut self) {
        let main = Subaddress {
            index: SubaddressIndex::MAIN,
            spend_public: self.spend_public,
            view_public: self.view_public,
            label: "Primary".to_string(),
            used: false,
        };

        self.spend_to_index
            .insert(*self.spend_public.as_bytes(), SubaddressIndex::MAIN);
        self.subaddresses.insert(SubaddressIndex::MAIN, main);
        self.highest_index.insert(0, 0);
    }

    /// Derive the scalar m for a subaddress index.
    ///
    /// AUDIT (R-85 fix, 2026-07-03): pre-fix code did
    ///   `[view_secret.as_bytes(), account_bytes, index_bytes].concat()`
    /// which allocates a heap `Vec<u8>` containing the raw
    /// view_secret bytes. The Vec drops after hashing WITHOUT
    /// zeroization, leaving view_secret bytes in freed heap for
    /// the next allocator hit. Build the buffer explicitly and
    /// wipe before scope-exit.
    fn derive_scalar(&self, index: SubaddressIndex) -> SecretScalar {
        // #280: delegate to the ONE canonical primitive in the crypto layer so
        // the wallet, the crypto Subaddress helper, and the audit scanner all
        // derive identically. The byte layout is unchanged
        // (COINCYNC_SUBADDR_v1 over view_secret ‖ account_le32 ‖ index_le32),
        // so existing subaddresses remain byte-for-byte identical — no funds are
        // lost. The R-85 secret-wipe now lives inside the primitive.
        crate::crypto::subaddress_spend_scalar(&self.view_secret, index.account, index.index)
    }

    /// Generate a subaddress at a specific index
    pub fn generate_at(&mut self, index: SubaddressIndex) -> Option<&Subaddress> {
        // Validate bounds
        if index.account >= MAX_ACCOUNTS || index.index >= MAX_SUBADDRESSES_PER_ACCOUNT {
            return None;
        }

        // Main address is special
        if index.is_main() {
            return self.subaddresses.get(&index);
        }

        // Check if already generated
        if self.subaddresses.contains_key(&index) {
            return self.subaddresses.get(&index);
        }

        // Derive the subaddress spend public key
        // D_i = m*G + B (where B is main spend public)
        let m = self.derive_scalar(index);
        let m_point = m.to_public(); // m*G

        // Add m*G to spend_public
        let spend_point = match PublicPoint::from_bytes(*self.spend_public.as_bytes()) {
            Some(p) => p,
            None => return None, // Invalid main spend public key
        };

        let subaddr_spend_point = spend_point.add(&m_point);
        let subaddr_spend_public = PublicKey::from_bytes(subaddr_spend_point.to_bytes());

        let subaddress = Subaddress {
            index,
            spend_public: subaddr_spend_public,
            view_public: self.view_public,
            label: String::new(),
            used: false,
        };

        // Store mapping for fast lookup
        self.spend_to_index
            .insert(*subaddr_spend_public.as_bytes(), index);

        // Update highest index
        let highest = self.highest_index.entry(index.account).or_insert(0);
        if index.index > *highest {
            *highest = index.index;
        }

        self.subaddresses.insert(index, subaddress);
        self.subaddresses.get(&index)
    }

    /// Generate the next subaddress in an account
    pub fn generate_next(&mut self, account: u32) -> Option<&Subaddress> {
        if account >= MAX_ACCOUNTS {
            return None;
        }

        let next_index = self.highest_index.get(&account).copied().unwrap_or(0) + 1;

        // For account 0, index 0 is main, so start from 1
        let next_index = if account == 0 && next_index == 0 {
            1
        } else {
            next_index
        };

        self.generate_at(SubaddressIndex::new(account, next_index))
    }

    /// Get a subaddress by index
    pub fn get(&self, index: SubaddressIndex) -> Option<&Subaddress> {
        self.subaddresses.get(&index)
    }

    /// Get mutable subaddress by index
    pub fn get_mut(&mut self, index: SubaddressIndex) -> Option<&mut Subaddress> {
        self.subaddresses.get_mut(&index)
    }

    /// Find subaddress index by spend public key
    pub fn find_by_spend_public(&self, spend_public: &PublicKey) -> Option<SubaddressIndex> {
        self.spend_to_index.get(spend_public.as_bytes()).copied()
    }

    /// Get all subaddresses for an account
    pub fn get_account(&self, account: u32) -> Vec<&Subaddress> {
        self.subaddresses
            .values()
            .filter(|s| s.index.account == account)
            .collect()
    }

    /// Get all subaddresses
    pub fn all(&self) -> Vec<&Subaddress> {
        self.subaddresses.values().collect()
    }

    /// Get number of subaddresses
    pub fn count(&self) -> usize {
        self.subaddresses.len()
    }

    /// Set label for a subaddress
    pub fn set_label(&mut self, index: SubaddressIndex, label: &str) -> bool {
        if let Some(subaddr) = self.subaddresses.get_mut(&index) {
            subaddr.label = label.to_string();
            true
        } else {
            false
        }
    }

    /// Mark a subaddress as used
    pub fn mark_used(&mut self, index: SubaddressIndex) {
        if let Some(subaddr) = self.subaddresses.get_mut(&index) {
            subaddr.used = true;
        }
    }

    /// Get all spend public keys for scanning
    pub fn all_spend_public_keys(&self) -> Vec<(PublicKey, SubaddressIndex)> {
        self.subaddresses
            .iter()
            .map(|(idx, sub)| (sub.spend_public, *idx))
            .collect()
    }

    /// Pregenerate subaddresses for lookahead scanning
    /// This generates subaddresses up to `lookahead` beyond the highest used index
    pub fn pregenerate_lookahead(&mut self, account: u32, lookahead: u32) {
        let highest_used = self
            .subaddresses
            .values()
            .filter(|s| s.index.account == account && s.used)
            .map(|s| s.index.index)
            .max()
            .unwrap_or(0);

        let target = (highest_used + lookahead).min(MAX_SUBADDRESSES_PER_ACCOUNT - 1);
        let current_highest = self.highest_index.get(&account).copied().unwrap_or(0);

        for i in (current_highest + 1)..=target {
            self.generate_at(SubaddressIndex::new(account, i));
        }
    }

    /// Export subaddress data for persistence
    pub fn export(&self) -> SubaddressData {
        SubaddressData {
            subaddresses: self
                .subaddresses
                .iter()
                .map(|(idx, sub)| SubaddressRecord {
                    account: idx.account,
                    index: idx.index,
                    label: sub.label.clone(),
                    used: sub.used,
                })
                .collect(),
        }
    }

    /// Import subaddress data from persistence
    pub fn import(&mut self, data: &SubaddressData) {
        for record in &data.subaddresses {
            let index = SubaddressIndex::new(record.account, record.index);

            // Generate the subaddress
            self.generate_at(index);

            // Set label and used status
            if let Some(sub) = self.subaddresses.get_mut(&index) {
                sub.label = record.label.clone();
                sub.used = record.used;
            }
        }
    }
}

/// Serializable subaddress record
#[derive(Clone, Debug, Serialize, Deserialize, BorshSerialize, BorshDeserialize)]
pub struct SubaddressRecord {
    pub account: u32,
    pub index: u32,
    pub label: String,
    pub used: bool,
}

/// Serializable subaddress data for wallet persistence
#[derive(Clone, Debug, Default, Serialize, Deserialize, BorshSerialize, BorshDeserialize)]
pub struct SubaddressData {
    pub subaddresses: Vec<SubaddressRecord>,
}

/// Compute the spend private key for spending from a subaddress
///
/// When spending from subaddress i, the effective spend secret is:
/// x_i = x + m_i (where x is main spend secret, m_i is the derivation scalar)
pub fn compute_subaddress_spend_secret(
    spend_secret: &SecretKey,
    view_secret: &SecretKey,
    index: SubaddressIndex,
) -> SecretKey {
    if index.is_main() {
        return spend_secret.clone();
    }

    // R-86 fix (2026-07-03): same view_secret concat-leak class as
    // R-85 above. Build the buffer explicitly and wipe on scope exit.
    let mut input = Vec::with_capacity(32 + 8 + 8);
    input.extend_from_slice(view_secret.as_bytes());
    input.extend_from_slice(&index.account.to_le_bytes());
    input.extend_from_slice(&index.index.to_le_bytes());

    let hash = hash_domain(b"COINCYNC_SUBADDR_v1", &input);
    {
        use zeroize::Zeroize;
        input.zeroize();
    }
    let m = SecretScalar::from_bytes(*hash.as_bytes());

    // x_i = x + m
    let x = SecretScalar::from_bytes(*spend_secret.as_bytes());
    let x_i = x.add(&m);

    SecretKey::from_bytes(x_i.to_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::SecretScalar;
    use rand::rngs::OsRng;

    fn generate_test_keys() -> (SecretKey, PublicKey, SecretKey, PublicKey) {
        let spend_scalar = SecretScalar::random(&mut OsRng);
        let view_scalar = SecretScalar::random(&mut OsRng);

        let spend_secret = SecretKey::from_bytes(spend_scalar.to_bytes());
        let spend_public = PublicKey::from_bytes(spend_scalar.to_public().to_bytes());
        let view_secret = SecretKey::from_bytes(view_scalar.to_bytes());
        let view_public = PublicKey::from_bytes(view_scalar.to_public().to_bytes());

        (spend_secret, spend_public, view_secret, view_public)
    }

    #[test]
    fn test_subaddress_generation() {
        let (_, spend_public, view_secret, view_public) = generate_test_keys();

        let mut manager = SubaddressManager::new(view_secret, spend_public, view_public);

        // Main address should exist
        assert!(manager.get(SubaddressIndex::MAIN).is_some());

        // Generate some subaddresses - copy the keys to avoid borrow issues
        manager.generate_at(SubaddressIndex::new(0, 1));
        manager.generate_at(SubaddressIndex::new(0, 2));

        let sub1_spend = manager
            .get(SubaddressIndex::new(0, 1))
            .unwrap()
            .spend_public;
        let sub1_view = manager.get(SubaddressIndex::new(0, 1)).unwrap().view_public;
        let sub2_spend = manager
            .get(SubaddressIndex::new(0, 2))
            .unwrap()
            .spend_public;
        let sub2_view = manager.get(SubaddressIndex::new(0, 2)).unwrap().view_public;

        // Subaddresses should have different spend keys
        assert_ne!(sub1_spend.as_bytes(), sub2_spend.as_bytes());

        // But same view key
        assert_eq!(sub1_view.as_bytes(), sub2_view.as_bytes());
    }

    #[test]
    fn test_subaddress_lookup() {
        let (_, spend_public, view_secret, view_public) = generate_test_keys();

        let mut manager = SubaddressManager::new(view_secret, spend_public, view_public);

        let sub = manager.generate_at(SubaddressIndex::new(0, 5)).unwrap();
        let spend_key = sub.spend_public;

        // Should be able to find by spend public key
        let found = manager.find_by_spend_public(&spend_key);
        assert_eq!(found, Some(SubaddressIndex::new(0, 5)));
    }

    #[test]
    fn test_subaddress_deterministic() {
        let (_, spend_public, view_secret, view_public) = generate_test_keys();

        // Create two managers with same keys
        let mut manager1 = SubaddressManager::new(view_secret.clone(), spend_public, view_public);
        let mut manager2 = SubaddressManager::new(view_secret, spend_public, view_public);

        let idx = SubaddressIndex::new(1, 42);
        let sub1 = manager1.generate_at(idx).unwrap();
        let sub2 = manager2.generate_at(idx).unwrap();

        // Should derive the same keys
        assert_eq!(sub1.spend_public.as_bytes(), sub2.spend_public.as_bytes());
    }

    #[test]
    fn test_subaddress_spend_secret() {
        let (spend_secret, spend_public, view_secret, view_public) = generate_test_keys();

        let mut manager = SubaddressManager::new(view_secret.clone(), spend_public, view_public);

        let idx = SubaddressIndex::new(0, 3);
        let subaddr = manager.generate_at(idx).unwrap();

        // Compute the subaddress spend secret
        let sub_spend_secret = compute_subaddress_spend_secret(&spend_secret, &view_secret, idx);

        // Verify: the public key from sub_spend_secret should match subaddress spend public
        let derived_public = SecretScalar::from_bytes(*sub_spend_secret.as_bytes()).to_public();

        assert_eq!(
            derived_public.to_bytes(),
            *subaddr.spend_public.as_bytes(),
            "Derived spend public should match subaddress spend public"
        );
    }

    #[test]
    fn test_main_address_unchanged() {
        let (spend_secret, spend_public, view_secret, view_public) = generate_test_keys();

        let manager = SubaddressManager::new(view_secret.clone(), spend_public, view_public);

        let main = manager.get(SubaddressIndex::MAIN).unwrap();

        // Main address spend key should be the original
        assert_eq!(main.spend_public.as_bytes(), spend_public.as_bytes());

        // Main address spend secret should be unchanged
        let main_spend_secret =
            compute_subaddress_spend_secret(&spend_secret, &view_secret, SubaddressIndex::MAIN);
        assert_eq!(main_spend_secret.as_bytes(), spend_secret.as_bytes());
    }

    #[test]
    fn test_generate_next() {
        let (_, spend_public, view_secret, view_public) = generate_test_keys();

        let mut manager = SubaddressManager::new(view_secret, spend_public, view_public);

        // Generate next should give index 1 (0 is main)
        let sub1 = manager.generate_next(0).unwrap();
        assert_eq!(sub1.index, SubaddressIndex::new(0, 1));

        let sub2 = manager.generate_next(0).unwrap();
        assert_eq!(sub2.index, SubaddressIndex::new(0, 2));
    }

    #[test]
    fn test_export_import() {
        let (_, spend_public, view_secret, view_public) = generate_test_keys();

        let mut manager = SubaddressManager::new(view_secret.clone(), spend_public, view_public);

        // Generate some subaddresses with labels
        manager.generate_at(SubaddressIndex::new(0, 1));
        manager.set_label(SubaddressIndex::new(0, 1), "Donations");
        manager.mark_used(SubaddressIndex::new(0, 1));

        manager.generate_at(SubaddressIndex::new(0, 2));
        manager.set_label(SubaddressIndex::new(0, 2), "Shop");

        // Export
        let data = manager.export();

        // Create new manager and import
        let mut manager2 = SubaddressManager::new(view_secret, spend_public, view_public);
        manager2.import(&data);

        // Verify data was imported
        let sub1 = manager2.get(SubaddressIndex::new(0, 1)).unwrap();
        assert_eq!(sub1.label, "Donations");
        assert!(sub1.used);

        let sub2 = manager2.get(SubaddressIndex::new(0, 2)).unwrap();
        assert_eq!(sub2.label, "Shop");
        assert!(!sub2.used);
    }

    #[test]
    fn test_cross_account_no_collision() {
        let (_, spend_public, view_secret, view_public) = generate_test_keys();
        let mut manager = SubaddressManager::new(view_secret, spend_public, view_public);

        // Same index in different accounts should produce different keys.
        // DRIVE-BY (C1 audit fix): `generate_at` returns `Option<&Subaddress>`
        // — a borrow of `manager`. Two consecutive calls would overlap mutable
        // borrows, so each result is converted to an owned `Vec<u8>` before
        // the next call.
        let bytes_0_1: Vec<u8> = manager
            .generate_at(SubaddressIndex::new(0, 1))
            .unwrap()
            .spend_public
            .as_bytes()
            .to_vec();
        let bytes_1_1: Vec<u8> = manager
            .generate_at(SubaddressIndex::new(1, 1))
            .unwrap()
            .spend_public
            .as_bytes()
            .to_vec();

        assert_ne!(
            bytes_0_1, bytes_1_1,
            "Account 0 index 1 must differ from account 1 index 1"
        );
    }
}
