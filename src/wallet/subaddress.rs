//! # Subaddress Implementation for CoinCync 1.0
//!
//! Subaddresses allow generating unlimited receiving addresses from a single wallet.
//! Each subaddress has:
//! - Unique spend public key (derived deterministically)
//! - Per-subaddress view key `C_i = a*D_i` (unlinkable across subaddresses)
//!
//! ## Derivation Scheme
//!
//! For subaddress at (account=i, index=j):
//! ```text
//! m   = H("COINCYNC_SUBADDR_v1" || view_secret || i || j)
//! D_i = m*G + spend_public            (subaddress spend key)
//! C_i = view_secret * D_i             (subaddress view key)
//! ```
//!
//! Each subaddress publishes a DISTINCT view key `C_i = a*D_i`, so subaddresses
//! are unlinkable to each other and to the main address. The wallet still scans
//! for all of them with the single view secret `a`: a payment to a subaddress
//! uses tx pubkey `R = r*D_i`, and the scanner computes `a*R = r*C_i`.
//!
//! ## Security
//!
//! - Subaddresses cannot be linked to each other or the main address by observers
//! - Only the wallet owner (with view key) can identify which subaddresses belong together
//! - Spending requires the original spend_secret plus the derivation scalar m
//!
//! ## Audit map
//! Each `§` is a code section below; it states the INVARIANT it guarantees, the
//! THREAT it defends, and the TESTS that prove it.
//!
//! - **§1 `SubaddressManager::generate_at`** — INVARIANT: derivation is
//!   deterministic and distinct per `(account, index)` — each subaddress gets a
//!   unique spend key `D_i` and a distinct, unlinkable view key `C_i = a·D_i`.
//!   THREAT: colliding or linkable subaddresses would deanonymize a wallet's
//!   receiving addresses. TESTS: `test_subaddress_generation`,
//!   `test_subaddress_deterministic`, `test_cross_account_no_collision`.
//! - **§2 `SubaddressManager::generate_next`** — INVARIANT: allocates the next
//!   sequential index in an account (skipping the main `0/0`).
//!   THREAT: index reuse would collide two receive addresses.
//!   TESTS: `test_generate_next`.
//! - **§3 `find_by_spend_public` / `all_spend_public_keys`** — INVARIANT: every
//!   generated subaddress (main + derived) is recoverable by spend key on scan,
//!   mapping back to its exact index.
//!   THREAT: a missing scan key means an owned output is never detected.
//!   TESTS: `test_subaddress_lookup`, `all_spend_public_keys_returns_every_generated_subaddress`.
//! - **§4 `compute_subaddress_spend_secret`** — INVARIANT: the subaddress spend
//!   secret `x_i = x + m` reproduces exactly the subaddress spend public `D_i`,
//!   and the main `0/0` secret is returned unchanged.
//!   THREAT: a mismatched offset (W-A) would make every subaddress output
//!   silently unspendable. TESTS: `test_subaddress_spend_secret`, `test_main_address_unchanged`.
//! - **§5 `pregenerate_lookahead`** — INVARIANT: extends the generated range to
//!   exactly `highest_used + lookahead`, clamped to `MAX_SUBADDRESSES_PER_ACCOUNT - 1`,
//!   starting from index 1 on a fresh account.
//!   THREAT: too small a gap window misses funds after a seed restore; an
//!   unclamped one derives out-of-range indices.
//!   TESTS: `pregenerate_lookahead_generates_up_to_highest_used_plus_lookahead`,
//!   `pregenerate_lookahead_caps_at_account_max`,
//!   `pregenerate_lookahead_on_fresh_account_generates_lookahead_from_index_one`,
//!   `mark_used_influences_subsequent_lookahead_target`.
//! - **§6 `export` / `import`** — INVARIANT: export→import round-trips labels and
//!   used flags and regenerates byte-identical spend keys deterministically.
//!   THREAT: a non-deterministic restore would leave the wallet not controlling
//!   its own subaddresses. TESTS: `test_export_import`,
//!   `export_import_roundtrips_labels_and_used_flags`, `import_regenerates_identical_spend_keys`.
//! - **§7 wallet ↔ audit derivation / `Subaddress::address`** — INVARIANT: the
//!   wallet and the audit/view-key path derive identical keys per `(account,
//!   index)`, the main `0/0` is never double-counted, and a subaddress encodes to
//!   a distinct, round-tripping address.
//!   THREAT: Jun #26 — divergent formulas would make an auditor's key unable to
//!   scan any wallet subaddress. TESTS: `test_wallet_and_audit_derivation_match`,
//!   `generate_at_main_zero_zero_is_not_double_counted`,
//!   `subaddress_address_differs_from_primary_and_roundtrips`.

use borsh::{BorshDeserialize, BorshSerialize};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use crate::crypto::{PublicPoint, SecretScalar};
use crate::primitives::{Address, Network, PublicKey, SecretKey};

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
        // Single canonical, account-aware derivation — shared byte-for-byte
        // with the audit / view-key scan path via `crypto::subaddress_scalar`,
        // so the two paths' keys always match (Jun #26). Formerly this was a
        // duplicated inline formula that diverged from the audit path.
        crate::crypto::subaddress_scalar(&self.view_secret, index.account, index.index)
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

        // Subaddress view key C_i = a * D_i (NOT the main a*G), so two
        // subaddresses of one wallet are unlinkable by their published view
        // keys. Still scannable with the single view secret a: the sender sets
        // R = r*D_i (crypto::generate_stealth_address_checked_ext) and the
        // scanner computes a*R = r*(a*D_i) = r*C_i (pre-mainnet review #3).
        let view_scalar = SecretScalar::from_bytes(*self.view_secret.as_bytes());
        let subaddr_view_public =
            PublicKey::from_bytes(subaddr_spend_point.mul(&view_scalar).to_bytes());

        let subaddress = Subaddress {
            index,
            spend_public: subaddr_spend_public,
            view_public: subaddr_view_public,
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

    // W-A / single-source-of-truth (2026-08-18): derive the per-subaddress
    // offset m via the SAME `crypto::subaddress_scalar` the D_i spend-pubkey
    // derivation uses (`SubaddressManager::derive_scalar`). This previously
    // inlined a second copy of the hash; if the two ever diverged, `x_i*G` would
    // no longer equal `D_i` and every subaddress-received output would silently
    // become unspendable. One function makes that impossible. (`subaddress_scalar`
    // zeroizes its own view-secret buffer — the R-86 concat-leak fix is
    // preserved inside it.)
    let m = crate::crypto::subaddress_scalar(view_secret, index.account, index.index);

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

        // ...and distinct view keys C_i = a*D_i (unlinkable). Previously all
        // subaddresses shared the main a*G view key, which made two subaddresses
        // of one wallet linkable by a byte-compare (pre-mainnet review #3).
        assert_ne!(sub1_view.as_bytes(), sub2_view.as_bytes());
        assert_ne!(sub1_view.as_bytes(), view_public.as_bytes());
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

    /// Jun #26: the wallet (`SubaddressManager`) and the audit / view-key path
    /// (`crypto::Subaddress::generate`) must derive **identical** subaddress
    /// keys for the same `(account, index)`. Before the unification the two used
    /// incompatible formulas, so an auditor's key could not scan any wallet
    /// subaddress. This locks the fix.
    #[test]
    fn test_wallet_and_audit_derivation_match() {
        let (_, spend_public, view_secret, view_public) = generate_test_keys();
        let mut manager = SubaddressManager::new(view_secret.clone(), spend_public, view_public);

        for &(account, index) in &[(0u32, 1u32), (0, 5), (1, 0), (1, 7), (3, 2)] {
            let wallet_spend: Vec<u8> = manager
                .generate_at(SubaddressIndex::new(account, index))
                .unwrap()
                .spend_public
                .as_bytes()
                .to_vec();
            let audit_spend =
                crate::crypto::Subaddress::generate(&spend_public, &view_secret, account, index)
                    .unwrap()
                    .spend_public;
            assert_eq!(
                wallet_spend,
                audit_spend.as_bytes().to_vec(),
                "wallet vs audit subaddress key mismatch at (account={account}, index={index})"
            );
        }
    }

    // ── lookahead pregeneration (gap-limit correctness) ────────────────────

    /// On a used-populated account, `pregenerate_lookahead` extends the
    /// generated range to exactly `highest_used + lookahead` and no further.
    #[test]
    fn pregenerate_lookahead_generates_up_to_highest_used_plus_lookahead() {
        let (_, spend_public, view_secret, view_public) = generate_test_keys();
        let mut manager = SubaddressManager::new(view_secret, spend_public, view_public);

        // Highest USED index is 3.
        manager.generate_at(SubaddressIndex::new(0, 3));
        manager.mark_used(SubaddressIndex::new(0, 3));

        manager.pregenerate_lookahead(0, 5);

        // highest_used(3) + lookahead(5) == 8 must be generated, 9 must not.
        assert!(
            manager.get(SubaddressIndex::new(0, 8)).is_some(),
            "index highest_used+lookahead must be pregenerated"
        );
        assert!(
            manager.get(SubaddressIndex::new(0, 9)).is_none(),
            "nothing beyond highest_used+lookahead may be pregenerated"
        );
    }

    /// The lookahead target is clamped to `MAX_SUBADDRESSES_PER_ACCOUNT - 1`
    /// so it can never generate an out-of-range index.
    #[test]
    fn pregenerate_lookahead_caps_at_account_max() {
        let (_, spend_public, view_secret, view_public) = generate_test_keys();
        let mut manager = SubaddressManager::new(view_secret, spend_public, view_public);

        // Used index just below the cap.
        let near_max = MAX_SUBADDRESSES_PER_ACCOUNT - 2; // 9998
        manager.generate_at(SubaddressIndex::new(0, near_max));
        manager.mark_used(SubaddressIndex::new(0, near_max));

        // A lookahead that would overshoot the cap must be clamped.
        manager.pregenerate_lookahead(0, 100);

        assert!(
            manager
                .get(SubaddressIndex::new(0, MAX_SUBADDRESSES_PER_ACCOUNT - 1))
                .is_some(),
            "the capped index (MAX-1) must be generated"
        );
        // MAX itself is out of range and can never exist.
        assert!(
            manager
                .get(SubaddressIndex::new(0, MAX_SUBADDRESSES_PER_ACCOUNT))
                .is_none(),
            "no index at/above the cap may exist"
        );
    }

    /// On a fresh account with no used addresses, lookahead starts from index 1
    /// and generates exactly `lookahead` addresses — this is the restore-time
    /// gap window that governs funds-detection after a seed restore.
    #[test]
    fn pregenerate_lookahead_on_fresh_account_generates_lookahead_from_index_one() {
        let (_, spend_public, view_secret, view_public) = generate_test_keys();
        let mut manager = SubaddressManager::new(view_secret, spend_public, view_public);

        // Account 5 is untouched (no addresses generated, none used).
        manager.pregenerate_lookahead(5, 4);

        // Exactly indices 1..=4 exist for account 5 (index 0 is not generated;
        // only (0,0) is the main address).
        assert!(manager.get(SubaddressIndex::new(5, 0)).is_none());
        for i in 1..=4 {
            assert!(
                manager.get(SubaddressIndex::new(5, i)).is_some(),
                "fresh-account lookahead must generate index {i}"
            );
        }
        assert!(manager.get(SubaddressIndex::new(5, 5)).is_none());
        assert_eq!(
            manager.get_account(5).len(),
            4,
            "fresh account must have exactly `lookahead` addresses"
        );
    }

    /// `mark_used` raises the highest-used index, which in turn pushes the
    /// lookahead target higher on the next pregeneration pass.
    #[test]
    fn mark_used_influences_subsequent_lookahead_target() {
        let (_, spend_public, view_secret, view_public) = generate_test_keys();

        // Manager A: index 1 is marked used → highest_used == 1 → target 3.
        let mut a = SubaddressManager::new(view_secret.clone(), spend_public, view_public);
        a.generate_at(SubaddressIndex::new(0, 1));
        a.mark_used(SubaddressIndex::new(0, 1));
        a.pregenerate_lookahead(0, 2);
        assert!(
            a.get(SubaddressIndex::new(0, 3)).is_some(),
            "marked-used index must extend the lookahead window"
        );

        // Manager B: same generation but NOT used → highest_used == 0 → target 2.
        let mut b = SubaddressManager::new(view_secret, spend_public, view_public);
        b.generate_at(SubaddressIndex::new(0, 1));
        b.pregenerate_lookahead(0, 2);
        assert!(
            b.get(SubaddressIndex::new(0, 3)).is_none(),
            "without a used marker the window must not reach index 3"
        );
    }

    // ── export / import round-trip and deterministic regeneration ──────────

    /// Export then import round-trips labels and used flags across a fresh
    /// manager (persistence restore path).
    #[test]
    fn export_import_roundtrips_labels_and_used_flags() {
        let (_, spend_public, view_secret, view_public) = generate_test_keys();
        let mut manager = SubaddressManager::new(view_secret.clone(), spend_public, view_public);

        manager.generate_at(SubaddressIndex::new(0, 1));
        manager.set_label(SubaddressIndex::new(0, 1), "Salary");
        manager.mark_used(SubaddressIndex::new(0, 1));
        manager.generate_at(SubaddressIndex::new(2, 4));
        manager.set_label(SubaddressIndex::new(2, 4), "Cold");

        let data = manager.export();

        let mut restored = SubaddressManager::new(view_secret, spend_public, view_public);
        restored.import(&data);

        let s1 = restored.get(SubaddressIndex::new(0, 1)).unwrap();
        assert_eq!(s1.label, "Salary");
        assert!(s1.used);
        let s2 = restored.get(SubaddressIndex::new(2, 4)).unwrap();
        assert_eq!(s2.label, "Cold");
        assert!(!s2.used);
    }

    /// Import must regenerate byte-identical spend keys deterministically, so a
    /// restored wallet controls exactly the same subaddresses (funds
    /// correctness).
    #[test]
    fn import_regenerates_identical_spend_keys() {
        let (_, spend_public, view_secret, view_public) = generate_test_keys();
        let mut manager = SubaddressManager::new(view_secret.clone(), spend_public, view_public);

        let idx = SubaddressIndex::new(1, 7);
        let original_spend = manager.generate_at(idx).unwrap().spend_public;
        let original_bytes = *original_spend.as_bytes();
        let data = manager.export();

        let mut restored = SubaddressManager::new(view_secret, spend_public, view_public);
        restored.import(&data);

        let restored_spend = restored.get(idx).unwrap().spend_public;
        assert_eq!(
            restored_spend.as_bytes(),
            &original_bytes,
            "imported subaddress must regenerate the identical spend key"
        );
    }

    /// `all_spend_public_keys` must surface every generated subaddress (main +
    /// derived), which is what the scanner is fed to detect owned outputs.
    #[test]
    fn all_spend_public_keys_returns_every_generated_subaddress() {
        let (_, spend_public, view_secret, view_public) = generate_test_keys();
        let mut manager = SubaddressManager::new(view_secret, spend_public, view_public);

        manager.generate_at(SubaddressIndex::new(0, 1));
        manager.generate_at(SubaddressIndex::new(0, 2));
        manager.generate_at(SubaddressIndex::new(3, 9));

        let all = manager.all_spend_public_keys();
        // One entry per subaddress, including the main (0,0).
        assert_eq!(all.len(), manager.count());
        assert_eq!(all.len(), 4);

        // Every returned (pubkey, index) pair is internally consistent, and the
        // expected indices are all present.
        for &(pk, idx) in &all {
            assert_eq!(manager.get(idx).unwrap().spend_public.as_bytes(), pk.as_bytes());
        }
        let indices: Vec<SubaddressIndex> = all.iter().map(|(_, i)| *i).collect();
        for expected in [
            SubaddressIndex::MAIN,
            SubaddressIndex::new(0, 1),
            SubaddressIndex::new(0, 2),
            SubaddressIndex::new(3, 9),
        ] {
            assert!(indices.contains(&expected), "missing {expected} in scan keys");
        }
    }

    /// Regenerating the main (0,0) address must not create a second entry — the
    /// main address is counted exactly once.
    #[test]
    fn generate_at_main_zero_zero_is_not_double_counted() {
        let (_, spend_public, view_secret, view_public) = generate_test_keys();
        let mut manager = SubaddressManager::new(view_secret, spend_public, view_public);

        assert_eq!(manager.count(), 1, "fresh manager holds only the main address");
        manager.generate_at(SubaddressIndex::MAIN);
        manager.generate_at(SubaddressIndex::new(0, 0));
        assert_eq!(manager.count(), 1, "main (0,0) must not be double-counted");
        assert_eq!(
            manager.get(SubaddressIndex::MAIN).unwrap().spend_public.as_bytes(),
            spend_public.as_bytes()
        );
    }

    /// A subaddress encodes to a string distinct from the primary address and
    /// round-trips through parse (on testnet, where subaddresses are enabled).
    #[test]
    fn subaddress_address_differs_from_primary_and_roundtrips() {
        let (_, spend_public, view_secret, view_public) = generate_test_keys();
        let mut manager = SubaddressManager::new(view_secret, spend_public, view_public);
        manager.generate_at(SubaddressIndex::new(0, 1));

        let net = Network::Testnet;
        let sub_addr = manager.get(SubaddressIndex::new(0, 1)).unwrap().address(net);
        let main_addr = manager.get(SubaddressIndex::MAIN).unwrap().address(net);

        assert_eq!(sub_addr.address_type, crate::primitives::AddressType::Subaddress);
        assert_eq!(main_addr.address_type, crate::primitives::AddressType::Standard);

        let sub_str = sub_addr.to_string();
        let main_str = main_addr.to_string();
        assert_ne!(sub_str, main_str, "subaddress string must differ from primary");

        let parsed = Address::from_string(&sub_str).expect("testnet subaddress must round-trip");
        assert_eq!(parsed.address_type, crate::primitives::AddressType::Subaddress);
        assert_eq!(
            parsed.spend_public_key.as_bytes(),
            sub_addr.spend_public_key.as_bytes()
        );
        assert_eq!(
            parsed.view_public_key.as_bytes(),
            sub_addr.view_public_key.as_bytes()
        );
    }
}
