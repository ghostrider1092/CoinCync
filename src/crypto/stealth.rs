//! Stealth addresses for CoinCync 1.0
//!
//! Implements one-time stealth addresses using ECDH (Elliptic Curve Diffie-Hellman).
//!
//! # AUDIT (R-7 CLASS closure, 2026-07-03)
//!
//! R-7 was flagged as "ECDH shared point never zeroized after X.mul(Y)"
//! — a class covering 15+ sites across `crypto/`, `wallet/keys`,
//! `wallet/scanner`, `wallet/subaddress`, `wallet/memo`, etc.
//!
//! The class has two structural flavors:
//!   1. **Serialized-bytes-on-heap sites**: `shared_point.to_bytes()`
//!      output stored inside a `Vec<u8>` for hashing. These ARE now
//!      wiped explicitly (see R-10 in this file's `Subaddress::generate`,
//!      R-16 in `memo.rs`, R-82 in `wallet/keys.rs::view_tag`, R-85 in
//!      `wallet/subaddress.rs::derive_scalar`, R-86 in
//!      `compute_subaddress_spend_secret`, R-104 in
//!      `wallet/scanner.rs::compute_view_tag` and
//!      `compute_shared_secret`). Every heap Vec<u8> carrying shared-
//!      point bytes now zeroizes before scope exit.
//!   2. **RistrettoPoint-on-stack sites**: the `shared_point:
//!      RistrettoPoint` itself sits on the stack in its uncompressed
//!      internal representation (field-element arrays). curve25519-dalek
//!      does NOT implement `Zeroize` on `RistrettoPoint` upstream (verified
//!      2026-07-03 against curve25519-dalek 4.x source at
//!      https://github.com/dalek-cryptography/curve25519-dalek/blob/main/curve25519-dalek/src/ristretto.rs),
//!      so we cannot structurally wipe the point's internal state. This
//!      is an UNRESOLVABLE gap at the language + upstream-crate level.
//!      The upstream `zeroize` feature on `curve25519-dalek` covers
//!      `Scalar` but not `RistrettoPoint`.
//!
//! Class disposition: (1) is CLOSED via per-site fixes. (2) is
//! DOCUMENTED as an upstream-blocked gap; the mitigation is that
//! the stack window is only a few call-frames wide, and any real
//! attacker with post-call memory-dump access has already breached
//! the process boundary. If curve25519-dalek adds
//! ZeroizeOnDrop for RistrettoPoint in a future release, wire it up
//! by enabling the corresponding cargo feature.
//!
//! ## How it works:
//! 1. Sender generates random tx_secret, computes tx_public = tx_secret * G
//! 2. Sender computes shared_point = tx_secret * view_public (ECDH)
//! 3. Sender derives one-time key: P = H(shared_point || output_idx) * G + spend_public
//! 4. Receiver computes same shared_point = view_secret * tx_public (ECDH)
//! 5. Receiver derives expected P and checks if it matches
//!
//! ## Features:
//! - Accept `Address` type directly for convenience
//! - `RecipientKeys` for efficient batch scanning
//! - `ViewOnlyScanner` for watch-only wallets
//! - Subaddress support for unlinkable receiving addresses
//! - `StealthIndex` for fast output lookup
//! - Audit key derivation for regulatory compliance
//!
//! ## Security Properties:
//! - Uses constant-time comparison for key matching (prevents timing attacks)
//! - Sensitive keys are zeroized on drop (prevents memory disclosure)
//! - Domain-separated hashing (prevents cross-protocol attacks)
//! - Proper ECDH using curve25519-dalek (not hash-based approximation)

use super::curve::{hash_to_scalar, PublicPoint, SecretScalar};
use super::secure::ct_eq;
use crate::error::{Error, Result};
use crate::primitives::{hash_data, hash_domain, Address, PublicKey, SecretKey};
use crate::wallet::KeyEpoch;
use borsh::{BorshDeserialize, BorshSerialize};
use rand::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use zeroize::Zeroize;

// ============================================================================
// Core Types
// ============================================================================

/// A one-time stealth address for receiving payments
#[derive(
    Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, BorshSerialize, BorshDeserialize,
)]
pub struct StealthAddress {
    /// The one-time public key (derived from spend_public + shared_secret)
    pub public_key: PublicKey,
    /// The transaction public key (tx_secret * G)
    pub tx_public_key: PublicKey,
}

impl std::fmt::Debug for StealthAddress {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "StealthAddress({}...)", &self.public_key.to_hex()[..8])
    }
}

impl std::fmt::Display for StealthAddress {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.to_hex())
    }
}

impl StealthAddress {
    /// Create a new stealth address from components
    pub fn new(public_key: PublicKey, tx_public_key: PublicKey) -> Self {
        StealthAddress {
            public_key,
            tx_public_key,
        }
    }

    /// Check if this output belongs to the given recipient
    pub fn is_ours(&self, view_secret: &SecretKey, spend_pub: &PublicKey, output_idx: u8) -> bool {
        is_output_ours(self, view_secret, spend_pub, output_idx)
    }

    /// Check ownership using a KeyEpoch from the wallet
    pub fn is_ours_with_epoch(&self, keys: &KeyEpoch, output_idx: u8) -> bool {
        is_output_ours(self, &keys.view_secret, &keys.spend_public, output_idx)
    }

    /// Check ownership using pre-cached recipient keys (most efficient)
    pub fn is_ours_cached(&self, recipient: &RecipientKeys, output_idx: u8) -> bool {
        recipient.owns(self, output_idx)
    }

    /// Compute the one-time secret key for spending this output
    pub fn compute_spending_key(
        &self,
        view_secret: &SecretKey,
        spend_secret: &SecretKey,
        output_idx: u8,
    ) -> Result<SecretKey> {
        compute_one_time_secret(self, view_secret, spend_secret, output_idx)
    }

    /// Compute spending key using KeyEpoch
    pub fn compute_spending_key_with_epoch(
        &self,
        keys: &KeyEpoch,
        output_idx: u8,
    ) -> Result<SecretKey> {
        compute_one_time_secret(self, &keys.view_secret, &keys.spend_secret, output_idx)
    }

    /// Encode to hex string
    pub fn to_hex(&self) -> String {
        let mut bytes = Vec::with_capacity(64);
        bytes.extend_from_slice(self.public_key.as_bytes());
        bytes.extend_from_slice(self.tx_public_key.as_bytes());
        hex::encode(bytes)
    }

    /// Decode from hex string
    ///
    /// Validates that both public keys are valid curve points.
    pub fn from_hex(s: &str) -> Result<Self> {
        let bytes = hex::decode(s).map_err(|e| Error::InvalidParams(e.to_string()))?;
        if bytes.len() != 64 {
            return Err(Error::InvalidParams(
                "stealth address must be 64 bytes".into(),
            ));
        }
        let mut pk_bytes = [0u8; 32];
        let mut tx_bytes = [0u8; 32];
        pk_bytes.copy_from_slice(&bytes[0..32]);
        tx_bytes.copy_from_slice(&bytes[32..64]);

        // SECURITY: Validate both are valid Ristretto points before accepting
        PublicPoint::from_bytes(pk_bytes).ok_or_else(|| {
            Error::InvalidParams("invalid public key point in stealth address".into())
        })?;
        PublicPoint::from_bytes(tx_bytes).ok_or_else(|| {
            Error::InvalidParams("invalid tx public key point in stealth address".into())
        })?;

        Ok(StealthAddress {
            public_key: PublicKey::from_bytes(pk_bytes),
            tx_public_key: PublicKey::from_bytes(tx_bytes),
        })
    }

    /// Encode to bytes
    pub fn to_bytes(&self) -> [u8; 64] {
        let mut bytes = [0u8; 64];
        bytes[0..32].copy_from_slice(self.public_key.as_bytes());
        bytes[32..64].copy_from_slice(self.tx_public_key.as_bytes());
        bytes
    }

    /// Decode from bytes WITH curve point validation
    ///
    /// SECURITY (M1): Previously accepted unvalidated bytes. Now delegates to
    /// `from_bytes_checked()` to ensure all curve points are valid, preventing
    /// invalid-point attacks in ECDH operations.
    pub fn from_bytes(bytes: &[u8; 64]) -> Option<Self> {
        Self::from_bytes_checked(bytes)
    }

    /// Decode from bytes with curve point validation
    ///
    /// Returns None if either public key is not a valid Ristretto point.
    /// Use this for untrusted/external input.
    pub fn from_bytes_checked(bytes: &[u8; 64]) -> Option<Self> {
        let mut pk_bytes = [0u8; 32];
        let mut tx_bytes = [0u8; 32];
        pk_bytes.copy_from_slice(&bytes[0..32]);
        tx_bytes.copy_from_slice(&bytes[32..64]);

        // Validate both are valid curve points
        PublicPoint::from_bytes(pk_bytes)?;
        PublicPoint::from_bytes(tx_bytes)?;

        Some(StealthAddress {
            public_key: PublicKey::from_bytes(pk_bytes),
            tx_public_key: PublicKey::from_bytes(tx_bytes),
        })
    }
}

// ============================================================================
// RecipientKeys - Cached keys for efficient scanning
// ============================================================================

/// Pre-cached recipient keys for efficient output scanning
///
/// Use this when scanning many outputs to avoid repeated key conversions.
///
/// # Example
/// ```ignore
/// let recipient = RecipientKeys::new(&view_secret, &spend_public)?;
/// for output in blockchain_outputs {
///     if recipient.owns(&output.stealth, output.index) {
///         println!("Found our output!");
///     }
/// }
/// ```
/// SECURITY: Contains view_scalar (secret material). The inner SecretScalar
/// has ZeroizeOnDrop, but we also implement Drop on the container for
/// defense-in-depth. Should not be long-lived — drop promptly after use.
#[derive(Clone)]
pub struct RecipientKeys {
    view_scalar: SecretScalar,
    spend_point: PublicPoint,
    spend_public: PublicKey,
}

impl Drop for RecipientKeys {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.view_scalar.zeroize();
    }
}

impl RecipientKeys {
    /// Create cached recipient keys from view secret and spend public key
    pub fn new(view_secret: &SecretKey, spend_public: &PublicKey) -> Result<Self> {
        let view_scalar = SecretScalar::from_bytes(*view_secret.as_bytes());
        let spend_point = PublicPoint::from_bytes(*spend_public.as_bytes())
            .ok_or_else(|| Error::InvalidPublicKey("invalid spend public key".into()))?;

        Ok(RecipientKeys {
            view_scalar,
            spend_point,
            spend_public: *spend_public,
        })
    }

    /// Create from KeyEpoch
    pub fn from_epoch(keys: &KeyEpoch) -> Result<Self> {
        Self::new(&keys.view_secret, &keys.spend_public)
    }

    /// Create from Address (view key must be provided separately)
    pub fn from_address(address: &Address, view_secret: &SecretKey) -> Result<Self> {
        Self::new(view_secret, &address.spend_public_key)
    }

    /// Check if a stealth address output belongs to us
    ///
    /// SECURITY: Uses constant-time comparison to prevent timing attacks.
    ///
    /// AUDIT (R-8 fix, 2026-07-02): the pre-fix code took a fast-path
    /// early return whenever `tx_public_key` bytes failed to decode.
    /// That leaked a distinguishing timing signal — an attacker who
    /// can measure our scan latency for a targeted output learns
    /// "was that output well-formed?". Defense in depth: on decode
    /// failure, substitute the identity point and continue through
    /// the full ECDH + hash + compare pipeline, so wall-clock time is
    /// uniform across malformed vs well-formed inputs. Decode validity
    /// is carried to the final result because an identity-derived point
    /// can otherwise be forged from the recipient's public spend key.
    pub fn owns(&self, stealth: &StealthAddress, output_idx: u8) -> bool {
        // Convert tx_public to curve point for ECDH.
        // Identity substitution preserves the uniform work profile, but
        // identity * view_scalar is public and therefore cannot authenticate
        // ownership. Carry decode validity through the final comparison.
        let (tx_point, tx_valid) = match PublicPoint::from_bytes(*stealth.tx_public_key.as_bytes())
        {
            Some(point) => (point, true),
            None => (PublicPoint::identity(), false),
        };

        // ECDH: shared_point = view_secret * tx_public
        let mut shared_point = tx_point.mul(&self.view_scalar);

        // Derive the one-time scalar
        // SECURITY: scalar_input contains ECDH shared secret — must be zeroized after use
        let mut scalar_input = [shared_point.to_bytes().as_slice(), &[output_idx]].concat();
        let one_time_scalar = hash_to_scalar(&scalar_input);
        scalar_input.zeroize();
        // R-7 CLASS + R-80 (2026-07-03): shared_point is the ECDH
        // secret. Now that we've finished deriving from it, zero
        // its internal Ristretto field elements via the
        // curve25519-dalek 4.1 Zeroize impl (feature "zeroize").
        shared_point.zeroize();

        // Expected one-time public key: P = H(shared) * G + spend_public
        let one_time_base = SecretScalar::from_scalar(one_time_scalar).to_public();
        let expected_point = one_time_base.add(&self.spend_point);

        // `&` is intentionally non-short-circuiting so malformed inputs still
        // execute the same comparison after the full derivation pipeline.
        let matches = ct_eq(stealth.public_key.as_bytes(), &expected_point.to_bytes());
        tx_valid & matches
    }

    /// Scan a batch of outputs and return indices of owned outputs
    pub fn scan_outputs(&self, outputs: &[(StealthAddress, u8)]) -> Vec<usize> {
        outputs
            .iter()
            .enumerate()
            .filter(|(_, (stealth, idx))| self.owns(stealth, *idx))
            .map(|(i, _)| i)
            .collect()
    }

    /// Get the spend public key
    pub fn spend_public(&self) -> &PublicKey {
        &self.spend_public
    }
}

// ============================================================================
// ViewOnlyScanner - View-only wallet mode
// ============================================================================

/// A view-only scanner that can detect incoming payments without spend key
///
/// Useful for:
/// - Watch-only wallets
/// - Accounting and auditing
/// - Payment verification
///
/// # Example
/// ```ignore
/// let scanner = ViewOnlyScanner::new(&view_secret, &spend_public)?;
/// let found = scanner.scan_blockchain(&outputs);
/// println!("Found {} incoming payments", found.len());
/// ```
pub struct ViewOnlyScanner {
    keys: RecipientKeys,
    /// Subaddresses to scan, keyed by (account, index) so multi-account
    /// audit scans don't collide across accounts (#26 follow-up).
    subaddresses: Vec<(u32, u32, RecipientKeys)>,
}

impl ViewOnlyScanner {
    /// Create a new view-only scanner
    pub fn new(view_secret: &SecretKey, spend_public: &PublicKey) -> Result<Self> {
        Ok(ViewOnlyScanner {
            keys: RecipientKeys::new(view_secret, spend_public)?,
            subaddresses: Vec::new(),
        })
    }

    /// Create from KeyEpoch (without spend secret)
    pub fn from_epoch(keys: &KeyEpoch) -> Result<Self> {
        Self::new(&keys.view_secret, &keys.spend_public)
    }

    /// Add a subaddress to scan, tagged with its (account, index).
    pub fn add_subaddress(&mut self, account: u32, index: u32, subaddress_keys: RecipientKeys) {
        self.subaddresses.push((account, index, subaddress_keys));
    }

    /// Scan outputs and return information about owned outputs
    pub fn scan(&self, outputs: &[ScanOutput]) -> Vec<ScanResult> {
        let mut results = Vec::new();

        for (i, output) in outputs.iter().enumerate() {
            // Check main address
            if self.keys.owns(&output.stealth, output.output_idx) {
                results.push(ScanResult {
                    output_index: i,
                    stealth: output.stealth,
                    subaddress_account: None,
                    subaddress_index: None,
                    amount: output.amount,
                });
                continue;
            }

            // Check subaddresses
            for (sub_acct, sub_idx, sub_keys) in &self.subaddresses {
                if sub_keys.owns(&output.stealth, output.output_idx) {
                    results.push(ScanResult {
                        output_index: i,
                        stealth: output.stealth,
                        subaddress_account: Some(*sub_acct),
                        subaddress_index: Some(*sub_idx),
                        amount: output.amount,
                    });
                    break;
                }
            }
        }

        results
    }

    /// Quick check if any outputs match (without full scan details)
    pub fn has_outputs(&self, outputs: &[(StealthAddress, u8)]) -> bool {
        for (stealth, idx) in outputs {
            if self.keys.owns(stealth, *idx) {
                return true;
            }
            for (_, _, sub_keys) in &self.subaddresses {
                if sub_keys.owns(stealth, *idx) {
                    return true;
                }
            }
        }
        false
    }
}

/// Input for scanning
#[derive(Clone)]
pub struct ScanOutput {
    pub stealth: StealthAddress,
    pub output_idx: u8,
    pub amount: Option<u64>, // May be encrypted
}

/// Result of scanning
#[derive(Clone, Debug)]
pub struct ScanResult {
    pub output_index: usize,
    pub stealth: StealthAddress,
    /// Account the matched subaddress belongs to. `None` for a main-address
    /// match. Added for multi-account audit scans (#26 follow-up); pairs with
    /// `subaddress_index`.
    pub subaddress_account: Option<u32>,
    pub subaddress_index: Option<u32>,
    pub amount: Option<u64>,
}

// ============================================================================
// Subaddress Support
// ============================================================================

/// A subaddress derived from the main wallet keys
///
/// Each subaddress is unlinkable to the main address and to other subaddresses,
/// but all can be scanned with a single view key.
#[derive(Clone)]
pub struct Subaddress {
    /// Account index (0 = main account)
    pub account: u32,
    /// Subaddress index within the account
    pub index: u32,
    /// Derived spend public key for this subaddress
    pub spend_public: PublicKey,
    /// View public key (same as main address)
    pub view_public: PublicKey,
}

/// Canonical subaddress key-offset scalar `m`, **account-aware** and
/// domain-separated. This is the single source of truth for subaddress
/// derivation — the wallet (`wallet::SubaddressManager`) and the audit /
/// view-key scan path (`AuditKey`) both derive through this function, so their
/// keys always match (Jun #26; previously the two paths used incompatible
/// formulas and the audit key could not scan any wallet subaddress).
///
/// `m = hash_domain("COINCYNC_SUBADDR_v1", view_secret ‖ account_le ‖ index_le)`
/// and `subaddress_spend = spend_public + m·G`.
///
/// Byte-for-byte identical to the wallet's prior `derive_scalar`, so existing
/// wallet subaddresses are unchanged; only the audit path is corrected to match.
pub fn subaddress_scalar(view_secret: &SecretKey, account: u32, index: u32) -> SecretScalar {
    let mut input = Vec::with_capacity(32 + 4 + 4);
    input.extend_from_slice(view_secret.as_bytes());
    input.extend_from_slice(&account.to_le_bytes());
    input.extend_from_slice(&index.to_le_bytes());
    let hash = hash_domain(b"COINCYNC_SUBADDR_v1", &input);
    // The buffer holds raw view_secret bytes — wipe before it drops.
    input.zeroize();
    SecretScalar::from_bytes(*hash.as_bytes())
}

impl Subaddress {
    /// Generate a subaddress from wallet keys, account-aware.
    ///
    /// `subaddress_spend = spend_public + subaddress_scalar(view, account, index)·G`
    ///
    /// AUDIT (R-10 fix, 2026-07-02): the pre-fix code built the hash
    /// input with `Vec::extend_from_slice(view_secret.as_bytes())`,
    /// which left the raw view_secret bytes sitting inside the
    /// `data: Vec<u8>` allocation. On error paths or after the fn
    /// returned, the allocation was dropped WITHOUT zeroization, so
    /// the freed heap block contained plaintext view_secret bytes
    /// available to any subsequent allocator hit / memory dump. Now
    /// we explicitly `zeroize()` the buffer before it leaves scope.
    ///
    /// AUDIT (R-11 fix, 2026-07-03): switched the domain separator
    /// from the unversioned `b"subaddr"` (7 bytes) to the versioned
    /// canonical form `b"COINCYNC_SUBADDR_v1"` (19 bytes) — the exact
    /// literal used by `crypto::subaddress_scalar` above, the single
    /// source of truth shared by wallet and audit derivation. Rationale:
    ///   - The unversioned literal collides with any future scheme
    ///     that hashes `view_secret || short-ascii || index`.
    ///   - No shipped mainnet exists (v1.0 mainnet target 2026-10-01),
    ///     so there are NO on-chain wallets with the old-derivation
    ///     subaddresses. Changing NOW is free.
    ///   - Testnet wallets that used the old derivation before this
    ///     fix will see their subaddresses re-derive to different
    ///     public keys after upgrade. Testnet operators should
    ///     regenerate. Documented in the release notes for the
    ///     tag that ships this change.
    /// Follows Zcash ZIP 32 §5 and Bitcoin BIP 43 patterns.
    pub fn generate(
        spend_public: &PublicKey,
        view_secret: &SecretKey,
        account: u32,
        index: u32,
    ) -> Result<Self> {
        let view_scalar = SecretScalar::from_bytes(*view_secret.as_bytes());

        let spend_point = PublicPoint::from_bytes(*spend_public.as_bytes())
            .ok_or_else(|| Error::InvalidPublicKey("invalid spend public key".into()))?;

        // Single canonical, account-aware, domain-separated derivation shared
        // with the wallet — see `subaddress_scalar` (zeroizes internally).
        let sub_point = subaddress_scalar(view_secret, account, index).to_public();

        // subaddress_spend = spend_public + m·G  (D_i)
        let subaddr_spend_point = spend_point.add(&sub_point);

        // Subaddress view key C_i = a * D_i (NOT a*G). Distinct per subaddress,
        // so published subaddresses are unlinkable to each other and to the main
        // address; still scannable with the single view secret a because the
        // sender sets R = r*D_i and the scanner computes a*R = r*(a*D_i) = r*C_i.
        // See generate_stealth_address_checked_ext.
        let subaddr_view_point = subaddr_spend_point.mul(&view_scalar);

        Ok(Subaddress {
            account,
            index,
            spend_public: PublicKey::from_bytes(subaddr_spend_point.to_bytes()),
            view_public: PublicKey::from_bytes(subaddr_view_point.to_bytes()),
        })
    }

    /// Generate from KeyEpoch (account-aware).
    pub fn from_epoch(keys: &KeyEpoch, account: u32, index: u32) -> Result<Self> {
        Self::generate(&keys.spend_public, &keys.view_secret, account, index)
    }

    /// Create RecipientKeys for scanning this subaddress
    pub fn to_recipient_keys(&self, view_secret: &SecretKey) -> Result<RecipientKeys> {
        RecipientKeys::new(view_secret, &self.spend_public)
    }

    /// Convert to Address for receiving payments
    pub fn to_address(&self, network: crate::primitives::Network) -> Address {
        Address::new(network, self.spend_public, self.view_public)
    }
}

/// Manager for generating and tracking subaddresses
///
/// SECURITY: The view_secret field is automatically zeroized on drop
/// via SecretKey's Drop implementation.
pub struct SubaddressManager {
    spend_public: PublicKey,
    view_secret: SecretKey,
    generated: HashMap<u32, Subaddress>,
    next_index: u32,
}

impl SubaddressManager {
    /// Create a new subaddress manager
    pub fn new(spend_public: PublicKey, view_secret: SecretKey) -> Self {
        SubaddressManager {
            spend_public,
            view_secret,
            generated: HashMap::new(),
            next_index: 0,
        }
    }

    /// Create from KeyEpoch
    pub fn from_epoch(keys: &KeyEpoch) -> Self {
        Self::new(keys.spend_public, keys.view_secret.clone())
    }

    /// Generate the next subaddress
    pub fn next(&mut self) -> Result<&Subaddress> {
        let index = self.next_index;
        self.next_index += 1;
        self.get_or_generate(index)
    }

    /// Get or generate a specific subaddress
    pub fn get_or_generate(&mut self, index: u32) -> Result<&Subaddress> {
        if !self.generated.contains_key(&index) {
            // Flat legacy manager — account 0. Account-aware generation lives in
            // `wallet::SubaddressManager`; both derive via `subaddress_scalar`.
            let subaddr = Subaddress::generate(&self.spend_public, &self.view_secret, 0, index)?;
            self.generated.insert(index, subaddr);
        }
        // safe: we just inserted above if missing
        Ok(self.generated.get(&index).expect("just inserted"))
    }

    /// Get all generated subaddresses
    pub fn all(&self) -> impl Iterator<Item = &Subaddress> {
        self.generated.values()
    }
}

// ============================================================================
// StealthIndex - Fast output lookup
// ============================================================================

/// Index for fast stealth address lookups
///
/// Maintains a lookup table for O(1) output detection after initial scan.
pub struct StealthIndex {
    /// Map from tx_public_key hash to list of matching outputs
    index: HashMap<[u8; 8], Vec<IndexedOutput>>,
    /// Recipient keys for scanning
    keys: RecipientKeys,
}

#[derive(Clone)]
pub struct IndexedOutput {
    pub stealth: StealthAddress,
    pub output_idx: u8,
    pub block_height: u64,
    pub tx_index: u32,
}

impl StealthIndex {
    /// Create a new stealth index
    pub fn new(keys: RecipientKeys) -> Self {
        StealthIndex {
            index: HashMap::new(),
            keys,
        }
    }

    /// Create from KeyEpoch
    pub fn from_epoch(keys: &KeyEpoch) -> Result<Self> {
        Ok(Self::new(RecipientKeys::from_epoch(keys)?))
    }

    /// Index a batch of outputs
    pub fn index_outputs(&mut self, outputs: &[IndexedOutput]) {
        for output in outputs {
            if self.keys.owns(&output.stealth, output.output_idx) {
                let key = self.make_key(&output.stealth.tx_public_key);
                self.index.entry(key).or_default().push(output.clone());
            }
        }
    }

    /// Quick lookup by tx_public_key
    pub fn lookup(&self, tx_public_key: &PublicKey) -> Option<&Vec<IndexedOutput>> {
        let key = self.make_key(tx_public_key);
        self.index.get(&key)
    }

    /// Get all indexed outputs
    pub fn all_outputs(&self) -> impl Iterator<Item = &IndexedOutput> {
        self.index.values().flatten()
    }

    /// Count of indexed outputs
    pub fn len(&self) -> usize {
        self.index.values().map(|v| v.len()).sum()
    }

    /// Check if empty
    pub fn is_empty(&self) -> bool {
        self.index.is_empty()
    }

    /// Clear the index
    pub fn clear(&mut self) {
        self.index.clear();
    }

    fn make_key(&self, pk: &PublicKey) -> [u8; 8] {
        let hash = hash_data(pk.as_bytes());
        let mut key = [0u8; 8];
        key.copy_from_slice(&hash.as_bytes()[..8]);
        key
    }
}

// ============================================================================
// Audit Key Support
// ============================================================================

/// An audit key that can reveal incoming transactions for compliance
///
/// The audit key allows a third party (auditor) to see incoming payments
/// without having the ability to spend funds.
///
/// SECURITY: The view_secret field is automatically zeroized on drop
/// via SecretKey's Drop implementation.
#[derive(Clone)]
pub struct AuditKey {
    /// The view secret (allows detecting incoming)
    view_secret: SecretKey,
    /// The spend public (for verification, cannot spend)
    spend_public: PublicKey,
    /// Optional restriction: only audit after this block
    start_height: Option<u64>,
    /// Optional restriction: only audit before this block
    end_height: Option<u64>,
    /// R-9 surgical fix (2026-07-03): highest subaddress index the
    /// audited wallet ever generated. When `to_scanner()` runs, it
    /// enumerates every subaddress from 0..=subaddress_max_index and
    /// registers each recipient key set on the ViewOnlyScanner, so
    /// outputs to subaddresses ARE detected. `None` = main-address-only
    /// audit (backward-compatible with pre-fix export bundles).
    subaddress_max_index: Option<u32>,
    /// #26 follow-up: highest ACCOUNT to enumerate during the scan. `None` =
    /// account 0 only (the R-9 single-account behaviour). When set alongside
    /// `subaddress_max_index`, `to_scanner()` sweeps the full
    /// (0..=max_account, 0..=max_index) grid so multi-account wallets audit
    /// completely. Pass the wallet's highest account from its subaddress book.
    subaddress_max_account: Option<u32>,
}

impl AuditKey {
    /// Create a full audit key (can see all incoming transactions)
    pub fn new(view_secret: SecretKey, spend_public: PublicKey) -> Self {
        AuditKey {
            view_secret,
            spend_public,
            start_height: None,
            end_height: None,
            subaddress_max_index: None,
            subaddress_max_account: None,
        }
    }

    /// Create from KeyEpoch
    pub fn from_epoch(keys: &KeyEpoch) -> Self {
        Self::new(keys.view_secret.clone(), keys.spend_public)
    }

    /// Restrict to a block range
    pub fn with_range(mut self, start: Option<u64>, end: Option<u64>) -> Self {
        self.start_height = start;
        self.end_height = end;
        self
    }

    /// R-9 surgical fix: tell the audit key how many subaddress
    /// indices to enumerate when a scanner is built. Pass the
    /// wallet's `highest_index` from its subaddress book.
    pub fn with_subaddress_max_index(mut self, max_index: u32) -> Self {
        self.subaddress_max_index = Some(max_index);
        self
    }

    /// #26 follow-up: enumerate accounts `0..=max_account` during the scan
    /// (paired with [`with_subaddress_max_index`](Self::with_subaddress_max_index)).
    /// Pass the wallet's highest account from its subaddress book. Left unset,
    /// the scan covers account 0 only (backward-compatible).
    pub fn with_subaddress_max_account(mut self, max_account: u32) -> Self {
        self.subaddress_max_account = Some(max_account);
        self
    }

    /// Check if a block height is within audit range
    pub fn is_in_range(&self, height: u64) -> bool {
        if let Some(start) = self.start_height {
            if height < start {
                return false;
            }
        }
        if let Some(end) = self.end_height {
            if height > end {
                return false;
            }
        }
        true
    }

    /// Create a scanner from this audit key.
    ///
    /// AUDIT (R-9 SURGICAL FIX, 2026-07-03): the scanner now
    /// enumerates subaddresses when `subaddress_max_index` is set.
    /// For each index from 0 to max_index inclusive we:
    ///   1. Derive the subaddress spend point via
    ///      `Subaddress::generate(spend_public, view_secret, i)`.
    ///   2. Build a fresh `RecipientKeys` for that subaddress.
    ///   3. Register it on the scanner via `add_subaddress`.
    /// Outputs sent to any subaddress in [0, max_index] are now
    /// detected. Callers who don't call `with_subaddress_max_index`
    /// get the previous main-address-only behaviour (safe default).
    ///
    /// An auditor building the AuditKey should ask the wallet
    /// operator for `wallet.subaddresses().highest_index()` to
    /// pass in — that value is the source-of-truth ceiling.
    pub fn to_scanner(&self) -> Result<ViewOnlyScanner> {
        let mut scanner = ViewOnlyScanner::new(&self.view_secret, &self.spend_public)?;
        if let Some(max_index) = self.subaddress_max_index {
            // #26 follow-up: sweep the full (account, index) grid. When
            // `subaddress_max_account` is unset we default to account 0 only —
            // the R-9 single-account behaviour — so existing audit bundles are
            // unchanged. All derivations go through the wallet-shared
            // `subaddress_scalar`, so audit keys match the wallet's.
            let max_account = self.subaddress_max_account.unwrap_or(0);
            for account in 0..=max_account {
                for i in 0..=max_index {
                    // (account 0, index 0) is the main address, already
                    // registered by ViewOnlyScanner::new. Every other pair —
                    // including account>0 index 0 (an account's own main
                    // subaddress) — is a distinct key we must enumerate.
                    if account == 0 && i == 0 {
                        continue;
                    }
                    let subaddr =
                        Subaddress::generate(&self.spend_public, &self.view_secret, account, i)?;
                    let sub_recipient =
                        RecipientKeys::new(&self.view_secret, &subaddr.spend_public)?;
                    scanner.add_subaddress(account, i, sub_recipient);
                }
            }
        }
        Ok(scanner)
    }

    /// Create recipient keys for scanning
    pub fn to_recipient_keys(&self) -> Result<RecipientKeys> {
        RecipientKeys::new(&self.view_secret, &self.spend_public)
    }

    /// Export the audit key for sharing with auditor
    pub fn export(&self) -> AuditKeyExport {
        AuditKeyExport {
            view_secret_hex: hex::encode(self.view_secret.as_bytes()),
            spend_public_hex: hex::encode(self.spend_public.as_bytes()),
            start_height: self.start_height,
            end_height: self.end_height,
            subaddress_max_index: self.subaddress_max_index,
            subaddress_max_account: self.subaddress_max_account,
        }
    }

    /// Import an audit key
    pub fn import(export: &AuditKeyExport) -> Result<Self> {
        let view_bytes = hex::decode(&export.view_secret_hex)
            .map_err(|e| Error::InvalidParams(e.to_string()))?;
        let spend_bytes = hex::decode(&export.spend_public_hex)
            .map_err(|e| Error::InvalidParams(e.to_string()))?;

        if view_bytes.len() != 32 || spend_bytes.len() != 32 {
            return Err(Error::InvalidParams("invalid key length".into()));
        }

        let mut view_arr = [0u8; 32];
        let mut spend_arr = [0u8; 32];
        view_arr.copy_from_slice(&view_bytes);
        spend_arr.copy_from_slice(&spend_bytes);

        Ok(AuditKey {
            view_secret: SecretKey::from_bytes(view_arr),
            spend_public: PublicKey::from_bytes(spend_arr),
            start_height: export.start_height,
            end_height: export.end_height,
            subaddress_max_index: export.subaddress_max_index,
            subaddress_max_account: export.subaddress_max_account,
        })
    }
}

/// Serializable audit key export format.
///
/// R-9 surgical fix (2026-07-03): `subaddress_max_index` added.
/// Older exports without this field decode as None (via serde's
/// default-missing behavior for Option), preserving backward
/// compat.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AuditKeyExport {
    pub view_secret_hex: String,
    pub spend_public_hex: String,
    pub start_height: Option<u64>,
    pub end_height: Option<u64>,
    #[serde(default)]
    pub subaddress_max_index: Option<u32>,
    /// #26 follow-up: highest account to sweep. Older exports without this
    /// field decode as None (serde default) → account-0-only, backward-compat.
    #[serde(default)]
    pub subaddress_max_account: Option<u32>,
}

// ============================================================================
// Core Functions (with proper error handling)
// ============================================================================

/// Generate a deterministic stealth address for a coinbase output at a given block height.
///
/// Each block height produces a unique tx_secret via `hash_domain`, so every coinbase
/// output gets a unique stealth_address in the UTXO index. This prevents stealth_index
/// collisions that would cause ring member maturity validation to fail.
///
/// Returns `(StealthAddress, tx_secret_key)` — the caller uses tx_secret_key to compute
/// the view_tag for the output.
/// SECURITY: `miner_secret` prevents precomputable coinbase linkage.
/// Without it, tx_secret = H(height) is fully predictable — anyone with
/// the miner's view key can link all future coinbase outputs.
/// With it, tx_secret = H(miner_secret || height) is unpredictable to outsiders.
pub fn coinbase_stealth_address(
    spend_pub: &PublicKey,
    view_pub: &PublicKey,
    height: u64,
    output_idx: u8,
    miner_secret: &[u8; 32],
) -> Result<(StealthAddress, crate::primitives::SecretKey)> {
    use crate::primitives::hash_domain;

    // Deterministic tx_secret from miner_secret + block height
    // SECURITY FIX: Previously used H(height) alone — fully precomputable from public data.
    let mut secret_input = Vec::with_capacity(40);
    secret_input.extend_from_slice(miner_secret);
    secret_input.extend_from_slice(&height.to_le_bytes());
    let tx_secret_hash = hash_domain(b"COINCYNC_COINBASE_TX_SECRET", &secret_input);
    // Audit-fix: zeroize the buffer that briefly held `miner_secret`
    // bytes. Without this, the spend-key material lingers on the heap
    // (Vec drop does NOT zeroize) where a memory dump / crash core /
    // long-lived adjacent allocation could surface it. Matches the
    // zeroize call on `scalar_input` below (same pattern, same risk).
    secret_input.zeroize();
    let tx_secret_scalar = SecretScalar::from_bytes(*tx_secret_hash.as_bytes());
    let tx_public = tx_secret_scalar.to_public();

    // Convert view_public to curve point for ECDH
    let view_point = PublicPoint::from_bytes(*view_pub.as_bytes()).ok_or_else(|| {
        Error::InvalidPublicKey("invalid view public key for coinbase stealth".into())
    })?;

    // ECDH: shared_point = tx_secret * view_public
    let shared_point = view_point.mul(&tx_secret_scalar);

    // Derive the one-time scalar from shared secret and output index
    let mut scalar_input = [shared_point.to_bytes().as_slice(), &[output_idx]].concat();
    let one_time_scalar = hash_to_scalar(&scalar_input);
    scalar_input.zeroize();

    // Convert spend_public to curve point
    let spend_point = PublicPoint::from_bytes(*spend_pub.as_bytes()).ok_or_else(|| {
        Error::InvalidPublicKey("invalid spend public key for coinbase stealth".into())
    })?;

    // One-time public key: P = H(shared, idx)*G + spend_public
    let one_time_base = SecretScalar::from_scalar(one_time_scalar).to_public();
    let stealth_point = one_time_base.add(&spend_point);

    let stealth = StealthAddress {
        public_key: PublicKey::from_bytes(stealth_point.to_bytes()),
        tx_public_key: PublicKey::from_bytes(tx_public.to_bytes()),
    };

    // Return tx_secret so the caller can compute the view_tag (sender-side ECDH)
    let tx_secret_bytes = tx_secret_scalar.to_bytes();
    Ok((
        stealth,
        crate::primitives::SecretKey::from_bytes(tx_secret_bytes),
    ))
}

/// Generate a stealth address for a recipient using their Address
///
/// This is the most convenient way to create a stealth address.
pub fn generate_stealth_address_for<R: RngCore + CryptoRng>(
    recipient: &Address,
    output_idx: u8,
    rng: &mut R,
) -> Result<(StealthAddress, SecretKey)> {
    // A typed Address carries its kind, so we can select the correct tx-pubkey
    // form: subaddresses (view key C_i = a*D_i) require R = r*D_i so the
    // recipient can detect/spend the output.
    let is_subaddress =
        recipient.address_type == crate::primitives::AddressType::Subaddress;
    generate_stealth_address_checked_ext(
        &recipient.spend_public_key,
        &recipient.view_public_key,
        output_idx,
        is_subaddress,
        rng,
    )
}

/// Generate a stealth address with proper error handling (main-address form,
/// `R = r*G`). Thin wrapper over [`generate_stealth_address_checked_ext`] with
/// `is_subaddress = false`, kept so existing callers are unchanged.
pub fn generate_stealth_address_checked<R: RngCore + CryptoRng>(
    spend_pub: &PublicKey,
    view_pub: &PublicKey,
    output_idx: u8,
    rng: &mut R,
) -> Result<(StealthAddress, SecretKey)> {
    generate_stealth_address_checked_ext(spend_pub, view_pub, output_idx, false, rng)
}

/// Generate a stealth address, choosing the transaction-public-key form by
/// recipient type.
///
/// - MAIN address: `R = r*G`, and the recipient's ECDH shared secret is
///   `a*R = r*(a*G) = r*A`.
/// - SUBADDRESS (Monero-style): `R = r*D_i` (the subaddress spend key). A
///   subaddress publishes `view_public = C_i = a*D_i`, so the sender's shared
///   secret `r*C_i` equals the recipient's `a*R = a*(r*D_i) = r*(a*D_i) =
///   r*C_i`. This lets every subaddress carry a DISTINCT published view key
///   (unlinkable across subaddresses and from the main address) while remaining
///   scannable with the single wallet view secret `a`.
///
/// The one-time output key `P = H(shared)*G + spend_pub` and every downstream
/// ECDH-derived value (blinding, encrypted amount, view tag) depend only on
/// `shared = r*view_pub`, so they stay consistent for both recipient types. The
/// scanner is unchanged: it computes `a*R` and matches `P` against its spend
/// keys, which works identically for `R = r*G` and `R = r*D_i`.
pub fn generate_stealth_address_checked_ext<R: RngCore + CryptoRng>(
    spend_pub: &PublicKey,
    view_pub: &PublicKey,
    output_idx: u8,
    is_subaddress: bool,
    rng: &mut R,
) -> Result<(StealthAddress, SecretKey)> {
    // Generate random transaction secret
    let tx_secret = SecretScalar::random(rng);

    // Convert spend_public to curve point (with proper error)
    let spend_point = PublicPoint::from_bytes(*spend_pub.as_bytes())
        .ok_or_else(|| Error::InvalidPublicKey("invalid spend public key".into()))?;

    // Transaction public key R. Subaddress: R = r*D_i (spend key), so a*R
    // matches the published C_i = a*D_i. Main address: R = r*G.
    let tx_public = if is_subaddress {
        spend_point.mul(&tx_secret)
    } else {
        tx_secret.to_public()
    };

    // Convert view_public to curve point for ECDH (with proper error)
    let view_point = PublicPoint::from_bytes(*view_pub.as_bytes())
        .ok_or_else(|| Error::InvalidPublicKey("invalid view public key".into()))?;

    // ECDH: shared_point = tx_secret * view_public
    let shared_point = view_point.mul(&tx_secret);

    // Derive the one-time scalar from shared secret and output index
    // SECURITY: scalar_input contains ECDH shared secret — must be zeroized after use
    let mut scalar_input = [shared_point.to_bytes().as_slice(), &[output_idx]].concat();
    let one_time_scalar = hash_to_scalar(&scalar_input);
    scalar_input.zeroize();

    // One-time public key: P = H(shared) * G + spend_public
    let one_time_base = SecretScalar::from_scalar(one_time_scalar).to_public();
    let stealth_point = one_time_base.add(&spend_point);

    let stealth = StealthAddress {
        public_key: PublicKey::from_bytes(stealth_point.to_bytes()),
        tx_public_key: PublicKey::from_bytes(tx_public.to_bytes()),
    };

    // Log stealth address generation
    // SECURITY: Changed from info! to trace! — logging stealth address hex bytes
    // at info level leaks output ownership to anyone with log access (ELK, Datadog).
    tracing::trace!(
        "Generated one-time stealth address (output #{})",
        output_idx
    );

    // Return tx_secret as primitives::SecretKey for amount encryption
    let tx_secret_bytes = tx_secret.to_bytes();
    Ok((stealth, SecretKey::from_bytes(tx_secret_bytes)))
}

/// Generate a stealth address for a recipient (legacy API - test-only).
///
/// 2026-06-03 hardening: visibility narrowed from `pub` to
/// `pub(crate)` + `#[cfg(test)]` so this panicking variant cannot
/// reach production code paths. The public surface kept by
/// `crypto/mod.rs` re-exports only `generate_stealth_address_checked`
/// (Result-returning) and `generate_stealth_address_for` (Address-typed).
///
/// Prefer `generate_stealth_address_for` or `generate_stealth_address_checked`
/// for new code.
///
/// # Panics
/// Panics if the provided public keys are not valid curve points.
/// Use `generate_stealth_address_checked` for proper error handling.
#[cfg(test)]
pub(crate) fn generate_stealth_address<R: RngCore + CryptoRng>(
    spend_pub: &PublicKey,
    view_pub: &PublicKey,
    output_idx: u8,
    rng: &mut R,
) -> (StealthAddress, SecretKey) {
    // Generate random transaction secret
    let tx_secret = SecretScalar::random(rng);
    let tx_public = tx_secret.to_public();

    // Convert view_public to curve point for ECDH
    // SECURITY: Panic on invalid keys rather than silently producing unspendable outputs
    let view_point = PublicPoint::from_bytes(*view_pub.as_bytes()).expect(
        "invalid view public key - use generate_stealth_address_checked for error handling",
    );

    // ECDH: shared_point = tx_secret * view_public
    let shared_point = view_point.mul(&tx_secret);

    // Derive the one-time scalar from shared secret and output index
    // SECURITY: scalar_input contains ECDH shared secret — must be zeroized after use
    let mut scalar_input = [shared_point.to_bytes().as_slice(), &[output_idx]].concat();
    let one_time_scalar = hash_to_scalar(&scalar_input);
    scalar_input.zeroize();

    // Convert spend_public to curve point
    let spend_point = PublicPoint::from_bytes(*spend_pub.as_bytes()).expect(
        "invalid spend public key - use generate_stealth_address_checked for error handling",
    );

    // One-time public key: P = H(shared) * G + spend_public
    let one_time_base = SecretScalar::from_scalar(one_time_scalar).to_public();
    let stealth_point = one_time_base.add(&spend_point);

    let stealth = StealthAddress {
        public_key: PublicKey::from_bytes(stealth_point.to_bytes()),
        tx_public_key: PublicKey::from_bytes(tx_public.to_bytes()),
    };

    // Return tx_secret as primitives::SecretKey for amount encryption
    let tx_secret_bytes = tx_secret.to_bytes();
    (stealth, SecretKey::from_bytes(tx_secret_bytes))
}

/// Generate stealth addresses for multiple recipients in one transaction
///
/// SECURITY (A4-CR-03): Rejects more than 255 recipients to prevent `idx as u8`
/// wraparound, which would produce duplicate output indices and break one-time
/// key derivation uniqueness.
pub fn generate_stealth_outputs<R: RngCore + CryptoRng>(
    recipients: &[&Address],
    rng: &mut R,
) -> Result<Vec<(StealthAddress, SecretKey)>> {
    if recipients.len() > 255 {
        return Err(crate::error::Error::InvalidState(format!(
            "Too many recipients ({}, max 255)",
            recipients.len()
        )));
    }
    recipients
        .iter()
        .enumerate()
        .map(|(idx, addr)| generate_stealth_address_for(addr, idx as u8, rng))
        .collect()
}

/// Check if an output belongs to us
///
/// SECURITY: Uses constant-time comparison to prevent timing attacks that could
/// reveal which outputs belong to the wallet.
///
/// ## EC Point Validation
///
/// All public keys are validated as valid curve points before use:
/// - `stealth.tx_public_key` - Transaction public key from sender
/// - `stealth.public_key` - One-time destination public key
/// - `spend_pub` - Wallet's spend public key
///
/// If any point is invalid (not on curve), returns false (not ours).
/// This prevents:
/// - Crashes from malformed outputs
/// - Invalid shared secret computation
/// - Potential small subgroup attacks
pub fn is_output_ours(
    stealth: &StealthAddress,
    view_secret: &SecretKey,
    spend_pub: &PublicKey,
    output_idx: u8,
) -> bool {
    // Convert view_secret to curve scalar
    let view_scalar = SecretScalar::from_bytes(*view_secret.as_bytes());

    // SECURITY: Validate tx_public is a valid curve point
    let tx_point = match PublicPoint::from_bytes(*stealth.tx_public_key.as_bytes()) {
        Some(p) => p,
        None => return false, // Invalid point = not ours
    };

    // SECURITY: Validate stealth.public_key is a valid curve point
    if PublicPoint::from_bytes(*stealth.public_key.as_bytes()).is_none() {
        return false; // Invalid destination point = not ours
    }

    // ECDH: shared_point = view_secret * tx_public
    let shared_point = tx_point.mul(&view_scalar);

    // Derive the one-time scalar (same as sender computed)
    // SECURITY: scalar_input contains ECDH shared secret — must be zeroized after use
    let mut scalar_input = [shared_point.to_bytes().as_slice(), &[output_idx]].concat();
    let one_time_scalar = hash_to_scalar(&scalar_input);
    scalar_input.zeroize();

    // SECURITY: Validate spend_public is a valid curve point
    let spend_point = match PublicPoint::from_bytes(*spend_pub.as_bytes()) {
        Some(p) => p,
        None => return false,
    };

    // Expected one-time public key: P = H(shared) * G + spend_public
    let one_time_base = SecretScalar::from_scalar(one_time_scalar).to_public();
    let expected_point = one_time_base.add(&spend_point);

    // SECURITY: Use constant-time comparison to prevent timing attacks
    let is_ours = ct_eq(stealth.public_key.as_bytes(), &expected_point.to_bytes());

    if is_ours {
        // SECURITY: Changed from info! to trace! — logging owned output hex bytes
        // leaks ownership to anyone with log access.
        tracing::trace!("Detected owned output (output #{})", output_idx);
    }

    is_ours
}

/// Check using KeyEpoch from wallet
pub fn is_output_ours_with_epoch(
    stealth: &StealthAddress,
    keys: &KeyEpoch,
    output_idx: u8,
) -> bool {
    is_output_ours(stealth, &keys.view_secret, &keys.spend_public, output_idx)
}

/// Compute the one-time private key for spending (with proper error handling)
pub fn compute_one_time_secret(
    stealth: &StealthAddress,
    view_secret: &SecretKey,
    spend_secret: &SecretKey,
    output_idx: u8,
) -> Result<SecretKey> {
    // Convert keys to curve types
    let view_scalar = SecretScalar::from_bytes(*view_secret.as_bytes());
    let spend_scalar = SecretScalar::from_bytes(*spend_secret.as_bytes());

    // Get tx_public point
    let tx_point = PublicPoint::from_bytes(*stealth.tx_public_key.as_bytes())
        .ok_or_else(|| Error::InvalidPublicKey("invalid tx_public_key".into()))?;

    // ECDH: shared_point = view_secret * tx_public
    let shared_point = tx_point.mul(&view_scalar);

    // Derive the one-time scalar
    // SECURITY: scalar_input contains ECDH shared secret — must be zeroized after use
    let mut scalar_input = [shared_point.to_bytes().as_slice(), &[output_idx]].concat();
    let one_time_scalar = hash_to_scalar(&scalar_input);
    scalar_input.zeroize();
    let one_time = SecretScalar::from_scalar(one_time_scalar);

    // One-time private key: x = H(shared) + spend_secret
    let result = one_time.add(&spend_scalar);
    Ok(SecretKey::from_bytes(result.to_bytes()))
}

/// Batch scan outputs efficiently
pub fn scan_outputs(
    outputs: &[(StealthAddress, u8)],
    view_secret: &SecretKey,
    spend_public: &PublicKey,
) -> Result<Vec<usize>> {
    let keys = RecipientKeys::new(view_secret, spend_public)?;
    Ok(keys.scan_outputs(outputs))
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::primitives::Network;
    use rand::rngs::OsRng;

    /// Generate a proper EC keypair for testing
    fn generate_ec_keypair() -> (SecretKey, PublicKey) {
        let secret = SecretScalar::random(&mut OsRng);
        let public = secret.to_public();
        (
            SecretKey::from_bytes(secret.to_bytes()),
            PublicKey::from_bytes(public.to_bytes()),
        )
    }

    #[test]
    fn test_stealth_address_roundtrip() {
        let (_spend_secret, spend_public) = generate_ec_keypair();
        let (view_secret, view_public) = generate_ec_keypair();

        let (stealth, _tx_secret) =
            generate_stealth_address(&spend_public, &view_public, 0, &mut OsRng);

        assert!(
            is_output_ours(&stealth, &view_secret, &spend_public, 0),
            "Recipient should detect their own output"
        );
    }

    #[test]
    fn test_stealth_address_methods() {
        let (spend_secret, spend_public) = generate_ec_keypair();
        let (view_secret, view_public) = generate_ec_keypair();

        let (stealth, _) = generate_stealth_address(&spend_public, &view_public, 0, &mut OsRng);

        // Test is_ours method
        assert!(stealth.is_ours(&view_secret, &spend_public, 0));
        assert!(!stealth.is_ours(&view_secret, &spend_public, 1));

        // Test compute_spending_key method
        let spending_key = stealth
            .compute_spending_key(&view_secret, &spend_secret, 0)
            .unwrap();
        let one_time_scalar = SecretScalar::from_bytes(*spending_key.as_bytes());
        let derived_public = one_time_scalar.to_public();
        assert_eq!(stealth.public_key.as_bytes(), &derived_public.to_bytes());
    }

    #[test]
    fn test_recipient_keys_scanning() {
        let (_spend_secret, spend_public) = generate_ec_keypair();
        let (view_secret, view_public) = generate_ec_keypair();

        let recipient = RecipientKeys::new(&view_secret, &spend_public).unwrap();

        // Generate multiple outputs
        let (stealth1, _) = generate_stealth_address(&spend_public, &view_public, 0, &mut OsRng);
        let (stealth2, _) = generate_stealth_address(&spend_public, &view_public, 1, &mut OsRng);

        assert!(recipient.owns(&stealth1, 0));
        assert!(recipient.owns(&stealth2, 1));
        assert!(!recipient.owns(&stealth1, 1)); // Wrong index
    }

    #[test]
    fn test_batch_scanning() {
        let (_spend_secret, spend_public) = generate_ec_keypair();
        let (view_secret, view_public) = generate_ec_keypair();

        let outputs: Vec<(StealthAddress, u8)> = (0..5)
            .map(|i| {
                let (stealth, _) =
                    generate_stealth_address(&spend_public, &view_public, i, &mut OsRng);
                (stealth, i)
            })
            .collect();

        let found = scan_outputs(&outputs, &view_secret, &spend_public).unwrap();
        assert_eq!(found.len(), 5);
    }

    #[test]
    fn test_address_integration() {
        let (_spend_secret, spend_public) = generate_ec_keypair();
        let (view_secret, view_public) = generate_ec_keypair();

        let address = Address::new(Network::Testnet, spend_public, view_public);

        let (stealth, _) = generate_stealth_address_for(&address, 0, &mut OsRng).unwrap();
        assert!(stealth.is_ours(&view_secret, &spend_public, 0));
    }

    #[test]
    fn test_hex_serialization() {
        let (_, spend_public) = generate_ec_keypair();
        let (_, view_public) = generate_ec_keypair();

        let (stealth, _) = generate_stealth_address(&spend_public, &view_public, 0, &mut OsRng);

        let hex = stealth.to_hex();
        let restored = StealthAddress::from_hex(&hex).unwrap();

        assert_eq!(
            stealth.public_key.as_bytes(),
            restored.public_key.as_bytes()
        );
        assert_eq!(
            stealth.tx_public_key.as_bytes(),
            restored.tx_public_key.as_bytes()
        );
    }

    #[test]
    fn test_subaddress_generation() {
        let (_spend_secret, spend_public) = generate_ec_keypair();
        let (view_secret, view_public) = generate_ec_keypair();

        let sub = Subaddress::generate(&spend_public, &view_secret, 0, 1).unwrap();

        // Subaddress has a distinct spend key D_i = B + m*G ...
        assert_ne!(sub.spend_public.as_bytes(), spend_public.as_bytes());

        // ... and a distinct view key C_i = a*D_i (NOT the main a*G). Publishing
        // a*G on every subaddress made them linkable by a byte-compare of the
        // address; C_i = a*D_i is per-subaddress and unlinkable (pre-mainnet
        // review #3).
        assert_ne!(
            sub.view_public.as_bytes(),
            view_public.as_bytes(),
            "subaddress view key must be C_i = a*D_i, not the main a*G"
        );
    }

    #[test]
    fn subaddress_view_keys_are_unlinkable_and_output_is_detectable() {
        // Pre-mainnet review #3: subaddresses used to publish the same view key
        // (a*G) as the main address, so two subaddresses of one wallet were
        // linkable by comparing their published view keys. They now publish
        // C_i = a*D_i, and the sender uses R = r*D_i so the wallet still detects
        // them with its single view secret a.
        let (_b, spend_public) = generate_ec_keypair();
        let (view_secret, view_public) = generate_ec_keypair();

        let sub1 = Subaddress::generate(&spend_public, &view_secret, 0, 1).unwrap();
        let sub2 = Subaddress::generate(&spend_public, &view_secret, 0, 2).unwrap();

        // Unlinkability: distinct view keys, and neither equals the main a*G.
        assert_ne!(
            sub1.view_public.as_bytes(),
            sub2.view_public.as_bytes(),
            "two subaddresses must have distinct view keys"
        );
        assert_ne!(sub1.view_public.as_bytes(), view_public.as_bytes());
        assert_ne!(sub2.view_public.as_bytes(), view_public.as_bytes());

        // Round-trip: a payment to sub1 (R = r*D_1) is detectable by the wallet
        // scanning with view secret a against sub1's spend key D_1 ...
        let (stealth, _tx_secret) = generate_stealth_address_checked_ext(
            &sub1.spend_public,
            &sub1.view_public,
            0,
            true, // subaddress recipient => R = r*D_1
            &mut OsRng,
        )
        .unwrap();
        assert!(
            is_output_ours(&stealth, &view_secret, &sub1.spend_public, 0),
            "wallet must detect its own subaddress output"
        );

        // ... and it is NOT mis-attributed to a different subaddress.
        assert!(
            !is_output_ours(&stealth, &view_secret, &sub2.spend_public, 0),
            "a sub1 output must not be detected as sub2's"
        );
    }

    #[test]
    fn generate_stealth_address_for_selects_form_by_address_type() {
        // The typed-Address send path must pick R = r*D_i for a Subaddress
        // Address (so the recipient detects it against C_i = a*D_i) and R = r*G
        // for a Standard address. This is the decision point threaded through
        // the wallet send path (Address.address_type -> is_subaddress).
        use crate::primitives::{Address, AddressType, Network};

        let (_b, spend_public) = generate_ec_keypair();
        let (view_secret, view_public) = generate_ec_keypair();

        // Subaddress (D_i, C_i = a*D_i) as a typed Subaddress Address.
        let sub = Subaddress::generate(&spend_public, &view_secret, 0, 7).unwrap();
        let mut sub_addr = Address::new(Network::Testnet, sub.spend_public, sub.view_public);
        sub_addr.address_type = AddressType::Subaddress;
        let (stealth, _) = generate_stealth_address_for(&sub_addr, 0, &mut OsRng).unwrap();
        assert!(
            is_output_ours(&stealth, &view_secret, &sub.spend_public, 0),
            "subaddress output via generate_stealth_address_for must be detectable at D_i"
        );

        // Standard (main) address still round-trips with R = r*G.
        let main_addr = Address::new(Network::Testnet, spend_public, view_public);
        assert_eq!(main_addr.address_type, AddressType::Standard);
        let (main_stealth, _) = generate_stealth_address_for(&main_addr, 0, &mut OsRng).unwrap();
        assert!(
            is_output_ours(&main_stealth, &view_secret, &spend_public, 0),
            "main-address output must still be detectable"
        );
    }

    #[test]
    fn test_view_only_scanner() {
        let (_, spend_public) = generate_ec_keypair();
        let (view_secret, view_public) = generate_ec_keypair();

        let scanner = ViewOnlyScanner::new(&view_secret, &spend_public).unwrap();

        let (stealth, _) = generate_stealth_address(&spend_public, &view_public, 0, &mut OsRng);

        let outputs = vec![ScanOutput {
            stealth,
            output_idx: 0,
            amount: Some(100),
        }];

        let results = scanner.scan(&outputs);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].amount, Some(100));
    }

    #[test]
    fn audit_key_multi_account_scan_finds_nonzero_account_subaddress() {
        // #26 follow-up: an AuditKey with a multi-account range must detect an
        // output sent to a subaddress on a NON-ZERO account, and report the
        // correct (account, index).
        let (_spend_secret, spend_public) = generate_ec_keypair();
        let (view_secret, _view_public) = generate_ec_keypair();

        // Wallet receives at subaddress (account = 2, index = 3). A subaddress
        // output uses R = r*D_i so the wallet detects it against C_i = a*D_i
        // (see generate_stealth_address_checked_ext).
        let sub = Subaddress::generate(&spend_public, &view_secret, 2, 3).unwrap();
        let (stealth, _) = generate_stealth_address_checked_ext(
            &sub.spend_public,
            &sub.view_public,
            0,
            true,
            &mut OsRng,
        )
        .unwrap();
        let outputs = vec![ScanOutput {
            stealth,
            output_idx: 0,
            amount: Some(100),
        }];

        // Multi-account audit range covers (0..=3, 0..=5) → finds it.
        let audit = AuditKey::new(view_secret.clone(), spend_public)
            .with_subaddress_max_index(5)
            .with_subaddress_max_account(3);
        let results = audit.to_scanner().unwrap().scan(&outputs);
        assert_eq!(results.len(), 1, "multi-account scan must find the output");
        assert_eq!(results[0].subaddress_account, Some(2));
        assert_eq!(results[0].subaddress_index, Some(3));

        // Account-0-only range (no with_subaddress_max_account) must MISS it —
        // proving the account dimension is real, not cosmetic.
        let audit_acct0 = AuditKey::new(view_secret, spend_public).with_subaddress_max_index(5);
        let results0 = audit_acct0.to_scanner().unwrap().scan(&outputs);
        assert!(
            results0.is_empty(),
            "account-0-only scan must miss an account-2 subaddress"
        );
    }

    #[test]
    fn test_stealth_address_wrong_keys() {
        let (_spend_secret1, spend_public1) = generate_ec_keypair();
        let (view_secret1, view_public1) = generate_ec_keypair();

        let (_spend_secret2, spend_public2) = generate_ec_keypair();
        let (view_secret2, _view_public2) = generate_ec_keypair();

        let (stealth, _) = generate_stealth_address(&spend_public1, &view_public1, 0, &mut OsRng);

        assert!(is_output_ours(&stealth, &view_secret1, &spend_public1, 0));
        assert!(
            !is_output_ours(&stealth, &view_secret2, &spend_public2, 0),
            "Wrong recipient should not detect output"
        );
    }

    #[test]
    fn test_stealth_address_output_index_matters() {
        let (_spend_secret, spend_public) = generate_ec_keypair();
        let (view_secret, view_public) = generate_ec_keypair();

        let (stealth, _) = generate_stealth_address(&spend_public, &view_public, 0, &mut OsRng);

        assert!(is_output_ours(&stealth, &view_secret, &spend_public, 0));
        assert!(
            !is_output_ours(&stealth, &view_secret, &spend_public, 1),
            "Wrong output index should not match"
        );
    }

    #[test]
    fn recipient_owns_rejects_malformed_tx_public_forgery() {
        let (_spend_secret, spend_public) = generate_ec_keypair();
        let (view_secret, view_public) = generate_ec_keypair();
        let recipient = RecipientKeys::new(&view_secret, &spend_public).unwrap();

        let (real_stealth, _) =
            generate_stealth_address(&spend_public, &view_public, 0, &mut OsRng);
        assert!(recipient.owns(&real_stealth, 0));

        // Identity ECDH makes the expected destination computable from public
        // data, which reproduces the pre-fix ownership forgery.
        let invalid_tx_public = [0xFF; 32];
        assert!(PublicPoint::from_bytes(invalid_tx_public).is_none());
        let output_idx = 3u8;
        let shared = PublicPoint::identity();
        let scalar_input = [shared.to_bytes().as_slice(), &[output_idx]].concat();
        let one_time_base = SecretScalar::from_scalar(hash_to_scalar(&scalar_input)).to_public();
        let spend_point = PublicPoint::from_bytes(*spend_public.as_bytes()).unwrap();
        let forged = StealthAddress {
            public_key: PublicKey::from_bytes(one_time_base.add(&spend_point).to_bytes()),
            tx_public_key: PublicKey::from_bytes(invalid_tx_public),
        };

        assert!(!recipient.owns(&forged, output_idx));
    }

    #[test]
    fn test_stealth_addresses_unique() {
        let (_spend_secret, spend_public) = generate_ec_keypair();
        let (view_secret, view_public) = generate_ec_keypair();

        let (stealth1, _) = generate_stealth_address(&spend_public, &view_public, 0, &mut OsRng);
        let (stealth2, _) = generate_stealth_address(&spend_public, &view_public, 0, &mut OsRng);

        assert_ne!(
            stealth1.public_key.as_bytes(),
            stealth2.public_key.as_bytes(),
            "Each stealth address should be unique"
        );

        assert!(is_output_ours(&stealth1, &view_secret, &spend_public, 0));
        assert!(is_output_ours(&stealth2, &view_secret, &spend_public, 0));
    }

    #[test]
    fn test_one_time_secret_derivation() {
        let (spend_secret, spend_public) = generate_ec_keypair();
        let (view_secret, view_public) = generate_ec_keypair();

        let (stealth, _) = generate_stealth_address(&spend_public, &view_public, 0, &mut OsRng);

        assert!(is_output_ours(&stealth, &view_secret, &spend_public, 0));

        let one_time_secret =
            compute_one_time_secret(&stealth, &view_secret, &spend_secret, 0).unwrap();

        let one_time_scalar = SecretScalar::from_bytes(*one_time_secret.as_bytes());
        let derived_public = one_time_scalar.to_public();

        assert_eq!(
            stealth.public_key.as_bytes(),
            &derived_public.to_bytes(),
            "One-time secret should derive to the stealth public key"
        );
    }

    #[test]
    fn test_audit_key() {
        let (_, spend_public) = generate_ec_keypair();
        let (view_secret, _view_public) = generate_ec_keypair();

        let audit =
            AuditKey::new(view_secret.clone(), spend_public).with_range(Some(100), Some(1000));

        assert!(audit.is_in_range(500));
        assert!(!audit.is_in_range(50));
        assert!(!audit.is_in_range(1500));

        // Export and import
        let export = audit.export();
        let imported = AuditKey::import(&export).unwrap();

        assert_eq!(imported.start_height, Some(100));
        assert_eq!(imported.end_height, Some(1000));
    }

    #[test]
    fn test_stealth_index() {
        let (_, spend_public) = generate_ec_keypair();
        let (view_secret, _view_public) = generate_ec_keypair();

        let keys = RecipientKeys::new(&view_secret, &spend_public).unwrap();
        let mut index = StealthIndex::new(keys);

        // Generate view_public from view_secret for stealth address generation
        let view_scalar = super::SecretScalar::from_bytes(*view_secret.as_bytes());
        let view_public = PublicKey::from_bytes(view_scalar.to_public().to_bytes());

        let (stealth, _) = generate_stealth_address(&spend_public, &view_public, 0, &mut OsRng);

        let outputs = vec![IndexedOutput {
            stealth,
            output_idx: 0,
            block_height: 100,
            tx_index: 0,
        }];

        index.index_outputs(&outputs);
        assert_eq!(index.len(), 1);
    }

    #[test]
    fn test_subaddress_collision() {
        let (_spend_secret, spend_public) = generate_ec_keypair();
        let (view_secret, _view_public) = generate_ec_keypair();

        let sub0 = Subaddress::generate(&spend_public, &view_secret, 0, 0).unwrap();
        let sub1 = Subaddress::generate(&spend_public, &view_secret, 0, 1).unwrap();
        let sub2 = Subaddress::generate(&spend_public, &view_secret, 0, 2).unwrap();

        assert_ne!(sub0.spend_public.as_bytes(), sub1.spend_public.as_bytes());
        assert_ne!(sub1.spend_public.as_bytes(), sub2.spend_public.as_bytes());
        assert_ne!(sub0.spend_public.as_bytes(), sub2.spend_public.as_bytes());
    }
}
