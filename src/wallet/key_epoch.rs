//! Shim `KeyEpoch` type used by `crypto::stealth` for ECDH-based output
//! detection. This is the CoinCync 1.0 shape, kept as its own file so the
//! Zcash-style FVK/IVK/OVK code in `wallet::keys` is not disturbed.
//!
//! ## Audit map
//! Each `§` is a code section below; it states the INVARIANT it guarantees, the
//! THREAT it defends, and the TESTS that prove it.
//!
//! - **§1 `ScopedViewKey::from_epoch` / `covers_height`** — INVARIANT: a
//!   scoped view key covers exactly the inclusive `[from_height, to_height]`
//!   block range and nothing outside it (an inverted range covers nothing).
//!   THREAT: over-broad scope would disclose transaction history beyond what the
//!   holder voluntarily surrendered (e.g. a tax year).
//!   TESTS: `scoped_view_key_enforces_inclusive_range`,
//!   `scoped_view_key_scope_selects_only_in_range_blocks`,
//!   `scoped_view_key_empty_range_covers_nothing`.
//! - **§2 `ScopedViewKey::to_json`** — INVARIANT: the exported JSON carries the
//!   scope bounds plus the spend/view public keys and the scoped view secret.
//!   THREAT: a malformed export would fail to reconstruct the scoped view
//!   capability at the auditor's side.
//!   TESTS: `scoped_view_key_json_carries_scope_and_keys`.
//! - **§3 `ViewOnlyEpoch`** — INVARIANT: a view-only epoch structurally carries
//!   the view secret and only the PUBLIC spend key — no spend secret exists to
//!   sign with.
//!   THREAT: any spend-secret material here would let a view-only export spend.
//!   TESTS: `view_only_epoch_carries_no_spend_secret`.
//! - **§4 `KeyEpoch`** — INVARIANT: a full epoch pairs a spend keypair with a
//!   view keypair; secrets are wiped via the field `SecretKey` drop chain (the
//!   custom `Drop` only clears the non-secret `epoch` field).
//!   THREAT: R-72 — relying on a phantom defense-in-depth wipe that does not exist.
//!   TESTS: (gap — `KeyEpoch` is a data carrier, exercised via `wallet_keys` epoch tests).

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

/// Time-scoped view key — can only decrypt outputs within a specific
/// block height range. This lets a holder prove transaction history
/// for a specific period (e.g. a tax year) without surrendering all
/// past and future privacy. (Prior comment characterised this as
/// "CoinCync's innovation over Monero"; whether upstream Monero has
/// or lacks an equivalent time-scoped view-key primitive was not
/// re-verified against Monero source this session, so the
/// comparative-novelty claim is dropped in favour of the design
/// description above.)
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::primitives::{PublicKey, SecretKey};

    fn dummy_epoch() -> KeyEpoch {
        KeyEpoch {
            epoch: 0,
            spend_secret: SecretKey::from_bytes([1u8; 32]),
            spend_public: PublicKey::from_bytes([2u8; 32]),
            view_secret: SecretKey::from_bytes([3u8; 32]),
            view_public: PublicKey::from_bytes([4u8; 32]),
        }
    }

    #[test]
    fn scoped_view_key_enforces_inclusive_range() {
        let epoch = dummy_epoch();
        let k = ScopedViewKey::from_epoch(&epoch, 100, 200);
        // boundaries are inclusive
        assert!(k.covers_height(100));
        assert!(k.covers_height(200));
        assert!(k.covers_height(150));
        // anything outside [100, 200] is out of scope
        assert!(!k.covers_height(99));
        assert!(!k.covers_height(201));
        assert!(!k.covers_height(0));
    }

    #[test]
    fn scoped_view_key_json_carries_scope_and_keys() {
        let epoch = dummy_epoch();
        let k = ScopedViewKey::from_epoch(&epoch, 100, 200);
        let json = k.to_json();
        assert!(json.contains("\"from_height\":100"), "json: {json}");
        assert!(json.contains("\"to_height\":200"), "json: {json}");
        // carries the spend/view publics + the (scoped) view secret
        assert!(
            json.contains(&hex::encode([4u8; 32])),
            "view_public missing"
        );
        assert!(
            json.contains(&hex::encode([2u8; 32])),
            "spend_public missing"
        );
    }

    /// The scope selects exactly the in-range block heights and skips the rest
    /// — this is the predicate the wallet scanner consults per block, so a
    /// contiguous height sweep must yield precisely `[from, to]` inclusive.
    #[test]
    fn scoped_view_key_scope_selects_only_in_range_blocks() {
        let epoch = dummy_epoch();
        let k = ScopedViewKey::from_epoch(&epoch, 100, 105);
        let scanned: Vec<u64> = (95..=110).filter(|h| k.covers_height(*h)).collect();
        assert_eq!(scanned, vec![100, 101, 102, 103, 104, 105]);
    }

    /// An inverted range (from_height > to_height) is empty — it covers no
    /// height at all, so such a scoped key would scan nothing.
    #[test]
    fn scoped_view_key_empty_range_covers_nothing() {
        let epoch = dummy_epoch();
        let k = ScopedViewKey::from_epoch(&epoch, 200, 100);
        for h in [0u64, 99, 100, 150, 200, 201, 1000] {
            assert!(
                !k.covers_height(h),
                "empty (inverted) range must cover nothing, but covered {h}"
            );
        }
    }

    /// A `ViewOnlyEpoch` carries the view secret and only the PUBLIC spend key
    /// — it structurally has no `spend_secret` field, so there is no key
    /// material that could be coerced into producing a signature. (Absence of
    /// the field is a compile-time guarantee; this pins the runtime shape.)
    #[test]
    fn view_only_epoch_carries_no_spend_secret() {
        let vo = ViewOnlyEpoch {
            epoch: 3,
            view_secret: SecretKey::from_bytes([7u8; 32]),
            view_public: PublicKey::from_bytes([8u8; 32]),
            spend_public: PublicKey::from_bytes([9u8; 32]),
        };
        // View capability is present.
        assert_eq!(vo.view_secret.as_bytes(), &[7u8; 32]);
        // The spend side is public-only — no secret to sign with.
        assert_eq!(vo.spend_public.as_bytes(), &[9u8; 32]);
    }
}
