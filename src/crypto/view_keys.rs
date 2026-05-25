//! Forward-secret view keys for CoinCync 1.0

use crate::primitives::{SecretKey, hash_domain};
use serde::{Serialize, Deserialize};
use zeroize::ZeroizeOnDrop;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ViewKeyScope { EpochOnly(u64), TimeRange { start: u64, end: u64 }, AmountCapped(u64), SingleUse }

/// Forward-secret view key.
///
/// SECURITY (A6-VIEWKEY): `key_data` is excluded from `Serialize` to prevent
/// accidental exposure in logs, RPC responses, or JSON dumps. The field is
/// zeroed on drop via `ZeroizeOnDrop` — `key_data` deliberately does NOT
/// carry `#[zeroize(skip)]` so the `[u8; 32]` Zeroize impl wipes it; the
/// non-secret metadata below carry `skip` only as a micro-optimization
/// (zeroing a u64 epoch is harmless but pointless).
///
/// HISTORICAL BUG: prior to 2026-05-24 this field had `#[zeroize(skip)]`
/// with an in-line comment claiming "skip only applies to non-secret
/// fields; key_data IS zeroized via the struct derive." The comment was
/// wrong — `zeroize_derive` v1.4.x explicitly excludes `skip`ped fields
/// from the generated `Zeroize::zeroize` impl (see zeroize_derive's
/// `zeroize_with_skip` test). The skip attribute on the secret meant the
/// claimed forward-secrecy guarantee was not enforced. Removing it
/// restores the documented behavior.
#[derive(Clone, ZeroizeOnDrop)]
pub struct ViewKey {
    /// EXCLUDED from Serialize — never leaves process memory unless explicitly exported.
    /// Zeroed on Drop via the struct's `ZeroizeOnDrop` derive (no `skip` attribute).
    pub key_data: [u8; 32],
    #[zeroize(skip)]
    pub epoch: u64,
    #[zeroize(skip)]
    pub scope: ViewKeyScope,
    #[zeroize(skip)]
    pub watermark: [u8; 8],
}

/// Manual Serialize: emit everything EXCEPT key_data.
impl Serialize for ViewKey {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeStruct;
        let mut s = serializer.serialize_struct("ViewKey", 3)?;
        s.serialize_field("epoch", &self.epoch)?;
        s.serialize_field("scope", &self.scope)?;
        s.serialize_field("watermark", &hex::encode(self.watermark))?;
        s.end()
    }
}

/// Manual Deserialize: key_data is zeroed — caller must re-derive after loading.
impl<'de> Deserialize<'de> for ViewKey {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        struct Helper {
            epoch: u64,
            scope: ViewKeyScope,
            watermark: String,
        }
        let h = Helper::deserialize(deserializer)?;
        let wm_bytes: [u8; 8] = hex::decode(&h.watermark)
            .map_err(serde::de::Error::custom)?
            .try_into()
            .map_err(|_| serde::de::Error::custom("watermark must be 8 bytes"))?;
        Ok(ViewKey {
            key_data: [0u8; 32], // must be re-derived
            epoch: h.epoch,
            scope: h.scope,
            watermark: wm_bytes,
        })
    }
}

impl ViewKey {
    pub fn derive(view_secret: &SecretKey, epoch: u64, scope: ViewKeyScope) -> Self {
        let key_data = hash_domain(b"COINCYNC_VIEWKEY_v2", &[view_secret.as_bytes().as_slice(), &epoch.to_le_bytes()].concat());
        let watermark = hash_domain(b"COINCYNC_WATERMARK", key_data.as_bytes());

        ViewKey {
            key_data: *key_data.as_bytes(),
            epoch,
            scope,
            // safe: slicing 8 bytes from a 32-byte hash always succeeds
            watermark: watermark.as_bytes()[..8].try_into().expect("8-byte slice from 32-byte hash"),
        }
    }

    pub fn is_valid_for_epoch(&self, epoch: u64) -> bool {
        match self.scope {
            ViewKeyScope::EpochOnly(e) => epoch == e,
            ViewKeyScope::TimeRange { start, end } => epoch >= start && epoch <= end,
            ViewKeyScope::AmountCapped(_) => epoch == self.epoch,
            ViewKeyScope::SingleUse => epoch == self.epoch,
        }
    }
}

/// SECURITY: Debug redacts key_data to prevent leakage in logs.
impl std::fmt::Debug for ViewKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ViewKey")
            .field("key_data", &"[REDACTED]")
            .field("epoch", &self.epoch)
            .field("scope", &self.scope)
            .field("watermark", &hex::encode(self.watermark))
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::primitives::SecretKey;

    #[test]
    fn test_view_key_derivation_determinism() {
        let secret = SecretKey::from_bytes([42u8; 32]);
        let vk1 = ViewKey::derive(&secret, 1, ViewKeyScope::EpochOnly(1));
        let vk2 = ViewKey::derive(&secret, 1, ViewKeyScope::EpochOnly(1));
        assert_eq!(vk1.key_data, vk2.key_data);
        assert_eq!(vk1.watermark, vk2.watermark);
    }

    #[test]
    fn test_view_key_different_epochs_differ() {
        let secret = SecretKey::from_bytes([42u8; 32]);
        let vk1 = ViewKey::derive(&secret, 1, ViewKeyScope::EpochOnly(1));
        let vk2 = ViewKey::derive(&secret, 2, ViewKeyScope::EpochOnly(2));
        assert_ne!(vk1.key_data, vk2.key_data);
    }

    #[test]
    fn test_view_key_epoch_validity() {
        let secret = SecretKey::from_bytes([42u8; 32]);
        let vk = ViewKey::derive(&secret, 5, ViewKeyScope::EpochOnly(5));
        assert!(vk.is_valid_for_epoch(5));
        assert!(!vk.is_valid_for_epoch(6));

        let vk_range = ViewKey::derive(&secret, 3, ViewKeyScope::TimeRange { start: 3, end: 7 });
        assert!(vk_range.is_valid_for_epoch(5));
        assert!(!vk_range.is_valid_for_epoch(8));
    }

    #[test]
    fn test_view_key_debug_redacts_key_data() {
        let secret = SecretKey::from_bytes([42u8; 32]);
        let vk = ViewKey::derive(&secret, 1, ViewKeyScope::EpochOnly(1));
        let debug = format!("{:?}", vk);
        assert!(debug.contains("REDACTED"), "Debug output should redact key_data");
        // key_data bytes should NOT appear in debug output
        assert!(!debug.contains(&format!("{:?}", vk.key_data)));
    }

    #[test]
    fn test_view_key_serialize_excludes_key_data() {
        let secret = SecretKey::from_bytes([42u8; 32]);
        let vk = ViewKey::derive(&secret, 1, ViewKeyScope::EpochOnly(1));
        let json = serde_json::to_string(&vk).unwrap();
        // JSON should NOT contain key_data
        assert!(!json.contains("key_data"), "Serialized ViewKey should not contain key_data");
        assert!(json.contains("epoch"), "Serialized ViewKey should contain epoch");
    }
}
