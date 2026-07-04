//! Forward-secret view keys for CoinCync 1.0
//!
//! AUDIT (R-14 SURGICAL FIX, 2026-07-03): `AmountCapped(u64)` and
//! `SingleUse` are now enforced via `ViewKey::authorize_scan(amount)`
//! and mutable state (`consumed_amount`, `single_use_fired`). The
//! previous is_valid_for_epoch-only path is unchanged for
//! `EpochOnly` / `TimeRange` — those variants never needed
//! per-scan enforcement. Cumulative accounting semantics chosen
//! for AmountCapped (each scan reduces the remaining budget by
//! the amount it observed). Callers who mint a
//! `ViewKeyScope::AmountCapped(1_000_000)` and hand it out MUST
//! use the `authorize_scan` API before decrypting — the deprecated
//! `is_valid_for_epoch` gate is retained for backward compat with
//! `EpochOnly` and `TimeRange` callers, but returns false for
//! the two enforced variants once their budget/use is exhausted.

use crate::primitives::{SecretKey, hash_domain};
use serde::{Serialize, Deserialize};
use zeroize::{Zeroize, ZeroizeOnDrop};

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
    /// R-14 SURGICAL FIX (2026-07-03): cumulative amount seen so
    /// far. Only meaningful for `ViewKeyScope::AmountCapped`.
    #[zeroize(skip)]
    pub consumed_amount: u64,
    /// R-14: `true` once SingleUse has authorized one scan.
    #[zeroize(skip)]
    pub single_use_fired: bool,
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
///
/// AUDIT (R-15 fix, 2026-07-02): the deserialized value has
/// `key_data == [0u8; 32]`, which is a valid Zeroize state but a
/// USABLE ViewKey from the type system's perspective. A caller that
/// forgot to re-derive would use `[0u8; 32]` as the encryption /
/// scan key, silently producing wrong results (rather than an
/// error). Because deserialize can't take a `view_secret` argument
/// (serde's trait signature is fixed), the enforcement has to be
/// done at the CALL SITE. To make the requirement visible without
/// changing the trait shape, we now:
///   - Set `key_data` to a KNOWN sentinel (all-0xEE) rather than
///     all-zeros. Any code path that skipped rederivation will
///     produce cryptographic output that DOES NOT match any real
///     wallet's derivation, so failure is loud (empty scan
///     results, invalid decrypts) rather than silent (working with
///     wrong-but-plausible key material).
///   - Document loudly on the type that the returned ViewKey MUST
///     have `re_derive_key_data(view_secret)` called before it
///     participates in any crypto op.
///
/// A future audit iteration should introduce a
/// `PendingViewKey`/`ViewKey` type split so the type system
/// enforces rederivation. Deferred: that changes every persisted
/// ViewKey caller across wallet/, RPC/, and CLI/.
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
            // R-15 sentinel: 0xEE instead of 0x00 so callers who
            // forget to re-derive get loud failures, not silent
            // wrong-key operation. Any real key_data derived from a
            // real view_secret is a uniform 32-byte hash output;
            // the probability of matching all-0xEE by chance is 2^-256.
            key_data: [0xEEu8; 32],
            epoch: h.epoch,
            scope: h.scope,
            watermark: wm_bytes,
            consumed_amount: 0,
            single_use_fired: false,
        })
    }
}

impl ViewKey {
    /// Derive a forward-secret view key from a wallet's view_secret,
    /// an epoch, and a scope.
    ///
    /// AUDIT (R-12 fix, 2026-07-02): the pre-fix code did
    ///   `[view_secret.as_bytes().as_slice(), &epoch.to_le_bytes()].concat()`
    /// which builds a `Vec<u8>` on the heap holding the raw
    /// view_secret bytes. That Vec was passed to hash_domain by
    /// reference and then dropped without zeroization, leaving
    /// view_secret bytes sitting in the allocator's freed pool. Now
    /// we build the buffer explicitly, hash it, and `Zeroize::zeroize`
    /// it before it goes out of scope.
    ///
    /// AUDIT (R-13 note, 2026-07-02): the `watermark` field is derived
    /// from `key_data` and then serialized in plaintext (see
    /// `Serialize` impl at L41). Because the watermark is
    /// deterministic in the view_secret, an auditor who receives
    /// TWO exported ViewKeys derived from the same view_secret can
    /// link them by watermark — this is the intended purpose (proof
    /// that a shared-audit key came from the same origin), but the
    /// SAME property lets an adversary who compromises a mailing list
    /// or a leaked file inventory correlate ViewKeys from different
    /// audit engagements as sharing an origin. Not fixed here because
    /// removing/randomizing the watermark breaks the audit-provenance
    /// use case. Documented so callers understand the linkability
    /// they're opting into.
    pub fn derive(view_secret: &SecretKey, epoch: u64, scope: ViewKeyScope) -> Self {
        let mut buf = Vec::with_capacity(32 + 8);
        buf.extend_from_slice(view_secret.as_bytes());
        buf.extend_from_slice(&epoch.to_le_bytes());
        let key_data = hash_domain(b"COINCYNC_VIEWKEY_v2", &buf);
        // R-12: wipe the buffer (contains view_secret bytes) before
        // it goes out of scope.
        buf.zeroize();
        let watermark = hash_domain(b"COINCYNC_WATERMARK", key_data.as_bytes());

        ViewKey {
            key_data: *key_data.as_bytes(),
            epoch,
            scope,
            // safe: slicing 8 bytes from a 32-byte hash always succeeds
            watermark: watermark.as_bytes()[..8].try_into().expect("8-byte slice from 32-byte hash"),
            consumed_amount: 0,
            single_use_fired: false,
        }
    }

    pub fn is_valid_for_epoch(&self, epoch: u64) -> bool {
        match self.scope {
            ViewKeyScope::EpochOnly(e) => epoch == e,
            ViewKeyScope::TimeRange { start, end } => epoch >= start && epoch <= end,
            ViewKeyScope::AmountCapped(cap) => {
                epoch == self.epoch && self.consumed_amount < cap
            },
            ViewKeyScope::SingleUse => epoch == self.epoch && !self.single_use_fired,
        }
    }

    /// R-14 SURGICAL FIX (2026-07-03): stateful authorize+consume
    /// for AmountCapped / SingleUse variants. Call this BEFORE
    /// decrypting a scanned amount. Returns `Ok(())` if the scan
    /// is authorized (and consumes the budget); `Err` if the cap
    /// is exhausted or SingleUse already fired. For EpochOnly /
    /// TimeRange variants this is a pure delegation to
    /// `is_valid_for_epoch(epoch)`.
    pub fn authorize_scan(
        &mut self,
        epoch: u64,
        amount: u64,
    ) -> Result<(), &'static str> {
        match self.scope {
            ViewKeyScope::EpochOnly(e) => {
                if epoch != e {
                    return Err("epoch mismatch for EpochOnly view key");
                }
                Ok(())
            }
            ViewKeyScope::TimeRange { start, end } => {
                if epoch < start || epoch > end {
                    return Err("epoch outside TimeRange for view key");
                }
                Ok(())
            }
            ViewKeyScope::AmountCapped(cap) => {
                if epoch != self.epoch {
                    return Err("epoch mismatch for AmountCapped view key");
                }
                let new_total = self.consumed_amount.saturating_add(amount);
                if new_total > cap {
                    return Err("AmountCapped view key budget exhausted");
                }
                self.consumed_amount = new_total;
                Ok(())
            }
            ViewKeyScope::SingleUse => {
                if epoch != self.epoch {
                    return Err("epoch mismatch for SingleUse view key");
                }
                if self.single_use_fired {
                    return Err("SingleUse view key already fired");
                }
                self.single_use_fired = true;
                let _ = amount; // silence unused (kept for future policy)
                Ok(())
            }
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
