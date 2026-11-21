//! Share-informed retarget — the connector + gated policy-slot (Observe-only).
//!
//! The retarget *rule* is built and tested here, fully, so it is ready to plug
//! in — but the hash-locked `difficulty.rs` / `validation.rs` are **not** edited.
//! Making the retarget LIVE means the locked validator must accept the new target,
//! which is a single coordinated-fork change at a post-audit Enforce height (see
//! `bobtail-spec.md` §10), done with review + lock regen + fingerprint change.
//! Until then this connector returns the ASERT target **unchanged**, so wiring it
//! into a call site is byte-identical — the connector/policy-slot pattern that
//! keeps churn out of the locked heart.
//!
//! The rule: blend the live ASERT target with the share-hashrate shadow target
//! (`super::shadow`). The share signal is ~60× denser, so it leads hashrate
//! shifts; a partial blend damps toward it without discarding ASERT's long-horizon
//! anchor. The blend is 0 while gated (Observe), a settled fraction at Enforce.

use super::biguint::U512;
use super::shadow::shadow_target;
use crate::primitives::Hash;

/// Enforce-time blend of the share-informed target into the next target, as
/// `num/den`. `0/den` = pure ASERT (Observe/off); `den/den` = pure share-informed.
/// Held at 0 until a coordinated Enforce fork sets it.
pub const SHARE_BLEND_NUMERATOR: u32 = 0;
pub const SHARE_BLEND_DENOMINATOR: u32 = 4;

/// Weighted blend of two targets in the 256-bit target domain:
/// `asert·(den−num)/den + shadow·num/den`. `num == 0` (or `den == 0`) returns the
/// ASERT target **unchanged**. The result is a convex combination of two
/// sub-2^256 values, so it never overflows the target domain.
pub fn retarget_blend(asert_target: &Hash, share_hashrate: f64, num: u32, den: u32) -> Hash {
    if num == 0 || den == 0 {
        return *asert_target; // Observe: byte-identical to ASERT
    }
    let num = num.min(den);
    let shadow = shadow_target(share_hashrate);
    let a = U512::from_big_endian(asert_target.as_bytes());
    let s = U512::from_big_endian(shadow.as_bytes());
    let (num_u, den_u) = (U512::from(num as u64), U512::from(den as u64));
    let blended = (a * (den_u - num_u) + s * num_u) / den_u; // ≤ max(a,s) < 2^256
    let mut be = [0u8; 64];
    blended.to_big_endian(&mut be);
    let mut out = [0u8; 32];
    out.copy_from_slice(&be[32..64]);
    Hash::from_bytes(out)
}

/// The target a share-informed retarget would set, at the settled Enforce blend.
pub fn share_informed_target(asert_target: &Hash, share_hashrate: f64) -> Hash {
    retarget_blend(
        asert_target,
        share_hashrate,
        SHARE_BLEND_NUMERATOR,
        SHARE_BLEND_DENOMINATOR,
    )
}

/// **The policy slot** the locked validator would consult at Enforce: the
/// share-informed target once [`super::bobtail_enforce_active_at`] is reached,
/// else the ASERT target unchanged. Fully built + tested here; the one remaining
/// change is the locked-core call site at a coordinated post-audit fork. With
/// Enforce gated off (`u64::MAX`) this is byte-identical to pure ASERT.
pub fn effective_next_target(height: u64, asert_target: &Hash, share_hashrate: f64) -> Hash {
    if super::bobtail_enforce_active_at(height) {
        share_informed_target(asert_target, share_hashrate)
    } else {
        *asert_target
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn blend_zero_is_asert_unchanged() {
        let a = Hash::from_difficulty(5_000);
        assert_eq!(retarget_blend(&a, 1234.0, 0, 4), a, "0 blend ⇒ ASERT unchanged");
        // The settled (gated) blend is 0, so share_informed_target == ASERT now.
        assert_eq!(share_informed_target(&a, 1234.0), a);
    }

    #[test]
    fn blend_full_is_the_shadow_target() {
        let a = Hash::from_difficulty(5_000);
        let full = retarget_blend(&a, 9_999.0, 4, 4);
        assert_eq!(full, shadow_target(9_999.0), "den/den ⇒ pure share-informed");
    }

    #[test]
    fn blend_is_between_the_two_targets() {
        // asert easy (big target), shadow hard (small target) ⇒ blend strictly between.
        let a = Hash::from_difficulty(100); // easier ⇒ larger target
        let hr = 1_000_000.0; // high hashrate ⇒ hard shadow target (small)
        let s = shadow_target(hr);
        assert!(s < a, "high hashrate ⇒ harder (smaller) shadow target than easy ASERT");
        let mid = retarget_blend(&a, hr, 2, 4);
        assert!(mid < a && mid > s, "half blend sits strictly between ASERT and shadow");
    }

    #[test]
    fn enforce_slot_is_gated_off_now() {
        let a = Hash::from_difficulty(5_000);
        // Enforce height is u64::MAX ⇒ the slot returns ASERT unchanged at any height.
        assert_eq!(effective_next_target(1_000_000, &a, 1234.0), a);
        assert_eq!(effective_next_target(u64::MAX - 1, &a, 1234.0), a);
    }
}
