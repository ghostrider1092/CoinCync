//! # CLSAG-FROST Integration — DESIGN DOCUMENT for a future distributed variant
//!
//! **THIS MODULE IS DESIGN-ONLY.** No production code path routes through it.
//! It documents the math for a FULLY DISTRIBUTED CLSAG threshold signing
//! variant (M FROST signers produce a CLSAG signature without ever
//! reconstructing the group secret) — that variant is NOT IMPLEMENTED.
//!
//! For the PRACTICAL threshold-CLSAG that actually ships in v1.0.x, see
//! [`crate::wallet::multisig::clsag_sign_multisig`]
//! (`src/wallet/multisig.rs:427-453`). That implementation uses the
//! "Reconstruct-Sign-Zeroize" model: the coordinator collects M signing
//! shares, Lagrange-interpolates the group secret, signs with the
//! standard `crypto::clsag::clsag_sign`, and immediately zeroizes the
//! reconstructed key. The reconstructed key exists in memory for
//! microseconds and never touches disk. `wallet::multisig`'s module
//! docstring at L319-338 explains this trade-off explicitly.
//!
//! ## Why this design document exists
//!
//! The fully-distributed variant would need a fork of `frost-core` to
//! expose raw nonce scalars and a custom challenge computation. That's a
//! v2 goal. Keeping the design here — even though no code implements it
//! — means the math is preserved for the next iteration.
//!
//! ## Prior C31-shape audit note (2026-07-02)
//!
//! An earlier version of this file exported `integration_status()`
//! reporting "FROST keygen + signing: COMPLETE" / "CLSAG ring
//! construction: COMPLETE" / "CLSAG-FROST threshold ring signing:
//! ARCHITECTURE DEFINED". Read literally, the string was defensible
//! (each subsystem exists somewhere), but the framing implied the
//! integration was done. It also referenced `clsag_sign() line 284`
//! — the actual s_real computation is at clsag.rs:293, and the line
//! number would have rotted regardless. Both problems are closed
//! below: `integration_status()` now names the real implementation
//! file, explicitly states the distributed variant is NOT
//! implemented, and drops the fragile line reference.

/// **Design-only.** Parameters the coordinator WOULD compute and share
/// with FROST signers in the fully-distributed CLSAG variant. Unused
/// by the shipped code. Kept so the design's data flow stays
/// documented at the type level for whoever implements the v2 path.
#[allow(dead_code)]
#[derive(Clone, Debug)]
pub struct ClsagThresholdParams {
    /// The challenge value at the real signer's position in the ring
    pub challenge_at_real: [u8; 32],
    /// The aggregate coefficient mu_p (applied to spend key)
    pub mu_p: [u8; 32],
    /// The message being signed (typically the transaction prefix hash)
    pub message: Vec<u8>,
    /// The CLSAG ring structure (for verification)
    pub ring_size: usize,
    /// Index of the real signer in the ring
    pub real_index: usize,
}

/// Honest status report of the CLSAG-FROST integration.
///
/// Rewritten 2026-07-02 to close R-27 (audit-catalogue). The prior
/// text mixed three unrelated subsystem statuses into a single "looks
/// COMPLETE" claim. This version names each subsystem, its actual
/// location, and whether it is implemented or design-only.
pub fn integration_status() -> &'static str {
    "─── CLSAG threshold-signing status ─────────────────────────────\n\
     \n\
     [SHIPPED] Standalone FROST(ed25519) keygen + signing\n\
     Location: src/wallet/multisig.rs (functions: generate_shares,\n\
     signing_round1, signing_round2, aggregate_signature).\n\
     \n\
     [SHIPPED] Standalone single-signer CLSAG\n\
     Location: src/crypto/clsag.rs (functions: clsag_sign, clsag_verify).\n\
     \n\
     [SHIPPED] Practical threshold CLSAG via Reconstruct-Sign-Zeroize\n\
     Location: src/wallet/multisig.rs::clsag_sign_multisig (line 427).\n\
     Coordinator collects M signing shares, Lagrange-interpolates the\n\
     group secret into a `SecretScalar` (ZeroizeOnDrop), signs via the\n\
     standard clsag_sign path, and the reconstructed key wipes on drop.\n\
     The on-chain signature is byte-indistinguishable from single-signer.\n\
     Security note: the group secret exists in coordinator memory for\n\
     ~microseconds; hardware-wallet-style single-machine signing has\n\
     the same window. See wallet/multisig.rs:319-338 for the trade-off.\n\
     \n\
     [NOT IMPLEMENTED] Fully-distributed CLSAG threshold signing\n\
     Location: this file (design only). Would require a fork of\n\
     frost-core to expose raw nonce scalars for the CLSAG-specific\n\
     challenge chain. Deferred to a future release.\n\
     \n\
     ─── Integration math (documented for the v2 distributed path) ──\n\
     s_real = alpha - c * (mu_p * x + mu_c * z)\n\
       - alpha  : FROST distributed nonce (round 1) — v2\n\
       - mu_p*x : FROST distributed signing (round 2) — v2\n\
       - mu_c*z : coordinator adds blinding factor\n\
     See `_protocol_documentation` below for the full math block."
}

/// Full math block for the FULLY DISTRIBUTED CLSAG-FROST variant.
///
/// **DESIGN-ONLY.** No code path implements this today. Kept as a
/// module-level docstring on a zero-body function so it appears in
/// `cargo doc` output for whoever implements the v2 distributed path.
///
/// ```text
/// STANDARD CLSAG (single signer):
///   alpha = random()
///   L_real = alpha * G
///   R_real = alpha * Hp(P_real)
///   ... challenge chain ...
///   s_real = alpha - c_real * (mu_p * x + mu_c * z)
///
/// THRESHOLD CLSAG (fully distributed FROST multi-sig — NOT YET IMPLEMENTED):
///   // Round 0: Coordinator computes ring + challenges for non-real indices
///   // This is identical to standard CLSAG
///
///   // Round 1: FROST nonce generation
///   // Each of M signers generates partial nonces
///   // Coordinator aggregates into group nonce = alpha_group
///   // L_real = alpha_group * G  (same as standard)
///   // R_real = alpha_group * Hp(P_group)
///
///   // Challenge chain proceeds normally
///   // c_real is computed from the chain
///
///   // Round 2: FROST signing
///   // The "message" for FROST is: c_real * mu_p (a scalar)
///   // Each signer computes: partial_s = partial_alpha - c_real * mu_p * x_i
///   // Coordinator aggregates: s_spend = sum(partial_s)
///   // Then adds blinding: s_real = s_spend - c_real * mu_c * z
///
///   // Final signature is identical format to standard CLSAG
/// ```
#[allow(dead_code)]
pub fn _protocol_documentation() {}

#[cfg(test)]
mod tests {
    use super::*;

    /// R-27 regression: `integration_status()` must NOT falsely report
    /// "COMPLETE" for the fully-distributed variant that isn't
    /// implemented. It MUST also name the file where the practical
    /// threshold-signing actually lives so an auditor can trace it.
    #[test]
    fn integration_status_names_actual_implementation() {
        let s = integration_status();
        assert!(
            s.contains("wallet/multisig.rs"),
            "must reference the file where threshold-CLSAG is actually implemented"
        );
        assert!(
            s.contains("NOT IMPLEMENTED"),
            "must be explicit that the distributed variant is not shipped"
        );
        assert!(
            s.contains("clsag_sign_multisig"),
            "must name the actual practical implementation function"
        );
        // Must NOT falsely claim the module's own subject is COMPLETE.
        assert!(
            !s.contains("threshold ring signing: COMPLETE"),
            "must NOT falsely mark the distributed variant complete"
        );
    }
}
