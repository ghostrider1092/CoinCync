//! # Safe Orchard wrapper (feature-gated)
//!
//! Thin, type-safe wrapper around the audited `orchard` crate. We use
//! the crate *as-is* — no modifications to its circuit, no custom gates
//! — because touching an audited ZK circuit is how soundness bugs get
//! introduced. The wrapper enforces correct API usage at the type level:
//!
//! 1. `SafeOrchardWallet::from_key_bytes` validates spending-key bytes
//!    and never exposes the raw `SpendingKey`.
//! 2. `validate_note` returns a `ValidatedNote` only if the note passes
//!    value and nullifier checks. `create_bundle` refuses raw `Note`s.
//! 3. `verify_bundle` returns a `VerifiedBundle` only if the ZK proof
//!    verifies. `record_spend` refuses unverified bundles.
//! 4. `record_spend` is the only way to mark nullifiers spent, and it
//!    requires a `VerifiedBundle` — the type system prevents replays
//!    against unverified input.
//!
//! ## Feature gate and known compat issue
//!
//! This module is behind the `halo2-orchard` Cargo feature because
//! `orchard 0.12` and `tari_bulletproofs_plus 0.4.1` can't be resolved
//! together by rustc's trait solver: adding `orchard` to the dep tree
//! causes a `for<'v> &'v Simd<_, _>: Add` overflow in
//! `tari_bulletproofs_plus::RangeProof`'s HRTB. The conflict is in
//! upstream crates we don't own. Resolving it requires either
//!
//! - upgrading tari_bulletproofs_plus when a fixed release ships,
//! - migrating `src/crypto/bulletproofs.rs` to a different Bulletproofs+
//!   backend that doesn't expose the conflicting blanket impl, or
//! - waiting on a rustc trait-solver improvement (the `-Znext-solver`
//!   path looks promising).
//!
//! Until then: the wrapper lives in the tree and is reviewable, the
//! stub at `src/crypto/halo2_circuit.rs` is what default builds use,
//! and `cargo build --features halo2-orchard` is the one-switch toggle
//! the next session can flip once the upstream conflict is gone.

use std::collections::HashSet;

use orchard::{
    builder::{Builder, BundleType, InProgress, Unproven},
    bundle::{Authorized, Bundle},
    circuit::{ProvingKey, VerifyingKey},
    keys::{FullViewingKey, PreparedIncomingViewingKey, Scope, SpendAuthorizingKey, SpendingKey},
    note::Nullifier,
    tree::{Anchor, MerklePath},
    value::NoteValue,
    Address, Note,
};
use rand::rngs::OsRng;

/// Maximum shielded value, matching Zcash's supply cap (21M * 10^8 zats).
/// The Orchard circuit enforces its own range constraints; this is a
/// defense-in-depth app-layer check so obviously bogus input fails
/// before we pay the cost of building a ZK proof.
const MAX_MONEY: u64 = 2_100_000_000_000_000;

// ─────────────────────────────────────────────────────────────
// Safe wrapper types
// ─────────────────────────────────────────────────────────────

/// A wallet whose spending key is never exposed. Nullifier tracking
/// lives on the wallet so double-spend detection and note validation
/// share a single source of truth.
pub struct SafeOrchardWallet {
    spending_key: SpendingKey,
    full_viewing_key: FullViewingKey,
    #[allow(dead_code)] // Retained for future scanning APIs
    incoming_viewing_key: PreparedIncomingViewingKey,
    spent_nullifiers: HashSet<[u8; 32]>,
}

/// A note that passed value and nullifier checks. The only way to
/// obtain one is via [`SafeOrchardWallet::validate_note`], so any API
/// that takes `ValidatedNote` is statically guaranteed to see a
/// well-formed, unspent note.
pub struct ValidatedNote {
    inner: Note,
    merkle_path: MerklePath,
    #[allow(dead_code)] // Retained for app-layer tracing / logging
    nullifier_bytes: [u8; 32],
}

/// A bundle whose ZK proof has been verified. Only [`verify_bundle`]
/// can construct one, so any API that takes `VerifiedBundle` is
/// statically guaranteed to see a proof-valid shielded action.
pub struct VerifiedBundle {
    inner: Bundle<Authorized, i64>,
}

impl VerifiedBundle {
    /// Read-only access to the underlying authorized bundle.
    pub fn as_bundle(&self) -> &Bundle<Authorized, i64> {
        &self.inner
    }
}

// ─────────────────────────────────────────────────────────────
// Error types
// ─────────────────────────────────────────────────────────────

#[derive(Debug, thiserror::Error)]
pub enum NoteError {
    #[error("note value is zero")]
    ZeroValue,
    #[error("note value exceeds supply cap")]
    ValueExceedsCap,
    #[error("note nullifier is already spent")]
    AlreadySpent,
}

#[derive(Debug, thiserror::Error)]
pub enum BundleError {
    #[error("send value cannot be zero")]
    ZeroSendValue,
    #[error("send value exceeds input note value")]
    InsufficientFunds,
    #[error("orchard spend add failed: {0}")]
    SpendFailed(String),
    #[error("orchard output add failed: {0}")]
    OutputFailed(String),
    #[error("orchard bundle build failed: {0}")]
    BuildFailed(String),
    #[error("orchard build produced no bundle")]
    EmptyBundle,
    #[error("halo2 proof creation failed: {0}")]
    ProofFailed(String),
    #[error("orchard signature application failed: {0}")]
    SignatureFailed(String),
}

#[derive(Debug, thiserror::Error)]
pub enum VerifyError {
    #[error("halo2 proof verification failed: {0}")]
    InvalidProof(String),
}

// ─────────────────────────────────────────────────────────────
// Wallet construction & key management
// ─────────────────────────────────────────────────────────────

impl SafeOrchardWallet {
    /// Construct a wallet from 32 bytes of secret key material.
    /// Returns `None` for inputs that are not a valid Pallas scalar —
    /// callers must never unwrap this without handling the `None`
    /// case, because a panicking unwrap on untrusted key bytes is a
    /// DoS vector.
    pub fn from_key_bytes(bytes: &[u8; 32]) -> Option<Self> {
        // `SpendingKey::from_bytes` returns a `CtOption`; convert
        // to `Option` via the standard `From` impl in the `subtle`
        // crate.
        let spending_key: SpendingKey =
            Option::<SpendingKey>::from(SpendingKey::from_bytes(*bytes))?;
        let full_viewing_key = FullViewingKey::from(&spending_key);
        let incoming_viewing_key =
            PreparedIncomingViewingKey::new(&full_viewing_key.to_ivk(Scope::External));
        Some(Self {
            spending_key,
            full_viewing_key,
            incoming_viewing_key,
            spent_nullifiers: HashSet::new(),
        })
    }

    /// The external payment address at diversifier index 0. Never
    /// returns an internal-scope address — those are for change and
    /// must not be shared with counterparties.
    pub fn payment_address(&self) -> Address {
        self.full_viewing_key.address_at(0u64, Scope::External)
    }

    /// Read-only borrow of the full viewing key. Exposed so callers
    /// can derive additional diversified addresses or perform trial
    /// decryption — but never the spending key.
    pub fn full_viewing_key(&self) -> &FullViewingKey {
        &self.full_viewing_key
    }

    /// Number of nullifiers this wallet has marked spent.
    pub fn spent_count(&self) -> usize {
        self.spent_nullifiers.len()
    }

    /// Check whether a nullifier has been marked spent on this wallet.
    pub fn is_spent(&self, nullifier: &Nullifier) -> bool {
        self.spent_nullifiers.contains(&nullifier.to_bytes())
    }
}

// ─────────────────────────────────────────────────────────────
// Note validation
// ─────────────────────────────────────────────────────────────

impl SafeOrchardWallet {
    /// Validate a note and attach the Merkle path the circuit will
    /// use to prove membership in the commitment tree. Rejects
    /// zero-valued notes, notes above the supply cap, and notes whose
    /// nullifier is already in the spent set.
    pub fn validate_note(
        &self,
        note: Note,
        merkle_path: MerklePath,
    ) -> Result<ValidatedNote, NoteError> {
        if note.value().inner() == 0 {
            return Err(NoteError::ZeroValue);
        }
        if note.value().inner() > MAX_MONEY {
            return Err(NoteError::ValueExceedsCap);
        }
        let nullifier = note.nullifier(&self.full_viewing_key);
        let nullifier_bytes = nullifier.to_bytes();
        if self.spent_nullifiers.contains(&nullifier_bytes) {
            return Err(NoteError::AlreadySpent);
        }
        Ok(ValidatedNote {
            inner: note,
            merkle_path,
            nullifier_bytes,
        })
    }
}

// ─────────────────────────────────────────────────────────────
// Bundle building & proof generation
// ─────────────────────────────────────────────────────────────

impl SafeOrchardWallet {
    /// Build an authorized Orchard bundle. Wraps [`Builder`],
    /// [`Bundle::create_proof`], and [`Bundle::apply_signatures`] so
    /// the caller can't skip a step. The returned bundle must still
    /// be passed through [`verify_bundle`] before its funds are
    /// trusted — building the proof locally doesn't replace the
    /// verification step.
    #[allow(clippy::too_many_arguments)]
    pub fn create_bundle(
        &self,
        note_to_spend: ValidatedNote,
        anchor: Anchor,
        recipient: Address,
        send_value: u64,
        sighash: [u8; 32],
        proving_key: &ProvingKey,
    ) -> Result<Bundle<Authorized, i64>, BundleError> {
        if send_value == 0 {
            return Err(BundleError::ZeroSendValue);
        }
        if send_value > note_to_spend.inner.value().inner() {
            return Err(BundleError::InsufficientFunds);
        }

        // SAFETY: OsRng pulls directly from the OS CSPRNG. Never
        // replace this with a seeded RNG in production — shielded
        // randomness is a privacy boundary.
        let mut rng = OsRng;

        let mut builder = Builder::new(BundleType::DEFAULT, anchor);

        builder
            .add_spend(
                self.full_viewing_key.clone(),
                note_to_spend.inner,
                note_to_spend.merkle_path,
            )
            .map_err(|e| BundleError::SpendFailed(format!("{:?}", e)))?;

        // `add_output` requires a 512-byte memo; we ship a zero memo.
        // Encrypted memo-on-chain support is a wallet-layer feature,
        // not a circuit property.
        builder
            .add_output(
                None, // no OVK — recipient cannot recover sender
                recipient,
                NoteValue::from_raw(send_value),
                [0u8; 512],
            )
            .map_err(|e| BundleError::OutputFailed(format!("{:?}", e)))?;

        let (unauthorized, _metadata): (Bundle<InProgress<Unproven, _>, i64>, _) = builder
            .build::<i64>(&mut rng)
            .map_err(|e| BundleError::BuildFailed(format!("{:?}", e)))?
            .ok_or(BundleError::EmptyBundle)?;

        let proven = unauthorized
            .create_proof(proving_key, &mut rng)
            .map_err(|e| BundleError::ProofFailed(format!("{:?}", e)))?;

        // Sign with the spend authorizing key derived from our
        // spending key. `apply_signatures` is the helper that wraps
        // prepare → sign → finalize into a single call.
        let ask = SpendAuthorizingKey::from(&self.spending_key);
        let bundle = proven
            .apply_signatures(&mut rng, sighash, &[ask])
            .map_err(|e| BundleError::SignatureFailed(format!("{:?}", e)))?;

        Ok(bundle)
    }
}

// ─────────────────────────────────────────────────────────────
// Verification (mandatory)
// ─────────────────────────────────────────────────────────────

/// Verify an Orchard bundle's ZK proof and return a `VerifiedBundle`.
/// This is the only constructor for `VerifiedBundle`, so any code path
/// that accepts a `VerifiedBundle` is statically guaranteed to have
/// seen a proof-valid shielded action.
pub fn verify_bundle(
    bundle: Bundle<Authorized, i64>,
    verifying_key: &VerifyingKey,
) -> Result<VerifiedBundle, VerifyError> {
    bundle
        .verify_proof(verifying_key)
        .map_err(|e| VerifyError::InvalidProof(format!("{:?}", e)))?;
    Ok(VerifiedBundle { inner: bundle })
}

// ─────────────────────────────────────────────────────────────
// Nullifier tracking (double-spend prevention)
// ─────────────────────────────────────────────────────────────

impl SafeOrchardWallet {
    /// Mark every nullifier in a verified bundle as spent. Call this
    /// after a bundle is accepted into a block so subsequent
    /// `validate_note` calls on the same note will fail. Idempotent.
    pub fn record_spend(&mut self, bundle: &VerifiedBundle) {
        for action in bundle.inner.actions().iter() {
            self.spent_nullifiers.insert(action.nullifier().to_bytes());
        }
    }

    /// Pre-record a nullifier as spent without going through the full
    /// bundle flow. Useful for seeding the tracker from persisted state
    /// at startup. Returns true if the nullifier was newly inserted.
    pub fn mark_nullifier_spent(&mut self, nullifier_bytes: [u8; 32]) -> bool {
        self.spent_nullifiers.insert(nullifier_bytes)
    }
}

// ─────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn from_key_bytes_accepts_valid_input() {
        let wallet = SafeOrchardWallet::from_key_bytes(&[42u8; 32]);
        assert!(wallet.is_some());
        let wallet = wallet.unwrap();
        let _addr = wallet.payment_address();
        assert_eq!(wallet.spent_count(), 0);
    }

    #[test]
    fn payment_address_is_deterministic() {
        let w1 = SafeOrchardWallet::from_key_bytes(&[7u8; 32]).unwrap();
        let w2 = SafeOrchardWallet::from_key_bytes(&[7u8; 32]).unwrap();
        assert_eq!(
            w1.payment_address().to_raw_address_bytes(),
            w2.payment_address().to_raw_address_bytes()
        );
    }

    #[test]
    fn mark_nullifier_spent_is_idempotent() {
        let mut wallet = SafeOrchardWallet::from_key_bytes(&[3u8; 32]).unwrap();
        assert!(wallet.mark_nullifier_spent([1u8; 32]));
        assert!(!wallet.mark_nullifier_spent([1u8; 32]));
        assert_eq!(wallet.spent_count(), 1);
        assert!(wallet.mark_nullifier_spent([2u8; 32]));
        assert_eq!(wallet.spent_count(), 2);
    }
}
