//! Typed errors for the Phase-2 Orchard skeleton.
//!
//! Same "load-bearing skeleton" pattern as `crates/coincync-swap`:
//! every public function returns [`Error::NotImplemented`] today, and
//! the `stage` field names the implementation step that will fill it
//! in. Callers can write error-handling code now and have it remain
//! valid against the shipped surface.

use thiserror::Error;

/// Top-level error type for the Orchard side.
#[derive(Debug, Error)]
pub enum Error {
    /// Returned by every public function until the corresponding
    /// stage is implemented. The `stage` field names which Orchard
    /// primitive is still skeleton, so future work has a clear
    /// `cargo grep` target.
    #[error("not implemented: stage `{stage}` is still skeleton — see crate-level docs")]
    NotImplemented {
        /// The implementation stage this call would belong to once
        /// shipped (e.g. "action.prove", "note.commit",
        /// "nullifier.derive").
        stage: &'static str,
    },

    /// Reserved: bridge boundary errors (already-validated inputs).
    /// We surface them at the orchard-side error type so the chain
    /// layer can match on a single error enum.
    #[error("bridge error: {0}")]
    Bridge(#[from] bridge::BridgeError),

    /// Reserved: proof verification rejected. The string names the
    /// constraint that failed (Halo2 gate label, lookup index, etc.)
    /// so a verifier failure has actionable diagnostic context.
    ///
    /// Carries an owned `String` so halo2's `Debug`-formatted error
    /// contexts (which include constraint indices + region names)
    /// can propagate without truncation.
    #[error("proof verification failed: {0}")]
    InvalidProof(String),

    /// Reserved: a serialized note / proof / action wire-format was
    /// rejected before any crypto check ran.
    #[error("malformed wire format: {0}")]
    MalformedWireFormat(&'static str),

    /// Reserved: the protocol detected a domain violation — e.g.
    /// a value commitment that doesn't balance, a nullifier that
    /// has already been seen, a Merkle anchor older than the
    /// per-network rollback window.
    #[error("domain rule violated: {0}")]
    DomainRule(&'static str),
}

impl Error {
    /// Convenience constructor for the common case.
    pub const fn not_implemented(stage: &'static str) -> Self {
        Self::NotImplemented { stage }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn not_implemented_carries_stage_name() {
        let e = Error::not_implemented("action.prove");
        let msg = format!("{e}");
        assert!(
            msg.contains("action.prove"),
            "stage name must appear in Display"
        );
    }

    #[test]
    fn bridge_error_conversion_works() {
        // The `#[from]` should let `?` lift a BridgeError into Error.
        // Sanity-check with a known constructor.
        fn lifts() -> Result<(), Error> {
            let _commit = bridge::BridgeCommitment::from_bytes([0u8; 32])?; // returns ZeroBytes
            Ok(())
        }
        assert!(matches!(lifts(), Err(Error::Bridge(_))));
    }
}
