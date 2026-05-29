//! Namecoin-style auxiliary-PoW merge-mining commitment, per CIP-002
//! §"Mechanism — Merge-Mining".
//!
//! ## Status: SKELETON
//!
//! ## Commitment layout
//!
//! A CYNC miner adds an `OP_RETURN`-equivalent output to their coinbase
//! containing:
//!
//! ```text
//! [4-byte magic: 0x43484342 ("CHCB")] [32-byte CyncHub block hash]
//! ```
//!
//! When the CYNC block satisfies CYNC's PoW difficulty, the CyncHub
//! block referenced in the commitment is **also** considered "found."
//! Its PoW proof consists of:
//!
//! 1. The CYNC block header (which satisfies CYNC's difficulty by
//!    construction)
//! 2. The Merkle path from the coinbase commitment to the CYNC block's
//!    transaction Merkle root
//! 3. The CyncHub block itself
//!
//! CyncHub miners forfeit fee revenue if their CYNC blocks don't include
//! a CyncHub commitment, so the reference miner (`coincync-rig`)
//! includes it by default.
//!
//! ## Strict-vs-relaxed validation
//!
//! With the `mergemining-strict` cargo feature off (default), validators
//! accept a CHCB commitment anywhere in the coinbase scriptSig. With
//! the feature on, validators require the commitment to be in the
//! canonical first position. The strict mode defends against accidental
//! dual-commitment ambiguity if a CYNC miner ever attempts to commit to
//! two CyncHub blocks in one CYNC block. See `Cargo.toml` `[features]`
//! for the operational rationale.

use crate::Error;

/// Magic prefix identifying a CyncHub merge-mining commitment in a
/// CYNC coinbase tx output. ASCII "CHCB" in big-endian byte order.
pub const COMMITMENT_MAGIC: [u8; 4] = [b'C', b'H', b'C', b'B'];

/// Total commitment length: 4-byte magic + 32-byte CyncHub block hash.
pub const COMMITMENT_LEN: usize = 4 + 32;

/// A parsed merge-mining commitment.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Commitment {
    /// The 32-byte CyncHub block hash this commitment pins.
    pub cynchub_block_hash: [u8; 32],
}

/// Parse a merge-mining commitment from raw coinbase output bytes.
///
/// Expects exactly `COMMITMENT_LEN` bytes starting with [`COMMITMENT_MAGIC`].
///
/// **Stub:** returns [`Error::NotImplemented`].
pub fn parse_commitment(_coinbase_output: &[u8]) -> Result<Commitment, Error> {
    Err(Error::NotImplemented { stage: "mergemining.parse_commitment" })
}

/// Verify a parsed commitment is valid for a given CyncHub block:
///
/// - The CYNC block's coinbase tx contains the expected commitment bytes
/// - The Merkle path connects the commitment to the CYNC block's tx Merkle root
/// - (With `mergemining-strict`:) the commitment is in the canonical position
///
/// **Stub:** returns [`Error::NotImplemented`].
pub fn verify_commitment(
    _commitment: &Commitment,
    _cync_block_header: &[u8],
    _merkle_path: &[u8],
) -> Result<(), Error> {
    Err(Error::NotImplemented { stage: "mergemining.verify_commitment" })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn magic_is_ascii_chcb() {
        assert_eq!(&COMMITMENT_MAGIC, b"CHCB");
        assert_eq!(COMMITMENT_LEN, 36);
    }

    #[test]
    fn parse_is_unimplemented_in_skeleton() {
        let err = parse_commitment(&[0u8; COMMITMENT_LEN]).unwrap_err();
        assert!(matches!(err, Error::NotImplemented { stage: "mergemining.parse_commitment" }));
    }
}
