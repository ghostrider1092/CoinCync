//! Consensus-rules fingerprint.
//!
//! A short digest of the chain-affecting consensus **parameters** — network
//! magic, genesis hash, and the hard-fork schedule — that two nodes must agree
//! on to stay on the same chain. Nodes advertise it in the P2P handshake (as a
//! capability-gated `ConsensusFingerprint` message, see
//! `network::firework::CAP_CONSENSUS_FINGERPRINT`), so a peer running divergent
//! consensus rules can be **detected early** — before it silently forks the
//! chain at a future activation height. This is ADVISORY: a mismatch is logged
//! and recorded on the peer, never an auto-disconnect (a staged upgrade must not
//! partition the network before the fork height it schedules).
//!
//! Why parameters and not source-file hashes: a chain-*compatible* change (e.g.
//! the C1 fork-validation bugfix, which edited `validation.rs` but left every
//! existing block valid) must NOT change the fingerprint, or every rolling
//! upgrade would light up as "divergent". Hashing the runtime-resolved rule
//! parameters — the things that actually decide block validity at a height —
//! flips the fingerprint exactly when consensus behavior changes (a fork height
//! moves, a checkpoint is added, the genesis differs) and not otherwise.
//!
//! See `docs/design/consensus-fingerprint.md`.

use crate::config::NetworkType;
use crate::primitives::{hash_domain, Hash};

/// Domain separator; bump the version suffix if the set of hashed parameters
/// changes (that is itself a fingerprint-format change, distinct from a
/// consensus-rule change).
pub const FINGERPRINT_DOMAIN: &[u8] = b"coincync/consensus-fingerprint/v1";

/// The runtime-resolved consensus parameters that define chain identity.
/// Kept explicit (rather than reading globals) so [`fingerprint_from_parts`]
/// is a pure function that tests can probe for sensitivity to each field.
pub struct FingerprintParts<'a> {
    pub magic: [u8; 4],
    pub genesis: Hash,
    pub fee_distribution_height: u64,
    pub min_output_age_hardfork_height: u64,
    pub rolling_finality_enable_height: u64,
    pub rolling_finality_enforce_height: u64,
    pub checkpoints: &'a [(u64, [u8; 32])],
}

/// Pure fingerprint over a canonical, unambiguous encoding of the parameters.
/// Fixed-width fields first, then the checkpoint list length-prefixed so its
/// boundary can never be confused with a following field.
pub fn fingerprint_from_parts(p: &FingerprintParts<'_>) -> Hash {
    let mut buf = Vec::with_capacity(4 + 32 + 8 * 4 + 8 + p.checkpoints.len() * 40);
    buf.extend_from_slice(&p.magic);
    buf.extend_from_slice(p.genesis.as_bytes());
    buf.extend_from_slice(&p.fee_distribution_height.to_le_bytes());
    buf.extend_from_slice(&p.min_output_age_hardfork_height.to_le_bytes());
    buf.extend_from_slice(&p.rolling_finality_enable_height.to_le_bytes());
    buf.extend_from_slice(&p.rolling_finality_enforce_height.to_le_bytes());
    buf.extend_from_slice(&(p.checkpoints.len() as u64).to_le_bytes());
    for (height, hash) in p.checkpoints {
        buf.extend_from_slice(&height.to_le_bytes());
        buf.extend_from_slice(hash);
    }
    hash_domain(FINGERPRINT_DOMAIN, &buf)
}

/// The consensus fingerprint for a given runtime network. Resolves every
/// parameter from the [`NetworkType`] accessors (the same source of truth the
/// validator uses), so it matches whatever rules this binary would actually
/// enforce.
pub fn consensus_fingerprint(network: NetworkType) -> Hash {
    let genesis = match network {
        NetworkType::Mainnet => crate::mainnet::expected_genesis_hash(),
        NetworkType::Testnet | NetworkType::Regtest => crate::testnet::expected_genesis_hash(),
    };
    // Resolved from the single canonical checkpoint source (#173), so the
    // fingerprint reflects exactly the checkpoints the validator enforces.
    let checkpoints = network.consensus_checkpoints();
    fingerprint_from_parts(&FingerprintParts {
        magic: network.magic_bytes(),
        genesis,
        fee_distribution_height: network.fee_distribution_height(),
        min_output_age_hardfork_height: network.min_output_age_hardfork_height(),
        rolling_finality_enable_height: network.rolling_finality_enable_height(),
        rolling_finality_enforce_height: network.rolling_finality_enforce_height(),
        checkpoints: &checkpoints,
    })
}

/// Convenience: the raw 32 bytes, for the wire message.
pub fn consensus_fingerprint_bytes(network: NetworkType) -> [u8; 32] {
    *consensus_fingerprint(network).as_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base_parts() -> FingerprintParts<'static> {
        FingerprintParts {
            magic: [1, 2, 3, 4],
            genesis: Hash::from_bytes([9u8; 32]),
            fee_distribution_height: 100,
            min_output_age_hardfork_height: 5000,
            rolling_finality_enable_height: 200,
            rolling_finality_enforce_height: 300,
            checkpoints: &[],
        }
    }

    #[test]
    fn fingerprint_is_deterministic() {
        assert_eq!(
            fingerprint_from_parts(&base_parts()),
            fingerprint_from_parts(&base_parts())
        );
    }

    #[test]
    fn changing_any_rule_parameter_changes_the_fingerprint() {
        let base = fingerprint_from_parts(&base_parts());

        let mut p = base_parts();
        p.magic = [4, 3, 2, 1];
        assert_ne!(fingerprint_from_parts(&p), base, "magic must matter");

        let mut p = base_parts();
        p.genesis = Hash::from_bytes([8u8; 32]);
        assert_ne!(fingerprint_from_parts(&p), base, "genesis must matter");

        let mut p = base_parts();
        p.min_output_age_hardfork_height = 6000;
        assert_ne!(fingerprint_from_parts(&p), base, "fork height must matter");

        let mut p = base_parts();
        p.rolling_finality_enforce_height = 301;
        assert_ne!(fingerprint_from_parts(&p), base, "finality height must matter");

        let cps: &[(u64, [u8; 32])] = &[(10, [7u8; 32])];
        let mut p = base_parts();
        p.checkpoints = cps;
        assert_ne!(fingerprint_from_parts(&p), base, "checkpoints must matter");
    }

    #[test]
    fn checkpoint_boundary_is_unambiguous() {
        // Two different (height, checkpoints) shapes must not collide. Guards
        // against a length-prefix-less encoding where a checkpoint height could
        // be absorbed into an adjacent field.
        let a: &[(u64, [u8; 32])] = &[(1, [0u8; 32])];
        let b: &[(u64, [u8; 32])] = &[];
        let mut pa = base_parts();
        pa.checkpoints = a;
        let mut pb = base_parts();
        pb.checkpoints = b;
        assert_ne!(fingerprint_from_parts(&pa), fingerprint_from_parts(&pb));
    }

    #[test]
    fn networks_have_distinct_fingerprints() {
        let t = consensus_fingerprint(NetworkType::Testnet);
        let m = consensus_fingerprint(NetworkType::Mainnet);
        assert_ne!(t, m, "testnet and mainnet must differ (magic + genesis)");
        // And stable across calls.
        assert_eq!(t, consensus_fingerprint(NetworkType::Testnet));
        assert_eq!(consensus_fingerprint_bytes(NetworkType::Testnet), *t.as_bytes());
    }
}
