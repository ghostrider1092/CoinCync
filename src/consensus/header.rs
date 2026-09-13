//! # Block Header for CoinCync 1.0
//!
//! Simpler than 2.0: `anchor_stamp` and `stamps` were removed in the 1.0
//! trim. The stamping / anchor machinery is covered by IronConsensus on
//! the chain-convergence side and is no longer a header-level consensus
//! input.
//!
//! ## Audit map
//! Each `§` is a code element below; it states the INVARIANT it guarantees, the
//! THREAT it defends, and the TESTS that prove it. The overarching property is
//! **non-malleability**: once a valid PoW is found, no header field may be
//! altered while keeping the block valid — every field is bound either by
//! `hash()` (§2) or by the PoW anchor via `pow_binding()` (§5). (Renders in
//! `cargo doc`.)
//!
//! - **§1 `BlockHeader` fields** — INVARIANT: the field set is the complete
//!   consensus commitment; `network_magic` is FIRST so it is checked before any
//!   crypto. `supply_commitment` is RESERVED / not yet enforced (see field doc)
//!   — do not treat it as an integrity control until it is both validated and
//!   PoW-bound. THREAT: a silently-added/omitted field escaping the hash preimage.
//!   TESTS: covered structurally by §2/§5 below.
//! - **§2 `hash` (field malleability)** — INVARIANT: EVERY field feeds the
//!   preimage, so mutating any one changes the hash. A field omitted from the
//!   preimage would be malleable after a valid PoW is found.
//!   THREAT: header-hash malleability / post-PoW field grinding.
//!   TESTS: `hash_changes_on_every_field_mutation`.
//! - **§3 `hash` (Option + Phase-2 encoding / determinism)** — INVARIANT:
//!   `checkpoint_vote` is length-tagged so `Some` vs `None` and two distinct
//!   `Some` values never collide; `spark_set_root` / `mw_kernel_root` are hashed
//!   unconditionally (zero pre-fork); repeated calls are deterministic.
//!   THREAT: ambiguous serialization letting two headers share a hash.
//!   TESTS: `hash_distinguishes_checkpoint_vote_variants`, `hash_is_deterministic`.
//! - **§4 domain tags (`HEADER_HASH_DOMAIN_TAG` / `POW_BINDING_DOMAIN_TAG`)** —
//!   INVARIANT: each preimage is prefixed with a distinct domain tag, so the
//!   header hash can never collide with the PoW binding (or any other protocol
//!   digest — tx signing, anchor, CLSAG, bulletproof). THREAT: cross-protocol
//!   hash collision / preimage reuse. TESTS: `hash_never_equals_pow_binding`.
//! - **§5 `pow_binding`** — INVARIANT: covers EXACTLY the fields not otherwise
//!   bound by the PoW (version, miner_pubkey, supply_commitment, checkpoint_vote,
//!   spark/mw roots) and EXCLUDES those already bound (nonce/tx_root via
//!   `compute_pow_hash`; prev_hash/height/timestamp via the anchor seed;
//!   target/algorithm via direct `verify_pow` checks; anchor itself to avoid
//!   circularity). THREAT: audit §1 — reusing one PoW solution with an unbound
//!   field mutated (block-hash malleability + tie-break grinding).
//!   TESTS: `pow_binding_covers_exactly_the_otherwise_unbound_fields`.
//! - **§6 `meets_target`** — INVARIANT: delegates to `Hash::meets_difficulty`;
//!   `pow_hash <= target` passes (equality is the inclusive boundary),
//!   strictly-greater fails. THREAT: off-by-one at the target boundary
//!   accepting/rejecting a block wrongly. TESTS: `meets_target_boundary_semantics`.

use crate::primitives::{hash_concat, Hash, PublicKey};
use borsh::{BorshDeserialize, BorshSerialize};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize, BorshSerialize, BorshDeserialize)]
pub struct BlockHeader {
    /// Network magic bytes — FIRST field, checked before any crypto validation.
    pub network_magic: [u8; 4],
    pub version: u8,
    pub height: u64,
    pub timestamp: u64,
    pub prev_hash: Hash,
    pub tx_root: Hash,
    pub anchor: Hash,
    pub algorithm: u8,
    pub nonce: u64,
    pub target: Hash,
    pub miner_pubkey: PublicKey,
    /// RESERVED / NOT YET ENFORCED (audit 2026-09-07). `calculate_supply_commitment`
    /// exists but no consensus rule compares this field to it, and every producer
    /// currently sets it to `[0u8; 32]`. Do NOT rely on it as an integrity control
    /// until it is both enforced in validation AND bound by PoW (see the §1 PoW
    /// header-binding change in `docs/SECURITY-REVIEW-2026-09-07.md`).
    pub supply_commitment: [u8; 32],
    pub checkpoint_vote: Option<(u64, Hash)>,

    /// Lelantus Spark accumulator root (Phase 2).
    /// Zero until the Lelantus Spark fork activates. Included in the header
    /// hash so every block commits to the current Spark set.
    pub spark_set_root: [u8; 32],

    /// MimbleWimble kernel-set root (Phase 2).
    /// Zero until the MW cut-through fork activates. Included in the header
    /// hash so every block commits to the current kernel set.
    pub mw_kernel_root: [u8; 32],
}

/// Domain-separation tag for the block header hash preimage. Prefixed to
/// every byte sequence fed into `hash_concat` for header hashing so this
/// hash can never collide with any other preimage in the protocol
/// (tx signing, pow anchor, CLSAG Fiat-Shamir, bulletproof transcript,
/// balance proof).
pub(crate) const HEADER_HASH_DOMAIN_TAG: &[u8] = b"coincync/header/v1";

/// Domain-separation tag for the PoW header-binding digest (see
/// [`BlockHeader::pow_binding`]).
pub(crate) const POW_BINDING_DOMAIN_TAG: &[u8] = b"coincync/pow-binding/v1";

impl BlockHeader {
    /// Compute block header hash.
    ///
    /// SECURITY: All fields are included to prevent block malleability where a
    /// miner could modify omitted fields after finding a valid PoW hash. The
    /// preimage is domain-separated with [`HEADER_HASH_DOMAIN_TAG`] so it can
    /// never collide with any other hash in the protocol.
    pub fn hash(&self) -> Hash {
        let mut data = Vec::with_capacity(HEADER_HASH_DOMAIN_TAG.len() + 256);
        // Domain separator — must be first.
        data.extend_from_slice(HEADER_HASH_DOMAIN_TAG);
        // Network magic is hashed next — binds every block to its network.
        data.extend_from_slice(&self.network_magic);
        data.push(self.version);
        data.extend_from_slice(&self.height.to_le_bytes());
        data.extend_from_slice(&self.timestamp.to_le_bytes());
        data.extend_from_slice(self.prev_hash.as_bytes());
        data.extend_from_slice(self.tx_root.as_bytes());
        data.extend_from_slice(self.anchor.as_bytes());
        data.push(self.algorithm);
        data.extend_from_slice(&self.nonce.to_le_bytes());
        data.extend_from_slice(self.target.as_bytes());
        data.extend_from_slice(self.miner_pubkey.as_bytes());
        data.extend_from_slice(&self.supply_commitment);
        // Serialize checkpoint_vote deterministically (Some/None distinct).
        match &self.checkpoint_vote {
            Some((height, hash)) => {
                data.push(1);
                data.extend_from_slice(&height.to_le_bytes());
                data.extend_from_slice(hash.as_bytes());
            }
            None => {
                data.push(0);
            }
        }
        // Phase 2 roots (Lelantus Spark + MimbleWimble). Hashed unconditionally
        // — zero bytes pre-activation, real roots after the forks activate.
        data.extend_from_slice(&self.spark_set_root);
        data.extend_from_slice(&self.mw_kernel_root);
        hash_concat(&[&data])
    }

    /// Digest of the header fields that are otherwise **not** committed to by the
    /// proof of work, so they can be folded into the anchor seed and thereby
    /// bound to the PoW (audit §1, 2026-09-07). Without this, a single PoW
    /// solution could be reused with these fields mutated (block-hash
    /// malleability + tie-break grinding).
    ///
    /// Excluded because they are already bound elsewhere: `prev_hash`, `height`,
    /// `timestamp` (anchor seed); `nonce`, `tx_root` (`compute_pow_hash` input);
    /// `target`, `algorithm` (checked directly in `verify_pow`); `network_magic`
    /// (checked before any PoW work). `anchor` itself is excluded to avoid
    /// circularity (the anchor is derived FROM this binding).
    pub fn pow_binding(&self) -> Hash {
        let mut data = Vec::with_capacity(POW_BINDING_DOMAIN_TAG.len() + 160);
        data.extend_from_slice(POW_BINDING_DOMAIN_TAG);
        data.push(self.version);
        data.extend_from_slice(self.miner_pubkey.as_bytes());
        data.extend_from_slice(&self.supply_commitment);
        match &self.checkpoint_vote {
            Some((height, hash)) => {
                data.push(1);
                data.extend_from_slice(&height.to_le_bytes());
                data.extend_from_slice(hash.as_bytes());
            }
            None => data.push(0),
        }
        data.extend_from_slice(&self.spark_set_root);
        data.extend_from_slice(&self.mw_kernel_root);
        hash_concat(&[&data])
    }

    pub fn meets_target(&self, pow_hash: &Hash) -> bool {
        pow_hash.meets_difficulty(&self.target)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::primitives::PublicKey;

    fn sample_header() -> BlockHeader {
        BlockHeader {
            network_magic: [1, 2, 3, 4],
            version: 1,
            height: 42,
            timestamp: 1_700_000_000,
            prev_hash: Hash::from_bytes([7u8; 32]),
            tx_root: Hash::from_bytes([8u8; 32]),
            anchor: Hash::from_bytes([9u8; 32]),
            algorithm: 0,
            nonce: 123,
            target: Hash::from_bytes([0xFF; 32]),
            miner_pubkey: PublicKey::from_bytes([5u8; 32]),
            supply_commitment: [0u8; 32],
            checkpoint_vote: None,
            spark_set_root: [0u8; 32],
            mw_kernel_root: [0u8; 32],
        }
    }

    /// audit §1: the PoW header-binding must cover EVERY field that isn't already
    /// bound by the anchor seed / `compute_pow_hash` / direct checks — otherwise
    /// that field is malleable while keeping a valid PoW. And it must NOT cover
    /// the fields bound elsewhere (double-binding / anchor circularity).
    #[test]
    fn pow_binding_covers_exactly_the_otherwise_unbound_fields() {
        let base = sample_header();
        let b0 = base.pow_binding();

        // Each currently-unbound field MUST change the binding.
        let mut h = base.clone();
        h.version ^= 1;
        assert_ne!(b0, h.pow_binding(), "version must be bound");
        let mut h = base.clone();
        h.miner_pubkey = PublicKey::from_bytes([6u8; 32]);
        assert_ne!(b0, h.pow_binding(), "miner_pubkey must be bound");
        let mut h = base.clone();
        h.supply_commitment = [1u8; 32];
        assert_ne!(b0, h.pow_binding(), "supply_commitment must be bound");
        let mut h = base.clone();
        h.checkpoint_vote = Some((1, Hash::from_bytes([2u8; 32])));
        assert_ne!(b0, h.pow_binding(), "checkpoint_vote must be bound");
        let mut h = base.clone();
        h.spark_set_root = [3u8; 32];
        assert_ne!(b0, h.pow_binding(), "spark_set_root must be bound");
        let mut h = base.clone();
        h.mw_kernel_root = [4u8; 32];
        assert_ne!(b0, h.pow_binding(), "mw_kernel_root must be bound");

        // Fields bound elsewhere MUST NOT change the binding.
        let mut h = base.clone();
        h.nonce = 999;
        assert_eq!(b0, h.pow_binding(), "nonce is bound via compute_pow_hash");
        let mut h = base.clone();
        h.tx_root = Hash::from_bytes([0xCD; 32]);
        assert_eq!(b0, h.pow_binding(), "tx_root is bound via compute_pow_hash");
        let mut h = base.clone();
        h.anchor = Hash::from_bytes([0xAB; 32]);
        assert_eq!(b0, h.pow_binding(), "anchor is DERIVED from the binding");
        let mut h = base.clone();
        h.target = Hash::from_bytes([0x01; 32]);
        assert_eq!(b0, h.pow_binding(), "target is checked directly in verify_pow");
    }

    /// Malleability guard: EVERY header field must feed the hash preimage, so
    /// mutating any one of them changes `hash()`. A field omitted from the
    /// preimage would be malleable after a valid PoW is found.
    #[test]
    fn hash_changes_on_every_field_mutation() {
        let base = sample_header();
        let h0 = base.hash();

        macro_rules! assert_field_bound {
            ($field:literal, $mutate:expr) => {{
                let mut h = base.clone();
                let mutate: fn(&mut BlockHeader) = $mutate;
                mutate(&mut h);
                assert_ne!(h0, h.hash(), concat!($field, " must be bound in hash()"));
            }};
        }

        assert_field_bound!("network_magic", |h| h.network_magic = [9, 9, 9, 9]);
        assert_field_bound!("version", |h| h.version ^= 1);
        assert_field_bound!("height", |h| h.height ^= 1);
        assert_field_bound!("timestamp", |h| h.timestamp ^= 1);
        assert_field_bound!("prev_hash", |h| h.prev_hash = Hash::from_bytes([0x11; 32]));
        assert_field_bound!("tx_root", |h| h.tx_root = Hash::from_bytes([0x22; 32]));
        assert_field_bound!("anchor", |h| h.anchor = Hash::from_bytes([0x33; 32]));
        assert_field_bound!("algorithm", |h| h.algorithm ^= 1);
        assert_field_bound!("nonce", |h| h.nonce ^= 1);
        assert_field_bound!("target", |h| h.target = Hash::from_bytes([0x44; 32]));
        assert_field_bound!("miner_pubkey", |h| h.miner_pubkey =
            PublicKey::from_bytes([0x55; 32]));
        assert_field_bound!("supply_commitment", |h| h.supply_commitment = [0x66; 32]);
        assert_field_bound!("spark_set_root", |h| h.spark_set_root = [0x77; 32]);
        assert_field_bound!("mw_kernel_root", |h| h.mw_kernel_root = [0x88; 32]);
    }

    /// checkpoint_vote Some vs None must produce distinct hashes, and two
    /// different Some values must also differ (the option is serialized
    /// unambiguously into the preimage).
    #[test]
    fn hash_distinguishes_checkpoint_vote_variants() {
        let none = sample_header();
        assert!(none.checkpoint_vote.is_none());
        let h_none = none.hash();

        let mut some_a = sample_header();
        some_a.checkpoint_vote = Some((10, Hash::from_bytes([0xA1; 32])));
        let h_a = some_a.hash();

        let mut some_b = sample_header();
        some_b.checkpoint_vote = Some((11, Hash::from_bytes([0xB2; 32])));
        let h_b = some_b.hash();

        assert_ne!(h_none, h_a, "Some vs None must differ");
        assert_ne!(h_a, h_b, "two distinct Some values must differ");
    }

    /// The header hash is domain-separated (`HEADER_HASH_DOMAIN_TAG`) while the
    /// PoW binding uses `POW_BINDING_DOMAIN_TAG`, so the two digests can never
    /// coincide for the same header.
    #[test]
    fn hash_never_equals_pow_binding() {
        let h = sample_header();
        assert_ne!(h.hash(), h.pow_binding());
    }

    /// Determinism: repeated calls on an unchanged header return the same hash.
    #[test]
    fn hash_is_deterministic() {
        let h = sample_header();
        assert_eq!(h.hash(), h.hash());
        let clone = h.clone();
        assert_eq!(h.hash(), clone.hash());
    }

    /// `meets_target` follows `Hash::meets_difficulty`: pow_hash <= target
    /// passes (equality is the inclusive boundary), strictly-greater fails.
    #[test]
    fn meets_target_boundary_semantics() {
        let mut h = sample_header();
        h.target = Hash::from_bytes([0x80; 32]);

        // Strictly below target → passes.
        let below = {
            let mut b = [0x80u8; 32];
            b[0] = 0x7F;
            Hash::from_bytes(b)
        };
        assert!(h.meets_target(&below), "pow_hash < target must pass");

        // Exactly equal → passes (inclusive boundary).
        let equal = Hash::from_bytes([0x80; 32]);
        assert!(h.meets_target(&equal), "pow_hash == target must pass");

        // Strictly above target → fails.
        let above = {
            let mut a = [0x00u8; 32];
            a[0] = 0x81;
            Hash::from_bytes(a)
        };
        assert!(!h.meets_target(&above), "pow_hash > target must fail");
    }
}
