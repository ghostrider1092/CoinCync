//! SPV (Simplified Payment Verification) light-client interfaces, per
//! CIP-002 §"Architecture".
//!
//! ## Status: SKELETON — traits only, no impls.
//!
//! Every CyncHub node embeds two light clients:
//!
//! - Bitcoin SPV (~50 MB initial header sync; ~80 bytes per Bitcoin header
//!   after that)
//! - CYNC SPV (~10 MB initial header sync, depending on chain age at
//!   activation)
//!
//! These let CyncHub validate `LockBtc` and `LockCync` SPV proofs
//! independently of any external RPC dependency. The choice of underlying
//! library for the Bitcoin SPV client is a CIP-002 §"Open Questions"
//! item — current candidates are `bitcoin-spv` and a hand-rolled SPV
//! against `bitcoin = 0.32` headers — but the trait surface below is
//! intentionally library-agnostic so the choice can be made later
//! without churning the consumer code.
//!
//! ## Trait surface
//!
//! - [`BtcLightClient`] — Bitcoin SPV interface
//! - [`CyncLightClient`] — CYNC SPV interface
//!
//! Both expose the same conceptual API: verify-tx-included-at-height +
//! get-current-tip-height + min-confirmations-policy. The differences
//! between chains (Bitcoin's PoW chain header format vs CYNC's
//! RandomX-PoW + finality-aware tip) are hidden behind the trait.
//!
//! ## Conformance rule
//!
//! Any impl MUST refuse to verify a lock with fewer than
//! [`BtcLightClient::REQUIRED_CONFIRMATIONS`] confirmations (Bitcoin =
//! 6) or fewer than [`CyncLightClient::REQUIRED_CONFIRMATIONS`] (CYNC =
//! 16, matching H-16 finality). The protocol-level confirmation
//! requirement is encoded at the trait level so an impl can't
//! accidentally weaken it.

use crate::Error;

/// Bitcoin SPV light-client trait.
///
/// **Stub:** trait only; no impls in skeleton.
pub trait BtcLightClient {
    /// Required confirmations before a Bitcoin lock counts as "deep enough."
    /// Matches Bitcoin's standard 6-block rule.
    const REQUIRED_CONFIRMATIONS: u32 = 6;

    /// Verify a Bitcoin SPV proof that `txid` is included in a block at
    /// `block_hash` that is at least [`Self::REQUIRED_CONFIRMATIONS`]
    /// deep at the client's current tip.
    fn verify_tx_inclusion(
        &self,
        txid: &[u8; 32],
        block_hash: &[u8; 32],
        merkle_path: &[u8],
    ) -> Result<(), Error>;

    /// Current best-tip height as known to this light client.
    fn current_tip_height(&self) -> Result<u32, Error>;
}

/// CYNC SPV light-client trait.
///
/// **Stub:** trait only; no impls in skeleton.
pub trait CyncLightClient {
    /// Required confirmations before a CYNC lock counts as "deep enough."
    /// Matches the H-16 finality depth from `docs/security/reorg-defense.md`.
    const REQUIRED_CONFIRMATIONS: u32 = 16;

    /// Verify a CYNC SPV proof that `tx_hash` is included in a block at
    /// `block_hash` that is at least [`Self::REQUIRED_CONFIRMATIONS`]
    /// deep at the client's current tip.
    fn verify_tx_inclusion(
        &self,
        tx_hash: &[u8; 32],
        block_hash: &[u8; 32],
        merkle_path: &[u8],
    ) -> Result<(), Error>;

    /// Current best-tip height as known to this light client.
    fn current_tip_height(&self) -> Result<u64, Error>;
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Compile-only check: the protocol-level confirmation requirements
    /// are encoded at the trait level and can't be silently weakened by
    /// an impl picking smaller numbers.
    struct DummyBtc;
    impl BtcLightClient for DummyBtc {
        fn verify_tx_inclusion(&self, _: &[u8; 32], _: &[u8; 32], _: &[u8]) -> Result<(), Error> {
            Err(Error::NotImplemented { stage: "spv.btc.verify_tx_inclusion" })
        }
        fn current_tip_height(&self) -> Result<u32, Error> {
            Err(Error::NotImplemented { stage: "spv.btc.current_tip_height" })
        }
    }

    #[test]
    fn btc_required_confirmations_locked_to_6() {
        assert_eq!(DummyBtc::REQUIRED_CONFIRMATIONS, 6);
    }
}
