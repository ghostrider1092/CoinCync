//! Peer-to-peer coordination between Alice and Bob during the swap.
//!
//! The atomic-swap protocol requires several rounds of off-chain
//! message exchange before either party commits anything to a
//! blockchain. Both parties need to agree on parameters, exchange
//! adaptor public keys, exchange cross-curve DL-equality proofs, and
//! coordinate the ordered chain operations.
//!
//! ## Status: SKELETON
//!
//! Transport choice (Tor onion service, libp2p, plain TCP+Noise) is
//! deliberately deferred to CIP-001. The minimal viable transport is
//! plain TCP+Noise (already in CoinCync's network stack); a Tor onion
//! service would be the privacy-preserving production default.
//!
//! The eventual implementation will provide an async coordinator
//! session that drives the swap state machine in response to peer
//! messages and chain events.

use crate::{Error, Result};

/// One side of an active coordination session.
#[derive(Debug)]
pub struct Coordinator {
    #[allow(dead_code)]
    pub(crate) endpoint: String,
}

impl Coordinator {
    /// Begin listening as Alice. Bob will connect with a swap-id.
    pub fn listen(_endpoint: &str) -> Result<Self> {
        Err(Error::not_implemented("coordinator.listen"))
    }

    /// Connect to Alice's listening endpoint as Bob.
    pub fn connect(_endpoint: &str, _swap_id: &str) -> Result<Self> {
        Err(Error::not_implemented("coordinator.connect"))
    }

    /// Run one round of the negotiation handshake. Returns when both
    /// sides have agreed on parameters or the round fails.
    pub fn handshake(&mut self) -> Result<()> {
        Err(Error::not_implemented("coordinator.handshake"))
    }
}
