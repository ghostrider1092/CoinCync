//! CoinCync-side primitives for the atomic swap.
//!
//! The CYNC side is "the hard side" — every transaction uses CLSAG
//! ring signatures, stealth addresses, and Pedersen commitments, and
//! the swap must preserve all of that privacy. A naive HTLC on CYNC
//! would leak the swap (the script-style condition would be visible
//! to anyone scanning the chain).
//!
//! The solution, per CIP-001, is the same one Monero uses: an
//! adaptor signature over the ring-signature scheme, where the
//! "lock" looks like an ordinary CYNC transaction to a chain
//! analyst. The privacy layer is not weakened by the swap — the
//! swap is invisible from outside.
//!
//! ## Status: SKELETON
//!
//! The eventual implementation will integrate with the parent
//! `coincync` crate's transaction builder (`coincync::transaction::*`)
//! and the consensus-side ring-signature primitives in
//! `coincync::crypto::clsag`. Same approach orchard-side took:
//! depend on the parent crate's audited primitives, never reimplement.

use crate::{Error, Result};

/// Configuration for CoinCync-side operations.
#[derive(Clone, Debug)]
pub struct CyncConfig {
    /// "mainnet" / "testnet" / "regtest".
    pub network: String,
    /// CoinCync daemon JSON-RPC endpoint (typically the user's own
    /// node; remote endpoints work but reveal the swap to whoever
    /// runs them).
    pub rpc_url: String,
    /// Optional bearer token if the RPC enforces auth.
    pub api_key: Option<String>,
}

/// Construct the CYNC lock transaction Alice will broadcast first.
/// The output is a stealth address whose spending key is bound to
/// the adaptor secret — when Alice claims Bob's BTC, the secret
/// becomes recoverable, allowing Bob to spend this output.
pub fn build_lock_tx(
    _config: &CyncConfig,
    _amount: u64,
    _alice_pub: &[u8],
    _bob_pub: &[u8],
    _timeout_blocks: u32,
) -> Result<Vec<u8>> {
    Err(Error::not_implemented("cync.build_lock_tx"))
}

/// Watch the CYNC chain for a given txid + N confirmations.
pub fn wait_for_confirmations(
    _config: &CyncConfig,
    _txid: &str,
    _confirmations: u32,
    _timeout_secs: u64,
) -> Result<()> {
    Err(Error::not_implemented("cync.wait_for_confirmations"))
}

/// Broadcast a signed CYNC transaction. Returns the txid on success.
pub fn broadcast(_config: &CyncConfig, _tx_bytes: &[u8]) -> Result<String> {
    Err(Error::not_implemented("cync.broadcast"))
}
