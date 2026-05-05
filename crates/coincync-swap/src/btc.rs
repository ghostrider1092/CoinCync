//! Bitcoin-side primitives for the atomic swap.
//!
//! The BTC side of the swap is "the easy side" — Bitcoin's scripting
//! supports HTLC + adaptor-signature constructions natively, and there
//! is no privacy layer to preserve. The implementation here will build
//! and broadcast standard P2WPKH transactions whose unlock conditions
//! are the swap's adaptor-signed witness.
//!
//! ## Status: SKELETON
//!
//! The eventual implementation will pull in:
//! - `bitcoin` crate for transaction construction
//! - `secp256k1` for adaptor signatures
//! - An Electrum or Bitcoin-Core RPC client for chain watching
//!
//! Network choice (mainnet vs. testnet vs. regtest) is a CLI flag.
//! Tests will use regtest with a local `bitcoind` instance; CI will
//! mock the chain interface.

use crate::{Error, Result};

/// Configuration for Bitcoin-side operations. `network` will be a
/// real `bitcoin::Network` once the dep is added.
#[derive(Clone, Debug)]
pub struct BtcConfig {
    /// "mainnet" / "testnet" / "regtest".
    pub network: String,
    /// Address of the Electrum or Core RPC server.
    pub rpc_url: String,
}

/// Construct the Bitcoin lock transaction Bob will broadcast after
/// seeing Alice's CYNC lock confirmed. The unlock witness will be
/// either: (a) Alice's adaptor-decrypted signature (success path) or
/// (b) Bob's refund signature after the timeout (refund path).
pub fn build_lock_tx(
    _config: &BtcConfig,
    _amount_sats: u64,
    _alice_pub: &[u8],
    _bob_pub: &[u8],
    _timeout_blocks: u32,
) -> Result<Vec<u8>> {
    Err(Error::not_implemented("btc.build_lock_tx"))
}

/// Watch the BTC chain for a given txid + N confirmations, returning
/// when the threshold is reached or the timeout elapses. The eventual
/// implementation will subscribe to Electrum block notifications.
pub fn wait_for_confirmations(
    _config: &BtcConfig,
    _txid: &str,
    _confirmations: u32,
    _timeout_secs: u64,
) -> Result<()> {
    Err(Error::not_implemented("btc.wait_for_confirmations"))
}

/// Broadcast a signed transaction to the Bitcoin network. Returns
/// the txid on success.
pub fn broadcast(_config: &BtcConfig, _tx_bytes: &[u8]) -> Result<String> {
    Err(Error::not_implemented("btc.broadcast"))
}
