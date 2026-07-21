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
//! ## Status: chain RPC shipped (2026-05-17 slice, symmetric to BTC).
//!
//! What lands in this file:
//! - [`CyncChain`] async trait — abstract interface (broadcast,
//!   wait_for_confirmations, get_block_count). Same shape as
//!   [`crate::btc::BtcChain`] so the swap state machine can be
//!   generic over which side it's talking to.
//! - [`CyncNodeRpc`] — JSON-RPC client targeting the existing
//!   `coincync-node` RPC server (`src/rpc/server.rs`). Uses the
//!   `send_raw_transaction` + `get_transaction` + `get_blockchain_info`
//!   methods that already ship in v1.0.8-testnet.
//! - [`MockCyncChain`] — in-memory implementation for unit tests.
//! - [`build_lock_tx`] remains stubbed pending the protocol
//!   integration with `coincync::transaction::Builder` and the
//!   CLSAG ring-binding for the adaptor — that's the next CYNC slice.
//!
//! ## RPC differences vs. Bitcoin Core
//!
//! - `send_raw_transaction` returns `{"accepted": bool, "hash": hex}`,
//!   not a bare txid string. We parse `hash`.
//! - `get_transaction` returns `block_height` (the height of the block
//!   that contains the tx) rather than a `confirmations` field. The
//!   client computes `confirmations = tip - block_height + 1` from a
//!   second call to `get_blockchain_info`.
//! - An unconfirmed (mempool) tx surfaces as an RPC error from
//!   `get_transaction`; we treat that as "confirmations = 0" and
//!   keep polling rather than failing.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use tokio::time::sleep;

use crate::{Error, Result};

// ── Public types ─────────────────────────────────────────────────────

/// Configuration for CoinCync-side operations.
#[derive(Clone, Debug)]
pub struct CyncConfig {
    /// `"mainnet"` / `"testnet"` / `"regtest"`.
    pub network: String,
    /// CoinCync daemon JSON-RPC endpoint — e.g.
    /// `"http://127.0.0.1:28085"` (testnet RPC default).
    /// Remote endpoints work but reveal the swap to whoever runs
    /// them; users running atomic swaps should target their own node.
    pub rpc_url: String,
    /// Optional bearer token if the RPC enforces auth. Sent as the
    /// `Authorization: Bearer <token>` header.
    pub api_key: Option<String>,
}

/// 32-byte CoinCync transaction id. Wrapped so it can't be mixed up
/// with a Bitcoin txid or an arbitrary `[u8; 32]`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct CyncTxid(pub [u8; 32]);

impl CyncTxid {
    /// Parse from a 64-character lowercase hex string. CYNC's RPC
    /// surface returns txids in the natural byte order (NOT reversed
    /// like Bitcoin Core does).
    pub fn from_hex(s: &str) -> Result<Self> {
        let trimmed = s.trim_start_matches("0x");
        let mut bytes = [0u8; 32];
        hex::decode_to_slice(trimmed, &mut bytes)
            .map_err(|_| Error::Verification("invalid CYNC txid hex"))?;
        Ok(Self(bytes))
    }

    /// Render as 64-character lowercase hex.
    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }
}

// ── CyncChain trait ──────────────────────────────────────────────────

/// Abstract CoinCync-chain interface. Implemented by the real
/// `coincync-node` RPC client and by the in-memory mock used in
/// tests. Mirrors [`crate::btc::BtcChain`] so the swap state machine
/// can be tested against either side using the same patterns.
#[async_trait]
pub trait CyncChain: Send + Sync {
    /// Broadcast a borsh-serialized CYNC transaction. `tx_hex` is the
    /// borsh bytes in lowercase hex (the format `send_raw_transaction`
    /// expects). Returns the txid on success; the chain may still
    /// reject the tx if mempool admission fails — that surfaces as
    /// `Error::Rpc`.
    async fn broadcast(&self, tx_hex: &str) -> Result<CyncTxid>;

    /// Block until `txid` has at least `min_confirmations` blocks on
    /// top of it, or `timeout` elapses. Returns `Err(Timeout)` on
    /// timeout, `Ok(())` on success.
    async fn wait_for_confirmations(
        &self,
        txid: &CyncTxid,
        min_confirmations: u32,
        timeout: Duration,
    ) -> Result<()>;

    /// Current chain tip height. Used to derive timeout heights from
    /// a known reference at swap-setup time.
    async fn get_block_count(&self) -> Result<u64>;
}

// ── Real CoinCync node JSON-RPC client ───────────────────────────────

/// Async JSON-RPC client for `coincync-node`.
#[derive(Clone, Debug)]
pub struct CyncNodeRpc {
    config: CyncConfig,
    http: reqwest::Client,
    poll_interval: Duration,
}

impl CyncNodeRpc {
    pub fn new(config: CyncConfig) -> Result<Self> {
        if !matches!(config.network.as_str(), "mainnet" | "testnet" | "regtest") {
            return Err(Error::Verification(
                "CyncConfig.network must be one of mainnet/testnet/regtest",
            ));
        }
        if reqwest::Url::parse(&config.rpc_url).is_err() {
            return Err(Error::Verification(
                "CyncConfig.rpc_url must be a valid URL",
            ));
        }
        let http = reqwest::Client::builder()
            .connect_timeout(Duration::from_secs(30))
            .timeout(Duration::from_secs(60))
            .build()
            .map_err(|e| Error::Rpc(format!("reqwest client build: {}", e)))?;
        Ok(Self {
            config,
            http,
            // CYNC blocks target ~120s, so a 10s poll is plenty.
            poll_interval: Duration::from_secs(10),
        })
    }

    /// Override the confirmation-poll interval.
    pub fn with_poll_interval(mut self, interval: Duration) -> Self {
        self.poll_interval = interval;
        self
    }

    async fn call<T: for<'de> Deserialize<'de>>(
        &self,
        method: &str,
        params: serde_json::Value,
    ) -> Result<T> {
        let body = JsonRpcRequest {
            jsonrpc: "2.0",
            id: "coincync-swap",
            method,
            params,
        };

        let mut req = self.http.post(&self.config.rpc_url).json(&body);
        if let Some(key) = &self.config.api_key {
            req = req.bearer_auth(key);
        }

        let resp = req
            .send()
            .await
            .map_err(|e| Error::Rpc(format!("RPC HTTP: {}", e)))?;
        let status = resp.status();
        let body: JsonRpcResponse<T> = resp
            .json()
            .await
            .map_err(|e| Error::Rpc(format!("RPC JSON decode: {}", e)))?;

        if let Some(err) = body.error {
            return Err(Error::Rpc(format!(
                "coincync-node {} returned code {}: {}",
                method, err.code, err.message
            )));
        }
        body.result.ok_or_else(|| {
            Error::Rpc(format!(
                "coincync-node {} returned no result (status {})",
                method, status
            ))
        })
    }

    /// Internal: try one `get_transaction` lookup, returning the
    /// block_height of the containing block (or `None` if not yet
    /// confirmed).
    async fn try_get_block_height(&self, txid: &CyncTxid) -> Option<u64> {
        let txid_hex = txid.to_hex();
        let info: serde_json::Value = match self
            .call("get_transaction", serde_json::json!([txid_hex]))
            .await
        {
            Ok(v) => v,
            Err(_) => return None,
        };
        info.get("block_height").and_then(|v| v.as_u64())
    }

    /// Internal: fetch the current tip height from `get_blockchain_info`.
    async fn current_tip(&self) -> Result<u64> {
        let info: serde_json::Value = self
            .call("get_blockchain_info", serde_json::json!([]))
            .await?;
        info.get("height")
            .and_then(|v| v.as_u64())
            .ok_or_else(|| Error::Rpc("get_blockchain_info missing 'height' field".into()))
    }
}

#[async_trait]
impl CyncChain for CyncNodeRpc {
    async fn broadcast(&self, tx_hex: &str) -> Result<CyncTxid> {
        // CYNC's send_raw_transaction returns `{"accepted": bool, "hash": hex}`.
        let resp: serde_json::Value = self
            .call("send_raw_transaction", serde_json::json!([tx_hex]))
            .await?;
        let accepted = resp
            .get("accepted")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        if !accepted {
            return Err(Error::Rpc("coincync-node rejected the tx".into()));
        }
        let hash_hex = resp
            .get("hash")
            .and_then(|v| v.as_str())
            .ok_or_else(|| Error::Rpc("send_raw_transaction missing 'hash' field".into()))?;
        CyncTxid::from_hex(hash_hex)
    }

    async fn wait_for_confirmations(
        &self,
        txid: &CyncTxid,
        min_confirmations: u32,
        timeout: Duration,
    ) -> Result<()> {
        let deadline = Instant::now() + timeout;
        loop {
            if let Some(block_height) = self.try_get_block_height(txid).await {
                // Confirmed at block_height; how deep?
                if let Ok(tip) = self.current_tip().await {
                    if tip >= block_height {
                        let confirmations = (tip - block_height + 1) as u32;
                        if confirmations >= min_confirmations {
                            return Ok(());
                        }
                    }
                }
            }
            if Instant::now() >= deadline {
                return Err(Error::Timeout {
                    stage: "cync.wait_for_confirmations",
                });
            }
            sleep(self.poll_interval).await;
        }
    }

    async fn get_block_count(&self) -> Result<u64> {
        self.current_tip().await
    }
}

// ── JSON-RPC wire types ──────────────────────────────────────────────

#[derive(Serialize)]
struct JsonRpcRequest<'a> {
    jsonrpc: &'a str,
    id: &'a str,
    method: &'a str,
    params: serde_json::Value,
}

#[derive(Deserialize)]
struct JsonRpcResponse<T> {
    result: Option<T>,
    error: Option<JsonRpcError>,
}

#[derive(Deserialize, Debug)]
struct JsonRpcError {
    code: i64,
    message: String,
}

// ── Mock implementation for tests ────────────────────────────────────

/// In-memory `CyncChain` implementation used by unit tests. Models a
/// regtest-like environment with deterministic txid derivation.
#[derive(Default)]
pub struct MockCyncChain {
    inner: Mutex<MockInner>,
}

#[derive(Default)]
struct MockInner {
    /// txid -> the chain height at which the tx was included.
    tx_block_height: HashMap<CyncTxid, u64>,
    /// Pretend tip height.
    tip: u64,
}

impl MockCyncChain {
    pub fn new() -> Self {
        Self::default()
    }

    /// Mine `n` blocks (advance the tip by `n`). Already-included txs
    /// keep their inclusion height; their confirmation depth grows.
    pub fn mine_blocks(&self, n: u32) {
        let mut g = self.inner.lock().unwrap();
        g.tip = g.tip.saturating_add(n as u64);
    }

    fn deterministic_txid(tx_hex: &str) -> CyncTxid {
        use sha2::{Digest, Sha256};
        let mut h = Sha256::new();
        // Domain-separate from the BTC mock so a stray collision
        // between the two test surfaces is impossible.
        h.update(b"CoinCync/MockCyncChain/Txid-v1");
        h.update(tx_hex.as_bytes());
        CyncTxid(h.finalize().into())
    }
}

#[async_trait]
impl CyncChain for MockCyncChain {
    async fn broadcast(&self, tx_hex: &str) -> Result<CyncTxid> {
        let txid = Self::deterministic_txid(tx_hex);
        let mut g = self.inner.lock().unwrap();
        // Mempool-only at first; mine_blocks promotes it.
        // Use the *next* block height as the inclusion height — i.e.
        // the broadcast is "in mempool, will land in the next block".
        let next_block = g.tip + 1;
        g.tx_block_height.entry(txid).or_insert(next_block);
        Ok(txid)
    }

    async fn wait_for_confirmations(
        &self,
        txid: &CyncTxid,
        min_confirmations: u32,
        timeout: Duration,
    ) -> Result<()> {
        let deadline = Instant::now() + timeout;
        loop {
            let depth = {
                let g = self.inner.lock().unwrap();
                match g.tx_block_height.get(txid).copied() {
                    Some(h) if g.tip >= h => Some((g.tip - h + 1) as u32),
                    Some(_) => Some(0), // included next block, but tip hasn't reached
                    None => None,
                }
            };
            if let Some(d) = depth {
                if d >= min_confirmations {
                    return Ok(());
                }
            }
            if Instant::now() >= deadline {
                return Err(Error::Timeout {
                    stage: "mock.wait_for_confirmations",
                });
            }
            sleep(Duration::from_millis(10)).await;
        }
    }

    async fn get_block_count(&self) -> Result<u64> {
        let g = self.inner.lock().unwrap();
        Ok(g.tip)
    }
}

// ── Swap key-derivation helpers ──────────────────────────────────────
//
// The CYNC half of the swap reuses the existing wallet's transaction
// builder — there is no swap-specific transaction encoding. What the
// swap protocol DOES need is two key-derivation helpers that bind
// the CYNC recipient/spender keys to the cross-curve adaptor secret:
//
//   [`derive_swap_recipient_spend_pub`] — given the counterparty's
//     spend pubkey `P` and the adaptor point `T = t·G_cync`,
//     produces `P + T`. The CYNC sender hands this to their
//     existing wallet's [`coincync::transaction::TransactionBuilder`]
//     as the recipient's spend public key. The lock output ends up
//     at a stealth address whose underlying spending key is
//     `s_recipient + t`.
//
//   [`derive_swap_spender_secret`] — given the counterparty's spend
//     secret `s` and the adaptor secret `t`, produces `s + t`. The
//     CYNC recipient — who learns `t` from the BTC-side adaptor
//     reveal — feeds this to the wallet's normal one-time-secret
//     derivation. The resulting one-time secret correctly signs a
//     spend of the lock output via the existing CLSAG path.
//
// The CYNC stealth address scheme matches this folding exactly
// (verified against `src/crypto/stealth.rs:829-869`):
//
//     stealth.public_key = H(ECDH(view, tx_pub) || idx) · G + spend_pub
//
// Replacing `spend_pub` with `P + T` is a clean substitution — no
// CYNC consensus change required, and the scan/spend machinery
// continues to work as long as the recipient's wallet uses the
// modified spend secret.
//
// What is deliberately NOT done in this slice:
// - **CLSAG ring-binding for the adaptor.** A more advanced
//   construction would fold the adaptor into the CLSAG c-value
//   directly so that the *act of spending* (rather than the
//   *recipient detection*) reveals `t`. That requires modifying
//   the ring-signature challenge derivation in
//   `coincync::crypto::clsag` and is a separate consensus-touching
//   slice. The shipped derivation is sufficient for the basic
//   atomic-swap protocol — `t` is revealed via the BTC-side
//   signature (which we already ship) and the recipient uses it
//   to derive the CYNC spend secret.

use curve25519_dalek::constants::RISTRETTO_BASEPOINT_TABLE;
use curve25519_dalek::ristretto::CompressedRistretto;
use curve25519_dalek::scalar::Scalar as Ristretto255Scalar;

/// CYNC swap recipient spend pubkey: `P + T` where `P` is the
/// counterparty's wallet spend pubkey and `T = t·G_cync` is the
/// adaptor point.
///
/// The caller hands the returned bytes to
/// [`coincync::transaction::Recipient.spend_public`] when building
/// the lock tx. The counterparty's view pubkey passes through
/// unchanged.
///
/// Both inputs and the output are 32-byte compressed Ristretto255
/// encodings — the same format the parent crate's
/// `primitives::PublicKey` carries.
///
/// # Errors
/// Returns `Verification` if either point doesn't decode (not on
/// the Ristretto255 prime-order group).
pub fn derive_swap_recipient_spend_pub(
    counterparty_spend_pub: &[u8; 32],
    adaptor_point: &[u8; 32],
) -> Result<[u8; 32]> {
    let p = CompressedRistretto::from_slice(counterparty_spend_pub)
        .map_err(|_| Error::Verification("counterparty_spend_pub length"))?
        .decompress()
        .ok_or(Error::Verification("counterparty_spend_pub decode"))?;
    let t = CompressedRistretto::from_slice(adaptor_point)
        .map_err(|_| Error::Verification("adaptor_point length"))?
        .decompress()
        .ok_or(Error::Verification("adaptor_point decode"))?;
    Ok((p + t).compress().to_bytes())
}

/// CYNC swap effective spend secret: `s + t` where `s` is the
/// counterparty's wallet spend secret and `t` is the adaptor
/// secret the spender learned via the BTC-side reveal.
///
/// Feed the returned bytes to `compute_one_time_secret` (or the
/// equivalent wallet path) in place of the wallet's regular
/// `spend_secret`. The resulting one-time secret correctly opens
/// the lock output for spending.
///
/// # Errors
/// Returns `Verification` if either scalar isn't a canonical
/// Ristretto255 element (`< ℓ`).
pub fn derive_swap_spender_secret(
    counterparty_spend_secret: &[u8; 32],
    adaptor_secret: &[u8; 32],
) -> Result<[u8; 32]> {
    let s = Option::<Ristretto255Scalar>::from(Ristretto255Scalar::from_canonical_bytes(
        *counterparty_spend_secret,
    ))
    .ok_or(Error::Verification(
        "counterparty_spend_secret out of range",
    ))?;
    let t = Option::<Ristretto255Scalar>::from(Ristretto255Scalar::from_canonical_bytes(
        *adaptor_secret,
    ))
    .ok_or(Error::Verification("adaptor_secret out of range"))?;
    Ok((s + t).to_bytes())
}

/// CYNC swap adaptor point: `T = t·G_cync`. Convenience wrapper so
/// callers building a [`derive_swap_recipient_spend_pub`] request
/// don't need to depend on `curve25519_dalek` directly.
///
/// Mirrors [`crate::adaptor::cync_adaptor_point`] (same math); kept
/// in this module so the swap key-derivation surface is
/// self-contained for callers who only care about the chain side.
pub fn cync_adaptor_point_from_secret(adaptor_secret: &[u8; 32]) -> Result<[u8; 32]> {
    let t = Option::<Ristretto255Scalar>::from(Ristretto255Scalar::from_canonical_bytes(
        *adaptor_secret,
    ))
    .ok_or(Error::Verification("adaptor_secret out of range"))?;
    Ok((&t * RISTRETTO_BASEPOINT_TABLE).compress().to_bytes())
}

// ── Public wrappers (preserve the pre-existing function signatures) ──

/// Bundle of CYNC-side wire bytes the wallet's tx builder needs to
/// construct a swap lock output. Produced by
/// [`compute_swap_lock_recipient`].
///
/// **Why a bundle, not a wallet `Recipient` directly?** This crate
/// cannot depend on the main `coincync` crate without dragging in
/// the entire consensus/storage/networking compile graph just to
/// use `TransactionBuilder`. By returning a typed bundle of bytes
/// the wallet drops into its existing `Recipient { spend_public,
/// view_public, amount, lock_height }` shape, the dep cycle stays
/// clean (wallet → swap, never swap → wallet's lib).
///
/// The wallet side does:
/// ```ignore
/// let params = coincync_swap::cync::compute_swap_lock_recipient(...)?;
/// let recipient = coincync::transaction::Recipient {
///     spend_public: PublicKey::from_bytes(&params.spend_public_bytes)?,
///     view_public:  PublicKey::from_bytes(&params.view_public_bytes)?,
///     amount:       Amount::from(params.amount_atomic),
///     lock_height:  params.lock_height,
/// };
/// // ...then add_output + add_input + build as normal.
/// ```
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SwapLockRecipient {
    /// 32-byte Ristretto spend pubkey for the lock output. Already
    /// includes the adaptor tweak: `P_lock = bob_spend_pub + T_cync`.
    /// The wallet drops this straight into `Recipient.spend_public`.
    pub spend_public_bytes: [u8; 32],

    /// 32-byte Ristretto view pubkey for the lock output. **Not**
    /// tweaked — the swap protocol does not modify the view key.
    /// Bob's view key passes through unchanged.
    pub view_public_bytes: [u8; 32],

    /// Lock amount in CYNC atomic units. Pass-through from the
    /// swap-parameters layer; the wallet wraps in its `Amount` type.
    pub amount_atomic: u64,

    /// Optional lock_height for the output (the on-chain CSV-style
    /// timeout). `Some(h)` means "cannot be spent before block h";
    /// `None` lets the wallet decide. The swap state machine uses
    /// the `SwapParameters::cync_timeout_blocks` value computed at
    /// negotiation time.
    pub lock_height: Option<u64>,
}

/// Compute the wallet-ready recipient bundle for the CYNC lock
/// output of an atomic swap. Pure byte math — no chain access, no
/// RNG, no wallet state.
///
/// This is the swap-specific half of CYNC tx construction. The
/// wallet side feeds the returned bytes into its existing
/// `TransactionBuilder::add_output(...)` along with its
/// wallet-specific signing material (UTXOs, decoys, blinding
/// factors, CLSAG ring composition) and broadcasts as normal.
///
/// On the spend side (after the BTC adaptor reveals `t`), the
/// receiver derives their effective spend secret via
/// [`derive_swap_spender_secret`] and uses the standard
/// stealth-address one-time-secret derivation to construct the
/// claim tx — again via the wallet's `TransactionBuilder`.
///
/// # Errors
///
/// - `Verification` if `counterparty_spend_pub` or `adaptor_point`
///   do not decode as canonical Ristretto compressed points.
/// - `Verification` if `counterparty_view_pub` is not 32 bytes
///   (length validation only — the view-pub isn't curve-validated
///   here because the wallet does the full check at `Recipient`
///   construction).
pub fn compute_swap_lock_recipient(
    counterparty_spend_pub: &[u8; 32],
    counterparty_view_pub: &[u8; 32],
    adaptor_point: &[u8; 32],
    amount_atomic: u64,
    lock_height: Option<u64>,
) -> Result<SwapLockRecipient> {
    if amount_atomic == 0 {
        return Err(Error::Verification("swap lock amount must be > 0"));
    }
    let spend_public_bytes =
        derive_swap_recipient_spend_pub(counterparty_spend_pub, adaptor_point)?;
    Ok(SwapLockRecipient {
        spend_public_bytes,
        view_public_bytes: *counterparty_view_pub,
        amount_atomic,
        lock_height,
    })
}

/// Construct the CYNC lock transaction.
///
/// **This is intentionally not implemented in this crate.** CYNC
/// transaction construction is too entangled with wallet state
/// (one-time secrets, blinding factors, decoy selection, CLSAG
/// ring composition) to live outside the wallet.
///
/// The recommended flow is now spelled out by the
/// [`compute_swap_lock_recipient`] helper above:
///
/// 1. Caller computes the swap recipient bundle via
///    [`compute_swap_lock_recipient`].
/// 2. Caller hands the bundle to the wallet's existing
///    `TransactionBuilder` along with its wallet-specific signing
///    material and broadcasts the resulting tx normally.
/// 3. After the swap reveals the adaptor secret `t`, the receiver
///    derives their effective spend secret via
///    [`derive_swap_spender_secret`] and uses the wallet's
///    standard one-time-secret derivation to construct the spend tx.
///
/// Returns `NotImplemented` with a `stage` of `cync.build_lock_tx`
/// so existing callers fail loudly rather than silently producing
/// an empty tx. The doc-comment direction (use
/// `compute_swap_lock_recipient`) is the supported path forward.
pub fn build_lock_tx(
    _config: &CyncConfig,
    _amount: u64,
    _alice_pub: &[u8],
    _bob_pub: &[u8],
    _timeout_blocks: u32,
) -> Result<Vec<u8>> {
    Err(Error::not_implemented("cync.build_lock_tx"))
}

/// Watch the CYNC chain for a given txid + N confirmations. Sync
/// wrapper for one-off CLI use; the async swap state machine should
/// call the [`CyncChain::wait_for_confirmations`] method on a chain
/// instance directly.
pub fn wait_for_confirmations(
    config: &CyncConfig,
    txid: &str,
    confirmations: u32,
    timeout_secs: u64,
) -> Result<()> {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| Error::Rpc(format!("tokio runtime: {}", e)))?;
    let chain = CyncNodeRpc::new(config.clone())?;
    let txid = CyncTxid::from_hex(txid)?;
    rt.block_on(chain.wait_for_confirmations(
        &txid,
        confirmations,
        Duration::from_secs(timeout_secs),
    ))
}

/// Broadcast a signed CYNC transaction. Sync wrapper.
pub fn broadcast(config: &CyncConfig, tx_bytes: &[u8]) -> Result<String> {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| Error::Rpc(format!("tokio runtime: {}", e)))?;
    let chain = CyncNodeRpc::new(config.clone())?;
    let tx_hex = hex::encode(tx_bytes);
    let txid = rt.block_on(chain.broadcast(&tx_hex))?;
    Ok(txid.to_hex())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cync_config_constructor_rejects_bad_network() {
        let cfg = CyncConfig {
            network: "fakenet".into(),
            rpc_url: "http://127.0.0.1:28085".into(),
            api_key: None,
        };
        assert!(CyncNodeRpc::new(cfg).is_err());
    }

    #[test]
    fn cync_config_constructor_rejects_bad_url() {
        let cfg = CyncConfig {
            network: "testnet".into(),
            rpc_url: "not a url".into(),
            api_key: None,
        };
        assert!(CyncNodeRpc::new(cfg).is_err());
    }

    #[test]
    fn cync_config_constructor_accepts_testnet() {
        let cfg = CyncConfig {
            network: "testnet".into(),
            rpc_url: "http://127.0.0.1:28085".into(),
            api_key: Some("api-token".into()),
        };
        CyncNodeRpc::new(cfg).expect("testnet config must parse");
    }

    #[test]
    fn cync_txid_round_trip_hex() {
        let bytes = [0x5a; 32];
        let txid = CyncTxid(bytes);
        let hex = txid.to_hex();
        assert_eq!(hex.len(), 64);
        let parsed = CyncTxid::from_hex(&hex).unwrap();
        assert_eq!(parsed, txid);
    }

    #[test]
    fn cync_txid_strips_0x_prefix() {
        // The CYNC RPC sometimes returns hashes with a "0x" prefix
        // (the wallet UI does it for display). Parser must tolerate
        // both forms.
        let bytes = [0x77; 32];
        let with_prefix = format!("0x{}", hex::encode(bytes));
        let parsed = CyncTxid::from_hex(&with_prefix).unwrap();
        assert_eq!(parsed.0, bytes);
    }

    #[test]
    fn cync_txid_distinct_from_btc_txid_namespace() {
        // The two Txid types share an underlying [u8; 32] but the
        // nominal types are distinct — accidentally passing one in
        // place of the other should not compile. This test exists
        // mainly as a compile-time guard for any future refactor
        // that might unify them; if the assertion below ever needs
        // updating, double-check the type discipline still holds.
        let cync = CyncTxid([1u8; 32]);
        let btc = crate::btc::Txid([1u8; 32]);
        assert_eq!(cync.0, btc.0); // bytes match
                                   // The types do not implement cross-type equality, so the
                                   // following would not compile:
                                   //   assert_eq!(cync, btc);   // ← E0308 mismatched types
    }

    #[tokio::test]
    async fn mock_cync_chain_broadcast_then_wait() {
        let chain = MockCyncChain::new();
        let tx_hex = "cafebabe";

        let txid = chain.broadcast(tx_hex).await.unwrap();
        // Idempotent re-broadcast.
        let txid2 = chain.broadcast(tx_hex).await.unwrap();
        assert_eq!(txid, txid2);

        // Just-broadcast tx is "in mempool" — 0 confirmations.
        let r = chain
            .wait_for_confirmations(&txid, 1, Duration::from_millis(50))
            .await;
        assert!(matches!(r, Err(Error::Timeout { .. })));

        // Mine the next block — tx is now included, 1 confirmation.
        chain.mine_blocks(1);
        chain
            .wait_for_confirmations(&txid, 1, Duration::from_millis(500))
            .await
            .expect("1 confirmation should now be visible");

        // Mine 4 more blocks — should now have 5 confirmations.
        chain.mine_blocks(4);
        chain
            .wait_for_confirmations(&txid, 5, Duration::from_millis(500))
            .await
            .expect("5 confirmations should now be visible");
    }

    #[tokio::test]
    async fn mock_cync_chain_unknown_txid_times_out() {
        let chain = MockCyncChain::new();
        let unknown = CyncTxid([0xee; 32]);
        let r = chain
            .wait_for_confirmations(&unknown, 1, Duration::from_millis(30))
            .await;
        assert!(matches!(r, Err(Error::Timeout { .. })));
    }

    #[tokio::test]
    async fn mock_cync_chain_block_count_tracks_mining() {
        let chain = MockCyncChain::new();
        assert_eq!(chain.get_block_count().await.unwrap(), 0);
        chain.mine_blocks(7);
        assert_eq!(chain.get_block_count().await.unwrap(), 7);
    }

    /// Timing test for `MockCyncChain::wait_for_confirmations`. Catches:
    ///   - cync.rs:362  `let deadline = Instant::now() + timeout` flipped to `-`
    ///   - cync.rs:377  `if Instant::now() >= deadline` flipped to `<`
    /// Both mutations would still return Err Timeout but return immediately.
    #[tokio::test]
    async fn mock_cync_chain_wait_respects_timeout_deadline() {
        let chain = MockCyncChain::new();
        let unknown = CyncTxid([0x77; 32]);
        let timeout = Duration::from_millis(150);
        let start = Instant::now();
        let r = chain.wait_for_confirmations(&unknown, 1, timeout).await;
        let elapsed = start.elapsed();
        assert!(matches!(r, Err(Error::Timeout { .. })));
        assert!(
            elapsed >= Duration::from_millis(100),
            "wait_for_confirmations returned in {:?} \u{2014} expected ~{:?}. \
             The deadline arithmetic or `>=` check appears mutated.",
            elapsed,
            timeout
        );
    }

    /// Precision test for cync.rs:367: `Some((g.tip - h + 1) as u32)`.
    /// Mutations replace `-` with `+` or `/`. To catch them, we set up a
    /// state where the *real* depth is below `min_confirmations` (so the
    /// real code times out) but the *mutated* depth is at or above
    /// `min_confirmations` (so the mutated code returns Ok prematurely).
    ///
    /// Setup: tip = 5, included-block height = 5
    ///   real:  depth = 5 - 5 + 1 = 1     (must wait, times out)
    ///   `+`:   depth = 5 + 5 + 1 = 11    (≥ 2 → returns Ok)
    ///   `/`:   depth = 5 / 5 + 1 = 2     (≥ 2 → returns Ok)
    /// Asserting Err Timeout catches both.
    #[tokio::test]
    async fn mock_cync_chain_depth_arithmetic_is_exact() {
        let chain = MockCyncChain::new();
        // Inject a tx mapped to height 5, then mine 5 blocks so tip=5.
        // Use the public API: broadcast → mine_blocks gets us close,
        // but broadcast records `next_block = tip + 1` which would be 1
        // with tip=0. We need the included block to equal the tip exactly,
        // so we mine first (tip=4), then broadcast (records at 5), then
        // mine once more (tip=5).
        chain.mine_blocks(4); // tip = 4
        let tx_hex = "feedface";
        let txid = chain.broadcast(tx_hex).await.unwrap(); // recorded at height 5
        chain.mine_blocks(1); // tip = 5
                              // Real depth = 5 - 5 + 1 = 1. Require 2 confirmations.
        let r = chain
            .wait_for_confirmations(&txid, 2, Duration::from_millis(80))
            .await;
        assert!(
            matches!(r, Err(Error::Timeout { .. })),
            "depth arithmetic appears mutated \u{2014} got {:?} when expecting Timeout. \
             With real arithmetic depth=1 (< 2 confirmations), but `-` flipped to `+` \
             gives depth=11 and `-` flipped to `/` gives depth=2, both of which \
             would erroneously return Ok.",
            r
        );
    }

    /// Sync wrapper `wait_for_confirmations` at cync.rs:639 must propagate
    /// errors from inner steps. A mutation that replaces the whole function
    /// body with `Ok(())` would silently succeed. Invalid txid catches this.
    #[test]
    fn sync_cync_wait_for_confirmations_propagates_invalid_txid() {
        let cfg = CyncConfig {
            network: "testnet".into(),
            rpc_url: "http://127.0.0.1:18999".into(),
            api_key: None,
        };
        let r = wait_for_confirmations(&cfg, "not-hex-too-short", 1, 1);
        assert!(r.is_err(),
            "wait_for_confirmations must reject invalid txid \u{2014} function body must not be replaced with Ok(())"
        );
    }

    /// Sync wrapper `broadcast` at cync.rs:664 must propagate RPC failures.
    /// Mutation replaces body with Ok(String::new()) or Ok("xyzzy"). Point
    /// at unreachable port and assert Err.
    #[test]
    fn sync_cync_broadcast_propagates_rpc_connect_failure() {
        let cfg = CyncConfig {
            network: "testnet".into(),
            rpc_url: "http://127.0.0.1:1".into(),
            api_key: None,
        };
        let r = broadcast(&cfg, &[0u8; 10]);
        match r {
            Err(_) => { /* expected */ }
            Ok(s) => panic!(
                "broadcast returned Ok({:?}) on unreachable RPC URL \u{2014} function body appears mutated",
                s
            ),
        }
    }

    // ── CyncNodeRpc wiremock-backed tests ─────────────────────────────────
    //
    // These tests run a wiremock HTTP server and exercise the actual
    // CyncNodeRpc function bodies (not the in-memory MockCyncChain).

    use wiremock::matchers::{body_string_contains, method};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    fn cync_rpc_against(mock_url: &str) -> CyncNodeRpc {
        CyncNodeRpc::new(CyncConfig {
            network: "regtest".into(),
            rpc_url: mock_url.into(),
            api_key: None,
        })
        .expect("CyncNodeRpc::new")
        .with_poll_interval(Duration::from_millis(10))
    }

    /// `current_tip` returns the exact `height` field from the
    /// `get_blockchain_info` response. Catches mutations at cync.rs:218.
    #[tokio::test]
    async fn rpc_cync_current_tip_returns_height_field() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(body_string_contains("get_blockchain_info"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "jsonrpc": "2.0",
                "id": "coincync-swap",
                "result": {"height": 999u64}
            })))
            .mount(&server)
            .await;

        let rpc = cync_rpc_against(&server.uri());
        let h = rpc.current_tip().await.expect("current_tip");
        assert_eq!(h, 999, "current_tip must return the exact height field");
    }

    /// `get_block_count` is a thin wrapper around `current_tip`. Same
    /// mock setup verifies the public method returns the correct value
    /// — catches the mutations at cync.rs:277 that replace the body
    /// with `Ok(0)` or `Ok(1)`.
    #[tokio::test]
    async fn rpc_cync_get_block_count_returns_current_tip() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(body_string_contains("get_blockchain_info"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "jsonrpc": "2.0",
                "id": "coincync-swap",
                "result": {"height": 8888u64}
            })))
            .mount(&server)
            .await;

        let rpc = cync_rpc_against(&server.uri());
        assert_eq!(rpc.get_block_count().await.expect("get_block_count"), 8888);
    }

    /// `try_get_block_height` returns `Some(block_height)` when the
    /// `get_transaction` RPC reports the tx is confirmed. Catches
    /// cync.rs:207 mutations that flip the return to None / Some(0) / Some(1).
    #[tokio::test]
    async fn rpc_cync_try_get_block_height_returns_block_height_field() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(body_string_contains("get_transaction"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "jsonrpc": "2.0",
                "id": "coincync-swap",
                "result": {"block_height": 42u64}
            })))
            .mount(&server)
            .await;

        let rpc = cync_rpc_against(&server.uri());
        let txid = CyncTxid([0x88; 32]);
        let h = rpc.try_get_block_height(&txid).await;
        assert_eq!(
            h,
            Some(42),
            "try_get_block_height must return the exact field"
        );
    }

    /// `broadcast` returns the txid hash on `accepted: true`. Catches
    /// cync.rs:238 mutation that deletes the `!` in `if !accepted`
    /// (with `!` deleted, the function would Err on accepted=true).
    #[tokio::test]
    async fn rpc_cync_broadcast_returns_txid_on_accepted() {
        let hash_hex = "1234567890abcdef".repeat(4); // 32 bytes (64 hex chars)
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(body_string_contains("send_raw_transaction"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "jsonrpc": "2.0",
                "id": "coincync-swap",
                "result": {"accepted": true, "hash": hash_hex}
            })))
            .mount(&server)
            .await;

        let rpc = cync_rpc_against(&server.uri());
        let txid = rpc.broadcast("deadbeef").await.expect("broadcast accepted");
        assert_eq!(
            txid.to_hex(),
            hash_hex.to_string(),
            "broadcast must return the hash from an accepted RPC response"
        );
    }

    /// `wait_for_confirmations` returns Ok when the computed depth
    /// `tip - block_height + 1` meets the threshold. Catches multiple
    /// mutations:
    ///   - cync.rs:254 deadline `+` → `-` (would time out immediately)
    ///   - cync.rs:259 `tip >= block_height` flip
    ///   - cync.rs:260 arithmetic `tip - block_height + 1` flips
    ///   - cync.rs:261 `confirmations >= min_confirmations` flip
    ///   - cync.rs:267 deadline `>=` flip
    ///
    /// Setup: tip = 105, block_height = 100 → depth = 6. Threshold = 5.
    ///   real:      depth = 6, 6 >= 5 → Ok
    ///   `-` → `+`: depth = 206, still ≥ 5 → Ok (not caught here; mock test catches)
    ///   `-` → `/`: depth = 2,   2 < 5  → times out (caught)
    ///   `>=` → `<` at 259: 105 < 100 → false → no depth check → times out
    ///   `>=` → `<` at 261: 6 < 5 → false → no Ok return → times out
    #[tokio::test]
    async fn rpc_cync_wait_returns_ok_with_sufficient_depth() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(body_string_contains("get_transaction"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "jsonrpc": "2.0",
                "id": "coincync-swap",
                "result": {"block_height": 100u64}
            })))
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(body_string_contains("get_blockchain_info"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "jsonrpc": "2.0",
                "id": "coincync-swap",
                "result": {"height": 105u64}
            })))
            .mount(&server)
            .await;

        let rpc = cync_rpc_against(&server.uri());
        let txid = CyncTxid([0x99; 32]);
        rpc.wait_for_confirmations(&txid, 5, Duration::from_millis(500))
            .await
            .expect("depth = 6 >= 5 threshold should return Ok");
    }

    /// `wait_for_confirmations` times out when no confirmations are
    /// reported. Catches cync.rs:254 deadline `+` → `-` and
    /// cync.rs:267 `>=` → `<` in the deadline check (both mutations
    /// still return Err Timeout but return immediately rather than
    /// waiting the requested duration).
    #[tokio::test]
    async fn rpc_cync_wait_respects_timeout_deadline() {
        let server = MockServer::start().await;
        // get_transaction returns no tx (transient missing tx case).
        Mock::given(method("POST"))
            .and(body_string_contains("get_transaction"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "jsonrpc": "2.0",
                "id": "coincync-swap",
                "error": {"code": -1, "message": "tx not found"}
            })))
            .mount(&server)
            .await;

        let rpc = cync_rpc_against(&server.uri());
        let txid = CyncTxid([0xaa; 32]);
        let timeout = Duration::from_millis(150);
        let start = Instant::now();
        let r = rpc.wait_for_confirmations(&txid, 1, timeout).await;
        let elapsed = start.elapsed();
        assert!(matches!(r, Err(Error::Timeout { .. })));
        assert!(
            elapsed >= Duration::from_millis(100),
            "cync rpc wait returned in {:?} \u{2014} expected ~{:?}",
            elapsed,
            timeout
        );
    }

    /// Depth precision: catches the `+` → `*` mutation specifically at
    /// cync.rs:260. The expression is `(tip - block_height + 1)`.
    /// Setup: tip = 5, block_height = 4, threshold = 2
    ///   real:      depth = 5 - 4 + 1 = 2, ≥ 2 → returns Ok
    ///   `+` → `*`: depth = 5 - 4 * 1 = 1, < 2 → would time out (catches!)
    ///
    /// The other `+` → `*` cousin tests (rpc_cync_wait_depth_arithmetic_is_exact
    /// below) catch the `-` → `+` / `-` → `/` mutations. This one fills the
    /// remaining `+ 1` boundary the others miss.
    #[tokio::test]
    async fn rpc_cync_wait_depth_addition_one_is_exact() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(body_string_contains("get_transaction"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "jsonrpc": "2.0",
                "id": "coincync-swap",
                "result": {"block_height": 4u64}
            })))
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(body_string_contains("get_blockchain_info"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "jsonrpc": "2.0",
                "id": "coincync-swap",
                "result": {"height": 5u64}
            })))
            .mount(&server)
            .await;

        let rpc = cync_rpc_against(&server.uri());
        let txid = CyncTxid([0xcc; 32]);
        rpc.wait_for_confirmations(&txid, 2, Duration::from_millis(200))
            .await
            .expect("depth = 5 - 4 + 1 = 2 must meet threshold 2 \u{2014} `+` → `*` mutation makes depth = 1");
    }

    /// Depth precision: catches the `-` → `+` and `-` → `/` mutations
    /// at cync.rs:260 specifically by setting up a state where the real
    /// depth is exactly below the threshold (must time out) but the
    /// mutated depth would be at or above (would return Ok).
    ///
    /// Setup: tip = 5, block_height = 5, threshold = 2
    ///   real:      depth = 5 - 5 + 1 = 1, 1 < 2 → times out
    ///   `-` → `+`: depth = 5 + 5 + 1 = 11, ≥ 2 → would Ok (catches!)
    ///   `-` → `/`: depth = 5 / 5 + 1 = 2,  ≥ 2 → would Ok (catches!)
    #[tokio::test]
    async fn rpc_cync_wait_depth_arithmetic_is_exact() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(body_string_contains("get_transaction"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "jsonrpc": "2.0",
                "id": "coincync-swap",
                "result": {"block_height": 5u64}
            })))
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(body_string_contains("get_blockchain_info"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "jsonrpc": "2.0",
                "id": "coincync-swap",
                "result": {"height": 5u64}
            })))
            .mount(&server)
            .await;

        let rpc = cync_rpc_against(&server.uri());
        let txid = CyncTxid([0xbb; 32]);
        // Threshold = 2; real depth = 1; mutations push depth to 11 or 2 → would Ok.
        let r = rpc
            .wait_for_confirmations(&txid, 2, Duration::from_millis(100))
            .await;
        assert!(
            matches!(r, Err(Error::Timeout { .. })),
            "depth arithmetic at cync.rs:260 appears mutated \u{2014} got {:?} when expecting Timeout",
            r
        );
    }

    // ── Swap key-derivation helpers ──────────────────────────────────

    /// Build a fresh Ristretto255 keypair (secret, public) for tests
    /// without depending on rand_core globally.
    fn test_ristretto_keypair(seed: u64) -> ([u8; 32], [u8; 32]) {
        use rand::rngs::StdRng;
        use rand::{RngCore, SeedableRng};
        let mut rng = StdRng::seed_from_u64(seed);
        let mut bytes = [0u8; 32];
        rng.fill_bytes(&mut bytes);
        // Reduce mod ℓ to guarantee canonical.
        let s = Ristretto255Scalar::from_bytes_mod_order(bytes);
        let sk_bytes = s.to_bytes();
        let pk_bytes = (&s * RISTRETTO_BASEPOINT_TABLE).compress().to_bytes();
        (sk_bytes, pk_bytes)
    }

    #[test]
    fn swap_recipient_spend_pub_equals_p_plus_t() {
        // Direct group-arithmetic check: derived pubkey = P + T.
        let (_, p_bytes) = test_ristretto_keypair(11);
        let (t_sk, t_pub) = test_ristretto_keypair(22);

        let derived = derive_swap_recipient_spend_pub(&p_bytes, &t_pub).unwrap();

        // Recompute manually.
        let p = CompressedRistretto::from_slice(&p_bytes)
            .unwrap()
            .decompress()
            .unwrap();
        let t = CompressedRistretto::from_slice(&t_pub)
            .unwrap()
            .decompress()
            .unwrap();
        let expected = (p + t).compress().to_bytes();
        assert_eq!(derived, expected);

        // Also verify: adaptor_point_from_secret(t_sk) == t_pub.
        assert_eq!(cync_adaptor_point_from_secret(&t_sk).unwrap(), t_pub);
    }

    #[test]
    fn swap_spender_secret_pubkey_matches_swap_recipient_pubkey() {
        // The load-bearing soundness property: the secret derived
        // by `derive_swap_spender_secret` is the discrete log of
        // the pubkey derived by `derive_swap_recipient_spend_pub`.
        // Without this, the recipient can't spend what the sender
        // sent them.
        let (s_sk, s_pub) = test_ristretto_keypair(101);
        let (t_sk, t_pub) = test_ristretto_keypair(102);

        let recipient_pub = derive_swap_recipient_spend_pub(&s_pub, &t_pub).unwrap();
        let spender_sec = derive_swap_spender_secret(&s_sk, &t_sk).unwrap();

        let derived_scalar = Ristretto255Scalar::from_canonical_bytes(spender_sec).unwrap();
        let derived_pub = (&derived_scalar * RISTRETTO_BASEPOINT_TABLE)
            .compress()
            .to_bytes();
        assert_eq!(
            derived_pub, recipient_pub,
            "spender's secret must be the discrete log of the recipient's pubkey"
        );
    }

    #[test]
    fn swap_derivation_round_trips_through_cync_stealth_scheme() {
        // Simulate the full CYNC stealth address derivation with
        // the swap-modified recipient + spender keys, mirroring
        // src/crypto/stealth.rs:829-869 and :972-998 byte-for-byte:
        //
        //   Sender (Alice):
        //     1. Pick tx_secret. tx_public = tx_secret · G.
        //     2. shared = view_pub · tx_secret
        //     3. h = SHA(shared || output_idx)  (a scalar)
        //     4. stealth = h·G + (recipient_spend_pub + T)
        //
        //   Recipient (Bob, after learning t):
        //     5. shared = view_secret · tx_public
        //     6. h = SHA(shared || output_idx)  (same scalar)
        //     7. one_time_secret = h + (bob_spend_secret + t)
        //     8. one_time_secret · G must equal stealth
        //
        // Step 8 is what this test asserts. We DON'T import the
        // CYNC stealth module here (it's behind the parent crate's
        // module privacy); instead we reimplement the four lines
        // of arithmetic locally. If the parent's derivation ever
        // changes shape, this test will surface the breakage
        // via the end-to-end soundness assertion.
        use sha2::{Digest, Sha512};

        let (bob_spend_sk, bob_spend_pub) = test_ristretto_keypair(200);
        let (bob_view_sk, bob_view_pub) = test_ristretto_keypair(201);
        let (t_sk, t_pub) = test_ristretto_keypair(202);
        let (tx_sk, _tx_pub) = test_ristretto_keypair(203);
        let output_idx: u8 = 7;

        // ── Sender derives the swap recipient spend pubkey ─────
        let swap_recipient_spend = derive_swap_recipient_spend_pub(&bob_spend_pub, &t_pub).unwrap();

        // ── Sender's side of the ECDH + stealth derivation ─────
        // shared = view_pub * tx_secret
        let view_pub_point = CompressedRistretto::from_slice(&bob_view_pub)
            .unwrap()
            .decompress()
            .unwrap();
        let tx_secret_scalar = Ristretto255Scalar::from_canonical_bytes(tx_sk).unwrap();
        let shared_sender = view_pub_point * tx_secret_scalar;

        // h = SHA512(shared || idx)  reduced into the Ristretto field.
        let mut h = Sha512::new();
        h.update(shared_sender.compress().to_bytes());
        h.update([output_idx]);
        let h_scalar = Ristretto255Scalar::from_hash(h);

        // stealth = h·G + swap_recipient_spend_pub
        let swap_recipient_point = CompressedRistretto::from_slice(&swap_recipient_spend)
            .unwrap()
            .decompress()
            .unwrap();
        let stealth_point = (&h_scalar * RISTRETTO_BASEPOINT_TABLE) + swap_recipient_point;

        // ── Recipient's side: derive the effective spend secret
        //    and verify it opens the stealth ─────────────────────
        let effective_spend = derive_swap_spender_secret(&bob_spend_sk, &t_sk).unwrap();

        // Recipient computes the same ECDH shared point: view_sk * tx_pub
        let tx_pub_point = &tx_secret_scalar * RISTRETTO_BASEPOINT_TABLE; // = tx_pub
        let view_sk_scalar = Ristretto255Scalar::from_canonical_bytes(bob_view_sk).unwrap();
        let shared_recipient = tx_pub_point * view_sk_scalar;

        // Should be the same shared point.
        assert_eq!(
            shared_recipient.compress().to_bytes(),
            shared_sender.compress().to_bytes(),
            "ECDH should yield the same shared point on both sides"
        );

        // Same h computation.
        let mut h2 = Sha512::new();
        h2.update(shared_recipient.compress().to_bytes());
        h2.update([output_idx]);
        let h2_scalar = Ristretto255Scalar::from_hash(h2);
        assert_eq!(h_scalar, h2_scalar);

        // one_time_secret = h + effective_spend
        let effective_spend_scalar =
            Ristretto255Scalar::from_canonical_bytes(effective_spend).unwrap();
        let one_time_secret = h2_scalar + effective_spend_scalar;

        // one_time_secret · G must equal the stealth point — the
        // soundness property of the entire swap CYNC-side derivation.
        let derived_stealth = &one_time_secret * RISTRETTO_BASEPOINT_TABLE;
        assert_eq!(
            derived_stealth.compress().to_bytes(),
            stealth_point.compress().to_bytes(),
            "effective_spend_secret must open the stealth output"
        );
    }

    #[test]
    fn swap_recipient_rejects_off_curve_inputs() {
        // Non-canonical Ristretto bytes (random garbage that isn't a
        // valid compressed point) must surface as Verification.
        // Picked a 32-byte value that doesn't represent a valid
        // Ristretto point (the high-bit pattern is a frequent
        // off-curve signal).
        let bad = [0xffu8; 32];
        let (_, p_pub) = test_ristretto_keypair(300);
        let r1 = derive_swap_recipient_spend_pub(&bad, &p_pub);
        assert!(matches!(r1, Err(Error::Verification(_))));
        let r2 = derive_swap_recipient_spend_pub(&p_pub, &bad);
        assert!(matches!(r2, Err(Error::Verification(_))));
    }

    #[test]
    fn swap_spender_secret_rejects_out_of_range_scalars() {
        // 32 bytes where the value is >= ℓ (the Ristretto group order)
        // should fail. The simplest unambiguous out-of-range value: all
        // 0xff bytes (~2^256, well above 2^252 + ℓ).
        let bad = [0xffu8; 32];
        let (s_sk, _) = test_ristretto_keypair(400);
        let r1 = derive_swap_spender_secret(&bad, &s_sk);
        assert!(matches!(r1, Err(Error::Verification(_))));
        let r2 = derive_swap_spender_secret(&s_sk, &bad);
        assert!(matches!(r2, Err(Error::Verification(_))));
    }

    #[test]
    fn swap_derivation_uses_same_basepoint_as_adaptor_module() {
        // Sanity: cync_adaptor_point_from_secret in this module must
        // produce the same byte output as the existing
        // `adaptor::cync_adaptor_point` helper for any given secret.
        // If they ever diverge (different basepoints, different
        // serialization), the swap derivations would be inconsistent
        // with the adaptor primitives and the whole CYNC-side would
        // silently break.
        use crate::adaptor::{cync_adaptor_point, AdaptorSecret};

        let (t_sk, _) = test_ristretto_keypair(500);
        // `test_ristretto_keypair` returns Ristretto-canonical (little-
        // endian) bytes — match that encoding when constructing the
        // AdaptorSecret so `cync_adaptor_point` reads the right scalar.
        let from_cync_module = cync_adaptor_point_from_secret(&t_sk).unwrap();
        let from_adaptor_module =
            cync_adaptor_point(&AdaptorSecret::from_ristretto_bytes(t_sk).unwrap()).unwrap();
        assert_eq!(from_cync_module, from_adaptor_module);
    }

    #[test]
    fn build_lock_tx_remains_stubbed() {
        let cfg = CyncConfig {
            network: "testnet".into(),
            rpc_url: "http://127.0.0.1:28085".into(),
            api_key: None,
        };
        let r = build_lock_tx(&cfg, 1_000_000, &[1u8; 32], &[2u8; 32], 1440);
        assert!(matches!(
            r,
            Err(Error::NotImplemented {
                stage: "cync.build_lock_tx"
            })
        ));
    }

    // ── Wallet-bridge tests: compute_swap_lock_recipient ────────────

    #[test]
    fn compute_swap_lock_recipient_bundles_all_four_fields() {
        let (bob_spend_pub, _) = test_ristretto_keypair(100);
        let bob_spend_pub_pt = Ristretto255Scalar::from_canonical_bytes(bob_spend_pub).unwrap();
        let bob_spend_pub_bytes = (&bob_spend_pub_pt * RISTRETTO_BASEPOINT_TABLE)
            .compress()
            .to_bytes();
        let (t_secret, _) = test_ristretto_keypair(200);
        let adaptor_point = cync_adaptor_point_from_secret(&t_secret).unwrap();
        let bob_view_pub = [0xAB; 32]; // view pub isn't curve-validated here

        let bundle = compute_swap_lock_recipient(
            &bob_spend_pub_bytes,
            &bob_view_pub,
            &adaptor_point,
            12_345,
            Some(987_654),
        )
        .unwrap();

        // spend_public must match derive_swap_recipient_spend_pub(bob, T).
        let expected =
            derive_swap_recipient_spend_pub(&bob_spend_pub_bytes, &adaptor_point).unwrap();
        assert_eq!(bundle.spend_public_bytes, expected);

        // view_public passes through unchanged.
        assert_eq!(bundle.view_public_bytes, bob_view_pub);

        // amount + lock_height passed through.
        assert_eq!(bundle.amount_atomic, 12_345);
        assert_eq!(bundle.lock_height, Some(987_654));
    }

    #[test]
    fn compute_swap_lock_recipient_rejects_zero_amount() {
        // Zero-amount lock would dust-out at the wallet layer anyway,
        // but rejecting at the swap boundary gives a clearer error +
        // prevents an accidental "swap zero CYNC for some BTC" config.
        let zero_pub = [0u8; 32];
        let view_pub = [0u8; 32];
        let r = compute_swap_lock_recipient(&zero_pub, &view_pub, &zero_pub, 0, None);
        assert!(matches!(r, Err(Error::Verification(_))));
    }

    #[test]
    fn compute_swap_lock_recipient_rejects_noncanonical_spend_pub() {
        // 0xFF...FF is non-canonical on Ristretto — exercises the
        // decode failure path in derive_swap_recipient_spend_pub.
        let bad_pub = [0xFFu8; 32];
        let view_pub = [0u8; 32];
        let adaptor = [0u8; 32]; // identity, fine
        let r = compute_swap_lock_recipient(&bad_pub, &view_pub, &adaptor, 1, None);
        assert!(matches!(r, Err(Error::Verification(_))));
    }

    #[test]
    fn compute_swap_lock_recipient_lock_height_none_passes_through() {
        let (s_pub, _) = test_ristretto_keypair(300);
        let spend_pt = (&Ristretto255Scalar::from_canonical_bytes(s_pub).unwrap()
            * RISTRETTO_BASEPOINT_TABLE)
            .compress()
            .to_bytes();
        let (t, _) = test_ristretto_keypair(400);
        let t_point = cync_adaptor_point_from_secret(&t).unwrap();

        let bundle = compute_swap_lock_recipient(&spend_pt, &[0u8; 32], &t_point, 1, None).unwrap();
        assert_eq!(bundle.lock_height, None);
    }
}
