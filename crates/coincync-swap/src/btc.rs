//! Bitcoin-side primitives for the atomic swap.
//!
//! The BTC side of the swap is "the easy side" â€” Bitcoin's scripting
//! supports HTLC + adaptor-signature constructions natively, and there
//! is no privacy layer to preserve. This file owns the chain
//! interaction (broadcast, confirmation watching, height queries);
//! transaction construction is a separate slice that depends on the
//! `bitcoin` crate.
//!
//! ## Status: chain RPC shipped (2026-05-17 slice).
//!
//! What lands in this file:
//! - [`BtcChain`] async trait â€” the abstract interface every BTC
//!   chain interactor implements (real Bitcoin Core, future Electrum,
//!   in-memory mock for tests).
//! - [`BitcoinCoreRpc`] â€” a working JSON-RPC client over `reqwest`.
//!   Handles cookie-auth or user/pass auth, batches nothing yet, and
//!   uses the minimal subset of methods the swap actually needs:
//!   `sendrawtransaction`, `getrawtransaction` (verbose), `getblockcount`.
//! - [`MockBtcChain`] â€” in-memory implementation for unit tests. Lets
//!   the swap state machine be tested without a `bitcoind` instance.
//! - [`build_lock_tx`] remains stubbed pending the `bitcoin` crate
//!   integration in the protocol-encoding addendum to CIP-001 â€”
//!   transaction construction is its own slice.
//!
//! ## Network choice
//!
//! `BtcConfig::network` is a string for now (`"mainnet" / "testnet" /
//! "regtest"`); when the `bitcoin` crate lands it will become a real
//! `bitcoin::Network` enum. Tests use regtest with a local `bitcoind`
//! instance (or [`MockBtcChain`] when no daemon is available).
//!
//! ## Why not `bitcoincore-rpc`?
//!
//! The canonical Rust client for bitcoind is `bitcoincore-rpc`. It's
//! sync (blocking) and pulls in the `bitcoin` crate transitively.
//! For the async swap state machine, blocking calls are awkward.
//! Rather than wrap each call in `spawn_blocking`, this slice ships
//! a minimal async client over `reqwest` that covers the swap's
//! three needs. When `build_lock_tx` lands and we depend on
//! `bitcoin` anyway, we can revisit and possibly migrate.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use tokio::time::sleep;

use crate::{Error, Result};

// â”€â”€ Public types â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

/// Configuration for Bitcoin-side operations.
#[derive(Clone, Debug)]
pub struct BtcConfig {
    /// `"mainnet"` / `"testnet"` / `"regtest"` (becomes a real
    /// `bitcoin::Network` once `bitcoin` is in the dep tree).
    pub network: String,
    /// JSON-RPC endpoint â€” e.g. `"http://127.0.0.1:18443"` (regtest)
    /// or `"http://127.0.0.1:18332"` (testnet) or
    /// `"http://127.0.0.1:8332"` (mainnet).
    pub rpc_url: String,
    /// Optional basic-auth credentials (`(user, pass)`). Bitcoin
    /// Core's `.cookie` file convention can be loaded by the caller
    /// and passed through here. `None` for cookie-less or read-only
    /// endpoints (e.g. some hosted Bitcoin RPC services).
    pub rpc_auth: Option<(String, String)>,
}

/// 32-byte Bitcoin transaction id. Wrapped so it can't be mixed up
/// with a CYNC txid or an arbitrary `[u8; 32]`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Txid(pub [u8; 32]);

impl Txid {
    /// Parse from a 64-character lowercase hex string (the standard
    /// Bitcoin RPC representation). Note: Bitcoin Core displays txids
    /// in **reverse byte order** vs. their internal hash; we follow
    /// the RPC convention here so the bytes round-trip through
    /// `to_hex` -> RPC -> `from_hex` correctly.
    pub fn from_hex(s: &str) -> Result<Self> {
        let mut bytes = [0u8; 32];
        hex::decode_to_slice(s, &mut bytes)
            .map_err(|_| Error::Verification("invalid Bitcoin txid hex"))?;
        Ok(Self(bytes))
    }

    /// Render as 64-character lowercase hex.
    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }
}

// â”€â”€ BtcChain trait â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

/// Abstract Bitcoin-chain interface. Implemented by the real
/// `bitcoind` RPC client and by the in-memory mock used in tests.
/// The swap state machine consumes this trait so it can be exercised
/// without a live `bitcoind`.
///
/// All methods are async. Network errors and bitcoind RPC errors
/// surface as `Error::Io` (with the original error message) or
/// `Error::Verification` (for protocol-level rejections like
/// double-spend or invalid tx).
#[async_trait]
pub trait BtcChain: Send + Sync {
    /// Broadcast a raw transaction to the network. `tx_hex` is the
    /// serialized transaction in lowercase hex (the format
    /// `sendrawtransaction` accepts). Returns the txid on success.
    async fn broadcast(&self, tx_hex: &str) -> Result<Txid>;

    /// Block until `txid` has at least `min_confirmations` blocks on
    /// top of it, or `timeout` elapses. Returns `Err(Timeout)` on
    /// timeout, `Ok(())` on success.
    ///
    /// Polls every 10 seconds in production; tests can use a mock
    /// with a faster clock.
    async fn wait_for_confirmations(
        &self,
        txid: &Txid,
        min_confirmations: u32,
        timeout: Duration,
    ) -> Result<()>;

    /// Current chain tip height. Used during initial setup to derive
    /// the swap's timeout heights from a known reference.
    async fn get_block_count(&self) -> Result<u64>;
}

// â”€â”€ Real Bitcoin Core JSON-RPC client â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

/// Async Bitcoin Core JSON-RPC client.
#[derive(Clone, Debug)]
pub struct BitcoinCoreRpc {
    config: BtcConfig,
    http: reqwest::Client,
    poll_interval: Duration,
}

impl BitcoinCoreRpc {
    /// Build a new client. Validates the config minimally: URL parses,
    /// network string is recognised.
    pub fn new(config: BtcConfig) -> Result<Self> {
        if !matches!(config.network.as_str(), "mainnet" | "testnet" | "regtest" | "signet") {
            return Err(Error::Verification(
                "BtcConfig.network must be one of mainnet/testnet/regtest/signet",
            ));
        }
        if reqwest::Url::parse(&config.rpc_url).is_err() {
            return Err(Error::Verification("BtcConfig.rpc_url must be a valid URL"));
        }
        // Reasonable defaults for HTTP transport. 30s connect timeout
        // tolerates a slow local-network bitcoind; 60s total accommodates
        // a busy `sendrawtransaction` on a backlogged mempool.
        let http = reqwest::Client::builder()
            .connect_timeout(Duration::from_secs(30))
            .timeout(Duration::from_secs(60))
            .build()
            .map_err(|e| Error::Rpc(format!("reqwest client build: {e}")))?;
        Ok(Self {
            config,
            http,
            poll_interval: Duration::from_secs(10),
        })
    }

    /// Override the confirmation-poll interval. Tests use a much
    /// shorter value; production keeps the 10s default to avoid
    /// hammering local `bitcoind`.
    pub fn with_poll_interval(mut self, interval: Duration) -> Self {
        self.poll_interval = interval;
        self
    }

    /// Issue a JSON-RPC call. Returns the raw `result` field on
    /// success, or surfaces the bitcoind error in the `Error` enum.
    async fn call<T: for<'de> Deserialize<'de>>(
        &self,
        method: &str,
        params: serde_json::Value,
    ) -> Result<T> {
        // Each request gets a fresh integer id; we don't actually
        // care about matching responses to requests because we don't
        // batch, but bitcoind insists on `id` being present.
        let body = JsonRpcRequest {
            jsonrpc: "1.0",
            id: "coincync-swap",
            method,
            params,
        };

        let mut req = self.http.post(&self.config.rpc_url).json(&body);
        if let Some((user, pass)) = &self.config.rpc_auth {
            req = req.basic_auth(user, Some(pass));
        }

        let resp = req
            .send()
            .await
            .map_err(|e| Error::Rpc(format!("RPC HTTP: {e}")))?;

        let status = resp.status();
        let body: JsonRpcResponse<T> = resp
            .json()
            .await
            .map_err(|e| Error::Rpc(format!("RPC JSON decode: {e}")))?;

        if let Some(err) = body.error {
            return Err(Error::Rpc(format!(
                "bitcoind {} returned code {}: {}",
                method, err.code, err.message
            )));
        }
        body.result.ok_or_else(|| {
            Error::Rpc(format!(
                "bitcoind {method} returned no result (status {status})"
            ))
        })
    }
}

#[async_trait]
impl BtcChain for BitcoinCoreRpc {
    async fn broadcast(&self, tx_hex: &str) -> Result<Txid> {
        // `sendrawtransaction` returns the txid as a hex string.
        let txid_hex: String = self
            .call("sendrawtransaction", serde_json::json!([tx_hex]))
            .await?;
        Txid::from_hex(&txid_hex)
    }

    async fn wait_for_confirmations(
        &self,
        txid: &Txid,
        min_confirmations: u32,
        timeout: Duration,
    ) -> Result<()> {
        let deadline = Instant::now() + timeout;
        loop {
            // `getrawtransaction <txid> true` returns a JSON object
            // including `confirmations` (omitted for unconfirmed tx,
            // so we treat the missing field as 0).
            let txid_hex = txid.to_hex();
            let info: serde_json::Value = match self
                .call("getrawtransaction", serde_json::json!([txid_hex, true]))
                .await
            {
                Ok(v) => v,
                Err(_) => {
                    // Tx may not be in the mempool/chain yet; keep
                    // polling until the deadline. Don't surface
                    // every transient lookup failure.
                    serde_json::Value::Null
                }
            };
            let confirmations = info
                .get("confirmations")
                .and_then(|v| v.as_u64())
                .unwrap_or(0) as u32;
            if confirmations >= min_confirmations {
                return Ok(());
            }
            if Instant::now() >= deadline {
                return Err(Error::Timeout {
                    stage: "btc.wait_for_confirmations",
                });
            }
            sleep(self.poll_interval).await;
        }
    }

    async fn get_block_count(&self) -> Result<u64> {
        self.call("getblockcount", serde_json::json!([])).await
    }
}

// â”€â”€ JSON-RPC wire types â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

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

// â”€â”€ Mock implementation for tests â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

/// In-memory `BtcChain` implementation used by unit tests. Models a
/// regtest-like environment: broadcast adds a tx to a "mempool", a
/// test can call [`MockBtcChain::mine_blocks`] to mature transactions
/// to a given confirmation depth.
#[derive(Default)]
pub struct MockBtcChain {
    inner: Mutex<MockInner>,
}

#[derive(Default)]
struct MockInner {
    /// txid -> confirmation depth (0 means in mempool only)
    txs: HashMap<Txid, u32>,
    /// Pretend tip height; incremented by mine_blocks.
    tip: u64,
}

impl MockBtcChain {
    pub fn new() -> Self {
        Self::default()
    }

    /// Mine `n` blocks, incrementing the confirmation depth of every
    /// previously-broadcast tx by `n`.
    pub fn mine_blocks(&self, n: u32) {
        let mut g = self.inner.lock().unwrap();
        g.tip = g.tip.saturating_add(n as u64);
        for depth in g.txs.values_mut() {
            *depth = depth.saturating_add(n);
        }
    }

    /// Compute a deterministic txid from the tx hex bytes. Hash with
    /// the same SHA-256 the rest of the crate uses; tests don't care
    /// that it isn't the real Bitcoin double-SHA256.
    fn deterministic_txid(tx_hex: &str) -> Txid {
        use sha2::{Digest, Sha256};
        let mut h = Sha256::new();
        h.update(tx_hex.as_bytes());
        Txid(h.finalize().into())
    }
}

#[async_trait]
impl BtcChain for MockBtcChain {
    async fn broadcast(&self, tx_hex: &str) -> Result<Txid> {
        let txid = Self::deterministic_txid(tx_hex);
        let mut g = self.inner.lock().unwrap();
        // Re-broadcast of the same tx is idempotent (matches
        // bitcoind's "transaction already in block chain" tolerance).
        g.txs.entry(txid).or_insert(0);
        Ok(txid)
    }

    async fn wait_for_confirmations(
        &self,
        txid: &Txid,
        min_confirmations: u32,
        timeout: Duration,
    ) -> Result<()> {
        let deadline = Instant::now() + timeout;
        loop {
            let depth = {
                let g = self.inner.lock().unwrap();
                g.txs.get(txid).copied().unwrap_or(u32::MAX) // MAX = "never seen"
            };
            if depth != u32::MAX && depth >= min_confirmations {
                return Ok(());
            }
            if Instant::now() >= deadline {
                return Err(Error::Timeout {
                    stage: "mock.wait_for_confirmations",
                });
            }
            // 10ms polling so tests run fast; the production
            // `BitcoinCoreRpc` uses 10s by default.
            sleep(Duration::from_millis(10)).await;
        }
    }

    async fn get_block_count(&self) -> Result<u64> {
        let g = self.inner.lock().unwrap();
        Ok(g.tip)
    }
}

// â”€â”€ Lock-transaction construction â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
//
// `build_lock_tx` constructs the *unsigned* Bitcoin tx that Bob
// broadcasts to lock his BTC. The witness is left empty â€” Bob's
// wallet signs it before broadcast. Why split: the swap coordinator
// owns the protocol but not the keys; the wallet owns the keys but
// not the protocol. Composing an unsigned tx here lets the wallet
// stay the only thing that ever sees private material.
//
// Output shape: a single P2TR (Taproot, BIP-341) output whose
// internal key is the adaptor-bound spending key â€” i.e. the
// x-only pubkey that Alice will claim against using her adaptor-
// decrypted signature. The refund branch (script-path with CSV
// timeout) is NOT included in this slice; the swap protocol
// currently relies on the cross-curve adaptor binding for safety,
// not on a script-path refund. A separate `build_refund_tx` slice
// covers that path.
//
// Coin selection is the caller's job â€” they pass the UTXOs they
// want to spend, the total funding value must cover
// `lock_amount_sats + fee_sats`, and any excess flows to
// `change_address`. We refuse dust outputs (sub-330-sat change)
// â€” let the caller adjust the fee instead of silently producing a
// non-relayable tx.

/// A UTXO funding the lock transaction. Caller selects these from
/// Bob's wallet via the BTC RPC client (the wallet's
/// `listunspent` is the natural source).
#[derive(Clone, Debug)]
pub struct FundingUtxo {
    /// The transaction that created this UTXO.
    pub txid: Txid,
    /// The output index within that transaction.
    pub vout: u32,
    /// Value in satoshis. Used for the input-vs-output balance check
    /// before signing; the actual on-chain value comes from the
    /// previous tx and is enforced by Bitcoin consensus.
    pub value_sats: u64,
}

/// Optional script-path refund branch in a Taproot lock output.
///
/// When the lock includes a refund branch, the output is a P2TR
/// with a single-leaf script tree. Two spend paths exist:
///
/// - **Key-path (happy path).** Alice claims using her adaptor-
///   decrypted signature against the *tweaked* output key
///   `Q = K + tweakÂ·G` where `tweak = TaggedHash("TapTweak",
///   K.x || merkle_root)`. The signer must hold a secret `q` such
///   that `qÂ·G = Q`; helpers like [`tweaked_claim_secret`] do the
///   tweak math.
/// - **Script-path (refund / unhappy path).** After `csv_blocks`
///   blocks have passed (BIP-68 / BIP-112), Bob can spend via the
///   script-path: reveal the CSV refund script + a witness signature
///   under `bob_pubkey`. See [`build_refund_tx`].
///
/// Without a refund branch, the lock output is key-path-only and
/// the funds become **permanently unspendable** if Alice never
/// claims. Production callers should always set this.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RefundBranch {
    /// Bob's x-only Schnorr pubkey for the refund spend signature.
    pub bob_pubkey: [u8; 32],
    /// CSV timeout in blocks. The lock tx confirms at some height
    /// H; the refund tx can only confirm at height H + csv_blocks
    /// or later. BIP-68 caps the blocks-relative form at
    /// `u16::MAX` (~1.2 years at 10-minute blocks); we mirror that
    /// type to make the cap a compile-time guarantee.
    pub csv_blocks: u16,
}

/// All inputs `build_lock_tx` needs beyond the static `BtcConfig`.
#[derive(Clone, Debug)]
pub struct LockTxRequest {
    /// UTXOs being spent to fund the lock. Sum must be at least
    /// `lock_amount_sats + fee_sats`.
    pub utxos: Vec<FundingUtxo>,
    /// Amount being locked, in satoshis. Becomes the P2TR output's
    /// value.
    pub lock_amount_sats: u64,
    /// 32-byte x-only Taproot internal key. This is the
    /// adaptor-bound key the swap protocol agreed on out-of-band
    /// (typically Alice's claim key combined with the adaptor
    /// point `T`). When [`refund_branch`] is `Some`, the actual
    /// spending key Bitcoin consensus enforces is the *tweaked*
    /// form `Q = K + TaggedHash("TapTweak", K.x || merkle_root)Â·G`.
    ///
    /// [`refund_branch`]: Self::refund_branch
    pub adaptor_internal_key: [u8; 32],
    /// Bech32m change address (Bob's). Must parse for the network
    /// in `BtcConfig`. If change after fee is below
    /// [`DUST_THRESHOLD_SATS`], construction fails â€” adjust fee
    /// rather than emit a dust output.
    pub change_address: String,
    /// Absolute fee in satoshis. Caller computes this from a fee
    /// estimate; the swap crate doesn't pick it.
    pub fee_sats: u64,
    /// `nLockTime` value. `0` for immediate broadcast; non-zero to
    /// require the tx to confirm at or after a specific height.
    pub locktime: u32,
    /// Optional script-path refund branch. **Always set this in
    /// production** â€” without it, the lock funds are permanently
    /// stranded if Alice never claims. `None` is supported only for
    /// the simplest happy-path tests and for protocols that
    /// arrange refund through a separate pre-signed cancel tx.
    pub refund_branch: Option<RefundBranch>,
}

/// Minimum value for a non-dust P2TR output. Bitcoin Core's policy:
/// 330 sats for a Taproot output (3Ã— the standard relay-fee floor
/// for a typical witness size). Below this and the tx won't relay.
pub const DUST_THRESHOLD_SATS: u64 = 330;

/// Construct the unsigned Bitcoin lock transaction.
///
/// Returns the consensus-serialized tx bytes â€” exactly what
/// `BitcoinCoreRpc::broadcast` expects after hex encoding, once the
/// wallet has signed each input.
///
/// Errors surface as `Error::Verification` for protocol-level
/// problems (bad network, malformed pubkey, insufficient funding,
/// dust change). HTTP / RPC problems can't happen here â€” this is a
/// pure construction function.
pub fn build_lock_tx(config: &BtcConfig, request: &LockTxRequest) -> Result<Vec<u8>> {
    use bitcoin::{
        absolute::LockTime, transaction::Version, Address, Amount, Network, OutPoint, Sequence,
        Transaction, TxIn, TxOut, Witness, XOnlyPublicKey,
    };
    use std::str::FromStr;

    // â”€â”€ Parse + validate inputs â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    let network = match config.network.as_str() {
        "mainnet" => Network::Bitcoin,
        "testnet" => Network::Testnet,
        "regtest" => Network::Regtest,
        "signet" => Network::Signet,
        _ => {
            return Err(Error::Verification(
                "BtcConfig.network must be mainnet/testnet/regtest/signet",
            ));
        }
    };

    if request.utxos.is_empty() {
        return Err(Error::Verification("LockTxRequest.utxos must be non-empty"));
    }
    if request.lock_amount_sats < DUST_THRESHOLD_SATS {
        return Err(Error::Verification(
            "lock_amount_sats is below the 330-sat P2TR dust threshold",
        ));
    }

    let total_input: u64 = request
        .utxos
        .iter()
        .try_fold(0u64, |acc, u| acc.checked_add(u.value_sats))
        .ok_or(Error::Verification("input value sum overflowed u64"))?;
    let total_required = request
        .lock_amount_sats
        .checked_add(request.fee_sats)
        .ok_or(Error::Verification("lock_amount + fee overflowed u64"))?;
    if total_input < total_required {
        return Err(Error::Verification(
            "funding UTXOs do not cover lock_amount + fee",
        ));
    }
    let change_sats = total_input - total_required;

    let internal_key = XOnlyPublicKey::from_slice(&request.adaptor_internal_key)
        .map_err(|_| Error::Verification("adaptor_internal_key is not a valid x-only pubkey"))?;

    let change_address: Address = Address::from_str(&request.change_address)
        .map_err(|_| Error::Verification("change_address parse failed"))?
        .require_network(network)
        .map_err(|_| Error::Verification("change_address network mismatch with BtcConfig"))?;

    // â”€â”€ Construct inputs â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    // Sequence::ENABLE_RBF_NO_LOCKTIME (=0xfffffffd) opts the tx
    // into BIP-125 RBF â€” useful if the initial fee turns out to be
    // too low. For atomic swaps the wallet may override this; the
    // important thing is that we don't set MAX (which would disable
    // both RBF and any future nLockTime).
    let tx_inputs: Vec<TxIn> = request
        .utxos
        .iter()
        .map(|u| {
            let prev_txid = bitcoin::Txid::from_raw_hash(
                bitcoin::hashes::Hash::from_byte_array(u.txid.0),
            );
            TxIn {
                previous_output: OutPoint {
                    txid: prev_txid,
                    vout: u.vout,
                },
                script_sig: Default::default(), // empty â€” wallet fills witness
                sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
                witness: Witness::new(),
            }
        })
        .collect();

    // â”€â”€ Construct outputs â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    // P2TR â€” key-path-only when refund_branch is None; with a
    // single-leaf script tree (CSV refund) when refund_branch is
    // Some. The merkle_root flows through to the output key tweak
    // per BIP-341.
    let secp = bitcoin::secp256k1::Secp256k1::verification_only();
    let lock_script = match &request.refund_branch {
        None => bitcoin::ScriptBuf::new_p2tr(&secp, internal_key, None),
        Some(branch) => {
            let merkle_root = refund_script_merkle_root(branch)?;
            bitcoin::ScriptBuf::new_p2tr(&secp, internal_key, Some(merkle_root))
        }
    };
    let lock_output = TxOut {
        value: Amount::from_sat(request.lock_amount_sats),
        script_pubkey: lock_script,
    };

    let mut outputs = vec![lock_output];
    if change_sats > 0 {
        if change_sats < DUST_THRESHOLD_SATS {
            return Err(Error::Verification(
                "change after fee is below dust threshold â€” adjust fee_sats",
            ));
        }
        outputs.push(TxOut {
            value: Amount::from_sat(change_sats),
            script_pubkey: change_address.script_pubkey(),
        });
    }

    // â”€â”€ Assemble the transaction â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    let tx = Transaction {
        // BIP-68 / BIP-112 require version 2 transactions for the
        // sequence-based locks the refund branch will eventually
        // need; using v2 here keeps the lock tx and a future refund
        // tx consistent.
        version: Version::TWO,
        lock_time: LockTime::from_consensus(request.locktime),
        input: tx_inputs,
        output: outputs,
    };

    // â”€â”€ Serialize and return â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    Ok(bitcoin::consensus::encode::serialize(&tx))
}

// â”€â”€ Claim-transaction construction â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
//
// The claim tx is the one Alice broadcasts to spend the lock UTXO
// after the swap completes. It uses BIP-341 key-path spending: a
// single 64-byte Schnorr signature in the witness, no script-path
// reveal. The signature is the **adaptor-decrypted** sig that
// [`crate::adaptor::decrypt_btc_adaptor`] produces â€” i.e. the
// pre-sig Bob handed Alice, combined with Alice's secret `t`.
//
// Critical sequencing: a Schnorr sig commits to the sighash of the
// **specific** tx being signed. That means Alice and Bob must agree
// on the claim tx structure BEFORE Bob creates the adaptor pre-sig.
// The API splits at the sighash boundary:
//
//   1. Alice fills out a [`ClaimTxBase`] with everything except the
//      signature.
//   2. [`claim_sighash`] returns the 32-byte BIP-341 sighash both
//      parties will sign over.
//   3. Bob creates an adaptor pre-sig via
//      [`crate::adaptor::create_pre_sig_bip340`] over that sighash.
//   4. Alice waits for the lock to confirm.
//   5. Alice decrypts the pre-sig with her secret `t` via
//      [`crate::adaptor::decrypt_btc_adaptor`], getting a real
//      64-byte Schnorr sig over the same sighash.
//   6. Alice calls [`build_claim_tx`] with the base + the signature
//      to get the broadcastable tx bytes.

/// Everything needed to construct Alice's claim tx, except the
/// signature itself. Used in two phases: first to compute the
/// sighash Bob's pre-sig commits to, then to assemble the
/// broadcastable tx after the adaptor is decrypted.
#[derive(Clone, Debug)]
pub struct ClaimTxBase {
    /// The lock tx's txid.
    pub lock_txid: Txid,
    /// The lock UTXO's output index (typically 0 â€” the P2TR lock
    /// output is the first output of `build_lock_tx`).
    pub lock_vout: u32,
    /// The lock UTXO's value in sats. Needed for BIP-341 sighash
    /// (the v0 segwit sighash includes the spent amount).
    pub lock_value_sats: u64,
    /// The 32-byte x-only Taproot **internal** key the lock was
    /// bound to (NOT the tweaked output key). Must match what was
    /// passed to `build_lock_tx`. The prev scriptPubkey is
    /// reconstructed from this + `refund_branch` so the sighash is
    /// computed against the same bytes Bitcoin consensus sees.
    pub lock_internal_key: [u8; 32],
    /// The refund branch the lock was built with â€” `None` if the
    /// lock was key-path-only. When `Some`, the lock's output key
    /// is the *tweaked* form of `lock_internal_key`, and the
    /// signature attached by [`build_claim_tx`] must be produced by
    /// a secret tweaked via [`tweaked_claim_secret`].
    pub refund_branch: Option<RefundBranch>,
    /// Alice's destination address. P2PKH, P2WPKH, or P2TR are all
    /// supported; address must parse for `BtcConfig.network`.
    pub dest_address: String,
    /// Fee in sats. Output value = lock_value - fee.
    pub fee_sats: u64,
}

/// Compute the BIP-341 sighash that Bob's adaptor pre-sig must
/// commit to.
///
/// This is the value Bob hashes into the adaptor's challenge â€” it
/// binds the pre-sig to this specific claim tx, so Alice can't
/// adapt-and-broadcast a different tx than the one Bob expected.
/// SIGHASH_DEFAULT (BIP-341 default sighash type) is used; the
/// resulting signature is 64 bytes, not 65.
pub fn claim_sighash(config: &BtcConfig, base: &ClaimTxBase) -> Result<[u8; 32]> {
    let (tx, prevout) = build_claim_tx_internal(config, base)?;
    let mut cache = bitcoin::sighash::SighashCache::new(&tx);
    let sighash = cache
        .taproot_key_spend_signature_hash(
            0, // single-input tx
            &bitcoin::sighash::Prevouts::All(&[prevout]),
            bitcoin::sighash::TapSighashType::Default,
        )
        .map_err(|_| Error::Verification("BIP-341 sighash compute failed"))?;
    Ok(*sighash.as_ref())
}

/// Assemble the broadcastable claim tx by attaching the adaptor-
/// decrypted Schnorr signature to the witness.
///
/// `signature` must be the 64-byte BIP-340 signature produced by
/// [`crate::adaptor::decrypt_btc_adaptor`]. The function performs
/// **full BIP-340 verification** against the claim's sighash and
/// the lock's internal key before assembling the witness â€” a
/// malformed or wrong-message signature is rejected at construction
/// time with a clear error, instead of producing a tx that bitcoind
/// will reject with "non-mandatory-script-verify-flag" on broadcast.
///
/// The verification is the same one a full node will run; doing it
/// here adds one schnorr-verify (~50 Âµs) but catches the entire
/// class of "caller wired the wrong sig" integration bugs early.
pub fn build_claim_tx(
    config: &BtcConfig,
    base: &ClaimTxBase,
    signature: &[u8; 64],
) -> Result<Vec<u8>> {
    let (mut tx, prevout) = build_claim_tx_internal(config, base)?;

    // BIP-340 verify the signature against the sighash + the lock's
    // internal key. Anything that fails here would also fail at
    // broadcast time; surfacing it now gives a clean error path.
    let parsed_sig = bitcoin::secp256k1::schnorr::Signature::from_slice(signature)
        .map_err(|_| Error::Verification("claim signature is not 64 bytes / invalid wire shape"))?;
    let mut cache = bitcoin::sighash::SighashCache::new(&tx);
    let sighash = cache
        .taproot_key_spend_signature_hash(
            0,
            &bitcoin::sighash::Prevouts::All(&[prevout]),
            bitcoin::sighash::TapSighashType::Default,
        )
        .map_err(|_| Error::Verification("BIP-341 sighash compute failed"))?;
    let msg = bitcoin::secp256k1::Message::from_digest(*sighash.as_ref());
    let internal_key = bitcoin::secp256k1::XOnlyPublicKey::from_slice(&base.lock_internal_key)
        .map_err(|_| Error::Verification("lock_internal_key is not a valid x-only pubkey"))?;
    let secp = bitcoin::secp256k1::Secp256k1::verification_only();

    // Bitcoin consensus verifies the witness sig against the OUTPUT
    // key the scriptPubkey commits to. For a key-path P2TR with a
    // script tree, that's the TWEAKED form of the internal key, not
    // the internal key itself. Fold in the merkle root via the same
    // TaprootBuilder path the lock used, so the tweaked key we
    // verify against is bit-for-bit identical to what bitcoind sees.
    let output_key = match base.refund_branch.as_ref() {
        None => internal_key,
        Some(branch) => {
            let script = refund_script(branch)?;
            let spend_info = bitcoin::taproot::TaprootBuilder::new()
                .add_leaf(0, script)
                .map_err(|_| Error::Verification("taproot add_leaf for verify failed"))?
                .finalize(&secp, internal_key)
                .map_err(|_| Error::Verification("taproot finalize for verify failed"))?;
            spend_info.output_key().to_x_only_public_key()
        }
    };

    secp.verify_schnorr(&parsed_sig, &msg, &output_key)
        .map_err(|_| {
            Error::Verification(
                "claim signature does not verify under BIP-340 against the sighash + lock key â€” \
                 wrong adaptor secret, wrong pre-sig, or wrong base parameters",
            )
        })?;

    // BIP-341 key-path spend: witness is a single 64-byte signature.
    let mut witness = bitcoin::Witness::new();
    witness.push(signature);
    tx.input[0].witness = witness;

    Ok(bitcoin::consensus::encode::serialize(&tx))
}

/// Verify that signed transaction bytes encode exactly the claim
/// described by `base`.
///
/// Rebuilding through [`build_claim_tx`] keeps broadcast-time
/// validation aligned with the transaction and signature checks used
/// during construction. This rejects alternate inputs, outputs,
/// transaction metadata, or witness shapes before a caller advances
/// swap state for an unrelated broadcast.
pub fn validate_claim_tx(
    config: &BtcConfig,
    base: &ClaimTxBase,
    tx_bytes: &[u8],
) -> Result<()> {
    let tx: bitcoin::Transaction = bitcoin::consensus::encode::deserialize(tx_bytes)
        .map_err(|_| Error::Verification("claim transaction consensus decode failed"))?;
    if tx.input.len() != 1 {
        return Err(Error::Verification(
            "claim transaction must contain exactly one input",
        ));
    }
    let input = &tx.input[0];
    if input.witness.len() != 1 {
        return Err(Error::Verification(
            "claim transaction must contain one key-path witness element",
        ));
    }
    let signature: &[u8; 64] = input
        .witness
        .iter()
        .next()
        .and_then(|bytes| bytes.try_into().ok())
        .ok_or(Error::Verification(
            "claim transaction witness must contain a 64-byte BIP-340 signature",
        ))?;

    let expected = build_claim_tx(config, base, signature)?;
    if expected != tx_bytes {
        return Err(Error::Verification(
            "claim transaction does not match the expected swap claim",
        ));
    }
    Ok(())
}

/// Construct the unsigned claim transaction and the corresponding
/// previous-output (`TxOut`) record. Internal helper shared by
/// `claim_sighash` (needs the tx to hash over) and `build_claim_tx`
/// (needs the tx to attach the witness to).
fn build_claim_tx_internal(
    config: &BtcConfig,
    base: &ClaimTxBase,
) -> Result<(bitcoin::Transaction, bitcoin::TxOut)> {
    use bitcoin::{
        absolute::LockTime, transaction::Version, Address, Amount, Network, OutPoint, Sequence,
        Transaction, TxIn, TxOut, Witness, XOnlyPublicKey,
    };
    use std::str::FromStr;

    let network = match config.network.as_str() {
        "mainnet" => Network::Bitcoin,
        "testnet" => Network::Testnet,
        "regtest" => Network::Regtest,
        "signet" => Network::Signet,
        _ => {
            return Err(Error::Verification(
                "BtcConfig.network must be mainnet/testnet/regtest/signet",
            ));
        }
    };

    if base.fee_sats >= base.lock_value_sats {
        return Err(Error::Verification(
            "fee_sats >= lock_value_sats â€” claim would have no output",
        ));
    }
    let claim_value = base.lock_value_sats - base.fee_sats;
    if claim_value < DUST_THRESHOLD_SATS {
        return Err(Error::Verification(
            "claim output is below dust threshold â€” reduce fee_sats",
        ));
    }

    let dest_address: Address = Address::from_str(&base.dest_address)
        .map_err(|_| Error::Verification("dest_address parse failed"))?
        .require_network(network)
        .map_err(|_| Error::Verification("dest_address network mismatch with BtcConfig"))?;

    let internal_key = XOnlyPublicKey::from_slice(&base.lock_internal_key)
        .map_err(|_| Error::Verification("lock_internal_key is not a valid x-only pubkey"))?;

    // Reconstruct the prev scriptPubkey to feed BIP-341 sighash.
    // Must exactly match what `build_lock_tx` put on-chain â€” the
    // `lock_prev_script` helper folds in the merkle root if the
    // lock had a refund branch.
    let prev_script = lock_prev_script(internal_key, base.refund_branch.as_ref())?;
    let prevout = TxOut {
        value: Amount::from_sat(base.lock_value_sats),
        script_pubkey: prev_script,
    };

    let prev_txid = bitcoin::Txid::from_raw_hash(
        bitcoin::hashes::Hash::from_byte_array(base.lock_txid.0),
    );
    let input = TxIn {
        previous_output: OutPoint {
            txid: prev_txid,
            vout: base.lock_vout,
        },
        script_sig: Default::default(),
        sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
        // Witness gets filled by `build_claim_tx`; left empty
        // here so the sighash is computed over the unsigned form.
        witness: Witness::new(),
    };

    let output = TxOut {
        value: Amount::from_sat(claim_value),
        script_pubkey: dest_address.script_pubkey(),
    };

    let tx = Transaction {
        version: Version::TWO,
        lock_time: LockTime::ZERO,
        input: vec![input],
        output: vec![output],
    };
    Ok((tx, prevout))
}

// â”€â”€ Taproot script-tree helpers â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

/// Construct the CSV refund script for a given refund branch.
///
/// Bitcoin script bytes:
/// ```text
///   <csv_blocks>            // CScriptNum push (1-3 bytes)
///   OP_CSV       (0xb2)     // BIP-112 OP_CHECKSEQUENCEVERIFY
///   OP_DROP      (0x75)
///   <bob_pubkey>            // OP_PUSHBYTES_32 + 32 bytes
///   OP_CHECKSIG  (0xac)
/// ```
///
/// Spendable only when the spending tx's input sequence is at least
/// `csv_blocks` (BIP-68 blocks-relative form) and carries a valid
/// Schnorr signature under `bob_pubkey` over the script-path
/// sighash.
fn refund_script(branch: &RefundBranch) -> Result<bitcoin::ScriptBuf> {
    use bitcoin::opcodes::all::{OP_CHECKSIG, OP_CSV, OP_DROP};
    use bitcoin::script::Builder;

    let bob_xonly = bitcoin::secp256k1::XOnlyPublicKey::from_slice(&branch.bob_pubkey)
        .map_err(|_| Error::Verification("refund branch bob_pubkey is not a valid x-only pubkey"))?;

    Ok(Builder::new()
        .push_int(branch.csv_blocks as i64)
        .push_opcode(OP_CSV)
        .push_opcode(OP_DROP)
        .push_x_only_key(&bob_xonly)
        .push_opcode(OP_CHECKSIG)
        .into_script())
}

/// Compute the BIP-341 merkle root for a lock with a single-leaf
/// refund script tree. Used both during lock construction (to derive
/// the output key) and during claim/refund construction (to
/// reconstruct the same scriptPubkey for sighash computation).
fn refund_script_merkle_root(
    branch: &RefundBranch,
) -> Result<bitcoin::taproot::TapNodeHash> {
    let script = refund_script(branch)?;
    let leaf_hash =
        bitcoin::taproot::TapLeafHash::from_script(&script, bitcoin::taproot::LeafVersion::TapScript);
    // For a single-leaf tree the merkle root *is* the leaf hash â€”
    // there's no sibling to combine with.
    Ok(bitcoin::taproot::TapNodeHash::from(leaf_hash))
}

/// Reconstruct the lock UTXO's `scriptPubkey` for sighash purposes.
/// Mirrors the construction in `build_lock_tx` so the two paths
/// stay byte-identical.
fn lock_prev_script(
    internal_key: bitcoin::secp256k1::XOnlyPublicKey,
    refund_branch: Option<&RefundBranch>,
) -> Result<bitcoin::ScriptBuf> {
    let secp = bitcoin::secp256k1::Secp256k1::verification_only();
    let merkle_root = match refund_branch {
        Some(b) => Some(refund_script_merkle_root(b)?),
        None => None,
    };
    Ok(bitcoin::ScriptBuf::new_p2tr(&secp, internal_key, merkle_root))
}

/// Tweak Alice's claim secret for a lock that has a script tree.
///
/// BIP-341 key-path spending against a P2TR output with merkle
/// root `m` requires the signer to use `q = (Â±d + tweak) mod n`
/// where `d` is the original internal-key secret, `tweak =
/// TaggedHash("TapTweak", X.x || m)`, and the `Â±` sign matches the
/// parity-of-d rule BIP-340 already imposes. This helper does the
/// arithmetic and returns the tweaked secret in big-endian 32-byte
/// form.
///
/// Returns the tweaked secret bytes. `secret` is the original
/// internal-key secret (the one whose pubkey equals
/// `refund_branch`'s associated internal key in the lock the
/// caller built). `refund_branch` is the same branch that was
/// passed to `build_lock_tx`.
pub fn tweaked_claim_secret(
    secret: &[u8; 32],
    refund_branch: Option<&RefundBranch>,
) -> Result<[u8; 32]> {
    use bitcoin::secp256k1::{Keypair, Secp256k1, SecretKey};

    let secp = Secp256k1::new();
    let sk = SecretKey::from_slice(secret)
        .map_err(|_| Error::Verification("claim secret is not a valid secp256k1 scalar"))?;

    let kp = Keypair::from_secret_key(&secp, &sk);
    let merkle_root = match refund_branch {
        Some(b) => Some(refund_script_merkle_root(b)?),
        None => None,
    };
    let tweaked = kp.add_xonly_tweak(&secp, &untweaked_to_taptweak(&kp, merkle_root)?)
        .map_err(|_| Error::Verification("Taproot tweak addition failed"))?;
    Ok(tweaked.secret_key().secret_bytes())
}

/// Compute the BIP-341 TapTweak scalar for an internal key + merkle root.
fn untweaked_to_taptweak(
    kp: &bitcoin::secp256k1::Keypair,
    merkle_root: Option<bitcoin::taproot::TapNodeHash>,
) -> Result<bitcoin::secp256k1::Scalar> {
    use bitcoin::hashes::Hash;
    let (xonly, _parity) = kp.x_only_public_key();
    let tweak = bitcoin::taproot::TapTweakHash::from_key_and_tweak(xonly, merkle_root);
    bitcoin::secp256k1::Scalar::from_be_bytes(tweak.to_byte_array())
        .map_err(|_| Error::Verification("TapTweak hash outside scalar range â€” vanishingly improbable"))
}

// â”€â”€ Refund-transaction construction â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
//
// The refund tx is Bob's escape valve: if Alice never claims by the
// CSV deadline, Bob spends the lock output via the script-path. The
// script-path spend reveals the refund script + a control block; the
// witness signature is a plain BIP-340 sig under Bob's pubkey over
// the script-path sighash.
//
// Sequence requirements (BIP-68): the spending input's `nSequence`
// must encode at least `csv_blocks` blocks-relative timeout â€” bit
// 22 (the type-bit) must be 0 (blocks not 512-second units), and
// the lower 16 bits hold the value.

/// Everything needed to construct Bob's refund tx, except the
/// signature itself. Same two-phase pattern as
/// [`ClaimTxBase`] / [`claim_sighash`] / [`build_claim_tx`].
#[derive(Clone, Debug)]
pub struct RefundTxBase {
    /// The lock tx's txid.
    pub lock_txid: Txid,
    /// The lock UTXO's output index.
    pub lock_vout: u32,
    /// The lock UTXO's value in sats.
    pub lock_value_sats: u64,
    /// The lock's untweaked internal key. Must match what was
    /// passed to [`build_lock_tx`].
    pub lock_internal_key: [u8; 32],
    /// The refund branch the lock was built with. Used to
    /// reconstruct the script + control block.
    pub refund_branch: RefundBranch,
    /// Bob's destination address (where the refund flows).
    pub dest_address: String,
    /// Fee in sats. Output value = lock_value - fee.
    pub fee_sats: u64,
}

/// Compute the BIP-341 script-path sighash that Bob's refund
/// signature must commit to.
pub fn refund_sighash(config: &BtcConfig, base: &RefundTxBase) -> Result<[u8; 32]> {
    let (tx, prevout, script) = build_refund_tx_internal(config, base)?;
    let mut cache = bitcoin::sighash::SighashCache::new(&tx);
    let leaf_hash = bitcoin::taproot::TapLeafHash::from_script(
        &script,
        bitcoin::taproot::LeafVersion::TapScript,
    );
    let sighash = cache
        .taproot_script_spend_signature_hash(
            0,
            &bitcoin::sighash::Prevouts::All(&[prevout]),
            leaf_hash,
            bitcoin::sighash::TapSighashType::Default,
        )
        .map_err(|_| Error::Verification("BIP-341 script-path sighash compute failed"))?;
    Ok(*sighash.as_ref())
}

/// Assemble the broadcastable refund tx by attaching Bob's
/// signature, the revealed refund script, and the control block.
///
/// The signature must verify under `refund_branch.bob_pubkey`
/// against the script-path sighash â€” full BIP-340 verification
/// runs here, matching the claim-tx pattern. A mismatch surfaces
/// as `Error::Verification` rather than a downstream broadcast
/// rejection.
pub fn build_refund_tx(
    config: &BtcConfig,
    base: &RefundTxBase,
    signature: &[u8; 64],
) -> Result<Vec<u8>> {
    let (mut tx, prevout, script) = build_refund_tx_internal(config, base)?;

    // Recompute sighash + verify the supplied signature against
    // Bob's pubkey.
    let parsed_sig = bitcoin::secp256k1::schnorr::Signature::from_slice(signature)
        .map_err(|_| Error::Verification("refund signature is not 64 bytes / invalid wire shape"))?;
    let bob_xonly = bitcoin::secp256k1::XOnlyPublicKey::from_slice(&base.refund_branch.bob_pubkey)
        .map_err(|_| Error::Verification("refund_branch.bob_pubkey invalid"))?;
    let mut cache = bitcoin::sighash::SighashCache::new(&tx);
    let leaf_hash = bitcoin::taproot::TapLeafHash::from_script(
        &script,
        bitcoin::taproot::LeafVersion::TapScript,
    );
    let sighash = cache
        .taproot_script_spend_signature_hash(
            0,
            &bitcoin::sighash::Prevouts::All(&[prevout]),
            leaf_hash,
            bitcoin::sighash::TapSighashType::Default,
        )
        .map_err(|_| Error::Verification("BIP-341 script-path sighash compute failed"))?;
    let msg = bitcoin::secp256k1::Message::from_digest(*sighash.as_ref());
    let secp = bitcoin::secp256k1::Secp256k1::verification_only();
    secp.verify_schnorr(&parsed_sig, &msg, &bob_xonly).map_err(|_| {
        Error::Verification(
            "refund signature does not verify under BIP-340 against the script-path \
             sighash + refund_branch.bob_pubkey",
        )
    })?;

    // â”€â”€ Compose the BIP-341 script-path witness â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    //
    //   witness stack:
    //     [0] = sig                                  // 64 bytes
    //     [1] = refund_script                        // CSV script bytes
    //     [2] = control_block                        // 33 bytes (single-leaf)
    //
    // The control block carries:
    //   1 byte  : leaf version | output-key parity
    //   32 bytes: internal key (x-only)
    //   0 bytes : merkle proof (empty for single-leaf tree)
    let internal_key = bitcoin::secp256k1::XOnlyPublicKey::from_slice(&base.lock_internal_key)
        .map_err(|_| Error::Verification("lock_internal_key invalid"))?;
    let merkle_root = refund_script_merkle_root(&base.refund_branch)?;
    let taproot_spend_info = bitcoin::taproot::TaprootBuilder::new()
        .add_leaf(0, script.clone())
        .map_err(|_| Error::Verification("taproot add_leaf failed"))?
        .finalize(&secp, internal_key)
        .map_err(|_| Error::Verification("taproot finalize failed"))?;
    debug_assert_eq!(
        taproot_spend_info.merkle_root(),
        Some(merkle_root),
        "TaprootBuilder must produce the same merkle root as refund_script_merkle_root"
    );
    let control_block = taproot_spend_info
        .control_block(&(script.clone(), bitcoin::taproot::LeafVersion::TapScript))
        .ok_or(Error::Verification("control block lookup failed"))?;

    let mut witness = bitcoin::Witness::new();
    witness.push(signature);
    witness.push(script.as_bytes());
    witness.push(control_block.serialize());
    tx.input[0].witness = witness;

    Ok(bitcoin::consensus::encode::serialize(&tx))
}

/// Construct the unsigned refund tx, its prevout, and the refund
/// script (needed for both sighash and final witness assembly).
fn build_refund_tx_internal(
    config: &BtcConfig,
    base: &RefundTxBase,
) -> Result<(bitcoin::Transaction, bitcoin::TxOut, bitcoin::ScriptBuf)> {
    use bitcoin::{
        absolute::LockTime, transaction::Version, Address, Amount, Network, OutPoint, Sequence,
        Transaction, TxIn, TxOut, Witness, XOnlyPublicKey,
    };
    use std::str::FromStr;

    let network = match config.network.as_str() {
        "mainnet" => Network::Bitcoin,
        "testnet" => Network::Testnet,
        "regtest" => Network::Regtest,
        "signet" => Network::Signet,
        _ => {
            return Err(Error::Verification(
                "BtcConfig.network must be mainnet/testnet/regtest/signet",
            ));
        }
    };

    if base.fee_sats >= base.lock_value_sats {
        return Err(Error::Verification(
            "fee_sats >= lock_value_sats â€” refund would have no output",
        ));
    }
    let refund_value = base.lock_value_sats - base.fee_sats;
    if refund_value < DUST_THRESHOLD_SATS {
        return Err(Error::Verification(
            "refund output is below dust threshold â€” reduce fee_sats",
        ));
    }

    let dest_address: Address = Address::from_str(&base.dest_address)
        .map_err(|_| Error::Verification("refund dest_address parse failed"))?
        .require_network(network)
        .map_err(|_| Error::Verification("refund dest_address network mismatch with BtcConfig"))?;

    let internal_key = XOnlyPublicKey::from_slice(&base.lock_internal_key)
        .map_err(|_| Error::Verification("lock_internal_key invalid"))?;

    let script = refund_script(&base.refund_branch)?;
    let prev_script = lock_prev_script(internal_key, Some(&base.refund_branch))?;
    let prevout = TxOut {
        value: Amount::from_sat(base.lock_value_sats),
        script_pubkey: prev_script,
    };

    let prev_txid = bitcoin::Txid::from_raw_hash(
        bitcoin::hashes::Hash::from_byte_array(base.lock_txid.0),
    );

    // BIP-68: blocks-relative sequence. Lower 16 bits hold the
    // value; type bit (bit 22) = 0 for blocks, 1 for 512-second
    // units. `csv_blocks` is u16 so it fits the lower 16 directly.
    // BIP-112's OP_CSV in the script then checks `nSequence >=
    // <csv_blocks>` (with matching type bits) â€” both sides must
    // agree on the type, which is "blocks" here.
    let sequence = Sequence::from_height(base.refund_branch.csv_blocks);

    let input = TxIn {
        previous_output: OutPoint {
            txid: prev_txid,
            vout: base.lock_vout,
        },
        script_sig: Default::default(),
        sequence,
        witness: Witness::new(),
    };

    let output = TxOut {
        value: Amount::from_sat(refund_value),
        script_pubkey: dest_address.script_pubkey(),
    };

    let tx = Transaction {
        version: Version::TWO,
        lock_time: LockTime::ZERO,
        input: vec![input],
        output: vec![output],
    };
    Ok((tx, prevout, script))
}

/// Watch the BTC chain for a given txid + N confirmations. Sync
/// wrapper around [`BtcChain::wait_for_confirmations`] for callers
/// that aren't async-aware yet.
///
/// Spawns a fresh `tokio::runtime::Runtime` per call â€” fine for one-
/// off CLI use, but the swap state machine should call the async
/// method on a [`BtcChain`] directly.
pub fn wait_for_confirmations(
    config: &BtcConfig,
    txid: &str,
    confirmations: u32,
    timeout_secs: u64,
) -> Result<()> {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| Error::Rpc(format!("tokio runtime: {e}")))?;
    let chain = BitcoinCoreRpc::new(config.clone())?;
    let txid = Txid::from_hex(txid)?;
    rt.block_on(chain.wait_for_confirmations(&txid, confirmations, Duration::from_secs(timeout_secs)))
}

/// Broadcast a signed transaction to the Bitcoin network. Returns
/// the txid on success. Sync wrapper around [`BtcChain::broadcast`].
pub fn broadcast(config: &BtcConfig, tx_bytes: &[u8]) -> Result<String> {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| Error::Rpc(format!("tokio runtime: {e}")))?;
    let chain = BitcoinCoreRpc::new(config.clone())?;
    let tx_hex = hex::encode(tx_bytes);
    let txid = rt.block_on(chain.broadcast(&tx_hex))?;
    Ok(txid.to_hex())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn btc_config_constructor_rejects_bad_network() {
        let cfg = BtcConfig {
            network: "fakenet".into(),
            rpc_url: "http://127.0.0.1:8332".into(),
            rpc_auth: None,
        };
        assert!(BitcoinCoreRpc::new(cfg).is_err());
    }

    #[test]
    fn btc_config_constructor_rejects_bad_url() {
        let cfg = BtcConfig {
            network: "regtest".into(),
            rpc_url: "not a url".into(),
            rpc_auth: None,
        };
        assert!(BitcoinCoreRpc::new(cfg).is_err());
    }

    #[test]
    fn btc_config_constructor_accepts_regtest() {
        let cfg = BtcConfig {
            network: "regtest".into(),
            rpc_url: "http://127.0.0.1:18443".into(),
            rpc_auth: Some(("user".into(), "pass".into())),
        };
        BitcoinCoreRpc::new(cfg).expect("regtest config must parse");
    }

    #[test]
    fn txid_round_trip_hex() {
        let bytes = [0xab; 32];
        let txid = Txid(bytes);
        let hex_str = txid.to_hex();
        assert_eq!(hex_str.len(), 64);
        let parsed = Txid::from_hex(&hex_str).unwrap();
        assert_eq!(parsed, txid);
    }

    #[test]
    fn txid_rejects_short_hex() {
        assert!(Txid::from_hex("abcd").is_err());
    }

    #[tokio::test]
    async fn mock_chain_broadcast_then_wait() {
        let chain = MockBtcChain::new();
        let tx_hex = "deadbeef";

        let txid = chain.broadcast(tx_hex).await.unwrap();
        // Same tx hex â†’ same txid (idempotent).
        let txid2 = chain.broadcast(tx_hex).await.unwrap();
        assert_eq!(txid, txid2);

        // No confirmations yet â€” wait should time out fast.
        let r = chain
            .wait_for_confirmations(&txid, 3, Duration::from_millis(50))
            .await;
        assert!(matches!(r, Err(Error::Timeout { .. })));

        // Mine 3 blocks; wait now returns immediately.
        chain.mine_blocks(3);
        chain
            .wait_for_confirmations(&txid, 3, Duration::from_millis(500))
            .await
            .expect("3 confirmations should now be visible");
    }

    #[tokio::test]
    async fn mock_chain_unknown_txid_times_out() {
        let chain = MockBtcChain::new();
        let unknown = Txid([0x55; 32]);
        let r = chain
            .wait_for_confirmations(&unknown, 1, Duration::from_millis(30))
            .await;
        assert!(matches!(r, Err(Error::Timeout { .. })));
    }

    #[tokio::test]
    async fn mock_chain_get_block_count_increments() {
        let chain = MockBtcChain::new();
        assert_eq!(chain.get_block_count().await.unwrap(), 0);
        chain.mine_blocks(5);
        assert_eq!(chain.get_block_count().await.unwrap(), 5);
    }

    /// Timing test for `MockBtcChain::wait_for_confirmations`. Catches:
    ///   - btc.rs:364  `let deadline = Instant::now() + timeout` flipped to `-`
    ///   - btc.rs:373  `if Instant::now() >= deadline` flipped to `<`
    /// Both mutations would still return Err Timeout but the call would
    /// return immediately (no waiting), so we assert the elapsed time is
    /// at least most of the requested timeout.
    #[tokio::test]
    async fn mock_chain_wait_respects_timeout_deadline() {
        let chain = MockBtcChain::new();
        let unknown = Txid([0x66; 32]);
        let timeout = Duration::from_millis(150);
        let start = Instant::now();
        let r = chain
            .wait_for_confirmations(&unknown, 1, timeout)
            .await;
        let elapsed = start.elapsed();
        assert!(matches!(r, Err(Error::Timeout { .. })));
        // Real impl waits ~150ms; both mutations exit immediately (<5ms).
        // Threshold 100ms gives generous headroom for scheduling jitter.
        assert!(
            elapsed >= Duration::from_millis(100),
            "wait_for_confirmations returned in {elapsed:?} \u{2014} expected ~{timeout:?}. \
             The deadline arithmetic or `>=` check appears mutated."
        );
    }

    /// Sync wrapper `wait_for_confirmations` at btc.rs:1218 (lines 1224-1230)
    /// must propagate errors from the inner steps (tokio runtime, RPC client,
    /// or txid parse). A mutation that replaces the whole function body with
    /// `Ok(())` would return Ok regardless of input. Feed a deliberately
    /// invalid txid and assert Err.
    #[test]
    fn sync_wait_for_confirmations_propagates_invalid_txid() {
        let cfg = BtcConfig {
            network: "regtest".into(),
            rpc_url: "http://127.0.0.1:18443".into(),
            rpc_auth: None,
        };
        let r = wait_for_confirmations(&cfg, "not-hex-too-short", 1, 1);
        assert!(r.is_err(),
            "wait_for_confirmations must reject invalid txid (function body must not be replaced with Ok(()))"
        );
    }

    /// Sync wrapper `broadcast` at btc.rs:1235 (lines 1236-1244) must
    /// propagate errors from the inner RPC call. A mutation that replaces
    /// the whole function body with `Ok(String::new())` or `Ok("xyzzy".into())`
    /// would return Ok without ever making the RPC call. Point at an
    /// unreachable port and assert Err.
    #[test]
    fn sync_broadcast_propagates_rpc_connect_failure() {
        let cfg = BtcConfig {
            network: "regtest".into(),
            // Port 1 is a reserved system port that no server should be bound to.
            rpc_url: "http://127.0.0.1:1".into(),
            rpc_auth: None,
        };
        let r = broadcast(&cfg, &[0u8; 10]);
        match r {
            Err(_) => { /* expected */ }
            Ok(s) => panic!(
                "broadcast returned Ok({s:?}) on unreachable RPC URL \u{2014} function body appears mutated"
            ),
        }
    }

    // â”€â”€ BitcoinCoreRpc wiremock-backed tests â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    //
    // These tests stand up a wiremock HTTP server, point the
    // BitcoinCoreRpc client at it, and exercise the actual function
    // bodies (not the MockBtcChain in-memory shortcut). They catch
    // mutations the in-memory mock can't reach.

    use wiremock::matchers::{body_string_contains, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    /// Build a BitcoinCoreRpc client pointed at the wiremock server with
    /// a sub-second poll interval (default is 10s, too slow for tests).
    fn rpc_against(mock_url: &str) -> BitcoinCoreRpc {
        BitcoinCoreRpc::new(BtcConfig {
            network: "regtest".into(),
            rpc_url: mock_url.into(),
            rpc_auth: None,
        })
        .expect("BitcoinCoreRpc::new")
        .with_poll_interval(Duration::from_millis(10))
    }

    /// `get_block_count` returns the exact `result` value from the
    /// `getblockcount` JSON-RPC response. Catches mutations at
    /// btc.rs:276 that replace the body with `Ok(0)` or `Ok(1)`.
    #[tokio::test]
    async fn rpc_get_block_count_returns_response_value() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/"))
            .and(body_string_contains("getblockcount"))
            .respond_with(ResponseTemplate::new(200).set_body_json(
                serde_json::json!({"result": 12345u64, "error": null, "id": "coincync-swap"}),
            ))
            .mount(&server)
            .await;

        let rpc = rpc_against(&server.uri());
        let h = rpc.get_block_count().await.expect("get_block_count");
        assert_eq!(h, 12345, "get_block_count must return the exact RPC value");
    }

    /// `wait_for_confirmations` returns Ok when `getrawtransaction`
    /// reports `confirmations` >= the threshold. Catches the `>=` check
    /// at btc.rs:263 — if flipped to `<`, the loop never returns Ok.
    #[tokio::test]
    async fn rpc_wait_for_confirmations_returns_ok_when_threshold_met() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(body_string_contains("getrawtransaction"))
            .respond_with(ResponseTemplate::new(200).set_body_json(
                serde_json::json!({"result": {"confirmations": 5u64}, "error": null, "id": "coincync-swap"}),
            ))
            .mount(&server)
            .await;

        let rpc = rpc_against(&server.uri());
        let txid = Txid([0x42; 32]);
        rpc.wait_for_confirmations(&txid, 3, Duration::from_millis(200))
            .await
            .expect("5 confirmations >= 3 threshold should return Ok");
    }

    /// `wait_for_confirmations` waits for the full timeout when
    /// confirmations never reach the threshold. Catches:
    ///   - btc.rs:241 (`+` flipped to `-` in deadline computation)
    ///   - btc.rs:266 (`>=` flipped to `<` in the deadline check)
    /// Both mutations would still return Err Timeout but immediately.
    #[tokio::test]
    async fn rpc_wait_for_confirmations_respects_timeout_deadline() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(body_string_contains("getrawtransaction"))
            .respond_with(ResponseTemplate::new(200).set_body_json(
                serde_json::json!({"result": {"confirmations": 0u64}, "error": null, "id": "coincync-swap"}),
            ))
            .mount(&server)
            .await;

        let rpc = rpc_against(&server.uri());
        let txid = Txid([0x43; 32]);
        let timeout = Duration::from_millis(150);
        let start = Instant::now();
        let r = rpc
            .wait_for_confirmations(&txid, 1, timeout)
            .await;
        let elapsed = start.elapsed();
        assert!(matches!(r, Err(Error::Timeout { .. })));
        assert!(
            elapsed >= Duration::from_millis(100),
            "rpc wait_for_confirmations returned in {elapsed:?} \u{2014} expected ~{timeout:?}"
        );
    }

    // â”€â”€ build_lock_tx (real impl) â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    /// Helper: produce a valid 32-byte x-only Taproot internal key
    /// for tests by deriving from a deterministic seed. The actual
    /// swap protocol generates this from Alice's claim key combined
    /// with the adaptor point; tests don't need that whole dance to
    /// exercise the tx-construction path.
    fn test_internal_key(seed: u8) -> [u8; 32] {
        use bitcoin::secp256k1::{Secp256k1, SecretKey};
        let secp = Secp256k1::new();
        let mut sk_bytes = [seed; 32];
        sk_bytes[0] = sk_bytes[0].saturating_add(1); // avoid the all-zero scalar
        let sk = SecretKey::from_slice(&sk_bytes).unwrap();
        let (xonly, _parity) = sk.x_only_public_key(&secp);
        xonly.serialize()
    }

    /// Helper: a regtest bech32m address derived from a known x-only
    /// key. P2TR addresses on regtest start with `bcrt1p...`.
    fn test_change_address(seed: u8) -> String {
        use bitcoin::{secp256k1::Secp256k1, Address, Network, XOnlyPublicKey};
        let secp = Secp256k1::verification_only();
        let xonly = XOnlyPublicKey::from_slice(&test_internal_key(seed)).unwrap();
        Address::p2tr(&secp, xonly, None, Network::Regtest).to_string()
    }

    fn standard_regtest_config() -> BtcConfig {
        BtcConfig {
            network: "regtest".into(),
            rpc_url: "http://127.0.0.1:18443".into(),
            rpc_auth: None,
        }
    }

    #[test]
    fn build_lock_tx_constructs_serializable_p2tr_tx() {
        let cfg = standard_regtest_config();
        let request = LockTxRequest {
            utxos: vec![FundingUtxo {
                txid: Txid([0xaa; 32]),
                vout: 0,
                value_sats: 1_000_000,
            }],
            lock_amount_sats: 500_000,
            adaptor_internal_key: test_internal_key(1),
            change_address: test_change_address(2),
            fee_sats: 1_000,
            locktime: 0,
            refund_branch: None,
        };

        let bytes = build_lock_tx(&cfg, &request).expect("build_lock_tx");

        // Must round-trip through the bitcoin crate's consensus codec
        // â€” that's the property that says "this is broadcastable".
        let parsed: bitcoin::Transaction =
            bitcoin::consensus::encode::deserialize(&bytes).expect("consensus decode");

        // v2 for BIP-68 compatibility.
        assert_eq!(parsed.version, bitcoin::transaction::Version::TWO);

        // One input matching the funding UTXO.
        assert_eq!(parsed.input.len(), 1);
        assert_eq!(parsed.input[0].previous_output.vout, 0);

        // Two outputs: lock + change.
        assert_eq!(parsed.output.len(), 2);
        let lock_out = &parsed.output[0];
        assert_eq!(lock_out.value.to_sat(), 500_000);
        // P2TR scriptPubkey is `OP_PUSHNUM_1 OP_PUSHBYTES_32 <32B>` (34 bytes).
        assert_eq!(lock_out.script_pubkey.len(), 34);
        assert!(lock_out.script_pubkey.is_p2tr());

        let change_out = &parsed.output[1];
        // change = input - lock - fee = 1_000_000 - 500_000 - 1_000 = 499_000
        assert_eq!(change_out.value.to_sat(), 499_000);
    }

    #[test]
    fn build_lock_tx_omits_change_output_when_zero_change() {
        let cfg = standard_regtest_config();
        let request = LockTxRequest {
            utxos: vec![FundingUtxo {
                txid: Txid([0xbb; 32]),
                vout: 1,
                value_sats: 100_000,
            }],
            // input == lock + fee â†’ no change.
            lock_amount_sats: 99_000,
            adaptor_internal_key: test_internal_key(3),
            change_address: test_change_address(4),
            fee_sats: 1_000,
            locktime: 0,
            refund_branch: None,
        };
        let bytes = build_lock_tx(&cfg, &request).unwrap();
        let parsed: bitcoin::Transaction =
            bitcoin::consensus::encode::deserialize(&bytes).unwrap();
        assert_eq!(parsed.output.len(), 1, "no change output expected");
        assert_eq!(parsed.output[0].value.to_sat(), 99_000);
    }

    #[test]
    fn build_lock_tx_rejects_insufficient_funding() {
        let cfg = standard_regtest_config();
        let request = LockTxRequest {
            utxos: vec![FundingUtxo {
                txid: Txid([0xcc; 32]),
                vout: 0,
                value_sats: 1_000,
            }],
            lock_amount_sats: 500_000,
            adaptor_internal_key: test_internal_key(5),
            change_address: test_change_address(6),
            fee_sats: 100,
            locktime: 0,
            refund_branch: None,
        };
        let r = build_lock_tx(&cfg, &request);
        assert!(matches!(r, Err(Error::Verification(_))));
    }

    #[test]
    fn build_lock_tx_rejects_dust_change() {
        let cfg = standard_regtest_config();
        let request = LockTxRequest {
            utxos: vec![FundingUtxo {
                txid: Txid([0xdd; 32]),
                vout: 0,
                value_sats: 100_300,
            }],
            // change = 100_300 - 100_000 - 100 = 200 sats (dust)
            lock_amount_sats: 100_000,
            adaptor_internal_key: test_internal_key(7),
            change_address: test_change_address(8),
            fee_sats: 100,
            locktime: 0,
            refund_branch: None,
        };
        let r = build_lock_tx(&cfg, &request);
        assert!(matches!(r, Err(Error::Verification(_))));
    }

    #[test]
    fn build_lock_tx_rejects_dust_lock_amount() {
        let cfg = standard_regtest_config();
        let request = LockTxRequest {
            utxos: vec![FundingUtxo {
                txid: Txid([0xee; 32]),
                vout: 0,
                value_sats: 10_000,
            }],
            lock_amount_sats: 100, // way under dust
            adaptor_internal_key: test_internal_key(9),
            change_address: test_change_address(10),
            fee_sats: 1_000,
            locktime: 0,
            refund_branch: None,
        };
        let r = build_lock_tx(&cfg, &request);
        assert!(matches!(r, Err(Error::Verification(_))));
    }

    #[test]
    fn build_lock_tx_rejects_mismatched_network_change_address() {
        // Regtest config but a mainnet address â€” must reject so a
        // chain-confusion attack can't slip past.
        let cfg = standard_regtest_config();
        // A known mainnet P2TR address (bc1p prefix).
        let mainnet_addr =
            "bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqzk5jj0";
        let request = LockTxRequest {
            utxos: vec![FundingUtxo {
                txid: Txid([0x11; 32]),
                vout: 0,
                value_sats: 1_000_000,
            }],
            lock_amount_sats: 500_000,
            adaptor_internal_key: test_internal_key(11),
            change_address: mainnet_addr.into(),
            fee_sats: 1_000,
            locktime: 0,
            refund_branch: None,
        };
        let r = build_lock_tx(&cfg, &request);
        assert!(matches!(r, Err(Error::Verification(_))));
    }

    #[test]
    fn build_lock_tx_rejects_empty_utxos() {
        let cfg = standard_regtest_config();
        let request = LockTxRequest {
            utxos: vec![],
            lock_amount_sats: 1000,
            adaptor_internal_key: test_internal_key(12),
            change_address: test_change_address(13),
            fee_sats: 1000,
            locktime: 0,
            refund_branch: None,
        };
        let r = build_lock_tx(&cfg, &request);
        assert!(matches!(r, Err(Error::Verification(_))));
    }

    #[test]
    fn build_lock_tx_input_sum_overflow_rejected() {
        let cfg = standard_regtest_config();
        let request = LockTxRequest {
            utxos: vec![
                FundingUtxo {
                    txid: Txid([0x22; 32]),
                    vout: 0,
                    value_sats: u64::MAX,
                },
                FundingUtxo {
                    txid: Txid([0x33; 32]),
                    vout: 1,
                    value_sats: 1,
                },
            ],
            lock_amount_sats: 500_000,
            adaptor_internal_key: test_internal_key(14),
            change_address: test_change_address(15),
            fee_sats: 1_000,
            locktime: 0,
            refund_branch: None,
        };
        let r = build_lock_tx(&cfg, &request);
        assert!(matches!(r, Err(Error::Verification(_))));
    }

    #[test]
    fn build_lock_tx_multiple_utxos_compose() {
        let cfg = standard_regtest_config();
        let request = LockTxRequest {
            utxos: vec![
                FundingUtxo {
                    txid: Txid([0x44; 32]),
                    vout: 0,
                    value_sats: 600_000,
                },
                FundingUtxo {
                    txid: Txid([0x55; 32]),
                    vout: 7,
                    value_sats: 400_000,
                },
            ],
            lock_amount_sats: 900_000,
            adaptor_internal_key: test_internal_key(16),
            change_address: test_change_address(17),
            fee_sats: 1_000,
            locktime: 0,
            refund_branch: None,
        };
        let bytes = build_lock_tx(&cfg, &request).unwrap();
        let parsed: bitcoin::Transaction =
            bitcoin::consensus::encode::deserialize(&bytes).unwrap();
        assert_eq!(parsed.input.len(), 2);
        // Verify the second input vout is preserved.
        assert_eq!(parsed.input[1].previous_output.vout, 7);
        // Outputs: lock (900_000) + change (99_000)
        assert_eq!(parsed.output.len(), 2);
        assert_eq!(parsed.output[1].value.to_sat(), 99_000);
    }

    /// Every supported network string ("mainnet"/"testnet"/"regtest"/"signet")
    /// must be matched by the network-selection block in build_lock_tx. A
    /// deletion of any one arm makes the function bail with the
    /// "BtcConfig.network must be..." error before it even reaches the
    /// require_network check. This test exercises each arm by supplying
    /// a regtest-formatted change_address against a non-regtest network:
    /// if the network arm is present, the function gets past the match
    /// and fails at require_network with a "change_address network
    /// mismatch" error; if the arm is deleted, the function fails at the
    /// match block instead, which the assertion catches.
    #[test]
    fn build_lock_tx_accepts_every_supported_network_string() {
        for net in ["mainnet", "testnet", "regtest", "signet"] {
            let cfg = BtcConfig {
                network: net.into(),
                rpc_url: "http://127.0.0.1:18443".into(),
                rpc_auth: None,
            };
            let request = LockTxRequest {
                utxos: vec![FundingUtxo {
                    txid: Txid([0xaa; 32]),
                    vout: 0,
                    value_sats: 1_000_000,
                }],
                lock_amount_sats: 500_000,
                adaptor_internal_key: test_internal_key(1),
                change_address: test_change_address(2), // regtest-formatted
                fee_sats: 1_000,
                locktime: 0,
                refund_branch: None,
            };
            let result = build_lock_tx(&cfg, &request);
            match (net, result) {
                ("regtest", Ok(_)) => { /* regtest network + regtest addr: full success */ }
                ("regtest", Err(e)) => {
                    panic!("build_lock_tx unexpectedly failed for regtest: {e:?}")
                }
                (_, Ok(_)) => panic!(
                    "build_lock_tx unexpectedly succeeded with {net} network + regtest address"
                ),
                (_, Err(Error::Verification(msg))) => {
                    assert!(
                        !msg.contains("BtcConfig.network must be"),
                        "build_lock_tx errored at network match for '{net}' \u{2014} arm appears to be missing. \
                         Got: {msg}"
                    );
                    // Should be the require_network error, not the match error.
                    assert!(
                        msg.contains("change_address") || msg.contains("network mismatch"),
                        "expected require_network error for '{net}', got: {msg}"
                    );
                }
                (_, Err(e)) => panic!("unexpected error variant for '{net}': {e:?}"),
            }
        }
    }

    /// Boundary test for the dust-threshold check in `build_lock_tx` at
    /// btc.rs:536 (`if request.lock_amount_sats < DUST_THRESHOLD_SATS`).
    /// A mutation that flips `<` to `<=` would make the equal-to-threshold
    /// case fail. The test feeds exactly DUST_THRESHOLD_SATS (330) and
    /// asserts the construction succeeds.
    #[test]
    fn build_lock_tx_accepts_lock_amount_exactly_at_dust_threshold() {
        let cfg = standard_regtest_config();
        let request = LockTxRequest {
            utxos: vec![FundingUtxo {
                txid: Txid([0xaa; 32]),
                vout: 0,
                value_sats: 10_000, // enough to cover lock + fee + change
            }],
            lock_amount_sats: DUST_THRESHOLD_SATS, // boundary: == 330
            adaptor_internal_key: test_internal_key(1),
            change_address: test_change_address(2),
            fee_sats: 1_000,
            locktime: 0,
            refund_branch: None,
        };
        // Pass: lock_amount = 330, fee = 1_000, change = 10_000 - 330 - 1_000 = 8_670 (well above dust).
        build_lock_tx(&cfg, &request)
            .expect("lock_amount_sats == DUST_THRESHOLD_SATS must be accepted (`<`, not `<=`)");
    }

    /// Boundary test for the change-output dust check at btc.rs:611
    /// (`if change_sats < DUST_THRESHOLD_SATS`). Set up so change is
    /// exactly DUST_THRESHOLD_SATS; a mutation that flips `<` to `<=`
    /// would erroneously reject this case.
    #[test]
    fn build_lock_tx_accepts_change_exactly_at_dust_threshold() {
        let cfg = standard_regtest_config();
        // utxo = lock + dust + fee → change = utxo - lock - fee = 330
        let lock_amount = 5_000u64;
        let fee = 1_000u64;
        let change_target = DUST_THRESHOLD_SATS;
        let request = LockTxRequest {
            utxos: vec![FundingUtxo {
                txid: Txid([0xab; 32]),
                vout: 0,
                value_sats: lock_amount + change_target + fee,
            }],
            lock_amount_sats: lock_amount,
            adaptor_internal_key: test_internal_key(1),
            change_address: test_change_address(2),
            fee_sats: fee,
            locktime: 0,
            refund_branch: None,
        };
        build_lock_tx(&cfg, &request)
            .expect("change_sats == DUST_THRESHOLD_SATS must be accepted (`<`, not `<=`)");
    }

    /// `refund_script` must produce a non-empty script. A mutation that
    /// replaces the function body with `Ok(Default::default())` returns
    /// an empty ScriptBuf, which this test catches (real impl produces
    /// at least 35 bytes: CSV + DROP + 32-byte xonly key + CHECKSIG).
    #[test]
    fn refund_script_returns_non_empty_script() {
        let branch = RefundBranch {
            bob_pubkey: test_internal_key(60),
            csv_blocks: 144,
        };
        let script = refund_script(&branch).expect("refund_script");
        assert!(
            !script.is_empty(),
            "refund_script returned an empty (Default) ScriptBuf"
        );
        // Sanity: must contain at least the bob_pubkey bytes (32 of them).
        // Real script is ~35 bytes; Default is 0 bytes.
        assert!(
            script.len() >= 32,
            "refund_script returned {} bytes, expected >= 32",
            script.len()
        );
    }

    // â”€â”€ Claim tx â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    fn standard_claim_base() -> ClaimTxBase {
        ClaimTxBase {
            lock_txid: Txid([0xab; 32]),
            lock_vout: 0,
            lock_value_sats: 500_000,
            lock_internal_key: test_internal_key(50),
            refund_branch: None,
            dest_address: test_change_address(51),
            fee_sats: 1_000,
        }
    }

    /// Helper for tests that need a real, BIP-340-valid claim sig.
    /// Returns the signature, the internal key it was signed under,
    /// and the base it was signed for. The signature commits to the
    /// sighash of the base; mutating the base afterward invalidates
    /// the sig (which is precisely the property `build_claim_tx`
    /// now verifies).
    fn sign_real_claim(
        cfg: &BtcConfig,
        lock_txid: Txid,
        lock_value: u64,
        fee: u64,
        dest_seed: u8,
        sk_byte: u8,
    ) -> ([u8; 64], [u8; 32], ClaimTxBase) {
        use bitcoin::secp256k1::{Keypair, Secp256k1, SecretKey};
        let secp = Secp256k1::new();
        let mut sk_bytes = [sk_byte; 32];
        sk_bytes[31] = sk_bytes[31].saturating_add(1); // ensure non-zero
        let sk = SecretKey::from_slice(&sk_bytes).unwrap();
        let kp = Keypair::from_secret_key(&secp, &sk);
        let (xonly, _parity) = kp.x_only_public_key();

        let base = ClaimTxBase {
            lock_txid,
            lock_vout: 0,
            lock_value_sats: lock_value,
            lock_internal_key: xonly.serialize(),
            refund_branch: None,
            dest_address: test_change_address(dest_seed),
            fee_sats: fee,
        };

        let sighash = claim_sighash(cfg, &base).unwrap();
        let msg = bitcoin::secp256k1::Message::from_digest(sighash);
        // BIP-340 key-path spends require the signer to use the
        // even-y form of the secret. `Keypair::sign_schnorr` handles
        // the parity dance internally.
        let sig = secp.sign_schnorr_no_aux_rand(&msg, &kp);
        // `Signature::as_ref()` already returns `&[u8; 64]`, so a
        // simple deref-and-copy gives us the owned array.
        let sig_bytes: [u8; 64] = *sig.as_ref();
        (sig_bytes, xonly.serialize(), base)
    }

    #[test]
    fn build_claim_tx_constructs_witnessed_p2tr_spend() {
        let cfg = standard_regtest_config();
        let (sig, _xonly, base) = sign_real_claim(&cfg, Txid([0xab; 32]), 500_000, 1_000, 51, 0x70);

        let bytes = build_claim_tx(&cfg, &base, &sig).expect("build_claim_tx");
        let parsed: bitcoin::Transaction =
            bitcoin::consensus::encode::deserialize(&bytes).expect("consensus decode");

        // Single input, single output.
        assert_eq!(parsed.input.len(), 1);
        assert_eq!(parsed.output.len(), 1);

        // Output value = lock - fee.
        assert_eq!(parsed.output[0].value.to_sat(), 499_000);

        // Witness has one element = the 64-byte signature.
        assert_eq!(parsed.input[0].witness.len(), 1);
        let wit_bytes: &[u8] = parsed.input[0].witness.iter().next().unwrap();
        assert_eq!(wit_bytes, &sig[..]);
    }

    #[test]
    fn validate_claim_tx_accepts_exact_constructed_claim() {
        let cfg = standard_regtest_config();
        let (sig, _, base) =
            sign_real_claim(&cfg, Txid([0xbc; 32]), 500_000, 1_000, 52, 0x71);
        let bytes = build_claim_tx(&cfg, &base, &sig).unwrap();

        validate_claim_tx(&cfg, &base, &bytes).unwrap();
    }

    #[test]
    fn validate_claim_tx_rejects_different_lock_outpoint() {
        let cfg = standard_regtest_config();
        let (sig, _, base) =
            sign_real_claim(&cfg, Txid([0xbd; 32]), 500_000, 1_000, 53, 0x72);
        let bytes = build_claim_tx(&cfg, &base, &sig).unwrap();
        let mut tx: bitcoin::Transaction =
            bitcoin::consensus::encode::deserialize(&bytes).unwrap();
        tx.input[0].previous_output.vout += 1;
        let altered = bitcoin::consensus::encode::serialize(&tx);

        assert!(matches!(
            validate_claim_tx(&cfg, &base, &altered),
            Err(Error::Verification(_))
        ));
    }

    #[test]
    fn validate_claim_tx_rejects_different_claim_output() {
        let cfg = standard_regtest_config();
        let (sig, _, base) =
            sign_real_claim(&cfg, Txid([0xbe; 32]), 500_000, 1_000, 54, 0x73);
        let bytes = build_claim_tx(&cfg, &base, &sig).unwrap();
        let mut tx: bitcoin::Transaction =
            bitcoin::consensus::encode::deserialize(&bytes).unwrap();
        tx.output[0].value = bitcoin::Amount::from_sat(498_999);
        let altered = bitcoin::consensus::encode::serialize(&tx);

        assert!(matches!(
            validate_claim_tx(&cfg, &base, &altered),
            Err(Error::Verification(_))
        ));
    }

    #[test]
    fn validate_claim_tx_rejects_different_session_amount() {
        let cfg = standard_regtest_config();
        let (sig, _, base) =
            sign_real_claim(&cfg, Txid([0xbf; 32]), 500_000, 1_000, 55, 0x74);
        let bytes = build_claim_tx(&cfg, &base, &sig).unwrap();
        let mut expected = base.clone();
        expected.lock_value_sats += 1;

        assert!(matches!(
            validate_claim_tx(&cfg, &expected, &bytes),
            Err(Error::Verification(_))
        ));
    }

    #[test]
    fn build_claim_tx_rejects_signature_for_different_destination() {
        // The new full verification should catch the case where
        // someone produces a valid sig for one base then tries to
        // attach it to a base with a different destination â€” the
        // sighash changes, the sig no longer verifies.
        let cfg = standard_regtest_config();
        let (sig, _xonly, mut base) = sign_real_claim(&cfg, Txid([0xcd; 32]), 500_000, 1_000, 60, 0x80);

        // Tamper: redirect to a different destination.
        base.dest_address = test_change_address(61);

        let r = build_claim_tx(&cfg, &base, &sig);
        assert!(
            matches!(r, Err(Error::Verification(_))),
            "sig over original sighash must not verify against tampered base"
        );
    }

    #[test]
    fn claim_sighash_is_deterministic_for_a_given_base() {
        let cfg = standard_regtest_config();
        let base = standard_claim_base();
        let h1 = claim_sighash(&cfg, &base).unwrap();
        let h2 = claim_sighash(&cfg, &base).unwrap();
        assert_eq!(h1, h2, "sighash must be deterministic");
    }

    #[test]
    fn claim_sighash_changes_when_destination_changes() {
        let cfg = standard_regtest_config();
        let mut base = standard_claim_base();
        let h1 = claim_sighash(&cfg, &base).unwrap();
        base.dest_address = test_change_address(99);
        let h2 = claim_sighash(&cfg, &base).unwrap();
        assert_ne!(h1, h2, "different dest must produce different sighash");
    }

    #[test]
    fn claim_sighash_changes_when_fee_changes() {
        let cfg = standard_regtest_config();
        let mut base = standard_claim_base();
        let h1 = claim_sighash(&cfg, &base).unwrap();
        base.fee_sats = 2_000;
        let h2 = claim_sighash(&cfg, &base).unwrap();
        assert_ne!(h1, h2, "different fee changes output value â†’ different sighash");
    }

    #[test]
    fn build_claim_tx_rejects_malformed_signature() {
        let cfg = standard_regtest_config();
        let base = standard_claim_base();
        // All-zero is not a valid BIP-340 signature (r must be a
        // valid x-coordinate; r = 0 is the identity).
        let bad_sig = [0u8; 64];
        let r = build_claim_tx(&cfg, &base, &bad_sig);
        assert!(matches!(r, Err(Error::Verification(_))));
    }

    #[test]
    fn build_claim_tx_rejects_fee_exceeds_lock_value() {
        let cfg = standard_regtest_config();
        let mut base = standard_claim_base();
        base.fee_sats = base.lock_value_sats;
        let r = build_claim_tx(&cfg, &base, &[0xaa; 64]);
        assert!(matches!(r, Err(Error::Verification(_))));
    }

    #[test]
    fn build_claim_tx_rejects_dust_output() {
        let cfg = standard_regtest_config();
        let mut base = standard_claim_base();
        base.fee_sats = base.lock_value_sats - 100; // output = 100, below 330 dust
        let r = build_claim_tx(&cfg, &base, &[0xaa; 64]);
        assert!(matches!(r, Err(Error::Verification(_))));
    }

    #[test]
    fn build_claim_tx_rejects_mismatched_network_dest_address() {
        let cfg = standard_regtest_config();
        let mut base = standard_claim_base();
        base.dest_address = "bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqzk5jj0".into();
        let r = build_claim_tx(&cfg, &base, &[0xaa; 64]);
        assert!(matches!(r, Err(Error::Verification(_))));
    }

    /// Boundary test for btc.rs:825 (`if claim_value < DUST_THRESHOLD_SATS`).
    /// claim_value is computed as `lock_value_sats - fee_sats`. Choose
    /// the two so the result is exactly DUST_THRESHOLD_SATS. A mutation
    /// that flips `<` to `==` or `<` to `<=` rejects this case. We don't
    /// have a valid signature so the call ultimately fails — but the
    /// failure must NOT be the dust-threshold error.
    #[test]
    fn build_claim_tx_accepts_claim_value_exactly_at_dust_threshold() {
        let cfg = standard_regtest_config();
        let fee = 1_000u64;
        let lock_value = fee + DUST_THRESHOLD_SATS; // claim_value == 330 exactly
        let base = ClaimTxBase {
            lock_txid: Txid([0xa1; 32]),
            lock_vout: 0,
            lock_value_sats: lock_value,
            lock_internal_key: test_internal_key(50),
            refund_branch: None,
            dest_address: test_change_address(51),
            fee_sats: fee,
        };
        let r = build_claim_tx(&cfg, &base, &[0xaa; 64]); // bogus sig
        match r {
            Err(Error::Verification(msg)) => {
                assert!(
                    !msg.contains("dust threshold"),
                    "build_claim_tx erroneously rejected claim_value == DUST_THRESHOLD_SATS \
                     (the `<` check at btc.rs:825 must NOT trigger at equality). Error: {msg}"
                );
                // We expect signature verification to fail downstream.
            }
            Err(e) => panic!("unexpected error variant: {e:?}"),
            Ok(_) => panic!("bogus sig should have failed verification, but build_claim_tx returned Ok"),
        }
    }

    /// Mirror of `build_lock_tx_accepts_every_supported_network_string` —
    /// exercises every arm of the network match in `build_claim_tx_internal`.
    /// If any arm ("mainnet"/"testnet"/"regtest"/"signet") is deleted, the
    /// function bails at the match block before reaching require_network.
    #[test]
    fn build_claim_tx_accepts_every_supported_network_string() {
        for net in ["mainnet", "testnet", "regtest", "signet"] {
            let cfg = BtcConfig {
                network: net.into(),
                rpc_url: "http://127.0.0.1:18443".into(),
                rpc_auth: None,
            };
            // dest_address is a regtest-formatted address; for non-regtest
            // networks require_network rejects it, but only AFTER the match.
            let base = standard_claim_base();
            let r = build_claim_tx(&cfg, &base, &[0xaa; 64]);
            if net == "regtest" {
                // regtest + regtest addr advances past require_network and
                // fails downstream (signature verification with bogus sig).
                assert!(
                    r.is_err(),
                    "regtest case should fail signature verification, got Ok"
                );
            } else {
                match r {
                    Err(Error::Verification(msg)) => {
                        assert!(
                            !msg.contains("BtcConfig.network must be"),
                            "build_claim_tx errored at network match for '{net}' \u{2014} arm appears to be missing. Got: {msg}"
                        );
                    }
                    Err(e) => panic!("unexpected error variant for '{net}': {e:?}"),
                    Ok(_) => panic!(
                        "build_claim_tx unexpectedly succeeded with {net} network + regtest dest_address"
                    ),
                }
            }
        }
    }

    /// End-to-end: full adaptor â†’ sighash â†’ pre-sig â†’ decrypt â†’
    /// finalize â†’ broadcastable tx. This is the load-bearing test
    /// for the claim path; it proves the construction interoperates
    /// correctly with the cryptographic primitives that produce the
    /// signature, AND that the resulting witness verifies under
    /// Bitcoin's BIP-340 consensus verifier when evaluated against
    /// the prev scriptPubkey.
    #[test]
    fn end_to_end_claim_signature_verifies_under_bip340() {
        use crate::adaptor::{
            create_pre_sig_bip340, cync_adaptor_point, decrypt_btc_adaptor, AdaptorSecret,
        };
        use bitcoin::secp256k1::{PublicKey, Secp256k1, SecretKey};

        let cfg = standard_regtest_config();
        let secp = Secp256k1::new();

        // Alice's spend key. Use a fixed seed for determinism.
        let alice_sk_bytes = [
            0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a,
            0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a,
            0x5a, 0x5a, 0x5a, 0x01,
        ];
        let alice_sk = SecretKey::from_slice(&alice_sk_bytes).unwrap();

        // The adaptor secret `t` Alice owns. Must be a valid
        // Ristretto scalar for cross-curve binding; for the BTC
        // half alone the constraint is just "valid secp256k1".
        let t_bytes = [
            0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42,
            0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42,
            0x42, 0x42, 0x42, 0x02,
        ];
        let t_sk = SecretKey::from_slice(&t_bytes).unwrap();
        let adaptor_secret = AdaptorSecret::from_bytes(t_bytes).unwrap();
        let _ = cync_adaptor_point(&adaptor_secret); // silence unused-import warning
        let adaptor_pt = PublicKey::from_secret_key(&secp, &t_sk);

        // Lock the funds at Alice's pubkey (the simplest version of
        // the protocol where the lock's internal key is just Alice's
        // x-only pubkey â€” the adaptor binding happens inside the
        // signature, not inside the key derivation).
        let (alice_xonly, _parity) = alice_sk.x_only_public_key(&secp);

        let base = ClaimTxBase {
            lock_txid: Txid([0x77; 32]),
            lock_vout: 0,
            lock_value_sats: 500_000,
            lock_internal_key: alice_xonly.serialize(),
            refund_branch: None,
            dest_address: test_change_address(100),
            fee_sats: 1_000,
        };

        // 1. Compute the sighash both parties will sign over.
        let sighash = claim_sighash(&cfg, &base).expect("sighash");

        // 2. Bob (or Alice acting as the pre-signer in this single-
        //    actor test) creates an adaptor pre-sig over the sighash.
        let aux_rand = [0xa1; 32];
        let (pre_sig, signer_x) =
            create_pre_sig_bip340(&alice_sk, &sighash, &adaptor_pt, &aux_rand)
                .expect("pre-sig");

        // The pre-signer's x-only pubkey must match the lock's
        // internal key (this is how the verifier ties the witness
        // back to the lock script).
        assert_eq!(signer_x.serialize(), base.lock_internal_key);

        // 3. Alice decrypts the pre-sig with her secret `t`.
        let final_sig = decrypt_btc_adaptor(&pre_sig, &adaptor_secret, &adaptor_pt)
            .expect("decrypt");

        // 4. Alice finalizes the claim tx with the real signature.
        let tx_bytes = build_claim_tx(&cfg, &base, &final_sig).expect("finalize");

        // 5. Decode and run the BIP-340 verifier against the
        //    claim's sighash + Alice's x-only pubkey â€” the witness
        //    must verify as a real Schnorr sig that Bitcoin would
        //    accept.
        let parsed: bitcoin::Transaction =
            bitcoin::consensus::encode::deserialize(&tx_bytes).expect("decode");
        let wit_bytes: Vec<u8> = parsed.input[0].witness.iter().next().unwrap().to_vec();
        assert_eq!(wit_bytes.len(), 64, "witness must be a 64-byte BIP-340 sig");

        let sig = bitcoin::secp256k1::schnorr::Signature::from_slice(&wit_bytes).unwrap();
        let msg = bitcoin::secp256k1::Message::from_digest(sighash);
        secp.verify_schnorr(&sig, &msg, &alice_xonly).expect(
            "the witness signature must verify under BIP-340 against the lock's internal key + claim sighash",
        );
    }

    // ── Refund branch (lock with script tree + script-path spend) ──

    /// Build a `RefundBranch` from a known seed for tests.
    fn test_refund_branch(seed: u8, csv_blocks: u16) -> RefundBranch {
        RefundBranch {
            bob_pubkey: test_internal_key(seed),
            csv_blocks,
        }
    }

    #[test]
    fn build_lock_tx_with_refund_branch_produces_p2tr_with_merkle_root() {
        let cfg = standard_regtest_config();
        let internal = test_internal_key(40);
        let refund = test_refund_branch(41, 144);
        let request = LockTxRequest {
            utxos: vec![FundingUtxo {
                txid: Txid([0xa1; 32]),
                vout: 0,
                value_sats: 1_000_000,
            }],
            lock_amount_sats: 500_000,
            adaptor_internal_key: internal,
            change_address: test_change_address(42),
            fee_sats: 1_000,
            locktime: 0,
            refund_branch: Some(refund.clone()),
        };
        let bytes = build_lock_tx(&cfg, &request).expect("build_lock_tx");
        let parsed: bitcoin::Transaction =
            bitcoin::consensus::encode::deserialize(&bytes).expect("decode");

        // Output 0 must be P2TR (34-byte witness program) — visually
        // identical to the no-refund case from outside, but the
        // 32-byte program is now the *tweaked* output key, not the
        // raw internal key.
        let lock_out = &parsed.output[0];
        assert!(lock_out.script_pubkey.is_p2tr());

        // Programmatic check: reconstruct the merkle root + tweaked
        // output key locally and assert the on-chain scriptPubkey
        // matches what `lock_prev_script` would compute.
        let internal_xonly =
            bitcoin::secp256k1::XOnlyPublicKey::from_slice(&internal).unwrap();
        let expected = lock_prev_script(internal_xonly, Some(&refund)).unwrap();
        assert_eq!(lock_out.script_pubkey, expected);
    }

    #[test]
    fn claim_path_works_against_lock_with_refund_branch() {
        // The claim still verifies when the lock has a refund
        // branch — the signer just has to use the tweaked secret.
        use bitcoin::secp256k1::{Keypair, Secp256k1, SecretKey};

        let cfg = standard_regtest_config();
        let secp = Secp256k1::new();

        // Alice's raw secret + internal key.
        let mut sk_bytes = [0x33u8; 32];
        sk_bytes[31] = 0x01;
        let sk = SecretKey::from_slice(&sk_bytes).unwrap();
        let kp = Keypair::from_secret_key(&secp, &sk);
        let (alice_xonly, _parity) = kp.x_only_public_key();

        let refund = test_refund_branch(99, 144);

        let base = ClaimTxBase {
            lock_txid: Txid([0xdd; 32]),
            lock_vout: 0,
            lock_value_sats: 500_000,
            lock_internal_key: alice_xonly.serialize(),
            refund_branch: Some(refund.clone()),
            dest_address: test_change_address(101),
            fee_sats: 1_000,
        };

        // Compute the sighash via the public API (which now folds
        // in the merkle root via lock_prev_script).
        let sighash = claim_sighash(&cfg, &base).unwrap();

        // The signer uses the *tweaked* secret per BIP-341 key-path
        // rules. tweaked_claim_secret does the arithmetic.
        let tweaked_bytes = tweaked_claim_secret(&sk_bytes, Some(&refund)).unwrap();
        let tweaked_sk = SecretKey::from_slice(&tweaked_bytes).unwrap();
        let tweaked_kp = Keypair::from_secret_key(&secp, &tweaked_sk);

        // Sign with the tweaked keypair.
        let msg = bitcoin::secp256k1::Message::from_digest(sighash);
        let sig = secp.sign_schnorr_no_aux_rand(&msg, &tweaked_kp);
        let sig_bytes: [u8; 64] = *sig.as_ref();

        // build_claim_tx's internal verification must accept this.
        let tx_bytes = build_claim_tx(&cfg, &base, &sig_bytes)
            .expect("claim with tweaked sig must verify against tweaked output key");

        // Final sanity: the on-chain witness signature also verifies
        // against the lock's tweaked output key per the BIP-340
        // consensus rules.
        let parsed: bitcoin::Transaction =
            bitcoin::consensus::encode::deserialize(&tx_bytes).unwrap();
        let wit_bytes: Vec<u8> = parsed.input[0].witness.iter().next().unwrap().to_vec();
        let parsed_sig =
            bitcoin::secp256k1::schnorr::Signature::from_slice(&wit_bytes).unwrap();
        let (tweaked_xonly, _) = tweaked_kp.x_only_public_key();
        secp.verify_schnorr(&parsed_sig, &msg, &tweaked_xonly)
            .expect("witness must verify under the tweaked output key");
    }

    #[test]
    fn refund_path_end_to_end_constructs_and_verifies() {
        // Build a lock with a refund branch, then construct Bob's
        // refund tx with a real signature and verify the witness.
        // This is the load-bearing test for the refund path.
        use bitcoin::secp256k1::{Keypair, Secp256k1, SecretKey};

        let cfg = standard_regtest_config();
        let secp = Secp256k1::new();

        // Bob's refund key.
        let mut bob_sk_bytes = [0x77u8; 32];
        bob_sk_bytes[31] = 0x07;
        let bob_sk = SecretKey::from_slice(&bob_sk_bytes).unwrap();
        let bob_kp = Keypair::from_secret_key(&secp, &bob_sk);
        let (bob_xonly, _parity) = bob_kp.x_only_public_key();

        // Alice's (adaptor-bound) internal key.
        let alice_internal = test_internal_key(45);

        let refund = RefundBranch {
            bob_pubkey: bob_xonly.serialize(),
            csv_blocks: 144,
        };

        // Build the refund tx base — assumes the lock has confirmed
        // and the CSV has elapsed.
        let base = RefundTxBase {
            lock_txid: Txid([0xfe; 32]),
            lock_vout: 0,
            lock_value_sats: 500_000,
            lock_internal_key: alice_internal,
            refund_branch: refund.clone(),
            dest_address: test_change_address(46),
            fee_sats: 1_000,
        };

        // 1. Compute the BIP-341 script-path sighash Bob signs over.
        let sighash = refund_sighash(&cfg, &base).expect("refund_sighash");

        // 2. Bob signs the sighash with his refund key. No tweak
        //    needed — script-path signatures are against the raw
        //    leaf script's keys, not the output key.
        let msg = bitcoin::secp256k1::Message::from_digest(sighash);
        let sig = secp.sign_schnorr_no_aux_rand(&msg, &bob_kp);
        let sig_bytes: [u8; 64] = *sig.as_ref();

        // 3. Bob finalizes the refund tx with his signature.
        let tx_bytes = build_refund_tx(&cfg, &base, &sig_bytes).expect("build_refund_tx");

        // 4. Decode and inspect the witness — must be exactly three
        //    elements: [sig, script, control_block].
        let parsed: bitcoin::Transaction =
            bitcoin::consensus::encode::deserialize(&tx_bytes).expect("decode");
        assert_eq!(parsed.input.len(), 1);
        assert_eq!(parsed.input[0].witness.len(), 3, "script-path witness has 3 elements");

        let mut wit_iter = parsed.input[0].witness.iter();
        let w_sig: &[u8] = wit_iter.next().unwrap();
        let w_script: &[u8] = wit_iter.next().unwrap();
        let w_control: &[u8] = wit_iter.next().unwrap();
        assert_eq!(w_sig.len(), 64, "witness sig is 64 bytes");
        assert_eq!(
            w_control.len(),
            33,
            "control block for single-leaf tree is 33 bytes (header + internal key)"
        );

        // 5. BIP-341 consensus check: the witness signature verifies
        //    under bob_pubkey against the script-path sighash.
        let parsed_sig =
            bitcoin::secp256k1::schnorr::Signature::from_slice(w_sig).unwrap();
        secp.verify_schnorr(&parsed_sig, &msg, &bob_xonly)
            .expect("script-path sig must verify under bob_pubkey");

        // 6. The revealed script matches what refund_script computes
        //    locally — control block + leaf script + key tweak all
        //    consistent with the lock's output script.
        let expected_script = refund_script(&refund).unwrap();
        assert_eq!(w_script, expected_script.as_bytes());

        // 7. The refund tx's input sequence encodes the CSV value
        //    in the BIP-68 blocks-relative form (lower 16 bits =
        //    csv_blocks, type bit = 0).
        let seq = parsed.input[0].sequence;
        assert_eq!(seq.0 as u16, 144, "sequence lower 16 bits = csv_blocks");
        assert_eq!(seq.0 & (1 << 22), 0, "type bit clear → blocks-relative");

        // 8. The refund output value must equal `lock_value_sats - fee_sats`
        //    exactly. Catches arithmetic mutations in
        //    build_refund_tx_internal at btc.rs:1153 (replace `-` with `+`
        //    or `/`). With lock=500_000, fee=1_000:
        //      real:  refund_value = 499_000
        //      `+`:   refund_value = 501_000
        //      `/`:   refund_value = 500
        //    The assertion below pins the correct subtraction.
        assert_eq!(parsed.output.len(), 1, "refund tx has exactly one output");
        assert_eq!(
            parsed.output[0].value.to_sat(),
            base.lock_value_sats - base.fee_sats,
            "refund output value must equal lock_value_sats - fee_sats exactly"
        );
    }

    /// Boundary test for btc.rs:1154 (`if refund_value < DUST_THRESHOLD_SATS`).
    /// refund_value is computed as `lock_value_sats - fee_sats`. Choose
    /// the two so the result is exactly DUST_THRESHOLD_SATS. A mutation
    /// that flips `<` to `==` or `<` to `<=` rejects this case. We pass
    /// a bogus signature so the call ultimately fails — but the failure
    /// must NOT be the dust-threshold error.
    #[test]
    fn build_refund_tx_accepts_refund_value_exactly_at_dust_threshold() {
        let cfg = standard_regtest_config();
        let fee = 1_000u64;
        let lock_value = fee + DUST_THRESHOLD_SATS; // refund_value == 330 exactly
        let base = RefundTxBase {
            lock_txid: Txid([0xc1; 32]),
            lock_vout: 0,
            lock_value_sats: lock_value,
            lock_internal_key: test_internal_key(61),
            refund_branch: RefundBranch {
                bob_pubkey: test_internal_key(60),
                csv_blocks: 144,
            },
            dest_address: test_change_address(62),
            fee_sats: fee,
        };
        let r = build_refund_tx(&cfg, &base, &[0xaa; 64]); // bogus sig
        match r {
            Err(Error::Verification(msg)) => {
                assert!(
                    !msg.contains("dust threshold"),
                    "build_refund_tx erroneously rejected refund_value == DUST_THRESHOLD_SATS \
                     (the `<` check at btc.rs:1154 must NOT trigger at equality). Error: {msg}"
                );
            }
            Err(e) => panic!("unexpected error variant: {e:?}"),
            Ok(_) => panic!("bogus sig should have failed verification, but build_refund_tx returned Ok"),
        }
    }

    #[test]
    fn build_refund_tx_rejects_wrong_signer() {
        // A signature under the WRONG key must be rejected by
        // build_refund_tx's full BIP-340 verification, before any
        // wire bytes are produced.
        use bitcoin::secp256k1::{Keypair, Secp256k1, SecretKey};

        let cfg = standard_regtest_config();
        let secp = Secp256k1::new();

        let bob_pubkey = test_internal_key(60);
        let refund = RefundBranch {
            bob_pubkey,
            csv_blocks: 144,
        };
        let base = RefundTxBase {
            lock_txid: Txid([0xc0; 32]),
            lock_vout: 0,
            lock_value_sats: 500_000,
            lock_internal_key: test_internal_key(61),
            refund_branch: refund,
            dest_address: test_change_address(62),
            fee_sats: 1_000,
        };

        // Sign with a DIFFERENT key.
        let mut wrong_sk_bytes = [0x88u8; 32];
        wrong_sk_bytes[31] = 0x08;
        let wrong_sk = SecretKey::from_slice(&wrong_sk_bytes).unwrap();
        let wrong_kp = Keypair::from_secret_key(&secp, &wrong_sk);
        let sighash = refund_sighash(&cfg, &base).unwrap();
        let msg = bitcoin::secp256k1::Message::from_digest(sighash);
        let sig = secp.sign_schnorr_no_aux_rand(&msg, &wrong_kp);
        let sig_bytes: [u8; 64] = *sig.as_ref();

        let r = build_refund_tx(&cfg, &base, &sig_bytes);
        assert!(matches!(r, Err(Error::Verification(_))));
    }

    /// Mirror of `build_lock_tx_accepts_every_supported_network_string` —
    /// exercises every arm of the network match in `build_refund_tx_internal`.
    /// If any arm ("mainnet"/"testnet"/"regtest"/"signet") is deleted, the
    /// function bails at the match block before reaching require_network.
    #[test]
    fn build_refund_tx_accepts_every_supported_network_string() {
        for net in ["mainnet", "testnet", "regtest", "signet"] {
            let cfg = BtcConfig {
                network: net.into(),
                rpc_url: "http://127.0.0.1:18443".into(),
                rpc_auth: None,
            };
            let base = RefundTxBase {
                lock_txid: Txid([0xc0; 32]),
                lock_vout: 0,
                lock_value_sats: 500_000,
                lock_internal_key: test_internal_key(61),
                refund_branch: RefundBranch {
                    bob_pubkey: test_internal_key(60),
                    csv_blocks: 144,
                },
                dest_address: test_change_address(62), // regtest-formatted
                fee_sats: 1_000,
            };
            let r = build_refund_tx(&cfg, &base, &[0xaa; 64]);
            if net == "regtest" {
                // regtest + regtest addr advances past require_network and
                // fails downstream (signature verification with bogus sig).
                assert!(
                    r.is_err(),
                    "regtest case should fail signature verification, got Ok"
                );
            } else {
                match r {
                    Err(Error::Verification(msg)) => {
                        assert!(
                            !msg.contains("BtcConfig.network must be"),
                            "build_refund_tx errored at network match for '{net}' \u{2014} arm appears to be missing. Got: {msg}"
                        );
                    }
                    Err(e) => panic!("unexpected error variant for '{net}': {e:?}"),
                    Ok(_) => panic!(
                        "build_refund_tx unexpectedly succeeded with {net} network + regtest dest_address"
                    ),
                }
            }
        }
    }

    #[test]
    fn refund_sighash_changes_with_destination() {
        let cfg = standard_regtest_config();
        let refund = test_refund_branch(70, 144);
        let mut base = RefundTxBase {
            lock_txid: Txid([0x90; 32]),
            lock_vout: 0,
            lock_value_sats: 500_000,
            lock_internal_key: test_internal_key(71),
            refund_branch: refund,
            dest_address: test_change_address(72),
            fee_sats: 1_000,
        };
        let h1 = refund_sighash(&cfg, &base).unwrap();
        base.dest_address = test_change_address(73);
        let h2 = refund_sighash(&cfg, &base).unwrap();
        assert_ne!(h1, h2);
    }

    #[test]
    fn build_lock_tx_locktime_honored() {
        let cfg = standard_regtest_config();
        let request = LockTxRequest {
            utxos: vec![FundingUtxo {
                txid: Txid([0x66; 32]),
                vout: 0,
                value_sats: 1_000_000,
            }],
            lock_amount_sats: 500_000,
            adaptor_internal_key: test_internal_key(18),
            change_address: test_change_address(19),
            fee_sats: 1_000,
            locktime: 800_000,
            refund_branch: None,
        };
        let bytes = build_lock_tx(&cfg, &request).unwrap();
        let parsed: bitcoin::Transaction =
            bitcoin::consensus::encode::deserialize(&bytes).unwrap();
        assert_eq!(parsed.lock_time.to_consensus_u32(), 800_000);
    }
}
