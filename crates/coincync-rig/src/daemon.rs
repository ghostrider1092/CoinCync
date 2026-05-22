// Phase 4 — daemon RPC client. See hasher.rs for the rustc 1.95 ICE
// note; remove the allow once the orchestrator wires every public item.
#![allow(dead_code)]

//! # Daemon JSON-RPC client — for solo mining.
//!
//! When `coincync-rig run-solo --node URL` is used, this is the client
//! that talks to the daemon. We POST JSON-RPC envelopes to `URL` and
//! parse the responses.
//!
//! ## What we call
//!
//! - `get_block_template` — returns the current template (anchor, prev,
//!   tx_root, target, difficulty, height). The miner builds the next
//!   block from this and searches for a valid nonce.
//! - `submit_block` — takes a hex-encoded `Block` (Borsh-serialized);
//!   returns success or an error string.
//!
//! ## What we DON'T do here
//!
//! - Coinbase construction. The daemon's template intentionally omits
//!   the coinbase so the node never holds the miner's reward keys.
//!   The miner is responsible for building its own coinbase tx that
//!   pays its `--address`. That's done in the orchestrator (Phase 4)
//!   on top of this client.
//! - Connection pooling. Each call is a fresh `reqwest` request; for
//!   solo mining at testnet difficulty (block ~ every 2 minutes) the
//!   overhead is irrelevant. If we ever do high-frequency template
//!   polling we'll add a long-lived `reqwest::Client`.

use std::time::Duration;

use anyhow::{anyhow, Context, Result};
use reqwest::header::{HeaderMap, HeaderValue, AUTHORIZATION, CONTENT_TYPE};
use serde::Deserialize;
use serde_json::{json, Value};
use tracing::debug;

/// Minimal JSON-RPC daemon client. Stateless — every call builds a
/// fresh request. Holds the bearer token in memory only; never logs it.
pub struct DaemonClient {
    base_url: String,
    api_key: Option<String>,
    http: reqwest::Client,
}

#[derive(Deserialize, Debug)]
struct JsonRpcEnvelope {
    #[serde(default)]
    result: Value,
    #[serde(default)]
    error: Value,
}

impl DaemonClient {
    /// Build a client pointed at a daemon's JSON-RPC endpoint. The
    /// `base_url` is what we POST to: typically
    /// `http://127.0.0.1:28081` for a local daemon, or
    /// `https://api.coincync.network/rpc/testnet` for the public
    /// nginx-fronted endpoint.
    pub fn new(base_url: impl Into<String>, api_key: Option<String>) -> Result<Self> {
        let base_url = base_url.into();

        // Warn loudly if the operator is pointing at a non-localhost daemon
        // over plaintext HTTP. The bearer token (when set) and every block
        // template + share submission then crosses the network unencrypted,
        // and any path-adjacent attacker can lift the token, submit shares
        // under the operator's address, or inject malicious templates.
        // Localhost http is fine — the network-stack hop never leaves the
        // box, and the upstream daemon ↔ public endpoint TLS handles the
        // wire from there.
        let is_http = base_url.starts_with("http://");
        let is_local = base_url.contains("://127.0.0.1")
            || base_url.contains("://localhost")
            || base_url.contains("://[::1]");
        if is_http && !is_local {
            tracing::warn!(
                base_url = %base_url,
                "DaemonClient: connecting to a remote daemon over plaintext http:// — \
                 the API key (if set) and mining traffic are exposed on the wire. \
                 Prefer https:// for any non-loopback destination."
            );
        }

        let http = reqwest::Client::builder()
            .timeout(Duration::from_secs(10))
            .build()
            .context("building reqwest client")?;
        Ok(Self {
            base_url,
            api_key,
            http,
        })
    }

    /// Fetch a block template. Returns the raw JSON object — the
    /// orchestrator decodes the fields it needs (height, prev_hash,
    /// target, transactions). We keep parsing in the orchestrator
    /// because the schema may evolve and this client should stay
    /// thin.
    pub async fn get_block_template(&self) -> Result<Value> {
        self.call("get_block_template", json!([])).await
    }

    /// Submit a hex-encoded Borsh-serialized `Block`. Returns the
    /// result value on success; bubbles up any RPC error.
    pub async fn submit_block(&self, block_hex: &str) -> Result<Value> {
        self.call("submit_block", json!([block_hex])).await
    }

    /// Get a quick liveness/info read. Used by the orchestrator's
    /// startup banner so the operator can see "yes, you're connected
    /// to a real daemon at height N" before mining starts.
    pub async fn get_info(&self) -> Result<Value> {
        self.call("get_info", json!([])).await
    }

    async fn call(&self, method: &str, params: Value) -> Result<Value> {
        let body = json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": method,
            "params": params,
        });

        let mut headers = HeaderMap::new();
        headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
        if let Some(key) = &self.api_key {
            // Token never logged — only attached to outgoing headers.
            let bearer = format!("Bearer {key}");
            headers.insert(
                AUTHORIZATION,
                HeaderValue::from_str(&bearer)
                    .context("api key contains illegal characters for an HTTP header")?,
            );
        }

        debug!(%method, "daemon: rpc call");
        let resp = self
            .http
            .post(&self.base_url)
            .headers(headers)
            .json(&body)
            .send()
            .await
            .with_context(|| format!("POST {method} to {}", self.base_url))?;

        let status = resp.status();
        let envelope: JsonRpcEnvelope = resp
            .json()
            .await
            .with_context(|| format!("parsing JSON-RPC response for {method}"))?;

        if !envelope.error.is_null() {
            return Err(anyhow!(
                "{method} returned error: {} (http {})",
                envelope.error,
                status
            ));
        }
        if !status.is_success() {
            return Err(anyhow!("{method} returned HTTP {}", status));
        }
        Ok(envelope.result)
    }
}
