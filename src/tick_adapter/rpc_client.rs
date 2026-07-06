//! Blocking JSON-RPC client for talking to a coincync-node instance
//! over loopback (or over-the-network for `probe_peer` against fleet
//! hosts).
//!
//! Sync-only surface because `tick::ChainAdapter` methods are sync.
//! `reqwest::blocking` internally spawns a tokio runtime, so callers
//! can invoke this from a non-async context safely.
//!
//! ## Timeout budget
//!
//! Default 5-second timeout on every call. RescueTick's quest loop
//! polls every fleet host; a hung request would stall the whole
//! quest, so we fail fast and let the tick classify the unreachable
//! host separately from a slow one.
//!
//! ## Auth
//!
//! Bearer token in the `Authorization` header, matching the
//! coincync-node RPC convention (see `src/rpc/server.rs`).

use std::time::Duration;

use serde_json::Value;

use tick::TickError;

/// Default HTTP request timeout.
///
/// 5 seconds is comfortably longer than any healthy `get_info` should
/// take (typically < 100ms) but short enough that a hung host doesn't
/// block the tick's quest loop for minutes at a time.
const DEFAULT_TIMEOUT: Duration = Duration::from_secs(5);

/// Maximum RPC response body we will buffer, in bytes.
///
/// Rule D.1: never allocate unbounded memory from a network peer. The
/// largest legitimate response is a `get_block` for a `MAX_BLOCK_SIZE`
/// (2 MiB) block, which is ~4 MiB of hex plus a small JSON envelope.
/// 16 MiB gives generous headroom while capping what a compromised or
/// MITM'd host can force us to allocate. Kept local (not derived from
/// the consensus constant) so this transport limit can't silently
/// track a future block-size change without review.
const MAX_RESPONSE_BYTES: u64 = 16 * 1024 * 1024;

/// Handle for a JSON-RPC connection to one coincync-node instance.
///
/// Cheap to clone (Arc-backed internally via `reqwest::blocking::Client`).
/// Callers typically build one client for the local node and re-use
/// per-peer clients transiently for fleet-wide polls.
#[derive(Clone)]
pub struct RpcClient {
    client: reqwest::blocking::Client,
    url: String,
    bearer: Option<String>,
}

impl std::fmt::Debug for RpcClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Rule A.6 (key hygiene): the bearer token must never appear in
        // Debug output. Report only whether auth is set, not its value.
        f.debug_struct("RpcClient")
            .field("url", &self.url)
            .field(
                "bearer",
                &self.bearer.as_ref().map(|_| "<redacted>"),
            )
            .finish_non_exhaustive()
    }
}

impl RpcClient {
    /// Build a new client pointing at `url` with the given bearer
    /// token.
    ///
    /// `bearer == None` disables auth (only valid against a coincync-
    /// node with `--rpc-no-auth`, essentially only in test builds).
    pub fn new(url: impl Into<String>, bearer: Option<String>) -> Result<Self, TickError> {
        let client = reqwest::blocking::Client::builder()
            .timeout(DEFAULT_TIMEOUT)
            .build()
            .map_err(|e| TickError::Other(format!("reqwest build failed: {}", e)))?;
        Ok(RpcClient {
            client,
            url: url.into(),
            bearer,
        })
    }

    /// Call a JSON-RPC method with the given params. Returns the raw
    /// `result` field on success, or `TickError::Unreachable` on
    /// network / HTTP failure, or `TickError::Other` on JSON-RPC
    /// error / decoding failure.
    ///
    /// The distinction matters: `Unreachable` maps to "host down,
    /// HealthTick concern," while `Other` maps to "chain returned
    /// something we didn't understand, log and continue."
    pub fn call(&self, method: &str, params: Value) -> Result<Value, TickError> {
        let body = serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": method,
            "params": params,
        });

        let mut req = self.client.post(&self.url).json(&body);
        if let Some(token) = &self.bearer {
            req = req.bearer_auth(token);
        }

        let mut resp = req
            .send()
            .map_err(|e| TickError::Unreachable(format!("{} POST failed: {}", self.url, e)))?;

        if !resp.status().is_success() {
            return Err(TickError::Unreachable(format!(
                "{} returned HTTP {}",
                self.url,
                resp.status()
            )));
        }

        // Read the body through a hard byte cap before deserializing —
        // never trust the Content-Length header or stream length a peer
        // reports (rule D.1). We read up to MAX_RESPONSE_BYTES + 1 so a
        // body that exactly fills the cap still parses, but anything
        // larger is rejected before it can grow the allocation further.
        use std::io::Read;
        let mut buf = Vec::new();
        (&mut resp)
            .take(MAX_RESPONSE_BYTES + 1)
            .read_to_end(&mut buf)
            .map_err(|e| TickError::Unreachable(format!("{} body read failed: {}", self.url, e)))?;
        if buf.len() as u64 > MAX_RESPONSE_BYTES {
            return Err(TickError::Other(format!(
                "{} response body exceeded {}-byte cap",
                self.url, MAX_RESPONSE_BYTES
            )));
        }

        let raw: Value = serde_json::from_slice(&buf)
            .map_err(|e| TickError::Other(format!("{} JSON decode failed: {}", self.url, e)))?;

        if let Some(err) = raw.get("error") {
            return Err(TickError::Other(format!(
                "{} RPC error: {}",
                self.url, err
            )));
        }

        raw.get("result")
            .cloned()
            .ok_or_else(|| TickError::Other(format!("{} RPC response missing `result`", self.url)))
    }

    /// The RPC endpoint URL. Used in logs.
    pub fn url(&self) -> &str {
        &self.url
    }
}

// ─── Response types ──────────────────────────────────────────────────────

/// Subset of the `get_info` RPC response that tick actually needs.
///
/// Coincync's real response has many more fields; we deserialize only
/// what we consume so a future extension doesn't break the tick.
#[derive(Debug, Clone, serde::Deserialize)]
pub struct GetInfoResponse {
    /// Chain tip height.
    pub height: u64,
    /// Cumulative work as a decimal string. Coincync serializes u128
    /// as string to avoid JSON's 2^53 int precision limit.
    pub total_difficulty: String,
    /// Hex-encoded 32-byte hash of the tip block.
    pub top_hash: String,
    /// True if the local node considers itself in sync with the
    /// network tip.
    #[serde(alias = "synced")]
    pub is_synced: bool,
    /// Current outbound peer count.
    pub peer_count: u32,
    /// Seconds since the tip's timestamp. `None` when the local clock
    /// is unreliable.
    #[serde(default)]
    pub tip_age_secs: Option<u64>,
    /// Number of transactions in the local mempool. Optional so a
    /// missing field (older node without the count) parses cleanly.
    /// Coincync's `get_info` emits both `mempool_size` and
    /// `tx_pool_size` as back-compat aliases; either satisfies this
    /// field.
    #[serde(default, alias = "tx_pool_size")]
    pub mempool_size: Option<usize>,
}

impl GetInfoResponse {
    /// Convert the wire-shape difficulty string into a `u128`.
    /// Missing / non-numeric → treat as `0` (a stalled sentinel that
    /// won't false-trigger divergence detection).
    pub fn difficulty_u128(&self) -> u128 {
        self.total_difficulty.parse::<u128>().unwrap_or(0)
    }

    /// Convert the hex-encoded `top_hash` into raw bytes.
    /// Returns `[0u8; 32]` on decode failure (safe sentinel).
    pub fn tip_bytes(&self) -> [u8; 32] {
        let mut out = [0u8; 32];
        if let Ok(bytes) = hex::decode(&self.top_hash) {
            if bytes.len() == 32 {
                out.copy_from_slice(&bytes);
            }
        }
        out
    }
}

/// Convenience wrapper: fetch and parse `get_info` from an RPC client.
///
/// Returns `TickError::Unreachable` if the transport is broken,
/// `TickError::Other` if the response shape is unexpected.
pub fn get_info(client: &RpcClient) -> Result<GetInfoResponse, TickError> {
    let raw = client.call("get_info", serde_json::json!([]))?;
    serde_json::from_value(raw)
        .map_err(|e| TickError::Other(format!("{} get_info decode failed: {}", client.url(), e)))
}

// ─── get_block_by_height ─────────────────────────────────────────────────

/// Subset of the `get_block_by_height` RPC response that verify_peer_
/// header_pow depends on. Only the `bytes` field is load-bearing —
/// it's the hex-encoded borsh-serialized `Block`, from which every
/// header field is recovered by local deserialization.
///
/// Keeping the response type narrow (just the `bytes` we deserialize
/// locally) is deliberate: the RPC also returns high-level derived
/// fields like `difficulty`, `algorithm_name`, `hash`, which we don't
/// TRUST for PoW verification. Trusting only the raw block bytes means
/// a peer that lies about a derived field can't fool the adapter's
/// PoW check — we recompute everything locally.
#[derive(Debug, Clone, serde::Deserialize)]
pub struct GetBlockByHeightResponse {
    /// Hex-encoded borsh serialization of the full `Block`.
    pub bytes: String,
}

/// Fetch a block by its `hash_hex` (64-char hex string) from
/// `client`. Uses the `get_block` RPC.
///
/// Errors are the same shape as `get_block_by_height`.
pub fn get_block_by_hash(
    client: &RpcClient,
    hash_hex: &str,
) -> Result<GetBlockByHeightResponse, TickError> {
    let raw = client.call("get_block", serde_json::json!([hash_hex]))?;
    serde_json::from_value(raw).map_err(|e| {
        TickError::Other(format!(
            "{} get_block({}) decode failed: {}",
            client.url(),
            &hash_hex.chars().take(12).collect::<String>(),
            e
        ))
    })
}

/// Fetch a block at the given `height` from `client`.
///
/// Returns `TickError::Other` if the JSON-RPC responds with an error
/// (typically "block at height N not found"), or `TickError::Other`
/// on unexpected response shape.
pub fn get_block_by_height(
    client: &RpcClient,
    height: u64,
) -> Result<GetBlockByHeightResponse, TickError> {
    let raw = client.call(
        "get_block_by_height",
        serde_json::json!([height]),
    )?;
    serde_json::from_value(raw).map_err(|e| {
        TickError::Other(format!(
            "{} get_block_by_height({}) decode failed: {}",
            client.url(),
            height,
            e
        ))
    })
}

// ─── submit_block ────────────────────────────────────────────────────────

/// Response shape for `submit_block`. The `accepted` field is always
/// present on success (JSON-RPC error on rejection). `status` is
/// present when the block was already known.
#[derive(Debug, Clone, serde::Deserialize)]
pub struct SubmitBlockResponse {
    pub accepted: bool,
    /// Hex-encoded 32-byte hash of the submitted block. Present on
    /// both fresh-accept and already-known paths.
    #[serde(default)]
    pub hash: String,
    /// Present when the block was already known to the receiver.
    #[serde(default)]
    pub status: Option<String>,
}

/// Submit a block to `client`.
///
/// `hex_block` is the hex-encoded borsh serialization of a `Block`
/// (matches the format `get_block_by_height` returns in its `bytes`
/// field, so round-trip is lossless).
///
/// Returns:
/// - `Ok(SubmitBlockResponse)` when the RPC returns success (block
///   accepted, or already known).
/// - `TickError::Unreachable` on transport failure.
/// - `TickError::Other` when the JSON-RPC returns an error (orphan,
///   invalid, size cap violation) — the error message carries the
///   specific rejection reason.
pub fn submit_block(
    client: &RpcClient,
    hex_block: String,
) -> Result<SubmitBlockResponse, TickError> {
    let raw = client.call("submit_block", serde_json::json!([hex_block]))?;
    serde_json::from_value(raw).map_err(|e| {
        TickError::Other(format!(
            "{} submit_block decode failed: {}",
            client.url(),
            e
        ))
    })
}

// ─── Tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::thread;

    /// Tiny hand-rolled HTTP server. Handles ONE request, responds
    /// with the caller-provided body, closes. Used instead of pulling
    /// in `wiremock` / `mockito` (scope creep).
    ///
    /// Returns the URL the server is listening on so the test can
    /// point an `RpcClient` at it.
    fn spawn_one_shot_server(response_body: String, response_status: u16) -> String {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let addr = listener.local_addr().expect("addr");
        thread::spawn(move || {
            if let Ok((mut stream, _)) = listener.accept() {
                // Read the request (we don't need to parse it — just
                // drain enough bytes that the client's send() completes
                // and the client waits for a response).
                let mut buf = [0u8; 4096];
                let _ = stream.set_read_timeout(Some(Duration::from_secs(1)));
                let _ = stream.read(&mut buf);

                // Respond.
                let status_text = match response_status {
                    200 => "200 OK",
                    401 => "401 Unauthorized",
                    500 => "500 Internal Server Error",
                    _ => "200 OK",
                };
                let response = format!(
                    "HTTP/1.1 {status}\r\n\
                     Content-Type: application/json\r\n\
                     Content-Length: {len}\r\n\
                     Connection: close\r\n\
                     \r\n\
                     {body}",
                    status = status_text,
                    len = response_body.len(),
                    body = response_body,
                );
                let _ = stream.write_all(response.as_bytes());
                let _ = stream.flush();
            }
        });
        format!("http://{}", addr)
    }

    #[test]
    fn call_rejects_oversized_response_body() {
        // Rule D.1 (adversarial): a peer that streams a body larger
        // than MAX_RESPONSE_BYTES must be rejected via the read cap,
        // not buffered wholesale. Send exactly cap + 1 bytes.
        let oversized = "a".repeat((MAX_RESPONSE_BYTES as usize) + 1);
        let url = spawn_one_shot_server(oversized, 200);
        let client = RpcClient::new(url, None).expect("build");
        let err = client
            .call("get_info", serde_json::json!([]))
            .expect_err("oversized body must error");
        assert!(
            matches!(err, TickError::Other(_)),
            "expected Other, got: {:?}",
            err
        );
        assert!(
            format!("{}", err).contains("exceeded"),
            "expected cap message, got: {}",
            err
        );
    }

    #[test]
    fn get_info_round_trip_deserializes_the_expected_fields() {
        let body = r#"{
            "jsonrpc": "2.0",
            "id": 1,
            "result": {
                "height": 9469,
                "total_difficulty": "720000000",
                "top_hash": "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789",
                "is_synced": true,
                "peer_count": 8,
                "tip_age_secs": 12
            }
        }"#
        .to_string();
        let url = spawn_one_shot_server(body, 200);
        let client = RpcClient::new(url, None).expect("build");
        let info = get_info(&client).expect("get_info");

        assert_eq!(info.height, 9469);
        assert_eq!(info.difficulty_u128(), 720_000_000);
        assert_eq!(info.tip_bytes()[0..2], [0xab, 0xcd]);
        assert!(info.is_synced);
        assert_eq!(info.peer_count, 8);
        assert_eq!(info.tip_age_secs, Some(12));
    }

    #[test]
    fn get_info_accepts_synced_alias() {
        // Coincync's real get_info emits BOTH `is_synced` and `synced`
        // (back-compat alias). Verify we accept the alias.
        let body = r#"{
            "jsonrpc": "2.0",
            "id": 1,
            "result": {
                "height": 100,
                "total_difficulty": "5",
                "top_hash": "0000000000000000000000000000000000000000000000000000000000000000",
                "synced": true,
                "peer_count": 2
            }
        }"#
        .to_string();
        let url = spawn_one_shot_server(body, 200);
        let client = RpcClient::new(url, None).expect("build");
        let info = get_info(&client).expect("get_info");
        assert!(info.is_synced);
    }

    #[test]
    fn http_500_maps_to_unreachable() {
        let body = "server error".to_string();
        let url = spawn_one_shot_server(body, 500);
        let client = RpcClient::new(url, None).expect("build");
        let err = get_info(&client).unwrap_err();
        assert!(matches!(err, TickError::Unreachable(_)), "got: {:?}", err);
    }

    #[test]
    fn json_rpc_error_maps_to_other() {
        let body = r#"{
            "jsonrpc": "2.0",
            "id": 1,
            "error": { "code": -32601, "message": "Method not found" }
        }"#
        .to_string();
        let url = spawn_one_shot_server(body, 200);
        let client = RpcClient::new(url, None).expect("build");
        let err = get_info(&client).unwrap_err();
        // JSON-RPC error → Other (not Unreachable) so HealthTick
        // doesn't mistakenly count it as a down host.
        assert!(matches!(err, TickError::Other(_)), "got: {:?}", err);
        let msg = format!("{}", err);
        assert!(msg.contains("Method not found"), "got: {}", msg);
    }

    #[test]
    fn unreachable_host_maps_to_unreachable() {
        // Point at a port that's guaranteed not listening (random high
        // port, no server started). Client should get connection
        // refused → Unreachable.
        let client = RpcClient::new("http://127.0.0.1:1", None).expect("build");
        let err = get_info(&client).unwrap_err();
        assert!(matches!(err, TickError::Unreachable(_)), "got: {:?}", err);
    }

    #[test]
    fn difficulty_u128_handles_non_numeric_gracefully() {
        let info = GetInfoResponse {
            height: 0,
            total_difficulty: "not-a-number".into(),
            top_hash: "".into(),
            is_synced: false,
            peer_count: 0,
            tip_age_secs: None,
            mempool_size: None,
        };
        // Should NOT panic; returns 0 as safe sentinel.
        assert_eq!(info.difficulty_u128(), 0);
    }

    #[test]
    fn tip_bytes_zero_on_bad_hex() {
        let info = GetInfoResponse {
            height: 0,
            total_difficulty: "0".into(),
            top_hash: "not-hex".into(),
            is_synced: false,
            peer_count: 0,
            tip_age_secs: None,
            mempool_size: None,
        };
        assert_eq!(info.tip_bytes(), [0u8; 32]);
    }

    // ─── submit_block ───────────────────────────────────────────────

    #[test]
    fn submit_block_happy_path() {
        let body = r#"{
            "jsonrpc": "2.0",
            "id": 1,
            "result": {
                "accepted": true,
                "hash": "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"
            }
        }"#
        .to_string();
        let url = spawn_one_shot_server(body, 200);
        let client = RpcClient::new(url, None).expect("build");
        let resp = submit_block(&client, "deadbeef".into()).expect("Ok");
        assert!(resp.accepted);
        assert!(!resp.hash.is_empty());
    }

    #[test]
    fn submit_block_already_known_path() {
        let body = r#"{
            "jsonrpc": "2.0",
            "id": 1,
            "result": {
                "accepted": true,
                "status": "already_known",
                "hash": "cafebabecafebabecafebabecafebabecafebabecafebabecafebabecafebabe"
            }
        }"#
        .to_string();
        let url = spawn_one_shot_server(body, 200);
        let client = RpcClient::new(url, None).expect("build");
        let resp = submit_block(&client, "aa".into()).expect("Ok");
        assert!(resp.accepted);
        assert_eq!(resp.status.as_deref(), Some("already_known"));
    }

    #[test]
    fn submit_block_orphan_rejection_maps_to_other() {
        // Coincync's real submit_block returns JSON-RPC error -32001
        // for orphan rejection. That maps to TickError::Other (per
        // RpcClient::call classification: 200-OK + `error` field →
        // Other, not Unreachable).
        let body = r#"{
            "jsonrpc": "2.0",
            "id": 1,
            "error": {"code": -32001, "message": "block rejected: orphan (parent not in chain), hash=abcd"}
        }"#
        .to_string();
        let url = spawn_one_shot_server(body, 200);
        let client = RpcClient::new(url, None).expect("build");
        let err = submit_block(&client, "cc".into()).unwrap_err();
        assert!(matches!(err, TickError::Other(_)), "got: {:?}", err);
        let msg = format!("{}", err);
        assert!(msg.contains("orphan"), "got: {}", msg);
    }

    // ─── get_block_by_hash ────────────────────────────────────────

    #[test]
    fn get_block_by_hash_happy_path() {
        let body = r#"{
            "jsonrpc": "2.0",
            "id": 1,
            "result": {
                "bytes": "deadbeef"
            }
        }"#
        .to_string();
        let url = spawn_one_shot_server(body, 200);
        let client = RpcClient::new(url, None).expect("build");
        let resp = get_block_by_hash(&client, "abcd").expect("Ok");
        assert_eq!(resp.bytes, "deadbeef");
    }

    #[test]
    fn get_block_by_hash_not_found_maps_to_other() {
        let body = r#"{
            "jsonrpc": "2.0",
            "id": 1,
            "error": {"code": -32000, "message": "block with hash abcd not found"}
        }"#
        .to_string();
        let url = spawn_one_shot_server(body, 200);
        let client = RpcClient::new(url, None).expect("build");
        let err = get_block_by_hash(&client, "abcd").unwrap_err();
        assert!(matches!(err, TickError::Other(_)));
    }
}
