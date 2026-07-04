//! # Generic maintainer-signed registry — infrastructure for Fort-Knox
//! items 2, 3, and future decentralized services.
//!
//! Fetches a maintainer-signed JSON payload from IPFS via a well-known
//! pointer URL. Verifies the payload's Ed25519 signature against a
//! per-service domain-separated namespace and returns the parsed
//! payload to the caller.
//!
//! ## What this module DOES
//!
//! - Fetches a small JSON pointer from a well-known HTTPS URL (e.g.
//!   `https://coincync.network/faucet-registry/latest-testnet.json`).
//! - Reads two IPFS CIDs from the pointer: one for the payload, one
//!   for a raw 64-byte Ed25519 signature.
//! - Tries a fixed list of public IPFS gateways in order until one
//!   serves both the payload bytes and the signature bytes.
//! - Verifies the signature over `namespace || payload_bytes` with
//!   the maintainer's public key.
//! - Runs the same clock-skew + replay defence as the peer-snapshot
//!   consumer.
//! - Parses the payload as user-supplied type `T` via
//!   `serde_json::from_slice` and returns it.
//!
//! ## What this module does NOT do
//!
//! - **Refactor `peer_snapshot.rs`** to use this generic path. That
//!   module still ships its own dedicated implementation for now.
//!   Consolidating them is a follow-up refactor that would need
//!   careful review because peer_snapshot is on the cold-start
//!   bootstrap path. Both modules coexist here.
//! - **Cache the fetched registry** to disk. Each cold start
//!   re-fetches. The pointer + gateway path is already redundant;
//!   adding on-disk cache is premature.
//! - **Sign** anything. Producer-side signing lives in the
//!   `coincync-sign-snapshot` bin and `scripts/publish-*.sh`
//!   scripts, mirroring the peer-snapshot pattern.
//!
//! ## Trust model
//!
//! Same as `peer_snapshot.rs`: trust is in the signature, not the
//! delivery channel. An attacker who controls any subset of the IPFS
//! gateways can serve any CID; they cannot forge a valid signature
//! under the maintainer's key. The maintainer public key is either
//! baked into the binary or configured via env var by the operator.
//!
//! ## Per-service isolation via namespace
//!
//! Each service (peer-snapshot, faucet-registry, coordinator-
//! registry, ...) uses a distinct byte-string `SIGNATURE_NAMESPACE`
//! passed through to `fetch_verified_json`. That namespace is
//! prepended to the payload bytes BEFORE signing, so:
//!
//!   * A valid faucet-registry signature CANNOT be replayed as a
//!     coordinator-registry payload (different namespace → different
//!     signed bytes → verify fails).
//!   * A valid peer-snapshot signature from the FK 6 path cannot be
//!     replayed here for the same reason.
//!
//! Each caller MUST pass a namespace unique to its domain. Reusing
//! the peer-snapshot namespace would defeat the isolation.

use std::time::Duration;

use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use reqwest::Client;
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use tracing::{debug, info};

// ─── constants ─────────────────────────────────────────────────────────

/// Same IPFS gateways as the peer-snapshot consumer. Kept in-sync at
/// the source; if a new gateway is added there, add it here too.
/// Duplicated deliberately so this module can be audited independently
/// of `peer_snapshot`'s constants.
pub const IPFS_GATEWAYS: &[&str] = &[
    "https://cloudflare-ipfs.com",
    "https://ipfs.io",
    "https://dweb.link",
];

/// Per-gateway HTTP timeout. Generous — registry fetch happens once
/// at cold start, latency budget is not tight.
pub const GATEWAY_TIMEOUT: Duration = Duration::from_secs(30);

/// Raw Ed25519 signature length in bytes.
pub const ED25519_SIGNATURE_LEN: usize = 64;

/// Maximum size of the signature file we're willing to buffer. We
/// only accept raw 64-byte Ed25519 signatures, so anything larger is
/// either a malformed producer output or a malicious gateway; either
/// way, reject cheaply before reading.
pub const MAX_SIGNATURE_BYTES: usize = 128;

// ─── wire types ────────────────────────────────────────────────────────

/// Well-known-URL pointer file (JSON).
///
/// Kept small so it fits in the average Cloudflare edge cache and
/// returns quickly. Advisory fields are `Option` so producers can
/// emit whichever subset makes sense for their service.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegistryPointer {
    /// Schema version. Bumped on incompatible layout changes.
    pub schema_version: u32,
    /// When the referenced payload was captured (unix seconds).
    pub unix_ts: u64,
    /// IPFS CID of the payload JSON bytes.
    pub payload_cid: String,
    /// IPFS CID of the raw 64-byte Ed25519 signature over
    /// `namespace || payload_bytes`.
    pub signature_cid: String,
    /// Advisory: human-readable source identifier. Not verified.
    pub source: Option<String>,
    /// Advisory: number of entries in the payload. Not verified,
    /// but useful for logging.
    pub entry_count: Option<u32>,
}

/// Trait every registry payload must implement so this generic
/// module can run the shared validation.
///
/// Callers define their own payload struct with whatever
/// service-specific fields they need, then implement this trait to
/// expose the three fields the validator inspects.
pub trait RegistryPayload {
    /// Which network the payload is for (`"testnet"`, `"mainnet"`,
    /// `"regtest"`). Compared against the caller's expected network
    /// so a testnet payload delivered on mainnet is rejected before
    /// any bytes touch the consumer's state.
    fn network(&self) -> &str;

    /// When the payload was signed. Used for clock-skew + replay
    /// defence — see `validate_payload_meta`.
    fn unix_ts(&self) -> u64;

    /// Payload schema version. Callers compare against a hard-coded
    /// expected value to reject future incompatible layouts.
    fn schema_version(&self) -> u32;
}

// ─── errors ────────────────────────────────────────────────────────────

/// Per-failure-mode errors. Callers can log each specifically instead
/// of "something went wrong."
#[derive(Debug)]
pub enum RegistryError {
    PointerUnreachable(String),
    PointerParseError(String),
    AllGatewaysFailed { attempts: Vec<String> },
    PayloadTooLarge { limit: usize, got: usize },
    SignatureTooLarge { limit: usize, got: usize },
    SignatureInvalidLength { actual: usize },
    SignatureVerifyFailed,
    PayloadParseError(String),
    NetworkMismatch { expected: String, got: String },
    SchemaMismatch { expected: u32, got: u32 },
    ClockSkew { payload_ts: u64, now_ts: u64 },
    StalePayload { payload_ts: u64, last_seen_ts: u64 },
}

impl std::fmt::Display for RegistryError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::PointerUnreachable(m) => write!(f, "pointer unreachable: {}", m),
            Self::PointerParseError(m) => write!(f, "pointer parse error: {}", m),
            Self::AllGatewaysFailed { attempts } => {
                write!(f, "all IPFS gateways failed: {}", attempts.join("; "))
            }
            Self::PayloadTooLarge { limit, got } => {
                write!(f, "payload {} bytes exceeds cap {}", got, limit)
            }
            Self::SignatureTooLarge { limit, got } => {
                write!(f, "signature {} bytes exceeds cap {}", got, limit)
            }
            Self::SignatureInvalidLength { actual } => {
                write!(f, "signature length {} != 64", actual)
            }
            Self::SignatureVerifyFailed => write!(f, "signature verification failed"),
            Self::PayloadParseError(m) => write!(f, "payload parse: {}", m),
            Self::NetworkMismatch { expected, got } => {
                write!(f, "network mismatch: expected {} got {}", expected, got)
            }
            Self::SchemaMismatch { expected, got } => {
                write!(f, "schema version mismatch: expected {} got {}", expected, got)
            }
            Self::ClockSkew { payload_ts, now_ts } => write!(
                f,
                "payload from the future: payload_ts={} now={}",
                payload_ts, now_ts
            ),
            Self::StalePayload { payload_ts, last_seen_ts } => write!(
                f,
                "payload {} not newer than last-seen {}",
                payload_ts, last_seen_ts
            ),
        }
    }
}

impl std::error::Error for RegistryError {}

// ─── entry point ───────────────────────────────────────────────────────

/// Fetch, verify, and parse a maintainer-signed registry payload.
///
/// Steps (in order — any failure short-circuits):
///
///   1. HTTP GET `pointer_url` → parse as `RegistryPointer`
///   2. For each gateway in `IPFS_GATEWAYS`, try to fetch both the
///      payload and signature. First gateway that serves both wins.
///   3. Verify the signature is exactly 64 bytes and validates over
///      `namespace || payload_bytes` under `pubkey`.
///   4. `serde_json::from_slice::<T>` on the payload bytes.
///   5. `validate_payload_meta` — schema version, network match,
///      clock-skew rejection, replay defence.
///
/// The caller passes:
///
/// - `pointer_url`: well-known HTTPS URL of the pointer JSON. Each
///   service publishes its own; do NOT share URLs across services.
/// - `expected_network`: current node network ("testnet" | "mainnet"
///   | "regtest"). Payload's `network` must match.
/// - `expected_schema_version`: hard-coded per-caller. Payload's
///   `schema_version` must match. Callers bump on incompatible
///   layout changes.
/// - `last_seen_ts`: replay defence. Payload's `unix_ts` must be
///   strictly greater than this. Pass 0 on a truly-fresh cold start.
/// - `pubkey`: 32-byte Ed25519 maintainer verifying key.
/// - `namespace`: domain-separator byte string. MUST be unique
///   per-service to prevent cross-service signature replay. Example:
///   `b"coincync-faucet-registry-v1"`.
/// - `payload_max_bytes`: reject-and-error cap on the payload byte
///   length. Each service picks based on how big its legit payload
///   can grow.
pub async fn fetch_verified_json<T>(
    pointer_url: &str,
    expected_network: &str,
    expected_schema_version: u32,
    last_seen_ts: u64,
    pubkey: &[u8; 32],
    namespace: &[u8],
    payload_max_bytes: usize,
) -> std::result::Result<T, RegistryError>
where
    T: RegistryPayload + DeserializeOwned,
{
    let client = Client::builder()
        .timeout(GATEWAY_TIMEOUT)
        .user_agent(format!("coincync/{}", env!("CARGO_PKG_VERSION")))
        .build()
        .map_err(|e| RegistryError::PointerUnreachable(format!("reqwest build: {}", e)))?;

    let pointer = fetch_pointer(&client, pointer_url).await?;
    info!(
        target: "signed_registry",
        "fetched pointer: unix_ts={} payload_cid={} entries={:?} source={:?}",
        pointer.unix_ts, pointer.payload_cid, pointer.entry_count, pointer.source,
    );

    let (payload_bytes, signature_bytes) =
        fetch_from_gateways(&client, &pointer.payload_cid, &pointer.signature_cid, payload_max_bytes)
            .await?;

    verify_signature(pubkey, namespace, &payload_bytes, &signature_bytes)?;

    let payload: T = serde_json::from_slice(&payload_bytes)
        .map_err(|e| RegistryError::PayloadParseError(e.to_string()))?;

    validate_payload_meta(&payload, expected_network, expected_schema_version, last_seen_ts)?;

    Ok(payload)
}

// ─── internals ─────────────────────────────────────────────────────────

async fn fetch_pointer(
    client: &Client,
    url: &str,
) -> std::result::Result<RegistryPointer, RegistryError> {
    let resp = client
        .get(url)
        .send()
        .await
        .map_err(|e| RegistryError::PointerUnreachable(format!("{}: {}", url, e)))?;

    if !resp.status().is_success() {
        return Err(RegistryError::PointerUnreachable(format!(
            "{} returned HTTP {}",
            url,
            resp.status()
        )));
    }

    let body = resp
        .text()
        .await
        .map_err(|e| RegistryError::PointerUnreachable(format!("read body: {}", e)))?;

    serde_json::from_str(&body).map_err(|e| RegistryError::PointerParseError(e.to_string()))
}

async fn fetch_from_gateways(
    client: &Client,
    payload_cid: &str,
    signature_cid: &str,
    payload_max_bytes: usize,
) -> std::result::Result<(Vec<u8>, Vec<u8>), RegistryError> {
    let mut attempts: Vec<String> = Vec::with_capacity(IPFS_GATEWAYS.len());

    for gateway in IPFS_GATEWAYS {
        let payload_url = format!("{}/ipfs/{}", gateway, payload_cid);
        let sig_url = format!("{}/ipfs/{}", gateway, signature_cid);
        debug!(target: "signed_registry", "trying gateway {}", gateway);

        let payload_result = fetch_bounded(client, &payload_url, payload_max_bytes).await;
        let sig_result = fetch_bounded(client, &sig_url, MAX_SIGNATURE_BYTES).await;

        match (payload_result, sig_result) {
            (Ok(payload), Ok(sig)) => {
                debug!(
                    target: "signed_registry",
                    "gateway {} served payload ({} bytes) + signature ({} bytes)",
                    gateway, payload.len(), sig.len(),
                );
                return Ok((payload, sig));
            }
            (Err(ep), Err(es)) => attempts.push(format!("{} (payload: {}, sig: {})", gateway, ep, es)),
            (Err(e), _) | (_, Err(e)) => attempts.push(format!("{} ({})", gateway, e)),
        }
    }

    Err(RegistryError::AllGatewaysFailed { attempts })
}

async fn fetch_bounded(
    client: &Client,
    url: &str,
    max_bytes: usize,
) -> std::result::Result<Vec<u8>, String> {
    let resp = client
        .get(url)
        .send()
        .await
        .map_err(|e| format!("HTTP send: {}", e))?;

    if !resp.status().is_success() {
        return Err(format!("HTTP {}", resp.status()));
    }

    if let Some(len) = resp.content_length() {
        if (len as usize) > max_bytes {
            return Err(format!("content-length {} exceeds cap {}", len, max_bytes));
        }
    }

    let bytes = resp.bytes().await.map_err(|e| format!("read body: {}", e))?;
    if bytes.len() > max_bytes {
        return Err(format!("body {} bytes exceeds cap {}", bytes.len(), max_bytes));
    }

    Ok(bytes.to_vec())
}

fn verify_signature(
    pubkey: &[u8; 32],
    namespace: &[u8],
    payload_bytes: &[u8],
    signature_bytes: &[u8],
) -> std::result::Result<(), RegistryError> {
    if signature_bytes.len() != ED25519_SIGNATURE_LEN {
        return Err(RegistryError::SignatureInvalidLength {
            actual: signature_bytes.len(),
        });
    }
    let sig_bytes: [u8; 64] = signature_bytes
        .try_into()
        .expect("length 64 confirmed above");

    let signature = Signature::from_bytes(&sig_bytes);
    let verifying_key = VerifyingKey::from_bytes(pubkey)
        .map_err(|_| RegistryError::SignatureVerifyFailed)?;

    // Domain-separated: signature covers namespace || payload_bytes.
    // A signature from any other coincync signing context (peer
    // snapshot, release tag, checkpoint, ...) cannot verify here
    // because their `namespace` prefix differs.
    let mut signed_payload = Vec::with_capacity(namespace.len() + payload_bytes.len());
    signed_payload.extend_from_slice(namespace);
    signed_payload.extend_from_slice(payload_bytes);

    verifying_key
        .verify(&signed_payload, &signature)
        .map_err(|_| RegistryError::SignatureVerifyFailed)
}

fn validate_payload_meta<T: RegistryPayload>(
    payload: &T,
    expected_network: &str,
    expected_schema_version: u32,
    last_seen_ts: u64,
) -> std::result::Result<(), RegistryError> {
    if payload.schema_version() != expected_schema_version {
        return Err(RegistryError::SchemaMismatch {
            expected: expected_schema_version,
            got: payload.schema_version(),
        });
    }

    if payload.network() != expected_network {
        return Err(RegistryError::NetworkMismatch {
            expected: expected_network.to_string(),
            got: payload.network().to_string(),
        });
    }

    let now_ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);

    // Clock-skew defence — 5 minute slack for legitimate NTP drift.
    if payload.unix_ts() > now_ts + 300 {
        return Err(RegistryError::ClockSkew {
            payload_ts: payload.unix_ts(),
            now_ts,
        });
    }

    // Replay defence — payload must be strictly newer than last-seen.
    if last_seen_ts > 0 && payload.unix_ts() <= last_seen_ts {
        return Err(RegistryError::StalePayload {
            payload_ts: payload.unix_ts(),
            last_seen_ts,
        });
    }

    Ok(())
}

// ─── tests ─────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};

    /// Deterministic test signing key. Never used in production.
    fn test_keys() -> (SigningKey, [u8; 32]) {
        let seed = [7u8; 32];
        let sk = SigningKey::from_bytes(&seed);
        let pk = sk.verifying_key().to_bytes();
        (sk, pk)
    }

    /// Synthetic registry payload for the unit tests. Real callers
    /// (faucet, coord) will define their own struct with real fields;
    /// this fixture exercises only the trait + validation.
    #[derive(Serialize, Deserialize, Debug)]
    struct TestPayload {
        pub schema_version: u32,
        pub network: String,
        pub unix_ts: u64,
        pub entries: Vec<String>,
    }
    impl RegistryPayload for TestPayload {
        fn network(&self) -> &str {
            &self.network
        }
        fn unix_ts(&self) -> u64 {
            self.unix_ts
        }
        fn schema_version(&self) -> u32 {
            self.schema_version
        }
    }

    const TEST_NAMESPACE: &[u8] = b"coincync-registry-test-v1";

    fn sign_payload(sk: &SigningKey, namespace: &[u8], payload_bytes: &[u8]) -> [u8; 64] {
        let mut signed = Vec::with_capacity(namespace.len() + payload_bytes.len());
        signed.extend_from_slice(namespace);
        signed.extend_from_slice(payload_bytes);
        sk.sign(&signed).to_bytes()
    }

    #[test]
    fn signature_verifies_when_namespace_and_payload_and_key_match() {
        let (sk, pk) = test_keys();
        let payload_bytes = br#"{"schema_version":1,"network":"testnet","unix_ts":0,"entries":[]}"#;
        let sig = sign_payload(&sk, TEST_NAMESPACE, payload_bytes);
        verify_signature(&pk, TEST_NAMESPACE, payload_bytes, &sig).expect("must verify");
    }

    #[test]
    fn signature_rejected_when_namespace_differs() {
        let (sk, pk) = test_keys();
        let payload_bytes = br#"{"schema_version":1,"network":"testnet","unix_ts":0,"entries":[]}"#;
        let sig = sign_payload(&sk, b"different-namespace-v1", payload_bytes);
        let err = verify_signature(&pk, TEST_NAMESPACE, payload_bytes, &sig)
            .expect_err("must reject cross-namespace signature");
        assert!(matches!(err, RegistryError::SignatureVerifyFailed));
    }

    #[test]
    fn signature_rejected_when_payload_tampered() {
        let (sk, pk) = test_keys();
        let payload_bytes = br#"{"schema_version":1,"network":"testnet","unix_ts":0,"entries":[]}"#;
        let sig = sign_payload(&sk, TEST_NAMESPACE, payload_bytes);
        let tampered = br#"{"schema_version":1,"network":"testnet","unix_ts":9,"entries":[]}"#;
        let err = verify_signature(&pk, TEST_NAMESPACE, tampered, &sig)
            .expect_err("must reject tampered payload");
        assert!(matches!(err, RegistryError::SignatureVerifyFailed));
    }

    #[test]
    fn signature_rejected_when_length_not_64() {
        let (_, pk) = test_keys();
        let short = vec![0u8; 32];
        let long = vec![0u8; 96];
        assert!(matches!(
            verify_signature(&pk, TEST_NAMESPACE, b"any", &short),
            Err(RegistryError::SignatureInvalidLength { actual: 32 })
        ));
        assert!(matches!(
            verify_signature(&pk, TEST_NAMESPACE, b"any", &long),
            Err(RegistryError::SignatureInvalidLength { actual: 96 })
        ));
    }

    #[test]
    fn validate_payload_rejects_wrong_network() {
        let payload = TestPayload {
            schema_version: 1,
            network: "mainnet".into(),
            unix_ts: 0,
            entries: vec![],
        };
        let err = validate_payload_meta(&payload, "testnet", 1, 0)
            .expect_err("must reject network mismatch");
        assert!(matches!(
            err,
            RegistryError::NetworkMismatch { expected: _, got: _ }
        ));
    }

    #[test]
    fn validate_payload_rejects_wrong_schema() {
        let payload = TestPayload {
            schema_version: 42,
            network: "testnet".into(),
            unix_ts: 0,
            entries: vec![],
        };
        let err = validate_payload_meta(&payload, "testnet", 1, 0)
            .expect_err("must reject schema mismatch");
        assert!(matches!(err, RegistryError::SchemaMismatch { expected: 1, got: 42 }));
    }

    #[test]
    fn validate_payload_rejects_stale_replay() {
        let payload = TestPayload {
            schema_version: 1,
            network: "testnet".into(),
            unix_ts: 100,
            entries: vec![],
        };
        // last_seen_ts = 100 → payload must be > 100; equal is stale.
        let err = validate_payload_meta(&payload, "testnet", 1, 100)
            .expect_err("must reject replay");
        assert!(matches!(err, RegistryError::StalePayload { .. }));
    }

    #[test]
    fn validate_payload_accepts_fresh_after_last_seen() {
        let payload = TestPayload {
            schema_version: 1,
            network: "testnet".into(),
            unix_ts: 101,
            entries: vec![],
        };
        // last_seen_ts = 100 → payload_ts 101 is strictly greater → OK
        validate_payload_meta(&payload, "testnet", 1, 100)
            .expect("payload newer than last-seen must accept");
    }

    #[test]
    fn validate_payload_rejects_future_beyond_slack() {
        // 1 hour in the future — beyond the 5-minute slack
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let payload = TestPayload {
            schema_version: 1,
            network: "testnet".into(),
            unix_ts: now + 3600,
            entries: vec![],
        };
        let err = validate_payload_meta(&payload, "testnet", 1, 0)
            .expect_err("must reject far-future payload");
        assert!(matches!(err, RegistryError::ClockSkew { .. }));
    }

    #[test]
    fn validate_payload_accepts_within_ntp_slack() {
        // 2 minutes in the future — well within the 5-minute slack
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let payload = TestPayload {
            schema_version: 1,
            network: "testnet".into(),
            unix_ts: now + 120,
            entries: vec![],
        };
        validate_payload_meta(&payload, "testnet", 1, 0)
            .expect("small clock skew must be tolerated");
    }

    #[test]
    fn validate_payload_ignores_replay_gate_on_fresh_cold_start() {
        // last_seen_ts=0 means "we have never accepted a payload before";
        // any valid unix_ts is fine.
        let payload = TestPayload {
            schema_version: 1,
            network: "testnet".into(),
            unix_ts: 1,
            entries: vec![],
        };
        validate_payload_meta(&payload, "testnet", 1, 0)
            .expect("fresh cold-start must accept any past ts");
    }

    #[test]
    fn registry_pointer_round_trips_through_json() {
        let pointer = RegistryPointer {
            schema_version: 1,
            unix_ts: 1_700_000_000,
            payload_cid: "bafybeitest".into(),
            signature_cid: "bafybeisig".into(),
            source: Some("relay1".into()),
            entry_count: Some(3),
        };
        let json = serde_json::to_string(&pointer).expect("serialize");
        let back: RegistryPointer = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(back.schema_version, 1);
        assert_eq!(back.unix_ts, 1_700_000_000);
        assert_eq!(back.payload_cid, "bafybeitest");
        assert_eq!(back.signature_cid, "bafybeisig");
        assert_eq!(back.source.as_deref(), Some("relay1"));
        assert_eq!(back.entry_count, Some(3));
    }

    #[test]
    fn registry_pointer_accepts_missing_optional_fields() {
        let minimal = r#"{"schema_version":1,"unix_ts":100,"payload_cid":"cidX","signature_cid":"cidY"}"#;
        let p: RegistryPointer = serde_json::from_str(minimal).expect("parse minimal");
        assert_eq!(p.schema_version, 1);
        assert!(p.source.is_none());
        assert!(p.entry_count.is_none());
    }
}
