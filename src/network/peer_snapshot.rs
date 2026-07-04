//! # Signed peer-snapshot bootstrap fallback (Fort-Knox Item 6, consumer half)
//!
//! Fetches a maintainer-signed peer address list from IPFS and uses it
//! as a fallback bootstrap path when DNS seeds AND hardcoded seed
//! nodes are both unreachable.
//!
//! Producer side: `scripts/publish-peer-snapshot.sh` (PR #136).
//!
//! ## Trust model
//!
//! The trust is in the **signature**, not the delivery channel. An
//! attacker who controls one IPFS gateway can serve any CID; they
//! cannot forge a valid signature under the maintainer's key.
//!
//! Consumer contract:
//!   1. Fetch the well-known pointer URL
//!      (`https://coincync.network/bootstrap/latest-<network>.json`)
//!      to learn the CURRENT snapshot's IPFS CIDs.
//!   2. Try each configured IPFS gateway in turn until one serves the
//!      snapshot bytes + signature bytes.
//!   3. Verify the signature against [`MAINTAINER_PUBKEY`] (baked into
//!      the binary).
//!   4. Sanity-check the snapshot: network matches, unix_ts is in the
//!      past AND newer than the last-seen snapshot (replay defence).
//!   5. Extract the routable peer addresses.
//!
//! ## Wire-format vs producer
//!
//! The producer script signs the snapshot JSON with `ssh-keygen -Y sign`
//! by default; that format is a PEM-armored envelope wrapping an
//! Ed25519 signature. To keep the consumer dep surface small (no
//! `ssh-key` crate), we require the SIGNATURE FILE to be **raw
//! 64-byte Ed25519** when it lands on IPFS. The producer script needs
//! a small update to emit raw bytes instead of the PEM envelope — see
//! `docs/operations/signed-peer-snapshots.md` "Producer wire-format
//! v2" note (added alongside this PR).
//!
//! Rationale: `ed25519-dalek` is already in the crate's dep tree
//! (see `wallet::wallet_keys`, `network::bootstrap` uses `Verifier`).
//! Adding `ssh-key` would pull ~40 KB of parser code plus its own
//! transitive deps, all to reach the same 64-byte primitive.
//!
//! ## What this does NOT do (honest scope)
//!
//! - **Maintainer key rotation**: [`MAINTAINER_PUBKEY`] is a fixed
//!   const for v1.0. Rotation belongs in a release-process addition,
//!   out of scope here.
//! - **IPFS gateway health scoring**: we try gateways in a fixed
//!   order, no adaptive ranking. Adequate for a monthly cold-start
//!   event; a hot-path cache would be premature optimization.
//! - **Automatic snapshot refresh**: the consumer fetches on cold
//!   start only. A long-running node doesn't re-poll — its live P2P
//!   peer discovery is authoritative once the mesh is established.
//! - **Onion transport**: gateway URLs are clearnet HTTPS. Tor-mode
//!   nodes would need to add .onion IPFS gateway URLs; deferred.

use std::net::SocketAddr;
use std::time::Duration;

use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use tracing::{debug, info};

// ─── constants ─────────────────────────────────────────────────────────

/// Env var holding the maintainer Ed25519 public key (32 bytes as hex).
///
/// Follows the same pattern as the existing local-manifest bootstrap
/// (`COINCYNC_BOOTSTRAP_SIGNING_PUBKEY`) so operators can enable
/// snapshot-fetching without a new binary. If unset, the snapshot
/// fallback is disabled entirely — the caller falls through to the
/// next bootstrap path (typically hardcoded seeds).
///
/// The "no key = disabled" default is intentional: it means a
/// mis-shipped binary CANNOT accept any real-world snapshot until an
/// operator deliberately enables it, and the failure mode is
/// "bootstrap falls through to hardcoded seeds", which is safe.
pub const MAINTAINER_PUBKEY_ENV: &str = "COINCYNC_PEER_SNAPSHOT_PUBKEY";

/// Namespace string used in signature domain-separation.
///
/// The signature is over
/// `H("coincync-peer-snapshot-v1" || snapshot_bytes)` — the namespace
/// prevents a signature over ANOTHER coincync-signed artifact
/// (release tag, checkpoint) from being replayed as a peer snapshot.
pub const SIGNATURE_NAMESPACE: &[u8] = b"coincync-peer-snapshot-v1";

/// IPFS gateways tried in order until one serves the snapshot bytes.
///
/// Each entry must accept `{gateway}/ipfs/{cid}` and return the raw
/// content. All three are commonly-used public gateways with
/// independent operators — no single failure or ban takes them all
/// down.
pub const IPFS_GATEWAYS: &[&str] = &[
    "https://cloudflare-ipfs.com",
    "https://ipfs.io",
    "https://dweb.link",
];

/// HTTP timeout per gateway request. Bootstrap is not latency-
/// sensitive; a generous timeout lets slow gateways still respond.
pub const GATEWAY_TIMEOUT: Duration = Duration::from_secs(30);

/// Maximum snapshot size accepted from any gateway. A legitimate
/// snapshot is a few KB. Anything larger is either a malicious
/// gateway serving garbage or a schema drift, both of which we want
/// to reject cheaply before parsing.
pub const MAX_SNAPSHOT_BYTES: usize = 128 * 1024;

// ─── wire format ───────────────────────────────────────────────────────

/// Well-known-URL pointer file.
///
/// A short JSON blob published at
/// `https://coincync.network/bootstrap/latest-<network>.json`. Tells
/// a fresh node which IPFS CIDs to fetch for the current snapshot.
///
/// Kept small (few hundred bytes) so it fits in the average Cloudflare
/// edge cache and returns quickly.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SnapshotPointer {
    /// Schema version — bumped on incompatible layout changes.
    pub schema_version: u32,
    /// When the snapshot was captured (unix seconds, UTC).
    pub unix_ts: u64,
    /// IPFS CID of the snapshot JSON bytes.
    pub snapshot_cid: String,
    /// IPFS CID of the raw 64-byte Ed25519 signature over
    /// `H(SIGNATURE_NAMESPACE || snapshot_bytes)`.
    pub signature_cid: String,
    /// Source fleet host name (advisory; not verified).
    pub source_host: Option<String>,
    /// Chain-tip height at capture (advisory freshness signal).
    pub chain_tip_height: Option<u64>,
    /// Number of peer entries in the snapshot (advisory sanity check).
    pub peer_count: Option<u32>,
}

/// The canonical peer-snapshot payload signed by the maintainer.
///
/// Matches the JSON schema in
/// `docs/operations/signed-peer-snapshots.md`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignedPeerSnapshot {
    pub schema_version: u32,
    pub network: String,
    pub unix_ts: u64,
    pub chain_tip_height: u64,
    pub chain_tip_hash: String,
    pub peers: Vec<PeerEntry>,
}

/// A single peer entry — dial-able listen address + last-seen timestamp.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerEntry {
    pub addr: String,
    pub last_seen: u64,
}

// ─── errors ────────────────────────────────────────────────────────────

/// Reasons the snapshot fallback might not yield peers. Each is a
/// specific-enough failure mode that the caller can log meaningfully
/// and decide whether to retry, alert, or fall through.
#[derive(Debug)]
pub enum SnapshotError {
    PointerUnreachable(String),
    PointerParseError(String),
    AllGatewaysFailed { attempts: Vec<String> },
    SnapshotTooLarge { actual: usize, max: usize },
    SnapshotParseError(String),
    SignatureInvalidLength { actual: usize },
    SignatureVerifyFailed,
    NetworkMismatch { expected: String, got: String },
    ClockSkew { snapshot_ts: u64, now_ts: u64 },
    StaleSnapshot { snapshot_ts: u64, last_seen_ts: u64 },
    NoPeersInSnapshot,
}

impl std::fmt::Display for SnapshotError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::PointerUnreachable(url) => {
                write!(f, "well-known snapshot pointer unreachable: {}", url)
            }
            Self::PointerParseError(e) => write!(f, "snapshot pointer JSON parse failed: {}", e),
            Self::AllGatewaysFailed { attempts } => {
                write!(
                    f,
                    "all {} IPFS gateways failed to serve the snapshot",
                    attempts.len()
                )
            }
            Self::SnapshotTooLarge { actual, max } => {
                write!(f, "snapshot exceeded byte cap: {} > {}", actual, max)
            }
            Self::SnapshotParseError(e) => write!(f, "snapshot JSON parse failed: {}", e),
            Self::SignatureInvalidLength { actual } => {
                write!(f, "signature file must be 64 raw Ed25519 bytes, got {}", actual)
            }
            Self::SignatureVerifyFailed => {
                write!(f, "signature verification failed against maintainer public key")
            }
            Self::NetworkMismatch { expected, got } => {
                write!(f, "snapshot network mismatch: expected {}, got {}", expected, got)
            }
            Self::ClockSkew { snapshot_ts, now_ts } => {
                write!(f, "snapshot timestamp {} is in the future (now = {})", snapshot_ts, now_ts)
            }
            Self::StaleSnapshot { snapshot_ts, last_seen_ts } => {
                write!(
                    f,
                    "snapshot ts {} is not newer than last-accepted ts {} (replay defence)",
                    snapshot_ts, last_seen_ts
                )
            }
            Self::NoPeersInSnapshot => write!(f, "snapshot contains no peer entries"),
        }
    }
}

impl std::error::Error for SnapshotError {}

// ─── fetch + verify pipeline ────────────────────────────────────────────

/// The complete cold-start snapshot flow.
///
/// Called by [`crate::network::bootstrap::Bootstrapper`] only after
/// DNS seeds AND hardcoded seed nodes have both yielded fewer than
/// the minimum bootstrap peer count.
///
/// Arguments:
/// - `pointer_url`: the well-known-URL to fetch the current
///   `SnapshotPointer`, e.g.
///   `https://coincync.network/bootstrap/latest-testnet.json`
/// - `expected_network`: `"testnet"` / `"mainnet"` — snapshots for
///   the wrong network are rejected before their peers can be used
/// - `last_seen_snapshot_ts`: replay defence — snapshot must be
///   NEWER than the last one this node accepted. Pass 0 on truly
///   fresh cold-start.
///
/// Returns dial-able `SocketAddr`s on success.
pub async fn fetch_verified_peers(
    pointer_url: &str,
    expected_network: &str,
    last_seen_snapshot_ts: u64,
    maintainer_pubkey: &[u8; 32],
) -> std::result::Result<Vec<SocketAddr>, SnapshotError> {
    let client = Client::builder()
        .timeout(GATEWAY_TIMEOUT)
        .user_agent(format!("coincync/{}", env!("CARGO_PKG_VERSION")))
        .build()
        .map_err(|e| SnapshotError::PointerUnreachable(format!("reqwest build: {}", e)))?;

    let pointer = fetch_pointer(&client, pointer_url).await?;
    info!(
        target: "peer_snapshot",
        "fetched snapshot pointer: unix_ts={} snapshot_cid={} peer_count={:?}",
        pointer.unix_ts, pointer.snapshot_cid, pointer.peer_count,
    );

    let (snapshot_bytes, signature_bytes) = fetch_from_gateways(
        &client,
        &pointer.snapshot_cid,
        &pointer.signature_cid,
    )
    .await?;

    verify_signature_with(maintainer_pubkey, &snapshot_bytes, &signature_bytes)?;

    let snapshot: SignedPeerSnapshot = serde_json::from_slice(&snapshot_bytes)
        .map_err(|e| SnapshotError::SnapshotParseError(e.to_string()))?;

    validate_snapshot(&snapshot, expected_network, last_seen_snapshot_ts)?;

    let peers: Vec<SocketAddr> = snapshot
        .peers
        .iter()
        .filter_map(|p| p.addr.parse::<SocketAddr>().ok())
        .collect();

    if peers.is_empty() {
        return Err(SnapshotError::NoPeersInSnapshot);
    }

    info!(
        target: "peer_snapshot",
        "verified snapshot delivered {} routable peers (schema_version={}, network={}, unix_ts={})",
        peers.len(), snapshot.schema_version, snapshot.network, snapshot.unix_ts,
    );

    Ok(peers)
}

async fn fetch_pointer(
    client: &Client,
    url: &str,
) -> std::result::Result<SnapshotPointer, SnapshotError> {
    let resp = client
        .get(url)
        .send()
        .await
        .map_err(|e| SnapshotError::PointerUnreachable(format!("{}: {}", url, e)))?;

    if !resp.status().is_success() {
        return Err(SnapshotError::PointerUnreachable(format!(
            "{} returned HTTP {}",
            url,
            resp.status()
        )));
    }

    let body = resp
        .text()
        .await
        .map_err(|e| SnapshotError::PointerUnreachable(format!("read body: {}", e)))?;

    serde_json::from_str(&body).map_err(|e| SnapshotError::PointerParseError(e.to_string()))
}

async fn fetch_from_gateways(
    client: &Client,
    snapshot_cid: &str,
    signature_cid: &str,
) -> std::result::Result<(Vec<u8>, Vec<u8>), SnapshotError> {
    let mut attempts: Vec<String> = Vec::with_capacity(IPFS_GATEWAYS.len());

    for gateway in IPFS_GATEWAYS {
        let snap_url = format!("{}/ipfs/{}", gateway, snapshot_cid);
        let sig_url = format!("{}/ipfs/{}", gateway, signature_cid);
        debug!(target: "peer_snapshot", "trying gateway {}", gateway);

        let snap_result = fetch_bounded(client, &snap_url, MAX_SNAPSHOT_BYTES).await;
        let sig_result = fetch_bounded(client, &sig_url, 128).await;

        match (snap_result, sig_result) {
            (Ok(snap), Ok(sig)) => {
                debug!(
                    target: "peer_snapshot",
                    "gateway {} served snapshot ({} bytes) + signature ({} bytes)",
                    gateway, snap.len(), sig.len(),
                );
                return Ok((snap, sig));
            }
            (Err(e_snap), Err(e_sig)) => {
                attempts.push(format!("{} (snap: {}, sig: {})", gateway, e_snap, e_sig));
            }
            (Err(e), _) | (_, Err(e)) => {
                attempts.push(format!("{} ({})", gateway, e));
            }
        }
    }

    Err(SnapshotError::AllGatewaysFailed { attempts })
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

    // Length-check via Content-Length header first; cheap rejection
    // before we buffer any body bytes.
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

/// Resolve the maintainer public key from env, returning None if
/// unset or malformed. Callers that get None should treat the
/// snapshot fallback as disabled.
pub fn maintainer_pubkey_from_env() -> Option<[u8; 32]> {
    let hex_str = std::env::var(MAINTAINER_PUBKEY_ENV).ok()?;
    let hex_trimmed = hex_str.trim();
    if hex_trimmed.is_empty() {
        return None;
    }
    let bytes = hex::decode(hex_trimmed).ok()?;
    if bytes.len() != 32 {
        return None;
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Some(out)
}

fn verify_signature_with(
    pubkey: &[u8; 32],
    snapshot_bytes: &[u8],
    signature_bytes: &[u8],
) -> std::result::Result<(), SnapshotError> {
    if signature_bytes.len() != 64 {
        return Err(SnapshotError::SignatureInvalidLength {
            actual: signature_bytes.len(),
        });
    }
    let sig_bytes: [u8; 64] = signature_bytes
        .try_into()
        .expect("length 64 confirmed above");

    let signature = Signature::from_bytes(&sig_bytes);
    let verifying_key = VerifyingKey::from_bytes(pubkey)
        .map_err(|_| SnapshotError::SignatureVerifyFailed)?;

    // Domain-separated: sig covers namespace || snapshot_bytes so a
    // signature from any other coincync signing context (release tag,
    // consensus checkpoint, etc.) cannot be replayed here.
    let mut signed_payload = Vec::with_capacity(SIGNATURE_NAMESPACE.len() + snapshot_bytes.len());
    signed_payload.extend_from_slice(SIGNATURE_NAMESPACE);
    signed_payload.extend_from_slice(snapshot_bytes);

    verifying_key
        .verify(&signed_payload, &signature)
        .map_err(|_| SnapshotError::SignatureVerifyFailed)
}

fn validate_snapshot(
    snapshot: &SignedPeerSnapshot,
    expected_network: &str,
    last_seen_snapshot_ts: u64,
) -> std::result::Result<(), SnapshotError> {
    if snapshot.network != expected_network {
        return Err(SnapshotError::NetworkMismatch {
            expected: expected_network.to_string(),
            got: snapshot.network.clone(),
        });
    }

    let now_ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);

    // Clock-skew defence — reject a snapshot claiming to be from the
    // future. Some slack for legitimate NTP drift: allow up to 5 min
    // ahead of local clock.
    if snapshot.unix_ts > now_ts + 300 {
        return Err(SnapshotError::ClockSkew {
            snapshot_ts: snapshot.unix_ts,
            now_ts,
        });
    }

    // Replay defence — snapshot must be newer than the last one we
    // accepted. On a truly-fresh cold start (last_seen == 0), any
    // snapshot is fine.
    if last_seen_snapshot_ts > 0 && snapshot.unix_ts <= last_seen_snapshot_ts {
        return Err(SnapshotError::StaleSnapshot {
            snapshot_ts: snapshot.unix_ts,
            last_seen_ts: last_seen_snapshot_ts,
        });
    }

    Ok(())
}

// ─── tests ─────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};

    /// Deterministic test signing key. NEVER used outside tests.
    fn test_signing_key() -> SigningKey {
        SigningKey::from_bytes(&[42u8; 32])
    }

    fn test_snapshot_bytes() -> Vec<u8> {
        let snapshot = SignedPeerSnapshot {
            schema_version: 1,
            network: "testnet".to_string(),
            unix_ts: 1751618400,
            chain_tip_height: 9342,
            chain_tip_hash: "abc123".to_string(),
            peers: vec![
                PeerEntry {
                    addr: "216.128.156.239:28080".to_string(),
                    last_seen: 1751618000,
                },
                PeerEntry {
                    addr: "140.82.57.168:28080".to_string(),
                    last_seen: 1751618000,
                },
            ],
        };
        serde_json::to_vec(&snapshot).unwrap()
    }

    fn sign_test_payload(signing_key: &SigningKey, payload: &[u8]) -> [u8; 64] {
        let mut signed = Vec::with_capacity(SIGNATURE_NAMESPACE.len() + payload.len());
        signed.extend_from_slice(SIGNATURE_NAMESPACE);
        signed.extend_from_slice(payload);
        signing_key.sign(&signed).to_bytes()
    }

    /// Local helper: swap MAINTAINER_PUBKEY at test time so we can
    /// verify against a known signing key.
    ///
    /// We don't actually mutate the const; instead we duplicate
    /// verify_signature's logic against a per-test verifying key.
    fn verify_against(pubkey: [u8; 32], payload: &[u8], sig: &[u8; 64]) -> bool {
        let verifying_key = match VerifyingKey::from_bytes(&pubkey) {
            Ok(k) => k,
            Err(_) => return false,
        };
        let signature = Signature::from_bytes(sig);
        let mut signed = Vec::with_capacity(SIGNATURE_NAMESPACE.len() + payload.len());
        signed.extend_from_slice(SIGNATURE_NAMESPACE);
        signed.extend_from_slice(payload);
        verifying_key.verify(&signed, &signature).is_ok()
    }

    #[test]
    fn signature_verifies_over_namespaced_payload() {
        let sk = test_signing_key();
        let pk_bytes: [u8; 32] = sk.verifying_key().to_bytes();
        let payload = test_snapshot_bytes();
        let sig = sign_test_payload(&sk, &payload);
        assert!(verify_against(pk_bytes, &payload, &sig));
    }

    #[test]
    fn signature_rejects_wrong_key() {
        let sk = test_signing_key();
        let wrong_sk = SigningKey::from_bytes(&[7u8; 32]);
        let payload = test_snapshot_bytes();
        let sig = sign_test_payload(&sk, &payload);
        let wrong_pk = wrong_sk.verifying_key().to_bytes();
        assert!(!verify_against(wrong_pk, &payload, &sig));
    }

    #[test]
    fn signature_rejects_tampered_payload() {
        let sk = test_signing_key();
        let pk_bytes: [u8; 32] = sk.verifying_key().to_bytes();
        let payload = test_snapshot_bytes();
        let sig = sign_test_payload(&sk, &payload);
        let mut tampered = payload.clone();
        tampered[0] ^= 0xFF;
        assert!(!verify_against(pk_bytes, &tampered, &sig));
    }

    #[test]
    fn signature_domain_separation_blocks_cross_context_replay() {
        // A signature produced OUTSIDE the SIGNATURE_NAMESPACE must
        // not verify. This blocks an attacker from replaying a
        // signature over e.g. a release tag as if it were a peer
        // snapshot.
        let sk = test_signing_key();
        let pk_bytes: [u8; 32] = sk.verifying_key().to_bytes();
        let payload = test_snapshot_bytes();
        // Sign with a DIFFERENT namespace
        let mut wrong_ns = Vec::with_capacity(20 + payload.len());
        wrong_ns.extend_from_slice(b"coincync-release-v1-");
        wrong_ns.extend_from_slice(&payload);
        let sig = sk.sign(&wrong_ns).to_bytes();
        assert!(!verify_against(pk_bytes, &payload, &sig));
    }

    #[test]
    fn maintainer_pubkey_from_env_returns_none_when_unset() {
        // Preserve any real value the operator has set — clear ONLY for
        // this test scope, restore after. Not thread-safe in isolation
        // but tests run sequentially by default in this crate.
        let prior = std::env::var(MAINTAINER_PUBKEY_ENV).ok();
        std::env::remove_var(MAINTAINER_PUBKEY_ENV);
        assert_eq!(maintainer_pubkey_from_env(), None);
        if let Some(v) = prior {
            std::env::set_var(MAINTAINER_PUBKEY_ENV, v);
        }
    }

    #[test]
    fn maintainer_pubkey_from_env_rejects_wrong_length_hex() {
        let prior = std::env::var(MAINTAINER_PUBKEY_ENV).ok();
        std::env::set_var(MAINTAINER_PUBKEY_ENV, "deadbeef"); // 4 bytes, not 32
        assert_eq!(maintainer_pubkey_from_env(), None);
        std::env::set_var(MAINTAINER_PUBKEY_ENV, "not-hex-at-all");
        assert_eq!(maintainer_pubkey_from_env(), None);
        if let Some(v) = prior {
            std::env::set_var(MAINTAINER_PUBKEY_ENV, v);
        } else {
            std::env::remove_var(MAINTAINER_PUBKEY_ENV);
        }
    }

    #[test]
    fn maintainer_pubkey_from_env_accepts_valid_32byte_hex() {
        let prior = std::env::var(MAINTAINER_PUBKEY_ENV).ok();
        let sk = test_signing_key();
        let pk_hex = hex::encode(sk.verifying_key().to_bytes());
        std::env::set_var(MAINTAINER_PUBKEY_ENV, &pk_hex);
        let loaded = maintainer_pubkey_from_env();
        assert!(loaded.is_some());
        assert_eq!(&loaded.unwrap()[..], &sk.verifying_key().to_bytes()[..]);
        if let Some(v) = prior {
            std::env::set_var(MAINTAINER_PUBKEY_ENV, v);
        } else {
            std::env::remove_var(MAINTAINER_PUBKEY_ENV);
        }
    }

    #[test]
    fn verify_signature_rejects_wrong_length() {
        let too_short = [0u8; 63];
        let too_long = [0u8; 65];
        assert!(matches!(
            verify_signature_with(&[0u8; 32], &[], &too_short),
            Err(SnapshotError::SignatureInvalidLength { actual: 63 })
        ));
        assert!(matches!(
            verify_signature_with(&[0u8; 32], &[], &too_long),
            Err(SnapshotError::SignatureInvalidLength { actual: 65 })
        ));
    }

    #[test]
    fn validate_snapshot_rejects_network_mismatch() {
        let snap = SignedPeerSnapshot {
            schema_version: 1,
            network: "mainnet".to_string(),
            unix_ts: 1000,
            chain_tip_height: 0,
            chain_tip_hash: String::new(),
            peers: vec![],
        };
        let result = validate_snapshot(&snap, "testnet", 0);
        assert!(matches!(
            result,
            Err(SnapshotError::NetworkMismatch { .. })
        ));
    }

    #[test]
    fn validate_snapshot_rejects_replayed_stale_ts() {
        let snap = SignedPeerSnapshot {
            schema_version: 1,
            network: "testnet".to_string(),
            unix_ts: 1000,
            chain_tip_height: 0,
            chain_tip_hash: String::new(),
            peers: vec![],
        };
        // last_seen is newer than snapshot.unix_ts → replay
        let result = validate_snapshot(&snap, "testnet", 2000);
        assert!(matches!(
            result,
            Err(SnapshotError::StaleSnapshot { .. })
        ));
    }

    #[test]
    fn validate_snapshot_rejects_far_future_ts() {
        // Snapshot claiming to be 24 hours in the future
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let snap = SignedPeerSnapshot {
            schema_version: 1,
            network: "testnet".to_string(),
            unix_ts: now + 86400,
            chain_tip_height: 0,
            chain_tip_hash: String::new(),
            peers: vec![],
        };
        let result = validate_snapshot(&snap, "testnet", 0);
        assert!(matches!(result, Err(SnapshotError::ClockSkew { .. })));
    }

    #[test]
    fn validate_snapshot_accepts_matching_network_and_fresh_ts() {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let snap = SignedPeerSnapshot {
            schema_version: 1,
            network: "testnet".to_string(),
            unix_ts: now - 60,
            chain_tip_height: 0,
            chain_tip_hash: String::new(),
            peers: vec![],
        };
        let result = validate_snapshot(&snap, "testnet", 0);
        assert!(result.is_ok(), "expected Ok, got {:?}", result);
    }
}
