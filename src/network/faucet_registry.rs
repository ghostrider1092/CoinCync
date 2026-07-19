//! # Faucet registry consumer (Fort-Knox item 2)
//!
//! Fetches the current fleet + community faucet directory from IPFS
//! via the generic [`signed_registry`](super::signed_registry) path.
//! Wallets consult this to show users a live list of testnet faucets;
//! failure to fetch is soft-fail (wallet still runs, just doesn't
//! show a dynamic faucet list).
//!
//! ## Topology (per operator decision)
//!
//! Federated community-run: multiple independent faucets, each with
//! its own wallet + rate-limit DB. The signed registry is the
//! discovery mechanism — a maintainer-signed JSON blob lists live
//! faucets. Users pick which they want to hit. If one is down,
//! rate-limited, or drained, another likely works.
//!
//! Rate limits between instances are DELIBERATELY independent — a
//! determined user can hit each one, but total testnet CYNC dripped
//! is bounded by (drip_amount × instance_count × cooldown_windows),
//! which stays small compared to the testnet supply.
//!
//! ## Trust model
//!
//! Trust is in the maintainer's Ed25519 signature over the registry
//! payload, NOT in the URLs themselves. If a community faucet
//! misbehaves (steals request info, doesn't drip, phishes), the
//! maintainer removes it from the next signed registry. Users get
//! updated within one publish cycle (weekly by default).
//!
//! Users who want a stricter trust posture can still hit
//! `faucet.coincync.network` directly without going through the
//! registry — this module is additive, not a mandate.
//!
//! ## Namespace + schema version
//!
//! - Namespace `b"coincync-faucet-registry-v1"` — DISTINCT from the
//!   peer-snapshot and coordinator-registry namespaces. A signature
//!   valid for one CANNOT be replayed as another; see
//!   [`signed_registry`] for the domain-separation guarantee.
//! - Schema version `1`. Bumped on incompatible layout changes.

use serde::{Deserialize, Serialize};

use crate::network::signed_registry::{fetch_verified_json, RegistryError, RegistryPayload};

/// Domain-separator for faucet-registry signatures. See module docs.
pub const FAUCET_REGISTRY_NAMESPACE: &[u8] = b"coincync-faucet-registry-v1";

/// Current schema version. Bumped on incompatible layout changes.
pub const FAUCET_REGISTRY_SCHEMA_VERSION: u32 = 1;

/// Registry payload size cap. 32 KB comfortably fits dozens of
/// entries (each entry is ~200 bytes worst case).
pub const MAX_FAUCET_REGISTRY_BYTES: usize = 32 * 1024;

/// Env var holding the maintainer Ed25519 public key (32 bytes hex).
/// Reuses the same key as the peer-snapshot consumer — same
/// maintainer, single ceremony, one key to rotate.
///
/// Kept as its OWN const so a future decision to split maintainer
/// authority per-service (e.g. delegate faucet registry signing to a
/// community steward) can flip this without touching peer-snapshot.
pub const MAINTAINER_PUBKEY_ENV: &str = "COINCYNC_PEER_SNAPSHOT_PUBKEY";

/// One entry in the faucet directory.
///
/// Reasonable-minimum fields — enough for a wallet to render a
/// picker + let the user click through. Anything more elaborate
/// (per-faucet fee schedules, geolocated availability, …) can wait
/// for a schema bump.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FaucetEntry {
    /// Short-name label for UI display. Not a stable identifier.
    /// Example: `"fleet-testnet-primary"`, `"community-alice"`.
    pub name: String,

    /// Full HTTPS URL of the faucet's `/faucet` POST endpoint.
    /// Example: `"https://faucet.coincync.network"`.
    pub url: String,

    /// Who runs this instance — `"fleet"` for maintainer-run,
    /// `"community"` for anyone else. UI can badge community
    /// entries so users know the trust boundary.
    pub operator: String,

    /// Optional free-form description. Community operators can put
    /// their Discord handle, contact email, project affiliation, etc.
    /// Wallet should truncate/sanitize before display.
    pub description: Option<String>,

    /// Advertised drip amount in atomic units (10⁻¹² CYNC).
    /// Wallet displays this so users can plan how many claims they
    /// need. Advisory only — the actual drip is whatever the faucet
    /// server chooses to send.
    pub drip_amount_atomic: u64,

    /// Which network this entry serves. Must match the wallet's
    /// active network before the wallet shows it. Redundant with
    /// the outer `network` field on the registry, but per-entry
    /// scoping makes it easy to bundle multi-network directories
    /// in the future.
    pub network: String,

    /// When the producer last verified this entry was live (unix
    /// seconds). Wallets can badge entries older than X days as
    /// "stale — may not respond."
    pub last_seen: u64,
}

/// The signed registry payload. Producer publishes this to IPFS;
/// consumer parses it here.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FaucetRegistry {
    /// Payload schema version. Must equal
    /// [`FAUCET_REGISTRY_SCHEMA_VERSION`].
    pub schema_version: u32,

    /// Which network this registry is for. Must match the wallet's
    /// active network before any entry is considered.
    pub network: String,

    /// When the producer signed this registry (unix seconds).
    /// Consumer uses this for replay defence: a fresh registry must
    /// be strictly newer than any previously accepted registry.
    pub unix_ts: u64,

    /// The live-faucet directory. Ordered by the producer; consumer
    /// may re-order for its own UI (e.g. fleet-run first, community
    /// alphabetical).
    pub faucets: Vec<FaucetEntry>,
}

impl RegistryPayload for FaucetRegistry {
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

/// Consumer entry point. Fetches, verifies, and returns the current
/// signed faucet registry.
///
/// Failure modes are returned as [`RegistryError`]. Callers should
/// log the specific error and fall back to the compiled-in
/// canonical faucet (`https://faucet.coincync.network`) — a
/// wallet with NO faucet at all is worse UX than one with a stale
/// canonical entry.
///
/// - `pointer_url`: well-known URL of the pointer JSON, e.g.
///   `https://coincync.network/faucet-registry/latest-testnet.json`.
/// - `expected_network`: the wallet's active network name
///   (`"testnet"`, `"mainnet"`, `"regtest"`). Payloads whose
///   `network` field differs are rejected before parsing entries.
/// - `last_seen_ts`: the `unix_ts` of the previous registry the
///   wallet accepted. Pass 0 on truly-fresh cold start. Payloads
///   whose `unix_ts <= last_seen_ts` are rejected as replays.
/// - `pubkey`: 32-byte Ed25519 maintainer verifying key. Callers
///   typically obtain this via [`maintainer_pubkey_from_env`] on
///   the same env var as the peer-snapshot consumer.
pub async fn fetch_verified_faucet_registry(
    pointer_url: &str,
    expected_network: &str,
    last_seen_ts: u64,
    pubkey: &[u8; 32],
) -> std::result::Result<FaucetRegistry, RegistryError> {
    fetch_verified_json::<FaucetRegistry>(
        pointer_url,
        expected_network,
        FAUCET_REGISTRY_SCHEMA_VERSION,
        last_seen_ts,
        pubkey,
        FAUCET_REGISTRY_NAMESPACE,
        MAX_FAUCET_REGISTRY_BYTES,
    )
    .await
}

/// Resolve the maintainer public key from env, returning None if
/// unset or malformed. Callers that get None should treat the
/// registry fallback as disabled and fall back to the compiled-in
/// canonical faucet.
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn faucet_entry_round_trips_through_json() {
        let e = FaucetEntry {
            name: "fleet-testnet-primary".into(),
            url: "https://faucet.coincync.network".into(),
            operator: "fleet".into(),
            description: Some("Canonical fleet-run testnet faucet.".into()),
            drip_amount_atomic: 10_000_000_000_000,
            network: "testnet".into(),
            last_seen: 1_751_600_000,
        };
        let json = serde_json::to_string(&e).expect("serialize");
        let back: FaucetEntry = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(back.name, e.name);
        assert_eq!(back.url, e.url);
        assert_eq!(back.operator, e.operator);
        assert_eq!(back.description, e.description);
        assert_eq!(back.drip_amount_atomic, e.drip_amount_atomic);
        assert_eq!(back.network, e.network);
        assert_eq!(back.last_seen, e.last_seen);
    }

    #[test]
    fn faucet_entry_accepts_missing_description() {
        let minimal = r#"{
            "name": "community-alice",
            "url": "https://alice.example/faucet",
            "operator": "community",
            "drip_amount_atomic": 5000000000000,
            "network": "testnet",
            "last_seen": 1751600000
        }"#;
        let e: FaucetEntry = serde_json::from_str(minimal).expect("parse minimal entry");
        assert_eq!(e.name, "community-alice");
        assert_eq!(e.operator, "community");
        assert!(e.description.is_none());
    }

    #[test]
    fn faucet_registry_implements_registry_payload_correctly() {
        let r = FaucetRegistry {
            schema_version: FAUCET_REGISTRY_SCHEMA_VERSION,
            network: "testnet".into(),
            unix_ts: 1_751_600_000,
            faucets: vec![],
        };
        // Trait accessors expose the same fields the generic
        // validator inspects — verify they line up.
        assert_eq!(r.schema_version(), FAUCET_REGISTRY_SCHEMA_VERSION);
        assert_eq!(r.network(), "testnet");
        assert_eq!(r.unix_ts(), 1_751_600_000);
    }

    #[test]
    fn faucet_registry_round_trips_with_multiple_entries() {
        let r = FaucetRegistry {
            schema_version: FAUCET_REGISTRY_SCHEMA_VERSION,
            network: "testnet".into(),
            unix_ts: 1_751_600_000,
            faucets: vec![
                FaucetEntry {
                    name: "fleet-testnet-primary".into(),
                    url: "https://faucet.coincync.network".into(),
                    operator: "fleet".into(),
                    description: None,
                    drip_amount_atomic: 10_000_000_000_000,
                    network: "testnet".into(),
                    last_seen: 1_751_599_000,
                },
                FaucetEntry {
                    name: "community-alice".into(),
                    url: "https://alice.example/faucet".into(),
                    operator: "community".into(),
                    description: Some("Discord: alice#0001".into()),
                    drip_amount_atomic: 5_000_000_000_000,
                    network: "testnet".into(),
                    last_seen: 1_751_598_000,
                },
            ],
        };
        let json = serde_json::to_string(&r).expect("serialize");
        let back: FaucetRegistry = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(back.faucets.len(), 2);
        assert_eq!(back.faucets[0].operator, "fleet");
        assert_eq!(back.faucets[1].operator, "community");
    }

    #[test]
    fn maintainer_pubkey_from_env_rejects_wrong_length() {
        // Shared lock: this var is also mutated by peer_snapshot's tests
        // (same env string) — serialize across both modules.
        let _env_guard = crate::network::MAINTAINER_ENV_TEST_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        // Save + restore any pre-existing env value; other tests may
        // have set it.
        let saved = std::env::var(MAINTAINER_PUBKEY_ENV).ok();
        std::env::set_var(MAINTAINER_PUBKEY_ENV, "deadbeef"); // 4 bytes, not 32
        assert!(maintainer_pubkey_from_env().is_none());
        std::env::remove_var(MAINTAINER_PUBKEY_ENV);
        assert!(maintainer_pubkey_from_env().is_none());
        if let Some(v) = saved {
            std::env::set_var(MAINTAINER_PUBKEY_ENV, v);
        }
    }

    #[test]
    fn maintainer_pubkey_from_env_accepts_32_byte_hex() {
        let _env_guard = crate::network::MAINTAINER_ENV_TEST_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let saved = std::env::var(MAINTAINER_PUBKEY_ENV).ok();
        // 32 bytes of 0xAB
        let key_hex = "ab".repeat(32);
        std::env::set_var(MAINTAINER_PUBKEY_ENV, &key_hex);
        let got = maintainer_pubkey_from_env().expect("must parse 32-byte hex");
        assert_eq!(got, [0xABu8; 32]);
        // Cleanup
        std::env::remove_var(MAINTAINER_PUBKEY_ENV);
        if let Some(v) = saved {
            std::env::set_var(MAINTAINER_PUBKEY_ENV, v);
        }
    }

    #[test]
    fn namespace_differs_from_peer_snapshot() {
        // Cross-service replay defence relies on distinct namespaces.
        // Lock this into a test so a future edit can't accidentally
        // align the strings.
        assert_ne!(
            FAUCET_REGISTRY_NAMESPACE,
            crate::network::peer_snapshot::SIGNATURE_NAMESPACE,
            "faucet-registry MUST have a distinct signing namespace from \
             peer-snapshot to prevent cross-service signature replay",
        );
    }
}
