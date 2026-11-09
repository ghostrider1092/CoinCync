//! # Chaindata snapshot fast-sync (consumer half)
//!
//! A fresh node started with `--fast-sync` fetches a signed chaindata snapshot
//! and imports it, so it resumes near the chain tip instead of grinding IBD
//! from genesis (RandomX-verifying every block).
//!
//! ## Trust model
//!
//! Trust is in the **signature** and the **checkpoint binding**, NOT the
//! delivery channel. The pointer URL and the tarball host are untrusted: an
//! attacker who controls them can at worst waste our bandwidth, because the
//! actual install goes through [`crate::snapshot::import`], which is
//! fail-closed — it refuses any snapshot that is not signed by a snapshot
//! signer baked into this binary ([`crate::testnet::TESTNET_SNAPSHOT_SIGNERS`])
//! or that disagrees with a hardcoded checkpoint. This mirrors
//! [`crate::network::peer_snapshot`]: "the trust is in the signature, not the
//! delivery channel."
//!
//! ## Honest scope / limits
//!
//! - **Opt-in** — only runs under `--fast-sync`; the default is normal IBD.
//! - **Fail-OPEN on fetch, fail-CLOSED on trust** — a fetch/parse/download
//!   failure logs loudly and falls back to full IBD (the node still works). But
//!   an *untrusted* snapshot is never installed — that guarantee lives in
//!   `snapshot::import`, which this module always routes through.
//! - **Single pointer URL** (overridable via env), no multi-mirror racing yet.
//! - **Format**: an uncompressed tar of the `snapshot-export` output
//!   (`db/` + `manifest.json` + `manifest.sig`). RocksDB SSTs are already
//!   compressed, so gzip would add cost for little gain. Producer side:
//!   `tar -cf snapshot.tar -C <export-dir> .` then publish it plus a pointer
//!   JSON.
//! - **Not Tor-aware** — pointer/tarball URLs are clearnet HTTPS (same caveat
//!   as peer_snapshot). An `onion-only` node should not enable `--fast-sync`.

use std::io::Read;
use std::path::{Path, PathBuf};
use std::time::Duration;

use serde::Deserialize;
use tracing::{info, warn};

use crate::config::NetworkType;

/// Env override for the well-known pointer URL. Lets a private fleet point at
/// its own mirror, and lets tests/local validation use a `file://` URL. When
/// unset, [`default_pointer_url`] is used.
pub const POINTER_URL_ENV: &str = "COINCYNC_FAST_SYNC_POINTER_URL";

/// Pointer JSON is tiny; reject anything larger before parsing.
pub const POINTER_MAX_BYTES: u64 = 64 * 1024;

/// Hard ceiling on the snapshot tarball download, independent of the pointer's
/// advertised `size_bytes`. A real testnet snapshot is a few hundred MB; this
/// bounds a malicious/misconfigured host from streaming us unbounded garbage.
pub const TARBALL_MAX_BYTES: u64 = 8 * 1024 * 1024 * 1024; // 8 GiB

/// Per-request HTTP timeout. Bootstrap is not latency-sensitive; the tarball
/// body stream has its own overall read bound (`TARBALL_MAX_BYTES`).
pub const HTTP_TIMEOUT: Duration = Duration::from_secs(120);

/// Well-known pointer URL for a network's current snapshot. Parallel to
/// `peer_snapshot`'s `latest-<network>.json`.
pub fn default_pointer_url(network: NetworkType) -> String {
    format!(
        "https://coincync.network/bootstrap/snapshot-latest-{}.json",
        net_str(network)
    )
}

fn net_str(n: NetworkType) -> &'static str {
    match n {
        NetworkType::Mainnet => "mainnet",
        NetworkType::Testnet => "testnet",
        NetworkType::Regtest => "regtest",
        NetworkType::Beta => "beta",
    }
}

/// Well-known pointer file published at the pointer URL. Small JSON telling a
/// fresh node where the current snapshot tarball lives. All fields are
/// advisory except `network` (a wrong-chain guard) — real authenticity is
/// enforced downstream by `snapshot::import` over the signed manifest.
#[derive(Debug, Clone, Deserialize)]
pub struct ChainSnapshotPointer {
    /// Schema version — bumped on incompatible layout changes.
    pub schema_version: u32,
    /// Network name ("testnet"/"mainnet"/…). Must match ours or we refuse.
    pub network: String,
    /// Chain height captured in the snapshot (advisory freshness signal).
    pub height: u64,
    /// Tip hash at capture (advisory; the manifest inside the tarball is
    /// authoritative).
    pub tip_hash: String,
    /// URL of the snapshot tarball (`https://…` or `file://…`).
    pub tarball_url: String,
    /// Advertised tarball size, used to bound the download early. Clamped to
    /// `TARBALL_MAX_BYTES` regardless.
    pub size_bytes: Option<u64>,
    /// When the snapshot was captured (unix seconds; advisory).
    pub unix_ts: Option<u64>,
}

/// Why a fast-sync attempt did not install a snapshot. Every variant is a
/// fall-back-to-IBD condition, not a fatal node error — the caller logs it and
/// proceeds with normal sync.
#[derive(Debug)]
pub enum FastSyncError {
    PointerUnreachable(String),
    PointerParse(String),
    NetworkMismatch { expected: String, got: String },
    DownloadFailed(String),
    TooLarge { max: u64 },
    ExtractFailed(String),
    BadArchive(String),
    Io(String),
}

impl std::fmt::Display for FastSyncError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::PointerUnreachable(u) => write!(f, "snapshot pointer unreachable: {u}"),
            Self::PointerParse(e) => write!(f, "snapshot pointer parse failed: {e}"),
            Self::NetworkMismatch { expected, got } => {
                write!(f, "pointer network '{got}' != ours '{expected}'")
            }
            Self::DownloadFailed(e) => write!(f, "snapshot tarball download failed: {e}"),
            Self::TooLarge { max } => write!(f, "snapshot exceeded the {max}-byte cap — refusing"),
            Self::ExtractFailed(e) => write!(f, "snapshot tarball extraction failed: {e}"),
            Self::BadArchive(e) => write!(f, "snapshot tarball has unexpected contents: {e}"),
            Self::Io(e) => write!(f, "fast-sync io error: {e}"),
        }
    }
}
impl std::error::Error for FastSyncError {}

/// Chaindata subdirectory for a network (matches node/snapshot layout).
fn net_subdir(n: NetworkType) -> &'static str {
    net_str(n)
}

/// Is `data_dir` fresh — i.e. has no existing chaindata to resume from?
///
/// We only fast-sync a fresh node: importing over an existing chain would throw
/// away sync progress, and `snapshot::import` already backs up and refuses to
/// clobber silently. A RocksDB datadir always has a `CURRENT` file once
/// initialized, so its absence is a reliable "nothing here yet" signal.
pub fn is_fresh_datadir(data_dir: &Path, network: NetworkType) -> bool {
    !data_dir.join(net_subdir(network)).join("CURRENT").exists()
}

/// Fetch the current snapshot and extract it into `staging_dir`, returning the
/// directory that holds `db/` + `manifest.json` (+ `manifest.sig`), ready to
/// hand to [`crate::snapshot::import`]. Does NOT install anything itself.
///
/// This is a blocking call (blocking HTTP + file I/O + extraction); the async
/// caller must run it on a blocking thread (`tokio::task::spawn_blocking`).
pub fn fetch_and_stage(
    network: NetworkType,
    staging_dir: &Path,
) -> Result<PathBuf, FastSyncError> {
    let url = std::env::var(POINTER_URL_ENV).unwrap_or_else(|_| default_pointer_url(network));
    info!("fast-sync: reading snapshot pointer from {url}");

    let ptr_bytes = fetch_bounded(&url, POINTER_MAX_BYTES)?;
    let ptr: ChainSnapshotPointer =
        serde_json::from_slice(&ptr_bytes).map_err(|e| FastSyncError::PointerParse(e.to_string()))?;

    if ptr.network != net_str(network) {
        return Err(FastSyncError::NetworkMismatch {
            expected: net_str(network).to_string(),
            got: ptr.network,
        });
    }
    info!(
        "fast-sync: pointer → height={} tip={} tarball={}",
        ptr.height, ptr.tip_hash, ptr.tarball_url
    );

    std::fs::create_dir_all(staging_dir).map_err(|e| FastSyncError::Io(e.to_string()))?;
    let tar_path = staging_dir.join("snapshot.tar");
    let cap = ptr.size_bytes.unwrap_or(TARBALL_MAX_BYTES).min(TARBALL_MAX_BYTES);
    let n = download_to_file(&ptr.tarball_url, &tar_path, cap)?;
    info!("fast-sync: downloaded {n} bytes → extracting");

    let extract_dir = staging_dir.join("extracted");
    let _ = std::fs::remove_dir_all(&extract_dir);
    std::fs::create_dir_all(&extract_dir).map_err(|e| FastSyncError::Io(e.to_string()))?;
    safe_unpack(&tar_path, &extract_dir)?;
    let _ = std::fs::remove_file(&tar_path);

    // Some tars wrap everything in a top-level dir; accept either layout.
    let root = resolve_snapshot_root(&extract_dir)?;
    if !root.join("manifest.json").is_file() || !root.join("db").is_dir() {
        return Err(FastSyncError::BadArchive(
            "missing manifest.json or db/ after extraction".into(),
        ));
    }
    Ok(root)
}

/// Accept both `extracted/{db,manifest.json}` and
/// `extracted/<somedir>/{db,manifest.json}` (a tar made with a leading path).
fn resolve_snapshot_root(extract_dir: &Path) -> Result<PathBuf, FastSyncError> {
    if extract_dir.join("manifest.json").is_file() {
        return Ok(extract_dir.to_path_buf());
    }
    let mut candidates = Vec::new();
    for entry in std::fs::read_dir(extract_dir).map_err(|e| FastSyncError::Io(e.to_string()))? {
        let entry = entry.map_err(|e| FastSyncError::Io(e.to_string()))?;
        if entry.path().is_dir() && entry.path().join("manifest.json").is_file() {
            candidates.push(entry.path());
        }
    }
    match candidates.len() {
        1 => Ok(candidates.pop().unwrap()),
        0 => Err(FastSyncError::BadArchive("no manifest.json in archive".into())),
        _ => Err(FastSyncError::BadArchive(
            "ambiguous archive: multiple manifest.json".into(),
        )),
    }
}

/// GET a small resource with a hard byte cap. Supports `file://` for local
/// mirrors and tests.
fn fetch_bounded(url: &str, max: u64) -> Result<Vec<u8>, FastSyncError> {
    if let Some(path) = url.strip_prefix("file://") {
        let data = std::fs::read(path).map_err(|e| FastSyncError::PointerUnreachable(e.to_string()))?;
        if data.len() as u64 > max {
            return Err(FastSyncError::TooLarge { max });
        }
        return Ok(data);
    }
    let client = http_client()?;
    let resp = client
        .get(url)
        .send()
        .map_err(|e| FastSyncError::PointerUnreachable(e.to_string()))?;
    if !resp.status().is_success() {
        return Err(FastSyncError::PointerUnreachable(format!(
            "HTTP {}",
            resp.status()
        )));
    }
    let mut buf = Vec::new();
    resp.take(max + 1)
        .read_to_end(&mut buf)
        .map_err(|e| FastSyncError::DownloadFailed(e.to_string()))?;
    if buf.len() as u64 > max {
        return Err(FastSyncError::TooLarge { max });
    }
    Ok(buf)
}

/// Stream a (potentially large) resource to `path`, bounded by `max` bytes.
/// Supports `file://` (copied) for local mirrors and tests.
fn download_to_file(url: &str, path: &Path, max: u64) -> Result<u64, FastSyncError> {
    let mut out = std::fs::File::create(path).map_err(|e| FastSyncError::Io(e.to_string()))?;

    if let Some(src) = url.strip_prefix("file://") {
        let mut f = std::fs::File::open(src).map_err(|e| FastSyncError::DownloadFailed(e.to_string()))?;
        let n = std::io::copy(&mut f.by_ref().take(max + 1), &mut out)
            .map_err(|e| FastSyncError::DownloadFailed(e.to_string()))?;
        if n > max {
            let _ = std::fs::remove_file(path);
            return Err(FastSyncError::TooLarge { max });
        }
        return Ok(n);
    }

    let client = http_client()?;
    let resp = client
        .get(url)
        .send()
        .map_err(|e| FastSyncError::DownloadFailed(e.to_string()))?;
    if !resp.status().is_success() {
        return Err(FastSyncError::DownloadFailed(format!("HTTP {}", resp.status())));
    }
    let n = std::io::copy(&mut resp.take(max + 1), &mut out)
        .map_err(|e| FastSyncError::DownloadFailed(e.to_string()))?;
    if n > max {
        let _ = std::fs::remove_file(path);
        return Err(FastSyncError::TooLarge { max });
    }
    Ok(n)
}

fn http_client() -> Result<reqwest::blocking::Client, FastSyncError> {
    reqwest::blocking::Client::builder()
        .timeout(HTTP_TIMEOUT)
        .build()
        .map_err(|e| FastSyncError::DownloadFailed(e.to_string()))
}

/// Extract `tar_path` into `dest`. The `tar` crate's `unpack` rejects entries
/// with absolute paths or `..` components, so a malicious archive cannot escape
/// `dest` (zip-slip). We also disable permission/ownership restoration — the
/// snapshot is just data files.
fn safe_unpack(tar_path: &Path, dest: &Path) -> Result<(), FastSyncError> {
    let file = std::fs::File::open(tar_path).map_err(|e| FastSyncError::Io(e.to_string()))?;
    let mut archive = tar::Archive::new(file);
    archive.set_preserve_permissions(false);
    archive.set_preserve_mtime(false);
    archive.set_overwrite(true);
    archive
        .unpack(dest)
        .map_err(|e| FastSyncError::ExtractFailed(e.to_string()))?;
    Ok(())
}

/// Log a friendly explanation and return — used by the node when `--fast-sync`
/// cannot proceed, so the operator sees WHY it fell back to IBD.
pub fn log_fallback(reason: &dyn std::fmt::Display) {
    warn!("--fast-sync: {reason}; falling back to full IBD from genesis");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_pointer_url_is_network_scoped() {
        assert!(default_pointer_url(NetworkType::Testnet).ends_with("snapshot-latest-testnet.json"));
        assert!(default_pointer_url(NetworkType::Mainnet).ends_with("snapshot-latest-mainnet.json"));
    }

    #[test]
    fn fresh_datadir_detection() {
        let tmp = std::env::temp_dir().join(format!("cc-fs-fresh-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&tmp);
        // No chaindata yet → fresh.
        assert!(is_fresh_datadir(&tmp, NetworkType::Testnet));
        // Simulate an initialized RocksDB datadir.
        let cd = tmp.join("testnet");
        std::fs::create_dir_all(&cd).unwrap();
        std::fs::write(cd.join("CURRENT"), b"MANIFEST-000001\n").unwrap();
        assert!(!is_fresh_datadir(&tmp, NetworkType::Testnet));
        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn fetch_bounded_file_scheme_and_cap() {
        let tmp = std::env::temp_dir().join(format!("cc-fs-ptr-{}.json", std::process::id()));
        std::fs::write(&tmp, br#"{"schema_version":1,"network":"testnet","height":10,"tip_hash":"x","tarball_url":"file:///nope"}"#).unwrap();
        let url = format!("file://{}", tmp.display());
        let data = fetch_bounded(&url, POINTER_MAX_BYTES).unwrap();
        let ptr: ChainSnapshotPointer = serde_json::from_slice(&data).unwrap();
        assert_eq!(ptr.network, "testnet");
        assert_eq!(ptr.height, 10);
        // Cap enforced.
        assert!(matches!(fetch_bounded(&url, 4), Err(FastSyncError::TooLarge { .. })));
        let _ = std::fs::remove_file(&tmp);
    }

    #[test]
    fn network_mismatch_is_rejected() {
        let dir = std::env::temp_dir().join(format!("cc-fs-nm-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let ptr = dir.join("ptr.json");
        std::fs::write(&ptr, br#"{"schema_version":1,"network":"mainnet","height":1,"tip_hash":"x","tarball_url":"file:///nope"}"#).unwrap();
        std::env::set_var(POINTER_URL_ENV, format!("file://{}", ptr.display()));
        let staging = dir.join("staging");
        let r = fetch_and_stage(NetworkType::Testnet, &staging);
        std::env::remove_var(POINTER_URL_ENV);
        assert!(matches!(r, Err(FastSyncError::NetworkMismatch { .. })));
        let _ = std::fs::remove_dir_all(&dir);
    }
}
