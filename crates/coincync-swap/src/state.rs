//! On-disk persistence for an in-progress swap.
//!
//! The `cyncswap` CLI runs as discrete invocations: the user
//! starts a swap with `cyncswap alice ...` or `cyncswap bob ...`,
//! the negotiation runs to completion, and the process exits. To
//! survive across invocations (and across crashes), the swap's
//! state must be written to disk after every state-machine
//! transition.
//!
//! This module is the persister. Same shape as the FROST
//! coordinator's `persistence` module: atomic write via
//! temp-file-and-rename, JSON file format with a schema version,
//! loud failure on version mismatch.
//!
//! ## File format
//!
//! ```json
//! {
//!   "version": 1,
//!   "saved_at": 1730000000,
//!   "swap": {
//!     "id": "...",
//!     "role": "Alice",
//!     "state": "AliceLocked",
//!     "parameters": { ... }
//!   }
//! }
//! ```
//!
//! `version` is bumped whenever the on-disk shape changes. A
//! bumped version triggers `StateError::UnsupportedVersion` on
//! load rather than a silent best-effort parse — losing track of
//! a swap-in-progress is exactly the failure mode atomic swaps
//! are designed to prevent.
//!
//! ## Atomic-write semantics
//!
//! 1. Serialize to JSON.
//! 2. Write to `<path>.tmp`.
//! 3. `sync_all` to flush page cache to disk.
//! 4. `rename(<path>.tmp, <path>)` — atomic on Linux/macOS,
//!    atomic-ish on Windows (`MoveFileEx` with
//!    `MOVEFILE_REPLACE_EXISTING`).
//!
//! A crash between steps 2 and 4 leaves an orphan `.tmp` that the
//! next save overwrites. A crash during step 4 either committed
//! or didn't — no observable middle state.
//!
//! ## When to call save / load / delete
//!
//! - **`save`** after every successful `Swap::apply`. The CLI's
//!   main loop is "load, apply transition, save, repeat."
//! - **`load`** at process start. Returns `None` for a fresh
//!   start (no state file).
//! - **`delete`** ONLY after the swap reaches a terminal state
//!   AND retention has elapsed. Premature deletion strands
//!   on-chain locks waiting for refund.

use std::fs::{rename, File, OpenOptions};
use std::io::{Read, Write};
#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use hmac::{Hmac, Mac};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use subtle::ConstantTimeEq;
use thiserror::Error;

use crate::protocol::Swap;

type HmacSha256 = Hmac<Sha256>;

/// Length of the HMAC key stored in the sidecar (`<path>.hmac-key`).
const HMAC_KEY_LEN: usize = 32;

/// Current state-file version. v2 added the `hmac` field + sidecar
/// key file. v1 files are explicitly rejected on load — operators
/// migrate by re-creating the swap (state-file integrity is moot
/// for an abandoned-and-restarted swap).
pub const STATE_VERSION: u32 = 2;

// ────────────────────────────────────────────────────────────────
// File format
// ────────────────────────────────────────────────────────────────

/// Body of the on-disk state file. The HMAC is computed over the
/// canonical JSON encoding of THIS struct (without the wrapping
/// `hmac` field). Splitting body + envelope keeps the HMAC input
/// deterministic regardless of how the envelope is later extended.
#[derive(Clone, Debug, Serialize, Deserialize)]
struct StateFileBody {
    version: u32,
    saved_at: u64,
    swap: Swap,
}

/// Full on-disk representation of a swap's state (v2 schema). The
/// `hmac` is hex-encoded HMAC-SHA256 over the canonical body bytes,
/// keyed by the per-state-file random key in the sidecar at
/// `<path>.hmac-key`. v1 files (no `hmac` field, no sidecar) are
/// explicitly rejected on load — operators migrate by re-creating
/// the swap.
#[derive(Clone, Debug, Serialize, Deserialize)]
struct StateFileEnvelope {
    #[serde(flatten)]
    body: StateFileBody,
    /// Hex-encoded HMAC-SHA256(canonical_body_bytes, sidecar_key).
    /// 64 hex chars = 32 raw bytes.
    hmac: String,
}

// ────────────────────────────────────────────────────────────────
// Errors
// ────────────────────────────────────────────────────────────────

/// Persistence operation errors. Distinct from the swap-protocol
/// `Error` because file-I/O failures are operational, not
/// protocol violations.
#[derive(Debug, Error)]
pub enum StateError {
    /// Underlying filesystem error (open, read, write, rename, sync).
    #[error("filesystem error: {0}")]
    Io(#[from] std::io::Error),

    /// JSON serialization or deserialization failed.
    #[error("JSON parse error: {0}")]
    Json(#[from] serde_json::Error),

    /// The on-disk version is something this binary doesn't
    /// understand. Almost always means the file was written by a
    /// newer binary. Loud failure rather than silent best-effort.
    #[error("unsupported state-file version: file is v{file_version}, this binary handles v2..={supported}")]
    UnsupportedVersion { file_version: u32, supported: u32 },

    /// The HMAC sidecar file is missing — either because the state
    /// file was written by a pre-v2 binary, or because an attacker
    /// truncated the directory after planting a forged state file.
    /// Either way, the state file cannot be trusted.
    #[error("HMAC sidecar missing at {0}: state file cannot be integrity-checked")]
    HmacKeyMissing(PathBuf),

    /// The HMAC stored in the state-file envelope does not match the
    /// HMAC recomputed from the body + sidecar key. The state file
    /// has been tampered with (or the sidecar key was rotated
    /// without re-saving the state).
    #[error("state-file integrity check failed: HMAC mismatch — file may have been tampered with")]
    IntegrityFailure,
}

pub type Result<T> = std::result::Result<T, StateError>;

// ────────────────────────────────────────────────────────────────
// SwapStore
// ────────────────────────────────────────────────────────────────

/// Path-bound swap-state persister. Construct once, save / load
/// many. Holds a single swap per file — multi-swap users pick
/// distinct paths.
#[derive(Clone, Debug)]
pub struct SwapStore {
    path: PathBuf,
}

impl SwapStore {
    /// Construct a store backed by `path`. Doesn't touch the
    /// filesystem; `load` and `save` do.
    pub fn new(path: impl Into<PathBuf>) -> Self {
        SwapStore { path: path.into() }
    }

    /// The path this store reads from and writes to.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Save `swap` to disk atomically. Existing file is replaced;
    /// the rename is the commit point.
    ///
    /// Caller is expected to invoke this after every successful
    /// transition. Failure to save means the on-disk view drifts
    /// from the in-memory view; the CLI should treat any
    /// `StateError::Io` from save as a hard error and abort
    /// rather than continue running with state divergence.
    pub fn save(&self, swap: &Swap) -> Result<()> {
        let saved_at = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let body = StateFileBody {
            version: STATE_VERSION,
            saved_at,
            swap: swap.clone(),
        };

        // HMAC over the canonical body bytes. Same `to_vec` call
        // used on save AND on load-verify so the byte sequences
        // match. The envelope then carries both body fields
        // (via `#[serde(flatten)]`) and the resulting hmac.
        let body_bytes = serde_json::to_vec(&body)?;
        let key = read_or_create_hmac_key(&hmac_key_path(&self.path))?;
        let hmac_hex = compute_hmac_hex(&key, &body_bytes);
        let envelope = StateFileEnvelope {
            body,
            hmac: hmac_hex,
        };
        let json = serde_json::to_vec_pretty(&envelope)?;

        // Make sure the parent directory exists. Lets the CLI's
        // first save just work without an explicit mkdir step.
        if let Some(parent) = self.path.parent() {
            if !parent.as_os_str().is_empty() {
                std::fs::create_dir_all(parent)?;
            }
        }

        // Write to a temp file in the SAME directory so the rename
        // is on the same volume.
        //
        // On Unix, open with `O_NOFOLLOW` so an attacker who can
        // pre-create the temp path as a symlink (e.g. pointing at
        // `/etc/passwd` or another user's keystore) can't trick the
        // save into writing through their symlink. Symlinked target →
        // `open` fails with `ELOOP` → save returns an io error → the
        // operator sees the failure rather than corrupting an
        // unrelated file. Windows has no equivalent O_NOFOLLOW
        // semantic and uses bare `OpenOptions`.
        let tmp_path = tmp_path_for(&self.path);
        {
            let mut opts = OpenOptions::new();
            opts.create(true).write(true).truncate(true);
            #[cfg(unix)]
            opts.custom_flags(libc::O_NOFOLLOW);
            let mut tmp = opts.open(&tmp_path)?;
            tmp.write_all(&json)?;
            tmp.sync_all()?;
        }
        rename(&tmp_path, &self.path)?;
        // fsync the parent directory so the rename itself is
        // durable. Without this, a crash after rename(2) but
        // before the dir's dentry is flushed can lose the rename
        // and leave the old file (or no file) in place — undoing
        // the atomic-write guarantee. No-op on Windows but harmless.
        if let Some(parent) = self.path.parent() {
            if !parent.as_os_str().is_empty() {
                if let Ok(dir) = File::open(parent) {
                    let _ = dir.sync_all();
                }
            }
        }
        Ok(())
    }

    /// Load the swap from disk. Returns `None` if no state file
    /// exists (fresh start).
    ///
    /// v2 files: HMAC is verified against the sidecar key. Mismatch
    /// returns `IntegrityFailure`. Missing sidecar returns
    /// `HmacKeyMissing`.
    ///
    /// v1 files: rejected as `UnsupportedVersion`. v1 files had no
    /// integrity check; trusting them would defeat the v2 hardening.
    /// Operators with a v1 file in flight at the upgrade moment
    /// must restart the swap.
    pub fn load(&self) -> Result<Option<Swap>> {
        if !self.path.exists() {
            return Ok(None);
        }
        let mut f = File::open(&self.path)?;
        let mut buf = Vec::new();
        f.read_to_end(&mut buf)?;

        // First peek at version so v1 files are rejected without
        // attempting envelope parsing (v1 has no `hmac` field).
        #[derive(Deserialize)]
        struct VersionOnly {
            version: u32,
        }
        let v: VersionOnly = serde_json::from_slice(&buf)?;
        if v.version != STATE_VERSION {
            return Err(StateError::UnsupportedVersion {
                file_version: v.version,
                supported: STATE_VERSION,
            });
        }

        let envelope: StateFileEnvelope = serde_json::from_slice(&buf)?;

        // Verify HMAC. Read sidecar key first; missing sidecar →
        // explicit error (not a silent pass).
        let key_path = hmac_key_path(&self.path);
        if !key_path.exists() {
            return Err(StateError::HmacKeyMissing(key_path));
        }
        let key = read_hmac_key(&key_path)?;
        let body_bytes = serde_json::to_vec(&envelope.body)?;
        let recomputed = compute_hmac_hex(&key, &body_bytes);

        // Constant-time hex comparison — defends against any future
        // hex-string equality timing oracle in serde / our parser.
        if recomputed.as_bytes().ct_eq(envelope.hmac.as_bytes()).unwrap_u8() != 1 {
            return Err(StateError::IntegrityFailure);
        }

        Ok(Some(envelope.body.swap))
    }

    /// Delete the state file. Returns `Ok(())` if the file
    /// didn't exist (idempotent).
    ///
    /// Caller MUST verify the swap is terminal AND retention has
    /// elapsed before calling. Premature deletion strands
    /// on-chain locks awaiting refund.
    pub fn delete(&self) -> Result<()> {
        match std::fs::remove_file(&self.path) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(StateError::Io(e)),
        }
    }

    /// Whether a state file currently exists at this path.
    pub fn exists(&self) -> bool {
        self.path.exists()
    }
}

// ────────────────────────────────────────────────────────────────
// HMAC helpers (v2 state-file integrity)
// ────────────────────────────────────────────────────────────────

/// Sidecar key path: `<state_file>.hmac-key`.
fn hmac_key_path(state_path: &Path) -> PathBuf {
    let mut p = state_path.to_path_buf();
    let suffix = match state_path.extension() {
        Some(ext) => {
            let mut s = ext.to_os_string();
            s.push(".hmac-key");
            s
        }
        None => "hmac-key".into(),
    };
    p.set_extension(suffix);
    p
}

/// Read the HMAC key from a sidecar file. Returns `Err(Io)` if the
/// file is missing or wrong length.
fn read_hmac_key(key_path: &Path) -> Result<[u8; HMAC_KEY_LEN]> {
    let mut f = File::open(key_path)?;
    let mut buf = [0u8; HMAC_KEY_LEN];
    f.read_exact(&mut buf)?;
    Ok(buf)
}

/// Get the sidecar key, creating a fresh random one if the sidecar
/// doesn't exist. Newly-created sidecars are written with
/// `O_NOFOLLOW` (Unix) and `0o600` permissions (Unix). Windows uses
/// bare `OpenOptions` — filesystem-permissions only.
fn read_or_create_hmac_key(key_path: &Path) -> Result<[u8; HMAC_KEY_LEN]> {
    if key_path.exists() {
        return read_hmac_key(key_path);
    }
    let mut key = [0u8; HMAC_KEY_LEN];
    rand::rngs::OsRng.fill_bytes(&mut key);

    // Make sure the parent directory exists (it should — `save()`
    // ensured it before calling us — but be defensive).
    if let Some(parent) = key_path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)?;
        }
    }

    let mut opts = OpenOptions::new();
    opts.create_new(true).write(true);
    #[cfg(unix)]
    {
        opts.mode(0o600);
        opts.custom_flags(libc::O_NOFOLLOW);
    }
    let mut f = opts.open(key_path)?;
    f.write_all(&key)?;
    f.sync_all()?;
    Ok(key)
}

/// HMAC-SHA256(key, body_bytes), hex-encoded (64 chars, lowercase).
fn compute_hmac_hex(key: &[u8; HMAC_KEY_LEN], body_bytes: &[u8]) -> String {
    let mut mac = HmacSha256::new_from_slice(key)
        .expect("HMAC-SHA256 accepts any key length (HMAC_KEY_LEN=32 fits)");
    mac.update(body_bytes);
    let result = mac.finalize().into_bytes();
    let mut hex_out = String::with_capacity(HMAC_KEY_LEN * 2);
    for b in result.iter() {
        hex_out.push_str(&format!("{b:02x}"));
    }
    hex_out
}

/// Compute the temp-file path used during atomic save. Returns
/// `<path>.tmp` (or `tmp` if the input has no extension).
fn tmp_path_for(path: &Path) -> PathBuf {
    let mut tmp = path.to_path_buf();
    let suffix = match path.extension() {
        Some(ext) => {
            let mut s = ext.to_os_string();
            s.push(".tmp");
            s
        }
        None => "tmp".into(),
    };
    tmp.set_extension(suffix);
    tmp
}

// ────────────────────────────────────────────────────────────────
// Tests
// ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::{Role, Swap, SwapParameters, Transition};
    use tempfile::tempdir;

    fn safe_params() -> SwapParameters {
        SwapParameters {
            cync_amount: 100_000_000,
            btc_amount_sats: 1_000_000,
            cync_timeout_blocks: 720,
            btc_timeout_blocks: 100,
            alice_cync_address: "alice".into(),
            bob_btc_address: "bob".into(),
cync_network: "regtest".to_string(),
btc_network: "regtest".to_string(),
        }
    }

    fn alice_swap() -> Swap {
        Swap::negotiate("test-1".into(), Role::Alice, safe_params()).unwrap()
    }

    #[test]
    fn save_and_load_round_trip() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("swap.json");
        let store = SwapStore::new(&path);

        let swap = alice_swap();
        store.save(&swap).unwrap();

        let loaded = store.load().unwrap();
        assert!(loaded.is_some());
        let loaded = loaded.unwrap();
        assert_eq!(loaded.id, swap.id);
        assert_eq!(loaded.role, swap.role);
        assert_eq!(loaded.state, swap.state);
        assert_eq!(loaded.parameters.cync_amount, swap.parameters.cync_amount);
    }

    #[test]
    fn load_missing_file_returns_none() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("swap.json");
        let store = SwapStore::new(&path);
        let loaded = store.load().unwrap();
        assert!(loaded.is_none());
    }

    #[test]
    fn save_overwrites_existing() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("swap.json");
        let store = SwapStore::new(&path);

        // Save initial state (Negotiated)
        let mut swap = alice_swap();
        store.save(&swap).unwrap();
        assert_eq!(store.load().unwrap().unwrap().state, swap.state);

        // Apply transition + re-save
        swap.apply(Transition::AliceLocksCync).unwrap();
        store.save(&swap).unwrap();
        let loaded = store.load().unwrap().unwrap();
        assert_eq!(loaded.state, swap.state); // AliceLocked
    }

    #[test]
    fn delete_removes_file() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("swap.json");
        let store = SwapStore::new(&path);

        store.save(&alice_swap()).unwrap();
        assert!(store.exists());
        store.delete().unwrap();
        assert!(!store.exists());
        assert!(store.load().unwrap().is_none());
    }

    #[test]
    fn delete_missing_file_is_ok() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("nonexistent.json");
        let store = SwapStore::new(&path);
        // Idempotent: deleting a non-existent file succeeds
        store.delete().unwrap();
    }

    #[test]
    fn save_creates_parent_directory() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("nested").join("dir").join("swap.json");
        let store = SwapStore::new(&path);

        // Parent dirs don't exist yet
        assert!(!path.parent().unwrap().exists());
        store.save(&alice_swap()).unwrap();
        // Save creates the dirs
        assert!(path.parent().unwrap().exists());
        assert!(path.exists());
    }

    #[test]
    fn unsupported_version_rejected() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("swap.json");

        let bogus = serde_json::json!({
            "version": 999,
            "saved_at": 1700000000u64,
            "swap": {
                "id": "x",
                "role": "Alice",
                "state": "Negotiated",
                "parameters": {
                    "cync_amount": 1u64,
                    "btc_amount_sats": 1u64,
                    "cync_timeout_blocks": 720u32,
                    "btc_timeout_blocks": 100u32,
                    "alice_cync_address": "a",
                    "bob_btc_address": "b"
                }
            }
        });
        std::fs::write(&path, serde_json::to_vec_pretty(&bogus).unwrap()).unwrap();

        let store = SwapStore::new(&path);
        let err = store.load().unwrap_err();
        assert!(matches!(
            err,
            StateError::UnsupportedVersion {
                file_version: 999,
                ..
            }
        ));
    }

    #[test]
    fn malformed_json_rejected_loudly() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("swap.json");
        std::fs::write(&path, b"not valid JSON {").unwrap();

        let store = SwapStore::new(&path);
        let err = store.load().unwrap_err();
        assert!(matches!(err, StateError::Json(_)));
    }

    #[test]
    fn save_leaves_no_orphan_tmp_after_success() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("swap.json");
        let store = SwapStore::new(&path);

        store.save(&alice_swap()).unwrap();
        let tmp = tmp_path_for(&path);
        assert!(!tmp.exists(), "orphan .tmp file remained after save");
    }

    #[test]
    fn terminal_state_round_trips() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("swap.json");
        let store = SwapStore::new(&path);

        let mut swap = alice_swap();
        swap.apply(Transition::Abort).unwrap();
        assert!(swap.state.is_terminal());

        store.save(&swap).unwrap();
        let loaded = store.load().unwrap().unwrap();
        assert!(loaded.state.is_terminal());
        assert_eq!(loaded.state, swap.state);
    }

    #[test]
    fn full_lifecycle_persisted_at_each_step() {
        // Simulates the cyncswap CLI's main loop: each transition
        // is followed by a save; a crash + reload at any point
        // recovers correctly.
        use crate::protocol::Role;
        let dir = tempdir().unwrap();
        let path = dir.path().join("swap.json");
        let store = SwapStore::new(&path);

        // Bob's machine (we use Bob because his happy path is the
        // simplest to drive synthetically: state forced to
        // AliceLocked, then BobLocksBtc, ObserveSecretRevealed,
        // BobClaimsCync).
        let mut swap = Swap::negotiate("life-1".into(), Role::Bob, safe_params()).unwrap();
        store.save(&swap).unwrap();

        // Force-transition to AliceLocked (in real flow Bob's
        // chain watcher delivers this; tests force).
        swap.state = crate::protocol::State::AliceLocked;
        store.save(&swap).unwrap();

        // Bob locks BTC
        swap.apply(Transition::BobLocksBtc).unwrap();
        store.save(&swap).unwrap();

        // Reload at this point — simulates a crash + restart
        let reloaded = store.load().unwrap().unwrap();
        assert_eq!(reloaded.state, crate::protocol::State::BobLocked);
        let mut swap = reloaded;

        // Continue
        swap.apply(Transition::ObserveSecretRevealed).unwrap();
        store.save(&swap).unwrap();
        swap.apply(Transition::BobClaimsCync).unwrap();
        store.save(&swap).unwrap();

        // Final state
        let final_loaded = store.load().unwrap().unwrap();
        assert_eq!(final_loaded.state, crate::protocol::State::Completed);
    }

    #[test]
    fn tmp_path_disambiguation() {
        let real = PathBuf::from("/var/lib/coincync/swap.json");
        let tmp = tmp_path_for(&real);
        assert_ne!(real, tmp);
        assert!(tmp.to_string_lossy().ends_with(".tmp"));
    }

    #[test]
    fn tmp_path_no_extension() {
        let real = PathBuf::from("/var/lib/coincync/swap");
        let tmp = tmp_path_for(&real);
        assert_ne!(real, tmp);
        assert_eq!(tmp.extension().unwrap(), "tmp");
    }

    // ─────────────────────────────────────────────────────────────
    // v2 HMAC forgery-defense tests (CYNC-AUDIT-2026-05-17-state-file-hmac)
    // ─────────────────────────────────────────────────────────────

    #[test]
    fn v1_legacy_file_rejected() {
        // Pre-HMAC v1 file forged with a terminal Completed state. The
        // upstream finding's exact attack shape. Must be rejected as
        // UnsupportedVersion; the binary must NOT echo "Completed".
        let dir = tempdir().unwrap();
        let path = dir.path().join("swap.json");
        let v1_forged = serde_json::json!({
            "version": 1,
            "saved_at": 1700000000u64,
            "swap": {
                "id": "forged-swap",
                "role": "Bob",
                "state": "Completed",
                "parameters": {
                    "cync_amount": 1u64,
                    "btc_amount_sats": 1u64,
                    "cync_timeout_blocks": 720u32,
                    "btc_timeout_blocks": 100u32,
                    "alice_cync_address": "a",
                    "bob_btc_address": "b",
                    "cync_network": "regtest",
                    "btc_network": "regtest"
                }
            }
        });
        std::fs::write(&path, serde_json::to_vec_pretty(&v1_forged).unwrap()).unwrap();
        let store = SwapStore::new(&path);
        let err = store.load().unwrap_err();
        assert!(matches!(
            err,
            StateError::UnsupportedVersion { file_version: 1, .. }
        ));
    }

    #[test]
    fn v2_file_missing_sidecar_rejected() {
        // Save a real v2 file (creates the sidecar), then delete the
        // sidecar before loading. Must return HmacKeyMissing.
        let dir = tempdir().unwrap();
        let path = dir.path().join("swap.json");
        let store = SwapStore::new(&path);
        store.save(&alice_swap()).unwrap();
        // Delete the sidecar key
        std::fs::remove_file(hmac_key_path(&path)).unwrap();
        let err = store.load().unwrap_err();
        assert!(matches!(err, StateError::HmacKeyMissing(_)));
    }

    #[test]
    fn v2_file_tampered_hmac_rejected() {
        // Save a real v2 file, then tamper with the `hmac` field to a
        // wrong value of the same length. Must return IntegrityFailure.
        let dir = tempdir().unwrap();
        let path = dir.path().join("swap.json");
        let store = SwapStore::new(&path);
        store.save(&alice_swap()).unwrap();
        // Rewrite with tampered HMAC
        let bytes = std::fs::read(&path).unwrap();
        let mut envelope: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        envelope["hmac"] = serde_json::Value::String("00".repeat(32));
        std::fs::write(&path, serde_json::to_vec_pretty(&envelope).unwrap()).unwrap();
        let err = store.load().unwrap_err();
        assert!(matches!(err, StateError::IntegrityFailure));
    }

    #[test]
    fn v2_file_tampered_body_rejected() {
        // Save a real v2 file, then change a swap-state field while
        // leaving the HMAC alone. Recomputed HMAC won't match — must
        // return IntegrityFailure. This is the canonical attack the
        // HMAC defends against: silent forge of swap state on disk.
        let dir = tempdir().unwrap();
        let path = dir.path().join("swap.json");
        let store = SwapStore::new(&path);
        store.save(&alice_swap()).unwrap();
        let bytes = std::fs::read(&path).unwrap();
        let mut envelope: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        // Mutate the state without touching the hmac field
        envelope["swap"]["state"] = serde_json::Value::String("Completed".into());
        std::fs::write(&path, serde_json::to_vec_pretty(&envelope).unwrap()).unwrap();
        let err = store.load().unwrap_err();
        assert!(matches!(err, StateError::IntegrityFailure));
    }
}
