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
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::protocol::Swap;

/// Current state-file version. Bumped when the on-disk format
/// changes in a way old readers cannot handle.
pub const STATE_VERSION: u32 = 1;

// ────────────────────────────────────────────────────────────────
// File format
// ────────────────────────────────────────────────────────────────

/// On-disk representation of a swap's state.
#[derive(Clone, Debug, Serialize, Deserialize)]
struct StateFile {
    version: u32,
    saved_at: u64,
    swap: Swap,
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
    #[error("unsupported state-file version: file is v{file_version}, this binary handles v1..={supported}")]
    UnsupportedVersion { file_version: u32, supported: u32 },
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
        let payload = StateFile {
            version: STATE_VERSION,
            saved_at,
            swap: swap.clone(),
        };
        let json = serde_json::to_vec_pretty(&payload)?;

        // Make sure the parent directory exists. Lets the CLI's
        // first save just work without an explicit mkdir step.
        if let Some(parent) = self.path.parent() {
            if !parent.as_os_str().is_empty() {
                std::fs::create_dir_all(parent)?;
            }
        }

        // Write to a temp file in the SAME directory so the rename
        // is on the same volume.
        let tmp_path = tmp_path_for(&self.path);
        {
            let mut tmp = OpenOptions::new()
                .create(true)
                .write(true)
                .truncate(true)
                .open(&tmp_path)?;
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
    pub fn load(&self) -> Result<Option<Swap>> {
        if !self.path.exists() {
            return Ok(None);
        }
        let mut f = File::open(&self.path)?;
        let mut buf = Vec::new();
        f.read_to_end(&mut buf)?;
        let payload: StateFile = serde_json::from_slice(&buf)?;
        if payload.version > STATE_VERSION {
            return Err(StateError::UnsupportedVersion {
                file_version: payload.version,
                supported: STATE_VERSION,
            });
        }
        Ok(Some(payload.swap))
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
}
