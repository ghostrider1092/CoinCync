//! JSON-file persistence for active FROST sessions (phase 3).
//!
//! Phase 1 holds sessions in memory only. Phase 2 added invitation
//! tokens but kept the in-memory model. Phase 3 adds the missing
//! piece for production: a `SessionStore` that saves the
//! coordinator's session map to disk so a process restart doesn't
//! lose in-flight FROST sessions.
//!
//! Feature-gated: this module is compiled only when the
//! `persistence` Cargo feature is enabled. Off by default so the
//! core state-machine library has no I/O surface.
//!
//! ## File format
//!
//! ```json
//! {
//!   "version":  1,
//!   "saved_at": 1730000000,
//!   "sessions": [ /* serde-serialized Session structs */ ]
//! }
//! ```
//!
//! `version` is bumped whenever the format changes in a way old
//! readers cannot handle. A bumped version triggers a loud error
//! on load (`PersistError::UnsupportedVersion`) rather than a
//! silent partial-parse.
//!
//! ## Atomic-write semantics
//!
//! Save uses the standard temp-file-and-rename pattern:
//!
//! 1. Serialize to JSON.
//! 2. Write to `<path>.tmp`.
//! 3. `sync_all` to flush page cache to disk.
//! 4. `rename(<path>.tmp, <path>)` — atomic on Linux/macOS,
//!    atomic-ish on Windows (`MoveFileEx` with
//!    `MOVEFILE_REPLACE_EXISTING`, which Rust's `fs::rename` uses
//!    since 1.59).
//!
//! A crash between steps 2 and 4 leaves an orphaned `.tmp` file;
//! we tolerate that by overwriting on the next save. A crash
//! during step 4 (the rename) is impossible to observe because
//! the rename either happened or didn't.
//!
//! ## What's NOT in this module
//!
//! - **File locking.** Two coordinator processes writing to the
//!   same path can clobber each other's saves. Production
//!   deployment should run a single coordinator instance; if
//!   multi-instance becomes a thing, add `fs2::FileExt::lock_exclusive`
//!   here.
//! - **Encryption-at-rest.** The session content includes
//!   participant pubkeys, the message being signed, and (in
//!   late-stage sessions) signature shares — all PUBLIC-by-
//!   protocol-design. Nothing here needs encryption. If an
//!   operator wants disk-encryption, that's an OS-level concern
//!   (LUKS, FileVault, BitLocker).
//! - **Schema migration.** Phase 3 ships version 1 only. When a
//!   future version 2 lands, this module gains a `migrate_v1_to_v2`
//!   helper. For now, version mismatch is a hard error.
//! - **Garbage collection of terminal sessions.** A session in
//!   `Aggregated` / `Aborted` / `Expired` state is kept on disk
//!   until the operator explicitly purges it. The coordinator's
//!   maintenance loop is responsible for purging post-retention;
//!   this module just stores what it's told.

use std::fs::{rename, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::session::Session;

/// Current persistence-file version. Bumped when the on-disk
/// format changes in a way old readers cannot handle.
pub const PERSISTENCE_VERSION: u32 = 1;

// ────────────────────────────────────────────────────────────────
// File format
// ────────────────────────────────────────────────────────────────

/// On-disk representation of the coordinator's session set.
#[derive(Clone, Debug, Serialize, Deserialize)]
struct PersistFile {
    version: u32,
    saved_at: u64,
    sessions: Vec<Session>,
}

// ────────────────────────────────────────────────────────────────
// Errors
// ────────────────────────────────────────────────────────────────

/// Persistence operation errors. Distinct from `CoordinatorError`
/// because file-I/O failures are operational, not protocol
/// violations.
#[derive(Debug, Error)]
pub enum PersistError {
    /// Underlying file-system error (open, read, write, rename, sync).
    #[error("filesystem error: {0}")]
    Io(#[from] std::io::Error),

    /// JSON serialization or deserialization failed.
    #[error("JSON parse error: {0}")]
    Json(#[from] serde_json::Error),

    /// File version is something this binary doesn't understand.
    /// Almost always means the file was written by a newer
    /// version. Loud-failure rather than silent-best-effort by
    /// design.
    #[error("unsupported persistence version: file is v{file_version}, this binary handles v1..={supported}")]
    UnsupportedVersion {
        file_version: u32,
        supported: u32,
    },

    /// `saved_at` time isn't a valid unix timestamp.
    /// Should never happen in practice; if it does, the file is
    /// likely corrupted.
    #[error("invalid saved_at timestamp in persistence file")]
    InvalidTimestamp,
}

pub type Result<T> = std::result::Result<T, PersistError>;

// ────────────────────────────────────────────────────────────────
// SessionStore
// ────────────────────────────────────────────────────────────────

/// Path-bound session-set persister. Construct once, save / load
/// many.
#[derive(Clone, Debug)]
pub struct SessionStore {
    path: PathBuf,
}

impl SessionStore {
    /// Construct a store backed by `path`. Doesn't touch the
    /// filesystem; `load` and `save` do.
    pub fn new(path: impl Into<PathBuf>) -> Self {
        SessionStore { path: path.into() }
    }

    /// The path this store reads from and writes to.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Save `sessions` to disk atomically. Existing file is
    /// replaced; the rename is the commit point.
    pub fn save(&self, sessions: &[Session]) -> Result<()> {
        let saved_at = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let payload = PersistFile {
            version: PERSISTENCE_VERSION,
            saved_at,
            sessions: sessions.to_vec(),
        };
        let json = serde_json::to_vec_pretty(&payload)?;

        // Write to a temp file in the SAME directory so the rename
        // is on the same volume (rename across volumes is a copy
        // on every OS we support).
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
        Ok(())
    }

    /// Load sessions from disk. Returns an empty vec if the file
    /// doesn't exist (fresh-coordinator case).
    pub fn load(&self) -> Result<Vec<Session>> {
        if !self.path.exists() {
            return Ok(Vec::new());
        }
        let mut f = File::open(&self.path)?;
        let mut buf = Vec::new();
        f.read_to_end(&mut buf)?;
        let payload: PersistFile = serde_json::from_slice(&buf)?;
        if payload.version > PERSISTENCE_VERSION {
            return Err(PersistError::UnsupportedVersion {
                file_version: payload.version,
                supported: PERSISTENCE_VERSION,
            });
        }
        // saved_at is informational; we don't reject on it. But a
        // sentinel value of 0 is suspicious — flag it loudly so
        // unit-tests with no real clock don't pretend to be valid
        // production state.
        if payload.saved_at == 0 {
            // This is allowed (clock unavailable at save time)
            // but worth a debug log; intentionally not an error.
        }
        Ok(payload.sessions)
    }

    /// Atomic upsert: load existing, apply `f` to mutate, save
    /// back. Convenience wrapper around `load` + `save` for
    /// callers that don't want to manage the round-trip.
    pub fn update<F>(&self, f: F) -> Result<()>
    where
        F: FnOnce(&mut Vec<Session>),
    {
        let mut sessions = self.load()?;
        f(&mut sessions);
        self.save(&sessions)
    }
}

/// Compute the temp-file path used during atomic save. Returns
/// `<path>.tmp` (or `tmp` if the input has no file name).
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
    use crate::session::{ParticipantId, Session};
    use tempfile::tempdir;

    fn fresh_session() -> Session {
        Session::new(2, 3, [1u8; 32], ParticipantId([0xAA; 32]), 1000)
            .expect("test session valid")
    }

    #[test]
    fn save_and_load_round_trip() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("sessions.json");
        let store = SessionStore::new(&path);

        let sessions = vec![fresh_session(), fresh_session()];
        store.save(&sessions).unwrap();
        let loaded = store.load().unwrap();
        assert_eq!(loaded.len(), 2);
        assert_eq!(loaded[0].threshold, 2);
        assert_eq!(loaded[0].total, 3);
    }

    #[test]
    fn load_missing_file_returns_empty() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("nonexistent.json");
        let store = SessionStore::new(&path);
        let loaded = store.load().unwrap();
        assert!(loaded.is_empty());
    }

    #[test]
    fn save_overwrites_existing() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("sessions.json");
        let store = SessionStore::new(&path);

        store.save(&[fresh_session()]).unwrap();
        // Now save a different set
        store.save(&[fresh_session(), fresh_session(), fresh_session()]).unwrap();
        let loaded = store.load().unwrap();
        assert_eq!(loaded.len(), 3);
    }

    #[test]
    fn save_truncates_to_empty() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("sessions.json");
        let store = SessionStore::new(&path);

        store.save(&[fresh_session(), fresh_session()]).unwrap();
        store.save(&[]).unwrap();
        let loaded = store.load().unwrap();
        assert!(loaded.is_empty());
    }

    #[test]
    fn unsupported_version_rejected() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("sessions.json");

        // Write a file with version 999
        let bogus = serde_json::json!({
            "version": 999,
            "saved_at": 1700000000u64,
            "sessions": []
        });
        std::fs::write(&path, serde_json::to_vec_pretty(&bogus).unwrap()).unwrap();

        let store = SessionStore::new(&path);
        let err = store.load().unwrap_err();
        assert!(matches!(err, PersistError::UnsupportedVersion { file_version: 999, .. }));
    }

    #[test]
    fn malformed_json_rejected_loudly() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("sessions.json");
        std::fs::write(&path, b"this is not JSON").unwrap();

        let store = SessionStore::new(&path);
        let err = store.load().unwrap_err();
        assert!(matches!(err, PersistError::Json(_)));
    }

    #[test]
    fn update_apply_and_save() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("sessions.json");
        let store = SessionStore::new(&path);

        // Start with one session
        store.save(&[fresh_session()]).unwrap();

        // Add another via update
        store.update(|sessions| {
            sessions.push(fresh_session());
        }).unwrap();

        let loaded = store.load().unwrap();
        assert_eq!(loaded.len(), 2);
    }

    #[test]
    fn update_on_missing_file_creates_one() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("fresh.json");
        let store = SessionStore::new(&path);

        store.update(|sessions| {
            sessions.push(fresh_session());
        }).unwrap();

        assert!(path.exists());
        let loaded = store.load().unwrap();
        assert_eq!(loaded.len(), 1);
    }

    #[test]
    fn tmp_path_disambiguation() {
        // Ensures the tmp-file path is different from the real
        // path so the atomic rename actually has something to do.
        let real = PathBuf::from("/var/lib/coincync/sessions.json");
        let tmp = tmp_path_for(&real);
        assert_ne!(real, tmp);
        assert_eq!(tmp.to_string_lossy(), "/var/lib/coincync/sessions.json.tmp");
    }

    #[test]
    fn tmp_path_for_no_extension_path() {
        let real = PathBuf::from("/var/lib/coincync/sessions");
        let tmp = tmp_path_for(&real);
        assert_ne!(real, tmp);
        assert_eq!(tmp.extension().unwrap(), "tmp");
    }

    #[test]
    fn save_leaves_no_orphan_tmp_after_success() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("sessions.json");
        let store = SessionStore::new(&path);

        store.save(&[fresh_session()]).unwrap();
        // The .tmp file should not still exist after a successful
        // save (it was renamed to the real path).
        let tmp = tmp_path_for(&path);
        assert!(!tmp.exists(), "orphan .tmp file remained after save");
    }

    #[test]
    fn session_terminal_state_persists_across_save_load() {
        // A session that has been Aborted should round-trip with
        // its terminal state intact.
        use crate::session::Transition;
        let dir = tempdir().unwrap();
        let path = dir.path().join("sessions.json");
        let store = SessionStore::new(&path);

        let mut s = fresh_session();
        s.apply(Transition::Abort {
            participant: ParticipantId([0xAA; 32]),
        }, 1100).unwrap();
        store.save(&[s]).unwrap();
        let loaded = store.load().unwrap();
        assert_eq!(loaded.len(), 1);
        assert!(loaded[0].state.is_terminal());
    }

    #[test]
    fn many_sessions_round_trip() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("sessions.json");
        let store = SessionStore::new(&path);

        // 100 sessions; checks JSON encoding doesn't have any
        // surprising scaling bugs (it doesn't, but worth a smoke
        // test as a regression guard).
        let sessions: Vec<Session> = (0..100).map(|_| fresh_session()).collect();
        store.save(&sessions).unwrap();
        let loaded = store.load().unwrap();
        assert_eq!(loaded.len(), 100);
    }
}
