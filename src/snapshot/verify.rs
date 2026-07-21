//! Snapshot trust verification — the safety layer.
//!
//! The parent module (`snapshot`) moves bytes: it copies a DB, writes/reads a
//! manifest, and refuses *accidents* — a wrong-chain snapshot (network / genesis
//! mismatch) or a corrupted one (blake3 mismatch). That is necessary but not
//! sufficient against a **malicious source**: an attacker can hand you a DB that
//! opens cleanly, carries our genesis hash, and hashes consistently, yet encodes
//! a *fabricated* history (e.g. a chain where they minted themselves coins, or a
//! deep alternate fork).
//!
//! This module has one job: decide whether an installed DB is **bound to the
//! canonical chain**. It does that with the consensus checkpoints already baked
//! into the binary (`testnet_checkpoints()` / `mainnet_checkpoints()`). An
//! attacker cannot produce a divergent history whose block hashes still match
//! those hard-coded checkpoints, so a fabricated or wrong-fork snapshot is
//! rejected here even though it passed the accident-level gates.
//!
//! The decision is a **pure function** (`verify_chain_binding`) over plain
//! inputs — no I/O — so every branch is unit-testable without spinning up sled.
//! `verify_installed_db` is the thin glue that opens the real DB and feeds those
//! facts in.

use std::path::Path;
use std::sync::Arc;

use crate::config::NetworkType;
use crate::error::{Error, Result};
use crate::primitives::Hash;

use super::SnapshotManifest;

/// Verify that a snapshot's DB is bound to the canonical chain.
///
/// Pure over its inputs (no I/O). Checks, in order:
///   1. **Manifest integrity** — the manifest must describe the DB it ships
///      with. The tip height and tip hash the DB actually reports must equal
///      what the manifest claims. (Stops a manifest that lies about its own
///      payload — e.g. advertising a high height over a stunted DB.)
///   2. **Checkpoint binding** — every consensus checkpoint at or below the
///      snapshot height must be present in the DB with the exact expected hash.
///      This is the defense against a fabricated / wrong-fork history.
///
/// `hash_at_height(h)` returns the DB's main-chain block hash at height `h`, or
/// `None` if the DB has no block there.
pub fn verify_chain_binding(
    manifest: &SnapshotManifest,
    db_tip_height: u64,
    db_tip_hash: &Hash,
    checkpoints: &[(u64, Hash)],
    hash_at_height: impl Fn(u64) -> Option<Hash>,
) -> Result<()> {
    // 1. The manifest must not lie about the DB it carries.
    if db_tip_height != manifest.height {
        return Err(Error::InvalidState(format!(
            "snapshot manifest claims height {} but the DB tip is {} — refusing (manifest/DB mismatch)",
            manifest.height, db_tip_height
        )));
    }
    if db_tip_hash.to_hex() != manifest.tip_hash {
        return Err(Error::InvalidState(format!(
            "snapshot manifest tip {} != DB tip {} — refusing (manifest/DB mismatch)",
            manifest.tip_hash,
            db_tip_hash.to_hex()
        )));
    }

    // 2. Checkpoint binding — the defense against a fabricated history.
    for (height, expected) in checkpoints {
        if *height > db_tip_height {
            // Snapshot doesn't reach this checkpoint yet — nothing to bind
            // against. (A shorter-than-checkpoint snapshot is still useful.)
            continue;
        }
        match hash_at_height(*height) {
            Some(actual) if actual == *expected => {}
            Some(actual) => {
                return Err(Error::InvalidState(format!(
                    "snapshot FAILS consensus checkpoint at height {}: DB has {} but the baked-in checkpoint is {} — refusing (fabricated or wrong-fork chain)",
                    height,
                    actual.to_hex(),
                    expected.to_hex()
                )));
            }
            None => {
                return Err(Error::InvalidState(format!(
                    "snapshot is missing a block at consensus checkpoint height {} (expected {}) — refusing (incomplete or fabricated chain)",
                    height,
                    expected.to_hex()
                )));
            }
        }
    }
    Ok(())
}

/// Open the installed chain DB at `chaindata_dir` and run
/// [`verify_chain_binding`] against it.
///
/// Thin glue over the pure verifier: opens the sled DB, loads chain state to
/// learn the tip, provides a hash-by-height lookup (which reads through to the
/// DB for heights outside the in-memory window), then drops the handle so the
/// sled lock is released before the node starts.
pub fn verify_installed_db(
    chaindata_dir: &Path,
    network: NetworkType,
    manifest: &SnapshotManifest,
    checkpoints: &[(u64, Hash)],
) -> Result<()> {
    use crate::chain::{Blockchain, ChainLoadOutcome};
    use crate::db::Database;

    let db = Database::open(chaindata_dir).map_err(|e| {
        Error::InvalidState(format!(
            "snapshot verify: cannot open installed DB at {}: {}",
            chaindata_dir.display(),
            e
        ))
    })?;
    let chain = Blockchain::with_database(Arc::new(db), network);
    if chain.load_from_database_with_outcome()? == ChainLoadOutcome::Fresh {
        return Err(Error::InvalidState(
            "snapshot verify: installed database has no chain state".into(),
        ));
    }
    let tip = chain.tip();
    verify_chain_binding(manifest, tip.height, &tip.hash, checkpoints, |h| {
        chain.get_block_hash(h)
    })
    // `chain` (and its `Arc<Database>`) is dropped here → sled lock released.
}

#[cfg(test)]
mod tests {
    use super::*;

    fn h(byte: u8) -> Hash {
        Hash::from_bytes([byte; 32])
    }

    fn manifest_at(height: u64, tip: &Hash) -> SnapshotManifest {
        SnapshotManifest {
            network: "testnet".into(),
            genesis_hash: h(0).to_hex(),
            height,
            tip_hash: tip.to_hex(),
            db_blake3: "deadbeef".into(),
            node_version: "1.0.12".into(),
            created_at: 1000,
        }
    }

    #[test]
    fn accepts_when_tip_and_checkpoints_match() {
        let tip = h(9);
        let m = manifest_at(100, &tip);
        // Genesis (h0) + a checkpoint at height 50, both present + correct.
        let cps = vec![(0u64, h(0)), (50u64, h(5))];
        let lookup = |height: u64| match height {
            0 => Some(h(0)),
            50 => Some(h(5)),
            100 => Some(h(9)),
            _ => None,
        };
        assert!(verify_chain_binding(&m, 100, &tip, &cps, lookup).is_ok());
    }

    #[test]
    fn rejects_manifest_height_lie() {
        let tip = h(9);
        let m = manifest_at(100, &tip); // manifest says 100...
        let cps = vec![(0u64, h(0))];
        // ...but the DB tip is really 30.
        let err = verify_chain_binding(&m, 30, &tip, &cps, |_| Some(h(0))).unwrap_err();
        assert!(format!("{:?}", err).contains("manifest/DB mismatch"));
    }

    #[test]
    fn rejects_manifest_tip_hash_lie() {
        let claimed = h(9);
        let m = manifest_at(100, &claimed); // manifest tip = h(9)...
        let actual = h(7); // ...but the DB tip hash is h(7).
        let cps = vec![(0u64, h(0))];
        let err = verify_chain_binding(&m, 100, &actual, &cps, |_| Some(h(0))).unwrap_err();
        assert!(format!("{:?}", err).contains("manifest/DB mismatch"));
    }

    #[test]
    fn rejects_fabricated_history_at_checkpoint() {
        let tip = h(9);
        let m = manifest_at(100, &tip);
        // Consensus checkpoint at 50 expects h(5), but the snapshot's DB has
        // a DIFFERENT block there — a fabricated / wrong-fork chain.
        let cps = vec![(0u64, h(0)), (50u64, h(5))];
        let lookup = |height: u64| match height {
            0 => Some(h(0)),
            50 => Some(h(0xAA)), // wrong!
            100 => Some(h(9)),
            _ => None,
        };
        let err = verify_chain_binding(&m, 100, &tip, &cps, lookup).unwrap_err();
        let s = format!("{:?}", err).to_lowercase();
        assert!(s.contains("checkpoint") && s.contains("height 50"));
    }

    #[test]
    fn rejects_missing_checkpoint_block() {
        let tip = h(9);
        let m = manifest_at(100, &tip);
        let cps = vec![(0u64, h(0)), (50u64, h(5))];
        // DB has genesis + tip but is missing the block at checkpoint 50.
        let lookup = |height: u64| match height {
            0 => Some(h(0)),
            100 => Some(h(9)),
            _ => None,
        };
        let err = verify_chain_binding(&m, 100, &tip, &cps, lookup).unwrap_err();
        assert!(format!("{:?}", err).to_lowercase().contains("missing a block"));
    }

    #[test]
    fn skips_checkpoints_above_snapshot_height() {
        // A snapshot at height 40 must not be rejected for lacking a block at
        // a checkpoint that lives at height 50 (beyond it).
        let tip = h(4);
        let m = manifest_at(40, &tip);
        let cps = vec![(0u64, h(0)), (50u64, h(5))];
        let lookup = |height: u64| match height {
            0 => Some(h(0)),
            40 => Some(h(4)),
            _ => None, // nothing at 50 — and that's fine, it's beyond the tip
        };
        assert!(verify_chain_binding(&m, 40, &tip, &cps, lookup).is_ok());
    }

    #[test]
    fn empty_checkpoints_still_checks_tip_integrity() {
        // With no checkpoints, binding is skipped but the manifest/DB tip
        // consistency check still runs.
        let tip = h(9);
        let m = manifest_at(100, &tip);
        assert!(verify_chain_binding(&m, 100, &tip, &[], |_| None).is_ok());
        let err = verify_chain_binding(&m, 99, &tip, &[], |_| None).unwrap_err();
        assert!(format!("{:?}", err).contains("manifest/DB mismatch"));
    }
}
