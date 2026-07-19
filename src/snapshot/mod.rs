//! Chain snapshot export / import — trusted fast-sync bootstrap.
//!
//! Lets a lagging node jump to a synced node's height by copying a consistent
//! snapshot of the chain DB, instead of grinding Initial Block Download from
//! genesis block-by-block. This is the "trusted local copy" pattern — the same
//! technique Monero documents (copying `data.mdb`) and Bitcoin's old
//! datadir-copy — used because full-genesis IBD does not scale as a chain
//! grows. Every major chain ships an equivalent: Bitcoin AssumeUTXO, Ethereum
//! snap-sync, Cosmos state-sync, Solana snapshots, Polkadot warp-sync.
//!
//! ## Scope / trust
//!
//! The snapshot source must be a node you control. Import verifies the
//! snapshot's declared **network** and **genesis hash** (so a wrong-chain
//! snapshot is refused) and a blake3 **integrity** hash (so corruption is
//! caught) — but it does NOT cryptographically prove the state is a valid
//! product of the chain's history. That background validation is what a
//! *verifiable, peer-served* snapshot (AssumeUTXO-style) would add, and is a
//! separate, larger feature for the untrusted public setting. On a private
//! trusted fleet the local-copy form is the right, minimal tool.
//!
//! ## On-disk format
//!
//! ```text
//!   <out>/db/            — a consistent copy of the sled chain DB directory
//!   <out>/manifest.json  — SnapshotManifest (below)
//! ```
//!
//! The node MUST be stopped when exporting or importing: the sled DB is
//! single-process (file-locked), and a copy taken while it is being written
//! could be inconsistent. `db::shim::open` failing on a locked DB is the guard.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::config::NetworkType;
use crate::error::{Error, Result};
use crate::primitives::Hash;

pub mod signing;
pub mod verify;

/// Metadata describing a chain snapshot. Written alongside the DB copy and
/// verified on import.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SnapshotManifest {
    /// Network the snapshot belongs to ("mainnet" | "testnet" | "regtest").
    pub network: String,
    /// Genesis block hash (hex). Import refuses a mismatch (wrong chain).
    pub genesis_hash: String,
    /// Chain tip height at export time (informational + shown on import).
    pub height: u64,
    /// Chain tip hash (hex) at export time.
    pub tip_hash: String,
    /// blake3 over the DB directory contents — integrity check on import.
    pub db_blake3: String,
    /// Node version that produced the snapshot.
    pub node_version: String,
    /// Unix seconds when the snapshot was taken.
    pub created_at: u64,
}

const DB_SUBDIR: &str = "db";
const MANIFEST_FILE: &str = "manifest.json";
const SIG_FILE: &str = "manifest.sig";

fn io_err(ctx: &str, e: std::io::Error) -> Error {
    Error::Other(format!("snapshot: {}: {}", ctx, e))
}

/// Sign an already-exported snapshot: read `out_dir/manifest.json`, sign its
/// exact bytes with the raw 32-byte Ed25519 `seed`, and write the sidecar to
/// `out_dir/manifest.sig`. A separate step (mirroring peer-snapshot signing) so
/// the producing node never has to hold a signing key in memory during export.
pub fn sign_snapshot_dir(out_dir: &Path, seed: &[u8; 32]) -> Result<signing::ManifestSignature> {
    let manifest_bytes = std::fs::read(out_dir.join(MANIFEST_FILE))
        .map_err(|e| io_err("read manifest to sign", e))?;
    let sig = signing::sign_manifest(seed, &manifest_bytes);
    let json =
        serde_json::to_string_pretty(&sig).map_err(|e| Error::SerializationError(e.to_string()))?;
    std::fs::write(out_dir.join(SIG_FILE), json).map_err(|e| io_err("write manifest.sig", e))?;
    Ok(sig)
}

/// Export a consistent snapshot of `chaindata_dir` into `out_dir`.
///
/// The caller supplies the chain identity (network/genesis/height/tip) read
/// from the opened chain, plus the node version + timestamp. Produces
/// `out_dir/db/` (a copy of the DB) and `out_dir/manifest.json`.
#[allow(clippy::too_many_arguments)]
pub fn export(
    chaindata_dir: &Path,
    out_dir: &Path,
    network: &str,
    genesis_hash: &str,
    height: u64,
    tip_hash: &str,
    node_version: &str,
    created_at: u64,
) -> Result<SnapshotManifest> {
    if !chaindata_dir.is_dir() {
        return Err(Error::InvalidState(format!(
            "chaindata directory not found: {}",
            chaindata_dir.display()
        )));
    }
    let db_dst = out_dir.join(DB_SUBDIR);
    if db_dst.exists() {
        return Err(Error::InvalidState(format!(
            "output already contains a db/ dir: {} (choose an empty --out)",
            db_dst.display()
        )));
    }
    std::fs::create_dir_all(out_dir).map_err(|e| io_err("create out dir", e))?;
    copy_dir_recursive(chaindata_dir, &db_dst)?;
    let db_blake3 = blake3_of_dir(&db_dst)?;
    let manifest = SnapshotManifest {
        network: network.to_string(),
        genesis_hash: genesis_hash.to_string(),
        height,
        tip_hash: tip_hash.to_string(),
        db_blake3,
        node_version: node_version.to_string(),
        created_at,
    };
    let json = serde_json::to_string_pretty(&manifest)
        .map_err(|e| Error::SerializationError(e.to_string()))?;
    std::fs::write(out_dir.join(MANIFEST_FILE), json).map_err(|e| io_err("write manifest", e))?;
    Ok(manifest)
}

/// Policy for verifying + installing a snapshot. Groups the trust inputs so the
/// call reads clearly and future trust layers can be added without churning the
/// signature.
pub struct ImportPolicy<'a> {
    /// Network the local node runs. Used to open the snapshot DB for
    /// verification and to require the manifest's `network` field match.
    pub network: NetworkType,
    /// Local node's genesis hash. The manifest must match (wrong-chain guard).
    pub expected_genesis: &'a Hash,
    /// Baked-in consensus checkpoints `(height, hash)`. Every checkpoint at or
    /// below the snapshot height must be present in the snapshot DB with the
    /// matching hash, or the import is refused (fabricated-history guard). An
    /// empty slice skips DB-level verification — an explicit *unverified*
    /// import for controlled/test use; the CLI always supplies the network's
    /// checkpoints (which always include genesis).
    pub checkpoints: &'a [(u64, Hash)],
    /// Trusted signer public keys (hex Ed25519). If NON-EMPTY, the snapshot
    /// MUST carry a `manifest.sig` whose signer is on this list and whose
    /// signature verifies over the manifest, or the import is refused
    /// (untrusted-source guard). Empty = signature not required — the private
    /// trusted-fleet default.
    pub trusted_signers: &'a [String],
    /// Stamp for the reversible backup of any pre-existing chaindata.
    pub backup_stamp: u64,
}

fn network_str(n: NetworkType) -> &'static str {
    match n {
        NetworkType::Mainnet => "mainnet",
        NetworkType::Testnet => "testnet",
        NetworkType::Regtest => "regtest",
    }
}

/// Verify + install a snapshot from `snapshot_dir` into `chaindata_dir`.
///
/// Trust checks, cheapest-first, ALL before any filesystem mutation:
///   1. **signature** (only if `policy.trusted_signers` is non-empty) — the
///      snapshot's `manifest.sig` must be signed by a trusted key over the
///      manifest (untrusted-source guard);
///   2. **network + genesis** — wrong-chain guard;
///   3. **blake3** — corruption guard.
///
/// Then the DB is installed (existing chaindata MOVED ASIDE to a reversible
/// `.pre-snapshot-<stamp>` sibling, never deleted) and bound to the consensus
/// checkpoints; any verification failure rolls the install back.
pub fn import(
    snapshot_dir: &Path,
    chaindata_dir: &Path,
    policy: &ImportPolicy,
) -> Result<SnapshotManifest> {
    let expected_network = network_str(policy.network);
    let expected_genesis = policy.expected_genesis.to_hex();

    let manifest_path = snapshot_dir.join(MANIFEST_FILE);
    let json = std::fs::read_to_string(&manifest_path).map_err(|e| io_err("read manifest", e))?;
    let manifest: SnapshotManifest =
        serde_json::from_str(&json).map_err(|e| Error::SerializationError(e.to_string()))?;

    // Signature (trusted-source) gate — before touching anything on disk. Only
    // enforced when the caller configures trusted signers; the private fleet
    // leaves this empty and relies on network/genesis/blake3 + checkpoints.
    if !policy.trusted_signers.is_empty() {
        let sig_raw = std::fs::read_to_string(snapshot_dir.join(SIG_FILE)).map_err(|_| {
            Error::InvalidState(format!(
                "snapshot requires a trusted signature but no {} was found — refusing",
                SIG_FILE
            ))
        })?;
        let sig: signing::ManifestSignature = serde_json::from_str(&sig_raw)
            .map_err(|e| Error::SerializationError(format!("parsing {}: {}", SIG_FILE, e)))?;
        signing::verify_manifest_signature(json.as_bytes(), &sig, policy.trusted_signers)?;
    }

    if manifest.network != expected_network {
        return Err(Error::InvalidState(format!(
            "snapshot network '{}' != local '{}' — refusing",
            manifest.network, expected_network
        )));
    }
    if manifest.genesis_hash != expected_genesis {
        return Err(Error::InvalidState(format!(
            "snapshot genesis {} != expected {} — refusing (wrong chain)",
            manifest.genesis_hash, expected_genesis
        )));
    }
    let db_src = snapshot_dir.join(DB_SUBDIR);
    if !db_src.is_dir() {
        return Err(Error::InvalidState(format!(
            "snapshot db/ dir missing: {}",
            db_src.display()
        )));
    }
    let actual = blake3_of_dir(&db_src)?;
    if actual != manifest.db_blake3 {
        return Err(Error::InvalidState(format!(
            "snapshot integrity check FAILED: computed blake3 {} != manifest {}",
            actual, manifest.db_blake3
        )));
    }

    // Back up any existing chaindata (reversible — moved, never deleted). Held
    // so a failed verification can roll the node back to its prior state.
    let backup_path = if chaindata_dir.exists() {
        let name = chaindata_dir
            .file_name()
            .and_then(|s| s.to_str())
            .unwrap_or("chaindata");
        let backup =
            chaindata_dir.with_file_name(format!("{}.pre-snapshot-{}", name, policy.backup_stamp));
        std::fs::rename(chaindata_dir, &backup)
            .map_err(|e| io_err("back up existing chaindata", e))?;
        Some(backup)
    } else {
        None
    };
    copy_dir_recursive(&db_src, chaindata_dir)?;

    // Trust verification: bind the freshly installed DB to the canonical chain
    // via consensus checkpoints (+ manifest/DB tip consistency). On ANY failure
    // the bad DB is removed and the prior chaindata restored, so a rejected
    // snapshot never becomes the node's live state.
    if !policy.checkpoints.is_empty() {
        if let Err(e) = verify::verify_installed_db(
            chaindata_dir,
            policy.network,
            &manifest,
            policy.checkpoints,
        ) {
            let _ = std::fs::remove_dir_all(chaindata_dir);
            if let Some(bp) = &backup_path {
                let _ = std::fs::rename(bp, chaindata_dir);
            }
            return Err(e);
        }
    }

    Ok(manifest)
}

fn copy_dir_recursive(src: &Path, dst: &Path) -> Result<()> {
    std::fs::create_dir_all(dst).map_err(|e| io_err("create dir", e))?;
    for entry in std::fs::read_dir(src).map_err(|e| io_err("read dir", e))? {
        let entry = entry.map_err(|e| io_err("dir entry", e))?;
        let ty = entry.file_type().map_err(|e| io_err("file type", e))?;
        let from = entry.path();
        let to = dst.join(entry.file_name());
        if ty.is_dir() {
            copy_dir_recursive(&from, &to)?;
        } else if ty.is_file() {
            std::fs::copy(&from, &to).map_err(|e| io_err("copy file", e))?;
        }
        // symlinks / special files are skipped — a sled DB directory has none.
    }
    Ok(())
}

/// Deterministic blake3 over every file in `dir` (relative path + byte length +
/// contents, files sorted), so identical DB content always hashes the same
/// regardless of directory-read order across machines.
fn blake3_of_dir(dir: &Path) -> Result<String> {
    let mut files: Vec<PathBuf> = Vec::new();
    collect_files(dir, &mut files)?;
    files.sort();
    let mut hasher = blake3::Hasher::new();
    for f in &files {
        let rel = f.strip_prefix(dir).unwrap_or(f);
        hasher.update(rel.to_string_lossy().as_bytes());
        hasher.update(&[0u8]);
        let bytes = std::fs::read(f).map_err(|e| io_err("read file for hash", e))?;
        hasher.update(&(bytes.len() as u64).to_le_bytes());
        hasher.update(&bytes);
    }
    Ok(hasher.finalize().to_hex().to_string())
}

fn collect_files(dir: &Path, out: &mut Vec<PathBuf>) -> Result<()> {
    for entry in std::fs::read_dir(dir).map_err(|e| io_err("read dir", e))? {
        let entry = entry.map_err(|e| io_err("dir entry", e))?;
        let p = entry.path();
        let ty = entry.file_type().map_err(|e| io_err("file type", e))?;
        if ty.is_dir() {
            collect_files(&p, out)?;
        } else if ty.is_file() {
            out.push(p);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn write_file(dir: &Path, name: &str, content: &[u8]) {
        std::fs::create_dir_all(dir).unwrap();
        std::fs::write(dir.join(name), content).unwrap();
    }

    fn scratch(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("cync-snap-{}-{}", tag, std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        d
    }

    #[test]
    fn export_then_import_round_trips_and_verifies() {
        let tmp = scratch("rt");
        let chaindata = tmp.join("testnet");
        write_file(&chaindata, "blocks.db", b"block-bytes");
        write_file(&chaindata.join("sub"), "state.db", b"state-bytes");

        let out = tmp.join("snap");
        let g = Hash::from_bytes([1u8; 32]);
        let m = export(
            &chaindata,
            &out,
            "testnet",
            &g.to_hex(),
            42,
            "TIPHASH",
            "1.0.12",
            1000,
        )
        .unwrap();
        assert_eq!(m.height, 42);
        assert_eq!(m.network, "testnet");
        assert!(out.join("manifest.json").exists());
        assert!(out.join("db").join("blocks.db").exists());

        let dest = tmp.join("dest_testnet");
        // Empty checkpoints: mechanics-only test over a synthetic DB dir, so
        // DB-level trust verification is skipped here — that path is covered by
        // the pure-function tests in `verify`.
        let policy = ImportPolicy {
            network: NetworkType::Testnet,
            expected_genesis: &g,
            checkpoints: &[],
            trusted_signers: &[],
            backup_stamp: 2000,
        };
        let imported = import(&out, &dest, &policy).unwrap();
        assert_eq!(imported, m);
        assert_eq!(
            std::fs::read(dest.join("blocks.db")).unwrap(),
            b"block-bytes"
        );
        assert_eq!(
            std::fs::read(dest.join("sub").join("state.db")).unwrap(),
            b"state-bytes"
        );

        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn import_refuses_wrong_genesis() {
        let tmp = scratch("gen");
        let chaindata = tmp.join("testnet");
        write_file(&chaindata, "b.db", b"x");
        let out = tmp.join("snap");
        let ga = Hash::from_bytes([0xAA; 32]);
        let gb = Hash::from_bytes([0xBB; 32]);
        export(
            &chaindata,
            &out,
            "testnet",
            &ga.to_hex(),
            1,
            "T",
            "1.0.12",
            1,
        )
        .unwrap();

        let dest = tmp.join("dest");
        let policy = ImportPolicy {
            network: NetworkType::Testnet,
            expected_genesis: &gb,
            checkpoints: &[],
            trusted_signers: &[],
            backup_stamp: 2,
        };
        let err = import(&out, &dest, &policy).unwrap_err();
        assert!(format!("{:?}", err).to_lowercase().contains("genesis"));
        assert!(!dest.exists(), "must not install a wrong-chain snapshot");
        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn import_detects_corruption() {
        let tmp = scratch("corrupt");
        let chaindata = tmp.join("testnet");
        write_file(&chaindata, "b.db", b"original");
        let out = tmp.join("snap");
        let g = Hash::from_bytes([7u8; 32]);
        export(
            &chaindata,
            &out,
            "testnet",
            &g.to_hex(),
            1,
            "T",
            "1.0.12",
            1,
        )
        .unwrap();

        // Tamper with the snapshot DB after export.
        std::fs::write(out.join("db").join("b.db"), b"tampered").unwrap();
        let dest = tmp.join("dest");
        let policy = ImportPolicy {
            network: NetworkType::Testnet,
            expected_genesis: &g,
            checkpoints: &[],
            trusted_signers: &[],
            backup_stamp: 2,
        };
        let err = import(&out, &dest, &policy).unwrap_err();
        assert!(format!("{:?}", err).to_lowercase().contains("integrity"));
        assert!(!dest.exists(), "corrupt snapshot must not be installed");
        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn import_backs_up_existing_chaindata() {
        let tmp = scratch("backup");
        let chaindata = tmp.join("testnet");
        write_file(&chaindata, "b.db", b"snap-content");
        let out = tmp.join("snap");
        let g = Hash::from_bytes([5u8; 32]);
        export(
            &chaindata,
            &out,
            "testnet",
            &g.to_hex(),
            5,
            "T",
            "1.0.12",
            1,
        )
        .unwrap();

        // Destination already has (different) chaindata.
        let dest = tmp.join("live");
        write_file(&dest, "b.db", b"OLD-LIVE-DATA");
        let policy = ImportPolicy {
            network: NetworkType::Testnet,
            expected_genesis: &g,
            checkpoints: &[],
            trusted_signers: &[],
            backup_stamp: 777,
        };
        import(&out, &dest, &policy).unwrap();

        // New content installed; old content preserved in the backup.
        assert_eq!(std::fs::read(dest.join("b.db")).unwrap(), b"snap-content");
        let backup = tmp.join("live.pre-snapshot-777");
        assert_eq!(
            std::fs::read(backup.join("b.db")).unwrap(),
            b"OLD-LIVE-DATA"
        );
        let _ = std::fs::remove_dir_all(&tmp);
    }

    // ── End-to-end tests over a REAL sled chain DB ──────────────────────────
    // The tests above exercise the copy/manifest/backup mechanics over synthetic
    // dirs (empty checkpoints → DB verification skipped). These build an actual
    // genesis chain DB so the full `verify::verify_installed_db` glue runs for
    // real: opening the installed DB, reading its tip, and binding it to the
    // network's consensus checkpoints.

    /// Build a real, on-disk testnet chain DB containing only the genesis block
    /// at `chaindata`, flush it, and release the sled lock. Returns the genesis
    /// hash. After this returns, `chaindata` is a complete, copyable DB dir.
    fn build_genesis_db(chaindata: &Path) -> Hash {
        use crate::chain::Blockchain;
        use crate::db::Database;
        use std::sync::Arc;

        std::fs::create_dir_all(chaindata).unwrap();
        let db = Arc::new(Database::open(chaindata).unwrap());
        let chain = Blockchain::with_database(db.clone(), NetworkType::Testnet);
        let hash = chain.init_genesis().unwrap();
        db.flush().unwrap(); // ensure sled files are complete before we copy
        drop(chain);
        drop(db); // release the sled lock before the dir is copied
        hash
    }

    #[test]
    fn verify_installed_db_accepts_real_genesis_chain() {
        let tmp = scratch("e2e-ok");
        let src = tmp.join("testnet");
        let genesis = build_genesis_db(&src);

        let out = tmp.join("snap");
        let m = export(
            &src,
            &out,
            "testnet",
            &genesis.to_hex(),
            0,
            &genesis.to_hex(),
            "1.0.12",
            1234,
        )
        .unwrap();
        assert_eq!(m.height, 0);

        // Real consensus checkpoints — genesis (h0) applies; any higher
        // checkpoint is above the snapshot tip and skipped.
        let checkpoints: Vec<(u64, Hash)> = crate::testnet::testnet_checkpoints()
            .into_iter()
            .map(|c| (c.height, c.hash))
            .collect();
        let dest = tmp.join("dest_testnet");
        let policy = ImportPolicy {
            network: NetworkType::Testnet,
            expected_genesis: &genesis,
            checkpoints: &checkpoints,
            trusted_signers: &[],
            backup_stamp: 5,
        };

        // Success here means verify_installed_db opened the real DB, confirmed
        // the tip matches the manifest, and bound genesis to the checkpoint.
        let imported = import(&out, &dest, &policy).unwrap();
        assert_eq!(imported.height, 0);
        assert!(dest.is_dir(), "verified snapshot must be installed");

        // The installed DB reopens as the same chain.
        let reopened = build_reopen_tip(&dest);
        assert_eq!(
            reopened, genesis,
            "reopened DB tip must be the genesis hash"
        );

        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn verify_installed_db_rejects_bad_checkpoint_and_rolls_back() {
        let tmp = scratch("e2e-bad");
        let src = tmp.join("testnet");
        let genesis = build_genesis_db(&src);

        let out = tmp.join("snap");
        export(
            &src,
            &out,
            "testnet",
            &genesis.to_hex(),
            0,
            &genesis.to_hex(),
            "1.0.12",
            1234,
        )
        .unwrap();

        // A bogus checkpoint at height 0 that does NOT match the real genesis —
        // simulates a snapshot whose history diverges from our consensus.
        let bogus = vec![(0u64, Hash::from_bytes([0xEE; 32]))];

        // Destination already holds prior chaindata — it must be restored when
        // the rejected snapshot is rolled back.
        let dest = tmp.join("live");
        write_file(&dest, "MARKER", b"PRIOR-CHAINDATA");
        let policy = ImportPolicy {
            network: NetworkType::Testnet,
            expected_genesis: &genesis,
            checkpoints: &bogus,
            trusted_signers: &[],
            backup_stamp: 9,
        };

        let err = import(&out, &dest, &policy).unwrap_err();
        assert!(
            format!("{:?}", err).to_lowercase().contains("checkpoint"),
            "expected a checkpoint failure, got: {:?}",
            err
        );
        // Rolled back: the prior chaindata is restored, the rejected snapshot is
        // gone.
        assert_eq!(
            std::fs::read(dest.join("MARKER")).unwrap(),
            b"PRIOR-CHAINDATA",
            "prior chaindata must be restored after a rejected snapshot"
        );

        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn import_accepts_trusted_signed_snapshot() {
        let tmp = scratch("sig-ok");
        let src = tmp.join("testnet");
        let genesis = build_genesis_db(&src);
        let out = tmp.join("snap");
        export(
            &src,
            &out,
            "testnet",
            &genesis.to_hex(),
            0,
            &genesis.to_hex(),
            "1.0.12",
            1234,
        )
        .unwrap();

        // Sign the exported manifest and trust that signer.
        let seed = [11u8; 32];
        sign_snapshot_dir(&out, &seed).unwrap();
        let trusted = vec![signing::pubkey_for_seed(&seed)];

        let checkpoints: Vec<(u64, Hash)> = crate::testnet::testnet_checkpoints()
            .into_iter()
            .map(|c| (c.height, c.hash))
            .collect();
        let dest = tmp.join("dest");
        let policy = ImportPolicy {
            network: NetworkType::Testnet,
            expected_genesis: &genesis,
            checkpoints: &checkpoints,
            trusted_signers: &trusted,
            backup_stamp: 1,
        };
        // Signature + checkpoints + tip all pass.
        assert!(import(&out, &dest, &policy).is_ok());
        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn import_rejects_untrusted_and_missing_signature() {
        let tmp = scratch("sig-bad");
        let src = tmp.join("testnet");
        let genesis = build_genesis_db(&src);
        let out = tmp.join("snap");
        export(
            &src,
            &out,
            "testnet",
            &genesis.to_hex(),
            0,
            &genesis.to_hex(),
            "1.0.12",
            1234,
        )
        .unwrap();

        let checkpoints: Vec<(u64, Hash)> = crate::testnet::testnet_checkpoints()
            .into_iter()
            .map(|c| (c.height, c.hash))
            .collect();

        // (a) Signed by seed A, but only seed B is trusted → refused, nothing
        // installed (the sig gate runs before any filesystem mutation).
        sign_snapshot_dir(&out, &[1u8; 32]).unwrap();
        let trusted_b = vec![signing::pubkey_for_seed(&[2u8; 32])];
        let dest_a = tmp.join("dest_a");
        let policy_a = ImportPolicy {
            network: NetworkType::Testnet,
            expected_genesis: &genesis,
            checkpoints: &checkpoints,
            trusted_signers: &trusted_b,
            backup_stamp: 1,
        };
        let err = import(&out, &dest_a, &policy_a).unwrap_err();
        assert!(format!("{:?}", err).contains("trusted-signer"));
        assert!(
            !dest_a.exists(),
            "untrusted-signed snapshot must not install"
        );

        // (b) Remove the signature; a trusted-signers policy must refuse the
        // now-unsigned snapshot.
        std::fs::remove_file(out.join("manifest.sig")).unwrap();
        let trusted_a = vec![signing::pubkey_for_seed(&[1u8; 32])];
        let dest_b = tmp.join("dest_b");
        let policy_b = ImportPolicy {
            network: NetworkType::Testnet,
            expected_genesis: &genesis,
            checkpoints: &checkpoints,
            trusted_signers: &trusted_a,
            backup_stamp: 1,
        };
        let err = import(&out, &dest_b, &policy_b).unwrap_err();
        assert!(format!("{:?}", err).to_lowercase().contains("signature"));
        assert!(!dest_b.exists(), "unsigned snapshot must not install");

        let _ = std::fs::remove_dir_all(&tmp);
    }

    /// Reopen a chaindata dir and return its loaded tip hash.
    fn build_reopen_tip(chaindata: &Path) -> Hash {
        use crate::chain::Blockchain;
        use crate::db::Database;
        use std::sync::Arc;

        let db = Arc::new(Database::open(chaindata).unwrap());
        let chain = Blockchain::with_database(db.clone(), NetworkType::Testnet);
        chain.load_from_database().unwrap();
        let tip = chain.tip().hash;
        drop(chain);
        drop(db);
        tip
    }
}
