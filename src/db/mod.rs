//! # Database Module
//!
//! Persistent storage using sled embedded database.
//!
//! ## Key Encoding Convention (H26)
//!
//! CONVENTION: All sled tree keys use big-endian (BE) encoding for correct
//! lexicographic ordering. PoW hash inputs use little-endian (LE) as part of
//! the hash preimage. These are different contexts and intentionally use
//! different encodings.
//!
//! ## Performance Tuning
//!
//! Sled is configured for optimal blockchain performance:
//! - Large cache for hot data (blocks, UTXOs)
//! - Async flushing to reduce write latency
//! - Optimized segment size for blockchain workloads
//! - Optional compression for storage efficiency

pub mod shim;
mod blocks;
mod utxos;
mod state;
mod keys;
mod mempool;
mod wallet;
mod output_index;
pub mod filters;
pub mod pruning;

pub use blocks::BlockDb;
pub use utxos::{UtxoDb, OutputEntry};
pub use state::{StateDb, ChainStateData};
pub use keys::{KeyDb, EncryptedKey, KeyEntry, KeyMetadata};
pub use mempool::{MempoolDb, MempoolEntry};
pub use wallet::{WalletDb, OwnedOutput, ScanState};
pub use output_index::{OutputIndexDb, OutputIndexEntry};
pub use filters::FilterDb;
pub use pruning::{PruneResult, prune_blocks, is_pruned};

use std::path::Path;
use crate::error::{Error, Result};
use crate::primitives::Hash;

/// Database performance mode
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DbMode {
    /// Fast mode: prioritize speed over durability
    /// Good for initial sync, uses async I/O aggressively
    Fast,
    /// Safe mode: prioritize durability over speed
    /// Good for normal operation, ensures writes are persisted
    Safe,
    /// Balanced mode: reasonable trade-off (default)
    Balanced,
}

impl Default for DbMode {
    fn default() -> Self {
        DbMode::Balanced
    }
}

/// Database configuration with performance tuning options
#[derive(Clone, Debug)]
pub struct DbConfig {
    /// Cache size in MB (default: 512 MB for good read performance)
    pub cache_size_mb: usize,
    /// Flush interval in ms (None = manual flush only)
    pub flush_interval_ms: Option<u64>,
    /// Performance mode
    pub mode: DbMode,
    /// Use compression (saves ~30% space, slight CPU cost)
    pub use_compression: bool,
    /// Segment size in bytes (larger = better sequential reads)
    /// Default: 16 MB (sled maximum)
    pub segment_size: usize,
    /// Maximum concurrent readers
    pub max_readers: usize,
    /// Print size limit for debugging (0 = disabled)
    pub print_profile_on_drop: bool,
}

impl Default for DbConfig {
    fn default() -> Self {
        DbConfig {
            cache_size_mb: 512,                    // 512 MB cache
            flush_interval_ms: Some(1000),         // Flush every second
            mode: DbMode::Balanced,
            use_compression: true,                 // Enable zstd compression
            segment_size: 16 * 1024 * 1024,       // 16 MB segments (sled max)
            max_readers: 128,
            print_profile_on_drop: false,
        }
    }
}

impl DbConfig {
    /// Configuration optimized for initial blockchain sync
    pub fn fast_sync() -> Self {
        DbConfig {
            cache_size_mb: 1024,                   // 1 GB cache for sync
            flush_interval_ms: Some(5000),         // Flush every 5 seconds
            mode: DbMode::Fast,
            use_compression: false,                // Skip compression during sync
            segment_size: 16 * 1024 * 1024,        // 16 MB (sled max)
            max_readers: 64,
            print_profile_on_drop: false,
        }
    }

    /// Configuration optimized for low-memory systems
    pub fn low_memory() -> Self {
        DbConfig {
            cache_size_mb: 128,                    // 128 MB cache
            flush_interval_ms: Some(500),          // Flush more often
            mode: DbMode::Safe,
            use_compression: true,                 // Save disk space
            segment_size: 8 * 1024 * 1024,        // 8 MB segments
            max_readers: 32,
            print_profile_on_drop: false,
        }
    }

    /// Configuration for maximum safety (exchanges, validators)
    pub fn maximum_safety() -> Self {
        DbConfig {
            cache_size_mb: 256,
            flush_interval_ms: Some(100),          // Flush very often
            mode: DbMode::Safe,
            use_compression: true,
            segment_size: 16 * 1024 * 1024,       // 16 MB (sled max)
            max_readers: 64,
            print_profile_on_drop: false,
        }
    }

    /// Auto-detect optimal config based on system resources
    pub fn auto() -> Self {
        let available_memory_mb = get_available_memory_mb();

        if available_memory_mb > 8192 {
            // 8+ GB RAM: use aggressive caching
            DbConfig {
                cache_size_mb: 1024,
                ..Default::default()
            }
        } else if available_memory_mb > 4096 {
            // 4-8 GB RAM: standard config
            DbConfig::default()
        } else if available_memory_mb > 2048 {
            // 2-4 GB RAM: conservative
            DbConfig {
                cache_size_mb: 256,
                ..Default::default()
            }
        } else {
            // <2 GB RAM: minimal
            DbConfig::low_memory()
        }
    }
}

/// Get available system memory in MB
fn get_available_memory_mb() -> usize {
    // Try to detect system memory
    // Falls back to conservative estimate if detection fails
    #[cfg(target_os = "linux")]
    {
        if let Ok(meminfo) = std::fs::read_to_string("/proc/meminfo") {
            for line in meminfo.lines() {
                if line.starts_with("MemTotal:") {
                    if let Some(kb_str) = line.split_whitespace().nth(1) {
                        if let Ok(kb) = kb_str.parse::<usize>() {
                            return kb / 1024;
                        }
                    }
                }
            }
        }
    }

    #[cfg(target_os = "windows")]
    {
        // R-33 fix (2026-07-03): pre-fix code left this block empty
        // (just a doc comment) and silently fell through to the
        // 4096 MB default. Consequence: every Windows deployment
        // got the "4-8 GB RAM" config regardless of actual host
        // memory — an 8+ GB box never enabled the 1024 MB
        // aggressive-cache config, and a 2 GB box got a config
        // that OOMs during IBD.
        //
        // Use the Win32 GlobalMemoryStatusEx API directly via the
        // minimal FFI declaration below — avoids pulling in a large
        // dependency (`sysinfo`, `windows-sys`) just for one call.
        // This is the same API sysinfo would ultimately dispatch to.
        //
        // Safety: GlobalMemoryStatusEx takes a MEMORYSTATUSEX* and
        // writes into it. We zero-init the struct with dwLength set
        // to the struct size (an OS-enforced discriminator). Return
        // value 0 = failure; we honor it by falling through to the
        // 4096 default with a tracing::warn.
        #[repr(C)]
        struct MemoryStatusEx {
            dw_length: u32,
            dw_memory_load: u32,
            ull_total_phys: u64,
            ull_avail_phys: u64,
            ull_total_page_file: u64,
            ull_avail_page_file: u64,
            ull_total_virtual: u64,
            ull_avail_virtual: u64,
            ull_avail_extended_virtual: u64,
        }
        extern "system" {
            fn GlobalMemoryStatusEx(lpBuffer: *mut MemoryStatusEx) -> i32;
        }

        let mut status: MemoryStatusEx = unsafe { std::mem::zeroed() };
        status.dw_length = std::mem::size_of::<MemoryStatusEx>() as u32;
        // Safety: pointer is to a stack-owned struct with matching
        // dw_length. GlobalMemoryStatusEx is documented as thread-safe
        // and does not retain the pointer past the call.
        let ok = unsafe { GlobalMemoryStatusEx(&mut status) };
        if ok != 0 {
            let mb = (status.ull_total_phys / (1024 * 1024)) as usize;
            if mb >= 512 {
                return mb;
            }
        }
        tracing::warn!(
            target: "db_config",
            "get_available_memory_mb: Win32 GlobalMemoryStatusEx returned \
             failure or an implausible value; falling back to 4096 MB \
             default. DB cache may be undersized on high-RAM hosts — set \
             cache_size_mb explicitly via DbConfig if this matters."
        );
    }

    // Default: assume 4 GB
    4096
}

/// Main database handle
pub struct Database {
    /// Underlying key/value store (RocksDB-backed shim)
    db: shim::Db,
    /// Block storage
    pub blocks: BlockDb,
    /// UTXO storage
    pub utxos: UtxoDb,
    /// Chain state
    pub state: StateDb,
    /// Key storage
    pub keys: KeyDb,
    /// Mempool storage
    pub mempool: MempoolDb,
    /// Permanent output index (for ring member validation of spent outputs)
    pub output_index: OutputIndexDb,
    /// Block filter storage for personal node protocol (Tier 2 serving)
    pub filters: FilterDb,
    /// Transaction hash → (block_height, tx_index) for O(1) tx lookups
    pub tx_index: shim::Tree,
    /// DB-level metadata (schema_version, future cross-cutting flags).
    /// Reserved key namespace `b"schema/*"` for versioning; future cross-
    /// cutting metadata can use other prefixes. Public so RPC/diagnostic
    /// code can read the schema version on a live node.
    pub metadata: shim::Tree,
}

// ─── Schema versioning ──────────────────────────────────────────────
//
// The DB carries a single `u32` schema-version stamp in the
// `__db_metadata__` tree under the key `b"schema/db_version"`. Every
// release increments `EXPECTED_DB_SCHEMA_VERSION` when ANY persisted
// Borsh struct's on-disk layout changes incompatibly. Open-time check:
//   - Fresh DB (no blocks yet) → stamp current version, proceed.
//   - Existing DB with matching version → proceed.
//   - Existing DB with missing version → refuse to start: legacy v0 DB
//     that predates this versioning scheme. Operator chooses wipe-and-
//     resync, or writes an explicit one-time migration. No silent
//     auto-migrate at this version because there's no v0→v1 mapping
//     yet (v0 had no version field — the layouts ARE byte-identical
//     today, but future v1.1 must not accidentally read a v0 layout
//     as if it were v1).
//   - Existing DB with stored > expected → refuse to start: future DB,
//     operator downgraded binary. Same as Bitcoin Core's
//     `kVersionNumberFromDb > kCurrentVersion` check.
//   - Existing DB with stored < expected → future PR will run
//     registered migration closures here. Today the migration table
//     is empty, so this branch returns an explicit "no migration
//     registered" error — better than a silent skip.
//
// ## Prior art
//
// - **Monero** (`BlockchainDB::get_db_version` + `m_open`): single
//   `uint32` per-DB version, compared against `MAX_VERSION` constant.
//   Same shape used here.
// - **Bitcoin Core** (`CDBWrapper::Read(kVersionKey, ...)`): per-DB
//   version stored in a reserved key; mismatch aborts startup.
//   CoinCync mirrors this pattern, with the additional fresh-DB
//   short-circuit Monero also has.
// - **Zcash** (`CDBEnv::version_check` in `walletdb.cpp`): same
//   pattern, version stored in DB header. Migration registry
//   dispatched per (from, to) tuple, which is the shape the future
//   v1.1 migration code will adopt here.
//
// ## Why u32 (not u8)
//
// u8 is sufficient for foreseeable lifetime (255 schema versions =
// 255 incompatible v1.X.Y releases — a chain that takes 30 years to
// hit). u32 is the Monero/Bitcoin/Zcash convention; following it
// avoids "why is CoinCync special?" review noise. Cost: 3 wasted
// bytes per DB. Trivial.
//
// ## Why the constant lives in this module (not in `constants.rs`)
//
// Schema version is a DB-layer invariant, not a consensus rule.
// Bumping it doesn't fork the chain — it changes how locally-stored
// data is laid out on disk. Keeping it adjacent to the open-time
// check makes both ends visible in one place; reviewers reading the
// schema-version logic don't have to context-switch to constants.rs
// to understand what "EXPECTED" means.

/// Verify the DB's stored schema version matches `EXPECTED_DB_SCHEMA_VERSION`,
/// or stamp it if the DB is fresh. Called once during `Database::open_with_config`.
///
/// Decision matrix:
///
/// | Stored version | Fresh DB?   | Action                                    |
/// |----------------|-------------|-------------------------------------------|
/// | None           | YES         | Stamp EXPECTED, proceed                   |
/// | None           | NO          | ERROR: legacy v0 DB needs migration       |
/// | Some(v == EXP) | (either)    | Proceed                                   |
/// | Some(v <  EXP) | (either)    | ERROR: no migration registered (today)    |
/// | Some(v >  EXP) | (either)    | ERROR: future DB, downgrade binary        |
///
/// Fresh-DB detection uses `BlockDb::is_empty()` (no blocks accepted yet).
/// This is the same shape Bitcoin Core uses (`pblockindex->empty()` check
/// during `LoadBlockIndexDB`) and Monero uses (`m_height == 0` check in
/// `BlockchainDB::is_open`).
fn verify_or_stamp_schema_version(
    metadata: &shim::Tree,
    blocks: &BlockDb,
) -> Result<()> {
    let stored = metadata.get(SCHEMA_VERSION_KEY)
        .map_err(|e| Error::DatabaseError(format!(
            "failed to read schema_version from metadata tree: {}", e
        )))?;

    match stored {
        None => {
            // No version stamp. Either fresh DB (no blocks yet) or
            // legacy v0 DB that predates this versioning scheme.
            if blocks.is_empty() {
                // Fresh DB: stamp it.
                let version_bytes = EXPECTED_DB_SCHEMA_VERSION.to_le_bytes();
                metadata.insert(SCHEMA_VERSION_KEY, &version_bytes)
                    .map_err(|e| Error::DatabaseError(format!(
                        "failed to stamp initial schema_version: {}", e
                    )))?;
                tracing::info!(
                    "Fresh database initialized with schema_version = {}",
                    EXPECTED_DB_SCHEMA_VERSION,
                );
                Ok(())
            } else {
                // Existing DB with no version stamp = legacy. Refuse to
                // open. Operator must wipe-and-resync OR write a one-time
                // migration script. Auto-migrate is unsafe at this stage
                // because pre-v1 layout has no formal definition we can
                // pin (the layout WAS v0 by convention, but v0 was never
                // explicitly stamped, so we can't be sure what we'd be
                // reading).
                Err(Error::DatabaseError(format!(
                    "Legacy database detected: blocks present but no schema_version \
                     stamp. This DB was created before schema versioning was \
                     introduced (pre-v1). To proceed, either (a) wipe the data dir \
                     and resync from genesis, or (b) restore from a v1-stamped \
                     chaindata snapshot. Expected schema_version = {}.",
                    EXPECTED_DB_SCHEMA_VERSION,
                )))
            }
        }
        Some(bytes) if bytes.len() != 4 => {
            // Length mismatch = corruption or future format
            // (e.g., if v2 switches to u64). Refuse to start.
            Err(Error::DatabaseError(format!(
                "schema_version key has wrong length: expected 4 bytes (u32 LE), \
                 got {} bytes. Either DB corruption or a binary built for a future \
                 schema-version format.",
                bytes.len(),
            )))
        }
        Some(bytes) => {
            let mut buf = [0u8; 4];
            buf.copy_from_slice(&bytes);
            let stored_version = u32::from_le_bytes(buf);

            match stored_version.cmp(&EXPECTED_DB_SCHEMA_VERSION) {
                std::cmp::Ordering::Equal => {
                    tracing::debug!(
                        "DB schema_version = {} (matches expected)",
                        stored_version,
                    );
                    Ok(())
                }
                std::cmp::Ordering::Greater => {
                    // Stored > expected: DB created by a future binary,
                    // operator downgraded. We refuse to start because we
                    // can't safely read a layout newer than we know.
                    Err(Error::DatabaseError(format!(
                        "DB schema_version is {} but this binary expects {}. \
                         The database was created by a newer binary; either \
                         upgrade this binary to a release that knows version {}, \
                         or wipe the data dir and resync.",
                        stored_version, EXPECTED_DB_SCHEMA_VERSION, stored_version,
                    )))
                }
                std::cmp::Ordering::Less => {
                    // Stored < expected: an upgrade path is needed. In v1.0
                    // there are no migrations (we're at v1). When v1.1
                    // bumps EXPECTED to 2, this branch will dispatch into
                    // a registered migration table (see future commit).
                    Err(Error::DatabaseError(format!(
                        "DB schema_version is {} but this binary expects {}. \
                         No migration is registered for {} → {} yet. This is a \
                         placeholder error — when v1.1 ships, this branch will \
                         run the registered migration. For now: wipe the data dir \
                         and resync from genesis, OR downgrade to a binary that \
                         expects schema_version {}.",
                        stored_version, EXPECTED_DB_SCHEMA_VERSION,
                        stored_version, EXPECTED_DB_SCHEMA_VERSION,
                        stored_version,
                    )))
                }
            }
        }
    }
}

/// Outcome of a [`migrate_legacy_db_to_v1`] call.
#[derive(Debug, PartialEq, Eq)]
pub enum MigrationOutcome {
    /// DB was already stamped at the expected version (idempotent re-run).
    AlreadyStamped,
    /// DB was unstamped (legacy pre-v1) and we stamped it as v1 after
    /// confirming the genesis block matches the expected hash.
    Stamped { genesis_hash: Hash },
}

/// One-shot legacy DB migration: stamp an existing pre-v1 chaindata
/// with `schema_version = 1`, after validating the genesis block in
/// the DB matches the expected genesis hash for the network.
///
/// This is the explicit-opt-in escape hatch for fleet and community
/// operators upgrading from v1.0.11.x (which did not write the
/// schema_version stamp) to v1.0.12+ (which requires it). Without this
/// helper the only options were "wipe and resync from genesis" or
/// "restore from a v1-stamped snapshot" — neither of which exists
/// yet in production.
///
/// ## Safety
///
/// The hard rule baked into [`verify_or_stamp_schema_version`] is "do
/// not silently auto-migrate; the layout of pre-v1 DBs was never
/// formally defined." This helper does NOT auto-stamp — it requires
/// the caller to:
///
///   1. Pass the network's `expected_genesis` hash explicitly. We then
///      read the actual block-0 hash from the DB and refuse to stamp
///      if they disagree. That guards against:
///        - Stamping a mainnet DB with a testnet binary (or vice versa)
///        - Stamping a DB that was forked off at genesis (different
///          chain entirely)
///        - Stamping a corrupted DB whose height index points at
///          the wrong block
///
///   2. Invoke this function explicitly via a CLI subcommand
///      (`coincync-node migrate-legacy-db`) — the normal `Database::open`
///      path still rejects unstamped DBs. This is operator-acknowledged
///      action, not silent on-startup behavior.
///
/// ## Idempotency
///
/// Re-running on an already-stamped DB returns [`MigrationOutcome::AlreadyStamped`]
/// and changes nothing. Safe to re-invoke in operator runbooks without
/// guard conditions.
///
/// ## Errors
///
/// - Empty DB (no block at height 0) — use normal [`Database::open`]
///   to initialize a fresh DB; this helper is only for legacy migration
/// - DB stamped at a non-v1 version (would need a real migration table,
///   not just a stamp)
/// - Genesis-hash mismatch (DB belongs to a different network/chain)
/// - Any RocksDB I/O error during read/write
///
/// ## Future
///
/// When v1 → v2 migration ships, the `Less` branch of
/// [`verify_or_stamp_schema_version`] will dispatch into a registered
/// migration table. This helper stays in place as the legacy-only
/// entry point for v0 → v1.
pub fn migrate_legacy_db_to_v1<P: AsRef<Path>>(
    path: P,
    config: DbConfig,
    expected_genesis: &Hash,
) -> Result<MigrationOutcome> {
    tracing::info!(
        "Opening database for legacy migration: cache={}MB, mode={:?}",
        config.cache_size_mb,
        config.mode,
    );

    let db = shim::Config::new()
        .path(path)
        .cache_capacity((config.cache_size_mb * 1024 * 1024) as u64)
        .flush_every_ms(config.flush_interval_ms)
        .open()
        .map_err(|e| Error::DatabaseError(format!(
            "failed to open DB for migration: {}", e
        )))?;

    let blocks = BlockDb::new(&db)?;
    let metadata = db.open_tree(METADATA_TREE_NAME)
        .map_err(|e| Error::DatabaseError(format!(
            "failed to open metadata tree: {}", e
        )))?;

    // Step 1: idempotency check — already stamped?
    let stored = metadata.get(SCHEMA_VERSION_KEY)
        .map_err(|e| Error::DatabaseError(format!(
            "failed to read schema_version: {}", e
        )))?;
    match stored {
        None => { /* legacy DB — proceed with migration */ }
        Some(bytes) if bytes.len() == 4 => {
            let mut buf = [0u8; 4];
            buf.copy_from_slice(&bytes);
            let v = u32::from_le_bytes(buf);
            if v == EXPECTED_DB_SCHEMA_VERSION {
                tracing::info!(
                    "DB already stamped at schema_version = {}. Nothing to do.",
                    v,
                );
                return Ok(MigrationOutcome::AlreadyStamped);
            }
            return Err(Error::DatabaseError(format!(
                "DB stamped at schema_version = {} but legacy migration only \
                 handles v0 → v1. Use the registered migration table (or wipe \
                 and resync) for non-v0 sources.",
                v,
            )));
        }
        Some(bytes) => {
            return Err(Error::DatabaseError(format!(
                "schema_version key has wrong length: expected 4 bytes (u32 LE), \
                 got {} bytes. DB appears corrupted; do not attempt migration.",
                bytes.len(),
            )));
        }
    }

    // Step 2: must not be empty — a fresh DB should go through normal open.
    if blocks.is_empty() {
        return Err(Error::DatabaseError(
            "Database is empty (no block at height 0). This helper migrates \
             EXISTING pre-v1 chaindata. For a fresh install, use normal \
             startup (`coincync-node`) which auto-stamps new DBs.".into()
        ));
    }

    // Step 3: validate genesis hash matches the network's expected hash.
    // This is the SAFETY GATE — without it we could silently stamp a DB
    // belonging to mainnet with a testnet binary (or any other chain
    // mismatch). The hash of block-0 is the canonical chain identifier.
    let actual_genesis = blocks.get_hash_by_height(0)
        .map_err(|e| Error::DatabaseError(format!(
            "failed to read block-0 hash: {}", e
        )))?
        .ok_or_else(|| Error::DatabaseError(
            "block height index has no entry at height 0 — DB corruption, \
             refusing to migrate".into()
        ))?;

    if &actual_genesis != expected_genesis {
        return Err(Error::DatabaseError(format!(
            "Genesis hash mismatch — refusing to migrate.\n  \
             DB genesis:       {}\n  \
             Expected genesis: {}\n  \
             This DB belongs to a different network or chain. Make sure \
             you're running `migrate-legacy-db` with the same --network \
             flag used to create the DB.",
            actual_genesis, expected_genesis,
        )));
    }

    // Step 4: stamp.
    let version_bytes = EXPECTED_DB_SCHEMA_VERSION.to_le_bytes();
    metadata.insert(SCHEMA_VERSION_KEY, &version_bytes)
        .map_err(|e| Error::DatabaseError(format!(
            "failed to write schema_version stamp: {}", e
        )))?;

    // Flush to disk before reporting success. If the binary crashes
    // between insert() and a subsequent flush, the stamp would be lost
    // and the operator would have to re-run migration. Force a flush
    // so the operation is durable once we return Ok.
    db.flush()
        .map_err(|e| Error::DatabaseError(format!(
            "failed to flush schema_version stamp to disk: {}", e
        )))?;

    tracing::info!(
        "Legacy DB migrated: schema_version stamped as {} (genesis verified: {})",
        EXPECTED_DB_SCHEMA_VERSION,
        actual_genesis,
    );
    Ok(MigrationOutcome::Stamped { genesis_hash: actual_genesis })
}

/// Current DB schema version. Bump on ANY incompatible on-disk
/// layout change to a persisted struct or tree.
///
/// History:
///   v1: initial mainnet-candidate (Oct 2026). Establishes the
///       versioning invariant — every subsequent layout change MUST
///       bump this AND ship a registered migration from v1 → vN.
pub const EXPECTED_DB_SCHEMA_VERSION: u32 = 1;

/// Reserved metadata tree name. Underscored name avoids accidental
/// collision with consensus-layer tree names (which are unprefixed,
/// e.g. `blocks`, `utxos`).
const METADATA_TREE_NAME: &str = "__db_metadata__";

/// Reserved key in the metadata tree where the schema version u32 lives.
const SCHEMA_VERSION_KEY: &[u8] = b"schema/db_version";

impl Database {
    /// Open or create database at path with auto-detected optimal config
    pub fn open<P: AsRef<Path>>(path: P) -> Result<Self> {
        Self::open_with_config(path, DbConfig::auto())
    }

    /// Open with default config
    pub fn open_default<P: AsRef<Path>>(path: P) -> Result<Self> {
        Self::open_with_config(path, DbConfig::default())
    }

    /// Open with custom config
    pub fn open_with_config<P: AsRef<Path>>(path: P, config: DbConfig) -> Result<Self> {
        tracing::info!(
            "Opening database with config: cache={}MB, mode={:?}, compression={}",
            config.cache_size_mb,
            config.mode,
            config.use_compression
        );

        // RocksDB-backed shim. DbConfig fields are preserved for API
        // parity but most are now no-ops (rocksdb tunes itself).
        let db = shim::Config::new()
            .path(path)
            .cache_capacity((config.cache_size_mb * 1024 * 1024) as u64)
            .flush_every_ms(config.flush_interval_ms)
            .open()
            .map_err(|e| Error::DatabaseError(e.to_string()))?;

        let blocks = BlockDb::new(&db)?;
        let utxos = UtxoDb::new(&db)?;
        let state = StateDb::new(&db)?;
        let keys = KeyDb::new(&db)?;
        let mempool = MempoolDb::new(&db)?;
        let output_index = OutputIndexDb::new(&db)?;
        let filters = FilterDb::new(&db)?;
        let tx_index = db.open_tree("tx_index")
            .map_err(|e| Error::DatabaseError(e.to_string()))?;
        let metadata = db.open_tree(METADATA_TREE_NAME)
            .map_err(|e| Error::DatabaseError(e.to_string()))?;

        // Schema-version check runs AFTER every tree is opened. We need
        // the BlockDb to detect "fresh DB" (no blocks → fresh) and we
        // need the metadata tree to read the stored version.
        //
        // If this returns Err, we explicitly do NOT proceed — refusing
        // to start is the SAFE behavior. A node that silently mutates
        // a misversioned DB is the failure mode that produces "the
        // testnet DB got bricked by the v1.1 upgrade" stories.
        verify_or_stamp_schema_version(&metadata, &blocks)?;

        tracing::info!("Database opened successfully");

        Ok(Database {
            db,
            blocks,
            utxos,
            state,
            keys,
            mempool,
            output_index,
            filters,
            tx_index,
            metadata,
        })
    }

    /// Read the current DB schema version. Returns the version stamp
    /// stored in the metadata tree (will equal `EXPECTED_DB_SCHEMA_VERSION`
    /// for any DB that successfully opened via `open_with_config`, since
    /// open-time validation rejects mismatched versions).
    ///
    /// Exposed for RPC + diagnostic tooling — `get_info` can include this
    /// so operators can verify all fleet nodes agree on the DB layout
    /// they're running. Differential schema versions across a fleet are
    /// invisible without an explicit accessor like this.
    pub fn schema_version(&self) -> Result<u32> {
        match self.metadata.get(SCHEMA_VERSION_KEY)
            .map_err(|e| Error::DatabaseError(e.to_string()))?
        {
            Some(bytes) if bytes.len() == 4 => {
                let mut buf = [0u8; 4];
                buf.copy_from_slice(&bytes);
                Ok(u32::from_le_bytes(buf))
            }
            Some(bytes) => Err(Error::DatabaseError(format!(
                "schema_version key has wrong length: expected 4 bytes, got {}",
                bytes.len(),
            ))),
            None => Err(Error::DatabaseError(
                "schema_version key missing from metadata tree (should be impossible \
                 after successful Database::open — file a bug)".into()
            )),
        }
    }

    /// Open a temporary database (for testing)
    #[cfg(test)]
    pub fn open_temp() -> Result<Self> {
        let dir = tempfile::tempdir()
            .map_err(|e: std::io::Error| Error::DatabaseError(e.to_string()))?;
        Self::open(dir.keep())
    }

    /// Index a transaction hash to its block height and position.
    pub fn index_tx(&self, tx_hash: &[u8], height: u64, tx_idx: u32) -> Result<()> {
        let mut value = [0u8; 12];
        value[..8].copy_from_slice(&height.to_le_bytes());
        value[8..].copy_from_slice(&tx_idx.to_le_bytes());
        self.tx_index.insert(tx_hash, &value)
            .map_err(|e| Error::DatabaseError(e.to_string()))?;
        Ok(())
    }

    /// Look up a transaction's block height and index within that block.
    pub fn get_tx_location(&self, tx_hash: &[u8]) -> Option<(u64, u32)> {
        match self.tx_index.get(tx_hash) {
            Ok(Some(data)) if data.len() >= 12 => {
                let height = u64::from_le_bytes(data[..8].try_into().unwrap());
                let tx_idx = u32::from_le_bytes(data[8..12].try_into().unwrap());
                Some((height, tx_idx))
            }
            _ => None,
        }
    }

    /// Remove a transaction from the index (used during reorgs).
    pub fn remove_tx_index(&self, tx_hash: &[u8]) {
        let _ = self.tx_index.remove(tx_hash);
    }

    /// Check if the tx_index tree is empty (for migration).
    pub fn tx_index_is_empty(&self) -> bool {
        self.tx_index.is_empty()
    }

    // ── Atomic reorg state transition ──────────────────────────────────────
    //
    // SECURITY: During a chain reorg, the output_index, height_index, state,
    // and tx_index trees must all transition atomically. A crash between
    // individual writes leaves the DB in a state where height mappings exist
    // but output_index entries don't (or vice versa), causing ring member
    // validation failures and wallet scan errors after restart.
    //
    // Sled's `Transactional` trait supports atomic multi-tree transactions.
    // We collect all mutations into a single `trees.transaction(|..| { })` call.

    /// Atomically apply a reorg's persistent state transition.
    ///
    /// All output_index removals, output_index additions, height→hash updates,
    /// height removals, state update, and tx_index changes land together or
    /// not at all. Called from `chain.rs` after in-memory UTXO set is already
    /// updated and all fork blocks are validated.
    ///
    /// # LOCKING CONTRACT (caller MUST satisfy)
    ///
    /// The caller MUST hold `Blockchain.inner.write()` for the entire window
    /// from gathering the reorg diff through to the return of this function.
    /// The implementation does a pre-transaction "already present" read
    /// against committed state (line ~349) to implement oldest-wins on
    /// output_index — that read is only race-free under the chain write
    /// lock, because sled's shim TxTree reads pass through to committed
    /// state (not the pending batch). Without the caller's write lock, a
    /// concurrent apply_block could insert into output_index between the
    /// pre-read and the transaction commit, and the oldest-wins decision
    /// would silently flip.
    ///
    /// # AUDIT (R-34 fix, 2026-07-03)
    ///
    /// Structural fix landed 2026-07-03: the caller at
    /// chain.rs::attempt_reorg re-acquires `self.inner.write()` via
    /// `let _reorg_commit_guard = self.inner.write();` at
    /// chain.rs L~2514 immediately before invoking this function.
    /// The guard is bound to the enclosing scope, which extends past
    /// the return of apply_reorg_atomic, so the pre-transaction
    /// "already present" read at L~411 below is protected against
    /// concurrent apply_block writers.
    ///
    /// The contract is now enforced in TWO layers:
    ///   1. The caller holds the write lock (verified 2026-07-03).
    ///   2. This docstring documents the contract for any future
    ///      caller that might be added.
    ///
    /// Fully structural enforcement (a phantom `WriteGuard` witness
    /// type required by the fn signature) is still a follow-up
    /// worth doing, but the immediate correctness gap is closed.
    pub fn apply_reorg_atomic(
        &self,
        // Output index entries to remove (disconnected blocks' output stealth keys)
        output_removals: &[[u8; 32]],
        // Output index entries to add (fork blocks' outputs): (stealth, serialized_entry)
        output_additions: &[([u8; 32], Vec<u8>)],
        // Height→hash mappings to set (fork blocks + new tip)
        height_sets: &[(u64, [u8; 32])],
        // Heights to remove (stale main-chain heights above new tip)
        height_removals: &[u64],
        // New chain state (serialized)
        new_state: &[u8],
        // Tx index additions: (tx_hash, height, tx_idx)
        tx_index_adds: &[([u8; 32], u64, u32)],
        // Tx index removals: tx_hash bytes
        tx_index_removes: &[[u8; 32]],
    ) -> Result<()> {
        use shim::transaction::Transactional;

        // Pre-compute oldest-wins additions: the transaction closure must
        // be purely writes (shim TxTree reads pass through to committed
        // state, not the pending batch), so do the "already present" check
        // up-front against the committed DB.
        let mut oi_to_insert: Vec<(&[u8; 32], &Vec<u8>)> = Vec::new();
        for (stealth, entry_bytes) in output_additions {
            if self.output_index.tree.get(stealth.as_slice())
                .map_err(|e| Error::DatabaseError(e.to_string()))?
                .is_none()
            {
                oi_to_insert.push((stealth, entry_bytes));
            }
        }

        let trees: &[&shim::Tree] = &[
            &self.output_index.tree,
            &self.blocks.height_index,
            &self.state.state,
            &self.tx_index,
        ];

        trees.transaction(|tx_trees| {
            let oi_tree = &tx_trees[0];
            let hi_tree = &tx_trees[1];
            let st_tree = &tx_trees[2];
            let ti_tree = &tx_trees[3];

            // 1. Remove disconnected outputs from output_index
            for stealth in output_removals {
                oi_tree.remove(stealth.as_slice())?;
            }

            // 2. Add fork-block outputs (filtered for oldest-wins above)
            for (stealth, entry_bytes) in &oi_to_insert {
                oi_tree.insert(stealth.as_slice(), entry_bytes.as_slice())?;
            }

            // 3. Set height→hash for fork blocks + new tip
            for (height, hash) in height_sets {
                hi_tree.insert(&height.to_be_bytes(), hash.as_slice())?;
            }

            // 4. Remove stale heights above new tip
            for height in height_removals {
                hi_tree.remove(&height.to_be_bytes())?;
            }

            // 5. Update chain state
            st_tree.insert(b"chain_state", new_state)?;

            // 6. Update tx index
            for hash in tx_index_removes {
                ti_tree.remove(hash.as_slice())?;
            }
            for (hash, height, tx_idx) in tx_index_adds {
                let mut value = [0u8; 12];
                value[..8].copy_from_slice(&height.to_le_bytes());
                value[8..].copy_from_slice(&tx_idx.to_le_bytes());
                ti_tree.insert(hash.as_slice(), &value)?;
            }

            Ok(())
        }).map_err(|e: shim::transaction::TransactionError| {
            Error::DatabaseError(format!("Atomic reorg transaction failed: {:?}", e))
        })?;

        // Sync to disk after atomic transaction completes
        self.flush()?;

        Ok(())
    }

    /// Flush all pending writes to disk
    pub fn flush(&self) -> Result<()> {
        self.db.flush()
            .map_err(|e| Error::DatabaseError(e.to_string()))?;
        Ok(())
    }

    /// Best-effort flush — calls sync flush and logs any error.
    /// For critical writes, use `flush()` which returns a Result.
    pub fn flush_best_effort(&self) {
        if let Err(e) = self.db.flush() {
            tracing::error!("Database flush failed: {}. Data may be lost on crash.", e);
        }
    }

    /// Get database size in bytes
    pub fn size_on_disk(&self) -> u64 {
        self.db.size_on_disk().unwrap_or(0)
    }

    /// Open (or lazily create) a column family by name. Used by
    /// standalone stores — e.g. the Phase 2 Spark/shielded/MW-kernel
    /// stores — that want their own trees without living inside the
    /// main `Database` struct.
    pub fn open_tree(&self, name: &str) -> Result<shim::Tree> {
        self.db
            .open_tree(name)
            .map_err(|e| Error::DatabaseError(e.to_string()))
    }

    /// Get human-readable database size
    pub fn size_on_disk_formatted(&self) -> String {
        let bytes = self.size_on_disk();
        if bytes < 1024 {
            format!("{} B", bytes)
        } else if bytes < 1024 * 1024 {
            format!("{:.1} KB", bytes as f64 / 1024.0)
        } else if bytes < 1024 * 1024 * 1024 {
            format!("{:.1} MB", bytes as f64 / (1024.0 * 1024.0))
        } else {
            format!("{:.2} GB", bytes as f64 / (1024.0 * 1024.0 * 1024.0))
        }
    }

    /// Get database statistics for monitoring.
    /// Returns (total_entries_across_trees, disk_size_bytes).
    pub fn cache_stats(&self) -> (u64, u64) {
        let entries = self.db.tree_names().iter().filter_map(|name| {
            let name_str = std::str::from_utf8(name).ok()?;
            self.db.open_tree(name_str).ok().map(|t| t.len() as u64)
        }).sum::<u64>();
        (entries, self.size_on_disk())
    }

    /// Generate a monotonically increasing ID
    pub fn generate_id(&self) -> Result<u64> {
        self.db.generate_id()
            .map_err(|e| Error::DatabaseError(e.to_string()))
    }

    /// Check if database was recovered from crash
    pub fn was_recovered(&self) -> bool {
        self.db.was_recovered()
    }

    /// Export database statistics.
    ///
    /// AUDIT (R-35 fix, 2026-07-03): the pre-fix inline comment said
    /// "blocks, utxos, state, keys, wallet, mempool, assets,
    /// output_index" — a list that did NOT match the current
    /// `Database` struct fields. `wallet` and `assets` are not
    /// separate Database fields (never were, once asset support was
    /// stripped in commit 46f0437). The correct enumeration matches
    /// the `Database` field list at ~L244: blocks, utxos, state,
    /// keys, mempool, output_index, filters, tx_index. Also note:
    /// several of these sub-DBs internally open MULTIPLE kv-trees
    /// (e.g. UtxoDb opens ~3, BlockDb opens 2), so `tree_count` here
    /// is the NOMINAL count of top-level Database fields, not the
    /// physical number of column families / trees the RocksDB shim
    /// has open. If a metric consumer cares about the physical
    /// count, they should call `self.db.tree_names().len()` instead.
    pub fn stats(&self) -> DbStats {
        DbStats {
            size_bytes: self.size_on_disk(),
            was_recovered: self.was_recovered(),
            // 8 top-level Database fields: blocks, utxos, state, keys,
            // mempool, output_index, filters, tx_index.
            tree_count: 8,
        }
    }
}

/// Database statistics
#[derive(Clone, Debug)]
pub struct DbStats {
    pub size_bytes: u64,
    pub was_recovered: bool,
    pub tree_count: usize,
}

/// Helper to serialize data for storage
pub fn serialize<T: borsh::BorshSerialize>(value: &T) -> Result<Vec<u8>> {
    borsh::to_vec(value)
        .map_err(|e| Error::SerializationError(e.to_string()))
}

/// Helper to deserialize data from storage
pub fn deserialize<T: borsh::BorshDeserialize>(bytes: &[u8]) -> Result<T> {
    borsh::from_slice(bytes)
        .map_err(|e| Error::SerializationError(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn test_database_open() {
        let dir = tempdir().unwrap();
        let db = Database::open(dir.path()).unwrap();
        // Database opened successfully - size might be 0 on fresh empty DB
        // Just verify it doesn't error
        let _ = db.size_on_disk();
        assert!(db.flush().is_ok());
    }

    #[test]
    fn test_database_config() {
        let dir = tempdir().unwrap();
        let db1 = Database::open(dir.path()).unwrap();
        db1.flush().unwrap();
        drop(db1);
        // Re-open same path should work (not corrupt)
        let db2 = Database::open(dir.path()).unwrap();
        assert!(db2.flush().is_ok());
    }

    // ─── Schema versioning ───────────────────────────────────────

    /// Fresh DB → first open stamps EXPECTED_DB_SCHEMA_VERSION.
    /// Pins the "fresh DB short-circuit" path in
    /// `verify_or_stamp_schema_version`.
    #[test]
    fn schema_version_stamped_on_fresh_db() {
        let dir = tempdir().unwrap();
        let db = Database::open(dir.path()).unwrap();
        let stamped = db.schema_version().expect("schema_version readable");
        assert_eq!(stamped, EXPECTED_DB_SCHEMA_VERSION);
    }

    /// Reopening the same DB does not re-stamp, does not error, and
    /// reports the same version. This is the steady-state path —
    /// 99%+ of opens take this branch.
    #[test]
    fn schema_version_preserved_across_reopen() {
        let dir = tempdir().unwrap();
        {
            let db = Database::open(dir.path()).unwrap();
            db.flush().unwrap();
        }
        // Reopen — must not error, must report same version.
        let db = Database::open(dir.path()).unwrap();
        assert_eq!(db.schema_version().unwrap(), EXPECTED_DB_SCHEMA_VERSION);
    }

    /// DB stamped with a FUTURE version (e.g., the operator downgraded
    /// from a v1.1 binary back to v1.0) refuses to open.
    /// This is the "downgrade safety" invariant — silently mutating a
    /// future-format DB with old code would corrupt data.
    #[test]
    fn schema_version_future_version_rejected() {
        let dir = tempdir().unwrap();
        // Open + corrupt schema_version to a future value
        {
            let db = Database::open(dir.path()).unwrap();
            let future_version: u32 = EXPECTED_DB_SCHEMA_VERSION + 1;
            db.metadata
                .insert(SCHEMA_VERSION_KEY, &future_version.to_le_bytes())
                .unwrap();
            db.flush().unwrap();
        }
        // Reopen MUST fail.
        let result = Database::open(dir.path());
        assert!(result.is_err(), "future-version DB must refuse to open");
        let msg = match result { Ok(_) => panic!("expected error, got Ok"), Err(e) => e.to_string() };
        assert!(
            msg.contains("created by a newer binary") || msg.contains("future"),
            "error message should explain the downgrade scenario; got: {}", msg,
        );
    }

    /// DB stamped with an OLDER version (e.g., the operator upgraded
    /// from v1.0 to a hypothetical v1.1) requires a registered migration.
    /// Today the migration table is empty so this errors with a
    /// migration-required message. When v1.1 ships with a v1→v2 migration
    /// registered, that test will need updating.
    #[test]
    fn schema_version_older_version_requires_migration() {
        // Skip if there's no "older" version (EXPECTED is at v1, lowest).
        // When EXPECTED bumps to 2 in a future PR, this test starts
        // running and asserts the migration-required error path.
        if EXPECTED_DB_SCHEMA_VERSION <= 1 {
            return;
        }
        let dir = tempdir().unwrap();
        {
            let db = Database::open(dir.path()).unwrap();
            let older_version: u32 = EXPECTED_DB_SCHEMA_VERSION - 1;
            db.metadata
                .insert(SCHEMA_VERSION_KEY, &older_version.to_le_bytes())
                .unwrap();
            db.flush().unwrap();
        }
        let result = Database::open(dir.path());
        assert!(result.is_err(), "older-version DB without migration must refuse to open");
        let msg = match result { Ok(_) => panic!("expected error, got Ok"), Err(e) => e.to_string() };
        assert!(
            msg.contains("No migration is registered"),
            "error should request a migration; got: {}", msg,
        );
    }

    /// DB with wrong-length schema_version value (corruption or future
    /// format) refuses to open. Defends against the case where v2
    /// switches to u64 — a v1 binary reading a v2 DB sees 8 bytes
    /// where it expects 4, and we want a clear error instead of
    /// reading a truncated value.
    #[test]
    fn schema_version_wrong_length_rejected() {
        let dir = tempdir().unwrap();
        {
            let db = Database::open(dir.path()).unwrap();
            // Write 8 bytes where 4 are expected
            db.metadata
                .insert(SCHEMA_VERSION_KEY, &[1u8, 0, 0, 0, 0, 0, 0, 0])
                .unwrap();
            db.flush().unwrap();
        }
        let result = Database::open(dir.path());
        assert!(result.is_err(), "wrong-length schema_version must refuse to open");
        let msg = match result { Ok(_) => panic!("expected error, got Ok"), Err(e) => e.to_string() };
        assert!(
            msg.contains("wrong length") || msg.contains("4 bytes"),
            "error should describe the length mismatch; got: {}", msg,
        );
    }

    /// Legacy v0 DB (existing blocks but no schema_version stamp)
    /// refuses to open. This is the critical defense against silently
    /// opening a pre-versioning DB with v1.0 code and mutating it as
    /// if it were already v1-stamped.
    ///
    /// Note: hard to simulate cleanly without an actual block-insertion
    /// path (which requires more setup than this test wants). Instead,
    /// we simulate by opening a fresh DB, stamping it, then DELETING
    /// the stamp + writing some data to blocks tree to simulate the
    /// "non-empty DB without stamp" shape.
    #[test]
    fn schema_version_legacy_unstamped_db_rejected() {
        let dir = tempdir().unwrap();
        {
            let db = Database::open(dir.path()).unwrap();
            // Simulate legacy state: data exists in blocks tree, but
            // no schema_version stamp. Insert a sentinel key into the
            // blocks tree (bypassing the typed API — we don't care if
            // the value is a real block, only that the tree isn't empty).
            db.blocks.height_index.insert(b"\x00\x00\x00\x00\x00\x00\x00\x00", b"sentinel")
                .unwrap();
            // Wait — height_index isn't the tree we check. Open the
            // actual blocks tree and stuff a key into it.
            let blocks_tree = db.db.open_tree("blocks").unwrap();
            blocks_tree.insert(b"sentinel_key", b"sentinel_value").unwrap();
            // Now remove the schema_version stamp.
            db.metadata.remove(SCHEMA_VERSION_KEY).unwrap();
            db.flush().unwrap();
        }
        let result = Database::open(dir.path());
        assert!(result.is_err(), "legacy unstamped DB must refuse to open");
        let msg = match result { Ok(_) => panic!("expected error, got Ok"), Err(e) => e.to_string() };
        assert!(
            msg.contains("Legacy database") || msg.contains("schema_version stamp"),
            "error should identify the legacy DB scenario; got: {}", msg,
        );
    }

    // ─── Legacy DB migration (migrate_legacy_db_to_v1) ───────────

    /// Test helper: build a synthetic "legacy v0" DB at `path` with
    /// a single block at height 0 whose hash is `genesis`. Matches the
    /// shape v1.0.11.x binaries produced (non-empty blocks tree, valid
    /// height_index entry at 0, no schema_version stamp). After this
    /// runs, `migrate_legacy_db_to_v1(path, …, &genesis)` should succeed.
    fn build_synthetic_legacy_db(path: &std::path::Path, genesis: Hash) {
        let db = Database::open(path).unwrap();
        // Make blocks tree non-empty so is_empty() returns false.
        let blocks_tree = db.db.open_tree("blocks").unwrap();
        blocks_tree.insert(genesis.as_bytes(), b"sentinel_block_body").unwrap();
        // Index height 0 → genesis hash so get_hash_by_height(0) works.
        db.blocks.height_index
            .insert(&0u64.to_be_bytes(), genesis.as_bytes())
            .unwrap();
        // Strip the schema_version stamp — this is what makes it "legacy".
        db.metadata.remove(SCHEMA_VERSION_KEY).unwrap();
        db.flush().unwrap();
    }

    /// Happy path: legacy DB with matching genesis hash gets stamped.
    /// After migration, `Database::open` succeeds and reports v1.
    #[test]
    fn migrate_legacy_db_to_v1_stamps_matching_genesis() {
        let dir = tempdir().unwrap();
        let genesis = Hash::from_bytes([0x42; 32]);
        build_synthetic_legacy_db(dir.path(), genesis);

        let outcome = migrate_legacy_db_to_v1(
            dir.path(), DbConfig::default(), &genesis,
        ).expect("migration should succeed on legacy DB with matching genesis");

        match outcome {
            MigrationOutcome::Stamped { genesis_hash } => {
                assert_eq!(genesis_hash, genesis, "outcome should report verified genesis");
            }
            other => panic!("expected Stamped, got {:?}", other),
        }

        // Normal open now works.
        let db = Database::open(dir.path()).expect("post-migration open should succeed");
        assert_eq!(db.schema_version().unwrap(), EXPECTED_DB_SCHEMA_VERSION);
    }

    /// Genesis hash mismatch (operator pointed migration at the wrong
    /// network) must abort without modifying the DB. The error must
    /// name both the actual and expected hashes so the operator can
    /// diagnose immediately.
    #[test]
    fn migrate_legacy_db_to_v1_rejects_wrong_genesis() {
        let dir = tempdir().unwrap();
        let actual = Hash::from_bytes([0x42; 32]);
        let wrong_expected = Hash::from_bytes([0xAB; 32]);
        build_synthetic_legacy_db(dir.path(), actual);

        let result = migrate_legacy_db_to_v1(
            dir.path(), DbConfig::default(), &wrong_expected,
        );

        let err = result.expect_err("must reject wrong-genesis migration");
        let msg = err.to_string();
        assert!(
            msg.contains("Genesis hash mismatch") || msg.contains("different network"),
            "error should name the mismatch; got: {}", msg,
        );

        // Critical: confirm the DB was NOT stamped despite the error.
        // (Otherwise operators retrying with the correct network would
        // silently get an "AlreadyStamped" no-op on a never-validated DB.)
        let db_path_again = dir.path();
        let db_check = shim::Config::new().path(db_path_again).open().unwrap();
        let meta = db_check.open_tree(METADATA_TREE_NAME).unwrap();
        assert!(meta.get(SCHEMA_VERSION_KEY).unwrap().is_none(),
            "stamp must not be written on a failed migration");
    }

    /// Empty DB (no blocks) — operator pointed migration at a freshly-
    /// created DB by mistake. Migration must refuse rather than stamp;
    /// the operator should be using normal startup instead.
    #[test]
    fn migrate_legacy_db_to_v1_rejects_empty_db() {
        let dir = tempdir().unwrap();
        // Fresh DB: opening it stamps it. To simulate "operator points
        // migration at an empty-but-existing dir" we strip the stamp
        // back off so the entry condition is met (no stamp), but leave
        // the blocks tree empty.
        {
            let db = Database::open(dir.path()).unwrap();
            db.metadata.remove(SCHEMA_VERSION_KEY).unwrap();
            db.flush().unwrap();
        }

        let result = migrate_legacy_db_to_v1(
            dir.path(), DbConfig::default(), &Hash::from_bytes([0xAA; 32]),
        );
        let err = result.expect_err("must reject empty-DB migration");
        let msg = err.to_string();
        assert!(
            msg.contains("empty") || msg.contains("EXISTING pre-v1"),
            "error should point at empty-DB scenario; got: {}", msg,
        );
    }

    /// Idempotency: re-running migration on an already-stamped DB is
    /// a no-op (returns AlreadyStamped) and changes nothing. Critical
    /// for operator runbooks that may re-run the migration step under
    /// uncertainty.
    #[test]
    fn migrate_legacy_db_to_v1_is_idempotent_when_already_stamped() {
        let dir = tempdir().unwrap();
        // Open + close to stamp a fresh DB at v1.
        {
            let db = Database::open(dir.path()).unwrap();
            db.flush().unwrap();
        }

        // Migration on the already-stamped DB should be a no-op. The
        // expected-genesis arg doesn't matter for this path — idempotency
        // checks happen before the genesis-hash check.
        let outcome = migrate_legacy_db_to_v1(
            dir.path(), DbConfig::default(), &Hash::from_bytes([0xFF; 32]),
        ).expect("migration should report idempotency");
        assert_eq!(outcome, MigrationOutcome::AlreadyStamped);

        // And the stamp is still correct after the no-op.
        let db = Database::open(dir.path()).unwrap();
        assert_eq!(db.schema_version().unwrap(), EXPECTED_DB_SCHEMA_VERSION);
    }
}
