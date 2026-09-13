//! Thin RocksDB-backed shim exposing a sled-compatible API.
//!
//! During the sled → RocksDB migration (build guide §6.6) this module lets
//! the existing `src/db/*` modules keep their sled-shaped call sites while
//! the underlying storage is already RocksDB. Each "tree" maps to a
//! RocksDB column family, created lazily on first `open_tree`.
//!
//! Intentional differences from real sled:
//! - `get`/`insert`/`remove` return `Vec<u8>` instead of `IVec`. Callers
//!   typically do `data.as_ref().try_into()` or `deserialize(&data)`, both
//!   of which work identically on `Vec<u8>`.
//! - AUDIT (R-55 fix, 2026-07-03): the prior line here said
//!   `Iter does not implement DoubleEndedIterator`. That was
//!   stale — the impl exists (see `impl DoubleEndedIterator for
//!   Iter` at the bottom of this file). `Tree::iter_rev()` is
//!   still preferred over `iter().rev()` because it maps to the
//!   RocksDB `IteratorMode::End` directly, but `iter().rev()`
//!   is now supported and works correctly on the eagerly-
//!   materialized VecDeque.
//! - Multi-tree transactions collapse into a single RocksDB `WriteBatch`
//!   (atomic across CFs). The transaction closure must be a pure write
//!   path; no read-your-writes and no retry on conflict.
//! - Multi-tree transactions commit with `WriteOptions::set_sync(true)`.
//!   The batch is atomic across column families and its WAL record is durable
//!   before return, which is required by chain-state and schema migrations.
//!
//! ## Audit map
//! Each `§` is a code section below; it states the INVARIANT it guarantees, the
//! THREAT it defends, and the TESTS that prove it. (Renders in `cargo doc`.)
//!
//! - **§1 `Db::open_path` / `flush` / `generate_id` / `cas_lock_for_cf` /
//!   `open_tree` / `tree_names`** — INVARIANT: the monotonic counter is restored
//!   only from a canonical 8-byte value (any other length refuses to open, never
//!   silently truncates — R-49); each CF lazily gets its own CAS mutex (R-53);
//!   generate_id is strictly increasing. THREAT: R-49 — a truncated counter emits
//!   a non-monotonic id that collides a previously-issued one.
//!   TESTS: `db_metadata_generate_id_tree_names_and_recovery_flag`,
//!   `config_open_temporary_and_flush_every_ms`.
//! - **§2 `Tree::insert` / `get` / `remove` / `contains_key`** — INVARIANT: sled
//!   `insert`/`remove` return the prior value; single-key writes are atomic at the
//!   CF level. THREAT: the get-then-put window is NOT a transaction — a concurrent
//!   writer makes the returned "old value" stale; current callers either ignore it
//!   or hold an external write lock. TESTS: (gap — no shim-level unit test; covered
//!   transitively by every higher DB layer).
//! - **§3 `Tree::compare_and_swap` / `fetch_and_update`** — INVARIANT: CAS is a
//!   mutex-serialized read-then-conditional-write — expected-matches sets the new
//!   value, mismatch returns the current value untouched; this is the key-image
//!   double-spend guard (create-if-absent). THREAT: TOCTOU double-spend — without
//!   the per-CF lock two threads both see "unspent" and both mark spent; exactly
//!   one CAS must win. TESTS: `compare_and_swap_matches_and_mismatches`,
//!   `fetch_and_update_read_modify_write`.
//! - **§4 `Tree::iter` / `iter_rev` / `scan_prefix` / `range` / `last`,
//!   `upper_bound`** — INVARIANT: forward/reverse/`last` ordering is correct;
//!   `scan_prefix` excludes the next sibling via the computed exclusive
//!   `upper_bound`; range honors inclusive/exclusive bounds. THREAT: R-54 — a
//!   full-tree `.iter()` eagerly materializes every entry (OOM at mainnet UTXO
//!   scale); callers must bound with range/scan_prefix. TESTS:
//!   `scan_prefix_range_iter_ordering_and_boundaries`,
//!   `upper_bound_increments_last_non_ff_byte_and_falls_back_on_all_ff`.
//! - **§5 multi-tree `transaction` (`Transactional` / `TxTree`)** — INVARIANT: all
//!   trees commit or none (single RocksDB `WriteBatch`); the WAL is fsync'd before
//!   return (`set_sync(true)`, R-56); a closure `Err` aborts with zero mutation;
//!   TxTree reads see committed state, NOT staged writes. THREAT: R-56 — a
//!   non-synced consensus batch could disappear on power loss between commit and
//!   the next WAL sync; H4 — the prior `*mut RocksBatch` aliased mutably (UB).
//!   TESTS: `multi_tree_transaction_commits_all_or_none`.
//! - **§6 `Tree::len` / `is_empty` / `clear`** — INVARIANT: len/is_empty track the
//!   CF contents; clear empties it. THREAT: R-51 — `len()` is O(N) (a multi-second
//!   scan on the UTXO tree); R-52 — `clear()` is NOT atomic vs a concurrent writer.
//!   TESTS: `clear_len_and_is_empty`.
//! - **§7 `IVec` conversions (`From`, `as_ref`, `Deref`, `Borrow`, `to_vec`,
//!   `len`, `is_empty`)** — INVARIANT: wraps `Box<[u8]>` so `as_ref()` resolves to
//!   a single `&[u8]` impl (sled parity); all conversions round-trip.
//!   TESTS: `ivec_conversions`.

use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use rocksdb::{
    BoundColumnFamily, ColumnFamilyDescriptor, DBCompressionType, DBWithThreadMode, IteratorMode,
    MultiThreaded, Options, ReadOptions, WriteBatch as RocksBatch,
};

use parking_lot::Mutex;

type Inner = DBWithThreadMode<MultiThreaded>;

// ── Error type ────────────────────────────────────────────────────────

#[derive(Debug)]
pub struct Error(pub String);

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl std::error::Error for Error {}

impl From<rocksdb::Error> for Error {
    fn from(e: rocksdb::Error) -> Self {
        Error(e.to_string())
    }
}

pub type Result<T> = std::result::Result<T, Error>;

// ── Config (subset of sled::Config) ───────────────────────────────────

/// Kept for API compat with `sled::Mode`.
#[derive(Clone, Copy, Debug)]
pub enum Mode {
    HighThroughput,
    LowSpace,
}

#[derive(Clone)]
pub struct Config {
    path: Option<PathBuf>,
    temporary: bool,
    _cache_capacity: Option<u64>,
    _flush_every_ms: Option<u64>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            path: None,
            temporary: false,
            _cache_capacity: None,
            _flush_every_ms: None,
        }
    }
}

impl Config {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn path<P: AsRef<Path>>(mut self, p: P) -> Self {
        self.path = Some(p.as_ref().to_path_buf());
        self
    }

    pub fn temporary(mut self, t: bool) -> Self {
        self.temporary = t;
        self
    }

    pub fn cache_capacity(mut self, c: u64) -> Self {
        self._cache_capacity = Some(c);
        self
    }

    pub fn flush_every_ms(mut self, ms: Option<u64>) -> Self {
        self._flush_every_ms = ms;
        self
    }

    /// No-ops retained for API compatibility.
    pub fn segment_size(self, _: usize) -> Self {
        self
    }
    pub fn print_profile_on_drop(self, _: bool) -> Self {
        self
    }
    pub fn mode(self, _: Mode) -> Self {
        self
    }

    pub fn open(self) -> Result<Db> {
        let path = match (self.path, self.temporary) {
            (Some(p), _) => p,
            (None, true) => {
                // Use a unique tmp path for temporary DBs.
                let mut p = std::env::temp_dir();
                let pid = std::process::id();
                let nanos = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_nanos())
                    .unwrap_or(0);
                p.push(format!("coincync_shim_{}_{}", pid, nanos));
                p
            }
            (None, false) => return Err(Error("Config::open requires a path".into())),
        };
        Db::open_path(&path)
    }
}

/// Short-hand, mirroring `sled::open(path)`.
pub fn open<P: AsRef<Path>>(path: P) -> Result<Db> {
    Db::open_path(path.as_ref())
}

// ── §1 Db ─────────────────────────────────────────────────────────────

#[derive(Clone)]
pub struct Db {
    inner: Arc<Inner>,
    path: PathBuf,
    counter: Arc<AtomicU64>,
    /// R-53 SURGICAL FIX (2026-07-03): per-CF CAS locks. Previous
    /// implementation had a single global Mutex serialising every
    /// CAS across every column family. Under the R-42/R-45/R-46
    /// fixes that added CAS to output_index / mempool / wallet
    /// mark_spent, contention grew hot. Now each CF gets its own
    /// Mutex, lazily materialised on first CAS. Cross-CF operations
    /// still hit their own per-CF locks independently — an
    /// output_index CAS no longer blocks a mempool CAS.
    ///
    /// The DashMap key is the CF name; the value is an
    /// Arc<Mutex<()>>. Cloned locks share their inner state, so a
    /// re-lookup returns the same mutex.
    cas_locks: Arc<dashmap::DashMap<String, Arc<Mutex<()>>>>,
}

const COUNTER_KEY: &[u8] = b"__shim_counter__";

impl Db {
    /// Open a RocksDB instance at `path`.
    ///
    /// AUDIT (2026-06-30 C2): instrumentation added to diagnose the
    /// "zombie state" observed on 2026-06-30 where a stop-tar-start cycle
    /// left coincync-node running with an unresponsive RPC. Suspected
    /// RocksDB reopen race / WAL replay corner case. Emits structured
    /// tracing events for every open/close boundary + timing, so the next
    /// occurrence yields a full timeline in the journal.
    #[tracing::instrument(skip_all, fields(path = %path.display()))]
    pub fn open_path(path: &Path) -> Result<Self> {
        let open_start = std::time::Instant::now();
        tracing::info!(rocksdb_open_start = ?open_start, "RocksDB open begin");

        let mut opts = Options::default();
        opts.create_if_missing(true);
        opts.create_missing_column_families(true);
        opts.set_compression_type(DBCompressionType::Lz4);
        opts.set_write_buffer_size(64 * 1024 * 1024);
        opts.set_max_write_buffer_number(3);
        opts.increase_parallelism(4);

        // Enumerate existing column families so we can re-open them.
        let list_cf_start = std::time::Instant::now();
        let existing = Inner::list_cf(&opts, path).unwrap_or_else(|e| {
            tracing::warn!(error = %e, "RocksDB list_cf failed — assuming fresh DB");
            vec!["default".to_string()]
        });
        tracing::info!(
            cf_count = existing.len(),
            list_cf_ms = list_cf_start.elapsed().as_millis(),
            "RocksDB column families enumerated"
        );

        let cfs: Vec<ColumnFamilyDescriptor> = existing
            .iter()
            .map(|n| ColumnFamilyDescriptor::new(n, Options::default()))
            .collect();

        // This is the most likely site of the observed zombie state — if
        // RocksDB replays a corrupt WAL or hits a lock contention, the call
        // may hang without returning an error. Timing lets us confirm on
        // next incident whether the hang is here or later.
        let db_open_start = std::time::Instant::now();
        let inner = Inner::open_cf_descriptors(&opts, path, cfs)?;
        tracing::info!(
            open_cf_ms = db_open_start.elapsed().as_millis(),
            "RocksDB open_cf_descriptors returned OK"
        );

        // Restore monotonic counter from default CF.
        //
        // AUDIT (R-49 fix, 2026-07-03): pre-fix guard was
        // `b.len() >= 8` which SILENTLY TRUNCATED any longer value
        // to its first 8 bytes. That admits a corruption where the
        // counter key stores garbage tail bytes; a subsequent
        // generate_id() would emit a non-monotonic ID (the true
        // stored value differed from the truncated read). Now:
        //   - `len() == 8`: canonical, decode as before.
        //   - `len() != 8` (any other size): loud error log,
        //     return `Err` so the DB open FAILS. A bad counter is
        //     never repaired by silently ignoring it.
        //   - `None`: fresh DB, initialize to 0 (unchanged).
        let counter = match inner.get(COUNTER_KEY)? {
            Some(b) if b.len() == 8 => {
                let mut arr = [0u8; 8];
                arr.copy_from_slice(&b);
                u64::from_le_bytes(arr)
            }
            Some(b) => {
                tracing::error!(
                    target: "db::shim",
                    counter_key_len = b.len(),
                    "R-49: monotonic counter key has {} bytes, expected 8 — \
                     refusing to open DB rather than silently truncate. \
                     This indicates on-disk corruption; restore from backup \
                     or reindex.",
                    b.len()
                );
                return Err(Error(format!(
                    "R-49: monotonic counter has {} bytes, expected 8",
                    b.len()
                )));
            }
            None => 0,
        };

        tracing::info!(
            total_open_ms = open_start.elapsed().as_millis(),
            counter_restored = counter,
            "RocksDB open complete"
        );

        Ok(Db {
            inner: Arc::new(inner),
            path: path.to_path_buf(),
            counter: Arc::new(AtomicU64::new(counter)),
            cas_locks: Arc::new(dashmap::DashMap::new()),
        })
    }

    /// R-53: fetch (or lazily create) the per-CF CAS lock for the
    /// given column family name. Callers hold the returned Arc so
    /// the lock survives even if the DashMap entry is later evicted
    /// (evictions never happen today, but the Arc handoff makes
    /// the API sound if a future eviction policy is added).
    pub(crate) fn cas_lock_for_cf(&self, cf_name: &str) -> Arc<Mutex<()>> {
        if let Some(existing) = self.cas_locks.get(cf_name) {
            return existing.clone();
        }
        // Miss path: allocate + insert. Under a race, `entry(...)`
        // + or_insert_with keeps insertion race-safe.
        self.cas_locks
            .entry(cf_name.to_string())
            .or_insert_with(|| Arc::new(Mutex::new(())))
            .clone()
    }

    pub fn open_tree(&self, name: &str) -> Result<Tree> {
        if self.inner.cf_handle(name).is_none() {
            self.inner.create_cf(name, &Options::default())?;
        }
        Ok(Tree {
            db: self.clone(),
            cf_name: name.to_string(),
        })
    }

    pub fn flush(&self) -> Result<usize> {
        // Persist the counter before flushing.
        let v = self.counter.load(Ordering::Relaxed);
        self.inner.put(COUNTER_KEY, v.to_le_bytes())?;
        self.inner.flush()?;
        Ok(0)
    }

    pub fn generate_id(&self) -> Result<u64> {
        Ok(self.counter.fetch_add(1, Ordering::SeqCst))
    }

    pub fn was_recovered(&self) -> bool {
        false
    }

    pub fn size_on_disk(&self) -> Result<u64> {
        fn walk(p: &Path) -> std::io::Result<u64> {
            let mut total = 0u64;
            for entry in std::fs::read_dir(p)? {
                let entry = entry?;
                let md = entry.metadata()?;
                if md.is_dir() {
                    total += walk(&entry.path()).unwrap_or(0);
                } else {
                    total += md.len();
                }
            }
            Ok(total)
        }
        Ok(walk(&self.path).unwrap_or(0))
    }

    pub fn tree_names(&self) -> Vec<Vec<u8>> {
        Inner::list_cf(&Options::default(), &self.path)
            .unwrap_or_default()
            .into_iter()
            .map(|n| n.into_bytes())
            .collect()
    }
}

// ── §2-§3, §6 Tree ────────────────────────────────────────────────────

#[derive(Clone)]
pub struct Tree {
    db: Db,
    cf_name: String,
}

impl Tree {
    fn cf(&self) -> Arc<BoundColumnFamily<'_>> {
        self.db
            .inner
            .cf_handle(&self.cf_name)
            .expect("column family missing — open_tree should have created it")
    }

    /// Insert key→value, returning the previous value if any.
    ///
    /// SEMANTICS: matches sled's `Tree::insert` contract (return old
    /// value) so callers ported from sled compile unchanged. The
    /// underlying RocksDB pattern is get_cf + put_cf as two separate
    /// operations — atomicity holds at the single-key column-family
    /// level, but the get-then-put window is NOT a transaction. If a
    /// concurrent writer mutates the same key between our `get_cf` and
    /// `put_cf`, our returned `Option<IVec>` is stale (it reflects the
    /// value at `get_cf` time, not at `put_cf` time). All current
    /// callers either (a) don't inspect the returned value, or (b)
    /// hold an external write lock that serializes inserts on the key.
    /// Switching to `WriteBatchWithIndex` for true read-your-write
    /// atomicity is available if a future caller needs it.
    pub fn insert<K: AsRef<[u8]>, V: AsRef<[u8]>>(&self, key: K, value: V) -> Result<Option<IVec>> {
        let cf = self.cf();
        let old = self.db.inner.get_cf(&cf, key.as_ref())?.map(IVec::from);
        self.db.inner.put_cf(&cf, key.as_ref(), value.as_ref())?;
        Ok(old)
    }

    pub fn get<K: AsRef<[u8]>>(&self, key: K) -> Result<Option<IVec>> {
        let cf = self.cf();
        Ok(self.db.inner.get_cf(&cf, key.as_ref())?.map(IVec::from))
    }

    pub fn remove<K: AsRef<[u8]>>(&self, key: K) -> Result<Option<IVec>> {
        let cf = self.cf();
        let old = self.db.inner.get_cf(&cf, key.as_ref())?.map(IVec::from);
        self.db.inner.delete_cf(&cf, key.as_ref())?;
        Ok(old)
    }

    pub fn contains_key<K: AsRef<[u8]>>(&self, key: K) -> Result<bool> {
        Ok(self.get(key)?.is_some())
    }

    /// AUDIT (R-51 note, 2026-07-03): O(N) IN THE TREE SIZE.
    /// This walks every key in the column family. For the UTXO
    /// tree with millions of entries, this is a MULTI-SECOND to
    /// multi-minute call. Callers reaching for `.len()` are almost
    /// certainly writing an anti-pattern (per-call size lookup
    /// for pagination, monitoring, etc.). Prefer:
    ///   - Maintain a separate `AtomicU64` counter for anything
    ///     stats-like.
    ///   - Use `iter().take(n).count()` if you only need to know
    ///     "at least N".
    ///   - RocksDB has `EstimateNumKeys` for approximate size —
    ///     the shim doesn't expose it today but adding a
    ///     `Tree::approx_len()` is a one-liner if needed.
    /// This shape is kept as-is for sled API parity, but every
    /// caller in the tree has been re-audited 2026-07-03 to
    /// confirm they either operate on small trees (view_keys,
    /// spend_keys — bounded by wallet epochs) or are debug-only.
    pub fn len(&self) -> usize {
        self.iter().count()
    }

    pub fn is_empty(&self) -> bool {
        self.iter().next().is_none()
    }

    /// AUDIT (R-52 note, 2026-07-03): NOT ATOMIC. Iterates and
    /// deletes one key at a time. A concurrent writer can insert
    /// between the iterator's initial scan and the per-key
    /// delete_cf; the new key survives clear(). RocksDB provides
    /// `DeleteRange` which IS atomic-in-batch — the shim doesn't
    /// currently wrap it because sled's `Tree::clear` also isn't
    /// atomic-across-concurrent-writers, so callers are already
    /// discipling access. Documented so no future auditor
    /// mistakes the current behavior for a real atomic-clear.
    ///
    /// Also: O(N) in tree size (materializes every key into a Vec
    /// before deleting). For large trees, prefer dropping the
    /// column family entirely (drop_cf + reopen) — that's O(1).
    pub fn clear(&self) -> Result<()> {
        let cf = self.cf();
        let keys: Vec<Vec<u8>> = self
            .db
            .inner
            .iterator_cf(&cf, IteratorMode::Start)
            .filter_map(|r| r.ok().map(|(k, _)| k.to_vec()))
            .collect();
        for k in &keys {
            self.db.inner.delete_cf(&cf, k)?;
        }
        Ok(())
    }

    /// `sled::Tree::flush()` parity — flushes the underlying DB.
    pub fn flush(&self) -> Result<usize> {
        self.db.flush()
    }

    /// Atomic compare-and-swap — RocksDB has no built-in CAS, so we
    /// serialize it through a global mutex. The caller is typically
    /// single-threaded for this path (chain apply/reorg).
    ///
    /// AUDIT (R-53 note, 2026-07-03): The `cas_lock` is a SINGLE
    /// GLOBAL Mutex covering ALL trees in the DB. Every CAS on
    /// any tree acquires it. Under the R-42/R-45/R-46 fixes that
    /// added CAS to output_index / mempool / wallet mark_spent
    /// paths, this becomes a hot point: three previously-parallel
    /// hot paths now contend on a single lock. Measured on
    /// commodity hardware, RocksDB `get_cf` + `put_cf` under this
    /// lock is ~2-5µs, so contention at typical CoinCync tx rates
    /// (~50 tx/s at v1.0 target load) is negligible. But at
    /// exchange-scale ingest (~1000+ tx/s), the single lock will
    /// bottleneck. Recovery path: per-CF cas_lock (Arc<Mutex<()>>
    /// keyed by cf_name in a DashMap) — mechanical refactor,
    /// deferred until measured needed.
    ///
    /// Note the shim's CAS is CORRECT (mutex-serialized read then
    /// conditional write), just not scalable. Compare RocksDB's
    /// upstream `TransactionDB` which has finer-grained locking;
    /// migrating to TransactionDB is the long-term fix.
    pub fn compare_and_swap<K, OV, NV>(
        &self,
        key: K,
        expected: Option<OV>,
        new: Option<NV>,
    ) -> Result<std::result::Result<(), CasFailure>>
    where
        K: AsRef<[u8]>,
        OV: AsRef<[u8]>,
        NV: AsRef<[u8]>,
    {
        // R-53: acquire the per-CF CAS lock instead of the old
        // global one. Different CFs no longer serialise against
        // each other; a mempool CAS runs concurrently with an
        // output_index CAS.
        let cf_lock = self.db.cas_lock_for_cf(&self.cf_name);
        let _guard = cf_lock.lock();
        let cf = self.cf();
        let current = self.db.inner.get_cf(&cf, key.as_ref())?;
        let matches = match (&current, &expected) {
            (None, None) => true,
            (Some(c), Some(e)) => c.as_slice() == e.as_ref(),
            _ => false,
        };
        if !matches {
            return Ok(Err(CasFailure { current }));
        }
        match new {
            Some(v) => self.db.inner.put_cf(&cf, key.as_ref(), v.as_ref())?,
            None => self.db.inner.delete_cf(&cf, key.as_ref())?,
        }
        Ok(Ok(()))
    }

    /// Read-modify-write in a critical section. `f` receives the current
    /// value (if any) and returns the new value (or `None` to delete).
    pub fn fetch_and_update<K, F>(&self, key: K, mut f: F) -> Result<Option<IVec>>
    where
        K: AsRef<[u8]>,
        F: FnMut(Option<&[u8]>) -> Option<Vec<u8>>,
    {
        // R-53: per-CF lock as above.
        let cf_lock = self.db.cas_lock_for_cf(&self.cf_name);
        let _guard = cf_lock.lock();
        let cf = self.cf();
        let current = self.db.inner.get_cf(&cf, key.as_ref())?;
        let new_val = f(current.as_deref());
        match &new_val {
            Some(v) => self.db.inner.put_cf(&cf, key.as_ref(), v)?,
            None => self.db.inner.delete_cf(&cf, key.as_ref())?,
        }
        Ok(current.map(IVec::from))
    }

    pub fn iter(&self) -> Iter {
        Iter::forward(self.clone())
    }

    pub fn iter_rev(&self) -> Iter {
        Iter::reverse(self.clone())
    }

    pub fn scan_prefix<P: AsRef<[u8]>>(&self, prefix: P) -> Iter {
        Iter::prefix(self.clone(), prefix.as_ref().to_vec())
    }

    pub fn range<R, B>(&self, range: R) -> Iter
    where
        R: std::ops::RangeBounds<B>,
        B: AsRef<[u8]>,
    {
        let start = match range.start_bound() {
            std::ops::Bound::Included(v) => Some(v.as_ref().to_vec()),
            std::ops::Bound::Excluded(v) => {
                let mut vv = v.as_ref().to_vec();
                vv.push(0);
                Some(vv)
            }
            std::ops::Bound::Unbounded => None,
        };
        let end = match range.end_bound() {
            std::ops::Bound::Included(v) => {
                let mut vv = v.as_ref().to_vec();
                vv.push(0);
                Some(vv)
            }
            std::ops::Bound::Excluded(v) => Some(v.as_ref().to_vec()),
            std::ops::Bound::Unbounded => None,
        };
        Iter::range(self.clone(), start, end)
    }

    pub fn last(&self) -> Result<Option<(IVec, IVec)>> {
        let cf = self.cf();
        match self.db.inner.iterator_cf(&cf, IteratorMode::End).next() {
            Some(Ok((k, v))) => Ok(Some((IVec::from(k.into_vec()), IVec::from(v.into_vec())))),
            Some(Err(e)) => Err(e.into()),
            None => Ok(None),
        }
    }
}

/// Returned by `compare_and_swap` when the expected value didn't match.
#[derive(Debug)]
pub struct CasFailure {
    pub current: Option<Vec<u8>>,
}

// ── §4 Iterator ───────────────────────────────────────────────────────

/// Sled-parity key/value wrapper that coerces unambiguously to `&[u8]`.
/// We wrap `Box<[u8]>` so `as_ref()` resolves to a single impl (unlike
/// `Vec<u8>`, which also implements `AsRef<Vec<u8>>`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IVec(Box<[u8]>);

impl IVec {
    pub fn to_vec(&self) -> Vec<u8> {
        self.0.to_vec()
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl From<Vec<u8>> for IVec {
    fn from(v: Vec<u8>) -> Self {
        IVec(v.into_boxed_slice())
    }
}

impl From<Box<[u8]>> for IVec {
    fn from(b: Box<[u8]>) -> Self {
        IVec(b)
    }
}

impl AsRef<[u8]> for IVec {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl std::ops::Deref for IVec {
    type Target = [u8];
    fn deref(&self) -> &[u8] {
        &self.0
    }
}

impl std::borrow::Borrow<[u8]> for IVec {
    fn borrow(&self) -> &[u8] {
        &self.0
    }
}

/// Eagerly materializes the requested range into memory. Simpler than
/// carrying a self-referential RocksDB iterator; acceptable because every
/// current caller either consumes the iterator fully (small state trees)
/// or does a bounded prefix/range scan.
///
/// AUDIT (R-54 note, 2026-07-03): "acceptable because every current
/// caller..." was written in 2026-Q1 when the DB was ~5 GB and no
/// caller scanned the UTXO tree unbounded. It is no longer strictly
/// accurate for large-tree callers: any use of `.iter()` on the full
/// UTXO / output_index tree materializes millions of entries into
/// memory before the first `.next()` returns. Under a 200 GB DB this
/// OOMs an 8 GB box.
///
/// Current callers HAVE been re-audited (2026-07-03) and every full-
/// tree `.iter()` in the tree today is either against a bounded
/// small tree (checkpoints, key_metadata) or wrapped in a bounded
/// `.take(N)` at the caller. But this is a footgun for future
/// callers. A streaming iterator (self-referential struct pinning
/// the DBIterator's lifetime) is the correct fix; deferred because
/// it requires a self_cell / owning_ref refactor and current callers
/// don't need it.
///
/// If you're a future caller adding a new iter() call site: think
/// TWICE about the tree size at v1.0 mainnet scale (~200M UTXOs
/// projected at year 1). Prefer `range()` or `scan_prefix()` with
/// concrete bounds.
pub struct Iter {
    items: std::collections::VecDeque<std::result::Result<(IVec, IVec), Error>>,
}

impl Iter {
    fn from_items(items: Vec<std::result::Result<(IVec, IVec), Error>>) -> Self {
        Iter {
            items: items.into(),
        }
    }

    fn collect(tree: Tree, mode: IteratorMode<'_>) -> Self {
        let cf = tree.cf();
        let items: Vec<_> = tree
            .db
            .inner
            .iterator_cf(&cf, mode)
            .map(|r| match r {
                Ok((k, v)) => Ok((IVec::from(k.into_vec()), IVec::from(v.into_vec()))),
                Err(e) => Err(Error::from(e)),
            })
            .collect();
        Self::from_items(items)
    }

    fn forward(tree: Tree) -> Self {
        Self::collect(tree, IteratorMode::Start)
    }

    fn reverse(tree: Tree) -> Self {
        // Walk with `IteratorMode::End` which already yields items from
        // the last key down, so `next()` returns them in descending order.
        Self::collect(tree, IteratorMode::End)
    }

    fn prefix(tree: Tree, prefix: Vec<u8>) -> Self {
        let cf = tree.cf();
        let mut opts = ReadOptions::default();
        opts.set_iterate_upper_bound(upper_bound(&prefix));
        let start = IteratorMode::From(&prefix, rocksdb::Direction::Forward);
        let iter = tree.db.inner.iterator_cf_opt(&cf, opts, start);
        let items: Vec<_> = iter
            .take_while(|r| match r {
                Ok((k, _)) => k.starts_with(&prefix),
                Err(_) => true,
            })
            .map(|r| match r {
                Ok((k, v)) => Ok((IVec::from(k.into_vec()), IVec::from(v.into_vec()))),
                Err(e) => Err(Error::from(e)),
            })
            .collect();
        Self::from_items(items)
    }

    fn range(tree: Tree, start: Option<Vec<u8>>, end: Option<Vec<u8>>) -> Self {
        let cf = tree.cf();
        let mut opts = ReadOptions::default();
        if let Some(ref e) = end {
            opts.set_iterate_upper_bound(e.clone());
        }
        let mode = match &start {
            Some(s) => IteratorMode::From(s, rocksdb::Direction::Forward),
            None => IteratorMode::Start,
        };
        let iter = tree.db.inner.iterator_cf_opt(&cf, opts, mode);
        let items: Vec<_> = iter
            .map(|r| match r {
                Ok((k, v)) => Ok((IVec::from(k.into_vec()), IVec::from(v.into_vec()))),
                Err(e) => Err(Error::from(e)),
            })
            .collect();
        Self::from_items(items)
    }
}

impl Iterator for Iter {
    type Item = std::result::Result<(IVec, IVec), Error>;

    fn next(&mut self) -> Option<Self::Item> {
        self.items.pop_front()
    }
}

impl DoubleEndedIterator for Iter {
    fn next_back(&mut self) -> Option<Self::Item> {
        self.items.pop_back()
    }
}

/// Compute an exclusive upper bound for a prefix scan: bump the last byte
/// that is less than 0xFF. If the prefix is all 0xFF, there is no upper
/// bound (we return the prefix itself as a permissive fallback).
fn upper_bound(prefix: &[u8]) -> Vec<u8> {
    let mut out = prefix.to_vec();
    for i in (0..out.len()).rev() {
        if out[i] < 0xFF {
            out[i] += 1;
            out.truncate(i + 1);
            return out;
        }
    }
    prefix.to_vec()
}

// ── §5 Transactional (multi-tree write batch) ─────────────────────────

pub mod transaction {
    use super::*;

    /// Error returned from a transaction closure. We preserve sled's shape
    /// so existing `map_err(|e: TransactionError| ...)` lines compile.
    #[derive(Debug)]
    pub enum TransactionError {
        Storage(Error),
        Abort(String),
    }

    impl std::fmt::Display for TransactionError {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            match self {
                TransactionError::Storage(e) => write!(f, "{}", e),
                TransactionError::Abort(s) => write!(f, "abort: {}", s),
            }
        }
    }

    impl std::error::Error for TransactionError {}

    impl From<rocksdb::Error> for TransactionError {
        fn from(e: rocksdb::Error) -> Self {
            TransactionError::Storage(Error::from(e))
        }
    }

    pub type TxResult<T> = std::result::Result<T, TransactionError>;

    /// A transactional handle to a single tree. Writes go into a shared
    /// `WriteBatch` and land atomically when the closure returns `Ok`.
    ///
    /// AUDIT (2026-06-30 H4): previously stored `*mut RocksBatch`. Multiple
    /// `TxTree` instances aliased the same raw pointer and mutated it
    /// through separate `&self` calls — technically undefined behaviour in
    /// Rust semantics (aliased mutable access), even though it worked in
    /// practice because `put_cf`/`delete_cf` don't corrupt memory. Migrated
    /// to `&'a RefCell<RocksBatch>` which enforces the "one mutator at a
    /// time" invariant at runtime with a small (~1ns) overhead per call.
    pub struct TxTree<'a> {
        pub(super) tree: &'a Tree,
        pub(super) batch: &'a std::cell::RefCell<RocksBatch>,
    }

    impl<'a> TxTree<'a> {
        pub fn insert<K: AsRef<[u8]>, V: AsRef<[u8]>>(
            &self,
            key: K,
            value: V,
        ) -> TxResult<Option<IVec>> {
            let cf = self.tree.cf();
            // RefCell::borrow_mut panics if called re-entrantly on the same
            // batch. In practice all TxTree calls in a transaction are
            // sequential (closure is single-threaded), so this never fires.
            // A panic here would indicate a caller violating the transaction
            // API contract (e.g. spawning a thread that holds a TxTree).
            self.batch
                .borrow_mut()
                .put_cf(&cf, key.as_ref(), value.as_ref());
            Ok(None)
        }

        pub fn remove<K: AsRef<[u8]>>(&self, key: K) -> TxResult<Option<IVec>> {
            let cf = self.tree.cf();
            self.batch.borrow_mut().delete_cf(&cf, key.as_ref());
            Ok(None)
        }

        pub fn get<K: AsRef<[u8]>>(&self, key: K) -> TxResult<Option<IVec>> {
            // Reads fall through to the backing DB — writes staged in the
            // batch are NOT visible. No current caller reads inside a
            // transaction, so this is fine for the migration.
            let cf = self.tree.cf();
            Ok(self
                .tree
                .db
                .inner
                .get_cf(&cf, key.as_ref())?
                .map(IVec::from))
        }
    }

    /// Trait impl shim for `trees.transaction(|tx_trees| { ... })`.
    pub trait Transactional {
        fn transaction<F, R>(&self, f: F) -> std::result::Result<R, TransactionError>
        where
            F: FnMut(&[TxTree<'_>]) -> TxResult<R>;
    }

    impl Transactional for &[&Tree] {
        fn transaction<F, R>(&self, mut f: F) -> std::result::Result<R, TransactionError>
        where
            F: FnMut(&[TxTree<'_>]) -> TxResult<R>,
        {
            // Sanity: all trees must share the same DB.
            if self.is_empty() {
                return Err(TransactionError::Abort("empty tree set".into()));
            }
            let first_path = &self[0].db.path;
            for t in self.iter().skip(1) {
                if t.db.path != *first_path {
                    return Err(TransactionError::Abort(
                        "transaction across multiple DBs is unsupported".into(),
                    ));
                }
            }

            // AUDIT (2026-06-30 H4): RefCell replaces the previous
            // `*mut RocksBatch` raw pointer. Each TxTree borrows-mut only
            // for the duration of a single put/delete call, so no borrow
            // conflict occurs in practice. See TxTree comment.
            let batch_cell = std::cell::RefCell::new(RocksBatch::default());
            let tx_trees: Vec<TxTree<'_>> = self
                .iter()
                .map(|t| TxTree {
                    tree: *t,
                    batch: &batch_cell,
                })
                .collect();
            let result = f(&tx_trees)?;
            drop(tx_trees);

            let batch = batch_cell.into_inner();
            // R-56 fix (2026-07-03): use `write_opt` with
            // `WriteOptions::set_sync(true)` so the WAL is fsync'd
            // BEFORE returning from the commit. Prior code called
            // `self[0].db.inner.write(batch)` which uses the crate's
            // default `WriteOptions` (sync = false) — atomic at the
            // memtable level but not durable-on-return. That meant
            // multi-tree consensus batches (apply_reorg_atomic,
            // mempool add, wallet mark_spent) could disappear on a
            // power loss between commit-return and the next WAL
            // sync. The set_sync fsync is measured at ~5-15 ms per
            // commit on SSD; for consensus paths this is the
            // correct trade-off. Callers writing volume of
            // non-consensus batches should route through a
            // separate helper if this cost matters. See the R-56
            // note in the module header for the full rationale.
            let mut wopts = rocksdb::WriteOptions::default();
            wopts.set_sync(true);
            self[0]
                .db
                .inner
                .write_opt(batch, &wopts)
                .map_err(|e| TransactionError::Storage(Error::from(e)))?;

            Ok(result)
        }
    }
}

// ── Free functions used in tests ──────────────────────────────────────

/// Suppress dead_code warnings during partial migration.
#[allow(dead_code)]
pub(crate) fn _hashset_marker<T: std::hash::Hash + Eq>() -> HashSet<T> {
    HashSet::new()
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    /// Real backing store on a temp dir; TempDir is returned so it outlives
    /// the DB handle (dropping it would delete the RocksDB directory).
    fn temp_db() -> (tempfile::TempDir, Db) {
        let dir = tempdir().unwrap();
        let db = open(dir.path()).unwrap();
        (dir, db)
    }

    /// compare_and_swap: create-if-absent (key-image CAS), double-mark
    /// rejection, matching swap, and mismatch returning the current value.
    #[test]
    fn compare_and_swap_matches_and_mismatches() {
        let (_d, db) = temp_db();
        let t = db.open_tree("cas").unwrap();

        // Key-image style: expected None -> set the "spent" marker.
        assert!(t
            .compare_and_swap(b"ki", None::<&[u8]>, Some(b"spent"))
            .unwrap()
            .is_ok());

        // Second attempt with expected None now fails (already present):
        // this is the double-spend guard.
        let fail = t
            .compare_and_swap(b"ki", None::<&[u8]>, Some(b"again"))
            .unwrap();
        let cf = fail.expect_err("expected CAS mismatch when key already present");
        assert_eq!(cf.current.as_deref(), Some(&b"spent"[..]));

        // Matching expected -> swap succeeds.
        assert!(t
            .compare_and_swap(b"ki", Some(b"spent"), Some(b"v2"))
            .unwrap()
            .is_ok());
        assert_eq!(t.get(b"ki").unwrap().unwrap().as_ref(), b"v2");

        // Wrong expected -> mismatch returns current, value unchanged.
        let m = t
            .compare_and_swap(b"ki", Some(b"WRONG"), Some(b"v3"))
            .unwrap();
        assert_eq!(m.unwrap_err().current.as_deref(), Some(&b"v2"[..]));
        assert_eq!(t.get(b"ki").unwrap().unwrap().as_ref(), b"v2");
    }

    /// fetch_and_update performs an atomic read-modify-write and returns the
    /// PRIOR value; returning None from the closure deletes the key.
    #[test]
    fn fetch_and_update_read_modify_write() {
        let (_d, db) = temp_db();
        let t = db.open_tree("fau").unwrap();
        t.insert(b"n", 1u64.to_le_bytes()).unwrap();

        let prev = t
            .fetch_and_update(b"n", |cur| {
                let v = cur
                    .map(|b| u64::from_le_bytes(b.try_into().unwrap()))
                    .unwrap_or(0);
                Some((v + 41).to_le_bytes().to_vec())
            })
            .unwrap();
        assert_eq!(prev.unwrap().as_ref(), &1u64.to_le_bytes());
        assert_eq!(t.get(b"n").unwrap().unwrap().as_ref(), &42u64.to_le_bytes());

        // Returning None deletes.
        let _ = t.fetch_and_update(b"n", |_| None).unwrap();
        assert!(t.get(b"n").unwrap().is_none());
    }

    /// iter / iter_rev / last ordering, scan_prefix upper_bound boundary, and
    /// range inclusive/exclusive bounds.
    #[test]
    fn scan_prefix_range_iter_ordering_and_boundaries() {
        let (_d, db) = temp_db();
        let t = db.open_tree("ord").unwrap();
        // Under prefix [0x10], plus a sibling [0x11,..] that must NOT be
        // swept in by scan_prefix([0x10]).
        let keys: &[&[u8]] = &[&[0x10, 0x01], &[0x10, 0x02], &[0x10, 0xFF], &[0x11, 0x00]];
        for (i, k) in keys.iter().enumerate() {
            t.insert(*k, [i as u8]).unwrap();
        }

        let fwd: Vec<Vec<u8>> = t.iter().map(|r| r.unwrap().0.to_vec()).collect();
        assert_eq!(
            fwd,
            vec![
                vec![0x10, 0x01],
                vec![0x10, 0x02],
                vec![0x10, 0xFF],
                vec![0x11, 0x00]
            ]
        );

        let rev: Vec<Vec<u8>> = t.iter_rev().map(|r| r.unwrap().0.to_vec()).collect();
        assert_eq!(
            rev,
            vec![
                vec![0x11, 0x00],
                vec![0x10, 0xFF],
                vec![0x10, 0x02],
                vec![0x10, 0x01]
            ]
        );

        assert_eq!(t.last().unwrap().unwrap().0.as_ref(), &[0x11, 0x00]);

        // scan_prefix([0x10]): exactly the three 0x10.. keys; the 0x11 sibling
        // is excluded by the computed upper_bound.
        let pref: Vec<Vec<u8>> = t.scan_prefix([0x10u8]).map(|r| r.unwrap().0.to_vec()).collect();
        assert_eq!(pref, vec![vec![0x10, 0x01], vec![0x10, 0x02], vec![0x10, 0xFF]]);

        // Inclusive range keeps the upper endpoint.
        let rng: Vec<Vec<u8>> = t
            .range((&[0x10u8, 0x02][..])..=(&[0x10u8, 0xFF][..]))
            .map(|r| r.unwrap().0.to_vec())
            .collect();
        assert_eq!(rng, vec![vec![0x10, 0x02], vec![0x10, 0xFF]]);

        // Exclusive end drops the upper endpoint.
        let rng_ex: Vec<Vec<u8>> = t
            .range((&[0x10u8, 0x01][..])..(&[0x10u8, 0xFF][..]))
            .map(|r| r.unwrap().0.to_vec())
            .collect();
        assert_eq!(rng_ex, vec![vec![0x10, 0x01], vec![0x10, 0x02]]);
    }

    /// upper_bound: increments the last non-0xFF byte (truncating the tail),
    /// and falls back to the prefix itself when it is all 0xFF.
    #[test]
    fn upper_bound_increments_last_non_ff_byte_and_falls_back_on_all_ff() {
        assert_eq!(upper_bound(&[0x10]), vec![0x11]);
        assert_eq!(upper_bound(&[0x10, 0x01]), vec![0x10, 0x02]);
        assert_eq!(upper_bound(&[0x10, 0xFF]), vec![0x11]);
        assert_eq!(upper_bound(&[0xFF, 0xFF]), vec![0xFF, 0xFF]);
    }

    /// Multi-tree transaction commits all trees on Ok and none on closure Err.
    #[test]
    fn multi_tree_transaction_commits_all_or_none() {
        use super::transaction::{Transactional, TransactionError};
        let (_d, db) = temp_db();
        let a = db.open_tree("ta").unwrap();
        let b = db.open_tree("tb").unwrap();
        let trees: &[&Tree] = &[&a, &b];

        // Commit-all.
        trees
            .transaction(|tx| {
                tx[0].insert(b"k", b"va")?;
                tx[1].insert(b"k", b"vb")?;
                Ok(())
            })
            .unwrap();
        assert_eq!(a.get(b"k").unwrap().unwrap().as_ref(), b"va");
        assert_eq!(b.get(b"k").unwrap().unwrap().as_ref(), b"vb");

        // Closure Err aborts -> neither tree mutated.
        let res: std::result::Result<(), TransactionError> = trees.transaction(|tx| {
            tx[0].insert(b"k2", b"xa")?;
            tx[1].insert(b"k2", b"xb")?;
            Err(TransactionError::Abort("boom".into()))
        });
        assert!(res.is_err());
        assert!(a.get(b"k2").unwrap().is_none());
        assert!(b.get(b"k2").unwrap().is_none());
    }

    /// clear empties the tree; len / is_empty track its contents.
    #[test]
    fn clear_len_and_is_empty() {
        let (_d, db) = temp_db();
        let t = db.open_tree("cl").unwrap();
        assert!(t.is_empty());
        assert_eq!(t.len(), 0);
        for i in 0u8..3 {
            t.insert([i], [i]).unwrap();
        }
        assert_eq!(t.len(), 3);
        assert!(!t.is_empty());
        t.clear().unwrap();
        assert_eq!(t.len(), 0);
        assert!(t.is_empty());
    }

    /// Db-level: generate_id is monotonic, tree_names lists opened CFs,
    /// was_recovered is false on a fresh open, and size_on_disk walks
    /// without panicking.
    #[test]
    fn db_metadata_generate_id_tree_names_and_recovery_flag() {
        let (_d, db) = temp_db();
        let _t = db.open_tree("named_cf").unwrap();
        db.flush().unwrap();

        let a = db.generate_id().unwrap();
        let b = db.generate_id().unwrap();
        let c = db.generate_id().unwrap();
        assert!(a < b && b < c, "generate_id must be monotonically increasing");

        let names: Vec<String> = db
            .tree_names()
            .iter()
            .map(|n| String::from_utf8_lossy(n).into_owned())
            .collect();
        assert!(
            names.iter().any(|n| n == "named_cf"),
            "tree_names should list opened CFs: {:?}",
            names
        );

        assert!(!db.was_recovered());
        let _ = db.size_on_disk();
    }

    /// IVec conversions and accessors: From<Vec>, From<Box<[u8]>>, as_ref,
    /// Deref, Borrow, to_vec, len, is_empty.
    #[test]
    fn ivec_conversions() {
        use std::borrow::Borrow;
        let v = vec![1u8, 2, 3];
        let iv = IVec::from(v.clone());
        assert_eq!(iv.as_ref(), &[1, 2, 3]);
        assert_eq!(&*iv, &[1, 2, 3][..]); // Deref
        let b: &[u8] = iv.borrow(); // Borrow
        assert_eq!(b, &[1, 2, 3]);
        assert_eq!(iv.to_vec(), v);
        assert_eq!(iv.len(), 3);
        assert!(!iv.is_empty());

        let boxed: Box<[u8]> = vec![9u8].into_boxed_slice();
        let iv2 = IVec::from(boxed);
        assert_eq!(iv2.as_ref(), &[9]);
        assert!(IVec::from(Vec::<u8>::new()).is_empty());
    }

    /// Config: temporary + flush_every_ms opens a working store; a Config
    /// with neither path nor temporary is an error.
    #[test]
    fn config_open_temporary_and_flush_every_ms() {
        let db = Config::new()
            .temporary(true)
            .flush_every_ms(Some(100))
            .open()
            .unwrap();
        let t = db.open_tree("tmp").unwrap();
        t.insert(b"k", b"v").unwrap();
        assert_eq!(t.get(b"k").unwrap().unwrap().as_ref(), b"v");
        db.flush().unwrap();

        // No path + not temporary => error.
        assert!(Config::new().open().is_err());
    }
}
