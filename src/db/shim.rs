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
//! - `Iter` does not implement `DoubleEndedIterator`. Callers that need
//!   reverse iteration call `Tree::iter_rev()` instead of `iter().rev()`.
//! - Multi-tree transactions collapse into a single RocksDB `WriteBatch`
//!   (atomic across CFs). The transaction closure must be a pure write
//!   path; no read-your-writes and no retry on conflict.

use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use rocksdb::{
    BoundColumnFamily, ColumnFamilyDescriptor, DBCompressionType, DBWithThreadMode,
    IteratorMode, MultiThreaded, Options, ReadOptions, WriteBatch as RocksBatch,
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

// ── Db ────────────────────────────────────────────────────────────────

#[derive(Clone)]
pub struct Db {
    inner: Arc<Inner>,
    path: PathBuf,
    counter: Arc<AtomicU64>,
    /// Serializes compare-and-swap / fetch-and-update operations which
    /// RocksDB has no direct equivalent for.
    cas_lock: Arc<Mutex<()>>,
}

const COUNTER_KEY: &[u8] = b"__shim_counter__";

impl Db {
    pub fn open_path(path: &Path) -> Result<Self> {
        let mut opts = Options::default();
        opts.create_if_missing(true);
        opts.create_missing_column_families(true);
        opts.set_compression_type(DBCompressionType::Lz4);
        opts.set_write_buffer_size(64 * 1024 * 1024);
        opts.set_max_write_buffer_number(3);
        opts.increase_parallelism(4);

        // Enumerate existing column families so we can re-open them.
        let existing = Inner::list_cf(&opts, path).unwrap_or_else(|_| vec!["default".to_string()]);
        let cfs: Vec<ColumnFamilyDescriptor> = existing
            .iter()
            .map(|n| ColumnFamilyDescriptor::new(n, Options::default()))
            .collect();

        let inner = Inner::open_cf_descriptors(&opts, path, cfs)?;

        // Restore monotonic counter from default CF.
        let counter = match inner.get(COUNTER_KEY)? {
            Some(b) if b.len() >= 8 => {
                let mut arr = [0u8; 8];
                arr.copy_from_slice(&b[..8]);
                u64::from_le_bytes(arr)
            }
            _ => 0,
        };

        Ok(Db {
            inner: Arc::new(inner),
            path: path.to_path_buf(),
            counter: Arc::new(AtomicU64::new(counter)),
            cas_lock: Arc::new(Mutex::new(())),
        })
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

// ── Tree ──────────────────────────────────────────────────────────────

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
    pub fn insert<K: AsRef<[u8]>, V: AsRef<[u8]>>(
        &self,
        key: K,
        value: V,
    ) -> Result<Option<IVec>> {
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

    pub fn len(&self) -> usize {
        self.iter().count()
    }

    pub fn is_empty(&self) -> bool {
        self.iter().next().is_none()
    }

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
        let _guard = self.db.cas_lock.lock();
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
        let _guard = self.db.cas_lock.lock();
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

// ── Iterator ──────────────────────────────────────────────────────────

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

// ── Transactional (multi-tree write batch) ────────────────────────────

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
    pub struct TxTree<'a> {
        pub(super) tree: &'a Tree,
        pub(super) batch: *mut RocksBatch,
    }

    impl<'a> TxTree<'a> {
        pub fn insert<K: AsRef<[u8]>, V: AsRef<[u8]>>(
            &self,
            key: K,
            value: V,
        ) -> TxResult<Option<IVec>> {
            let cf = self.tree.cf();
            // SAFETY: self.batch is a raw pointer to a WriteBatch that is guaranteed
            // valid for the lifetime of this TransactionalTree. The pointer is created
            // in TransactionalDb::transaction() and dropped after the closure returns.
            // No concurrent access is possible because the transaction closure has
            // exclusive ownership of the batch through &self.
            unsafe {
                (*self.batch).put_cf(&cf, key.as_ref(), value.as_ref());
            }
            Ok(None)
        }

        pub fn remove<K: AsRef<[u8]>>(&self, key: K) -> TxResult<Option<IVec>> {
            let cf = self.tree.cf();
            // SAFETY: Same invariant as insert — batch pointer valid for closure lifetime.
            unsafe {
                (*self.batch).delete_cf(&cf, key.as_ref());
            }
            Ok(None)
        }

        pub fn get<K: AsRef<[u8]>>(&self, key: K) -> TxResult<Option<IVec>> {
            // Reads fall through to the backing DB — writes staged in the
            // batch are NOT visible. No current caller reads inside a
            // transaction, so this is fine for the migration.
            let cf = self.tree.cf();
            Ok(self.tree.db.inner.get_cf(&cf, key.as_ref())?.map(IVec::from))
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

            let mut batch = RocksBatch::default();
            let batch_ptr: *mut RocksBatch = &mut batch;
            let tx_trees: Vec<TxTree<'_>> = self
                .iter()
                .map(|t| TxTree {
                    tree: *t,
                    batch: batch_ptr,
                })
                .collect();
            let result = f(&tx_trees)?;
            drop(tx_trees);

            self[0]
                .db
                .inner
                .write(batch)
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
