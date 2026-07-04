//! # Proof of Work — CoinCync 1.0 (RandomX-only)
//!
//! Single algorithm: **RandomX**. No rotation, no Yescrypt.
//!
//! Design:
//! - A per-block `Anchor` is computed from `(prev_hash, height, timestamp)`
//!   via a sequential hash chain (see `compute_sequential_padding`) plus a
//!   blake3 mixing step. This is NOT a VDF — it provides no verifiable
//!   sequential delay property. It binds the PoW to the previous block.
//! - The PoW hash is RandomX over `(anchor || nonce || tx_root)`, with the
//!   RandomX VM key derived from the block height's epoch and the
//!   chain-specific genesis hash.

use crate::primitives::{Hash, hash_concat, hash_domain};
use crate::error::Result;
use crate::constants::SEQ_PAD_ITERATIONS;
use std::collections::VecDeque;
use std::sync::OnceLock;
use parking_lot::Mutex;

// =============================================================================
// Sequential Padding Cache — FIFO eviction via VecDeque
// =============================================================================

/// Maximum cache entries to prevent unbounded memory growth.
const SEQ_PAD_CACHE_MAX: usize = 10_000;

/// FIFO-evicting cache for sequential-padding anchors keyed by
/// `(prev_hash, height, timestamp)`.
///
/// ## Design
///
/// Two-structure design for O(1) on every operation:
///
/// - `anchors`: `HashMap<key, Anchor>` for O(1) lookup
/// - `insertion_order`: `VecDeque<key>` for O(1) FIFO eviction
///
/// On insert: push key onto the back of `insertion_order`, insert
/// into `anchors`. When `anchors.len() >= MAX`, pop_front the
/// oldest key from `insertion_order` and `anchors.remove()` it.
///
/// On get: just hit `anchors` directly. O(1).
///
/// ## Why this changed (2026-06-03)
///
/// The previous design stored `Vec<(key, anchor, seq)>` in a VecDeque
/// and used a parallel HashMap mapping `key → seq`. The lookup path
/// was `index.get(key).and_then(|seq| entries.iter().find(|e| e.seq == seq))`
/// — that `.find()` linearly scans every entry to match the seq number.
/// With the cache at its 10,000-entry cap, each cache lookup was
/// ~10,000 comparisons. This hits the hot path: every PoW verification
/// calls `compute_full_anchor` which checks this cache first.
///
/// Restructuring to two parallel collections keyed by the actual key
/// (not a synthetic seq) makes lookup truly O(1) without changing the
/// semantics or the FIFO eviction order.
struct SeqPadCache {
    anchors: std::collections::HashMap<(Hash, u64, u64), Anchor>,
    insertion_order: VecDeque<(Hash, u64, u64)>,
}

impl SeqPadCache {
    fn new() -> Self {
        SeqPadCache {
            anchors: std::collections::HashMap::with_capacity(SEQ_PAD_CACHE_MAX),
            insertion_order: VecDeque::with_capacity(SEQ_PAD_CACHE_MAX),
        }
    }

    /// O(1) lookup by key.
    fn get(&self, key: &(Hash, u64, u64)) -> Option<&Anchor> {
        self.anchors.get(key)
    }

    /// O(1) amortized insert with FIFO eviction.
    ///
    /// If the key is already present, this is a no-op — preserves the
    /// existing entry's insertion-order position. (A re-insert with
    /// the same key but different value would corrupt the FIFO order,
    /// but anchors are deterministic from the key so the value would
    /// be the same anyway.)
    fn insert(&mut self, key: (Hash, u64, u64), anchor: Anchor) {
        if self.anchors.contains_key(&key) {
            return;
        }
        if self.anchors.len() >= SEQ_PAD_CACHE_MAX {
            if let Some(oldest) = self.insertion_order.pop_front() {
                self.anchors.remove(&oldest);
            }
        }
        self.insertion_order.push_back(key);
        self.anchors.insert(key, anchor);
    }
}

static SEQ_PAD_CACHE: std::sync::LazyLock<Mutex<SeqPadCache>> =
    std::sync::LazyLock::new(|| Mutex::new(SeqPadCache::new()));

/// Genesis bytes used to derive RandomX VM keys per epoch (`randomx_key_for_height`).
/// Set once from each binary via [`bind_randomx_genesis_for_network`] so PoW matches
/// `--network` / `--testnet`. Without this, the code fell back to `COINCYNC_NETWORK`
/// defaulting to **mainnet** genesis while `coincync-node` defaults to testnet — peers
/// then appear to send blocks with "invalid PoW".
#[cfg(feature = "randomx")]
static RANDOMX_GENESIS_BYTES: OnceLock<[u8; 32]> = OnceLock::new();

/// Bind RandomX epoch keys to the genesis hash for the selected network.
/// Call once at process startup from `coincync-node` and `coincync-miner` (before PoW).
pub fn bind_randomx_genesis_for_network(network: crate::config::NetworkType) {
    #[cfg(feature = "randomx")]
    {
        let genesis: [u8; 32] = match network {
            crate::config::NetworkType::Mainnet => crate::mainnet::MAINNET_GENESIS_HASH,
            crate::config::NetworkType::Testnet | crate::config::NetworkType::Regtest => {
                crate::testnet::TESTNET_GENESIS_HASH
            }
        };
        if let Err(attempted) = RANDOMX_GENESIS_BYTES.set(genesis) {
            if let Some(existing) = RANDOMX_GENESIS_BYTES.get() {
                if *existing != attempted {
                    tracing::warn!(
                        "bind_randomx_genesis_for_network: genesis already set (prefix {}...) \
                         — ignoring conflicting request (prefix {}...)",
                        hex::encode(&existing[..4]),
                        hex::encode(&attempted[..4])
                    );
                }
            }
        }
    }
    #[cfg(not(feature = "randomx"))]
    {
        let _ = network;
    }
}

#[cfg(not(feature = "randomx"))]
static RANDOMX_WARNING_SHOWN: std::sync::Once = std::sync::Once::new();

// =============================================================================
// PowAlgorithm — single variant, kept as an enum so match arms across the
// codebase still compile without surgery.
// =============================================================================

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum PowAlgorithm {
    RandomX = 0,
}

impl PowAlgorithm {
    pub fn from_index(_i: u8) -> Self {
        Self::RandomX
    }

    pub fn at_height(_height: u64) -> Self {
        Self::RandomX
    }

    pub fn name(&self) -> &'static str {
        "RandomX"
    }

    pub fn from_str_opt(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "randomx" | "rx" | "0" => Some(Self::RandomX),
            _ => None,
        }
    }

    pub fn is_available(&self) -> bool {
        #[cfg(feature = "randomx")]
        { true }
        #[cfg(not(feature = "randomx"))]
        { false }
    }
}

/// Sequential anchor for PoW.
#[derive(Debug, Clone)]
pub struct Anchor {
    pub sequential_hash: Hash,
    pub mixed_hash: Hash,
    pub algorithm: PowAlgorithm,
    pub height: u64,
    pub timestamp: u64,
}

/// M-7 FIX: Sequential padding — a hash chain that provides no verifiable
/// sequential delay property. This is NOT a VDF. It merely binds the PoW
/// anchor to the previous block via iterated hashing.
fn compute_sequential_padding(seed: &Hash, iterations: u32) -> Hash {
    let mut current = *seed;
    for _ in 0..iterations {
        current = hash_domain(b"SEQ_PAD_ITER", current.as_bytes());
    }
    current
}

/// Blake3-based mix of sequential output with prev_hash.
/// Replaces 2.0's yescrypt_mix — RandomX-only build, no memory-hard mix needed
/// before RandomX itself (which is already memory-hard).
fn blake3_mix(sequential: &Hash, prev_hash: &Hash) -> Hash {
    hash_domain(
        b"CYNC1_ANCHOR_MIX",
        &[sequential.as_bytes().as_slice(), prev_hash.as_bytes().as_slice()].concat(),
    )
}

/// Compute full anchor with metadata.
pub fn compute_full_anchor(prev_hash: &Hash, height: u64, timestamp: u64) -> Result<Anchor> {
    let cache_key = (*prev_hash, height, timestamp);

    {
        let cache = SEQ_PAD_CACHE.lock();
        if let Some(cached) = cache.get(&cache_key) {
            return Ok(cached.clone());
        }
    }

    let seed = hash_concat(&[
        prev_hash.as_bytes(),
        &height.to_le_bytes(),
        &timestamp.to_le_bytes(),
    ]);

    let sequential = compute_sequential_padding(&seed, SEQ_PAD_ITERATIONS);
    let mixed = blake3_mix(&sequential, prev_hash);

    let anchor = Anchor {
        sequential_hash: sequential,
        mixed_hash: mixed,
        algorithm: PowAlgorithm::RandomX,
        height,
        timestamp,
    };

    {
        let mut cache = SEQ_PAD_CACHE.lock();
        cache.insert(cache_key, anchor.clone());
    }

    Ok(anchor)
}

/// Compute PoW hash. Always RandomX.
pub fn compute_pow_hash(
    algo: PowAlgorithm,
    anchor: &Hash,
    nonce: u64,
    tx_root: &Hash,
    height: u64,
) -> Result<Hash> {
    let _ = algo; // single algorithm — parameter kept for API compatibility
    let input = hash_concat(&[
        anchor.as_bytes(),
        &nonce.to_le_bytes(),
        tx_root.as_bytes(),
    ]);
    let _ = anchor;

    #[cfg(feature = "randomx")]
    {
        compute_randomx_hash(&input, height)
    }
    #[cfg(not(feature = "randomx"))]
    {
        let _ = height;
        RANDOMX_WARNING_SHOWN.call_once(|| {
            tracing::error!(
                "FATAL: RandomX feature not enabled. CoinCync 1.0 is RandomX-only — \
                 rebuild with `cargo build --release --features randomx`."
            );
        });
        Err(Error::Internal(
            "RandomX feature not enabled — CoinCync 1.0 requires --features randomx".into()
        ))
    }
}

// =============================================================================
// RandomX Support
// =============================================================================

#[cfg(feature = "randomx")]
// Increased from 64 to 2048 — the RandomX VM is reused for 2048
// blocks before the key rotates. At ~2 min/block that's ~2.8 days
// per VM rebuild. During IBD sync this is the critical bottleneck:
// every epoch boundary triggers a 0.5-1s VM reinit that stalls the
// validation pipeline. Longer epochs = faster sync.
const RANDOMX_KEY_EPOCH: u64 = 2048;

#[cfg(feature = "randomx")]
mod randomx_cache {
    use randomx_rs::{RandomXCache, RandomXDataset, RandomXFlag, RandomXVM};
    use parking_lot::RwLock;
    use std::cell::RefCell;
    use std::sync::atomic::{AtomicU64, Ordering};

    /// Shared dataset entry — cache + (optional) dataset + flags for
    /// the current epoch key. Cache and Dataset are `Arc<*Inner>`
    /// internally (verified against randomx_rs v1.4.1) so `.clone()`
    /// is a refcount bump — every thread builds its VM from these
    /// shared building blocks rather than duplicating the 256 MB
    /// cache or 2 GB dataset per thread.
    struct DatasetEntry {
        key: [u8; 32],
        cache: RandomXCache,
        dataset: Option<RandomXDataset>,
        flags: RandomXFlag,
    }

    // SAFETY: RandomXCache and RandomXDataset wrap Arc<inner>; both
    // are Send + Sync via their derive. Marking the entry Send + Sync
    // makes the wrapping struct usable inside a static. The actual
    // thread-safety guarantee is "no two threads ever share a single
    // RandomXVM instance" — enforced by the thread_local! VM cache
    // below.
    #[allow(unsafe_code)]
    unsafe impl Send for DatasetEntry {}
    #[allow(unsafe_code)]
    unsafe impl Sync for DatasetEntry {}

    static DATASET_CACHE: RwLock<Option<DatasetEntry>> = RwLock::new(None);
    static RETRY_AFTER: AtomicU64 = AtomicU64::new(0);

    thread_local! {
        /// Per-thread RandomX VM. Each thread builds its own VM from
        /// the shared `DatasetEntry` on first hash (or on epoch
        /// boundary when the key rotates) and reuses it thereafter
        /// without any locking. RandomXVM does NOT impl Clone and is
        /// NOT thread-safe for concurrent calls — keeping it
        /// thread-local satisfies the library's threading contract by
        /// construction.
        static THREAD_VM: RefCell<Option<ThreadVm>> = const { RefCell::new(None) };
    }

    struct ThreadVm {
        key: [u8; 32],
        vm: RandomXVM,
    }

    /// Hash dispatch — Phase 2 architecture.
    ///
    /// **Hot path** (steady state, no epoch flip):
    ///   1. THREAD_VM.with(...) — zero contention, thread-local
    ///   2. vm.calculate_hash(input) — the actual work
    ///
    /// **Epoch boundary** (seed changes ~every 2048 blocks):
    ///   - First thread to notice takes DATASET_CACHE.write() and
    ///     rebuilds the shared cache + (optional) dataset. Pays the
    ///     ~30-60s dataset build cost ONCE on its own thread.
    ///   - Every other thread sees the new key via DATASET_CACHE.read()
    ///     and Arc-clones the cache + dataset into a freshly-built
    ///     thread-local VM (~ms cost — the dataset is already built,
    ///     just attaching a new VM head to it).
    ///   - 2026-05-25 Phase 2 refactor: before this change there was a
    ///     single global VM behind a `parking_lot::Mutex`, so N mining
    ///     threads serialized through one VM. With per-thread VMs,
    ///     aggregate hashrate now scales linearly with `--threads`.
    pub fn compute_hash(seed: &[u8; 32], input: &[u8]) -> std::result::Result<[u8; 32], crate::error::Error> {
        let now_secs = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let retry_at = RETRY_AFTER.load(Ordering::Relaxed);
        if retry_at != 0 && now_secs < retry_at {
            return Err(crate::error::Error::Internal(
                format!("RandomX in backoff for {}s", retry_at - now_secs),
            ));
        }

        // 1. Ensure the global dataset matches the current seed.
        //    Fast path: read lock + matching key (no allocation).
        //    Slow path: write lock + rebuild (only on epoch boundary or
        //    first hash ever).
        let (cache, dataset, flags) = match ensure_dataset(seed, now_secs) {
            Ok(triple) => triple,
            Err(e) => return Err(e),
        };

        // 2. Per-thread VM. If the thread's local VM matches the seed,
        //    we hash through it directly — no global lock involvement at
        //    all. Otherwise rebuild from the shared cache + dataset
        //    (cheap given dataset is already built).
        THREAD_VM.with(|cell| {
            let mut guard = cell.borrow_mut();
            let needs_new = match &*guard {
                Some(tvm) => tvm.key != *seed,
                None => true,
            };
            if needs_new {
                // Drop the stale VM before building the new one so
                // peak memory during epoch flip is one VM, not two.
                *guard = None;
                let vm = RandomXVM::new(flags, Some(cache.clone()), dataset.clone())
                    .map_err(|e| crate::error::Error::Internal(
                        format!("per-thread RandomX VM init: {}", e)
                    ))?;
                *guard = Some(ThreadVm { key: *seed, vm });
            }
            // INVARIANT: the block above set `*guard = Some(ThreadVm { .. })`
            // and no code path releases the guard between there and here.
            // The `expect` documents that invariant; it can only fire if
            // the `*guard = Some(..)` line above is removed by future
            // refactoring, in which case an explicit panic here surfaces
            // the break faster than a silent None-then-crash-elsewhere.
            let tvm = guard.as_ref()
                .expect("BUG: thread VM guard is None immediately after being set — invariant broken by refactor");
            let hash = tvm.vm.calculate_hash(input)
                .map_err(|e| crate::error::Error::Internal(format!("RandomX hash failed: {}", e)))?;
            let mut output = [0u8; 32];
            output.copy_from_slice(&hash[..32]);
            Ok(output)
        })
    }

    /// Ensure `DATASET_CACHE` contains an entry for `seed`. Returns
    /// (cache, dataset, flags) cloned (Arc-bump cheap) for the caller
    /// to build a per-thread VM from.
    fn ensure_dataset(
        seed: &[u8; 32],
        now_secs: u64,
    ) -> std::result::Result<(RandomXCache, Option<RandomXDataset>, RandomXFlag), crate::error::Error> {
        // Fast path: read-only check.
        {
            let guard = DATASET_CACHE.read();
            if let Some(entry) = guard.as_ref() {
                if entry.key == *seed {
                    return Ok((entry.cache.clone(), entry.dataset.clone(), entry.flags));
                }
            }
        }

        // Slow path: build a new entry. Take the write lock; another
        // thread may have raced ahead and built it first — re-check.
        let mut guard = DATASET_CACHE.write();
        if let Some(entry) = guard.as_ref() {
            if entry.key == *seed {
                return Ok((entry.cache.clone(), entry.dataset.clone(), entry.flags));
            }
        }
        match create_dataset_entry(seed) {
            Ok(entry) => {
                let triple = (entry.cache.clone(), entry.dataset.clone(), entry.flags);
                *guard = Some(entry);
                RETRY_AFTER.store(0, Ordering::Relaxed);
                Ok(triple)
            }
            Err(e) => {
                RETRY_AFTER.store(now_secs + 60, Ordering::Relaxed);
                Err(e)
            }
        }
    }

    /// Build the shared `DatasetEntry` for `seed` using the 4-tier
    /// fallback ladder (full-mem → light-jit → jit-only → interpreted).
    ///
    /// This is called from `ensure_dataset` under the DATASET_CACHE
    /// write lock — only ONE thread runs this per epoch boundary,
    /// even with N parallel mining threads. Every other thread
    /// arrives at the read lock, sees the new entry, and Arc-clones
    /// the cache + dataset for its own VM construction (~ms, not
    /// 30-60s).
    fn create_dataset_entry(seed: &[u8; 32]) -> std::result::Result<DatasetEntry, crate::error::Error> {
        let start = std::time::Instant::now();
        let recommended = RandomXFlag::get_recommended_flags();

        // Memory budget: full-mode RandomX needs ~2.5 GB total (cache
        // + 2 GB dataset, both shared across all threads via Arc).
        // Operators on low-RAM systems can opt out via env var; we
        // then fall straight to light mode (cache-only, ~256 MB
        // total, 5-10× slower per hash).
        let light_mode_forced = std::env::var("COINCYNC_RANDOMX_LIGHT_MODE")
            .map(|v| matches!(v.trim(), "1" | "true" | "TRUE" | "yes" | "on"))
            .unwrap_or(false);

        // Tier 1: full-memory mode. JIT + AES + the 2 GB dataset.
        // Skipped if the operator opted out.
        if !light_mode_forced {
            let full_flags = recommended | RandomXFlag::FLAG_FULL_MEM;
            tracing::info!(
                "Building RandomX dataset (mode: full-mem): active={:?}, key={}... \
                 (one-time ~30-60s build per epoch; subsequent thread VMs are ~ms)",
                full_flags,
                hex::encode(&seed[..4])
            );
            match try_build_entry(full_flags, seed) {
                Ok(entry) => {
                    tracing::info!(
                        "RandomX dataset ready in {:.2}s (mode: full-mem, flags: {:?})",
                        start.elapsed().as_secs_f64(),
                        full_flags
                    );
                    return Ok(entry);
                }
                Err(e) => {
                    tracing::warn!(
                        "RandomX full-mem init failed: {}. Falling back to light mode. \
                         Common cause: insufficient RAM for the 2 GB dataset, or \
                         randomx_rs build without full-mem support. Set \
                         COINCYNC_RANDOMX_LIGHT_MODE=1 to skip this attempt next time.",
                        e
                    );
                }
            }
        } else {
            tracing::info!(
                "Skipping full-mem RandomX (COINCYNC_RANDOMX_LIGHT_MODE=1 set); \
                 using light mode directly"
            );
        }

        // Tier 2: light mode (cache-only).
        let active_flags = recommended & !RandomXFlag::FLAG_FULL_MEM;
        tracing::info!(
            "Building RandomX cache (mode: light-jit): active={:?}, key={}...",
            active_flags,
            hex::encode(&seed[..4])
        );
        match try_build_entry(active_flags, seed) {
            Ok(entry) => {
                tracing::info!(
                    "RandomX cache ready in {:.2}s (mode: light-jit, flags: {:?})",
                    start.elapsed().as_secs_f64(),
                    active_flags
                );
                return Ok(entry);
            }
            Err(e) => {
                tracing::warn!(
                    "RandomX init with {:?} failed: {}. Falling back.",
                    active_flags, e
                );
            }
        }

        // Tier 3: JIT-only fallback.
        let jit_only = RandomXFlag::FLAG_JIT;
        tracing::info!("Building RandomX cache with JIT-only fallback...");
        match try_build_entry(jit_only, seed) {
            Ok(entry) => {
                tracing::warn!(
                    "RandomX cache ready in {:.2}s (mode: jit-only, DEGRADED ~30-50% of normal)",
                    start.elapsed().as_secs_f64()
                );
                eprintln!(
                    "\n⚠️  RandomX fell back to JIT-only mode. Hashrate will be reduced.\n\
                       Likely cause: AES/SSSE3 instruction set unavailable, or antivirus\n\
                       blocking some JIT features. Mining will continue but slower.\n"
                );
                return Ok(entry);
            }
            Err(e) => {
                tracing::warn!("JIT-only also failed: {}. Falling to interpreted.", e);
            }
        }

        // Tier 4: interpreted (disaster mode).
        tracing::info!("Building RandomX cache in FLAG_DEFAULT (interpreted mode)...");
        match try_build_entry(RandomXFlag::FLAG_DEFAULT, seed) {
            Ok(entry) => {
                tracing::error!(
                    "RandomX cache ready in {:.2}s (mode: INTERPRETED, ~100× SLOWER than normal)",
                    start.elapsed().as_secs_f64()
                );
                eprintln!(
                    "\n╔════════════════════════════════════════════════════════════════════╗\n\
                       ║  ⚠️  RandomX fell back to INTERPRETED MODE.                         ║\n\
                       ║                                                                    ║\n\
                       ║  Your hashrate will be ~100× SLOWER than normal                    ║\n\
                       ║  (expect ~10-50 H/s instead of 500-2000 H/s per thread).           ║\n\
                       ║                                                                    ║\n\
                       ║  Most common cause on Windows: antivirus blocking JIT memory       ║\n\
                       ║  pages. Fix:                                                       ║\n\
                       ║    • Add the coincync-rig binary to Windows Defender exclusions    ║\n\
                       ║    • Or temporarily disable third-party AV and restart the miner   ║\n\
                       ║    • Or run the miner as Administrator                             ║\n\
                       ║                                                                    ║\n\
                       ║  On Linux: ensure /proc/sys/kernel/perf_event_paranoid <= 2 and    ║\n\
                       ║  that the process isn't sandboxed without W^X relaxation.          ║\n\
                       ╚════════════════════════════════════════════════════════════════════╝\n"
                );
                Ok(entry)
            }
            Err(e) => {
                tracing::error!("RandomX init failed with all flag combinations: {}", e);
                Err(crate::error::Error::Internal(format!(
                    "RandomX init failed: {}",
                    e
                )))
            }
        }
    }

    /// Build a `DatasetEntry` for the given flag set. Returns Err
    /// (with operator-visible context) on cache or dataset alloc
    /// failure so the caller's tier ladder can retry with weaker
    /// flags.
    fn try_build_entry(flags: RandomXFlag, seed: &[u8; 32]) -> std::result::Result<DatasetEntry, String> {
        let cache = RandomXCache::new(flags, seed)
            .map_err(|e| format!("cache init: {}", e))?;

        let dataset = if flags.contains(RandomXFlag::FLAG_FULL_MEM) {
            tracing::info!(
                "Building RandomX dataset (~2 GB, ~30-60s, one-time per epoch)..."
            );
            let ds_start = std::time::Instant::now();
            match RandomXDataset::new(flags, cache.clone(), 0) {
                Ok(ds) => {
                    tracing::info!(
                        "RandomX dataset built in {:.2}s",
                        ds_start.elapsed().as_secs_f64()
                    );
                    Some(ds)
                }
                Err(e) => {
                    return Err(format!(
                        "dataset alloc failed (likely insufficient RAM for 2 GB): {}",
                        e
                    ));
                }
            }
        } else {
            None
        };

        Ok(DatasetEntry { key: *seed, cache, dataset, flags })
    }

    /// Test helper: build a single VM for the given flag set. The
    /// production hot path no longer goes through this — VMs live in
    /// `thread_local!` cells, built from a shared dataset entry — but
    /// the equivalence test still uses this to assemble two VMs side
    /// by side and compare their hash output.
    #[cfg(test)]
    fn try_create_vm(flags: RandomXFlag, seed: &[u8; 32]) -> std::result::Result<RandomXVM, String> {
        let entry = try_build_entry(flags, seed)?;
        RandomXVM::new(flags, Some(entry.cache), entry.dataset)
            .map_err(|e| format!("VM init: {}", e))
    }

    /// Drop the global dataset cache. Used by tests and tooling that
    /// need to force a rebuild on the next hash. Note: thread-local
    /// VMs in OTHER threads can't be cleared from here — they'll
    /// rebuild themselves on their next hash call when they see the
    /// new (or absent) dataset key. Within the calling thread, the
    /// thread-local VM is also cleared so the rebuild path is
    /// exercised on the next call here.
    #[allow(dead_code)]
    pub fn clear_cache() {
        let mut guard = DATASET_CACHE.write();
        *guard = None;
        THREAD_VM.with(|cell| { *cell.borrow_mut() = None; });
    }

    /// Consensus-equivalence test: full-mem mode and light mode MUST
    /// produce bit-identical hashes for the same seed + input. This is
    /// guaranteed by the RandomX spec (the whole point of the two
    /// modes is that verifiers run light, miners run fast, and they
    /// must agree) — this test catches *our* wiring bugs that would
    /// break the guarantee (e.g. accidentally building the dataset
    /// from a different seed than the cache).
    ///
    /// Marked `#[ignore]` because building the 2 GB dataset takes
    /// 30-60s and uses ~2.5 GB RAM; not appropriate for default
    /// `cargo test` runs. Run explicitly with:
    ///
    ///   cargo test --release --features randomx -- --ignored \
    ///     randomx_cache::tests::fast_light_equivalence
    #[cfg(test)]
    #[allow(unsafe_code)]
    mod tests {
        use super::*;

        #[test]
        #[ignore]
        fn fast_light_equivalence() {
            let seed = [0xA1u8; 32];
            let input = b"coincync randomx fast-vs-light equivalence test";

            // Light mode — recommended flags minus FULL_MEM.
            let light_flags = RandomXFlag::get_recommended_flags()
                & !RandomXFlag::FLAG_FULL_MEM;
            let light_vm = try_create_vm(light_flags, &seed)
                .expect("light-mode VM build must succeed on test host");
            let light_hash = light_vm.calculate_hash(input)
                .expect("light-mode hash must succeed");

            // Full mode — recommended flags including FULL_MEM. This
            // is the 30-60s init.
            let full_flags = RandomXFlag::get_recommended_flags()
                | RandomXFlag::FLAG_FULL_MEM;
            let full_vm = try_create_vm(full_flags, &seed)
                .expect("full-mem VM build must succeed on test host with ~3 GB free");
            let full_hash = full_vm.calculate_hash(input)
                .expect("full-mem hash must succeed");

            assert_eq!(
                light_hash, full_hash,
                "RandomX fast and light modes MUST produce identical hashes — \
                 if this fails, our cache/dataset wiring has a seed mismatch \
                 and the chain will fork between full-mem miners and light-mode verifiers"
            );
        }

        /// Phase 2 invariant: N mining threads hashing the same
        /// (seed, input) MUST all produce the same hash. If the
        /// per-thread VM design has a cross-thread sharing bug,
        /// one or more threads will see corrupted state and return
        /// a different hash.
        ///
        /// Marked `#[ignore]` because it touches the global
        /// DATASET_CACHE and would race with other tests in the
        /// same process. Run explicitly with:
        ///
        ///   cargo test --release --features randomx -- --ignored \
        ///     randomx_cache::tests::concurrent_threads_consistent_hashes
        #[test]
        #[ignore]
        fn concurrent_threads_consistent_hashes() {
            use std::thread;

            // Use light mode to keep the test cheap (~ms not 30-60s
            // for dataset build). The per-thread VM path being tested
            // is the same in both modes — only the underlying
            // dataset/cache differs.
            std::env::set_var("COINCYNC_RANDOMX_LIGHT_MODE", "1");
            super::clear_cache();

            let seed = [0xC0u8; 32];
            let input = b"coincync randomx phase-2 concurrent-threads consistency test";

            // Single-thread baseline: what the hash SHOULD be.
            let baseline = super::compute_hash(&seed, input)
                .expect("baseline hash must succeed");

            // Fan out: each thread hashes the same input and reports.
            const N_THREADS: usize = 8;
            let mut handles = Vec::with_capacity(N_THREADS);
            for tid in 0..N_THREADS {
                let seed = seed;
                handles.push(thread::spawn(move || {
                    // Run several rounds per thread to maximize
                    // opportunity for any racy/shared state to
                    // corrupt the output.
                    let mut hashes = Vec::with_capacity(32);
                    for _ in 0..32 {
                        let h = super::compute_hash(&seed, input)
                            .unwrap_or_else(|e| panic!("thread {tid} hash failed: {e}"));
                        hashes.push(h);
                    }
                    hashes
                }));
            }

            // Every thread × every round MUST match the baseline.
            for (tid, h) in handles.into_iter().enumerate() {
                let results = h.join().expect("thread panicked");
                for (round, hash) in results.iter().enumerate() {
                    assert_eq!(
                        hash, &baseline,
                        "thread {tid} round {round} produced a different hash than the \
                         single-thread baseline — the per-thread VM design has a \
                         cross-thread sharing bug; mining nodes would produce invalid \
                         shares and consensus would split"
                    );
                }
            }
        }

        /// Phase 2 invariant: changing the seed forces every thread
        /// to rebuild its VM, and the new hash output reflects the
        /// new seed. Catches a stale-thread-local bug where a thread
        /// keeps hashing through a VM bound to a previous epoch's key
        /// after the global dataset has rotated.
        #[test]
        #[ignore]
        fn epoch_rotation_rebuilds_thread_vms() {
            std::env::set_var("COINCYNC_RANDOMX_LIGHT_MODE", "1");
            super::clear_cache();

            let input = b"coincync randomx epoch-rotation test";
            let seed_a = [0xAAu8; 32];
            let seed_b = [0xBBu8; 32];

            let hash_a_1 = super::compute_hash(&seed_a, input).unwrap();
            let hash_b_1 = super::compute_hash(&seed_b, input).unwrap();
            assert_ne!(
                hash_a_1, hash_b_1,
                "different seeds MUST produce different hashes — \
                 if they don't, the seed isn't reaching the VM and \
                 epoch rotation is broken"
            );

            // Round-trip back to seed_a: same output as before.
            let hash_a_2 = super::compute_hash(&seed_a, input).unwrap();
            assert_eq!(
                hash_a_1, hash_a_2,
                "re-using a seed MUST give the same hash — \
                 the cache key check is comparing the wrong bytes"
            );
        }
    }
}

/// Derive a stable RandomX key from height, bound to the chain's genesis hash.
///
/// AUDIT (R-2 fix, 2026-07-02): the fallback path (when
/// `bind_randomx_genesis_for_network` was never called) used to
/// consult `COINCYNC_NETWORK` and default to testnet ENTIRELY
/// SILENTLY. If a binary forgot to call the bind function (which
/// happened during the 2026-06-27 rc3 deploy), the whole PoW chain
/// derived from the wrong genesis and looked like network-wide
/// invalid-PoW. Now:
/// 1. The first time the fallback fires, emit an ERROR-level log
///    (via `std::sync::Once`) so ops see it. Deduplicated so the
///    hot path isn't flooded, but LOUD once.
/// 2. Structured `tracing::error!` with the specific reason so the
///    log is greppable in observability tooling.
/// 3. Behavior unchanged (still falls back), because panicking here
///    would kill mining/validation loops mid-block. But the fall-
///    back is no longer silent, which was the whole R-2 issue.
///
/// See `bind_randomx_genesis_for_network` at L109; the correct call
/// site is `coincync-node`/`coincync-miner` process startup.
#[cfg(feature = "randomx")]
fn randomx_key_for_height(height: u64) -> [u8; 32] {
    use crate::primitives::hash_domain;
    let epoch = height / RANDOMX_KEY_EPOCH;
    let genesis_bytes: [u8; 32] = RANDOMX_GENESIS_BYTES.get().copied().unwrap_or_else(|| {
        static WARN_ONCE: std::sync::Once = std::sync::Once::new();
        WARN_ONCE.call_once(|| {
            let network_env = std::env::var("COINCYNC_NETWORK")
                .ok()
                .unwrap_or_else(|| "<unset>".to_string());
            tracing::error!(
                target: "consensus_pow",
                event = "randomx_genesis_not_bound",
                network_env = %network_env,
                "RANDOMX GENESIS NOT BOUND: bind_randomx_genesis_for_network was \
                 never called before PoW derivation; falling back to \
                 COINCYNC_NETWORK env var ('{}'). If this daemon is producing \
                 rejected blocks, the wrong-genesis fallback is why. Restart the \
                 binary and ensure bind_randomx_genesis_for_network is invoked \
                 during process init, BEFORE the first block is mined or verified.",
                network_env
            );
        });
        let network = std::env::var("COINCYNC_NETWORK")
            .ok()
            .map(|v| v.trim().to_ascii_lowercase())
            // Match `coincync-node`'s default `--network testnet` when unset.
            .unwrap_or_else(|| "testnet".to_string());
        match network.as_str() {
            "testnet" | "regtest" => crate::testnet::TESTNET_GENESIS_HASH,
            _ => crate::mainnet::MAINNET_GENESIS_HASH,
        }
    });

    let mut seed = Vec::with_capacity(8 + 32);
    seed.extend_from_slice(&epoch.to_le_bytes());
    seed.extend_from_slice(&genesis_bytes);
    let key_hash = hash_domain(b"CYNC1_RANDOMX_KEY_EPOCH", &seed);
    *key_hash.as_bytes()
}

#[cfg(feature = "randomx")]
fn compute_randomx_hash(input: &Hash, height: u64) -> Result<Hash> {
    let seed = randomx_key_for_height(height);
    randomx_cache::compute_hash(&seed, input.as_bytes())
        .map(Hash::from_bytes)
}

// =============================================================================
// Verification
// =============================================================================

#[derive(Debug, Clone)]
pub enum PowVerifyError {
    AnchorMismatch { expected: Hash, claimed: Hash },
    AlgorithmMismatch { expected: u8, claimed: u8 },
    TargetNotMet { hash: Hash, target: Hash },
    AnchorComputation(String),
}

impl std::fmt::Display for PowVerifyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PowVerifyError::AnchorMismatch { expected, claimed } => {
                write!(f, "Anchor mismatch: expected {}, got {}",
                    hex::encode(&expected.as_bytes()[..8]),
                    hex::encode(&claimed.as_bytes()[..8]))
            }
            PowVerifyError::AlgorithmMismatch { expected, claimed } => {
                write!(f, "Algorithm mismatch: expected {}, got {}", expected, claimed)
            }
            PowVerifyError::TargetNotMet { hash, target } => {
                write!(f, "Hash doesn't meet target: hash={}, target={}",
                    hex::encode(&hash.as_bytes()[..8]),
                    hex::encode(&target.as_bytes()[..8]))
            }
            PowVerifyError::AnchorComputation(e) => {
                write!(f, "Anchor computation failed: {}", e)
            }
        }
    }
}

pub fn verify_pow(
    prev_hash: &Hash,
    height: u64,
    timestamp: u64,
    nonce: u64,
    tx_root: &Hash,
    target: &Hash,
    claimed_anchor: &Hash,
    claimed_algo: u8,
) -> Result<()> {
    let anchor = compute_full_anchor(prev_hash, height, timestamp)
        .map_err(|e| crate::error::Error::PowValidation(
            PowVerifyError::AnchorComputation(e.to_string()).to_string()
        ))?;

    if anchor.mixed_hash != *claimed_anchor {
        let error = PowVerifyError::AnchorMismatch {
            expected: anchor.mixed_hash,
            claimed: *claimed_anchor,
        };
        return Err(crate::error::Error::PowValidation(error.to_string()));
    }

    if anchor.algorithm as u8 != claimed_algo {
        let error = PowVerifyError::AlgorithmMismatch {
            expected: anchor.algorithm as u8,
            claimed: claimed_algo,
        };
        return Err(crate::error::Error::PowValidation(error.to_string()));
    }

    // Time the RandomX VM call in isolation. Scoping the timer to just
    // this line keeps the observation tight to the expensive work — the
    // rest of `verify_pow` is cheap header arithmetic. `verify_pow` runs
    // ~once per accepted block (low-frequency, high-signal); the miner's
    // inner loop is deliberately *not* instrumented, since per-hash
    // observations there would dominate the histogram and add real
    // overhead to the hash hot path. See `src/metrics.rs::RANDOMX_HASH`
    // for the bucket boundaries.
    let pow_hash = {
        let _timer = crate::metrics::RANDOMX_HASH.start_timer();
        compute_pow_hash(anchor.algorithm, &anchor.mixed_hash, nonce, tx_root, height)?
    };

    if !pow_hash.meets_difficulty(target) {
        let error = PowVerifyError::TargetNotMet {
            hash: pow_hash,
            target: *target,
        };
        return Err(crate::error::Error::PowValidation(error.to_string()));
    }

    Ok(())
}

pub fn meets_difficulty(hash: &Hash, target: &Hash) -> bool {
    hash.meets_difficulty(target)
}

/// Calculate work from target (difficulty). `max_target / target` (Bitcoin formula).
///
/// AUDIT (R-3 doc-only fix, 2026-07-02): the function reads ONLY the
/// upper 128 bits of the 256-bit target and does the divide in u128.
/// This is deliberate — the return type is u128 (chain work
/// aggregated across all blocks fits comfortably in u128 for any
/// realistic chain lifetime; see Bitcoin's `nChainWork` which is
/// stored as arith_uint256 but only the upper bits ever matter in
/// practice). Dropping the lower 128 bits loses at most 1 part in
/// 2^128 of precision on any single block's work contribution,
/// which is well below the granularity of the difficulty-adjustment
/// algorithm's output.
///
/// The tradeoff DOES mean that two targets differing only in their
/// bottom 128 bits produce identical `work_from_target` values — but
/// the DAA (see `difficulty.rs`) rounds to whole ~28-bit steps
/// anyway, so no two consecutive real targets can differ only in the
/// bottom half. If a future change makes the DAA finer-grained past
/// 128 bits of resolution, this function must switch to u256 or
/// arith_uint256 arithmetic (see Bitcoin Core's `arith_uint256::GetLow64`
/// pattern and the `#include <arith_uint256.h>` uses in `pow.cpp`).
///
/// This function is used ONLY for fork-choice work comparison; it is
/// NOT used to compute or verify the target bytes themselves. Target
/// bytes are compared full-width via `Hash::meets_difficulty`.
pub fn work_from_target(target: &Hash) -> u128 {
    let bytes = target.as_bytes();
    let mut buf = [0u8; 16];
    buf.copy_from_slice(&bytes[..16]);
    let target_u128 = u128::from_be_bytes(buf);

    if target_u128 == 0 {
        return u128::MAX;
    }

    u128::MAX / target_u128
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_full_anchor_deterministic_and_distinct() {
        let prev1 = Hash::from_bytes([1u8; 32]);
        let prev2 = Hash::from_bytes([2u8; 32]);
        let height = 100;
        let ts = 1_700_000_000u64;

        let a1 = compute_full_anchor(&prev1, height, ts).unwrap();
        let a2 = compute_full_anchor(&prev1, height, ts).unwrap();
        assert_eq!(a1.mixed_hash, a2.mixed_hash, "must be deterministic");

        let a3 = compute_full_anchor(&prev2, height, ts).unwrap();
        assert_ne!(a1.mixed_hash, a3.mixed_hash, "different prev_hash must give different anchor");

        let a4 = compute_full_anchor(&prev1, height + 1, ts).unwrap();
        assert_ne!(a1.mixed_hash, a4.mixed_hash, "different height must give different anchor");

        let a5 = compute_full_anchor(&prev1, height, ts + 1).unwrap();
        assert_ne!(a1.mixed_hash, a5.mixed_hash, "different timestamp must give different anchor");
    }

    #[test]
    fn test_pow_algorithm_single() {
        assert_eq!(PowAlgorithm::from_index(0), PowAlgorithm::RandomX);
        assert_eq!(PowAlgorithm::from_index(1), PowAlgorithm::RandomX);
        assert_eq!(PowAlgorithm::at_height(42), PowAlgorithm::RandomX);
        assert_eq!(PowAlgorithm::RandomX.name(), "RandomX");
    }

    #[test]
    fn seq_pad_cache_eviction() {
        let mut cache = SeqPadCache::new();
        let dummy_anchor = Anchor {
            sequential_hash: Hash::from_bytes([0; 32]),
            mixed_hash: Hash::from_bytes([0; 32]),
            algorithm: PowAlgorithm::RandomX,
            height: 0,
            timestamp: 0,
        };

        for i in 0..(SEQ_PAD_CACHE_MAX + 100) {
            let key = (Hash::from_bytes([i as u8; 32]), i as u64, 0u64);
            cache.insert(key, dummy_anchor.clone());
        }

        assert!(cache.anchors.len() <= SEQ_PAD_CACHE_MAX);
        assert!(cache.insertion_order.len() <= SEQ_PAD_CACHE_MAX);
        assert_eq!(cache.anchors.len(), cache.insertion_order.len(),
            "anchors and insertion_order must stay in lockstep");

        let oldest_key = (Hash::from_bytes([0u8; 32]), 0u64, 0u64);
        assert!(cache.get(&oldest_key).is_none(), "oldest entry should be evicted");

        let newest_i = (SEQ_PAD_CACHE_MAX + 99) as u8;
        let newest_key = (Hash::from_bytes([newest_i; 32]), (SEQ_PAD_CACHE_MAX + 99) as u64, 0u64);
        assert!(cache.get(&newest_key).is_some(), "newest entry should be present");
    }
}
