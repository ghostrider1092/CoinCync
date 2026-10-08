//! # Sluice — the unified heavy-verify valve (Warren Phase 0 foundation)
//!
//! See `docs/design/warren-architecture.md` §3.5/§3.7/§3.8. This is the shared
//! seam every heavy privacy-verify path (Bulletproofs, CLSAG, Spark, …) plugs
//! into, plus the self-regulating concurrency valve that governs them on a
//! bounded pool kept SEPARATE from the RandomX mining pool.
//!
//! ## The one invariant that makes it safe
//! **The valve setting controls throughput, NEVER the result.** A node running
//! this on 1 core (serial) or 32 cores (wide-open), mining or idle, computes the
//! IDENTICAL `Ok`/`Err` per item. Consensus never depends on the valve. This is
//! enforced by construction — the parallel phase calls [`HeavyVerify::verify_one`],
//! which is contractually PURE over `&self` + `item` (no shared mutable state) —
//! and checked by [`assert_valve_invariant`] in tests.
//!
//! ## Status
//! Foundation scaffold: the trait + the valve + the determinism harness are real
//! and used today only where a path opts in. The ADAPTIVE resize (shrink while
//! mining) and the per-path auto-wiring are left as marked TODOs for mainnet —
//! the seam is here so they are a fill-in, not a rebuild.

use std::panic::AssertUnwindSafe;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;

use rayon::prelude::*;

/// A heavy verification path whose per-item work is INDEPENDENT and therefore
/// parallelizable. The caller runs the serial "conclusion" gate (e.g. the
/// shielded pool-value accumulate + within-block linking-tag uniqueness) on the
/// returned per-item outputs, in order.
pub trait HeavyVerify: Sync {
    /// One unit of work to verify (a tx, an input, a bundle). `Sync` so it can be
    /// shared across verify threads.
    type Item: Sync;
    /// What a successful verify yields (e.g. the revealed linking tags).
    type Output: Send;
    /// The verify error type.
    type Error: Send;

    /// Verify ONE item.
    ///
    /// CONTRACT: pure over `&self` + `item` — it MUST NOT read or write shared
    /// mutable state. Any state it needs (spent-tag set, cover set) must be an
    /// immutable snapshot captured before the valve fans out. Violating this
    /// breaks the valve invariant and is a consensus-safety bug.
    fn verify_one(&self, item: &Self::Item) -> Result<Self::Output, Self::Error>;

    /// A verify-result cache key for `item`, or `None` if this path must not be
    /// cached (the default).
    ///
    /// SAFETY: return `Some(key)` ONLY if the item's accept/reject verdict is a
    /// pure function of `item` alone and `key` uniquely commits to every input
    /// that verdict depends on. If the verdict depends on any state outside
    /// `item` — e.g. a store's spent-tag set, where the same payload is valid
    /// before its tag is spent and invalid after — this MUST stay `None`, or a
    /// cached verdict would be served stale. The `None` default makes
    /// "not cacheable" the safe fallback for every new path.
    fn cache_key(&self, _item: &Self::Item) -> Option<[u8; 32]> {
        None
    }
}

/// The Sluice valve: governs how a [`HeavyVerify`] path is fanned out.
///
/// Holds a dedicated rayon pool (kept separate from the RandomX mining pool so
/// the two never oversubscribe) and a circuit-breaker. When the breaker is
/// tripped — or the pool is 1-wide — verification runs serial. The result is
/// identical either way.
#[derive(Clone)]
pub struct Sluice {
    pool: Option<Arc<rayon::ThreadPool>>,
    /// Circuit-breaker: once tripped (e.g. a thread-safety self-check failed, or a
    /// worker panicked) this path falls back to serial. Shared so a trip sticks.
    healthy: Arc<AtomicBool>,
    /// Opt-in metrics sink (§3.7). `None` → zero overhead (the default); `Some`
    /// → every batch records items/timing/utilization/cache/breaker counters.
    /// Shared across clones so a cloned valve feeds the same counters.
    metrics: Option<Arc<SluiceMetrics>>,
}

impl Sluice {
    /// Auto-sized valve: `max(1, available_parallelism − HEADROOM)` threads,
    /// overridable with `COINCYNC_VERIFY_THREADS` (0 = auto, 1 = serial).
    ///
    /// TODO(mainnet): make this ADAPTIVE — shrink the pool while
    /// `NODE_MINING_ACTIVE` so verify never steals cores from RandomX, grow it
    /// when idle/syncing. The seam: recompute `want` from the mining flag and
    /// swap the pool. For now the static headroom is the safe default.
    pub fn auto() -> Self {
        const HEADROOM: usize = 2; // leave cores for block-apply + the main loop
        let cores = std::thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(1);
        let want = match std::env::var("COINCYNC_VERIFY_THREADS").ok().and_then(|s| s.trim().parse::<usize>().ok()) {
            Some(0) | None => cores.saturating_sub(HEADROOM).max(1),
            Some(n) => n.max(1),
        };
        Self::with_threads(want)
    }

    /// Fixed-width valve. `threads <= 1` → serial (no pool).
    pub fn with_threads(threads: usize) -> Self {
        let pool = if threads <= 1 {
            None
        } else {
            rayon::ThreadPoolBuilder::new()
                .num_threads(threads)
                .thread_name(|i| format!("cync-verify-{i}"))
                .build()
                .ok()
                .map(Arc::new)
        };
        Self { pool, healthy: Arc::new(AtomicBool::new(true)), metrics: None }
    }

    /// Serial valve — the circuit-broken / single-core path.
    pub fn serial() -> Self {
        Self { pool: None, healthy: Arc::new(AtomicBool::new(true)), metrics: None }
    }

    /// Attach a metrics sink. The counters are shared (`Arc`), so clones of this
    /// valve feed the same sink; call `snapshot()` on the `SluiceMetrics` to read.
    #[must_use]
    pub fn with_metrics(mut self, metrics: Arc<SluiceMetrics>) -> Self {
        self.metrics = Some(metrics);
        self
    }

    fn record_batch(&self, items: u64, parallel: bool, elapsed: std::time::Duration) {
        if let Some(m) = &self.metrics {
            m.items_verified.fetch_add(items, Ordering::Relaxed);
            let bucket = if parallel { &m.batches_parallel } else { &m.batches_serial };
            bucket.fetch_add(1, Ordering::Relaxed);
            let nanos = elapsed.as_nanos().min(u64::MAX as u128) as u64;
            m.verify_nanos.fetch_add(nanos, Ordering::Relaxed);
        }
    }

    fn record_cache(&self, hits: u64, misses: u64) {
        if let Some(m) = &self.metrics {
            m.cache_hits.fetch_add(hits, Ordering::Relaxed);
            m.cache_misses.fetch_add(misses, Ordering::Relaxed);
        }
    }

    /// Trip the circuit-breaker: this path runs serial from now on. Call when a
    /// backend's thread-safety self-check fails (see the libspark FFI gate).
    pub fn trip(&self) {
        self.healthy.store(false, Ordering::SeqCst);
    }

    fn parallel_enabled(&self) -> bool {
        self.pool.is_some() && self.healthy.load(Ordering::SeqCst)
    }

    /// Whether this valve will currently fan out (a pool exists and the breaker
    /// has not tripped). `false` ⇒ serial. Observability / gate checks.
    pub fn is_parallel(&self) -> bool {
        self.parallel_enabled()
    }

    /// Verify every item, returning per-item results IN INPUT ORDER. Runs on the
    /// dedicated pool when the valve is open and the path is healthy, serial
    /// otherwise — identical results either way. Each parallel task is wrapped in
    /// `catch_unwind`: a panic becomes that item's `Err` via `on_panic` and trips
    /// the breaker, so one bad item can neither crash the node nor be misread as
    /// a verify success.
    pub fn verify<V: HeavyVerify>(
        &self,
        v: &V,
        items: &[V::Item],
        on_panic: impl Fn() -> V::Error + Sync,
    ) -> Vec<Result<V::Output, V::Error>> {
        let start = std::time::Instant::now();
        let parallel = self.parallel_enabled();
        let out: Vec<Result<V::Output, V::Error>> = if !parallel {
            items.iter().map(|it| v.verify_one(it)).collect()
        } else {
            let healthy = &self.healthy;
            let metrics = self.metrics.as_ref();
            let run = || {
                items
                    .par_iter()
                    .map(|it| {
                        match std::panic::catch_unwind(AssertUnwindSafe(|| v.verify_one(it))) {
                            Ok(r) => r,
                            Err(_) => {
                                healthy.store(false, Ordering::SeqCst); // trip the breaker
                                if let Some(m) = metrics {
                                    m.breaker_trips.fetch_add(1, Ordering::Relaxed);
                                }
                                Err(on_panic())
                            }
                        }
                    })
                    .collect()
            };
            // Install on the dedicated pool so verify work never runs on rayon's
            // global pool (which other subsystems — and potentially mining — share).
            self.pool.as_ref().map(|p| p.install(run)).unwrap_or_else(run)
        };
        self.record_batch(items.len() as u64, parallel, start.elapsed());
        out
    }

    /// Like [`verify`](Self::verify) but consulting a [`VerifyResultCache`], and
    /// returning per-item validity (`true` = valid) in input order — the §3.7
    /// "verified once, not re-verified in a block or on reorg replay" skip.
    ///
    /// For each item: if the path yields a `cache_key` and it is a known-valid
    /// hit, the item is accepted WITHOUT re-verifying; otherwise it is verified
    /// through the valve (misses only, fanned out on the pool), and a VALID
    /// verdict with a key is recorded (positive-only). Items without a key are
    /// always verified and never cached.
    ///
    /// The result is identical to verifying every item fresh: a hit can only be
    /// a statement that previously verified valid under a key that commits to
    /// all its inputs (the `cache_key` contract + positive-only storage), so the
    /// cache changes throughput, never the verdict — the valve invariant holds
    /// across widths AND across cache states.
    pub fn verify_valid_cached<V: HeavyVerify>(
        &self,
        v: &V,
        items: &[V::Item],
        cache: &dyn crate::crypto::verify_cache::VerifyResultCache,
    ) -> Vec<bool> {
        // 1. Serial cache pass (cheap hashmap lookups): record each item's key
        //    and resolve known-valid hits; everything else is a miss to verify.
        let keys: Vec<Option<[u8; 32]>> = items.iter().map(|it| v.cache_key(it)).collect();
        let mut result = vec![false; items.len()];
        let mut misses: Vec<usize> = Vec::new();
        for (i, key) in keys.iter().enumerate() {
            match key {
                Some(k) if cache.is_known_valid(k) => result[i] = true,
                _ => misses.push(i),
            }
        }

        let hits = (items.len() - misses.len()) as u64;
        self.record_cache(hits, misses.len() as u64);

        // 2. Verify the misses through the valve (parallel when open+healthy),
        //    with the same per-item panic isolation as `verify`.
        let start = std::time::Instant::now();
        let parallel = self.parallel_enabled();
        let healthy = &self.healthy;
        let metrics = self.metrics.as_ref();
        let verify_ok = |i: usize| -> bool {
            match std::panic::catch_unwind(AssertUnwindSafe(|| v.verify_one(&items[i]))) {
                Ok(r) => r.is_ok(),
                Err(_) => {
                    healthy.store(false, Ordering::SeqCst);
                    if let Some(m) = metrics {
                        m.breaker_trips.fetch_add(1, Ordering::Relaxed);
                    }
                    false
                }
            }
        };
        let miss_results: Vec<(usize, bool)> = if parallel {
            let run = || misses.par_iter().map(|&i| (i, verify_ok(i))).collect();
            self.pool.as_ref().map(|p| p.install(run)).unwrap_or_else(run)
        } else {
            misses.iter().map(|&i| (i, verify_ok(i))).collect()
        };
        self.record_batch(misses.len() as u64, parallel, start.elapsed());

        // 3. Merge + record positives (positive-only: never cache a reject).
        for (i, ok) in miss_results {
            result[i] = ok;
            if ok {
                if let Some(k) = keys[i] {
                    cache.record_valid(k);
                }
            }
        }
        result
    }
}

impl Default for Sluice {
    fn default() -> Self {
        Self::auto()
    }
}

/// Opt-in metrics counters for a [`Sluice`] (§3.7): per-path verify timing, pool
/// utilization (parallel vs serial batches), cache hit-rate, and breaker trips.
/// These feed BOTH operators (export a [`snapshot`](Self::snapshot)) and the
/// adaptive valve (utilization + timing inform pool sizing). All `Relaxed` — the
/// counters are observability, never a consensus input.
#[derive(Debug, Default)]
pub struct SluiceMetrics {
    /// Total items run through `verify` / `verify_valid_cached` (misses only for
    /// the cached path — cache hits are counted separately).
    pub items_verified: AtomicU64,
    /// Items served from the verify-result cache without re-verifying.
    pub cache_hits: AtomicU64,
    /// Items that missed the cache and were verified.
    pub cache_misses: AtomicU64,
    /// Batches that ran on the parallel pool.
    pub batches_parallel: AtomicU64,
    /// Batches that ran serial (valve closed / circuit-broken / 1-wide).
    pub batches_serial: AtomicU64,
    /// Worker panics caught (each trips the breaker to serial).
    pub breaker_trips: AtomicU64,
    /// Cumulative wall-clock nanoseconds spent verifying (saturating).
    pub verify_nanos: AtomicU64,
}

impl SluiceMetrics {
    pub fn new() -> Self {
        Self::default()
    }

    /// A consistent-enough point-in-time read of all counters.
    pub fn snapshot(&self) -> SluiceMetricsSnapshot {
        use Ordering::Relaxed;
        SluiceMetricsSnapshot {
            items_verified: self.items_verified.load(Relaxed),
            cache_hits: self.cache_hits.load(Relaxed),
            cache_misses: self.cache_misses.load(Relaxed),
            batches_parallel: self.batches_parallel.load(Relaxed),
            batches_serial: self.batches_serial.load(Relaxed),
            breaker_trips: self.breaker_trips.load(Relaxed),
            verify_nanos: self.verify_nanos.load(Relaxed),
        }
    }
}

/// A plain-data snapshot of [`SluiceMetrics`] with the usual derived ratios.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SluiceMetricsSnapshot {
    pub items_verified: u64,
    pub cache_hits: u64,
    pub cache_misses: u64,
    pub batches_parallel: u64,
    pub batches_serial: u64,
    pub breaker_trips: u64,
    pub verify_nanos: u64,
}

impl SluiceMetricsSnapshot {
    /// Cache hits / (hits + misses). `0.0` when nothing has been looked up.
    pub fn cache_hit_rate(&self) -> f64 {
        let total = self.cache_hits + self.cache_misses;
        if total == 0 {
            0.0
        } else {
            self.cache_hits as f64 / total as f64
        }
    }

    /// Fraction of batches that ran on the parallel pool (pool utilization).
    pub fn parallel_batch_rate(&self) -> f64 {
        let total = self.batches_parallel + self.batches_serial;
        if total == 0 {
            0.0
        } else {
            self.batches_parallel as f64 / total as f64
        }
    }

    /// Mean wall-clock nanoseconds per verified item. `0.0` when none verified.
    pub fn avg_verify_nanos(&self) -> f64 {
        if self.items_verified == 0 {
            0.0
        } else {
            self.verify_nanos as f64 / self.items_verified as f64
        }
    }
}

/// Determinism harness: assert the valve invariant for a path — serial and
/// every parallel width produce the IDENTICAL per-item Ok/Err pattern. Any path
/// wired to [`HeavyVerify`] should be covered by this so parallelizing it is
/// safe by construction.
#[cfg(test)]
pub fn assert_valve_invariant<V>(v: &V, items: &[V::Item], on_panic: impl Fn() -> V::Error + Sync + Copy)
where
    V: HeavyVerify,
{
    let baseline: Vec<bool> = Sluice::serial()
        .verify(v, items, on_panic)
        .iter()
        .map(|r| r.is_ok())
        .collect();
    for threads in [1usize, 2, 4, 8] {
        let got: Vec<bool> = Sluice::with_threads(threads)
            .verify(v, items, on_panic)
            .iter()
            .map(|r| r.is_ok())
            .collect();
        assert_eq!(
            baseline, got,
            "valve invariant violated at {threads} threads: result differs from serial"
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A toy path: an item is "valid" iff it is even. Pure, so it must verify
    /// identically at any valve width.
    struct EvenOnly;
    impl HeavyVerify for EvenOnly {
        type Item = u64;
        type Output = u64;
        type Error = ();
        fn verify_one(&self, item: &u64) -> Result<u64, ()> {
            if item % 2 == 0 {
                Ok(*item)
            } else {
                Err(())
            }
        }
    }

    #[test]
    fn valve_result_is_independent_of_width() {
        let items: Vec<u64> = (0..1000).collect();
        assert_valve_invariant(&EvenOnly, &items, || ());
    }

    #[test]
    fn serial_and_parallel_agree_on_order_and_values() {
        let items: Vec<u64> = (0..64).collect();
        let serial = Sluice::serial().verify(&EvenOnly, &items, || ());
        let par = Sluice::with_threads(4).verify(&EvenOnly, &items, || ());
        assert_eq!(serial.len(), par.len());
        for (s, p) in serial.iter().zip(par.iter()) {
            assert_eq!(s.as_ref().ok(), p.as_ref().ok(), "same value, same order");
        }
    }

    #[test]
    fn metrics_record_items_utilization_and_cache_rate() {
        use crate::crypto::verify_cache::LruVerifyCache;

        // A cacheable toy path (even = valid), keyed by the value.
        struct EvenCacheable;
        impl HeavyVerify for EvenCacheable {
            type Item = u64;
            type Output = ();
            type Error = ();
            fn verify_one(&self, item: &u64) -> Result<(), ()> {
                if item % 2 == 0 { Ok(()) } else { Err(()) }
            }
            fn cache_key(&self, item: &u64) -> Option<[u8; 32]> {
                let mut k = [0u8; 32];
                k[..8].copy_from_slice(&item.to_le_bytes());
                Some(k)
            }
        }

        let metrics = Arc::new(SluiceMetrics::new());
        let valve = Sluice::with_threads(4).with_metrics(Arc::clone(&metrics));
        let items: Vec<u64> = (0..100).collect(); // 50 even (valid), 50 odd

        // Plain verify: a parallel batch of 100 items, none cached.
        let _ = valve.verify(&EvenCacheable, &items, || ());
        let s = metrics.snapshot();
        assert_eq!(s.items_verified, 100);
        assert_eq!(s.batches_parallel, 1);
        assert_eq!(s.batches_serial, 0);
        assert_eq!(s.parallel_batch_rate(), 1.0);
        assert_eq!(s.breaker_trips, 0);

        // Cached cold pass: all 100 miss, 50 valid recorded.
        let cache = LruVerifyCache::default();
        let _ = valve.verify_valid_cached(&EvenCacheable, &items, &cache);
        // Cached warm pass: the 50 valid are hits; 50 odd miss (never cached).
        let _ = valve.verify_valid_cached(&EvenCacheable, &items, &cache);
        let s = metrics.snapshot();
        assert_eq!(s.cache_hits, 50, "warm pass: the 50 valid items are cache hits");
        assert_eq!(s.cache_misses, 150, "100 cold + 50 odd warm = 150 misses");
        assert!(s.cache_hit_rate() > 0.0 && s.avg_verify_nanos() >= 0.0);
    }

    #[test]
    fn circuit_breaker_falls_back_to_serial() {
        let valve = Sluice::with_threads(4);
        assert!(valve.parallel_enabled());
        valve.trip();
        assert!(!valve.parallel_enabled(), "tripped valve runs serial");
        // Still produces correct results after tripping.
        let items: Vec<u64> = (0..16).collect();
        let got = valve.verify(&EvenOnly, &items, || ());
        assert_eq!(got.iter().filter(|r| r.is_ok()).count(), 8);
    }
}
