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

struct SeqPadCacheEntry {
    key: (Hash, u64, u64),
    anchor: Anchor,
    seq: usize,
}

struct SeqPadCache {
    entries: VecDeque<SeqPadCacheEntry>,
    index: std::collections::HashMap<(Hash, u64, u64), usize>,
    next_seq: usize,
}

impl SeqPadCache {
    fn new() -> Self {
        SeqPadCache {
            entries: VecDeque::new(),
            index: std::collections::HashMap::new(),
            next_seq: 0,
        }
    }

    fn get(&self, key: &(Hash, u64, u64)) -> Option<&Anchor> {
        self.index.get(key).and_then(|&seq| {
            self.entries.iter().find(|e| e.seq == seq).map(|e| &e.anchor)
        })
    }

    fn insert(&mut self, key: (Hash, u64, u64), anchor: Anchor) {
        if self.entries.len() >= SEQ_PAD_CACHE_MAX {
            if let Some(oldest) = self.entries.pop_front() {
                self.index.remove(&oldest.key);
            }
        }
        let seq = self.next_seq;
        self.next_seq = self.next_seq.wrapping_add(1);
        self.index.insert(key, seq);
        self.entries.push_back(SeqPadCacheEntry { key, anchor, seq });
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
    use parking_lot::Mutex;
    use std::sync::atomic::Ordering;

    struct SendSyncVm {
        key: [u8; 32],
        vm: RandomXVM,
    }

    // SAFETY: RandomX VM is thread-safe when each thread uses its own VM instance.
    // The VM_CACHE holds a single instance protected by a Mutex, ensuring exclusive
    // access. The RandomX C library documentation confirms that randomx_calculate_hash()
    // is safe to call from any thread as long as the VM is not shared concurrently.
    // The Mutex guarantees this invariant.
    #[allow(unsafe_code)]
    unsafe impl Send for SendSyncVm {}
    #[allow(unsafe_code)]
    unsafe impl Sync for SendSyncVm {}

    static VM_CACHE: Mutex<Option<SendSyncVm>> = Mutex::new(None);

    use std::sync::atomic::AtomicU64;
    static RETRY_AFTER: AtomicU64 = AtomicU64::new(0);

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

        let mut guard = VM_CACHE.lock();

        let needs_new_vm = match &*guard {
            Some(cached) => cached.key != *seed,
            None => true,
        };

        if needs_new_vm {
            match create_vm(seed) {
                Ok(vm) => {
                    *guard = Some(SendSyncVm { key: *seed, vm });
                    RETRY_AFTER.store(0, Ordering::Relaxed);
                }
                Err(e) => {
                    RETRY_AFTER.store(now_secs + 60, Ordering::Relaxed);
                    return Err(e);
                }
            }
        }

        let cached = guard.as_ref().ok_or_else(|| {
            crate::error::Error::Internal("RandomX VM not initialized after successful creation".into())
        })?;
        let hash = cached.vm.calculate_hash(input)
            .map_err(|e| crate::error::Error::Internal(format!("RandomX hash failed: {}", e)))?;

        let mut output = [0u8; 32];
        output.copy_from_slice(&hash[..32]);
        Ok(output)
    }

    fn create_vm(seed: &[u8; 32]) -> std::result::Result<RandomXVM, crate::error::Error> {
        let start = std::time::Instant::now();

        let recommended = RandomXFlag::get_recommended_flags();

        // FLAG_FULL_MEM is not yet supported here — it requires a separate
        // RandomXDataset (2 GB) instead of the current Cache-only wiring,
        // and the library returns "No dataset and FLAG_FULL_MEM set" if
        // we just OR it into the flags. Strip it unconditionally until we
        // add dataset support. Light-mode RandomX with JIT + HARD_AES is
        // already fast enough for testnet mining (~500-2000 H/s on Intel
        // vCPUs vs the ~10 H/s pure-interpreted fallback).
        let active_flags = recommended & !RandomXFlag::FLAG_FULL_MEM;

        tracing::info!(
            "Creating RandomX VM: active={:?}, key={}...",
            active_flags,
            hex::encode(&seed[..4])
        );

        match try_create_vm(active_flags, seed) {
            Ok(vm) => {
                tracing::info!(
                    "RandomX VM created in {:.2}s (flags: {:?})",
                    start.elapsed().as_secs_f64(),
                    active_flags
                );
                return Ok(vm);
            }
            Err(e) => {
                tracing::warn!(
                    "RandomX init with {:?} failed: {}. Falling back.",
                    active_flags, e
                );
            }
        }

        // First fallback: keep JIT but drop everything else. Much faster
        // than FLAG_DEFAULT (interpreted), which does ~10-100x worse.
        let jit_only = RandomXFlag::FLAG_JIT;
        tracing::info!("Creating RandomX VM with JIT-only fallback...");
        match try_create_vm(jit_only, seed) {
            Ok(vm) => {
                tracing::info!(
                    "RandomX VM created in {:.2}s (JIT-only)",
                    start.elapsed().as_secs_f64()
                );
                return Ok(vm);
            }
            Err(e) => {
                tracing::warn!("JIT-only also failed: {}. Falling to interpreted.", e);
            }
        }

        tracing::info!("Creating RandomX VM with FLAG_DEFAULT (interpreted mode)...");
        match try_create_vm(RandomXFlag::FLAG_DEFAULT, seed) {
            Ok(vm) => {
                tracing::info!(
                    "RandomX VM created in {:.2}s (interpreted mode)",
                    start.elapsed().as_secs_f64()
                );
                Ok(vm)
            }
            Err(e) => {
                tracing::error!("RandomX VM creation failed with all flag combinations: {}", e);
                Err(crate::error::Error::Internal(format!(
                    "RandomX VM creation failed: {}",
                    e
                )))
            }
        }
    }

    fn try_create_vm(flags: RandomXFlag, seed: &[u8; 32]) -> std::result::Result<RandomXVM, String> {
        let cache = RandomXCache::new(flags, seed)
            .map_err(|e| format!("cache init: {}", e))?;

        // If FULL_MEM is requested, build the 2GB dataset from the cache.
        // This takes 30-60s but hashing is 5-10x faster afterward.
        let dataset = if flags.contains(RandomXFlag::FLAG_FULL_MEM) {
            tracing::info!("Building RandomX dataset (2 GB) — this takes 30-60s...");
            match RandomXDataset::new(flags, cache.clone(), 0) {
                Ok(ds) => {
                    tracing::info!("RandomX dataset built successfully");
                    Some(ds)
                }
                Err(e) => {
                    tracing::warn!("Dataset allocation failed: {} — falling back to light mode", e);
                    None
                }
            }
        } else {
            None
        };

        RandomXVM::new(flags, Some(cache), dataset)
            .map_err(|e| format!("VM init: {}", e))
    }

    #[allow(dead_code)]
    pub fn clear_cache() {
        let mut guard = VM_CACHE.lock();
        *guard = None;
    }
}

/// Derive a stable RandomX key from height, bound to the chain's genesis hash.
#[cfg(feature = "randomx")]
fn randomx_key_for_height(height: u64) -> [u8; 32] {
    use crate::primitives::hash_domain;
    let epoch = height / RANDOMX_KEY_EPOCH;
    let genesis_bytes: [u8; 32] = RANDOMX_GENESIS_BYTES.get().copied().unwrap_or_else(|| {
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

    let pow_hash = compute_pow_hash(anchor.algorithm, &anchor.mixed_hash, nonce, tx_root, height)?;

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

        assert!(cache.entries.len() <= SEQ_PAD_CACHE_MAX);

        let oldest_key = (Hash::from_bytes([0u8; 32]), 0u64, 0u64);
        assert!(cache.get(&oldest_key).is_none(), "oldest entry should be evicted");

        let newest_i = (SEQ_PAD_CACHE_MAX + 99) as u8;
        let newest_key = (Hash::from_bytes([newest_i; 32]), (SEQ_PAD_CACHE_MAX + 99) as u64, 0u64);
        assert!(cache.get(&newest_key).is_some(), "newest entry should be present");
    }
}
