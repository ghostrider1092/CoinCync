//! # Spark Pool Store — the libspark-FFI-aligned canonical shielded store
//!
//! This is the store the **audited libspark spend path** actually needs, and
//! the one `SparkBackend::verify_solvency` checks tags against. It holds, for
//! the chosen "one audited Spark pool" ([[coincync-strategy-narrow-shielded]]):
//!
//! 1. **Coins by outpoint.** Each minted Spark coin is stored as its full
//!    libspark serialization ([`spark_connector::CoinBytes`], which carries the
//!    on-wire `S, K, C`), keyed by its outpoint (`tx_hash ‖ vout`), together
//!    with the **deterministic serial context** derived from that outpoint
//!    (`spark_connector::ffi::serial_context`). Storing the context makes a
//!    coin recoverable/spendable later from its chain position alone.
//! 2. **Ordered cover set.** Coins are appended in a dense `cover_index` order,
//!    so [`cover_set`](SparkPoolStore::cover_set) yields the exact `&[CoinBytes]`
//!    a spender passes to `build_spend_over_set`.
//! 3. **Spent VRF-tag set.** The double-spend / unspent nullifier set, keyed on
//!    the **34-byte VRF linking tag** `T = (U−D)·s⁻¹` the spend proof reveals
//!    (not the 32-byte serial of the earlier native sketch).
//!    [`spent_tags`](SparkPoolStore::spent_tags) feeds `verify_solvency`, whose
//!    `T ∉ spent-set` check is what makes "I own an in-range coin" mean "…that
//!    is still unspent."
//!
//! ## Relationship to the other stores (honest note)
//! The tree accumulated three partial shielded designs: the Halo2/Orchard
//! [`shielded`](crate::storage::shielded) tree (BLAKE3 leaves; ZK spend never
//! implemented) and the native [`spark`](crate::storage::spark) `SparkStore`
//! (32-byte commitments + 32-byte serials, pre-FFI sketch). Neither matches the
//! libspark FFI's data shapes (variable-length `CoinBytes`, 34-byte VRF tags).
//! This store is the FFI-aligned one; retiring the other two under the one-pool
//! consolidation is follow-up migration, not done here.
//!
//! ## Status
//! Gated `sketch-gk-proof`, **in-memory**, and **unwired from consensus** — it
//! is inert scaffolding for the shielded-solvency path. RocksDB persistence
//! (mirroring [`SparkStore::open_with_db`](crate::storage::spark)) and the
//! chain.rs reorg wiring are deliberate follow-ups; the reorg API
//! ([`checkpoint_at_height`](SparkPoolStore::checkpoint_at_height) /
//! [`rewind`](SparkPoolStore::rewind)) is present so the shape matches the
//! sibling Phase-2 stores when that wiring lands.

use std::collections::HashMap;

use borsh::{BorshDeserialize, BorshSerialize};
use parking_lot::RwLock;
use spark_connector::{CoinBytes, Nullifier};

use crate::db::shim;
use crate::db::Database;
use crate::error::{Error, Result};

/// Bound on the reorg checkpoint stack — matches the sibling Phase-2 stores
/// (`ShieldedStore` / `SparkStore` use 1000, covering testnet max_reorg_depth).
const MAX_CHECKPOINTS: usize = 1000;

/// Borsh-serializable form of a [`SparkPoolCoin`] for RocksDB. `CoinBytes` /
/// `Nullifier` are the connector's plain byte wrappers (not Borsh), so the
/// persisted row uses plain `Vec<u8>` fields and converts at the boundary.
#[derive(Clone, Debug, BorshSerialize, BorshDeserialize)]
struct PersistedCoin {
    outpoint: Vec<u8>,
    coin: Vec<u8>,
    serial_context: Vec<u8>,
    height: u64,
    cover_index: u64,
}

/// Optional RocksDB-backed persistence: coins keyed by `cover_index` (BE), and
/// spent VRF tags keyed by the tag bytes.
struct SparkPoolPersistence {
    coins: shim::Tree,
    tags: shim::Tree,
    /// Small metadata CF: the running pool value survives restart (key
    /// `POOL_VALUE_KEY`, an i128 in little-endian).
    meta: shim::Tree,
}

/// Persistence key for the running pool value in the meta CF.
const POOL_VALUE_KEY: &[u8] = b"pool_value";

/// Persistence key for the reorg checkpoint stack in the meta CF. The stack is
/// stored as ONE borsh blob (≤ `MAX_CHECKPOINTS` small entries), rewritten on
/// every checkpoint/rewind, so a restarted node can rewind past its restart
/// point (a reorg deeper than the restart no longer strands Phase-2 state).
const CHECKPOINTS_KEY: &[u8] = b"checkpoints";

/// Borsh-serializable mirror of [`PoolCheckpoint`] (borsh has no `usize`, so
/// `coins_len` widens to `u64`).
#[derive(borsh::BorshSerialize, borsh::BorshDeserialize)]
struct PersistedCheckpoint {
    height: u64,
    coins_len: u64,
    pool_value: i128,
}

/// One coin in the pool: its libspark serialization plus the metadata needed to
/// re-derive its spend witness (the deterministic serial context) and to place
/// it in the cover set.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SparkPoolCoin {
    /// The coin's outpoint identity (`tx_hash ‖ vout`) — also the seed the
    /// deterministic serial context is derived from.
    pub outpoint: Vec<u8>,
    /// The full libspark-serialized `Coin` (carries `S, K, C`).
    pub coin: CoinBytes,
    /// The deterministic serial context bound into this coin (from the
    /// outpoint). Kept so a spender need not re-derive it.
    pub serial_context: Vec<u8>,
    /// Block height the coin was minted at.
    pub height: u64,
    /// Dense position in the ordered cover set.
    pub cover_index: u64,
}

/// One reorg checkpoint boundary — taken BEFORE a block applies. `coins_len` is
/// the cover-set length at the boundary (coins at index `>= coins_len` belong to
/// the block being guarded); `height` is that block (tags spent at or above it
/// are dropped on rewind).
#[derive(Clone, Copy, Debug)]
struct PoolCheckpoint {
    height: u64,
    coins_len: usize,
    /// Pool value (`Σ value_balance`) at the boundary, so a reorg restores the
    /// exact pre-block total.
    pool_value: i128,
}

/// The libspark-aligned Spark pool store. RocksDB-backed when opened via
/// [`SparkPoolStore::open_with_db`] (coins, spent tags, pool value, and the
/// reorg checkpoint stack all persist + replay); a plain `new()` is in-memory
/// (tests). See module docs for the gated/inert status.
pub struct SparkPoolStore {
    /// Ordered cover set — coins in `cover_index` order.
    coins: RwLock<Vec<SparkPoolCoin>>,
    /// `outpoint -> cover_index`, so a coin is locatable by its chain identity.
    by_outpoint: RwLock<HashMap<Vec<u8>, u64>>,
    /// Spent VRF-tag set: tag bytes -> spend height.
    spent_tags: RwLock<HashMap<Vec<u8>, u64>>,
    /// Reorg checkpoint stack (in lock-step with the block-apply path), capped
    /// at `MAX_CHECKPOINTS`. Persisted to the meta CF on every checkpoint/rewind
    /// and replayed on open, so a reorg past a restart can still rewind.
    checkpoints: RwLock<Vec<PoolCheckpoint>>,
    /// Maintained max coin/tag heights so the security guard is O(1) on the hot
    /// path (a per-block O(n) scan would itself be a DoS as the pool grows).
    /// Updated on add/mark; recomputed on the (rare) rewind.
    max_coin_height: RwLock<Option<u64>>,
    max_spent_tag_height: RwLock<Option<u64>>,
    /// The running shielded pool value: `Σ value_balance` applied, where a
    /// shield-in (`value_balance < 0`) grows it and an unshield-out shrinks it.
    /// The "no inflation across the veil" invariant is `pool_value >= 0` — you
    /// cannot unshield more than was ever shielded in. Persisted + reorg-aware.
    pool_value: RwLock<i128>,
    /// RocksDB-backed persistence. `None` for in-memory tests.
    persistence: Option<SparkPoolPersistence>,
}

impl SparkPoolStore {
    /// A fresh, empty in-memory pool store.
    pub fn new() -> Self {
        Self {
            coins: RwLock::new(Vec::new()),
            by_outpoint: RwLock::new(HashMap::new()),
            spent_tags: RwLock::new(HashMap::new()),
            checkpoints: RwLock::new(Vec::new()),
            max_coin_height: RwLock::new(None),
            max_spent_tag_height: RwLock::new(None),
            pool_value: RwLock::new(0),
            persistence: None,
        }
    }

    /// Open a persistent pool store. Replays coins by `cover_index`, loads spent
    /// VRF tags, the running pool value, AND the reorg checkpoint stack — so a
    /// reorg deeper than a node restart can still rewind the pool (restart-durable
    /// Phase-2 rewind) instead of stranding a disconnected block's state.
    pub fn open_with_db(database: &Database) -> Result<Self> {
        let coins_tree = database.open_tree("spark_pool_coins")?;
        let tags_tree = database.open_tree("spark_pool_tags")?;
        let meta_tree = database.open_tree("spark_pool_meta")?;

        // Collect + sort coins by cover_index (the BE-encoded key).
        let mut loaded: Vec<(u64, PersistedCoin)> = Vec::new();
        for item in coins_tree.iter() {
            let (key, value) =
                item.map_err(|e| Error::DatabaseError(format!("spark_pool coins iter: {}", e)))?;
            let key_bytes: [u8; 8] = key.as_ref().try_into().map_err(|_| {
                Error::DatabaseError("spark_pool_coins key must be 8 bytes".into())
            })?;
            let entry: PersistedCoin = borsh::from_slice(value.as_ref())
                .map_err(|e| Error::SerializationError(format!("spark_pool coin: {}", e)))?;
            loaded.push((u64::from_be_bytes(key_bytes), entry));
        }
        loaded.sort_by_key(|(id, _)| *id);

        let mut coins = Vec::with_capacity(loaded.len());
        let mut by_outpoint = HashMap::with_capacity(loaded.len());
        for (cover_index, p) in loaded {
            by_outpoint.insert(p.outpoint.clone(), cover_index);
            coins.push(SparkPoolCoin {
                outpoint: p.outpoint,
                coin: CoinBytes(p.coin),
                serial_context: p.serial_context,
                height: p.height,
                cover_index,
            });
        }

        let mut spent_tags = HashMap::new();
        for item in tags_tree.iter() {
            let (key, value) =
                item.map_err(|e| Error::DatabaseError(format!("spark_pool tags iter: {}", e)))?;
            let h_bytes: [u8; 8] = value.as_ref().try_into().map_err(|_| {
                Error::DatabaseError("spark_pool_tags value must be 8 bytes".into())
            })?;
            spent_tags.insert(key.as_ref().to_vec(), u64::from_le_bytes(h_bytes));
        }

        let max_coin_height = coins.iter().map(|c| c.height).max();
        let max_spent_tag_height = spent_tags.values().copied().max();

        // Restore the running pool value (i128 LE); default 0 if unset.
        let pool_value = meta_tree
            .get(POOL_VALUE_KEY)
            .ok()
            .flatten()
            .and_then(|v| <[u8; 16]>::try_from(v.as_ref()).ok())
            .map(i128::from_le_bytes)
            .unwrap_or(0);

        // Restore the reorg checkpoint stack (restart-durable rewind): a reorg
        // deeper than the restart can now roll the pool back instead of
        // stranding a disconnected block's state. Persisted + rewound in
        // lock-step with the coins/tags, so the (coins, stack) pair is
        // consistent. Empty (default) if never written.
        let checkpoints: Vec<PoolCheckpoint> = meta_tree
            .get(CHECKPOINTS_KEY)
            .ok()
            .flatten()
            .and_then(|v| borsh::from_slice::<Vec<PersistedCheckpoint>>(v.as_ref()).ok())
            .map(|persisted| {
                persisted
                    .into_iter()
                    .map(|p| PoolCheckpoint {
                        height: p.height,
                        coins_len: p.coins_len as usize,
                        pool_value: p.pool_value,
                    })
                    .collect()
            })
            .unwrap_or_default();

        Ok(Self {
            coins: RwLock::new(coins),
            by_outpoint: RwLock::new(by_outpoint),
            spent_tags: RwLock::new(spent_tags),
            checkpoints: RwLock::new(checkpoints),
            max_coin_height: RwLock::new(max_coin_height),
            max_spent_tag_height: RwLock::new(max_spent_tag_height),
            pool_value: RwLock::new(pool_value),
            persistence: Some(SparkPoolPersistence {
                coins: coins_tree,
                tags: tags_tree,
                meta: meta_tree,
            }),
        })
    }

    /// Append a minted coin at `outpoint` (with its libspark bytes, its
    /// deterministic serial context, and mint height). Returns the assigned
    /// dense `cover_index`, or `None` if `outpoint` is already present (a coin's
    /// outpoint is unique, so a duplicate is a caller bug / replay).
    pub fn add_coin(
        &self,
        outpoint: Vec<u8>,
        coin: CoinBytes,
        serial_context: Vec<u8>,
        height: u64,
    ) -> Option<u64> {
        let mut by_op = self.by_outpoint.write();
        if by_op.contains_key(&outpoint) {
            return None;
        }
        let mut coins = self.coins.write();
        let cover_index = coins.len() as u64;
        let entry = SparkPoolCoin {
            outpoint: outpoint.clone(),
            coin,
            serial_context,
            height,
            cover_index,
        };
        // R-61 CLASS site: a persistence failure on a consensus coin must halt,
        // not continue in-memory-only (would diverge the replayed store after
        // restart). Mirrors `SparkStore`/`ShieldedStore`.
        if let Some(p) = &self.persistence {
            let persisted = PersistedCoin {
                outpoint: entry.outpoint.clone(),
                coin: entry.coin.0.clone(),
                serial_context: entry.serial_context.clone(),
                height: entry.height,
                cover_index,
            };
            let value = borsh::to_vec(&persisted).unwrap_or_else(|e| {
                panic!("R-61: SparkPoolCoin borsh serialize failed at cover_index {cover_index}: {e}")
            });
            if let Err(e) = p.coins.insert(cover_index.to_be_bytes(), value) {
                panic!("R-61: spark_pool_coins write failed at cover_index {cover_index}: {e}");
            }
        }
        by_op.insert(outpoint, cover_index);
        coins.push(entry);
        // O(1) guard maintenance.
        let mut m = self.max_coin_height.write();
        *m = Some(m.map_or(height, |cur| cur.max(height)));
        Some(cover_index)
    }

    /// The ordered cover set as `CoinBytes` — exactly what a spender hands to
    /// `spark_connector::ffi::build_spend_over_set`.
    pub fn cover_set(&self) -> Vec<CoinBytes> {
        self.coins.read().iter().map(|c| c.coin.clone()).collect()
    }

    /// The cover set anchored at a pool snapshot: coins with `height <=
    /// anchor_height`, in `cover_index` order (canonical, so every node resolves
    /// the identical `{C_i}` a Grootle proof was built against). `cover_set_id`
    /// is reserved for multi-group buckets (cip-shielded-anonset); today the
    /// whole pool is one monotonic group, so it is accepted and ignored.
    pub fn cover_set_at(&self, _cover_set_id: u64, anchor_height: u64) -> Vec<CoinBytes> {
        self.coins
            .read()
            .iter()
            .filter(|c| c.height <= anchor_height)
            .map(|c| c.coin.clone())
            .collect()
    }

    /// Number of coins in the cover set.
    pub fn coin_count(&self) -> usize {
        self.coins.read().len()
    }

    /// The anchored cover set as `(outpoint, coin bytes, serial_context,
    /// height)` in canonical cover-index order — coins with `height <=
    /// anchor_height`. This is exactly the set [`cover_set_at`](Self::cover_set_at)
    /// resolves (same filter + order), enriched with each coin's serial context
    /// and outpoint so a REMOTE wallet (which lacks the store) can identify its
    /// owned coin and build a spend against the identical set the verifier will
    /// resolve. The position in this `Vec` is the coin's spend index for a proof
    /// anchored at `(cover_set_id, anchor_height)`. `cover_set_id` is reserved
    /// for multi-group buckets (accepted and ignored while the pool is one
    /// monotonic group — mirrors `cover_set_at`).
    pub fn cover_entries_at(
        &self,
        _cover_set_id: u64,
        anchor_height: u64,
    ) -> Vec<(Vec<u8>, Vec<u8>, Vec<u8>, u64)> {
        self.coins
            .read()
            .iter()
            .filter(|c| c.height <= anchor_height)
            .map(|c| {
                (
                    c.outpoint.clone(),
                    c.coin.0.clone(),
                    c.serial_context.clone(),
                    c.height,
                )
            })
            .collect()
    }

    /// Every pool coin as `(outpoint, coin bytes, serial_context, height)` in
    /// cover-set order — what a wallet scan needs to test ownership (via
    /// `SparkBackend::identify` on the coin bytes) and, for owned coins, key the
    /// note by its outpoint + recover its serial context for a later spend.
    pub fn coin_entries(&self) -> Vec<(Vec<u8>, CoinBytes, Vec<u8>, u64)> {
        self.coins
            .read()
            .iter()
            .map(|c| (c.outpoint.clone(), c.coin.clone(), c.serial_context.clone(), c.height))
            .collect()
    }

    /// The cover-set index of the coin at `outpoint`, if present.
    pub fn index_of(&self, outpoint: &[u8]) -> Option<u64> {
        self.by_outpoint.read().get(outpoint).copied()
    }

    /// The coin at a cover-set index, if present.
    pub fn coin_at(&self, cover_index: u64) -> Option<SparkPoolCoin> {
        self.coins.read().get(cover_index as usize).cloned()
    }

    /// The deterministic serial context stored for the coin at `outpoint`.
    pub fn context_for(&self, outpoint: &[u8]) -> Option<Vec<u8>> {
        let idx = *self.by_outpoint.read().get(outpoint)?;
        self.coins
            .read()
            .get(idx as usize)
            .map(|c| c.serial_context.clone())
    }

    /// Mark a VRF linking tag spent at `height`. Returns `false` if the tag was
    /// already spent (double-spend / not-unspent).
    pub fn mark_tag_spent(&self, tag: &Nullifier, height: u64) -> bool {
        let mut tags = self.spent_tags.write();
        if tags.contains_key(&tag.0) {
            return false;
        }
        // R-61 CLASS site: halt on a persistence failure for a consensus tag.
        if let Some(p) = &self.persistence {
            if let Err(e) = p.tags.insert(&tag.0, height.to_le_bytes()) {
                panic!("R-61: spark_pool_tags write failed at height {height}: {e}");
            }
        }
        tags.insert(tag.0.clone(), height);
        // O(1) guard maintenance.
        let mut m = self.max_spent_tag_height.write();
        *m = Some(m.map_or(height, |cur| cur.max(height)));
        true
    }

    /// Whether a VRF linking tag has been spent.
    pub fn is_tag_spent(&self, tag: &Nullifier) -> bool {
        self.spent_tags.read().contains_key(&tag.0)
    }

    /// The height a tag was spent at, if spent. (Read-only; used by the pool
    /// security service for forensic investigation.)
    pub fn spent_tag_height(&self, tag: &Nullifier) -> Option<u64> {
        self.spent_tags.read().get(&tag.0).copied()
    }

    /// Number of spent tags.
    pub fn spent_tag_count(&self) -> usize {
        self.spent_tags.read().len()
    }

    /// The highest block height any coin was minted at (`None` if empty). O(1):
    /// a maintained field, so the security guard never scans the pool.
    pub fn max_coin_height(&self) -> Option<u64> {
        *self.max_coin_height.read()
    }

    /// The highest block height any tag was spent at (`None` if none spent).
    /// O(1) maintained field.
    pub fn max_spent_tag_height(&self) -> Option<u64> {
        *self.max_spent_tag_height.read()
    }

    /// How many coins were minted at `height` or later — a velocity signal for
    /// the surveillance scan.
    pub fn coins_at_or_after(&self, height: u64) -> usize {
        self.coins.read().iter().filter(|c| c.height >= height).count()
    }

    /// Apply one shielded tx's `value_balance` to the running pool total: a
    /// shield-in (`value_balance < 0`) grows it, an unshield-out (`> 0`) shrinks
    /// it. Returns `Err` (and leaves the total unchanged) if it would drive the
    /// pool NEGATIVE — an attempt to unshield more than was ever shielded in
    /// ("no inflation across the veil"). Persists the new total. Reorg-safe: a
    /// checkpoint snapshots the pre-block total and `rewind` restores it.
    pub fn apply_value_balance(&self, value_balance: i64) -> Result<()> {
        let mut pv = self.pool_value.write();
        // total_after = total − value_balance (value_balance > 0 removes value).
        let after = *pv - value_balance as i128;
        if after < 0 {
            return Err(Error::InvalidTransaction(format!(
                "shielded pool underflow: pool {} − value_balance {} = {} < 0 \
                 (cannot unshield more than the pool holds)",
                *pv, value_balance, after
            )));
        }
        *pv = after;
        if let Some(p) = &self.persistence {
            let _ = p.meta.insert(POOL_VALUE_KEY, after.to_le_bytes());
        }
        Ok(())
    }

    /// The current shielded pool value (`Σ value_balance`). The invariant is
    /// `>= 0`; the security detail guards it.
    pub fn pool_value(&self) -> i128 {
        *self.pool_value.read()
    }

    /// A snapshot of the spent VRF-tag set — passed straight to
    /// `SparkBackend::verify_solvency` as the `spent_tags` the proof's revealed
    /// tag must NOT be in.
    pub fn spent_tags(&self) -> Vec<Nullifier> {
        self.spent_tags
            .read()
            .keys()
            .cloned()
            .map(Nullifier)
            .collect()
    }

    /// Mark a reorg checkpoint for the block at `height`, taken BEFORE its coins
    /// and tags are applied. Capped at `MAX_CHECKPOINTS` (oldest dropped past
    /// the cap), matching the sibling stores.
    pub fn checkpoint_at_height(&self, height: u64) {
        let coins_len = self.coins.read().len();
        let pool_value = *self.pool_value.read();
        let snapshot = {
            let mut cps = self.checkpoints.write();
            cps.push(PoolCheckpoint { height, coins_len, pool_value });
            if cps.len() > MAX_CHECKPOINTS {
                cps.remove(0);
            }
            cps.clone()
        };
        // Mirror the stack to disk so a reorg deeper than a node restart can
        // still rewind (restart-durable Phase-2 rewind).
        self.persist_checkpoints(&snapshot);
    }

    /// Persist the current in-memory checkpoint stack to the meta CF (one borsh
    /// blob under `CHECKPOINTS_KEY`). Best-effort: a serialize/write failure is
    /// logged, not fatal — the in-memory stack stays authoritative for the
    /// running session, and the next successful checkpoint rewrites the blob.
    fn persist_checkpoints(&self, cps: &[PoolCheckpoint]) {
        let Some(p) = &self.persistence else {
            return;
        };
        let persisted: Vec<PersistedCheckpoint> = cps
            .iter()
            .map(|c| PersistedCheckpoint {
                height: c.height,
                coins_len: c.coins_len as u64,
                pool_value: c.pool_value,
            })
            .collect();
        match borsh::to_vec(&persisted) {
            Ok(bytes) => {
                let _ = p.meta.insert(CHECKPOINTS_KEY, bytes);
            }
            Err(e) => {
                tracing::error!(
                    target: "storage::spark_pool",
                    error = %e,
                    "failed to serialize Spark pool checkpoint stack for persistence"
                );
            }
        }
    }

    /// Number of reorg checkpoints currently held.
    pub fn checkpoint_count(&self) -> usize {
        self.checkpoints.read().len()
    }

    /// A blake3 accumulator root over the ordered coin serializations. This is a
    /// diagnostic / lock-step quantity for the [`Phase2Store`] seam — the store
    /// is not (yet) a consensus commitment, so this root is not anchored into
    /// block headers.
    pub fn current_root(&self) -> [u8; 32] {
        let coins = self.coins.read();
        let mut h = blake3::Hasher::new();
        h.update(b"COINCYNC_SPARK_POOL_ROOT_v1");
        for c in coins.iter() {
            h.update(&(c.coin.0.len() as u64).to_le_bytes());
            h.update(&c.coin.0);
        }
        *h.finalize().as_bytes()
    }

    /// Rewind one checkpoint — disconnect the most recently applied block:
    /// truncate the cover set to the checkpoint's `coins_len` (dropping the
    /// disconnected block's coins and their `by_outpoint` entries) and drop
    /// every tag spent at `height >= restore.height`. Returns `false` if the
    /// checkpoint stack was empty.
    pub fn rewind(&self) -> bool {
        let restore = match self.checkpoints.write().pop() {
            Some(cp) => cp,
            None => return false,
        };

        // Drop coins at or past the boundary, and their outpoint index entries.
        let removed_indices: Vec<u64> = {
            let mut coins = self.coins.write();
            let mut by_op = self.by_outpoint.write();
            let removed: Vec<u64> = (restore.coins_len as u64..coins.len() as u64).collect();
            for c in coins.iter().skip(restore.coins_len) {
                by_op.remove(&c.outpoint);
            }
            coins.truncate(restore.coins_len);
            removed
        };

        // Drop tags spent at or after the disconnected block's height.
        let removed_tags: Vec<Vec<u8>> = {
            let mut tags = self.spent_tags.write();
            let drop: Vec<Vec<u8>> = tags
                .iter()
                .filter(|(_, &h)| h >= restore.height)
                .map(|(t, _)| t.clone())
                .collect();
            for t in &drop {
                tags.remove(t);
            }
            drop
        };

        // Clean persistence so a future `open_with_db` replay reconstructs the
        // rewound state instead of resurrecting the disconnected block.
        if let Some(p) = &self.persistence {
            for idx in &removed_indices {
                let _ = p.coins.remove(idx.to_be_bytes());
            }
            for t in &removed_tags {
                let _ = p.tags.remove(t.as_slice());
            }
        }

        // Recompute the O(1) guard maxes from the surviving state (rewind is
        // rare, so an O(n) recompute here is fine; the hot path stays O(1)).
        *self.max_coin_height.write() = self.coins.read().iter().map(|c| c.height).max();
        *self.max_spent_tag_height.write() = self.spent_tags.read().values().copied().max();

        // Restore the pool value to the disconnected block's pre-apply boundary
        // and mirror it to disk, so a reorg (and a later replay) is exact.
        *self.pool_value.write() = restore.pool_value;
        if let Some(p) = &self.persistence {
            let _ = p.meta.insert(POOL_VALUE_KEY, restore.pool_value.to_le_bytes());
        }
        // Mirror the now-shorter checkpoint stack so a replay reconstructs the
        // rewound depth (restart-durable rewind).
        let remaining = self.checkpoints.read().clone();
        self.persist_checkpoints(&remaining);
        true
    }
}

impl Default for SparkPoolStore {
    fn default() -> Self {
        Self::new()
    }
}

/// The libspark-aligned pool store is a first-class Phase-2 store: it takes a
/// reorg checkpoint before each block and rewinds one block at a time, in
/// lock-step with `ShieldedStore` / `SparkStore` / `KernelStore` through the
/// unified [`Phase2Store`](crate::storage::phase2::Phase2Store) seam. (Inherent
/// methods win resolution, so the forwards below call the store's own methods,
/// never these trait methods.)
impl crate::storage::phase2::Phase2Store for SparkPoolStore {
    fn store_label(&self) -> &'static str {
        "spark_pool"
    }
    fn checkpoint_at_height(&self, height: u64) {
        self.checkpoint_at_height(height)
    }
    fn checkpoint_count(&self) -> usize {
        self.checkpoint_count()
    }
    fn rewind(&self) -> bool {
        self.rewind()
    }
    fn element_count(&self) -> usize {
        self.coin_count()
    }
    fn current_root(&self) -> [u8; 32] {
        self.current_root()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn coin(tag: u8) -> CoinBytes {
        CoinBytes(vec![tag; 40])
    }
    fn nf(tag: u8) -> Nullifier {
        Nullifier(vec![tag; 34])
    }

    #[test]
    fn add_coins_dense_cover_set_and_lookup_round_trip() {
        let s = SparkPoolStore::new();
        let i0 = s.add_coin(b"tx1:0".to_vec(), coin(1), b"ctx1".to_vec(), 10).unwrap();
        let i1 = s.add_coin(b"tx1:1".to_vec(), coin(2), b"ctx2".to_vec(), 10).unwrap();
        assert_eq!((i0, i1), (0, 1));
        assert_eq!(s.coin_count(), 2);
        assert_eq!(s.cover_set(), vec![coin(1), coin(2)]);
        assert_eq!(s.index_of(b"tx1:1"), Some(1));
        assert_eq!(s.context_for(b"tx1:1").as_deref(), Some(&b"ctx2"[..]));
        assert_eq!(s.coin_at(0).unwrap().outpoint, b"tx1:0");
        assert!(s.index_of(b"nope").is_none());
    }

    #[test]
    fn cover_entries_at_filters_by_height_and_preserves_cover_order() {
        let s = SparkPoolStore::new();
        s.add_coin(b"op:0".to_vec(), coin(1), b"ctx-a".to_vec(), 5).unwrap();
        s.add_coin(b"op:1".to_vec(), coin(2), b"ctx-b".to_vec(), 10).unwrap();
        s.add_coin(b"op:2".to_vec(), coin(3), b"ctx-c".to_vec(), 15).unwrap();

        // Anchor at height 10 → only the first two coins, in cover order.
        let e = s.cover_entries_at(0, 10);
        assert_eq!(e.len(), 2, "coin at height 15 is excluded");
        assert_eq!(e[0].0, b"op:0");
        assert_eq!(e[0].1, coin(1).0, "coin bytes");
        assert_eq!(e[0].2, b"ctx-a", "serial context");
        assert_eq!(e[0].3, 5, "height");
        assert_eq!(e[1].0, b"op:1");
        // The same set + order cover_set_at resolves (what the verifier uses).
        let cs = s.cover_set_at(0, 10);
        assert_eq!(cs, vec![coin(1), coin(2)]);
        assert_eq!(e.iter().map(|x| x.1.clone()).collect::<Vec<_>>(), vec![coin(1).0, coin(2).0]);

        // Anchor above every coin → the full set.
        assert_eq!(s.cover_entries_at(0, 100).len(), 3);
        // Anchor below every coin → empty.
        assert!(s.cover_entries_at(0, 1).is_empty());
    }

    #[test]
    fn duplicate_outpoint_is_rejected() {
        let s = SparkPoolStore::new();
        assert_eq!(s.add_coin(b"tx:0".to_vec(), coin(1), b"c".to_vec(), 1), Some(0));
        assert!(
            s.add_coin(b"tx:0".to_vec(), coin(9), b"c".to_vec(), 1).is_none(),
            "same outpoint must not be added twice"
        );
        assert_eq!(s.coin_count(), 1);
    }

    #[test]
    fn tag_spent_set_and_double_spend() {
        let s = SparkPoolStore::new();
        assert!(!s.is_tag_spent(&nf(7)));
        assert!(s.mark_tag_spent(&nf(7), 5));
        assert!(s.is_tag_spent(&nf(7)));
        assert!(!s.mark_tag_spent(&nf(7), 6), "second spend of a tag is a double-spend");
        assert_eq!(s.spent_tags(), vec![nf(7)]);
    }

    #[test]
    fn checkpoint_and_rewind_disconnects_a_block() {
        let s = SparkPoolStore::new();
        // Block 1: one coin + one spent tag.
        s.checkpoint_at_height(1);
        s.add_coin(b"b1:0".to_vec(), coin(1), b"c1".to_vec(), 1);
        s.mark_tag_spent(&nf(0x11), 1);

        // Block 2: two coins + one spent tag.
        s.checkpoint_at_height(2);
        s.add_coin(b"b2:0".to_vec(), coin(2), b"c2".to_vec(), 2);
        s.add_coin(b"b2:1".to_vec(), coin(3), b"c3".to_vec(), 2);
        s.mark_tag_spent(&nf(0x22), 2);
        assert_eq!(s.coin_count(), 3);

        // Disconnect block 2.
        assert!(s.rewind());
        assert_eq!(s.coin_count(), 1, "block-2 coins dropped");
        assert!(s.index_of(b"b2:0").is_none(), "block-2 outpoint index dropped");
        assert!(s.index_of(b"b1:0").is_some(), "block-1 coin kept");
        assert!(!s.is_tag_spent(&nf(0x22)), "block-2 tag dropped");
        assert!(s.is_tag_spent(&nf(0x11)), "block-1 tag kept");

        // Disconnect block 1 → empty; stack exhausted.
        assert!(s.rewind());
        assert_eq!(s.coin_count(), 0);
        assert!(!s.is_tag_spent(&nf(0x11)));
        assert!(!s.rewind(), "empty checkpoint stack → false");
    }

    #[test]
    fn spent_tags_feeds_verify_solvency_shape() {
        // The store's spent_tags() is exactly the `&[Nullifier]` type
        // SparkBackend::verify_solvency takes — this is the wiring contract.
        let s = SparkPoolStore::new();
        s.mark_tag_spent(&nf(0xAB), 3);
        let tags: Vec<Nullifier> = s.spent_tags();
        // A tag in the set is "already spent"; one not in it is unspent.
        assert!(tags.contains(&nf(0xAB)));
        assert!(!tags.contains(&nf(0xCD)));
    }

    #[test]
    fn pool_value_shield_unshield_and_underflow() {
        let s = SparkPoolStore::new();
        assert_eq!(s.pool_value(), 0);
        // Shield 100 in (value_balance = -100) → pool 100.
        s.apply_value_balance(-100).unwrap();
        assert_eq!(s.pool_value(), 100);
        // Unshield 40 out → pool 60.
        s.apply_value_balance(40).unwrap();
        assert_eq!(s.pool_value(), 60);
        // Unshield 100 (more than held) → rejected, pool unchanged.
        assert!(s.apply_value_balance(100).is_err(), "cannot unshield more than the pool holds");
        assert_eq!(s.pool_value(), 60, "rejected apply leaves the total unchanged");
    }

    #[test]
    fn pool_value_rewinds_with_reorg() {
        let s = SparkPoolStore::new();
        s.checkpoint_at_height(1);
        s.apply_value_balance(-100).unwrap(); // block 1 shields 100 → pool 100
        s.checkpoint_at_height(2);
        s.apply_value_balance(-50).unwrap(); // block 2 shields 50 → pool 150
        assert_eq!(s.pool_value(), 150);
        // Disconnect block 2 → pool back to its pre-block-2 boundary (100).
        assert!(s.rewind());
        assert_eq!(s.pool_value(), 100);
        // Disconnect block 1 → back to 0.
        assert!(s.rewind());
        assert_eq!(s.pool_value(), 0);
    }

    #[test]
    fn pool_value_persists_across_reopen() {
        use crate::db::Database;
        let dir = tempfile::tempdir().unwrap();
        let db = std::sync::Arc::new(Database::open(dir.path()).unwrap());
        {
            let s = SparkPoolStore::open_with_db(&db).unwrap();
            s.apply_value_balance(-250).unwrap(); // shield 250 in
            assert_eq!(s.pool_value(), 250);
        }
        // Reopen: the pool value replays from the meta CF.
        let re = SparkPoolStore::open_with_db(&db).unwrap();
        assert_eq!(re.pool_value(), 250, "pool value survives restart");
    }

    #[test]
    fn checkpoint_stack_survives_restart_so_reorg_past_restart_rewinds() {
        use crate::db::Database;
        let dir = tempfile::tempdir().unwrap();
        let db = std::sync::Arc::new(Database::open(dir.path()).unwrap());

        // Session 1: apply two checkpointed blocks (coin + shield-in each).
        {
            let s = SparkPoolStore::open_with_db(&db).unwrap();
            s.checkpoint_at_height(1); // captures pool_value 0
            s.add_coin(b"b1:0".to_vec(), coin(1), b"c".to_vec(), 1);
            s.apply_value_balance(-100).unwrap(); // pool 100
            s.checkpoint_at_height(2); // captures pool_value 100
            s.add_coin(b"b2:0".to_vec(), coin(2), b"c".to_vec(), 2);
            s.apply_value_balance(-50).unwrap(); // pool 150
            assert_eq!((s.coin_count(), s.pool_value(), s.checkpoint_count()), (2, 150, 2));
        }

        // Session 2 (RESTART): the checkpoint stack replays — a reorg DEEPER than
        // the restart can now rewind (previously the stack was empty on open, so
        // the disconnected block's state was stranded).
        let re = SparkPoolStore::open_with_db(&db).unwrap();
        assert_eq!(re.checkpoint_count(), 2, "checkpoint stack survived the restart");

        // Disconnect block 2 (reorg past the restart) → exact rollback.
        assert!(re.rewind(), "reorg past restart must rewind");
        assert_eq!(re.coin_count(), 1, "block 2's coin dropped");
        assert_eq!(re.pool_value(), 100, "pool value restored to pre-block-2");
        assert_eq!(re.checkpoint_count(), 1);
        // Disconnect block 1 too.
        assert!(re.rewind());
        assert_eq!((re.coin_count(), re.pool_value(), re.checkpoint_count()), (0, 0, 0));
        assert!(!re.rewind(), "stack exhausted");

        // Session 3: the rewound-to-empty state persists (no resurrection).
        let re2 = SparkPoolStore::open_with_db(&db).unwrap();
        assert_eq!((re2.checkpoint_count(), re2.coin_count(), re2.pool_value()), (0, 0, 0));
    }

    #[test]
    fn persist_and_replay_roundtrips() {
        use crate::db::Database;
        let dir = tempfile::tempdir().unwrap();
        let db = std::sync::Arc::new(Database::open(dir.path()).unwrap());

        // Session 1: two coins, one spent tag.
        {
            let s = SparkPoolStore::open_with_db(&db).unwrap();
            s.add_coin(b"op:0".to_vec(), coin(1), b"ctx0".to_vec(), 1);
            s.add_coin(b"op:1".to_vec(), coin(2), b"ctx1".to_vec(), 1);
            assert!(s.mark_tag_spent(&nf(0x55), 2));
        }

        // Session 2: reopen — coins (order + context) and the tag replay.
        let s2 = SparkPoolStore::open_with_db(&db).unwrap();
        assert_eq!(s2.coin_count(), 2);
        assert_eq!(s2.cover_set(), vec![coin(1), coin(2)]);
        assert_eq!(s2.index_of(b"op:1"), Some(1));
        assert_eq!(s2.context_for(b"op:1").as_deref(), Some(&b"ctx1"[..]));
        assert!(s2.is_tag_spent(&nf(0x55)));
        // A fresh append continues the dense index.
        assert_eq!(s2.add_coin(b"op:2".to_vec(), coin(3), b"ctx2".to_vec(), 3), Some(2));
    }

    #[test]
    fn rewind_cleans_persistence_so_replay_matches() {
        use crate::db::Database;
        let dir = tempfile::tempdir().unwrap();
        let db = std::sync::Arc::new(Database::open(dir.path()).unwrap());

        let (count_after_1, tags_after_1) = {
            let s = SparkPoolStore::open_with_db(&db).unwrap();
            s.checkpoint_at_height(1);
            s.add_coin(b"b1:0".to_vec(), coin(1), b"c".to_vec(), 1);
            s.mark_tag_spent(&nf(0x11), 1);
            let snap = (s.coin_count(), s.spent_tags().len());

            // Block 2, then reorged out.
            s.checkpoint_at_height(2);
            s.add_coin(b"b2:0".to_vec(), coin(2), b"c".to_vec(), 2);
            s.mark_tag_spent(&nf(0x22), 2);
            assert!(s.rewind());
            assert_eq!(s.coin_count(), snap.0);
            assert!(!s.is_tag_spent(&nf(0x22)));
            snap
        };

        // Reopen: replay must NOT resurrect block 2's coin or tag.
        let re = SparkPoolStore::open_with_db(&db).unwrap();
        assert_eq!(re.coin_count(), count_after_1);
        assert_eq!(re.spent_tags().len(), tags_after_1);
        assert!(re.is_tag_spent(&nf(0x11)), "block-1 tag survives");
        assert!(!re.is_tag_spent(&nf(0x22)), "reorged block-2 tag not resurrected");
        assert!(re.index_of(b"b2:0").is_none(), "reorged coin not resurrected");
    }

    #[test]
    fn satisfies_phase2_seam_and_rewinds_in_lockstep() {
        // SparkPoolStore, driven ONLY through the Phase2Store seam + shared
        // drivers, must checkpoint/rewind together with the three existing
        // Phase-2 stores — the reorg lock-step contract a fourth store must
        // satisfy before it can be wired into chain.rs.
        use crate::storage::phase2::{checkpoint_all, rewind_all, Phase2Store, RewindOutcome};
        use crate::storage::{KernelStore, ShieldedStore, SparkStore};

        let shielded = ShieldedStore::new();
        let spark = SparkStore::new();
        let kernel = KernelStore::new();
        let pool = SparkPoolStore::new();
        let stores: [&dyn Phase2Store; 4] = [&shielded, &spark, &kernel, &pool];

        for h in 1..=5u64 {
            assert_eq!(checkpoint_all(&stores, h).unwrap(), h as usize, "lock-step at {h}");
        }
        for _ in 0..5 {
            for (label, outcome) in rewind_all(&stores) {
                assert!(
                    matches!(outcome, RewindOutcome::RolledBack | RewindOutcome::EmptyNoop),
                    "{label} failed to roll back cleanly"
                );
            }
        }
        assert_eq!(pool.checkpoint_count(), 0, "pool drained in lock-step");
    }

    // End-to-end over the REAL libspark backend: mint coins into the store,
    // build a spend over the store's cover set, and run the unspent-solvency
    // check against the store's spent-tag set — the full Route-B loop. Needs the
    // C++ FFI, so it only compiles/runs with `libspark-ffi` on.
    #[cfg(feature = "libspark-ffi")]
    #[test]
    fn end_to_end_store_drives_spend_and_unspent_check() {
        use spark_connector::ffi::{
            build_spend_over_set, cover_set_size, mint_to_seed, serial_context, LibsparkBackend,
        };
        use spark_connector::SparkBackend;

        let store = SparkPoolStore::new();
        let seed = b"treasury-e2e-seed";
        let n = cover_set_size().expect("cover set size");

        // Mint N coins into the store, each keyed by a synthetic outpoint whose
        // deterministic serial context we store alongside the coin.
        for i in 0..n {
            let outpoint = format!("e2e:tx:{i}").into_bytes();
            let ctx = serial_context(&outpoint).expect("ctx");
            let coin = mint_to_seed(seed, 10_000 + i as u64, &ctx).expect("mint");
            store.add_coin(outpoint, coin, ctx, 1).expect("store coin");
        }
        assert_eq!(store.coin_count(), n);

        // Build a spend over the STORE's cover set, spending the coin at index 3.
        let spend_index = 3usize;
        let owned_outpoint = format!("e2e:tx:{spend_index}").into_bytes();
        let ctx = store.context_for(&owned_outpoint).expect("stored ctx");
        let cover = store.cover_set();
        let spend = build_spend_over_set(seed, &cover, spend_index, &ctx, 4_000)
            .expect("build spend over store cover set");

        let backend = LibsparkBackend;
        // Unspent: the store's (empty) spent-tag set → solvency holds.
        let tags = backend
            .verify_solvency(&[], &spend, 0, 0, &store.spent_tags())
            .expect("unspent coin proves solvency");
        assert_eq!(tags.len(), 1);

        // Record the tag as spent in the store; the SAME proof is now rejected.
        assert!(store.mark_tag_spent(&tags[0], 5));
        assert!(
            backend
                .verify_solvency(&[], &spend, 0, 0, &store.spent_tags())
                .is_err(),
            "once the store marks the tag spent, the coin is no longer unspent"
        );
    }
}
