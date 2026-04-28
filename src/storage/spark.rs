//! # Spark Store
//!
//! Persistent storage for the Lelantus Spark accumulator and the set of
//! spent serial tags. When constructed via [`SparkStore::open_with_db`]
//! each new coin and each spent serial is written through to two
//! RocksDB column families (`spark_coins`, `spark_serials`); on startup
//! the accumulator is rebuilt by replaying coins in `coin_id` order.

use borsh::{BorshDeserialize, BorshSerialize};
use parking_lot::RwLock;
use std::collections::HashMap;

use crate::db::shim;
use crate::db::Database;
use crate::error::{Error, Result};

/// An entry in the Spark accumulator: one minted coin.
#[derive(Clone, Debug, BorshSerialize, BorshDeserialize)]
pub struct SparkCoinEntry {
    pub coin_id: u64,
    pub commitment: [u8; 32],
    pub height: u64,
}

struct SparkPersistence {
    coins: shim::Tree,
    serials: shim::Tree,
}

/// Spark accumulator store with optional RocksDB persistence.
pub struct SparkStore {
    coins: RwLock<Vec<SparkCoinEntry>>,
    spent_serials: RwLock<HashMap<[u8; 32], u64>>,
    root: RwLock<[u8; 32]>,
    persistence: Option<SparkPersistence>,
}

impl SparkStore {
    /// Create a fresh in-memory store (tests, standalone chains).
    pub fn new() -> Self {
        Self {
            coins: RwLock::new(Vec::new()),
            spent_serials: RwLock::new(HashMap::new()),
            root: RwLock::new([0u8; 32]),
            persistence: None,
        }
    }

    /// Open a persistent Spark store. Replays coins by `coin_id` and
    /// loads spent serials from disk, then recomputes the accumulator
    /// root from the replayed coin vector.
    pub fn open_with_db(database: &Database) -> Result<Self> {
        let coins_tree = database.open_tree("spark_coins")?;
        let serials_tree = database.open_tree("spark_serials")?;

        // Collect coins, sort by coin_id (the BE-encoded key).
        let mut loaded: Vec<(u64, SparkCoinEntry)> = Vec::new();
        for item in coins_tree.iter() {
            let (key, value) = item
                .map_err(|e| Error::DatabaseError(format!("spark coins iter: {}", e)))?;
            let key_bytes: [u8; 8] = key
                .as_ref()
                .try_into()
                .map_err(|_| Error::DatabaseError("spark_coins key must be 8 bytes".into()))?;
            let coin_id = u64::from_be_bytes(key_bytes);
            let entry: SparkCoinEntry = borsh::from_slice(value.as_ref())
                .map_err(|e| Error::SerializationError(format!("spark coin: {}", e)))?;
            loaded.push((coin_id, entry));
        }
        loaded.sort_by_key(|(id, _)| *id);
        let coins: Vec<SparkCoinEntry> = loaded.into_iter().map(|(_, e)| e).collect();

        let mut spent = HashMap::new();
        for item in serials_tree.iter() {
            let (key, value) = item
                .map_err(|e| Error::DatabaseError(format!("spark serials iter: {}", e)))?;
            let nf: [u8; 32] = key.as_ref().try_into().map_err(|_| {
                Error::DatabaseError("spark_serials key must be 32 bytes".into())
            })?;
            let h_bytes: [u8; 8] = value.as_ref().try_into().map_err(|_| {
                Error::DatabaseError("spark_serials value must be 8 bytes".into())
            })?;
            spent.insert(nf, u64::from_le_bytes(h_bytes));
        }

        let mut h = blake3::Hasher::new();
        for c in &coins {
            h.update(&c.commitment);
        }
        let root = *h.finalize().as_bytes();

        Ok(Self {
            coins: RwLock::new(coins),
            spent_serials: RwLock::new(spent),
            root: RwLock::new(root),
            persistence: Some(SparkPersistence {
                coins: coins_tree,
                serials: serials_tree,
            }),
        })
    }

    /// Add a newly-minted Spark coin to the accumulator.
    pub fn add_coin(&self, entry: SparkCoinEntry) {
        if let Some(p) = &self.persistence {
            let key = entry.coin_id.to_be_bytes();
            let value = borsh::to_vec(&entry)
                .expect("SparkCoinEntry borsh encoding is infallible");
            p.coins
                .insert(key, value)
                .expect("spark_coins write failed — consensus storage is dead");
        }
        let mut coins = self.coins.write();
        coins.push(entry);
        // TODO (Phase 2): recompute via a real vector commitment.
        let mut h = blake3::Hasher::new();
        for c in coins.iter() {
            h.update(&c.commitment);
        }
        *self.root.write() = *h.finalize().as_bytes();
    }

    /// Record that a serial tag has been spent.
    pub fn mark_serial_spent(&self, serial: [u8; 32], height: u64) {
        self.spent_serials.write().insert(serial, height);
        if let Some(p) = &self.persistence {
            p.serials
                .insert(serial, height.to_le_bytes())
                .expect("spark_serials write failed — consensus storage is dead");
        }
    }

    /// Returns true if the serial has already been used to spend.
    pub fn is_serial_spent(&self, serial: &[u8; 32]) -> bool {
        self.spent_serials.read().contains_key(serial)
    }

    /// Current accumulator size (coin count).
    pub fn size(&self) -> usize {
        self.coins.read().len()
    }

    /// Current accumulator root, to be committed in `BlockHeader::spark_set_root`.
    pub fn current_root(&self) -> [u8; 32] {
        *self.root.read()
    }
}

impl Default for SparkStore {
    fn default() -> Self {
        Self::new()
    }
}
