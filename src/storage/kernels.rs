//! # MW Kernel Store
//!
//! Persistent storage for MimbleWimble kernels that survive cut-through
//! pruning. The input/output pairs are deleted after `MW_CUTTHROUGH_DEPTH`
//! confirmations, but the kernel stays so the chain's balance proof
//! remains verifiable.
//!
//! When constructed via [`KernelStore::open_with_db`] each appended
//! kernel is written through to the `mw_kernels` column family, keyed
//! on a monotonic index. On startup the in-memory vector and root are
//! rebuilt by replaying the stored kernels in key order.

use parking_lot::RwLock;

use crate::crypto::mw_cutthrough::MwKernel;
use crate::db::shim;
use crate::db::Database;
use crate::error::{Error, Result};

struct KernelPersistence {
    kernels: shim::Tree,
}

pub struct KernelStore {
    kernels: RwLock<Vec<MwKernel>>,
    root: RwLock<[u8; 32]>,
    persistence: Option<KernelPersistence>,
}

impl KernelStore {
    /// Create a fresh in-memory store (tests, standalone chains).
    pub fn new() -> Self {
        Self {
            kernels: RwLock::new(Vec::new()),
            root: RwLock::new([0u8; 32]),
            persistence: None,
        }
    }

    /// Open a persistent kernel store. Replays stored kernels in key
    /// order (BE u64 index) and recomputes the root from the loaded
    /// vector.
    pub fn open_with_db(database: &Database) -> Result<Self> {
        let kernels_tree = database.open_tree("mw_kernels")?;

        let mut loaded: Vec<(u64, MwKernel)> = Vec::new();
        for item in kernels_tree.iter() {
            let (key, value) = item
                .map_err(|e| Error::DatabaseError(format!("mw_kernels iter: {}", e)))?;
            let key_bytes: [u8; 8] = key
                .as_ref()
                .try_into()
                .map_err(|_| Error::DatabaseError("mw_kernels key must be 8 bytes".into()))?;
            let idx = u64::from_be_bytes(key_bytes);
            let kernel: MwKernel = borsh::from_slice(value.as_ref())
                .map_err(|e| Error::SerializationError(format!("mw kernel: {}", e)))?;
            loaded.push((idx, kernel));
        }
        loaded.sort_by_key(|(i, _)| *i);
        let kernels: Vec<MwKernel> = loaded.into_iter().map(|(_, k)| k).collect();

        let mut h = blake3::Hasher::new();
        for k in &kernels {
            h.update(&k.excess);
            h.update(&k.height.to_le_bytes());
        }
        let root = *h.finalize().as_bytes();

        Ok(Self {
            kernels: RwLock::new(kernels),
            root: RwLock::new(root),
            persistence: Some(KernelPersistence {
                kernels: kernels_tree,
            }),
        })
    }

    /// Append a kernel that has survived cut-through pruning.
    pub fn append(&self, kernel: MwKernel) {
        let mut kernels = self.kernels.write();
        let idx = kernels.len() as u64;
        if let Some(p) = &self.persistence {
            let key = idx.to_be_bytes();
            let value = borsh::to_vec(&kernel)
                .expect("MwKernel borsh encoding is infallible");
            p.kernels
                .insert(key, value)
                .expect("mw_kernels write failed — consensus storage is dead");
        }
        kernels.push(kernel);
        let mut h = blake3::Hasher::new();
        for k in kernels.iter() {
            h.update(&k.excess);
            h.update(&k.height.to_le_bytes());
        }
        *self.root.write() = *h.finalize().as_bytes();
    }

    pub fn len(&self) -> usize {
        self.kernels.read().len()
    }

    pub fn is_empty(&self) -> bool {
        self.kernels.read().is_empty()
    }

    /// Current kernel-set root, committed in `BlockHeader::mw_kernel_root`.
    pub fn current_root(&self) -> [u8; 32] {
        *self.root.read()
    }
}

impl Default for KernelStore {
    fn default() -> Self {
        Self::new()
    }
}
