//! # CoinCync Prelude
//!
//! Common types and traits for convenient imports.

// Re-export primitives
pub use crate::primitives::{
    Address, Amount, Hash, KeyImage, KeyPair, PublicKey, SecretKey, Signature,
};

// Re-export error handling
pub use crate::error::{Error, Result};

// Re-export core consensus types
pub use crate::consensus::{Block, BlockHeader, Transaction};

// Re-export chain types
pub use crate::chain::{Blockchain, SharedBlockchain};

// Re-export mempool types
pub use crate::mempool::{Mempool, SharedMempool};

// Common traits
pub use std::fmt::{Debug, Display};
pub use std::str::FromStr;
