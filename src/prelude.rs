//! # CoinCync Prelude
//!
//! Common types and traits for convenient imports.

// Re-export primitives
pub use crate::primitives::{Hash, PublicKey, SecretKey, KeyPair, Signature, Amount, Address, KeyImage};

// Re-export error handling
pub use crate::error::{Error, Result};

// Re-export core consensus types
pub use crate::consensus::{Block, BlockHeader, Transaction};

// Re-export chain types
pub use crate::chain::{Blockchain, SharedBlockchain};

// Re-export mempool types
pub use crate::mempool::{Mempool, SharedMempool};

// Common traits
pub use std::str::FromStr;
pub use std::fmt::{Debug, Display};
