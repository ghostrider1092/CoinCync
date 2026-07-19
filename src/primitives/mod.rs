//! # Primitive Types
//!
//! Core types used throughout CoinCync 1.0.

mod address;
mod amount;
mod hash;
mod keys;

pub use address::{Address, AddressType, Network};
pub use amount::Amount;
pub use hash::{hash_concat, hash_data, hash_domain, merkle_root, Hash};
pub use keys::{KeyImage, KeyPair, PublicKey, SecretKey, Signature};
