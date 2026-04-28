//! # Primitive Types
//!
//! Core types used throughout CoinCync 1.0.

mod hash;
mod keys;
mod amount;
mod address;

pub use hash::{Hash, hash_data, hash_concat, hash_domain, merkle_root};
pub use keys::{PublicKey, SecretKey, KeyPair, Signature, KeyImage};
pub use amount::Amount;
pub use address::{Address, AddressType, Network};
