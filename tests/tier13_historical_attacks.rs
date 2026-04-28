//! # Tier 13 — Historical Attack Reproduction Suite
//! Each submodule tests a named, dated, documented blockchain attack.

#[path = "historical_attacks/bitcoin_2010_value_overflow.rs"]
mod bitcoin_2010_value_overflow;

#[path = "historical_attacks/bitcoin_2018_inflation.rs"]
mod bitcoin_2018_inflation;

#[path = "historical_attacks/monero_2017_key_image.rs"]
mod monero_2017_key_image;

#[path = "historical_attacks/monero_2019_overflow.rs"]
mod monero_2019_overflow;

#[path = "historical_attacks/monero_2020_janus.rs"]
mod monero_2020_janus;

#[path = "historical_attacks/monero_2018_burning_bug.rs"]
mod monero_2018_burning_bug;

#[path = "historical_attacks/verge_2018_timestamp.rs"]
mod verge_2018_timestamp;

#[path = "historical_attacks/etc_2019_deep_reorg.rs"]
mod etc_2019_deep_reorg;

#[path = "historical_attacks/monero_ring_linkability.rs"]
mod monero_ring_linkability;

#[path = "historical_attacks/zcash_2018_proof_forgery.rs"]
mod zcash_2018_proof_forgery;
