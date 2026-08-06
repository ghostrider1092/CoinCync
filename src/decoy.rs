use crate::primitives::PublicKey;
use serde::{Deserialize, Serialize};

pub const DECOY_LOCATOR_POLICY_VERSION: u16 = 1;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash, Serialize, Deserialize)]
pub struct OutputLocator {
    pub height: u64,
    pub ordinal: u32,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct HeightOutputCount {
    pub height: u64,
    pub count: u32,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ResolvedDecoyOutput {
    pub locator: OutputLocator,
    pub public_key: PublicKey,
    pub commitment: [u8; 32],
    pub height: u64,
    pub is_coinbase: bool,
    pub lock_height: Option<u64>,
}
