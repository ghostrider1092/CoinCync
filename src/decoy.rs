use crate::primitives::{Hash, PublicKey};
use borsh::{BorshDeserialize, BorshSerialize};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeSet, HashMap};

pub const DECOY_LOCATOR_POLICY_VERSION: u16 = 1;

#[derive(
    Clone,
    Copy,
    Debug,
    Eq,
    PartialEq,
    Hash,
    Serialize,
    Deserialize,
    BorshSerialize,
    BorshDeserialize,
)]
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

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct DecoyDistributionSnapshot {
    pub snapshot_height: u64,
    pub snapshot_hash: Hash,
    pub policy_version: u16,
    pub heights: Vec<HeightOutputCount>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ResolvedDecoySnapshot {
    pub snapshot_height: u64,
    pub snapshot_hash: Hash,
    pub policy_version: u16,
    pub outputs: Vec<ResolvedDecoyOutput>,
}

pub fn canonical_output_locators<I>(height: u64, outputs: I) -> HashMap<(Hash, u8), OutputLocator>
where
    I: IntoIterator<Item = (Hash, u8)>,
{
    BTreeSet::from_iter(outputs)
        .into_iter()
        .enumerate()
        .map(|(ordinal, key)| {
            (
                key,
                OutputLocator {
                    height,
                    ordinal: ordinal as u32,
                },
            )
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonical_output_order_is_hash_then_index() {
        let low = Hash::from_bytes([1; 32]);
        let high = Hash::from_bytes([2; 32]);
        let locators = canonical_output_locators(7, [(high, 1), (low, 2), (high, 0)]);

        assert_eq!(locators[&(low, 2)].ordinal, 0);
        assert_eq!(locators[&(high, 0)].ordinal, 1);
        assert_eq!(locators[&(high, 1)].ordinal, 2);
        assert!(locators.values().all(|locator| locator.height == 7));
    }
}
