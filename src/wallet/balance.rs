//! # Balance tracking for CoinCync 1.0
//!
//! Wallet UTXO set + balance queries. The 2.0 confidential-asset layer
//! was removed during the asset strip (commit 46f0437), so every UTXO
//! is implicitly CYNC and the `AssetId` / `asset_id` / `asset_blinding_bytes`
//! fields are gone. Per-asset query helpers have been removed too — they
//! were all single-asset against `AssetId::native()`, so they degenerate
//! to the plain `total` / `spendable` / `available_utxos` helpers.

use crate::primitives::{Hash, Amount, KeyImage, PublicKey};
use serde::{Serialize, Deserialize};
use borsh::{BorshSerialize, BorshDeserialize};
use std::collections::HashMap;

#[derive(Clone, Debug, Serialize, Deserialize, BorshSerialize, BorshDeserialize)]
pub struct UTXO {
    pub tx_hash: Hash,
    pub output_index: u8,
    pub amount: Amount,
    pub height: u64,
    pub key_image: KeyImage,
    pub spent: bool,
    /// Raw bytes of the amount Pedersen blinding factor.
    /// Use `BlindingFactor::from_bytes(utxo.amount_blinding_bytes)` to
    /// reconstruct. Must match the blinding used in the on-chain
    /// commitment, or CLSAG ring signatures will fail validation.
    pub amount_blinding_bytes: [u8; 32],
    /// The tx_public_key from the output that sent us this UTXO.
    /// Used to recompute the one-time spend secret.
    pub tx_public_key: PublicKey,
    /// Optional time lock: output cannot be spent until this block height.
    /// `None` means immediately spendable.
    pub lock_height: Option<u64>,
}

#[derive(Clone, Default)]
pub struct Balance {
    utxos: HashMap<(Hash, u8), UTXO>,
}

impl Balance {
    pub fn new() -> Self { Balance::default() }

    /// Create a Balance from a list of UTXOs.
    pub fn from_utxos(utxos: Vec<UTXO>) -> Self {
        let mut balance = Balance::new();
        for utxo in utxos {
            balance.add_utxo(utxo);
        }
        balance
    }

    pub fn add_utxo(&mut self, utxo: UTXO) {
        self.utxos.insert((utxo.tx_hash, utxo.output_index), utxo);
    }

    pub fn mark_spent(&mut self, tx_hash: Hash, output_index: u8) {
        if let Some(utxo) = self.utxos.get_mut(&(tx_hash, output_index)) {
            utxo.spent = true;
        }
    }

    /// Total confirmed balance (including immature + locked).
    pub fn total(&self) -> Amount {
        self.utxos.values().filter(|u| !u.spent).map(|u| u.amount).sum()
    }

    /// Spendable balance: unspent, past `min_age`, past `lock_height`.
    pub fn spendable(&self, current_height: u64, min_age: u64) -> Amount {
        self.utxos.values()
            .filter(|u| !u.spent
                && current_height >= u.height.saturating_add(min_age)
                && u.lock_height.map_or(true, |lh| current_height >= lh))
            .map(|u| u.amount)
            .sum()
    }

    /// UTXOs that are legally spendable right now.
    pub fn available_utxos(&self, current_height: u64, min_age: u64) -> Vec<&UTXO> {
        self.utxos.values()
            .filter(|u| !u.spent
                && current_height >= u.height.saturating_add(min_age)
                && u.lock_height.map_or(true, |lh| current_height >= lh))
            .collect()
    }

    /// All UTXOs (including spent) by value.
    pub fn all_utxos(&self) -> Vec<UTXO> {
        self.utxos.values().cloned().collect()
    }

    /// All unspent UTXOs regardless of age.
    pub fn unspent_utxos(&self) -> Vec<&UTXO> {
        self.utxos.values().filter(|u| !u.spent).collect()
    }

    /// UTXOs that are unspent but held back by `lock_height`.
    pub fn locked_utxos(&self, current_height: u64) -> Vec<&UTXO> {
        self.utxos.values()
            .filter(|u| !u.spent && u.lock_height.map_or(false, |lh| current_height < lh))
            .collect()
    }

    /// Total balance tied up in time-locked outputs.
    pub fn locked_balance(&self, current_height: u64) -> Amount {
        self.locked_utxos(current_height).iter().map(|u| u.amount).sum()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_utxo(amount: u64, height: u64, spent: bool) -> UTXO {
        UTXO {
            tx_hash: Hash::from_bytes([0u8; 32]),
            output_index: 0,
            amount: Amount::from_atomic(amount),
            height,
            key_image: KeyImage::from_bytes([0u8; 32]),
            spent,
            amount_blinding_bytes: [0u8; 32],
            tx_public_key: PublicKey::from_bytes([0u8; 32]),
            lock_height: None,
        }
    }

    #[test]
    fn test_spendable_balance() {
        let mut balance = Balance::new();
        balance.add_utxo(make_utxo(1000, 0, false));
        assert_eq!(balance.spendable(100, 10), Amount::from_atomic(1000));
        assert_eq!(balance.spendable(5, 10), Amount::ZERO);
    }

    #[test]
    fn test_spent_utxo_not_counted() {
        let mut balance = Balance::new();
        balance.add_utxo(make_utxo(500, 0, true));
        assert_eq!(balance.total(), Amount::ZERO);
    }

    #[test]
    fn test_locked_utxo() {
        let mut balance = Balance::new();
        let mut utxo = make_utxo(2000, 0, false);
        utxo.lock_height = Some(100);
        utxo.output_index = 1;
        balance.add_utxo(utxo);
        assert_eq!(balance.spendable(50, 0), Amount::ZERO);
        assert_eq!(balance.locked_balance(50), Amount::from_atomic(2000));
        assert_eq!(balance.spendable(100, 0), Amount::from_atomic(2000));
    }
}
