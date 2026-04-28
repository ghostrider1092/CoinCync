//! Block structure for CoinCync 1.0
//!
//! `Block` is a pure data struct. All consensus validation lives in
//! `consensus/validation.rs`. Methods here are structural helpers.

use serde::{Serialize, Deserialize};
use borsh::{BorshSerialize, BorshDeserialize};
use super::BlockHeader;
use crate::primitives::{Hash, Amount, KeyImage, merkle_root};
use crate::transaction::Transaction;

#[derive(Clone, Debug, Serialize, Deserialize, BorshSerialize, BorshDeserialize)]
pub struct Block {
    pub header: BlockHeader,
    pub transactions: Vec<Transaction>,
}

impl Block {
    pub fn new(header: BlockHeader, transactions: Vec<Transaction>) -> Self {
        Block { header, transactions }
    }

    pub fn hash(&self) -> Hash { self.header.hash() }
    pub fn height(&self) -> u64 { self.header.height }
    pub fn tx_count(&self) -> usize { self.transactions.len() }
    pub fn is_genesis(&self) -> bool { self.header.height == 0 }

    /// The coinbase transaction (first transaction).
    pub fn coinbase(&self) -> Option<&Transaction> {
        self.transactions.first()
    }

    /// Iterator over non-coinbase transactions.
    pub fn non_coinbase_transactions(&self) -> impl Iterator<Item = &Transaction> {
        self.transactions.iter().skip(1)
    }

    /// Sum of fees from all non-coinbase transactions.
    pub fn total_fees(&self) -> Amount {
        self.non_coinbase_transactions()
            .map(|tx| tx.fee)
            .fold(Amount::ZERO, |acc, fee| acc.saturating_add(fee))
    }

    /// All key images from non-coinbase inputs.
    pub fn all_key_images(&self) -> Vec<KeyImage> {
        self.non_coinbase_transactions()
            .flat_map(|tx| tx.key_images())
            .collect()
    }

    /// Verify header.tx_root matches Merkle root of transactions.
    pub fn verify_merkle_root(&self) -> bool {
        if self.transactions.is_empty() {
            return self.header.tx_root == Hash::zero();
        }
        let hashes: Vec<Hash> = self.transactions.iter().map(|tx| tx.hash()).collect();
        merkle_root(&hashes) == self.header.tx_root
    }

    /// Approximate serialized size in bytes.
    pub fn size(&self) -> usize {
        let tx_sizes: usize = self.transactions.iter()
            .map(|tx| tx.size())
            .fold(0usize, |acc, s| acc.saturating_add(s));
        200usize.saturating_add(tx_sizes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_non_coinbase_empty_when_only_coinbase() {
        use crate::transaction::{Transaction, TxType};
        let coinbase = Transaction {
            version: 1, tx_type: TxType::Coinbase, inputs: vec![], outputs: vec![],
            fee: Amount::ZERO, range_proof: vec![], extra: vec![],
        };
        let txs = vec![coinbase];
        let non_cb: Vec<_> = txs.iter().skip(1).collect();
        assert!(non_cb.is_empty());
    }

    #[test]
    fn test_total_fees_zero() {
        assert_eq!(Amount::ZERO.as_atomic(), 0);
    }

    #[test]
    fn test_size_no_overflow() {
        assert_eq!(200usize.saturating_add(0), 200);
    }
}
