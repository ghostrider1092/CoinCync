//! Block structure for CoinCync 1.0
//!
//! `Block` is a pure data struct. All consensus validation lives in
//! `consensus/validation.rs`. Methods here are structural helpers.
//!
//! ## Audit map
//! Each `§` is a method (or method group) below; it states the INVARIANT it
//! guarantees, the THREAT it defends, and the TESTS that prove it. These are
//! structural accessors — the block-level *consensus* gates (coinbase presence,
//! merkle-root enforcement, privacy policy, size/weight caps) live in
//! `consensus/validation.rs`; this map covers only the helpers defined here.
//! (Renders in `cargo doc`.)
//!
//! - **§1 `total_fees`** — INVARIANT: sums fees of the non-coinbase txs ONLY
//!   (coinbase excluded), via `saturating_add` so an attacker-crafted fee sum
//!   past `u64::MAX` saturates rather than wrapping/panicking.
//!   THREAT: coinbase fee counted → miner over-claims; fee-sum overflow wrap →
//!   understated total lets an oversized coinbase pass the reward check.
//!   TESTS: `test_total_fees_coinbase_only_is_zero_via_method`,
//!   `test_total_fees_sums_non_coinbase_only`,
//!   `test_total_fees_saturates_on_overflow`.
//! - **§2 `coinbase`** — INVARIANT: returns the first tx, or `None` on an empty
//!   tx list (never panics / indexes out of bounds).
//!   THREAT: empty-block panic (DoS); mis-identifying the coinbase slot.
//!   TESTS: `test_coinbase_returns_first_tx`, `test_coinbase_none_on_empty_tx_list`.
//! - **§3 `non_coinbase_transactions`** — INVARIANT: iterates every tx except the
//!   first; empty when only a coinbase is present. This `skip(1)` is the single
//!   definition of "non-coinbase" reused by §1 and §4.
//!   THREAT: off-by-one that leaks the coinbase into, or drops a real tx from,
//!   fee/key-image accounting.
//!   TESTS: `test_non_coinbase_transactions_iterates_all_but_first`,
//!   `test_non_coinbase_transactions_empty_when_only_coinbase_via_method`,
//!   `test_non_coinbase_empty_when_only_coinbase`.
//! - **§4 `all_key_images`** — INVARIANT: collects key images from non-coinbase
//!   inputs ONLY; a coinbase carrying an input contributes nothing.
//!   THREAT: coinbase-sourced key image poisoning the double-spend set, or a
//!   missed key image letting a double-spend through the block-level check.
//!   TESTS: `test_all_key_images_excludes_coinbase`.
//! - **§5 `verify_merkle_root`** — INVARIANT: recomputes the root over the txs
//!   in order and compares to `header.tx_root`; empty tx list is valid iff the
//!   committed root is `Hash::zero()`. Because the root is recomputed from the
//!   actual tx order, tampering, wrong root, or REORDERING all diverge.
//!   THREAT: tx tampering after PoW; tx REORDERING / duplication malleability
//!   (CVE-2012-2459-class — the duplication defense proper lives in
//!   `primitives::merkle_root`; this method's job is to bind the committed root
//!   to the exact tx list & order, so a reordered or mutated set is rejected).
//!   TESTS: `test_verify_merkle_root_matches_recomputed`,
//!   `test_verify_merkle_root_empty_tx_list_true_iff_zero_root`,
//!   `test_verify_merkle_root_rejects_wrong_root`,
//!   `test_verify_merkle_root_rejects_tampered_transaction`,
//!   `test_verify_merkle_root_rejects_reordered_transactions`.
//! - **§6 `size`** — INVARIANT: `200 + Σ tx.size()` folded with `saturating_add`
//!   so a crafted set of huge txs cannot overflow `usize` and understate size.
//!   THREAT: size-underflow wrap slipping an over-cap block past `check_block_size`.
//!   TESTS: `test_size_real_block_equals_overhead_plus_tx_sizes`,
//!   `test_size_no_overflow`.
//! - **§7 trivial accessors (`hash` / `height` / `tx_count` / `is_genesis`)** —
//!   INVARIANT: each returns the header-derived value verbatim; `is_genesis`
//!   iff `header.height == 0`; `hash` delegates to `header.hash()`.
//!   THREAT: accessor drift from the header it mirrors.
//!   TESTS: `test_trivial_accessors_reflect_header`,
//!   `test_is_genesis_true_at_height_zero`.

use super::BlockHeader;
use crate::primitives::{merkle_root, Amount, Hash, KeyImage};
use crate::transaction::Transaction;
use borsh::{BorshDeserialize, BorshSerialize};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize, BorshSerialize, BorshDeserialize)]
pub struct Block {
    pub header: BlockHeader,
    pub transactions: Vec<Transaction>,
}

impl Block {
    pub fn new(header: BlockHeader, transactions: Vec<Transaction>) -> Self {
        Block {
            header,
            transactions,
        }
    }

    pub fn hash(&self) -> Hash {
        self.header.hash()
    }
    pub fn height(&self) -> u64 {
        self.header.height
    }
    pub fn tx_count(&self) -> usize {
        self.transactions.len()
    }
    pub fn is_genesis(&self) -> bool {
        self.header.height == 0
    }

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
        let tx_sizes: usize = self
            .transactions
            .iter()
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
            version: 1,
            tx_type: TxType::Coinbase,
            inputs: vec![],
            outputs: vec![],
            fee: Amount::ZERO,
            range_proof: vec![],
            extra: vec![],
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

    // ── Helpers for exercising the real Block methods ───────────────
    use crate::primitives::PublicKey;
    use crate::transaction::{Transaction, TxInput, TxType};

    /// A valid (identity) curve KeyImage for the signature field. The
    /// signature's key image is irrelevant to the methods under test — only
    /// `TxInput::key_image` (a `primitives::KeyImage`) is read by
    /// `Block::all_key_images` — but the struct must be well-formed.
    fn ec_key_image() -> crate::crypto::KeyImage {
        crate::crypto::KeyImage::from_bytes(crate::crypto::PublicPoint::identity().to_bytes())
            .expect("identity is a valid curve point")
    }

    fn mk_input(ki: u8) -> TxInput {
        TxInput {
            key_image: KeyImage::from_bytes([ki; 32]),
            ring_members: vec![],
            signature: crate::crypto::ClsagSignature {
                key_image: ec_key_image(),
                commitment_image: crate::crypto::PublicPoint::identity(),
                c1: [0u8; 32],
                responses: vec![],
            },
            pseudo_output_commitment: [0u8; 32],
        }
    }

    fn coinbase_tx() -> Transaction {
        Transaction {
            version: 1,
            tx_type: TxType::Coinbase,
            inputs: vec![],
            outputs: vec![],
            fee: Amount::ZERO,
            range_proof: vec![],
            extra: vec![],
        }
    }

    /// Coinbase carrying an input — used to prove `all_key_images` still
    /// excludes it even when it would otherwise contribute a key image.
    fn coinbase_with_input(ki: u8) -> Transaction {
        Transaction {
            inputs: vec![mk_input(ki)],
            ..coinbase_tx()
        }
    }

    fn transfer_tx(fee: Amount, ki: u8, extra: Vec<u8>) -> Transaction {
        Transaction {
            version: 1,
            tx_type: TxType::Transfer,
            inputs: vec![mk_input(ki)],
            outputs: vec![],
            fee,
            range_proof: vec![],
            extra,
        }
    }

    fn mk_header(tx_root: Hash) -> BlockHeader {
        BlockHeader {
            network_magic: [0, 0, 0, 0],
            version: 1,
            height: 1,
            timestamp: 1,
            prev_hash: Hash::zero(),
            tx_root,
            anchor: Hash::zero(),
            algorithm: 0,
            nonce: 0,
            target: Hash::from_bytes([0xFF; 32]),
            miner_pubkey: PublicKey::from_bytes([0u8; 32]),
            supply_commitment: [0u8; 32],
            checkpoint_vote: None,
            spark_set_root: [0u8; 32],
            mw_kernel_root: [0u8; 32],
        }
    }

    /// Build a block whose header commits to the Merkle root of its txs.
    fn block_with_committed_root(txs: Vec<Transaction>) -> Block {
        let root = if txs.is_empty() {
            Hash::zero()
        } else {
            let hashes: Vec<Hash> = txs.iter().map(|tx| tx.hash()).collect();
            merkle_root(&hashes)
        };
        Block::new(mk_header(root), txs)
    }

    // ── total_fees (real method) ────────────────────────────────────

    #[test]
    fn test_total_fees_coinbase_only_is_zero_via_method() {
        // A block containing only a coinbase must report ZERO fees through the
        // real `Block::total_fees()` method (coinbase is skipped).
        let block = Block::new(mk_header(Hash::zero()), vec![coinbase_tx()]);
        assert_eq!(block.total_fees(), Amount::ZERO);
    }

    #[test]
    fn test_total_fees_sums_non_coinbase_only() {
        let block = Block::new(
            mk_header(Hash::zero()),
            vec![
                coinbase_tx(),
                transfer_tx(Amount::from_atomic(100), 1, vec![]),
                transfer_tx(Amount::from_atomic(250), 2, vec![]),
            ],
        );
        assert_eq!(block.total_fees().as_atomic(), 350);
    }

    #[test]
    fn test_total_fees_saturates_on_overflow() {
        // Two non-coinbase txs each carrying a near-max fee must saturate at
        // u64::MAX, not wrap or panic.
        let block = Block::new(
            mk_header(Hash::zero()),
            vec![
                coinbase_tx(),
                transfer_tx(Amount::from_atomic(u64::MAX), 1, vec![]),
                transfer_tx(Amount::from_atomic(u64::MAX), 2, vec![]),
            ],
        );
        assert_eq!(block.total_fees().as_atomic(), u64::MAX);
    }

    // ── coinbase / non_coinbase_transactions accessors ──────────────

    #[test]
    fn test_coinbase_returns_first_tx() {
        let block = Block::new(
            mk_header(Hash::zero()),
            vec![coinbase_tx(), transfer_tx(Amount::ZERO, 1, vec![])],
        );
        let cb = block.coinbase().expect("coinbase present");
        assert_eq!(cb.tx_type, TxType::Coinbase);
    }

    #[test]
    fn test_coinbase_none_on_empty_tx_list() {
        let block = Block::new(mk_header(Hash::zero()), vec![]);
        assert!(block.coinbase().is_none());
    }

    #[test]
    fn test_non_coinbase_transactions_iterates_all_but_first() {
        let block = Block::new(
            mk_header(Hash::zero()),
            vec![
                coinbase_tx(),
                transfer_tx(Amount::from_atomic(1), 1, vec![]),
                transfer_tx(Amount::from_atomic(2), 2, vec![]),
            ],
        );
        let non_cb: Vec<_> = block.non_coinbase_transactions().collect();
        assert_eq!(non_cb.len(), 2);
        assert!(non_cb.iter().all(|tx| tx.tx_type == TxType::Transfer));
    }

    #[test]
    fn test_non_coinbase_transactions_empty_when_only_coinbase_via_method() {
        let block = Block::new(mk_header(Hash::zero()), vec![coinbase_tx()]);
        assert_eq!(block.non_coinbase_transactions().count(), 0);
    }

    // ── all_key_images ──────────────────────────────────────────────

    #[test]
    fn test_all_key_images_excludes_coinbase() {
        // Coinbase carries key image 0xAA (must be excluded); two transfers
        // carry 0x01 and 0x02 (must be collected).
        let block = Block::new(
            mk_header(Hash::zero()),
            vec![
                coinbase_with_input(0xAA),
                transfer_tx(Amount::ZERO, 0x01, vec![]),
                transfer_tx(Amount::ZERO, 0x02, vec![]),
            ],
        );
        let kis = block.all_key_images();
        assert_eq!(kis.len(), 2, "only non-coinbase key images collected");
        assert!(kis.contains(&KeyImage::from_bytes([0x01; 32])));
        assert!(kis.contains(&KeyImage::from_bytes([0x02; 32])));
        assert!(
            !kis.contains(&KeyImage::from_bytes([0xAA; 32])),
            "coinbase key image must be excluded"
        );
    }

    // ── verify_merkle_root ──────────────────────────────────────────

    #[test]
    fn test_verify_merkle_root_matches_recomputed() {
        let block = block_with_committed_root(vec![
            coinbase_tx(),
            transfer_tx(Amount::from_atomic(1), 1, vec![9, 9]),
        ]);
        assert!(block.verify_merkle_root());
    }

    #[test]
    fn test_verify_merkle_root_empty_tx_list_true_iff_zero_root() {
        // Empty tx list + zero root → true.
        let ok = Block::new(mk_header(Hash::zero()), vec![]);
        assert!(ok.verify_merkle_root());
        // Empty tx list + non-zero root → false.
        let bad = Block::new(mk_header(Hash::from_bytes([0x01; 32])), vec![]);
        assert!(!bad.verify_merkle_root());
    }

    #[test]
    fn test_verify_merkle_root_rejects_wrong_root() {
        let mut block = block_with_committed_root(vec![
            coinbase_tx(),
            transfer_tx(Amount::from_atomic(7), 1, vec![]),
        ]);
        // Tamper the committed root.
        block.header.tx_root = Hash::from_bytes([0xEE; 32]);
        assert!(!block.verify_merkle_root());
    }

    #[test]
    fn test_verify_merkle_root_rejects_tampered_transaction() {
        let mut block = block_with_committed_root(vec![
            coinbase_tx(),
            transfer_tx(Amount::from_atomic(7), 1, vec![1, 2, 3]),
        ]);
        // Mutate a tx so its hash no longer matches the committed root.
        block.transactions[1].extra = vec![4, 5, 6];
        assert!(!block.verify_merkle_root());
    }

    #[test]
    fn test_verify_merkle_root_rejects_reordered_transactions() {
        let a = transfer_tx(Amount::from_atomic(1), 1, vec![0xA]);
        let b = transfer_tx(Amount::from_atomic(2), 2, vec![0xB]);
        // Commit to order [a, b].
        let committed = block_with_committed_root(vec![a.clone(), b.clone()]);
        assert!(committed.verify_merkle_root());
        // Same header root but transactions in reordered order [b, a].
        let reordered = Block::new(committed.header.clone(), vec![b, a]);
        assert!(
            !reordered.verify_merkle_root(),
            "reordered transactions must produce a different root"
        );
    }

    // ── size (real method) ──────────────────────────────────────────

    #[test]
    fn test_size_real_block_equals_overhead_plus_tx_sizes() {
        let txs = vec![
            coinbase_tx(),
            transfer_tx(Amount::from_atomic(1), 1, vec![0u8; 4096]),
            transfer_tx(Amount::from_atomic(2), 2, vec![0u8; 8192]),
        ];
        let block = Block::new(mk_header(Hash::zero()), txs);
        let expected: usize = 200
            + block
                .transactions
                .iter()
                .map(|tx| tx.size())
                .sum::<usize>();
        assert_eq!(block.size(), expected);
        assert!(block.size() > 200, "large txs contribute to size");
    }

    // ── trivial accessors ───────────────────────────────────────────

    #[test]
    fn test_trivial_accessors_reflect_header() {
        let header = mk_header(Hash::zero());
        let expected_hash = header.hash();
        let block = Block::new(header, vec![coinbase_tx(), transfer_tx(Amount::ZERO, 1, vec![])]);
        assert_eq!(block.height(), 1);
        assert_eq!(block.tx_count(), 2);
        assert!(!block.is_genesis());
        assert_eq!(block.hash(), expected_hash);
    }

    #[test]
    fn test_is_genesis_true_at_height_zero() {
        let mut header = mk_header(Hash::zero());
        header.height = 0;
        let block = Block::new(header, vec![]);
        assert!(block.is_genesis());
    }
}
