//! # Wallet reorg-recovery end-to-end (Task #9)
//!
//! Exercises the full wallet-side rewind machinery end-to-end: scanner
//! journal + balance UTXO state + TransactionHistory records. Each test
//! drives the same `RewindOutcome` flow the live orchestrator (Task #5
//! + #6) uses, so a regression in any of the unmark/remove paths trips
//! here even if the per-module unit tests still pass.
//!
//! Why not stand up a real chain: the wallet-side recovery is fully
//! deterministic once `RewindOutcome` is in hand, and constructing
//! real wallet-detectable outputs is heavy (stealth addresses + view
//! tags + commitment blinding). For end-to-end CHAIN reorg coverage
//! see `tests/tier14_reorg_defense.rs` and the existing `tier5_*`
//! suite — those exercise the consensus / blockchain layer with a
//! competing fork. This file fills the complementary gap on the
//! wallet-state-after-rewind side.

use coincync::primitives::{Amount, Hash, KeyImage, PublicKey};
use coincync::wallet::balance::{Balance, UTXO};
use coincync::wallet::history::{TransactionHistory, TransactionRecord, TxStatus};
use coincync::wallet::scanner::{BlockApplyDiff, WalletScanner};

// ─── Helpers ────────────────────────────────────────────────────────

/// Build a synthetic UTXO at `height` tagged by `seed`. The
/// `(tx_hash, output_index)` pair derived from `seed` is what the
/// scanner's journal will record as `outputs_added`, so the rewind
/// path can find + drop the UTXO via `Balance::remove_outputs`.
fn make_utxo(seed: u8, height: u64, amount: u64) -> UTXO {
    UTXO {
        tx_hash: Hash::from_bytes([seed; 32]),
        output_index: 0,
        output_locator: None,
        amount: Amount::from_atomic(amount),
        height,
        key_image: KeyImage::from_bytes([seed; 32]),
        spent: false,
        amount_blinding_bytes: [0u8; 32],
        tx_public_key: PublicKey::from_bytes([0u8; 32]),
        lock_height: None,
        subaddress_account: None,
        subaddress_index: None,
        payment_id: None,
    }
}

/// Push a journal entry that journals one wallet-owned output at
/// `(seed, 0)`. Matches the UTXO shape produced by `make_utxo(seed)`
/// so rewind's `outputs_to_remove` lines up with what's in `Balance`.
fn push_journal_entry(scanner: &mut WalletScanner, seed: u8, height: u64) {
    scanner.record_journal_entry(BlockApplyDiff {
        height,
        block_hash: Hash::from_bytes([seed; 32]),
        prev_block_hash: Hash::from_bytes([seed.wrapping_sub(1); 32]),
        outputs_added: vec![(Hash::from_bytes([seed; 32]), 0)],
        key_images_marked_spent: vec![],
    });
}

// ─── Test 1: rewind drops UTXOs + history rows ──────────────────────

/// End-to-end: 5 wallet outputs land in heights 1-5; reorg drops the
/// top 3; rewind correctly removes them from BOTH Balance and
/// TransactionHistory, and the key_image_index reverse-pointer is
/// cleaned up so a subsequent `lookup_by_key_image` doesn't return a
/// dead UTXO.
#[test]
fn wallet_rewind_drops_phantom_utxos_and_history() {
    let mut scanner = WalletScanner::new();
    let mut balance = Balance::new();
    let mut history = TransactionHistory::new();

    // Apply blocks 1..=5. Each block adds one of our outputs.
    for h in 1u64..=5 {
        let seed = h as u8;
        push_journal_entry(&mut scanner, seed, h);
        balance.add_utxo(make_utxo(seed, h, 1_000));
        history.add(TransactionRecord::incoming(
            Hash::from_bytes([seed; 32]),
            Amount::from_atomic(1_000),
            h,
            1_700_000_000 + h * 120,
            0,
            None,
        ));
    }
    assert_eq!(balance.unspent_utxos().len(), 5);
    assert_eq!(history.count(), 5);

    // Reorg detected: rewind down to height 2 (keep blocks 1 + 2).
    let outcome = scanner
        .rewind_to_height(2)
        .expect("rewind to in-window height should succeed");
    assert_eq!(outcome.entries_undone, 3);
    assert_eq!(outcome.outputs_to_remove.len(), 3);

    // Apply the outcome to wallet state — the same calls the
    // orchestrator's BlockScanner::handle_reorg_recovery impl will
    // perform in production.
    let removed_balance = balance.remove_outputs(&outcome.outputs_to_remove);
    let removed_history = history.remove_incoming_outputs(&outcome.outputs_to_remove);
    history.revert_outgoing_above_height(outcome.new_height);
    for ki in &outcome.key_images_to_unspend {
        balance.unmark_spent_by_key_image(ki);
    }

    // Post-state: only heights 1-2 should remain.
    assert_eq!(removed_balance, 3);
    assert_eq!(removed_history, 3);
    assert_eq!(balance.unspent_utxos().len(), 2);
    assert_eq!(history.count(), 2);

    // Reverse-index sanity: the 3 dropped UTXOs' key_images must no
    // longer resolve (regression for the bug where remove_outputs
    // forgets to clear key_image_index alongside utxos).
    for seed in 3u8..=5 {
        let ki = KeyImage::from_bytes([seed; 32]);
        assert!(
            balance.lookup_by_key_image(&ki).is_none(),
            "dropped UTXO's key_image still resolves: seed={}",
            seed
        );
    }
    // The kept UTXOs (heights 1-2) must STILL resolve.
    for seed in 1u8..=2 {
        let ki = KeyImage::from_bytes([seed; 32]);
        assert!(
            balance.lookup_by_key_image(&ki).is_some(),
            "kept UTXO's key_image went missing: seed={}",
            seed
        );
    }
}

// ─── Test 2: rewind unspends orphaned spends ────────────────────────

/// End-to-end Task #1b: a UTXO at height 1 is spent by a tx in
/// block 3 (the wallet's own outgoing tx). Block 3 then gets orphaned.
/// The wallet must restore `UTXO.spent = false` so the user's balance
/// reflects canonical chain state.
#[test]
fn wallet_rewind_unspends_orphaned_spend() {
    let mut scanner = WalletScanner::new();
    let mut balance = Balance::new();

    // Block 1: wallet receives a UTXO tagged "0xAA".
    let received_seed = 0xAAu8;
    push_journal_entry(&mut scanner, received_seed, 1);
    balance.add_utxo(make_utxo(received_seed, 1, 5_000));

    // Blocks 2 and 3 happen. In block 3, our UTXO gets spent
    // (key_image lands in a tx input). We mark spent and record the
    // spend in the journal (what the orchestrator's wallet-side
    // adapter would do via `record_spend_for_last_block`).
    push_journal_entry(&mut scanner, 0x02, 2);
    push_journal_entry(&mut scanner, 0x03, 3);
    let received_ki = KeyImage::from_bytes([received_seed; 32]);
    balance.mark_spent(Hash::from_bytes([received_seed; 32]), 0);
    assert!(scanner.record_spend_for_last_block(received_ki));

    // Pre-reorg sanity.
    assert_eq!(
        balance.total(),
        Amount::ZERO,
        "marked-spent UTXO must not count in total"
    );
    assert!(
        balance.lookup_by_key_image(&received_ki).is_none(),
        "lookup_by_key_image filters spent UTXOs"
    );

    // Reorg: block 3 is orphaned. Rewind down to height 2.
    let outcome = scanner.rewind_to_height(2).expect("rewind");
    assert_eq!(outcome.entries_undone, 1);
    assert_eq!(outcome.key_images_to_unspend.len(), 1);
    assert_eq!(outcome.key_images_to_unspend[0], received_ki);

    // Apply unspend to balance.
    for ki in &outcome.key_images_to_unspend {
        assert!(
            balance.unmark_spent_by_key_image(ki),
            "unmark_spent_by_key_image should return true on a previously-spent UTXO"
        );
    }

    // Post-reorg: the originally-received UTXO is spendable again.
    assert_eq!(
        balance.total(),
        Amount::from_atomic(5_000),
        "unspent UTXO must reappear in total"
    );
    assert!(
        balance.lookup_by_key_image(&received_ki).is_some(),
        "unspent UTXO must resolve via key_image_index"
    );
}

// ─── Test 3: outgoing-record height pass ────────────────────────────

/// `revert_outgoing_above_height` resets only the outgoing records
/// whose `block_height` is strictly above the new tip — incoming
/// records and outgoing records at-or-below the new tip stay put.
#[test]
fn wallet_rewind_resets_only_above_height_outgoing() {
    let mut history = TransactionHistory::new();

    let mut sent_low = TransactionRecord::outgoing(
        Hash::from_bytes([0x01; 32]),
        Amount::from_atomic(100),
        Amount::from_atomic(1),
        50,
        1_700_000_000,
    );
    sent_low.status = TxStatus::Confirmed;

    let mut sent_high = TransactionRecord::outgoing(
        Hash::from_bytes([0x02; 32]),
        Amount::from_atomic(200),
        Amount::from_atomic(1),
        80,
        1_700_000_000,
    );
    sent_high.status = TxStatus::Confirmed;

    let mut received_high = TransactionRecord::incoming(
        Hash::from_bytes([0x03; 32]),
        Amount::from_atomic(300),
        80,
        1_700_000_000,
        0,
        None,
    );
    received_high.status = TxStatus::Confirmed;

    history.add(sent_low);
    history.add(sent_high);
    history.add(received_high);

    // Rewind to height 60: only sent_high (h=80, outgoing) should reset.
    let updated = history.revert_outgoing_above_height(60);
    assert_eq!(updated, 1);

    let lo = history.get(&Hash::from_bytes([0x01; 32])).unwrap();
    assert_eq!(lo.block_height, 50);
    assert_eq!(lo.status, TxStatus::Confirmed);

    let hi_sent = history.get(&Hash::from_bytes([0x02; 32])).unwrap();
    assert_eq!(hi_sent.block_height, 0);
    assert_eq!(hi_sent.status, TxStatus::Pending);

    // Incoming record at the same height as the reset outgoing one is
    // NOT touched — incoming uses the precise `outputs_to_remove`
    // path, not this coarse height pass.
    let hi_recv = history.get(&Hash::from_bytes([0x03; 32])).unwrap();
    assert_eq!(hi_recv.block_height, 80);
    assert_eq!(hi_recv.status, TxStatus::Confirmed);
}

// ─── Test 4: rewind-then-reapply round-trip ─────────────────────────

/// A reorg recovers by rewinding to the fork, then the orchestrator
/// re-applies canonical blocks past the fork. The wallet must end up
/// in a state indistinguishable from "we just scanned the canonical
/// chain straight through" — balance, history, journal all coherent.
#[test]
fn wallet_rewind_then_reapply_yields_equivalent_state() {
    // Round 1: apply blocks 1-5 on the LOSING chain.
    let mut scanner = WalletScanner::new();
    let mut balance = Balance::new();
    let mut history = TransactionHistory::new();
    for h in 1u64..=5 {
        let seed = h as u8;
        push_journal_entry(&mut scanner, seed, h);
        balance.add_utxo(make_utxo(seed, h, 1_000));
        history.add(TransactionRecord::incoming(
            Hash::from_bytes([seed; 32]),
            Amount::from_atomic(1_000),
            h,
            1_700_000_000 + h * 120,
            0,
            None,
        ));
    }

    // Reorg: rewind to fork height 2.
    let outcome = scanner.rewind_to_height(2).expect("rewind");
    balance.remove_outputs(&outcome.outputs_to_remove);
    history.remove_incoming_outputs(&outcome.outputs_to_remove);
    history.revert_outgoing_above_height(outcome.new_height);
    for ki in &outcome.key_images_to_unspend {
        balance.unmark_spent_by_key_image(ki);
    }

    // Reapply: canonical heights 3'-5' use DIFFERENT seeds (different
    // block hashes + different outputs from the same height range).
    for h in 3u64..=5 {
        let seed = h as u8 + 0x80;
        push_journal_entry(&mut scanner, seed, h);
        balance.add_utxo(make_utxo(seed, h, 1_000));
        history.add(TransactionRecord::incoming(
            Hash::from_bytes([seed; 32]),
            Amount::from_atomic(1_000),
            h,
            1_700_000_000 + h * 120,
            0,
            None,
        ));
    }

    // Final state: same 5-UTXO / 5-record count as the original
    // forward path, but the contents reflect heights 1, 2, 3', 4', 5'.
    assert_eq!(balance.unspent_utxos().len(), 5);
    assert_eq!(history.count(), 5);
    assert_eq!(balance.total(), Amount::from_atomic(5_000));

    // Heights 1 + 2 retained their original seeds; heights 3-5 have
    // the canonical seeds (0x83, 0x84, 0x85).
    for seed in 1u8..=2 {
        let ki = KeyImage::from_bytes([seed; 32]);
        assert!(
            balance.lookup_by_key_image(&ki).is_some(),
            "pre-fork UTXO seed={} should remain",
            seed
        );
    }
    for seed in [0x83u8, 0x84, 0x85] {
        let ki = KeyImage::from_bytes([seed; 32]);
        assert!(
            balance.lookup_by_key_image(&ki).is_some(),
            "post-reorg canonical UTXO seed={:#x} should be present",
            seed
        );
    }
    // The pre-rewind losing-chain UTXOs (3, 4, 5) must NOT resolve.
    for seed in 3u8..=5 {
        let ki = KeyImage::from_bytes([seed; 32]);
        assert!(
            balance.lookup_by_key_image(&ki).is_none(),
            "losing-chain UTXO seed={} should be gone",
            seed
        );
    }

    // Journal tip is at canonical height 5 with the canonical seed.
    let (h, hash) = scanner.position();
    assert_eq!(h, 5);
    assert_eq!(hash, Hash::from_bytes([0x85; 32]));
}
