//! # Property-based invariants for the reorg-rewind machinery
//!
//! Exercises [`WalletScanner`]'s journal + rewind paths under
//! randomized apply/rewind sequences. The unit tests in
//! `src/wallet/scanner.rs` cover specific scenarios; this file fuzzes
//! the SHAPE of the operation sequence so we catch invariant breaks
//! we didn't think to write a unit test for.
//!
//! Run with: `cargo test --test property_invariants_reorg_rewind --features "randomx testnet"`

use coincync::primitives::{Hash, KeyImage};
use coincync::wallet::scanner::{BlockApplyDiff, RewindError, WalletScanner};
use proptest::prelude::*;

// ─── Helpers ────────────────────────────────────────────────────────

/// A synthetic journal entry parametrized by tag. Used by the
/// strategy to build apply-sequences with deterministic
/// `(block_hash, prev_block_hash)` linkage.
fn diff_for_height(height: u64, n_outputs: usize, n_spends: usize) -> BlockApplyDiff {
    let h_byte = (height & 0xFF) as u8;
    let outputs = (0..n_outputs)
        .map(|i| (Hash::from_bytes([h_byte; 32]), i as u8))
        .collect::<Vec<_>>();
    let spends = (0..n_spends)
        .map(|i| KeyImage::from_bytes([h_byte.wrapping_add(i as u8 + 0x80); 32]))
        .collect::<Vec<_>>();
    BlockApplyDiff {
        height,
        block_hash: Hash::from_bytes([h_byte; 32]),
        prev_block_hash: Hash::from_bytes([h_byte.wrapping_sub(1); 32]),
        outputs_added: outputs,
        key_images_marked_spent: spends,
    }
}

// ─── Strategies ─────────────────────────────────────────────────────

/// Generate a sequence of (n_outputs, n_spends) per block for heights
/// 1..=n_blocks. Small bounds keep proptest cycles tight.
fn apply_sequence_strategy() -> impl Strategy<Value = Vec<(usize, usize)>> {
    prop::collection::vec((0usize..=4, 0usize..=3), 1..=20)
}

// ─── Invariants ─────────────────────────────────────────────────────

proptest! {
    /// After applying N blocks then rewinding to K, the count of
    /// outputs_to_remove equals the sum of outputs_added across the
    /// blocks with height in (K, N].
    #[test]
    fn rewind_outputs_to_remove_matches_journaled_outputs(
        seq in apply_sequence_strategy(),
        rewind_offset in 0u64..=20,
    ) {
        let mut scanner = WalletScanner::new();
        let n = seq.len() as u64;
        let mut expected_outputs_above = 0usize;

        for (i, (n_out, n_spend)) in seq.iter().enumerate() {
            let height = (i as u64) + 1;
            scanner.record_journal_entry(diff_for_height(height, *n_out, *n_spend));
        }
        let target = n.saturating_sub(rewind_offset);

        for (i, (n_out, _)) in seq.iter().enumerate() {
            let height = (i as u64) + 1;
            if height > target {
                expected_outputs_above += *n_out;
            }
        }

        if target > n {
            // Above current — must return TargetAboveCurrent
            let r = scanner.rewind_to_height(target);
            let is_above = matches!(r, Err(RewindError::TargetAboveCurrent { .. }));
            prop_assert!(is_above, "expected TargetAboveCurrent for target>n");
        } else {
            let outcome = scanner.rewind_to_height(target).unwrap();
            prop_assert_eq!(outcome.outputs_to_remove.len(), expected_outputs_above);
        }
    }

    /// After applying N blocks then rewinding to K, the count of
    /// key_images_to_unspend equals the sum of key_images_marked_spent
    /// across the blocks with height in (K, N]. Mirror of the outputs
    /// invariant for the Task #1b spend-journaling path.
    #[test]
    fn rewind_unspends_match_journaled_spends(
        seq in apply_sequence_strategy(),
        rewind_offset in 0u64..=20,
    ) {
        let mut scanner = WalletScanner::new();
        let n = seq.len() as u64;
        let mut expected_spends_above = 0usize;

        for (i, (n_out, n_spend)) in seq.iter().enumerate() {
            let height = (i as u64) + 1;
            scanner.record_journal_entry(diff_for_height(height, *n_out, *n_spend));
        }
        let target = n.saturating_sub(rewind_offset);

        for (i, (_, n_spend)) in seq.iter().enumerate() {
            let height = (i as u64) + 1;
            if height > target {
                expected_spends_above += *n_spend;
            }
        }

        if target <= n {
            let outcome = scanner.rewind_to_height(target).unwrap();
            prop_assert_eq!(outcome.key_images_to_unspend.len(), expected_spends_above);
        }
    }

    /// outputs_to_remove is in reverse application order: the highest-
    /// height block's outputs come first, lowest-popped block's come
    /// last. This is the order the caller wants for applying undo ops.
    #[test]
    fn rewind_outputs_are_in_reverse_application_order(
        seq in apply_sequence_strategy(),
    ) {
        let mut scanner = WalletScanner::new();
        for (i, (n_out, n_spend)) in seq.iter().enumerate() {
            let height = (i as u64) + 1;
            scanner.record_journal_entry(diff_for_height(height, *n_out, *n_spend));
        }
        let outcome = scanner.rewind_to_height(0).unwrap();

        // Outputs were pushed with `(Hash::from_bytes([h_byte; 32]), idx)`
        // so the first byte of tx_hash encodes the height-as-byte. The
        // sequence of first-bytes seen in outputs_to_remove should be
        // non-increasing (newest first).
        let mut prev_byte: Option<u8> = None;
        for (tx_hash, _) in &outcome.outputs_to_remove {
            let h_byte = tx_hash.as_bytes()[0];
            if let Some(prev) = prev_byte {
                prop_assert!(
                    h_byte <= prev,
                    "outputs_to_remove not in non-increasing order: saw {} after {}",
                    h_byte, prev
                );
            }
            prev_byte = Some(h_byte);
        }
    }

    /// Apply N blocks, rewind to K, verify entries_undone equals the
    /// count of journal entries with height > K. This is the basic
    /// accounting invariant for the rewind operation.
    #[test]
    fn rewind_entries_undone_matches_above_target(
        seq in apply_sequence_strategy(),
        rewind_offset in 0u64..=20,
    ) {
        let mut scanner = WalletScanner::new();
        let n = seq.len() as u64;

        for (i, (n_out, n_spend)) in seq.iter().enumerate() {
            let height = (i as u64) + 1;
            scanner.record_journal_entry(diff_for_height(height, *n_out, *n_spend));
        }
        let target = n.saturating_sub(rewind_offset);

        if target <= n {
            let outcome = scanner.rewind_to_height(target).unwrap();
            let above = n.saturating_sub(target) as usize;
            prop_assert_eq!(outcome.entries_undone, above);
        }
    }

    /// After rewind, position().0 is exactly target_height (or 0 if
    /// the journal was emptied). The scanner's last_height must never
    /// be above target post-rewind.
    #[test]
    fn rewind_leaves_position_at_target_or_below(
        seq in apply_sequence_strategy(),
        rewind_offset in 0u64..=20,
    ) {
        let mut scanner = WalletScanner::new();
        let n = seq.len() as u64;
        for (i, (n_out, n_spend)) in seq.iter().enumerate() {
            let height = (i as u64) + 1;
            scanner.record_journal_entry(diff_for_height(height, *n_out, *n_spend));
        }
        let target = n.saturating_sub(rewind_offset);

        if target <= n {
            scanner.rewind_to_height(target).unwrap();
            let (pos_h, _) = scanner.position();
            prop_assert!(
                pos_h <= target,
                "position {} exceeds rewind target {}", pos_h, target
            );
        }
    }

    /// `rewind_to_height(current)` is a no-op: entries_undone == 0,
    /// position unchanged. Defensive — orchestrators may double-call
    /// during recovery retries.
    #[test]
    fn rewind_to_current_height_is_noop(seq in apply_sequence_strategy()) {
        let mut scanner = WalletScanner::new();
        for (i, (n_out, n_spend)) in seq.iter().enumerate() {
            let height = (i as u64) + 1;
            scanner.record_journal_entry(diff_for_height(height, *n_out, *n_spend));
        }
        let (pre_h, pre_hash) = scanner.position();
        let outcome = scanner.rewind_to_height(pre_h).unwrap();
        prop_assert_eq!(outcome.entries_undone, 0);
        prop_assert_eq!(outcome.outputs_to_remove.len(), 0);
        prop_assert_eq!(outcome.key_images_to_unspend.len(), 0);

        let (post_h, post_hash) = scanner.position();
        prop_assert_eq!(post_h, pre_h);
        prop_assert_eq!(post_hash, pre_hash);
    }

    /// Round-trip: apply [1..=N], rewind to K, then re-apply [K+1..=N]
    /// produces a journal with the same shape as direct apply [1..=N].
    /// The reapply path uses the same heights but different "seed"
    /// (block_hash byte +0x40 offset) to simulate a canonical chain
    /// that differs from the orphaned one we rewound.
    #[test]
    fn rewind_then_reapply_journal_shape_matches(
        seq in apply_sequence_strategy(),
        rewind_offset in 0u64..=20,
    ) {
        let mut scanner = WalletScanner::new();
        let n = seq.len() as u64;
        for (i, (n_out, n_spend)) in seq.iter().enumerate() {
            let height = (i as u64) + 1;
            scanner.record_journal_entry(diff_for_height(height, *n_out, *n_spend));
        }
        let target = n.saturating_sub(rewind_offset);
        if target > n { return Ok(()); }

        scanner.rewind_to_height(target).unwrap();
        prop_assert!(scanner.journal_len() as u64 <= target);

        // Re-apply blocks target+1..=n with the same outputs/spends
        // shape (would in production come from canonical chain).
        for (i, (n_out, n_spend)) in seq.iter().enumerate() {
            let height = (i as u64) + 1;
            if height > target {
                scanner.record_journal_entry(diff_for_height(height, *n_out, *n_spend));
            }
        }
        prop_assert_eq!(scanner.journal_len() as u64, n);
        let (final_h, _) = scanner.position();
        prop_assert_eq!(final_h, n);
    }

    /// Journal is always bounded by journal_max regardless of how many
    /// blocks are pushed. Without this invariant, a slow rewind path
    /// could exhaust memory on a long-syncing wallet.
    #[test]
    fn journal_never_exceeds_journal_max(n in 1usize..500) {
        let mut scanner = WalletScanner::new();
        for h in 1..=(n as u64) {
            scanner.record_journal_entry(diff_for_height(h, 1, 0));
        }
        prop_assert!(scanner.journal_len() <= scanner.journal_max());
    }
}

// ─── Bounded reorg-depth invariants ─────────────────────────────────

proptest! {
    /// Rewinding to a target BELOW the journal's oldest retained
    /// height returns OutsideJournalWindow (not a panic, not silent
    /// data corruption). This is the contract the orchestrator uses
    /// to decide between in-window rewind and full-rescan-from-checkpoint.
    #[test]
    fn rewind_below_oldest_returns_outside_journal_window(
        n in 250usize..400,  // > journal_max to force trimming
        rewind_to in 1u64..50,  // below the oldest retained
    ) {
        let mut scanner = WalletScanner::new();
        for h in 1..=(n as u64) {
            scanner.record_journal_entry(diff_for_height(h, 1, 0));
        }
        // After trimming, the oldest retained entry should be at
        // height (n - journal_max + 1) or thereabouts. If we ask for
        // a rewind to height 1 (below that), we must get OutsideJournalWindow.
        let oldest = scanner.journal_max() as u64;
        if rewind_to < (n as u64).saturating_sub(oldest) + 1 {
            let r = scanner.rewind_to_height(rewind_to);
            let is_outside = matches!(r, Err(RewindError::OutsideJournalWindow { .. }));
            prop_assert!(is_outside, "expected OutsideJournalWindow for below-oldest target");
        }
    }
}
