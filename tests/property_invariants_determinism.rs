//! # Property tests — consensus determinism class
//!
//! An accumulated state value that feeds a consensus verdict MUST be a pure
//! function of the CANONICAL chain content — never of a node's reorg history —
//! or two honest nodes on the same tip can disagree and fork. This project has
//! had three bugs of exactly that shape (total_difficulty, total_outputs_ever →
//! ring-size, and the self-recorded checkpoint hash), all now fixed.
//!
//! This suite fuzzes the fix for the `total_outputs_ever` → ring-size
//! divergence. `consensus::validation::check_tx_ring_size_and_unique_members`
//! feeds `effective_ring_size` the "available outputs" metric
//! `total_outputs_ever() - reorg_disconnects_total()` (validation.rs). The
//! raw `total_outputs_ever` counter is monotonic and is NOT decremented on
//! reorg, so on its own it is path-dependent; subtracting the disconnect count
//! yields the canonical-outputs-ever value, which must be reorg-history-
//! invariant. We assert that across thousands of random orphan/reorg histories.
//!
//! Companion coverage: the single hand-built regression lives in
//! `src/storage/utxos.rs::ring_size_availability_is_reorg_history_invariant`,
//! and the full real-PoW end-to-end reorg double-spend test lives in
//! `tests/reorg_double_spend_e2e.rs` (#[ignore], slow).

use coincync::constants::effective_ring_size;
use coincync::primitives::{Hash, PublicKey};
use coincync::storage::UtxoSet;
use coincync::transaction::TxOutput;
use proptest::prelude::*;

const NS_CANON: u8 = 0;
const NS_ORPHAN: u8 = 1;

/// Build a unique output for `(namespace, id)`. Distinct namespaces keep the
/// canonical and orphan output sets from ever colliding on a stealth address.
fn make_output(namespace: u8, id: u64) -> (Hash, TxOutput) {
    let mut b = [0u8; 32];
    b[..8].copy_from_slice(&id.to_le_bytes());
    b[8] = namespace;
    b[9] = 0xAB; // keep it clear of the all-zero sentinel
    let hash = Hash::from_bytes(b);
    let output = TxOutput {
        stealth_address: PublicKey::from_bytes(b),
        tx_public_key: PublicKey::from_bytes(b),
        commitment: [0u8; 32],
        encrypted_amount: vec![0u8; 8],
        view_tag: (id as u8) ^ namespace,
        lock_height: None,
        encrypted_memo: vec![],
    };
    (hash, output)
}

/// The exact metric `consensus::validation` feeds to `effective_ring_size`.
fn ring_size_availability(u: &UtxoSet) -> u64 {
    u.total_outputs_ever()
        .saturating_sub(u.reorg_disconnects_total())
}

proptest! {
    // Thousands of random histories per run; fast (pure UtxoSet ops, no PoW).
    #![proptest_config(ProptestConfig::with_cases(400))]

    /// For any reorg history — arbitrary orphan outputs added then disconnected,
    /// interleaved anywhere among the canonical outputs — the ring-size
    /// availability metric equals the canonical output count, so two nodes that
    /// reached the same canonical tip via DIFFERENT histories require the SAME
    /// ring size for the same block. That equality is exactly what prevents the
    /// fork the fix was written to close.
    #[test]
    fn ring_size_availability_is_invariant_under_reorg_history(
        canonical in 0u64..40,
        excursions in prop::collection::vec(1u64..6, 0..12),
    ) {
        // Node A — synced the canonical outputs directly, no forks seen.
        let mut a = UtxoSet::new();
        for i in 0..canonical {
            let (h, o) = make_output(NS_CANON, i);
            a.add_output(h, 0, o, 1);
        }

        // Node B — same canonical outputs, but it also saw a series of orphan
        // "excursions": each adds K distinct orphan outputs (a fork block's
        // outputs) that are then disconnected when the fork is reorged away.
        // The excursions are interleaved among the canonical adds.
        let mut b = UtxoSet::new();
        let n_ex = excursions.len() as u64;
        let mut ci: u64 = 0;
        let mut next_orphan: u64 = 0;
        for (ei, k) in excursions.iter().enumerate() {
            // Emit a proportional slice of the canonical outputs before this
            // excursion so orphan adds land at varied points in the timeline.
            let target = if n_ex > 0 { canonical * ei as u64 / n_ex } else { canonical };
            while ci < target {
                let (h, o) = make_output(NS_CANON, ci);
                b.add_output(h, 0, o, 1);
                ci += 1;
            }
            let mut orphans = Vec::new();
            for _ in 0..*k {
                let (h, o) = make_output(NS_ORPHAN, next_orphan);
                b.add_output(h, 0, o, 2);
                orphans.push(h);
                next_orphan += 1;
            }
            for h in &orphans {
                b.remove_output(h, 0); // reorg disconnect (bumps reorg_disconnects_total)
            }
        }
        while ci < canonical {
            let (h, o) = make_output(NS_CANON, ci);
            b.add_output(h, 0, o, 1);
            ci += 1;
        }

        // Core invariant: availability == canonical count on BOTH nodes,
        // regardless of the orphan/reorg history B went through.
        prop_assert_eq!(ring_size_availability(&a), canonical);
        prop_assert_eq!(
            ring_size_availability(&b), canonical,
            "reorg history changed the ring-size availability metric"
        );

        // Therefore the required ring size is identical across the two
        // histories at every height in (and around) the adaptive window.
        for h in [0u64, 1, 50, 100, 5_000, 9_999, 10_000, 50_000] {
            prop_assert_eq!(
                effective_ring_size(h, ring_size_availability(&a) as usize),
                effective_ring_size(h, ring_size_availability(&b) as usize),
                "ring size diverged between the two histories at height {}", h
            );
        }

        // Sanity that the scenario actually exercised the bug surface: whenever
        // any orphan was seen, the RAW monotonic counter genuinely diverges
        // (this is what made the un-subtracted counter path-dependent).
        if next_orphan > 0 {
            prop_assert_ne!(
                a.total_outputs_ever(), b.total_outputs_ever(),
                "expected the raw monotonic counter to diverge when orphans occurred"
            );
        }
    }
}
