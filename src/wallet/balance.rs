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

/// In-flight reservation on a UTXO. Tracks that the wallet has built and
/// submitted a tx using this UTXO as input, but the chain hasn't yet
/// confirmed or rejected that tx. While reserved, the UTXO is hidden from
/// `available_utxos()` so consecutive sends from the same wallet cannot
/// race to pick the same input.
///
/// Reservations are released in three ways:
///   1. **Explicit confirmation**: scan sees the claimant tx's key_image
///      land in the chain. `mark_spent` clears the reservation as part
///      of marking the UTXO permanently spent.
///   2. **Explicit failure**: a wallet caller (e.g. cmd_send) sees its
///      submission rejected and calls `release_reservations_by_tx` to
///      free the UTXOs immediately.
///   3. **Auto-expiry**: when the chain advances past
///      `height + RESERVATION_EXPIRY_BLOCKS`, the reservation is treated
///      as abandoned. Set above the mempool's TX_EXPIRY_BLOCKS (288) so
///      the wallet can never disagree with the mempool: if a reservation
///      expires here, the in-flight tx has also fallen out of mempool.
#[derive(Clone, Debug, Serialize, Deserialize, BorshSerialize, BorshDeserialize, PartialEq, Eq)]
pub struct Reservation {
    /// The tx that claims this UTXO.
    pub by_tx: Hash,
    /// Chain height when the reservation was made.
    pub height: u64,
}

/// Number of blocks after a reservation is made before the wallet treats
/// it as abandoned and the UTXO becomes selectable again. Must be >= the
/// mempool's TX_EXPIRY_BLOCKS (288) so a reservation can never expire
/// while the tx is still active in any peer's mempool.
pub const RESERVATION_EXPIRY_BLOCKS: u64 = 300;

/// Reservation conflict: caller tried to reserve a UTXO that is already
/// held by another in-flight tx. Carries the UTXO key plus (when known)
/// the existing reservation so callers can log diagnostically.
#[derive(Clone, Debug)]
pub struct ReservationConflict {
    pub utxo_key: (Hash, u8),
    pub existing: Option<Reservation>,
}

impl std::fmt::Display for ReservationConflict {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self.existing {
            Some(r) => write!(
                f,
                "UTXO {:?}:{} already reserved by tx {} (since height {})",
                self.utxo_key.0, self.utxo_key.1, r.by_tx, r.height
            ),
            None => write!(
                f,
                "UTXO {:?}:{} reservation conflict (no record)",
                self.utxo_key.0, self.utxo_key.1
            ),
        }
    }
}

impl std::error::Error for ReservationConflict {}

#[derive(Clone, Default)]
pub struct Balance {
    utxos: HashMap<(Hash, u8), UTXO>,
    /// In-flight UTXO claims. See `Reservation` doc for lifecycle.
    /// Persisted separately from `utxos` (wallet sidecar `.reservations`)
    /// so tx-build crashes between reserve and submit don't lose state.
    reservations: HashMap<(Hash, u8), Reservation>,
    /// O(1) reverse index from KeyImage to (tx_hash, output_index).
    /// (Item 8) Without this, `mark_spent_by_key_image` linearly scans
    /// every UTXO once per chain key-image, turning scan into O(utxos *
    /// inputs_per_block). Wallets with thousands of UTXOs and active
    /// chain throughput hit this hard. Index is rebuilt-from-utxos in
    /// `add_utxo` and lookups always check `!utxo.spent` so a stale
    /// entry (UTXO marked spent without index update) is harmless —
    /// just a dead pointer.
    key_image_index: HashMap<KeyImage, (Hash, u8)>,
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
        let key = (utxo.tx_hash, utxo.output_index);
        // (Item 8) Maintain key_image -> utxo-key reverse index.
        self.key_image_index.insert(utxo.key_image, key);
        self.utxos.insert(key, utxo);
    }

    /// O(1) lookup of a UTXO key by its key image. Returns None if no
    /// owned UTXO has this key image, or if the key image was indexed
    /// but the corresponding UTXO is now marked spent. Used by
    /// `Wallet::mark_spent_by_key_image` to avoid the prior O(n) scan.
    pub fn lookup_by_key_image(&self, ki: &KeyImage) -> Option<(Hash, u8)> {
        let key = self.key_image_index.get(ki)?;
        match self.utxos.get(key) {
            Some(u) if !u.spent => Some(*key),
            _ => None,
        }
    }

    /// Drop a set of outputs from the wallet's UTXO state. Returns the
    /// number of UTXOs actually removed (silently skips entries the wallet
    /// no longer has, which is the expected path when a rewind retargets
    /// a height that the wallet had already processed partially or whose
    /// outputs were spent and pruned).
    ///
    /// Used during reorg rewind: when `WalletScanner::rewind_to_height`
    /// returns a `RewindOutcome`, its `outputs_to_remove` field lists
    /// the `(tx_hash, output_index)` pairs the scanner journaled as
    /// "ours" in the now-orphaned blocks. Applying that list here:
    ///   - drops the UTXOs from `self.utxos`
    ///   - clears each UTXO's `key_image` from `self.key_image_index`
    ///     (the reverse-lookup index would otherwise hold a dead pointer)
    ///   - removes any in-flight reservation on the dropped UTXO (an
    ///     orphaned UTXO cannot be the input to a canonical-chain tx,
    ///     so the reservation is moot regardless of by_tx's state).
    pub fn remove_outputs(&mut self, outputs: &[(Hash, u8)]) -> usize {
        let mut removed = 0;
        for key in outputs {
            if let Some(utxo) = self.utxos.remove(key) {
                self.key_image_index.remove(&utxo.key_image);
                self.reservations.remove(key);
                removed += 1;
            }
        }
        removed
    }

    /// Mark a UTXO as confirmed-spent on chain.
    /// Also releases any in-flight reservation on this UTXO (the reservation
    /// has been "consumed" by chain confirmation, no longer needed).
    pub fn mark_spent(&mut self, tx_hash: Hash, output_index: u8) {
        let key = (tx_hash, output_index);
        if let Some(utxo) = self.utxos.get_mut(&key) {
            utxo.spent = true;
        }
        // Reservation is now satisfied by the actual on-chain spend. Drop it
        // so subsequent expiry sweeps don't re-emit log noise about it.
        self.reservations.remove(&key);
    }

    /// Inverse of `mark_spent_by_key_image`: flip the spent flag on the
    /// UTXO this key image identifies back to `false`. Returns true if
    /// a UTXO was found and updated, false otherwise.
    ///
    /// Used during reorg rewind for the Task #1b case: when the only
    /// reason a UTXO was marked spent is a tx in a now-orphaned block,
    /// the rewind needs to restore that UTXO to spendable state. The
    /// scanner journals such key images via `record_spend_for_last_block`
    /// and surfaces them via `RewindOutcome.key_images_to_unspend`.
    ///
    /// Looks up via `key_image_index` even when the UTXO is currently
    /// spent — `lookup_by_key_image` filters those out by design, so we
    /// reach into the underlying maps here. The reverse index entry was
    /// preserved across `mark_spent` precisely to support this path.
    pub fn unmark_spent_by_key_image(&mut self, ki: &KeyImage) -> bool {
        let key = match self.key_image_index.get(ki) {
            Some(k) => *k,
            None => return false,
        };
        match self.utxos.get_mut(&key) {
            Some(u) if u.spent => {
                u.spent = false;
                true
            }
            // UTXO is present but already unspent — caller may be
            // double-applying; report no-op rather than panic.
            Some(_) => false,
            None => false,
        }
    }

    /// Total confirmed balance (including immature + locked, AND including
    /// in-flight reservations — a reserved UTXO still belongs to the wallet,
    /// it just isn't available for new tx-building).
    pub fn total(&self) -> Amount {
        self.utxos.values().filter(|u| !u.spent).map(|u| u.amount).sum()
    }

    /// Spendable balance: unspent, past `min_age`, past `lock_height`,
    /// and NOT currently reserved by an in-flight tx (with reservation
    /// expiry honored — if a reservation is older than
    /// `RESERVATION_EXPIRY_BLOCKS`, the UTXO counts as spendable again).
    pub fn spendable(&self, current_height: u64, min_age: u64) -> Amount {
        self.utxos.values()
            .filter(|u| !u.spent
                && current_height >= u.height.saturating_add(min_age)
                && u.lock_height.map_or(true, |lh| current_height >= lh)
                && !self.is_reserved(&(u.tx_hash, u.output_index), current_height))
            .map(|u| u.amount)
            .sum()
    }

    /// UTXOs that are legally spendable right now: unspent, mature, unlocked,
    /// AND not held by an active in-flight reservation (expired reservations
    /// are ignored, see `is_reserved`).
    pub fn available_utxos(&self, current_height: u64, min_age: u64) -> Vec<&UTXO> {
        self.utxos.values()
            .filter(|u| !u.spent
                && current_height >= u.height.saturating_add(min_age)
                && u.lock_height.map_or(true, |lh| current_height >= lh)
                && !self.is_reserved(&(u.tx_hash, u.output_index), current_height))
            .collect()
    }

    // === Reservation API (Item 1: in-flight UTXO tracking) =============

    /// True if the UTXO key is currently held by a reservation that hasn't
    /// yet expired. Expiry is checked dynamically so callers don't need to
    /// remember to sweep. Returns false for UTXOs with no reservation OR
    /// whose reservation is older than RESERVATION_EXPIRY_BLOCKS.
    pub fn is_reserved(&self, key: &(Hash, u8), current_height: u64) -> bool {
        match self.reservations.get(key) {
            Some(r) => current_height < r.height.saturating_add(RESERVATION_EXPIRY_BLOCKS),
            None => false,
        }
    }

    /// Reserve a set of UTXOs for an in-flight tx. Atomic: if ANY of the
    /// requested UTXOs is already reserved (and not expired), the call
    /// returns Err and no reservations are added. The intended pattern is:
    ///
    ///   1. Caller builds tx (selects UTXOs via `available_utxos`).
    ///   2. Caller calls `reserve_utxos(&keys, tx_hash, current_height)`.
    ///   3. If reserve succeeded, caller submits tx to mempool.
    ///   4. On submit success: leave reservation in place (scan will
    ///      eventually clear it when the tx confirms via `mark_spent`).
    ///   5. On submit failure: caller calls `release_reservations_by_tx`
    ///      immediately to make the UTXOs available again.
    pub fn reserve_utxos(
        &mut self,
        keys: &[(Hash, u8)],
        by_tx: Hash,
        current_height: u64,
    ) -> Result<(), ReservationConflict> {
        // First pass: validate that every requested UTXO is free. We do
        // this BEFORE inserting any reservations so a partial failure
        // doesn't leave a confused state.
        for k in keys {
            if self.is_reserved(k, current_height) {
                let existing = self.reservations.get(k).cloned();
                return Err(ReservationConflict {
                    utxo_key: *k,
                    existing,
                });
            }
        }
        // Second pass: insert.
        for k in keys {
            self.reservations.insert(*k, Reservation { by_tx, height: current_height });
        }
        Ok(())
    }

    /// Release every reservation held by `by_tx`. Returns the number of
    /// reservations actually released. Used when a submission is rejected
    /// and the caller wants to immediately re-select.
    pub fn release_reservations_by_tx(&mut self, by_tx: Hash) -> usize {
        let to_remove: Vec<(Hash, u8)> = self.reservations.iter()
            .filter(|(_, r)| r.by_tx == by_tx)
            .map(|(k, _)| *k)
            .collect();
        for k in &to_remove {
            self.reservations.remove(k);
        }
        to_remove.len()
    }

    /// Sweep expired reservations. Returns the number released. Cheap to
    /// call periodically (e.g., every scan invocation) — typical wallets
    /// will have at most a handful of in-flight reservations.
    pub fn release_expired_reservations(&mut self, current_height: u64) -> usize {
        let to_remove: Vec<(Hash, u8)> = self.reservations.iter()
            .filter(|(_, r)| current_height >= r.height.saturating_add(RESERVATION_EXPIRY_BLOCKS))
            .map(|(k, _)| *k)
            .collect();
        for k in &to_remove {
            self.reservations.remove(k);
        }
        to_remove.len()
    }

    /// Snapshot of all current reservations (for persistence sidecar).
    pub fn all_reservations(&self) -> Vec<((Hash, u8), Reservation)> {
        self.reservations.iter().map(|(k, v)| (*k, v.clone())).collect()
    }

    /// Restore reservations from a persisted sidecar. Does NOT clear
    /// existing reservations; the caller is expected to load on a fresh
    /// Balance struct. Skips entries with stale (already-expired) heights
    /// to keep the in-memory set tight.
    pub fn restore_reservations(
        &mut self,
        entries: Vec<((Hash, u8), Reservation)>,
        current_height: u64,
    ) {
        for (key, reservation) in entries {
            if current_height < reservation.height.saturating_add(RESERVATION_EXPIRY_BLOCKS) {
                self.reservations.insert(key, reservation);
            }
        }
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

    // === Reservation tests (Item 1: in-flight UTXO tracking) ==========

    fn make_utxo_at_idx(amount: u64, height: u64, idx: u8) -> UTXO {
        UTXO {
            tx_hash: Hash::from_bytes([idx; 32]),
            output_index: idx,
            amount: Amount::from_atomic(amount),
            height,
            key_image: KeyImage::from_bytes([idx; 32]),
            spent: false,
            amount_blinding_bytes: [0u8; 32],
            tx_public_key: PublicKey::from_bytes([0u8; 32]),
            lock_height: None,
        }
    }

    /// Reserved UTXOs are excluded from `available_utxos` and `spendable`.
    /// This is the regression case for the 2026-05-07 bug where two
    /// consecutive sends from the same wallet picked the same input.
    #[test]
    fn test_reserve_excludes_from_available() {
        let mut balance = Balance::new();
        balance.add_utxo(make_utxo_at_idx(100, 0, 1));
        balance.add_utxo(make_utxo_at_idx(200, 0, 2));
        assert_eq!(balance.available_utxos(100, 10).len(), 2);
        assert_eq!(balance.spendable(100, 10), Amount::from_atomic(300));

        let tx_hash = Hash::from_bytes([99; 32]);
        balance.reserve_utxos(
            &[(Hash::from_bytes([1; 32]), 1)],
            tx_hash,
            100,
        ).expect("reserve");
        assert_eq!(balance.available_utxos(100, 10).len(), 1);
        assert_eq!(balance.spendable(100, 10), Amount::from_atomic(200));
    }

    /// Re-reserving an already-reserved UTXO returns ReservationConflict
    /// without partially mutating state. Both the request that succeeded
    /// and the conflict must hold even when the second request includes a
    /// mix of free and reserved UTXOs.
    #[test]
    fn test_reserve_double_fails_atomically() {
        let mut balance = Balance::new();
        balance.add_utxo(make_utxo_at_idx(100, 0, 1));
        balance.add_utxo(make_utxo_at_idx(200, 0, 2));
        let tx_a = Hash::from_bytes([0xAA; 32]);
        let tx_b = Hash::from_bytes([0xBB; 32]);
        balance.reserve_utxos(&[(Hash::from_bytes([1; 32]), 1)], tx_a, 100).expect("first");
        // tx_b tries to reserve UTXO 1 (held by tx_a) AND UTXO 2 (free).
        // Atomic behavior: neither gets reserved, error returned.
        let err = balance.reserve_utxos(
            &[(Hash::from_bytes([1; 32]), 1), (Hash::from_bytes([2; 32]), 2)],
            tx_b,
            100,
        ).expect_err("must fail");
        assert_eq!(err.utxo_key, (Hash::from_bytes([1; 32]), 1));
        // UTXO 2 must still be available since the conflict aborted before
        // any insertion.
        assert!(!balance.is_reserved(&(Hash::from_bytes([2; 32]), 2), 100));
    }

    /// `release_reservations_by_tx` only releases reservations from the
    /// given tx, not unrelated ones held by other in-flight txs.
    #[test]
    fn test_release_only_matches_caller_tx() {
        let mut balance = Balance::new();
        balance.add_utxo(make_utxo_at_idx(100, 0, 1));
        balance.add_utxo(make_utxo_at_idx(200, 0, 2));
        let tx_a = Hash::from_bytes([0xAA; 32]);
        let tx_b = Hash::from_bytes([0xBB; 32]);
        balance.reserve_utxos(&[(Hash::from_bytes([1; 32]), 1)], tx_a, 100).unwrap();
        balance.reserve_utxos(&[(Hash::from_bytes([2; 32]), 2)], tx_b, 100).unwrap();
        let released = balance.release_reservations_by_tx(tx_a);
        assert_eq!(released, 1);
        assert!(!balance.is_reserved(&(Hash::from_bytes([1; 32]), 1), 100));
        assert!(balance.is_reserved(&(Hash::from_bytes([2; 32]), 2), 100));
    }

    /// Reservations expire after RESERVATION_EXPIRY_BLOCKS. Past expiry,
    /// the UTXO becomes selectable again without an explicit release call.
    /// This handles the case where a tx silently drops out of mempool.
    #[test]
    fn test_reservation_expiry() {
        let mut balance = Balance::new();
        balance.add_utxo(make_utxo_at_idx(100, 0, 1));
        let tx = Hash::from_bytes([0xCC; 32]);
        balance.reserve_utxos(&[(Hash::from_bytes([1; 32]), 1)], tx, 100).unwrap();
        assert!(balance.is_reserved(&(Hash::from_bytes([1; 32]), 1), 100));
        // Just before expiry: still reserved.
        assert!(balance.is_reserved(
            &(Hash::from_bytes([1; 32]), 1),
            100 + RESERVATION_EXPIRY_BLOCKS - 1,
        ));
        // At expiry (current_height >= height + EXPIRY): freed.
        assert!(!balance.is_reserved(
            &(Hash::from_bytes([1; 32]), 1),
            100 + RESERVATION_EXPIRY_BLOCKS,
        ));
    }

    /// `mark_spent` consumes the reservation: a confirmed-on-chain spend
    /// is the canonical way for an in-flight tx to graduate, and we don't
    /// want stale reservations lingering in the persisted sidecar.
    #[test]
    fn test_mark_spent_clears_reservation() {
        let mut balance = Balance::new();
        balance.add_utxo(make_utxo_at_idx(100, 0, 1));
        let tx = Hash::from_bytes([0xDD; 32]);
        balance.reserve_utxos(&[(Hash::from_bytes([1; 32]), 1)], tx, 100).unwrap();
        balance.mark_spent(Hash::from_bytes([1; 32]), 1);
        assert!(!balance.is_reserved(&(Hash::from_bytes([1; 32]), 1), 100));
    }

    /// `release_expired_reservations` actually removes entries from the
    /// underlying map (not just hides them via is_reserved). Confirms
    /// the persistence sidecar won't grow unboundedly.
    #[test]
    fn test_release_expired_actually_removes() {
        let mut balance = Balance::new();
        balance.add_utxo(make_utxo_at_idx(100, 0, 1));
        balance.add_utxo(make_utxo_at_idx(200, 0, 2));
        let tx = Hash::from_bytes([0xEE; 32]);
        balance.reserve_utxos(
            &[(Hash::from_bytes([1; 32]), 1), (Hash::from_bytes([2; 32]), 2)],
            tx,
            100,
        ).unwrap();
        assert_eq!(balance.all_reservations().len(), 2);
        let released = balance.release_expired_reservations(100 + RESERVATION_EXPIRY_BLOCKS);
        assert_eq!(released, 2);
        assert_eq!(balance.all_reservations().len(), 0);
    }

    // === Reorg rewind tests (Task #3b: balance side) ==================

    /// `remove_outputs` drops the UTXO AND clears its `key_image_index`
    /// entry. Without the index cleanup, `lookup_by_key_image` would
    /// return a dead pointer after a reorg.
    #[test]
    fn test_remove_outputs_drops_utxo_and_key_image() {
        let mut balance = Balance::new();
        balance.add_utxo(make_utxo_at_idx(100, 0, 1));
        balance.add_utxo(make_utxo_at_idx(200, 0, 2));
        let ki_dropped = KeyImage::from_bytes([1; 32]);
        let ki_kept = KeyImage::from_bytes([2; 32]);

        let removed = balance.remove_outputs(&[(Hash::from_bytes([1; 32]), 1)]);
        assert_eq!(removed, 1);
        assert_eq!(balance.unspent_utxos().len(), 1);
        assert!(balance.lookup_by_key_image(&ki_dropped).is_none());
        // Other UTXO untouched.
        assert!(balance.lookup_by_key_image(&ki_kept).is_some());
    }

    /// `remove_outputs` returns 0 when none of the keys are present.
    /// Idempotent under repeat calls — the reorg orchestrator may
    /// double-apply on retry without corrupting state.
    #[test]
    fn test_remove_outputs_missing_keys_silently_skip() {
        let mut balance = Balance::new();
        balance.add_utxo(make_utxo_at_idx(100, 0, 1));
        let removed = balance.remove_outputs(&[
            (Hash::from_bytes([0xAA; 32]), 0),
            (Hash::from_bytes([0xBB; 32]), 0),
        ]);
        assert_eq!(removed, 0);
        // Re-applying the same removal again is still safe.
        let again = balance.remove_outputs(&[(Hash::from_bytes([1; 32]), 1)]);
        assert_eq!(again, 1);
        let third = balance.remove_outputs(&[(Hash::from_bytes([1; 32]), 1)]);
        assert_eq!(third, 0);
    }

    /// `unmark_spent_by_key_image` restores a previously-spent UTXO to
    /// spendable. Used during reorg rewind for the Task #1b case
    /// (orphaned tx spent one of our pre-existing UTXOs).
    #[test]
    fn test_unmark_spent_by_key_image_restores_utxo() {
        let mut balance = Balance::new();
        balance.add_utxo(make_utxo_at_idx(100, 0, 1));
        let ki = KeyImage::from_bytes([1; 32]);
        balance.mark_spent(Hash::from_bytes([1; 32]), 1);

        // After mark_spent, lookup_by_key_image returns None (filters spent).
        assert!(balance.lookup_by_key_image(&ki).is_none());
        // Balance total reflects the spent state.
        assert_eq!(balance.total(), Amount::ZERO);

        // Unmark — UTXO becomes spendable again.
        assert!(balance.unmark_spent_by_key_image(&ki));
        assert!(balance.lookup_by_key_image(&ki).is_some());
        assert_eq!(balance.total(), Amount::from_atomic(100));
    }

    /// `unmark_spent_by_key_image` returns false on unknown key images
    /// and on already-unspent UTXOs — both are no-ops, never errors,
    /// so the orchestrator can double-apply safely.
    #[test]
    fn test_unmark_spent_by_key_image_noop_paths() {
        let mut balance = Balance::new();
        balance.add_utxo(make_utxo_at_idx(100, 0, 1));
        let known_ki = KeyImage::from_bytes([1; 32]);
        let unknown_ki = KeyImage::from_bytes([0xFF; 32]);

        // Already unspent — no-op, returns false.
        assert!(!balance.unmark_spent_by_key_image(&known_ki));
        // Unknown key image — no-op, returns false.
        assert!(!balance.unmark_spent_by_key_image(&unknown_ki));
    }

    /// `remove_outputs` also releases any reservation on the removed
    /// UTXO. The in-flight tx that held the reservation is itself dead
    /// (its inputs are now invalid), so the reservation is moot.
    #[test]
    fn test_remove_outputs_releases_reservation() {
        let mut balance = Balance::new();
        balance.add_utxo(make_utxo_at_idx(100, 0, 1));
        let tx = Hash::from_bytes([0xDE; 32]);
        balance.reserve_utxos(&[(Hash::from_bytes([1; 32]), 1)], tx, 100).unwrap();
        assert_eq!(balance.all_reservations().len(), 1);

        balance.remove_outputs(&[(Hash::from_bytes([1; 32]), 1)]);
        assert_eq!(balance.all_reservations().len(), 0);
        // UTXO is gone too.
        assert_eq!(balance.unspent_utxos().len(), 0);
    }

    /// `restore_reservations` skips already-expired entries: persistence
    /// across long pauses (laptop closed for hours, wallet idle for days)
    /// shouldn't resurrect dead reservations.
    #[test]
    fn test_restore_skips_expired() {
        let mut balance = Balance::new();
        let stale = (Hash::from_bytes([1; 32]), 1u8);
        let fresh = (Hash::from_bytes([2; 32]), 2u8);
        let entries = vec![
            (stale, Reservation { by_tx: Hash::from_bytes([0; 32]), height: 0 }),
            (fresh, Reservation { by_tx: Hash::from_bytes([0; 32]), height: 1000 }),
        ];
        balance.restore_reservations(entries, 1000 + 50); // stale is way past expiry, fresh is recent
        assert!(!balance.is_reserved(&stale, 1000 + 50));
        assert!(balance.is_reserved(&fresh, 1000 + 50));
    }
}
