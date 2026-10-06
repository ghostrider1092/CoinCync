//! Wallet-side shielded (Spark) note tracking — the receive + spend-select half
//! of shielded wallet integration.
//!
//! A wallet SCANS the on-chain Spark pool to find coins it OWNS (via the
//! libspark `identify` primitive), tracks them as [`OwnedNote`]s, reports a
//! shielded balance, and SELECTS notes to fund a spend (whose outpoints feed
//! `consensus::spark_payload::build::build_spend_payload`).
//!
//! HONEST SCOPE / gating:
//! - Gated `sketch-gk-proof` + `libspark-ffi` (needs the pool store + the real
//!   libspark backend); never compiled in a production build (shielded is off
//!   there — activation is `u64::MAX`).
//! - Scanning uses the wallet SEED (full authority), not a true view-only key.
//!   A *view-only* shielded scan is BLOCKED on an upstream libspark
//!   `IncomingViewKey` reconstruction ctor (see `docs/design/cip-shielded-notes.md`);
//!   the native `SparkScanKey` belongs to the retired native-GK engine and
//!   cannot detect a libspark bound-coin.
//! - Spent-tracking is LOCAL ([`ShieldedNoteStore::mark_spent`] on our own
//!   spend). A full sync that cross-checks the pool's spent-tag set needs each
//!   note's linking tag (seed-derivable) — a follow-up.

use spark_connector::ffi::{identify_view_only, IncomingViewKeyBytes, LibsparkBackend};
use spark_connector::{CoinBytes, SparkBackend};

use crate::consensus::spark_payload::build::{build_spend_payload, build_transfer_payload};
use crate::consensus::spark_payload::SparkPayload;
use crate::storage::spark_pool::SparkPoolStore;

/// A shielded coin this wallet owns.
#[derive(Clone, Debug)]
pub struct OwnedNote {
    /// The coin's chain outpoint — its key in the pool and what a spend targets.
    pub outpoint: Vec<u8>,
    /// Authenticated value (recovered via `identify`).
    pub value: u64,
    /// The libspark coin bytes.
    pub coin: CoinBytes,
    /// The deterministic serial context the coin was minted with (needed to
    /// recover its spend witness).
    pub serial_context: Vec<u8>,
    /// Mint height.
    pub height: u64,
    /// Locally marked spent (this wallet spent it this session).
    pub spent: bool,
}

/// The wallet's set of owned shielded notes.
#[derive(Clone, Debug, Default)]
pub struct ShieldedNoteStore {
    notes: Vec<OwnedNote>,
}

impl ShieldedNoteStore {
    pub fn new() -> Self {
        Self { notes: Vec::new() }
    }

    /// Scan the pool for coins owned by `seed`, adding any not already tracked.
    /// Returns the number of NEW owned notes found. Idempotent — re-scanning
    /// does not duplicate. Uses the libspark backend's `identify` (seed-derived
    /// view key) on each pool coin.
    pub fn scan(&mut self, seed: &[u8], pool: &SparkPoolStore) -> usize {
        let backend = LibsparkBackend;
        let mut found = 0;
        for (outpoint, coin, serial_context, height) in pool.coin_entries() {
            if self.notes.iter().any(|n| n.outpoint == outpoint) {
                continue; // already tracked
            }
            if let Ok(Some(id)) = backend.identify(seed, &coin, &serial_context) {
                self.notes.push(OwnedNote {
                    outpoint,
                    value: id.value,
                    coin,
                    serial_context,
                    height,
                    spent: false,
                });
                found += 1;
            }
        }
        found
    }

    /// Scan the pool with a WATCH-ONLY view key `(s1, P2)` — no seed. Same as
    /// [`scan`](Self::scan) but uses `identify_view_only`, so a watch-only wallet
    /// can report balances it owns. The resulting notes CANNOT be spent (this
    /// material carries no spend key); `build_self_spend`/`build_transfer` need a
    /// seed. Returns the number of NEW owned notes found. Idempotent.
    pub fn scan_view_only(
        &mut self,
        view_key: &IncomingViewKeyBytes,
        pool: &SparkPoolStore,
    ) -> usize {
        let mut found = 0;
        for (outpoint, coin, serial_context, height) in pool.coin_entries() {
            if self.notes.iter().any(|n| n.outpoint == outpoint) {
                continue;
            }
            if let Ok(Some(id)) = identify_view_only(view_key, &coin, &serial_context) {
                self.notes.push(OwnedNote {
                    outpoint,
                    value: id.value,
                    coin,
                    serial_context,
                    height,
                    spent: false,
                });
                found += 1;
            }
        }
        found
    }

    /// Unspent owned notes.
    pub fn unspent(&self) -> impl Iterator<Item = &OwnedNote> {
        self.notes.iter().filter(|n| !n.spent)
    }

    /// Total unspent shielded balance.
    pub fn balance(&self) -> u64 {
        self.unspent().map(|n| n.value).sum()
    }

    /// Number of tracked notes (spent + unspent).
    pub fn len(&self) -> usize {
        self.notes.len()
    }

    pub fn is_empty(&self) -> bool {
        self.notes.is_empty()
    }

    /// Select unspent notes whose values sum to at least `target` (greedy,
    /// largest-first). Returns the selected notes' outpoints, or `None` if the
    /// unspent balance is insufficient.
    pub fn select_for_spend(&self, target: u64) -> Option<Vec<Vec<u8>>> {
        if self.balance() < target {
            return None;
        }
        let mut notes: Vec<&OwnedNote> = self.unspent().collect();
        notes.sort_by(|a, b| b.value.cmp(&a.value)); // largest first
        let mut acc = 0u64;
        let mut chosen = Vec::new();
        for n in notes {
            if acc >= target {
                break;
            }
            acc = acc.saturating_add(n.value);
            chosen.push(n.outpoint.clone());
        }
        Some(chosen)
    }

    /// Mark the note at `outpoint` spent (call after this wallet spends it).
    /// Returns true if a matching unspent note was found.
    pub fn mark_spent(&mut self, outpoint: &[u8]) -> bool {
        for n in self.notes.iter_mut() {
            if n.outpoint == outpoint && !n.spent {
                n.spent = true;
                return true;
            }
        }
        false
    }

    /// Build a consensus-verifiable shielded spend from one owned note and mark
    /// that note spent.
    ///
    /// Selects the smallest unspent note whose value is STRICTLY GREATER than
    /// `output_value` (so the fee `note.value − output_value` is positive),
    /// builds a single-input spend over the pool's cover set anchored at
    /// `(cover_set_id, anchor_height)`, and — only if the build succeeds — marks
    /// the note spent. Returns the [`SparkPayload`], or `None` if no single note
    /// covers `output_value` or the build fails (nothing is marked in that case).
    ///
    /// NOTE: the spend pays `output_value` back to THIS wallet's own address (a
    /// consolidation / change spend). Paying a foreign recipient is a shim
    /// follow-up — `build_spend_over_set` currently hardcodes the wallet address.
    pub fn build_self_spend(
        &mut self,
        seed: &[u8],
        pool: &SparkPoolStore,
        output_value: u64,
        cover_set_id: u64,
        anchor_height: u64,
    ) -> Option<SparkPayload> {
        // Smallest unspent note strictly greater than the output (positive fee).
        let chosen = self
            .unspent()
            .filter(|n| n.value > output_value)
            .min_by_key(|n| n.value)?
            .outpoint
            .clone();
        // Build first; only mark spent if the spend actually built.
        let payload =
            build_spend_payload(seed, pool, &chosen, output_value, cover_set_id, anchor_height)?;
        self.mark_spent(&chosen);
        Some(payload)
    }

    /// Build a consensus-verifiable shielded TRANSFER paying `output_value` to
    /// `recipient_addr` (a bech32m Spark address, as bytes) and mark the funding
    /// note spent.
    ///
    /// Same note-selection as [`ShieldedNoteStore::build_self_spend`] (smallest
    /// unspent note strictly greater than `output_value`, for a positive fee),
    /// but the output coin is paid to the recipient. Once applied, that coin
    /// re-enters the pool and the recipient recovers it by scanning. Returns the
    /// [`SparkPayload`], or `None` if no single note covers `output_value`, the
    /// recipient is empty, or the build fails (nothing is marked on failure).
    pub fn build_transfer(
        &mut self,
        seed: &[u8],
        pool: &SparkPoolStore,
        recipient_addr: &[u8],
        output_value: u64,
        cover_set_id: u64,
        anchor_height: u64,
    ) -> Option<SparkPayload> {
        if recipient_addr.is_empty() {
            return None;
        }
        let chosen = self
            .unspent()
            .filter(|n| n.value > output_value)
            .min_by_key(|n| n.value)?
            .outpoint
            .clone();
        let payload = build_transfer_payload(
            seed,
            pool,
            &chosen,
            output_value,
            cover_set_id,
            anchor_height,
            recipient_addr,
        )?;
        self.mark_spent(&chosen);
        Some(payload)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::consensus::spark_payload::derive_outpoint;
    use spark_connector::ffi::{build_mint_bundle, serial_context, verify_mint_bundle};

    /// Mint an authenticated bundle to `seed` and feed the pool exactly as the
    /// chain's apply hook does (shared tx-level context, keyed by per-vout
    /// outpoint).
    fn mint_to_pool(pool: &SparkPoolStore, seed: &[u8], values: &[u64]) {
        let ctx = serial_context(&derive_outpoint(&[], 0)).unwrap();
        let bundle = build_mint_bundle(seed, values, &ctx).unwrap();
        let (_total, coins) = verify_mint_bundle(&bundle).unwrap();
        for (i, coin) in coins.iter().enumerate() {
            let op = derive_outpoint(&[], i as u32);
            assert!(pool.add_coin(op, coin.clone(), ctx.clone(), 1).is_some());
        }
    }

    #[test]
    fn scan_owns_reports_balance_and_selects() {
        let pool = SparkPoolStore::new();
        let seed_a = b"wallet-seed-a";
        let seed_b = b"wallet-seed-b";
        mint_to_pool(&pool, seed_a, &[1_000, 2_000, 3_000]);

        // Wallet A finds + values its three coins.
        let mut a = ShieldedNoteStore::new();
        assert_eq!(a.scan(seed_a, &pool), 3, "wallet A owns its 3 minted coins");
        assert_eq!(a.balance(), 6_000);
        assert_eq!(a.len(), 3);
        // Re-scan is idempotent (no duplicates).
        assert_eq!(a.scan(seed_a, &pool), 0);
        assert_eq!(a.balance(), 6_000);

        // Wallet B owns none of A's coins.
        let mut b = ShieldedNoteStore::new();
        assert_eq!(b.scan(seed_b, &pool), 0);
        assert_eq!(b.balance(), 0);

        // Spend-selection: enough → some outpoints; too much → None.
        let sel = a.select_for_spend(2_500).expect("6000 >= 2500");
        assert!(!sel.is_empty());
        assert!(a.select_for_spend(10_000).is_none(), "insufficient balance");

        // Marking a selected note spent drops the balance and is one-shot.
        let op0 = sel[0].clone();
        assert!(a.mark_spent(&op0));
        assert!(a.balance() < 6_000);
        assert!(!a.mark_spent(&op0), "already spent");
    }

    #[test]
    fn scan_view_only_finds_owned_notes_without_the_seed() {
        use spark_connector::ffi::export_incoming_view_key;

        let pool = SparkPoolStore::new();
        let seed_a = b"vo-wallet-A";
        let seed_b = b"vo-wallet-B";
        mint_to_pool(&pool, seed_a, &[1_000, 2_000]);

        // A watch-only wallet holds only A's exported view key (no seed).
        let vk_a = export_incoming_view_key(seed_a).expect("export A view key");
        let mut a = ShieldedNoteStore::new();
        assert_eq!(a.scan_view_only(&vk_a, &pool), 2, "A's view key sees its 2 coins");
        assert_eq!(a.balance(), 3_000);
        // Idempotent.
        assert_eq!(a.scan_view_only(&vk_a, &pool), 0);

        // A foreign view key sees none of A's coins.
        let vk_b = export_incoming_view_key(seed_b).expect("export B view key");
        let mut b = ShieldedNoteStore::new();
        assert_eq!(b.scan_view_only(&vk_b, &pool), 0);
        assert_eq!(b.balance(), 0);
    }

    #[test]
    fn build_self_spend_produces_consensus_verifiable_spend() {
        use crate::consensus::spark_payload::verify_spark_payload;

        let pool = SparkPoolStore::new();
        let seed = b"self-spend-seed";
        // Coins minted at height 1; anchor the spend's cover set there.
        mint_to_pool(&pool, seed, &[1_000, 2_000, 3_000]);

        let mut store = ShieldedNoteStore::new();
        assert_eq!(store.scan(seed, &pool), 3);
        assert_eq!(store.balance(), 6_000);

        // Pay 1_500 back to ourselves → smallest note strictly > 1_500 is 2_000
        // (fee 500). Build over the height-1 cover set (cover_set_id 0).
        let payload = store
            .build_self_spend(seed, &pool, 1_500, 0, 1)
            .expect("spend builds from the 2_000 note");
        assert!(payload.spend.is_some(), "produced a spend payload");

        // The wallet produced a consensus-valid spend: the node verifies it and
        // recovers exactly one linking tag.
        let backend = LibsparkBackend;
        let tags = verify_spark_payload(&pool, &backend, &payload, 0).expect("node verifies spend");
        assert_eq!(tags.len(), 1, "single-input spend → one nullifier tag");

        // The 2_000 note is now spent locally; balance drops to 4_000.
        assert_eq!(store.balance(), 4_000);

        // A second self-spend of 1_500 now selects the 3_000 note (2_000 gone).
        let payload2 = store
            .build_self_spend(seed, &pool, 1_500, 0, 1)
            .expect("spend builds from the 3_000 note");
        assert!(payload2.spend.is_some());
        assert_eq!(store.balance(), 1_000, "only the 1_000 note remains unspent");

        // 1_000 note cannot cover a 1_500 output (needs value strictly greater).
        assert!(store.build_self_spend(seed, &pool, 1_500, 0, 1).is_none());
    }

    #[test]
    fn build_transfer_sends_to_recipient_who_scans_it_from_the_pool() {
        use crate::consensus::spark_payload::verify_spark_payload;
        use spark_connector::ffi::{address_from_seed, spend_outputs};

        let pool = SparkPoolStore::new();
        let seed_a = b"transfer-sender-A";
        let seed_b = b"transfer-recipient-B";
        let addr_b = address_from_seed(seed_b).expect("B's address");

        // A owns three pool coins.
        mint_to_pool(&pool, seed_a, &[1_000, 2_000, 3_000]);
        let mut a = ShieldedNoteStore::new();
        assert_eq!(a.scan(seed_a, &pool), 3);
        assert_eq!(a.balance(), 6_000);

        // A sends 1_500 to B → funded by the 2_000 note (fee 500).
        let payload = a
            .build_transfer(seed_a, &pool, &addr_b, 1_500, 0, 1)
            .expect("transfer builds");
        assert!(payload.spend.is_some());
        assert_eq!(a.balance(), 4_000, "A's funding note is spent");

        // The node verifies the transfer.
        let backend = LibsparkBackend;
        let tags = verify_spark_payload(&pool, &backend, &payload, 0).expect("node verifies");
        assert_eq!(tags.len(), 1);

        // Feed the spend's output coin into the pool, exactly as the chain's
        // apply hook does (keyed by a per-coin id, recoverable serial context).
        let sb = payload.spend.as_ref().unwrap();
        let (out_coins, out_ctx) = spend_outputs(&sb.bundle).expect("extract outputs");
        for coin in &out_coins {
            let key = blake3::hash(&coin.0).as_bytes().to_vec();
            assert!(pool.add_coin(key, coin.clone(), out_ctx.clone(), 2).is_some());
        }

        // B scans the pool and finds exactly the 1_500 coin A sent.
        let mut b = ShieldedNoteStore::new();
        let found = b.scan(seed_b, &pool);
        assert_eq!(found, 1, "B owns exactly the transferred coin");
        assert_eq!(b.balance(), 1_500, "B receives the sent value");

        // A does NOT see the coin it sent away (re-scan finds nothing new).
        assert_eq!(a.scan(seed_a, &pool), 0, "the sent coin is not A's");

        // An empty recipient is rejected.
        assert!(a.build_transfer(seed_a, &pool, &[], 500, 0, 1).is_none());
    }
}
