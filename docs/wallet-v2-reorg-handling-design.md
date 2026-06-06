<!-- markdownlint-disable MD013 MD032 MD036 MD060 -->
# Wallet reorg-handling — design

**Status:** Design / pre-implementation (2026-05-23). Identifies an open functional gap in the v1.0 wallet that the audit firm will flag and that affects real-world mainnet correctness from day 1. No code written yet against this doc.

**Severity:** **High.** Not a v1.0 ship blocker in the "chain doesn't start" sense, but a **correctness gap** that causes user-visible balance corruption when reorgs happen. Mainnet reorgs are inevitable (especially with CIP-009.D dormant per the decision doc).

---

## 1. The problem

The wallet has no reorg-handling code. Verified by:

```bash
grep -lE "reorg|rewind|undo|rollback" src/wallet/*.rs
# (returns nothing)
```

What this means in practice — when the chain reorgs:

1. **Scanner state stays advanced.** `Scanner::last_height` + `last_hash` advance monotonically and are never checked against canonical-chain hashes. Once at height N, the scanner has no way to detect that N is no longer on the canonical chain.

2. **Decrypted outputs from reorged-out blocks linger.** Any output the wallet found in a reorged-out block remains in the wallet's UTXO set, displayed as spendable. Attempting to spend it produces a TX with key images the network doesn't yet know about — likely rejected, but the user sees the "send" fail mysteriously.

3. **Spent key_images stay marked spent.** `Balance::key_image_index` is insert-only after a normal "I spent this" lifecycle. If the spending transaction is reorged out, the key image is *actually unspent again on the new canonical chain*, but the wallet still treats it as spent — the user sees a lower balance than the actual chain says they have.

4. **TX history shows phantom transactions.** `History::add()` doesn't differentiate "received in canonical block" from "received in some-block-that-may-get-orphaned". After a reorg, history rows can reference TXs that don't exist on the canonical chain.

5. **Mining rewards in reorged-out blocks vanish silently.** A miner who finds a block on the orphaned side sees the coinbase reward in their wallet, watches it disappear when the reorg resolves, and gets no signal about why.

The chain side has rich reorg machinery (`evaluate_reorg_acceptability`, `find_fork_point` now returning `Option<u64>` per the recent fix, `rewind_phase2_stores`, the 6-layer reorg defense). The wallet side has **none of this awareness propagated to it**.

---

## 2. User-visible symptoms

| Scenario | What the user sees | Severity |
|---|---|---|
| Their incoming TX was confirmed in block N, then N gets reorged out (depth ≤10) | Balance shows the receive, then on rescan one block later the balance silently drops back. No notification, no history entry explaining it. | **High** |
| Their outgoing TX was mined in block N, then N gets reorged out | Wallet shows it as confirmed; the canonical chain shows the recipient never got it. Both wallets disagree with reality. | **Critical** |
| They mined a block that gets orphaned | Coinbase reward appears, then silently vanishes on next scan tick. No audit trail. | **High** (miner UX) |
| Wallet was offline during a reorg, comes back online | First scan tick advances past the now-orphaned blocks and writes them into history again, then writes the new canonical blocks too — double-counting. | **Critical** |
| Reorg depth > scanner.last_height (chain rolled past wallet) | Undefined behavior. Probably silent staleness. | **Catastrophic** in the rare case |

The Critical-severity cases are real day-1 mainnet bugs that the audit firm will write up.

---

## 3. Design proposal

### 3.1 Detection

The scanner gains a **chain-continuity check** in `scan_block(&self, block: &Block)`:

```rust
// Pseudo-code shape (real impl lands in src/wallet/scanner.rs)
pub fn scan_block(&mut self, block: &Block) -> ScanResult {
    let block_hash = block.hash();
    let block_height = block.height();
    let block_prev_hash = block.header.prev_hash;

    // Reorg detection. If we previously scanned a block at height N-1
    // and its hash doesn't match this block's prev_hash, we're on a
    // different chain than we used to be.
    if block_height > 0 && block_height == self.last_height + 1 {
        if block_prev_hash != self.last_hash {
            // Reorg: this block is the first canonical block after the
            // fork point, but we don't know how deep yet. Caller must
            // resolve via rewind_and_rescan(target_height) below.
            return ScanResult::ReorgDetected {
                at_height: block_height,
                expected_prev: self.last_hash,
                actual_prev: block_prev_hash,
            };
        }
    }
    if block_height <= self.last_height {
        // Receiving a block at an old height also signals reorg.
        return ScanResult::ReorgDetected {
            at_height: block_height,
            expected_prev: self.last_hash,
            actual_prev: block_prev_hash,
        };
    }

    // ... existing per-tx scan logic, with the diff journaled below ...
    let diff = BlockApplyDiff {
        height: block_height,
        block_hash,
        outputs_added: /* ... */,
        key_images_marked_spent: /* ... */,
        tx_history_entries_added: /* ... */,
    };
    self.journal.push(diff);
    self.last_height = block_height;
    self.last_hash = block_hash;

    ScanResult::Scanned { outputs: /* ... */ }
}
```

The new `ScanResult` enum replaces the current `Vec<DecryptedOutput>` return. Old callers continue to work via a `.outputs()` accessor on `ScanResult::Scanned`.

### 3.2 Journal

Add a per-scanned-block journal so we can rewind without re-deriving state:

```rust
struct BlockApplyDiff {
    height: u64,
    block_hash: Hash,
    outputs_added: Vec<KeyImage>,                // for removal from UTXO set
    key_images_marked_spent: Vec<KeyImage>,      // for un-marking on rewind
    tx_history_entries_added: Vec<Hash>,         // for removal from history
}

pub struct Scanner {
    // ... existing fields ...

    /// Rolling journal of the last N scanned blocks. N = max_reorg_depth +
    /// safety margin (e.g., 200). Older entries are dropped — reorgs
    /// deeper than this trigger a full rescan from genesis or from the
    /// last hardcoded checkpoint.
    journal: VecDeque<BlockApplyDiff>,
    journal_max: usize,
}
```

The journal bounds the memory cost. At ~20 KiB per `BlockApplyDiff` for a typical block × 200 = 4 MiB max. Trivial.

### 3.3 Rewind

New method on `Scanner`:

```rust
/// Undo wallet state from `(target_height, infinity)` down to
/// `(0, target_height]`. After this call the scanner's last_height +
/// last_hash refer to the journal entry at target_height (or genesis
/// if target_height == 0).
///
/// Returns Err if target_height is older than the journal's earliest
/// entry — caller must trigger a full rescan from a hardcoded
/// checkpoint or genesis in that case.
pub fn rewind_to_height(&mut self, target_height: u64) -> Result<RewindOutcome> {
    // Pop journal entries from the end until we reach target_height.
    // For each popped entry: undo its outputs/key_images/history adds.
    // Update last_height + last_hash to the entry just before target_height.
    // Return diagnostic info (how many entries undone, what got removed).
}

pub struct RewindOutcome {
    entries_undone: usize,
    outputs_removed: usize,
    key_images_unmarked: usize,
    history_entries_removed: usize,
}
```

### 3.4 Trigger: where does rewind get called?

Two trigger paths:

**(A) Inline during `scan_block`** when `ScanResult::ReorgDetected` returns. The orchestrator (currently `background_sync.rs::run_scan_cycle` or similar) must:

1. Receive the `ReorgDetected` result
2. Query the node for the canonical chain at the fork-detected height
3. Walk back through both chains (or use the chain's `find_fork_point` exposed via RPC) to find the deepest common ancestor
4. Call `scanner.rewind_to_height(fork_point)`
5. Re-scan from fork_point + 1 forward, using the new canonical chain

**(B) Periodic chain-tip-hash check.** Cheap background poll: ask the node for `get_block_hash(scanner.last_height)`. If the returned hash doesn't match `scanner.last_hash`, trigger the same flow as (A) without waiting for the next scan tick.

Both should be implemented; (B) catches the "wallet was offline through a reorg" case that (A) doesn't surface until the next forward-block arrives.

### 3.5 RPC surface needed

The wallet needs node RPCs:

- `get_block_hash_at_height(h: u64) -> Hash` — already exists as part of the `get_block_header` family. Just expose it ergonomically.
- `find_fork_point(known_hash: Hash, known_height: u64) -> Option<u64>` — new. Server walks back from its tip looking for the fork point against the wallet's last-known state. Returns `Some(fork_point_height)` or `None` if the wallet's last-known hash isn't on any reachable ancestor (catastrophic — wallet must rescan from a checkpoint or genesis).

These belong in `src/rpc/lightwallet.rs` (the wallet-facing RPC namespace) or a new `wallet_reorg_*` subset.

### 3.6 Notification to the user

When a reorg is detected + rewind completes, emit a wallet-state event so the UI can:

- Show a non-modal banner ("Chain reorg detected at depth N — your balance was updated")
- Add an audit-trail entry to the TX history (separate "Event: Reorg" row)
- Avoid silently changing the balance number without explanation

This is critical for trust. Users who see their balance change for no reason will not use the wallet.

The push-event channel `wallet_state` already exists (per the v2 wiring); add a new field `last_reorg_at_height: Option<u64>` and a `last_reorg_depth: Option<u64>` so the UI can render the banner.

---

## 4. Implementation plan

In dependency order, each task is a separate commit:

| # | Task | Files touched | Test coverage | Effort |
|---|---|---|---|---|
| 1 | Add `BlockApplyDiff` + journal to `Scanner` | scanner.rs | unit test: journal-bounded growth | ~2-3 hours — **DONE 2026-05-22** |
| 2 | Refactor `scan_block` return type to `ScanResult` enum (Scanned / ReorgDetected) | scanner.rs + callers | unit test: returns ReorgDetected on non-monotonic | ~2-3 hours — **DONE 2026-05-22** (additive: scan_block_with_result, legacy scan_block delegates; scan_blocks migrated) |
| 3 | Implement `Scanner::rewind_to_height` | scanner.rs | unit test: rewind window + idempotency | ~2 hours — **DONE 2026-05-22** |
| 3b | Wire `outputs_to_remove` through Balance + TransactionHistory | balance.rs + history.rs | unit tests: remove_outputs / remove_incoming_outputs / revert_outgoing_above_height | ~2 hours — **DONE 2026-05-23** |
| 4 | Add `find_fork_point` RPC method | src/rpc/lightwallet.rs | integration test: returns correct fork | ~2 hours — **DONE 2026-05-23** (MVP stub: cheap-path canonical-hash match; walk-backwards deferred to v1.1) |
| 1b | Extend `BlockApplyDiff` with `key_images_marked_spent` + propagate to `RewindOutcome.key_images_to_unspend`; add `Balance::unmark_spent_by_key_image` + `TransactionHistory::unmark_spent_by_key_image` + `Wallet` wrapper | scanner.rs + balance.rs + history.rs + wallet.rs | unit tests: spend journaling + reverse-order surfacing on rewind | ~1 hour — **DONE 2026-05-23** |
| 5 | Wire reorg-trigger path (A) in background_sync | wallet/background_sync.rs | unit tests via StubReorgScanner + helper round-trip | ~2-3 hours — **DONE 2026-05-23** (ScanBlockOutcome + ReorgRecoveryStats + try_reorg_recovery helper; orchestrator branches on ReorgDetected) |
| 6 | Wire periodic tip-hash check (B) | wallet/background_sync.rs | unit tests via current_position default + try_reorg_recovery shared path | ~2-3 hours — **DONE 2026-05-23** (tip_check_interval_secs config; reuses Task #5 helper) |
| 7 | Emit `wallet_state` event on rewind with depth/height | coincync-wallet-v2/src-tauri | manual UI test pending | ~1-2 hours — **DONE 2026-05-23** (AppState + WalletStateEvent fields; scan_wallet output parser; dismiss_reorg_notification command) |
| 8 | Add UI banner for reorg notification | coincync-wallet-v2/web/src | manual UI test pending | ~1-2 hours — **DONE 2026-05-23** (renderShell injects reorgBannerHtml + dismiss wiring + amber-themed CSS) |
| 9 | End-to-end integration test: wallet rewind drops phantom UTXOs / unspends orphaned spends / round-trips | tests/wallet_reorg_recovery.rs | new test file | ~3-4 hours — **DONE 2026-05-23** (4 tests; see file) |

**All 9 tasks shipped 2026-05-22 → 2026-05-23 (~18h focused work across two days).**

Tasks 1-3 are pure wallet-side changes — no chain or RPC dependency. They can land first as a self-contained PR.

Task 4 is the smallest RPC addition — could ship as part of the wallet PR via a `wallet_rpc_v2` feature gate.

Tasks 5-9 are integration work that depends on 1-4 being in place.

---

## 5. Test plan

Three test categories, in order of complexity:

### 5.1 Unit tests (in `src/wallet/scanner.rs::tests`)

- `journal_bounded_at_max_capacity` — push N+1 entries, assert journal length = N
- `scan_block_detects_non_monotonic_height` — block at height H after H+1 already scanned → `ScanResult::ReorgDetected`
- `scan_block_detects_prev_hash_mismatch` — block at H+1 with wrong prev_hash → `ScanResult::ReorgDetected`
- `rewind_to_height_removes_journal_entries` — apply 5 blocks, rewind to height 2, assert journal length = 2
- `rewind_then_reapply_yields_same_state` — apply A, rewind to fork, apply B, assert wallet UTXO set + key_image_index match expected canonical state
- `rewind_below_journal_window_returns_err` — rewind target < journal's earliest entry → `Err(RewindOutsideJournalWindow)`

### 5.2 Integration tests (in `tests/wallet_reorg_recovery.rs`)

These need a real-ish chain. Use the existing test infrastructure in `tests/full_pipeline_real_crypto.rs` as a template.

- `wallet_recovers_from_depth_1_reorg` — wallet at height 100, chain reorgs at 99 with new chain having different block at 99-100. Wallet rewinds + rescans.
- `wallet_recovers_from_depth_10_reorg` — same but at max-typical reorg depth.
- `wallet_recovers_from_reorged_outgoing_tx` — wallet sent a TX in block N which gets reorged out. After recovery, the spent key images are unmarked, balance restored, sent-TX history entry removed.
- `wallet_offline_during_reorg_recovers_on_reconnect` — wallet at height 50, network reorgs to height 100 with depth 5. Wallet reconnects, periodic tip-hash check finds mismatch, rewinds.
- `reorg_deeper_than_journal_triggers_full_rescan` — depth-1000 reorg → journal too shallow → caller falls back to rescan from genesis or last checkpoint.

### 5.3 Property tests (proptest, in scanner.rs::tests)

- `roundtrip(canonical_chain, candidate_reorg) -> wallet state matches if reorg is applied then unapplied`
- `monotonicity: applying blocks in order then any number of reorg-rewind-reapply cycles yields identical state to applying canonical chain in order`

---

## 6. Done-ness criteria

- All 9 implementation tasks shipped
- All 5 integration tests passing in CI
- The wallet successfully recovers in a manual mainnet-testnet drill where the operator induces a 5-block reorg via a private mining race
- Audit firm has reviewed `tests/wallet_reorg_recovery.rs` and the reorg-handling section of `src/wallet/scanner.rs`
- Updated `docs/v1.0-mainnet-audit-prep.md` to mark reorg-handling as in-scope and verified

---

## 7. What this design intentionally does NOT do

- **Doesn't change the chain's reorg policy.** `evaluate_reorg_acceptability` keeps its current tiered logic. The wallet is reactive to chain decisions, not consultative on them.
- **Doesn't propose chain-wide rollback events.** The chain emits whatever reorg events the RPC layer wants to forward; we don't bake the wallet into the consensus protocol.
- **Doesn't try to handle reorgs deeper than the last hardcoded checkpoint.** Those are catastrophic-mode; the wallet should fall back to "rescan from checkpoint" rather than try to reason about a parallel history.
- **Doesn't expose reorg-recovery as user-controllable behavior.** No "auto-rewind toggle" — it just happens. The notification banner is the user-visible surface.
- **Doesn't try to recover key-image-index "spent → unspent" transitions across the journal window.** If the spending TX is older than the journal, the wallet can't unsink the key image automatically; it falls back to a full rescan in that case (which DOES unsink it correctly via re-derivation).

---

## 8. Next steps after this doc

This document is the design — it is **not yet implementation**. To execute:

1. Get user approval on the design (the trigger-path choices, the journal vs rescan trade-off, the notification UX)
2. Open a tracking issue in the public repo referencing this doc
3. Implement task 1-3 in a single self-contained PR (wallet-side, no chain or RPC dependency)
4. Land + ship the wallet-side PR before tackling 4-9 which need the new RPC method
5. Schedule the audit firm to specifically review the `tests/wallet_reorg_recovery.rs` corpus once it exists

**Estimated calendar time from this doc to "reorg-handling shipped":** ~3-4 weeks of part-time focus, or ~1.5 weeks of full-time focus. v1.0 mainnet target Oct 1 means **this needs to land by August** if it's going to ship with v1.0.

If August slips, ship-time decision: (a) slip mainnet, (b) ship v1.0 with documented known-issue + accept day-1 user reports about phantom balances on reorg events. Option (a) is the right call; option (b) is what gets agreed when calendar pressure wins.

---

## 9. Honest read

The wallet's lack of reorg-handling is the single biggest correctness gap in the v1.0 perimeter that nobody has been talking about. It's not in the hardening punchlist (the punchlist is about defensive coding patterns, not architecture-level gaps). The audit firm WILL find it — every privacy-coin audit firm reads the wallet's scan path because that's where the user actually loses money on bugs.

Shipping v1.0 without reorg-handling is a decision the project can make, but it should be a *deliberate* decision documented in a sibling decision-doc — not an oversight.
