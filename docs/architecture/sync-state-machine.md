# `ChainSync` State Machine — Canonical Reference

> **Status**: Phase 0 of the 2026-06-19 sync-state refactor. This document
> captures the EXISTING `src/network/sync.rs` behavior as observed. It is
> deliberately descriptive, not prescriptive — bugs and quirks are documented
> as-is, then mapped to violated invariants in §7.
>
> **Purpose**: a single source of truth that subsequent phases (proptest
> harness, total-difficulty trust, lifecycle cleanup, patch audit) all work
> against. Every fix proposed after this doc must reference which transition,
> data structure, or invariant it touches.

---

## 1. The five states

Defined at `src/network/sync.rs:14-20`:

| State | Semantic intent |
|---|---|
| **Idle** | Initial state at construction. Set by `clear()`. No outbound IBD activity expected. |
| **Headers** | We believe we're behind the network. Actively requesting `GetHeaders` from peers. Outbound block broadcast is **deprioritized**. |
| **Blocks** | We have header chain that exceeds local tip; downloading the actual block bodies via `GetBlocks`. Broadcast still deprioritized. |
| **ConfirmingSynced** | We've finished a Headers cycle that returned no new headers above our tip. Probationary "maybe synced." One more Headers round confirms before transition to Synced. |
| **Synced** | Confident our chain is the heaviest we've seen. Broadcast resumes; new local blocks are gossiped outbound. **This is the only state where the node behaves as a chain leader.** |

### State characteristics by behavior axis

| Axis | Idle | Headers | Blocks | ConfirmingSynced | Synced |
|---|---|---|---|---|---|
| GetHeaders sent? | no | yes | no | yes (one final round) | no |
| GetBlocks sent? | no | (drained) | yes | no | no |
| Outgoing block broadcast | suppressed | suppressed | suppressed | suppressed | **enabled** |
| Accepts gossiped blocks | yes | yes | yes | yes | yes |

> **OBSERVATION**: broadcast is only enabled in `Synced`. Every other state
> assumes "we're catching up; relaying our tip would mislead peers." This is
> the operational root of every chain-leader-stuck-in-IBD stall.

---

## 2. Transition table

Each row: `(current_state) — trigger → (next_state)`. Trigger column lists
both the method and the data condition that fires the transition.

| # | From | Method (line) | Trigger condition | To | Notes |
|---|---|---|---|---|---|
| T1 | * | `set_local_tip:138` | `local_height >= best_known_height && pending_headers.is_empty() && downloading.is_empty()` | **Synced** | THE key transition. All three conditions must hold simultaneously. |
| T2 | {Synced, Idle, ConfirmingSynced} | `update_peer_height_for:169` | `peer_height > local_height` | **Headers** | A single peer's claim flips us into IBD. Other peers' claims, peer scoring, total_difficulty — none consulted. |
| T3 | * | `set_state:208` | direct API call (`pub fn set_state`) | argument | Used by tests and external callers. Bypasses invariants — a known smell. |
| T4 | ConfirmingSynced | `queue_headers:219` | `headers.is_empty() && local_height > 0` | **Synced** | Empty headers response confirms we're at tip. |
| T5 | {Headers, ConfirmingSynced} | `queue_headers:223` | `headers.is_empty() && true_best_height() > local + 2` | **Headers** | If best peer height still above us, re-enter Headers (request again). |
| T6 | * | `queue_headers:237` | `!pending_headers.is_empty()` after queueing | **Blocks** | Once we have headers queued, fetch the bodies. |
| T7 | {Synced, ConfirmingSynced, Idle} | `mark_block_orphan:397` | orphan received; parent added to `pending_headers` | **Blocks** | Gossip-orphan path forces re-entry to IBD. |
| T8 | * | `on_block_processed:414` | block accepted at `height < true_best_height() - 1` | **Headers** | We're still behind; re-request headers for next batch. |
| T9 | * | `on_block_processed:419` | accepted block at height 0 (genesis) AND any peer claims > 0 | **Headers** | Initial-sync kicker. |
| T10 | * | `on_block_processed:423` | block accepted at `height >= true_best_height() - 1` | **ConfirmingSynced** | Close enough to tip — start the confirm cycle. |
| T11 | * | `clear:552` | direct API call | **Idle** | Resets all in-flight state. Used on hard error / wipe. |
| T12 | Blocks | `recover_stuck_downloads:591` | `stuck_count >= 5` | **Headers** | Too many stuck downloads → restart from Headers. |
| T13 | {Synced, Idle} | `trigger_resync:627` | direct API call | **Headers** | Force a re-sync (called from operator paths). |

### Implicit transitions / non-transitions

- **Blocks → Synced**: There is NO direct transition. The path is Blocks → (`on_block_processed:423`) → ConfirmingSynced → (`queue_headers:219` with empty headers) → Synced. Both steps must complete.
- **Headers → Synced**: Only via ConfirmingSynced (T10 → T4) or by `set_local_tip` (T1) firing when queues happen to be empty.
- **Spontaneous return to Synced**: The ONLY path is T1, which requires the conjunction of `local_height >= best_known_height` AND empty `pending_headers` AND empty `downloading`. **If any one of these stays stuck, we never return to Synced.** This is the structural cause of every recurring stall.

---

## 3. Triggers, in dependency order

These are the external events that drive the machine. Listed in the order
they typically fire in a healthy lifecycle:

| Trigger | Source | Side effects on data structures |
|---|---|---|
| `new(local_height, local_tip)` | Node startup | initializes everything; state = Idle |
| `update_peer_height_for(peer_id, height)` | P2P Version handshake; Headers/Inv messages | inserts into `peer_heights`; calls `refresh_best_known`; may flip to Headers |
| `set_local_tip(height, tip)` | chain.rs after block commit/reorg | updates `local_height/tip`; prunes peer_heights below new local (post-`e80a2df9`); may flip to Synced |
| `queue_headers(headers)` | Headers response from peer | appends to `pending_headers`; flips state based on emptiness |
| `get_blocks_to_request(max)` | Periodic sync tick | moves hashes from `pending_headers` to `downloading` |
| `record_request(hash, peer, ts)` | When GetBlocks sent | inserts into `pending_requests`; tracks for timeout |
| `on_block_received_from(block, peer)` | P2P block message | removes from `downloading`/`pending_requests`; may queue as orphan; may drain `orphan_by_parent` forward |
| `mark_block_received(hash)` | Companion to on_block_received | clears `downloading`/`pending_requests` entry |
| `mark_block_failed(hash)` | After max retries | re-queues hash in `pending_headers` (front) |
| `mark_block_orphan(orphan, parent)` | When chain returns Orphan status | queues parent fetch in `pending_headers`; on `a60e7adf` branch also stores body in `orphan_blocks` |
| `on_block_processed(hash, height)` | chain.rs after block applied | updates state based on relative position |
| `on_timeout(hash)` | Periodic timeout scan | removes hash from `downloading`/`pending_requests` |
| `cleanup_expired_orphans(now)` | Periodic cleanup | evicts `orphan_blocks` entries older than `ORPHAN_TTL_SECONDS` |
| `cleanup_sync_bans(now)` | Periodic | evicts `sync_banned_peers` entries past their TTL |
| `trigger_resync()` | Operator RPC | forces transition to Headers |
| `clear()` | Hard reset | empties everything; state = Idle |

---

## 4. Data structure inventory (the 22-field bloat)

All fields of `pub struct ChainSync` at `src/network/sync.rs:57-81`. For each:
purpose, **growth source**, **shrink source**, and lifecycle invariant
(where stated; **UNBOUNDED?** means no cleanup exists).

| Field | Type | Purpose | Grows on | Shrinks on | Invariant |
|---|---|---|---|---|---|
| `local_height` | `u64` | Our current chain tip height | `set_local_tip`, `set_local_height` | n/a | monotonic in healthy operation; reorgs decrease |
| `local_tip` | `Hash` | Our current chain tip hash | `set_local_tip` | n/a | always paired with `local_height` |
| `best_known_height` | `u64` | Max height advertised by any peer | `update_peer_height_for`, `update_peer_height` (`refresh_best_known`) | `set_local_tip` post-`e80a2df9` only | **VIOLATED**: pre-`e80a2df9`, only ever raised; never lowered |
| `state` | `SyncState` | Current FSM state | 13 sites (see §2) | same | should be consistent with data quotas (often isn't) |
| `pending_requests` | `HashMap<Hash, BlockRequest>` | Per-block "we asked peer X for it at time Y" | `record_request` | `mark_block_received`, `mark_block_failed`, `on_timeout` | bounded by `MAX_PENDING_REQUESTS = 10_000` |
| `orphan_blocks` | `HashMap<Hash, OrphanBlock>` | Block bodies whose parent is missing (post-`a60e7adf`) | `on_block_received_from`, `mark_block_orphan` | `cleanup_expired_orphans` (TTL `ORPHAN_TTL_SECONDS = 1800`), eviction at `MAX_ORPHAN_BLOCKS = 1000` | bounded by both count and age — **healthy** |
| `orphan_by_parent` | `HashMap<Hash, Vec<Hash>>` | Reverse index for orphan drain | parallels `orphan_blocks` | parallels | invariant: every value in this map exists in `orphan_blocks` (informally) |
| `pending_headers` | `VecDeque<Hash>` | Block hashes we plan to fetch | `queue_headers`, `mark_block_failed`, `mark_block_orphan` | `get_blocks_to_request`, `clear` | bounded by `MAX_PH = 50_000` |
| `downloading` | `HashSet<Hash>` | Blocks currently being fetched | `get_blocks_to_request` | `mark_block_received`, `mark_block_failed`, `on_timeout` | should match `pending_requests` keys; **OFTEN DRIFTS** during reorg |
| `download_timestamps` | `HashMap<Hash, DownloadEntry>` | When did this block enter `downloading`? | same as `downloading` | same | parallel to `downloading`; same drift risk |
| `max_concurrent` | `usize` | Concurrency cap for `get_blocks_to_request` | n/a | n/a | constant, set to 100 |
| `request_timeout` | `u64` | Adjustable timeout for stuck-block recovery | `increase_timeout` | n/a | grows-only on failure; never decays |
| `last_orphan_cleanup` | `u64` | Throttle for `cleanup_expired_orphans` | each cleanup call | n/a | invariant: only advances forward |
| `peer_failures` | `HashMap<PeerId, u32>` | Per-peer count of failures | many sites | n/a | **UNBOUNDED?** No explicit reset. Grows monotonically per peer. |
| `sync_banned_peers` | `HashMap<PeerId, u64>` | Peers temporarily banned from sync requests, with unban-after timestamp | sync-ban sites | `cleanup_sync_bans` | bounded by TTL |
| `last_sync_peer` | `Option<PeerId>` | Last peer we asked for headers | header-request sites | n/a | scalar; no growth concern |
| `headers_request_time` | `Option<u64>` | Timestamp of last GetHeaders | header sites | reset on state changes | scalar; no growth concern |
| `headers_received_this_cycle` | `bool` | Have we gotten any headers this cycle? | header sites | state changes | scalar; no growth concern |
| `peer_heights` | `HashMap<PeerId, u64>` | Per-peer claimed height | `update_peer_height_for` | `remove_peer_height`, `set_local_tip` post-`e80a2df9` | **PARTIALLY BOUNDED**: only height-based pruning; no TTL. **THIS IS THE CURRENT BUG.** |
| `pending_header_nonces` | `HashSet<u64>` | Header request nonces in flight | header-send sites | matching responses | should be small; unclear cleanup on peer disconnect |
| `next_header_nonce` | `u64` | Monotonic nonce counter | header-send sites | n/a | grows forever (u64 overflow not a practical concern) |
| `orphans_per_peer` | `HashMap<PeerId, usize>` | Per-peer orphan count for flood detection | orphan-receive sites | orphan-drain sites | bounded by `MAX_ORPHANS_PER_PEER = 50` per peer, but **UNBOUNDED** in peer count |
| `blocks_entered_at` | `Option<u64>` | When did we enter Blocks state? | T6 | state changes | scalar |

### Field-pair coherence (cross-field invariants that should hold but often don't)

| Coherence rule | Status |
|---|---|
| `downloading.keys() == pending_requests.keys() == download_timestamps.keys()` | **VIOLATED** under timeout race conditions; partial fixes scattered |
| `pending_headers.iter().none(|h| downloading.contains(h))` | should hold; **not enforced anywhere** |
| `orphan_blocks.keys()` ⊆ values of `orphan_by_parent` | informal; would require audit |
| `best_known_height == max(peer_heights.values()).max(local_height)` | **POST `e80a2df9` partially** — only true at moments where `set_local_tip` was just called |
| `peer_heights.contains_key(p) ⇒ p is in active P2P peer set` | **VIOLATED** — disconnected peers leave entries behind |

---

## 5. Constants and tunables

Listed at `src/network/sync.rs:30-45`:

| Constant | Value | Purpose | Tested? |
|---|---|---|---|
| `MAX_ORPHAN_BLOCKS` | 1000 | Cap on `orphan_blocks` count | implicit |
| `MAX_PENDING_REQUESTS` | 10_000 | Cap on `pending_requests` | informal |
| `ORPHAN_TTL_SECONDS` | 1800 (30 min) | How long an orphan body is retained | yes |
| `ORPHAN_CLEANUP_INTERVAL` | 60 | Throttle on cleanup_expired_orphans | yes |
| `MAX_ORPHANS_PER_PEER` | 50 | Per-peer orphan flood limit | yes |
| `STUCK_DOWNLOAD_TIMEOUT_SECS` | 8 | When to re-queue a block stuck in `downloading` | yes (Bug 3 fix) |
| `BLOCKS_STUCK_TIMEOUT` | 10 | Different stuck-detection threshold (relation to above is unclear) | unclear |
| `BLOCK_DOWNLOAD_TIMEOUT_BASE` | 5 | Base of per-peer block timeout | yes |
| `BLOCK_DOWNLOAD_TIMEOUT_PER_PEER` | 2 | Per-peer increment | yes |

> **Missing constant**: no `PEER_HEIGHT_CLAIM_TTL` anywhere. This is the
> Phase 3 add.

---

## 6. Invariants (what SHOULD always hold)

Each invariant has: ID, statement, **current enforcement** (where in code),
and **whether currently violated** (with link to §7).

| ID | Statement | Enforcement | Violated? |
|---|---|---|---|
| **I1** | `local_height` is the chain tip height we believe in | `set_local_tip`, `set_local_height` | ✓ holds |
| **I2** | `best_known_height >= local_height` always | implicit; `set_local_tip` recomputes (post-`e80a2df9`) | ✓ post-fix |
| **I3** | `best_known_height == max(peer_heights.values()).max(local_height)` at all times | **NOT ENFORCED** between method calls; only after `set_local_tip` or `refresh_best_known` | partial |
| **I4** | Every `peer_heights` entry was advertised by a peer that is STILL connected | **NOT ENFORCED** — `remove_peer_height` exists but is called inconsistently | ✗ §7.V1 |
| **I5** | Every `peer_heights` entry was advertised within the last T seconds | **NOT ENFORCED** — no TTL | ✗ §7.V2 — TONIGHT'S RECURRING BUG |
| **I6** | `state == Synced ⇒ local_height >= max(peer's TOTAL-DIFFICULTY claim, local total_diff)` | **NOT ENFORCED**; we use height, not total_diff | ✗ §7.V3 |
| **I7** | `pending_headers.iter().none(|h| downloading.contains(h))` | not enforced | unknown frequency |
| **I8** | `downloading`, `pending_requests`, `download_timestamps` have identical key sets | partial enforcement at each mutation site | ✗ §7.V4 — drift observed |
| **I9** | A spammer cannot pin `best_known_height` above local indefinitely | not enforced | ✗ §7.V2 same as I5 |
| **I10** | Once `local_height >= best_known_height` AND no pending IBD requests are LEGITIMATELY outstanding, state returns to Synced within bounded time | not enforced — depends on queue drains | ✗ §7.V5 |
| **I11** | `orphan_blocks.len() <= MAX_ORPHAN_BLOCKS` | enforced at insert (`a60e7adf`) | ✓ |
| **I12** | `orphan_blocks` entry whose `received_at` < now - TTL is evicted within `ORPHAN_CLEANUP_INTERVAL` | enforced | ✓ |
| **I13** | `peer_failures` count grows monotonically per peer; never reset on success | by design? unclear | maybe-bug |

---

## 7. Known violations (the bug catalog)

Each violation: V-ID, statement, evidence (incident date/log), the
invariant from §6 it breaks, and **the fix candidate (a Phase 2/3 item)**.

### V1 — `peer_heights` entries for disconnected peers persist
- **Invariant violated**: I4
- **Evidence**: `remove_peer_height` is `pub` and called from `network/node.rs` on peer disconnect, but races with `update_peer_height_for` on reconnect can leave stale entries.
- **Phase 2/3 candidate**: Make `peer_heights` integrate with peer connection lifecycle — e.g., wrap in a struct that requires a "connected peer set" reference to query.

### V2 — `peer_heights` entries can stay valid forever (no TTL)
- **Invariant violated**: I5, I9
- **Evidence**: Live observation 2026-06-17/18 — a peer advertised height N+5 once, then never served us any blocks; `best_known_height` stayed pinned at N+5 indefinitely; broadcast suppressed. Operational mitigation was repeated `systemctl restart`.
- **Original surface fix**: `e80a2df9` (2026-06-19) — prune when local catches up. **DID NOT COVER** the case where local never catches up because peer claims chronically higher height.
- **Phase 3 candidate**: Time-bound peer claims via `PEER_HEIGHT_CLAIM_TTL_SECONDS`. Each `update_peer_height_for` records `(height, advertised_at)`; cleanup evicts entries older than TTL.

### V3 — Peer trust is height-based, not total-difficulty-based
- **Invariant violated**: I6
- **Evidence**: A spam peer can pin our state machine in IBD just by lying about a higher height. It doesn't need to provide PoW to do this.
- **Phase 2 candidate**: Replace `peer_heights: HashMap<PeerId, u64>` with `peer_chain_weights: HashMap<PeerId, TotalDifficulty>`. State transitions consult `total_difficulty`, not height. Spam peers cannot fake PoW; this closes the entire class.
- **Cross-cutting**: Requires `Version` message protocol field for `total_difficulty`. May require fleet upgrade coordination (compatible with v1.0.12 hard-fork window).

### V4 — `downloading` / `pending_requests` / `download_timestamps` drift
- **Invariant violated**: I8
- **Evidence**: Bug 3 (NYC stuck at height 12) was a manifestation. `mark_block_failed` re-queues to `pending_headers` but doesn't always clear `downloading` in all paths. Reorg paths are particularly suspect.
- **Phase 3 candidate**: Encapsulate the three fields behind a single `DownloadTracker` struct with a unified API. Make drift structurally impossible.

### V5 — Synced transition has 3 simultaneous conditions; if any sticks, state pins in IBD
- **Invariant violated**: I10
- **Evidence**: T1 requires `local_height >= best_known_height && pending_headers.is_empty() && downloading.is_empty()`. If `pending_headers` has stale entries from a failed prior IBD attempt against a now-evicted peer, this condition never holds.
- **Phase 3 candidate**: When `set_local_tip` advances AND `best_known_height` drops to local, drain `pending_headers`/`downloading` entries that no longer correspond to known peer claims.

### V6 — `peer_failures` grows monotonically; healthy peers eventually look bad
- **Invariant violated**: I13 (potentially)
- **Evidence**: code-archaeology: no reset path for `peer_failures` count.
- **Phase 3 candidate**: Decide policy — sliding window? Reset on N successful blocks from peer?

### V7 — `set_state` public API bypasses transition table
- **Invariant violated**: meta — the transition table assumes all transitions go through documented paths.
- **Evidence**: `pub fn set_state(state: SyncState)` at line 206 directly assigns whatever the caller passes. Used by tests; potentially abused.
- **Phase 4 candidate**: Mark as `#[cfg(test)]`-only or remove. Convert callers to use the documented triggers.

### V8 — `mark_block_orphan` path (PRE-`a60e7adf`) dropped block bodies
- **Invariant violated**: implicit — orphan bodies were dropped, requiring gossip re-delivery
- **Evidence**: 200-block-deep gossip-orphan loop observed 2026-06-17; chain stuck at h=167 with cascading orphan-fetches.
- **Fix already shipped**: `a60e7adf` (`v1.0.11.3-testnet`). Phase 4 will verify the fix matches the model.

---

## 8. Open questions

These are places where the code's intent is unclear and Phase 1's test
harness will help us decide what's right.

1. **What's the relationship between `STUCK_DOWNLOAD_TIMEOUT_SECS = 8` and `BLOCKS_STUCK_TIMEOUT = 10`?** Both exist; both are used in slightly different code paths. Are they both correct? Is one of them dead code?

2. **Should `peer_heights` claims age out, or should they be tied to peer connection lifecycle?** Or both?

3. **When `mark_block_orphan` is called with a parent we already have, what should happen?** Today: we'd queue it for fetch redundantly. Should the path return early?

4. **What's the intended behavior of `Idle` state in steady state?** Today only `clear()` enters Idle. Is Idle ever supposed to be a runtime state, or is it purely a startup placeholder?

5. **`trigger_resync` bypasses several invariants — is that a deliberate "force" mode or a leak?**

6. **`set_local_height` (singular, separate from `set_local_tip`) — when is it called?** Are the two ever called together? If not, why are they separate?

7. **For reorgs**: how does the state machine behave when chain.rs reports a reorg via `set_local_tip(new_tip_at_LOWER_height)`? Today: nothing special. Should `peer_heights` be invalidated?

---

## 9. What this doc enables (the work plan it unblocks)

Each Phase 1+ task references this doc:

- **Phase 1 — proptest harness**: generates random adversarial sequences
  of triggers (§3) and asserts the invariants (§6) hold after each. The
  known violations (§7) become failing test cases that drive Phase 3.

- **Phase 2 — total-difficulty trust**: directly addresses §7.V3 by
  replacing the data structure listed in §4 (`peer_heights`) with
  `peer_chain_weights`. Cross-references §1's "behavior axis" table — the
  decision to broadcast / suppress is what hinges on this.

- **Phase 3 — lifecycle invariants**: takes each unbounded-growth row from
  §4's table and either bounds it (TTL, cap, both) or proves it doesn't
  matter. Drives §7.V1, V2, V4, V5, V6 to closed status.

- **Phase 4 — re-derive prior patches**: walks `git log src/network/sync.rs`
  and marks each historical fix against the current model. Subsumed
  fixes can be deleted in favor of the model's invariants. Required
  fixes (because the model can't express them) are kept with rationale.

---

## 10. Change log

- **2026-06-19** — Initial document. Phase 0 of the refactor.
  Author: ghostrider1092 / Claude session.
  Status: descriptive (captures existing code); not yet prescriptive.
