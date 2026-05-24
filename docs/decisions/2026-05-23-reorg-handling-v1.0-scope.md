<!-- markdownlint-disable MD013 MD032 MD036 MD060 -->
# Reorg-handling scope at v1.0 mainnet

**Date:** 2026-05-23
**Status:** Decided — **Option B (finish reorg-handling for v1.0)**, see signed block below
**Refers to:** [docs/wallet-v2-reorg-handling-design.md](../wallet-v2-reorg-handling-design.md) — the full 9-task design + implementation plan

---

## The question

The wallet has had **zero reorg-handling code** until this week. Mainnet WILL have reorgs (especially with CIP-009.D dormant per the recent decision). The full implementation is ~20-30 hours across 9 tasks. We've shipped tasks #1-#4 this week (scanner-side primitives + RPC stub). What ships in v1.0 mainnet on October 1, 2026?

Three options:

- **(A) Ship v1.0 with DETECTION-ONLY reorg handling** — what's currently in main: the scanner detects reorgs (warn-log, no state advance), but the orchestrator doesn't invoke recovery (no rewind, no balance/history undo, no UI banner). Document the gap as a known-issue with planned v1.0.1 follow-up.
- **(B) Finish reorg-handling for v1.0** — implement remaining Tasks #3b + #5-9 (~3-4 focused weeks; ~20 hours of work). Target landed-and-tested by August 2026 to make October 1 mainnet.
- **(C) Slip v1.0 mainnet by 3-4 weeks** to fit (B) without rushing other work.

---

## What's already done (Tasks #1-#4)

After this week's work:

| Task | What it does | State |
|---|---|---|
| #1 BlockApplyDiff + bounded journal | Per-block diff records (height, hash, prev_hash, outputs added) | ✅ shipped (`src/wallet/scanner.rs`) |
| #2a Chain-continuity check (legacy path) | scan_block warns + skips journal write on reorg detection | ✅ shipped |
| #2b ScanResult enum + scan_block_with_result | Typed return surface — Scanned / ReorgDetected variants | ✅ shipped (additive, backward-compat) |
| #3 rewind_to_height + RewindOutcome | Scanner-side undo primitive returning outputs_to_remove | ✅ shipped |
| #4 find_fork_point RPC (MVP stub) | Node returns Some(height) if wallet's (hash, height) still canonical | ✅ shipped |

**13 scanner tests pass.** Production scan_blocks now stops at first reorg detection (won't apply blocks on an orphan chain).

## What's still missing (Tasks #3b, #5-9)

| Task | What | Effort |
|---|---|---|
| #3b balance.rs + history.rs rewind wiring | Apply RewindOutcome.outputs_to_remove to wallet UTXO state + TX history | ~3-4h |
| #5 Orchestrator path A: scan-detected reorg → trigger recovery | When scan_block_with_result returns ReorgDetected, orchestrator calls rewind + RPC.find_fork_point + rescans | ~3h |
| #6 Orchestrator path B: periodic tip-hash check | Background poll asks node for current hash at scanner.last_height; mismatch triggers recovery | ~2h |
| #7 Emit wallet_state event with reorg details | UI gets last_reorg_at_height + last_reorg_depth fields for banner display | ~1h |
| #8 UI reorg-notification banner | Wallet v2 web shows "Chain reorg detected at depth N — balance updated" | ~2h |
| #9 End-to-end integration test: 2-block reorg recovered | tests/wallet_reorg_recovery.rs — simulates reorg via local chain, verifies wallet recovers | ~3-4h |

**Total remaining: ~15-20 hours focused work, ~1.5-2 weeks part-time.**

---

## Option (A) — Ship v1.0 with detection-only

**What users see on a reorg:**

- Their balance does NOT silently corrupt (detection layer prevents the worst case)
- Their TX history does NOT gain phantom entries (orphan blocks aren't journaled)
- BUT outputs that were already in their wallet state from BEFORE the orphan block remain
- AND they get NO notification that anything happened
- The orchestrator's next scan loop ticks forward as if nothing happened

**What we tell users + audit firm:**

A documented known-issue at [docs/known-issues/](../known-issues/) explaining:
- The chain CAN reorg (per the 6-layer reorg-defense design)
- The wallet detects reorgs at the scanner layer but doesn't yet automatically recover the UTXO state
- Workaround: full-rescan from a hardcoded checkpoint when the user notices odd balance behavior
- Fix shipping in v1.0.1 (~Q4 2026 / Q1 2027)

**Pros:**
- Ship-on-time. Oct 1 mainnet doesn't slip.
- Detection is the hardest part (already done). Recovery is mechanical wiring.
- Audit firm sees a designed gap + roadmap — better than no design.
- v1.0.1 patch can ship without consensus changes (wallet-only).

**Cons:**
- Audit firm WILL flag this. Severity probably "Medium-High" in their report.
- A user who hits a reorg with funds in the orphan block has corrupted UTXO state until they full-rescan.
- "Known-issue at ship" is the kind of thing skeptical reviewers cite.

## Option (B) — Finish reorg-handling for v1.0

**What it takes:**

- 1 focused person, ~3-4 weeks of part-time work to land Tasks #3b + #5-9
- Or 1.5-2 weeks of full-time focus
- Schedule: tasks complete by mid-August 2026 to make Oct 1 ship window
- All 7 remaining tasks have explicit acceptance criteria in the design doc

**Risks:**

- Task #9 (end-to-end integration test) requires standing up a simulated chain that can be force-reorged. Test infrastructure work.
- Touching balance.rs + history.rs adds audit-perimeter LOC for the firm to review. Audit cost goes up.
- Wallet v2 UI changes (Task #8) are easy in isolation but interact with the dashboard polish track we deferred.

**Pros:**
- Real day-1 mainnet correctness. No phantom balance issues from reorgs.
- Audit firm sees a complete reorg-recovery story.
- Stronger v1.0 narrative — "the privacy chain that handles reorgs right."

## Option (C) — Slip v1.0 to fit (B)

**What it means:**

- October 1, 2026 ship date moves to ~November 1, 2026 or later
- The slip is publicly documented as a quality decision, not a calendar surprise
- The audit firm's August engagement target moves to ~September

**Pros:**
- Best possible v1.0 quality
- No "but we have a known-issue" narrative to manage
- Audit firm has more time to review (better engagement)

**Cons:**
- Slipping a publicly-announced date is a real reputation cost
- Slippage tends to be habit-forming
- v1.0 was already deferred from "bundle cyncswap" to "base-chain-only" once — slipping again starts to look like pattern

---

## Recommendation (subject to override)

**Lean toward (B) — finish reorg-handling for v1.0.**

Three reasons:

1. **The hard part (detection + scanner-side primitives) is already done.** The remaining 15-20 hours is mechanical wiring + tests, not architecture. Risk of overrun is bounded.
2. **"Known-issue at mainnet" is the kind of thing that haunts the project.** Day-1 users hitting balance corruption + finding a known-issue doc is a worse outcome than a 2-week ship delay.
3. **The calendar can absorb it.** Mid-August completion is achievable with focused effort. The audit firm engagement target (~July) gives ~6 weeks of buffer.

**(A) is acceptable** if calendar pressure becomes severe AND the v1.0.1 follow-up is committed publicly. The 6-layer reorg-defense + the 23 hardening fixes already make CoinCync more reorg-aware than most v1.0 privacy coins; shipping with detection-only is defensible.

**(C) is the wrong call** unless we discover an unexpected blocker. Slipping for engineering quality is fine; slipping for "we underestimated this" is brand damage.

---

## Decision

```text
Decision:      B — finish reorg-handling for v1.0
Made on:       2026-05-23
Made by:       ghostrider1092 (maintainer)

If B:
  Implementation deadline:   2026-08-15 (mid-August — gives ~6 weeks buffer before Oct 1 mainnet)
  Owner:                     self (maintainer)
  Audit firm aware:          to-be-communicated in next audit-prep update (the firm engagement
                             target is ~July, so the in-scope reorg-recovery story will be
                             part of the initial brief)

Rationale (one paragraph):
The hard part (detection + scanner-side primitives — journal, BlockApplyDiff, rewind_to_height,
scan_block_with_result, find_fork_point RPC stub, 13 passing tests) is already shipped this
week as Tasks #1-#4. The remaining ~15-20 hours is mechanical wiring (balance/history removal
paths, two orchestrator trigger paths, a wallet_state event, a UI banner, and one end-to-end
integration test). Risk of overrun is bounded by the design doc's explicit acceptance
criteria per task. "Known-issue at mainnet" is the kind of artifact that haunts a project —
day-1 users hitting balance corruption and finding a docs/known-issues/ file would be a worse
outcome than the modest implementation cost. The calendar absorbs the work without slipping
Oct 1. Option (A) remains the documented fallback if an unexpected blocker surfaces; Option
(C) is off the table unless something architectural breaks.
```

---

## Follow-on work once the decision lands

**If (A):**

- Write `docs/known-issues/2026-MM-DD-wallet-reorg-detection-only.md` with:
  - User-facing description of the gap
  - Workaround (full-rescan)
  - v1.0.1 commitment date
- Link from `docs/v1.0-mainnet-audit-prep.md` so the audit firm sees the disclosure on Day 1
- Add an `is_reorg_safe()` accessor to the wallet API that returns `false` for v1.0; `true` for v1.0.1+
- File a tracking issue for v1.0.1 referencing the design doc tasks #3b + #5-9

**If (B):**

- Schedule the 7-task implementation across the next 2-3 weeks
- Open a `v1.0-mainnet-reorg-recovery` tracking issue with the task list
- Each task = one PR with its own tests
- Final Task #9 PR includes the wallet_reorg_recovery.rs integration test
- Update `docs/v1.0-mainnet-audit-prep.md` to mark reorg-handling as **in-scope and verified**

**If (C):**

- Public communication: Discord + BTT + website all updated within 24 hours
- Update `docs/roadmap.md` with the new date + rationale
- Update `docs/launch/MILESTONE-2026-05-22.md` with an "EDIT" block noting the slip
- New genesis-ceremony T-minus timeline (most milestones shift by the same delta)
