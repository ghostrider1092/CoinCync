<!-- markdownlint-disable MD036 MD013 -->
# cyncswap User Safety Stack

**Purpose:** Specifies the layered defenses that keep cyncswap (CIP-001) and CyncHub V1 (CIP-002) users safe in the realistic case — accepting that bugs will exist even after audit. The goal is **~80% safe in worst-case scenarios, ~99% safe in expected-value terms**, with the residual risk capped to survivable losses by hard exposure limits.

**Audience:** cyncswap + CyncHub V1 implementers; wallet authors; audit firms scoping the user-safety review.

**Status:** Draft (2026-05-18). Companion to [CIP-001](cip/CIP-001-atomic-swap.md), [CIP-002](cip/CIP-002-cynchub-merge-mined-liquidity-layer.md), and [cyncswap-audit-prep.md](cyncswap-audit-prep.md).

---

## 0. Design Principle

> **Boring and simple is better.** Cap the blast radius of any one bug to a survivable amount, eliminate as many failure modes as code can structurally prevent, and accept that the residual ~0.01% crypto-bug-class risk is bounded by Layer 1's hard cap — not unbounded.

The realistic safety ceiling for any trustless swap is **~99% across the user base, ~80% in worst-case scenarios** (audit-missed crypto bug, infrastructure black-swan). The goal is to make the worst-case loss survivable, not zero.

The 6 layers below are ordered by how many user-loss scenarios each kills. Higher-numbered layers catch what lower-numbered layers miss.

---

## 1. The Six-Layer Safety Stack

### Layer 1 — Hard exposure cap (kills ~50% of catastrophic-loss scenarios)

The single biggest user-safety lever. Most "I lost everything" stories come from one swap taking the user's whole stack.

| Period | Per-swap cap | Per-user weekly cap | Trigger for next tier |
|---|---|---|---|
| **V1 launch — month 3** | **$500** | **$2,500** | Zero verified principal-loss incidents |
| Month 4 — 6 | $5,000 | $25,000 | Zero verified incidents in month 4-6 |
| Month 7 — 12 | $25,000 | $125,000 | Zero verified incidents in month 7-12 |
| Month 12+ | $100,000 | $500,000 | Reviewed quarterly, ratcheted on operational maturity |

**Enforcement:**

- Per-swap cap is a **compile-time const** in the reference wallet (`coincync-wallet`). Raised only by a signed wallet update — there is no runtime config flag to disable it.
- Per-user weekly cap is a wallet-side rolling counter (resets every 7 days from first lock). Persists across wallet restarts.
- The CYNC↔BTC exchange rate used to convert lock amounts to USD-equivalent comes from an oracle quorum (median of N reputable price feeds); wallet refuses to lock if oracles are unavailable or disagree by >5%.
- No "advanced mode" that uncaps. Users who want bigger trades wait for the ramp or use multiple wallets (multiple wallets do not stack from cyncswap's perspective — the wallet enforces per-wallet, but bypass via fresh wallet is acceptable; the cap exists to prevent accidental single-swap catastrophe, not to enforce KYC-style limits).

**Why this works:** even if a catastrophic crypto bug escapes audit and a user hits it, the maximum loss is bounded at $500 in V1. Bug + $500 cap = "I lost $500, that sucks" not "I lost my retirement."

---

### Layer 2 — Mandatory watchtower default (kills ~25% of remaining)

The single user behavior most likely to cause principal loss is "I locked my coins then went offline before the claim window." Watchtowers eliminate this entirely.

**Rules:**

- Wallet refuses to initiate a swap if zero watchtowers are configured. **Hard requirement, not a warning dialog.**
- Default config at install time: 2 public reference watchtowers, run as part of seed-node software, listed in a community-maintained registry.
- Pre-signed claim + refund txs handed to each watchtower at lock-creation. Watchtower has no power beyond "broadcast or not" — they can't forge or steal because the txs are pre-signed.
- User can swap in their own watchtower(s) (CLI: `cyncswap watchtower add <endpoint>`), but cannot drop below 1.
- Watchtower retainer fee (~100 sats per swap) bundled into the lock; user never sees it as a separate cost.
- Wallet runs a periodic health check on configured watchtowers; if any go offline for >24h, surfaces a yellow status banner with a one-click "fix" that selects a replacement from the public registry.

**Why this works:** the failure mode "user offline at critical moment" becomes "watchtower broadcasts on user's behalf." Automatic, redundant, no user action required.

---

### Layer 3 — Refund-by-default architecture (kills ~15% of remaining)

Make the FAILURE MODE be "trade didn't happen, you lost tx fees" instead of "money disappeared."

**Already in the design (CIP-001 + CIP-002):**

- Refunds happen on the **native chain** (Bitcoin nLockTime, CYNC adaptor refund condition), not via cyncswap or CyncHub.
- If CyncHub dies → refund still works.
- If counterparty disappears → refund.
- If RPC drops → refund.
- If user makes a UX mistake → cancel → refund.

**What this doc adds (wallet-side enforcement rules):**

- **Pre-flight verification gate:** wallet refuses to broadcast the lock tx until the refund tx is constructed, signed, and verified valid against the lock's UTXO. This is enforced by the type system — `LockReady` is only constructible from `RefundVerified::new(...)`. It is a *compile error* to attempt a broadcast that skipped the refund check.
- **Refund auto-broadcast:** scheduled via an OS-level timer at `lock_time + (timeout - 30min)`. The watchtower also broadcasts. Two independent triggers means a single point of failure on either can't strand the user.
- **Refund visibility:** the wallet's active-swap screen prominently shows "your funds will refund automatically at [absolute timestamp], no action needed if no match happens" — no interpretation required.
- **Pre-flight refund test in onboarding:** on first swap, wallet runs a small test swap (e.g. $5 dust) and successfully refunds it to prove the refund path works in this user's environment before allowing larger swaps.

---

### Layer 4 — Circuit breakers + kill-switches (kills ~5%, catastrophic-event protection)

When something goes wrong globally, limit blast radius.

**Wallet-side circuit breakers (automatic, no admin involvement):**

- 3+ swaps fail for the same user in 24h → wallet pauses new swaps and requires explicit user re-confirmation + shows a diagnostic of what went wrong on the prior failures.
- Network-wide swap failure rate >5% in the last 1h (observed by the wallet's connected nodes / public status page) → red banner: "Swaps temporarily disabled — check coincync.org/status for details."

**Protocol-side kill-switch (signed advisory, default-honored):**

The dev team can publish a signed kill notice if a critical bug is discovered post-launch. Wallets check the notice feed on startup; if an active advisory exists, the wallet refuses to start NEW swaps. Existing in-flight swaps continue normally via the refund path.

**Constitutional fit:**

This is **not** a federation, not an admin authority, not a custody-touching control. The kill-switch:

- Cannot move funds
- Cannot freeze in-flight swaps
- Cannot prevent refunds from working
- Can be ignored by a user setting `cyncswap_ignore_advisories=true` (default false)
- Is published by a publicly-known key in the repo (multisig recommended for robustness)
- Acts only as a "recall notice" — like a car company saying "do not drive this model until we patch it"

The user retains full control. The default behavior is conservative. The Constitution forbids algorithmic capture and admin authority *over funds*; this is neither — it's a one-way "stop new actions" signal that the user can override.

---

### Layer 5 — Triple-backup state + recovery (kills ~3% — disaster recovery)

When state files corrupt or hardware dies, users should not lose locked funds because they "lost the swap file."

**Rules:**

- On lock-creation, wallet writes the swap state to **three** locations:
  1. Local encrypted file (existing — see `crates/coincync-swap/src/state.rs` + HMAC sidecar)
  2. Cloud backup (encrypted with user passphrase; user-chosen provider — Dropbox, iCloud, custom WebDAV; opt-out possible but discouraged with on-screen warning)
  3. **Paper recovery sheet:** printable PDF with QR-encoded secret + human-readable backup phrase (32 words, BIP-39-style for memorability)
- **One-line CLI recovery:** `cyncswap recover --from-paper` accepts the paper sheet and completes any swap from any state. Works offline (no network needed except for broadcasting the final tx).
- **Recovery test in onboarding:** wallet's first-run flow forces the user to verify they have the paper backup before allowing the first real swap. (Wallet prints the PDF, user scans the QR with the wallet's "verify backup" feature, wallet confirms readability.)

**Why this works:** the three failure modes that historically destroy user funds (lost device, corrupted state, forgotten passphrase) each have a documented recovery path that returns principal.

---

### Layer 6 — Audit + bug bounty + slow rollout (kills ~1% — the residual crypto-bug class)

The unavoidable crypto-bug class. Audit catches most; bounty catches more; slow rollout limits damage from what slips through.

**Audit (pre-mainnet):**

- **Two independent audits before mainnet**, from different firms. Candidates: Cure53, Trail of Bits, NCC Group, Kudelski Security.
- Audit scope per the [cyncswap-farcaster-comit-alignment.md](cyncswap-farcaster-comit-alignment.md) doc — differential review against Comit + Farcaster prior art reduces audit cost ~50% without reducing rigor.
- Audit findings published in full once remediated. No "the audit cleared us" without the report.

**Bug bounty (ongoing post-mainnet):**

- **$100,000 pool**, published at `coincync.org/security`.
- Tiered payouts:
  - Critical (principal-loss-class crypto bug): up to $50,000
  - High (DoS, privacy leak, refund-blocking): up to $15,000
  - Medium (wallet UX bug that could lead to user error): up to $5,000
- All payouts public; findings disclosed after fix ships.

**Slow rollout schedule (binds Layer 1's cap to operational maturity):**

The cap ramps in [Layer 1's table] are *gated on zero verified principal-loss incidents in the preceding period*. If an incident is verified during any period, the cap **does not raise** until the bug is patched and a new clean period elapses.

This means: if a $500-cap bug hits in month 2, the cap stays at $500 for month 4-6 (one extra clean quarter required) before ramping to $5k. The audit-missed bug class scales with the cap — slow rollout means a bug at month 12 affects users at the lower cap level, not at $100k.

---

## 2. Layers Considered + Rejected

### Insurance pool — REJECTED (constitutional conflict)

A small % of swap fees routed to a community insurance pool would reimburse principal losses from audit-missed crypto bugs.

**Why rejected:**

- Requires custody of pooled funds → conflicts with Article XII ("No Admin Authority").
- Could be ruled "treasury" under Article XI ("No Algorithmic Capture").
- Requires governance to decide payouts → introduces social trust.
- Has been done badly elsewhere (DAO bailouts, etc.) — usually ends in capture.

**Mitigation:** Layers 1, 4, and 6 (cap + slow rollout + bounty) collectively address the same risk surface without requiring custody or governance. The expected loss to a user is bounded at $500 × P(audit-missed bug hits this user) ≈ ~$0.05/swap, which is below the noise floor of tx fees they already accept.

### Mandatory KYC / address whitelisting — REJECTED (constitutional conflict)

Would catch some social-engineering attacks but violates Article XIV ("No Surveillance Layer") and the core Right X ("No Compliance Hooks").

### Federated dispute resolution (Bisq-style arbitration) — REJECTED (changes trust model)

Bisq's 2-of-3 arbitrated multisig is a different trust model than non-custodial HTLCs. Adopting it would weaken the "no federation" property that's the whole point of cyncswap.

### Insurance via centralized provider (Nexus Mutual, etc.) — REJECTED (third-party trust)

Adds a centralized counterparty that can deny payouts. Users can buy this on the open market if they want it; cyncswap doesn't bundle it.

---

## 3. Realistic User Outcome Distribution

After all 6 layers ship, with the $500 V1 cap, here is what a typical cyncswap user faces per swap:

| Scenario | Probability | Loss | Recoverable? |
|---|---|---|---|
| Trade completes normally | ~96% | 0 | N/A |
| Trade doesn't match → auto-refund | ~3% | Tx fees ($2-10) | Already recovered |
| User offline → watchtower handles | ~0.9% | 0 | Already recovered |
| User loses device → recover via paper | ~0.05% | 0 | Yes (CLI recovery) |
| Network issue → manual refund | ~0.04% | 0 | Yes (CLI recovery) |
| Audit-missed crypto bug hits user | ~0.01% | Capped at $500 in V1 | Bug-bounty payout may compensate; no constitutional reimbursement guaranteed |

**Expected loss per swap:** `0.97 × $5 fee + 0.03 × $5 fee + 0.0001 × $500 cap = ~$5.05 + $0.05 = $5.10`

The principal-loss expected value (`$0.05/swap`) is **well below the tx-fee floor users already accept**. That's "80% safe" in any reasonable interpretation — actually closer to 99.9% safe in expected-value terms, with the 0.1% residual capped at survivable levels by Layer 1.

---

## 4. Code-Enforced vs Process-Enforced

| Layer | Enforced by code? | Enforced by process? |
|---|---|---|
| 1. $500 cap | **Yes** — compile-time const in `coincync-wallet`. No runtime override. | Ramp schedule reviewed quarterly. |
| 2. Mandatory watchtower | **Yes** — wallet refuses to lock without ≥1 configured. | Public watchtower registry curated by seed-node operators. |
| 3. Refund-by-default + pre-flight | **Yes** — type-state pattern (`LockReady` requires `RefundVerified`). | Auto-broadcast scheduled via OS timer. |
| 4. Circuit breakers | **Yes** — wallet logic counts failures, applies thresholds. | Kill-switch advisory feed maintained by dev team key. |
| 5. Triple backup | **Yes** — wallet refuses first swap until backup verified. | Public watchtower registry; user-chosen cloud provider. |
| 6. Audit + bounty + rollout | **Partial** — cap ramp gated on incident-free periods. | Audits + bounty are process-level commitments. |

Layers 1, 2, 3, and 5 are *structurally impossible to bypass without modifying the wallet binary*. Layers 4 and 6 mix code + process. This split is intentional — anything that protects user principal lives in code; anything that requires ongoing operational judgment lives in process.

---

## 5. Acceptance Criteria

The user-safety stack is considered complete when **all** of the following are true:

1. Reference wallet (`coincync-wallet` "Trade" tab) enforces the $500 per-swap cap via compile-time const. CI test: `cargo test wallet_cap_is_500` asserts the value.
2. Reference wallet refuses to start a swap with zero watchtowers configured. CI test exists.
3. Type-state pattern enforced: `coincync_swap::types::LockReady` is only constructible from `RefundVerified::new(...)`. Documented in `crates/coincync-swap/src/protocol.rs`. CI test exists.
4. Triple-backup flow tested end-to-end: wallet writes local + cloud + paper, recovery CLI restores from each independently. Integration test exists.
5. Two independent audit reports published in full at `coincync.org/security`.
6. Bug bounty pool funded ($100k initial), public scoreboard live at `coincync.org/security/bounty`.
7. Kill-switch advisory feed live at `coincync.org/security/advisories`, wallet checks on startup.

Until all 7 items above ship, the wallet displays a yellow banner: "cyncswap is in early rollout — see safety status at coincync.org/security."

---

## 6. Open Questions

1. **Cap denomination — USD vs sats?** $500 in USD-equivalent requires an oracle. $500 in sats (a constant ~833,333 sat at $60k BTC) is simpler but drifts with price. Current proposal: USD-equivalent via oracle quorum with conservative fallback; revisit at first quarterly review.

2. **Per-wallet vs per-user enforcement.** The cap is currently per-wallet (a user with multiple wallets can stack). This is acceptable because the cap protects against accidental single-swap catastrophe, not against intentional bypass. Bypass via fresh wallet is not a meaningful attack vector. Revisit if data shows otherwise.

3. **Recovery sheet format.** 32-word BIP-39-style phrase is human-friendly but bulky. Compact base32 alternative is shorter but less robust to OCR. Pick before V1 ships.

4. **Watchtower retainer fee level.** 100 sats is the proposal; real operators may need more for sustainable operation. Reassess after first 6 months of public watchtower operation data.

5. **Bounty pool funding source.** $100k is the proposal. Options: dev team allocates from project funds; community crowdfunding round; grant from NLnet or similar (see `project_sustainability_grants.md`). Decide before mainnet.

---

## 7. Changelog

- **2026-05-18** — Document created. Captures the 6-layer safety stack agreed during CIP-002 V1 design discussion. V1 cap set to **$500 per swap** with a documented ramp schedule. Insurance pool rejected on constitutional grounds. Acceptance criteria specified. Open questions surfaced.

---

*This document is a design commitment, not a free-form roadmap. The $500 cap, the mandatory watchtower default, the type-state refund-verification pattern, and the dual-audit requirement are non-negotiable for mainnet ship. The ramp schedule, watchtower governance, and bounty mechanics may be tuned based on operational data, but the structural safety properties (cap exists, watchtower required, refund verified before lock) are part of what makes cyncswap a non-custodial swap and cannot be relaxed without changing the product.*
