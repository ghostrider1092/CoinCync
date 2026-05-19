<!-- markdownlint-disable MD036 MD013 -->
# Decision Record — cyncswap Path Forward

**Decision date:** 2026-05-18
**Status:** Accepted
**Decision owners:** Project lead
**Supersedes:** None
**Related specs:** [CIP-001](../cip/CIP-001-atomic-swap.md), [cyncswap-audit-prep.md](../cyncswap-audit-prep.md), [cyncswap-farcaster-comit-alignment.md](../cyncswap-farcaster-comit-alignment.md), [cyncswap-user-safety.md](../cyncswap-user-safety.md)

---

## Decision

**Ship cyncswap with the existing cross-curve adaptor-signature + DLEQ design as specified in CIP-001, hardened by the 6-layer user-safety stack (cyncswap-user-safety.md), with audit aligned to Comit + Farcaster prior art (cyncswap-farcaster-comit-alignment.md), and capped at $500 per swap for the V1 launch period.**

This locks the cryptographic approach. The hash-locked stealth-address alternative was considered and explicitly rejected.

---

## Context

During the 2026-05-18 design discussion that produced [CIP-002 V1](../cip/CIP-002-cynchub-merge-mined-liquidity-layer.md) (CyncHub) and [cyncswap-user-safety.md](../cyncswap-user-safety.md), the project lead surfaced concern about the residual principal-loss risk inherent in the cross-curve adaptor-signature design. Specifically:

- The two unavoidable bug classes (DLEQ proof bug, adaptor-binding bug) require audit catch; structural code-side prevention is not possible.
- Even with a clean audit, bugs can still exist post-launch.
- The user wanted users to be ~80% safe in worst-case scenarios — not zero risk, but bounded survivable risk.

A simpler-crypto alternative was identified mid-discussion: **hash-locked stealth-address derivation on the CYNC side**, which would eliminate the cross-curve DLEQ requirement and reduce audit-scope crypto from ~3,500 LOC to ~500 LOC. This alternative was evaluated against the existing design.

---

## The Decision in Detail

### The 5-step path

1. **Keep the existing adaptor-sig design.** Finish the remaining ~30% of [`crates/coincync-swap`](../../crates/coincync-swap/): wallet integration, the 58 currently-failing tests, dual-testnet smoke harness.
2. **Do the Farcaster + Comit alignment work**, Steps 1, 4, 5 from [cyncswap-farcaster-comit-alignment.md](../cyncswap-farcaster-comit-alignment.md) (test-vector import, primitive citations, prior-art audit precedent). Approximately 1 week of focused work. Cuts audit cost by ~50%.
3. **Ship V1 with the user-safety stack** from [cyncswap-user-safety.md](../cyncswap-user-safety.md): $500 per-swap cap, $2,500 per-user weekly cap, mandatory ≥1 watchtower default, type-state refund verification, triple-backup state + recovery, slow-rollout cap ramp gated on zero verified incidents.
4. **Engage one audit firm first**, fix all findings, then engage a second firm for differential review. Audit results published in full.
5. **Ship to mainnet with the wallet displaying a safety-status banner** until all 7 acceptance criteria from [cyncswap-user-safety.md §5](../cyncswap-user-safety.md) are met.

### What "shipping" requires

Before mainnet ship:

- All 346 cyncswap tests pass (currently 288/346)
- Wallet integration complete with the $500 cap enforced as a compile-time const
- Mandatory watchtower default enforced (wallet refuses to lock without ≥1 configured)
- Type-state pattern enforced (`LockReady` only constructible from `RefundVerified`)
- Triple-backup flow tested end-to-end
- Two independent audit reports published
- $100k bug-bounty pool funded and public
- Kill-switch advisory feed live

---

## Alternatives Considered

### Alternative A — Pivot to hash-locked stealth-address on CYNC

**What it is:** CYNC-side spend key derived as `D = stealth_pubkey + H(view_key || S) · G`. BTC side stays as standard P2WSH HTLC. Same privacy property on CYNC chain (looks like a normal stealth-address payment). No cross-curve DLEQ. No adaptor signatures.

**Why rejected:**

- **Unsolved refund-path problem.** CYNC has no native CLTV-equivalent. A refund mechanism would require either a CYNC consensus change (audit + timeline hit) or a complicated second-stealth-output refund construction (audit hit, less prior art).
- **Throws away ~70% of existing `coincync-swap` work** (~16,500 LOC across implementation + tests).
- **Less prior-art reuse** — Comit and Farcaster both ship the adaptor-sig design; hash-locked stealth atomic swaps have no equivalent production track record. The audit-cost win is real but smaller than it looks because differential audit against prior art (the basis for the ~$40-80k estimate after alignment work) wouldn't apply.
- **Net audit cost may land in the same place** once the refund-path design and its review are factored in.
- **Doesn't resolve the underlying concern** — the residual bug-risk concern is fundamental to any non-custodial swap protocol and is addressed by the safety stack (Layer 1 cap especially), not by switching crypto.

### Alternative B — Don't ship cyncswap at all

**What it is:** Users use ChangeNOW, FixedFloat, Exolix, or other custodial instant-swap services for CYNC↔BTC trades. The project takes no implementation responsibility.

**Why rejected:**

- Custodial services are subpoenable, hackable, can exit-scam. ChangeNOW has held customer funds against KYC demands historically. Worse trust model than audited cyncswap.
- Violates the constitutional positioning of cyncswap as the listing-independence answer to CYNC's expected CEX delisting trajectory (per `project_atomic_swap_mainnet_blocker.md`).
- "Privacy-first cryptocurrency that requires you to use a custodial KYC service to trade out to Bitcoin" is the worst available narrative.

### Alternative C — Delay cyncswap until mainnet is 12+ months stable

**What it is:** Ship CYNC mainnet without cyncswap. Add cyncswap as a v1.2 release once the network has track record and audit budget materializes from grants or community funding.

**Why considered but not chosen:**

- Defensible — would let `coincync-swap` mature further and let audit budget come from established funding sources rather than initial dev-team allocation.
- However, this means users spend 12-24 months using custodial swap services (Alternative B's downsides) during a period when CYNC needs liquidity-bootstrap most.
- The mainnet-blocker classification per `project_atomic_swap_mainnet_blocker.md` reflects the strategic importance of having a trustless exit at launch, not just operational readiness.

If audit budget genuinely doesn't materialize, this becomes the fallback. Until then, the 5-step plan above is preferred.

### Alternative D — Hybrid: ship both adaptor and hash-locked stealth, user picks per swap

**Why rejected:**

- Doubles the audit surface, doubles the code to maintain.
- Users would pick the "easy" mode by default regardless of privacy-criticality — UX paradox.
- Splits liquidity (CyncHub orderbook would fragment into "private orders" and "express orders").
- Worst of both worlds with no clear win.

---

## Consequences

### What this commits us to

- The cross-curve adaptor + DLEQ design is the cryptographic shape we ship and audit.
- The existing `crates/coincync-swap` codebase is the implementation. No restart.
- The $500 per-swap cap is a compile-time const in the reference wallet for V1 launch.
- The ramp schedule ($500 → $5k → $25k → $100k+) is gated on zero verified principal-loss incidents in each preceding period.
- Two independent audits before mainnet ship. No single-audit shortcut.
- The $100k bug-bounty pool is funded before mainnet ship.

### What this leaves open

- **Cap denomination** (USD-via-oracle vs sats) — open question in [cyncswap-user-safety.md §6](../cyncswap-user-safety.md).
- **Bounty pool funding source** — dev allocation, crowdfunding, NLnet grant — also open.
- **Watchtower retainer fee level** — 100 sats is the current proposal; may need tuning.
- **Recovery sheet format** — 32-word phrase vs base32 — pick before V1 ships.

These are tuning knobs, not blockers. The decision above stands regardless of how they resolve.

### What this rules out (without explicit revisit)

- A pivot to hash-locked stealth-address mid-implementation.
- Shipping with a single-firm audit.
- Shipping without the $500 cap.
- Shipping without mandatory watchtower default.
- Adding a custodial / federated / arbitrated / multisig safety net.

---

## Revisit Conditions

The decision above is binding **unless** one of the following triggers a re-evaluation:

1. **First audit identifies a critical unfixable issue in the adaptor + DLEQ construction** that requires consensus or protocol change to fix. In that case: re-evaluate hash-locked stealth-address path as an alternative to the redesign.

2. **Audit budget genuinely fails to materialize** within 6 months of mainnet-readiness. In that case: re-evaluate Alternative C (delay) or Alternative B (don't ship) honestly.

3. **A principal-loss incident occurs in V1 launch period** even with the $500 cap in place. In that case: halt the ramp schedule, run full post-mortem, decide whether to patch + continue or pull the design.

4. **Comit or Farcaster discloses a critical bug in the adaptor / DLEQ primitives** that would also affect our implementation. In that case: pause swap activity via the kill-switch advisory, patch, re-audit the patch, resume.

Any of these triggers warrants opening a new decision record (`docs/decisions/<date>-cyncswap-<topic>.md`) that supersedes or amends this one. Casual chat discussion does not amend the decision.

---

## References

- [CIP-001 — CYNC↔BTC Atomic Swap](../cip/CIP-001-atomic-swap.md)
- [CIP-002 — `cynchub` Merge-Mined Liquidity Layer](../cip/CIP-002-cynchub-merge-mined-liquidity-layer.md)
- [cyncswap-audit-prep.md](../cyncswap-audit-prep.md)
- [cyncswap-farcaster-comit-alignment.md](../cyncswap-farcaster-comit-alignment.md)
- [cyncswap-user-safety.md](../cyncswap-user-safety.md)
- [crates/coincync-swap/](../../crates/coincync-swap/) — implementation
- `project_atomic_swap_mainnet_blocker.md` (project memory)

---

## Changelog

- **2026-05-18** — Decision recorded. Path locked: adaptor-sig design + safety stack + alignment work + dual audit + $500 V1 cap. Alternatives A, B, C, D considered and rejected with documented rationale. Revisit conditions specified.
