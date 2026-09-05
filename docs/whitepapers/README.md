# CoinCync Whitepaper Series

Design papers for the mechanisms CoinCync invented or composed distinctively —
and a ledger of the failures we found and removed.

This series exists because of a positioning choice: **ship the standard, not just
the chain.** What travels in this space is specifications, not codebases. Each
paper is written so another project can adopt that one idea without adopting our
stack. Where a design is inherited (RingCT, CLSAG, Bulletproofs+, stealth
addresses, RandomX), we say so and cite upstream — our node and architecture are
from scratch, our cryptography is not.

## Ground rules for every paper

1. **Honest about limits.** No paper claims a mechanism is unbreakable. Each ends
   with a *Known limits* section. If something is gated off, a placeholder, or
   unverified, its status says so in the header — not in a footnote.
2. **Attack → assumption → removal.** Defenses are presented against the
   assumption they delete, not as feature bullets.
3. **Receipts.** Every claim links to the implementing file, and where possible a
   commit, a regression test, or a live-test result. A paper without receipts is
   an assertion; a paper with them is evidence.
4. **Subtraction counts.** Where the defense is the *absence* of a feature, that
   is stated as a design result, not a gap.

## Status vocabulary

| Label | Meaning |
|---|---|
| **Shipped** | Active in consensus or the default build; covered by tests |
| **Gated** | Implemented but behind a non-default feature flag or activation height |
| **Placeholder** | Field/scaffold exists; the mechanism is not yet real |
| **Proposed** | Design only; not implemented |
| **Unverified** | Present in code, status not confirmed by this series yet |

## Paper format

```
Title · Status · Layer
1. Motivation            — what problem, in one paragraph
2. Threat addressed      — attack → assumption it needs → what we removed
3. Design                — the precise mechanism (the substance)
4. Security analysis     — why it holds; what it does NOT protect against
5. Implementation        — files, commits, tests, live results
6. Known limits          — honest boundaries + open work
7. References            — prior art, post-mortems, papers
```

---

## Series index

### Part I — Consensus & protocol

| # | Paper | Status |
|---|---|---|
| WP-001 | Difficulty stability: dual-anchor ASERT, genesis calibration, and the startup grace | Shipped |
| WP-002 | Supply auditability for a confidential-amount chain | **Proposed** (the open workstream) |
| WP-003 | Emission: asymptotic tail, zero dev tax, height-determined reward | Shipped |
| WP-004 | Proof-of-work binding: the block anchor and RandomX epoch/seed derivation | Shipped |
| WP-005 | Layered reorg defense: MESS, finality floor, and checkpoints | Shipped |
| WP-006 | Cumulative-work determinism: why two honest nodes must agree on total work | Shipped |
| WP-007 | Consensus integrity by build gate: the critical-files hash lock | Shipped |
| WP-008 | Miner-signed rolling checkpoints (soft finality) | Gated |
| **WP-009** | **Privacy feature composition: how seven privacy features share one transaction** | Shipped (2 gated exceptions) |

### Part II — Privacy & wallet

| # | Paper | Status |
|---|---|---|
| WP-010 | Decoy selection: gamma sampling, generation awareness, and poison exclusion | Shipped |
| WP-011 | Transaction uniformity and the canonical observable envelope | Shipped (canonical UA unwired) |
| WP-012 | Traffic shaping: timing jitter, size normalisation, cover traffic | Shipped |
| WP-013 | Selective disclosure: balance, ownership, and scoped view keys | Shipped |
| WP-014 | Encrypted memos and payment metadata | Shipped |
| WP-015 | Dead-man's switch and auto-churn | Shipped |
| WP-016 | Subaddresses with per-subaddress view keys | Gated (mainnet-disabled, W-1) |
| WP-017 | Private light-wallet sync: the digest protocol | Shipped |
| WP-018 | Dust quarantine | **Proposed** |

### Part III — Network & infrastructure

| # | Paper | Status |
|---|---|---|
| WP-020 | Dandelion++ origination privacy | Shipped |
| WP-021 | Orphan reconnection and the sync engine's generation nonces | Shipped |
| WP-022 | Relative peer eviction: eclipse resistance without absolute protection | Shipped |
| WP-023 | Share-replay resistance: the per-canonical-job nonce ledger | Shipped |
| WP-024 | Snapshot bootstrap and warp sync | Shipped |
| WP-025 | The colony: advisory biomimetic telemetry castes | Shipped (non-consensus) |
| WP-026 | Reproducible builds and release attestation | Shipped |

### Part IV — The record

| # | Paper | Status |
|---|---|---|
| **WP-100** | **Solved-issues ledger: every failure found, and the assumption it died on** | Living |
| WP-101 | Safe-by-default threat model (adopted from the project design draft) | Living |

---

## How to cite

Papers are stable by number. `WP-001` is the difficulty design regardless of how
the file is later renamed. Superseded papers are marked, never deleted — the
record of what we believed and why is part of the evidence.
