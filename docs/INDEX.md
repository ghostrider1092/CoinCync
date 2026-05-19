<!-- markdownlint-disable MD036 MD013 -->
# Documentation

**Privacy money that requires no permission.**

This is the canonical entry point for everything you can read about CoinCync. Anything not linked from here is internal — not yet meant for outside readers.

---

## Start here (new to CoinCync)

| Read this | If you want to |
| --- | --- |
| [README](../README.md) | One-page overview of what CoinCync is, current status, and quick start |
| [CONSTITUTION](../CONSTITUTION.md) | The seven articles + ten rights that bound what CoinCync can become |
| [roadmap](roadmap.md) | The next three releases — v1.1, v1.2, v1.3 — with shippable bars |
| [explicitly-not-doing](explicitly-not-doing.md) | The features CoinCync will never have, and why |
| [deprecation-schedule](deprecation-schedule.md) | What's queued for removal in each release, and the N-1 warning policy |
| [v1.1-prep](v1.1-prep.md) | Synthesis tracker for what's between today and v1.1 ship — the 8 shippable-bar criteria, the 7 work categories, the 5 open decisions |
| [property-testing](property-testing.md) | Property-based testing discipline — when to add, how to triage, what it buys in the audit |

---

## Use CoinCync (end user)

| Read this | If you want to |
| --- | --- |
| [README §Quick Start](../README.md#quick-start) | Get a node + wallet running in 5 minutes |
| [website/release](../website/release/) | Download a signed release binary |
| _Wallet user guide_ — coming with v1.1 | Send / receive / back up / recover |
| _Recovery guide_ — coming with v1.1 | What to do if you lose your device, file, or passphrase |

---

## Run infrastructure (operator)

| Read this | If you want to |
| --- | --- |
| [release/operator](release/operator/) | Operator-facing release artifacts |
| [security/reorg-defense](security/reorg-defense.md) | The 6-layer reorg defense + finality model |
| [BLOCKCHAIN_ROADMAP](BLOCKCHAIN_ROADMAP.md) | Historical technical context across CIPs |

---

## Build on CoinCync (developer)

| Read this | If you want to |
| --- | --- |
| [cip/](cip/) | All CoinCync Improvement Proposals (CIP register) |
| [cyncswap-audit-prep](cyncswap-audit-prep.md) | Audit-firm wayfinding for the cyncswap crate |
| [cyncswap-farcaster-comit-alignment](cyncswap-farcaster-comit-alignment.md) | The plan for aligning cyncswap audit with Comit/Farcaster prior art |
| [cyncswap-user-safety](cyncswap-user-safety.md) | The 6-layer user safety stack + $500 V1 cap |
| [decisions/](decisions/) | Recorded design decisions — what we picked, why, what would change our mind |

---

## Specifications (CIP register)

The spec is in [cip/](cip/). Highlights:

| Read this | If you want to |
| --- | --- |
| [CIP-001](cip/CIP-001-atomic-swap.md) | The cyncswap atomic-swap protocol (mainnet blocker, v1.1 headline) |
| [CIP-002](cip/CIP-002-cynchub-merge-mined-liquidity-layer.md) | CyncHub orderbook design (Sketch — v1.3+ conditional) |
| [CIP-007](cip/CIP-007-hard-fork-activation-policy.md) | How consensus rule changes activate |
| [CIP-009](cip/CIP-009-reorg-defense-decision.md) + [CIP-009.D](cip/CIP-009-D-miner-signed-rolling-checkpoints.md) | Reorg defense + miner-signed rolling checkpoints |

Anything in `cip/` marked **Sketch** is research, not roadmap. See [cip/README](cip/README.md) for the full status legend.

---

## What this index leaves out

If something isn't linked from here, it's intentionally internal:

- Working notes in `out/`
- Audit-pre-receipt findings in `audit-suite/` (released after triage)
- Future-update sketches in `future-update/`
- Development-flow scripts in `scripts/` (operator docs are in `release/operator/`)
- Source-code-level docs (read the code; READMEs in each `crates/<crate>/` are the entry point)

If you think something here is missing, open a question — don't add to this list without considering whether it belongs.

---

## How this document stays clean

- One canonical entry point. If it's not linked from here, it's not user-facing.
- One section per audience (user / operator / developer / spec reader).
- Each link has a "if you want to" hook — no orphan links.
- Drift discipline: anything that becomes irrelevant gets removed, not annotated as "obsolete."

If you're tempted to add three new sections, three new audience categories, or three new doc subdirectories — pick one. Apple-style.

---

## Changelog

- **2026-05-18** — Index created as part of the Apple-style discipline shift. Single canonical doc home. Replaces ad-hoc discovery via repository browsing.
