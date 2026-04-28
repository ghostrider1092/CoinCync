# CoinCync Extended Test Battery — Tiers 12 through 20

_Nine additional tiers extending the adversarial test battery beyond cryptography and protocol-level attacks. Covers post-quantum preparation, supply chain integrity, governance, novel threats, scalability, cross-protocol attacks, social engineering, insider threats, and discovery of unknown unknowns._

---

## Overview

Tiers 1 through 11 test what your code does. Tiers 12 through 20 test what surrounds your code: your processes, your team, your dependencies, your future.

Not all of these are runnable test suites. Some are Rust tests. Some are shell scripts. Most are structured documents — playbooks, threat models, checklists. The format reflects the nature of the threat: you can't `cargo test` your response to a coordinated smear campaign, but you can document what to do when one happens.

---

## The files

| Tier | Subject | Format | File |
|------|---------|--------|------|
| 12 | Post-quantum resistance | Threat model + assertions | `tier-12-post-quantum.md` |
| 13 | Supply chain / build integrity | Executable shell script | `tier-13-supply-chain.sh` |
| 14 | Governance attack scenarios | Playbook (9 scenarios) | `tier-14-governance-attacks.md` |
| 15 | Novel cryptographic threats | Research watch list | `tier-15-novel-crypto-threats.md` |
| 16 | State bloat / scalability | Rust test code | `tier-16-scalability.rs` |
| 17 | Cross-protocol attacks | Rust test code | `tier-17-cross-protocol.rs` |
| 18 | Social engineering | Response playbook | `tier-18-social-engineering.md` |
| 19 | Insider threats | Security policy document | `tier-19-insider-threats.md` |
| 20 | Unknown unknowns | Meta-document on discovery | `tier-20-unknown-unknowns.md` |

---

## Directly testable today

- **Tier 13** (supply chain script) — run it, fix findings
- **Tier 16** (scalability tests) — adapt stubs to CoinCync types, run

## Partially testable today

- **Tier 17** (cross-protocol) — what runs locally works; BGP-level attacks don't

## Process documents (not code tests)

- **Tier 12** (post-quantum) — threat model and migration plan
- **Tier 14** (governance) — 9 tabletop exercise scenarios
- **Tier 15** (novel threats) — quarterly research watch list
- **Tier 18** (social engineering) — response playbook
- **Tier 19** (insider threats) — security policy
- **Tier 20** (unknown unknowns) — meta-document on discovery
