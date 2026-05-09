---
name: Feature request
about: Propose a new feature or behavior change
title: "[feat] "
labels: ["enhancement", "needs-triage"]
assignees: []
---

## Summary
<!-- One sentence: what should CoinCync do that it doesn't today? -->

## Problem
<!--
Describe the user-facing problem this would solve. Concrete scenarios are
much more useful than abstract benefits. "I can't do X because Y" beats
"It would be nice to have X."
-->

## Proposed approach
<!--
How would you implement this? A sketch is fine — code-level detail is
not required, but say enough that a maintainer can judge complexity and
spot constitutional conflicts before writing code.
-->

## Alternatives considered
<!-- What else did you try or rule out, and why? -->

## Constitutional review
<!--
CoinCync is governed by an explicit Constitution + Bill of Rights
(see CONSTITUTION.md / docs/governance/bill-of-rights.md). Some categories
of change are categorically forbidden:

  - Stablecoins, smart-contract VMs, cross-chain bridges
  - NFTs / on-chain name services
  - Governance tokens, admin keys, upgrade keys
  - Fee redirects to any party (dev tax, foundation tax, treasury)
  - Surveillance / metadata leakage on non-opt-in paths

Confirm your proposal does NOT introduce any of the above. If unsure,
read the Constitution articles before opening this issue.
-->
- [ ] I have read CONTRIBUTING.md and confirmed this proposal does not
      conflict with the Constitution or Bill of Rights.

## Component(s) affected
- [ ] Node (`coincyncd`)
- [ ] Wallet (Tauri desktop)
- [ ] CLI / RPC
- [ ] Explorer / faucet
- [ ] Build / packaging
- [ ] Documentation
- [ ] Other:

## Hard-fork required?
<!--
Changes that alter consensus rules, block format, transaction format, or
emission curve require coordinated hard-fork activation. If you're unsure,
say so — a maintainer will help classify.
-->
- [ ] No (compatible with current testnet/mainnet)
- [ ] Yes (hard-fork required)
- [ ] Unsure
