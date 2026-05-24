# Bus-factor inventory

What breaks if the primary maintainer disappears, and who (if anyone) can fix it.

This is the dependency map [`MAINTAINERS.md`](../../MAINTAINERS.md) is trying to close. Every row below is a critical-path responsibility that currently has a single point of failure. The goal between now and the v1.0 mainnet date (2026-10-01) is to drive the **"Backup"** column toward "named person" instead of "none."

**Threat model for this document:** the primary maintainer becomes unavailable for 2-4 weeks with no warning (medical, legal, hardware-loss, hostile state action, fatal accident). For each row, the question is: *what does the project need to do during that window, and does it have the people and access to do it?*

This is not a hypothetical pre-mainnet, but it becomes load-bearing post-mainnet. Once real users hold tCYNC/CYNC on the chain, "we can't ship a fix for 4 weeks" stops being a continuity inconvenience and starts being a user-harm event.

---

## Code review + merge authority

| Path | Current reviewers | Backup | What breaks if primary is out | Severity |
|---|---|---|---|---|
| `src/consensus/` (block validation, supply, reorg policy) | [@ghostrider1092](https://github.com/ghostrider1092) | none | No consensus PR can land. Audit findings can't be patched. Hard-fork hotfix path is closed. | **Critical** post-mainnet |
| `src/crypto/` (CLSAG, Bulletproofs+, stealth derivation) | [@ghostrider1092](https://github.com/ghostrider1092) | none | No crypto fix can land. Silent privacy bugs (linkability, range-proof inflation) cannot be patched until primary returns. | **Critical** at all stages |
| `src/wallet/` send + scan paths | [@ghostrider1092](https://github.com/ghostrider1092) | none | User-fund-loss fixes blocked. Reorg-recovery patches blocked. | **High** post-mainnet |
| `src/network/` + `src/mempool.rs` | [@ghostrider1092](https://github.com/ghostrider1092) | none | Chain-stall fixes blocked (see 2026-05-07 shadow-conflict incident). | **High** post-mainnet |
| `src/rpc/` | [@ghostrider1092](https://github.com/ghostrider1092) | none | RPC vulnerabilities can't be patched. Allowlist mistakes can't be reverted. | **Medium** |
| Constitution, Bill of Rights, threat model, KNOWN_ISSUES | [@ghostrider1092](https://github.com/ghostrider1092) | none | No documentation updates — non-critical for ~weeks. | **Low** |

**Mitigation in flight:** CONTRIBUTING.md mandates "Two-of-N maintainer sign-offs for anything touching consensus rules." This rule is unenforceable with N=1; once a second consensus reviewer is named in CODEOWNERS, GitHub's branch protection can be tightened to require two reviews on those paths.

---

## Operational access (the keys + accounts that keep the network alive)

| Resource | Current holder | Backup | What breaks | Severity |
|---|---|---|---|---|
| Fleet SSH key (`C:\Users\unkno\.ssh\coincync_fleet`) — root access to seed1-3, explorer, api | primary, single copy on primary's laptop | none | Cannot deploy fixes, cannot rotate certs, cannot triage incidents. **Hard fail** if primary's laptop is destroyed without a backup of this key. | **Critical** |
| Cloudflare account — fronts `coincync.network` + `coincync.org` | primary | none | Cannot update DNS, cannot purge cache after a deploy, cannot rotate origin certs. WAF rule changes blocked. | **High** |
| Vultr account — billing + control plane for the 5 fleet nodes | primary | none | Billing failure → node shutdown after grace period. Cannot resize nodes, cannot reboot from console if SSH is locked out. | **High** |
| Domain registrar (for `coincync.network`, `coincync.org`) | primary | none | If domain renewal fails during primary's absence, the network's user-facing URL stops resolving. | **Critical** if outage spans renewal date |
| GitHub admin (repo, branch protection, secrets) | primary | none | Cannot adjust CI, cannot rotate Actions secrets, cannot grant access to a new maintainer. | **Medium** |
| Release-signing key (used for binary artifact signatures) | primary | none | Cannot cut signed releases. Users have no trusted artifact path. | **High** post-mainnet |
| `security@coincync.network` mailbox | primary | none | Vuln reports go unread. The 24-hour SLA in [SECURITY.md](../../SECURITY.md) silently breaks. | **Critical** post-mainnet |

**Recommended near-term mitigations** (each is independent and cheap):

1. **Encrypt + escrow a copy of the fleet SSH key.** GPG-encrypt to a backup maintainer's key, store in a separate secure location (safety deposit box, separate cloud-storage account with 2FA). Restore is one command.
2. **Set up Cloudflare + Vultr account-recovery contacts.** Both support an account-recovery email and (Vultr) a billing-only secondary user. No co-admin needed.
3. **Configure registrar auto-renewal + a 2nd payment method.** A credit-card-expiry isn't a continuity event — but a single point of payment failure IS.
4. **Forward `security@` to a 2nd address** (Gmail "always forward a copy" rule or equivalent). Once a backup maintainer exists, point this at their address.
5. **Generate a 2nd release-signing key now** and register it as a valid signer in advance, before there's a person to give it to. When the backup maintainer is named, they get the key.

---

## Decision-making continuity

| Decision class | Current decider | Backup | What breaks |
|---|---|---|---|
| CIP final-call (after the 60-day public window) | project lead | none | CIPs stuck indefinitely. CoinCync's whole protocol-evolution path stalls. |
| Audit-fix prioritization | project lead | none | If audit firm reports during primary's absence, fixes can't be triaged. Audit clock keeps ticking. |
| Hard-fork activation timing | project lead | none | Cannot coordinate miner signaling. Already-merged consensus changes can't activate. |
| Emergency disclosure (an exploited bug) | project lead | none | The 90-day disclosure window in [SECURITY.md](../../SECURITY.md) can't be honored if no one can authorize early disclosure. |

These are the hardest to delegate because they require both judgment AND the trust of the community. **Mitigation:** publish a written escalation protocol — "if the project lead is unreachable for >14 days during an active incident, the consensus reviewer takes over emergency-disclosure authority for the duration." Written in advance, scrutinized in calm conditions, applied unilaterally in a crisis.

---

## Genesis-ceremony-specific roles

The [GENESIS-DECISIONS-WORKSHEET](../launch/GENESIS-DECISIONS-WORKSHEET.md) adopted "**on-call B: maintainer + backups by T-30 = 2026-09-01**". This deadline is **load-bearing**: the genesis ceremony is the one moment in CoinCync's history that can never be redone. A single-point-of-failure ceremony is a credibility risk for the chain's entire lifetime.

Open questions to close by 2026-09-01:

- Who is the named backup operator for the genesis-block ceremony?
- If the primary operator is unreachable at T-0, what's the rollback / postpone procedure?
- Where are the genesis seed words for the recovery-address being held? (Per the worksheet: coinbase A = burn, so this is moot for coinbase — but other ceremony keys may apply.)
- Who has the authority to declare a genesis "do-over" if something goes wrong in the first hour? Under what conditions?

---

## What's already mitigated

Credit where it exists:

- **Reproducible builds** (Right XIII + [REPRODUCIBLE_BUILDS.md](../operations/REPRODUCIBLE_BUILDS.md)) — anyone can rebuild a release from source and verify against the published artifact, so a missing release-signing key doesn't strand users at a known-good version. They can rebuild and verify themselves.
- **Public CODEOWNERS file** ([.github/CODEOWNERS](../../.github/CODEOWNERS)) — the policy framework is in place; only the names need to change.
- **Operational runbooks** (`docs/operations/`) — CHECKPOINT_PROCEDURE, DNS_FAILOVER, INCIDENT_RUNBOOKS, STATUS_PAGE, CONTINUOUS_FUZZING, REPRODUCIBLE_BUILDS — a new operator inheriting the fleet has documentation to read instead of starting from zero.
- **Constitutional commitment to disclosure** (Article XV) — the rules for what gets disclosed when are written down, not held in primary's head.
- **Open-source license + public repo** — worst case (everyone walks away), users can fork. CoinCync would not die quietly; it would be picked up by whoever cares enough.

---

## Recovery path if nothing else worked

[`docs/operations/MAINTAINER_RECOVERY.md`](../operations/MAINTAINER_RECOVERY.md) is the bootstrap document a new operator reads when the primary is gone and the backup chain is empty. Read it before you need it.
