# Maintainers

Who can review, merge, deploy, sign releases, and read the security inbox.

This file is the single source of truth for **named-person** responsibilities. The [CODEOWNERS](.github/CODEOWNERS) file is the machine-readable view of who reviews which code paths; this file is the human-readable view of who covers which **operational role**, who their backup is, and how to contact them.

If you're a contributor who needs a PR reviewed and the listed reviewer hasn't responded within the SLA, fall back to the next person in the role's chain. If the chain is exhausted (every named person is unresponsive), see [`docs/operations/MAINTAINER_RECOVERY.md`](docs/operations/MAINTAINER_RECOVERY.md).

---

## Active maintainers

| Role | Primary | Backup | Public contact |
|---|---|---|---|
| **Project lead** — strategic direction, CIP final-call | [@ghostrider1092](https://github.com/ghostrider1092) | _unfilled — see [Recruiting](#recruiting)_ | Discord `@ghostrider1092` |
| **Consensus + crypto reviewer** — PRs touching `src/consensus/`, `src/crypto/`, `src/transaction/validator.rs`, `src/chain.rs`, `src/emission.rs`, `src/constants.rs` | [@ghostrider1092](https://github.com/ghostrider1092) | _unfilled_ | Discord `@ghostrider1092` |
| **Wallet + RPC reviewer** — PRs touching `src/wallet/`, `src/rpc/`, `src/bin/wallet.rs`, `coincync-wallet-v2/` | [@ghostrider1092](https://github.com/ghostrider1092) | _unfilled_ | Discord `@ghostrider1092` |
| **Network + mempool reviewer** — PRs touching `src/network/`, `src/mempool.rs` | [@ghostrider1092](https://github.com/ghostrider1092) | _unfilled_ | Discord `@ghostrider1092` |
| **Release manager** — cuts tags, signs artifacts, publishes binaries | [@ghostrider1092](https://github.com/ghostrider1092) | _unfilled_ | n/a |
| **Fleet operator** — SSH access to seed/explorer/api nodes; deploys + incident response | [@ghostrider1092](https://github.com/ghostrider1092) | _unfilled_ | n/a |
| **Security inbox** — reads `security@coincync.network`, triages disclosures | [@ghostrider1092](https://github.com/ghostrider1092) | _unfilled_ | `security@coincync.network` |
| **Community + Discord moderation** | [@ghostrider1092](https://github.com/ghostrider1092) | _unfilled_ | Discord `@ghostrider1092` |

**Every role currently lists the same primary.** That is the bus-factor problem [`docs/governance/bus-factor.md`](docs/governance/bus-factor.md) was written to surface. The goal between now and the v1.0 mainnet date (2026-10-01) is to fill at least one `_unfilled_` per row.

---

## Review SLAs

These are the response windows contributors and security reporters can expect. If a window slips, escalate to the role backup (when one exists) or to the project lead.

| PR / report type | First response | Decision |
|---|---|---|
| Trivial doc/typo PR | 3 days | 7 days |
| Non-consensus code PR (wallet, RPC, perf, docs) | 7 days | 14 days |
| Consensus or crypto PR | 7 days | 30 days (research lag is expected; ping if no acknowledgment in 7) |
| CIP draft | 7 days | n/a (CIPs require a 60-day public window per [CONTRIBUTING.md](CONTRIBUTING.md#cip-process--for-protocol-changes)) |
| Security disclosure | 24 hours | 7 days for classification; 30 days for fix-in-development; 90 days for public disclosure ([SECURITY.md](SECURITY.md)) |

---

## Recruiting

We need backups, not co-founders. A useful backup maintainer can:

1. Read Rust well enough to spot an obvious bug in a PR (you don't have to be the world's best cryptographer to catch a missing nonce-uniqueness check).
2. Operate a Linux server (SSH, systemd, log inspection).
3. Be reachable on a predictable schedule — "I'm available 2 hours/week, M/W evenings" is a useful commitment; "maybe sometime" is not.
4. Tolerate pseudonymity. Per [Right V](docs/BILL_OF_RIGHTS.md), maintainers may operate under any name.

Critically — a backup is **not** a substitute primary. They cover gaps; they don't carry the project. If the role's primary disappears, the backup's first job is to **find a new primary**, not to become the new primary by default.

If you'd like to be considered: open a PR adding yourself with `[backup-applicant]` status (e.g., `_unfilled_` → `@yourhandle [backup-applicant]`), or DM the project lead on Discord. Expect a multi-week conversation — trust transfers slowly for crypto-money projects, by design.

---

## Process — how a maintainer gets added or removed

**Adding:** primary maintainer of the affected role nominates; project lead approves; lead opens the PR updating this file + CODEOWNERS; lead grants the operational access (GitHub team membership, fleet key copy, security@ alias). Wait 7 days from PR open for community comment before merging.

**Removing (voluntary):** the leaving maintainer opens a PR moving themselves out of all rows, rotates any keys/credentials they hold, and updates `docs/operations/MAINTAINER_RECOVERY.md` with what they were responsible for that hasn't been transferred yet. The role's backup is promoted to primary if there is one; otherwise the role becomes `_unfilled_` and is escalated as a recruiting priority.

**Removing (involuntary — unresponsive or hostile):** any other active maintainer may open an issue tagged `governance:maintainer-removal` describing the situation. The project lead decides; if the project lead is the one being removed, all other active maintainers must reach 2/3 consensus and post the decision publicly with reasoning. Keys/access revoked within 24 hours of the decision.

---

## How CODEOWNERS relates to this file

[`.github/CODEOWNERS`](.github/CODEOWNERS) lists GitHub handles per code path; GitHub's branch-protection uses it to auto-request reviews. This file lists **operational roles** that aren't visible to GitHub (fleet ops, inbox monitoring, release signing). Keep both in sync when names change.

When a backup gets named in a row above, also add their handle to the relevant CODEOWNERS line so PR auto-assignment reaches them.
