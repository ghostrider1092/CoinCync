# Maintainer recovery — if you're reading this and the primary is gone

This document is the bootstrap procedure for someone who finds themselves having to keep CoinCync running when the primary maintainer is unreachable and no named backup exists.

Read it before you need it. If you ARE reading it because you need it right now: start at [Step 1](#step-1-triage-whats-actually-broken).

---

## Who this is for

You are:

- A community member who cares enough about the project to step up
- Someone who has read [CONTRIBUTING.md](../../CONTRIBUTING.md), [MAINTAINERS.md](../../MAINTAINERS.md), and [docs/governance/bus-factor.md](../governance/bus-factor.md)
- Comfortable on a Linux shell, can read Rust well enough to spot obvious bugs
- Willing to act in the open — coordinate via the public Discord and GitHub issues, not via DM

You are **not** expected to:

- Have any prior access (keys, accounts, inboxes) — assume you have none
- Be authorized to make binding decisions for the project — your job is to **stabilize** until either the primary returns or the community converges on a new maintainer
- Operate alone — pull others in from the public channels immediately

---

## Step 1 — Triage what's actually broken

Before doing anything, determine which of these are still working:

| Resource | How to check | If broken |
|---|---|---|
| Public website ([coincync.network](https://coincync.network)) | HTTP GET; expect 200 | DNS or Cloudflare account issue → Step 2 |
| Block explorer ([coincync.network/explorer](https://coincync.network/explorer)) | HTTP GET; expect chain tip within last hour | Explorer node down → Step 2; chain stalled → Step 3 |
| API ([api.coincync.network/rpc/testnet](https://api.coincync.network/rpc/testnet) — replace `testnet` with `mainnet` post-2026-10-01) | JSON-RPC `get_info` call | API node down → Step 2 |
| Discord server | Is the user-facing invite at the project's README still working? Can community members log in? | Server deleted → Step 4 |
| GitHub repo | Can you `git clone` and read it? Are issues being filed? | Repo deleted/private → Step 5 |
| Block production | Chain tip moving on the explorer at the expected rate | Stalled → Step 3 (priority) |

**Most likely scenario:** everything is technically still running on autopilot; what's broken is *governance* (no one can review/merge PRs, no one is reading `security@`). In that case, skip to Step 4.

---

## Step 2 — Network infrastructure recovery

If a node has gone offline:

1. **Don't panic.** A single node down does not stop the network. Seed1, seed2, seed3 are redundant; either of the explorer or api nodes going down degrades user experience but doesn't break consensus.
2. **Check Vultr status page.** If the outage is upstream, wait.
3. **You probably cannot SSH in** — the fleet key is `C:\Users\unkno\.ssh\coincync_fleet` on the primary's laptop, single copy, no escrow as of this writing (this is the bus-factor item to close first).
4. **Coordinate a community-run node.** While the fleet is offline, the network is still alive if community-run nodes exist. Post in the Discord `#operators` channel asking who's running a node. Provide their addresses as additional seed nodes to users.

If DNS is broken:

1. Check the domain WHOIS — is the registration expired, or just misconfigured?
2. Expired: you cannot fix this without registrar access. Document the date publicly and prepare community for a possible URL migration.
3. Misconfigured: same problem — you need Cloudflare access. Without it, the recovery path is to publish IP addresses directly and ask users to add hosts-file entries. Crude but works.

---

## Step 3 — Consensus / chain stall

This is the most severe failure mode. If the chain has stopped producing blocks:

1. **First, confirm it's actually stalled** and not a temporary network partition. Wait 30 minutes; check multiple block explorers (community-run if any exist); check Discord `#chain-events`.
2. **If genuinely stalled:** the cause is one of: (a) a bug in mempool admit / block validation, (b) a CIP-009 finality lock blocking advancement, (c) all seed nodes simultaneously down. Check the [INCIDENT_RUNBOOKS.md](INCIDENT_RUNBOOKS.md) in this same directory for the standard recovery procedures — they're written by the primary for this exact situation.
3. **Communicate early.** Post to Discord, GitHub Issues, and any community-aggregated status page. Underpromise on timeline.
4. **You cannot deploy a fix without fleet access.** What you CAN do is build the fix locally (the repo is public, the toolchain is pinned in `rust-toolchain.toml`), publish a community release on a fork, and announce its hash on Discord. Operators of community-run nodes will adopt; the official fleet won't until access is regained.

---

## Step 4 — Governance vacancy

This is the most common bus-factor scenario. The chain is fine, the nodes are fine, but PRs are stacking up and `security@` is going unread.

1. **Post a public Discord + GitHub Issue: "Primary maintainer unreachable since YYYY-MM-DD."** Be factual. Don't speculate on cause. Invite community input.
2. **Wait 7 days for the primary to respond.** Most "absences" are not absences; they're slow weeks. Don't escalate prematurely.
3. **If primary is still silent after 14 days:** convene the named backups (when this section reads "_unfilled_" everywhere, fall through to step 4).
4. **If there are no named backups:** the community has to converge on a new primary through public discussion. This is intentionally slow. The Constitution's Article XV ("Spirit and Construction") and the [CODE_OF_CONDUCT.md](../../CODE_OF_CONDUCT.md) provide the framework — apply them in good faith. A reasonable threshold for "the community has chosen a new primary" is: a public Discord vote with at least 30 days of notice, supported by a public GitHub-issue discussion thread visible to anyone with repo read access, with a clear majority of self-identified community members supporting one candidate.
5. **A new primary cannot grant themselves keys.** They can only grant themselves the things that don't require key custody:
   - Reviewing + merging PRs (requires GitHub admin → only available if old primary granted it, or if GitHub support agrees to transfer based on community evidence)
   - Reading `security@` (only if email forwarding can be set up or DNS for the domain is recoverable)
   - Cutting an unsigned release (always possible; users would have to choose to trust it)

---

## Step 5 — GitHub-level recovery

If the GitHub repo itself is lost (account deleted, transferred to an unresponsive account, etc.):

1. The MIT license + Right XIII (reproducible builds) mean the code itself is recoverable from any cloned copy. Anyone who has ever run `git clone` has a complete snapshot up to the moment of the clone.
2. Coordinate via the [Discord server](https://discord.gg/5tYNSCsqzy) (if it's still accessible) to identify the most recent known-complete clone.
3. Push that clone to a fresh repository under a community-controlled organization. Update community materials to point to the new location.
4. Reconstruct issue/PR history from anyone who has copies (GitHub's API + a community member's prior `gh repo backup` saves you years of work; without those, history is lost but the code itself is not).

---

## What to tell users while you're recovering

A short, honest, regularly-updated post is more valuable than a perfect long one. Suggested template:

> **CoinCync maintainer status — \[date]**
>
> The primary maintainer has been unreachable since \[date]. Recovery is in progress.
>
> **What still works:** \[chain produces blocks / wallets sync / mining works / etc.]
> **What doesn't work:** \[security disclosures unanswered / no new releases / etc.]
> **What we're doing:** \[Step number from MAINTAINER_RECOVERY.md being executed]
> **What you can do:** \[run a node / mirror the repo / etc.]
> **Next update:** \[date and time, in 48h max]

Underpromise. The fastest way to lose user trust is to commit to a timeline you can't keep. The fastest way to earn it is to ship updates on the cadence you said you would, even when there's nothing new to report.

---

## Closing the loop

If the primary returns: do NOT just hand back access silently. There should be a public Discord post acknowledging the recovery period, a debrief on what worked and what didn't, and an immediate priority on closing the bus-factor gaps that made the recovery harder than it needed to be. Use [docs/governance/bus-factor.md](../governance/bus-factor.md) as the checklist.

If the primary does not return: the community has effectively chosen a new primary by following Step 4. The new primary's first job is to update this document, [MAINTAINERS.md](../../MAINTAINERS.md), and [docs/governance/bus-factor.md](../governance/bus-factor.md) to reflect the new reality, and to recruit their own backups so the next person reading this isn't starting from zero.
