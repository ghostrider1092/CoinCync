<!-- markdownlint-disable MD036 -->
# Discord opsec policy

**Threat model:** assume any of the following can happen at any moment and design every webhook + post around the assumption that it *will*.

1. A Discord moderator account is compromised and the attacker scrapes channel history
2. A webhook URL leaks (committed by accident, posted in screenshot, fished from a backup)
3. Discord itself gets a server-side data exposure
4. A current community member becomes hostile after a falling-out and exports their channel access

If any of those happens, what's in `#dev-log` / `#commits` / `#testnet-status` becomes public. Therefore: **never post anything that wouldn't be safe to publish on coincync.network's blog tomorrow**.

## What's safe to post (already public anyway)

| Category | Examples |
|---|---|
| Public chain data | block heights, tx hashes, total drips, network hashrate, peer counts (aggregated) |
| Repo activity | commit hashes, commit messages, PR/CIP references, build status |
| Public CIP work | CIP numbers, design summaries, links to spec documents |
| Failure summaries | "block-X validation failed at component Y, fix at commit Z" — once the fix has shipped |
| Aggregated user metrics | "47 drips today" — single number per day, no per-request detail |
| Live event commentary | tx hashes from a planned live event, public block heights, public confirmations |
| Soak / fleet aggregates | "all 5 nodes synced, max-stall under 5 min" — aggregate-only |
| Schedule / calendar | upcoming dry runs, audit kickoffs, mainnet timelines |

## What's NEVER safe to post

| Category | Why |
|---|---|
| **RPC bearer tokens** (`COINCYNC_RPC_API_KEY`) | Direct compromise of the node's RPC. |
| **Wallet passwords** (`FAUCET_WALLET_PASSWORD`, any wallet) | Direct compromise of funds. |
| **Wallet seed phrases / mnemonics** | Same. |
| **Private keys, signing keys, SSH keys** | Same. |
| **Webhook URLs themselves** | Anyone with a webhook URL can post (or, depending on settings, read history). Treat them like passwords. |
| **Internal IP addresses of fleet boxes** | Maps your infrastructure for an attacker. Use hostnames or fleet positions ("seed-region-A"), never IPs. |
| **Wallet hot-balance amounts** | Tells an attacker how much is in the faucet — sets the priority of attacking it. Post drip *counts*, not balances. |
| **Per-request user IPs** | Privacy violation against users. The faucet logs IPs locally for rate-limit; never echoes them to Discord. |
| **Per-drip user addresses** (full string) | Privacy violation. If you must mention a drip, truncate: `tCYNC3ZN8…ZmLZF` (first 8 + last 8 chars). |
| **Per-tx user addresses** | Same. |
| **Audit findings before disclosure** | Until the audit firm has cleared a finding for public disclosure, don't mention it in any channel — including dev-log. |
| **Active vulnerability details** | Including the existence of one, until patched + disclosed. |
| **Personally identifiable info about contributors / users** | Names, emails, IPs unless they explicitly chose to be public. |

## Specific rules per channel

### `#dev-log` (manual posts via `scripts/post-to-discord.ps1`)

- ✅ Weekly digest using the `DEV_LOG_TEMPLATE.md` format
- ✅ Ad-hoc shipping notices ("X just landed at commit Y")
- ✅ Live event commentary (planned milestones)
- ❌ Anything from the "never safe" list above
- ❌ Off-the-cuff venting about specific contributors / users / community members

### `#commits` (auto-stream from Forgejo)

- ✅ Commit hashes, author display name (NOT email — configure Forgejo to omit)
- ✅ Commit messages (assuming you've followed the no-secrets-in-commits rule)
- ❌ The webhook URL itself in any commit message (paranoid but easy)
- ❌ Diff content of commits that touched secret-handling code (Forgejo can be configured to skip diff payload for posts; do that)

### `#testnet-status` (auto-stream from soak / selfcheck)

- ✅ Aggregate metrics: chain tip, network hashrate, total nodes synced, incident count
- ✅ Incident alerts using **fleet-position labels** (`seed-A`, `seed-B`, `seed-C`, `explorer`, `api`) — NOT hostnames or IPs
- ✅ Resolution notices
- ❌ Hostnames (`api`, `explorer`, `seed1` — the bot post should use generic labels)
- ❌ Sample raw data with bearer tokens / RPC URLs in error messages
- ❌ Per-peer IP addresses if a peer is identified (use peer-id short hash instead)

### `#faucet-activity` (planned, post-launch)

If you wire faucet drip notifications:

- ✅ Aggregate counters: "drip count today: 47", "uptime since X"
- ✅ Truncated addresses for context: `tCYNC3ZN8…ZmLZF`
- ❌ Full user addresses
- ❌ User IP addresses
- ❌ Hot-wallet balance ("the faucet has 73.4 tCYNC remaining")

## Webhook URL hygiene

1. **Store webhook URLs in env files** with mode 0600 (already done for fleet boxes via `/etc/coincync/coincync.env`). Never in committed scripts.
2. **Rotate webhook URLs** if there's any chance one leaked: Discord channel → Edit → Integrations → Webhooks → delete and recreate.
3. **Use a separate webhook URL per service** so a single leak only compromises one channel.
4. **Audit posted history** monthly — scroll back, look for anything that violates the policy above. If you find anything, ROTATE the webhook + DELETE the post + assume the cat is out of the bag.

## If a leak happens

The webhook URL was the leak path. Rotate it immediately:

```bash
# 1. Discord: delete + recreate the webhook in channel settings
# 2. Update the env file on the affected boxes
ssh root@<box-ip> "vi /etc/coincync/coincync.env  # update DISCORD_WEBHOOK"
ssh root@<box-ip> "systemctl restart coincync-soak.service coincync-selfcheck.timer"
# 3. (or for the dev-log webhook in your local PowerShell session)
$env:COINCYNC_DEV_LOG_WEBHOOK = '<new-url>'
```

If sensitive content was actually in the leaked history (per the "never safe" list above):

1. Treat the underlying secret as compromised
2. Rotate the secret (RPC token, wallet password, etc.)
3. Post a transparency notice in `#dev-log` describing what was rotated and why — being honest about leaks is the only way to keep credibility through them

## What this doc is NOT

It's not a substitute for thinking. The list above is the floor, not the ceiling. When in doubt, **don't post it** and ask — the cost of a missed update is approximately zero; the cost of a leaked credential is hours of recovery work and credibility loss.
