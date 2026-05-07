<!-- markdownlint-disable MD036 -->
# Dev log — weekly template + posting protocol

**Audience:** community in your Discord `#dev-log` channel.
**Cadence:** every Sunday or Monday morning. Hit it consistently.
**Automation:** `scripts/post-to-discord.ps1 -WebhookUrl <url> -File <this rendered md>`.
**Tone:** factual, no marketing, failures included.
**Before posting:** every dev log goes through the opsec review in [DISCORD_OPSEC.md](DISCORD_OPSEC.md). Assume Discord channel history can be scraped at any time. Anything that wouldn't be safe to publish on the website doesn't go in `#dev-log`.

The single most important thing about this format is that it survives if you skip a week — but **don't skip a week**. Inconsistent cadence is worse than no cadence; the perception of "the project is dying" sets in fast. If a week is rough, post a short version that says so. The "tried, didn't work" section makes that easier than it sounds.

---

## Template (copy into a fresh file each week)

```markdown
## Dev log — week of YYYY-MM-DD

**Shipped this week**
- [<short-hash>] one-line description
- [<short-hash>] one-line description
- ...

**In progress**
- description (state: ~X% / waiting on Y / blocked by Z)
- ...

**Tried, didn't work**
- description + what I learned
- (skip section if nothing applies — but if you ship perfectly every week,
  you're probably not pushing hard enough)

**Next week**
- specific items, not aspirational ones

**Soak / fleet health**
- block height: X
- network hashrate: ~Y H/s
- uptime: 100% / N% — Z incidents in window
- known issues: list / "none"

**Open questions for the community**
- (only if any — skip if not)
```

---

## Posting protocol

1. **Pick a fixed day and time.** Sunday 18:00 ET or Monday 09:00 ET works well — both catch the start of the week's news cycle without being on the work-hours busy schedule.
2. **Write it from notes you already have.** You should be jotting commit hashes + outcomes as you work, not stitching them together on Sunday. The post should take 15 minutes max if you're keeping notes.
3. **Render through `scripts/post-to-discord.ps1`** with the webhook URL stored in `$env:COINCYNC_DEV_LOG_WEBHOOK`. Don't hardcode the URL anywhere committed.
4. **Pin the most recent log** if your Discord has channel-pinning. Replace the previous pin each week.
5. **Don't edit a posted log.** If something needs correcting, post a follow-up reply in the channel.

---

## What goes in vs. what doesn't

| Goes in | Doesn't go in |
|---|---|
| Concrete commit hashes / PR links | "Made progress on stuff" |
| Specific test outcomes (PASS / FAIL with diagnosis) | "Working hard" |
| Failures + what you learned | Hidden failures |
| Soak/fleet metrics from real data | Estimated/aspirational metrics |
| Calendar dates with explicit caveats | "Soon" / "in the coming weeks" |
| Audit / security work in non-sensitive detail | Active vulnerability details |
| User-facing wallet/UX changes that shipped | UX changes that didn't ship yet |
| New CIP discussion threads | Marketing for upcoming CIPs |

---

## Special-case post: live milestone events

When you're about to attempt something with audience value (first end-to-end CYNC↔BTC atomic swap on testnet, mainnet RC dry run, audit findings disclosure) — schedule it 1-2 weeks in advance and post a "save the date" notice in `#dev-log`. Then on the day, do live tx-by-tx commentary in the channel.

Format:

```markdown
## Live event — first end-to-end CYNC↔BTC atomic swap on testnet

**When:** YYYY-MM-DD HH:MM UTC
**Where:** this channel + explorer + Bitcoin testnet (links below)
**Duration:** ~30-45 minutes for the full swap
**What I'll be doing:**
1. Post the swap setup (BTC + CYNC sides) live
2. Post each transaction hash as it broadcasts, with a watch-link
3. Post the unlock proof + final tx hash when complete
4. Field questions in real time

If it fails, you'll see why. If it succeeds, you'll see exactly what happened. Either is interesting.

Watch live:
- CoinCync explorer: https://explorer.coincync.network
- Bitcoin testnet explorer: https://blockstream.info/testnet/
```

Live events are the highest-leverage Discord posts you'll do all year. Each one is concrete, watchable, share-able to other communities, and ships even when it fails. Plan three of them between now and mainnet:

1. First successful CYNC↔BTC atomic swap on testnet (Jul-Aug)
2. CIP-003 cut-through activation dry run on testnet (Aug-Sep)
3. Mainnet RC1 dry run (Sep)

---

## Anti-patterns to flag if you catch yourself doing them

- **Apologizing for slow weeks** — slow weeks happen. Just write what shipped. No "sorry for the slow week" preamble.
- **Promising things in dev logs** — if it's promised, it's a CIP. Dev logs report; CIPs commit.
- **Engaging with price questions** — *"price talk goes in `#general` or skip — this channel is dev work only."*
- **Marketing language** — anything that reads like LinkedIn doesn't belong here.
- **Hyping the next post** — *"big news next week"* is a marketing tic. Just ship the thing, then post.

---

## Reference

`scripts/post-to-discord.ps1` — wrapper that posts to a Discord webhook from a file or stdin.
`#dev-log` — read-only channel where these go (community can react with emoji; discussion goes in `#general`).
`#commits` — auto-stream of every commit (webhook from Forgejo).
`#testnet-status` — auto-stream of fleet health + incident alerts.
