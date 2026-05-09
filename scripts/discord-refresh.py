#!/usr/bin/env python3
"""
discord-refresh.py — push the canonical CoinCync content into Discord.

Usage (PowerShell):
    $env:DISCORD_BOT_TOKEN = "<paste-bot-token>"
    python scripts/discord-refresh.py

Usage (bash):
    DISCORD_BOT_TOKEN=<paste-bot-token> python3 scripts/discord-refresh.py

What it does (idempotent up to duplicate pins — see --dry-run first):
  • Updates the server description
  • Sets the topic on every text channel that matches our naming
  • Posts the pinned-message block in the matching channel
  • Pins the new message (requires Manage Messages permission)

Channels not present in the server are skipped with a note.

Permissions the bot needs (grant via OAuth2 URL Generator → bot scope):
  Send Messages, Embed Links, Manage Messages, Manage Channels, Manage Server
("Administrator" covers all of these.)

Source of truth for the content: docs/launch/DISCORD_REFRESH.md
"""

import json
import os
import sys
import urllib.error
import urllib.request

# ─────────────────────────────────────────────────────────────────────────
# Server description (Discord limit: 120 chars)
# ─────────────────────────────────────────────────────────────────────────
SERVER_DESCRIPTION = (
    "Privacy-first PoW · constitutionally locked · CYNC<->BTC atomic-swap mainnet blocker · MIT · public testnet live"
)

# ─────────────────────────────────────────────────────────────────────────
# Channel topics (Discord limit: 1024 chars per topic)
# Keys are matched case-insensitively against channel names.
# ─────────────────────────────────────────────────────────────────────────
TOPICS = {
    # ── Top-level ─────────────────────────────────────────────────
    "announcements":   "Project-level announcements only. Read-only for members. Updates: launch, releases, incidents.",
    "rules":           "Server rules. Read first, then say hello in #general. Bug reports -> #bug-reports.",
    "general":         "Open chat. Be technical, be patient. No price talk on testnet. Bug reports -> #bug-reports.",
    "international":   "Non-English chat welcome. Tag the language at the start of your message if you'd like translation help.",
    "links":           "Useful CoinCync links curated by the community. Don't post your own referral / pool links here.",
    "memes":           "CoinCync memes only. Off-topic shitposts -> nope. Quality over quantity.",
    "ideas":           "Pre-CIP brainstorming. If an idea matures, it gets a CIP draft in #internal-specs.",
    "feature-requests": "Concrete feature requests with rationale. Read the Constitution first; categorically forbidden things won't move.",
    "roadmap":         "Mainnet target 2026-10-01. Pinned: live milestone tracker. Discussion of the path; decisions in #internal-specs.",
    "releases":        "Release artifacts + checksums. SHA256SUMS.txt shipped per release. Verify your downloads.",
    "github-feed":     "Auto-posted commits + PRs from git.coincync.network/coincync/cync-protocol. Don't post manually here.",
    "roles":           "Self-assign roles: Node Operator, Miner, Wallet Dev. React to the role-message to get / drop.",

    # ── Network operations ────────────────────────────────────────
    "testnet":         "Testnet status, height, peer issues, sync help. Live: height 5675+, 5 nodes, all synced.",
    "testnet-status":  "Live operational status board. Webhook posts incidents. Don't @ here unless something is on fire.",
    "network-health":  "Fleet observability: peer counts, sync state, tip-age. 5 nodes (NJ + AMS + Tokyo + Dallas + Frankfurt).",
    "network-audit":   "External-perspective network checks: latency, reachability, DNS-seed health from third parties.",
    "node-setup":      "Running your own node — sync, peer count, RPC, systemd, builds. seed1/2/3.coincync.network are the public DNS seeds.",
    "infrastructure":  "Self-hosted forgejo (git.coincync.network), explorer, faucet, public API. Operations + ops runbooks.",
    "mainnet":         "Mainnet target 2026-10-01. Hard launch-blockers: CYNC<->BTC atomic swaps (CIP-001), audit, M-of-N signed releases.",

    # ── Mining ────────────────────────────────────────────────────
    "mining-general":  "RandomX CPU mining. Solo or pool. Testnet hashrate ~250 H/s. No GPU/ASIC advantage by design.",
    "mining-help":     "Mining setup help — coincync-miner CLI, GUI miner, threads, address format. CPU-only.",
    "mining-stats":    "Hashrate, block-finds, difficulty over time. Auto-posts from explorer if a miner-stats webhook is configured.",
    "pool-discussion": "Public pool discussion. No pools yet on testnet — solo mining is realistic at ~250 H/s.",
    "price-talk":      "Mainnet price discussion only. Testnet coins have ZERO monetary value — please ignore anyone trading them.",

    # ── Wallet ────────────────────────────────────────────────────
    "wallet-help":     "Wallet setup, restore-from-seed, send/receive, address types. tCYNC = testnet, CYNC = mainnet (later).",
    "wallet-bugs":     "Wallet-specific bugs. For consensus/privacy bugs, security@coincync.network instead.",

    # ── Privacy & security ────────────────────────────────────────
    "privacy-general": "Privacy stack discussion: CLSAG-16, Bulletproofs+, stealth addresses, Pedersen, Dandelion++, FROST.",
    "cryptography":    "Cryptography deep-dives. Adaptor sigs, ring sigs, ZK proofs, threshold schemes. Long-form welcome.",
    "papers":          "Cryptography papers, privacy theory, adversarial analysis. Drop a link + a 2-line summary.",
    "attack-defense":  "Adversarial analysis: traffic analysis, tx graph deanonymization, eclipse, Sybil. Threat-model discussion.",
    "security-audit":  "Audit prep + audit findings (post-disclosure). Embargoed reports -> security@coincync.network with PGP.",
    "security-fixes":  "Public coordination of disclosed vulns post-fix. Includes commit links, CVE numbers when assigned.",
    "audit-discussion": "Discussion of audit scope, audit findings (post-disclosure), and what auditors should focus on.",
    "known-vulns":     "Disclosed vulnerabilities post-fix. Pinned: timeline, severity, mitigation. CVE numbers when assigned.",
    "scam-alerts":     "Confirmed scams targeting CoinCync users. Read pins before reporting; we filter for already-known scams.",

    # ── Development ───────────────────────────────────────────────
    "dev-general":     "Implementation discussion — Rust, cryptography, protocol, CIPs. Read the Constitution before proposing changes.",
    "internal-specs":  "CIPs (CoinCync Improvement Proposals). Drafts, reviews, ratification. RFC-style discussion.",
    "bug-reports":     "Public bug reports. Anything weird, slow, or wrong. Consensus/privacy bugs -> security@coincync.network instead.",
    "known-issues":    "Currently-known limitations + their fix status. Read this before filing a duplicate in #bug-reports.",

    # ── Help ──────────────────────────────────────────────────────
    "faq":             "Pinned answers to repeated questions. Read pins before asking.",

    # ── Mod-only (topic only — not posting) ──────────────────────
    "mod-chat":        "Moderator-only coordination. Anti-spam, anti-scam, channel ownership.",
    "mod-log":         "Auto-log of mod actions: bans, kicks, deletions. Audit trail; don't post manually.",
}

# ─────────────────────────────────────────────────────────────────────────
# Pinned messages (per channel). Posted via embed because some are >2000 chars.
# Discord embed description limit: 4096 chars.
# ─────────────────────────────────────────────────────────────────────────
PINS = {
    "announcements": {
        "title": "📡  CoinCync Public Testnet — Live Operational Status",
        "description": (
            "**Date:** 2026-05-08\n"
            "**Height:** 5675+\n"
            "**Fleet:** 5 nodes (NJ, AMS, Tokyo, Dallas explorer, Frankfurt API)\n"
            "**Sync state:** all 5 nodes synced, spread ±1 block\n"
            "**Public testnet launch:** 2026-05-11\n\n"
            "**Recent operational events**\n"
            "• 2026-05-09 04:00 UTC — Cloudflare 521 incident on explorer (~10 min); zone SSL/TLS mode mismatch, fixed. Origin Cert installed, full-strict TLS now end-to-end.\n"
            "• 2026-05-04 → 05-07 — 72h pre-launch soak: GO verdict, chain stable across all 5 boxes.\n"
            "• 2026-05-05 — Explorer peer-wedge (13h max-stall on one box) — diagnosed, fixed mid-soak (commit 28b3420), no recurrence.\n\n"
            "**Public endpoints (verified reachable now)**\n"
            "• Explorer: https://explorer.coincync.network\n"
            "• API:      https://api.coincync.network\n"
            "• Faucet:   https://coincync.network/faucet.html\n"
            "• P2P:      seed1/2/3.coincync.network:28080 (TCP-reachable from external)\n\n"
            "**Latest changes**\n"
            "• Explorer block-detail page now shows 'What it's for' cards on all 11 privacy features\n"
            "• 6 bug-hunt findings closed (HandshakeAction trap, attestations leak, Bob-Negotiated arc, persist-failure rollback, GetFilterCheckpoints DoS, parent-dir fsync)\n"
            "• Cloudflare Origin Certs installed on explorer.coincync.network — Full (strict) TLS\n\n"
            "**Mainnet target:** 2026-10-01"
        ),
    },
    "node-setup": {
        "title": "🛰️  How to Run a CoinCync Testnet Node",
        "description": (
            "**1. Build the node from source**\n"
            "```bash\n"
            "git clone https://git.coincync.network/coincync/cync-protocol\n"
            "cd cync-protocol\n"
            "cargo build --release --features \"randomx testnet\"\n"
            "```\n\n"
            "**2. Run it**\n"
            "```bash\n"
            "./target/release/coincync-node --network testnet\n"
            "```\n"
            "DNS seeds (auto-discovered):\n"
            "  • seed1.coincync.network (66.135.23.193)\n"
            "  • seed2.coincync.network (140.82.57.168)\n"
            "  • seed3.coincync.network (207.148.111.76)\n\n"
            "**3. Watch sync progress**\n"
            "```bash\n"
            "curl -s -X POST -H 'Content-Type: application/json' \\\n"
            "  -d '{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"get_info\"}' \\\n"
            "  http://127.0.0.1:28081 | jq\n"
            "```\n"
            "Fresh node should reach height 5675+ within ~10–30 min.\n\n"
            "**Troubleshooting**\n"
            "• Stuck at height 0 → port 28080 outbound firewalled?\n"
            "• 0 peers → `dig seed1.coincync.network` to confirm DNS\n"
            "• Other → post here with last 50 lines of logs + `get_info` output"
        ),
    },
    "mining-help": {
        "title": "⛏️  Mining Setup Help",
        "description": (
            "RandomX CPU mining. No GPU/ASIC advantage by design.\n\n"
            "**Requirements**\n"
            "• 64-bit x86 or ARM CPU\n"
            "• ~2.5 GB RAM headroom (RandomX dataset)\n"
            "• Linux, macOS, or Windows\n"
            "• A running coincync-node — see #node-setup\n\n"
            "**Quick start (CLI)**\n"
            "```bash\n"
            "./target/release/coincync-miner \\\n"
            "  --address tCYNC<your_addr> \\\n"
            "  --threads <num_cpu_cores> \\\n"
            "  --node 127.0.0.1:28081\n"
            "```\n\n"
            "**GUI miner** — bundled in the desktop installer at coincync.network. One-click start.\n\n"
            "**Pool vs solo** — testnet hashrate ~250 H/s; SOLO is realistic. No public pools yet.\n\n"
            "**Rewards**\n"
            "• Block reward: ~50 CYNC at genesis, asymptotic decay\n"
            "• Tail emission: 0.6 CYNC/block perpetually\n"
            "• Fee share: 70% (30% permanently burned)\n\n"
            "**Hit a block?** Post the height + your hash. We'll celebrate."
        ),
    },
    "testnet": {
        "title": "🛰️  Testnet Status",
        "description": (
            "**Network state — 2026-05-08**\n"
            "• Block height: 5675+\n"
            "• Block time: 120s target\n"
            "• Network hashrate: ~250 H/s (low — your laptop CPU meaningfully contributes)\n"
            "• 5 fleet nodes synced (NJ, AMS, Tokyo, Dallas, Frankfurt); tip-age <2 min\n"
            "• Build: `28b342099695`\n\n"
            "**Public endpoints (verified reachable now)**\n"
            "• Explorer: https://explorer.coincync.network\n"
            "• API:      https://api.coincync.network\n"
            "• Faucet:   https://coincync.network/faucet.html\n"
            "• P2P:      seed1/2/3.coincync.network:28080\n\n"
            "**Want to run a node?** See #node-setup pinned message.\n"
            "**Want to mine?** See #mining-help pinned message.\n\n"
            "**Public testnet launch:** 2026-05-11"
        ),
    },
    "mining-general": {
        "title": "⛏️  Mining on CoinCync Testnet (CPU-only, RandomX)",
        "description": (
            "CoinCync uses RandomX, the same proof-of-work algorithm as Monero. RandomX is deliberately memory-hard; CPUs are first-class miners and GPUs / ASICs have no meaningful advantage.\n\n"
            "**Requirements**\n"
            "• 64-bit x86 or ARM CPU\n"
            "• ~2.5 GB RAM headroom (for the RandomX dataset)\n"
            "• Linux, macOS, or Windows\n"
            "• A running coincync-node (see #testnet pinned message)\n\n"
            "**Quick start (CLI)**\n"
            "```bash\n"
            "./target/release/coincync-miner \\\n"
            "  --address tCYNC<your_addr> \\\n"
            "  --threads <num_cpu_cores> \\\n"
            "  --node 127.0.0.1:28081\n"
            "```\n\n"
            "**GUI miner (Windows / macOS)**\n"
            "Download from coincync.network — the desktop installer includes a GUI mining tab with one-click start.\n\n"
            "**Pool vs solo**\n"
            "Testnet hashrate is low (~250 H/s) so SOLO is realistic — you may hit a block in hours of single-machine CPU time. No public pools yet.\n\n"
            "**Rewards**\n"
            "• Block reward: ~50 CYNC at genesis, asymptotic decay\n"
            "• Tail emission: 0.6 CYNC/block perpetually\n"
            "• Fee share: 70% (the other 30% is permanently burned)\n\n"
            "**What works / what doesn't**\n"
            "✅ Solo CPU mining via the bundled coincync-miner binary\n"
            "✅ Submit-block via JSON-RPC for custom miners\n"
            "❌ ASIC mining (impossible by design)\n"
            "❌ GPU mining (massively underperforms CPU on RandomX)\n"
            "❌ Stratum public TLS (testnet uses loopback-only stratum currently)\n\n"
            "**Report**\n"
            "If you hit a block, post the height + your hash. We'll celebrate."
        ),
    },
    "wallet-help": {
        "title": "💳  Wallet Quickstart",
        "description": (
            "**Desktop (Windows / macOS / Linux)**\n"
            "1. Download from coincync.network\n"
            "2. Run the installer\n"
            "3. Choose 'Create New Wallet' → write down your 25-word seed phrase ON PAPER, NOT IN A FILE. Lose this and you lose your funds.\n"
            "4. Get tCYNC: faucet at coincync.network/faucet.html\n"
            "5. Send / receive normally — every tx is private by default\n\n"
            "**CLI (advanced)**\n"
            "```bash\n"
            "./target/release/coincync-wallet create -p <password>\n"
            "./target/release/coincync-wallet --help\n"
            "```\n\n"
            "**Address types**\n"
            "• tCYNC...   — testnet address (95-character base58)\n"
            "• CYNC...    — mainnet address (placeholder; mainnet not live yet)\n"
            "• stCYNC...  — testnet sub-address (one-time, derived from your main)\n\n"
            "**Privacy defaults**\n"
            "• Every output goes to a fresh stealth address derived from receiver's view+spend keys\n"
            "• Amounts hidden via Pedersen commitments + Bulletproofs+ range proofs\n"
            "• Sender hidden in a CLSAG-16 ring of decoy outputs\n"
            "• Origin IP hidden via Dandelion++ propagation\n"
            "None of this is opt-in. There is no transparent mode.\n\n"
            "**Lost seed phrase = lost funds**\n"
            "The wallet does not phone home. There is no 'forgot password' flow. Write your 25 words on paper and store them somewhere you'll find them in 5 years. Two paper copies in different physical locations is the standard advice.\n\n"
            "**Common errors**\n"
            "• 'insufficient funds' with positive balance → outputs not yet unlocked; wait 10 confirmations (~20 min)\n"
            "• 'no view key' → restoring from seed; let the wallet finish scanning\n"
            "• Anything else → post here with the wallet log file (NOT your seed)"
        ),
    },
    "faq": {
        "title": "❓  Frequently Asked, Answered Once",
        "description": (
            "**Q: Is CoinCync a Monero fork?**\n"
            "A: No. CoinCync is an independent Rust implementation that uses the same privacy primitives as Monero (CLSAG, Bulletproofs+, stealth addresses, RandomX, Dandelion++) because they're battle-tested. Code is independently written, MIT-licensed, hash-locked, constitutionally bound. Not a fork of Monero source.\n\n"
            "**Q: When mainnet?**\n"
            "A: 2026-10-01 target. Hard launch-blockers: working CYNC↔BTC atomic swaps (CIP-001), third-party audit, multi-maintainer signed-release infrastructure (M-of-N), real testnet operational track record.\n\n"
            "**Q: Is there a presale / IDO / token sale?**\n"
            "A: No. There never will be. There is no premine. Article II forbids it. Every CYNC will be mined by someone who contributed proof-of-work.\n\n"
            "**Q: Is there a developer fund?**\n"
            "A: No. 0% dev tax, no foundation, no governance token. Article III.\n\n"
            "**Q: Can I trade testnet CYNC?**\n"
            "A: Technically yes, ethically no, financially never. Testnet coins have zero monetary value and are reset-able. Anyone trying to sell them is wasting your time.\n\n"
            "**Q: Does CoinCync support smart contracts?**\n"
            "A: No. Article IX forbids them — Turing-complete on-chain execution is incompatible with the privacy stack. CoinCync is a payments coin.\n\n"
            "**Q: Why solo dev?**\n"
            "A: One person can codify a Constitution, ship MIT-licensed code, and run a 5-node testnet fleet. The audit + multi-sig release infrastructure (Article XV) ramps the maintainer count before mainnet — by design.\n\n"
            "**Q: Why a Constitution?**\n"
            "A: Privacy coins die from regulatory capture (changing the rules to comply) or insider corruption (changing the rules to steal). Compile-time-enforced articles + hash-locked critical files + tripwire constants make both technically impossible without a public, attributable, build-breaking commit.\n\n"
            "**Q: Where do I file bugs?**\n"
            "A: #bugs for non-security issues. security@coincync.network for anything touching consensus, privacy, or wallet integrity. PGP welcomed.\n\n"
            "**Q: Block explorer?**\n"
            "A: explorer.coincync.network — search by height, hash, or address.\n\n"
            "**Q: How do I verify my download?**\n"
            "A: SHA256SUMS.txt is shipped with each release. Run `sha256sum -c SHA256SUMS.txt`."
        ),
    },
    "network-health": {
        "title": "🟢  CoinCync Testnet — Status Board",
        "description": (
            "Updated by automated webhooks + manual posts. Don't @ here unless something is on fire.\n\n"
            "**Current (2026-05-08)**\n"
            "• Network: 🟢 healthy\n"
            "• Height: 5675+\n"
            "• Fleet sync: 5/5 nodes synced\n"
            "• Tip age: < 2 min\n"
            "• Public endpoints: explorer, api, faucet, P2P all reachable\n"
            "• Build: 28b342099695\n\n"
            "**Ops runbooks**\n"
            "• Cloudflare account loss → see DNS_FAILOVER.md (deSEC backup, 15-min recovery)\n"
            "• Origin server outage → multi-region fallback in INCIDENT_RUNBOOKS.md\n"
            "• TLS issue → SSL/TLS mode must be Full (strict); Origin Certs at /etc/nginx/ssl/\n\n"
            "**Incident history (last 7 days)**\n"
            "• 2026-05-09 04:00 UTC — explorer Cloudflare 521 — RESOLVED (10 min)\n"
            "• 2026-05-05 — explorer peer-wedge — RESOLVED (commit 28b3420)\n"
            "• Prior to 05-04 — see soak summary in #announcements pin\n\n"
            "**Emergency contact**\n"
            "• Solo dev: response time best-effort, typically <12 h\n"
            "• Consensus/privacy emergencies: security@coincync.network\n"
            "• Chain-split / suspected attack: post here AND email security@"
        ),
    },
}

CYNC_GOLD = 0xD4A059  # accent color used in the explorer

# ─────────────────────────────────────────────────────────────────────────
# Discord API helpers
# ─────────────────────────────────────────────────────────────────────────
API = "https://discord.com/api/v10"


def call(method, path, token, body=None):
    url = API + path
    data = json.dumps(body).encode() if body is not None else None
    headers = {
        "Authorization": f"Bot {token}",
        "Content-Type": "application/json",
        "User-Agent": "CoinCync-Refresh/1.0 (+https://coincync.network)",
    }
    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=15) as r:
            txt = r.read().decode()
            return json.loads(txt) if txt else None
    except urllib.error.HTTPError as e:
        body_resp = e.read().decode() if e.fp else ""
        raise SystemExit(f"  HTTP {e.code} on {method} {path}: {body_resp}") from e
    except urllib.error.URLError as e:
        raise SystemExit(f"  network error on {method} {path}: {e}") from e


def main():
    token = os.environ.get("DISCORD_BOT_TOKEN")
    if not token:
        print("ERROR: set DISCORD_BOT_TOKEN env var first.")
        print('  PowerShell: $env:DISCORD_BOT_TOKEN = "<paste-token>"')
        print("  bash:       export DISCORD_BOT_TOKEN=<paste-token>")
        sys.exit(1)

    dry_run = "--dry-run" in sys.argv

    # Discover the bot's own identity
    me = call("GET", "/users/@me", token)
    print(f"Bot:    {me['username']}#{me.get('discriminator','')} (id={me['id']})")

    # Discover guilds
    guilds = call("GET", "/users/@me/guilds", token)
    if not guilds:
        print("ERROR: bot is in zero guilds. Invite it first via OAuth2 URL Generator.")
        sys.exit(1)
    print(f"Guilds ({len(guilds)}):")
    for g in guilds:
        print(f"  • {g['name']} (id={g['id']})")
    if len(guilds) == 1:
        guild = guilds[0]
    else:
        print()
        name = input("Multiple guilds — paste the EXACT name of the one to update: ").strip()
        matches = [g for g in guilds if g["name"] == name]
        if not matches:
            print(f"ERROR: no match for {name!r}. Aborting.")
            sys.exit(1)
        guild = matches[0]
    guild_id = guild["id"]
    print(f"\nUsing guild: {guild['name']} (id={guild_id})")
    if dry_run:
        print("(--dry-run: no API writes will happen)")

    # Get text channels
    channels = call("GET", f"/guilds/{guild_id}/channels", token)
    text_channels = {c["name"].lower(): c for c in channels if c["type"] == 0}
    print(f"\nText channels found: {sorted(text_channels.keys())}")

    # ─── 1. Server description ──────────────────────────────────────────
    print("\n[1/3] Server description")
    print(f"      target: {SERVER_DESCRIPTION!r}")
    if not dry_run:
        try:
            call("PATCH", f"/guilds/{guild_id}", token, {"description": SERVER_DESCRIPTION})
            print("      ✓ updated")
        except SystemExit as e:
            print(f"      ⊘ failed: {e}")
            print("        (needs Manage Server perm + community-server features enabled)")

    # ─── 2. Channel topics ──────────────────────────────────────────────
    print("\n[2/3] Channel topics")
    for name, topic in TOPICS.items():
        ch = text_channels.get(name.lower())
        if not ch:
            continue
        print(f"      {name:14s} -> {topic[:60]}{'…' if len(topic)>60 else ''}")
        if not dry_run:
            call("PATCH", f"/channels/{ch['id']}", token, {"topic": topic})

    # ─── 3. Pinned messages ─────────────────────────────────────────────
    print("\n[3/3] Pinned messages")
    for name, content in PINS.items():
        ch = text_channels.get(name.lower())
        if not ch:
            print(f"      ⊘ #{name}: channel not found, skipping")
            continue
        print(f"      #{name}: posting + pinning…")
        if dry_run:
            print(f"        (dry-run: would post embed '{content['title']}', {len(content['description'])} chars)")
            continue

        msg = call(
            "POST",
            f"/channels/{ch['id']}/messages",
            token,
            {
                "embeds": [
                    {
                        "title": content["title"],
                        "description": content["description"],
                        "color": CYNC_GOLD,
                    }
                ]
            },
        )
        msg_id = msg["id"]
        print(f"        ✓ posted msg id={msg_id}")
        try:
            call("PUT", f"/channels/{ch['id']}/pins/{msg_id}", token)
            print("        ✓ pinned")
        except SystemExit as e:
            print(f"        ⊘ pin failed (need Manage Messages perm): {e}")

    print("\n✅ Done. Verify the result in Discord.")
    print("If anything looks wrong, edit/delete in Discord directly — re-running this script will post duplicates.")


if __name__ == "__main__":
    main()
