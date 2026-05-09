#!/usr/bin/env python3
"""
discord-cleanup.py — unpin (and optionally delete) stale pinned messages
in the 8 channels we refreshed via discord-refresh.py.

The refresh script could only ADD pins; it can't see what's stale. This
script keeps ONLY the most recent pin authored by the refresh bot in
each target channel, and unpins everything else.

Usage (PowerShell):
    $env:DISCORD_BOT_TOKEN = "<paste-bot-token>"

    # See what it WOULD do (default — no writes):
    python scripts\discord-cleanup.py

    # Actually unpin the stale pins:
    python scripts\discord-cleanup.py --confirm

    # Also DELETE the messages (not just unpin them):
    python scripts\discord-cleanup.py --confirm --delete

Safety properties:
  • Defaults to dry-run; nothing changes without --confirm.
  • Only touches the 8 channels listed in TARGET_CHANNELS.
  • Keeps the most recent pin authored by THIS bot (highest message id).
  • Pins from any OTHER author or earlier bot runs get unpinned.
  • Sleeps between API calls — Discord rate-limits pin/unpin tightly.
  • --delete is destructive (removes the message, not just the pin).
    Without it, only the pin status is removed; the message stays.
"""

import json
import os
import sys
import time
import urllib.error
import urllib.request

API = "https://discord.com/api/v10"

# Channels we posted refreshed pins to. Anything else is left alone.
TARGET_CHANNELS = {
    "announcements",
    "node-setup",
    "mining-help",
    "testnet",
    "mining-general",
    "wallet-help",
    "faq",
    "network-health",
}


def call(method, path, token, body=None, allow_404=False):
    url = API + path
    data = json.dumps(body).encode() if body is not None else None
    headers = {
        "Authorization": f"Bot {token}",
        "Content-Type": "application/json",
        "User-Agent": "CoinCync-Cleanup/1.0 (+https://coincync.network)",
    }
    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=15) as r:
            txt = r.read().decode()
            return json.loads(txt) if txt else None
    except urllib.error.HTTPError as e:
        if allow_404 and e.code == 404:
            return None
        # Discord 429 = rate-limited; surface for visibility.
        body_resp = e.read().decode() if e.fp else ""
        raise SystemExit(f"  HTTP {e.code} on {method} {path}: {body_resp}") from e


def main():
    token = os.environ.get("DISCORD_BOT_TOKEN")
    if not token:
        print("ERROR: set DISCORD_BOT_TOKEN env var first.")
        sys.exit(1)

    confirm = "--confirm" in sys.argv
    delete = "--delete" in sys.argv

    print(f"Mode: {'CONFIRM' if confirm else 'DRY-RUN'}{' + DELETE' if delete else ''}")
    print()

    # Identify bot
    me = call("GET", "/users/@me", token)
    bot_id = me["id"]
    print(f"Bot:    {me['username']} (id={bot_id})")

    # Find guild
    guilds = call("GET", "/users/@me/guilds", token)
    if not guilds:
        print("ERROR: bot is in zero guilds.")
        sys.exit(1)
    guild = guilds[0] if len(guilds) == 1 else None
    if not guild:
        name = input("Multiple guilds — paste exact name to clean: ").strip()
        matches = [g for g in guilds if g["name"] == name]
        if not matches:
            sys.exit("no match")
        guild = matches[0]
    print(f"Guild:  {guild['name']} (id={guild['id']})")
    print()

    # Get text channels
    channels = call("GET", f"/guilds/{guild['id']}/channels", token)
    text_channels = {c["name"].lower(): c for c in channels if c["type"] == 0}

    summary = {"unpinned": 0, "deleted": 0, "kept": 0, "skipped_channels": 0}

    for name in sorted(TARGET_CHANNELS):
        ch = text_channels.get(name)
        if not ch:
            print(f"⊘ #{name}: channel not found, skipping")
            summary["skipped_channels"] += 1
            continue

        ch_id = ch["id"]
        pins = call("GET", f"/channels/{ch_id}/pins", token)
        if not pins:
            print(f"#{name}: no pins, nothing to do")
            continue

        # Decide which one to keep: the most recent pin authored by this
        # bot. If the bot has no pins in this channel, keep nothing
        # (our refresh either failed or never ran for this channel).
        bot_pins = [p for p in pins if p["author"]["id"] == bot_id]
        keep_id = None
        if bot_pins:
            # Highest snowflake id is the most recently created.
            bot_pins.sort(key=lambda p: int(p["id"]), reverse=True)
            keep_id = bot_pins[0]["id"]

        print(f"#{name}: {len(pins)} pin(s) total, {len(bot_pins)} from bot")
        for p in pins:
            mid = p["id"]
            author = p["author"]["username"]
            preview = ""
            if p.get("content"):
                preview = p["content"][:60].replace("\n", " ")
            elif p.get("embeds"):
                preview = p["embeds"][0].get("title", "")[:60]

            if mid == keep_id:
                print(f"  ✓ KEEP   {mid}  by {author}  {preview!r}")
                summary["kept"] += 1
                continue

            print(f"  ✗ UNPIN  {mid}  by {author}  {preview!r}")
            summary["unpinned"] += 1
            if confirm:
                call("DELETE", f"/channels/{ch_id}/pins/{mid}", token, allow_404=True)
                # Discord pin route is rate-limited; sleep between calls.
                time.sleep(0.4)

            if delete:
                print(f"    ✗ DELETE {mid}")
                summary["deleted"] += 1
                if confirm:
                    call(
                        "DELETE",
                        f"/channels/{ch_id}/messages/{mid}",
                        token,
                        allow_404=True,
                    )
                    time.sleep(0.4)

    print()
    print("=" * 60)
    print(f"Summary  ({'CONFIRMED' if confirm else 'DRY-RUN'})")
    print(f"  channels skipped:  {summary['skipped_channels']}")
    print(f"  pins kept:         {summary['kept']}")
    print(f"  pins unpinned:     {summary['unpinned']}")
    if delete:
        print(f"  messages deleted:  {summary['deleted']}")
    print()

    if not confirm:
        print("This was a DRY-RUN. To actually unpin, re-run with --confirm.")
        print("To unpin AND delete the messages, add --delete.")


if __name__ == "__main__":
    main()
