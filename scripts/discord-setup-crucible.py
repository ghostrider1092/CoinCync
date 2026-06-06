#!/usr/bin/env python3
"""
discord-setup-crucible.py — create The Crucible roles, category, and
channels in the CoinCync Discord server.

Idempotent. Safe to re-run: detects existing roles/channels by name and
skips creation. Permission overwrites are re-applied each run so a
manual permission change can be reset by re-running.

Usage (PowerShell):
    $env:DISCORD_BOT_TOKEN = "<paste-token>"

    # See what it WOULD do (default — no writes):
    python scripts\discord-setup-crucible.py

    # Actually create / update:
    python scripts\discord-setup-crucible.py --confirm

Bot permissions needed (grant via OAuth2 URL Generator or assign an
admin role to the bot):
  Manage Roles, Manage Channels, View Channel, Send Messages.
("Administrator" covers all of these.)

What it creates:
  Roles:
    • "Crucible Veteran"   — gold-orange, hoisted, mentionable
    • "Crucible Recruit"   — warm gray, not hoisted, not mentionable
  Category:
    • "The Crucible" — visible to everyone (everyone can see the
      category header); inner channel visibility is controlled per
      channel via the overwrites below.
  Channels (text):
    • #crucible    — public; everyone can view + send. Discussion +
      onboarding entry point for Recruits and Veterans.
    • #veterans    — private; only Crucible Veteran role + admins can
      view. Used for early-binary access coordination and
      maintainer-direct findings.
  Channel topics: short descriptions matching CRUCIBLE.md.

What it does NOT do:
  • Assign roles to humans. Maintainers grant Crucible Recruit on
    request and Crucible Veteran on promotion. The bot only creates
    the role; humans hand it out.
  • Pin messages. Pin the CRUCIBLE.md announcement manually after
    drafting it in #crucible.
  • Announce the launch. Operator decides the announcement timing
    and tone separately.

Source of truth: CRUCIBLE.md at repo root.
"""

import json
import os
import sys
import urllib.error
import urllib.request


# ─────────────────────────────────────────────────────────────────────────
# What to create
# ─────────────────────────────────────────────────────────────────────────

# Discord role color is stored as a 24-bit integer (R<<16 | G<<8 | B).
# Veteran color matches the CoinCync brand accent (#d4a059) used in the
# explorer. Recruit color is a warm gray (#8a7e6a) — recognizable as a
# Crucible member without competing visually with Veteran.
ROLES = [
    {
        "name": "Crucible Veteran",
        "color": 0xD4A059,
        "hoist": True,          # display separately in member list
        "mentionable": True,    # @Crucible Veteran is allowed
        "permissions": "0",     # no extra perms beyond @everyone; recognition only
    },
    {
        "name": "Crucible Recruit",
        "color": 0x8A7E6A,
        "hoist": False,
        "mentionable": False,
        "permissions": "0",
    },
]

CATEGORY_NAME = "The Crucible"

# Channel topic strings (Discord limit: 1024 chars; keep them short).
CRUCIBLE_TOPIC = (
    "CoinCync testing-contributors program. Open to anyone running a "
    "testnet node, wallet, or miner. Post intros, share log captures, "
    "file what you find. See CRUCIBLE.md in the repo for the full "
    "program description. Tagline: hammer it until it sings."
)

VETERANS_TOPIC = (
    "Private channel for Crucible Veterans and maintainers. Early-"
    "binary access coordination, direct findings, judgment-call "
    "discussions. Promotion to Veteran is invite-based; see CRUCIBLE.md."
)


# ─────────────────────────────────────────────────────────────────────────
# Discord API helpers (mirrors scripts/discord-refresh.py)
# ─────────────────────────────────────────────────────────────────────────
API = "https://discord.com/api/v10"


def call(method, path, token, body=None):
    url = API + path
    data = json.dumps(body).encode() if body is not None else None
    headers = {
        "Authorization": f"Bot {token}",
        "Content-Type": "application/json",
        "User-Agent": "CoinCync-Crucible-Setup/1.0 (+https://coincync.network)",
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


# Permission bit flags (Discord docs: discord-api-types/v10/permissions).
PERM_VIEW_CHANNEL = 1 << 10   # 1024
PERM_SEND_MESSAGES = 1 << 11  # 2048


def perm_overwrite(target_id, allow_bits=0, deny_bits=0, target_type=0):
    """Build a permission overwrite object. target_type: 0=role, 1=member."""
    return {
        "id": str(target_id),
        "type": target_type,
        "allow": str(allow_bits),
        "deny": str(deny_bits),
    }


# ─────────────────────────────────────────────────────────────────────────
def main():
    token = os.environ.get("DISCORD_BOT_TOKEN")
    if not token:
        print("ERROR: set DISCORD_BOT_TOKEN env var first.")
        print('  PowerShell: $env:DISCORD_BOT_TOKEN = "<paste-token>"')
        print("  bash:       export DISCORD_BOT_TOKEN=<paste-token>")
        sys.exit(1)

    dry_run = "--confirm" not in sys.argv

    # ─── Bot identity + guild discovery ────────────────────────────────
    me = call("GET", "/users/@me", token)
    print(f"Bot:    {me['username']}#{me.get('discriminator','')} (id={me['id']})")

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
        print("(dry-run mode — no API writes. Pass --confirm to apply.)")

    # @everyone role id is the guild id (Discord convention).
    everyone_role_id = guild_id

    # ─── 1. Roles ───────────────────────────────────────────────────────
    print("\n[1/3] Roles")
    existing_roles = call("GET", f"/guilds/{guild_id}/roles", token)
    existing_by_name = {r["name"]: r for r in existing_roles}
    role_ids = {}  # name -> role id

    for spec in ROLES:
        name = spec["name"]
        if name in existing_by_name:
            existing = existing_by_name[name]
            print(f"  ✓ already exists: {name} (id={existing['id']})")
            role_ids[name] = existing["id"]
            continue
        print(f"  + create: {name} (color=#{spec['color']:06x}, "
              f"hoist={spec['hoist']}, mentionable={spec['mentionable']})")
        if not dry_run:
            created = call("POST", f"/guilds/{guild_id}/roles", token, {
                "name": name,
                "color": spec["color"],
                "hoist": spec["hoist"],
                "mentionable": spec["mentionable"],
                "permissions": spec["permissions"],
            })
            role_ids[name] = created["id"]
            print(f"    ✓ created (id={created['id']})")

    # If dry-run, we don't have real ids yet — synthesize placeholders so
    # the rest of the dry-run output is meaningful.
    for spec in ROLES:
        role_ids.setdefault(spec["name"], "<would-be-created>")

    # ─── 2. Category ────────────────────────────────────────────────────
    print(f"\n[2/3] Category: {CATEGORY_NAME!r}")
    existing_channels = call("GET", f"/guilds/{guild_id}/channels", token) or []
    existing_categories = {c["name"]: c for c in existing_channels if c.get("type") == 4}

    if CATEGORY_NAME in existing_categories:
        category = existing_categories[CATEGORY_NAME]
        category_id = category["id"]
        print(f"  ✓ already exists (id={category_id})")
    else:
        print(f"  + create category {CATEGORY_NAME!r}")
        if not dry_run:
            category = call("POST", f"/guilds/{guild_id}/channels", token, {
                "name": CATEGORY_NAME,
                "type": 4,  # 4 = GUILD_CATEGORY
            })
            category_id = category["id"]
            print(f"    ✓ created (id={category_id})")
        else:
            category_id = "<would-be-created>"

    # ─── 3. Channels ────────────────────────────────────────────────────
    print("\n[3/3] Channels")
    existing_text = {c["name"]: c for c in existing_channels if c.get("type") == 0}

    veteran_role_id = role_ids.get("Crucible Veteran", "<would-be-created>")

    channel_specs = [
        {
            "name": "crucible",
            "topic": CRUCIBLE_TOPIC,
            "private": False,
        },
        {
            "name": "veterans",
            "topic": VETERANS_TOPIC,
            "private": True,
        },
    ]

    for ch in channel_specs:
        name = ch["name"]
        if ch["private"]:
            # Private: deny VIEW_CHANNEL to @everyone, allow to Veteran role.
            overwrites = [
                perm_overwrite(everyone_role_id, deny_bits=PERM_VIEW_CHANNEL),
                perm_overwrite(veteran_role_id, allow_bits=PERM_VIEW_CHANNEL | PERM_SEND_MESSAGES),
            ]
        else:
            overwrites = []  # inherit category / server defaults

        body = {
            "name": name,
            "type": 0,  # 0 = GUILD_TEXT
            "topic": ch["topic"],
            "parent_id": category_id if category_id != "<would-be-created>" else None,
            "permission_overwrites": overwrites,
        }

        if name in existing_text:
            ch_obj = existing_text[name]
            print(f"  ✓ already exists: #{name} (id={ch_obj['id']}) — re-applying topic + permissions")
            if not dry_run:
                # PATCH cannot change `type`; remove it.
                patch_body = {k: v for k, v in body.items() if k != "type"}
                call("PATCH", f"/channels/{ch_obj['id']}", token, patch_body)
                print("    ✓ updated topic + overwrites")
        else:
            visibility = "private (Veterans + admins only)" if ch["private"] else "public"
            print(f"  + create: #{name} ({visibility})")
            print(f"           topic: {ch['topic'][:60]}...")
            if not dry_run:
                created = call("POST", f"/guilds/{guild_id}/channels", token, body)
                print(f"    ✓ created (id={created['id']})")

    # ─── Summary ────────────────────────────────────────────────────────
    print()
    if dry_run:
        print("Dry-run complete. Re-run with --confirm to apply.")
    else:
        print("Setup complete. Next steps (manual):")
        print("  1. In Discord, drag the role list so Crucible Veteran sits ABOVE Crucible Recruit.")
        print("  2. In #crucible, post a pinned announcement linking to CRUCIBLE.md.")
        print("  3. Verify #veterans is invisible to a non-Veteran test account.")
        print("  4. Grant Crucible Recruit to the first wave of self-enrollees as they post intros.")


if __name__ == "__main__":
    main()
