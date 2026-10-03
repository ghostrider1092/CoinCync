#!/usr/bin/env bash
#
# push-both.sh — push ONE branch to the project's GitHub home(s).
#
#   • origin  (ghostrider1092/CoinCync)     — the PRIMARY personal repo
#   • mirror  (Coincync/Coincync-Testnet-)  — the org mirror (optional)
#
# Codeberg was REMOVED 2026-08-20: Codeberg's usage policy prohibits
# cryptocurrency/blockchain projects, so it was never a valid home and pushing
# there risked a ToS takedown. NLnet/NGI0 is host-agnostic and does not require
# it. If you want a non-GitHub fallback that ACTUALLY tolerates the project, use
# one that permits it (GitLab.com, sourcehut, self-hosted Forgejo/Gitea, or
# Radicle) — NOT Codeberg — and add it to the mirror list below.
#
# Usage:  scripts/push-both.sh <branch>
#
# SAFETY: this pushes only the single named branch (explicit refspec). It never
# uses --all / --mirror, so the held-supply branch and any other local-only
# branch never leave this machine. Do not "fix" that by adding --all.
set -euo pipefail

branch="${1:?usage: scripts/push-both.sh <branch>}"

# The PRIMARY: the personal repo. `origin` always exists in a clone/worktree, so
# a failure here is a real error and must stop the script (set -e).
echo "→ GitHub origin (ghostrider1092/CoinCync) — PRIMARY …"
git push origin "$branch:refs/heads/$branch"

# Additional mirrors: push each configured remote, but do NOT fail the whole run
# if a mirror is missing or transiently rejects — the primary already has the
# branch. (Previously this script pushed ONLY `mirror` and skipped origin, so a
# branch reached the org but not the personal primary — the bug this fixes.)
for m in mirror; do
    if git remote get-url "$m" >/dev/null 2>&1; then
        echo "→ GitHub mirror ($m) …"
        if ! git push "$m" "$branch:refs/heads/$branch"; then
            echo "  ! mirror '$m' push failed (primary already has '$branch'); continuing." >&2
        fi
    else
        echo "  (mirror '$m' not configured — skipping)"
    fi
done

echo "✓ '$branch' pushed to origin (primary)$(git remote get-url mirror >/dev/null 2>&1 && echo ' + org mirror')."
