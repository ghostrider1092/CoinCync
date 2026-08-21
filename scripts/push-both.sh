#!/usr/bin/env bash
#
# push-both.sh — push ONE branch to the project's public home(s).
#
#   • GitHub    (ghostrider1092/CoinCync)  remote: mirror  (HTTPS/gh)
#
# Codeberg was REMOVED 2026-08-20: Codeberg's usage policy prohibits
# cryptocurrency/blockchain projects, so it was never a valid home (the old
# "crypto-tolerant" label here was wrong) and pushing there risked a ToS
# takedown. NLnet/NGI0 does not require Codeberg — it is host-agnostic. If you
# want a non-GitHub fallback that ACTUALLY tolerates the project, use one that
# permits it (GitLab.com, sourcehut, a self-hosted Forgejo/Gitea, or Radicle) —
# NOT Codeberg — and wire it into the optional block below.
#
# Usage:  scripts/push-both.sh <branch>
#
# SAFETY: this pushes only the single named branch (explicit refspec). It never
# uses --all / --mirror, so the held-supply branch and any other local-only
# branch never leave this machine. Do not "fix" that by adding --all.
set -euo pipefail

branch="${1:?usage: scripts/push-both.sh <branch>}"

echo "→ GitHub mirror (ghostrider1092/CoinCync) …"
git push mirror "$branch:refs/heads/$branch"

# ── Optional second home (a REAL crypto-tolerant forge — NOT Codeberg) ────────
# Add the remote once, e.g.:
#   git remote add fallback git@gitlab.com:<you>/coincync.git
# then uncomment (keep the explicit single-branch refspec — never --all):
#
# echo "→ fallback forge …"
# git push fallback "$branch:refs/heads/$branch"
# ─────────────────────────────────────────────────────────────────────────────

echo "✓ '$branch' pushed to the GitHub mirror."
