#!/usr/bin/env bash
#
# push-both.sh — push ONE branch to the project's GitHub home(s).
#
#   • PRIMARY  GitHub user  (ghostrider1092/CoinCync)     remote: origin
#   • MIRROR   GitHub org   (Coincync/Coincync-Testnet-)   remote: mirror
#
# 2026-09-26: primary reverted to the personal account. The Coincync org was
# flagged by GitHub and HIDDEN FROM PUBLIC (twice now — abuse/ToS detection
# keeps re-flagging the crypto org), so it is no longer a reliable *public*
# home. The org repo still works (not disabled) and is kept as a secondary
# mirror; the unflagged, public personal repo is primary again. Org `main` is
# ruleset-protected (PR review + signed commits + required CI); the personal
# repo is not. This script pushes feature branches to both.
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

echo "→ GitHub user — PRIMARY (ghostrider1092/CoinCync) …"
git push origin "$branch:refs/heads/$branch"

echo "→ GitHub org — mirror (Coincync/Coincync-Testnet-) …"
git push mirror "$branch:refs/heads/$branch"

# ── Optional third home (a REAL crypto-tolerant forge — NOT Codeberg) ─────────
# Add the remote once, e.g.:
#   git remote add fallback git@gitlab.com:<you>/coincync.git
# then uncomment (keep the explicit single-branch refspec — never --all):
#
# echo "→ fallback forge …"
# git push fallback "$branch:refs/heads/$branch"
# ─────────────────────────────────────────────────────────────────────────────

echo "✓ '$branch' pushed to the GitHub user (primary) + org mirror."
