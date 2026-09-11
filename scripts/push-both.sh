#!/usr/bin/env bash
#
# push-both.sh — push ONE branch to BOTH of the project's homes, kept in sync.
#
#   • GitHub    (ghostrider1092/CoinCync)   remote: origin
#   • Codeberg  (ghostrider1092/Coincync)   remote: codeberg   ← NLnet review target
#
# Codeberg is re-enabled 2026-09-10 as the NLnet/NGI0 review target. NOTE: Codeberg's
# usage policy is unfriendly to cryptocurrency projects, so the mirror there carries a
# standing ToS-takedown risk — it is used because it is the agreed review host, an
# ACCEPTED risk, not an oversight. GitHub (origin) remains the canonical tree.
#
# The two MUST stay in sync. On 2026-09-10 they had silently diverged (Codeberg was
# ~9 days / 65 commits behind, so reviewers would have seen stale code); they were
# reconciled with a union merge. Always push with THIS script so both homes advance
# together and never drift apart again.
#
# Usage:  scripts/push-both.sh <branch>
#
# SAFETY: pushes only the single named branch (explicit refspec). It never uses
# --all / --mirror / --force, so local-only branches never leave this machine and a
# remote is never rewound. Do not "fix" that by adding --all or --force.
set -euo pipefail

branch="${1:?usage: scripts/push-both.sh <branch>}"

for remote in origin codeberg; do
  if ! git remote get-url "$remote" >/dev/null 2>&1; then
    echo "✗ remote '$remote' is not configured. Add it first, e.g.:" >&2
    echo "    git remote add origin   https://github.com/ghostrider1092/CoinCync.git" >&2
    echo "    git remote add codeberg https://codeberg.org/ghostrider1092/Coincync.git" >&2
    exit 1
  fi
done

echo "→ GitHub (origin) …"
git push origin "$branch:refs/heads/$branch"
echo "✓ '$branch' → GitHub."

echo "→ Codeberg (codeberg) …"
git push codeberg "$branch:refs/heads/$branch"
echo "✓ '$branch' → Codeberg."

echo "✓ '$branch' pushed to BOTH homes (GitHub + Codeberg)."
