#!/usr/bin/env bash
#
# push-both.sh — push ONE branch to both homes:
#   • Codeberg  (canonical, crypto-tolerant)      remote: codeberg  (SSH)
#   • GitHub    (ghostrider1092/CoinCync, mirror)  remote: mirror    (HTTPS/gh)
#
# Usage:  scripts/push-both.sh <branch>
#
# SAFETY: this pushes only the single named branch (explicit refspec). It never
# uses --all / --mirror, so the held-supply branch and any other local-only
# branch never leave this machine. Do not "fix" that by adding --all.
#
# The Codeberg SSH key defaults to ~/.ssh/id_ed25519; override with
#   COINCYNC_CODEBERG_KEY=/path/to/key scripts/push-both.sh <branch>
set -euo pipefail

branch="${1:?usage: scripts/push-both.sh <branch>}"
key="${COINCYNC_CODEBERG_KEY:-$HOME/.ssh/id_ed25519}"
gsc="ssh -i $key -o IdentitiesOnly=yes -o StrictHostKeyChecking=accept-new"

echo "→ Codeberg (canonical) …"
GIT_SSH_COMMAND="$gsc" git push codeberg "$branch:refs/heads/$branch"

echo "→ GitHub mirror …"
git push mirror "$branch:refs/heads/$branch"

echo "✓ '$branch' pushed to Codeberg + mirror."
