#!/usr/bin/env bash
# safe-deploy.sh — GUARDED fleet deploy.
#
# Prevents the two failures that took the testnet down on 2026-10-10:
#   (1) Two operators / Claude sessions deploying at once and stomping each
#       other (one stopped every node + overwrote the binary while the other
#       was mid-rollout). Guarded by a per-host advisory LOCK.
#   (2) A broken / wrong-chain binary getting installed and crash-looping
#       (a segfaulting build replaced the good one; every node SIGSEGV'd).
#       Guarded by a binary PREFLIGHT: the staged binary must run `--version`
#       cleanly AND print a testnet consensus fingerprint equal to
#       `expected_consensus_fingerprint_testnet` in scripts/fleet-config.json.
#
# Usage (run locally; drives the fleet over SSH):
#   bash deploy/fleet/safe-deploy.sh <local-coincync-node-binary> <host> [host...]
#
# Env overrides:
#   KEY        SSH key                (default ~/.ssh/coincync_fleet)
#   OPERATOR   lock holder id         (default "<user>@<host>-<pid>")
#   LOCK_TTL   lock freshness seconds (default 1800)
#   FORCE_LOCK 1 = steal a stale/foreign lock (use only when you KNOW the other
#              operator has stopped) (default 0)
set -uo pipefail

KEY="${KEY:-$HOME/.ssh/coincync_fleet}"
OPERATOR="${OPERATOR:-$(whoami)@$(hostname 2>/dev/null || echo host)-$$}"
LOCK_TTL="${LOCK_TTL:-1800}"
FORCE_LOCK="${FORCE_LOCK:-0}"
LOCKFILE="/run/coincync-deploy.lock"

# STAGED_PATH: when the binary is already present on each host at this path
# (e.g. distributed box-to-box over the fast intra-DC network), skip the slow
# per-host copy and preflight+install that staged file instead. Pass "-" as the
# binary arg in that mode.
STAGED_PATH="${STAGED_PATH:-}"
BIN="${1:-}"; shift || true
HOSTS="$*"
if [ -z "$HOSTS" ]; then
  echo "usage: $0 <local-coincync-node-binary> <host> [host...]" >&2
  echo "   or: STAGED_PATH=/root/coincync-node $0 - <host> [host...]   (binary already on each host)" >&2
  exit 64
fi
if [ -z "$STAGED_PATH" ]; then
  { [ -n "$BIN" ] && [ -f "$BIN" ]; } || { echo "binary not found: '$BIN' (or set STAGED_PATH)" >&2; exit 64; }
fi

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CFG="$HERE/../../scripts/fleet-config.json"
EXPECT="$(grep -o '"expected_consensus_fingerprint_testnet"[^0-9a-f]*[0-9a-f]\{64\}' "$CFG" 2>/dev/null | grep -o '[0-9a-f]\{64\}' | head -1)"
if [ -z "$EXPECT" ]; then
  echo "FATAL: no expected_consensus_fingerprint_testnet in $CFG — refusing to deploy blind." >&2; exit 65
fi
echo "== safe-deploy: expected testnet fingerprint = $EXPECT =="
echo "== operator = $OPERATOR  lock_ttl = ${LOCK_TTL}s =="

S(){ ssh -i "$KEY" -o ConnectTimeout=12 -o BatchMode=yes -o ServerAliveInterval=30 root@"$1" "${@:2}"; }

LOCKED_HOSTS=""
release_all(){ for h in $LOCKED_HOSTS; do S "$h" "rm -f $LOCKFILE /root/.coincync-node.staged" 2>/dev/null || true; done; }
trap release_all EXIT

for H in $HOSTS; do
  echo "######## $H ########"
  now=$(date +%s)

  # ---- 1. advisory lock ----------------------------------------------------
  held="$(S "$H" "cat $LOCKFILE 2>/dev/null" || true)"
  if [ -n "$held" ]; then
    holder="${held%%|*}"; ts="${held##*|}"
    age=$(( now - ${ts:-0} ))
    if [ "$holder" != "$OPERATOR" ] && [ "$age" -lt "$LOCK_TTL" ] && [ "$FORCE_LOCK" != "1" ]; then
      echo "REFUSING: $H is locked by '$holder' (${age}s ago, ttl ${LOCK_TTL}s)." >&2
      echo "  Another deploy is in progress. Stop it first, or re-run with FORCE_LOCK=1 if you are SURE it is dead." >&2
      exit 75
    fi
    [ "$FORCE_LOCK" = "1" ] && echo "  (stealing lock held by '$holder')"
  fi
  S "$H" "echo '$OPERATOR|$now' > $LOCKFILE"
  LOCKED_HOSTS="$LOCKED_HOSTS $H"

  # ---- 2. stage binary + PREFLIGHT ----------------------------------------
  if [ -n "$STAGED_PATH" ]; then
    STAGEDBIN="$STAGED_PATH"                 # already on the host (box-to-box)
  else
    STAGEDBIN="/root/.coincync-node.staged"  # copy from local
    S "$H" "cat > $STAGEDBIN && chmod +x $STAGEDBIN" < "$BIN"
  fi
  ver="$(S "$H" "$STAGEDBIN --version 2>&1" || echo __RUN_FAILED__)"
  if printf '%s' "$ver" | grep -q __RUN_FAILED__; then
    echo "REFUSING: staged binary does NOT run on $H (segfault / incompatible). Not installing." >&2; exit 76
  fi
  fp="$(printf '%s' "$ver" | grep -i 'consensus-fingerprint testnet' | grep -o '[0-9a-f]\{64\}' | head -1)"
  if [ "$fp" != "$EXPECT" ]; then
    echo "REFUSING: fingerprint mismatch on $H — got '${fp:-none}', expected '$EXPECT'. Wrong chain/build. Not installing." >&2; exit 77
  fi
  echo "  preflight OK — runs cleanly, testnet fingerprint $fp"

  # ---- 3. install + restart + verify it stays up --------------------------
  S "$H" "install -m0755 $STAGEDBIN /usr/local/bin/coincync-node; systemctl reset-failed coincync-node 2>/dev/null || true; systemctl restart coincync-node"
  sleep 8
  st="$(S "$H" 'systemctl is-active coincync-node' || true)"
  nr="$(S "$H" 'systemctl show coincync-node -p NRestarts --value' || echo '?')"
  sha="$(S "$H" "sha256sum /usr/local/bin/coincync-node | cut -d' ' -f1")"
  S "$H" "mkdir -p /var/log/coincync; echo \"\$(date -uIseconds) operator=$OPERATOR sha=$sha fp=$fp state=$st nrestarts=$nr\" >> /var/log/coincync/deploy.journal"
  if [ "$st" = "active" ]; then
    echo "  installed OK — sha=${sha:0:12} state=$st restarts=$nr"
  else
    echo "  WARN: $H state=$st restarts=$nr after install — check 'journalctl -u coincync-node'." >&2
  fi

  # ---- 4. release this host's lock ----------------------------------------
  S "$H" "rm -f $LOCKFILE /root/.coincync-node.staged"
  LOCKED_HOSTS="$(echo "$LOCKED_HOSTS" | sed "s/ $H//")"
done

echo "SAFE_DEPLOY_DONE (fingerprint $EXPECT verified on every host)"
