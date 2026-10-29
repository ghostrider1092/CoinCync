#!/usr/bin/env bash
# ──────────────────────────────────────────────────────────────────────────
# activate-shielded-testnet.sh — deploy the libspark-MANDATORY testnet build to
# ONE fleet node for the coordinated shielded activation. Run on EACH node.
#
# This is a PRESERVE-DB rebuild+restart (a future-height activation does NOT
# invalidate pre-H blocks), so it wraps deploy/ops/roll-fleet.sh — NOT
# redeploy-fleet.sh (no genesis wipe). The ONLY differences from a normal roll:
#   (1) it installs the libspark build prerequisites (roll-fleet does not), and
#   (2) it builds with the shielded VERIFIER compiled in.
#
# WHY THIS SCRIPT EXISTS (do not shortcut it): the activation feature set must
# include every shielded feature. A node built WITHOUT the verifier cannot
# validate a shielded tx at the activation height H — it fail-closes and FORKS.
# And because the consensus fingerprint does NOT encode H, such a node is NOT
# rejected at handshake; it silently follows the chain and forks at H. So every
# node MUST run this build, and you MUST confirm 100% coverage out-of-band
# BEFORE the chain reaches H. See docs/design/cip-shielded-testnet-activation.md.
#
# Mainnet is untouched — activation is testnet-scoped.
#
#   Usage (per host):  sudo bash deploy/ops/activate-shielded-testnet.sh
#   Env: REPO_DIR, SPARK_OPENSSL_DIR (default /usr), plus roll-fleet.sh's env
#        (NODE_SERVICE, DATA_DIR, RPC_PORT, BRANCH, …).
# ──────────────────────────────────────────────────────────────────────────
set -euo pipefail

REPO_DIR="${REPO_DIR:-/opt/coincync}"
# The activation feature set: randomx + testnet PLUS the shielded verifier.
# Omitting ANY of these ships a fork-at-H node (the test-fast-pow-class mistake).
ACTIVATION_FEATURES="randomx testnet sketch-gk-proof libspark-ffi"
export SPARK_OPENSSL_DIR="${SPARK_OPENSSL_DIR:-/usr}"  # system OpenSSL for libspark (ubuntu)

log()   { printf '\e[36m==>\e[0m %s\n' "$*"; }
warn()  { printf '\e[33m[!]\e[0m %s\n' "$*" >&2; }
fatal() { printf '\e[31m[ERR]\e[0m %s\n' "$*" >&2; exit 1; }

[ "$EUID" -eq 0 ] || fatal "run as root/sudo (stops systemd, writes binaries)"
[ -d "$REPO_DIR" ] || fatal "repo not found at ${REPO_DIR} (set REPO_DIR=...)"
[ -f "$REPO_DIR/deploy/ops/roll-fleet.sh" ] || fatal "roll-fleet.sh not found under ${REPO_DIR}/deploy/ops"

# 1. libspark build prerequisites — roll-fleet.sh does NOT install these.
if command -v apt-get >/dev/null 2>&1; then
  log "installing libspark build deps (cmake clang libssl-dev pkg-config)…"
  apt-get update -y
  apt-get install -y cmake clang libssl-dev pkg-config
else
  warn "non-apt host: ensure clang, cmake, OpenSSL dev headers and pkg-config are"
  warn "present and SPARK_OPENSSL_DIR (=$SPARK_OPENSSL_DIR) points at an OpenSSL prefix."
fi

# 2. Preserve-DB rebuild + restart with the activation features. roll-fleet.sh
#    stops the node, pulls, builds with CARGO_FEATURES, installs, restarts, waits
#    for RPC, and confirms the running build_commit matches HEAD — which is the
#    proof this node is on the activation binary (and therefore the correct,
#    compiled-in activation height).
log "deploying activation build (features: ${ACTIVATION_FEATURES}) via roll-fleet.sh"
CARGO_FEATURES="$ACTIVATION_FEATURES" bash "$REPO_DIR/deploy/ops/roll-fleet.sh"

cat <<EOF

────────────────────────────────────────────────────────────────────────────
Activation build deployed on THIS node (chain DB preserved).
  * roll-fleet confirmed the running build_commit == HEAD → this node carries
    the compiled-in activation height from that commit.
REMAINING (coordination):
  * Run this on EVERY node (seed, fleet, community).
  * Confirm 100% of the node inventory reports the activation build_commit
    BEFORE the chain reaches the activation height. The fingerprint will NOT
    warn you about a laggard — verify out-of-band.
  * If a laggard cannot be upgraded in time: ship a push-out binary (bump the
    height) to everyone before the original height — see the runbook §7.
────────────────────────────────────────────────────────────────────────────
EOF
