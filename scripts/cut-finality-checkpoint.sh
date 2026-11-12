#!/usr/bin/env bash
# ──────────────────────────────────────────────────────────────────────────────
# cut-finality-checkpoint.sh — post-h29,000 shielded finality checkpoint (testnet)
#
# ONE command for the LOCAL prep of the finality checkpoint, so the operator only
# has one deliberate action left afterward (the coordinated fleet redeploy).
# Companion to docs/operations/runbook-h29000-shielded-finality-checkpoint.md.
#
# It does, in order:
#   1. precondition — refuse unless tip >= H + BUFFER (never cut early)
#   2. pull block hash at H from a TRUSTED local node, cross-check it against
#      block H+1's prev_hash (canonical-tip proof)
#   3. human confirmation gate (type the height)
#   4. edit src/testnet.rs — pin (H, hash) in TESTNET_CHECKPOINT_LIST + bump the
#      empty-list guard assertion
#   5. regenerate critical_files.lock (testnet.rs is hash-locked)
#   6. build + run the testnet unit tests
#   7. print the NEW consensus fingerprint and the remaining DELIBERATE steps
#      (commit, 2-of-N review, fleet flag-day redeploy) — it does NOT commit,
#      push, or redeploy. A fingerprint-moving consensus relaunch is never run
#      unattended.
#
# Usage:   H=30000 bash scripts/cut-finality-checkpoint.sh
#
# Env:
#   H         checkpoint height to pin (default 30000; must be > 29000 activation)
#   BUFFER    blocks the tip must be ABOVE H before cutting (default 500; never 0)
#   RPC       trusted node to pull from (default http://127.0.0.1:28081 — a node
#             YOU control; a public RPC could feed a fake hash)
#   KEY_FILE  RPC bearer-key file (auto: $APPDATA/coincync/rpc.key or
#             ~/.config/coincync/rpc.key)
# ──────────────────────────────────────────────────────────────────────────────
set -euo pipefail

H="${H:-30000}"
BUFFER="${BUFFER:-500}"
RPC="${RPC:-http://127.0.0.1:28081}"
ACTIVATION=29000
F="src/testnet.rs"

command -v jq >/dev/null || { echo "FATAL: jq is required" >&2; exit 1; }
[ -f "$F" ] || { echo "FATAL: run from the repo root ($F not found)" >&2; exit 1; }
[ "$H" -gt "$ACTIVATION" ] || { echo "FATAL: H=$H must be > activation height $ACTIVATION" >&2; exit 1; }

# Resolve RPC bearer key (optional).
if [ -z "${KEY_FILE:-}" ]; then
  if [ -n "${APPDATA:-}" ] && [ -f "$APPDATA/coincync/rpc.key" ]; then KEY_FILE="$APPDATA/coincync/rpc.key";
  elif [ -f "$HOME/.config/coincync/rpc.key" ]; then KEY_FILE="$HOME/.config/coincync/rpc.key"; fi
fi
AUTH=()
if [ -n "${KEY_FILE:-}" ] && [ -f "$KEY_FILE" ]; then AUTH=(-H "authorization: Bearer $(cat "$KEY_FILE")"); fi

rpc() { curl -sS -m 8 -X POST "$RPC" "${AUTH[@]}" -H 'content-type: application/json' -d "$1"; }

# ── 1. precondition ───────────────────────────────────────────────────────────
tip=$(rpc '{"jsonrpc":"2.0","id":1,"method":"get_info"}' | jq -r '.result.height // empty')
[ -n "$tip" ] || { echo "FATAL: could not read tip from $RPC" >&2; exit 2; }
need=$((H + BUFFER))
echo "tip=$tip  H=$H  BUFFER=$BUFFER  (need tip >= $need)"
if [ "$tip" -lt "$need" ]; then
  echo "ABORT: tip $tip < $need — do NOT cut early. Wait for the block at H to bury." >&2
  exit 2
fi

# ── 2. pull hash at H + cross-check against H+1 prev_hash ──────────────────────
hH=$(rpc "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"get_block_by_height\",\"params\":[$H]}" | jq -r '.result.hash // empty')
pprev=$(rpc "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"get_block_by_height\",\"params\":[$((H+1))]}" | jq -r '.result.prev_hash // empty')
echo "hash(H)        = $hH"
echo "prev_hash(H+1) = $pprev"
if [ -z "$hH" ] || [ "$hH" != "$pprev" ] || [ "${#hH}" -ne 64 ]; then
  echo "ABORT: hash(H) is not confirmed by prev_hash(H+1), or is malformed — not canonical." >&2
  exit 3
fi
case "$hH" in *[!0-9a-f]*) echo "ABORT: hash is not lowercase hex" >&2; exit 3;; esac

# ── 3. human confirmation gate ────────────────────────────────────────────────
echo
echo "About to pin checkpoint ($H, $hH) into TESTNET_CHECKPOINT_LIST."
echo "This MOVES consensus_fingerprint(Testnet) — it is a coordinated flag-day"
echo "relaunch, NOT a soft update. The fleet must all upgrade together afterward."
read -r -p "Type the height $H to proceed (anything else aborts): " ok
[ "$ok" = "$H" ] || { echo "aborted."; exit 4; }

# ── 4. edit src/testnet.rs ────────────────────────────────────────────────────
if grep -qE "^\s*\($H, " "$F"; then echo "FATAL: height $H already present in $F" >&2; exit 5; fi
# pin the entry right after the list opener
sed -i "/const TESTNET_CHECKPOINT_LIST:/a\\    ($H, \"$hH\"),  // post-h29000 shielded-activation finality anchor" "$F"
# bump the empty-list guard assertion (0 -> H)
sed -i "s/assert_eq!(h, 0,/assert_eq!(h, $H,/" "$F"
echo "edited $F:"
git --no-pager diff -- "$F" | sed -n '1,40p'
echo "NOTE: review the test_checkpoints_populated message in $F (it still reads"
echo "      'must stay empty'); reword it for the pinned entry before the PR."

# ── 5. regenerate the lock ────────────────────────────────────────────────────
echo "regenerating critical_files.lock…"
COINCYNC_REGEN_LOCK=1 cargo run --locked --release --features testnet --bin update-critical-hashes
git --no-pager diff --stat -- critical_files.lock

# ── 6. build + testnet unit tests ─────────────────────────────────────────────
echo "building + testing (testnet)…"
cargo build --release --features testnet --bin coincync-node
cargo test  --release --features testnet --lib "testnet::"

# ── 7. hand off the deliberate steps ──────────────────────────────────────────
echo
echo "=============================================================================="
echo " LOCAL PREP COMPLETE. New consensus fingerprint:"
COINCYNC_ACCEPT_RISK=1 ./target/release/coincync-node --version 2>/dev/null | grep -i "fingerprint testnet" || true
echo
echo " REMAINING — DELIBERATE, human-run (a consensus relaunch is never automated):"
echo "   1. Review the diff + the reworded guard-test message."
echo "   2. git add $F critical_files.lock && git commit   (signed)"
echo "   3. 2-of-N crypto review of the checkpoint PR."
echo "   4. Flag-day fleet redeploy — ALL nodes together (community too):"
echo "        bash deploy/fleet/safe-deploy.sh"
echo "      (safe-deploy's fingerprint preflight refuses the wrong binary.)"
echo "   5. Verify every node reports the NEW fingerprint + converged tip; 0 forks."
echo "=============================================================================="
