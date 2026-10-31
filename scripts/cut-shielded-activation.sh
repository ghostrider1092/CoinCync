#!/usr/bin/env bash
# ──────────────────────────────────────────────────────────────────────────
# cut-shielded-activation.sh — set the testnet shielded activation HEIGHT, then
# verify. This is the "finite-height activation commit" step of the rollout,
# made push-button: the activation height is the ONLY human input.
#
# It does NOT commit, push, or deploy. It edits the knob, regenerates the
# consensus lock, and runs the gated correctness suite, then prints the manual
# gates that must follow (2-of-N review, signed commit, coordinated fleet
# deploy). See docs/design/cip-shielded-testnet-activation.md.
#
#   Usage:  scripts/cut-shielded-activation.sh <activation-height>
#
# H = (live testnet tip at cut time) + (upgrade-window lead). READ the live tip
# from the seed (get_info height) — do NOT guess. At 120s blocks ~1 week ≈ 5040
# blocks is a sane lead floor for a public net.
#
# DO NOT run this during a chaos soak — it does a gated release build that would
# contend with (and could overwrite) the soak binaries. Run it at rollout time.
#
# Mainnet is untouched: this sets SHIELDED_TESTNET_ACTIVATION_HEIGHT only;
# SHIELDED_TX_ACTIVATION_HEIGHT (mainnet) stays u64::MAX.
# ──────────────────────────────────────────────────────────────────────────
set -euo pipefail

log()   { printf '\e[36m==>\e[0m %s\n' "$*"; }
fatal() { printf '\e[31m[ERR]\e[0m %s\n' "$*" >&2; exit 1; }

H="${1:-}"
[ -n "$H" ] || fatal "usage: $0 <activation-height>   (finite; = live testnet tip + upgrade lead)"
case "$H" in *[!0-9]*) fatal "height must be a positive integer, got '$H'";; esac
U64MAX=18446744073709551615
[ "$H" -lt "$U64MAX" ] || fatal "height == u64::MAX means 'off', not an activation"
# A tiny height leaves no upgrade window → guaranteed fork. Force tip+lead.
[ "$H" -ge 1000 ] || fatal "refusing height < 1000 (no upgrade window; use live tip + lead)"

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
CONST="src/constants.rs"
KNOB="SHIELDED_TESTNET_ACTIVATION_HEIGHT"

grep -qE "pub const ${KNOB}: u64 = " "$CONST" \
  || fatal "${KNOB} not found in ${CONST} — commit the activation-knob structural prep first"

CUR="$(grep -oE "pub const ${KNOB}: u64 = [^;]+;" "$CONST" | head -1)"
log "current: ${CUR}"
log "setting ${KNOB} = ${H}"
# Replace only the RHS of the knob line.
sed -i -E "s/(pub const ${KNOB}: u64 = )[^;]+;/\1${H};/" "$CONST"
grep -qE "pub const ${KNOB}: u64 = ${H};" "$CONST" || fatal "edit did not apply as expected"

# Build env for the gated build (host overrides as needed; LIBCLANG_PATH on Windows).
export COINCYNC_RANDOMX_LIGHT_MODE="${COINCYNC_RANDOMX_LIGHT_MODE:-1}"
export SPARK_OPENSSL_DIR="${SPARK_OPENSSL_DIR:-/usr}"   # system OpenSSL for libspark (ubuntu)

log "regenerating critical_files.lock (constants.rs is hash-locked)…"
COINCYNC_REGEN_LOCK=1 cargo run --locked --bin update-critical-hashes
log "lock diff (expect ONLY the constants.rs line):"
git --no-pager diff -- critical_files.lock || true

# The gated correctness suite — NEVER with test-fast-pow (it skips real PoW and
# breaks the checkpoint test). This is the 2400/0 bar that validates the bridge.
GATED="testnet fuse block-integrity-breaker supply-breaker shielded-breaker regtest-chaos sketch-gk-proof libspark-ffi"
log "running gated unit suite (no test-fast-pow): --features \"$GATED\""
cargo test --release --lib --features "$GATED"

cat <<EOF

────────────────────────────────────────────────────────────────────────────
Activation height set to ${H} and verified (gated suite green, lock regenerated).
NOTHING committed / pushed / deployed. Next, MANUALLY:

  1. Review: git diff src/constants.rs critical_files.lock
  2. 2-of-N sign-off on the locked change (see docs/audit/signoff-*.md).
  3. Commit SIGNED (plain git commit; never -c commit.gpgsign=false).
  4. Deploy the libspark-mandatory build to EVERY node:
       sudo bash deploy/ops/activate-shielded-testnet.sh    (run on each host)
  5. Confirm 100% of the node inventory is on the activation build BEFORE
     block ${H}. The consensus fingerprint does NOT encode the activation
     height, so a laggard will NOT be rejected at handshake — it forks at ${H}.
  6. Cross ${H} with real shielded activity (shield-in / shielded-send /
     unshield / subaddress) and confirm the mesh stays converged.
────────────────────────────────────────────────────────────────────────────
EOF
