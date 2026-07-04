#!/usr/bin/env bash
# publish-peer-snapshot.sh — weekly signed peer-list snapshot to IPFS.
#
# Bootstrap resilience: the CoinCync fleet historically relies on
# DNS seeds + a hardcoded seed list baked into the binary. Both are
# centralised — DNS seeds require a live registrar+DNS provider, and
# the hardcoded list can go stale as fleet IPs churn (see [[project_
# infra_topology]] rev history). Nothing catches "all DNS seeds
# unreachable + hardcoded list fully stale" — that scenario would
# make it impossible for a NEW node to find the network.
#
# Fix: every week, this script:
#
#   1. Queries a designated healthy fleet host for its current active
#      peer list via `get_peers` RPC.
#   2. Filters the response to routable public addresses (drops
#      loopback / RFC1918 / CGNAT / docs / v6-link-local per the same
#      `is_routable` predicate the code enforces on gossip).
#   3. Emits a canonical JSON blob:
#        {
#          "schema_version": 1,
#          "network": "testnet",
#          "unix_ts": 1751618400,
#          "chain_tip_height": 9342,
#          "chain_tip_hash": "…",
#          "peers": [ {"addr":"1.2.3.4:28080", "last_seen": 1751618000}, … ]
#        }
#   4. Signs it with `coincync-sign-snapshot` (a small Rust CLI in
#      this repo) using a rotating operational Ed25519 seed. Output
#      is raw 64 bytes — matches the consumer's wire contract in
#      src/network/peer_snapshot.rs exactly.
#   5. Uploads the signed blob to IPFS via `ipfs add`, records the CID,
#      and (if configured) pins it via Pinata + web3.storage.
#   6. Publishes the latest CID at a well-known URL so consumers can
#      resolve "current snapshot" without knowing the CID up front.
#
# ─────────────────────────────────────────────────────────────────────
# WHY IPFS (vs a plain HTTP mirror or a chain-embedded checkpoint):
#
# - Content-addressed: the CID IS the hash of the file. Verifying you
#   got the right file is `sha256sum` against the CID prefix — no PKI
#   needed on the delivery channel.
# - Multi-gateway: any of ipfs.io, cloudflare-ipfs.com, dweb.link, or
#   Pinata's gateway can serve the same CID. No single gateway is
#   load-bearing.
# - Pin-able for cheap: Pinata's free tier and web3.storage both accept
#   a few-KB blob at zero cost.
# - Doesn't need chain consensus. This is a bootstrap-time aid, not a
#   consensus-critical fact.
#
# The SIGNATURE is what makes this trustworthy — an attacker who
# controls one gateway can't forge a blob because they don't have the
# maintainer's ssh signing key. The consumer verifies signature against
# the well-known maintainer public key (baked into the binary, updated
# via consensus-signed bump — separate mechanism, out of scope for
# THIS script).
#
# ─────────────────────────────────────────────────────────────────────
# USAGE
#
#   ./scripts/publish-peer-snapshot.sh                    # normal run
#   ./scripts/publish-peer-snapshot.sh --dry-run          # skip upload
#   ./scripts/publish-peer-snapshot.sh --host seed1       # override source
#
# Configuration via environment:
#   SIGN_SEED_HEX  — 32-byte Ed25519 seed as 64 hex chars, used by the
#                    coincync-sign-snapshot CLI. Rotating operational
#                    key, separate from your SSH commit-signing key.
#                    Generate with:
#                        head -c 32 /dev/urandom | xxd -p -c 64
#                    Get the public key (pin into every consumer's
#                    COINCYNC_PEER_SNAPSHOT_PUBKEY env var) with:
#                        coincync-sign-snapshot pubkey $SIGN_SEED_HEX
#   SIGN_BIN       — path to coincync-sign-snapshot binary. Defaults
#                    to `coincync-sign-snapshot` on PATH.
#   IPFS_API       — Kubo daemon API URL. Defaults to /ip4/127.0.0.1/tcp/5001.
#   PINATA_TOKEN   — if set, additionally pin via Pinata REST.
#   OUT_DIR        — where to write the local artifact copies.
#                    Defaults to ./out/peer-snapshots/.
#   SSH_KEY        — SSH key for reaching the fleet source host.
#                    Defaults to $HOME/.ssh/coincync_fleet.
#   FLEET_CONFIG   — path to fleet-config.json for host resolution.
#
# WIRE-FORMAT v2 (2026-07-04): switched from ssh-keygen -Y sign
# (PEM-armored envelope) to coincync-sign-snapshot (raw 64-byte
# Ed25519). Consumer at src/network/peer_snapshot.rs expects raw
# bytes. See docs/operations/signed-peer-snapshots-consumer.md
# "Producer wire-format v2" section for design rationale.

set -euo pipefail

# Repo root — script may run from any directory. Resolve relative to $0.
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

# ─── args ─────────────────────────────────────────────────────────────
DRY_RUN=0
# Default to a loopback-only-RPC host: those don't set
# COINCYNC_RPC_MIN_METADATA=1, so `get_peers` returns real addr values.
# Public-bind hosts (api, seed1, seed2) redact addr under the P7-R1/R2
# metadata-minimization hardening — snapshot production would end up
# with a peer list of "[redacted]" strings. Loopback-only hosts:
# seed3, explorer, relay1, relay2, randomx, randomx2 (per fleet-
# config.json rpc_bind fields).
SOURCE_HOST="relay1"

while [[ $# -gt 0 ]]; do
    case "$1" in
        --dry-run) DRY_RUN=1; shift ;;
        --host)    SOURCE_HOST="$2"; shift 2 ;;
        -h|--help) sed -n '1,/^set -e/p' "$0" | sed 's/^# \?//'; exit 0 ;;
        *)         echo "unknown arg: $1" >&2; exit 1 ;;
    esac
done

# ─── config with fall-back defaults ────────────────────────────────────
SIGN_BIN="${SIGN_BIN:-coincync-sign-snapshot}"
SSH_KEY="${SSH_KEY:-$HOME/.ssh/coincync_fleet}"
IPFS_API="${IPFS_API:-/ip4/127.0.0.1/tcp/5001}"
FLEET_CONFIG="${FLEET_CONFIG:-$REPO_ROOT/scripts/fleet-config.json}"
OUT_DIR="${OUT_DIR:-$REPO_ROOT/out/peer-snapshots}"

mkdir -p "$OUT_DIR"

# ─── preflight ────────────────────────────────────────────────────────
if [[ ! -f "$FLEET_CONFIG" ]]; then
    echo "✗ fleet-config.json not found: $FLEET_CONFIG" >&2
    exit 1
fi

command -v jq       >/dev/null || { echo "✗ jq required" >&2; exit 1; }
command -v ssh      >/dev/null || { echo "✗ ssh required" >&2; exit 1; }

if [[ $DRY_RUN -eq 0 ]]; then
    command -v ipfs     >/dev/null || { echo "✗ ipfs required (or use --dry-run)" >&2; exit 1; }
    command -v "$SIGN_BIN" >/dev/null || {
        echo "✗ signing binary '$SIGN_BIN' not found on PATH. Build with:" >&2
        echo "    cargo build --release --bin coincync-sign-snapshot" >&2
        echo "  then either install to PATH or set SIGN_BIN=./target/release/coincync-sign-snapshot" >&2
        exit 1
    }
    if [[ -z "${SIGN_SEED_HEX:-}" ]]; then
        echo "✗ SIGN_SEED_HEX env var required (64-char hex, 32-byte Ed25519 seed)." >&2
        echo "  Generate a fresh seed with:" >&2
        echo "    head -c 32 /dev/urandom | xxd -p -c 64" >&2
        exit 1
    fi
    if [[ ${#SIGN_SEED_HEX} -ne 64 ]]; then
        echo "✗ SIGN_SEED_HEX must be exactly 64 hex chars, got ${#SIGN_SEED_HEX}." >&2
        exit 1
    fi
fi

# ─── resolve source host IP + RPC port from fleet-config ──────────────
SOURCE_IP=$(jq -r --arg h "$SOURCE_HOST" '.nodes[$h].ip // empty' "$FLEET_CONFIG")
RPC_PORT=$(jq -r '.rpc_port // 28081' "$FLEET_CONFIG")
NETWORK=$(jq -r '.network // "testnet"' "$FLEET_CONFIG")
if [[ -z "$SOURCE_IP" ]]; then
    echo "✗ host '$SOURCE_HOST' not in $FLEET_CONFIG" >&2
    exit 1
fi

echo "==> source: $SOURCE_HOST @ $SOURCE_IP  rpc_port=$RPC_PORT  network=$NETWORK"

# ─── query source host: get_peers + get_info for tip ──────────────────
# Both calls need the bearer token if the source runs with auth.
# We read the token from the source host itself so this script doesn't
# need to be re-configured every rotation.
# shellcheck disable=SC2086
# SC2086: $SSH_OPTS is a multi-option string that MUST word-split into
# separate argv entries — quoting it as "$SSH_OPTS" would pass it as a
# single argument that ssh doesn't understand. Same pattern used
# throughout scripts/deploy-node-binary.sh.
SSH_OPTS="-i $SSH_KEY -o StrictHostKeyChecking=accept-new -o ConnectTimeout=10 -o BatchMode=yes"

# shellcheck disable=SC2029
# SC2029: the remote command contains client-side variable expansion
# ($SSH_OPTS is client-side; the grep body is single-quoted so shell
# metacharacters in it are safe). Intentional.
BEARER=$(ssh $SSH_OPTS "root@${SOURCE_IP}" \
    "grep -h '^COINCYNC_RPC_API_KEY=' /etc/coincync/coincync.env /etc/systemd/system/coincync-node.service.d/*.conf 2>/dev/null | head -1 | cut -d= -f2 | tr -d '\"'" \
    2>/dev/null || true)
BEARER_HEADER=""
[[ -n "$BEARER" ]] && BEARER_HEADER="-H \"Authorization: Bearer $BEARER\""

# shellcheck disable=SC2087
# SC2087: unquoted EOSSH is INTENTIONAL — we want $RPC_PORT, $NETWORK,
# $BEARER_HEADER to be substituted CLIENT-SIDE before the script is
# sent to the server. If we quoted 'EOSSH' those would be empty on the
# server side (they're not exported into the SSH environment).
# Wrap the two curls in one SSH call to save round-trips.
RPC_RESPONSE=$(ssh $SSH_OPTS "root@${SOURCE_IP}" bash -s <<EOSSH
set -e
info_body='{"jsonrpc":"2.0","id":1,"method":"get_info","params":[]}'
peers_body='{"jsonrpc":"2.0","id":2,"method":"get_peers","params":[]}'
info=\$(curl -s -m 8 http://127.0.0.1:${RPC_PORT}/rpc/${NETWORK} \
    -H 'Content-Type: application/json' \
    ${BEARER_HEADER} \
    -d "\$info_body")
peers=\$(curl -s -m 8 http://127.0.0.1:${RPC_PORT}/rpc/${NETWORK} \
    -H 'Content-Type: application/json' \
    ${BEARER_HEADER} \
    -d "\$peers_body")
echo "\$info"
echo "---SEP---"
echo "\$peers"
EOSSH
)

INFO_JSON=$(echo "$RPC_RESPONSE" | awk '/---SEP---/{exit} {print}')
PEERS_JSON=$(echo "$RPC_RESPONSE" | awk '/---SEP---/{f=1; next} f{print}')

TIP_HEIGHT=$(echo "$INFO_JSON" | jq -r '.result.height // 0')
TIP_HASH=$(echo "$INFO_JSON" | jq -r '.result.top_hash // ""')

# Timestamp captured once, used by BOTH the peer filter (as last_seen
# floor) and the outer snapshot envelope. Defined here so the jq
# filter below can reference $UNIX_TS via --argjson.
UNIX_TS=$(date -u +%s)

# ─── filter peers to routable public addresses ───────────────────────
# Same predicate the node uses on gossip (network/node.rs::is_routable):
# drops loopback, unspecified, RFC1918 private ranges, IPv4 link-local
# (169.254/16), CGNAT (100.64/10), docs (192.0.2 / 198.51.100 / 203.0.113),
# benchmark (198.18/15), 0.0.0.0/8, broadcast (255.255.255.255),
# multicast (224/4, ff00::/8), IPv6 unique-local (fc00::/7), IPv6
# link-local (fe80::/10), IPv6 docs (2001:db8::/32).
#
# We DON'T re-implement is_routable in bash — we do a coarse-grained
# filter here and trust the node's server-side filter for authoritative
# rejection. The consumer will re-verify anyway.
# CRITICAL: filter to OUTBOUND peers only. For inbound peers, `.addr`
# is the peer's outbound socket (ephemeral port), NOT their listen
# address — a consumer dialing that port won't reach the peer's node.
# Only outbound peers' `.addr` is guaranteed to be the listen address
# we dialed to establish the connection. Downside: snapshots have
# fewer peers. Correct trade-off: 5 dial-able addresses > 40
# ephemeral-port stubs.
FILTERED=$(echo "$PEERS_JSON" | jq --compact-output --argjson now "$UNIX_TS" '
    [.result.peers[]?
     | select(.outbound == true)
     | select(.addr != null)
     | select(.addr != "[redacted]")
     | select(.addr | startswith("127.") | not)
     | select(.addr | startswith("10.") | not)
     | select(.addr | startswith("192.168.") | not)
     | select(.addr | startswith("169.254.") | not)
     | select(.addr | startswith("172.16.") | not)
     | select(.addr | startswith("172.17.") | not)
     | select(.addr | startswith("172.18.") | not)
     | select(.addr | startswith("172.19.") | not)
     | select(.addr | startswith("172.20.") | not)
     | select(.addr | startswith("172.21.") | not)
     | select(.addr | startswith("172.22.") | not)
     | select(.addr | startswith("172.23.") | not)
     | select(.addr | startswith("172.24.") | not)
     | select(.addr | startswith("172.25.") | not)
     | select(.addr | startswith("172.26.") | not)
     | select(.addr | startswith("172.27.") | not)
     | select(.addr | startswith("172.28.") | not)
     | select(.addr | startswith("172.29.") | not)
     | select(.addr | startswith("172.30.") | not)
     | select(.addr | startswith("172.31.") | not)
     | select(.addr | startswith("100.64.") | not)
     | select(.addr | startswith("100.65.") | not)
     | select(.addr | startswith("100.66.") | not)
     | select(.addr | startswith("100.67.") | not)
     | {addr: .addr, last_seen: $now}]
')
PEER_COUNT=$(echo "$FILTERED" | jq 'length')
echo "==> filtered peers: $PEER_COUNT routable public addresses"

# Reject degenerate snapshots — 0 peers means the source is unhealthy
# and this snapshot would poison future bootstrapping. Publishing a
# stale (last week's) snapshot is safer than publishing an empty one.
if [[ "$PEER_COUNT" -lt 3 ]]; then
    echo "✗ source $SOURCE_HOST only sees $PEER_COUNT routable peers — refusing to publish." >&2
    echo "  Try a different --host, or investigate the source's connectivity." >&2
    exit 2
fi

# ─── build canonical snapshot ────────────────────────────────────────
# UNIX_TS was captured earlier (before the peer filter) so the filter
# could set each peer's last_seen to the snapshot time.
SNAPSHOT=$(jq -n --argjson peers "$FILTERED" \
    --arg network "$NETWORK" \
    --argjson unix_ts "$UNIX_TS" \
    --argjson height "$TIP_HEIGHT" \
    --arg hash "$TIP_HASH" \
    '{schema_version: 1, network: $network, unix_ts: $unix_ts,
      chain_tip_height: $height, chain_tip_hash: $hash, peers: $peers}')

SNAP_PATH="$OUT_DIR/peer-snapshot-${NETWORK}-${UNIX_TS}.json"
echo "$SNAPSHOT" > "$SNAP_PATH"
echo "==> snapshot written: $SNAP_PATH ($(wc -c < "$SNAP_PATH") bytes)"

# ─── sign ────────────────────────────────────────────────────────────
if [[ $DRY_RUN -eq 1 ]]; then
    echo "[dry-run] skipping signature + IPFS upload"
    exit 0
fi

SIG_PATH="${SNAP_PATH}.sig"
# Wire-format v2: raw 64-byte Ed25519 signature over
# b"coincync-peer-snapshot-v1" || snapshot_bytes.
#
# The signing binary must be in sync with the consumer's namespace
# constant at src/network/peer_snapshot.rs::SIGNATURE_NAMESPACE.
# There's a build-time test in src/bin/sign_snapshot.rs
# (sign_output_verifies_with_derived_pubkey_and_matching_namespace)
# that would fail if the two drift.
#
# The seed is read from SIGN_SEED_HEX env var so it never appears in
# process argv (visible via /proc/*/cmdline to other users).
COINCYNC_SIGN_SEED_HEX="$SIGN_SEED_HEX" \
    "$SIGN_BIN" sign "$SNAP_PATH" "$SIG_PATH"

# Sanity check: signature file must be exactly 64 bytes.
SIG_SIZE=$(stat -c%s "$SIG_PATH" 2>/dev/null || stat -f%z "$SIG_PATH")
if [[ "$SIG_SIZE" -ne 64 ]]; then
    echo "✗ signature file wrong size: $SIG_SIZE bytes (expected 64)" >&2
    exit 3
fi
echo "==> signature written: $SIG_PATH ($SIG_SIZE bytes, raw Ed25519)"

# ─── upload to IPFS ──────────────────────────────────────────────────
CID_SNAP=$(ipfs add --api="$IPFS_API" --pin --quiet "$SNAP_PATH")
CID_SIG=$(ipfs add  --api="$IPFS_API" --pin --quiet "$SIG_PATH")
echo "==> uploaded to IPFS"
echo "    snapshot CID:  $CID_SNAP"
echo "    signature CID: $CID_SIG"

# ─── optionally pin via Pinata ───────────────────────────────────────
if [[ -n "${PINATA_TOKEN:-}" ]]; then
    echo "==> pinning via Pinata..."
    curl -s -X POST "https://api.pinata.cloud/pinning/pinByHash" \
        -H "Authorization: Bearer $PINATA_TOKEN" \
        -H "Content-Type: application/json" \
        -d "{\"hashToPin\":\"$CID_SNAP\"}" >/dev/null || echo "  Pinata snapshot pin failed (non-fatal)"
    curl -s -X POST "https://api.pinata.cloud/pinning/pinByHash" \
        -H "Authorization: Bearer $PINATA_TOKEN" \
        -H "Content-Type: application/json" \
        -d "{\"hashToPin\":\"$CID_SIG\"}" >/dev/null || echo "  Pinata sig pin failed (non-fatal)"
fi

# ─── record latest CID in the local repo for the well-known URL ─────
LATEST_PATH="$OUT_DIR/latest-${NETWORK}.json"
jq -n --arg snap "$CID_SNAP" --arg sig "$CID_SIG" \
      --argjson unix_ts "$UNIX_TS" --argjson height "$TIP_HEIGHT" \
      --arg source "$SOURCE_HOST" --argjson peer_count "$PEER_COUNT" \
      '{schema_version: 1, unix_ts: $unix_ts, snapshot_cid: $snap,
        signature_cid: $sig, source_host: $source,
        chain_tip_height: $height, peer_count: $peer_count}' \
    > "$LATEST_PATH"
echo "==> latest pointer written: $LATEST_PATH"
echo ""
echo "Next step: publish the latest CID at a well-known URL"
echo "  (e.g., https://coincync.network/bootstrap/latest-testnet.json)"
echo "  so a fresh node can resolve the current CID without knowing it."
