#!/usr/bin/env bash
# scripts/create-chaindata-snapshot.sh
#
# Create a downloadable chaindata snapshot ("bootstrap pack") that
# community-member nodes can untar to skip the multi-hour initial
# sync. Run this on a healthy, fully-synced fleet node (typically
# seed1.coincync.network) after stopping the node service.
#
# The snapshot is a tar.gz of the node's RocksDB data directory plus
# a JSON manifest describing what's inside (tip height, tip hash,
# build version, file sha256). New nodes verify the snapshot by:
#   1) sha256 matches the manifest (defends against transfer error)
#   2) on startup, their binary's HARDCODED CHECKPOINTS re-verify the
#      chain head matches a known good height/hash (defends against
#      malicious tampering — a tampered snapshot would fail the
#      checkpoint at the next block they receive).
#
# This is a stopgap until warp sync ships per CIP-015 (v2.0). It is
# a TRUST-MINIMIZED bootstrap, not a TRUSTLESS one. Operators who
# want zero trust must sync from genesis until CIP-015 ships.
#
# USAGE (on a fleet node, after stopping coincync-node):
#   sudo systemctl stop coincync-node
#   bash scripts/create-chaindata-snapshot.sh \
#     --data-dir=/var/lib/coincync/testnet \
#     --out=/srv/snapshots
#   sudo systemctl start coincync-node
#
# OUTPUT:
#   /srv/snapshots/coincync-chaindata-testnet-h<HEIGHT>.tar.gz
#   /srv/snapshots/coincync-chaindata-testnet-h<HEIGHT>.manifest.json
#   /srv/snapshots/coincync-chaindata-testnet-h<HEIGHT>.sha256
#
# After running, upload all three files to the v1.0.9.1 release page
# (or a dedicated bootstrap-snapshots release) and post the download
# URL to Discord. The .sha256 file is what users will check against.

set -euo pipefail

# --- Defaults -------------------------------------------------------------
DATA_DIR="$HOME/.coincync/testnet"
OUT_DIR="$HOME/snapshots"
NETWORK="testnet"
NODE_BINARY="${NODE_BINARY:-coincync-node}"

# --- Args -----------------------------------------------------------------
while [ $# -gt 0 ]; do
  case "$1" in
    --data-dir=*) DATA_DIR="${1#*=}"; shift;;
    --out=*)      OUT_DIR="${1#*=}"; shift;;
    --network=*)  NETWORK="${1#*=}"; shift;;
    --help|-h)
      sed -n '2,/^set -euo pipefail$/p' "$0" | grep -E '^#( |$)' | sed 's/^# \?//'
      exit 0;;
    *) echo "unknown arg: $1" >&2; exit 1;;
  esac
done

# --- Safety checks --------------------------------------------------------
if [ ! -d "$DATA_DIR" ]; then
  echo "fatal: data directory $DATA_DIR does not exist" >&2
  exit 2
fi

# RocksDB does not allow concurrent writers. If the node is still
# running, the tar would capture an inconsistent state and the
# resulting snapshot would be corrupt. Hard-fail rather than silently
# producing a bad snapshot.
if pgrep -x "$NODE_BINARY" >/dev/null 2>&1; then
  echo "fatal: $NODE_BINARY is still running — stop it first:" >&2
  echo "       sudo systemctl stop coincync-node" >&2
  echo "       (or: pkill -x $NODE_BINARY)" >&2
  exit 2
fi

# LOCK file check — RocksDB writes a LOCK file in its data dir while
# open. If we see LOCK with a non-zero size, a node may have crashed
# mid-write and the data is inconsistent. Warn but don't block (operator
# may have intentionally cleared LOCK).
if [ -f "$DATA_DIR/LOCK" ] && [ -s "$DATA_DIR/LOCK" ]; then
  echo "WARN: $DATA_DIR/LOCK exists and is non-empty — last node shutdown" >&2
  echo "      may have been unclean. The snapshot may be inconsistent." >&2
  echo "      Recommended: restart the node briefly so RocksDB recovers, then re-run." >&2
fi

mkdir -p "$OUT_DIR"

# --- Read chain tip from the data dir ------------------------------------
# We need the tip height + tip hash to name the snapshot and write the
# manifest. The cleanest way is to launch the node binary with a
# read-only get_info call, but since the node is stopped, we'll do this
# the simple way: spin the node up against a dummy RPC port for 5
# seconds, hit get_info, then kill it. Avoid touching the chain.
#
# Alternative: parse RocksDB directly. Considered + rejected — too
# fragile across binary versions.
#
# Even simpler: just use file mtime + a placeholder height. Done below
# since this script runs after the operator has confirmed the node is
# synced — they know the height.
TIP_HEIGHT="${TIP_HEIGHT:-unknown}"
TIP_HASH="${TIP_HASH:-unknown}"

if [ "$TIP_HEIGHT" = "unknown" ] || [ "$TIP_HASH" = "unknown" ]; then
  echo "----------------------------------------------------------------------"
  echo "  TIP_HEIGHT and TIP_HASH not set via env vars."
  echo ""
  echo "  Get them from a live node BEFORE stopping it:"
  echo "    curl -s -X POST http://127.0.0.1:28081 \\"
  echo "      -H 'Content-Type: application/json' \\"
  echo "      -d '{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"get_info\"}' \\"
  echo "      | jq -r '.result | \"TIP_HEIGHT=\\(.height) TIP_HASH=\\(.tip_hash)\"'"
  echo ""
  echo "  Then re-run this script with:"
  echo "    TIP_HEIGHT=<N> TIP_HASH=<hex> bash $0 ..."
  echo "----------------------------------------------------------------------"
  exit 2
fi

# --- Compute snapshot details --------------------------------------------
TIMESTAMP_ISO="$(date -u +%FT%TZ)"
BASE_NAME="coincync-chaindata-${NETWORK}-h${TIP_HEIGHT}"
TARBALL="$OUT_DIR/${BASE_NAME}.tar.gz"
MANIFEST="$OUT_DIR/${BASE_NAME}.manifest.json"
SHA_FILE="$OUT_DIR/${BASE_NAME}.sha256"
BINARY_VERSION="$($NODE_BINARY --version 2>/dev/null || echo "unknown")"

echo "===================================================================="
echo "  chaindata snapshot — ${NETWORK}"
echo "===================================================================="
echo "  data dir:        $DATA_DIR"
echo "  out dir:         $OUT_DIR"
echo "  tip height:      $TIP_HEIGHT"
echo "  tip hash:        $TIP_HASH"
echo "  binary version:  $BINARY_VERSION"
echo "  tarball:         $TARBALL"
echo "  started:         $TIMESTAMP_ISO"
echo "===================================================================="
echo ""

# --- Estimate snapshot size BEFORE tar (so operator can abort) -----------
DU_RAW="$(du -sh "$DATA_DIR" | cut -f1)"
echo "Source size (raw):    $DU_RAW"
echo "Compressing now — gzip is single-threaded, expect ~1-3 min per GB."
echo ""

# --- Create the tarball (deterministic ordering) -------------------------
# --sort=name: deterministic file ordering so same-input → same-tarball.
# --owner=0 --group=0 --numeric-owner: strip uid/gid so the snapshot
#   doesn't leak operator's local account info.
# --mtime: pin mtimes so a re-snapshot at same height byte-equals.
# Note: GNU tar required (BSD tar lacks --sort).
PARENT_DIR="$(dirname "$DATA_DIR")"
LEAF_DIR="$(basename "$DATA_DIR")"

cd "$PARENT_DIR"
tar --sort=name \
    --owner=0 --group=0 --numeric-owner \
    --mtime="$TIMESTAMP_ISO" \
    -czf "$TARBALL" \
    "$LEAF_DIR"

DU_PACKED="$(du -sh "$TARBALL" | cut -f1)"
echo "Compressed size:      $DU_PACKED"

# --- Compute SHA256 ------------------------------------------------------
echo ""
echo "Computing SHA256..."
SHA256="$(sha256sum "$TARBALL" | cut -d' ' -f1)"
echo "$SHA256  $(basename "$TARBALL")" > "$SHA_FILE"
echo "  $SHA256"

# --- Write manifest ------------------------------------------------------
cat > "$MANIFEST" <<MANIFEST_EOF
{
  "schema_version": 1,
  "snapshot_kind": "chaindata-tarball-bootstrap",
  "network": "$NETWORK",
  "tip_height": $TIP_HEIGHT,
  "tip_hash": "$TIP_HASH",
  "binary_version": "$BINARY_VERSION",
  "created_utc": "$TIMESTAMP_ISO",
  "tarball_filename": "$(basename "$TARBALL")",
  "tarball_size_bytes": $(stat -c%s "$TARBALL"),
  "tarball_sha256": "$SHA256",
  "trust_model": "checkpoint-verified",
  "trust_model_notes": "New nodes verify this snapshot by re-running their binary's hardcoded checkpoint set against the imported chain. Tampering with a snapshot would cause the next-block validation to fail at the first checkpoint above the snapshot height. This is a stopgap until trustless warp sync ships per CIP-015 (v2.0).",
  "deprecation": {
    "superseded_by": "CIP-015 warp sync (v2.0)",
    "removal_target": "v2.0 release"
  }
}
MANIFEST_EOF

echo ""
echo "===================================================================="
echo "  Snapshot complete."
echo "===================================================================="
echo "  Tarball:   $TARBALL  ($DU_PACKED)"
echo "  Manifest:  $MANIFEST"
echo "  SHA256:    $SHA_FILE"
echo ""
echo "Next steps:"
echo "  1. Upload all THREE files to the v1.0.9.1 release page:"
echo "     gh release upload v1.0.9.1-testnet \\"
echo "       \"$TARBALL\" \\"
echo "       \"$MANIFEST\" \\"
echo "       \"$SHA_FILE\""
echo ""
echo "  2. Post the URLs to Discord with the SHA256 and the operator"
echo "     restore procedure documented in"
echo "     docs/src/operations/bootstrap-from-snapshot.md"
echo ""
echo "  3. Restart your fleet node:"
echo "     sudo systemctl start coincync-node"
echo "===================================================================="
