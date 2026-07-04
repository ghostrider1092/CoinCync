#!/usr/bin/env bash
# publish-explorer-ipfs.sh — snapshot the explorer to a clean dist
# directory and publish it to IPFS. The pinned CID is the fallback
# entry point community members use when explorer.coincync.network is
# unreachable (Cloudflare edge outage, DNS zone compromise, etc.).
#
# The published bundle is a plain static site. When served from any
# IPFS gateway (e.g. https://cloudflare-ipfs.com/ipfs/<cid>/), the
# frontend's `_computeApiBase()` (see src/explorer/index.html) picks
# up that we're off-origin and points its RPC calls at
# `api.coincync.network`. Prerequisites (verified by the runbook
# before running this script):
#   1. api.coincync.network serves `Access-Control-Allow-Origin: *`
#      (or an allowlist covering the common IPFS gateway domains).
#   2. Either a local Kubo IPFS daemon at 127.0.0.1:5001 OR a Pinata
#      JWT in $PINATA_TOKEN.
#
# Usage:
#   bash scripts/publish-explorer-ipfs.sh                          # local IPFS only
#   PINATA_TOKEN=<jwt> bash scripts/publish-explorer-ipfs.sh       # local + Pinata
#   SKIP_LOCAL_IPFS=1 PINATA_TOKEN=<jwt> bash scripts/publish-explorer-ipfs.sh
#                                                                  # Pinata only
#   bash scripts/publish-explorer-ipfs.sh --dry-run                # snapshot but don't publish
#
# Environment:
#   IPFS_API              Kubo API endpoint (default http://127.0.0.1:5001)
#   PINATA_TOKEN          Pinata JWT (optional; enables Pinata pinning)
#   SKIP_LOCAL_IPFS       Set to 1 to skip local Kubo (Pinata-only mode)
#   DIST                  Output dir (default ./out/explorer-static)
#   POINTER_FILE          Where to write latest.json (default ./out/explorer-latest.json)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

SRC="$REPO_ROOT/src/explorer"
DIST="${DIST:-$REPO_ROOT/out/explorer-static}"
POINTER_FILE="${POINTER_FILE:-$REPO_ROOT/out/explorer-latest.json}"
IPFS_API="${IPFS_API:-http://127.0.0.1:5001}"
DRY_RUN=0

while [ $# -gt 0 ]; do
  case "$1" in
    --dry-run) DRY_RUN=1; shift ;;
    -h|--help) sed -n '2,40p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) echo "unknown arg: $1" >&2; exit 1 ;;
  esac
done

# ── Preflight ────────────────────────────────────────────────────────
if [ ! -d "$SRC" ]; then
  echo "ERROR: source dir not found: $SRC" >&2
  exit 1
fi

if [ ! -f "$SRC/index.html" ]; then
  echo "ERROR: $SRC/index.html not found" >&2
  exit 1
fi

# Confirm the frontend already has the _computeApiBase() function. The
# publish is meaningless without it — an origin-relative build served
# via IPFS gateway would just 404 on every /api/ fetch.
if ! grep -q "_computeApiBase" "$SRC/index.html"; then
  echo "ERROR: $SRC/index.html does not contain _computeApiBase()." >&2
  echo "       The IPFS-portable frontend fix is missing. Merge the" >&2
  echo "       Fort-Knox item 4 PR before publishing to IPFS." >&2
  exit 1
fi

# Dry-run skips the IPFS reachability check — the whole point is to
# inspect the snapshotted bundle without publishing. The publish path
# (below the DRY_RUN early-exit) re-verifies before touching the network.
if [ "$DRY_RUN" -ne 1 ]; then
  if [ -z "${SKIP_LOCAL_IPFS:-}" ] && [ -z "${PINATA_TOKEN:-}" ]; then
    # Verify local Kubo is reachable if we're going to use it.
    if ! curl -sf -X POST -m 5 "$IPFS_API/api/v0/id" >/dev/null 2>&1; then
      echo "ERROR: neither PINATA_TOKEN set nor local IPFS ($IPFS_API) reachable." >&2
      echo "       Options:" >&2
      echo "         * Start Kubo:              ipfs daemon &" >&2
      echo "         * Or use Pinata only:      SKIP_LOCAL_IPFS=1 PINATA_TOKEN=<jwt> ..." >&2
      echo "         * Or check without publishing: --dry-run" >&2
      exit 1
    fi
  fi
fi

# ── Snapshot ─────────────────────────────────────────────────────────
echo "==> Snapshotting explorer to $DIST"
rm -rf "$DIST"
mkdir -p "$DIST"

# Copy tree, excluding dev-only pieces. serve.py is Python dev proxy;
# placeholder.html is the pre-launch landing (kept — deployers may want
# it as a fallback root). Preserve everything else — the frontend is
# self-contained.
#
# Prefer rsync where available (it handles the exclude patterns
# cleanly). Fall back to `cp -r` + manual cleanup on hosts without
# rsync — Windows Git Bash notably lacks it by default. Behavior is
# identical from the caller's perspective.
if command -v rsync >/dev/null 2>&1; then
  rsync -a \
    --exclude=serve.py \
    --exclude='__pycache__' \
    --exclude='*.pyc' \
    "$SRC/" "$DIST/"
else
  cp -R "$SRC"/. "$DIST/"
  rm -f "$DIST/serve.py"
  find "$DIST" -type d -name '__pycache__' -exec rm -rf {} + 2>/dev/null || true
  find "$DIST" -type f -name '*.pyc' -delete 2>/dev/null || true
fi

# Add a small README so users landing directly at
# https://ipfs.io/ipfs/<cid>/README.md understand what they're seeing.
cat > "$DIST/README.md" <<'READMEEOF'
# CoinCync Explorer — IPFS mirror

This is a content-addressed snapshot of the CoinCync blockchain
explorer, published to IPFS as a fallback for
`explorer.coincync.network`.

## How to use

Open `index.html` on any IPFS gateway:

- <https://cloudflare-ipfs.com/ipfs/CID/>
- <https://ipfs.io/ipfs/CID/>
- <https://dweb.link/ipfs/CID/>
- <https://gateway.pinata.cloud/ipfs/CID/>

(Replace `CID` with the CID this bundle was published under.)

The frontend detects it's running on an IPFS gateway and points its
API calls at `https://api.coincync.network`. If you'd rather point at
your own coincync-node, append `?api=http://your-node:28081` to the
gateway URL, OR run:

```js
localStorage.setItem('cync-api-base', 'http://your-node:28081')
```

in the browser console and reload.

## Verification

The frontend's SHA256 is recorded in the Fort-Knox item 4 rollout
runbook. If you want to verify this snapshot matches source, clone
`https://github.com/ghostrider1092/Coincync-Testnet-` at the commit
recorded in `BUILD_INFO.txt` (see next to this README) and run
`bash scripts/publish-explorer-ipfs.sh --dry-run`. The `$DIST` output
must sha256sum-match the bytes here.

READMEEOF

# Record what commit + when this was built, for reproducibility.
COMMIT="$(git -C "$REPO_ROOT" rev-parse HEAD 2>/dev/null || echo unknown)"
SHORT="$(git -C "$REPO_ROOT" rev-parse --short HEAD 2>/dev/null || echo unknown)"
UNIX="$(date -u +%s)"
cat > "$DIST/BUILD_INFO.txt" <<EOF
commit: $COMMIT
short:  $SHORT
built:  $(date -u +%FT%TZ)
unix:   $UNIX
EOF

# Sha256 the index.html so operators + auditors can verify off-the-wire.
INDEX_SHA="$(sha256sum "$DIST/index.html" | awk '{print $1}')"
echo "    index.html sha256: $INDEX_SHA"

if [ "$DRY_RUN" -eq 1 ]; then
  echo ""
  echo "==> Dry run: bundle prepared at $DIST"
  echo "    Total: $(du -sh "$DIST" | awk '{print $1}')"
  echo "    Not publishing."
  exit 0
fi

# ── Publish to local Kubo ────────────────────────────────────────────
LOCAL_CID=""
if [ -z "${SKIP_LOCAL_IPFS:-}" ]; then
  echo ""
  echo "==> Adding to local IPFS at $IPFS_API"
  # `--cid-version 1` gives CIDv1 (bafk...) which most modern gateways
  # prefer. `--pin=true` prevents GC from evicting it.
  ADD_JSON="$(curl -sf -X POST \
    -F "file=@$DIST" \
    "$IPFS_API/api/v0/add?recursive=true&pin=true&cid-version=1&wrap-with-directory=false" \
    2>&1 | tail -1)"

  # The last line of the add response is the root object. Parse its Hash field.
  LOCAL_CID="$(echo "$ADD_JSON" | python3 -c 'import sys,json; d=json.loads(sys.stdin.read()); print(d.get("Hash",""))' 2>/dev/null || true)"
  if [ -z "$LOCAL_CID" ]; then
    echo "WARN: could not parse Kubo add response:" >&2
    echo "$ADD_JSON" >&2
    echo "      (proceeding — Pinata pin path may still succeed)" >&2
  else
    echo "    Local CID: $LOCAL_CID"
  fi
fi

# ── Publish to Pinata (optional) ─────────────────────────────────────
PINATA_CID=""
if [ -n "${PINATA_TOKEN:-}" ]; then
  echo ""
  echo "==> Pinning to Pinata"
  TARBALL="$(mktemp --suffix=.tar.gz)"
  tar -C "$DIST" -czf "$TARBALL" .
  # Pinata's pinFileToIPFS endpoint accepts a multipart upload of the
  # bundle. The response includes `IpfsHash` (the CID).
  RESP="$(curl -sf \
    -X POST "https://api.pinata.cloud/pinning/pinFileToIPFS" \
    -H "Authorization: Bearer $PINATA_TOKEN" \
    -F "file=@$TARBALL" \
    -F 'pinataMetadata={"name":"coincync-explorer-mirror"}' \
    2>&1 || true)"
  rm -f "$TARBALL"
  PINATA_CID="$(echo "$RESP" | python3 -c 'import sys,json; d=json.loads(sys.stdin.read()); print(d.get("IpfsHash",""))' 2>/dev/null || true)"
  if [ -z "$PINATA_CID" ]; then
    echo "WARN: Pinata pin failed. Response:" >&2
    echo "$RESP" >&2
  else
    echo "    Pinata CID: $PINATA_CID"
  fi
fi

# ── Consistency check ───────────────────────────────────────────────
# If we published to both, the CIDs SHOULD match (content-addressed).
# A mismatch would mean the two paths disagree on the bundle — most
# likely a Pinata tarball-vs-directory addressing quirk. Surface it
# but don't fail.
if [ -n "$LOCAL_CID" ] && [ -n "$PINATA_CID" ] && [ "$LOCAL_CID" != "$PINATA_CID" ]; then
  echo ""
  echo "WARN: local CID ($LOCAL_CID) != Pinata CID ($PINATA_CID)." >&2
  echo "      Pinata's tarball-upload wraps the content differently" >&2
  echo "      than Kubo's directory-add. The Kubo CID is the" >&2
  echo "      canonical gateway URL; Pinata is redundancy." >&2
fi

# ── Pointer file ─────────────────────────────────────────────────────
PRIMARY_CID="${LOCAL_CID:-$PINATA_CID}"
if [ -z "$PRIMARY_CID" ]; then
  echo ""
  echo "ERROR: no CID produced by any path. Nothing to advertise." >&2
  exit 2
fi

cat > "$POINTER_FILE" <<EOF
{
  "schema_version": 1,
  "cid": "$PRIMARY_CID",
  "local_cid": "${LOCAL_CID:-null}",
  "pinata_cid": "${PINATA_CID:-null}",
  "index_html_sha256": "$INDEX_SHA",
  "commit": "$COMMIT",
  "built_unix": $UNIX,
  "built_iso": "$(date -u +%FT%TZ)",
  "gateways_examples": [
    "https://cloudflare-ipfs.com/ipfs/$PRIMARY_CID/",
    "https://ipfs.io/ipfs/$PRIMARY_CID/",
    "https://dweb.link/ipfs/$PRIMARY_CID/",
    "https://gateway.pinata.cloud/ipfs/$PRIMARY_CID/"
  ]
}
EOF

echo ""
echo "==> Published."
echo "    Primary CID:      $PRIMARY_CID"
echo "    index.html sha256:$INDEX_SHA"
echo "    Pointer written:  $POINTER_FILE"
echo ""
echo "    Verify via any gateway:"
echo "      https://cloudflare-ipfs.com/ipfs/$PRIMARY_CID/"
echo "      https://ipfs.io/ipfs/$PRIMARY_CID/"
echo ""
echo "    Next: publish $POINTER_FILE to a well-known URL so the"
echo "    community can discover the current CID. Example:"
echo "      scp $POINTER_FILE root@explorer:/var/www/well-known/explorer-latest.json"
