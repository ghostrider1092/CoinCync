#!/usr/bin/env bash
# publish-faucet-registry.sh — sign + publish the current faucet
# directory to IPFS. Consumers (coincync-wallet) discover live
# faucets via this registry when their compiled-in canonical entry
# is down or the operator wants users to see community-run instances.
#
# Companion to `publish-peer-snapshot.sh` (Fort-Knox item 6) and
# `publish-coord-registry.sh` (Fort-Knox item 3). All three use the
# same underlying signing CLI (`coincync-sign-snapshot`) and IPFS
# publishing path — they differ only in the signature namespace and
# the input source.
#
# ── HOW IT WORKS ──────────────────────────────────────────────────────
#
# 1. Read a CURATED list of live faucets from a local JSON config
#    file (not from RPC — faucets are operator-managed, not
#    P2P-gossiped like peers).
# 2. Validate the file against the FaucetRegistry schema
#    (schema_version, network, unix_ts stamped now, faucets array).
# 3. Sign the canonical JSON with `coincync-sign-snapshot` using the
#    domain-separated namespace `coincync-faucet-registry-v1`.
# 4. Upload the JSON + signature to IPFS via a local Kubo daemon.
# 5. If PINATA_TOKEN is set, also pin via Pinata for gateway
#    redundancy.
# 6. Write a small `latest-<network>.json` pointer that lists the
#    CIDs — that pointer goes at the well-known URL wallets fetch.
#
# ── USAGE ─────────────────────────────────────────────────────────────
#
#   bash scripts/publish-faucet-registry.sh --network testnet
#   PINATA_TOKEN=... bash scripts/publish-faucet-registry.sh
#   bash scripts/publish-faucet-registry.sh --input custom-list.json
#   bash scripts/publish-faucet-registry.sh --dry-run
#
# ── ENVIRONMENT ──────────────────────────────────────────────────────
#
#   COINCYNC_SIGN_SEED_HEX  Ed25519 signing seed as 64 hex chars.
#                          REQUIRED for a real publish; --dry-run
#                          bypasses.
#   PINATA_TOKEN            Pinata JWT with pinFileToIPFS scope.
#                          Optional; local Kubo used if unset.
#   IPFS_API                Kubo API endpoint (default
#                          http://127.0.0.1:5001).
#
# ── SEE ALSO ──────────────────────────────────────────────────────────
#
#   docs/operations/runbook-faucet-registry.md — operator ceremony,
#     verification steps, rotation cadence
#   src/network/faucet_registry.rs                  — consumer side
#   src/network/signed_registry.rs                  — generic infra

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

# ── args ────────────────────────────────────────────────────────────
NETWORK="testnet"
INPUT_FILE=""
OUTPUT_DIR="$REPO_ROOT/out"
IPFS_API="${IPFS_API:-http://127.0.0.1:5001}"
DRY_RUN=0

while [ $# -gt 0 ]; do
  case "$1" in
    --network) NETWORK="$2"; shift 2 ;;
    --input)   INPUT_FILE="$2"; shift 2 ;;
    --output-dir) OUTPUT_DIR="$2"; shift 2 ;;
    --dry-run) DRY_RUN=1; shift ;;
    -h|--help)
      sed -n '2,50p' "$0" | sed 's/^# \{0,1\}//'
      exit 0 ;;
    *) echo "unknown arg: $1" >&2; exit 1 ;;
  esac
done

# Default input path — one per network so mainnet vs testnet stays
# organised.
if [ -z "$INPUT_FILE" ]; then
  INPUT_FILE="$REPO_ROOT/deploy/faucet-registry/${NETWORK}.json"
fi

case "$NETWORK" in
  testnet|mainnet|regtest) ;;
  *) echo "ERROR: --network must be one of testnet|mainnet|regtest (got: $NETWORK)" >&2; exit 1 ;;
esac

# ── preflight ───────────────────────────────────────────────────────
if [ ! -f "$INPUT_FILE" ]; then
  echo "ERROR: input file not found: $INPUT_FILE" >&2
  echo "" >&2
  echo "Create it with the schema below. See" >&2
  echo "docs/operations/runbook-faucet-registry.md for the ceremony." >&2
  echo "" >&2
  cat <<'SCHEMA' >&2
{
  "schema_version": 1,
  "network": "testnet",
  "faucets": [
    {
      "name": "fleet-testnet-primary",
      "url": "https://faucet.coincync.network",
      "operator": "fleet",
      "description": "Canonical fleet-run testnet faucet.",
      "drip_amount_atomic": 10000000000000,
      "network": "testnet",
      "last_seen": 1751600000
    }
  ]
}
SCHEMA
  exit 1
fi

command -v jq >/dev/null || { echo "ERROR: jq required" >&2; exit 1; }

# Verify the input parses as JSON, has the right network + schema
# version, and every entry has the required fields.
INPUT_JSON="$(cat "$INPUT_FILE")"

if ! echo "$INPUT_JSON" | jq . >/dev/null 2>&1; then
  echo "ERROR: input file is not valid JSON" >&2
  exit 1
fi

INPUT_NETWORK="$(echo "$INPUT_JSON" | jq -r '.network // ""')"
INPUT_SCHEMA="$(echo "$INPUT_JSON" | jq -r '.schema_version // 0')"

if [ "$INPUT_NETWORK" != "$NETWORK" ]; then
  echo "ERROR: input file network=\"$INPUT_NETWORK\" != --network=\"$NETWORK\"" >&2
  exit 1
fi
if [ "$INPUT_SCHEMA" != "1" ]; then
  echo "ERROR: input schema_version must be 1 (got $INPUT_SCHEMA)" >&2
  exit 1
fi

ENTRY_COUNT="$(echo "$INPUT_JSON" | jq '.faucets | length')"
if [ "$ENTRY_COUNT" -lt 1 ]; then
  echo "ERROR: no faucets in input — refusing to publish an empty registry" >&2
  exit 1
fi

# Every entry must have required fields non-null.
BAD_ENTRIES="$(echo "$INPUT_JSON" | jq -r '
  [.faucets[] | select(
    (.name // "") == "" or
    (.url // "") == "" or
    (.operator // "") == "" or
    (.drip_amount_atomic // 0) == 0 or
    (.network // "") == "" or
    (.last_seen // 0) == 0
  )] | length
')"
if [ "$BAD_ENTRIES" != "0" ]; then
  echo "ERROR: $BAD_ENTRIES entries missing required fields" >&2
  echo "(name, url, operator, drip_amount_atomic, network, last_seen must all be set)" >&2
  exit 1
fi

# Every entry's network must match the outer network — catch a
# publisher accidentally listing a mainnet faucet in a testnet
# registry.
MISMATCH_ENTRIES="$(echo "$INPUT_JSON" | jq -r "[.faucets[] | select(.network != \"$NETWORK\")] | length")"
if [ "$MISMATCH_ENTRIES" != "0" ]; then
  echo "ERROR: $MISMATCH_ENTRIES entries have network != \"$NETWORK\"" >&2
  exit 1
fi

echo "==> Input validated"
echo "    network:      $NETWORK"
echo "    schema:       $INPUT_SCHEMA"
echo "    entries:      $ENTRY_COUNT"

# ── stamp unix_ts + canonicalize ───────────────────────────────────
UNIX_TS="$(date -u +%s)"
CANONICAL_JSON="$(echo "$INPUT_JSON" | jq --argjson ts "$UNIX_TS" '
  {
    schema_version: .schema_version,
    network: .network,
    unix_ts: $ts,
    faucets: .faucets
  }
')"

mkdir -p "$OUTPUT_DIR"
CANONICAL_FILE="$OUTPUT_DIR/faucet-registry-${NETWORK}-${UNIX_TS}.json"
echo "$CANONICAL_JSON" > "$CANONICAL_FILE"
echo "    canonical:    $CANONICAL_FILE"
echo "    unix_ts:      $UNIX_TS ($(date -u -d @$UNIX_TS +%FT%TZ 2>/dev/null || date -u -r $UNIX_TS +%FT%TZ 2>/dev/null))"

REGISTRY_SHA="$(sha256sum "$CANONICAL_FILE" | awk '{print $1}')"
echo "    sha256:       $REGISTRY_SHA"

if [ "$DRY_RUN" -eq 1 ]; then
  echo ""
  echo "==> Dry run: canonical JSON written but not signed or published."
  echo "    Ship: --dry-run OFF + COINCYNC_SIGN_SEED_HEX set to publish."
  exit 0
fi

# ── sign ────────────────────────────────────────────────────────────
if [ -z "${COINCYNC_SIGN_SEED_HEX:-}" ]; then
  echo "ERROR: COINCYNC_SIGN_SEED_HEX not set." >&2
  echo "       Load from your offline seed store, e.g.:" >&2
  echo "         export COINCYNC_SIGN_SEED_HEX=\$(cat ~/.coincync-maintainer-seed/testnet-seed.hex)" >&2
  echo "       (Same seed as the peer-snapshot ceremony.)" >&2
  exit 1
fi

SIGN_CLI="$REPO_ROOT/target/release/coincync-sign-snapshot"
if [ ! -x "$SIGN_CLI" ]; then
  # Fall back to a debug build if release isn't available.
  SIGN_CLI="$REPO_ROOT/target/debug/coincync-sign-snapshot"
fi
if [ ! -x "$SIGN_CLI" ]; then
  echo "ERROR: coincync-sign-snapshot binary not found at target/release/ or target/debug/" >&2
  echo "       Build with: cargo build --release --bin coincync-sign-snapshot" >&2
  exit 1
fi

SIGNATURE_FILE="$OUTPUT_DIR/faucet-registry-${NETWORK}-${UNIX_TS}.sig"

# Set the faucet-specific namespace via env var. The
# coincync-sign-snapshot CLI reads COINCYNC_SIGN_NAMESPACE_HEX and
# uses those bytes verbatim as the domain-separator prefix, so this
# signature won't verify as a peer-snapshot (or any other service's
# signature) — matches the FAUCET_REGISTRY_NAMESPACE constant in
# src/network/faucet_registry.rs exactly.
FAUCET_NAMESPACE_HEX="$(printf 'coincync-faucet-registry-v1' | xxd -p -c 64)"
env COINCYNC_SIGN_NAMESPACE_HEX="$FAUCET_NAMESPACE_HEX" \
    "$SIGN_CLI" sign "$COINCYNC_SIGN_SEED_HEX" "$CANONICAL_FILE" "$SIGNATURE_FILE"
echo "    signed:       $SIGNATURE_FILE (namespace: coincync-faucet-registry-v1)"

# ── publish ─────────────────────────────────────────────────────────
if ! curl -sf -X POST -m 5 "$IPFS_API/api/v0/id" >/dev/null 2>&1; then
  if [ -z "${PINATA_TOKEN:-}" ]; then
    echo "ERROR: local IPFS ($IPFS_API) unreachable and no PINATA_TOKEN." >&2
    echo "       Start Kubo (ipfs daemon &) or set PINATA_TOKEN=<jwt>." >&2
    exit 1
  fi
fi

# Add to local Kubo (if reachable). Kubo's add API returns line-per-file
# JSON; grab the Hash field.
REGISTRY_CID=""
SIGNATURE_CID=""

if curl -sf -X POST -m 5 "$IPFS_API/api/v0/id" >/dev/null 2>&1; then
  echo "==> ipfs add via $IPFS_API"
  REGISTRY_CID="$(curl -sf -X POST -F "file=@$CANONICAL_FILE" \
    "$IPFS_API/api/v0/add?pin=true&cid-version=1" \
    | jq -r '.Hash')"
  SIGNATURE_CID="$(curl -sf -X POST -F "file=@$SIGNATURE_FILE" \
    "$IPFS_API/api/v0/add?pin=true&cid-version=1" \
    | jq -r '.Hash')"
fi

# Also pin via Pinata if configured.
if [ -n "${PINATA_TOKEN:-}" ]; then
  echo "==> Pinata pin"
  P_REG="$(curl -sf \
    -H "Authorization: Bearer $PINATA_TOKEN" \
    -F "file=@$CANONICAL_FILE" \
    -F "pinataMetadata={\"name\":\"faucet-registry-${NETWORK}-${UNIX_TS}\"}" \
    "https://api.pinata.cloud/pinning/pinFileToIPFS" \
    | jq -r '.IpfsHash')"
  P_SIG="$(curl -sf \
    -H "Authorization: Bearer $PINATA_TOKEN" \
    -F "file=@$SIGNATURE_FILE" \
    -F "pinataMetadata={\"name\":\"faucet-registry-sig-${NETWORK}-${UNIX_TS}\"}" \
    "https://api.pinata.cloud/pinning/pinFileToIPFS" \
    | jq -r '.IpfsHash')"

  # Prefer local Kubo's CID if both paths returned one; they should
  # match (content-addressed), but if they don't, the local-Kubo CID
  # is canonical.
  REGISTRY_CID="${REGISTRY_CID:-$P_REG}"
  SIGNATURE_CID="${SIGNATURE_CID:-$P_SIG}"

  if [ "$P_REG" != "$REGISTRY_CID" ] || [ "$P_SIG" != "$SIGNATURE_CID" ]; then
    echo "WARN: Pinata CID differs from local Kubo CID." >&2
    echo "      This means the two paths produced different byte-streams." >&2
    echo "      Local: reg=$REGISTRY_CID sig=$SIGNATURE_CID" >&2
    echo "      Pinata: reg=$P_REG sig=$P_SIG" >&2
    echo "      (Content-addressed CIDs should match. Investigate.)" >&2
  fi
fi

if [ -z "$REGISTRY_CID" ] || [ -z "$SIGNATURE_CID" ]; then
  echo "ERROR: publish path produced no CID." >&2
  exit 1
fi

# ── pointer file ────────────────────────────────────────────────────
POINTER_FILE="$OUTPUT_DIR/faucet-registry-latest-${NETWORK}.json"
cat > "$POINTER_FILE" <<POINTER
{
  "schema_version": 1,
  "unix_ts": ${UNIX_TS},
  "payload_cid": "${REGISTRY_CID}",
  "signature_cid": "${SIGNATURE_CID}",
  "source": "publish-faucet-registry.sh",
  "entry_count": ${ENTRY_COUNT}
}
POINTER

echo ""
echo "==> Published faucet registry (${NETWORK})"
echo "    registry CID:  $REGISTRY_CID"
echo "    signature CID: $SIGNATURE_CID"
echo "    entries:       $ENTRY_COUNT"
echo "    unix_ts:       $UNIX_TS"
echo "    sha256:        $REGISTRY_SHA"
echo ""
echo "    Pointer file (upload to well-known URL):"
echo "      $POINTER_FILE"
echo ""
echo "    Consumers (coincync-wallet) fetch this pointer to discover"
echo "    the current faucet directory. See"
echo "    docs/operations/runbook-faucet-registry.md for the ceremony."
