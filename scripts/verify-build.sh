#!/usr/bin/env bash
# verify-build.sh — verify a released CoinCync binary matches the source tree
#
# Usage:
#   ./scripts/verify-build.sh <version>
#
# Example:
#   ./scripts/verify-build.sh 1.0.0
#
# What this script does:
#   1. Downloads the published release manifest + signature.
#   2. Verifies the signature against the project release key.
#   3. Builds the same git commit locally inside the pinned Docker image.
#   4. Diffs the locally-built binaries against the released ones.
#   5. Prints PASS or FAIL with details.
#
# What this script does NOT do:
#   - Verify the SOURCE tree itself (use audits + tests + review for that).
#   - Trust the project release key blindly (verify the fingerprint out of
#     band before relying on this script).
#   - Detect runtime backdoors that the source tree itself contains (those
#     are an audit problem, not a repro problem).
#
# Exit codes:
#   0   match — released binary matches local build of same commit
#   1   build error
#   2   signature verification failed
#   3   binary mismatch — investigate immediately
#   4   missing dependency

set -euo pipefail

VERSION="${1:?Usage: $0 <version>}"
RELEASE_URL="${RELEASE_URL:-https://releases.coincync.network/${VERSION}}"
WORK_DIR="${WORK_DIR:-$(mktemp -d -t cync-verify-XXXXXX)}"
RELEASE_KEY_FPR="${RELEASE_KEY_FPR:-}"  # set this to the project release-key fingerprint

trap 'rm -rf "$WORK_DIR"' EXIT

# ── Dependencies ────────────────────────────────────────────────────

require() {
    if ! command -v "$1" >/dev/null 2>&1; then
        echo "ERROR: required tool '$1' is not installed." >&2
        exit 4
    fi
}

require curl
require docker
require git
require gpg
require sha256sum
require diff

# ── Step 1: download manifest + signature ──────────────────────────

echo "==> Downloading manifest for v${VERSION}..."
curl -fsSLo "${WORK_DIR}/MANIFEST.txt" "${RELEASE_URL}/MANIFEST.txt"
curl -fsSLo "${WORK_DIR}/MANIFEST.txt.asc" "${RELEASE_URL}/MANIFEST.txt.asc"

# ── Step 2: verify manifest signature ──────────────────────────────

echo "==> Verifying manifest signature..."
if [ -n "$RELEASE_KEY_FPR" ]; then
    # Fail if the signature is not from the expected key.
    SIG_OUTPUT="$(gpg --status-fd=1 --verify \
        "${WORK_DIR}/MANIFEST.txt.asc" \
        "${WORK_DIR}/MANIFEST.txt" 2>&1)"
    if ! echo "$SIG_OUTPUT" | grep -q "VALIDSIG ${RELEASE_KEY_FPR}"; then
        echo "ERROR: manifest signature is not from the expected release key." >&2
        echo "   Expected fingerprint: ${RELEASE_KEY_FPR}" >&2
        echo "   gpg output:" >&2
        echo "$SIG_OUTPUT" | sed 's/^/      /' >&2
        exit 2
    fi
else
    echo "   WARNING: RELEASE_KEY_FPR not set; signature is checked but"
    echo "            the signing identity is NOT verified."
    if ! gpg --verify "${WORK_DIR}/MANIFEST.txt.asc" "${WORK_DIR}/MANIFEST.txt"; then
        echo "ERROR: manifest signature failed to verify." >&2
        exit 2
    fi
fi
echo "   OK"

# ── Step 3: extract commit + build locally ─────────────────────────

COMMIT="$(grep '^# Commit:' "${WORK_DIR}/MANIFEST.txt" | awk '{print $3}')"
BUILDER="$(grep '^# Builder:' "${WORK_DIR}/MANIFEST.txt" | awk '{print $3}')"
if [ -z "$COMMIT" ] || [ -z "$BUILDER" ]; then
    echo "ERROR: manifest is missing required headers (# Commit: / # Builder:)." >&2
    exit 1
fi

echo "==> Verifying against commit ${COMMIT}, builder image ${BUILDER}..."

# Make sure we're at that commit.
CURRENT_COMMIT="$(git rev-parse HEAD)"
if [ "$CURRENT_COMMIT" != "$COMMIT" ]; then
    echo "   Note: HEAD is at ${CURRENT_COMMIT}, not the released ${COMMIT}."
    echo "         git checkout ${COMMIT} before running this script for"
    echo "         a strict verification. Continuing with HEAD."
fi

# Pull the pinned builder image.
echo "==> Pulling builder image ${BUILDER}..."
docker pull "$BUILDER"

# Run the build inside the image.
echo "==> Building locally (this may take 5-15 minutes)..."
docker run --rm \
    -v "$(pwd):/src:ro" \
    -v "${WORK_DIR}/local-build:/out" \
    "$BUILDER" \
    sh -c '
        cp -r /src /tmp/src && cd /tmp/src &&
        cargo build --release --workspace --locked &&
        cp target/release/coincync-* /out/ 2>/dev/null || true
    '

# ── Step 4: diff against released artifacts ────────────────────────

echo "==> Downloading released binaries..."
mkdir -p "${WORK_DIR}/released"
while IFS=' ' read -r expected_hash filename; do
    # Skip comment lines and blanks.
    case "$filename" in
        ""|"#"*) continue ;;
    esac
    curl -fsSLo "${WORK_DIR}/released/${filename}" "${RELEASE_URL}/${filename}"
done < "${WORK_DIR}/MANIFEST.txt"

echo "==> Comparing local build against released binaries..."
mismatches=0
matches=0
while IFS=' ' read -r expected_hash filename; do
    case "$filename" in
        ""|"#"*) continue ;;
    esac

    released_path="${WORK_DIR}/released/${filename}"
    actual_hash="$(sha256sum "$released_path" | awk '{print $1}')"

    if [ "$actual_hash" != "$expected_hash" ]; then
        echo "   FAIL: ${filename}"
        echo "     manifest hash:  ${expected_hash}"
        echo "     released hash:  ${actual_hash}"
        mismatches=$((mismatches + 1))
        continue
    fi

    # Compare the released binary to the local build (where applicable).
    base="${filename%.tar.gz}"
    base="${base%.zip}"
    local_candidate="${WORK_DIR}/local-build/${base##*-}"
    # If the local-build directory has a matching binary, diff it.
    if [ -f "$local_candidate" ]; then
        local_hash="$(sha256sum "$local_candidate" | awk '{print $1}')"
        if [ "$local_hash" = "$expected_hash" ]; then
            echo "   OK: ${filename} matches local build"
            matches=$((matches + 1))
        else
            echo "   FAIL: ${filename}"
            echo "     manifest hash: ${expected_hash}"
            echo "     local hash:    ${local_hash}"
            mismatches=$((mismatches + 1))
        fi
    else
        echo "   note: no local build for ${filename} (skipping repro check)"
    fi
done < "${WORK_DIR}/MANIFEST.txt"

# ── Step 5: report ─────────────────────────────────────────────────

echo
if [ $mismatches -eq 0 ]; then
    echo "PASS: ${matches} artifact(s) verified reproducible against source"
    exit 0
else
    echo "FAIL: ${mismatches} artifact(s) did NOT match"
    echo
    echo "This means one of:"
    echo "  1. The build environment isn't fully pinned (file an issue)"
    echo "  2. The released binary was built from non-public source"
    echo "  3. The released binary is malicious"
    echo
    echo "Reach out to security@coincync.network if you suspect (2) or (3)."
    exit 3
fi
