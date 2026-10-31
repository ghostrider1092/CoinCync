#!/usr/bin/env bash
# ──────────────────────────────────────────────────────────────────────────
# gen-cli-docs.sh — regenerate docs/CLI_COMMANDS.md from the SOURCE OF TRUTH:
#   • every binary's `--help` (and each subcommand's, recursively) — clap-derived
#   • the cargo/build command surface, generated from Cargo.toml [features], the
#     workspace bins, and the gated feature string read LIVE from the CI workflow
#
# So the reference cannot drift from the code: run it and the doc is current.
# This is a DOC GENERATOR, not a new feature — it only reads help text + manifests.
#
#   Usage:
#     scripts/gen-cli-docs.sh            # use prebuilt target/release binaries
#     scripts/gen-cli-docs.sh --build    # build the gated binaries first, then dump
#
# By default it does NOT build (so it is safe to run while a soak/build holds the
# binaries): it dumps the --help of whatever is already in target/release. The
# shielded `shielded-*` commands only appear if those binaries were built with
# `sketch-gk-proof + libspark-ffi`. Pass --build to force a gated build first
# (do NOT during a chaos soak — it would contend with the soak binaries).
# ──────────────────────────────────────────────────────────────────────────
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

OUT="docs/CLI_COMMANDS.md"
WORKFLOW=".github/workflows/shielded-gate.yml"
DO_BUILD=0
[ "${1:-}" = "--build" ] && DO_BUILD=1

log()   { printf '\e[36m==>\e[0m %s\n' "$*" >&2; }
fatal() { printf '\e[31m[ERR]\e[0m %s\n' "$*" >&2; exit 1; }

# .exe suffix on Windows/Git-Bash, empty elsewhere.
EXE=""; case "$(uname -s 2>/dev/null || echo)" in MINGW*|MSYS*|CYGWIN*) EXE=".exe";; esac
BIN_DIR="target/release"

# The gated feature set — read LIVE from CI so this doc never contradicts the gate.
GATED_FEATURES="$(grep -oE 'GATED_FEATURES: *"[^"]*"' "$WORKFLOW" 2>/dev/null | sed -E 's/.*"([^"]*)".*/\1/' | head -1)"
[ -n "$GATED_FEATURES" ] || GATED_FEATURES="testnet fuse block-integrity-breaker supply-breaker shielded-breaker regtest-chaos sketch-gk-proof libspark-ffi"
HARNESS_FEATURES="randomx $GATED_FEATURES test-fast-pow"

if [ "$DO_BUILD" = "1" ]; then
  log "building gated binaries (coincync-node, coincync-wallet) with: randomx $GATED_FEATURES"
  SPARK_OPENSSL_DIR="${SPARK_OPENSSL_DIR:-/usr}" COINCYNC_RANDOMX_LIGHT_MODE="${COINCYNC_RANDOMX_LIGHT_MODE:-1}" \
    cargo build --release --features "randomx $GATED_FEATURES" --bin coincync-node --bin coincync-wallet
fi

# Resolve each binary to whichever of <name>.exe / <name> is actually on disk, so
# the script works from Git Bash (uname=MINGW, EXE=.exe) AND WSL bash (uname=Linux,
# EXE="" but the Windows .exe is what's present). -f (exists), not -x: the Windows
# executable bit is unreliable under WSL bash.
resolve_bin() {
  if   [ -f "$BIN_DIR/$1.exe" ]; then echo "$BIN_DIR/$1.exe"
  elif [ -f "$BIN_DIR/$1" ];     then echo "$BIN_DIR/$1"
  else echo "$BIN_DIR/$1$EXE"; fi   # non-existent: keep a sensible name for the error
}
NODE="$(resolve_bin coincync-node)"
WALLET="$(resolve_bin coincync-wallet)"
for b in "$NODE" "$WALLET"; do
  [ -f "$b" ] || fatal "missing binary: $b  (build it, or re-run with --build)"
done

# ── helpers ────────────────────────────────────────────────────────────────
# Print `<bin> <args...> --help`, swallowing a nonzero exit (clap returns 0 for
# --help, but be defensive).
help_of() { "$@" --help 2>&1 || true; }

# Extract subcommand names from a clap "Commands:" block: lines indented two
# spaces with a lowercase first token, stopping at the first blank line after the
# header. Excludes the auto `help` subcommand.
subcommands_of() {
  # A command row is: two-space indent + name + two-or-more spaces (the description
  # column), e.g. "  shielded-send   Build + verify ...". Wrapped description
  # continuation lines are indented MUCH deeper, so `^  [name]  ` excludes them.
  # The block ends at the first NON-indented line (the next section header, e.g.
  # "Options:"); blank lines do not end it (clap may wrap long descriptions). This
  # is robust across TTY/width/WSL differences in how clap lays out --help.
  awk '
    /^Commands:/ {inblk=1; next}
    inblk && /^[^ ]/ {exit}                                  # non-indented line ends the block
    inblk && /^  [a-zA-Z0-9][a-zA-Z0-9_-]*([ ]{2,}|[ ]*$)/ { print $1 }
  ' <<<"$1" | grep -vx 'help' || true
}

fence() { printf '```text\n%s\n```\n\n' "$1"; }

# Emit a binary: top-level help, then every subcommand (one level of nesting).
emit_binary() {
  local bin="$1" label="$2"
  printf '## `%s`\n\n' "$label"
  local top; top="$(help_of "$bin")"
  fence "$top"
  local sub
  while IFS= read -r sub; do
    [ -n "$sub" ] || continue
    printf '### `%s %s`\n\n' "$label" "$sub"
    local h; h="$(help_of "$bin" "$sub")"
    fence "$h"
    # one level of nesting (e.g. `wallet treasury watch`)
    local nested
    while IFS= read -r nested; do
      [ -n "$nested" ] || continue
      printf '#### `%s %s %s`\n\n' "$label" "$sub" "$nested"
      fence "$(help_of "$bin" "$sub" "$nested")"
    done < <(subcommands_of "$h")
  done < <(subcommands_of "$top")
}

# List workspace features from the root Cargo.toml [features] table (name = ...).
features_table() {
  awk '
    /^\[features\]/ {f=1; next}
    f && /^\[/ {exit}
    f && /^[a-zA-Z0-9_-]+[ ]*=/ {
      name=$1;
      line=$0; sub(/^[^=]*=[ ]*/,"",line);
      printf "| `%s` | `%s` |\n", name, line
    }
  ' Cargo.toml
}

# List buildable workspace bins: root bins under src/bin + each crate package.
bins_list() {
  echo "- \`coincync-node\`, \`coincync-wallet\` (root package bins)"
  echo "- root helper bins: $(ls src/bin/*.rs 2>/dev/null | sed 's#.*/##; s/\.rs$//' | grep -v '^wallet$\|^node$' | sed 's/^/`/; s/$/`/' | paste -sd',' - | sed 's/,/, /g')"
  echo "- workspace crates (\`-p <name>\`): $(ls crates 2>/dev/null | sed 's/^/`/; s/$/`/' | paste -sd',' - | sed 's/,/, /g')"
}

# ── write the doc ────────────────────────────────────────────────────────────
log "writing $OUT"
{
  cat <<EOF
<!-- GENERATED by scripts/gen-cli-docs.sh — DO NOT EDIT BY HAND. Re-run the
     script to refresh. Curated recipes live in docs/COMMANDS.md. -->
# CoinCync CLI — generated command reference

Generated $(date -u +%Y-%m-%dT%H:%M:%SZ) from the \`--help\` of the built
binaries plus the cargo surface (features, bins, and the CI gated feature set).
This file is **auto-generated** — edit the code or the generator, not this file.
For hand-written recipes see [\`COMMANDS.md\`](COMMANDS.md); for build/test/deploy
see [\`DEVELOPER.md\`](DEVELOPER.md).

> **Gated commands.** The \`shielded-*\` wallet commands exist only in a build with
> \`sketch-gk-proof + libspark-ffi\`. If they are absent below, the dumped binary
> was a stock build; re-run with \`--build\` (off a chaos soak) to include them.

---

EOF

  emit_binary "$NODE" "coincync-node"
  emit_binary "$WALLET" "coincync-wallet"

  cat <<EOF
---

## Cargo / build command surface

The gated feature set is read live from \`$WORKFLOW\` so it always matches CI:

\`\`\`text
GATED_FEATURES = $GATED_FEATURES
\`\`\`

### Canonical recipes

\`\`\`bash
# Standard release build (ring-privacy chain, shielded OFF)
cargo build --release --features "randomx testnet"

# Gated CORRECTNESS suite — the 2400/0 bar. NEVER with test-fast-pow.
SPARK_OPENSSL_DIR=/usr COINCYNC_RANDOMX_LIGHT_MODE=1 \\
  cargo test --release --lib --features "$GATED_FEATURES"

# Gated integration + lock-integrity check (what CI runs)
cargo test  --release --features "$GATED_FEATURES" --test full_pipeline_real_crypto
cargo check --release --features "$GATED_FEATURES"        # runs build.rs lock guard

# Chaos HARNESS binaries — WITH test-fast-pow (instant mining). Harness only,
# never a correctness build (test-fast-pow skips real PoW).
cargo build --release --features "$HARNESS_FEATURES" --bin coincync-node --bin coincync-wallet

# Regenerate critical_files.lock after a reviewed change to a locked file
COINCYNC_REGEN_LOCK=1 cargo run --locked --release --bin update-critical-hashes

# Per-crate (rig miner shown; swap -p for any crate below)
cargo build --release -p coincync-rig

# Regenerate THIS doc
scripts/gen-cli-docs.sh            # dump prebuilt binaries
scripts/gen-cli-docs.sh --build    # build gated binaries first (NOT during a soak)
\`\`\`

> Windows/WSL build env (clang + static OpenSSL for libspark) is documented in
> [\`DEVELOPER.md\`](DEVELOPER.md) — \`LIBCLANG_PATH\`, \`SPARK_OPENSSL_DIR\`,
> \`CARGO_INCREMENTAL=0\`, \`RUST_MIN_STACK\`.

### Buildable targets

EOF
  bins_list
  cat <<EOF

### Feature flags (root \`Cargo.toml\`)

| Feature | Definition |
| --- | --- |
EOF
  features_table
} > "$OUT.tmp"

# Safety guard: a degraded run (e.g. a shell where clap --help parsing misfires)
# must never clobber the good doc. Require a plausible number of command sections.
SECTIONS="$(grep -cE '^### ' "$OUT.tmp" || true)"
MIN_SECTIONS=30
if [ "${SECTIONS:-0}" -lt "$MIN_SECTIONS" ]; then
  rm -f "$OUT.tmp"
  fatal "degraded output: only ${SECTIONS} command sections (< ${MIN_SECTIONS}). Kept existing ${OUT} unchanged. Re-run under Git Bash (e.g. \"C:\\Program Files\\Git\\bin\\bash.exe\" scripts/gen-cli-docs.sh)."
fi
mv -f "$OUT.tmp" "$OUT"
log "done → $OUT ($(wc -l < "$OUT") lines, ${SECTIONS} command sections)"
