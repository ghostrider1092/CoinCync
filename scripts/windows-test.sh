#!/usr/bin/env bash
# ──────────────────────────────────────────────────────────────────────
# scripts/windows-test.sh — parallel-test workaround for Windows
# ──────────────────────────────────────────────────────────────────────
#
# The symptom:
#
#   cargo test -p coincync             # on native Windows / MSVC
#
# fails partway through with:
#
#   error: crate `librocksdb_sys` required to be available in rlib
#   format, but was not found in this form
#
# Running individual integration test binaries one-at-a-time works,
# `cargo test --lib -p coincync` works, and Linux / macOS are
# unaffected.
#
# ROOT CAUSE:
#
# The failure is a **parallel-link race**, not a code bug. When
# `cargo test -p coincync` runs, cargo builds ~12 integration test
# binaries, and every one of them statically links `librocksdb_sys`.
# Cargo defaults to parallelism = NUM_CPUS, so several of those final
# link steps run at the same moment. Each rustc invocation opens
# `target/<profile>/deps/liblibrocksdb_sys-<hash>.rlib` as a static
# archive to pull symbols out of. On Windows, the file-sharing
# semantics for static-archive reads are strict enough that a second
# reader occasionally sees a truncated / partially-written view of
# the archive — especially because librocksdb_sys is ~80 MB and the
# OS disk cache has to spill to disk mid-read.
#
# This was previously misdiagnosed as a OneDrive sync race. That was
# wrong: relocating `CARGO_TARGET_DIR` to `%LOCALAPPDATA%\coincync-target`
# (completely outside any sync daemon) does NOT fix the race. The
# real fix is to serialize the link phase.
#
# THE FIX (used by this script):
#
#   cargo test -p coincync --jobs 1
#
# `--jobs 1` tells cargo to build one target at a time. Compilation
# of dependencies is slower end-to-end (because rustc can't parallelize
# across crates), but the rlib-read race cannot happen because there
# is only ever one reader at a time. Test execution itself is still
# parallel under the Rust test harness — `--jobs` affects the build,
# not the runner.
#
# This script also (still) relocates `CARGO_TARGET_DIR` off OneDrive
# by default, because keeping build artifacts out of sync daemons is
# a separate correctness win (faster IO, fewer spurious reindexes)
# even though it isn't what was causing the specific librocksdb_sys
# failure.
#
# Usage:
#
#   scripts/windows-test.sh                       # full suite, serial build
#   scripts/windows-test.sh --test wallet_roundtrip   # one integration test
#   scripts/windows-test.sh --lib                 # library tests only
#   CARGO_TARGET_DIR=/d/build scripts/windows-test.sh    # override target
#   COINCYNC_SERIAL_BUILD=0 scripts/windows-test.sh      # disable --jobs 1
#                                                       # (only use this on Linux/macOS
#                                                       # where the race does not occur)
#
# Linux and macOS can invoke this script too — it is a no-op on
# non-Windows (no target relocation, no --jobs 1 forced).

set -euo pipefail

# ── Figure out whether we're on Windows ─────────────────────────────
is_windows() {
    case "$(uname -s 2>/dev/null || echo unknown)" in
        MINGW*|MSYS*|CYGWIN*|Windows_NT) return 0 ;;
        *) return 1 ;;
    esac
}

# ── Pick a non-OneDrive target dir if the caller didn't set one ────
choose_target_dir() {
    if [ -n "${CARGO_TARGET_DIR:-}" ]; then
        echo "${CARGO_TARGET_DIR}"
        return
    fi

    if is_windows; then
        local lad="${LOCALAPPDATA:-}"
        if [ -z "$lad" ]; then
            lad="${HOME}/AppData/Local"
        fi
        lad="$(echo "$lad" | tr '\\' '/')"
        echo "${lad}/coincync-target"
    else
        echo ""
    fi
}

target_dir="$(choose_target_dir)"

if [ -n "$target_dir" ]; then
    mkdir -p "$target_dir"
    export CARGO_TARGET_DIR="$target_dir"
    printf 'using CARGO_TARGET_DIR=%s\n' "$CARGO_TARGET_DIR" >&2
fi

# ── Decide whether to force serial build ────────────────────────────
#
# On Windows we force `--jobs 1` by default to avoid the parallel-link
# rlib race on librocksdb_sys. Users who know what they're doing can
# disable this with `COINCYNC_SERIAL_BUILD=0`, but they really should
# not on a Windows host.
jobs_arg=()
if is_windows && [ "${COINCYNC_SERIAL_BUILD:-1}" != "0" ]; then
    jobs_arg=(--jobs 1)
    printf 'serializing build with --jobs 1 (librocksdb_sys parallel-link race workaround)\n' >&2
fi

# ── Run cargo test -p coincync with whatever args the caller passed ─
exec cargo test -p coincync "${jobs_arg[@]}" "$@"
