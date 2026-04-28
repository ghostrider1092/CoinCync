#!/usr/bin/env python3
"""
Preflight check for signed bootstrap manifest configuration.

Intended for systemd ExecStartPre (fail-fast before node startup).
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
from pathlib import Path


def fail(msg: str) -> int:
    print(f"[bootstrap-preflight] ERROR: {msg}", file=sys.stderr)
    return 1


def main() -> int:
    manifest = os.environ.get("COINCYNC_BOOTSTRAP_SIGNED_MANIFEST", "").strip()
    pubkey = os.environ.get("COINCYNC_BOOTSTRAP_SIGNING_PUBKEY", "").strip()
    sig = os.environ.get("COINCYNC_BOOTSTRAP_SIGNED_MANIFEST_SIG", "").strip()

    if not manifest:
        return fail("COINCYNC_BOOTSTRAP_SIGNED_MANIFEST is not set")
    if not pubkey:
        return fail("COINCYNC_BOOTSTRAP_SIGNING_PUBKEY is not set")

    manifest_path = Path(manifest)
    if not manifest_path.exists():
        return fail(f"manifest not found: {manifest_path}")

    sig_path = Path(sig) if sig else Path(f"{manifest}.sig")
    if not sig_path.exists():
        return fail(f"signature not found: {sig_path}")

    # Write pubkey to a temporary file so we can use the existing verification tool.
    tmp_pub = manifest_path.parent / ".bootstrap_pubkey.tmp"
    try:
        tmp_pub.write_text(pubkey + "\n", encoding="utf-8")
    except Exception as e:
        return fail(f"unable to write temp pubkey file: {e}")

    # Prefer compiled binary if present; fall back to cargo run.
    exe = shutil.which("bootstrap_manifest_tool")
    if exe:
        cmd = [
            exe,
            "verify",
            "--manifest",
            str(manifest_path),
            "--public-key",
            str(tmp_pub),
            "--signature",
            str(sig_path),
        ]
    else:
        cmd = [
            "cargo",
            "run",
            "--quiet",
            "--bin",
            "bootstrap_manifest_tool",
            "--",
            "verify",
            "--manifest",
            str(manifest_path),
            "--public-key",
            str(tmp_pub),
            "--signature",
            str(sig_path),
        ]

    try:
        proc = subprocess.run(cmd, check=False, capture_output=True, text=True)
    finally:
        try:
            tmp_pub.unlink(missing_ok=True)
        except Exception:
            pass

    if proc.returncode != 0:
        stderr = (proc.stderr or "").strip()
        stdout = (proc.stdout or "").strip()
        detail = stderr or stdout or "verification command failed"
        return fail(f"signature verification failed: {detail}")

    print("[bootstrap-preflight] OK: signed bootstrap manifest verified")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
