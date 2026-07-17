#!/usr/bin/env python3
"""
CI guardrails for insecure defaults on critical surfaces.
"""

from __future__ import annotations

import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def read(rel: str) -> str:
    return (ROOT / rel).read_text(encoding="utf-8")


def main() -> int:
    failures: list[str] = []

    stratum = read("src/mining/stratum.rs")
    if "COINCYNC_STRATUM_PUBLIC_BIND" not in stratum:
        failures.append("src/mining/stratum.rs missing COINCYNC_STRATUM_PUBLIC_BIND safety gate")
    if "COINCYNC_STRATUM_PUBLIC_BIND_ACK" not in stratum:
        failures.append("src/mining/stratum.rs missing COINCYNC_STRATUM_PUBLIC_BIND_ACK guard")
    if "COINCYNC_STRATUM_PASSWORD" not in stratum:
        failures.append("src/mining/stratum.rs should enforce COINCYNC_STRATUM_PASSWORD on public bind")
    if "\"127.0.0.1:3333\"" not in stratum:
        failures.append("src/mining/stratum.rs should keep loopback default bind")

    faucet = read("scripts/faucet.py")
    if "faucet123" in faucet:
        failures.append("scripts/faucet.py contains insecure default password")
    if "COINCYNC_FAUCET_PASSWORD" not in faucet:
        failures.append("scripts/faucet.py must require COINCYNC_FAUCET_PASSWORD")
    if "COINCYNC_FAUCET_BIND" not in faucet or "127.0.0.1" not in faucet:
        failures.append("scripts/faucet.py must default bind to loopback")

    explorer_manifest = ROOT / "src/explorer/index.parts"
    explorer_parts = [
        read(f"src/explorer/{entry}")
        for raw in explorer_manifest.read_text(encoding="utf-8").splitlines()
        if (entry := raw.strip()) and not entry.startswith("#")
    ]
    explorer_parts.extend(
        path.read_text(encoding="utf-8")
        for path in sorted((ROOT / "src/explorer/app").glob("*.js"))
    )
    explorer = "".join(explorer_parts)
    if "allow_remote_crypto" not in explorer:
        failures.append("explorer sources must gate remote crypto import behind explicit opt-in")
    if "enable_browser_wallet" not in explorer:
        failures.append("explorer sources must gate browser wallet generation behind explicit dev opt-in")
    if "window.location.hostname === 'localhost'" not in explorer:
        failures.append("explorer sources should restrict browser wallet generation to localhost")
    if "dev_explorer" not in explorer:
        failures.append("explorer sources must gate non-core explorer pages behind explicit dev_explorer opt-in")

    dev_server = read("src/explorer/serve.py")
    if "COINCYNC_EXPLORER_DEV_PROXY" not in dev_server:
        failures.append("src/explorer/serve.py must gate proxy mode behind COINCYNC_EXPLORER_DEV_PROXY")
    if "COINCYNC_EXPLORER_RPC" not in dev_server:
        failures.append("src/explorer/serve.py must use configurable LOCAL RPC upstream")

    bootstrap = read("src/network/bootstrap.rs")
    if "COINCYNC_BOOTSTRAP_DISABLE_DNS" not in bootstrap:
        failures.append("src/network/bootstrap.rs should support DNS disable safety knob")
    if "COINCYNC_BOOTSTRAP_SEED_ALLOWLIST" not in bootstrap:
        failures.append("src/network/bootstrap.rs should support seed allowlist guard")
    if "COINCYNC_BOOTSTRAP_SIGNED_MANIFEST" not in bootstrap:
        failures.append("src/network/bootstrap.rs should support signed manifest bootstrap source")
    if "COINCYNC_BOOTSTRAP_SIGNING_PUBKEY" not in bootstrap:
        failures.append("src/network/bootstrap.rs should require explicit signing pubkey for manifest verification")
    if "COINCYNC_BOOTSTRAP_MANIFEST_ONLY" not in bootstrap:
        failures.append("src/network/bootstrap.rs should support manifest-only bootstrap mode")

    preflight = read("scripts/preflight_bootstrap_manifest.py")
    if "COINCYNC_BOOTSTRAP_SIGNED_MANIFEST" not in preflight:
        failures.append("scripts/preflight_bootstrap_manifest.py must validate manifest env var")
    if "COINCYNC_BOOTSTRAP_SIGNING_PUBKEY" not in preflight:
        failures.append("scripts/preflight_bootstrap_manifest.py must validate signing pubkey env var")

    rpc_server = read("src/rpc/server.rs")
    if "rpc_auth_enabled" not in rpc_server:
        failures.append("src/rpc/server.rs should expose rpc_auth_enabled in info responses for operator verification")
    if "metadata_minimized" not in rpc_server:
        failures.append("src/rpc/server.rs should expose metadata_minimized runtime posture in info responses")

    if failures:
        print("Insecure default checks failed:", file=sys.stderr)
        for f in failures:
            print(f" - {f}", file=sys.stderr)
        return 1

    print("Insecure default checks passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
