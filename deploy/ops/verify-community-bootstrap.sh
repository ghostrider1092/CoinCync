#!/usr/bin/env bash
# Verify public testnet bootstrap: DNS seeds resolve and hardcoded P2P seeds accept TCP.
# Run from repo root (or any directory if COINCYNC_REPO_ROOT is set).
#
# COINCYNC_STRICT_TCP=1 — require every hardcoded seed to accept TCP (strict audit).
# Default — DNS must resolve; at least one seed must accept TCP (matches PowerShell script).
set -euo pipefail

ROOT="${COINCYNC_REPO_ROOT:-$(cd "$(dirname "$0")/../.." && pwd)}"
TESTNET_RS="$ROOT/src/testnet.rs"
P2P_PORT="${COINCYNC_P2P_PORT:-28080}"
STRICT_TCP="${COINCYNC_STRICT_TCP:-0}"

if [[ ! -f "$TESTNET_RS" ]]; then
  echo "error=missing_file path=$TESTNET_RS"
  exit 2
fi

echo "repo=$ROOT"
echo "p2p_port=$P2P_PORT"
echo "strict_tcp=$STRICT_TCP"

fail=0
tcp_ok=0
tcp_fail=0

tcp_probe() {
  local host="$1" port="$2"
  if command -v nc >/dev/null 2>&1; then
    if nc -z -w 4 "$host" "$port" >/dev/null 2>&1; then
      echo "tcp_ok=$host:$port"
      return 0
    fi
  elif timeout 4 bash -c "echo >/dev/tcp/$host/$port" >/dev/null 2>&1; then
    echo "tcp_ok=$host:$port"
    return 0
  fi
  echo "tcp_fail=$host:$port"
  return 1
}

echo "--- dns_seeds (resolve) ---"
while IFS= read -r name; do
  [[ -z "$name" ]] && continue
  if command -v dig >/dev/null 2>&1; then
    if dig +short "$name" A | grep -qE '^[0-9.]+\s*$'; then
      echo "dns_ok=$name -> $(dig +short "$name" A | tr '\n' ' ')"
    else
      echo "dns_warn=$name (no A record from dig; may still work via other paths)"
      fail=1
    fi
  else
    echo "dns_skip=$name (install dig: bind-dnsutils / bind-tools)"
  fi
done < <(sed -n '/TESTNET_DNS_SEEDS/,/];/p' "$TESTNET_RS" | grep -oE '"[^"]+"' | tr -d '"' | grep '\.')

echo "--- hardcoded_seed_p2p (tcp $P2P_PORT) ---"
while IFS= read -r ep; do
  [[ -z "$ep" ]] && continue
  host="${ep%%:*}"
  port="${ep##*:}"
  if [[ "$port" != "$P2P_PORT" ]]; then
    echo "warn=unexpected_port endpoint=$ep"
  fi
  if tcp_probe "$host" "$port"; then
    tcp_ok=$((tcp_ok + 1))
  else
    tcp_fail=$((tcp_fail + 1))
  fi
done < <(sed -n '/TESTNET_SEED_NODES/,/];/p' "$TESTNET_RS" | grep -oE '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+:'"${P2P_PORT}")

if [[ "$tcp_ok" -eq 0 ]]; then
  echo "result=FAIL no_tcp_path (open inbound P2P $P2P_PORT on at least one seed)"
  exit 1
fi
if [[ "$STRICT_TCP" == "1" ]] && [[ "$tcp_fail" -gt 0 ]]; then
  echo "result=FAIL strict_tcp ($tcp_fail hosts unreachable)"
  exit 1
fi
if [[ "$tcp_fail" -gt 0 ]]; then
  echo "note=some_tcp_failed $tcp_fail/$((tcp_ok + tcp_fail)) (often firewall; DNS bootstrap may still work)"
fi

if [[ "$fail" -ne 0 ]]; then
  echo "result=FAIL (fix DNS seeds; see deploy/ops/README.md)"
  exit 1
fi

echo "result=OK"
exit 0
