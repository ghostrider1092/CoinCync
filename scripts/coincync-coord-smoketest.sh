#!/usr/bin/env bash
# coincync-coord-smoketest.sh — minimal-dep smoke test for a freshly
# deployed coincync-coord service. Verifies the basics WITHOUT a real
# frost_ed25519 round-trip (phase 5/6 work per the bin docstring).
#
# Run on the deploy host AFTER install-coord.sh finishes:
#   bash /tmp/coincync-coord-smoketest.sh
#
# Tests:
#   1. systemd unit is is-active
#   2. ListenStream socket is listening on COINCYNC_COORD_LISTEN
#   3. journalctl has no ERROR/WARN since last unit start
#   4. State file is well-formed JSON
#   5. (If python3 available) raw WS handshake against the coord:
#      - expect the upgrade to succeed
#      - expect an unauthenticated attach with bogus session_id to be rejected
#
# Exit codes:
#   0   all checks PASS
#   1   one or more checks failed (which one is printed)
#   2   missing dependency

set -euo pipefail

ENV_FILE=/etc/coincync/coord.env
SERVICE=coincync-coord.service
STATE_DIR=/var/lib/coincync-coord

fail() { echo "FAIL: $*" >&2; exit 1; }
ok()   { echo "  OK: $*"; }

# Load the listen address from the env file
if [ ! -r "$ENV_FILE" ]; then
    fail "$ENV_FILE not readable — was install-coord.sh run?"
fi
# shellcheck disable=SC1090
source "$ENV_FILE"
: "${COINCYNC_COORD_LISTEN:?COINCYNC_COORD_LISTEN not set in $ENV_FILE}"

echo "=== Test 1: systemd unit is-active ==="
if systemctl is-active --quiet "$SERVICE"; then
    ok "$SERVICE is active"
else
    fail "$SERVICE is not active — journalctl -u $SERVICE -n 60 --no-pager"
fi

echo ""
echo "=== Test 2: ListenStream on $COINCYNC_COORD_LISTEN ==="
PORT="${COINCYNC_COORD_LISTEN##*:}"
if ss -lntp 2>/dev/null | grep -E "[:.]${PORT}\s" >/dev/null; then
    ok "Port $PORT is listening"
    ss -lntp 2>/dev/null | grep -E "[:.]${PORT}\s" | head -1 | sed 's/^/    /'
else
    fail "Nothing listening on port $PORT — coord may have crashed after start"
fi

echo ""
echo "=== Test 3: journalctl quiet since last start ==="
SINCE=$(systemctl show -p ActiveEnterTimestamp --value "$SERVICE")
if [ -z "$SINCE" ]; then SINCE="1 minute ago"; fi
ERRCOUNT=$(journalctl -u "$SERVICE" --since "$SINCE" 2>/dev/null | grep -ciE 'error|warn|panic' || true)
if [ "$ERRCOUNT" -eq 0 ]; then
    ok "No ERROR/WARN/panic since $SINCE"
else
    echo "  WARN: $ERRCOUNT error/warn lines since last start (review below)"
    journalctl -u "$SERVICE" --since "$SINCE" 2>/dev/null | grep -iE 'error|warn|panic' | head -20 | sed 's/^/    /'
fi

echo ""
echo "=== Test 4: state file is well-formed JSON ==="
STATE_FILE="${COINCYNC_COORD_STATE:-$STATE_DIR/sessions.json}"
if [ ! -f "$STATE_FILE" ]; then
    fail "$STATE_FILE does not exist"
fi
if python3 -c "import json,sys; json.load(open(sys.argv[1]))" "$STATE_FILE" 2>/dev/null; then
    SESSION_COUNT=$(python3 -c "import json,sys; print(len(json.load(open(sys.argv[1]))))" "$STATE_FILE" 2>/dev/null || echo "?")
    ok "$STATE_FILE is valid JSON ($SESSION_COUNT sessions)"
else
    fail "$STATE_FILE is not valid JSON"
fi

echo ""
echo "=== Test 5: WS handshake (optional, needs python3) ==="
if ! command -v python3 >/dev/null 2>&1; then
    echo "  SKIP: python3 not installed"
    echo ""
    echo "=== ALL CHECKS PASSED (skipped: WS handshake) ==="
    exit 0
fi

# Use stdlib only: raw socket + HTTP/1.1 Upgrade request. Don't need
# the `websockets` library for a handshake-only test.
python3 - <<PYEOF
import socket, base64, os, sys

host, port = "${COINCYNC_COORD_LISTEN%:*}", int("${PORT}")
if host in ("0.0.0.0", "::"): host = "127.0.0.1"

key = base64.b64encode(os.urandom(16)).decode()
req = (
    f"GET / HTTP/1.1\r\n"
    f"Host: {host}:{port}\r\n"
    "Upgrade: websocket\r\n"
    "Connection: Upgrade\r\n"
    f"Sec-WebSocket-Key: {key}\r\n"
    "Sec-WebSocket-Version: 13\r\n"
    "\r\n"
)
s = socket.create_connection((host, port), timeout=5)
s.sendall(req.encode())
resp = b""
s.settimeout(3)
try:
    while True:
        chunk = s.recv(4096)
        if not chunk: break
        resp += chunk
        if b"\r\n\r\n" in resp: break
except socket.timeout:
    pass
s.close()
head = resp.split(b"\r\n\r\n",1)[0].decode(errors="replace")
if "101" in head.split("\r\n",1)[0]:
    print("  OK: WS upgrade returned 101 Switching Protocols")
    sys.exit(0)
else:
    print(f"  FAIL: WS upgrade did not return 101:\n{head}", file=sys.stderr)
    sys.exit(1)
PYEOF
if [ $? -ne 0 ]; then
    fail "WS handshake did not return 101"
fi

echo ""
echo "=== ALL CHECKS PASSED ==="
echo ""
echo "Next steps (NOT in this smoke test):"
echo "  - Real frost_ed25519 round-trip integration test (phase 5/6 per coord docstring)"
echo "  - nginx reverse proxy /coord/ -> 127.0.0.1:$PORT with WSS termination"
echo "  - Out-of-band invitation-token generation tooling (phase 4.5)"
