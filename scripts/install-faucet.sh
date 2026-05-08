#!/bin/bash
# install-faucet.sh — provision the coincync-faucet service on the
# api box. Run as root, with the staged binaries already at:
#   /tmp/coincync-faucet
#   /tmp/coincync-wallet
#
# Steps:
#   1. Move binaries into /usr/local/bin
#   2. Create coincync user + faucet data dir
#   3. Create the hot wallet (or skip if already provisioned)
#   4. Generate /etc/coincync/faucet.env with random password
#   5. Install + start the systemd unit
#   6. Add nginx route /faucet -> 127.0.0.1:8082 with CORS-friendly proxy
#   7. Reload nginx
#   8. Print the hot wallet's address so the operator can fund it
#
# Idempotent: re-running is safe and won't reset an already-funded wallet.

set -euo pipefail

FAUCET_BIN_SRC=${FAUCET_BIN_SRC:-/tmp/coincync-faucet}
WALLET_BIN_SRC=${WALLET_BIN_SRC:-/tmp/coincync-wallet}

FAUCET_BIN_DST=/usr/local/bin/coincync-faucet
WALLET_BIN_DST=/usr/local/bin/coincync-wallet

DATA_DIR=/var/lib/coincync/faucet
ENV_DIR=/etc/coincync
ENV_FILE=$ENV_DIR/faucet.env
WALLET_FILE=$DATA_DIR/hot.wallet
SEED_FILE=$DATA_DIR/hot.wallet.seed
SYSTEMD_UNIT=/etc/systemd/system/coincync-faucet.service
NGINX_SNIPPET=/etc/nginx/conf.d/coincync-faucet.conf
LISTEN_PORT=${LISTEN_PORT:-8082}
NETWORK=${NETWORK:-testnet}

log() { echo "==> $*"; }

# ── 1. binaries ─────────────────────────────────────────────────────
log "installing binaries"
[ -f "$FAUCET_BIN_SRC" ] || { echo "ERROR: $FAUCET_BIN_SRC missing"; exit 1; }
[ -f "$WALLET_BIN_SRC" ] || { echo "ERROR: $WALLET_BIN_SRC missing"; exit 1; }
install -m 0755 -o root -g root "$FAUCET_BIN_SRC" "$FAUCET_BIN_DST"
install -m 0755 -o root -g root "$WALLET_BIN_SRC" "$WALLET_BIN_DST"

# ── 2. data dir ─────────────────────────────────────────────────────
log "preparing $DATA_DIR"
mkdir -p "$DATA_DIR" "$ENV_DIR"
chown -R root:root "$DATA_DIR" "$ENV_DIR"
chmod 0755 "$ENV_DIR"
chmod 0700 "$DATA_DIR"

# ── 3. hot wallet ───────────────────────────────────────────────────
if [ ! -f "$WALLET_FILE" ]; then
  log "creating hot wallet at $WALLET_FILE"
  PWD_GEN=$(head -c 32 /dev/urandom | base64 | tr -d '/+=' | head -c 40)
  # Persist the password BEFORE wallet create, so a crash doesn't lock us out.
  umask 077
  printf 'FAUCET_WALLET_PASSWORD=%s\n' "$PWD_GEN" > "$ENV_FILE"
  chmod 0600 "$ENV_FILE"

  CREATE_OUT=$("$WALLET_BIN_DST" \
    --network "$NETWORK" \
    --wallet "$WALLET_FILE" \
    --node "http://127.0.0.1:28081" \
    create --password "$PWD_GEN" --force 2>&1)
  echo "$CREATE_OUT"
  # Pull the seed phrase from the create output and save it locked-down,
  # in case the wallet file is ever lost.
  echo "$CREATE_OUT" | grep -E 'word|seed|mnemonic' -i > "$SEED_FILE" || true
  chmod 0600 "$SEED_FILE"
else
  log "hot wallet already exists, skipping create"
  # Make sure env file exists; if it's missing the operator must
  # rebuild from the seed before this script can finish.
  if [ ! -f "$ENV_FILE" ]; then
    echo "ERROR: $WALLET_FILE exists but $ENV_FILE missing — cannot recover password automatically"
    exit 2
  fi
fi

# ── 4. extend the env file with non-secret config ───────────────────
log "writing config block to $ENV_FILE"
# Preserve only the password line; rewrite everything else.
PWD_LINE=$(grep '^FAUCET_WALLET_PASSWORD=' "$ENV_FILE")
cat > "$ENV_FILE" <<ENV
$PWD_LINE
FAUCET_LISTEN_ADDR=127.0.0.1:$LISTEN_PORT
FAUCET_DB_PATH=$DATA_DIR/drips.db
FAUCET_WALLET_PATH=$WALLET_FILE
FAUCET_WALLET_BIN=$WALLET_BIN_DST
FAUCET_NODE_RPC=http://127.0.0.1:28081
FAUCET_NETWORK=$NETWORK
FAUCET_DRIP_AMOUNT_ATOMIC=10000000000000
FAUCET_RATE_LIMIT_ADDRESS_SECS=3600
FAUCET_RATE_LIMIT_IP_SECS=1800
FAUCET_CORS_ORIGINS=https://coincync.network,https://www.coincync.network,https://coincync.org,https://www.coincync.org
RUST_LOG=info,coincync_faucet=info,tower_http=info
ENV
chmod 0600 "$ENV_FILE"

# ── 5. systemd unit ─────────────────────────────────────────────────
log "installing systemd unit"
cat > "$SYSTEMD_UNIT" <<UNIT
[Unit]
Description=CoinCync testnet faucet
After=network-online.target coincync-node.service
Wants=network-online.target

[Service]
Type=simple
# Load the node's env first so the wallet subprocess inherits
# COINCYNC_RPC_API_KEY (the local node's RPC is auth-gated).
# Then load the faucet's own env on top so faucet-specific values
# can override on collision.
EnvironmentFile=/etc/coincync/coincync.env
EnvironmentFile=$ENV_FILE
ExecStart=$FAUCET_BIN_DST
Restart=on-failure
RestartSec=5
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
ReadWritePaths=$DATA_DIR
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
UNIT
chmod 0644 "$SYSTEMD_UNIT"

systemctl daemon-reload
systemctl enable coincync-faucet.service >/dev/null
systemctl restart coincync-faucet.service

# ── 6. nginx route ──────────────────────────────────────────────────
log "installing nginx snippet"
cat > "$NGINX_SNIPPET" <<NGX
# CoinCync faucet — reverse-proxy to the local Rust service.
# Drop-in for the existing api.coincync.network server block.
location = /faucet {
    proxy_pass http://127.0.0.1:$LISTEN_PORT/faucet;
    proxy_set_header Host \$host;
    proxy_set_header X-Real-IP \$remote_addr;
    proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
    proxy_set_header X-Forwarded-Proto \$scheme;
}
location = /faucet/stats {
    proxy_pass http://127.0.0.1:$LISTEN_PORT/faucet/stats;
    proxy_set_header Host \$host;
    proxy_set_header X-Real-IP \$remote_addr;
    proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
}
location = /faucet/health {
    proxy_pass http://127.0.0.1:$LISTEN_PORT/faucet/health;
    access_log off;
}
NGX

# Validate + reload.
if nginx -t >/dev/null 2>&1; then
    systemctl reload nginx
    log "nginx reloaded"
else
    log "WARNING: nginx config test failed; not reloading. fix manually:"
    nginx -t
fi

# ── 7. report state ─────────────────────────────────────────────────
log "service status"
systemctl is-active --quiet coincync-faucet.service && echo "  coincync-faucet: ACTIVE" || echo "  coincync-faucet: INACTIVE (check journalctl -u coincync-faucet)"

log "hot wallet address (FUND THIS BEFORE GOING LIVE)"
"$WALLET_BIN_DST" \
    --network "$NETWORK" \
    --wallet "$WALLET_FILE" \
    --node "http://127.0.0.1:28081" \
    address --password "$(grep '^FAUCET_WALLET_PASSWORD=' "$ENV_FILE" | cut -d= -f2-)" \
    2>&1 | grep -E '^\s*Address:' || echo "  could not extract address"

log "done."
echo ""
echo "Next steps for the operator:"
echo "  1. Copy the address above"
echo "  2. Send testnet CYNC to it from your local wallet (~100 CYNC seeds enough drips for launch week)"
echo "  3. Verify with:  curl https://api.coincync.network/faucet/health"
echo "  4. Test a drip:  curl -XPOST https://api.coincync.network/faucet -d '{\"address\":\"<your-test-address>\"}' -H 'Content-Type: application/json'"
echo ""
echo "Env file:        $ENV_FILE  (mode 600 — has the wallet password)"
echo "Wallet file:     $WALLET_FILE"
echo "Seed phrase:     $SEED_FILE  (mode 600 — recovery phrase if file lost)"
echo "DB:              $DATA_DIR/drips.db"
echo "Service logs:    journalctl -u coincync-faucet -f"
