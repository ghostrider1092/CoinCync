#!/usr/bin/env bash
# Install/update nginx vhost for api.coincync.network (nginx-only).
#
# Usage:
#   sudo bash deploy/api/install-nginx-api.sh [server_name]
#
# Defaults:
#   server_name: api.coincync.network
set -euo pipefail

if [[ "${EUID}" -ne 0 ]]; then
  echo "Run as root (sudo)." >&2
  exit 1
fi

SERVER_NAME="${1:-api.coincync.network}"
SITE_PATH="/etc/nginx/sites-available/${SERVER_NAME}"
SITE_LINK="/etc/nginx/sites-enabled/${SERVER_NAME}"

cat >"${SITE_PATH}" <<EOF
server {
    listen 443 ssl;
    server_name ${SERVER_NAME};

    # CORS for SDKs/wallets
    add_header Access-Control-Allow-Origin * always;
    add_header Access-Control-Allow-Methods "GET, POST, OPTIONS" always;
    add_header Access-Control-Allow-Headers "Content-Type, Authorization" always;
    if (\$request_method = OPTIONS) { return 204; }

    # JSON-RPC (testnet)
    location = /rpc {
        rewrite ^ / break;
        proxy_pass http://127.0.0.1:28081;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header Content-Type application/json;
    }

    # JSON-RPC (mainnet, prelaunch-safe if upstream absent -> 502)
    location = /rpc/mainnet {
        rewrite ^ / break;
        proxy_pass http://127.0.0.1:19081;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header Content-Type application/json;
    }

    # REST v1 (if enabled in node)
    location /v1/ {
        proxy_pass http://127.0.0.1:28083/v1/;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
    }

    # Minimal API landing response
    location = / {
        default_type application/json;
        return 200 '{"service":"CoinCync API","network":"testnet","rpc":"\/rpc","mainnet_rpc":"\/rpc\/mainnet"}';
    }

    ssl_certificate /etc/letsencrypt/live/${SERVER_NAME}/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/${SERVER_NAME}/privkey.pem;
    include /etc/letsencrypt/options-ssl-nginx.conf;
    ssl_dhparam /etc/letsencrypt/ssl-dhparams.pem;
}

server {
    listen 80;
    server_name ${SERVER_NAME};
    return 301 https://\$host\$request_uri;
}
EOF

ln -sfn "${SITE_PATH}" "${SITE_LINK}"
nginx -t
systemctl reload nginx
echo "Installed ${SITE_PATH} and reloaded nginx."
