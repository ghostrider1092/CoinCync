#!/usr/bin/env bash
# Install/update nginx vhost for explorer.coincync.network with authenticated
# /api/{testnet,mainnet} and /health/* JSON-RPC proxy routes.
#
# Usage:
#   sudo bash deploy/explorer/install-nginx-explorer.sh <COINCYNC_RPC_API_KEY>
#
# Optional environment overrides:
#   EXPLORER_SERVER_NAME (default: explorer.coincync.network)
#   EXPLORER_ROOT        (default: /var/www/explorer)
#   NGINX_SITE_PATH      (default: /etc/nginx/sites-available/explorer.coincync.network)
#   EXPLORER_TESTNET_RPC_UPSTREAM (default: 127.0.0.1:28081)
#   EXPLORER_MAINNET_RPC_UPSTREAM (default: 127.0.0.1:19081)
set -euo pipefail

if [[ "${EUID}" -ne 0 ]]; then
  echo "Run as root (sudo)." >&2
  exit 1
fi

RPC_KEY="${1:-}"
if [[ -z "${RPC_KEY}" ]]; then
  echo "Usage: $0 <COINCYNC_RPC_API_KEY>" >&2
  exit 1
fi

EXPLORER_SERVER_NAME="${EXPLORER_SERVER_NAME:-explorer.coincync.network}"
EXPLORER_ROOT="${EXPLORER_ROOT:-/var/www/explorer}"
NGINX_SITE_PATH="${NGINX_SITE_PATH:-/etc/nginx/sites-available/explorer.coincync.network}"
NGINX_SITE_LINK="/etc/nginx/sites-enabled/$(basename "${NGINX_SITE_PATH}")"
EXPLORER_TESTNET_RPC_UPSTREAM="${EXPLORER_TESTNET_RPC_UPSTREAM:-127.0.0.1:28081}"
EXPLORER_MAINNET_RPC_UPSTREAM="${EXPLORER_MAINNET_RPC_UPSTREAM:-127.0.0.1:19081}"

# Refuse to proxy to a remote upstream. The explorer host should always
# query its own coincync-node, not another fleet member's. We hit this
# the hard way once: LON was deployed with EXPLORER_TESTNET_RPC_UPSTREAM
# pointed at RIC, and when RIC's chain stalled the explorer banner read
# stale data ("Chain data is X minutes old") even though LON itself was
# fully synced. Rule of thumb: this script renders the public RPC proxy
# for one nginx host; that host must be self-sufficient.
for upstream in "${EXPLORER_TESTNET_RPC_UPSTREAM}" "${EXPLORER_MAINNET_RPC_UPSTREAM}"; do
  host="${upstream%:*}"
  case "$host" in
    127.0.0.1|::1|localhost) ;;
    *)
      echo "ERROR: RPC upstream '$upstream' is not loopback." >&2
      echo "  The explorer must proxy to its own local coincync-node." >&2
      echo "  Set EXPLORER_TESTNET_RPC_UPSTREAM=127.0.0.1:28081 (default)." >&2
      exit 2
      ;;
  esac
done

cat >"${NGINX_SITE_PATH}" <<EOF
server {
    server_name ${EXPLORER_SERVER_NAME};

    root ${EXPLORER_ROOT};
    index index.html;

    # Shared JSON-RPC bearer key used for upstream node probes.
    set \$coincync_rpc_key "${RPC_KEY}";

    # CORS
    add_header Access-Control-Allow-Origin * always;
    add_header Access-Control-Allow-Methods "GET, POST, OPTIONS" always;
    add_header Access-Control-Allow-Headers "Content-Type, Authorization" always;
    if (\$request_method = OPTIONS) { return 204; }

    proxy_http_version 1.1;
    proxy_connect_timeout 3s;
    proxy_read_timeout 8s;
    proxy_send_timeout 8s;

    # JSON-RPC: explorer fetch() posts to /api/testnet and /api/mainnet.
    # Rewrite path to root for jsonrpsee endpoint.
    location = /api/testnet {
        rewrite ^ / break;
        proxy_pass http://${EXPLORER_TESTNET_RPC_UPSTREAM};
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header Content-Type application/json;
        proxy_set_header Authorization "Bearer \$coincync_rpc_key";
    }

    location = /api/mainnet {
        rewrite ^ / break;
        proxy_pass http://${EXPLORER_MAINNET_RPC_UPSTREAM};
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header Content-Type application/json;
        proxy_set_header Authorization "Bearer \$coincync_rpc_key";
    }

    # Node Health dashboard fan-out routes.
    location = /health/lon  { proxy_pass http://138.68.172.80:28081;  proxy_set_header Content-Type application/json; proxy_set_header Authorization "Bearer \$coincync_rpc_key"; }
    location = /health/sfo  { proxy_pass http://64.227.49.44:28081;   proxy_set_header Content-Type application/json; proxy_set_header Authorization "Bearer \$coincync_rpc_key"; }
    location = /health/nyc1 { proxy_pass http://192.34.59.42:28081;   proxy_set_header Content-Type application/json; proxy_set_header Authorization "Bearer \$coincync_rpc_key"; }
    location = /health/fra  { proxy_pass http://46.101.138.120:28081; proxy_set_header Content-Type application/json; proxy_set_header Authorization "Bearer \$coincync_rpc_key"; }
    location = /health/nyc3 { proxy_pass http://45.55.32.13:28081;    proxy_set_header Content-Type application/json; proxy_set_header Authorization "Bearer \$coincync_rpc_key"; }
    location = /health/tor  { proxy_pass http://143.110.218.99:28081; proxy_set_header Content-Type application/json; proxy_set_header Authorization "Bearer \$coincync_rpc_key"; }
    location = /health/ric  { proxy_pass http://165.245.161.62:28081; proxy_set_header Content-Type application/json; proxy_set_header Authorization "Bearer \$coincync_rpc_key"; }
    location = /health/atl  { proxy_pass http://165.245.140.113:28081; proxy_set_header Content-Type application/json; proxy_set_header Authorization "Bearer \$coincync_rpc_key"; }
    location = /health/ams  { proxy_pass http://164.92.153.24:28081;  proxy_set_header Content-Type application/json; proxy_set_header Authorization "Bearer \$coincync_rpc_key"; }
    location = /health/syd  { proxy_pass http://170.64.142.146:28081; proxy_set_header Content-Type application/json; proxy_set_header Authorization "Bearer \$coincync_rpc_key"; }

    # Keep legacy endpoints alive if external tools still call these.
    location = /api {
        rewrite ^ / break;
        proxy_pass http://127.0.0.1:28081;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header Content-Type application/json;
        proxy_set_header Authorization "Bearer \$coincync_rpc_key";
    }

    location / {
        try_files \$uri \$uri/ /index.html;
    }

    listen 443 ssl;
    ssl_certificate /etc/letsencrypt/live/${EXPLORER_SERVER_NAME}/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/${EXPLORER_SERVER_NAME}/privkey.pem;
    include /etc/letsencrypt/options-ssl-nginx.conf;
    ssl_dhparam /etc/letsencrypt/ssl-dhparams.pem;
}

server {
    if (\$host = ${EXPLORER_SERVER_NAME}) { return 301 https://\$host\$request_uri; }
    listen 80;
    server_name ${EXPLORER_SERVER_NAME};
    return 404;
}
EOF

ln -sfn "${NGINX_SITE_PATH}" "${NGINX_SITE_LINK}"

nginx -t
systemctl reload nginx

echo "Installed ${NGINX_SITE_PATH} and reloaded nginx."
echo "Explorer testnet upstream: ${EXPLORER_TESTNET_RPC_UPSTREAM}"
echo "Explorer mainnet upstream: ${EXPLORER_MAINNET_RPC_UPSTREAM}"
echo "Quick check:"
echo "curl -sS -X POST https://${EXPLORER_SERVER_NAME}/health/sfo -H 'content-type: application/json' -d '{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"get_info\"}'"
