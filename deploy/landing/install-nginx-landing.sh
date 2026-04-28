#!/usr/bin/env bash
# Install/update nginx vhosts for coincync.network and docs.coincync.network.
#
# Usage:
#   sudo bash deploy/landing/install-nginx-landing.sh
set -euo pipefail

if [[ "${EUID}" -ne 0 ]]; then
  echo "Run as root (sudo)." >&2
  exit 1
fi

SITE_PATH="/etc/nginx/sites-available/coincync.network"
SITE_LINK="/etc/nginx/sites-enabled/coincync.network"

cat >"${SITE_PATH}" <<'EOF'
server {
    listen 443 ssl;
    server_name coincync.network www.coincync.network;

    root /var/www/landing;
    index index.html;
    location / {
        try_files $uri $uri/ /index.html;
    }

    # Mirrors directory JSON served from landing deployment directory.
    location = /mirrors.json {
        root /opt/coincync/deploy/landing;
        default_type application/json;
        try_files /mirrors.json =404;
    }

    ssl_certificate /etc/letsencrypt/live/coincync.network/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/coincync.network/privkey.pem;
    include /etc/letsencrypt/options-ssl-nginx.conf;
    ssl_dhparam /etc/letsencrypt/ssl-dhparams.pem;
}

server {
    listen 80;
    server_name coincync.network www.coincync.network;
    return 301 https://$host$request_uri;
}

server {
    listen 443 ssl;
    server_name docs.coincync.network;

    root /var/www/docs;
    index index.html;
    location / {
        try_files $uri $uri/ =404;
    }

    # Also expose mirrors.json from docs host.
    location = /mirrors.json {
        root /opt/coincync/deploy/landing;
        default_type application/json;
        try_files /mirrors.json =404;
    }

    ssl_certificate /etc/letsencrypt/live/docs.coincync.network/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/docs.coincync.network/privkey.pem;
    include /etc/letsencrypt/options-ssl-nginx.conf;
    ssl_dhparam /etc/letsencrypt/ssl-dhparams.pem;
}

server {
    listen 80;
    server_name docs.coincync.network;
    return 301 https://$host$request_uri;
}
EOF

ln -sfn "${SITE_PATH}" "${SITE_LINK}"
nginx -t
systemctl reload nginx
echo "Installed ${SITE_PATH} and reloaded nginx."
