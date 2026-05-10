#!/bin/bash
# Generate a self-signed cert and add an nginx 443 listener.
#
# Why self-signed: Cloudflare Full mode validates origin TLS but does not
# require a trusted CA — a self-signed cert is accepted. Only Full (strict)
# would reject this. Tomorrow's cleanup: replace with Cloudflare Origin
# Certificate (free, 15-year, only Cloudflare validates) and switch to
# Full (strict) for proper end-to-end encryption.
set -euo pipefail

CERT_DIR=/etc/nginx/ssl
CERT=$CERT_DIR/origin.crt
KEY=$CERT_DIR/origin.key

mkdir -p "$CERT_DIR"
chmod 0750 "$CERT_DIR"

if [ ! -f "$CERT" ] || [ ! -f "$KEY" ]; then
  openssl req -x509 -nodes -newkey rsa:2048 \
    -days 3650 \
    -keyout "$KEY" \
    -out "$CERT" \
    -subj "/CN=explorer.coincync.network" \
    -addext "subjectAltName=DNS:explorer.coincync.network,DNS:explorer.coincync.org,DNS:api.coincync.network,DNS:api.coincync.org" \
    >/dev/null 2>&1
  chmod 0600 "$KEY"
  chmod 0644 "$CERT"
  echo "Generated self-signed cert at $CERT"
else
  echo "Cert already exists at $CERT - leaving in place"
fi

# Patch the existing nginx config: add a 443 listener block after the 80 one.
SITE=/etc/nginx/sites-available/coincync-explorer
if [ ! -f "$SITE" ]; then
  echo "ERROR: $SITE not found - run deploy-explorer-nginx.ps1 first"
  exit 1
fi

# Idempotent — only add 443 block if not already present
if ! grep -q 'listen 443 ssl' "$SITE"; then
  # Replace the single "listen 80;" with both listeners
  sed -i 's|listen 80;|listen 80;\n    listen 443 ssl;\n    ssl_certificate /etc/nginx/ssl/origin.crt;\n    ssl_certificate_key /etc/nginx/ssl/origin.key;\n    ssl_protocols TLSv1.2 TLSv1.3;|' "$SITE"
  echo "Patched $SITE with 443 listener"
else
  echo "443 listener already present in $SITE"
fi

nginx -t
systemctl reload nginx

echo "--- listeners now ---"
ss -tlnp | grep -E ':80 |:443 ' | sort

echo "--- local HTTPS probe (-k = ignore self-signed) ---"
curl -sS -o /dev/null -w "HTTP %{http_code}, %{size_download} bytes\n" \
  -k -H "Host: explorer.coincync.network" https://127.0.0.1/
