#requires -Version 5.1
# deploy-api-nginx.ps1
# Same architecture as deploy-explorer-nginx.ps1, but:
#  - server_name = api.coincync.network + api.coincync.org
#  - no static frontend (the explorer serves UI; api is for programmatic JSON-RPC)
#  - / returns a tiny JSON banner so curlers know they hit the right host
#  - HTTP + HTTPS (self-signed) listeners, same SAN pattern

$ErrorActionPreference = 'Stop'
$KeyPath = "$env:USERPROFILE\.ssh\coincync_fleet"
$ApiIP   = '95.179.165.225'

$nginxConf = @'
set_real_ip_from 173.245.48.0/20;
set_real_ip_from 103.21.244.0/22;
set_real_ip_from 103.22.200.0/22;
set_real_ip_from 103.31.4.0/22;
set_real_ip_from 141.101.64.0/18;
set_real_ip_from 108.162.192.0/18;
set_real_ip_from 190.93.240.0/20;
set_real_ip_from 188.114.96.0/20;
set_real_ip_from 197.234.240.0/22;
set_real_ip_from 198.41.128.0/17;
set_real_ip_from 162.158.0.0/15;
set_real_ip_from 104.16.0.0/13;
set_real_ip_from 104.24.0.0/14;
set_real_ip_from 172.64.0.0/13;
set_real_ip_from 131.0.72.0/22;
real_ip_header CF-Connecting-IP;

server {
    listen 80;
    listen 443 ssl;
    server_name api.coincync.network api.coincync.org;

    ssl_certificate /etc/nginx/ssl/origin.crt;
    ssl_certificate_key /etc/nginx/ssl/origin.key;
    ssl_protocols TLSv1.2 TLSv1.3;

    set $coincync_rpc_key "__RPC_API_KEY__";

    add_header Access-Control-Allow-Origin * always;
    add_header Access-Control-Allow-Methods "GET, POST, OPTIONS" always;
    add_header Access-Control-Allow-Headers "Content-Type, Authorization" always;
    if ($request_method = OPTIONS) { return 204; }

    proxy_http_version 1.1;
    proxy_connect_timeout 3s;
    proxy_read_timeout    8s;
    proxy_send_timeout    8s;

    location = / {
        default_type application/json;
        return 200 '{"service":"coincync-api","testnet":"/rpc/testnet or /rpc","mainnet":"/rpc/mainnet"}';
    }

    # /rpc and /rpc/testnet -> testnet RPC
    location = /rpc { rewrite ^ / break; proxy_pass http://127.0.0.1:28081; proxy_set_header Authorization "Bearer $coincync_rpc_key"; proxy_set_header Content-Type application/json; }
    location = /rpc/testnet { rewrite ^ / break; proxy_pass http://127.0.0.1:28081; proxy_set_header Authorization "Bearer $coincync_rpc_key"; proxy_set_header Content-Type application/json; }
    # /rpc/mainnet -> mainnet RPC (not running yet, will 502 — fine)
    location = /rpc/mainnet { rewrite ^ / break; proxy_pass http://127.0.0.1:19081; proxy_set_header Authorization "Bearer $coincync_rpc_key"; proxy_set_header Content-Type application/json; }

    # /coord/ -> FROST signing coordinator (CIP-008). The coord binary
    # speaks plain WS on 127.0.0.1:8443; nginx terminates WSS in front.
    # WebSocket-specific overrides: Upgrade headers + long read/send
    # timeouts so idle WS connections aren't reaped by the 8s global.
    location /coord/ {
        proxy_pass http://127.0.0.1:8443/;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        # WS sessions can idle through round-1 / round-2 deliberation.
        # 5 minutes is the coord's idle-timeout default; raise both
        # together if you ever extend it.
        proxy_read_timeout 300s;
        proxy_send_timeout 300s;
        # No buffering — round-trip latency matters for signing UX.
        proxy_buffering off;
    }

    # Anything else: 404 with JSON
    location / {
        default_type application/json;
        return 404 '{"error":"not found"}';
    }
}
'@

$nginxConfB64 = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($nginxConf))

$installScript = @"
#!/bin/bash
set -euo pipefail

# nginx
if ! command -v nginx >/dev/null 2>&1; then
  apt-get update -qq
  apt-get install -yqq nginx
fi

# self-signed cert (same SAN list as explorer for portability)
mkdir -p /etc/nginx/ssl
chmod 0750 /etc/nginx/ssl
if [ ! -f /etc/nginx/ssl/origin.crt ]; then
  openssl req -x509 -nodes -newkey rsa:2048 \
    -days 3650 \
    -keyout /etc/nginx/ssl/origin.key \
    -out /etc/nginx/ssl/origin.crt \
    -subj "/CN=api.coincync.network" \
    -addext "subjectAltName=DNS:api.coincync.network,DNS:api.coincync.org,DNS:explorer.coincync.network,DNS:explorer.coincync.org" \
    >/dev/null 2>&1
  chmod 0600 /etc/nginx/ssl/origin.key
fi

# load API key from env file
. /etc/coincync/coincync.env
if [ -z "`${COINCYNC_RPC_API_KEY:-}" ]; then
  echo "ERROR: COINCYNC_RPC_API_KEY not set"
  exit 1
fi

echo '$nginxConfB64' | base64 -d > /etc/nginx/sites-available/coincync-api
sed -i "s|__RPC_API_KEY__|`$COINCYNC_RPC_API_KEY|" /etc/nginx/sites-available/coincync-api
chmod 0640 /etc/nginx/sites-available/coincync-api
chown root:www-data /etc/nginx/sites-available/coincync-api

ln -sf /etc/nginx/sites-available/coincync-api /etc/nginx/sites-enabled/coincync-api
rm -f /etc/nginx/sites-enabled/default

nginx -t
systemctl enable --now nginx
systemctl reload nginx

echo '--- local probes ---'
curl -sS -o /dev/null -w "HTTP %{http_code} HTTP-port-80 / route\n" -H 'Host: api.coincync.network' http://127.0.0.1/
curl -sS -o /dev/null -w "HTTP %{http_code} HTTPS-port-443 / route\n" -k -H 'Host: api.coincync.network' https://127.0.0.1/
curl -sS -X POST -H 'Host: api.coincync.network' -H 'Content-Type: application/json' \
     -d '{"jsonrpc":"2.0","id":1,"method":"get_info"}' \
     -k https://127.0.0.1/rpc/testnet | head -c 200
echo
# /coord/ probe: WS handshake against the upstream returns 400 from
# nginx if the coord is down, 101 if up. We don't send a proper
# Upgrade dance with curl, so 426/400 is the expected "nginx is
# forwarding, coord may or may not be running" signal. A 502 means
# nginx can't reach the coord at 127.0.0.1:8443 — check that the
# coincync-coord.service is active.
curl -sS -o /dev/null -w "HTTP %{http_code} HTTPS-port-443 /coord/ (expect 400/426 if coord up, 502 if down)\n" -k -H 'Host: api.coincync.network' https://127.0.0.1/coord/
echo "OK on `$(hostname)"
"@

$tmp = [IO.Path]::GetTempFileName()
try {
  [IO.File]::WriteAllText($tmp, $installScript, [Text.UTF8Encoding]::new($false))
  & scp -i $KeyPath -o StrictHostKeyChecking=accept-new -q $tmp "root@${ApiIP}:/tmp/install-api.sh"
  if ($LASTEXITCODE -ne 0) { throw "scp failed" }
  & ssh -i $KeyPath "root@${ApiIP}" "bash /tmp/install-api.sh; ec=`$?; rm -f /tmp/install-api.sh; exit `$ec"
  if ($LASTEXITCODE -ne 0) { throw "remote install returned $LASTEXITCODE" }
} finally {
  Remove-Item -Force -ErrorAction SilentlyContinue $tmp
}

Write-Host ""
Write-Host "Waiting 5 sec..."
Start-Sleep -Seconds 5

Write-Host ""
Write-Host "=== HTTPS probes through Cloudflare ==="
foreach ($url in @(
  'https://api.coincync.network/',
  'https://api.coincync.org/',
  'https://api.coincync.network/rpc/testnet'
)) {
  try {
    if ($url -like '*rpc/testnet*') {
      $r = Invoke-WebRequest -Uri $url -Method POST -Body '{"jsonrpc":"2.0","id":1,"method":"get_info"}' -ContentType 'application/json' -TimeoutSec 12 -UseBasicParsing
    } else {
      $r = Invoke-WebRequest -Uri $url -Method Get -TimeoutSec 12 -UseBasicParsing -MaximumRedirection 3
    }
    Write-Host ("{0,-50}  status={1}  via={2}" -f $url, $r.StatusCode, $r.Headers.Server)
  } catch {
    Write-Host ("{0,-50}  FAIL: {1}" -f $url, $_.Exception.Message)
  }
}
