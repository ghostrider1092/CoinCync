#requires -Version 5.1
# deploy-explorer-nginx.ps1
#
# Install nginx + the explorer static frontend on the Vultr explorer box.
# Cloudflare proxies SSL — origin runs HTTP only on port 80.
#
# Layout on the box:
#   /var/www/explorer/index.html
#   /var/www/explorer/assets/...
#   /var/www/explorer/static/...
#   /var/www/explorer/static/vendor/...   (chart.js, globe.gl, etc.)
#
# nginx config:
#   - server_name covers BOTH explorer.coincync.network AND explorer.coincync.org
#   - /api/testnet  -> 127.0.0.1:28081 (this box's coincync-node) with Bearer auth
#   - /api/mainnet  -> 127.0.0.1:19081 (mainnet not running yet, returns 502, harmless)
#   - /            -> static files
#   - Cloudflare real-IP headers honored
#
# Cloudflare SSL/TLS mode for both zones MUST be set to "Flexible" or
# "Full" — NOT "Full (strict)" — since origin has no certificate.
# (Future: install Cloudflare Origin Cert and switch to Full strict.)

$ErrorActionPreference = 'Stop'

$KeyPath    = "$env:USERPROFILE\.ssh\coincync_fleet"
$ExplorerIP = '207.148.6.50'
$RepoRoot   = "C:\dev\coincync"

# ─── 1. Bundle the explorer assets into a tarball ────────────────────────
$tar = "$env:TEMP\explorer-bundle.tar.gz"
Remove-Item -Force -ErrorAction SilentlyContinue $tar

Write-Host "Bundling explorer assets..."
Push-Location $RepoRoot
try {
  # Git Bash's GNU tar interprets `C:\foo` as host C, path \foo (SSH-style
  # remote spec). Setting MSYS_NO_PATHCONV in PowerShell's $env doesn't
  # always propagate cleanly to the child process — explicitly use the
  # Windows-bundled BSD tar instead, which has no MSYS path conventions.
  # (BSD tar ships with Windows 10/11 at System32\tar.exe.)
  $bsdTar = "$env:SystemRoot\System32\tar.exe"
  if (-not (Test-Path $bsdTar)) {
    throw "Windows BSD tar not found at $bsdTar -- install via 'Manage Optional Features' or use WSL"
  }
  & $bsdTar -czf $tar `
    'src/explorer/index.html' `
    'src/explorer/assets' `
    'src/explorer/static' `
    'deploy/explorer/static/vendor'
  if ($LASTEXITCODE -ne 0) { throw "tar failed with exit $LASTEXITCODE" }
} finally {
  Pop-Location
}
Write-Host ("Bundle size: {0:N1} MB" -f ((Get-Item $tar).Length/1MB))

# ─── 2. nginx config (HTTP only, both zones) ─────────────────────────────
# API key gets injected on the box via envsubst from /etc/coincync/coincync.env
$nginxConf = @'
# Trust Cloudflare's proxy IPs and use CF-Connecting-IP as the real client IP.
# Ranges from https://www.cloudflare.com/ips-v4/ — review periodically.
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
    listen [::]:80;
    listen 443 ssl;
    listen [::]:443 ssl;
    server_name explorer.coincync.network explorer.coincync.org;

    # Cloudflare Origin Certificates (CF-only trust, selected by SNI).
    # Two certs because each was generated for a single zone and the
    # auto-append in the CF dashboard added the wrong SAN entries when
    # crossing zones. Working hostnames: *.coincync.network on .network.crt,
    # *.coincync.org on .crt. Regenerate cleanly when convenient.
    # Files must exist on the box BEFORE running this script — see scripts/install-origin-cert.ps1.
    ssl_certificate     /etc/nginx/ssl/origin.network.crt;
    ssl_certificate_key /etc/nginx/ssl/origin.network.key;
    ssl_certificate     /etc/nginx/ssl/origin.crt;
    ssl_certificate_key /etc/nginx/ssl/origin.key;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384;
    ssl_prefer_server_ciphers off;
    ssl_session_cache shared:SSL:10m;
    ssl_session_timeout 10m;

    root /var/www/explorer;
    index index.html;

    # The bearer key for upstream node probes is loaded from
    # /etc/coincync/coincync.env at install time and injected here:
    set $coincync_rpc_key "__RPC_API_KEY__";

    # CORS so the wallet / external tooling can call /api/* from any origin.
    add_header Access-Control-Allow-Origin * always;
    add_header Access-Control-Allow-Methods "GET, POST, OPTIONS" always;
    add_header Access-Control-Allow-Headers "Content-Type, Authorization" always;
    if ($request_method = OPTIONS) { return 204; }

    proxy_http_version 1.1;
    proxy_connect_timeout 3s;
    # Timeouts bumped 8s -> 15s on 2026-05-25. The wider window doesn't
    # change steady-state behavior (every observed RPC responds in <300ms
    # against the current backend); it just buffers against future
    # heavier endpoints (histogram queries, multi-block summaries) so a
    # slow path doesn't surface to the user as a silent "stalled" panel
    # when nginx 504s under the prior 8s ceiling.
    proxy_read_timeout    15s;
    proxy_send_timeout    15s;

    # JSON-RPC endpoints — explorer frontend posts to these.
    location = /api/testnet {
        rewrite ^ / break;
        proxy_pass http://127.0.0.1:28081;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header Content-Type application/json;
        proxy_set_header Authorization "Bearer $coincync_rpc_key";
    }

    location = /api/mainnet {
        rewrite ^ / break;
        proxy_pass http://127.0.0.1:19081;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header Content-Type application/json;
        proxy_set_header Authorization "Bearer $coincync_rpc_key";
    }

    # Legacy /api endpoint kept alive in case external tools still call it.
    location = /api {
        rewrite ^ / break;
        proxy_pass http://127.0.0.1:28081;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header Content-Type application/json;
        proxy_set_header Authorization "Bearer $coincync_rpc_key";
    }

    # Per-box health probes hit by the explorer's Node Health dashboard.
    # Each route proxies the JSON-RPC call to the matching fleet member's
    # RPC port (28081) with the Bearer key added server-side, so the
    # browser never sees the API key. Each box's UFW restricts source to
    # the explorer's IP only — Bearer + IP allowlist is two layers.
    # NODE_POLL_MS in the dashboard JS controls poll cadence (~12 s).
    # IPs updated 2026-06-27 to match current fleet (scripts/fleet-config.json).
    # Previously hardcoded to destroyed hosts: seed1 was 66.135.23.193 (destroyed
    # 2026-06-25), seed3 was 207.148.111.76 (destroyed 2026-06-18) — both 504'd
    # for weeks. Also added randomx, randomx2, relay1, relay2 which didn't exist
    # when this file was first written.
    # api intentionally absent — that host runs nginx-only (no coincync-node)
    # so health-probing it would always 504.
    location = /health/seed1    { rewrite ^ / break; proxy_pass http://216.128.156.239:28081; proxy_set_header Authorization "Bearer $coincync_rpc_key"; proxy_set_header Content-Type application/json; }
    location = /health/seed2    { rewrite ^ / break; proxy_pass http://140.82.57.168:28081;  proxy_set_header Authorization "Bearer $coincync_rpc_key"; proxy_set_header Content-Type application/json; }
    location = /health/seed3    { rewrite ^ / break; proxy_pass http://45.32.251.6:28081;    proxy_set_header Authorization "Bearer $coincync_rpc_key"; proxy_set_header Content-Type application/json; }
    location = /health/explorer { rewrite ^ / break; proxy_pass http://127.0.0.1:28081;      proxy_set_header Authorization "Bearer $coincync_rpc_key"; proxy_set_header Content-Type application/json; }
    location = /health/randomx  { rewrite ^ / break; proxy_pass http://173.199.93.21:28081;  proxy_set_header Authorization "Bearer $coincync_rpc_key"; proxy_set_header Content-Type application/json; }
    location = /health/randomx2 { rewrite ^ / break; proxy_pass http://45.32.79.234:28081;   proxy_set_header Authorization "Bearer $coincync_rpc_key"; proxy_set_header Content-Type application/json; }
    location = /health/relay1   { rewrite ^ / break; proxy_pass http://208.85.17.18:28081;   proxy_set_header Authorization "Bearer $coincync_rpc_key"; proxy_set_header Content-Type application/json; }
    location = /health/relay2   { rewrite ^ / break; proxy_pass http://70.34.250.31:28081;   proxy_set_header Authorization "Bearer $coincync_rpc_key"; proxy_set_header Content-Type application/json; }

    # REST API proxy. The explorer's `rest()` helper calls
    # /api/v1/<network>/<path>; rewrite into the backend's /v1/<path>
    # form and target the daemon's REST port (28082, which is
    # rpc_port + 1 in our convention). Used by future panels (the
    # current code has the helper defined but no calls yet — adding the
    # proxy now so the location is in place when the JS starts using it,
    # rather than discovering the 405/HTML-fallthrough at the moment a
    # new feature ships).
    location ~ ^/api/v1/(testnet|mainnet)/(.*)$ {
        set $rest_path $2;
        rewrite ^ /v1/$rest_path break;
        proxy_pass http://127.0.0.1:28082;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header Authorization "Bearer $coincync_rpc_key";
    }

    # Catch-all for any /api/* path that didn't match a specific block
    # above. Returns 404 JSON instead of falling through to the
    # static-file catch-all below (which would return /index.html — the
    # HTML SPA shell — and the explorer's fetch().json() would throw on
    # the unexpected text/html response, leaving the panel "stalled"
    # with no visible error). 2026-05-25 hardening.
    location ~ ^/api/ {
        default_type application/json;
        return 404 '{"jsonrpc":"2.0","error":{"code":-32601,"message":"unknown api path"},"id":null}';
    }

    # Static files for everything else.
    location / {
        try_files $uri $uri/ /index.html;
    }
}
'@

# ─── 3. Build the remote install script ──────────────────────────────────
$nginxConfB64 = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($nginxConf))

$installScript = @"
#!/bin/bash
set -euo pipefail

# Install nginx if not present
if ! command -v nginx >/dev/null 2>&1; then
  apt-get update -qq
  apt-get install -yqq nginx
fi

# Pre-check: SSL certs must already be installed. If they're missing the new
# nginx config (with listen 443 ssl;) won't validate. Fail before touching
# any state so the running nginx keeps serving the prior config.
for f in /etc/nginx/ssl/origin.network.crt /etc/nginx/ssl/origin.network.key /etc/nginx/ssl/origin.crt /etc/nginx/ssl/origin.key; do
  if [ ! -f "`$f" ]; then
    echo "ERROR: required cert/key missing: `$f"
    echo "Install certs first (CF dashboard -> Origin Server -> Create Certificate),"
    echo "scp them to /etc/nginx/ssl/, chmod 0644 the .crt and 0600 the .key, then re-run."
    exit 1
  fi
done

# Layout the static tree
install -d -m 0755 -o www-data -g www-data /var/www/explorer
tar -xzf /tmp/explorer-bundle.tar.gz -C /tmp/explorer-stage --one-top-level=src 2>/dev/null || {
  rm -rf /tmp/explorer-stage; mkdir -p /tmp/explorer-stage
  tar -xzf /tmp/explorer-bundle.tar.gz -C /tmp/explorer-stage
}

# Move into final layout. The tar has src/explorer/* and deploy/explorer/static/vendor — flatten
rm -rf /var/www/explorer/*
cp -r /tmp/explorer-stage/src/explorer/index.html /var/www/explorer/
cp -r /tmp/explorer-stage/src/explorer/assets    /var/www/explorer/   2>/dev/null || true
cp -r /tmp/explorer-stage/src/explorer/static    /var/www/explorer/   2>/dev/null || true
mkdir -p /var/www/explorer/static/vendor
cp -r /tmp/explorer-stage/deploy/explorer/static/vendor/* /var/www/explorer/static/vendor/ 2>/dev/null || true
chown -R www-data:www-data /var/www/explorer
rm -rf /tmp/explorer-stage /tmp/explorer-bundle.tar.gz

# Pull the API key from coincync.env and inject into the nginx config
if [ ! -f /etc/coincync/coincync.env ]; then
  echo "ERROR: /etc/coincync/coincync.env not found (was deploy-rpc-key-and-verify.ps1 ever run?)"
  exit 1
fi
. /etc/coincync/coincync.env
if [ -z "`${COINCYNC_RPC_API_KEY:-}" ]; then
  echo "ERROR: COINCYNC_RPC_API_KEY not set in /etc/coincync/coincync.env"
  exit 1
fi

echo '$nginxConfB64' | base64 -d > /etc/nginx/sites-available/coincync-explorer
sed -i "s|__RPC_API_KEY__|`$COINCYNC_RPC_API_KEY|" /etc/nginx/sites-available/coincync-explorer
chmod 0640 /etc/nginx/sites-available/coincync-explorer
chown root:www-data /etc/nginx/sites-available/coincync-explorer

# Enable our site, disable the default
ln -sf /etc/nginx/sites-available/coincync-explorer /etc/nginx/sites-enabled/coincync-explorer
rm -f /etc/nginx/sites-enabled/default

# Validate + reload
nginx -t
systemctl enable --now nginx
systemctl reload nginx

# Local sanity probe — should return 200 with the index.html
echo "--- local probe ---"
curl -sS -o /dev/null -w "HTTP %{http_code}, %{size_download} bytes\n" \
  -H "Host: explorer.coincync.network" http://127.0.0.1/

echo "--- API probe ---"
curl -sS -X POST http://127.0.0.1/api/testnet \
  -H "Host: explorer.coincync.network" \
  -d '{"jsonrpc":"2.0","id":1,"method":"get_info"}' \
  | head -c 200
echo ""
echo "OK: nginx serving explorer on `$(hostname)"
"@

# ─── 4. Push and run ─────────────────────────────────────────────────────
Write-Host ""
Write-Host "Pushing assets to $ExplorerIP..."
& scp -i $KeyPath -o StrictHostKeyChecking=accept-new -q $tar "root@${ExplorerIP}:/tmp/explorer-bundle.tar.gz"
if ($LASTEXITCODE -ne 0) { throw "scp bundle failed" }

$tmp = [IO.Path]::GetTempFileName()
try {
  # Normalize CRLF -> LF: PowerShell here-strings on Windows use CRLF
  # line endings, and bash on the remote interprets the trailing CR as
  # part of the last token on each line — `set -euo pipefail\r` becomes
  # "set -o pipefail<CR>", and bash reports "pipefail: invalid option name"
  # (it's looking up "pipefail\r"). This is the bash equivalent of
  # `dos2unix` happening at write time so we don't depend on a tool on
  # the remote host.
  [IO.File]::WriteAllText($tmp, $installScript.Replace("`r`n", "`n"), [Text.UTF8Encoding]::new($false))
  & scp -i $KeyPath -q $tmp "root@${ExplorerIP}:/tmp/install-explorer.sh"
  if ($LASTEXITCODE -ne 0) { throw "scp script failed" }

  Write-Host "Running install on remote..."
  # PS5.1 native-stderr trap: ssh's tar emits benign stderr warnings
  # ("Ignoring unknown extended header keyword 'SCHILY.fflags'" when
  # extracting a BSD-tar tarball with Linux tar) which PowerShell sees
  # as NativeCommandError under $ErrorActionPreference='Stop' and bails
  # BEFORE the explicit $LASTEXITCODE check. Same fix as in
  # verify-reproducible-build.ps1 (commit 54cebaa): drop EAP to
  # Continue around the call, merge stderr into stdout, then check
  # $LASTEXITCODE explicitly.
  $prevEAP = $ErrorActionPreference
  $ErrorActionPreference = 'Continue'
  try {
    & ssh -i $KeyPath "root@${ExplorerIP}" "bash /tmp/install-explorer.sh; ec=`$?; rm -f /tmp/install-explorer.sh; exit `$ec" 2>&1 | ForEach-Object { Write-Host $_ }
  } finally {
    $ErrorActionPreference = $prevEAP
  }
  if ($LASTEXITCODE -ne 0) { throw "Remote install failed with exit $LASTEXITCODE" }
} finally {
  Remove-Item -Force -ErrorAction SilentlyContinue $tmp
  Remove-Item -Force -ErrorAction SilentlyContinue $tar
}

# ─── 5. End-to-end verification (through Cloudflare) ─────────────────────
Write-Host ""
Write-Host "Waiting 5 sec for nginx to settle..."
Start-Sleep -Seconds 5

Write-Host ""
Write-Host "=== HTTPS probes through Cloudflare ==="
# .org is intentionally NOT routed to the explorer at the Cloudflare
# layer; only .network is. nginx still listens for both server_names
# (harmless dead-code branch) but probing .org returns 403 from
# Cloudflare and adds spurious FAIL noise to every deploy log.
foreach ($url in @('https://explorer.coincync.network/','https://explorer.coincync.network/api/testnet')) {
  try {
    if ($url -like '*api/testnet*') {
      $r = Invoke-WebRequest -Uri $url -Method POST -Body '{"jsonrpc":"2.0","id":1,"method":"get_info"}' -ContentType 'application/json' -TimeoutSec 12 -UseBasicParsing
    } else {
      $r = Invoke-WebRequest -Uri $url -Method Head -TimeoutSec 12 -UseBasicParsing -MaximumRedirection 3
    }
    Write-Host ("{0,-55}  status={1}  via={2}" -f $url, $r.StatusCode, $r.Headers.Server)
  } catch {
    $msg = $_.Exception.Message
    if ($msg -match '521|525|526') {
      Write-Host ("{0,-55}  FAIL: {1}  >>> set Cloudflare SSL/TLS mode to Flexible <<<" -f $url, $msg)
    } else {
      Write-Host ("{0,-55}  FAIL: {1}" -f $url, $msg)
    }
  }
}
