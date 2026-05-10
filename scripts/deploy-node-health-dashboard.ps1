#requires -Version 5.1
<#
deploy-node-health-dashboard.ps1
================================
Wire up the explorer's "Node Health" widget to the new 5-box fleet.

Three actions, in this order:

1. Each fleet box: change coincync-node systemd unit to bind RPC on
   0.0.0.0:28081 (was 127.0.0.1) so the explorer box can reach it.
   UFW rule restricts source to ONLY the explorer's IP (207.148.6.50).
   Two layers of defence: UFW + Bearer token.
   Skipped on the explorer itself (it polls its own loopback).

2. Explorer box: write nginx /health/<box> proxy routes for each of the
   5 fleet members. Each route adds the Bearer header server-side so
   the browser never sees the API key.

3. Explorer box: re-deploy the updated index.html (the GNODES/MNODES/
   NODES arrays are now correct for the new fleet).

Idempotent — re-runnable.
#>

$ErrorActionPreference = 'Stop'

$KeyPath  = "$env:USERPROFILE\.ssh\coincync_fleet"
$RepoRoot = "C:\Users\unkno\OneDrive\coincync 1.0"
$ExplorerIP = '207.148.6.50'

# Boxes whose RPC needs to become reachable from explorer
$RpcExposeBoxes = @(
  @{ Name='seed1'; IP='66.135.23.193'  },
  @{ Name='seed2'; IP='140.82.57.168'  },
  @{ Name='seed3'; IP='207.148.111.76' },
  @{ Name='api';   IP='95.179.165.225' }
)

# ─── 1. Open RPC on seed1/2/3 + api to explorer ─────────────────────────
$exposeScript = @"
#!/bin/bash
set -euo pipefail

# UFW: allow 28081/tcp from explorer's IP only
if ! ufw status | grep -q '28081/tcp.*ALLOW.*$ExplorerIP'; then
  ufw allow from $ExplorerIP to any port 28081 proto tcp comment 'Explorer RPC poll' >/dev/null
fi

# Systemd unit: rebind RPC from 127.0.0.1 to 0.0.0.0
UNIT=/etc/systemd/system/coincync-node.service
if grep -q -- '--rpc-bind 127.0.0.1:28081' "`$UNIT"; then
  sed -i 's|--rpc-bind 127.0.0.1:28081|--rpc-bind 0.0.0.0:28081|' "`$UNIT"
  systemctl daemon-reload
  systemctl restart coincync-node
  for i in 1 2 3 4 5 6 7 8 9 10; do sleep 1; systemctl is-active --quiet coincync-node && break; done
  systemctl is-active --quiet coincync-node || { echo "FAIL: service not active"; exit 1; }
fi

# Verify listener
echo "Listener:"
ss -tlnp | grep ':28081 ' || echo "(no listener — check)"
echo "OK on `$(hostname)"
"@

foreach ($n in $RpcExposeBoxes) {
  Write-Host ""
  Write-Host ("=== {0} ({1}) - exposing RPC to explorer ===" -f $n.Name, $n.IP)
  $tmp = [IO.Path]::GetTempFileName()
  try {
    [IO.File]::WriteAllText($tmp, $exposeScript, [Text.UTF8Encoding]::new($false))
    & scp -i $KeyPath -o StrictHostKeyChecking=accept-new -q $tmp "root@$($n.IP):/tmp/expose.sh"
    if ($LASTEXITCODE -ne 0) { throw "SCP to $($n.IP) failed" }
    & ssh -i $KeyPath "root@$($n.IP)" "bash /tmp/expose.sh; ec=`$?; rm -f /tmp/expose.sh; exit `$ec"
    if ($LASTEXITCODE -ne 0) { throw "SSH to $($n.IP) returned $LASTEXITCODE" }
  } finally {
    Remove-Item -Force -ErrorAction SilentlyContinue $tmp
  }
}

# ─── 2. Patch explorer nginx with /health/* routes ──────────────────────
# Block of new location directives — inserted before "location / {"
$healthBlock = @'
    # Per-box health probes — proxy to each fleet member's RPC with the
    # bearer token added server-side so the browser never sees the key.
    # These are hit by the explorer dashboard at NODE_POLL_MS interval.
    location = /health/seed1    { rewrite ^ / break; proxy_pass http://66.135.23.193:28081;  proxy_set_header Authorization "Bearer $coincync_rpc_key"; proxy_set_header Content-Type application/json; }
    location = /health/seed2    { rewrite ^ / break; proxy_pass http://140.82.57.168:28081;  proxy_set_header Authorization "Bearer $coincync_rpc_key"; proxy_set_header Content-Type application/json; }
    location = /health/seed3    { rewrite ^ / break; proxy_pass http://207.148.111.76:28081; proxy_set_header Authorization "Bearer $coincync_rpc_key"; proxy_set_header Content-Type application/json; }
    location = /health/explorer { rewrite ^ / break; proxy_pass http://127.0.0.1:28081;      proxy_set_header Authorization "Bearer $coincync_rpc_key"; proxy_set_header Content-Type application/json; }
    location = /health/api      { rewrite ^ / break; proxy_pass http://95.179.165.225:28081; proxy_set_header Authorization "Bearer $coincync_rpc_key"; proxy_set_header Content-Type application/json; }

'@

$nginxPatchScript = @"
#!/bin/bash
set -euo pipefail

SITE=/etc/nginx/sites-available/coincync-explorer
if [ ! -f "`$SITE" ]; then
  echo "ERROR: \$SITE missing - run deploy-explorer-nginx.ps1 first"
  exit 1
fi

# Idempotent: only insert health block if not already present
if ! grep -q 'location = /health/seed1' "`$SITE"; then
  # Insert before the catch-all "location / {"
  python3 - <<'PYEOF'
import re, base64
HEALTH = base64.b64decode("__HEALTH_B64__").decode()
with open("/etc/nginx/sites-available/coincync-explorer") as f:
    src = f.read()
src = src.replace("    location / {", HEALTH + "    location / {")
with open("/etc/nginx/sites-available/coincync-explorer", "w") as f:
    f.write(src)
PYEOF
  echo "Patched nginx with /health/* routes"
else
  echo "/health/* routes already present"
fi

nginx -t
systemctl reload nginx
echo "nginx reloaded"
"@

$healthB64 = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($healthBlock))
$nginxPatchScript = $nginxPatchScript -replace '__HEALTH_B64__', $healthB64

Write-Host ""
Write-Host ("=== explorer ({0}) - patching nginx with /health/* routes ===" -f $ExplorerIP)
$tmp = [IO.Path]::GetTempFileName()
try {
  [IO.File]::WriteAllText($tmp, $nginxPatchScript, [Text.UTF8Encoding]::new($false))
  & scp -i $KeyPath -q $tmp "root@${ExplorerIP}:/tmp/nginx-patch.sh"
  if ($LASTEXITCODE -ne 0) { throw "SCP to explorer failed" }
  & ssh -i $KeyPath "root@${ExplorerIP}" "bash /tmp/nginx-patch.sh; ec=`$?; rm -f /tmp/nginx-patch.sh; exit `$ec"
  if ($LASTEXITCODE -ne 0) { throw "SSH to explorer returned $LASTEXITCODE" }
} finally {
  Remove-Item -Force -ErrorAction SilentlyContinue $tmp
}

# ─── 3. Redeploy explorer index.html ────────────────────────────────────
Write-Host ""
Write-Host "=== explorer - redeploying index.html with new fleet arrays ==="
$indexHtml = Join-Path $RepoRoot 'src\explorer\index.html'
& scp -i $KeyPath -q $indexHtml "root@${ExplorerIP}:/tmp/index.html.new"
if ($LASTEXITCODE -ne 0) { throw "SCP index.html failed" }
& ssh -i $KeyPath "root@${ExplorerIP}" "install -m 0644 -o www-data -g www-data /tmp/index.html.new /var/www/explorer/index.html && rm /tmp/index.html.new && echo 'index.html installed'" 2>&1 | Where-Object { $_ -notmatch 'Permanently added' }

# ─── 4. Verify each /health/* route end-to-end through Cloudflare ───────
Write-Host ""
Write-Host "=== Verifying /health/* through Cloudflare ==="
foreach ($box in @('seed1','seed2','seed3','explorer','api')) {
  $url = "https://explorer.coincync.network/health/$box"
  try {
    $r = Invoke-WebRequest -Uri $url -Method POST -Body '{"jsonrpc":"2.0","id":1,"method":"get_info"}' -ContentType 'application/json' -TimeoutSec 12 -UseBasicParsing
    $body = $r.Content | ConvertFrom-Json
    if ($body.result.height) {
      Write-Host ("  /health/{0,-10}  status={1}  height={2}  peers={3}" -f $box, $r.StatusCode, $body.result.height, $body.result.peer_count) -ForegroundColor Green
    } else {
      Write-Host ("  /health/{0,-10}  status={1}  no result" -f $box, $r.StatusCode) -ForegroundColor Yellow
    }
  } catch {
    Write-Host ("  /health/{0,-10}  FAIL: {1}" -f $box, $_.Exception.Message) -ForegroundColor Red
  }
}

Write-Host ""
Write-Host "Done. Open https://explorer.coincync.network/ - the Node Health widget should now show the 5 boxes with live data."
