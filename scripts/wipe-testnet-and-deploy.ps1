#requires -Version 5.1
# wipe-testnet-and-deploy.ps1
#
# CONSENSUS HARD FORK 2026-06-05 — deploys the canonical CLSAG binary
# to the 5-node fleet AND wipes /var/lib/coincync chaindata so the
# fleet boots from fresh genesis under the new CLSAG aggregate-
# coefficient rule. ALL existing testnet blocks (h=1..N) become
# invalid under the new code; this script's job is to coordinate the
# clean reset.
#
# Usage:
#   .\wipe-testnet-and-deploy.ps1 -BinaryPath out\coincync-node
#
# Per-box procedure:
#   1. systemctl stop coincync-node
#   2. rm -rf /var/lib/coincync/*
#   3. install -m 0755 /tmp/coincync-node-new /usr/local/bin/coincync-node
#   4. chown -R coincync:coincync /var/lib/coincync
#   5. systemctl start coincync-node
#   6. verify service is active

param(
  [Parameter(Mandatory=$true)]
  [string]$BinaryPath
)

$ErrorActionPreference = 'Stop'

$KeyPath = "$env:USERPROFILE\.ssh\coincync_fleet"

if (-not (Test-Path $BinaryPath)) {
  throw "Binary not found at: $BinaryPath"
}
$binSize = (Get-Item $BinaryPath).Length

Write-Host ""
Write-Host "================================================================="
Write-Host "  TESTNET WIPE + CANONICAL CLSAG DEPLOY"
Write-Host "================================================================="
Write-Host "  Binary: $BinaryPath ($([math]::Round($binSize/1MB, 1)) MB)"
Write-Host "  ALL chaindata across 5 fleet boxes will be deleted."
Write-Host "  Fresh genesis under new CLSAG rules."
Write-Host "================================================================="
Write-Host ""

$Fleet = @(
  @{ Name='seed1';    IP='66.135.23.193'  },
  @{ Name='seed2';    IP='140.82.57.168'  },
  @{ Name='seed3';    IP='207.148.111.76' },
  @{ Name='explorer'; IP='207.148.6.50'   },
  @{ Name='api';      IP='95.179.165.225' }
)

$wipeScript = @'
#!/bin/bash
set -euo pipefail

echo "[$(hostname)] stopping coincync-node..."
systemctl stop coincync-node

echo "[$(hostname)] wiping chaindata..."
# Refuse if it's not where we expect it
if [ ! -d /var/lib/coincync ]; then
  echo "FAIL: /var/lib/coincync missing — refusing to proceed" >&2
  exit 1
fi
# Wipe contents but keep the directory itself + ownership/perms
find /var/lib/coincync -mindepth 1 -delete
chown coincync:coincync /var/lib/coincync

echo "[$(hostname)] installing new binary..."
install -m 0755 /tmp/coincync-node-new /usr/local/bin/coincync-node
rm -f /tmp/coincync-node-new
/usr/local/bin/coincync-node --version 2>&1 || true

echo "[$(hostname)] starting coincync-node..."
systemctl start coincync-node

for i in 1 2 3 4 5 6 7 8 9 10; do
  sleep 1
  systemctl is-active --quiet coincync-node && break
done

if ! systemctl is-active --quiet coincync-node; then
  echo "FAIL: service did not become active" >&2
  journalctl -u coincync-node -n 30 --no-pager >&2
  exit 1
fi

sleep 3
echo "[$(hostname)] service active. Tail of journal:"
journalctl -u coincync-node -n 8 --no-pager | sed "s/^/  /"
'@

foreach ($n in $Fleet) {
  Write-Host ""
  Write-Host ("=== {0} ({1}) - wiping + redeploying ===" -f $n.Name, $n.IP)

  & scp -i $KeyPath -o StrictHostKeyChecking=accept-new -q $BinaryPath "root@$($n.IP):/tmp/coincync-node-new"
  if ($LASTEXITCODE -ne 0) { throw "SCP binary to $($n.IP) failed" }

  $tmp = [IO.Path]::GetTempFileName()
  try {
    [IO.File]::WriteAllText($tmp, $wipeScript, [Text.UTF8Encoding]::new($false))
    & scp -i $KeyPath -q $tmp "root@$($n.IP):/tmp/wipe-and-deploy.sh"
    if ($LASTEXITCODE -ne 0) { throw "SCP script to $($n.IP) failed" }
    & ssh -i $KeyPath "root@$($n.IP)" "bash /tmp/wipe-and-deploy.sh; ec=`$?; rm -f /tmp/wipe-and-deploy.sh; exit `$ec"
    if ($LASTEXITCODE -ne 0) { throw "SSH to $($n.IP) returned $LASTEXITCODE" }
  } finally {
    Remove-Item -Force -ErrorAction SilentlyContinue $tmp
  }
}

Write-Host ""
Write-Host "================================================================="
Write-Host "  Fleet wipe complete. Waiting 30s for nodes to settle..."
Write-Host "================================================================="
Start-Sleep -Seconds 30

Write-Host ""
Write-Host "================================================================="
Write-Host "  Post-deploy RPC summary"
Write-Host "================================================================="
foreach ($n in $Fleet) {
  $resp = & ssh -i $KeyPath -o StrictHostKeyChecking=no "root@$($n.IP)" "curl -sS --max-time 5 -X POST -H 'Content-Type: application/json' http://127.0.0.1:28081/rpc/testnet -d '{\""jsonrpc\"":\""2.0\"",\""id\"":1,\""method\"":\""get_info\"",\""params\"":[]}' 2>/dev/null"
  Write-Host ("[{0}] {1}" -f $n.Name, $resp)
}
Write-Host ""
Write-Host "Fresh genesis under canonical CLSAG. Restart the local rig to begin mining."
