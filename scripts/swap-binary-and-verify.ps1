#requires -Version 5.1
# swap-binary-and-verify.ps1
#
# Push a freshly-built coincync-node binary to all 5 fleet boxes, restart
# the service, and re-query get_info to confirm the IBD orphan-loop wedge
# is resolved (height should advance past 936 toward target).
#
# Usage:
#   .\swap-binary-and-verify.ps1 -BinaryPath <path-to-new-linux-binary>
#
# If -BinaryPath is omitted, defaults to release\v1.0.1-testnet\coincync-node-linux-x86_64
# (the original deployed binary — probably not what you want).

param(
  [string]$BinaryPath = "C:\Users\unkno\OneDrive\coincync 1.0\release\v1.0.1-testnet\coincync-node-linux-x86_64-fresh"
)

$ErrorActionPreference = 'Stop'

$KeyPath  = "$env:USERPROFILE\.ssh\coincync_fleet"
$KeyStash = "$env:USERPROFILE\.coincync\fleet-rpc-key"

if (-not (Test-Path $BinaryPath)) {
  throw "Binary not found at: $BinaryPath`nPass -BinaryPath <path> to point at the freshly-built binary."
}
if (-not (Test-Path $KeyStash)) {
  throw "API key stash missing at $KeyStash. Run deploy-rpc-key-and-verify.ps1 first."
}
$apiKey = (Get-Content $KeyStash -Raw).Trim()
$binSize = (Get-Item $BinaryPath).Length

Write-Host "Deploying binary: $BinaryPath ($([math]::Round($binSize/1MB, 1)) MB)"

$Fleet = @(
  @{ Name='seed1';    IP='66.135.23.193'  },
  @{ Name='seed2';    IP='140.82.57.168'  },
  @{ Name='seed3';    IP='207.148.111.76' },
  @{ Name='explorer'; IP='207.148.6.50'   },
  @{ Name='api';      IP='95.179.165.225' }
)

$swapScript = @'
#!/bin/bash
set -euo pipefail
systemctl stop coincync-node
install -m 0755 /tmp/coincync-node-new /usr/local/bin/coincync-node
rm -f /tmp/coincync-node-new
systemctl start coincync-node
for i in 1 2 3 4 5 6 7 8 9 10; do sleep 1; systemctl is-active --quiet coincync-node && break; done
systemctl is-active --quiet coincync-node || { echo "FAIL"; journalctl -u coincync-node -n 30 --no-pager; exit 1; }
sleep 3
/usr/local/bin/coincync-node --version 2>&1 || true
echo "Service active with new binary."
'@

foreach ($n in $Fleet) {
  Write-Host ""
  Write-Host ("=== {0} ({1}) - swapping binary ===" -f $n.Name, $n.IP)
  & scp -i $KeyPath -o StrictHostKeyChecking=accept-new -q $BinaryPath "root@$($n.IP):/tmp/coincync-node-new"
  if ($LASTEXITCODE -ne 0) { throw "SCP binary to $($n.IP) failed" }

  $tmp = [IO.Path]::GetTempFileName()
  try {
    [IO.File]::WriteAllText($tmp, $swapScript, [Text.UTF8Encoding]::new($false))
    & scp -i $KeyPath -q $tmp "root@$($n.IP):/tmp/swap.sh"
    if ($LASTEXITCODE -ne 0) { throw "SCP script to $($n.IP) failed" }
    & ssh -i $KeyPath "root@$($n.IP)" "bash /tmp/swap.sh; ec=`$?; rm -f /tmp/swap.sh; exit `$ec"
    if ($LASTEXITCODE -ne 0) { throw "SSH to $($n.IP) returned $LASTEXITCODE" }
  } finally {
    Remove-Item -Force -ErrorAction SilentlyContinue $tmp
  }
}

Write-Host ""
Write-Host "Waiting 15 seconds for nodes to settle..."
Start-Sleep -Seconds 15

Write-Host ""
Write-Host "================================================================="
Write-Host "  Fleet RPC summary after binary swap"
Write-Host "================================================================="
Write-Host ("{0,-10} {1,-18} {2,-7} {3,-7} {4,-7} {5,-7}" -f 'name','ip','height','target','synced','peers')
Write-Host ("{0,-10} {1,-18} {2,-7} {3,-7} {4,-7} {5,-7}" -f '----','--','------','------','------','-----')

$queryScript = "curl -sS --max-time 8 -X POST http://127.0.0.1:28081 -H 'Content-Type: application/json' -H 'Authorization: Bearer $apiKey' -d '{`"jsonrpc`":`"2.0`",`"id`":1,`"method`":`"get_info`"}'"

foreach ($n in $Fleet) {
  $tmp = [IO.Path]::GetTempFileName()
  try {
    [IO.File]::WriteAllText($tmp, $queryScript, [Text.UTF8Encoding]::new($false))
    & scp -i $KeyPath -q $tmp "root@$($n.IP):/tmp/q.sh" 2>&1 | Out-Null
    $resp = & ssh -i $KeyPath "root@$($n.IP)" "bash /tmp/q.sh; rm -f /tmp/q.sh" 2>&1 |
            Where-Object { $_ -notmatch 'Permanently added' }
    $body = ($resp -join '').Trim()
    try {
      $json = $body | ConvertFrom-Json -ErrorAction Stop
      if ($json.result) {
        $r = $json.result
        Write-Host ("{0,-10} {1,-18} {2,-7} {3,-7} {4,-7} {5,-7}" -f $n.Name, $n.IP, $r.height, $r.target_height, $r.synced, $r.peer_count)
      } else {
        Write-Host ("{0,-10} {1,-18} ERROR {2}" -f $n.Name, $n.IP, $body)
      }
    } catch {
      Write-Host ("{0,-10} {1,-18} BAD JSON: {2}" -f $n.Name, $n.IP, $body)
    }
  } finally {
    Remove-Item -Force -ErrorAction SilentlyContinue $tmp
  }
}
