#requires -Version 5.1
# snap-explorer-api.ps1
#
# Push the chain snapshot to explorer + api (which provisioned at height 0
# because the original script only restored snapshots on seeds), then re-run
# the fleet RPC summary so we see the new state.

$ErrorActionPreference = 'Stop'

$KeyPath  = "$env:USERPROFILE\.ssh\coincync_fleet"
$KeyStash = "$env:USERPROFILE\.coincync\fleet-rpc-key"
$Snapshot = "C:\Users\unkno\OneDrive\coincync 1.0\fleet-backup-20260502T203842Z\fleet-backup-20260502T203842Z\chain-snapshot-NYC3.tar.gz"

if (-not (Test-Path $Snapshot)) { throw "Missing snapshot: $Snapshot" }
if (-not (Test-Path $KeyStash)) { throw "Missing API key: $KeyStash. Run deploy-rpc-key-and-verify.ps1 first." }
$apiKey = (Get-Content $KeyStash -Raw).Trim()

$Targets = @(
  @{ Name='explorer'; IP='207.148.6.50'   },
  @{ Name='api';      IP='95.179.165.225' }
)

$AllFleet = @(
  @{ Name='seed1';    IP='66.135.23.193'  },
  @{ Name='seed2';    IP='140.82.57.168'  },
  @{ Name='seed3';    IP='207.148.111.76' },
  @{ Name='explorer'; IP='207.148.6.50'   },
  @{ Name='api';      IP='95.179.165.225' }
)

$snapScript = @'
#!/bin/bash
set -euo pipefail
systemctl stop coincync-node
rm -rf /var/lib/coincync/testnet
sudo -u coincync tar -xzf /tmp/chain-snapshot.tar.gz -C /var/lib/coincync
rm -f /tmp/chain-snapshot.tar.gz
systemctl start coincync-node
for i in 1 2 3 4 5 6 7 8 9 10; do sleep 1; systemctl is-active --quiet coincync-node && break; done
systemctl is-active --quiet coincync-node || { echo "FAIL: service not active"; journalctl -u coincync-node -n 30 --no-pager; exit 1; }
sleep 3
echo "Snapshot restored, service active."
'@

foreach ($t in $Targets) {
  Write-Host ""
  Write-Host ("=== {0} ({1}) - pushing snapshot ===" -f $t.Name, $t.IP)
  & scp -i $KeyPath -o StrictHostKeyChecking=accept-new -q $Snapshot "root@$($t.IP):/tmp/chain-snapshot.tar.gz"
  if ($LASTEXITCODE -ne 0) { throw "SCP snapshot to $($t.IP) failed" }

  $tmp = [IO.Path]::GetTempFileName()
  try {
    [IO.File]::WriteAllText($tmp, $snapScript, [Text.UTF8Encoding]::new($false))
    & scp -i $KeyPath -q $tmp "root@$($t.IP):/tmp/snap.sh"
    if ($LASTEXITCODE -ne 0) { throw "SCP script to $($t.IP) failed" }
    & ssh -i $KeyPath "root@$($t.IP)" "bash /tmp/snap.sh; ec=`$?; rm -f /tmp/snap.sh; exit `$ec"
    if ($LASTEXITCODE -ne 0) { throw "SSH to $($t.IP) returned $LASTEXITCODE" }
  } finally {
    Remove-Item -Force -ErrorAction SilentlyContinue $tmp
  }
}

Write-Host ""
Write-Host "Waiting 10 seconds for nodes to settle..."
Start-Sleep -Seconds 10

Write-Host ""
Write-Host "================================================================="
Write-Host "  Updated fleet RPC summary"
Write-Host "================================================================="
Write-Host ("{0,-10} {1,-18} {2,-7} {3,-7} {4,-7} {5,-7}" -f 'name','ip','height','target','synced','peers')
Write-Host ("{0,-10} {1,-18} {2,-7} {3,-7} {4,-7} {5,-7}" -f '----','--','------','------','------','-----')

$queryScript = "curl -sS --max-time 8 -X POST http://127.0.0.1:28081 -H 'Content-Type: application/json' -H 'Authorization: Bearer $apiKey' -d '{`"jsonrpc`":`"2.0`",`"id`":1,`"method`":`"get_info`"}'"

foreach ($n in $AllFleet) {
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
