#requires -Version 5.1
# deploy-rpc-key-and-verify.ps1
#
# 1. Generate a fresh 32-byte hex RPC API key (the leaked one in
#    fleet-backup-20260502T203842Z is now in conversation log + OneDrive,
#    so it is compromised and must NOT be reused).
# 2. Save key to %USERPROFILE%\.coincync\fleet-rpc-key (outside OneDrive).
# 3. Push to /etc/coincync/coincync.env on each of the 5 fleet boxes.
# 4. Patch the systemd unit to load EnvironmentFile and restart.
# 5. Query each box's RPC get_info and print height / peer count / sync.

$ErrorActionPreference = 'Stop'

$KeyPath  = "$env:USERPROFILE\.ssh\coincync_fleet"
$KeyStash = "$env:USERPROFILE\.coincync\fleet-rpc-key"

$Fleet = @(
  @{ Name='seed1';    IP='66.135.23.193'  },
  @{ Name='seed2';    IP='140.82.57.168'  },
  @{ Name='seed3';    IP='207.148.111.76' },
  @{ Name='explorer'; IP='207.148.6.50'   },
  @{ Name='api';      IP='95.179.165.225' }
)

# 1. generate or load API key
if (-not (Test-Path (Split-Path $KeyStash -Parent))) {
  New-Item -ItemType Directory -Path (Split-Path $KeyStash -Parent) -Force | Out-Null
}
if (Test-Path $KeyStash) {
  $apiKey = (Get-Content $KeyStash -Raw).Trim()
  Write-Host "Reusing existing API key from $KeyStash"
} else {
  $bytes = New-Object byte[] 32
  [System.Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($bytes)
  $apiKey = -join ($bytes | ForEach-Object { $_.ToString('x2') })
  [System.IO.File]::WriteAllText($KeyStash, $apiKey, [System.Text.UTF8Encoding]::new($false))
  Write-Host "Generated new API key and saved to $KeyStash"
}

# 2. build the bash deploy script
$envContent = "COINCYNC_RPC_API_KEY=$apiKey`n"
$envB64 = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($envContent))

$deployScript = @"
#!/bin/bash
set -euo pipefail
install -d -m 0750 -o root -g coincync /etc/coincync
echo '$envB64' | base64 -d > /etc/coincync/coincync.env
chmod 0640 /etc/coincync/coincync.env
chown root:coincync /etc/coincync/coincync.env
UNIT=/etc/systemd/system/coincync-node.service
if ! grep -q '^EnvironmentFile=/etc/coincync/coincync.env' "`$UNIT"; then
  sed -i '/^\[Service\]/a EnvironmentFile=/etc/coincync/coincync.env' "`$UNIT"
fi
systemctl daemon-reload
systemctl restart coincync-node
for i in 1 2 3 4 5 6 7 8 9 10; do sleep 1; systemctl is-active --quiet coincync-node && break; done
systemctl is-active --quiet coincync-node || { echo "FAIL: service not active after restart"; journalctl -u coincync-node -n 30 --no-pager; exit 1; }
sleep 3
echo "Service restarted with EnvironmentFile."
"@

# 3. push to each box
foreach ($n in $Fleet) {
  Write-Host ""
  Write-Host ("=== {0} ({1}) - deploying API key ===" -f $n.Name, $n.IP)
  $tmp = [IO.Path]::GetTempFileName()
  try {
    [IO.File]::WriteAllText($tmp, $deployScript, [Text.UTF8Encoding]::new($false))
    & scp -i $KeyPath -o StrictHostKeyChecking=accept-new -q $tmp "root@$($n.IP):/tmp/deploy-key.sh"
    if ($LASTEXITCODE -ne 0) { throw "SCP to $($n.IP) failed" }
    & ssh -i $KeyPath -o StrictHostKeyChecking=accept-new "root@$($n.IP)" "bash /tmp/deploy-key.sh; ec=`$?; rm -f /tmp/deploy-key.sh; exit `$ec"
    if ($LASTEXITCODE -ne 0) { throw "SSH to $($n.IP) returned $LASTEXITCODE" }
  } finally {
    Remove-Item -Force -ErrorAction SilentlyContinue $tmp
  }
}

# 4. fleet-wide get_info comparison
Write-Host ""
Write-Host "================================================================="
Write-Host "  Fleet RPC summary"
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

Write-Host ""
Write-Host "API key stored at: $KeyStash"
Write-Host "(NOT committed to git, NOT in OneDrive - keep this file safe.)"
