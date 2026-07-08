#requires -Version 5.1
# deploy-coincync-rig-to-api.ps1
#
# Replace the api box's `coincync-miner.service` with the new
# `coincync-rig.service`. coincync-rig has multi-thread + auto-reconnect
# + TOML config; coincync-miner stays installed but disabled, so a
# `systemctl disable coincync-rig && systemctl enable coincync-miner`
# rolls back instantly if anything goes sideways.

$ErrorActionPreference = 'Stop'

$KeyPath = "$env:USERPROFILE\.ssh\coincync_fleet"
$ApiIP   = '95.179.165.225'
$RewardAddr = 'tCYNC3ZGvevYahmapH24ZkiKudimf5p5MZZrCq7Jc9SHkgjgQgji8EfgiaNJyEB4NdTCRGr5VX6KAX94cggvnAZCpUGWTW2LqDtE'

# 1. Copy the WSL-built rig binary out to the Windows release dir
$src = "\\wsl.localhost\Ubuntu\home\$($env:USERNAME)\coincync-build\target\release\coincync-rig"
$dst = "C:\Users\unkno\OneDrive\coincync 1.0\release\v1.0.1-testnet\coincync-rig-linux-x86_64"
Write-Host "Copying binary $src -> $dst"
Copy-Item -Path $src -Destination $dst -Force
Get-Item $dst | Format-List Name, Length, LastWriteTime

# 2. Build the systemd unit. We point at the LOCAL daemon (loopback)
#    not the public api endpoint — no need to round-trip through nginx
#    + Cloudflare for the box to mine its own chain. Threads = 1 because
#    the api box is 1 vCPU and shares cycles with coincync-node + nginx.
$serviceUnit = @"
[Unit]
Description=CoinCync Rig (canonical CPU miner, replaces coincync-miner)
After=coincync-node.service
Requires=coincync-node.service

[Service]
Type=simple
User=coincync
Group=coincync
EnvironmentFile=/etc/coincync/coincync.env
ExecStart=/usr/local/bin/coincync-rig run-solo \
    --node http://127.0.0.1:28081 \
    --address $RewardAddr \
    --network testnet \
    --threads 1 \
    --poll-interval-secs 60
Restart=on-failure
RestartSec=15
TimeoutStartSec=60
TimeoutStopSec=30

# Same sandboxing as coincync-miner — strict, but with read access to
# /etc/coincync for the env file and write to nothing.
NoNewPrivileges=yes
PrivateTmp=yes
ProtectSystem=strict
ProtectHome=yes

# Mining is intentionally low-priority so the node + nginx come first.
Nice=10
CPUSchedulingPolicy=idle
IOSchedulingClass=idle

StandardOutput=journal
StandardError=journal
SyslogIdentifier=coincync-rig

[Install]
WantedBy=multi-user.target
"@

# 3. Push binary + unit, swap services atomically
$installScript = @"
#!/bin/bash
set -euo pipefail

# Install rig binary
install -m 0755 /tmp/coincync-rig /usr/local/bin/coincync-rig
chown root:root /usr/local/bin/coincync-rig
rm -f /tmp/coincync-rig

# Quick smoke test — make sure the binary actually runs on this box
/usr/local/bin/coincync-rig --version || { echo 'rig binary failed --version'; exit 1; }

# Install systemd unit
cat > /etc/systemd/system/coincync-rig.service <<'UNITEOF'
$serviceUnit
UNITEOF

systemctl daemon-reload

# Stop + disable the OLD coincync-miner so we don't have two miners
# racing for the same blocks. Don't UNINSTALL — keeps the rollback
# trivially fast: `systemctl disable coincync-rig && systemctl enable
# --now coincync-miner` puts us back where we started.
systemctl stop coincync-miner.service 2>/dev/null || true
systemctl disable coincync-miner.service 2>/dev/null || true

# Start the rig
systemctl enable coincync-rig.service
systemctl start coincync-rig.service

# Wait for active
for i in 1 2 3 4 5 6 7 8 9 10; do
  sleep 1
  systemctl is-active --quiet coincync-rig.service && break
done
systemctl is-active --quiet coincync-rig.service || {
  echo "FAIL: coincync-rig.service did not become active"
  journalctl -u coincync-rig.service -n 30 --no-pager
  exit 1
}

# Show last log lines so the operator sees mining starting up
echo '--- coincync-rig startup logs ---'
journalctl -u coincync-rig.service -n 20 --no-pager
echo "OK: coincync-rig running on `$(hostname)"
"@

Write-Host ""
Write-Host "Pushing binary..."
& scp -i $KeyPath -o StrictHostKeyChecking=accept-new -q $dst "root@${ApiIP}:/tmp/coincync-rig"
if ($LASTEXITCODE -ne 0) { throw "SCP binary failed" }

$tmp = [IO.Path]::GetTempFileName()
try {
  [IO.File]::WriteAllText($tmp, $installScript, [Text.UTF8Encoding]::new($false))
  & scp -i $KeyPath -q $tmp "root@${ApiIP}:/tmp/install-rig.sh"
  if ($LASTEXITCODE -ne 0) { throw "SCP script failed" }
  & ssh -i $KeyPath "root@${ApiIP}" "bash /tmp/install-rig.sh; ec=`$?; rm -f /tmp/install-rig.sh; exit `$ec"
  if ($LASTEXITCODE -ne 0) { throw "Remote install returned $LASTEXITCODE" }
} finally {
  Remove-Item -Force -ErrorAction SilentlyContinue $tmp
}

Write-Host ""
Write-Host "Waiting 30 sec for mining to find first block..."
Start-Sleep -Seconds 30

Write-Host ""
Write-Host "=== Chain state via api endpoint ==="
$apiKey = (Get-Content "$env:USERPROFILE\.coincync\fleet-rpc-key" -Raw).Trim()
try {
  $r = Invoke-WebRequest -Uri 'https://api.coincync.network/rpc/testnet' -Method POST `
        -Body '{"jsonrpc":"2.0","id":1,"method":"get_info"}' `
        -ContentType 'application/json' -TimeoutSec 12 -UseBasicParsing
  $j = $r.Content | ConvertFrom-Json
  Write-Host ("height={0}  target={1}  tip_age={2}s" -f $j.result.height, $j.result.target_height, $j.result.tip_age_secs)
} catch {
  Write-Host "FAIL: $($_.Exception.Message)"
}

Write-Host ""
Write-Host "Rollback if anything is wrong:"
Write-Host "  ssh root@$ApiIP 'systemctl disable --now coincync-rig.service && systemctl enable --now coincync-miner.service'"
