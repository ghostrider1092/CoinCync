#requires -Version 5.1
# deploy-selfcheck.ps1
#
# Deploy the self-check script + systemd timer to all 5 fleet boxes:
#  1. Append DISCORD_WEBHOOK to each box's /etc/coincync/coincync.env
#  2. Install /usr/local/bin/coincync-selfcheck (script)
#  3. Install /etc/systemd/system/coincync-selfcheck.{service,timer}
#  4. systemctl daemon-reload + enable + start the .timer
#  5. Trigger one immediate run so we see it work

$ErrorActionPreference = 'Stop'

$KeyPath  = "$env:USERPROFILE\.ssh\coincync_fleet"
$KeyStash = "$env:USERPROFILE\.coincync\fleet-rpc-key"
$RepoRoot = "C:\Users\unkno\OneDrive\coincync 1.0"

if (-not (Test-Path $KeyStash)) { throw "Missing API key: $KeyStash" }

# Read Discord webhook from the repo's webhook config (stats channel)
$webhooksFile = Join-Path $RepoRoot 'discord_webhooks.json'
if (-not (Test-Path $webhooksFile)) { throw "Missing $webhooksFile" }
$webhooks = Get-Content -Raw $webhooksFile | ConvertFrom-Json
$discord = $webhooks.stats_webhook
if (-not $discord) { throw "stats_webhook not set in discord_webhooks.json" }

$Fleet = @(
  @{ Name='seed1';    IP='66.135.23.193'  },
  @{ Name='seed2';    IP='140.82.57.168'  },
  @{ Name='seed3';    IP='207.148.111.76' },
  @{ Name='explorer'; IP='207.148.6.50'   },
  @{ Name='api';      IP='95.179.165.225' }
)

$selfcheckScript = Get-Content -Raw (Join-Path $RepoRoot 'scripts\coincync-selfcheck.sh')
$serviceUnit     = Get-Content -Raw (Join-Path $RepoRoot 'scripts\coincync-selfcheck.service')
$timerUnit       = Get-Content -Raw (Join-Path $RepoRoot 'scripts\coincync-selfcheck.timer')

# Base64-encode payloads to avoid quoting trouble in the remote shell
$selfcheckB64 = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($selfcheckScript))
$serviceB64   = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($serviceUnit))
$timerB64     = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($timerUnit))

$deployScript = @"
#!/bin/bash
set -euo pipefail

# 1. Add DISCORD_WEBHOOK to coincync.env (idempotent)
ENV_FILE=/etc/coincync/coincync.env
if grep -q '^DISCORD_WEBHOOK=' "`$ENV_FILE" 2>/dev/null; then
  sed -i 's|^DISCORD_WEBHOOK=.*|DISCORD_WEBHOOK=$discord|' "`$ENV_FILE"
else
  echo 'DISCORD_WEBHOOK=$discord' >> "`$ENV_FILE"
fi
chmod 0640 "`$ENV_FILE"
chown root:coincync "`$ENV_FILE"

# 2. Install selfcheck script
echo '$selfcheckB64' | base64 -d > /usr/local/bin/coincync-selfcheck
chmod 0755 /usr/local/bin/coincync-selfcheck
chown root:root /usr/local/bin/coincync-selfcheck

# Ensure python3 + curl are present (used by the post helper)
command -v python3 >/dev/null || apt-get install -yqq python3 >/dev/null

# 3. Install systemd units
echo '$serviceB64' | base64 -d > /etc/systemd/system/coincync-selfcheck.service
echo '$timerB64'   | base64 -d > /etc/systemd/system/coincync-selfcheck.timer
chmod 0644 /etc/systemd/system/coincync-selfcheck.service /etc/systemd/system/coincync-selfcheck.timer
systemctl daemon-reload

# 4. Enable + start the timer
systemctl enable --now coincync-selfcheck.timer

# 5. Run one immediate check (so we see Discord get a post or know if anything is broken)
systemctl start coincync-selfcheck.service || true
sleep 2
journalctl -u coincync-selfcheck.service -n 5 --no-pager 2>/dev/null || true

# Show timer state
echo '--- timer state ---'
systemctl list-timers coincync-selfcheck.timer --no-pager 2>/dev/null | head -3 || true
echo "OK on `$(hostname)"
"@

foreach ($n in $Fleet) {
  Write-Host ""
  Write-Host ("=== {0} ({1}) - deploying selfcheck ===" -f $n.Name, $n.IP)
  $tmp = [IO.Path]::GetTempFileName()
  try {
    [IO.File]::WriteAllText($tmp, $deployScript, [Text.UTF8Encoding]::new($false))
    & scp -i $KeyPath -o StrictHostKeyChecking=accept-new -q $tmp "root@$($n.IP):/tmp/dep.sh"
    if ($LASTEXITCODE -ne 0) { throw "SCP to $($n.IP) failed" }
    & ssh -i $KeyPath "root@$($n.IP)" "bash /tmp/dep.sh; ec=`$?; rm -f /tmp/dep.sh; exit `$ec"
    if ($LASTEXITCODE -ne 0) { throw "SSH to $($n.IP) returned $LASTEXITCODE" }
  } finally {
    Remove-Item -Force -ErrorAction SilentlyContinue $tmp
  }
}

Write-Host ""
Write-Host "================================================================="
Write-Host "  Self-check deployed to all 5 boxes"
Write-Host "================================================================="
Write-Host "Timer fires every 10 min on each box. Each box reports its OWN"
Write-Host "state to the stats Discord channel on drift transitions."
Write-Host ""
Write-Host "If you see no Discord activity in the next 10 min, that means all"
Write-Host "5 are healthy (no drift = no message). Check transitions only."
