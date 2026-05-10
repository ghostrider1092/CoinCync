#requires -Version 5.1
# deploy-weekly-review.ps1
#
# Push the weekly review script + systemd timer to all 5 fleet boxes.
# Same architecture as deploy-selfcheck.ps1 — each box runs its own review,
# posts to the shared Discord stats channel.

$ErrorActionPreference = 'Stop'

$KeyPath  = "$env:USERPROFILE\.ssh\coincync_fleet"
$RepoRoot = "C:\Users\unkno\OneDrive\coincync 1.0"

$Fleet = @(
  @{ Name='seed1';    IP='66.135.23.193'  },
  @{ Name='seed2';    IP='140.82.57.168'  },
  @{ Name='seed3';    IP='207.148.111.76' },
  @{ Name='explorer'; IP='207.148.6.50'   },
  @{ Name='api';      IP='95.179.165.225' }
)

$reviewScript = Get-Content -Raw (Join-Path $RepoRoot 'scripts\coincync-weekly-review.sh')
$serviceUnit  = Get-Content -Raw (Join-Path $RepoRoot 'scripts\coincync-weekly-review.service')
$timerUnit    = Get-Content -Raw (Join-Path $RepoRoot 'scripts\coincync-weekly-review.timer')

$reviewB64  = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($reviewScript))
$serviceB64 = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($serviceUnit))
$timerB64   = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($timerUnit))

$deployScript = @"
#!/bin/bash
set -euo pipefail

# Install review script
echo '$reviewB64' | base64 -d > /usr/local/bin/coincync-weekly-review
chmod 0755 /usr/local/bin/coincync-weekly-review
chown root:root /usr/local/bin/coincync-weekly-review

# Install systemd units
echo '$serviceB64' | base64 -d > /etc/systemd/system/coincync-weekly-review.service
echo '$timerB64'   | base64 -d > /etc/systemd/system/coincync-weekly-review.timer
chmod 0644 /etc/systemd/system/coincync-weekly-review.service /etc/systemd/system/coincync-weekly-review.timer

# Reload + enable + start the timer (the .service is fired BY the timer; don't start it directly here)
systemctl daemon-reload
systemctl enable coincync-weekly-review.timer
systemctl start coincync-weekly-review.timer

# One immediate run so user sees the format land in Discord NOW
systemctl start coincync-weekly-review.service || true
sleep 3
journalctl -u coincync-weekly-review.service -n 8 --no-pager 2>/dev/null | tail -8 || true

echo '--- timer state ---'
systemctl list-timers coincync-weekly-review.timer --no-pager 2>/dev/null | head -3
echo "OK on `$(hostname)"
"@

foreach ($n in $Fleet) {
  Write-Host ""
  Write-Host ("=== {0} ({1}) - deploying weekly review ===" -f $n.Name, $n.IP)
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
Write-Host "  Weekly review deployed to all 5 boxes"
Write-Host "================================================================="
Write-Host "Recurring schedule:  Sunday 16:00 UTC = 9am PT (PDT) / 8am PT (PST)"
Write-Host "On-demand run:       systemctl start coincync-weekly-review.service"
Write-Host ""
Write-Host "Each box just fired one immediate review. Check the Discord stats"
Write-Host "channel - you should see 5 posts in the next ~30 seconds."
