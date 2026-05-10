#requires -Version 5.1
# deploy-soak.ps1
#
# Push the soak script + systemd unit to all 5 fleet boxes and start it.
# By default soaks for 12h (overnight) — set $Hours to override.

param(
  [int]$Hours = 12,
  [int]$IntervalSec = 300
)

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

$soakScript  = Get-Content -Raw (Join-Path $RepoRoot 'scripts\coincync-soak.sh')
$serviceUnit = Get-Content -Raw (Join-Path $RepoRoot 'scripts\coincync-soak.service')

$soakB64    = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($soakScript))
$serviceB64 = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($serviceUnit))

$deployScript = @"
#!/bin/bash
set -euo pipefail

# Install soak script
echo '$soakB64' | base64 -d > /usr/local/bin/coincync-soak
chmod 0755 /usr/local/bin/coincync-soak
chown root:root /usr/local/bin/coincync-soak

# Per-box override env (so we can change duration via deploy without
# editing the script)
cat > /etc/coincync/soak.env <<EOF
SOAK_HOURS=$Hours
SAMPLE_INTERVAL=$IntervalSec
EOF
chmod 0644 /etc/coincync/soak.env

# Install service unit
echo '$serviceB64' | base64 -d > /etc/systemd/system/coincync-soak.service
chmod 0644 /etc/systemd/system/coincync-soak.service
systemctl daemon-reload

# If a soak is already running, stop it cleanly first
if systemctl is-active --quiet coincync-soak; then
  systemctl stop coincync-soak
  sleep 2
fi

# Kick off the new soak (oneshot — runs to completion)
systemctl start --no-block coincync-soak
sleep 1
systemctl status coincync-soak --no-pager 2>&1 | head -8 || true
echo "OK soak started on `$(hostname) for $Hours hours"
"@

foreach ($n in $Fleet) {
  Write-Host ""
  Write-Host ("=== {0} ({1}) - deploying soak ({2}h) ===" -f $n.Name, $n.IP, $Hours)
  $tmp = [IO.Path]::GetTempFileName()
  try {
    [IO.File]::WriteAllText($tmp, $deployScript, [Text.UTF8Encoding]::new($false))
    & scp -i $KeyPath -o StrictHostKeyChecking=accept-new -q $tmp "root@$($n.IP):/tmp/dep-soak.sh"
    if ($LASTEXITCODE -ne 0) { throw "SCP to $($n.IP) failed" }
    & ssh -i $KeyPath "root@$($n.IP)" "bash /tmp/dep-soak.sh; ec=`$?; rm -f /tmp/dep-soak.sh; exit `$ec"
    if ($LASTEXITCODE -ne 0) { throw "SSH to $($n.IP) returned $LASTEXITCODE" }
  } finally {
    Remove-Item -Force -ErrorAction SilentlyContinue $tmp
  }
}

Write-Host ""
Write-Host "================================================================="
Write-Host ("  Soak running on all 5 boxes for {0} hours" -f $Hours)
Write-Host "================================================================="
Write-Host "Each box will:"
Write-Host "  - Sample its own RPC every $($IntervalSec/60) min"
Write-Host "  - Log JSONL to /var/lib/coincync/soak/<timestamp>.jsonl"
Write-Host "  - Post Discord 'started' message NOW"
Write-Host ("  - Post Discord summary in {0} hours" -f $Hours)
Write-Host ""
Write-Host "Self-check stays running in parallel - if anything goes sideways"
Write-Host "during the soak, you'll get the same transition alerts you've seen."
Write-Host ""
Write-Host "Check progress on any box with:"
Write-Host "  ssh -i `$env:USERPROFILE\.ssh\coincync_fleet root@<IP> 'tail -f /var/lib/coincync/soak/*.jsonl'"
