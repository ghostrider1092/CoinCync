#requires -Version 5.1
<#
.SYNOPSIS
  Deploy the testnet baseline miner to the api Vultr node.

.DESCRIPTION
  Installs `coincync-rig run-solo --threads 1` as a systemd service
  on the api node (95.179.165.225). Goal: guarantee a continuous
  block producer on testnet so ASERT has stable hashrate to converge
  against, instead of the chain drifting above 120s target during
  community-mining lulls.

  Idempotent. Re-running updates the binary + unit file in place
  without dropping the running miner (systemd handles the restart).

  Pre-reqs:
    1. SSH key at $env:USERPROFILE\.ssh\coincync_fleet
    2. Linux binary at target\release\coincync-rig (built in WSL via
       `cargo build --release -p coincync-rig`)
    3. systemd unit at deploy\coincync-baseline-miner.service
    4. A funded testnet wallet address (tCYNC...) — pass via
       -MinerAddress. This is the address mining rewards land at.

.PARAMETER MinerAddress
  Testnet wallet address (tCYNC...) for mining rewards. REQUIRED —
  no default, because mining to an unknown address effectively
  burns the rewards.

.PARAMETER ApiIp
  IP of the api node. Default 95.179.165.225.

.PARAMETER KeyPath
  SSH key. Default $env:USERPROFILE\.ssh\coincync_fleet.

.PARAMETER DryRun
  Print the planned actions without touching the remote.

.EXAMPLE
  .\scripts\deploy-baseline-miner.ps1 -MinerAddress tCYNC1abc...xyz

.EXAMPLE
  .\scripts\deploy-baseline-miner.ps1 -MinerAddress tCYNC1abc...xyz -DryRun

.NOTES
  After deploy, verify the miner is actually finding blocks:
    ssh root@95.179.165.225 'journalctl -u coincync-baseline-miner -n 20 --no-pager'
  Expected: "orchestrator: BLOCK FOUND" within ~5-10 min.
#>

[CmdletBinding()]
param(
  [Parameter(Mandatory=$true)][string]$MinerAddress,
  [string]$ApiIp = '95.179.165.225',
  [string]$KeyPath = "$env:USERPROFILE\.ssh\coincync_fleet",
  [switch]$DryRun
)

$ErrorActionPreference = 'Stop'

# --- Pre-flight ------------------------------------------------------
$RepoRoot   = Resolve-Path "$PSScriptRoot\.."
$BinaryPath = Join-Path $RepoRoot 'target\release\coincync-rig'
$UnitPath   = Join-Path $RepoRoot 'deploy\coincync-baseline-miner.service'

foreach ($p in @($KeyPath, $BinaryPath, $UnitPath)) {
  if (-not (Test-Path $p)) {
    Write-Host "ERROR: missing required file: $p" -ForegroundColor Red
    if ($p -eq $BinaryPath) {
      Write-Host "  Build via: wsl -- bash -lc 'cd /mnt/c/dev/coincync && cargo build --release -p coincync-rig'" -ForegroundColor Yellow
    }
    exit 1
  }
}

if ($MinerAddress -notmatch '^t?CYNC[a-zA-Z0-9]+$') {
  Write-Host "ERROR: -MinerAddress doesn't look like a CoinCync address (expect tCYNC... or CYNC...)" -ForegroundColor Red
  Write-Host "  Got: $MinerAddress" -ForegroundColor Red
  exit 1
}

Write-Host ""
Write-Host "===================================================================="
Write-Host "  CoinCync testnet baseline miner deploy" -ForegroundColor Yellow
Write-Host "===================================================================="
Write-Host "  target host:       $ApiIp"
Write-Host "  mine to address:   $MinerAddress"
Write-Host "  binary path:       $BinaryPath ($((Get-Item $BinaryPath).Length) bytes)"
Write-Host "  binary SHA256:     $((Get-FileHash $BinaryPath -Algorithm SHA256).Hash)"
Write-Host "  systemd unit:      $UnitPath"
Write-Host "  threads:           1 (chain-liveness floor, not perf)"
Write-Host "===================================================================="
Write-Host ""

if ($DryRun) {
  Write-Host "DRY RUN -- no remote actions. Re-run without -DryRun to apply." -ForegroundColor Yellow
  exit 0
}

# --- Copy binary + unit to remote ------------------------------------
$sshOpts = @('-i', $KeyPath, '-o', 'StrictHostKeyChecking=accept-new', '-o', 'ConnectTimeout=10')

Write-Host "Pushing binary to /usr/local/bin/coincync-rig..." -ForegroundColor Cyan
$prevEAP = $ErrorActionPreference
$ErrorActionPreference = 'Continue'
try {
  & scp @sshOpts $BinaryPath "root@${ApiIp}:/usr/local/bin/coincync-rig.new" 2>&1 | ForEach-Object { Write-Host $_ }
} finally {
  $ErrorActionPreference = $prevEAP
}
if ($LASTEXITCODE -ne 0) { throw "scp coincync-rig failed (exit $LASTEXITCODE)" }

Write-Host "Pushing systemd unit..." -ForegroundColor Cyan
$ErrorActionPreference = 'Continue'
try {
  & scp @sshOpts $UnitPath "root@${ApiIp}:/etc/systemd/system/coincync-baseline-miner.service" 2>&1 | ForEach-Object { Write-Host $_ }
} finally {
  $ErrorActionPreference = $prevEAP
}
if ($LASTEXITCODE -ne 0) { throw "scp service unit failed (exit $LASTEXITCODE)" }

# --- Install + enable on remote --------------------------------------
# Atomic swap of the binary (mv is atomic on Linux; restart picks
# it up). Append the BASELINE_MINER_ADDRESS to /etc/coincync/coincync.env
# (the existing EnvironmentFile the node service already uses).
$install = @"
set -euo pipefail

# Atomic binary swap (mv is rename(2) on Linux — no torn-file risk).
chmod 0755 /usr/local/bin/coincync-rig.new
chown root:root /usr/local/bin/coincync-rig.new
mv -f /usr/local/bin/coincync-rig.new /usr/local/bin/coincync-rig

# Make sure the coincync user exists (the node service already
# created it, but defensive check).
id -u coincync >/dev/null 2>&1 || useradd --system --no-create-home --shell /usr/sbin/nologin coincync

# Append/replace the BASELINE_MINER_ADDRESS line in the existing
# coincync env file. Idempotent — won't duplicate on re-run.
ENV_FILE=/etc/coincync/coincync.env
touch `"`$ENV_FILE`"
chmod 0640 `"`$ENV_FILE`"
chown root:coincync `"`$ENV_FILE`"
if grep -q '^BASELINE_MINER_ADDRESS=' `"`$ENV_FILE`"; then
  sed -i `"s|^BASELINE_MINER_ADDRESS=.*|BASELINE_MINER_ADDRESS=$MinerAddress|`" `"`$ENV_FILE`"
else
  echo `"BASELINE_MINER_ADDRESS=$MinerAddress`" >> `"`$ENV_FILE`"
fi

# Reload systemd, enable + restart the service.
systemctl daemon-reload
systemctl enable coincync-baseline-miner.service
systemctl restart coincync-baseline-miner.service

# Quick health probe — wait 5s and confirm it's active.
sleep 5
systemctl is-active coincync-baseline-miner.service
systemctl status coincync-baseline-miner.service --no-pager -n 10 || true
"@

Write-Host "Running install on remote..." -ForegroundColor Cyan
$ErrorActionPreference = 'Continue'
try {
  & ssh @sshOpts "root@${ApiIp}" $install 2>&1 | ForEach-Object { Write-Host $_ }
} finally {
  $ErrorActionPreference = $prevEAP
}
if ($LASTEXITCODE -ne 0) { throw "Remote install failed with exit $LASTEXITCODE" }

# --- Post-deploy: confirm it's actually mining -----------------------
Write-Host ""
Write-Host "Waiting 30s, then checking for first block-found log line..." -ForegroundColor Cyan
Start-Sleep -Seconds 30

$ErrorActionPreference = 'Continue'
try {
  & ssh @sshOpts "root@${ApiIp}" "journalctl -u coincync-baseline-miner -n 30 --no-pager" 2>&1 | ForEach-Object { Write-Host $_ }
} finally {
  $ErrorActionPreference = $prevEAP
}

Write-Host ""
Write-Host "===================================================================="
Write-Host "  Baseline miner deployed." -ForegroundColor Green
Write-Host "===================================================================="
Write-Host "  Tail logs:   ssh root@$ApiIp 'journalctl -u coincync-baseline-miner -f'"
Write-Host "  Stop:        ssh root@$ApiIp 'systemctl stop coincync-baseline-miner'"
Write-Host "  Disable:     ssh root@$ApiIp 'systemctl disable --now coincync-baseline-miner'"
Write-Host ""
Write-Host "Expect first BLOCK FOUND log within 5-10 min. Soak monitor should"
Write-Host "show block time converging toward 120s over the next hour as ASERT"
Write-Host "raises difficulty against the now-guaranteed hashrate floor."
