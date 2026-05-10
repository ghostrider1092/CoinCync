#requires -Version 5.1
<#
.SYNOPSIS
  Deploy the coincync-faucet service to the api box.

.DESCRIPTION
  Runs the WSL build of coincync-faucet + coincync-wallet, scps both
  binaries plus the install script to the api box, then runs the
  install script as root.

  After this script finishes, the operator MUST manually fund the
  hot wallet with testnet CYNC. Run-output prints the wallet address.

  Usage:
    .\scripts\deploy-faucet.ps1
    .\scripts\deploy-faucet.ps1 -ApiIp 95.179.165.225
    .\scripts\deploy-faucet.ps1 -SkipBuild   # if binaries already at target/release
#>

param(
  [string]$ApiIp = '95.179.165.225',
  [string]$SshKey = "$env:USERPROFILE\.ssh\coincync_fleet",
  [switch]$SkipBuild
)

$ErrorActionPreference = 'Stop'
$RepoRoot = Split-Path -Parent $PSScriptRoot

$FaucetBin = Join-Path $RepoRoot 'target\release\coincync-faucet'
$WalletBin = Join-Path $RepoRoot 'target\release\coincync-wallet'

# ── 1. Build (Linux release) ───────────────────────────────────────
if (-not $SkipBuild) {
  Write-Host "=== Building coincync-faucet + coincync-wallet (Linux release) ===" -ForegroundColor Cyan
  $prevPref = $ErrorActionPreference
  $ErrorActionPreference = 'Continue'
  try {
    & wsl --distribution Ubuntu bash -c 'source $HOME/.cargo/env && cd "/mnt/c/Users/unkno/OneDrive/coincync 1.0" && cargo build --release -p coincync-faucet && cargo build --release --features "randomx testnet" --bin coincync-wallet && strip target/release/coincync-faucet target/release/coincync-wallet'
    if ($LASTEXITCODE -ne 0) { throw "build failed: exit $LASTEXITCODE" }
  } finally {
    $ErrorActionPreference = $prevPref
  }
} else {
  Write-Host "=== Skipping build (-SkipBuild) ===" -ForegroundColor Yellow
}

if (-not (Test-Path $FaucetBin)) { throw "missing $FaucetBin" }
if (-not (Test-Path $WalletBin)) { throw "missing $WalletBin" }

# ── 2. Stage binaries to /tmp on the api box ──────────────────────
Write-Host "=== Staging binaries to root@${ApiIp}:/tmp ===" -ForegroundColor Cyan
$sshOpts = @('-i', $SshKey, '-o', 'StrictHostKeyChecking=no')
& scp @sshOpts $FaucetBin "root@${ApiIp}:/tmp/coincync-faucet"
if ($LASTEXITCODE -ne 0) { throw "scp coincync-faucet failed" }
& scp @sshOpts $WalletBin "root@${ApiIp}:/tmp/coincync-wallet"
if ($LASTEXITCODE -ne 0) { throw "scp coincync-wallet failed" }

# ── 3. Stage install script ───────────────────────────────────────
$InstallScript = Join-Path $RepoRoot 'scripts\install-faucet.sh'
& scp @sshOpts $InstallScript "root@${ApiIp}:/tmp/install-faucet.sh"
if ($LASTEXITCODE -ne 0) { throw "scp install-faucet.sh failed" }

# ── 4. Run install script remotely ────────────────────────────────
Write-Host "=== Running install-faucet.sh on root@${ApiIp} ===" -ForegroundColor Cyan
& ssh @sshOpts "root@${ApiIp}" 'chmod +x /tmp/install-faucet.sh && /tmp/install-faucet.sh'
if ($LASTEXITCODE -ne 0) { throw "remote install failed: exit $LASTEXITCODE" }

# ── 5. Health probe ───────────────────────────────────────────────
Write-Host ""
Write-Host "=== Probing public endpoint ===" -ForegroundColor Cyan
Start-Sleep -Seconds 2
try {
  $health = Invoke-WebRequest -Uri 'https://api.coincync.network/faucet/health' -TimeoutSec 8 -UseBasicParsing
  Write-Host "  /faucet/health:  $($health.StatusCode) $($health.Content.Trim())"
} catch {
  Write-Host "  /faucet/health:  NOT REACHABLE — Cloudflare or nginx may need a few seconds, retry manually"
}

Write-Host ""
Write-Host "=== Done ===" -ForegroundColor Green
Write-Host "  Fund the hot wallet (address printed above), then test a drip."
