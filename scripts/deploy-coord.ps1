#requires -Version 5.1
<#
.SYNOPSIS
  Deploy the coincync-frost-coordinator (coord) to a Vultr fleet box.

.DESCRIPTION
  Builds the coord binary in WSL, scps it plus the service unit,
  env example, and install script to the target box, then runs the
  install script as root. Idempotent — re-runs are safe.

  After this script finishes, the operator can run a smoke test with
  scripts/coincync-coord-smoketest.sh (also pushed by this script).

  Usage:
    .\scripts\deploy-coord.ps1                          # default = api box
    .\scripts\deploy-coord.ps1 -TargetIp 207.148.111.76 # seed3
    .\scripts\deploy-coord.ps1 -SkipBuild               # if binary already at target/release

.NOTES
  Per project_vultr_fleet memory: 5 boxes by IP. The api host
  (95.179.165.225) has the lightest load and is the default
  candidate; seed3 (207.148.111.76) is the fallback.
#>

param(
  [string]$TargetIp = '95.179.165.225',
  [string]$SshKey = "$env:USERPROFILE\.ssh\coincync_fleet",
  [switch]$SkipBuild
)

$ErrorActionPreference = 'Stop'
$RepoRoot = Split-Path -Parent $PSScriptRoot

$CoordBin = Join-Path $RepoRoot 'target\release\coord'

# ── 1. Build (Linux release with the `server cli` features) ───────
if (-not $SkipBuild) {
  Write-Host "=== Building coincync-frost-coordinator (Linux release) ===" -ForegroundColor Cyan
  $prevPref = $ErrorActionPreference
  $ErrorActionPreference = 'Continue'
  try {
    & wsl --distribution Ubuntu bash -c 'source $HOME/.cargo/env && cd "/mnt/c/Users/unkno/OneDrive/coincync 1.0" && cargo build --release -p coincync-frost-coordinator --features "server cli" --bin coord && strip target/release/coord'
    if ($LASTEXITCODE -ne 0) { throw "build failed: exit $LASTEXITCODE" }
  } finally {
    $ErrorActionPreference = $prevPref
  }
} else {
  Write-Host "=== Skipping build (-SkipBuild) ===" -ForegroundColor Yellow
}

if (-not (Test-Path $CoordBin)) { throw "missing $CoordBin" }

# ── 2. Stage binary + service + env-example + install script ──────
Write-Host "=== Staging artifacts to root@${TargetIp}:/tmp ===" -ForegroundColor Cyan
$sshOpts = @('-i', $SshKey, '-o', 'StrictHostKeyChecking=no')

$payload = @(
  @{ src = $CoordBin;                                                                      dst = '/tmp/coincync-coord' },
  @{ src = Join-Path $RepoRoot 'scripts\coincync-coord.service';                           dst = '/tmp/coincync-coord.service' },
  @{ src = Join-Path $RepoRoot 'scripts\coincync-coord.env.example';                       dst = '/tmp/coincync-coord.env.example' },
  @{ src = Join-Path $RepoRoot 'scripts\install-coord.sh';                                 dst = '/tmp/install-coord.sh' },
  @{ src = Join-Path $RepoRoot 'scripts\coincync-coord-smoketest.sh';                      dst = '/tmp/coincync-coord-smoketest.sh' }
)

foreach ($p in $payload) {
  if (-not (Test-Path $p.src)) { throw "missing $($p.src)" }
  & scp @sshOpts $p.src "root@${TargetIp}:$($p.dst)"
  if ($LASTEXITCODE -ne 0) { throw "scp $($p.src) failed" }
}

# ── 3. Run install script remotely ────────────────────────────────
Write-Host "=== Running install-coord.sh on root@${TargetIp} ===" -ForegroundColor Cyan
& ssh @sshOpts "root@${TargetIp}" 'chmod +x /tmp/install-coord.sh && /tmp/install-coord.sh'
if ($LASTEXITCODE -ne 0) { throw "remote install failed: exit $LASTEXITCODE" }

# ── 4. Health probe ───────────────────────────────────────────────
Write-Host ""
Write-Host "=== Probing coord service on root@${TargetIp} ===" -ForegroundColor Cyan
& ssh @sshOpts "root@${TargetIp}" 'systemctl is-active coincync-coord.service && ss -lntp | grep -E ":8443\s" || true'

Write-Host ""
Write-Host "=== Done ===" -ForegroundColor Green
Write-Host "  1. Smoke test the local listener:"
Write-Host "       ssh -i `"$SshKey`" root@$TargetIp 'bash /tmp/coincync-coord-smoketest.sh'"
Write-Host ""
Write-Host "  2. Deploy/refresh nginx so /coord/ routes through WSS:"
Write-Host "       .\scripts\deploy-api-nginx.ps1"
Write-Host "     (adds the /coord/ location block; re-running is idempotent)"
Write-Host ""
Write-Host "  3. Public participant URL:"
Write-Host "       wss://api.coincync.network/coord/"
