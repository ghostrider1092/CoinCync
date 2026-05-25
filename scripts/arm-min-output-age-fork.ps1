#requires -Version 5.1
<#
.SYNOPSIS
  Arm the MIN_OUTPUT_AGE 10 -> 100 hard-fork activation height for the
  v1.0.10-testnet tag cut.

.DESCRIPTION
  Pulls the current testnet tip height from a seed node's RPC, adds the
  operator-supplied buffer (default 5000 blocks ≈ 7 days at 120s), and
  edits src/constants.rs to set MIN_OUTPUT_AGE_HARDFORK_HEIGHT to the
  computed activation height. Also refreshes critical_files.lock via the
  build-error trick (compile, capture the new hash from the failure
  message, paste it into the lockfile).

  This script is the LAST step of the pre-tag PR -- run it the
  morning of cut, after the soak window has passed cleanly.

.PARAMETER SeedRpc
  HTTPS URL of a seed node's JSON-RPC endpoint. Defaults to the
  api.coincync.network public endpoint.

.PARAMETER Buffer
  Block buffer between current tip and activation height. Default 5000
  blocks (~7 days at 120s block time). Don't go below 3000 -- operators
  need a real upgrade window.

.PARAMETER DryRun
  Print the computed activation height + the lockfile hash that would
  be written, but don't actually edit any files.

.EXAMPLE
  .\arm-min-output-age-fork.ps1
  # Pulls live tip, picks tip+5000, edits constants.rs + critical_files.lock

.EXAMPLE
  .\arm-min-output-age-fork.ps1 -DryRun
  # Same calculation, but no file edits -- preview only

.EXAMPLE
  .\arm-min-output-age-fork.ps1 -Buffer 10000
  # Twice the standard buffer -- use if you anticipate a slow operator
  # upgrade window (holiday weeks, etc.)
#>

[CmdletBinding()]
param(
  [string]$SeedRpc = "https://api.coincync.network/rpc/testnet",
  [int]$Buffer = 5000,
  [switch]$DryRun
)

$ErrorActionPreference = 'Stop'

# --- Sanity -----------------------------------------------------------
if ($Buffer -lt 3000) {
  Write-Host "ERROR: Buffer < 3000 blocks gives operators <5 days to upgrade." -ForegroundColor Red
  Write-Host "       Either pass -Buffer with a higher value, or accept the risk explicitly." -ForegroundColor Red
  exit 1
}

$repoRoot = Resolve-Path "$PSScriptRoot\.."
$constantsPath = Join-Path $repoRoot "src\constants.rs"
$lockfilePath  = Join-Path $repoRoot "critical_files.lock"

foreach ($f in @($constantsPath, $lockfilePath)) {
  if (-not (Test-Path $f)) {
    Write-Host "ERROR: required file missing: $f" -ForegroundColor Red
    exit 1
  }
}

# --- Pull current testnet tip ----------------------------------------
Write-Host "Querying tip from $SeedRpc ..." -ForegroundColor Cyan
$body = '{"jsonrpc":"2.0","id":1,"method":"get_info"}'

try {
  $resp = Invoke-WebRequest -Uri $SeedRpc -Method POST -Body $body `
            -ContentType 'application/json' -TimeoutSec 10 -UseBasicParsing
} catch {
  Write-Host "ERROR: RPC query failed: $($_.Exception.Message)" -ForegroundColor Red
  Write-Host "       Check the seed is reachable, or pass -SeedRpc <other-seed>." -ForegroundColor Red
  exit 1
}

$info = $resp.Content | ConvertFrom-Json
if (-not $info.result -or -not $info.result.height) {
  Write-Host "ERROR: RPC response missing .result.height field. Raw response:" -ForegroundColor Red
  Write-Host $resp.Content -ForegroundColor Red
  exit 1
}

$tip = [uint64]$info.result.height
$activation = $tip + [uint64]$Buffer

# Compute estimated wall-clock time to activation
$blockTimeSecs = 120
$secsToActivation = $Buffer * $blockTimeSecs
$hoursToActivation = [math]::Round($secsToActivation / 3600.0, 1)
$daysToActivation  = [math]::Round($secsToActivation / 86400.0, 2)

Write-Host ""
Write-Host "===================================================================="
Write-Host "  MIN_OUTPUT_AGE 10 -> 100 HARD-FORK ACTIVATION PLAN" -ForegroundColor Yellow
Write-Host "===================================================================="
Write-Host "  Current testnet tip:        $tip"
Write-Host "  Buffer:                     $Buffer blocks"
Write-Host "  Activation height:          $activation"
Write-Host "  Estimated wallclock:        $hoursToActivation hours ($daysToActivation days)"
Write-Host "  Seed used:                  $SeedRpc"
Write-Host "===================================================================="
Write-Host ""

if ($DryRun) {
  Write-Host "DRY RUN -- no files edited. Run without -DryRun to apply." -ForegroundColor Yellow
  exit 0
}

# --- Edit src/constants.rs -------------------------------------------
Write-Host "Editing $constantsPath ..." -ForegroundColor Cyan

$constantsContent = Get-Content $constantsPath -Raw
$oldLine = '#[cfg(feature = "testnet")]
pub const MIN_OUTPUT_AGE_HARDFORK_HEIGHT: u64 = u64::MAX;'
$newLine = "#[cfg(feature = ""testnet"")]
pub const MIN_OUTPUT_AGE_HARDFORK_HEIGHT: u64 = $activation; // armed $(Get-Date -Format 'yyyy-MM-dd HH:mm') from tip $tip + $Buffer buffer"

if ($constantsContent -notmatch [regex]::Escape($oldLine)) {
  Write-Host "ERROR: expected u64::MAX placeholder not found in constants.rs." -ForegroundColor Red
  Write-Host "       Possibilities:" -ForegroundColor Red
  Write-Host "         (a) Already armed (someone ran this script before)" -ForegroundColor Red
  Write-Host "         (b) Constant was renamed or moved" -ForegroundColor Red
  Write-Host "         (c) Hard fork was rolled back via v1.0.10-ROLLBACK-PLAN.md §1" -ForegroundColor Red
  Write-Host "       Check src/constants.rs manually before retrying." -ForegroundColor Red
  exit 1
}

$constantsNew = $constantsContent.Replace($oldLine, $newLine)
[IO.File]::WriteAllText($constantsPath, $constantsNew, [Text.UTF8Encoding]::new($false))
Write-Host "  [OK] constants.rs armed to activation height $activation" -ForegroundColor Green

# --- Refresh critical_files.lock via the build-error trick -----------
Write-Host ""
Write-Host "Refreshing critical_files.lock (build will fail intentionally to surface the new hash)..." -ForegroundColor Cyan

Push-Location $repoRoot
try {
  $buildOutput = & cargo check --lib 2>&1 | Out-String
} finally {
  Pop-Location
}

# Parse "CHANGED: src/constants.rs ... actual: <hash>"
$hashMatch = $buildOutput -match 'CHANGED:\s+src/constants\.rs\s+expected:\s+([0-9a-f]{64})\s+actual:\s+([0-9a-f]{64})'
if (-not $hashMatch) {
  Write-Host "ERROR: build did not surface the expected hash mismatch." -ForegroundColor Red
  Write-Host "       Possible causes:" -ForegroundColor Red
  Write-Host "         (a) Compilation failed before the integrity check ran" -ForegroundColor Red
  Write-Host "         (b) The integrity-check format changed" -ForegroundColor Red
  Write-Host "         (c) build.rs is broken" -ForegroundColor Red
  Write-Host ""
  Write-Host "Last 30 lines of build output:" -ForegroundColor Yellow
  $buildOutput -split "`n" | Select-Object -Last 30 | ForEach-Object { Write-Host "  $_" }
  exit 1
}

$oldHash = $Matches[1]
$newHash = $Matches[2]
Write-Host "  Old hash: $oldHash" -ForegroundColor Gray
Write-Host "  New hash: $newHash" -ForegroundColor Green

$lockContent = Get-Content $lockfilePath -Raw
$lockNew = $lockContent.Replace("src/constants.rs=$oldHash", "src/constants.rs=$newHash")
if ($lockNew -eq $lockContent) {
  Write-Host "ERROR: lockfile substitution didn't match. Manual edit needed." -ForegroundColor Red
  exit 1
}
[IO.File]::WriteAllText($lockfilePath, $lockNew, [Text.UTF8Encoding]::new($false))
Write-Host "  [OK] critical_files.lock refreshed" -ForegroundColor Green

# --- Final sanity build ----------------------------------------------
Write-Host ""
Write-Host "Re-running cargo check to confirm clean compile..." -ForegroundColor Cyan
Push-Location $repoRoot
try {
  & cargo check --lib 2>&1 | Out-Null
  $exitCode = $LASTEXITCODE
} finally {
  Pop-Location
}

if ($exitCode -ne 0) {
  Write-Host "ERROR: post-edit cargo check failed with exit $exitCode." -ForegroundColor Red
  Write-Host "       Revert with: git checkout -- src/constants.rs critical_files.lock" -ForegroundColor Red
  exit 1
}
Write-Host "  [OK] cargo check clean" -ForegroundColor Green

# --- Final report ----------------------------------------------------
Write-Host ""
Write-Host "===================================================================="
Write-Host "  ARMED. Next steps:" -ForegroundColor Yellow
Write-Host "===================================================================="
Write-Host "  1. Review the diff:"
Write-Host "       git diff src/constants.rs critical_files.lock"
Write-Host ""
Write-Host "  2. Run the full pre-tag checklist per"
Write-Host "       docs/launch/v1.0.10-CHECKLIST.md §6"
Write-Host ""
Write-Host "  3. Commit:"
Write-Host "       git add src/constants.rs critical_files.lock"
Write-Host "       git commit -m ""arm: MIN_OUTPUT_AGE hard fork at testnet height $activation"""
Write-Host ""
Write-Host "  4. After CI green, tag:"
Write-Host "       git tag -s v1.0.10-testnet -m ""..."""
Write-Host ""
Write-Host "  5. Update the {ACTIVATION_HEIGHT_TBD} placeholder in"
Write-Host "       out/discord-release-post-v1.0.10.txt with $activation"
Write-Host ""
Write-Host "  Activation in approximately $hoursToActivation hours ($daysToActivation days) from tag time." -ForegroundColor Cyan
