#requires -Version 5.1
<#
.SYNOPSIS
  One-shot pre-tag readiness check for v1.0.10-testnet.

.DESCRIPTION
  Runs the mechanical pre-tag checklist items from
  docs/launch/v1.0.10-CHECKLIST.md §6 and reports pass/fail for each.
  Designed for the morning-of-tag run: paste, eyeball, decide.

  What it checks:
    1. Git tree state -- uncommitted changes, ahead of origin, etc.
    2. Critical-files lockfile integrity (cargo build succeeds = OK)
    3. Full lib test suite (default features)
    4. Consensus test suite (--features randomx)
    5. Version-string consistency across the 4 version-bearing files
    6. Activation-height armed (MIN_OUTPUT_AGE_HARDFORK_HEIGHT != u64::MAX)
    7. Required artifacts in place (docs, scripts, release notes)

  What it does NOT check (operator-confirms separately):
    - 5-day soak completed cleanly (operator memory)
    - Reproducible Docker build sha matches (separate script)
    - Fuzz overnight cleared in CI (operator checks GH Actions)
    - Real testnet self-send dogfood passed (operator runs separately)
    - >=80% fleet upgrade % (peer-versions.ps1 is its own gate)

.PARAMETER ExpectVersion
  Version string that should appear consistently across all
  version-bearing files. Default "1.0.10".

.PARAMETER SkipTests
  Skip the cargo test runs (fast preview mode). Don't ship from a
  -SkipTests run -- only use for quick iteration.

.EXAMPLE
  .\pretag-check.ps1
  # Full check ~10-15 min wallclock for the test runs

.EXAMPLE
  .\pretag-check.ps1 -SkipTests
  # ~30 seconds, structural checks only
#>

[CmdletBinding()]
param(
  [ValidatePattern('^\d+\.\d+\.\d+$')]
  [string]$ExpectVersion = "1.0.10",

  [switch]$SkipTests
)

$ErrorActionPreference = 'Stop'
$repoRoot = Resolve-Path "$PSScriptRoot\.."
Push-Location $repoRoot

$results = @()
function Add-Check {
  param([string]$Name, [string]$Status, [string]$Detail = "")
  $script:results += [PSCustomObject]@{ Name = $Name; Status = $Status; Detail = $Detail }
  $color = switch ($Status) {
    'PASS' { 'Green' }
    'FAIL' { 'Red' }
    'WARN' { 'Yellow' }
    default { 'Gray' }
  }
  $marker = switch ($Status) {
    'PASS' { '  [OK] ' }
    'FAIL' { '  [X] ' }
    'WARN' { '  ! ' }
    default { '  . ' }
  }
  Write-Host "$marker$($Name.PadRight(48)) $Status" -ForegroundColor $color
  if ($Detail) { Write-Host "        $Detail" -ForegroundColor Gray }
}

Write-Host ""
Write-Host "===================================================================="
Write-Host "  v1.0.10 PRE-TAG CHECK -- target version v$ExpectVersion" -ForegroundColor Yellow
Write-Host "===================================================================="
Write-Host ""

try {

# --- 1. Git tree state ------------------------------------------------
Write-Host "Git tree state" -ForegroundColor Cyan
$gitStatus = git status --porcelain 2>&1
$dirty = $gitStatus -split "`n" | Where-Object { $_ -match '^[MA?]' -and $_ -notmatch '^\?\? ' }
if ($dirty) {
  Add-Check "git status clean" "WARN" "$($dirty.Count) tracked-file modifications uncommitted"
} else {
  Add-Check "git status clean" "PASS" "tracked files: clean (untracked OK)"
}

$ahead = (git rev-list --count origin/main..HEAD 2>&1) -as [int]
if ($ahead -eq 0) {
  Add-Check "no commits ahead of origin/main" "PASS"
} else {
  Add-Check "no commits ahead of origin/main" "WARN" "$ahead unpushed commit(s) -- push before tagging or tag will be on a stale base"
}

# --- 2. Critical-files lockfile + cargo build clean ------------------
Write-Host ""
Write-Host "Critical-files integrity" -ForegroundColor Cyan
Write-Host "  Running cargo check --lib (touches build.rs integrity check)..."
$check = & cargo check --lib 2>&1 | Out-String
if ($LASTEXITCODE -eq 0) {
  Add-Check "cargo check --lib clean" "PASS" "build.rs integrity check passed = lockfile consistent"
} else {
  $hashLine = ($check -split "`n" | Where-Object { $_ -match 'CHANGED:|actual:' }) -join "; "
  Add-Check "cargo check --lib clean" "FAIL" "build failed -- $hashLine"
}

# --- 3. Full lib test suite -------------------------------------------
Write-Host ""
Write-Host "Test suites" -ForegroundColor Cyan
if ($SkipTests) {
  Add-Check "cargo test --lib (default features)" "WARN" "skipped (-SkipTests)"
  Add-Check "cargo test --lib --features randomx" "WARN" "skipped (-SkipTests)"
} else {
  Write-Host "  Running cargo test --lib (5-10 min)..."
  $testOut = & cargo test --lib 2>&1 | Out-String
  if ($LASTEXITCODE -eq 0) {
    $summary = ($testOut -split "`n" | Where-Object { $_ -match '^test result:' } | Select-Object -Last 1)
    Add-Check "cargo test --lib (default features)" "PASS" $summary.Trim()
  } else {
    $failures = ($testOut -split "`n" | Where-Object { $_ -match 'FAILED' } | Select-Object -First 5) -join "; "
    Add-Check "cargo test --lib (default features)" "FAIL" $failures
  }

  Write-Host "  Running cargo test --lib --features randomx consensus:: (2-3 min)..."
  $testOut2 = & cargo test --lib --features randomx consensus:: 2>&1 | Out-String
  if ($LASTEXITCODE -eq 0) {
    $summary = ($testOut2 -split "`n" | Where-Object { $_ -match '^test result:' } | Select-Object -Last 1)
    Add-Check "cargo test consensus:: (--features randomx)" "PASS" $summary.Trim()
  } else {
    $failures = ($testOut2 -split "`n" | Where-Object { $_ -match 'FAILED' } | Select-Object -First 5) -join "; "
    Add-Check "cargo test consensus:: (--features randomx)" "FAIL" $failures
  }
}

# --- 5. Version-string consistency ------------------------------------
Write-Host ""
Write-Host "Version-string consistency (target: v$ExpectVersion)" -ForegroundColor Cyan
$versionFiles = @(
  @{ Path = "Cargo.toml";                                Pattern = '(?m)^version\s*=\s*"([\d.]+)"';        Label = "Cargo.toml (root)" }
  @{ Path = "coincync-wallet-v2\src-tauri\Cargo.toml";   Pattern = '(?m)^version\s*=\s*"([\d.]+)"';        Label = "wallet-v2/src-tauri" }
  @{ Path = "coincync-wallet-v2\package.json";           Pattern = '"version":\s*"([\d.]+)"';              Label = "wallet-v2/package.json" }
  @{ Path = "src\explorer\fragments\00-shell.html";      Pattern = 'v([\d.]+)';                            Label = "explorer (first match)" }
)
$allConsistent = $true
foreach ($vf in $versionFiles) {
  if (-not (Test-Path $vf.Path)) {
    Add-Check "$($vf.Label)" "FAIL" "file missing: $($vf.Path)"
    $allConsistent = $false
    continue
  }
  $content = Get-Content $vf.Path -Raw
  $m = [regex]::Match($content, $vf.Pattern)
  if (-not $m.Success) {
    Add-Check "$($vf.Label)" "FAIL" "version pattern not found"
    $allConsistent = $false
    continue
  }
  $found = $m.Groups[1].Value
  if ($found -eq $ExpectVersion) {
    Add-Check "$($vf.Label)" "PASS" "v$found"
  } else {
    Add-Check "$($vf.Label)" "FAIL" "found v$found, expected v$ExpectVersion -- run bump-version.ps1"
    $allConsistent = $false
  }
}

# --- 6. Activation-height armed ---------------------------------------
Write-Host ""
Write-Host "MIN_OUTPUT_AGE activation guard" -ForegroundColor Cyan
$constants = Get-Content "src\constants.rs" -Raw
if ($constants -match 'MIN_OUTPUT_AGE_HARDFORK_HEIGHT:\s*u64\s*=\s*u64::MAX') {
  Add-Check "activation height armed" "FAIL" "still u64::MAX -- run arm-min-output-age-fork.ps1 before tagging"
} elseif ($constants -match 'MIN_OUTPUT_AGE_HARDFORK_HEIGHT:\s*u64\s*=\s*(\d+)') {
  $armedHeight = $Matches[1]
  Add-Check "activation height armed" "PASS" "set to $armedHeight"
} else {
  Add-Check "activation height armed" "WARN" "couldn't parse MIN_OUTPUT_AGE_HARDFORK_HEIGHT line -- manual check"
}

# --- 7. Required artifacts --------------------------------------------
Write-Host ""
Write-Host "Release artifacts" -ForegroundColor Cyan
$artifacts = @(
  "docs\launch\v1.0.10-CHECKLIST.md"
  "docs\launch\v1.0.10-ROLLBACK-PLAN.md"
  "out\discord-release-post-v1.0.10.txt"
  "scripts\arm-min-output-age-fork.ps1"
  "scripts\bump-version.ps1"
  "scripts\peer-versions.ps1"
)
foreach ($a in $artifacts) {
  if (Test-Path $a) { Add-Check "artifact: $a" "PASS" }
  else              { Add-Check "artifact: $a" "FAIL" "missing -- create before tagging" }
}

# Check the Discord post no longer has placeholder
if (Test-Path "out\discord-release-post-v1.0.10.txt") {
  $discord = Get-Content "out\discord-release-post-v1.0.10.txt" -Raw
  if ($discord -match '\{ACTIVATION_HEIGHT_TBD\}') {
    Add-Check "Discord post: activation height filled in" "FAIL" "still has {ACTIVATION_HEIGHT_TBD} placeholder"
  } else {
    Add-Check "Discord post: activation height filled in" "PASS"
  }
}

# --- Summary ----------------------------------------------------------
Write-Host ""
Write-Host "===================================================================="
$passCount = ($results | Where-Object { $_.Status -eq 'PASS' }).Count
$warnCount = ($results | Where-Object { $_.Status -eq 'WARN' }).Count
$failCount = ($results | Where-Object { $_.Status -eq 'FAIL' }).Count
Write-Host "  Summary: $passCount pass / $warnCount warn / $failCount fail" -ForegroundColor $(if ($failCount -gt 0) { 'Red' } elseif ($warnCount -gt 0) { 'Yellow' } else { 'Green' })
Write-Host "===================================================================="

if ($failCount -gt 0) {
  Write-Host ""
  Write-Host "  [X] NOT READY TO TAG. Fix the failures above and re-run." -ForegroundColor Red
  Write-Host ""
  Write-Host "  Operator-side items NOT covered by this script (verify separately):" -ForegroundColor Yellow
  Write-Host "    * 5-day soak completed cleanly with the activation height armed"
  Write-Host "    * Reproducible Docker build hash matches local release build"
  Write-Host "    * Fuzz overnight run cleared in CI"
  Write-Host "    * Real testnet self-send dogfood passed"
  Write-Host "    * peer-versions.ps1 reports >=80% fleet upgrade"
  Pop-Location
  exit 1
}

if ($warnCount -gt 0) {
  Write-Host ""
  Write-Host "  ! TAG WITH CAUTION. Warnings above -- read each and decide." -ForegroundColor Yellow
}

Write-Host ""
Write-Host "  Mechanical checks pass. Operator-side items still required:" -ForegroundColor Cyan
Write-Host "    * 5-day soak completed cleanly with the activation height armed"
Write-Host "    * Reproducible Docker build hash matches local release build"
Write-Host "    * Fuzz overnight run cleared in CI"
Write-Host "    * Real testnet self-send dogfood passed"
Write-Host "    * peer-versions.ps1 reports >=80% fleet upgrade"
Write-Host ""
Write-Host "  When all of the above are green: proceed to §7 (Launch coordination)." -ForegroundColor Green
Pop-Location
exit 0

} catch {
  Pop-Location
  throw
}
