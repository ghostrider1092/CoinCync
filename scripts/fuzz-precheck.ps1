#requires -Version 5.1
<#
.SYNOPSIS
  Verify the fuzz crate compiles cleanly before kicking off an overnight run.

.DESCRIPTION
  The fuzz overnight is an 8h+ wallclock investment. Before launching it,
  confirm:
    1. Every declared fuzz target compiles (no API drift from a recent
       refactor that would crash the fuzz launch at minute 5)
    2. The fuzz crate's deps list is consistent with the targets that
       use them (one prior session burned a debug round on serde/axum/
       tokio being declared in the wrong place in Cargo.toml)
    3. The 2026-05-24 session's two flagged-failing targets
       (fuzz_p2p_message, fuzz_wallet_persistence) reference live
       library symbols
    4. Corpora directories exist where targets need them

.PARAMETER WslFuzzPath
  Where the WSL fuzz workspace lives. Default ~/coincync-fuzz per the
  reference_windows_tooling memory entry. If running on Linux directly
  rather than via WSL, pass the path explicitly.

.PARAMETER Quick
  Skip the full cargo check on the fuzz crate (which takes 3-5 min
  cold). Just do the syntactic/symbolic checks.

.EXAMPLE
  .\fuzz-precheck.ps1
  # Full precheck including cargo check on fuzz crate

.EXAMPLE
  .\fuzz-precheck.ps1 -Quick
  # ~10 second check (skip cargo check)
#>

[CmdletBinding()]
param(
  [string]$WslFuzzPath = "~/coincync-fuzz",
  [switch]$Quick
)

$ErrorActionPreference = 'Stop'
$repoRoot = Resolve-Path "$PSScriptRoot\.."
Push-Location $repoRoot

$results = @()
function Add-Check {
  param([string]$Name, [string]$Status, [string]$Detail = "")
  $script:results += [PSCustomObject]@{ Name = $Name; Status = $Status; Detail = $Detail }
  $marker = switch ($Status) {
    'PASS' { '  [OK] ' }
    'FAIL' { '  [X] ' }
    'WARN' { '  ! ' }
  }
  $color = switch ($Status) {
    'PASS' { 'Green' }
    'FAIL' { 'Red' }
    'WARN' { 'Yellow' }
  }
  Write-Host "$marker$($Name.PadRight(56)) $Status" -ForegroundColor $color
  if ($Detail) { Write-Host "        $Detail" -ForegroundColor Gray }
}

Write-Host ""
Write-Host "===================================================================="
Write-Host "  FUZZ PRECHECK" -ForegroundColor Yellow
Write-Host "===================================================================="
Write-Host ""

try {

# --- 1. Every fuzz target source file exists + has a [[bin]] entry -----
$targetSources = Get-ChildItem "fuzz\fuzz_targets\*.rs" | Select-Object -ExpandProperty BaseName
$fuzzToml = Get-Content "fuzz\Cargo.toml" -Raw
$declaredBins = [regex]::Matches($fuzzToml, '\[\[bin\]\][^[]*name\s*=\s*"([^"]+)"') | ForEach-Object { $_.Groups[1].Value }

Write-Host "Source files vs [[bin]] declarations" -ForegroundColor Cyan
foreach ($src in $targetSources) {
  if ($declaredBins -contains $src) {
    Add-Check "$src" "PASS"
  } else {
    Add-Check "$src" "FAIL" "source exists at fuzz_targets/$src.rs but no [[bin]] in fuzz/Cargo.toml -- won't be exercised"
  }
}
$orphanBins = $declaredBins | Where-Object { $_ -notin $targetSources }
foreach ($orph in $orphanBins) {
  Add-Check "$orph (declared)" "FAIL" "[[bin]] in fuzz/Cargo.toml but no fuzz_targets/$orph.rs source -- cargo-fuzz will error"
}

# --- 2. Top-level deps are positioned before any [dependencies.X] subtable -
# The historical bug: serde/serde_json/axum/etc. were placed AFTER
# [dependencies.coincync-rolling-finality] and TOML parsed them as
# *keys of that dep spec*. Six targets silently failed to compile.
Write-Host ""
Write-Host "Dep-list positioning (catches the 2026-05-17 mis-parse)" -ForegroundColor Cyan
$lines = Get-Content "fuzz\Cargo.toml"
$firstSubtable = -1
for ($i = 0; $i -lt $lines.Count; $i++) {
  if ($lines[$i] -match '^\[dependencies\.\w') {
    $firstSubtable = $i
    break
  }
}
if ($firstSubtable -ge 0) {
  $stragglers = $false
  for ($i = $firstSubtable + 1; $i -lt $lines.Count; $i++) {
    # A new section header resets us into safe territory.
    if ($lines[$i] -match '^\[') { break }
    if ($lines[$i] -match '^[a-zA-Z][\w-]*\s*=') {
      # This is a top-level dep nested under the subtable -- bug.
      Add-Check "no orphan top-level deps under [dependencies.X]" "FAIL" `
        "line $($i+1): '$($lines[$i].Trim())' is being parsed as a key of the subtable above, not a top-level dep"
      $stragglers = $true
      break
    }
  }
  if (-not $stragglers) {
    Add-Check "no orphan top-level deps under [dependencies.X]" "PASS"
  }
} else {
  Add-Check "no orphan top-level deps under [dependencies.X]" "PASS" "no [dependencies.X] subtables yet"
}

# --- 3. The two flagged-failing targets reference live symbols ----------
Write-Host ""
Write-Host "Flagged-failing targets reference live library symbols" -ForegroundColor Cyan

# fuzz_p2p_message: uses borsh::from_slice::<TypedMessage>(payload) per the
# API-drift fix in commit 03fb1af. Verify TypedMessage is still pub.
$p2pSrc = Get-Content "fuzz\fuzz_targets\fuzz_p2p_message.rs" -Raw
if ($p2pSrc -notmatch 'borsh::from_slice') {
  Add-Check "fuzz_p2p_message uses post-drift API" "WARN" "doesn't reference borsh::from_slice -- may have regressed"
} else {
  Add-Check "fuzz_p2p_message uses post-drift API" "PASS"
}

# fuzz_wallet_persistence: uses load_wallet_from_bytes.
$walletSrc = Get-Content "fuzz\fuzz_targets\fuzz_wallet_persistence.rs" -Raw
if ($walletSrc -notmatch 'load_wallet_from_bytes') {
  Add-Check "fuzz_wallet_persistence references load_wallet_from_bytes" "WARN"
} else {
  # Confirm the lib symbol is still pub
  $libCheck = Select-String -Path "src\wallet\persistence.rs" -Pattern 'pub fn load_wallet_from_bytes' -Quiet
  if ($libCheck) {
    Add-Check "fuzz_wallet_persistence references load_wallet_from_bytes" "PASS"
  } else {
    Add-Check "fuzz_wallet_persistence references load_wallet_from_bytes" "FAIL" "load_wallet_from_bytes not pub in src/wallet/persistence.rs -- fuzz target will fail to compile"
  }
}

# --- 4. Corpora directories exist for the targets that pre-seed them ----
Write-Host ""
Write-Host "Corpora directories" -ForegroundColor Cyan
$corporaParent = "fuzz\corpus"
if (Test-Path $corporaParent) {
  foreach ($src in $targetSources) {
    $corpDir = Join-Path $corporaParent $src
    if (Test-Path $corpDir) {
      $seedCount = (Get-ChildItem $corpDir -File).Count
      if ($seedCount -gt 0) {
        Add-Check "$src corpus seeded" "PASS" "$seedCount seed(s)"
      } else {
        Add-Check "$src corpus seeded" "WARN" "directory exists but empty"
      }
    }
  }
} else {
  Add-Check "fuzz/corpus parent dir" "WARN" "no corpus dir -- first run will start from scratch"
}

# --- 5. Full cargo check (skippable) -------------------------------------
if (-not $Quick) {
  Write-Host ""
  Write-Host "Full compile check (cargo check on fuzz crate, 3-5 min cold)" -ForegroundColor Cyan
  Write-Host "  (Pass -Quick to skip)" -ForegroundColor Gray
  Push-Location "fuzz"
  try {
    $checkOut = & cargo check 2>&1 | Out-String
    if ($LASTEXITCODE -eq 0) {
      $warnCount = ([regex]::Matches($checkOut, 'warning:')).Count
      Add-Check "cargo check on fuzz crate" "PASS" "$warnCount warnings"
    } else {
      $errors = ($checkOut -split "`n" | Where-Object { $_ -match '^error\[' -or $_ -match '^error:' } | Select-Object -First 5) -join '; '
      Add-Check "cargo check on fuzz crate" "FAIL" $errors
    }
  } finally {
    Pop-Location
  }
}

# --- 6. WSL fuzz workspace exists (reference check, not a hard fail) -----
Write-Host ""
Write-Host "WSL fuzz workspace (reference)" -ForegroundColor Cyan
$wslCheck = wsl test -d $WslFuzzPath 2>&1
if ($LASTEXITCODE -eq 0) {
  Add-Check "WSL workspace at $WslFuzzPath" "PASS"
} else {
  Add-Check "WSL workspace at $WslFuzzPath" "WARN" "not found -- operator runs fuzz from there per scripts/fuzz-wsl-setup.md"
}

# --- Summary -------------------------------------------------------------
Write-Host ""
Write-Host "===================================================================="
$passCount = ($results | Where-Object { $_.Status -eq 'PASS' }).Count
$warnCount = ($results | Where-Object { $_.Status -eq 'WARN' }).Count
$failCount = ($results | Where-Object { $_.Status -eq 'FAIL' }).Count
Write-Host "  Summary: $passCount pass / $warnCount warn / $failCount fail" `
  -ForegroundColor $(if ($failCount -gt 0) { 'Red' } elseif ($warnCount -gt 0) { 'Yellow' } else { 'Green' })
Write-Host "===================================================================="

if ($failCount -gt 0) {
  Write-Host ""
  Write-Host "  Fix the failures above before kicking off the overnight fuzz run." -ForegroundColor Red
  Write-Host "  An 8h fuzz run that crashes at minute 5 with an API-drift error" -ForegroundColor Red
  Write-Host "  wastes 8h of wallclock and tells you nothing about chain security." -ForegroundColor Red
  Pop-Location
  exit 1
}

Write-Host ""
Write-Host "  Precheck clear. Kick off the overnight fuzz run on WSL:" -ForegroundColor Green
Write-Host "    wsl -e bash -c 'cd $WslFuzzPath && bash $repoRoot/scripts/fuzz-overnight.sh'" -ForegroundColor Cyan
Pop-Location
exit 0

} catch {
  Pop-Location
  throw
}
