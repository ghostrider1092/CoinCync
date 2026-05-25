#requires -Version 5.1
<#
.SYNOPSIS
  Bump CoinCync version across all four version-bearing files atomically.

.DESCRIPTION
  At tag-cut time, the version string lives in 4 separate files. Editing
  them by hand has historically produced mismatches (wallet showed
  v1.0.9 while the node logged v1.0.10 because the wallet bump was
  forgotten). This script does all four at once with a single source of
  truth.

  Files updated:
    1. Cargo.toml                                — workspace root
    2. coincync-wallet-v2/src-tauri/Cargo.toml   — desktop wallet (Rust)
    3. coincync-wallet-v2/package.json           — desktop wallet (JS)
    4. src/explorer/index.html                   — explorer footer + ticker

.PARAMETER NewVersion
  Target version string, e.g. "1.0.10" (no leading "v"). Must match the
  X.Y.Z semver shape; pre-release suffixes (-testnet, -rc1) belong on
  the tag, not in the version field.

.PARAMETER DryRun
  Print the diff that would be applied, but don't write.

.EXAMPLE
  .\bump-version.ps1 -NewVersion 1.0.10
#>

[CmdletBinding()]
param(
  [Parameter(Mandatory = $true)]
  [ValidatePattern('^\d+\.\d+\.\d+$')]
  [string]$NewVersion,

  [switch]$DryRun
)

$ErrorActionPreference = 'Stop'
$repoRoot = Resolve-Path "$PSScriptRoot\.."

$targets = @(
  @{
    Path     = Join-Path $repoRoot "Cargo.toml"
    Label    = "Cargo.toml (workspace root)"
    Pattern  = '(?m)^version\s*=\s*"\d+\.\d+\.\d+"'
    Replace  = "version = ""$NewVersion"""
  }
  @{
    Path     = Join-Path $repoRoot "coincync-wallet-v2\src-tauri\Cargo.toml"
    Label    = "wallet-v2 src-tauri Cargo.toml"
    Pattern  = '(?m)^version\s*=\s*"\d+\.\d+\.\d+"'
    Replace  = "version = ""$NewVersion"""
  }
  @{
    Path     = Join-Path $repoRoot "coincync-wallet-v2\package.json"
    Label    = "wallet-v2 package.json"
    Pattern  = '"version":\s*"\d+\.\d+\.\d+"'
    Replace  = """version"": ""$NewVersion"""
  }
  @{
    Path     = Join-Path $repoRoot "src\explorer\index.html"
    Label    = "explorer ticker/footer"
    # Matches: v1.0.9, v1.0.10, etc. across multiple sites — footer + ticker
    Pattern  = 'v\d+\.\d+\.\d+'
    Replace  = "v$NewVersion"
  }
)

# ─── Pre-flight: check all files exist ─────────────────────────────────
$missing = $targets | Where-Object { -not (Test-Path $_.Path) }
if ($missing.Count -gt 0) {
  Write-Host "ERROR: missing files:" -ForegroundColor Red
  $missing | ForEach-Object { Write-Host "  $($_.Path)" -ForegroundColor Red }
  exit 1
}

# ─── For each file: snapshot current version, plan the diff ───────────
$results = @()
foreach ($t in $targets) {
  $content = Get-Content $t.Path -Raw
  $matches = [regex]::Matches($content, $t.Pattern)

  if ($matches.Count -eq 0) {
    Write-Host "ERROR: pattern not found in $($t.Label): $($t.Pattern)" -ForegroundColor Red
    Write-Host "       Either the file's version-line format changed, or this script is out of date." -ForegroundColor Red
    exit 1
  }

  # All matches in a single file should be the same current version — sanity check.
  $currentValues = $matches | ForEach-Object { $_.Value } | Sort-Object -Unique
  if ($currentValues.Count -gt 1) {
    Write-Host "ERROR: $($t.Label) contains multiple distinct version strings:" -ForegroundColor Red
    $currentValues | ForEach-Object { Write-Host "  $_" -ForegroundColor Red }
    Write-Host "       Manual reconcile before re-running." -ForegroundColor Red
    exit 1
  }

  $newContent = [regex]::Replace($content, $t.Pattern, $t.Replace)

  $results += [PSCustomObject]@{
    Path        = $t.Path
    Label       = $t.Label
    Current     = $currentValues[0]
    New         = $t.Replace
    SiteCount   = $matches.Count
    NewContent  = $newContent
  }
}

# ─── Report ───────────────────────────────────────────────────────────
Write-Host ""
Write-Host "════════════════════════════════════════════════════════════════════"
Write-Host "  VERSION BUMP → $NewVersion" -ForegroundColor Yellow
Write-Host "════════════════════════════════════════════════════════════════════"
foreach ($r in $results) {
  $sites = if ($r.SiteCount -gt 1) { " ($($r.SiteCount) sites)" } else { "" }
  Write-Host "  $($r.Label)$sites"
  Write-Host "    $($r.Current)  →  $($r.New)" -ForegroundColor Gray
}
Write-Host "════════════════════════════════════════════════════════════════════"
Write-Host ""

if ($DryRun) {
  Write-Host "DRY RUN — no files written. Run without -DryRun to apply." -ForegroundColor Yellow
  exit 0
}

# ─── Write ────────────────────────────────────────────────────────────
foreach ($r in $results) {
  [IO.File]::WriteAllText($r.Path, $r.NewContent, [Text.UTF8Encoding]::new($false))
  Write-Host "  ✓ $($r.Label) updated" -ForegroundColor Green
}

Write-Host ""
Write-Host "Next steps:" -ForegroundColor Cyan
Write-Host "  1. Verify the diff:"
Write-Host "       git diff Cargo.toml coincync-wallet-v2 src/explorer/index.html"
Write-Host ""
Write-Host "  2. Confirm the workspace still builds:"
Write-Host "       cargo check --lib"
Write-Host ""
Write-Host "  3. Commit alongside the tag-cut PR:"
Write-Host "       git add Cargo.toml coincync-wallet-v2/src-tauri/Cargo.toml \\"
Write-Host "               coincync-wallet-v2/package.json src/explorer/index.html"
Write-Host "       git commit -m ""release: bump to v$NewVersion"""
