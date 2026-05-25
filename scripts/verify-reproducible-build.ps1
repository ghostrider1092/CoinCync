#requires -Version 5.1
<#
.SYNOPSIS
  Verify the v1.0.10 release binaries are reproducibly buildable.

.DESCRIPTION
  Runs the canonical Docker build TWICE from the same git commit, then
  diffs the binary hashes. Byte-identical hashes prove the build is
  reproducible — the audit firm's reviewer can rebuild from source and
  verify the published SHA256SUMS file matches their own build, with
  no "trust me" leap.

  Designed to be run on the tag-cut day:
    - Run-1 produces the release artifacts that ship with the GitHub release
    - Run-2 produces a fresh-clone equivalent to compare against
    - If hashes diverge, that's a reproducibility regression and a tag blocker

  Also writes out the SHA256SUMS file that goes alongside the release,
  formatted so operators can verify with the standard sha256sum -c.

.PARAMETER GitBashPath
  Path to Git Bash on Windows. Default "C:\Program Files\Git\bin\bash.exe".

.PARAMETER SkipSecondRun
  Skip the run-2 comparison (single-build mode). Use for fast preview;
  the actual repro guarantee requires two runs.

.EXAMPLE
  .\verify-reproducible-build.ps1
  # Full two-run repro verification (~30 min if Docker cache cold,
  # ~10 min warm — runs build twice)

.EXAMPLE
  .\verify-reproducible-build.ps1 -SkipSecondRun
  # Single build; outputs SHA256SUMS but does NOT prove reproducibility
#>

[CmdletBinding()]
param(
  [string]$GitBashPath = "C:\Program Files\Git\bin\bash.exe",
  [switch]$SkipSecondRun
)

$ErrorActionPreference = 'Stop'
$repoRoot = Resolve-Path "$PSScriptRoot\.."
Push-Location $repoRoot

try {

# ─── Pre-flight ───────────────────────────────────────────────────────
if (-not (Test-Path $GitBashPath)) {
  Write-Host "ERROR: Git Bash not found at $GitBashPath" -ForegroundColor Red
  Write-Host "       Pass -GitBashPath <path> or install Git for Windows." -ForegroundColor Red
  exit 1
}

# Docker daemon reachable?
$dockerPing = & docker version --format '{{.Server.Version}}' 2>&1
if ($LASTEXITCODE -ne 0) {
  Write-Host "ERROR: Docker daemon unreachable. Start Docker Desktop and retry." -ForegroundColor Red
  exit 1
}
Write-Host "Docker daemon: $dockerPing" -ForegroundColor Gray

# Git state should be clean — repro-build of a dirty tree is meaningless.
$dirty = git status --porcelain 2>&1 | Where-Object { $_ -match '^[MA]' }
if ($dirty) {
  Write-Host "ERROR: working tree has uncommitted modifications:" -ForegroundColor Red
  $dirty | ForEach-Object { Write-Host "  $_" -ForegroundColor Red }
  Write-Host "       Commit or stash first — reproducible build only meaningful on a tagged commit." -ForegroundColor Red
  exit 1
}

$currentCommit = git rev-parse HEAD
Write-Host "Current commit: $currentCommit" -ForegroundColor Cyan

# ─── Run 1 — primary build ────────────────────────────────────────────
Write-Host ""
Write-Host "════════════════════════════════════════════════════════════════════"
Write-Host "  RUN 1 — primary Docker build" -ForegroundColor Yellow
Write-Host "════════════════════════════════════════════════════════════════════"
Write-Host ""

$runStart = Get-Date
$env:MSYS_NO_PATHCONV = "1"  # prevents Git Bash from rewriting /out → C:/Program Files/Git/out
& $GitBashPath -c "cd '$($repoRoot -replace '\\','/')' && ./scripts/build-in-docker.sh"
if ($LASTEXITCODE -ne 0) {
  Write-Host "ERROR: run-1 Docker build failed (exit $LASTEXITCODE)" -ForegroundColor Red
  Pop-Location
  exit 1
}
$run1Elapsed = (Get-Date) - $runStart
Write-Host "  Run-1 complete in $($run1Elapsed.TotalMinutes.ToString('0.0')) min" -ForegroundColor Green

# Capture hashes from run-1
$outDir = Join-Path $repoRoot "out"
if (-not (Test-Path (Join-Path $outDir "SHA256SUMS"))) {
  Write-Host "ERROR: run-1 did not produce out/SHA256SUMS" -ForegroundColor Red
  exit 1
}
$run1Hashes = Get-Content (Join-Path $outDir "SHA256SUMS") -Raw
Write-Host ""
Write-Host "Run-1 hashes:" -ForegroundColor Cyan
$run1Hashes -split "`n" | Where-Object { $_.Trim() } | ForEach-Object { Write-Host "  $_" -ForegroundColor Gray }

if ($SkipSecondRun) {
  Write-Host ""
  Write-Host "════════════════════════════════════════════════════════════════════"
  Write-Host "  -SkipSecondRun: bypassing run-2 comparison." -ForegroundColor Yellow
  Write-Host "  These hashes are POSSIBLY reproducible but unverified." -ForegroundColor Yellow
  Write-Host "  For the tag-cut release, run without -SkipSecondRun." -ForegroundColor Yellow
  Write-Host "════════════════════════════════════════════════════════════════════"
  Write-Host ""
  Write-Host "  SHA256SUMS at: $outDir\SHA256SUMS"
  Write-Host "  Operators verify with: sha256sum -c SHA256SUMS"
  Pop-Location
  exit 0
}

# ─── Stash run-1 outputs before run-2 overwrites ──────────────────────
$run1Backup = Join-Path $env:TEMP "coincync-repro-run1-$(Get-Date -Format yyyyMMdd-HHmmss)"
New-Item -ItemType Directory -Path $run1Backup -Force | Out-Null
Copy-Item -Path "$outDir\*" -Destination $run1Backup -Recurse
Write-Host ""
Write-Host "Run-1 outputs backed up to: $run1Backup" -ForegroundColor Gray

# ─── Run 2 — verification build ───────────────────────────────────────
Write-Host ""
Write-Host "════════════════════════════════════════════════════════════════════"
Write-Host "  RUN 2 — verification Docker build" -ForegroundColor Yellow
Write-Host "════════════════════════════════════════════════════════════════════"
Write-Host ""

# Force fresh build by clearing cargo cache in the Docker volume.
# This is more aggressive than necessary but it's the audit-firm
# replication path — they'll start from cold.
Write-Host "Clearing Docker build cache (forces fresh compile)..." -ForegroundColor Gray
& docker builder prune --filter "label=coincync-build" --force 2>&1 | Out-Null

$runStart = Get-Date
& $GitBashPath -c "cd '$($repoRoot -replace '\\','/')' && ./scripts/build-in-docker.sh"
if ($LASTEXITCODE -ne 0) {
  Write-Host "ERROR: run-2 Docker build failed (exit $LASTEXITCODE)" -ForegroundColor Red
  Pop-Location
  exit 1
}
$run2Elapsed = (Get-Date) - $runStart
Write-Host "  Run-2 complete in $($run2Elapsed.TotalMinutes.ToString('0.0')) min" -ForegroundColor Green

$run2Hashes = Get-Content (Join-Path $outDir "SHA256SUMS") -Raw

# ─── Compare ──────────────────────────────────────────────────────────
Write-Host ""
Write-Host "════════════════════════════════════════════════════════════════════"
Write-Host "  REPRODUCIBILITY VERDICT" -ForegroundColor Yellow
Write-Host "════════════════════════════════════════════════════════════════════"
Write-Host ""

if ($run1Hashes.Trim() -eq $run2Hashes.Trim()) {
  Write-Host "  ✓ REPRODUCIBLE — both runs produced byte-identical binaries." -ForegroundColor Green
  Write-Host ""
  Write-Host "  Final SHA256SUMS:" -ForegroundColor Cyan
  $run2Hashes -split "`n" | Where-Object { $_.Trim() } | ForEach-Object { Write-Host "    $_" }
  Write-Host ""
  Write-Host "  Ship $outDir\SHA256SUMS alongside the GitHub release." -ForegroundColor Cyan
  Write-Host "  Operators verify with: sha256sum -c SHA256SUMS" -ForegroundColor Cyan
  Write-Host "  Audit firm can re-run this script to independently confirm." -ForegroundColor Cyan
  Pop-Location
  exit 0
} else {
  Write-Host "  ✗ NON-REPRODUCIBLE — run-1 and run-2 hashes diverge." -ForegroundColor Red
  Write-Host ""
  Write-Host "  Run-1 hashes (backed up at $run1Backup):" -ForegroundColor Yellow
  $run1Hashes -split "`n" | Where-Object { $_.Trim() } | ForEach-Object { Write-Host "    $_" }
  Write-Host ""
  Write-Host "  Run-2 hashes (currently in $outDir):" -ForegroundColor Yellow
  $run2Hashes -split "`n" | Where-Object { $_.Trim() } | ForEach-Object { Write-Host "    $_" }
  Write-Host ""
  Write-Host "  DO NOT TAG. Reproducibility regression — fix before shipping." -ForegroundColor Red
  Write-Host "  Common causes:" -ForegroundColor Yellow
  Write-Host "    • Embedded build timestamp in a binary (audit cargo.toml + build.rs)" -ForegroundColor Yellow
  Write-Host "    • Non-deterministic dep version in Cargo.lock" -ForegroundColor Yellow
  Write-Host "    • Host-specific path or env leaking into the binary" -ForegroundColor Yellow
  Write-Host "    • Docker base image floated between runs (verify rust-toolchain pin)" -ForegroundColor Yellow
  Pop-Location
  exit 1
}

} catch {
  Pop-Location
  throw
}
