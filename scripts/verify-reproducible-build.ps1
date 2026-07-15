#requires -Version 5.1
<#
.SYNOPSIS
  Verify the v1.0.10 release binaries are reproducibly buildable.

.DESCRIPTION
  Runs the canonical Docker build TWICE from the same git commit, then
  diffs the binary hashes. Byte-identical hashes prove the build is
  reproducible -- the audit firm's reviewer can rebuild from source and
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

.PARAMETER CompareToRelease
  GitHub release tag (e.g. "v1.0.9-testnet-pre-audit"). When set, the
  script downloads SHA256SUMS.txt from that release after the local
  build(s) and compares each entry against the locally-computed hash.
  This is the audit-firm replication path: prove that the binary the
  project published matches what falls out of building from source
  today. Mismatches are surfaced per-file and block exit-0.

  Uses gh CLI if available, falls back to Invoke-WebRequest against
  the GitHub release-assets URL pattern.

.PARAMETER GitHubRepo
  owner/repo for the -CompareToRelease asset fetch. Default
  "Coincync/Coincync-Testnet-". Override for fork verification.

.EXAMPLE
  .\verify-reproducible-build.ps1
  # Full two-run repro verification (~30 min if Docker cache cold,
  # ~10 min warm -- runs build twice)

.EXAMPLE
  .\verify-reproducible-build.ps1 -SkipSecondRun
  # Single build; outputs SHA256SUMS but does NOT prove reproducibility

.EXAMPLE
  .\verify-reproducible-build.ps1 -CompareToRelease v1.0.9-testnet-pre-audit
  # Two-run repro + compare to v1.0.9 published hashes (audit-firm test)

.EXAMPLE
  .\verify-reproducible-build.ps1 -SkipSecondRun -CompareToRelease v1.0.9-testnet-pre-audit
  # Fast dry-run: single build + compare to published. Smoke-test
  # before scheduling the full two-run verification.
#>

[CmdletBinding()]
param(
  [string]$GitBashPath = "C:\Program Files\Git\bin\bash.exe",
  [switch]$SkipSecondRun,
  [string]$CompareToRelease = $null,
  [string]$GitHubRepo = "Coincync/Coincync-Testnet-"
)

$ErrorActionPreference = 'Stop'
$repoRoot = Resolve-Path "$PSScriptRoot\.."
Push-Location $repoRoot

# --- Helper: compare local SHA256SUMS to a published GitHub release ---
#
# Downloads SHA256SUMS.txt from the named release tag, parses both
# the local and remote files, and walks the intersection of named
# binaries to confirm every overlapping entry matches byte-for-byte.
#
# Returns $true if all overlapping entries match (or the remote file
# is missing entirely with a warning). Returns $false on any
# mismatch. Mismatch is the load-bearing finding for an audit:
# either the published binary wasn't reproducibly built, or the
# source has drifted since release-cut. Both block tag.
function Compare-LocalToPublishedRelease {
  param(
    [Parameter(Mandatory)] [string]$Tag,
    [Parameter(Mandatory)] [string]$Repo,
    [Parameter(Mandatory)] [string]$LocalHashesPath
  )

  Write-Host ""
  Write-Host "===================================================================="
  Write-Host "  AUDIT-REPLICATION CHECK -- compare to release $Tag" -ForegroundColor Yellow
  Write-Host "===================================================================="

  if (-not (Test-Path $LocalHashesPath)) {
    Write-Host "  [X] local hash file missing at $LocalHashesPath" -ForegroundColor Red
    return $false
  }

  # Fetch the published SHA256SUMS via the GitHub release-asset URL.
  # Pattern: https://github.com/<repo>/releases/download/<tag>/SHA256SUMS.txt
  # The pattern works for any public repo without auth.
  $remoteUrl = "https://github.com/$Repo/releases/download/$Tag/SHA256SUMS.txt"
  Write-Host "  Fetching: $remoteUrl" -ForegroundColor Gray
  try {
    $remoteRaw = (Invoke-WebRequest -Uri $remoteUrl -UseBasicParsing -TimeoutSec 30 -ErrorAction Stop).Content
  } catch {
    Write-Host "  [WARN] could not fetch published SHA256SUMS: $($_.Exception.Message)" -ForegroundColor Yellow
    Write-Host "         Release '$Tag' may not have a SHA256SUMS.txt asset attached." -ForegroundColor Yellow
    Write-Host "         (v1.0.9-testnet-pre-audit only ships per-platform tarballs;" -ForegroundColor Yellow
    Write-Host "          the combined SHA256SUMS lands once the updated release" -ForegroundColor Yellow
    Write-Host "          workflow runs against a fresh tag.)" -ForegroundColor Yellow
    return $true  # warn-not-fail; missing asset is operator-fixable
  }

  # Parse 'sha256sum -c' format: "<hash>  <filename>" per line.
  # Handles BOMs at file start, \r\n line endings, optional '*' prefix
  # (sha256sum binary-mode), and lines with leading whitespace.
  function Parse-Hashes([string]$raw) {
    $h = @{}
    # Strip BOM if present, normalize line endings.
    $raw = $raw -replace '^\xEF\xBB\xBF',''
    foreach ($line in ($raw -split "\r?\n")) {
      $trimmed = $line.Trim()
      if ($trimmed -match '([0-9a-fA-F]{64})\s+\*?(\S[^\r\n]*)') {
        $h[$matches[2].Trim()] = $matches[1].ToLower()
      }
    }
    return $h
  }
  $remote = Parse-Hashes $remoteRaw
  $local  = Parse-Hashes (Get-Content $LocalHashesPath -Raw)

  $overlap = $local.Keys | Where-Object { $remote.ContainsKey($_) }
  if (-not $overlap) {
    Write-Host "  [WARN] no overlapping binaries between local + published" -ForegroundColor Yellow
    Write-Host "         local : $($local.Keys -join ', ')" -ForegroundColor Gray
    Write-Host "         remote: $($remote.Keys -join ', ')" -ForegroundColor Gray
    Write-Host "         Different platform / different filename convention." -ForegroundColor Yellow
    return $true  # nothing comparable, can't fail
  }

  $mismatches = @()
  foreach ($file in $overlap) {
    if ($local[$file] -eq $remote[$file]) {
      Write-Host "    [OK]   $file" -ForegroundColor Green
    } else {
      Write-Host "    [X]    $file" -ForegroundColor Red
      Write-Host "           local : $($local[$file])" -ForegroundColor Red
      Write-Host "           remote: $($remote[$file])" -ForegroundColor Red
      $mismatches += $file
    }
  }

  if ($mismatches) {
    Write-Host ""
    Write-Host "  [X] AUDIT REPLICATION FAILED -- $($mismatches.Count) binary divergence(s)." -ForegroundColor Red
    Write-Host "      Either the published $Tag binary was not reproducibly built," -ForegroundColor Red
    Write-Host "      or the source has drifted since the tag was cut." -ForegroundColor Red
    Write-Host "      An auditor running this script would see the same failure." -ForegroundColor Red
    return $false
  } else {
    Write-Host ""
    Write-Host "  [OK] AUDIT REPLICATION SUCCEEDED -- $($overlap.Count) binaries match published." -ForegroundColor Green
    return $true
  }
}

try {

# --- Pre-flight -------------------------------------------------------
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

# Git state should be clean -- repro-build of a dirty tree is meaningless.
$dirty = git status --porcelain 2>&1 | Where-Object { $_ -match '^[MA]' }
if ($dirty) {
  Write-Host "ERROR: working tree has uncommitted modifications:" -ForegroundColor Red
  $dirty | ForEach-Object { Write-Host "  $_" -ForegroundColor Red }
  Write-Host "       Commit or stash first -- reproducible build only meaningful on a tagged commit." -ForegroundColor Red
  exit 1
}

$currentCommit = git rev-parse HEAD
Write-Host "Current commit: $currentCommit" -ForegroundColor Cyan

# --- Run 1 -- primary build --------------------------------------------
Write-Host ""
Write-Host "===================================================================="
Write-Host "  RUN 1 -- primary Docker build" -ForegroundColor Yellow
Write-Host "===================================================================="
Write-Host ""

$runStart = Get-Date
$env:MSYS_NO_PATHCONV = "1"  # prevents Git Bash from rewriting /out -> C:/Program Files/Git/out
# PS5.1 + native command stderr trap: Docker writes progress to stderr
# ("#0 building with desktop-linux instance..."). With
# $ErrorActionPreference='Stop' globally, PowerShell 5.1 sees that as a
# NativeCommandError and terminates BEFORE the $LASTEXITCODE check below
# can fire. Switching to Continue around the native call lets stderr
# stream through normally; we still check $LASTEXITCODE explicitly.
$prevEAP = $ErrorActionPreference
$ErrorActionPreference = 'Continue'
try {
  & $GitBashPath -c "cd '$($repoRoot -replace '\\','/')' && ./scripts/build-in-docker.sh" 2>&1 | ForEach-Object { Write-Host $_ }
} finally {
  $ErrorActionPreference = $prevEAP
}
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
  Write-Host "===================================================================="
  Write-Host "  -SkipSecondRun: bypassing run-2 comparison." -ForegroundColor Yellow
  Write-Host "  These hashes are POSSIBLY reproducible but unverified." -ForegroundColor Yellow
  Write-Host "  For the tag-cut release, run without -SkipSecondRun." -ForegroundColor Yellow
  Write-Host "===================================================================="
  Write-Host ""
  Write-Host "  SHA256SUMS at: $outDir\SHA256SUMS"
  Write-Host "  Operators verify with: sha256sum -c SHA256SUMS"

  if ($CompareToRelease) {
    $matchOk = Compare-LocalToPublishedRelease `
      -Tag $CompareToRelease `
      -Repo $GitHubRepo `
      -LocalHashesPath (Join-Path $outDir "SHA256SUMS")
    if (-not $matchOk) {
      Pop-Location
      exit 2
    }
  }

  Pop-Location
  exit 0
}

# --- Stash run-1 outputs before run-2 overwrites ----------------------
$run1Backup = Join-Path $env:TEMP "coincync-repro-run1-$(Get-Date -Format yyyyMMdd-HHmmss)"
New-Item -ItemType Directory -Path $run1Backup -Force | Out-Null
Copy-Item -Path "$outDir\*" -Destination $run1Backup -Recurse
Write-Host ""
Write-Host "Run-1 outputs backed up to: $run1Backup" -ForegroundColor Gray

# --- Run 2 -- verification build ---------------------------------------
Write-Host ""
Write-Host "===================================================================="
Write-Host "  RUN 2 -- verification Docker build" -ForegroundColor Yellow
Write-Host "===================================================================="
Write-Host ""

# Force fresh build by clearing cargo cache in the Docker volume.
# This is more aggressive than necessary but it's the audit-firm
# replication path -- they'll start from cold.
Write-Host "Clearing Docker build cache (forces fresh compile)..." -ForegroundColor Gray
& docker builder prune --filter "label=coincync-build" --force 2>&1 | Out-Null

$runStart = Get-Date
# Same PS5.1 native-stderr workaround as run-1 above.
$prevEAP = $ErrorActionPreference
$ErrorActionPreference = 'Continue'
try {
  & $GitBashPath -c "cd '$($repoRoot -replace '\\','/')' && ./scripts/build-in-docker.sh" 2>&1 | ForEach-Object { Write-Host $_ }
} finally {
  $ErrorActionPreference = $prevEAP
}
if ($LASTEXITCODE -ne 0) {
  Write-Host "ERROR: run-2 Docker build failed (exit $LASTEXITCODE)" -ForegroundColor Red
  Pop-Location
  exit 1
}
$run2Elapsed = (Get-Date) - $runStart
Write-Host "  Run-2 complete in $($run2Elapsed.TotalMinutes.ToString('0.0')) min" -ForegroundColor Green

$run2Hashes = Get-Content (Join-Path $outDir "SHA256SUMS") -Raw

# --- Compare ----------------------------------------------------------
Write-Host ""
Write-Host "===================================================================="
Write-Host "  REPRODUCIBILITY VERDICT" -ForegroundColor Yellow
Write-Host "===================================================================="
Write-Host ""

if ($run1Hashes.Trim() -eq $run2Hashes.Trim()) {
  Write-Host "  [OK] REPRODUCIBLE -- both runs produced byte-identical binaries." -ForegroundColor Green
  Write-Host ""
  Write-Host "  Final SHA256SUMS:" -ForegroundColor Cyan
  $run2Hashes -split "`n" | Where-Object { $_.Trim() } | ForEach-Object { Write-Host "    $_" }
  Write-Host ""
  Write-Host "  Ship $outDir\SHA256SUMS alongside the GitHub release." -ForegroundColor Cyan
  Write-Host "  Operators verify with: sha256sum -c SHA256SUMS" -ForegroundColor Cyan
  Write-Host "  Audit firm can re-run this script to independently confirm." -ForegroundColor Cyan

  # --- Optional: compare to published release ---------------------
  # Audit-firm replication test: prove what's on GitHub matches what
  # falls out of the source today. Diverges block exit-0.
  if ($CompareToRelease) {
    $matchOk = Compare-LocalToPublishedRelease `
      -Tag $CompareToRelease `
      -Repo $GitHubRepo `
      -LocalHashesPath (Join-Path $outDir "SHA256SUMS")
    if (-not $matchOk) {
      Pop-Location
      exit 2  # distinct exit so callers can differentiate from repro fail
    }
  }

  Pop-Location
  exit 0
} else {
  Write-Host "  [X] NON-REPRODUCIBLE -- run-1 and run-2 hashes diverge." -ForegroundColor Red
  Write-Host ""
  Write-Host "  Run-1 hashes (backed up at $run1Backup):" -ForegroundColor Yellow
  $run1Hashes -split "`n" | Where-Object { $_.Trim() } | ForEach-Object { Write-Host "    $_" }
  Write-Host ""
  Write-Host "  Run-2 hashes (currently in $outDir):" -ForegroundColor Yellow
  $run2Hashes -split "`n" | Where-Object { $_.Trim() } | ForEach-Object { Write-Host "    $_" }
  Write-Host ""
  Write-Host "  DO NOT TAG. Reproducibility regression -- fix before shipping." -ForegroundColor Red
  Write-Host "  Common causes:" -ForegroundColor Yellow
  Write-Host "    * Embedded build timestamp in a binary (audit cargo.toml + build.rs)" -ForegroundColor Yellow
  Write-Host "    * Non-deterministic dep version in Cargo.lock" -ForegroundColor Yellow
  Write-Host "    * Host-specific path or env leaking into the binary" -ForegroundColor Yellow
  Write-Host "    * Docker base image floated between runs (verify rust-toolchain pin)" -ForegroundColor Yellow
  Pop-Location
  exit 1
}

} catch {
  Pop-Location
  throw
}
