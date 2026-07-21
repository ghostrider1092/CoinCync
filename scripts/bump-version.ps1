#requires -Version 5.1
<#
.SYNOPSIS
  Bump CoinCync version across all version-bearing components atomically.

.DESCRIPTION
  At tag-cut time, the version string lives in several source files. Editing
  them by hand has historically produced mismatches (wallet showed
  v1.0.9 while the node logged v1.0.10 because the wallet bump was
  forgotten). This script updates them together from a single source of
  truth.

  Files updated:
    1. Cargo.toml                                -- workspace root
    2. coincync-wallet-v2/src-tauri/Cargo.toml   -- desktop wallet (Rust)
    3. coincync-wallet-v2/package.json           -- desktop wallet (JS)
    4. src/explorer/fragments/00-shell.html      -- explorer ticker
    5. src/explorer/fragments/99-footer.html     -- explorer footer

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
    Path     = Join-Path $repoRoot "src\explorer\fragments\00-shell.html"
    Label    = "explorer ticker"
    Pattern  = 'v\d+\.\d+\.\d+'
    Replace  = "v$NewVersion"
  }
  @{
    Path     = Join-Path $repoRoot "src\explorer\fragments\99-footer.html"
    Label    = "explorer footer"
    Pattern  = 'v\d+\.\d+\.\d+'
    Replace  = "v$NewVersion"
  }
)

# --- Pre-flight: check all files exist ---------------------------------
$missing = $targets | Where-Object { -not (Test-Path $_.Path) }
if ($missing.Count -gt 0) {
  Write-Host "ERROR: missing files:" -ForegroundColor Red
  $missing | ForEach-Object { Write-Host "  $($_.Path)" -ForegroundColor Red }
  exit 1
}

# --- For each file: snapshot current version, plan the diff -----------
$results = @()
foreach ($t in $targets) {
  $content = Get-Content $t.Path -Raw
  $matches = [regex]::Matches($content, $t.Pattern)

  if ($matches.Count -eq 0) {
    Write-Host "ERROR: pattern not found in $($t.Label): $($t.Pattern)" -ForegroundColor Red
    Write-Host "       Either the file's version-line format changed, or this script is out of date." -ForegroundColor Red
    exit 1
  }

  # All matches in a single file should be the same current version -- sanity
  # check. Exception: the explorer HTML routinely contains forward-references
  # like "Coming in v1.0.10" alongside the current-version label "v1.0.9".
  # Those forward refs are intentional copy and should not block the bump.
  #
  # Heuristic: for each match, look at the 30 chars BEFORE it. If that context
  # contains "Coming in" or "Upcoming" or "in vX.Y.Z (", classify the match as
  # a forward-reference and exclude it from the distinct-values check. The
  # actual replacement at line 100 still rewrites all matches (forward refs
  # too — once v1.0.10 ships, the explorer can carry a new "Coming in v1.0.11"
  # forward ref instead). This keeps the bump idempotent while letting normal
  # release copy mention upcoming versions.
  # Two classes of matches we want to EXEMPT from the distinct-values check:
  #   (a) Forward references: "Coming in v1.0.10", "Upcoming v1.0.10",
  #       "in version v1.0.10" — intentional preview text
  #   (b) Historical / comment references: "v1.0.8 NETWORK STATUS PANEL"
  #       (HTML comment), "Removed in v1.0.8" (JS comment), "the v1.0.8
  #       status panel" — descriptions of when a feature was introduced,
  #       NOT current-version labels. Should not be rewritten on bump.
  #
  # Both (a) and (b) get classified as "exempt" and excluded from the
  # uniqueness check; the actual regex replacement at the bottom still
  # rewrites all matches (forward refs become the next forward ref;
  # historical refs become the next historical ref). If the operator
  # wants to preserve true historical accuracy in comments, they can
  # post-edit; the common case is that this churn is acceptable.
  $contextChars = 80
  $currentMatchTexts = @()
  $exemptTexts       = @()
  foreach ($m in $matches) {
    $startContext = [Math]::Max(0, $m.Index - $contextChars)
    $contextLen   = $m.Index - $startContext
    $context      = $content.Substring($startContext, $contextLen)

    # Forward-ref patterns
    $isForwardRef = ($context -match 'Coming in\s*$' -or
                     $context -match 'Upcoming\s*[:\-]?\s*$' -or
                     $context -match 'in version\s*$')

    # Historical / comment patterns. We look at the LAST line of context
    # (a version string buried in a multi-line block comment counts if
    # the line it sits on starts with a comment marker).
    $lastLineStart = $context.LastIndexOfAny([char[]]@("`n", "`r"))
    $lastLine = if ($lastLineStart -ge 0) { $context.Substring($lastLineStart + 1) } else { $context }
    $isInComment = ($lastLine -match '^\s*<!--' -or
                    $lastLine -match '^\s*//' -or
                    $lastLine -match '^\s*\*' -or       # JS block-comment continuation line
                    $lastLine -match '^\s*/\*' -or
                    $lastLine -match '<!--[^>]*$' -or   # HTML comment opened earlier in line
                    $lastLine -match '/\*[^*]*$')       # JS block comment opened earlier in line

    # Phrasing that describes a past introduction: "Removed in", "Added in",
    # "Introduced in", "Renamed in", "Deprecated in"
    $isHistoricalPhrasing = ($context -match '(Removed|Added|Introduced|Renamed|Deprecated|Shipped|Landed)\s+in\s*$')

    if ($isForwardRef -or $isInComment -or $isHistoricalPhrasing) {
      $exemptTexts += $m.Value
    } else {
      $currentMatchTexts += $m.Value
    }
  }

  # Backward compat with the prior naming
  $forwardRefTexts = $exemptTexts

  if ($currentMatchTexts.Count -eq 0) {
    Write-Host "ERROR: $($t.Label) has no non-forward-reference version strings - every match looks like 'Coming in vX.Y.Z'." -ForegroundColor Red
    Write-Host "       The file probably needs at least one current-version label that isn't a forward ref." -ForegroundColor Red
    exit 1
  }

  $currentValues = @($currentMatchTexts | Sort-Object -Unique)
  if ($currentValues.Count -gt 1) {
    Write-Host "ERROR: $($t.Label) contains multiple distinct CURRENT version strings (forward refs are exempt):" -ForegroundColor Red
    $currentValues | ForEach-Object { Write-Host "  $_" -ForegroundColor Red }
    if ($forwardRefTexts.Count -gt 0) {
      $fwdSummary = ($forwardRefTexts | Sort-Object -Unique) -join ", "
      Write-Host "       (Forward references identified + exempted: $fwdSummary)" -ForegroundColor DarkGray
    }
    Write-Host "       Manual reconcile before re-running." -ForegroundColor Red
    exit 1
  }

  if ($forwardRefTexts.Count -gt 0) {
    $fwdSummary = ($forwardRefTexts | Sort-Object -Unique) -join ", "
    Write-Host "INFO: $($t.Label) - forward refs detected + exempted: $fwdSummary" -ForegroundColor DarkGray
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

# --- Report -----------------------------------------------------------
Write-Host ""
Write-Host "===================================================================="
Write-Host "  VERSION BUMP -> $NewVersion" -ForegroundColor Yellow
Write-Host "===================================================================="
foreach ($r in $results) {
  $sites = if ($r.SiteCount -gt 1) { " ($($r.SiteCount) sites)" } else { "" }
  Write-Host "  $($r.Label)$sites"
  Write-Host "    $($r.Current)  ->  $($r.New)" -ForegroundColor Gray
}
Write-Host "===================================================================="
Write-Host ""

if ($DryRun) {
  Write-Host "DRY RUN -- no files written. Run without -DryRun to apply." -ForegroundColor Yellow
  exit 0
}

# --- Write ------------------------------------------------------------
foreach ($r in $results) {
  [IO.File]::WriteAllText($r.Path, $r.NewContent, [Text.UTF8Encoding]::new($false))
  Write-Host "  [OK] $($r.Label) updated" -ForegroundColor Green
}

Write-Host ""
Write-Host "Next steps:" -ForegroundColor Cyan
Write-Host "  1. Verify the diff:"
Write-Host "       git diff Cargo.toml coincync-wallet-v2 src/explorer/fragments/00-shell.html src/explorer/fragments/99-footer.html"
Write-Host ""
Write-Host "  2. Confirm the workspace still builds:"
Write-Host "       cargo check --lib"
Write-Host ""
Write-Host "  3. Commit alongside the tag-cut PR:"
Write-Host "       git add Cargo.toml coincync-wallet-v2/src-tauri/Cargo.toml \\"
Write-Host "               coincync-wallet-v2/package.json src/explorer/fragments/00-shell.html \"
Write-Host "               src/explorer/fragments/99-footer.html"
Write-Host "       git commit -m ""release: bump to v$NewVersion"""
