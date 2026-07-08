#requires -Version 5.1
<#
.SYNOPSIS
  One-command publish for the coincync.network landing site and the
  docs.coincync.network mdbook site.

.DESCRIPTION
  Runs `wrangler pages deploy` against the matching Cloudflare Pages
  project for whichever site you specify. For the docs site, also
  rebuilds the mdbook in WSL first so you don't have to remember.

  First-time setup: run `npx wrangler login` once and click Allow in
  the browser. Token is cached after that.

.PARAMETER Site
  Which site to publish:
    landing  - the marketing site (website/) -> coincync.network
    docs     - the mdbook site (docs/)        -> docs.coincync.network
    both     - publish both (default)

.EXAMPLE
  .\scripts\publish.ps1
  .\scripts\publish.ps1 -Site landing
  .\scripts\publish.ps1 -Site docs
#>

[CmdletBinding()]
param(
  [ValidateSet('landing','docs','both')]
  [string]$Site = 'both'
)

$ErrorActionPreference = 'Stop'
$RepoRoot = Split-Path -Parent $PSScriptRoot

function Publish-Landing {
  $src = Join-Path $RepoRoot 'website'
  if (-not (Test-Path $src)) { throw "website/ not found at $src" }
  Write-Host "=== Publishing landing site (coincync.network) ===" -ForegroundColor Cyan
  & npx wrangler pages deploy $src --project-name=coincync-landing --branch=main --commit-dirty=true
  if ($LASTEXITCODE -ne 0) { throw "wrangler pages deploy (landing) failed: exit $LASTEXITCODE" }
}

function Publish-Docs {
  $bookOut = "\\wsl.localhost\Ubuntu\home\$($env:USERNAME)\coincync-docs-book"

  Write-Host "=== Building mdbook in WSL ===" -ForegroundColor Cyan
  # mdbook prints "INFO ..." lines to stderr. PowerShell 5.1 with
  # $ErrorActionPreference='Stop' wraps each native-stderr line in a
  # NativeCommandError and aborts the script even on a clean exit-0
  # build. Drop to Continue around the WSL call and rely on
  # $LASTEXITCODE for the real result.
  $prevPref = $ErrorActionPreference
  $ErrorActionPreference = 'Continue'
  try {
    # Pipe stderr to stdout inside bash so PowerShell sees the
    # mdbook INFO/ERROR lines as normal stream output (callers can
    # then see the build log instead of a silent gap).
    & wsl --distribution Ubuntu bash -c 'source $HOME/.cargo/env && cd "/mnt/c/Users/unkno/OneDrive/coincync 1.0/docs" && rm -rf $HOME/coincync-docs-book && mdbook build --dest-dir $HOME/coincync-docs-book 2>&1'
    if ($LASTEXITCODE -ne 0) { throw "mdbook build failed: exit $LASTEXITCODE" }
  } finally {
    $ErrorActionPreference = $prevPref
  }

  if (-not (Test-Path $bookOut)) { throw "mdbook output not found at $bookOut" }

  Write-Host "=== Publishing docs site (docs.coincync.network) ===" -ForegroundColor Cyan
  & npx wrangler pages deploy $bookOut --project-name=coincync-docs --branch=main --commit-dirty=true
  if ($LASTEXITCODE -ne 0) { throw "wrangler pages deploy (docs) failed: exit $LASTEXITCODE" }
}

switch ($Site) {
  'landing' { Publish-Landing }
  'docs'    { Publish-Docs }
  'both'    {
    Publish-Landing
    Write-Host ""
    Publish-Docs
  }
}

Write-Host ""
Write-Host "=== Done ===" -ForegroundColor Green
Write-Host "Production URLs:"
if ($Site -eq 'landing' -or $Site -eq 'both') { Write-Host "  https://coincync.network/" }
if ($Site -eq 'docs'    -or $Site -eq 'both') { Write-Host "  https://docs.coincync.network/introduction" }
