#requires -Version 5.1
# build-docs-pages.ps1
#
# Build the mdbook docs in WSL and produce a zip ready for upload to a
# new Cloudflare Pages project (`coincync-docs`).
#
# Output:  tmp-deploy-fix\coincync-docs.zip
#          (and also \\wsl.localhost\Ubuntu\home\<wsl-user>\coincync-docs-book\
#           if you want to inspect the raw HTML before upload)

$ErrorActionPreference = 'Stop'

$RepoRoot = "C:\Users\unkno\OneDrive\coincync 1.0"
$Zip = Join-Path $RepoRoot 'tmp-deploy-fix\coincync-docs.zip'
$BookOut = "\\wsl.localhost\Ubuntu\home\$($env:USERNAME)\coincync-docs-book"

# 1. Build mdbook in WSL — output to a Linux-fs path for speed
# Write the build script to a temp file (UTF-8 NO BOM) and exec — piping
# via stdin sends a BOM that crashes bash with "source: command not found".
Write-Host "=== Building mdbook in WSL ==="
$buildCmd = @'
#!/bin/bash
set -euo pipefail
source $HOME/.cargo/env
cd "/mnt/c/Users/unkno/OneDrive/coincync 1.0/docs"
rm -rf "$HOME/coincync-docs-book"
mdbook build --dest-dir "$HOME/coincync-docs-book"
echo "=== build done ==="
ls -la "$HOME/coincync-docs-book" | head -20
'@
# Write to a path inside the repo (which is /mnt/c/... in WSL) so we
# don't have to translate Windows tempfile paths through wslpath.
$tmpScript = Join-Path $RepoRoot 'tmp-deploy-fix\_build-docs.sh'
if (-not (Test-Path "$RepoRoot\tmp-deploy-fix")) {
  New-Item -ItemType Directory -Path "$RepoRoot\tmp-deploy-fix" -Force | Out-Null
}
try {
  [IO.File]::WriteAllText($tmpScript, $buildCmd, [Text.UTF8Encoding]::new($false))
  & wsl --distribution Ubuntu bash '/mnt/c/Users/unkno/OneDrive/coincync 1.0/tmp-deploy-fix/_build-docs.sh'
  if ($LASTEXITCODE -ne 0) { throw "mdbook build failed with exit $LASTEXITCODE" }
} finally {
  Remove-Item -Force -ErrorAction SilentlyContinue $tmpScript
}

# 2. Zip the output for Pages upload
Write-Host ""
Write-Host "=== Zipping for Cloudflare Pages ==="
if (-not (Test-Path "$RepoRoot\tmp-deploy-fix")) {
    New-Item -ItemType Directory -Path "$RepoRoot\tmp-deploy-fix" -Force | Out-Null
}
if (Test-Path $Zip) { Remove-Item -Force $Zip }
Compress-Archive -Path "$BookOut\*" -DestinationPath $Zip -CompressionLevel Optimal
Get-Item $Zip | Format-List Name, Length, FullName

Write-Host ""
Write-Host "Upload this zip to a new Cloudflare Pages project named 'coincync-docs',"
Write-Host "then add 'docs.coincync.network' as a custom domain."
