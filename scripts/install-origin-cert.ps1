#requires -Version 5.1
# install-origin-cert.ps1
#
# Replace self-signed origin certs on explorer + api boxes with the
# Cloudflare Origin Certificate (cf-origin.crt + cf-origin.key).
#
# Layout on remote: /etc/nginx/ssl/origin.{crt,key}, mode 0644 + 0600.
# Same paths the existing nginx config already references — no nginx
# config changes needed, just file replacement + reload.
#
# After deploy, moves the local cert + key OUT of the OneDrive-synced
# repo folder to %USERPROFILE%\.coincync\ (NOT OneDrive-synced), and
# warns if any version was committed to git.

$ErrorActionPreference = 'Stop'
$KeyPath = "$env:USERPROFILE\.ssh\coincync_fleet"

$SrcCert = "C:\Users\unkno\OneDrive\coincync 1.0\cf-origin.crt"
$SrcKey  = "C:\Users\unkno\OneDrive\coincync 1.0\cf-origin.key"

if (-not (Test-Path $SrcCert)) { throw "Missing: $SrcCert" }
if (-not (Test-Path $SrcKey))  { throw "Missing: $SrcKey" }

$Boxes = @(
  @{ Name='explorer'; IP='207.148.6.50'   },
  @{ Name='api';      IP='95.179.165.225' }
)

foreach ($b in $Boxes) {
  Write-Host ""
  Write-Host ("=== {0} ({1}) - installing Cloudflare Origin Cert ===" -f $b.Name, $b.IP)

  # SCP both files into /tmp first (atomic move on remote keeps nginx happy)
  & scp -i $KeyPath -o StrictHostKeyChecking=accept-new -q $SrcCert "root@$($b.IP):/tmp/origin.crt.new"
  if ($LASTEXITCODE -ne 0) { throw "SCP cert to $($b.IP) failed" }
  & scp -i $KeyPath -q $SrcKey "root@$($b.IP):/tmp/origin.key.new"
  if ($LASTEXITCODE -ne 0) { throw "SCP key to $($b.IP) failed" }

  $remote = @'
set -euo pipefail
mkdir -p /etc/nginx/ssl
mv /tmp/origin.crt.new /etc/nginx/ssl/origin.crt
mv /tmp/origin.key.new /etc/nginx/ssl/origin.key
chmod 0644 /etc/nginx/ssl/origin.crt
chmod 0600 /etc/nginx/ssl/origin.key
chown root:root /etc/nginx/ssl/origin.*
nginx -t
systemctl reload nginx
echo "issuer:  $(openssl x509 -in /etc/nginx/ssl/origin.crt -noout -issuer)"
echo "subject: $(openssl x509 -in /etc/nginx/ssl/origin.crt -noout -subject)"
echo "expires: $(openssl x509 -in /etc/nginx/ssl/origin.crt -noout -enddate)"
'@

  $tmp = [IO.Path]::GetTempFileName()
  try {
    [IO.File]::WriteAllText($tmp, $remote, [Text.UTF8Encoding]::new($false))
    & scp -i $KeyPath -q $tmp "root@$($b.IP):/tmp/install.sh"
    if ($LASTEXITCODE -ne 0) { throw "SCP install.sh to $($b.IP) failed" }
    & ssh -i $KeyPath "root@$($b.IP)" "bash /tmp/install.sh; ec=`$?; rm -f /tmp/install.sh; exit `$ec"
    if ($LASTEXITCODE -ne 0) { throw "Remote install on $($b.IP) returned $LASTEXITCODE" }
  } finally {
    Remove-Item -Force -ErrorAction SilentlyContinue $tmp
  }
}

Write-Host ""
Write-Host "=== Verifying through Cloudflare ==="
Start-Sleep -Seconds 3
foreach ($url in @(
  'https://explorer.coincync.org/',
  'https://explorer.coincync.network/',
  'https://api.coincync.org/',
  'https://api.coincync.network/'
)) {
  try {
    $r = Invoke-WebRequest -Uri $url -Method Head -TimeoutSec 12 -UseBasicParsing -MaximumRedirection 3
    Write-Host ("{0,-45}  status={1}  via={2}" -f $url, $r.StatusCode, $r.Headers.Server)
  } catch {
    Write-Host ("{0,-45}  FAIL: {1}" -f $url, $_.Exception.Message)
  }
}

# Move source files out of OneDrive
Write-Host ""
Write-Host "=== Moving cert + key out of OneDrive ==="
$dest = "$env:USERPROFILE\.coincync"
Move-Item -Path $SrcCert -Destination "$dest\cf-origin.crt" -Force
Move-Item -Path $SrcKey  -Destination "$dest\cf-origin.key" -Force
Write-Host "Moved to: $dest\cf-origin.crt and $dest\cf-origin.key"
Write-Host ("  cert: {0:N0} bytes" -f (Get-Item "$dest\cf-origin.crt").Length)
Write-Host ("  key:  {0:N0} bytes" -f (Get-Item "$dest\cf-origin.key").Length)

# Make sure they didn't get committed
$gitDir = "C:\Users\unkno\OneDrive\coincync 1.0"
Push-Location $gitDir
try {
  $tracked = & git ls-files cf-origin.crt cf-origin.key 2>&1
  if ($tracked) {
    Write-Host ""
    Write-Host "WARNING: cf-origin.* files appear to be tracked by git!" -ForegroundColor Red
    Write-Host "Run: git rm --cached cf-origin.crt cf-origin.key; git commit"
  } else {
    Write-Host "Git check: not tracked - safe."
  }
} finally {
  Pop-Location
}
