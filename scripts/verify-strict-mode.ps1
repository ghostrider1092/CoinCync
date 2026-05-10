#requires -Version 5.1
# Confirm Cloudflare Full (strict) is working on coincync.org by hitting
# all .org-served endpoints. If any returns 521/525/526, strict mode is on
# but origin cert isn't matching SNI — would mean the SAN gap matters.

Write-Host "=== Hitting all coincync.org endpoints ==="
foreach ($url in @(
  'https://coincync.org/',
  'https://www.coincync.org/',
  'https://explorer.coincync.org/',
  'https://api.coincync.org/'
)) {
  try {
    $r = Invoke-WebRequest -Uri $url -Method Head -TimeoutSec 12 -UseBasicParsing -MaximumRedirection 3
    Write-Host ("{0,-40}  status={1}  via={2}" -f $url, $r.StatusCode, $r.Headers.Server) -ForegroundColor Green
  } catch {
    $msg = $_.Exception.Message
    if ($msg -match '521|525|526') {
      Write-Host ("{0,-40}  STRICT MODE FAIL: {1}" -f $url, $msg) -ForegroundColor Red
      Write-Host "   ^ origin cert SAN doesn't match this hostname" -ForegroundColor Red
    } else {
      Write-Host ("{0,-40}  FAIL: {1}" -f $url, $msg) -ForegroundColor Yellow
    }
  }
}

Write-Host ""
Write-Host "=== For comparison, .network endpoints (still in Full, not strict) ==="
foreach ($url in @(
  'https://explorer.coincync.network/',
  'https://api.coincync.network/'
)) {
  try {
    $r = Invoke-WebRequest -Uri $url -Method Head -TimeoutSec 12 -UseBasicParsing -MaximumRedirection 3
    Write-Host ("{0,-40}  status={1}  via={2}" -f $url, $r.StatusCode, $r.Headers.Server)
  } catch {
    Write-Host ("{0,-40}  FAIL: {1}" -f $url, $_.Exception.Message)
  }
}
