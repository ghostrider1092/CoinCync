# Verify the Cloudflare Pages deploy of coincync.org + www.
# Run this AFTER the custom domains in Pages show "Active".

Write-Host "=== DNS check ==="
foreach ($n in @('coincync.org','www.coincync.org')) {
  Write-Host ("`n{0}:" -f $n)
  Resolve-DnsName -Name $n -Server 1.1.1.1 -ErrorAction SilentlyContinue |
    Where-Object { $_.Type -in @('A','AAAA','CNAME') } |
    Select-Object Name,Type,@{n='Value';e={if($_.IPAddress){$_.IPAddress}else{$_.NameHost}}} |
    Format-Table -AutoSize
}

Write-Host "`n=== HTTP check (should be 200, served by cloudflare) ==="
foreach ($url in @('https://coincync.org/','https://www.coincync.org/')) {
  try {
    $r = Invoke-WebRequest -Uri $url -Method Head -MaximumRedirection 5 -TimeoutSec 10 -UseBasicParsing
    Write-Host ("{0}  status={1}  server={2}" -f $url, $r.StatusCode, $r.Headers.Server)
  } catch {
    Write-Host ("{0}  FAIL: {1}" -f $url, $_.Exception.Message)
  }
}

Write-Host "`n=== Content check (should contain CoinCync brand text) ==="
try {
  $body = (Invoke-WebRequest -Uri 'https://coincync.org/' -TimeoutSec 10 -UseBasicParsing).Content
  if ($body -match 'CoinCync|coincync\.network|explorer') {
    Write-Host "OK: page renders with expected content"
  } else {
    Write-Host "WARN: page responded but expected content not found"
  }
} catch {
  Write-Host ("FAIL: " + $_.Exception.Message)
}
