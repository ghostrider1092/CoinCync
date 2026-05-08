#requires -Version 5.1
<#
test-tx-propagation.ps1 -- propagate a tx and measure time-to-mempool-on-each-box.

Workflow:
  1. You already submitted a tx via `coincync-wallet send` (or any other path).
     The wallet printed the tx hash in stdout. Pass it here.
  2. This script polls each of the 5 fleet boxes' mempool every 2 sec
     for up to 90 sec, looking for that tx hash.
  3. Prints a table: which boxes saw it, and how many seconds after
     submission each one first saw it.

This is the empirical test of the broadcast_raw fix from earlier in
the same evening. If a tx submitted to one box reaches all 4 others
within ~5-15 seconds, the lossy-propagation symptom is gone.

Usage:
  .\test-tx-propagation.ps1 -TxHash <64-hex-chars>
  .\test-tx-propagation.ps1 -TxHash <hash> -TimeoutSec 120

Encoding note: this script is intentionally pure ASCII. PowerShell 5.1
without a UTF-8 BOM reads non-ASCII source bytes as the system code page,
which on Windows-1252 turns multi-byte UTF-8 sequences (em-dashes,
checkmarks, box-drawing chars) into mojibake that the parser then
mis-tokenizes -- the resulting "Unexpected token" errors point at the
wrong line. Keeping the source ASCII avoids the trap entirely.
#>

param(
  [Parameter(Mandatory=$true)]
  [string]$TxHash,

  [int]$TimeoutSec = 90,
  [int]$IntervalSec = 2
)

$ErrorActionPreference = 'Stop'

# Normalize: lowercase, no whitespace
$TxHash = $TxHash.Trim().ToLower()
if ($TxHash -notmatch '^[0-9a-f]{64}$') {
  throw "TxHash must be 64 hex chars. Got: '$TxHash' (length $($TxHash.Length))"
}

$KeyPath  = "$env:USERPROFILE\.ssh\coincync_fleet"
$KeyStash = "$env:USERPROFILE\.coincync\fleet-rpc-key"
if (-not (Test-Path $KeyStash)) { throw "Missing API key: $KeyStash" }
$apiKey = (Get-Content $KeyStash -Raw).Trim()

$Fleet = @(
  @{ Name='seed1';    IP='66.135.23.193'  },
  @{ Name='seed2';    IP='140.82.57.168'  },
  @{ Name='seed3';    IP='207.148.111.76' },
  @{ Name='explorer'; IP='207.148.6.50'   },
  @{ Name='api';      IP='95.179.165.225' }
)

# Single bash query: returns 1 if mempool contains $TxHash, 0 otherwise
$probe = @"
curl -sS --max-time 5 -X POST http://127.0.0.1:28081 \
  -H 'Content-Type: application/json' \
  -H 'Authorization: Bearer __KEY__' \
  -d '{"jsonrpc":"2.0","id":1,"method":"get_mempool_transactions"}' \
  | grep -c '"hash":"__HASH__"'
"@
$probe = $probe -replace '__KEY__', $apiKey -replace '__HASH__', $TxHash

# Track first-seen timestamp per box
$startTime = Get-Date
$seen = @{}
foreach ($n in $Fleet) { $seen[$n.Name] = $null }

Write-Host ""
Write-Host "================================================================="
Write-Host "  Watching for tx $($TxHash.Substring(0,16))... in fleet mempools"
Write-Host "  Polling every $IntervalSec sec, timeout $TimeoutSec sec"
Write-Host "================================================================="
Write-Host ""

# Stage the probe script on each box once (small, fast)
foreach ($n in $Fleet) {
  $tmp = [IO.Path]::GetTempFileName()
  [IO.File]::WriteAllText($tmp, $probe, [Text.UTF8Encoding]::new($false))
  & scp -i $KeyPath -o StrictHostKeyChecking=accept-new -q $tmp "root@$($n.IP):/tmp/probe.sh" 2>&1 | Out-Null
  Remove-Item -Force $tmp
}

# Poll loop
$deadline = $startTime.AddSeconds($TimeoutSec)
$tick = 0
while ((Get-Date) -lt $deadline) {
  $tick++
  $allSeen = $true
  $line = ""
  foreach ($n in $Fleet) {
    if ($null -ne $seen[$n.Name]) {
      $line += ("{0,-12}" -f "$($n.Name):OK")
      continue
    }
    $allSeen = $false
    # Build the SSH target host once to avoid the PS5.1 quote-parser tripping
    # on inline `$($n.IP)` interpolation inside an argument that is itself
    # quoted. The previous form (one-liner with embedded interpolation in
    # quoted args) failed to parse cleanly under PS 5.1.
    $sshHost = "root@" + $n.IP
    $count = (& ssh -i $KeyPath -o ConnectTimeout=5 $sshHost "bash /tmp/probe.sh" 2>$null).Trim()
    if ($count -eq '1') {
      $elapsed = ((Get-Date) - $startTime).TotalSeconds
      $seen[$n.Name] = [math]::Round($elapsed, 1)
      $line += ("{0,-12}" -f "$($n.Name):FOUND")
    } else {
      $line += ("{0,-12}" -f "$($n.Name):.")
    }
  }
  $tElapsed = [math]::Round(((Get-Date) - $startTime).TotalSeconds, 1)
  Write-Host ("  t={0,5}s  {1}" -f $tElapsed, $line)
  if ($allSeen) { break }
  Start-Sleep -Seconds $IntervalSec
}

# Final cleanup of probe scripts
foreach ($n in $Fleet) {
  $sshHost = "root@" + $n.IP
  & ssh -i $KeyPath $sshHost "rm -f /tmp/probe.sh" 2>$null | Out-Null
}

# Report
Write-Host ""
Write-Host "================================================================="
Write-Host "  Propagation results"
Write-Host "================================================================="
Write-Host ("{0,-10} {1}" -f "box", "first-seen (sec after start)")
Write-Host ("{0,-10} {1}" -f "----", "--------------------------")
foreach ($n in $Fleet) {
  $val = $seen[$n.Name]
  if ($null -eq $val) {
    Write-Host ("{0,-10} {1}" -f $n.Name, "NEVER (timed out)") -ForegroundColor Red
  } elseif ($val -lt 5) {
    Write-Host ("{0,-10} {1}s" -f $n.Name, $val) -ForegroundColor Green
  } elseif ($val -lt 15) {
    Write-Host ("{0,-10} {1}s" -f $n.Name, $val) -ForegroundColor Yellow
  } else {
    Write-Host ("{0,-10} {1}s" -f $n.Name, $val)
  }
}

Write-Host ""
$reached = ($Fleet | Where-Object { $null -ne $seen[$_.Name] } | Measure-Object).Count
Write-Host ("  Reached: {0} of 5 boxes within {1}s timeout" -f $reached, $TimeoutSec)

if ($reached -eq 5) {
  $maxTime = ($seen.Values | Where-Object { $null -ne $_ } | Measure-Object -Maximum).Maximum
  Write-Host ("  Worst-case propagation: {0}s" -f $maxTime) -ForegroundColor Green
  Write-Host ""
  if ($maxTime -lt 15) {
    Write-Host "  RESULT: PROPAGATION HEALTHY -- broadcast_raw fix is working." -ForegroundColor Green
  } else {
    Write-Host "  RESULT: ALL REACHED, but slow ($maxTime s). Investigate broadcast queues." -ForegroundColor Yellow
  }
} elseif ($reached -ge 3) {
  Write-Host "  RESULT: PARTIAL -- most peers got it, some didn't. Check journal on missing boxes." -ForegroundColor Yellow
} else {
  Write-Host "  RESULT: BROKEN -- propagation is barely working. broadcast_raw fix may not be live." -ForegroundColor Red
}
