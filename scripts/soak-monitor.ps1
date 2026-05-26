#requires -Version 5.1
<#
.SYNOPSIS
  Capture v1.0.10 sandbox-soak health signals in one shot.

.DESCRIPTION
  Run this every ~6 hours during the 5-day soak window (or set up
  cron at e.g. every 4h). Captures the signals the soak procedure
  defines as pass/fail criteria and either prints to stdout or
  appends a row to a CSV trend log.

  Designed for the dual workflow: an operator can run it interactively
  to glance at current state, AND can `-CsvAppend` to build a trend
  file that surfaces growth/leak patterns over the soak window.

  Exits 0 if all current-snapshot signals are within the expected
  ranges per docs/launch/v1.0.10-SOAK-PROCEDURE.md, 1 if any signal
  is in the WARN range, 2 if any signal is in the FAIL range.

.PARAMETER NodeRpc
  Sandbox node's local RPC endpoint. Default http://127.0.0.1:28081.

.PARAMETER CsvAppend
  Path to a CSV file to append a row to. Headers are written on
  first row (file doesn't exist). Subsequent runs just append.

.PARAMETER SkipWalletCheck
  Skip the wallet-balance + pending-maturity check. Use if the
  sandbox isn't running a wallet under the same RPC, OR if you
  haven't unlocked the wallet for this monitor run.

.EXAMPLE
  .\soak-monitor.ps1
  # One-shot, prints to stdout

.EXAMPLE
  .\soak-monitor.ps1 -CsvAppend soak-2026-06.csv
  # Append a row to the trend log

.EXAMPLE
  while ($true) { .\soak-monitor.ps1 -CsvAppend soak.csv; Start-Sleep -Seconds 21600 }
  # Manual 6h polling loop (Ctrl+C to stop)
#>

[CmdletBinding()]
param(
  [string]$NodeRpc = "http://127.0.0.1:28081",
  [string]$CsvAppend = $null,
  [switch]$SkipWalletCheck
)

$ErrorActionPreference = 'Stop'

# Null-coalescing helper. PowerShell 5.1 (the Windows-bundled version)
# does NOT have the `??` operator -- that's a PS 7+ feature. Earlier
# revision of this script used `??` extensively and silently failed
# the entire soak loop on every iteration because the Windows
# powershell.exe could not parse the script. This helper restores the
# coalescing behavior in PS 5.1.
#
# Usage: Coalesce $maybeNull $fallback
#        Coalesce $first $second $third $fallback  # left-to-right
function Coalesce {
  param([Parameter(ValueFromRemainingArguments=$true)]$Values)
  foreach ($v in $Values) { if ($null -ne $v) { return $v } }
  return $null
}

function Invoke-RpcCall {
  param([string]$Url, [string]$Method, [hashtable]$Params = @{})
  $body = @{ jsonrpc = "2.0"; id = 1; method = $Method }
  if ($Params.Count -gt 0) { $body['params'] = $Params }
  $bodyJson = $body | ConvertTo-Json -Compress
  try {
    $resp = Invoke-WebRequest -Uri $Url -Method POST -Body $bodyJson `
              -ContentType 'application/json' -TimeoutSec 8 -UseBasicParsing
    return ($resp.Content | ConvertFrom-Json).result
  } catch {
    return $null
  }
}

$timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
$signals = @{}
$verdict = 'PASS'
$notes = @()

# --- Chain health ----------------------------------------------------
$info = Invoke-RpcCall -Url $NodeRpc -Method 'get_info'
if ($null -eq $info) {
  Write-Host "FAIL: sandbox node $NodeRpc unreachable" -ForegroundColor Red
  $signals['tip_height'] = $null
  $signals['tip_age_secs'] = $null
  $verdict = 'FAIL'
  $notes += "node unreachable"
} else {
  $signals['tip_height']       = [int64](Coalesce $info.height $info.tip_height 0)
  $signals['tip_age_secs']     = [int](Coalesce $info.tip_age_secs 0)
  $signals['difficulty']       = "$($info.difficulty)"
  $signals['peer_count']       = [int](Coalesce $info.peer_count 0)
  $signals['mempool_size']     = [int](Coalesce $info.mempool_size 0)

  if ($signals['tip_age_secs'] -gt 1800) {
    $verdict = 'FAIL'; $notes += "tip age >30min ($($signals['tip_age_secs'])s) -- sandbox out of sync"
  } elseif ($signals['tip_age_secs'] -gt 600) {
    if ($verdict -eq 'PASS') { $verdict = 'WARN' }
    $notes += "tip age >10min ($($signals['tip_age_secs'])s) -- transient or beginning of trouble"
  }

  if ($signals['peer_count'] -lt 5) {
    if ($signals['peer_count'] -eq 0) {
      $verdict = 'FAIL'; $notes += "peer count = 0"
    } else {
      if ($verdict -eq 'PASS') { $verdict = 'WARN' }
      $notes += "peer count low ($($signals['peer_count']))"
    }
  }
}

# --- Mempool size + oldest entry age ---------------------------------
#
# The JSON-RPC interface exposes get_mempool_info (size/bytes/fees) and
# get_mempool_transactions (per-tx hash/kind/fee/size). Neither surfaces
# per-tx insertion timestamps today, so oldest-entry-age cannot be
# computed against the live testnet RPC -- only via direct DB access on
# a sandbox node. We capture what's available and flag the gap rather
# than blocking soak progress.
#
# Follow-up (tracked separately): extend get_mempool_transactions tx
# records with an added_time field so oldest-age becomes a remote signal.
$mpInfo = Invoke-RpcCall -Url $NodeRpc -Method 'get_mempool_info'
if ($null -ne $mpInfo) {
  # mempool_size was already captured from get_info above; reconcile if
  # they disagree (would indicate an internal inconsistency worth flagging)
  $infoSize = [int](Coalesce $mpInfo.size 0)
  if ($signals.ContainsKey('mempool_size') -and $signals['mempool_size'] -ne $infoSize) {
    if ($verdict -eq 'PASS') { $verdict = 'WARN' }
    $notes += "mempool size disagreement: get_info=$($signals['mempool_size']) vs get_mempool_info=$infoSize"
  }
  $signals['mempool_size'] = $infoSize
  $signals['mempool_oldest_age_secs'] = $null  # not exposed via JSON-RPC yet
} else {
  $signals['mempool_oldest_age_secs'] = $null
  if ($verdict -eq 'PASS') { $verdict = 'WARN' }
  $notes += "get_mempool_info unreachable"
}

# --- Reorg counter ---------------------------------------------------
$reorgStats = Invoke-RpcCall -Url $NodeRpc -Method 'get_reorg_stats'
if ($null -ne $reorgStats) {
  $signals['reorg_count']      = [int](Coalesce $reorgStats.total_reorgs 0)
  $signals['deepest_reorg']    = [int](Coalesce $reorgStats.deepest_reorg_depth 0)

  if ($signals['deepest_reorg'] -gt 10) {
    $verdict = 'FAIL'
    $notes += "deep reorg detected (depth $($signals['deepest_reorg']))"
  } elseif ($signals['reorg_count'] -gt 0) {
    $notes += "$($signals['reorg_count']) reorg(s) seen, deepest depth $($signals['deepest_reorg'])"
  }
} else {
  $signals['reorg_count'] = $null
  $signals['deepest_reorg'] = $null
}

# --- MIN_OUTPUT_AGE activation distance ------------------------------
# Pull the armed activation height by reading constants.rs locally
# (this assumes monitor runs on the same machine as the source tree;
# remove this check if it's not your setup).
$repoRoot = Resolve-Path "$PSScriptRoot\.."
$constantsPath = Join-Path $repoRoot "src\constants.rs"
$activationHeight = $null
if (Test-Path $constantsPath) {
  $c = Get-Content $constantsPath -Raw
  if ($c -match 'MIN_OUTPUT_AGE_HARDFORK_HEIGHT:\s*u64\s*=\s*(\d+)') {
    $activationHeight = [int64]$Matches[1]
    $signals['activation_height'] = $activationHeight
    if ($signals['tip_height']) {
      $blocksToActivation = $activationHeight - $signals['tip_height']
      $signals['blocks_to_activation'] = $blocksToActivation
      if ($blocksToActivation -lt 0) {
        $signals['activation_status'] = 'past'
      } elseif ($blocksToActivation -lt 100) {
        $signals['activation_status'] = 'imminent'
        if ($verdict -eq 'PASS') { $verdict = 'WARN' }
        $notes += "activation imminent -- $blocksToActivation blocks; monitor closely"
      } elseif ($blocksToActivation -lt 500) {
        $signals['activation_status'] = 'approaching'
      } else {
        $signals['activation_status'] = 'future'
      }
    }
  } elseif ($c -match 'MIN_OUTPUT_AGE_HARDFORK_HEIGHT:\s*u64\s*=\s*u64::MAX') {
    $signals['activation_status'] = 'placeholder-u64max'
    if ($verdict -eq 'PASS') { $verdict = 'WARN' }
    $notes += "activation guard still at u64::MAX placeholder -- this soak isn't testing the armed rule"
  }
}

# --- Wallet check (optional) -----------------------------------------
if (-not $SkipWalletCheck) {
  $balance = Invoke-RpcCall -Url $NodeRpc -Method 'get_wallet_balance'
  if ($null -ne $balance) {
    $signals['wallet_total_atomic']     = [int64](Coalesce $balance.total_atomic 0)
    $signals['wallet_spendable_atomic'] = [int64](Coalesce $balance.spendable_atomic 0)
    $signals['wallet_pending_atomic']   = $signals['wallet_total_atomic'] - $signals['wallet_spendable_atomic']
  }
}

# --- Process memory (Linux/Windows differ; do best-effort) ------------
try {
  $proc = Get-Process -Name 'coincync-node' -ErrorAction Stop
  $signals['process_rss_mb'] = [math]::Round($proc.WorkingSet64 / 1MB, 0)
} catch {
  $signals['process_rss_mb'] = $null
}

# --- RandomX mode (read from latest log line if available) ------------
# Look in the standard log location; this is a best-effort signal.
$logPaths = @(
  "$env:LOCALAPPDATA\coincync\coincync-node.log"
  "$HOME\.coincync-testnet\node.log"
  "/var/log/coincync-node.log"
)
foreach ($lp in $logPaths) {
  if (Test-Path $lp) {
    $lastModeLine = Get-Content $lp -Tail 500 | Where-Object { $_ -match 'RandomX VM created.*mode:\s*([\w-]+)' } | Select-Object -Last 1
    if ($lastModeLine -match 'mode:\s*([\w-]+)') {
      $signals['randomx_mode'] = $Matches[1]
      if ($Matches[1] -eq 'INTERPRETED') {
        $verdict = 'FAIL'
        $notes += "RandomX in INTERPRETED mode -- soak is testing wrong perf path"
      } elseif ($Matches[1] -ne 'full-mem' -and $Matches[1] -ne 'light-jit') {
        if ($verdict -eq 'PASS') { $verdict = 'WARN' }
        $notes += "RandomX mode: $($Matches[1]) -- soak may underestimate prod perf"
      }
    }
    break
  }
}

# --- Report -----------------------------------------------------------
if ([string]::IsNullOrEmpty($CsvAppend)) {
  # Stdout pretty-print
  Write-Host ""
  Write-Host "===================================================================="
  Write-Host "  SOAK MONITOR -- $timestamp" -ForegroundColor Yellow
  Write-Host "===================================================================="
  Write-Host "  Verdict:                       $verdict" -ForegroundColor $(if ($verdict -eq 'PASS') { 'Green' } elseif ($verdict -eq 'WARN') { 'Yellow' } else { 'Red' })
  Write-Host ""
  Write-Host "  Chain health:"
  Write-Host "    tip_height                   $($signals['tip_height'])"
  Write-Host "    tip_age_secs                 $($signals['tip_age_secs'])"
  Write-Host "    difficulty                   $($signals['difficulty'])"
  Write-Host "    peer_count                   $($signals['peer_count'])"
  Write-Host "    mempool_size                 $($signals['mempool_size'])"
  Write-Host "    mempool_oldest_age_secs      $($signals['mempool_oldest_age_secs'])"
  Write-Host ""
  Write-Host "  Reorg state:"
  Write-Host "    reorg_count                  $($signals['reorg_count'])"
  Write-Host "    deepest_reorg                $($signals['deepest_reorg'])"
  Write-Host ""
  Write-Host "  Activation:"
  Write-Host "    activation_height            $($signals['activation_height'])"
  Write-Host "    blocks_to_activation         $($signals['blocks_to_activation'])"
  Write-Host "    activation_status            $($signals['activation_status'])"
  Write-Host ""
  if (-not $SkipWalletCheck) {
    Write-Host "  Wallet:"
    Write-Host "    total_atomic                 $($signals['wallet_total_atomic'])"
    Write-Host "    spendable_atomic             $($signals['wallet_spendable_atomic'])"
    Write-Host "    pending_atomic               $($signals['wallet_pending_atomic'])"
    Write-Host ""
  }
  Write-Host "  Runtime:"
  Write-Host "    process_rss_mb               $($signals['process_rss_mb'])"
  Write-Host "    randomx_mode                 $($signals['randomx_mode'])"
  Write-Host ""
  if ($notes.Count -gt 0) {
    Write-Host "  Notes:" -ForegroundColor Yellow
    $notes | ForEach-Object { Write-Host "    * $_" -ForegroundColor Yellow }
    Write-Host ""
  }
} else {
  # CSV-append mode
  $headers = @('timestamp','verdict','tip_height','tip_age_secs','peer_count','mempool_size','mempool_oldest_age_secs',
               'reorg_count','deepest_reorg','activation_height','blocks_to_activation','activation_status',
               'wallet_total_atomic','wallet_spendable_atomic','wallet_pending_atomic','process_rss_mb','randomx_mode','notes')
  $row = @{
    timestamp = $timestamp
    verdict   = $verdict
    notes     = ($notes -join '; ')
  }
  foreach ($k in $signals.Keys) { $row[$k] = $signals[$k] }

  $writeHeader = -not (Test-Path $CsvAppend)
  if ($writeHeader) {
    ($headers -join ',') | Out-File -FilePath $CsvAppend -Encoding utf8
  }
  $values = $headers | ForEach-Object {
    $v = $row[$_]
    if ($null -eq $v) { '' }
    elseif ($v -is [string] -and $v.Contains(',')) { '"' + $v.Replace('"','""') + '"' }
    else { "$v" }
  }
  ($values -join ',') | Out-File -FilePath $CsvAppend -Encoding utf8 -Append

  Write-Host "$timestamp  $verdict  tip=$($signals['tip_height'])  blocks_to_activation=$($signals['blocks_to_activation'])  $(if ($notes) { '-- ' + ($notes -join '; ') })"
}

# --- Exit code --------------------------------------------------------
switch ($verdict) {
  'PASS' { exit 0 }
  'WARN' { exit 1 }
  'FAIL' { exit 2 }
  default { exit 0 }
}
