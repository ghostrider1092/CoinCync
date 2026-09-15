<#
.SYNOPSIS
  One command to bring up a local CoinCync testnet and SEE everything: a
  mining node + a live metrics view + a live chain-events/incident feed, each
  in its own Windows Terminal tab.

.DESCRIPTION
  Starts three tabs in a single Windows Terminal window:
    1. node+miner  - `coincync-node` with the built-in solo miner (--mine),
                     showing boot, sync, mining, block acceptance, peer +
                     reorg/reject logs live.
    2. metrics     - polls the node's JSON-RPC `get_metrics` every few seconds
                     (height, difficulty, mempool, peers, supply). The raw
                     Prometheus scrape is also at http://127.0.0.1:<rpc+1>/metrics.
    3. events      - polls `get_chain_events` + `get_info`: reorgs, forks,
                     rejects, checkpoints (the "incidents" feed) + tip/sync.

  If -Address is omitted, a throwaway local dev wallet is created (encrypted with
  a fixed dev password - TESTNET ONLY) and its address is used for the coinbase.

  Ctrl+C in the node tab stops the node; close the other tabs to stop the pollers.

.EXAMPLE
  .\scripts\start-all.ps1                       # testnet, 4 mining threads, auto wallet
.EXAMPLE
  .\scripts\start-all.ps1 -Threads 8 -Network regtest   # regtest = fast blocks to watch
.EXAMPLE
  .\scripts\start-all.ps1 -Address tCYNC... -NoMine     # run a non-mining node
#>
[CmdletBinding()]
param(
  [ValidateSet("testnet", "regtest", "mainnet")]
  [string]$Network = "testnet",
  [int]$Threads = 4,
  [string]$Address = "",
  [string]$DataDir = "",
  [switch]$NoMine,
  [int]$PollSecs = 5,
  # Live testnet Hetzner seed to dial (in addition to DNS seeds). Ignored on regtest.
  [string]$Seed = "2.29.34.197:28080",
  # By default each component opens in its OWN window. Pass -Tabs for one window
  # with four tabs instead.
  [switch]$Tabs
)

$ErrorActionPreference = "Stop"
$repo = Split-Path -Parent $PSScriptRoot

# -- env (RandomX light mode + LLVM, matching the build) --------------------
$env:COINCYNC_RANDOMX_LIGHT_MODE = "1"
$env:RUST_MIN_STACK = "268435456"
if (Test-Path "C:\Program Files\LLVM\bin") {
  $env:LIBCLANG_PATH = "C:\Program Files\LLVM\bin"
  $env:PATH = "C:\Program Files\LLVM\bin;$env:PATH"
}

if ([string]::IsNullOrWhiteSpace($DataDir)) { $DataDir = Join-Path $repo ".localnet" }
# Make it ABSOLUTE: each tab opens in its own window with a different working
# directory, so relative tab-script paths passed to -File would not resolve.
if (-not [System.IO.Path]::IsPathRooted($DataDir)) { $DataDir = Join-Path (Get-Location).Path $DataDir }
New-Item -ItemType Directory -Force -Path $DataDir | Out-Null
$DataDir = (Resolve-Path -LiteralPath $DataDir).Path

# -- locate binaries (release preferred) ------------------------------------
function Find-Bin([string]$name) {
  foreach ($p in @("$repo\target\release\$name.exe", "$repo\target\debug\$name.exe")) {
    if (Test-Path $p) { return $p }
  }
  return $null
}
$node = Find-Bin "coincync-node"
$wallet = Find-Bin "coincync-wallet"
# miner-top is a standalone crate under tools/ with its own target dir.
$minerTop = $null
foreach ($p in @("$repo\tools\miner-top\target\release\miner-top.exe", "$repo\tools\miner-top\target\debug\miner-top.exe", "$repo\target\release\miner-top.exe")) {
  if (Test-Path $p) { $minerTop = $p; break }
}
if (-not $node) {
  Write-Error "coincync-node not built. Run:`n  cargo build --release --features $Network --bin coincync-node"
  exit 1
}

# -- RPC/metrics ports for the chosen network -------------------------------
$rpcPort = switch ($Network) { "testnet" { 28081 } "regtest" { 18081 } default { 8081 } }
$metricsPort = $rpcPort + 1
$rpcUrl = "http://127.0.0.1:$rpcPort"
$logFile = Join-Path $DataDir "node.log"

# -- mining address: use -Address, else auto-provision a dev wallet ---------
if ($NoMine) {
  $Address = ""
} elseif ([string]::IsNullOrWhiteSpace($Address)) {
  if (-not $wallet) {
    Write-Error "coincync-wallet not built (needed to auto-create a mining address). Build it, or pass -Address.`n  cargo build --release --features $Network --bin coincync-wallet"
    exit 1
  }
  Write-Host "No -Address given: provisioning a local dev wallet (TESTNET ONLY)..." -ForegroundColor Yellow
  $env:COINCYNC_WALLET_PASSWORD = "coincync-localnet-dev"
  $walletFile = Join-Path $DataDir "dev.wallet"
  # Windows PowerShell 5.1 turns ANY native-exe stderr line (the wallet prints a
  # harmless WARN) into a terminating NativeCommandError under -EAP Stop. Drop to
  # Continue for the native calls so a cosmetic warning can't abort provisioning.
  $prevEAP = $ErrorActionPreference
  $ErrorActionPreference = "Continue"
  # create only if the file doesn't exist yet (create --force would rotate the seed).
  if (-not (Test-Path $walletFile)) {
    & $wallet --network $Network --wallet $walletFile create *> $null
  }
  # `address --json` prints a WARN on stderr then the JSON object on stdout;
  # capture stdout only and take the JSON line.
  $addrOut = (& $wallet --network $Network --wallet $walletFile address --json 2> $null)
  $ErrorActionPreference = $prevEAP
  $jsonLine = ($addrOut | Where-Object { $_.TrimStart().StartsWith('{') } | Select-Object -First 1)
  try { $Address = ($jsonLine | ConvertFrom-Json).address } catch { $Address = "" }
  if ([string]::IsNullOrWhiteSpace($Address)) {
    Write-Error "Could not derive a mining address from the dev wallet. Pass -Address explicitly."
    exit 1
  }
  Write-Host "Mining to: $Address" -ForegroundColor Green
}

# -- node args: join the live testnet via the Hetzner seed (+ DNS seeds); ----
#    regtest stays isolated.
$nodeArgs = "--network $Network --data-dir `"$DataDir`""
if ($Network -eq "testnet" -and $Seed) { $nodeArgs += " --addnode $Seed" }
if (-not $NoMine -and $Address) { $nodeArgs += " --mine $Address --mine-threads $Threads" }

# Tab scripts are built from LITERAL here-strings (no interpolation) with __TOKENS__
# substituted afterwards - avoids all here-string $-escaping pitfalls.
function Write-Tab([string]$path, [string]$body) { Set-Content -Encoding UTF8 -Path $path -Value $body }

$nodeTab = Join-Path $DataDir "_tab_node.ps1"
$body = @'
$host.UI.RawUI.WindowTitle = 'CoinCync node+miner (__NET__)'
Write-Host '=== coincync-node (__NET__) - one command = a node that mines to you ===' -ForegroundColor Cyan
# Tee all node output to the log so the incidents tab can tail it live.
& '__NODE__' __ARGS__ 2>&1 | Tee-Object -FilePath '__LOG__'
Write-Host 'node exited - press Enter to close'; Read-Host
'@
$body = $body.Replace('__NET__', $Network).Replace('__NODE__', $node).Replace('__ARGS__', $nodeArgs).Replace('__LOG__', $logFile)
Write-Tab $nodeTab $body

$metricsTab = Join-Path $DataDir "_tab_metrics.ps1"
if ($minerTop) {
  # Detailed ratatui dashboard (chain stats from --node get_info, gauges from --rig /metrics).
  $body = @'
$host.UI.RawUI.WindowTitle = 'CoinCync dashboard (miner-top)'
# wait for the node RPC before launching the TUI so it opens populated.
$probe = '{"jsonrpc":"2.0","id":1,"method":"get_info","params":[]}'
while ($true) { try { if ((Invoke-RestMethod -Uri '__RPC__' -Method Post -Body $probe -ContentType 'application/json' -TimeoutSec 3).result) { break } } catch { Start-Sleep -Milliseconds 800 } }
& '__MT__' --node '__RPC__' --rig 'http://127.0.0.1:__MPORT__/metrics'
Write-Host 'miner-top exited - press Enter to close'; Read-Host
'@
  $body = $body.Replace('__MT__', $minerTop).Replace('__RPC__', $rpcUrl).Replace('__MPORT__', "$metricsPort")
} else {
  # Fallback: plain PowerShell poller (no miner-top build found).
  $body = @'
$host.UI.RawUI.WindowTitle = 'CoinCync metrics'
$body = '{"jsonrpc":"2.0","id":1,"method":"get_metrics","params":[]}'
while ($true) {
  try {
    $m = (Invoke-RestMethod -Uri '__RPC__' -Method Post -Body $body -ContentType 'application/json' -TimeoutSec 4).result
    Clear-Host
    Write-Host ("=== CoinCync metrics (__NET__)  " + (Get-Date -Format T) + " ===") -ForegroundColor Cyan
    Write-Host ('height           : {0}' -f $m.chain_height)
    Write-Host ('difficulty       : {0}' -f $m.chain_difficulty)
    Write-Host ('total blocks     : {0}' -f $m.chain_total_blocks)
    Write-Host ('total txs        : {0}' -f $m.chain_total_transactions)
    Write-Host ('supply (atomic)  : {0}' -f $m.chain_supply_atomic)
    Write-Host ('mempool          : {0} tx / {1} bytes' -f $m.mempool_size, $m.mempool_bytes)
    Write-Host ('peers            : {0}' -f $m.peer_count)
    Write-Host ''
    Write-Host 'Prometheus scrape: http://127.0.0.1:__MPORT__/metrics' -ForegroundColor DarkGray
  } catch {
    Clear-Host; Write-Host 'waiting for node RPC on __RPC__ ...' -ForegroundColor Yellow
  }
  Start-Sleep -Seconds __POLL__
}
'@
  $body = $body.Replace('__RPC__', $rpcUrl).Replace('__NET__', $Network).Replace('__MPORT__', "$metricsPort").Replace('__POLL__', "$PollSecs")
}
Write-Tab $metricsTab $body

$eventsTab = Join-Path $DataDir "_tab_events.ps1"
$body = @'
$host.UI.RawUI.WindowTitle = 'CoinCync events/incidents'
$info = '{"jsonrpc":"2.0","id":1,"method":"get_info","params":[]}'
$evs  = '{"jsonrpc":"2.0","id":1,"method":"get_chain_events","params":[20]}'
while ($true) {
  try {
    $i = (Invoke-RestMethod -Uri '__RPC__' -Method Post -Body $info -ContentType 'application/json' -TimeoutSec 4).result
    $e = (Invoke-RestMethod -Uri '__RPC__' -Method Post -Body $evs  -ContentType 'application/json' -TimeoutSec 4).result
    Clear-Host
    Write-Host ("=== CoinCync status + events (__NET__)  " + (Get-Date -Format T) + " ===") -ForegroundColor Cyan
    Write-Host ('status {0} | height {1}/{2} | synced {3} | peers {4} | tip_age {5}s' -f $i.status, $i.height, $i.target_height, $i.synced, $i.peer_count, $i.tip_age_secs)
    Write-Host ''
    Write-Host 'recent chain events (reorgs / forks / rejects / checkpoints):' -ForegroundColor Yellow
    if ($e.events -and $e.events.Count -gt 0) {
      $e.events | Select-Object -First 15 | ForEach-Object { Write-Host ('  h{0,-8} {1}' -f $_.height, ($_ | ConvertTo-Json -Compress)) }
    } else { Write-Host '  (none yet)' -ForegroundColor DarkGray }
  } catch {
    Clear-Host; Write-Host 'waiting for node RPC on __RPC__ ...' -ForegroundColor Yellow
  }
  Start-Sleep -Seconds __POLL__
}
'@
$body = $body.Replace('__RPC__', $rpcUrl).Replace('__NET__', $Network).Replace('__POLL__', "$PollSecs")
Write-Tab $eventsTab $body

# incidents tab: live-tail the node log filtered to problems (the "bugs" feed).
$incidentsTab = Join-Path $DataDir "_tab_incidents.ps1"
$body = @'
$host.UI.RawUI.WindowTitle = 'CoinCync incidents'
Write-Host '=== live incidents: WARN / ERROR / reorg / reject / orphan / stall / panic ===' -ForegroundColor Red
$pat = 'WARN|ERROR|reorg|Reorg|REORG|reject|Reject|orphan|Orphan|stall|Stall|FAILED|Invalid|duplicate|panic|segfault|banned|disconnect'
while (-not (Test-Path '__LOG__')) { Start-Sleep -Milliseconds 500 }
Get-Content -Path '__LOG__' -Wait -Tail 500 | Select-String -Pattern $pat | ForEach-Object {
  $line = $_.Line
  $color = if ($line -match 'ERROR|FAILED|panic|segfault|Invalid') { 'Red' } else { 'Yellow' }
  Write-Host $line -ForegroundColor $color
}
'@
$body = $body.Replace('__LOG__', $logFile)
Write-Tab $incidentsTab $body

# -- launch: one Windows Terminal window, three tabs (backtick-; = wt tab sep) -
# Use PowerShell 7 (pwsh) if installed, else Windows PowerShell 5.1 (powershell).
$psExe = if (Get-Command pwsh -ErrorAction SilentlyContinue) { "pwsh" } else { "powershell" }
$hasWt = [bool](Get-Command wt.exe -ErrorAction SilentlyContinue)

if ($Tabs -and $hasWt) {
  # ONE window, four tabs. A quoted ";" is passed to wt as its tab separator
  # (PowerShell does not treat it as a statement terminator).
  wt -w 0 new-tab --title "node+miner" $psExe -NoExit -File "$nodeTab" ";" new-tab --title "metrics" $psExe -NoExit -File "$metricsTab" ";" new-tab --title "events" $psExe -NoExit -File "$eventsTab" ";" new-tab --title "incidents" $psExe -NoExit -File "$incidentsTab"
  Write-Host "Launched Windows Terminal with 4 tabs." -ForegroundColor Green
} elseif ($hasWt) {
  # DEFAULT: four SEPARATE Windows Terminal windows. A distinct -w <name> per call
  # forces each into its own window.
  wt -w cync-node      new-tab --title "node+miner" $psExe -NoExit -File "$nodeTab"
  wt -w cync-metrics   new-tab --title "metrics"    $psExe -NoExit -File "$metricsTab"
  wt -w cync-events    new-tab --title "events"     $psExe -NoExit -File "$eventsTab"
  wt -w cync-incidents new-tab --title "incidents"  $psExe -NoExit -File "$incidentsTab"
  Write-Host "Launched 4 separate Windows Terminal windows (node+miner / metrics / events / incidents)." -ForegroundColor Green
} else {
  # No Windows Terminal: four separate plain PowerShell windows.
  Start-Process $psExe -ArgumentList @("-NoExit", "-File", "$nodeTab")
  Start-Process $psExe -ArgumentList @("-NoExit", "-File", "$metricsTab")
  Start-Process $psExe -ArgumentList @("-NoExit", "-File", "$eventsTab")
  Start-Process $psExe -ArgumentList @("-NoExit", "-File", "$incidentsTab")
  Write-Host "Launched 4 separate PowerShell windows." -ForegroundColor Green
}
Write-Host "Data dir: $DataDir   RPC: $rpcUrl   metrics: http://127.0.0.1:$metricsPort/metrics"
if ($Network -eq "testnet") { Write-Host "Joining live testnet via seed $Seed + DNS seeds (seed1/2/3.coincync.network)." -ForegroundColor DarkGray }
