<#
.SYNOPSIS
  Local multi-node soak: bring up N new-code CoinCync nodes on one box (fresh
  regtest genesis, isolated from the live fleet), mine on node 0, and monitor
  that every node stays converged on the same tip and keeps advancing.

.DESCRIPTION
  This is the "test the new code on a network without the old fleet" rung. All
  nodes run THIS build, share a fresh genesis, never dial the internet
  (--no-peers), and peer only with each other via an explicit --addnode full
  mesh. Node 0 runs the built-in miner; nodes 1..N-1 must sync from it.

  Opens one window per node (logs tee'd to <DataDir>\nodeI.log) plus a monitor
  window that every -PollSecs polls all nodes' get_info and records:
    - each node's height + tip
    - CONVERGED  (all reachable nodes share the tip, or within 1 block) vs
      DIVERGED   (two nodes at the same height with different tips = a real bug)
    - any node DOWN (crash)
  Everything is appended as JSON to <DataDir>\soak.log for post-run analysis.

  Go/no-go for a Hetzner deploy after ~24h: no DOWN, no sustained DIVERGED,
  height advanced steadily, and no Invalid/FAILED in the node logs.

.EXAMPLE
  .\scripts\soak-local.ps1 -Nodes 4 -Threads 2            # 4-node mesh, node0 mines
.EXAMPLE
  .\scripts\soak-local.ps1 -Nodes 3 -Fresh -PollSecs 30   # wipe + start fresh
#>
[CmdletBinding()]
param(
  [ValidateRange(2, 8)][int]$Nodes = 4,
  [int]$Threads = 2,
  [string]$DataDir = "",
  [int]$PollSecs = 30,
  [switch]$Fresh
)

$ErrorActionPreference = "Stop"
$repo = Split-Path -Parent $PSScriptRoot
$env:COINCYNC_RANDOMX_LIGHT_MODE = "1"
$env:RUST_MIN_STACK = "268435456"
if (Test-Path "C:\Program Files\LLVM\bin") { $env:PATH = "C:\Program Files\LLVM\bin;$env:PATH" }

if ([string]::IsNullOrWhiteSpace($DataDir)) { $DataDir = Join-Path $repo ".localnet-soak" }
if (-not [System.IO.Path]::IsPathRooted($DataDir)) { $DataDir = Join-Path (Get-Location).Path $DataDir }
if ($Fresh -and (Test-Path $DataDir)) { Remove-Item -Recurse -Force $DataDir }
New-Item -ItemType Directory -Force -Path $DataDir | Out-Null
$DataDir = (Resolve-Path -LiteralPath $DataDir).Path

function Find-Bin([string]$name) {
  foreach ($p in @("$repo\target\release\$name.exe", "$repo\target\debug\$name.exe")) { if (Test-Path $p) { return $p } }
  return $null
}
$node = Find-Bin "coincync-node"
$wallet = Find-Bin "coincync-wallet"
if (-not $node) { Write-Error "coincync-node not built: cargo build --release --features testnet --bin coincync-node"; exit 1 }
if (-not $wallet) { Write-Error "coincync-wallet not built: cargo build --release --features testnet --bin coincync-wallet"; exit 1 }
$minerTop = $null
foreach ($p in @("$repo\tools\miner-top\target\release\miner-top.exe", "$repo\tools\miner-top\target\debug\miner-top.exe")) { if (Test-Path $p) { $minerTop = $p; break } }

# -- port plan: node i -> p2p 19000+i*10, rpc 19001+i*10, metrics rpc+1 --------
function P2p([int]$i) { 19000 + $i * 10 }
function Rpc([int]$i) { 19001 + $i * 10 }

# -- mining address (regtest dev wallet) -------------------------------------
$env:COINCYNC_WALLET_PASSWORD = "coincync-soak-dev"
$walletFile = Join-Path $DataDir "soak.wallet"
$prevEAP = $ErrorActionPreference; $ErrorActionPreference = "Continue"
if (-not (Test-Path $walletFile)) { & $wallet --network regtest --wallet $walletFile create *> $null }
$addrOut = (& $wallet --network regtest --wallet $walletFile address --json 2> $null)
$ErrorActionPreference = $prevEAP
$jsonLine = ($addrOut | Where-Object { $_.TrimStart().StartsWith('{') } | Select-Object -First 1)
try { $Address = ($jsonLine | ConvertFrom-Json).address } catch { $Address = "" }
if (-not $Address) { Write-Error "could not derive mining address"; exit 1 }
Write-Host "Soak: $Nodes nodes, node0 mines to $Address ($Threads threads)" -ForegroundColor Green

$psExe = if (Get-Command pwsh -ErrorAction SilentlyContinue) { "pwsh" } else { "powershell" }
$hasWt = [bool](Get-Command wt.exe -ErrorAction SilentlyContinue)

# -- per-node tab scripts ----------------------------------------------------
$nodeTabs = @()
for ($i = 0; $i -lt $Nodes; $i++) {
  $ndir = Join-Path $DataDir "node$i"
  New-Item -ItemType Directory -Force -Path $ndir | Out-Null
  # full-mesh --addnode to every other node
  $peers = ""
  for ($j = 0; $j -lt $Nodes; $j++) { if ($j -ne $i) { $peers += " --addnode 127.0.0.1:$(P2p $j)" } }
  $nargs = "--network regtest --data-dir `"$ndir`" --no-peers --p2p-bind 127.0.0.1:$(P2p $i) --rpc-bind 127.0.0.1:$(Rpc $i)$peers"
  if ($i -eq 0) { $nargs += " --mine $Address --mine-threads $Threads" }
  $log = Join-Path $DataDir "node$i.log"
  $tab = Join-Path $DataDir "_soak_node$i.ps1"
  $b = @'
$host.UI.RawUI.WindowTitle = 'soak node __I__ (rpc __RPC__)'
Write-Host '=== soak node __I__  p2p=__P2P__ rpc=__RPC__  mine=__MINE__ ===' -ForegroundColor Cyan
& '__NODE__' __ARGS__ 2>&1 | Tee-Object -FilePath '__LOG__'
Write-Host 'node exited - press Enter'; Read-Host
'@
  $b = $b.Replace('__I__', "$i").Replace('__RPC__', "$(Rpc $i)").Replace('__P2P__', "$(P2p $i)").Replace('__MINE__', $(if ($i -eq 0) { "yes" } else { "no" })).Replace('__NODE__', $node).Replace('__ARGS__', $nargs).Replace('__LOG__', $log)
  Set-Content -Encoding UTF8 -Path $tab -Value $b
  $nodeTabs += $tab
}

# -- soak monitor tab --------------------------------------------------------
$soakLog = Join-Path $DataDir "soak.log"
$rpcList = (0..($Nodes - 1) | ForEach-Object { "http://127.0.0.1:$(Rpc $_)" }) -join ","
$monTab = Join-Path $DataDir "_soak_monitor.ps1"
$b = @'
$host.UI.RawUI.WindowTitle = 'soak MONITOR'
$urls = '__RPCS__'.Split(',')
$body = '{"jsonrpc":"2.0","id":1,"method":"get_info","params":[]}'
$soakLog = '__SOAKLOG__'
$startH = $null
while ($true) {
  $rows = @()
  foreach ($u in $urls) {
    try {
      $r = (Invoke-RestMethod -Uri $u -Method Post -Body $body -ContentType 'application/json' -TimeoutSec 4).result
      $rows += [pscustomobject]@{ url = $u; up = $true; height = [int]$r.height; tip = "$($r.tip_hash)".Substring(0, [Math]::Min(12, "$($r.tip_hash)".Length)); peers = $r.peer_count }
    } catch {
      $rows += [pscustomobject]@{ url = $u; up = $false; height = -1; tip = "DOWN"; peers = 0 }
    }
  }
  $upRows = $rows | Where-Object { $_.up }
  $maxH = ($upRows | Measure-Object height -Maximum).Maximum
  if ($null -eq $startH -and $maxH) { $startH = $maxH }
  # convergence: among nodes at the max height, do they share one tip?
  $atMax = $upRows | Where-Object { $_.height -eq $maxH }
  $tips = ($atMax | Select-Object -ExpandProperty tip -Unique)
  $down = ($rows | Where-Object { -not $_.up }).Count
  $status = if ($down -gt 0) { "DOWN($down)" } elseif ($tips.Count -le 1) { "CONVERGED" } else { "DIVERGED" }
  $color = switch ($status) { "CONVERGED" { "Green" } "DIVERGED" { "Red" } default { "Yellow" } }
  Clear-Host
  Write-Host ("=== SOAK MONITOR  " + (Get-Date -Format 'MM-dd HH:mm:ss') + "  ===") -ForegroundColor Cyan
  Write-Host ("status: {0}   maxHeight: {1}   advanced: +{2}" -f $status, $maxH, ($(if ($startH) { $maxH - $startH } else { 0 }))) -ForegroundColor $color
  Write-Host ''
  $rows | ForEach-Object { Write-Host ("  {0}  h={1,-7} tip={2,-14} peers={3} {4}" -f $_.url, $_.height, $_.tip, $_.peers, $(if ($_.up) { '' } else { '<-- DOWN' })) }
  $obj = [ordered]@{ utc = [DateTime]::UtcNow.ToString('o'); status = $status; max_height = $maxH; down = $down; distinct_tips_at_max = $tips.Count; nodes = $rows }
  ($obj | ConvertTo-Json -Compress) | Out-File -FilePath $soakLog -Encoding utf8 -Append
  Start-Sleep -Seconds __POLL__
}
'@
$b = $b.Replace('__RPCS__', $rpcList).Replace('__SOAKLOG__', $soakLog).Replace('__POLL__', "$PollSecs")
Set-Content -Encoding UTF8 -Path $monTab -Value $b

# -- launch: node windows + monitor (+ optional miner-top on node0) ----------
function Launch([string]$title, [string]$tab, [string]$winName) {
  if ($hasWt) { wt -w $winName new-tab --title $title $psExe -NoExit -File "$tab" }
  else { Start-Process $psExe -ArgumentList @("-NoExit", "-File", "$tab") }
}
for ($i = 0; $i -lt $Nodes; $i++) { Launch "node$i" $nodeTabs[$i] "cync-soak-n$i" }
Launch "MONITOR" $monTab "cync-soak-mon"
if ($minerTop) {
  $mt = Join-Path $DataDir "_soak_minertop.ps1"
  $b = "& '$minerTop' --node 'http://127.0.0.1:$(Rpc 0)' --rig 'http://127.0.0.1:$((Rpc 0)+1)/metrics'"
  Set-Content -Encoding UTF8 -Path $mt -Value $b
  Launch "dashboard" $mt "cync-soak-dash"
}

Write-Host ""
Write-Host "Soak running. Data dir: $DataDir" -ForegroundColor Green
Write-Host "  monitor log: $soakLog   (JSON per poll)"
Write-Host "  node logs:   $DataDir\node*.log"
Write-Host "Go/no-go after ~24h: no DOWN, no sustained DIVERGED, height advanced, no Invalid/FAILED in node logs."
Write-Host "Stop everything: taskkill /F /IM coincync-node.exe"
