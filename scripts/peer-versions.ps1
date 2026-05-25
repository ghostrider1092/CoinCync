#requires -Version 5.1
<#
.SYNOPSIS
  Scan testnet peers and report the % already running v1.0.10 or later.

.DESCRIPTION
  Before activating the MIN_OUTPUT_AGE hard fork, we need to know
  what fraction of the seed/miner fleet has upgraded to v1.0.10. If
  <80% have upgraded, the activation should be postponed — forking off
  20% of the network damages the testnet metrics and operator trust.

  This script queries each seed in the operator-supplied list via the
  `get_peers` JSON-RPC method, deduplicates the union of peers reported
  by all seeds, then queries each peer's version string via `get_info`.
  Reports the % at-or-above the target version.

  Limitations:
  - Only sees peers that at least one of the polled seeds knows about.
    Peers behind NAT that have only outbound connections aren't visible
    here. The seeds themselves should be a representative cross-section.
  - Some peers may not expose JSON-RPC publicly; those count as
    "unreachable" rather than "running old version" — adjust your
    threshold mental model accordingly.

.PARAMETER Seeds
  Array of seed RPC URLs. Defaults to the three published testnet seeds.

.PARAMETER TargetVersion
  Minimum acceptable version, in "MAJOR.MINOR.PATCH" form. Defaults to
  "1.0.10". Peers at-or-above this version count as "upgraded."

.PARAMETER Threshold
  Pass/fail threshold for the upgrade % required. Default 80. Below
  this prints a clear DO-NOT-ACTIVATE recommendation.

.PARAMETER TimeoutSec
  Per-peer RPC timeout. Default 5 seconds.

.EXAMPLE
  .\peer-versions.ps1
  # Default: scan 3 seeds, target v1.0.10, fail below 80%

.EXAMPLE
  .\peer-versions.ps1 -TargetVersion 1.0.10 -Threshold 90
  # Stricter: require 90% upgraded before activation

.EXAMPLE
  .\peer-versions.ps1 -Seeds @("https://my-private-seed/rpc")
  # Custom seed list
#>

[CmdletBinding()]
param(
  [string[]]$Seeds = @(
    "https://api.coincync.network/rpc/testnet"
    # Add additional seeds as they come online — diversity reduces seed-set bias
  ),

  [ValidatePattern('^\d+\.\d+\.\d+$')]
  [string]$TargetVersion = "1.0.10",

  [ValidateRange(50, 100)]
  [int]$Threshold = 80,

  [ValidateRange(1, 60)]
  [int]$TimeoutSec = 5
)

$ErrorActionPreference = 'Stop'

# ─── Helpers ──────────────────────────────────────────────────────────
function Invoke-RpcCall {
  param(
    [string]$Url,
    [string]$Method,
    [int]$Timeout
  )
  $body = ConvertTo-Json @{
    jsonrpc = "2.0"
    id = 1
    method = $Method
  } -Compress
  try {
    $resp = Invoke-WebRequest -Uri $Url -Method POST -Body $body `
              -ContentType 'application/json' -TimeoutSec $Timeout -UseBasicParsing
    return ($resp.Content | ConvertFrom-Json).result
  } catch {
    return $null
  }
}

function Compare-Versions {
  # Returns -1 if a < b, 0 if equal, 1 if a > b
  param([string]$a, [string]$b)
  $av = [version]$a
  $bv = [version]$b
  return $av.CompareTo($bv)
}

function Parse-VersionFromString {
  # Pull "X.Y.Z" out of a peer's version string. Examples:
  #   "coincync 1.0.9"           → "1.0.9"
  #   "coincync-node/v1.0.10"    → "1.0.10"
  #   "1.0.9-testnet-pre-audit"  → "1.0.9"
  param([string]$s)
  if ($null -eq $s) { return $null }
  $m = [regex]::Match($s, '\d+\.\d+\.\d+')
  if ($m.Success) { return $m.Value }
  return $null
}

# ─── Discover the peer set ────────────────────────────────────────────
Write-Host "Discovering peers from $($Seeds.Count) seed(s)..." -ForegroundColor Cyan

$peerSet = [System.Collections.Generic.HashSet[string]]::new()
$seedsReached = 0

foreach ($seed in $Seeds) {
  Write-Host "  Polling $seed ... " -NoNewline
  $info = Invoke-RpcCall -Url $seed -Method 'get_peers' -Timeout $TimeoutSec
  if ($null -eq $info) {
    Write-Host "UNREACHABLE" -ForegroundColor Red
    continue
  }
  $seedsReached++

  # get_peers returns an array of {address: "host:port", ...} entries.
  # Schema varies a bit by version; try a couple of shapes.
  $peerList = if ($info -is [array]) { $info } elseif ($info.peers) { $info.peers } else { @() }

  $addedThisSeed = 0
  foreach ($peer in $peerList) {
    $addr = if ($peer.address) { $peer.address } elseif ($peer -is [string]) { $peer } else { $null }
    if ($addr -and $peerSet.Add($addr)) { $addedThisSeed++ }
  }
  Write-Host "$($peerList.Count) reported, $addedThisSeed new" -ForegroundColor Gray
}

if ($seedsReached -eq 0) {
  Write-Host ""
  Write-Host "ERROR: no seeds reachable. Cannot assess upgrade %." -ForegroundColor Red
  exit 1
}

Write-Host ""
Write-Host "Discovered $($peerSet.Count) unique peers across $seedsReached seed(s)." -ForegroundColor Cyan

if ($peerSet.Count -lt 10) {
  Write-Host "WARNING: peer set is small (<10). Statistical confidence is poor; treat results as advisory only." -ForegroundColor Yellow
}

# ─── Query each peer's version ────────────────────────────────────────
Write-Host ""
Write-Host "Querying version from each peer (timeout ${TimeoutSec}s each)..." -ForegroundColor Cyan
Write-Host "  This may take up to $($peerSet.Count * $TimeoutSec) seconds in the worst case."
Write-Host ""

$upgraded   = 0
$outdated   = @()
$unreachable = 0
$peerVersions = @{}

foreach ($peerAddr in $peerSet) {
  # Peers report host:port for P2P, but JSON-RPC is on a different port.
  # Assume the standard RPC port (28081 testnet) and HTTPS isn't there
  # on most operator nodes — try plain HTTP first.
  $host_part = ($peerAddr -split ':')[0]
  $rpcUrl = "http://${host_part}:28081"

  $info = Invoke-RpcCall -Url $rpcUrl -Method 'get_info' -Timeout $TimeoutSec
  if ($null -eq $info) {
    $unreachable++
    continue
  }

  # Try a few common fields for the version string.
  $versionRaw = $info.version `
              ?? $info.client_version `
              ?? $info.node_version `
              ?? $info.user_agent
  $version = Parse-VersionFromString $versionRaw

  if ($null -eq $version) {
    $unreachable++
    continue
  }

  $peerVersions[$peerAddr] = $version
  if ((Compare-Versions $version $TargetVersion) -ge 0) {
    $upgraded++
  } else {
    $outdated += @{ Addr = $peerAddr; Version = $version }
  }
}

$totalReachable = $upgraded + $outdated.Count
$pctUpgraded = if ($totalReachable -gt 0) {
  [math]::Round(($upgraded / $totalReachable) * 100.0, 1)
} else { 0 }

# ─── Report ───────────────────────────────────────────────────────────
Write-Host "════════════════════════════════════════════════════════════════════"
Write-Host "  FLEET UPGRADE STATUS — target ≥ v$TargetVersion" -ForegroundColor Yellow
Write-Host "════════════════════════════════════════════════════════════════════"
Write-Host "  Peers discovered:           $($peerSet.Count)"
Write-Host "  Peers reachable on RPC:     $totalReachable"
Write-Host "  Peers RPC-unreachable:      $unreachable" -ForegroundColor $(if ($unreachable -gt $peerSet.Count / 2) { 'Yellow' } else { 'Gray' })
Write-Host ""
Write-Host "  At-or-above target version: $upgraded ($pctUpgraded%)" -ForegroundColor $(if ($pctUpgraded -ge $Threshold) { 'Green' } else { 'Red' })
Write-Host "  Outdated:                   $($outdated.Count)" -ForegroundColor $(if ($outdated.Count -eq 0) { 'Green' } else { 'Yellow' })
Write-Host ""

if ($outdated.Count -gt 0) {
  Write-Host "  Outdated peers (DM these operators):" -ForegroundColor Yellow
  $outdated | Sort-Object Version, Addr | ForEach-Object {
    Write-Host "    $($_.Addr.PadRight(40)) v$($_.Version)" -ForegroundColor Gray
  }
  Write-Host ""
}

Write-Host "════════════════════════════════════════════════════════════════════"
if ($pctUpgraded -ge $Threshold) {
  Write-Host "  ✓ ACTIVATION SAFE: ${pctUpgraded}% upgraded ≥ ${Threshold}% threshold" -ForegroundColor Green
  Write-Host "════════════════════════════════════════════════════════════════════"
  exit 0
} else {
  Write-Host "  ✗ DO NOT ACTIVATE: ${pctUpgraded}% upgraded < ${Threshold}% threshold" -ForegroundColor Red
  Write-Host "════════════════════════════════════════════════════════════════════"
  Write-Host ""
  Write-Host "Recommended action:" -ForegroundColor Yellow
  Write-Host "  1. Postpone activation height per docs/launch/v1.0.10-CHECKLIST.md §8" -ForegroundColor Yellow
  Write-Host "  2. Re-arm with a later height using:" -ForegroundColor Yellow
  Write-Host "       .\arm-min-output-age-fork.ps1 -Buffer 10000" -ForegroundColor Yellow
  Write-Host "  3. Re-poll with this script in 48h to check upgrade progress" -ForegroundColor Yellow
  exit 2
}
