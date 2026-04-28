<#
.SYNOPSIS
  Verifies public testnet bootstrap health from your machine:
  - DNS seeds in src/testnet.rs resolve
  - Hardcoded seed IPs accept TCP on the testnet P2P port (default 28080)

.PARAMETER RepoRoot
  Path to coincync repo root (folder containing src/testnet.rs).

.PARAMETER P2pPort
  Expected P2P port on seed IPs (default 28080 for testnet).

.PARAMETER StrictTcp
  If set, require every hardcoded seed IP to accept inbound TCP (often fails from home ISPs / host firewalls).
  Default: DNS must all resolve; at least one seed must accept TCP (enough to prove a join path exists).
#>
param(
  [string]$RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path,
  [int]$P2pPort = 28080,
  [switch]$StrictTcp
)

$ErrorActionPreference = "Stop"
$testnetRs = Join-Path $RepoRoot "src/testnet.rs"
if (-not (Test-Path $testnetRs)) {
  Write-Error "Missing $testnetRs (wrong RepoRoot?)"
  exit 2
}

function Get-RustStringArray {
  param([string]$ConstName)
  $lines = Get-Content -Path $testnetRs
  $capture = $false
  $out = [System.Collections.Generic.List[string]]::new()
  foreach ($line in $lines) {
    if ($line -match "pub const $ConstName") { $capture = $true; continue }
    if ($capture) {
      if ($line -match '^\s*\];') { break }
      $m = [regex]::Match($line, '"([^"]+)"')
      if ($m.Success) { $out.Add($m.Groups[1].Value) }
    }
  }
  return $out
}

$dnsSeeds = Get-RustStringArray "TESTNET_DNS_SEEDS"
$seedHosts = Get-RustStringArray "TESTNET_SEED_NODES"

Write-Host "repo=$RepoRoot"
Write-Host "p2p_port=$P2pPort"
$anyFail = $false

Write-Host "--- dns_seeds ---"
foreach ($name in $dnsSeeds) {
  try {
    $r = Resolve-DnsName -Name $name -Type A -ErrorAction Stop
    $ips = ($r | Where-Object { $_.Type -eq 'A' } | ForEach-Object { $_.IPAddress }) -join ' '
    if ($ips) { Write-Host "dns_ok=$name -> $ips" }
    else {
      Write-Host "dns_fail=$name (no A records)"
      $anyFail = $true
    }
  } catch {
    Write-Host "dns_fail=$name $($_.Exception.Message)"
    $anyFail = $true
  }
}

function Test-TcpOpen {
  param([string]$HostName, [int]$Port, [int]$TimeoutMs = 3000)
  $client = New-Object System.Net.Sockets.TcpClient
  try {
    $iar = $client.BeginConnect($HostName, $Port, $null, $null)
    if (-not $iar.AsyncWaitHandle.WaitOne($TimeoutMs, $false)) {
      return $false
    }
    $client.EndConnect($iar)
    return $client.Connected
  } catch {
    return $false
  } finally {
    try { $client.Close() } catch {}
  }
}

Write-Host "--- hardcoded_seed_p2p ---"
$tcpOk = 0
$tcpFail = 0
foreach ($ep in $seedHosts) {
  $parts = $ep -split ':'
  if ($parts.Count -lt 2) { continue }
  $hostOnly = $parts[0]
  $port = [int]$parts[1]
  if ($port -ne $P2pPort) {
    Write-Host "warn=unexpected_port endpoint=$ep"
  }
  if (Test-TcpOpen -HostName $hostOnly -Port $port) {
    Write-Host "tcp_ok=$ep"
    $tcpOk++
  } else {
    Write-Host "tcp_fail=$ep"
    $tcpFail++
    if ($StrictTcp) { $anyFail = $true }
  }
}

if ($tcpOk -eq 0) {
  Write-Host "result=FAIL no_tcp_path (open inbound P2P $P2pPort on at least one seed, or run from a network that can reach seeds)"
  exit 1
}
if ($StrictTcp -and $tcpFail -gt 0) {
  Write-Host "result=FAIL strict_tcp ($tcpFail hosts unreachable)"
  exit 1
}
if ($tcpFail -gt 0) {
  $tcpTotal = $tcpOk + $tcpFail
  Write-Host ("note=some_tcp_failed {0}/{1} - often host firewall; DNS bootstrap may still work" -f $tcpFail, $tcpTotal)
}

if ($anyFail) {
  Write-Host "result=FAIL"
  exit 1
}
Write-Host "result=OK"
exit 0
