#Requires -Version 5.1
<#
.SYNOPSIS
  Faucet-based end-to-end smoke test of the user-onboarding flow.

.DESCRIPTION
  Mirrors what a real testnet user does on day one:

    1. Create wallet A
    2. Claim 10 tCYNC from the public faucet (POST /api/faucet)
    3. Wait for the drip to confirm in wallet A's balance
    4. Create wallet B
    5. Send a small amount A -> B
    6. Wait for the send tx to confirm in wallet B's balance

  This is the path 99% of testnet users hit on launch day. The
  mining-based smoke (smoke-test-tx.ps1) tests the same end-to-end
  flow but is gated by hashrate variance, which is irrelevant to
  user onboarding.

  PASS / FAIL reported with exit code 0 / 1.

.PARAMETER Node
  RPC endpoint for wallet scan + send. Defaults to the public testnet API.

.PARAMETER FaucetUrl
  Faucet API endpoint. Defaults to the production faucet at coincync.network.

.PARAMETER Network
  Network name. Default testnet.

.PARAMETER FaucetTimeoutMinutes
  Max wait for the faucet drip to confirm in wallet A. Default 5.

.PARAMETER ConfirmTimeoutMinutes
  Max wait for the A -> B send to confirm in wallet B. Default 5.

.PARAMETER KeepArtifacts
  If set, the temp wallet files are kept after the run for debugging.
  Default: cleanup on success, keep on failure.

.EXAMPLE
  .\scripts\smoke-test-faucet.ps1
#>

param(
  [string]$Node = 'https://api.coincync.network/rpc/testnet',
  [string]$FaucetUrl = 'https://api.coincync.network/faucet',
  [string]$Network = 'testnet',
  [int]$FaucetTimeoutMinutes = 5,
  [int]$ConfirmTimeoutMinutes = 5,
  [switch]$KeepArtifacts
)

$ErrorActionPreference = 'Stop'
$AtomicUnitsPerCync = [int64]1000000000000

# ── locate binaries ─────────────────────────────────────────────────
$RepoRoot = Split-Path -Parent $PSScriptRoot
$WalletBin = Join-Path $RepoRoot 'target\release\coincync-wallet.exe'

if (-not (Test-Path $WalletBin)) {
  Write-Host "FAIL: wallet binary not found at $WalletBin" -ForegroundColor Red
  Write-Host "Run: cargo build --release --bin coincync-wallet" -ForegroundColor Yellow
  exit 1
}

# ── temp dir for this run ───────────────────────────────────────────
$ts        = Get-Date -Format 'yyyyMMdd-HHmmss'
$tmpDir    = Join-Path $env:TEMP "coincync-smoketest-faucet-$ts"
New-Item -ItemType Directory -Force -Path $tmpDir | Out-Null
$walletA   = Join-Path $tmpDir 'walletA.bin'
$walletB   = Join-Path $tmpDir 'walletB.bin'
$logA      = Join-Path $tmpDir 'walletA.log'
$logB      = Join-Path $tmpDir 'walletB.log'
$pwd       = 'smoketest-faucet-do-not-reuse'

# Header
Write-Host ''
Write-Host '------------------------------------------------------------'   -ForegroundColor DarkGray
Write-Host '   CoinCync faucet smoke test - faucet -> wallet -> send'        -ForegroundColor Cyan
Write-Host '------------------------------------------------------------'   -ForegroundColor DarkGray
Write-Host ("  workspace:  $tmpDir")
Write-Host ("  rpc node:   $Node")
Write-Host ("  faucet url: $FaucetUrl")
Write-Host ("  network:    $Network")
Write-Host ''

$failure = $null

# ── helper: invoke wallet binary, capture output ───────────────────
function Invoke-Wallet {
  param([string]$Wallet, [Parameter(ValueFromRemainingArguments)][string[]]$Rest)
  $args = @(
    '--network', $Network,
    '--wallet', $Wallet,
    '--node', $Node
  ) + $Rest
  & $WalletBin @args 2>&1
}

# ── helper: parse "Field: value" lines from wallet output ──────────
function Parse-Field {
  param([string[]]$Output, [string]$Label)
  $hit = $Output | Select-String -Pattern "^\s*${Label}:\s*(.+)$"
  if ($hit) { return $hit.Matches[0].Groups[1].Value.Trim() }
  return $null
}

# ── helper: read balance from a wallet ─────────────────────────────
function Get-Balance {
  param([string]$Wallet)
  $out = Invoke-Wallet $Wallet balance --password $pwd
  $bal = Parse-Field $out 'Balance'
  if (-not $bal) { return 0 }
  # Balance line format example: "Balance: 10.000000000000 tCYNC (10000000000000 atomic)"
  $m = [regex]::Match($bal, '\(([0-9]+)\s+atomic\)')
  if ($m.Success) { return [int64]$m.Groups[1].Value }
  return 0
}

# ── stage 1: create wallet A ───────────────────────────────────────
try {
  Write-Host '[1/6] creating wallet A...' -ForegroundColor Yellow
  Invoke-Wallet $walletA create --password $pwd --force | Tee-Object -FilePath $logA | Out-Null
  Write-Host '      wallet A: ' -NoNewline; Write-Host $walletA -ForegroundColor DarkGray
} catch {
  $failure = "wallet A create failed: $_"
}

# ── stage 2: read A's address ──────────────────────────────────────
$aAddr = $null
if (-not $failure) {
  try {
    Write-Host '[2/6] reading wallet A address...' -ForegroundColor Yellow
    $aOut = Invoke-Wallet $walletA address --password $pwd
    $aAddr = Parse-Field $aOut 'Address'
    if (-not $aAddr) { throw 'failed to parse Address from wallet output' }
    Write-Host '      A address: ' -NoNewline; Write-Host ($aAddr.Substring(0,32) + '...') -ForegroundColor DarkGray
  } catch {
    $failure = "address read failed: $_"
  }
}

# ── stage 3: claim from faucet ─────────────────────────────────────
$faucetTxHash = $null
if (-not $failure) {
  try {
    Write-Host "[3/6] claiming 10 tCYNC from $FaucetUrl ..." -ForegroundColor Yellow
    $body = @{ address = $aAddr } | ConvertTo-Json -Compress
    $resp = Invoke-RestMethod -Uri $FaucetUrl `
                              -Method Post `
                              -ContentType 'application/json' `
                              -Body $body `
                              -TimeoutSec 30
    if (-not $resp.success) {
      $errMsg = if ($resp.error) { $resp.error } else { 'unknown' }
      throw "faucet returned error: $errMsg"
    }
    $faucetTxHash = $resp.tx_hash
    Write-Host '      faucet tx: ' -NoNewline; Write-Host $faucetTxHash -ForegroundColor DarkGray
  } catch {
    $failure = "faucet claim failed: $_"
  }
}

# ── stage 4: wait for drip to confirm in wallet A ──────────────────
if (-not $failure) {
  try {
    $deadline = (Get-Date).AddMinutes($FaucetTimeoutMinutes)
    Write-Host "[4/6] waiting up to $FaucetTimeoutMinutes min for drip to confirm in wallet A..." -ForegroundColor Yellow
    $confirmedAtomic = 0
    while ((Get-Date) -lt $deadline) {
      $confirmedAtomic = Get-Balance $walletA
      if ($confirmedAtomic -gt 0) {
        Write-Host "      wallet A balance: " -NoNewline
        Write-Host "$confirmedAtomic atomic (~$([math]::Round($confirmedAtomic / $AtomicUnitsPerCync, 2)) tCYNC)" -ForegroundColor Green
        break
      }
      $left = [int]([math]::Ceiling(($deadline - (Get-Date)).TotalSeconds))
      Write-Host "      still waiting... ${left}s left"
      Start-Sleep -Seconds 30
    }
    if ($confirmedAtomic -le 0) {
      throw "faucet drip never confirmed in wallet A within $FaucetTimeoutMinutes min"
    }
  } catch {
    $failure = "drip confirm failed: $_"
  }
}

# ── stage 5: create wallet B + send A -> B ─────────────────────────
$bAddr = $null
$sendAtomic = $AtomicUnitsPerCync  # 1 tCYNC
if (-not $failure) {
  try {
    Write-Host '[5/6] creating wallet B + sending 1 tCYNC A -> B...' -ForegroundColor Yellow
    Invoke-Wallet $walletB create --password $pwd --force | Tee-Object -FilePath $logB | Out-Null
    $bOut = Invoke-Wallet $walletB address --password $pwd
    $bAddr = Parse-Field $bOut 'Address'
    if (-not $bAddr) { throw 'failed to parse B address' }
    Write-Host '      B address: ' -NoNewline; Write-Host ($bAddr.Substring(0,32) + '...') -ForegroundColor DarkGray

    $sendOut = Invoke-Wallet $walletA send `
        --password $pwd `
        --to $bAddr `
        --amount $sendAtomic
    $sendTx = Parse-Field $sendOut 'Transaction hash'
    if (-not $sendTx) {
      # fall back to grep for any 64-char hex
      $hexMatch = $sendOut | Select-String -Pattern '\b[a-f0-9]{64}\b' | Select-Object -First 1
      if ($hexMatch) { $sendTx = $hexMatch.Matches[0].Value }
    }
    if (-not $sendTx) { throw "could not extract tx hash from send output" }
    Write-Host '      send tx: ' -NoNewline; Write-Host $sendTx -ForegroundColor DarkGray
  } catch {
    $failure = "send failed: $_"
  }
}

# ── stage 6: wait for B to receive ─────────────────────────────────
if (-not $failure) {
  try {
    $deadline = (Get-Date).AddMinutes($ConfirmTimeoutMinutes)
    Write-Host "[6/6] waiting up to $ConfirmTimeoutMinutes min for B to receive..." -ForegroundColor Yellow
    $bAtomic = 0
    while ((Get-Date) -lt $deadline) {
      $bAtomic = Get-Balance $walletB
      if ($bAtomic -ge $sendAtomic) {
        Write-Host "      wallet B balance: " -NoNewline
        Write-Host "$bAtomic atomic (~$([math]::Round($bAtomic / $AtomicUnitsPerCync, 2)) tCYNC)" -ForegroundColor Green
        break
      }
      $left = [int]([math]::Ceiling(($deadline - (Get-Date)).TotalSeconds))
      Write-Host "      still waiting... ${left}s left"
      Start-Sleep -Seconds 30
    }
    if ($bAtomic -lt $sendAtomic) {
      throw "wallet B never received >= $sendAtomic atomic within $ConfirmTimeoutMinutes min"
    }
  } catch {
    $failure = "receive confirm failed: $_"
  }
}

# ── result ─────────────────────────────────────────────────────────
Write-Host ''
Write-Host '------------------------------------------------------------' -ForegroundColor DarkGray
if ($failure) {
  Write-Host "  FAIL  $failure" -ForegroundColor Red
  Write-Host '------------------------------------------------------------' -ForegroundColor DarkGray
  Write-Host "  artifacts kept for debugging: $tmpDir"
  exit 1
}

Write-Host "  PASS  faucet -> wallet -> send -> receive flow verified end-to-end" -ForegroundColor Green
Write-Host '------------------------------------------------------------' -ForegroundColor DarkGray
if (-not $KeepArtifacts) {
  Remove-Item -Recurse -Force $tmpDir -ErrorAction SilentlyContinue
  Write-Host "  artifacts cleaned up: $tmpDir"
} else {
  Write-Host "  artifacts kept (--KeepArtifacts): $tmpDir"
}
exit 0
